//! The daemon's built-in TURN server: startup resolution of its realm and secret, its
//! configuration, and spawning its listeners.
//!
//! The realm and the `static-auth-secret` (coturn's `use-auth-secret` REST profile) are resolved
//! once, before anything binds, so a half-configured server is a refused start instead of a TURN
//! server that silently stays off.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use siphon_rtp_datapath::{Datapath, RxPacket};
use siphon_rtp_turn::{tls, NoFastPath, PeerIpPolicy, SystemUnixClock, Turn, TurnConfig};
use tokio::net::{TcpListener, UdpSocket};

use crate::daemon::RunConfig;

/// Environment variable carrying the TURN realm (`--turn-realm`, config key `turn_realm`).
pub(crate) const TURN_REALM_ENV: &str = "SIPHON_RTP_TURN_REALM";

/// Environment variable carrying the TURN static-auth-secret directly.
pub(crate) const TURN_SECRET_ENV: &str = "SIPHON_RTP_TURN_SECRET";

/// Environment variable naming a file that holds the TURN static-auth-secret, the `*_FILE`
/// convention for a container whose secrets live on a volume (no shell wrapper to read them).
pub(crate) const TURN_SECRET_FILE_ENV: &str = "SIPHON_RTP_TURN_SECRET_FILE";

/// Why the TURN server's realm and secret were refused at startup.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TurnServerSettingsError {
    /// A secret from the environment and a secret file at once.
    #[error(
        "both {TURN_SECRET_ENV} and a TURN secret file ({path}) are set; pick one, refusing to \
         guess which secret the TURN server should authenticate with"
    )]
    SecretAndFile {
        /// The secret file.
        path: String,
    },
    /// The secret file could not be read.
    #[error("cannot read TURN secret file {path}: {reason}")]
    UnreadableSecretFile {
        /// The secret file.
        path: String,
        /// The I/O error.
        reason: String,
    },
    /// The secret file holds nothing but whitespace.
    #[error("TURN secret file {path} is empty; remove the option to run without the TURN server")]
    EmptySecretFile {
        /// The secret file.
        path: String,
    },
    /// `SIPHON_RTP_TURN_SECRET` is set to the empty string.
    #[error(
        "{TURN_SECRET_ENV} is set but empty; an empty secret would let anyone mint credentials, \
         unset it to run without the TURN server"
    )]
    EmptySecret,
    /// An environment variable holds a value that is not Unicode.
    #[error("environment variable {name} is not valid Unicode")]
    NotUnicode {
        /// The variable (its value is never printed).
        name: &'static str,
    },
    /// A realm without a secret.
    #[error(
        "a TURN realm is set (--turn-realm, turn_realm or {TURN_REALM_ENV}) but no secret is: \
         give {TURN_SECRET_ENV} or --turn-secret-file, or remove the realm to run without TURN"
    )]
    RealmWithoutSecret,
    /// A secret without a realm.
    #[error(
        "a TURN secret is set ({TURN_SECRET_ENV} or --turn-secret-file) but no realm is: give \
         --turn-realm, turn_realm or {TURN_REALM_ENV}, or remove the secret to run without TURN"
    )]
    SecretWithoutRealm,
}

/// The realm and secret the built-in TURN server authenticates REST credentials against.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    /// The realm advertised in the 401 challenge (RFC 8656 §7.2).
    pub realm: String,
    /// The static-auth-secret the time-limited credentials are an HMAC of.
    pub secret: Vec<u8>,
}

impl std::fmt::Debug for TurnCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnCredentials")
            .field("realm", &self.realm)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Resolve the built-in TURN server's credentials: `realm` and `secret_file` are the already
/// merged flag-or-config values, with `SIPHON_RTP_TURN_REALM` / `SIPHON_RTP_TURN_SECRET_FILE` as
/// the fallback, and `SIPHON_RTP_TURN_SECRET` the direct form of the secret.
///
/// TURN is on when a realm **and** a secret are present, off when neither is. Anything in between
/// is a fatal startup error: it used to leave the server silently off, which a deployment finds
/// out about when the first browser fails to allocate.
///
/// Both a secret in the environment and a secret file is refused rather than preferring one, for
/// the reason the control secret does the same: they would be different secrets in every case worth
/// worrying about. One trailing newline (and any other surrounding whitespace) is trimmed from the
/// file; an empty file is refused rather than read as "no secret".
pub(crate) fn resolve_turn_credentials(
    realm: Option<&str>,
    secret_file: Option<&Path>,
) -> Result<Option<TurnCredentials>, TurnServerSettingsError> {
    let realm = match realm {
        Some(realm) => Some(realm.to_string()),
        None => env_value(TURN_REALM_ENV)?,
    }
    .filter(|value| !value.is_empty());
    // Set-but-empty counts as set, as it does for the control secret: an empty secret beside a file
    // is a conflict, and on its own an empty secret, never "TURN off".
    let from_env = env_value(TURN_SECRET_ENV)?;
    let path: Option<PathBuf> = match secret_file {
        Some(path) => Some(path.to_path_buf()),
        None => env_value(TURN_SECRET_FILE_ENV)?
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
    };
    let secret = match (path, from_env) {
        (Some(path), Some(_)) => {
            return Err(TurnServerSettingsError::SecretAndFile {
                path: path.display().to_string(),
            })
        }
        (Some(path), None) => Some(read_secret_file(&path)?),
        (None, Some(secret)) if secret.is_empty() => {
            return Err(TurnServerSettingsError::EmptySecret)
        }
        (None, secret) => secret,
    };
    match (realm, secret) {
        (None, None) => Ok(None),
        (Some(realm), Some(secret)) => Ok(Some(TurnCredentials {
            realm,
            secret: secret.into_bytes(),
        })),
        (Some(_), None) => Err(TurnServerSettingsError::RealmWithoutSecret),
        (None, Some(_)) => Err(TurnServerSettingsError::SecretWithoutRealm),
    }
}

/// [`resolve_turn_credentials`] over the merged flag-and-config-file options of `settings`.
pub(crate) fn turn_credentials_for(
    settings: &RunConfig,
) -> Result<Option<TurnCredentials>, TurnServerSettingsError> {
    resolve_turn_credentials(
        settings.turn_realm.as_deref(),
        settings.turn_secret_file.as_deref(),
    )
}

/// The value of environment variable `name`: `None` when unset. A value that is not Unicode is a
/// startup error that names the variable and never prints the value, which may be the secret.
fn env_value(name: &'static str) -> Result<Option<String>, TurnServerSettingsError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(TurnServerSettingsError::NotUnicode { name }),
    }
}

/// Read and trim the secret file.
fn read_secret_file(path: &Path) -> Result<String, TurnServerSettingsError> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        TurnServerSettingsError::UnreadableSecretFile {
            path: path.display().to_string(),
            reason: error.to_string(),
        }
    })?;
    let secret = contents.trim();
    if secret.is_empty() {
        return Err(TurnServerSettingsError::EmptySecretFile {
            path: path.display().to_string(),
        });
    }
    Ok(secret.to_string())
}

/// The built-in TURN server's configuration for `settings`: the realm and secret, the advertised
/// relay address, and the peer denylist.
///
/// The denylist is the secure default (loopback, private, link-local and multicast peers refused,
/// RFC 8656 §21) unless `--turn-permit-private-peers` is set, which lifts only the loopback and
/// private-range denials; link-local and multicast stay refused.
pub(crate) fn turn_config(realm: String, secret: Vec<u8>, settings: &RunConfig) -> TurnConfig {
    let mut config = TurnConfig::new(realm, secret);
    config.relay_address = settings.turn_relay_ip;
    if settings.turn_permit_private_peers {
        config.denied_peers = PeerIpPolicy {
            deny_loopback: false,
            deny_private: false,
            ..PeerIpPolicy::default()
        };
        tracing::warn!(
            "--turn-permit-private-peers: the TURN server will relay to loopback and private \
             peers, which weakens the anti-SSRF default (RFC 8656 §21, security-and-nat.md §11 \
             R3). Never enable it on a server reachable by untrusted clients."
        );
    }
    config
}

/// Build and start the TURN server for the resolved `credentials`,
/// spawning whichever of the UDP/TCP/TLS listeners are configured. Returns `None` when TURN is off.
/// Generic over the datapath backend so TURN shares whichever one the daemon selected.
pub(crate) async fn spawn_turn<D>(
    datapath: Arc<D>,
    settings: &RunConfig,
    credentials: Option<TurnCredentials>,
) -> Result<(Option<Turn>, Option<flume::Sender<RxPacket>>), Box<dyn std::error::Error>>
where
    D: Datapath + 'static,
{
    let Some(TurnCredentials { realm, secret }) = credentials else {
        return Ok((None, None));
    };

    let config = turn_config(realm.clone(), secret, settings);
    // TURN's relay packets are fed by the redirect dispatcher (it shares datapath.rx() with the SRTP
    // bridge), not drained by TURN directly. Drop-newest on a full mailbox — late media is worthless.
    let (relay_tx, relay_rx) = flume::bounded(2048);
    let turn = Turn::spawn_with_relay_source(
        datapath,
        config,
        Arc::new(SystemUnixClock),
        Box::new(NoFastPath),
        relay_rx,
    )?;
    tracing::info!(realm, "TURN server enabled (coturn replacement)");

    if let Some(addr) = settings.turn_udp {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(turn_udp = %addr, "TURN UDP listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_udp(socket).await;
        });
    }
    if let Some(addr) = settings.turn_tcp {
        let tcp = TcpListener::bind(addr).await?;
        tracing::info!(turn_tcp = %addr, "TURN TCP listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_tcp(tcp).await;
        });
    }
    if let Some(addr) = settings.turn_tls {
        let (Some(cert), Some(key)) = (&settings.turn_tls_cert, &settings.turn_tls_key) else {
            return Err("turns: (--turn-tls) requires --turn-tls-cert and --turn-tls-key".into());
        };
        tls::install_crypto_provider();
        let acceptor = tls::acceptor_from_pem(cert, key)?;
        let tls_listener = TcpListener::bind(addr).await?;
        tracing::info!(turn_tls = %addr, "TURN TLS listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_tls(tls_listener, acceptor).await;
        });
    }

    if settings.turn_udp.is_none() && settings.turn_tcp.is_none() && settings.turn_tls.is_none() {
        tracing::warn!(
            "TURN is configured but no --turn-udp/--turn-tcp/--turn-tls listener was given"
        );
    }
    Ok((Some(turn), Some(relay_tx)))
}

#[cfg(test)]
mod tests {
    use super::{
        resolve_turn_credentials, TurnServerSettingsError, TURN_REALM_ENV, TURN_SECRET_ENV,
        TURN_SECRET_FILE_ENV,
    };

    /// These tests mutate process-wide environment variables, so they run under one mutex and
    /// always restore what they found. Nothing else reads these three variables outside
    /// `resolve_turn_credentials`.
    static TURN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const VARIABLES: [&str; 3] = [TURN_REALM_ENV, TURN_SECRET_ENV, TURN_SECRET_FILE_ENV];

    /// Run `body` with the three TURN variables set to `values` (unset when `None`), then restore.
    fn with_env<T>(values: [Option<&str>; 3], body: impl FnOnce() -> T) -> T {
        let _guard = TURN_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let saved: Vec<Option<String>> = VARIABLES
            .iter()
            .map(|name| std::env::var(name).ok())
            .collect();
        for (name, value) in VARIABLES.iter().zip(values) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        let outcome = body();
        for (name, value) in VARIABLES.iter().zip(saved) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        outcome
    }

    fn secret_file(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("turn.secret");
        std::fs::write(&path, contents).expect("write");
        (dir, path)
    }

    #[test]
    fn neither_realm_nor_secret_leaves_turn_off() {
        with_env([None, None, None], || {
            assert_eq!(resolve_turn_credentials(None, None), Ok(None));
        });
    }

    #[test]
    fn a_secret_file_and_a_realm_enable_turn_and_the_newline_is_trimmed() {
        with_env([None, None, None], || {
            let (_dir, path) = secret_file("s3cret\n");
            let credentials = resolve_turn_credentials(Some("turn.example.com"), Some(&path))
                .expect("resolve")
                .expect("enabled");
            assert_eq!(credentials.realm, "turn.example.com");
            assert_eq!(credentials.secret, b"s3cret");
        });
    }

    #[test]
    fn the_environment_alone_still_enables_turn() {
        with_env([Some("turn.example.com"), Some("direct"), None], || {
            let credentials = resolve_turn_credentials(None, None)
                .expect("resolve")
                .expect("enabled");
            assert_eq!(credentials.realm, "turn.example.com");
            assert_eq!(credentials.secret, b"direct");
        });
    }

    #[test]
    fn the_secret_file_can_come_from_the_environment() {
        let (_dir, path) = secret_file("  from-env-path \n");
        let path_text = path.display().to_string();
        with_env([Some("turn.example.com"), None, Some(&path_text)], || {
            let credentials = resolve_turn_credentials(None, None)
                .expect("resolve")
                .expect("enabled");
            assert_eq!(credentials.secret, b"from-env-path");
        });
    }

    #[test]
    fn the_realm_flag_wins_over_the_environment() {
        with_env([Some("from-env"), Some("direct"), None], || {
            let credentials = resolve_turn_credentials(Some("from-flag"), None)
                .expect("resolve")
                .expect("enabled");
            assert_eq!(credentials.realm, "from-flag");
        });
    }

    #[test]
    fn a_secret_file_beside_the_secret_variable_is_refused() {
        with_env([Some("turn.example.com"), Some("direct"), None], || {
            let (_dir, path) = secret_file("from-file\n");
            let error = resolve_turn_credentials(None, Some(&path)).expect_err("must refuse");
            assert!(
                matches!(error, TurnServerSettingsError::SecretAndFile { .. }),
                "{error}"
            );
        });
    }

    #[test]
    fn an_empty_or_unreadable_secret_file_is_refused() {
        with_env([None, None, None], || {
            let (_dir, path) = secret_file(" \n\t\n");
            let error = resolve_turn_credentials(Some("realm"), Some(&path)).expect_err("empty");
            assert!(
                matches!(error, TurnServerSettingsError::EmptySecretFile { .. }),
                "{error}"
            );
            let missing = path.with_file_name("absent");
            let error =
                resolve_turn_credentials(Some("realm"), Some(&missing)).expect_err("unreadable");
            assert!(
                matches!(error, TurnServerSettingsError::UnreadableSecretFile { .. }),
                "{error}"
            );
        });
    }

    #[test]
    fn a_realm_without_a_secret_is_a_startup_error_not_a_silent_off() {
        with_env([None, None, None], || {
            assert_eq!(
                resolve_turn_credentials(Some("turn.example.com"), None),
                Err(TurnServerSettingsError::RealmWithoutSecret)
            );
        });
        with_env([Some("turn.example.com"), None, None], || {
            assert_eq!(
                resolve_turn_credentials(None, None),
                Err(TurnServerSettingsError::RealmWithoutSecret)
            );
        });
    }

    #[test]
    fn a_secret_without_a_realm_is_a_startup_error_not_a_silent_off() {
        with_env([None, Some("direct"), None], || {
            assert_eq!(
                resolve_turn_credentials(None, None),
                Err(TurnServerSettingsError::SecretWithoutRealm)
            );
        });
        let (_dir, path) = secret_file("from-file\n");
        with_env([None, None, None], || {
            assert_eq!(
                resolve_turn_credentials(None, Some(&path)),
                Err(TurnServerSettingsError::SecretWithoutRealm)
            );
        });
    }

    #[test]
    fn an_empty_secret_variable_beside_a_file_is_the_same_conflict() {
        let (_dir, path) = secret_file("from-file\n");
        with_env([Some("turn.example.com"), Some(""), None], || {
            let error = resolve_turn_credentials(None, Some(&path)).expect_err("must refuse");
            assert!(matches!(
                error,
                TurnServerSettingsError::SecretAndFile { .. }
            ));
        });
    }

    #[test]
    fn an_empty_secret_variable_alone_is_fatal_not_off() {
        with_env([Some("turn.example.com"), Some(""), None], || {
            assert_eq!(
                resolve_turn_credentials(None, None),
                Err(TurnServerSettingsError::EmptySecret)
            );
        });
        with_env([None, Some(""), None], || {
            assert_eq!(
                resolve_turn_credentials(None, None),
                Err(TurnServerSettingsError::EmptySecret)
            );
        });
    }

    #[test]
    fn a_non_unicode_environment_value_is_fatal_and_never_printed() {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::ffi::OsStr::from_bytes(b"s3cr\xffet");
        for name in VARIABLES {
            with_env([None, None, None], || {
                std::env::set_var(name, bad);
                let error = resolve_turn_credentials(None, None).expect_err("refused");
                assert_eq!(error, TurnServerSettingsError::NotUnicode { name });
                let text = error.to_string();
                assert!(text.contains(name) && !text.contains("s3cr"), "{text}");
                std::env::remove_var(name);
            });
        }
    }

    #[test]
    fn an_empty_realm_never_enables_turn() {
        with_env([Some(""), Some("direct"), None], || {
            assert_eq!(
                resolve_turn_credentials(None, None),
                Err(TurnServerSettingsError::SecretWithoutRealm)
            );
        });
        with_env([Some(""), None, None], || {
            assert_eq!(resolve_turn_credentials(None, None), Ok(None));
        });
    }

    #[test]
    fn credentials_never_print_the_secret() {
        let credentials = super::TurnCredentials {
            realm: "turn.example.com".into(),
            secret: b"hunter2".to_vec(),
        };
        let printed = format!("{credentials:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }
}
