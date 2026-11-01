//! Startup validation and resolution of the daemon's TURN client options (`--turn-client`,
//! `--turn-client-secret-file`, `--turn-client-ttl`) into an engine [`TurnClientConfig`].
//!
//! Everything that can be wrong with the operator's configuration is refused here, at startup, with
//! a message that says what to change: a relay that is silently not configured is a call that
//! fails over the internet later.

use std::net::SocketAddr;
use std::path::Path;

use crate::engine::{TurnClientConfig, TurnCredentialSource};

/// Built-in default for `--turn-client-ttl`: one day, in seconds. The REST username cannot change
/// during an allocation (RFC 8656 §7.2, 441 Wrong Credentials), so this has to outlive the longest
/// call; every allocation mints its own username, so it does not have to outlive the process.
pub const DEFAULT_TURN_CLIENT_TTL_SECS: u64 = 86_400;

/// Default TURN port when the URI names none (RFC 8656 §3.1).
const DEFAULT_TURN_PORT: u16 = 3478;

/// Why the TURN client options were refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TurnClientSettingsError {
    /// `--turn-client` was given without `--ice-full`.
    #[error(
        "--turn-client requires --ice-full: a relayed candidate is only usable once the remote \
         candidates have a permission on the allocation, which only the full ICE agent's checklist \
         knows, and an ICE-lite agent advertises host candidates only (RFC 8445 §2.5)"
    )]
    NeedsFullIce,
    /// `turns:` or a non-UDP transport was asked for.
    #[error(
        "TURN server `{uri}`: only UDP is supported for now (use `turn:host:port`, optionally \
         `?transport=udp`); `turns:` and `?transport=tcp` need a stream transport the client does \
         not have yet"
    )]
    UdpOnly {
        /// The URI as the operator wrote it.
        uri: String,
    },
    /// The URI is not `turn:host[:port][?transport=udp]`.
    #[error("TURN server `{uri}` is not of the form turn:host[:port][?transport=udp]: {reason}")]
    BadUri {
        /// The URI as the operator wrote it.
        uri: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The hostname did not resolve to any address.
    #[error("TURN server `{uri}` did not resolve: {reason}")]
    Unresolvable {
        /// The URI as the operator wrote it.
        uri: String,
        /// The resolver's message.
        reason: String,
    },
    /// Servers were given with no secret to mint credentials from.
    #[error(
        "--turn-client needs --turn-client-secret-file (the TURN server's static-auth-secret)"
    )]
    MissingSecret,
    /// A secret file was given with no server to use it for.
    #[error("--turn-client-secret-file is set but no --turn-client server is configured")]
    SecretWithoutServer,
    /// The secret file could not be read.
    #[error("cannot read TURN client secret file {path}: {reason}")]
    UnreadableSecret {
        /// The file.
        path: String,
        /// The I/O error.
        reason: String,
    },
    /// The secret file holds no secret.
    #[error("TURN client secret file {path} is empty")]
    EmptySecret {
        /// The file.
        path: String,
    },
    /// A zero credential lifetime would mint usernames that are already expired.
    #[error("--turn-client-ttl must be at least 1 second")]
    ZeroTtl,
}

/// A parsed `turn:` URI: the host (name or literal) and port, not yet resolved.
#[derive(Debug, PartialEq, Eq)]
struct TurnUri {
    host: String,
    port: u16,
}

/// Parse `turn:host[:port][?transport=udp]` (RFC 7064 §3.1), refusing `turns:` and any transport
/// other than UDP.
fn parse_turn_uri(uri: &str) -> Result<TurnUri, TurnClientSettingsError> {
    let bad = |reason| TurnClientSettingsError::BadUri {
        uri: uri.to_string(),
        reason,
    };
    let udp_only = || TurnClientSettingsError::UdpOnly {
        uri: uri.to_string(),
    };
    let lowered = uri.to_ascii_lowercase();
    if lowered.starts_with("turns:") {
        return Err(udp_only());
    }
    let Some(rest) = uri
        .get("turn:".len()..)
        .filter(|_| lowered.starts_with("turn:"))
    else {
        return Err(bad("missing `turn:` scheme"));
    };
    let (authority, query) = match rest.split_once('?') {
        Some((authority, query)) => (authority, Some(query)),
        None => (rest, None),
    };
    if let Some(query) = query {
        // RFC 7064 §3.1: the only query parameter is `transport`.
        match query.to_ascii_lowercase().strip_prefix("transport=") {
            Some("udp") => {}
            Some(_) => return Err(udp_only()),
            None => return Err(bad("unknown query parameter")),
        }
    }
    if authority.is_empty() {
        return Err(bad("empty host"));
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, after)) = bracketed.split_once(']') else {
            return Err(bad("unterminated `[` in IPv6 literal"));
        };
        let port = match after.strip_prefix(':') {
            Some(port) => Some(port),
            None if after.is_empty() => None,
            None => return Err(bad("unexpected text after IPv6 literal")),
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            Some(_) => return Err(bad("an IPv6 literal must be written in brackets")),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(bad("empty host"));
    }
    let port = match port {
        Some(port) => port.parse::<u16>().map_err(|_| bad("invalid port"))?,
        None => DEFAULT_TURN_PORT,
    };
    Ok(TurnUri {
        host: host.to_string(),
        port,
    })
}

/// Read the `static-auth-secret` from `path`: trimmed, and refused when empty (an empty secret
/// would mint credentials anyone can forge).
fn read_secret(path: &Path) -> Result<String, TurnClientSettingsError> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        TurnClientSettingsError::UnreadableSecret {
            path: path.display().to_string(),
            reason: error.to_string(),
        }
    })?;
    let secret = contents.trim();
    if secret.is_empty() {
        return Err(TurnClientSettingsError::EmptySecret {
            path: path.display().to_string(),
        });
    }
    Ok(secret.to_string())
}

/// Resolve the TURN client options. `None` when no `--turn-client` server is configured.
///
/// Hostnames are resolved here, once, at startup; the first address a name resolves to is used.
///
/// # Errors
/// See [`TurnClientSettingsError`]: every misconfiguration is refused with a message naming the
/// option to change.
pub async fn resolve_turn_client(
    uris: &[String],
    secret_file: Option<&Path>,
    ttl_secs: u64,
    ice_full: bool,
    identity: &str,
) -> Result<Option<TurnClientConfig>, TurnClientSettingsError> {
    if uris.is_empty() {
        return match secret_file {
            Some(_) => Err(TurnClientSettingsError::SecretWithoutServer),
            None => Ok(None),
        };
    }
    if !ice_full {
        return Err(TurnClientSettingsError::NeedsFullIce);
    }
    // Parsed first, so a malformed URI is refused before any lookup is attempted.
    let parsed = uris
        .iter()
        .map(|uri| parse_turn_uri(uri).map(|parsed| (uri, parsed)))
        .collect::<Result<Vec<_>, _>>()?;
    let path = secret_file.ok_or(TurnClientSettingsError::MissingSecret)?;
    let secret = read_secret(path)?;
    if ttl_secs == 0 {
        return Err(TurnClientSettingsError::ZeroTtl);
    }
    let mut servers: Vec<SocketAddr> = Vec::with_capacity(parsed.len());
    for (uri, parsed) in parsed {
        let mut addresses = tokio::net::lookup_host((parsed.host.as_str(), parsed.port))
            .await
            .map_err(|error| TurnClientSettingsError::Unresolvable {
                uri: uri.clone(),
                reason: error.to_string(),
            })?;
        let address = addresses
            .next()
            .ok_or_else(|| TurnClientSettingsError::Unresolvable {
                uri: uri.clone(),
                reason: "no addresses".to_string(),
            })?;
        servers.push(address);
    }
    Ok(Some(TurnClientConfig {
        servers,
        credentials: TurnCredentialSource::Rest {
            secret,
            identity: identity.to_string(),
            ttl_secs,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uris(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn secret_file(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes()).expect("write secret");
        file
    }

    #[test]
    fn parses_host_port_and_default_port() {
        assert_eq!(
            parse_turn_uri("turn:relay.example.com:3479").expect("parse"),
            TurnUri {
                host: "relay.example.com".into(),
                port: 3479
            }
        );
        assert_eq!(
            parse_turn_uri("turn:relay.example.com")
                .expect("parse")
                .port,
            3478
        );
        assert_eq!(
            parse_turn_uri("TURN:192.0.2.1:3478?transport=UDP").expect("parse"),
            TurnUri {
                host: "192.0.2.1".into(),
                port: 3478
            }
        );
        assert_eq!(
            parse_turn_uri("turn:[2001:db8::1]:3478").expect("parse"),
            TurnUri {
                host: "2001:db8::1".into(),
                port: 3478
            }
        );
    }

    #[test]
    fn turns_and_tcp_are_refused_as_udp_only() {
        for uri in [
            "turns:relay.example.com:5349",
            "turn:relay.example.com:3478?transport=tcp",
            "turn:relay.example.com?transport=tls",
        ] {
            assert!(
                matches!(
                    parse_turn_uri(uri),
                    Err(TurnClientSettingsError::UdpOnly { .. })
                ),
                "{uri}"
            );
        }
        let message = parse_turn_uri("turns:relay.example.com")
            .expect_err("refused")
            .to_string();
        assert!(message.contains("only UDP"), "{message}");
    }

    #[test]
    fn malformed_uris_are_refused() {
        for uri in [
            "relay.example.com:3478",
            "stun:relay.example.com",
            "turn:",
            "turn::3478",
            "turn:host:notaport",
            "turn:host:70000",
            "turn:2001:db8::1",
            "turn:[2001:db8::1",
            "turn:host?foo=bar",
        ] {
            assert!(
                matches!(
                    parse_turn_uri(uri),
                    Err(TurnClientSettingsError::BadUri { .. })
                ),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn nothing_configured_resolves_to_none() {
        assert_eq!(
            resolve_turn_client(&[], None, 60, false, "node")
                .await
                .expect("resolve"),
            None
        );
    }

    #[tokio::test]
    async fn turn_client_without_ice_full_is_refused_citing_rfc_8445() {
        let file = secret_file("s3cret\n");
        let error = resolve_turn_client(
            &uris(&["turn:127.0.0.1:3478"]),
            Some(file.path()),
            60,
            false,
            "node",
        )
        .await
        .expect_err("refused");
        assert_eq!(error, TurnClientSettingsError::NeedsFullIce);
        assert!(error.to_string().contains("RFC 8445 §2.5"));
    }

    #[tokio::test]
    async fn an_empty_secret_file_is_refused() {
        let file = secret_file(" \n");
        let error = resolve_turn_client(
            &uris(&["turn:127.0.0.1:3478"]),
            Some(file.path()),
            60,
            true,
            "node",
        )
        .await
        .expect_err("refused");
        assert!(matches!(error, TurnClientSettingsError::EmptySecret { .. }));
    }

    #[tokio::test]
    async fn a_missing_secret_file_or_option_is_refused() {
        let error = resolve_turn_client(&uris(&["turn:127.0.0.1:3478"]), None, 60, true, "node")
            .await
            .expect_err("refused");
        assert_eq!(error, TurnClientSettingsError::MissingSecret);
        let error = resolve_turn_client(
            &uris(&["turn:127.0.0.1:3478"]),
            Some(Path::new("/nonexistent/turn-secret")),
            60,
            true,
            "node",
        )
        .await
        .expect_err("refused");
        assert!(matches!(
            error,
            TurnClientSettingsError::UnreadableSecret { .. }
        ));
        let file = secret_file("s3cret");
        let error = resolve_turn_client(&[], Some(file.path()), 60, true, "node")
            .await
            .expect_err("refused");
        assert_eq!(error, TurnClientSettingsError::SecretWithoutServer);
    }

    #[tokio::test]
    async fn a_zero_ttl_is_refused() {
        let file = secret_file("s3cret");
        let error = resolve_turn_client(
            &uris(&["turn:127.0.0.1:3478"]),
            Some(file.path()),
            0,
            true,
            "node",
        )
        .await
        .expect_err("refused");
        assert_eq!(error, TurnClientSettingsError::ZeroTtl);
    }

    #[tokio::test]
    async fn servers_resolve_in_the_order_given_with_rest_credentials() {
        let file = secret_file("s3cret\n");
        let config = resolve_turn_client(
            &uris(&["turn:127.0.0.1:3479", "turn:localhost:3480"]),
            Some(file.path()),
            120,
            true,
            "node-a",
        )
        .await
        .expect("resolve")
        .expect("configured");
        assert_eq!(config.servers.len(), 2);
        assert_eq!(
            config.servers[0],
            "127.0.0.1:3479".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(config.servers[1].port(), 3480);
        assert!(config.servers[1].ip().is_loopback());
        assert_eq!(
            config.credentials,
            TurnCredentialSource::Rest {
                secret: "s3cret".into(),
                identity: "node-a".into(),
                ttl_secs: 120
            }
        );
    }

    #[tokio::test]
    async fn an_unresolvable_host_is_refused_at_startup() {
        let file = secret_file("s3cret");
        let error = resolve_turn_client(
            &uris(&["turn:no-such-host.invalid:3478"]),
            Some(file.path()),
            60,
            true,
            "node",
        )
        .await
        .expect_err("refused");
        assert!(matches!(
            error,
            TurnClientSettingsError::Unresolvable { .. }
        ));
    }
}
