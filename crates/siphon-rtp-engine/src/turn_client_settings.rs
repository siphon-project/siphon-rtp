//! Startup validation and resolution of the daemon's TURN client options (`--turn-client`,
//! `--turn-client-secret-file`, `--turn-client-ttl`, `--turn-client-ca-file`) into an engine [`TurnClientConfig`].
//!
//! Everything that can be wrong with the operator's configuration is refused here, at startup, with
//! a message that says what to change: a relay that is silently not configured is a call that
//! fails over the internet later.

use std::path::Path;
use std::sync::Arc;

use crate::engine::{TurnClientConfig, TurnCredentialSource, TurnServer, TurnTransport};

/// Built-in default for `--turn-client-ttl`: one day, in seconds. The REST username cannot change
/// during an allocation (RFC 8656 §7.2, 441 Wrong Credentials), so this has to outlive the longest
/// call; every allocation mints its own username, so it does not have to outlive the process.
pub const DEFAULT_TURN_CLIENT_TTL_SECS: u64 = 86_400;

/// Default port of `turn:` when the URI names none (RFC 8656 §3.1).
const DEFAULT_TURN_PORT: u16 = 3478;

/// Default port of `turns:` when the URI names none (RFC 7065 §3.1: 5349, the TLS port).
const DEFAULT_TURNS_PORT: u16 = 5349;

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
    /// A transport the client cannot run.
    #[error("TURN server `{uri}`: {reason}")]
    UnsupportedTransport {
        /// The URI as the operator wrote it.
        uri: String,
        /// What cannot be done and what to write instead.
        reason: &'static str,
    },
    /// `--turn-client-ca-file` was given but no server is `turns:`.
    #[error(
        "--turn-client-ca-file is set but no --turn-client server is a turns: URI, so no TLS \
         connection would use it"
    )]
    CaWithoutTls,
    /// The CA file could not be read or holds no usable certificate.
    #[error("cannot use TURN client CA file {path}: {reason}")]
    BadCaFile {
        /// The file.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The URI is not `turn:host[:port][?transport=...]` or `turns:host[:port]`.
    #[error("TURN server `{uri}` is not of the form turn:host[:port][?transport=udp|tcp] or turns:host[:port]: {reason}")]
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

/// A parsed `turn:` or `turns:` URI: the host (name or literal), port and transport, not yet
/// resolved.
#[derive(Debug, PartialEq, Eq)]
struct TurnUri {
    host: String,
    port: u16,
    transport: UriTransport,
}

/// The transport a URI selects (RFC 7065 §3.1, RFC 7064 §3.1).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum UriTransport {
    Udp,
    Tcp,
    Tls,
}

/// Parse `turn:host[:port][?transport=udp|tcp]` and `turns:host[:port][?transport=tcp]`
/// (RFC 7064 §3.1, RFC 7065 §3.1). `turn:` defaults to UDP on 3478; `turns:` is TLS over TCP, on
/// 5349 by default. `turns:` with `transport=udp` would be DTLS (RFC 7350), which the client does
/// not speak, and is refused rather than quietly downgraded.
fn parse_turn_uri(uri: &str) -> Result<TurnUri, TurnClientSettingsError> {
    let bad = |reason| TurnClientSettingsError::BadUri {
        uri: uri.to_string(),
        reason,
    };
    let unsupported = |reason| TurnClientSettingsError::UnsupportedTransport {
        uri: uri.to_string(),
        reason,
    };
    let lowered = uri.to_ascii_lowercase();
    let (secure, scheme_len) = if lowered.starts_with("turns:") {
        (true, "turns:".len())
    } else if lowered.starts_with("turn:") {
        (false, "turn:".len())
    } else {
        return Err(bad("missing `turn:` or `turns:` scheme"));
    };
    let rest = &uri[scheme_len..];
    let (authority, query) = match rest.split_once('?') {
        Some((authority, query)) => (authority, Some(query)),
        None => (rest, None),
    };
    let mut transport = if secure {
        UriTransport::Tls
    } else {
        UriTransport::Udp
    };
    if let Some(query) = query {
        // RFC 7064 §3.1: the only query parameter is `transport`.
        let lowered_query = query.to_ascii_lowercase();
        let Some(value) = lowered_query.strip_prefix("transport=") else {
            return Err(bad("unknown query parameter"));
        };
        match (secure, value) {
            (false, "udp") => transport = UriTransport::Udp,
            (false, "tcp") => transport = UriTransport::Tcp,
            (true, "tcp") => transport = UriTransport::Tls,
            (true, "udp") => {
                return Err(unsupported(
                    "turns: with transport=udp is TURN over DTLS, which is not supported; use \
                     turns:host (TLS over TCP) or turn:host",
                ))
            }
            (false, "tls") => {
                return Err(unsupported(
                    "write TURN over TLS as turns:host, not turn:host?transport=tls",
                ))
            }
            _ => return Err(unsupported("transport must be udp or tcp")),
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
    if secure && rustls_pki_types::ServerName::try_from(host.to_string()).is_err() {
        return Err(bad("the host is not a valid TLS server name"));
    }
    let port = match port {
        Some(port) => port.parse::<u16>().map_err(|_| bad("invalid port"))?,
        None if secure => DEFAULT_TURNS_PORT,
        None => DEFAULT_TURN_PORT,
    };
    Ok(TurnUri {
        host: host.to_string(),
        port,
        transport,
    })
}

/// Build the TLS client configuration for `turns:` servers from a private CA bundle: the file's
/// certificates are the only trust anchors, replacing the public web roots, so the server must
/// chain to the operator's own CA. TLS 1.3 preferred, 1.2 accepted; ring only.
///
/// # Errors
/// [`TurnClientSettingsError::BadCaFile`] when the file cannot be read, holds no certificate, or
/// holds one rustls rejects.
pub fn build_ca_client_config(
    path: &Path,
) -> Result<Arc<rustls::ClientConfig>, TurnClientSettingsError> {
    use rustls_pki_types::pem::PemObject;
    let bad = |reason: String| TurnClientSettingsError::BadCaFile {
        path: path.display().to_string(),
        reason,
    };
    siphon_rtp_turn::tls::install_crypto_provider();
    let bytes = std::fs::read(path).map_err(|error| bad(error.to_string()))?;
    let mut roots = rustls::RootCertStore::empty();
    let mut count = 0usize;
    for certificate in rustls_pki_types::CertificateDer::pem_slice_iter(&bytes) {
        let certificate = certificate.map_err(|error| bad(error.to_string()))?;
        roots
            .add(certificate)
            .map_err(|error| bad(error.to_string()))?;
        count += 1;
    }
    if count == 0 {
        return Err(bad("no PEM certificate found".to_string()));
    }
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
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
    ca_file: Option<&Path>,
) -> Result<Option<TurnClientConfig>, TurnClientSettingsError> {
    if uris.is_empty() {
        return match (secret_file, ca_file) {
            (Some(_), _) => Err(TurnClientSettingsError::SecretWithoutServer),
            (None, Some(_)) => Err(TurnClientSettingsError::CaWithoutTls),
            (None, None) => Ok(None),
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
    if ca_file.is_some()
        && !parsed
            .iter()
            .any(|(_, parsed)| parsed.transport == UriTransport::Tls)
    {
        return Err(TurnClientSettingsError::CaWithoutTls);
    }
    let path = secret_file.ok_or(TurnClientSettingsError::MissingSecret)?;
    let secret = read_secret(path)?;
    if ttl_secs == 0 {
        return Err(TurnClientSettingsError::ZeroTtl);
    }
    let tls = ca_file.map(build_ca_client_config).transpose()?;
    let mut servers: Vec<TurnServer> = Vec::with_capacity(parsed.len());
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
        // The URI's hostname is kept for the TLS handshake: the resolved address cannot be
        // verified against a certificate (RFC 6125 §6.4), the name can.
        let transport = match parsed.transport {
            UriTransport::Udp => TurnTransport::Udp,
            UriTransport::Tcp => TurnTransport::Tcp,
            UriTransport::Tls => TurnTransport::Tls {
                server_name: parsed.host.clone(),
            },
        };
        servers.push(TurnServer { address, transport });
    }
    Ok(Some(TurnClientConfig {
        servers,
        credentials: TurnCredentialSource::Rest {
            secret,
            identity: identity.to_string(),
            ttl_secs,
        },
        tls,
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
                port: 3479,
                transport: UriTransport::Udp
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
                port: 3478,
                transport: UriTransport::Udp
            }
        );
        assert_eq!(
            parse_turn_uri("turn:[2001:db8::1]:3478").expect("parse"),
            TurnUri {
                host: "2001:db8::1".into(),
                port: 3478,
                transport: UriTransport::Udp
            }
        );
    }

    #[test]
    fn tcp_and_tls_uris_select_their_transport_and_default_port() {
        let tcp = parse_turn_uri("turn:relay.example.com?transport=tcp").expect("parse");
        assert_eq!((tcp.port, tcp.transport), (3478, UriTransport::Tcp));
        let tls = parse_turn_uri("turns:relay.example.com").expect("parse");
        assert_eq!(tls.host, "relay.example.com");
        assert_eq!((tls.port, tls.transport), (5349, UriTransport::Tls));
        // RFC 7065 §3.1: `turns:` may name its (TCP) transport explicitly.
        let explicit = parse_turn_uri("TURNS:relay.example.com:443?transport=TCP").expect("parse");
        assert_eq!(
            (explicit.port, explicit.transport),
            (443, UriTransport::Tls)
        );
        let literal = parse_turn_uri("turns:[2001:db8::1]").expect("parse");
        assert_eq!((literal.port, literal.transport), (5349, UriTransport::Tls));
    }

    #[test]
    fn dtls_and_the_legacy_tls_transport_spelling_are_refused_with_what_to_write() {
        for (uri, hint) in [
            ("turns:relay.example.com?transport=udp", "DTLS"),
            ("turn:relay.example.com?transport=tls", "turns:host"),
            ("turn:relay.example.com?transport=sctp", "udp or tcp"),
        ] {
            let error = parse_turn_uri(uri).expect_err("refused");
            assert!(
                matches!(error, TurnClientSettingsError::UnsupportedTransport { .. }),
                "{uri}"
            );
            assert!(error.to_string().contains(hint), "{uri}: {error}");
        }
    }

    #[test]
    fn a_turns_host_must_be_a_valid_tls_server_name() {
        assert!(matches!(
            parse_turn_uri("turns:bad_name!.example.com"),
            Err(TurnClientSettingsError::BadUri { .. })
        ));
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
            "turns:",
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
        assert!(resolve_turn_client(&[], None, 60, false, "node", None)
            .await
            .expect("resolve")
            .is_none());
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
            None,
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
            None,
        )
        .await
        .expect_err("refused");
        assert!(matches!(error, TurnClientSettingsError::EmptySecret { .. }));
    }

    #[tokio::test]
    async fn a_missing_secret_file_or_option_is_refused() {
        let error = resolve_turn_client(
            &uris(&["turn:127.0.0.1:3478"]),
            None,
            60,
            true,
            "node",
            None,
        )
        .await
        .expect_err("refused");
        assert_eq!(error, TurnClientSettingsError::MissingSecret);
        let error = resolve_turn_client(
            &uris(&["turn:127.0.0.1:3478"]),
            Some(Path::new("/nonexistent/turn-secret")),
            60,
            true,
            "node",
            None,
        )
        .await
        .expect_err("refused");
        assert!(matches!(
            error,
            TurnClientSettingsError::UnreadableSecret { .. }
        ));
        let file = secret_file("s3cret");
        let error = resolve_turn_client(&[], Some(file.path()), 60, true, "node", None)
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
            None,
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
            None,
        )
        .await
        .expect("resolve")
        .expect("configured");
        assert_eq!(config.servers.len(), 2);
        assert_eq!(
            config.servers[0],
            TurnServer::from(
                "127.0.0.1:3479"
                    .parse::<std::net::SocketAddr>()
                    .expect("addr")
            )
        );
        assert_eq!(config.servers[1].address.port(), 3480);
        assert!(config.servers[1].address.ip().is_loopback());
        assert!(config.tls.is_none(), "no CA file: the default trust store");
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
            None,
        )
        .await
        .expect_err("refused");
        assert!(matches!(
            error,
            TurnClientSettingsError::Unresolvable { .. }
        ));
    }

    /// A self-signed CA certificate as PEM, for the CA-file tests.
    fn ca_pem() -> String {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("key");
        params.self_signed(&key).expect("certificate").pem()
    }

    #[tokio::test]
    async fn stream_servers_resolve_with_their_transport_and_the_name_kept_for_tls() {
        let secret = secret_file("s3cret");
        let config = resolve_turn_client(
            &uris(&[
                "turn:127.0.0.1",
                "turn:127.0.0.1:3479?transport=tcp",
                "turns:localhost",
            ]),
            Some(secret.path()),
            60,
            true,
            "node",
            None,
        )
        .await
        .expect("resolve")
        .expect("configured");
        assert_eq!(config.servers[0].transport, TurnTransport::Udp);
        assert_eq!(
            config.servers[1],
            TurnServer::tcp("127.0.0.1:3479".parse().expect("addr"))
        );
        assert_eq!(config.servers[2].address.port(), 5349);
        assert_eq!(
            config.servers[2].transport,
            TurnTransport::Tls {
                server_name: "localhost".into()
            },
            "the hostname survives resolution for SNI and certificate verification"
        );
    }

    #[tokio::test]
    async fn a_ca_file_builds_the_tls_configuration_for_turns_servers() {
        let secret = secret_file("s3cret");
        let ca = secret_file(&ca_pem());
        let config = resolve_turn_client(
            &uris(&["turns:127.0.0.1"]),
            Some(secret.path()),
            60,
            true,
            "node",
            Some(ca.path()),
        )
        .await
        .expect("resolve")
        .expect("configured");
        assert!(config.tls.is_some());
    }

    #[tokio::test]
    async fn a_ca_file_without_a_turns_server_is_refused() {
        let secret = secret_file("s3cret");
        let ca = secret_file(&ca_pem());
        for list in [
            uris(&["turn:127.0.0.1"]),
            uris(&["turn:127.0.0.1?transport=tcp"]),
            Vec::new(),
        ] {
            let error = resolve_turn_client(
                &list,
                if list.is_empty() {
                    None
                } else {
                    Some(secret.path())
                },
                60,
                true,
                "node",
                Some(ca.path()),
            )
            .await
            .expect_err("refused");
            assert_eq!(error, TurnClientSettingsError::CaWithoutTls);
        }
    }

    #[tokio::test]
    async fn an_unreadable_or_empty_ca_file_is_refused() {
        let secret = secret_file("s3cret");
        let empty = secret_file("not a certificate\n");
        for path in [Path::new("/nonexistent/turn-ca.pem"), empty.path()] {
            let error = resolve_turn_client(
                &uris(&["turns:127.0.0.1"]),
                Some(secret.path()),
                60,
                true,
                "node",
                Some(path),
            )
            .await
            .expect_err("refused");
            assert!(
                matches!(error, TurnClientSettingsError::BadCaFile { .. }),
                "{error}"
            );
        }
    }
}
