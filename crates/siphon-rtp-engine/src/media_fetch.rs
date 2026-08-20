//! Bounded HTTP(S) fetch for `play_media` from a URL.
//!
//! A controller can point `play_media` at an `http://` or `https://` WAV instead of shipping the
//! bytes inline or provisioning a file on the engine host. The whole design here is about the
//! **failure mode**, because a media fetch sits between a control request and a live call:
//!
//! - a **connect timeout** bounds DNS + TCP + TLS,
//! - a **first-byte timeout** bounds the wait for response headers,
//! - an **overall deadline** bounds everything including the body read, so a server that dribbles
//!   one byte per second cannot hold the fetch open,
//! - a **body-size cap** is checked against `Content-Length` up front *and* enforced while reading,
//!   so a `Content-Length`-less chunked response cannot exhaust memory,
//! - a **redirect cap** bounds the chain, and every hop is re-validated against the scheme and
//!   allow-list rules.
//!
//! None of this runs on the media path. The engine accepts the `play_media` immediately with a
//! `play_id`, fetches on its own task, and only then hands the decoded PCM to the media actor; a
//! fetch that fails resolves the playback with `Event::PlayFinished { reason: error }`. The media
//! tick never waits on a socket.
//!
//! # Security posture
//!
//! The URL is **controller-supplied and fetched by the engine from the engine's own network
//! position** — an SSRF surface by construction, exactly like rtpengine's `file` source is a local
//! filesystem surface. Three things bound it:
//!
//! 1. only `http` and `https` are accepted (no `file:`, `gopher:`, `ftp:`, …),
//! 2. redirects are capped and each hop is re-checked against the same scheme rule, so an
//!    open-redirect cannot walk the fetch onto another protocol,
//! 3. an optional **host allow-list** ([`MediaFetchLimits::allow_hosts`]) restricts which hosts the
//!    engine will dial at all.
//!
//! With an empty allow-list the engine will fetch any host it can route to, which is the right
//! default only when the control plane is trusted (it is: the control connection is authenticated
//! and owns the call). Operators who do not want that must set the allow-list, put the engine
//! behind an egress policy, or leave the URL source unused.
//!
//! Pure Rust throughout: `hyper` for HTTP/1.1 and `tokio-rustls` on the **ring** backend for TLS —
//! the same stack the `wss://` bridge already dials with, so no new TLS surface is introduced.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::header::{CONTENT_LENGTH, HOST, LOCATION, USER_AGENT};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Default bound on DNS + TCP connect + TLS handshake for one hop.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 2_000;

/// Default bound on the wait for response headers after the request is sent.
pub const DEFAULT_FIRST_BYTE_TIMEOUT_MS: u64 = 5_000;

/// Default bound on the whole fetch, redirects and body read included.
pub const DEFAULT_TOTAL_TIMEOUT_MS: u64 = 15_000;

/// Default cap on the response body. 8 MiB is about 8 minutes of 8 kHz 16-bit mono WAV — far more
/// than any prompt, and small enough that a hostile server cannot make the engine swallow a disk.
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Default cap on the redirect chain.
pub const DEFAULT_MAX_REDIRECTS: u8 = 3;

/// What the engine sends as `User-Agent`, so an operator can see which component fetched.
const FETCH_USER_AGENT: &str = "siphon-rtp";

/// The bounds a media fetch runs under. Every one of them is a hard stop, not a hint.
#[derive(Debug, Clone)]
pub struct MediaFetchLimits {
    /// DNS + TCP connect + TLS handshake, per hop.
    pub connect_timeout: Duration,
    /// Wait for response headers after the request is written.
    pub first_byte_timeout: Duration,
    /// The whole fetch: every redirect hop and the body read together.
    pub total_timeout: Duration,
    /// Largest response body accepted, in bytes.
    pub max_body_bytes: usize,
    /// Redirect hops followed before giving up.
    pub max_redirects: u8,
    /// Hosts the engine may dial. **Empty means unrestricted** — see the module's security note.
    /// Matched case-insensitively against the URL's host, exactly (no wildcards, no suffix match:
    /// an operator naming `prompts.example` must not accidentally allow `prompts.example.evil`).
    pub allow_hosts: Arc<Vec<String>>,
}

impl Default for MediaFetchLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            first_byte_timeout: Duration::from_millis(DEFAULT_FIRST_BYTE_TIMEOUT_MS),
            total_timeout: Duration::from_millis(DEFAULT_TOTAL_TIMEOUT_MS),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            allow_hosts: Arc::new(Vec::new()),
        }
    }
}

impl MediaFetchLimits {
    /// Whether `host` may be dialled. An empty allow-list permits everything.
    #[must_use]
    pub fn permits_host(&self, host: &str) -> bool {
        self.allow_hosts.is_empty()
            || self
                .allow_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
    }
}

/// Everything that can go wrong fetching playback media, as a typed error the control plane turns
/// into a `PlayFinished{Error}` (and, for the checks that run before the accept, a `CmdResult`).
#[derive(Debug, thiserror::Error)]
pub enum MediaFetchError {
    /// The URL did not parse, or carried no host.
    #[error("media URL is not usable: {reason}")]
    InvalidUrl {
        /// What was wrong with it.
        reason: String,
    },
    /// A scheme other than `http` / `https`.
    #[error("unsupported media URL scheme '{scheme}' (only http and https)")]
    UnsupportedScheme {
        /// The rejected scheme.
        scheme: String,
    },
    /// The host is not on the configured allow-list.
    #[error("host '{host}' is not on the media-fetch allow-list")]
    HostNotAllowed {
        /// The rejected host.
        host: String,
    },
    /// DNS returned nothing usable for the host.
    #[error("no address for host '{host}'")]
    NoAddress {
        /// The host that did not resolve.
        host: String,
    },
    /// DNS + TCP connect + TLS did not complete inside the connect timeout.
    #[error("connect to '{host}' timed out after {timeout_ms} ms")]
    ConnectTimeout {
        /// The host being dialled.
        host: String,
        /// The bound that expired.
        timeout_ms: u64,
    },
    /// The transport failed (DNS error, refused connection, reset).
    #[error("connect to '{host}' failed: {reason}")]
    Connect {
        /// The host being dialled.
        host: String,
        /// The underlying failure.
        reason: String,
    },
    /// The TLS handshake failed (bad certificate, protocol mismatch).
    #[error("TLS handshake with '{host}' failed: {reason}")]
    Tls {
        /// The host being dialled.
        host: String,
        /// The underlying failure.
        reason: String,
    },
    /// No response headers arrived inside the first-byte timeout.
    #[error("no response headers from '{host}' within {timeout_ms} ms")]
    FirstByteTimeout {
        /// The host being dialled.
        host: String,
        /// The bound that expired.
        timeout_ms: u64,
    },
    /// The whole fetch outlived its deadline.
    #[error("media fetch exceeded its {timeout_ms} ms deadline")]
    DeadlineExceeded {
        /// The bound that expired.
        timeout_ms: u64,
    },
    /// HTTP itself failed (malformed response, connection dropped mid-body).
    #[error("HTTP request failed: {reason}")]
    Http {
        /// The underlying failure.
        reason: String,
    },
    /// The server answered with a non-success, non-redirect status.
    #[error("server answered HTTP {status}")]
    Status {
        /// The status code.
        status: u16,
    },
    /// The body was larger than the cap — detected from `Content-Length` or while reading.
    #[error("response body exceeds the {limit}-byte cap")]
    BodyTooLarge {
        /// The cap.
        limit: usize,
    },
    /// The redirect chain never reached a body.
    #[error("followed {limit} redirects without reaching a body")]
    TooManyRedirects {
        /// The cap.
        limit: u8,
    },
    /// A redirect carried no usable `Location`.
    #[error("redirect from '{from}' carried no usable Location header")]
    BadRedirect {
        /// The URL that redirected.
        from: String,
    },
}

/// A connected transport, plaintext or TLS. Boxed behind one trait so the HTTP/1.1 handshake below
/// is written once rather than twice.
trait FetchStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> FetchStream for T {}

/// One hop's outcome: either the body, or the URL to try next.
enum HopOutcome {
    Body(Vec<u8>),
    Redirect(String),
}

/// Validate a media URL without dialling anything: scheme, host, and the allow-list.
///
/// Run before the `play_media` accept so an obviously-unusable URL is a synchronous control error
/// rather than an accepted playback that fails a second later — and re-run on every redirect hop.
pub fn validate_media_url(url: &str, limits: &MediaFetchLimits) -> Result<Uri, MediaFetchError> {
    // Check the scheme against the raw string *before* parsing. `file:///etc/passwd` is a perfectly
    // legal URI but not a legal `http::Uri` (it carries no authority), so leaning on the parse alone
    // would report the most security-relevant rejection we make as a vague "malformed URL".
    let scheme = url
        .trim()
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| MediaFetchError::InvalidUrl {
            reason: "no scheme".to_string(),
        })?;
    if scheme != "http" && scheme != "https" {
        return Err(MediaFetchError::UnsupportedScheme { scheme });
    }
    let uri: Uri = url
        .trim()
        .parse()
        .map_err(|error| MediaFetchError::InvalidUrl {
            reason: format!("{error}"),
        })?;
    let host = uri.host().ok_or_else(|| MediaFetchError::InvalidUrl {
        reason: "no host".to_string(),
    })?;
    if !limits.permits_host(host) {
        return Err(MediaFetchError::HostNotAllowed {
            host: host.to_string(),
        });
    }
    Ok(uri)
}

/// Fetch `url` under `limits`, returning the response body.
///
/// The whole call — redirects, connects, headers and body — runs inside `limits.total_timeout`, so
/// this future always resolves. `tls` is the engine's shared ring-backed rustls client config.
pub async fn fetch_media(
    url: &str,
    limits: &MediaFetchLimits,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Vec<u8>, MediaFetchError> {
    let total_timeout_ms = limits.total_timeout.as_millis() as u64;
    tokio::time::timeout(limits.total_timeout, fetch_chain(url, limits, tls))
        .await
        .unwrap_or(Err(MediaFetchError::DeadlineExceeded {
            timeout_ms: total_timeout_ms,
        }))
}

/// Follow the redirect chain, at most `limits.max_redirects` hops past the first request.
async fn fetch_chain(
    url: &str,
    limits: &MediaFetchLimits,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Vec<u8>, MediaFetchError> {
    let mut current = url.to_string();
    for _ in 0..=limits.max_redirects {
        // Every hop is re-validated: an open redirect must not be able to walk the fetch onto
        // another scheme or off the allow-list.
        let uri = validate_media_url(&current, limits)?;
        match fetch_once(&uri, limits, tls.clone()).await? {
            HopOutcome::Body(body) => return Ok(body),
            HopOutcome::Redirect(location) => {
                current = resolve_location(&uri, &location)?;
            }
        }
    }
    Err(MediaFetchError::TooManyRedirects {
        limit: limits.max_redirects,
    })
}

/// Resolve a `Location` header against the URL it came from, supporting the absolute form and the
/// origin-relative form (`/other.wav`). A relative form without a leading `/` is rejected rather
/// than guessed at — a prompt URL is operator-controlled, so an ambiguous redirect is a bug.
fn resolve_location(from: &Uri, location: &str) -> Result<String, MediaFetchError> {
    let location = location.trim();
    if location.is_empty() {
        return Err(MediaFetchError::BadRedirect {
            from: from.to_string(),
        });
    }
    if location.contains("://") {
        return Ok(location.to_string());
    }
    if let Some(path) = location.strip_prefix('/') {
        let scheme = from.scheme_str().unwrap_or("http");
        let authority = from
            .authority()
            .ok_or_else(|| MediaFetchError::BadRedirect {
                from: from.to_string(),
            })?;
        return Ok(format!("{scheme}://{authority}/{path}"));
    }
    Err(MediaFetchError::BadRedirect {
        from: from.to_string(),
    })
}

/// One request/response round trip.
async fn fetch_once(
    uri: &Uri,
    limits: &MediaFetchLimits,
    tls: Arc<rustls::ClientConfig>,
) -> Result<HopOutcome, MediaFetchError> {
    let host = uri
        .host()
        .ok_or_else(|| MediaFetchError::InvalidUrl {
            reason: "no host".to_string(),
        })?
        .to_string();
    let secure = uri.scheme_str().is_some_and(|scheme| scheme == "https");
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });

    let stream = tokio::time::timeout(
        limits.connect_timeout,
        connect(&host, port, secure, tls.clone()),
    )
    .await
    .map_err(|_| MediaFetchError::ConnectTimeout {
        host: host.clone(),
        timeout_ms: limits.connect_timeout.as_millis() as u64,
    })??;

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| MediaFetchError::Http {
            reason: error.to_string(),
        })?;
    // The connection future drives the socket; it ends when the response is complete or the
    // request sender is dropped, so it cannot outlive the fetch. Errors surface on `send_request`.
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let authority = match uri.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    let target = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let request = Request::builder()
        .uri(target)
        .header(HOST, authority)
        .header(USER_AGENT, FETCH_USER_AGENT)
        .body(Empty::<bytes::Bytes>::new())
        .map_err(|error| MediaFetchError::Http {
            reason: error.to_string(),
        })?;

    let response = tokio::time::timeout(limits.first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| MediaFetchError::FirstByteTimeout {
            host: host.clone(),
            timeout_ms: limits.first_byte_timeout.as_millis() as u64,
        })?
        .map_err(|error| MediaFetchError::Http {
            reason: error.to_string(),
        })?;

    let status = response.status();
    if status.is_redirection() {
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        connection_task.abort();
        return match location {
            Some(location) => Ok(HopOutcome::Redirect(location)),
            None => Err(MediaFetchError::BadRedirect {
                from: uri.to_string(),
            }),
        };
    }
    if status != StatusCode::OK && !status.is_success() {
        connection_task.abort();
        return Err(MediaFetchError::Status {
            status: status.as_u16(),
        });
    }

    // Reject an oversized body from the declared length before a byte of it is buffered; a response
    // that declares nothing (or lies) is still cut off by the running check below.
    if let Some(declared) = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
    {
        if declared > limits.max_body_bytes {
            connection_task.abort();
            return Err(MediaFetchError::BodyTooLarge {
                limit: limits.max_body_bytes,
            });
        }
    }

    let mut body = response.into_body();
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| MediaFetchError::Http {
            reason: error.to_string(),
        })?;
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        if bytes.len() + chunk.len() > limits.max_body_bytes {
            connection_task.abort();
            return Err(MediaFetchError::BodyTooLarge {
                limit: limits.max_body_bytes,
            });
        }
        bytes.extend_from_slice(chunk);
    }
    connection_task.abort();
    Ok(HopOutcome::Body(bytes))
}

/// Resolve, connect and (for `https`) complete the TLS handshake.
async fn connect(
    host: &str,
    port: u16,
    secure: bool,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Box<dyn FetchStream>, MediaFetchError> {
    let mut addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| MediaFetchError::Connect {
            host: host.to_string(),
            reason: error.to_string(),
        })?;
    let address = addresses.next().ok_or_else(|| MediaFetchError::NoAddress {
        host: host.to_string(),
    })?;
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| MediaFetchError::Connect {
            host: host.to_string(),
            reason: error.to_string(),
        })?;
    if !secure {
        return Ok(Box::new(stream));
    }
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| {
        MediaFetchError::InvalidUrl {
            reason: format!("'{host}' is not a valid TLS server name"),
        }
    })?;
    let connector = tokio_rustls::TlsConnector::from(tls);
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| MediaFetchError::Tls {
            host: host.to_string(),
            reason: error.to_string(),
        })?;
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> MediaFetchLimits {
        MediaFetchLimits {
            connect_timeout: Duration::from_millis(300),
            first_byte_timeout: Duration::from_millis(300),
            total_timeout: Duration::from_millis(1_500),
            max_body_bytes: 4_096,
            max_redirects: 2,
            allow_hosts: Arc::new(Vec::new()),
        }
    }

    #[test]
    fn only_http_and_https_are_accepted() {
        for url in [
            "file:///etc/passwd",
            "ftp://example.invalid/p.wav",
            "gopher://example.invalid/p.wav",
            "ws://example.invalid/p.wav",
        ] {
            match validate_media_url(url, &limits()) {
                Err(MediaFetchError::UnsupportedScheme { .. }) => {}
                other => panic!("{url} must be rejected as an unsupported scheme, got {other:?}"),
            }
        }
        assert!(validate_media_url("http://example.invalid/p.wav", &limits()).is_ok());
        assert!(validate_media_url("https://example.invalid/p.wav", &limits()).is_ok());
        // Scheme comparison is case-insensitive, as RFC 3986 §3.1 requires.
        assert!(validate_media_url("HTTPS://example.invalid/p.wav", &limits()).is_ok());
    }

    #[test]
    fn a_url_without_a_host_or_scheme_is_rejected() {
        for url in ["/just/a/path.wav", "not a url at all", "http://"] {
            assert!(
                validate_media_url(url, &limits()).is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn the_allow_list_is_an_exact_case_insensitive_host_match() {
        let mut restricted = limits();
        restricted.allow_hosts = Arc::new(vec!["prompts.example".to_string()]);
        assert!(validate_media_url("http://prompts.example/p.wav", &restricted).is_ok());
        assert!(validate_media_url("http://PROMPTS.EXAMPLE/p.wav", &restricted).is_ok());
        // A suffix match would let an attacker register `prompts.example.invalid`; it must not.
        for url in [
            "http://prompts.example.invalid/p.wav",
            "http://evil.invalid/p.wav",
            "http://notprompts.example/p.wav",
        ] {
            match validate_media_url(url, &restricted) {
                Err(MediaFetchError::HostNotAllowed { .. }) => {}
                other => panic!("{url} must be refused by the allow-list, got {other:?}"),
            }
        }
        // An empty allow-list permits everything (the documented default).
        assert!(limits().permits_host("anything.invalid"));
    }

    #[test]
    fn a_location_header_resolves_absolute_and_origin_relative_forms() {
        let from: Uri = "http://host.invalid:8080/a/b.wav".parse().expect("uri");
        assert_eq!(
            resolve_location(&from, "https://other.invalid/c.wav").expect("absolute"),
            "https://other.invalid/c.wav"
        );
        assert_eq!(
            resolve_location(&from, "/c.wav").expect("origin-relative"),
            "http://host.invalid:8080/c.wav"
        );
        // An empty or path-relative Location is a bug, not something to guess at.
        assert!(resolve_location(&from, "").is_err());
        assert!(resolve_location(&from, "   ").is_err());
        assert!(resolve_location(&from, "c.wav").is_err());
    }

    #[test]
    fn the_defaults_are_the_documented_bounds() {
        let defaults = MediaFetchLimits::default();
        assert_eq!(
            defaults.connect_timeout,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(
            defaults.first_byte_timeout,
            Duration::from_millis(DEFAULT_FIRST_BYTE_TIMEOUT_MS)
        );
        assert_eq!(
            defaults.total_timeout,
            Duration::from_millis(DEFAULT_TOTAL_TIMEOUT_MS)
        );
        assert_eq!(defaults.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(defaults.max_redirects, DEFAULT_MAX_REDIRECTS);
        assert!(defaults.allow_hosts.is_empty());
        // The first-byte and connect bounds must both fit inside the overall deadline, or the
        // narrower bound could never fire.
        assert!(defaults.connect_timeout < defaults.total_timeout);
        assert!(defaults.first_byte_timeout < defaults.total_timeout);
    }

    #[test]
    fn every_error_variant_renders_a_message() {
        for error in [
            MediaFetchError::InvalidUrl {
                reason: "no scheme".into(),
            },
            MediaFetchError::UnsupportedScheme {
                scheme: "file".into(),
            },
            MediaFetchError::HostNotAllowed {
                host: "evil.invalid".into(),
            },
            MediaFetchError::NoAddress {
                host: "nowhere.invalid".into(),
            },
            MediaFetchError::ConnectTimeout {
                host: "slow.invalid".into(),
                timeout_ms: 2_000,
            },
            MediaFetchError::Connect {
                host: "gone.invalid".into(),
                reason: "refused".into(),
            },
            MediaFetchError::Tls {
                host: "bad.invalid".into(),
                reason: "bad certificate".into(),
            },
            MediaFetchError::FirstByteTimeout {
                host: "quiet.invalid".into(),
                timeout_ms: 5_000,
            },
            MediaFetchError::DeadlineExceeded { timeout_ms: 15_000 },
            MediaFetchError::Http {
                reason: "connection reset".into(),
            },
            MediaFetchError::Status { status: 404 },
            MediaFetchError::BodyTooLarge { limit: 8_388_608 },
            MediaFetchError::TooManyRedirects { limit: 3 },
            MediaFetchError::BadRedirect {
                from: "http://host.invalid/".into(),
            },
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
