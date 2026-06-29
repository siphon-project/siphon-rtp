//! Operational metrics, the `/metrics` + health HTTP endpoint, and the control-plane rate limiter.
//!
//! Production hardening for the engine daemon:
//! - [`Metrics`] — a set of process-wide [`AtomicU64`](std::sync::atomic::AtomicU64) counters,
//!   shared via `Arc`, rendered to the Prometheus/OpenMetrics text exposition format.
//! - [`serve_metrics`] — a deliberately minimal, hand-rolled HTTP/1.1 server (no hyper/axum/warp,
//!   keeping deps lean and the pure-Rust posture intact) exposing `/metrics`, `/healthz`, `/readyz`.
//! - [`RateLimiter`] — a deterministic token bucket gating per-connection control request rate.
//!
//! Everything here is pure Rust over `std` atomics + Tokio sockets; the only metric that reaches
//! outside is `siphon_rtp_jemalloc_allocated_bytes`, read via `tikv_jemalloc_ctl` (already a leak-gate
//! dependency).

use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Process-wide operational counters and gauges, shared via `Arc`.
///
/// Counters are monotonic `AtomicU64`s incremented on the control path; gauges that track live
/// state (session count, jemalloc live bytes) are read on demand at render time from the engine and
/// the allocator, so they are passed into [`Metrics::render`] rather than stored here.
#[derive(Debug, Default)]
pub struct Metrics {
    offers_total: AtomicU64,
    answers_total: AtomicU64,
    deletes_total: AtomicU64,
    control_errors_total: AtomicU64,
    control_rate_limited_total: AtomicU64,
}

impl Metrics {
    /// A fresh metrics surface with every counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count an accepted `offer` command.
    pub fn record_offer(&self) {
        self.offers_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count an accepted `answer` command.
    pub fn record_answer(&self) {
        self.answers_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count an accepted `delete` command.
    pub fn record_delete(&self) {
        self.deletes_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a control command that produced a [`CmdResult::Error`](siphon_rtp_proto::CmdResult).
    pub fn record_control_error(&self) {
        self.control_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a control command rejected by the per-connection rate limiter.
    pub fn record_rate_limited(&self) {
        self.control_rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the Prometheus/OpenMetrics text exposition for the current counters plus the two
    /// on-demand gauges: `sessions` (live call count) and `jemalloc_allocated_bytes` (live heap).
    ///
    /// The body is valid `text/plain; version=0.0.4`: each series carries a `# HELP` and `# TYPE`
    /// line, then the sample. Numbers only (no labels) keeps the surface trivially scrapeable.
    #[must_use]
    pub fn render(&self, sessions: u64, jemalloc_allocated_bytes: u64) -> String {
        let offers = self.offers_total.load(Ordering::Relaxed);
        let answers = self.answers_total.load(Ordering::Relaxed);
        let deletes = self.deletes_total.load(Ordering::Relaxed);
        let errors = self.control_errors_total.load(Ordering::Relaxed);
        let rate_limited = self.control_rate_limited_total.load(Ordering::Relaxed);

        let mut output = String::with_capacity(1024);
        metric(
            &mut output,
            "siphon_rtp_sessions",
            "Live calls in the session registry.",
            "gauge",
            sessions,
        );
        metric(
            &mut output,
            "siphon_rtp_offers_total",
            "Control offer commands accepted.",
            "counter",
            offers,
        );
        metric(
            &mut output,
            "siphon_rtp_answers_total",
            "Control answer commands accepted.",
            "counter",
            answers,
        );
        metric(
            &mut output,
            "siphon_rtp_deletes_total",
            "Control delete commands accepted.",
            "counter",
            deletes,
        );
        metric(
            &mut output,
            "siphon_rtp_control_errors_total",
            "Control commands that returned an error result.",
            "counter",
            errors,
        );
        metric(
            &mut output,
            "siphon_rtp_control_rate_limited_total",
            "Control commands rejected by the per-connection rate limiter.",
            "counter",
            rate_limited,
        );
        metric(
            &mut output,
            "siphon_rtp_jemalloc_allocated_bytes",
            "Live bytes allocated, per jemalloc stats.allocated.",
            "gauge",
            jemalloc_allocated_bytes,
        );
        output
    }
}

/// Append one fully-formed metric series (`# HELP`, `# TYPE`, sample) to `output`.
fn metric(output: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    output.push_str("# HELP ");
    output.push_str(name);
    output.push(' ');
    output.push_str(help);
    output.push('\n');
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push(' ');
    output.push_str(kind);
    output.push('\n');
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

/// The Prometheus text exposition content type (`text/plain; version=0.0.4`).
pub const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// The route an HTTP request targets, parsed from its request line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `GET /metrics` — the Prometheus exposition.
    Metrics,
    /// `GET /healthz` — liveness.
    Healthz,
    /// `GET /readyz` — readiness.
    Readyz,
    /// Anything else (unknown path, non-GET method, or a malformed request line).
    NotFound,
}

/// Classify an HTTP request from its first (request) line, e.g. `GET /metrics HTTP/1.1`.
///
/// Only `GET` is routed; any other method, an unknown path, or a malformed line maps to
/// [`Route::NotFound`] — the parser never panics on hostile input (it only ever splits and matches).
#[must_use]
pub fn route_request_line(request_line: &str) -> Route {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "GET" {
        return Route::NotFound;
    }
    // Ignore any query string on the path (`/metrics?foo=bar`).
    let path = target.split('?').next().unwrap_or_default();
    match path {
        "/metrics" => Route::Metrics,
        "/healthz" => Route::Healthz,
        "/readyz" => Route::Readyz,
        _ => Route::NotFound,
    }
}

/// Build a complete HTTP/1.1 response (status line, headers, body) for `status`/`body`.
///
/// `Connection: close` is always sent — this server serves one request per connection (no
/// keep-alive), which keeps the hand-rolled reader correct and trivially bounded.
fn http_response(status_line: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Live bytes allocated, per jemalloc (`stats.allocated`), refreshing the cached epoch first.
///
/// Returns 0 if the allocator stats are unavailable (a non-jemalloc target / read failure) so the
/// metrics endpoint never fails on a best-effort gauge.
#[cfg(not(target_env = "msvc"))]
fn jemalloc_allocated_bytes() -> u64 {
    if tikv_jemalloc_ctl::epoch::advance().is_err() {
        return 0;
    }
    tikv_jemalloc_ctl::stats::allocated::read()
        .map(|bytes| bytes as u64)
        .unwrap_or(0)
}

#[cfg(target_env = "msvc")]
fn jemalloc_allocated_bytes() -> u64 {
    0
}

/// Serve the metrics + health HTTP endpoint on `listener` until it errors.
///
/// `sessions` is a closure read on each `/metrics` scrape so the gauge reflects the live call count
/// without the metrics module borrowing the engine's type. Each accepted connection is handled in
/// its own task; a slow or malformed client never blocks the accept loop.
pub async fn serve_metrics<F>(listener: TcpListener, metrics: std::sync::Arc<Metrics>, sessions: F)
where
    F: Fn() -> u64 + Clone + Send + Sync + 'static,
{
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "metrics listener accept failed");
                return;
            }
        };
        let metrics = metrics.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_metrics_connection(stream, &metrics, &sessions).await {
                tracing::debug!(%peer, %error, "metrics connection closed with error");
            }
        });
    }
}

/// Read one request off `stream`, route it, and write the response. One request per connection.
async fn handle_metrics_connection<F>(
    mut stream: TcpStream,
    metrics: &Metrics,
    sessions: &F,
) -> std::io::Result<()>
where
    F: Fn() -> u64,
{
    // Read until we have the request line (the first CRLF). Bounded so a client cannot stream
    // unbounded bytes into our buffer before sending a newline (control-plane DoS hygiene).
    const MAX_REQUEST_BYTES: usize = 8192;
    let mut buffer = Vec::with_capacity(256);
    let mut chunk = [0u8; 1024];
    let request_line = loop {
        if let Some(position) = buffer.windows(2).position(|window| window == b"\r\n") {
            break String::from_utf8_lossy(&buffer[..position]).into_owned();
        }
        if buffer.len() >= MAX_REQUEST_BYTES {
            // No request line within the bound — treat as malformed, answer 404, do not panic.
            break String::new();
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break String::from_utf8_lossy(&buffer).into_owned();
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let response = match route_request_line(&request_line) {
        Route::Metrics => {
            let body = metrics.render(sessions(), jemalloc_allocated_bytes());
            http_response("200 OK", METRICS_CONTENT_TYPE, &body)
        }
        Route::Healthz => http_response("200 OK", "text/plain", "ok\n"),
        Route::Readyz => http_response("200 OK", "text/plain", "ok\n"),
        Route::NotFound => http_response("404 Not Found", "text/plain", "not found\n"),
    };
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// A deterministic token-bucket rate limiter for one control connection.
///
/// The bucket holds up to `capacity` tokens and refills at `capacity` tokens per second. The core
/// is countable and unit-testable: refill is driven by an explicit elapsed-seconds value
/// ([`RateLimiter::refill`]), never `Instant::now()`, so tests advance a logical clock. The server
/// wires a `tokio::time` interval to call `refill` each second; `try_acquire` spends one token.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: u64,
    tokens: u64,
}

impl RateLimiter {
    /// A bucket of `capacity` tokens (the per-second request cap), starting full.
    ///
    /// A `capacity` of 0 is treated as "unlimited": [`try_acquire`](Self::try_acquire) always
    /// admits. Otherwise the bucket starts full so a fresh connection may burst up to `capacity`.
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
        }
    }

    /// Whether this limiter enforces any cap (a 0 capacity disables limiting).
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.capacity == 0
    }

    /// Try to spend one token for an incoming request. Returns `true` if admitted (a token was
    /// available, or the limiter is unlimited), `false` if the bucket is empty (rate exceeded).
    pub fn try_acquire(&mut self) -> bool {
        if self.is_unlimited() {
            return true;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// Refill the bucket for `elapsed_seconds` of wall time, capped at `capacity`. Deterministic:
    /// the caller supplies the elapsed seconds (logical or real), so the limiter holds no clock.
    pub fn refill(&mut self, elapsed_seconds: u64) {
        if self.is_unlimited() {
            return;
        }
        let added = self.capacity.saturating_mul(elapsed_seconds);
        self.tokens = self.tokens.saturating_add(added).min(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_all_series_with_help_and_type() {
        let metrics = Metrics::new();
        metrics.record_offer();
        metrics.record_offer();
        metrics.record_answer();
        metrics.record_delete();
        metrics.record_control_error();
        metrics.record_rate_limited();

        let body = metrics.render(3, 4096);

        // Gauges reflect the arguments; counters reflect the increments.
        assert!(body.contains("# TYPE siphon_rtp_sessions gauge\nsiphon_rtp_sessions 3\n"));
        assert!(body.contains("# TYPE siphon_rtp_offers_total counter\nsiphon_rtp_offers_total 2\n"));
        assert!(body.contains("siphon_rtp_answers_total 1\n"));
        assert!(body.contains("siphon_rtp_deletes_total 1\n"));
        assert!(body.contains("siphon_rtp_control_errors_total 1\n"));
        assert!(body.contains("siphon_rtp_control_rate_limited_total 1\n"));
        assert!(body.contains(
            "# TYPE siphon_rtp_jemalloc_allocated_bytes gauge\nsiphon_rtp_jemalloc_allocated_bytes 4096\n"
        ));
        // Every series carries a HELP line.
        assert_eq!(body.matches("# HELP ").count(), 7);
        assert_eq!(body.matches("# TYPE ").count(), 7);
    }

    #[test]
    fn fresh_metrics_render_zeroes() {
        let body = Metrics::new().render(0, 0);
        assert!(body.contains("siphon_rtp_offers_total 0\n"));
        assert!(body.contains("siphon_rtp_sessions 0\n"));
    }

    #[test]
    fn routes_known_paths() {
        assert_eq!(route_request_line("GET /metrics HTTP/1.1"), Route::Metrics);
        assert_eq!(route_request_line("GET /healthz HTTP/1.1"), Route::Healthz);
        assert_eq!(route_request_line("GET /readyz HTTP/1.1"), Route::Readyz);
    }

    #[test]
    fn routes_path_with_query_string() {
        assert_eq!(route_request_line("GET /metrics?foo=bar HTTP/1.0"), Route::Metrics);
    }

    #[test]
    fn unknown_path_is_not_found() {
        assert_eq!(route_request_line("GET /nope HTTP/1.1"), Route::NotFound);
        assert_eq!(route_request_line("GET / HTTP/1.1"), Route::NotFound);
    }

    #[test]
    fn non_get_method_is_not_found() {
        assert_eq!(route_request_line("POST /metrics HTTP/1.1"), Route::NotFound);
        assert_eq!(route_request_line("DELETE /healthz HTTP/1.1"), Route::NotFound);
    }

    #[test]
    fn malformed_request_line_does_not_panic() {
        // Garbage / empty / partial lines must classify as NotFound, never panic.
        assert_eq!(route_request_line(""), Route::NotFound);
        assert_eq!(route_request_line("GET"), Route::NotFound);
        assert_eq!(route_request_line("\0\0\0 \t  "), Route::NotFound);
        assert_eq!(route_request_line("🤖 not http"), Route::NotFound);
    }

    #[test]
    fn rate_limiter_allows_under_cap() {
        let mut limiter = RateLimiter::new(3);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
    }

    #[test]
    fn rate_limiter_rejects_over_cap() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire(), "third request over a cap of 2 is rejected");
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn rate_limiter_refills() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
        // One second of refill restores the full cap (capacity tokens/second).
        limiter.refill(1);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn rate_limiter_refill_caps_at_capacity() {
        let mut limiter = RateLimiter::new(2);
        // Never spent a token; a long idle does not let the bucket overflow past capacity.
        limiter.refill(100);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn rate_limiter_zero_capacity_is_unlimited() {
        let mut limiter = RateLimiter::new(0);
        assert!(limiter.is_unlimited());
        for _ in 0..1000 {
            assert!(limiter.try_acquire());
        }
    }

    #[test]
    fn http_response_has_content_length() {
        let response = http_response("200 OK", "text/plain", "ok\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 3\r\n"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(response.ends_with("\r\n\r\nok\n"));
    }
}
