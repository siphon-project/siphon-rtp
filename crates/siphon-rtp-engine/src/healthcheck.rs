//! The probe side of the liveness endpoint: `--healthcheck <ADDR>`.
//!
//! The runtime image is distroless — no shell, no `curl`, no `wget` — so a container health
//! check has nothing to ask `GET /healthz` with. The engine binary is the one executable the
//! image is guaranteed to hold, so it carries the probe: started with `--healthcheck`, it asks
//! a running engine's `--metrics-addr` for `/healthz`, exits `0` on a `200` and `1` on anything
//! else, and starts nothing.
//!
//! Liveness, deliberately, and not readiness: `/healthz` stays `200` through a drain, because an
//! orchestrator that restarts an unhealthy container would otherwise kill a node in the middle
//! of draining its calls.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long the whole probe may take. Well inside the shortest sensible container
/// health-check timeout, so a hung engine is reported as unhealthy by the probe itself and not
/// by the runtime killing the probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The most of a response the probe reads: enough for any status line, and a bound on what a
/// misdirected probe will accept from whatever else is listening on the port.
const MAX_STATUS_LINE_BYTES: usize = 256;

/// Ask the engine at `address` whether it is alive: `Ok` when `GET /healthz` answers `200`
/// within `limit`, otherwise the reason it did not.
pub async fn probe(address: SocketAddr, limit: Duration) -> Result<(), String> {
    match tokio::time::timeout(limit, request_healthz(address)).await {
        Ok(outcome) => outcome,
        Err(_) => Err(format!(
            "no answer from {address} within {} ms",
            limit.as_millis()
        )),
    }
}

/// One `GET /healthz` over a fresh connection, judged by its status line alone.
async fn request_healthz(address: SocketAddr) -> Result<(), String> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|error| format!("cannot connect to {address}: {error}"))?;
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("cannot send the request to {address}: {error}"))?;

    let mut received = Vec::with_capacity(MAX_STATUS_LINE_BYTES);
    let mut chunk = [0u8; MAX_STATUS_LINE_BYTES];
    let status_line = loop {
        if let Some(end) = received.iter().position(|byte| *byte == b'\n') {
            break String::from_utf8_lossy(&received[..end]).trim().to_string();
        }
        if received.len() >= MAX_STATUS_LINE_BYTES {
            return Err(format!("{address} did not answer with an HTTP status line"));
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("cannot read the answer from {address}: {error}"))?;
        if read == 0 {
            return Err(format!("{address} closed the connection without answering"));
        }
        received.extend_from_slice(&chunk[..read]);
    };
    if is_ok_status_line(&status_line) {
        Ok(())
    } else {
        Err(format!("{address} answered {status_line:?}, not 200"))
    }
}

/// Whether an HTTP status line (RFC 9112 §4) reports `200`.
fn is_ok_status_line(status_line: &str) -> bool {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    version.starts_with("HTTP/1.") && status == "200"
}

/// Run the probe and end the process with its verdict: `0` alive, `1` not, the reason on stderr
/// where a container runtime's health log picks it up. `program` prefixes that line.
pub async fn probe_and_exit(program: &str, address: SocketAddr) -> ! {
    match probe(address, PROBE_TIMEOUT).await {
        Ok(()) => std::process::exit(0),
        Err(reason) => {
            eprintln!("{program}: unhealthy: {reason}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{serve_metrics, LiveGauges, Metrics};
    use tokio::net::TcpListener;

    const LIMIT: Duration = Duration::from_secs(2);

    async fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        (listener, address)
    }

    /// A server that reads the request and answers with `response`, once.
    async fn answering(response: &'static [u8]) -> SocketAddr {
        let (listener, address) = listener().await;
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 512];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(response).await;
            }
        });
        address
    }

    #[tokio::test]
    async fn a_running_engines_health_endpoint_is_reported_alive() {
        // Against the engine's real endpoint, not a stand-in: the probe and the server have to
        // agree on the path and the answer.
        let (listener, address) = listener().await;
        tokio::spawn(serve_metrics(
            listener,
            std::sync::Arc::new(Metrics::default()),
            LiveGauges::default,
        ));
        assert_eq!(probe(address, LIMIT).await, Ok(()));
    }

    #[tokio::test]
    async fn a_draining_engine_is_still_alive() {
        // Readiness flips during a drain; liveness must not, or the runtime kills a node that
        // is still finishing its calls.
        let (listener, address) = listener().await;
        tokio::spawn(serve_metrics(
            listener,
            std::sync::Arc::new(Metrics::default()),
            || LiveGauges {
                draining: true,
                ..LiveGauges::default()
            },
        ));
        assert_eq!(probe(address, LIMIT).await, Ok(()));
    }

    #[tokio::test]
    async fn nothing_listening_is_unhealthy() {
        let (listener, address) = listener().await;
        drop(listener);
        let reason = probe(address, LIMIT).await.expect_err("nothing listens");
        assert!(reason.contains("cannot connect"), "{reason}");
    }

    #[tokio::test]
    async fn an_answer_other_than_200_is_unhealthy() {
        let address =
            answering(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
        let reason = probe(address, LIMIT).await.expect_err("503 is not alive");
        assert!(reason.contains("503"), "{reason}");
    }

    #[tokio::test]
    async fn something_that_is_not_http_is_unhealthy() {
        // The probe pointed at the control port, say: an answer, but not this endpoint's.
        let address = answering(b"{\"id\":0,\"result\":\"error\"}\n").await;
        assert!(probe(address, LIMIT).await.is_err());
        let address = answering(&[b'x'; 600]).await;
        let reason = probe(address, LIMIT).await.expect_err("no status line");
        assert!(reason.contains("status line"), "{reason}");
    }

    #[tokio::test]
    async fn a_connection_closed_without_an_answer_is_unhealthy() {
        let address = answering(b"").await;
        let reason = probe(address, LIMIT).await.expect_err("no answer");
        assert!(reason.contains("without answering"), "{reason}");
    }

    #[tokio::test]
    async fn an_engine_that_accepts_and_never_answers_is_unhealthy_within_the_limit() {
        // A hung process: the socket is open and nothing is served. The probe has to give up
        // on its own rather than hang until the runtime kills it.
        let (listener, address) = listener().await;
        let _held = tokio::spawn(async move {
            let accepted = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(accepted);
        });
        let reason = probe(address, Duration::from_millis(100))
            .await
            .expect_err("no answer in time");
        assert!(reason.contains("within 100 ms"), "{reason}");
    }

    #[test]
    fn only_a_200_status_line_counts() {
        assert!(is_ok_status_line("HTTP/1.1 200 OK"));
        assert!(is_ok_status_line("HTTP/1.0 200"));
        for line in [
            "HTTP/1.1 204 No Content",
            "HTTP/1.1 503 Service Unavailable",
            "HTTP/1.1 2000 OK",
            "200 OK",
            "SIP/2.0 200 OK",
            "",
        ] {
            assert!(!is_ok_status_line(line), "{line:?}");
        }
    }
}
