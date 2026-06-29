//! Integration test for the metrics + health HTTP endpoint over a real `TcpStream`.
//!
//! Stands the hand-rolled HTTP/1.1 server up on an ephemeral loopback port, drives a few control
//! commands through an [`Engine`] so the counters move, then scrapes `/metrics`, `/healthz`,
//! `/readyz`, and an unknown path — asserting the exposition body and the health/404 status lines.
//! NIC-free (UDP-loopback datapath + loopback HTTP socket).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{metrics, ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const CLIENT: ClientId = ClientId(7);

/// A two-port SDP (RTP + default RTCP at port+1). Documentation-range address (RFC 5737).
fn sdp_for(host: &str, port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {host}\r\ns=-\r\nc=IN IP4 {host}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    )
}

/// Send one HTTP/1.1 GET over a fresh connection and return the full response text.
async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect metrics");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write http request");
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("response not timed out")
        .expect("read http response");
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn metrics_and_health_endpoint_over_tcp() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));

    // Drive control commands so the counters move: one accepted offer, one error (delete of an
    // unknown call → CmdResult::Error → control_errors_total).
    let host = "198.51.100.10"; // RFC 5737 documentation range
    let offer = engine
        .handle(CLIENT, Command::Offer {
            call_id: "call-metrics".to_string(),
            from_tag: "a-tag".to_string(),
            sdp: sdp_for(host, 4000),
            profile: Default::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "offer accepted");

    let bad_delete = engine
        .handle(CLIENT, Command::Delete {
            call_id: "does-not-exist".to_string(),
            from_tag: "a-tag".to_string(),
            to_tag: None,
        })
        .await;
    assert!(matches!(bad_delete, CmdResult::Error { .. }), "delete of unknown call errors");

    // Stand the metrics HTTP server up on an ephemeral port.
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind metrics listener");
    let addr = listener.local_addr().expect("metrics local addr");
    let session_engine = engine.clone();
    let sessions = move || session_engine.session_count() as u64;
    tokio::spawn(metrics::serve_metrics(listener, engine.metrics(), sessions));

    // GET /metrics — OpenMetrics body with the moved counters and the live sessions gauge (== 1).
    let metrics_response = http_get(addr, "/metrics").await;
    assert!(metrics_response.starts_with("HTTP/1.1 200 OK\r\n"), "metrics 200");
    assert!(
        metrics_response.contains("Content-Type: text/plain; version=0.0.4\r\n"),
        "metrics content type"
    );
    assert!(metrics_response.contains("siphon_rtp_sessions 1\n"), "one live session");
    assert!(metrics_response.contains("siphon_rtp_offers_total 1\n"), "one offer counted");
    assert!(
        metrics_response.contains("siphon_rtp_control_errors_total 1\n"),
        "one control error counted"
    );
    assert!(
        metrics_response.contains("siphon_rtp_jemalloc_allocated_bytes "),
        "jemalloc gauge present"
    );

    // GET /healthz and /readyz — 200 OK liveness/readiness.
    let healthz = http_get(addr, "/healthz").await;
    assert!(healthz.starts_with("HTTP/1.1 200 OK\r\n"), "healthz 200");
    let readyz = http_get(addr, "/readyz").await;
    assert!(readyz.starts_with("HTTP/1.1 200 OK\r\n"), "readyz 200");

    // An unknown path is a 404 (and the server does not panic / hang).
    let not_found = http_get(addr, "/nope").await;
    assert!(not_found.starts_with("HTTP/1.1 404 Not Found\r\n"), "unknown path 404");
}
