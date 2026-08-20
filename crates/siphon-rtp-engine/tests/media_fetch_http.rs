//! `play_media` from an http(s) URL, against a **loopback** test server.
//!
//! The point of these tests is the failure mode, not the happy path: a media fetch sits between a
//! control request and a live call, so what matters is that a server which never answers, answers
//! with garbage, or answers with too much, all resolve inside their bounds and leave the leg alone.
//!
//! No external network — every server here is a `TcpListener` on 127.0.0.1 speaking just enough
//! HTTP/1.1 to be answered by a real client.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_engine::media_fetch::{fetch_media, MediaFetchError, MediaFetchLimits};
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::player::WavSource;
use siphon_rtp_media::wav::WavRecorder;

/// Bounds tight enough that a hung server fails a test in well under a second.
fn limits() -> MediaFetchLimits {
    MediaFetchLimits {
        connect_timeout: Duration::from_millis(500),
        first_byte_timeout: Duration::from_millis(400),
        total_timeout: Duration::from_millis(1_500),
        max_body_bytes: 64 * 1024,
        max_redirects: 2,
        allow_hosts: Arc::new(Vec::new()),
    }
}

/// The ring-backed rustls client config the engine dials with. Never used by the plaintext servers
/// below, but the fetch signature takes one.
fn tls_config() -> Arc<rustls::ClientConfig> {
    siphon_rtp_turn::tls::install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A small 8 kHz mono WAV, the shape a real prompt has.
fn wav_bytes(samples: usize) -> Vec<u8> {
    let mut recorder = WavRecorder::new(8_000, 1);
    recorder.write_pcm(&vec![1_234i16; samples]);
    recorder.into_wav()
}

/// Read one HTTP/1.1 request off `stream` (headers only — the client sends no body).
fn read_request(stream: &mut TcpStream) -> String {
    use std::io::Read as _;
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while request.len() < 8_192 {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

/// Spawn a loopback server that answers each connection with `responder(request) -> Option<bytes>`;
/// `None` means "accept the connection and never answer". Returns its address and a request counter.
fn serve(
    responder: impl Fn(String) -> Option<Vec<u8>> + Send + Sync + 'static,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let address = listener.local_addr().expect("addr");
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    std::thread::spawn(move || {
        // Blocking accept loop on its own OS thread: the daemon under test is async, but a test
        // server has no reason to be, and a thread keeps it independent of the runtime being probed.
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_request(&mut stream);
            counter.fetch_add(1, Ordering::Relaxed);
            match responder(request) {
                Some(response) => {
                    let _ = stream.write_all(&response);
                    let _ = stream.flush();
                }
                // Hold the connection open and answer nothing — the first-byte timeout's job.
                None => std::thread::sleep(Duration::from_secs(5)),
            }
        }
    });
    (address, requests)
}

/// A complete HTTP/1.1 response with `body`.
fn http_response(status_line: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetches_a_wav_body_and_parses_it() {
    let wav = wav_bytes(320);
    let expected = wav.clone();
    let (address, requests) = serve(move |request| {
        assert!(request.starts_with("GET /prompt.wav "), "{request}");
        assert!(
            request.to_ascii_lowercase().contains("host:"),
            "HTTP/1.1 requires a Host header: {request}"
        );
        Some(http_response("HTTP/1.1 200 OK", "audio/wav", &expected))
    });

    let body = fetch_media(
        &format!("http://{address}/prompt.wav"),
        &limits(),
        tls_config(),
    )
    .await
    .expect("the fetch succeeds");
    assert_eq!(body, wav, "the body arrives byte-for-byte");
    let parsed = WavSource::parse(&body).expect("the fetched body is a valid WAV");
    assert_eq!(parsed.sample_rate_hz(), 8_000);
    assert_eq!(requests.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_never_answers_fails_within_the_first_byte_timeout() {
    // The requirement: an open-ended fetch is not acceptable. The connection is accepted, so this
    // is not a connect failure — the client must give up on its own.
    let (address, _requests) = serve(|_request| None);
    let started = std::time::Instant::now();
    let error = fetch_media(
        &format!("http://{address}/hangs.wav"),
        &limits(),
        tls_config(),
    )
    .await
    .expect_err("a server that never answers must fail");
    let elapsed = started.elapsed();
    assert!(
        matches!(error, MediaFetchError::FirstByteTimeout { .. }),
        "expected a first-byte timeout, got {error:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_200),
        "the fetch must give up on its own bound, took {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_to_a_dead_port_fails_rather_than_hanging() {
    // Bind and immediately drop, so the port is (almost certainly) closed.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let address = listener.local_addr().expect("addr");
    drop(listener);
    let error = fetch_media(&format!("http://{address}/p.wav"), &limits(), tls_config())
        .await
        .expect_err("a closed port must fail");
    assert!(
        matches!(
            error,
            MediaFetchError::Connect { .. } | MediaFetchError::ConnectTimeout { .. }
        ),
        "expected a connect failure, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_wav_bytes_fail_cleanly_at_the_parser() {
    let (address, _requests) = serve(|_request| {
        Some(http_response(
            "HTTP/1.1 200 OK",
            "text/html",
            b"<html>not audio</html>",
        ))
    });
    let body = fetch_media(
        &format!("http://{address}/page.html"),
        &limits(),
        tls_config(),
    )
    .await
    .expect("the transfer itself succeeds");
    // The fetch is content-agnostic; the WAV reader is what rejects it, with a typed error.
    let error = WavSource::parse(&body).expect_err("non-WAV bytes must not parse");
    assert!(!error.to_string().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_oversized_body_is_rejected_before_it_is_buffered() {
    // Content-Length over the cap: refused without reading the body at all.
    let mut bounds = limits();
    bounds.max_body_bytes = 1_024;
    let (address, _requests) = serve(|_request| {
        Some(
            b"HTTP/1.1 200 OK\r\nContent-Type: audio/wav\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
    });
    let error = fetch_media(&format!("http://{address}/big.wav"), &bounds, tls_config())
        .await
        .expect_err("an oversized declared body must be refused");
    assert!(
        matches!(error, MediaFetchError::BodyTooLarge { limit: 1_024 }),
        "expected the size cap, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undeclared_oversized_body_is_cut_off_while_reading() {
    // No Content-Length (chunked): the running check is the only thing standing between the engine
    // and a server that streams forever.
    let mut bounds = limits();
    bounds.max_body_bytes = 2_048;
    let (address, _requests) = serve(|_request| {
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: audio/wav\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        // Ten 1 KiB chunks — five times the cap.
        for _ in 0..10 {
            response.extend_from_slice(b"400\r\n");
            response.extend_from_slice(&[0x41u8; 1_024]);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        Some(response)
    });
    let error = fetch_media(
        &format!("http://{address}/stream.wav"),
        &bounds,
        tls_config(),
    )
    .await
    .expect_err("an undeclared oversized body must be cut off");
    assert!(
        matches!(error, MediaFetchError::BodyTooLarge { limit: 2_048 }),
        "expected the size cap, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_success_status_is_reported_as_such() {
    let (address, _requests) = serve(|_request| {
        Some(http_response(
            "HTTP/1.1 404 Not Found",
            "text/plain",
            b"nope",
        ))
    });
    let error = fetch_media(
        &format!("http://{address}/missing.wav"),
        &limits(),
        tls_config(),
    )
    .await
    .expect_err("404 must fail");
    assert!(
        matches!(error, MediaFetchError::Status { status: 404 }),
        "expected a status error, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirect_is_followed_once_and_capped_when_it_loops() {
    let wav = wav_bytes(160);
    let expected = wav.clone();
    // `/a.wav` redirects to `/b.wav`, which serves the body; `/loop.wav` redirects to itself.
    let (address, requests) = serve(move |request| {
        if request.starts_with("GET /a.wav ") {
            return Some(
                b"HTTP/1.1 302 Found\r\nLocation: /b.wav\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            );
        }
        if request.starts_with("GET /loop.wav ") {
            return Some(
                b"HTTP/1.1 302 Found\r\nLocation: /loop.wav\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            );
        }
        Some(http_response("HTTP/1.1 200 OK", "audio/wav", &expected))
    });

    let body = fetch_media(&format!("http://{address}/a.wav"), &limits(), tls_config())
        .await
        .expect("one redirect is followed");
    assert_eq!(body, wav);
    assert_eq!(
        requests.load(Ordering::Relaxed),
        2,
        "the redirect cost exactly one extra request"
    );

    let error = fetch_media(
        &format!("http://{address}/loop.wav"),
        &limits(),
        tls_config(),
    )
    .await
    .expect_err("a redirect loop must be capped");
    assert!(
        matches!(error, MediaFetchError::TooManyRedirects { limit: 2 }),
        "expected the redirect cap, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirect_onto_another_scheme_is_refused() {
    // An open redirect must not be able to walk the fetch off http(s) — every hop is re-validated.
    let (address, _requests) = serve(|request| {
        let location = if request.starts_with("GET /to-file.wav ") {
            "file:///etc/passwd"
        } else {
            "ftp://elsewhere.invalid/p.wav"
        };
        Some(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
        )
    });
    for path in ["to-file.wav", "to-ftp.wav"] {
        let error = fetch_media(&format!("http://{address}/{path}"), &limits(), tls_config())
            .await
            .expect_err("a scheme-changing redirect must be refused");
        assert!(
            matches!(error, MediaFetchError::UnsupportedScheme { .. }),
            "expected an unsupported-scheme rejection for {path}, got {error:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirect_off_the_allow_list_is_refused() {
    let (address, _requests) = serve(|_request| {
        Some(
            b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere.invalid/p.wav\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
    });
    let mut bounds = limits();
    bounds.allow_hosts = Arc::new(vec!["127.0.0.1".to_string()]);
    let error = fetch_media(
        &format!("http://{address}/offsite.wav"),
        &bounds,
        tls_config(),
    )
    .await
    .expect_err("a redirect off the allow-list must be refused");
    assert!(
        matches!(error, MediaFetchError::HostNotAllowed { .. }),
        "expected an allow-list rejection, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_overall_deadline_bounds_a_slow_dribbling_body() {
    // Headers arrive promptly (so the first-byte bound never fires) and then the body dribbles
    // forever. Only the overall deadline can stop this.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let address = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = read_request(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: audio/wav\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            let _ = stream.flush();
            for _ in 0..200 {
                if stream.write_all(b"1\r\nA\r\n").is_err() || stream.flush().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });

    let mut bounds = limits();
    bounds.total_timeout = Duration::from_millis(600);
    let started = std::time::Instant::now();
    let error = fetch_media(
        &format!("http://{address}/dribble.wav"),
        &bounds,
        tls_config(),
    )
    .await
    .expect_err("a dribbling body must hit the deadline");
    assert!(
        matches!(error, MediaFetchError::DeadlineExceeded { .. }),
        "expected the overall deadline, got {error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1_500),
        "the deadline must actually fire"
    );
}
