//! The JSON-over-TCP control server.
//!
//! Each accepted connection is a persistent stream of length-prefixed JSON frames
//! ([`siphon_rtp_proto::frame`]). Requests are processed in order per connection and answered with
//! a correlated [`Response`]; connections are handled concurrently. This is SIPhon's native
//! front-end — the rtpengine NG/bencode compat listener is a separate front-end added later.

use std::sync::Arc;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{frame, CmdResult, Command, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::{ClientId, Engine};
use crate::metrics::RateLimiter;
use crate::shutdown::Shutdown;

/// Default per-connection control request cap (requests/second) when none is configured. Generous
/// for a legitimate SIPhon controller; a hostile flood that exceeds it is rejected, not processed.
pub const DEFAULT_MAX_CONTROL_RPS: u64 = 200;

/// Accept loop with no control-plane authentication — suitable only for a trusted, private control
/// network. Use [`serve_with_auth`] to require a shared secret.
pub async fn serve<D>(engine: Arc<Engine<D>>, listener: TcpListener) -> std::io::Result<()>
where
    D: Datapath + Clone + Send + 'static,
{
    serve_with_auth(engine, listener, None).await
}

/// Accept loop: serve control connections against `engine` until the listener errors. When `secret`
/// is `Some`, a connection must first send [`Command::Authenticate`] with the matching token before
/// any other command is honoured (docs/security-and-nat.md §5).
pub async fn serve_with_auth<D>(
    engine: Arc<Engine<D>>,
    listener: TcpListener,
    secret: Option<String>,
) -> std::io::Result<()>
where
    D: Datapath + Clone + Send + 'static,
{
    let (_trigger, never) = crate::shutdown::channel();
    serve_with_options(engine, listener, secret, never, DEFAULT_MAX_CONTROL_RPS).await
}

/// Accept loop with the full production posture: optional auth `secret`, a `shutdown` flag that
/// stops the loop accepting new connections (in-flight connections drain), and a per-connection
/// control request cap (`max_control_rps`; 0 disables limiting).
///
/// Returns once `shutdown` is tripped or the listener errors. Already-accepted connections keep
/// running on their own tasks — the daemon waits for the session count to drain separately.
pub async fn serve_with_options<D>(
    engine: Arc<Engine<D>>,
    listener: TcpListener,
    secret: Option<String>,
    shutdown: Shutdown,
    max_control_rps: u64,
) -> std::io::Result<()>
where
    D: Datapath + Clone + Send + 'static,
{
    let secret = secret.map(Arc::new);
    // Each accepted connection gets a distinct identity; a call is private to the connection that
    // created it (docs/security-and-nat.md §5).
    let next_client_id = std::sync::atomic::AtomicU64::new(0);
    loop {
        let (stream, peer) = tokio::select! {
            // Stop accepting the moment shutdown is requested; drop out of the loop cleanly so the
            // daemon can drain in-flight calls and return from main (Drops run).
            _ = shutdown.cancelled() => {
                tracing::info!("control accept loop draining (shutdown requested)");
                return Ok(());
            }
            accepted = listener.accept() => accepted?,
        };
        let client = ClientId(next_client_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        tracing::debug!(%peer, ?client, "control connection accepted");
        let engine = engine.clone();
        let secret = secret.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(engine, client, secret, stream, max_control_rps).await
            {
                tracing::warn!(%peer, %error, "control connection closed with error");
            }
        });
    }
}

/// Deregisters a client's event sink when its connection ends, on every exit path (clean close,
/// error, or task drop).
struct ClientGuard<D: Datapath + Clone + Send + 'static> {
    engine: Arc<Engine<D>>,
    client: ClientId,
}

impl<D: Datapath + Clone + Send + 'static> Drop for ClientGuard<D> {
    fn drop(&mut self) {
        self.engine.deregister_client(self.client);
    }
}

/// Drive one connection: decode request frames and dispatch them, write back responses, and push
/// the engine's asynchronous events (e.g. `MediaTimeout`) out the same socket.
///
/// A per-connection token bucket caps the request rate at `max_control_rps` requests/second (0
/// disables it). A command that breaches the cap is answered `Error { reason: "rate limit
/// exceeded" }` and counted in `siphon_rtp_control_rate_limited_total` instead of being processed —
/// closing the control-plane flood/OOM surface (docs/security-and-nat.md §5). Refill is driven by a
/// `tokio::time` 1-second interval; the bucket logic itself is the deterministic [`RateLimiter`].
async fn handle_connection<D>(
    engine: Arc<Engine<D>>,
    client: ClientId,
    secret: Option<Arc<String>>,
    stream: TcpStream,
    max_control_rps: u64,
) -> std::io::Result<()>
where
    D: Datapath + Clone + Send + 'static,
{
    let events = engine.register_client(client);
    let metrics = engine.metrics();
    let _guard = ClientGuard {
        engine: engine.clone(),
        client,
    };
    // Split so the inbound-read future and the event/response writes borrow disjoint halves.
    let (mut read_half, mut write_half) = stream.into_split();

    // With no configured secret the connection starts authenticated; otherwise it must authenticate
    // before any other command is honoured.
    let mut authenticated = secret.is_none();
    // Per-connection request rate cap. The refill interval ticks once a second; the first tick
    // fires immediately and is harmless (the bucket starts full).
    let mut rate_limiter = RateLimiter::new(max_control_rps);
    let mut refill = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        // Drain every complete request frame currently buffered, writing each response.
        loop {
            match frame::decode::<Request>(&buffer) {
                Ok(Some((request, consumed))) => {
                    buffer.drain(..consumed);
                    // Spend a rate-limit token first: a breach is rejected before any work (and
                    // before the auth check) so a flood cannot drive engine work or probe auth.
                    // Every command answers immediately — `play_media` accepts on start and reports
                    // its end asynchronously via `Event::PlayFinished`, so nothing defers the response.
                    let result = if !rate_limiter.try_acquire() {
                        metrics.record_rate_limited();
                        CmdResult::Error {
                            reason: "rate limit exceeded".to_string(),
                        }
                    } else {
                        match request.command {
                            Command::Authenticate { token } => match secret.as_deref() {
                                None => auth_ok(),
                                Some(secret)
                                    if tokens_match(token.as_bytes(), secret.as_bytes()) =>
                                {
                                    authenticated = true;
                                    auth_ok()
                                }
                                Some(_) => CmdResult::Error {
                                    reason: "authentication failed".to_string(),
                                },
                            },
                            command if !authenticated => {
                                let _ = command;
                                CmdResult::Error {
                                    reason: "authentication required".to_string(),
                                }
                            }
                            command => engine.handle(client, command).await,
                        }
                    };
                    let response = Response {
                        id: request.id,
                        result,
                    };
                    match frame::encode(&response) {
                        Ok(bytes) => write_half.write_all(&bytes).await?,
                        Err(error) => {
                            tracing::error!(%error, "failed to encode control response");
                        }
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%error, "malformed control frame; closing connection");
                    return Ok(());
                }
            }
        }

        // Wait for more inbound data, an event to push, or a rate-limit refill tick. Every arm is
        // cancellation-safe: a read that loses the race drops without consuming, an unreceived event
        // stays queued, and the interval tick is idempotent.
        tokio::select! {
            read = read_half.read(&mut chunk) => {
                let read = read?;
                if read == 0 {
                    return Ok(()); // peer closed
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            event = events.recv_async() => {
                if let Ok(event) = event {
                    match frame::encode(&event) {
                        Ok(bytes) => write_half.write_all(&bytes).await?,
                        Err(error) => tracing::error!(%error, "failed to encode control event"),
                    }
                }
            }
            _ = refill.tick() => {
                rate_limiter.refill(1);
            }
        }
    }
}

/// Length-checked, branch-free token comparison — no early exit on the first differing byte.
fn tokens_match(provided: &[u8], expected: &[u8]) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(expected) {
        diff |= a ^ b;
    }
    diff == 0
}

/// The success result for an accepted control verb that carries no payload (e.g. `Authenticate`).
fn auth_ok() -> CmdResult {
    CmdResult::Ok {
        sdp: None,
        duration_ms: None,
        play_id: None,
        to_tag: None,
        stats: None,
    }
}
