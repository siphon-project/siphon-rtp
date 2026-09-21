//! The JSON-over-TCP control server.
//!
//! Each accepted connection is a persistent stream of length-prefixed JSON frames
//! ([`siphon_rtp_proto::frame`]). Requests are processed in order per connection and answered with
//! a correlated [`Response`]; connections are handled concurrently. This is SIPhon's native
//! front-end — the rtpengine NG/bencode compat listener is a separate front-end added later.

use std::sync::Arc;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{frame, CmdResult, Command, Event, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::{ClientGeneration, ClientId, ControllerAttachError, Engine};
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
                tracing::info!(target: "siphon_rtp::control", "control accept loop draining (shutdown requested)");
                return Ok(());
            }
            accepted = listener.accept() => accepted?,
        };
        let client = ClientId(next_client_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        tracing::info!(target: "siphon_rtp::control", %peer, client = client.0, "control connection accepted");
        let engine = engine.clone();
        let secret = secret.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(engine, client, secret, stream, max_control_rps).await
            {
                tracing::warn!(target: "siphon_rtp::control", %peer, client = client.0, %error, "control connection closed with error");
            }
        });
    }
}

/// Everything a `controller_id` claim rewrites about a live connection: the [`ClientId`] its verbs
/// are keyed by, the event receiver drained to the socket, the flag a newer connection on the same
/// identity trips, and the registrations its teardown releases.
///
/// Releasing on drop covers every exit path (clean close, error, eviction, or task drop), and both
/// releases are conditional on the generation *this* connection registered — a reconnecting
/// controller resolves to the same `ClientId`, so an unconditional release would let the connection
/// being replaced silence the one replacing it.
struct ConnectionIdentity<D: Datapath + Clone + Send + 'static> {
    engine: Arc<Engine<D>>,
    client: ClientId,
    generation: ClientGeneration,
    /// The stable identity this connection claimed, if it claimed one.
    controller: Option<String>,
    events: flume::Receiver<Event>,
    evicted: Shutdown,
}

impl<D: Datapath + Clone + Send + 'static> ConnectionIdentity<D> {
    /// Claim the stable identity `controller_id`, re-keying this connection onto the [`ClientId`]
    /// the engine already minted for it (docs/security-and-nat.md §5).
    ///
    /// Claimed once or not at all: the identity decides which calls the connection owns, so letting
    /// it change mid-connection would strand them exactly as a reconnect does today. Re-presenting
    /// the *same* id is a no-op, since a controller that re-authenticates has not changed identity.
    fn claim(&mut self, controller_id: &str) -> Result<(), ControllerAttachError> {
        if let Some(claimed) = &self.controller {
            return if claimed == controller_id {
                Ok(())
            } else {
                Err(ControllerAttachError::AlreadyClaimed)
            };
        }
        // The attach registers a sink under the resolved id, so the connection-ordinal one goes
        // first — otherwise it would linger in the registry with nothing left to release it.
        self.engine.deregister_client(self.client, self.generation);
        let attachment = match self.engine.attach_controller(controller_id, self.client) {
            Ok(attachment) => attachment,
            Err(error) => {
                // The claim failed but the connection lives on, so put it back on its own identity.
                let (generation, events) = self.engine.register_client_generation(self.client);
                self.generation = generation;
                self.events = events;
                return Err(error);
            }
        };
        self.client = attachment.client;
        self.generation = attachment.generation;
        self.events = attachment.events;
        self.evicted = attachment.evicted;
        self.controller = Some(controller_id.to_string());
        Ok(())
    }
}

impl<D: Datapath + Clone + Send + 'static> Drop for ConnectionIdentity<D> {
    fn drop(&mut self) {
        self.engine.deregister_client(self.client, self.generation);
        if let Some(controller) = &self.controller {
            self.engine.detach_controller(controller, self.generation);
        }
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
    let (generation, events) = engine.register_client_generation(client);
    let metrics = engine.metrics();
    // A connection that claims no identity is never evicted: it holds the trigger for its own
    // placeholder flag for its whole life, so the flag neither trips nor resolves on a dropped
    // sender. A successful claim replaces the flag with the registry-backed one.
    let (_never_evicted, evicted) = crate::shutdown::channel();
    let mut identity = ConnectionIdentity {
        engine: engine.clone(),
        client,
        generation,
        controller: None,
        events,
        evicted,
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
                            Command::Authenticate {
                                token,
                                controller_id,
                            } => {
                                // Judged on this frame's token alone, so a wrong one is refused
                                // whether or not the connection authenticated earlier.
                                let accepted = match secret.as_deref() {
                                    None => true,
                                    Some(secret) => {
                                        tokens_match(token.as_bytes(), secret.as_bytes())
                                    }
                                };
                                authenticated |= accepted;
                                // A controller id is an identity claim, not a credential: where a
                                // secret is configured it is honoured only on a connection that
                                // presented the matching token (docs/security-and-nat.md §5).
                                match (accepted, controller_id) {
                                    (false, _) => CmdResult::Error {
                                        reason: "authentication failed".to_string(),
                                    },
                                    (true, None) => auth_ok(),
                                    (true, Some(controller_id)) => {
                                        match identity.claim(&controller_id) {
                                            Ok(()) => auth_ok(),
                                            Err(error) => CmdResult::Error {
                                                reason: error.to_string(),
                                            },
                                        }
                                    }
                                }
                            }
                            command if !authenticated => {
                                let _ = command;
                                CmdResult::Error {
                                    reason: "authentication required".to_string(),
                                }
                            }
                            command => engine.handle(identity.client, command).await,
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
            event = identity.events.recv_async() => {
                if let Ok(event) = event {
                    match frame::encode(&event) {
                        Ok(bytes) => write_half.write_all(&bytes).await?,
                        Err(error) => tracing::error!(%error, "failed to encode control event"),
                    }
                }
            }
            () = identity.evicted.cancelled() => {
                // A newer connection claimed this connection's controller identity. Newest wins,
                // so this one closes rather than two connections sharing one identity's calls.
                tracing::warn!(
                    target: "siphon_rtp::control",
                    client = identity.client.0,
                    "control connection superseded by a newer one on the same controller identity"
                );
                return Ok(());
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
        recording_id: None,
        to_tag: None,
        stats: None,
    }
}
