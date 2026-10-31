//! The JSON-over-TCP control server.
//!
//! Each accepted connection is a persistent stream of length-prefixed JSON frames
//! ([`siphon_rtp_proto::frame`]). Requests are processed in order per connection and answered with
//! a correlated [`Response`]; connections are handled concurrently. This is SIPhon's native
//! front-end — the rtpengine NG/bencode compat listener is a separate front-end added later.

use std::sync::Arc;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{frame, CmdResult, Command, Event, Request, Response, Scoped};
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
    let mut lanes = Lanes::new(engine.clone(), client);
    loop {
        // Drain every complete request frame currently buffered, writing each response.
        loop {
            match frame::decode::<Scoped<Request>>(&buffer) {
                Ok(Some((frame, consumed))) => {
                    // A frame without a `scope` key is the frame every earlier controller sends,
                    // and addresses the unscoped call.
                    let Scoped {
                        scope,
                        inner: request,
                    } = frame;
                    buffer.drain(..consumed);
                    // Spend a rate-limit token first: a breach is rejected before any work (and
                    // before the auth check) so a flood cannot drive engine work or probe auth.
                    // Every command answers at once, except one that dials a WebSocket server: that
                    // one runs off this loop and answers when its dial has, see [`Lanes`].
                    let result = if !rate_limiter.try_acquire() {
                        metrics.record_rate_limited();
                        Some(CmdResult::Error {
                            reason: "rate limit exceeded".to_string(),
                        })
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
                                Some(match (accepted, controller_id) {
                                    (false, _) => CmdResult::Error {
                                        reason: "authentication failed".to_string(),
                                    },
                                    (true, None) => auth_ok(),
                                    (true, Some(controller_id)) => {
                                        match identity.claim(&controller_id) {
                                            Ok(()) => {
                                                // The claim may have given this connection another
                                                // identity's calls: later commands act as it.
                                                lanes.client = identity.client;
                                                auth_ok()
                                            }
                                            Err(error) => CmdResult::Error {
                                                reason: error.to_string(),
                                            },
                                        }
                                    }
                                })
                            }
                            command if !authenticated => {
                                let _ = command;
                                Some(CmdResult::Error {
                                    reason: "authentication required".to_string(),
                                })
                            }
                            command => lanes.admit(request.id, scope, command).await,
                        }
                    };
                    if let Some(result) = result {
                        write_response(&mut write_half, request.id, result).await?;
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
        //
        // Biased, eviction first and the read (which sees the end of the stream) next, ahead of the
        // events. A reconnect hands the new connection a receiver on the *same* event channel, so
        // until this loop has noticed it was superseded it is a second consumer of it. Polled with
        // its eviction, its end of stream and a new event all ready, an unbiased select picked one
        // at random and sometimes took the event, writing it into the closed socket while the
        // connection that replaced it never saw it: a lost call summary after every reconnect race.
        tokio::select! {
            biased;
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
            read = read_half.read(&mut chunk) => {
                let read = read?;
                if read == 0 {
                    return Ok(()); // peer closed
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            finished = lanes.finished.recv_async() => {
                // A command that was dialling has its answer. Write it, then serve what waited
                // behind it on the same call, in the order it arrived.
                if let Ok(finished) = finished {
                    let lane = finished.lane;
                    write_response(&mut write_half, finished.id, finished.result).await?;
                    // Then the events it raised, which were kept back so that they follow the
                    // response as they do for a command served in line.
                    for event in lanes.take_deferred(&lane) {
                        write_half.write_all(&event).await?;
                    }
                    while let Some((id, scope, command)) = lanes.next_waiting(&lane) {
                        if let Some(result) = lanes.serve(id, scope, command, &lane).await {
                            write_response(&mut write_half, id, result).await?;
                        } else {
                            break; // it dials too: the lane stays held until it answers
                        }
                    }
                }
            }
            event = identity.events.recv_async() => {
                if let Ok(event) = event {
                    // The engine's actors name a call by its key; the wire names it by `call_id`
                    // with the scope beside it, and an unscoped event is unchanged by this. A held
                    // lane is named by the key too, so it is looked up before the key is taken out.
                    let lane = lanes.held_lane(&event);
                    match frame::encode(&crate::engine::scope::scoped_event(event)) {
                        Ok(bytes) => {
                            if let Some(bytes) = lanes.defer_event(lane, bytes) {
                                write_half.write_all(&bytes).await?;
                            }
                        }
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

/// Write one response frame.
async fn write_response(
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    id: u64,
    result: CmdResult,
) -> std::io::Result<()> {
    match frame::encode(&Response { id, result }) {
        Ok(bytes) => write_half.write_all(&bytes).await,
        Err(error) => {
            tracing::error!(%error, "failed to encode control response");
            Ok(())
        }
    }
}

/// The most commands that may wait behind one call's pending dial. A controller that pipelines
/// more than this onto a call that is still dialling is answered with an error for the excess.
const MAX_WAITING_PER_LANE: usize = 64;

/// A command waiting behind its call's pending dial: the request id, the scope its frame named and
/// the command.
type Waiting = (u64, Option<String>, Command);

/// A command that ran off the connection's loop, finished.
struct Finished {
    id: u64,
    lane: String,
    result: CmdResult,
}

/// Which commands of one control connection run when.
///
/// A connection serves its requests in order, one at a time, and that order is what a controller
/// relies on: an `answer` after its `offer`, a `delete` after everything else. Almost every
/// command is over in microseconds, so serving them in line is also the fastest way. The
/// exception is a command that makes the engine dial a WebSocket server
/// ([`Engine::command_dials`]): it takes as long as that server takes to answer, up to the connect
/// timeout, and a server that accepts a connection and then says nothing takes all of it. Served
/// in line, such a command stops the connection for that long: no health probe is answered, no
/// other call is set up or torn down.
///
/// So a command that dials runs as a task of its own, and its answer is written when it has one.
/// While it runs, its **lane** (the call or conference it addresses, a call being the one of its
/// scope: two scopes of one `call_id` are two lanes) is held: later commands for
/// the same call wait behind it and are then served in the order they arrived, so nothing a
/// controller sent for one call is ever reordered. Commands for any other call, and the ones that
/// address no call at all, are served at once. Responses carry the request id, so one that
/// arrives after a later request's is still correlated.
///
/// An event about a call whose lane is held is kept back until that command's response has been
/// written, so that a controller sees `ok` and then `ws_tee_started`, never the reverse, exactly
/// as it does for a command served in line. Events about other calls are written at once.
///
/// A task is not cancelled when the connection goes away: a command half-applied is worse than
/// one whose answer nobody reads, and the dial inside it is bounded.
struct Lanes<D: Datapath> {
    engine: Arc<Engine<D>>,
    client: ClientId,
    /// The lanes held by a running task, each with the commands waiting behind it.
    held: std::collections::HashMap<String, std::collections::VecDeque<Waiting>>,
    /// Encoded events kept back for a held lane, in the order they were raised.
    deferred: std::collections::HashMap<String, Vec<Vec<u8>>>,
    done: flume::Sender<Finished>,
    finished: flume::Receiver<Finished>,
}

impl<D> Lanes<D>
where
    D: Datapath + Clone + Send + 'static,
{
    fn new(engine: Arc<Engine<D>>, client: ClientId) -> Self {
        let (done, finished) = flume::unbounded();
        Self {
            engine,
            client,
            held: std::collections::HashMap::new(),
            deferred: std::collections::HashMap::new(),
            done,
            finished,
        }
    }

    /// Take a command off the wire: its result when it was served in line, `None` when it waits
    /// behind its call's pending dial or dials itself, and will be answered later.
    async fn admit(
        &mut self,
        id: u64,
        scope: Option<String>,
        command: Command,
    ) -> Option<CmdResult> {
        let lane = Self::lane(scope.as_deref(), &command);
        if let Some(waiting) = lane.as_ref().and_then(|lane| self.held.get_mut(lane)) {
            if waiting.len() >= MAX_WAITING_PER_LANE {
                return Some(CmdResult::Error {
                    reason: "too many commands queued behind a pending dial on this call"
                        .to_string(),
                });
            }
            waiting.push_back((id, scope, command));
            return None;
        }
        match lane {
            Some(lane) => self.serve(id, scope, command, &lane).await,
            None => Some(self.handle(scope.as_deref(), command).await),
        }
    }

    /// The lane of a command: the key of the call it addresses under `scope`, which is how the
    /// engine and its events name that call, or the conference it addresses. `None` for a verb
    /// that addresses neither, and for a frame the engine refuses before any work (a malformed
    /// scope, a `call_id` that cannot be keyed), which is answered at once.
    fn lane(scope: Option<&str>, command: &Command) -> Option<String> {
        let addressed = Engine::<D>::command_lane(command)?;
        let scope = siphon_rtp_proto::normalize_scope(scope).ok()?;
        crate::engine::scope::compose(scope, addressed).ok()
    }

    async fn handle(&self, scope: Option<&str>, command: Command) -> CmdResult {
        self.engine.handle_scoped(self.client, scope, command).await
    }

    /// Serve a command whose lane is free (or is this command's to hold): in line, or as a task
    /// that holds the lane when it dials.
    async fn serve(
        &mut self,
        id: u64,
        scope: Option<String>,
        command: Command,
        lane: &str,
    ) -> Option<CmdResult> {
        if !Engine::<D>::command_dials(&command) {
            return Some(self.handle(scope.as_deref(), command).await);
        }
        self.held.entry(lane.to_owned()).or_default();
        let (engine, client, done) = (self.engine.clone(), self.client, self.done.clone());
        let lane = lane.to_owned();
        tokio::spawn(async move {
            let result = engine
                .handle_scoped(client, scope.as_deref(), command)
                .await;
            // The connection may be gone by now; the command was served all the same.
            let _ = done.send(Finished { id, lane, result });
        });
        None
    }

    /// The held lane an event is about, if any, read off the event as the engine emitted it (it
    /// names a call by its key). Only looks when a lane is held at all, which is the rare case.
    fn held_lane(&self, event: &Event) -> Option<String> {
        if self.held.is_empty() {
            return None;
        }
        let lane = serde_json::to_value(event).ok().and_then(|value| {
            ["call_id", "conference_id"]
                .iter()
                .find_map(|key| value.get(key)?.as_str().map(str::to_owned))
        })?;
        self.held.contains_key(&lane).then_some(lane)
    }

    /// Keep an encoded event back when it is about a call whose lane is held ([`Self::held_lane`]),
    /// or hand it back to be written now.
    fn defer_event(&mut self, lane: Option<String>, bytes: Vec<u8>) -> Option<Vec<u8>> {
        match lane {
            Some(lane) => {
                self.deferred.entry(lane).or_default().push(bytes);
                None
            }
            None => Some(bytes),
        }
    }

    /// The events kept back for `lane`, to be written after its command's response.
    fn take_deferred(&mut self, lane: &str) -> Vec<Vec<u8>> {
        self.deferred.remove(lane).unwrap_or_default()
    }

    /// The next command waiting on `lane`, releasing the lane when there is none.
    fn next_waiting(&mut self, lane: &str) -> Option<Waiting> {
        let next = self
            .held
            .get_mut(lane)
            .and_then(|waiting| waiting.pop_front());
        if next.is_none() {
            self.held.remove(lane);
        }
        next
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
