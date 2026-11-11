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
    /// The client's `rtcp_app` queue, drained beside `events` (see [`crate::app_events`]).
    app_events: flume::Receiver<Event>,
    evicted: Shutdown,
}

impl<D: Datapath + Clone + Send + 'static> ConnectionIdentity<D> {
    /// Point the APP-event receiver at the queue of the client this connection is now registered as.
    fn refresh_app_events(&mut self) {
        if let Some(receiver) = self.engine.app_event_receiver(self.client) {
            self.app_events = receiver;
        }
    }

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
                self.refresh_app_events();
                return Err(error);
            }
        };
        self.client = attachment.client;
        self.generation = attachment.generation;
        self.events = attachment.events;
        self.refresh_app_events();
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
    let app_events = engine
        .app_event_receiver(client)
        .unwrap_or_else(|| flume::bounded(1).1);
    let mut identity = ConnectionIdentity {
        engine: engine.clone(),
        client,
        generation,
        controller: None,
        events,
        app_events,
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
            event = next_event(&identity.events, &identity.app_events) => {
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
            _ = refill.tick() => {
                rate_limiter.refill(1);
            }
        }
    }
}

/// The next event for the wire, from the ordinary queue or the APP queue, whichever has one.
/// Cancellation-safe: both arms are `recv_async`, and a receive that loses the race consumes nothing.
async fn next_event(events: &flume::Receiver<Event>, app_events: &flume::Receiver<Event>) -> Event {
    /// A closed queue never yields again; park it rather than spin the loop on its error.
    async fn receive(queue: &flume::Receiver<Event>) -> Event {
        match queue.recv_async().await {
            Ok(event) => event,
            Err(_) => std::future::pending().await,
        }
    }
    tokio::select! {
        event = receive(events) => event,
        event = receive(app_events) => event,
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
/// Ending a call's media is the other such command ([`Engine::command_runs_off_loop`]): a
/// `delete` or `stop_recording` may wait, up to a bound, for a WebSocket bridge blocked on its
/// peer to let go of a recording, and one call's slow teardown must not be every call's.
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
        if !Engine::<D>::command_runs_off_loop(&command) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ordinary(call: &str) -> Event {
        Event::MediaTimeout {
            call_id: call.into(),
            from_tag: "a".into(),
            conference_id: None,
            reason: siphon_rtp_proto::MediaTimeoutReason::NoMedia,
        }
    }

    fn app(subtype: u8) -> Event {
        Event::RtcpApp {
            call_id: None,
            conference_id: Some("room".into()),
            from_tag: "a".into(),
            stream: siphon_rtp_proto::RtcpAppStream::Floor,
            ssrc: 1,
            name: "MCPT".into(),
            subtype,
            payload: Vec::new(),
        }
    }

    #[tokio::test]
    async fn the_connection_drains_the_app_queue_beside_the_ordinary_one_in_order() {
        let (ordinary_tx, events) = flume::bounded(8);
        let (floor, app_events) = flume::bounded(8);
        floor.send(app(1)).unwrap();
        floor.send(app(2)).unwrap();
        ordinary_tx.send(ordinary("call")).unwrap();
        let mut heard = Vec::new();
        for _ in 0..3 {
            heard.push(next_event(&events, &app_events).await);
        }
        let subtypes: Vec<u8> = heard
            .iter()
            .filter_map(|event| match event {
                Event::RtcpApp { subtype, .. } => Some(*subtype),
                _ => None,
            })
            .collect();
        assert_eq!(subtypes, [1, 2], "APP events keep their order");
        assert_eq!(heard.len(), 3);
    }

    #[tokio::test]
    async fn a_closed_queue_parks_instead_of_spinning() {
        let (_keep_open, events) = flume::bounded::<Event>(1);
        let (floor, app_events) = flume::bounded::<Event>(1);
        drop(floor);
        let waited = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            next_event(&events, &app_events),
        )
        .await;
        assert!(
            waited.is_err(),
            "nothing to deliver, and no busy error loop"
        );
    }

    /// A slow teardown on one call, over the real control connection.
    mod stalled_bot {
        use std::net::{Ipv4Addr, SocketAddr};
        use std::time::{Duration, Instant};

        use futures_util::StreamExt;
        use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
        use siphon_rtp_datapath::Datapath;
        use siphon_rtp_proto::{
            frame, CmdResult, Command, ProfileFlags, RecordingChannels, RecordingDirection,
            RecordingFormat, Request, Response, Scoped,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream, UdpSocket};
        use tokio::time::timeout;

        use crate::server::serve;
        use crate::Engine;

        /// How long a command unrelated to the slow one may take.
        const PROMPT: Duration = Duration::from_millis(400);

        struct Control {
            stream: TcpStream,
            buffer: Vec<u8>,
            next_id: u64,
        }

        impl Control {
            async fn send(&mut self, command: Command) -> u64 {
                let id = self.next_id;
                self.next_id += 1;
                let bytes =
                    frame::encode(&Scoped::new(None, Request { id, command })).expect("encode");
                self.stream.write_all(&bytes).await.expect("write request");
                id
            }

            /// The next response (events skipped), which must answer `id`, inside `wait`.
            async fn response_to(&mut self, id: u64, wait: Duration) -> CmdResult {
                let deadline = Instant::now() + wait;
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some((value, consumed)) =
                        frame::decode::<serde_json::Value>(&self.buffer).expect("decode frame")
                    {
                        self.buffer.drain(..consumed);
                        if value.get("event").is_none() {
                            let response: Response =
                                serde_json::from_value(value).expect("response shape");
                            assert_eq!(response.id, id, "the next response answers request {id}");
                            return response.result;
                        }
                    }
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .unwrap_or_else(|| panic!("no response to request {id} within {wait:?}"));
                    let read = timeout(remaining, self.stream.read(&mut chunk))
                        .await
                        .unwrap_or_else(|_| panic!("no response to request {id} within {wait:?}"))
                        .expect("read control");
                    assert_ne!(read, 0, "control connection closed");
                    self.buffer.extend_from_slice(&chunk[..read]);
                }
            }
        }

        /// A bot that accepts the bridge and reads (and ignores) whatever it is sent.
        async fn bot() -> String {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind bot");
            let addr = listener.local_addr().expect("bot addr");
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        if let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await {
                            while let Some(Ok(_)) = socket.next().await {}
                        }
                    });
                }
            });
            format!("ws://{addr}/voice")
        }

        async fn phone_sdp() -> String {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind phone");
            let addr: SocketAddr = socket.local_addr().expect("phone addr");
            format!(
                "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                 m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
                ip = addr.ip(),
                port = addr.port()
            )
        }

        fn answer_local(call_id: &str, sdp: String, ws_uri: Option<String>) -> Command {
            Command::AnswerLocal {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp,
                profile: ProfileFlags {
                    ws_uri,
                    ..Default::default()
                },
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn a_teardown_waiting_on_a_stalled_bot_holds_up_no_other_call() {
            // The controller multiplexes every call over one connection. A `delete` that has to wait
            // for a bot's bridge to let go of a recording must answer the other calls meanwhile.
            let engine = std::sync::Arc::new(Engine::new(UdpLoopbackDatapath::new()));
            tokio::spawn(crate::srtp_bridge::run_redirect_dispatcher(
                engine.datapath().rx(),
                engine.bridge(),
                engine.media(),
                engine.ws(),
                engine.conference(),
                None,
            ));
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind control");
            let addr = listener.local_addr().expect("control addr");
            let serving = engine.clone();
            tokio::spawn(async move {
                let _ = serve(serving, listener).await;
            });
            let mut control = Control {
                stream: TcpStream::connect(addr).await.expect("connect control"),
                buffer: Vec::new(),
                next_id: 1,
            };

            let answered = control
                .send(answer_local("slow", phone_sdp().await, Some(bot().await)))
                .await;
            let answered = control.response_to(answered, Duration::from_secs(3)).await;
            assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
            let directory = tempfile::tempdir().expect("tempdir");
            let recording = control
                .send(Command::StartRecording {
                    call_id: "slow".into(),
                    from_tag: "tag-a".into(),
                    recording_dir: Some(directory.path().to_string_lossy().into_owned()),
                    format: Some(RecordingFormat::Wav),
                    direction: Some(RecordingDirection::Both),
                    channels: Some(RecordingChannels::Stereo),
                    max_duration_ms: None,
                    silence_ms: None,
                    path: None,
                    bitrate_bps: None,
                })
                .await;
            let recording = control.response_to(recording, PROMPT).await;
            assert!(matches!(recording, CmdResult::Ok { .. }), "{recording:?}");
            let _unread = engine
                .stall_ws_bridge_mailbox("slow")
                .expect("the call has a bridge");

            let started = Instant::now();
            let deleted = control
                .send(Command::Delete {
                    call_id: "slow".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                })
                .await;
            let ping = control.send(Command::Ping).await;
            let bystander = control
                .send(answer_local("bystander", phone_sdp().await, None))
                .await;
            assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
            let bystander = control.response_to(bystander, PROMPT).await;
            assert!(matches!(bystander, CmdResult::Ok { .. }), "{bystander:?}");
            assert!(
                started.elapsed() < crate::engine::BRIDGE_REQUEST_TIMEOUT,
                "the other call was served while the delete still waited"
            );

            let bound = crate::engine::BRIDGE_REQUEST_TIMEOUT
                + crate::engine::WRITER_CLOSE_TIMEOUT
                + Duration::from_secs(4);
            let deleted = control.response_to(deleted, bound).await;
            assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
            assert_eq!(engine.session_count(), 1, "only the bystander is left");
        }
    }
}
