//! The session engine: maps control [`Command`]s onto datapath endpoints and relay flows.
//!
//! The port model mirrors rtpengine. A call owns two **legs**:
//! - `near` — the offerer (A) side;
//! - `far` — the answerer (B) side.
//!
//! Each leg owns an RTP endpoint and, unless the stream is `a=rtcp-mux`, a companion RTCP
//! endpoint. `offer` allocates the leg endpoints, records A's RTP/RTCP addresses, and returns SDP
//! advertising the `far` leg. `answer` records B's addresses, returns SDP advertising the `near`
//! leg, and installs the relay flows (RTP↔RTP and, when not muxed, RTCP↔RTCP). Each flow latches,
//! so once a party's packets are seen the relay replies to their observed source (symmetric RTP).
//! Under rtcp-mux the single endpoint relays RTP and RTCP alike — the datapath is payload-agnostic.
//!
//! The per-call **actor** (flume mailbox + owned media pipeline) arrives with the slow-path media
//! work; for plain relay the datapath's per-endpoint receive tasks are the data-plane workers.

use dashmap::DashMap;
use std::sync::Arc;

use siphon_rtp_datapath::{
    AddressFamily, Datapath, Endpoint, EndpointId, FlowAction, ForwardRule, IceConfig, LatchPolicy,
    ObservedRtcp, SourceFilter,
};
use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_hep::{protocol_type, Capture};
use siphon_rtp_media::player::{PcmPlayer, WavSource};
use siphon_rtp_media::wav::WavRecorder;
use siphon_rtp_proto::{CmdResult, Command, Event, PlayMediaSource, ProfileFlags, SessionStats};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};

use crate::ice::{self, IceCredentials};
use crate::media_pipeline::{
    DirectionConfig, MediaCall, MediaControl, MediaRegistry, RawTee, RelayConfig,
};
use crate::metrics::Metrics;
use crate::sdp::{self, EngineMedia, SecurityAdvertisement};
use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, BridgeOp, SrtpBridge};
use crate::ws_bridge::WsRegistry;

use siphon_rtp_media::bridge::protocol::{Direction as WsDirection, MediaFormat};
use siphon_rtp_media::bridge::{run_bridge, BridgeSession};
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;

/// Identity of a control client — one persistent JSON-over-TCP connection. A call is owned by the
/// client that created it via `offer`; only that client may answer, query, or delete it (A3 —
/// docs/security-and-nat.md §5). This assumes one persistent control connection per SIPhon instance;
/// a shared identity across a connection pool needs the deferred control-channel auth.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientId(pub u64);

/// One side of a call: an RTP endpoint, an optional companion RTCP endpoint (absent under
/// rtcp-mux), and the remote addresses learned from that side's SDP.
#[derive(Debug, Clone, Copy)]
struct Leg {
    rtp: Endpoint,
    rtcp: Option<Endpoint>,
    remote_rtp: Option<std::net::SocketAddr>,
    remote_rtcp: Option<std::net::SocketAddr>,
}

impl Leg {
    /// All datapath endpoints this leg owns (for teardown / stats).
    fn endpoint_ids(&self) -> impl Iterator<Item = EndpointId> {
        std::iter::once(self.rtp.id).chain(self.rtcp.map(|endpoint| endpoint.id))
    }
}

/// A negotiated (or half-negotiated) call: its owner and its two legs.
#[derive(Debug)]
struct Call {
    /// The control client that created the call; only it may answer/query/delete it.
    owner: ClientId,
    /// Logical-clock tick at creation (offer), the media-timeout baseline before any media arrives.
    created_tick: u64,
    /// The engine's own ICE-lite credentials for this call (its identity as the ICE server), or
    /// `None` for a non-ICE call.
    ice: Option<IceCredentials>,
    from_tag: String,
    to_tag: Option<String>,
    near: Leg,
    far: Leg,
    /// When the far (answerer) leg is offered as secure (`RTP/SAVP`), the engine's own SDES key
    /// advertised to B — kept to key the SRTP bridge once B's answer brings its key. `None` for a
    /// plain relay. (Scenario 1: AVP near ↔ SAVP far; the reverse, a secure near, is a follow-up.)
    far_local_crypto: Option<CryptoAttribute>,
    /// The near (offerer) leg's primary audio codec, captured at offer — paired with the answer's
    /// codec to decide whether the call transcodes (the media slow path).
    near_codec: Option<CodecSpec>,
    /// The far (answerer) leg's primary audio codec, captured at answer — the fork codec for a
    /// `subscribe_request` that forks leg B. `None` until the call is answered.
    far_codec: Option<CodecSpec>,
    /// The near leg's negotiated RFC 4733 telephone-event payload type, if any.
    near_telephone_event: Option<u8>,
    /// How this call's media is handled once answered (set in `answer`).
    pipeline: PipelineKind,
    /// For a passthrough relay, the forward actions installed at answer — kept so `block`/`unblock`
    /// can flip the endpoints to `Drop` and restore them. Empty for media/SRTP calls.
    relay_flows: Vec<(EndpointId, FlowAction)>,
}

/// A SIPREC / monitor media subscription (RFC 7866): one or more source legs' **raw ingress RTP** is
/// tee'd byte-for-byte toward a send-only subscriber (a Session Recording Server, SRS). Unlike a
/// re-encode fork, the raw tee carries each leg's negotiated codec verbatim — so it works on a plain
/// G.711 relay and on a codec the engine has no encoder for (AMR-WB), with no transcode.
///
/// `subscribe_request` allocates the subscriber endpoint and records the subscription as *pending*
/// (no `srs_rtp`, no installed tee) — media cannot flow until `subscribe_answer` brings the SRS's
/// address. `subscribe_answer` installs a raw tee on each tapped leg of the call's [`MediaCall`]. The
/// subscriber is **send-only** (engine → SRS): the engine never opens a Forward/Redirect flow on
/// `subscriber_endpoint`, so it accepts no inbound media (RTPBleed has no surface here — §4).
struct Subscription {
    /// The subscription identity returned to the controller as the UAS to-tag.
    subscription_id: String,
    /// Which source legs are tee'd: each entry is a leg selector (`true` ⇒ leg A, `false` ⇒ leg B).
    /// More than one entry is an MPTY subscription (each named leg is a separate tap into this one
    /// subscriber). Mirrors [`crate::media_pipeline::MediaControl::AddRawTee`]'s `source_a`.
    taps: Vec<bool>,
    /// The engine endpoint the tee'd RTP is transmitted from (send-only toward the SRS).
    subscriber_endpoint: Endpoint,
    /// The SRS's RTP address, learned from `subscribe_answer`. `None` while the subscription is
    /// pending (offered but not yet answered) — no media flows until it is known.
    srs_rtp: Option<std::net::SocketAddr>,
}

/// How a call's media is carried once answered. The resolver picks this from the profile + the two
/// legs' negotiated codecs (see [`Engine::resolve_pipeline`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelineKind {
    /// Plain in-datapath relay (the `Forward` fast path) — both legs share a codec, no record/stream.
    Passthrough,
    /// Userspace SRTP bridge (an `RTP/AVP` ↔ `RTP/SAVP` secure leg).
    Srtp,
    /// Userspace media slow path: transcode / record / DTMF-extraction via a [`MediaCall`] actor.
    Media,
    /// WebSocket bridge: leg A's audio is attached to an external WS media server (mod_audio_stream /
    /// voice-AI). The A↔B relay/transcode path is not wired — the WS server is A's far side.
    Ws,
}

/// The session engine, generic over a [`Datapath`] backend.
///
/// The backend must be `Clone + 'static` (already true of every backend): the media slow path
/// spawns a per-call actor that owns a datapath handle.
pub struct Engine<D: Datapath> {
    datapath: D,
    calls: DashMap<String, Call>,
    /// Maximum concurrent calls per control client; `usize::MAX` is unbounded.
    max_calls_per_client: usize,
    /// Live call count per client, for the per-client quota.
    client_calls: DashMap<ClientId, usize>,
    /// Per-client async event sinks, registered by the control server one per connection.
    events: DashMap<ClientId, flume::Sender<Event>>,
    /// Reverse index endpoint → call-id, correlating observed RTCP back to its call (HEP telemetry).
    endpoint_calls: DashMap<EndpointId, String>,
    /// The userspace SRTP bridge: the `Redirect`-path crypto for secure (`RTP/SAVP`) legs. Shared
    /// with the redirect dispatcher (see [`crate::srtp_bridge`]).
    bridge: Arc<SrtpBridge<D>>,
    /// The userspace media slow path: per-call transcode / record / DTMF actors. Shared with the
    /// redirect dispatcher, which routes media-owned endpoints' datagrams here (see
    /// [`crate::media_pipeline`]).
    media: Arc<MediaRegistry>,
    /// The WebSocket-bridge slow path: per-call WS bridges (mod_audio_stream / voice-AI). Shared with
    /// the redirect dispatcher, which routes WS-owned endpoints' datagrams here (see
    /// [`crate::ws_bridge`]).
    ws: Arc<WsRegistry>,
    /// SIPREC / monitor media subscriptions, keyed by call-id (RFC 7866). Each entry's source leg is
    /// forked to a send-only subscriber endpoint; freed alongside the parent call on delete/reap.
    subscriptions: DashMap<String, Vec<Subscription>>,
    /// Operational counters (offers/answers/deletes/errors), incremented on the control path and
    /// rendered by the `/metrics` HTTP endpoint. Shared so the metrics server reads the same surface.
    metrics: Arc<Metrics>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Create an engine over `datapath` with no per-client call quota.
    pub fn new(datapath: D) -> Self
    where
        D: Clone,
    {
        Self::with_max_calls_per_client(datapath, usize::MAX)
    }

    /// Create an engine that admits at most `max_calls_per_client` concurrent calls per control
    /// client — a soft DoS quota (the datapath media-port pool is the hard cap).
    pub fn with_max_calls_per_client(datapath: D, max_calls_per_client: usize) -> Self
    where
        D: Clone,
    {
        let bridge = Arc::new(SrtpBridge::new(datapath.clone()));
        Self {
            datapath,
            calls: DashMap::new(),
            max_calls_per_client,
            client_calls: DashMap::new(),
            events: DashMap::new(),
            endpoint_calls: DashMap::new(),
            bridge,
            media: Arc::new(MediaRegistry::default()),
            ws: Arc::new(WsRegistry::default()),
            subscriptions: DashMap::new(),
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// The shared operational metrics — handed to the `/metrics` HTTP endpoint so it renders the
    /// same counters the control path increments, alongside the live `session_count()` gauge.
    #[must_use]
    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    /// Borrow the underlying datapath (used by tests and, later, the media pipeline).
    pub fn datapath(&self) -> &D {
        &self.datapath
    }

    /// The shared SRTP bridge — handed to the redirect dispatcher so it can route bridge-owned
    /// endpoints' datagrams here (see [`crate::srtp_bridge::run_redirect_dispatcher`]).
    pub fn bridge(&self) -> Arc<SrtpBridge<D>> {
        self.bridge.clone()
    }

    /// The shared media registry — handed to the redirect dispatcher so it can route media-owned
    /// endpoints' datagrams to the per-call transcode/record/DTMF actors.
    pub fn media(&self) -> Arc<MediaRegistry> {
        self.media.clone()
    }

    /// The shared WebSocket-bridge registry — handed to the redirect dispatcher so it can route
    /// WS-owned endpoints' datagrams to the per-call WS bridges.
    pub fn ws(&self) -> Arc<WsRegistry> {
        self.ws.clone()
    }

    /// Number of live calls in the session registry.
    ///
    /// Used by the memory-leak soak to confirm the registry drains on teardown, and (later) by the
    /// metrics surface as the `sessions` gauge.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.calls.len()
    }

    /// Register `client`'s async event sink — one persistent control connection — and return the
    /// receiver the control server drains to the wire. Bounded: events are dropped under
    /// backpressure rather than blocking the engine on a slow control consumer.
    pub fn register_client(&self, client: ClientId) -> flume::Receiver<Event> {
        let (sender, receiver) = flume::bounded(64);
        self.events.insert(client, sender);
        receiver
    }

    /// Drop `client`'s event sink when its control connection closes.
    pub fn deregister_client(&self, client: ClientId) {
        self.events.remove(&client);
    }

    /// Push an asynchronous event to `client`, dropping it if the client is gone or its queue is
    /// full (late events are worthless — never block the engine on a slow consumer).
    fn push_event(&self, client: ClientId, event: Event) {
        if let Some(sender) = self.events.get(&client) {
            if sender.try_send(event).is_err() {
                tracing::debug!(?client, "control event dropped (queue full or closed)");
            }
        }
    }

    /// Handle one control command from `client`, producing the result to return to the caller.
    ///
    /// Increments the operational counters as a side effect: per-command totals (offer/answer/
    /// delete) before dispatch, and `control_errors_total` whenever the result is an error — so the
    /// `/metrics` surface reflects every command this engine processed (including over the NG and WS
    /// front-ends, which all funnel through here).
    pub async fn handle(&self, client: ClientId, command: Command) -> CmdResult {
        match &command {
            Command::Offer { .. } => self.metrics.record_offer(),
            Command::Answer { .. } => self.metrics.record_answer(),
            Command::Delete { .. } => self.metrics.record_delete(),
            _ => {}
        }
        let result = self.dispatch(client, command).await;
        if matches!(result, CmdResult::Error { .. }) {
            self.metrics.record_control_error();
        }
        result
    }

    /// Dispatch one control command to its handler (the metric-free inner of [`Self::handle`]).
    async fn dispatch(&self, client: ClientId, command: Command) -> CmdResult {
        match command {
            Command::Ping => CmdResult::Pong,
            Command::Offer {
                call_id,
                from_tag,
                sdp,
                profile,
            } => {
                self.offer(client, call_id, from_tag, &sdp, &profile)
                    .await
            }
            Command::Answer {
                call_id,
                from_tag,
                to_tag,
                sdp,
                profile,
            } => {
                self.answer(client, &call_id, &from_tag, to_tag, &sdp, &profile)
                    .await
            }
            Command::Delete { call_id, .. } => self.delete(client, &call_id).await,
            Command::Query { call_id, .. } => self.query(client, &call_id),
            Command::BlockMedia { call_id, .. } => self.set_block(client, &call_id, true).await,
            Command::UnblockMedia { call_id, .. } => self.set_block(client, &call_id, false).await,
            Command::SilenceMedia { call_id, .. } => self.set_silence(client, &call_id, true),
            Command::UnsilenceMedia { call_id, .. } => self.set_silence(client, &call_id, false),
            Command::PlayMedia {
                call_id,
                from_tag,
                source,
                repeat_times,
                start_pos_ms,
                ..
            } => {
                self.play_media(client, &call_id, &from_tag, source, repeat_times, start_pos_ms)
                    .await
            }
            Command::StopMedia { call_id, from_tag } => self.stop_media(client, &call_id, &from_tag),
            Command::PlayDtmf {
                call_id,
                from_tag,
                code,
                duration_ms,
                volume_dbm0,
                ..
            } => self.play_dtmf(client, &call_id, &from_tag, &code, duration_ms, volume_dbm0),
            Command::SubscribeRequest {
                call_id,
                from_tags,
                sdp,
                profile,
            } => {
                self.subscribe_request(client, &call_id, &from_tags, sdp.as_deref(), &profile)
                    .await
            }
            Command::SubscribeAnswer {
                call_id,
                from_tag,
                to_tag,
                sdp,
                ..
            } => {
                self.subscribe_answer(client, &call_id, &from_tag, &to_tag, &sdp)
                    .await
            }
            Command::Unsubscribe {
                call_id,
                from_tag,
                to_tag,
            } => self.unsubscribe(client, &call_id, &from_tag, &to_tag).await,
            other => CmdResult::Error {
                reason: format!("unsupported command: {}", command_name(&other)),
            },
        }
    }

    /// Allocate `count` endpoints of `family`, rolling back all of them if any allocation fails. The
    /// family is the address family of the call's signalled `c=` line (RFC 4566 §5.7), so a
    /// `c=IN IP6` call gets v6 engine endpoints and a `c=IN IP4` call gets v4.
    async fn alloc_endpoints(
        &self,
        count: usize,
        family: AddressFamily,
    ) -> Result<Vec<Endpoint>, String> {
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            match self.datapath.alloc_endpoint_for(family).await {
                Ok(endpoint) => endpoints.push(endpoint),
                Err(error) => {
                    for allocated in &endpoints {
                        self.datapath.remove_endpoint(allocated.id).await;
                    }
                    return Err(format!("alloc endpoint: {error}"));
                }
            }
        }
        Ok(endpoints)
    }

    async fn free(&self, endpoints: &[Endpoint]) {
        for endpoint in endpoints {
            self.datapath.remove_endpoint(endpoint.id).await;
        }
    }

    /// Current live call count for `client`.
    fn client_call_count(&self, client: ClientId) -> usize {
        self.client_calls.get(&client).map_or(0, |count| *count)
    }

    /// Release one call from `client`'s quota, dropping the entry when it reaches zero so the map
    /// does not retain rows for disconnected clients.
    fn release_client_call(&self, client: ClientId) {
        let mut drained = false;
        if let Some(mut count) = self.client_calls.get_mut(&client) {
            *count = count.saturating_sub(1);
            drained = *count == 0;
        }
        if drained {
            self.client_calls.remove_if(&client, |_, &count| count == 0);
        }
    }

    async fn offer(
        &self,
        client: ClientId,
        call_id: String,
        from_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        // Soft per-client call quota (the datapath media-port pool is the hard cap). Reject before
        // allocating anything. (A3 / DoS — docs/security-and-nat.md §5.)
        if self.client_call_count(client) >= self.max_calls_per_client {
            return CmdResult::Error {
                reason: "per-client call quota exceeded".to_string(),
            };
        }
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("offer SDP parse failed: {error}"),
                }
            }
        };

        // ICE-lite: if the peer offered ICE, mint our own short-term credentials — advertised in the
        // rewritten SDP and installed on the endpoints so the responder can validate the peer's
        // connectivity checks (docs/security-and-nat.md §4 layer 4).
        let ice_creds = if info.is_ice() {
            ice::generate_credentials()
        } else {
            None
        };

        // Two RTP endpoints, plus two companion RTCP endpoints unless the stream is muxed. Bind the
        // engine endpoints in the address family of the offer's signalled `c=` line (RFC 4566 §5.7),
        // so a `c=IN IP6` offer is relayed on v6 engine ports (and advertised back as `c=IN IP6`).
        // A mixed-family call (A v4 ↔ B v6) is IPv4↔IPv6 interworking — a separate roadmap item; here
        // both legs share the offer family, which covers the IPv6-only-network VoLTE case.
        let family = AddressFamily::of(info.remote_rtp.ip());
        let count = if info.rtcp_mux { 2 } else { 4 };
        let endpoints = match self.alloc_endpoints(count, family).await {
            Ok(endpoints) => endpoints,
            Err(reason) => return CmdResult::Error { reason },
        };
        let near_rtp = endpoints[0];
        let far_rtp = endpoints[1];
        let (near_rtcp, far_rtcp) = if info.rtcp_mux {
            (None, None)
        } else {
            (Some(endpoints[2]), Some(endpoints[3]))
        };

        // The rewritten offer is delivered to B, so it advertises the `far` leg.
        let engine = EngineMedia {
            rtp: far_rtp.local_addr,
            rtcp: far_rtcp.map(|endpoint| endpoint.local_addr),
        };
        let advert = ice_creds.as_ref().map(|creds| sdp::IceAdvertisement {
            ufrag: creds.ufrag.as_str(),
            pwd: creds.pwd.as_str(),
        });

        // SRTP bridge (Scenario 1): when the control profile asks for a secure far leg
        // (transport-protocol RTP/SAVP), mint our own SDES key and advertise RTP/SAVP + a=crypto to
        // B. B's answer brings its key and `answer` wires the bridge. The reverse (a secure near
        // leg, i.e. A offered SAVP) is a follow-up — see Call::far_local_crypto.
        let far_secure = profile
            .transport_protocol
            .as_deref()
            .is_some_and(|protocol| protocol.contains("SAVP"));
        let far_local_crypto = if far_secure {
            match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                Ok(crypto) => Some(crypto),
                Err(error) => {
                    self.free(&endpoints).await;
                    return error_result("generate SDES key", &error);
                }
            }
        } else {
            None
        };
        let security = far_local_crypto.map(SecurityAdvertisement::Secure);

        let rewritten = match sdp::rewrite(sdp, engine, advert, security) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                self.free(&endpoints).await;
                return CmdResult::Error {
                    reason: format!("offer SDP rewrite failed: {error}"),
                };
            }
        };

        // WebSocket bridge (mod_audio_stream / voice-AI): a native siphon-rtp extension. When the
        // profile carries `ws_uri`, leg A (the offerer) is bridged to that WS server using A's
        // negotiated (primary) codec — the engine dials the WS as a client and pumps A's audio in
        // both directions. The A↔B relay/transcode path is not wired in this mode (the WS is A's far
        // side). Resolved at offer because A's codec + signalled address are both known here.
        let near_codec = info.primary_codec();
        let ws_uri = profile.ws_uri.clone();
        let pipeline = if ws_uri.is_some() {
            PipelineKind::Ws
        } else {
            PipelineKind::Passthrough
        };

        *self.client_calls.entry(client).or_insert(0) += 1;
        // Index this call's endpoints so observed RTCP can be correlated back to the call-id.
        for endpoint in [Some(near_rtp), near_rtcp, Some(far_rtp), far_rtcp]
            .into_iter()
            .flatten()
        {
            self.endpoint_calls.insert(endpoint.id, call_id.clone());
        }
        self.calls.insert(
            call_id.clone(),
            Call {
                owner: client,
                created_tick: self.datapath.now_ticks(),
                ice: ice_creds,
                from_tag,
                to_tag: None,
                near: Leg {
                    rtp: near_rtp,
                    rtcp: near_rtcp,
                    remote_rtp: Some(info.remote_rtp),
                    remote_rtcp: Some(info.remote_rtcp),
                },
                far: Leg {
                    rtp: far_rtp,
                    rtcp: far_rtcp,
                    remote_rtp: None,
                    remote_rtcp: None,
                },
                far_local_crypto,
                near_codec: near_codec.clone(),
                far_codec: None,
                near_telephone_event: info.telephone_event_payload_type(),
                pipeline,
                relay_flows: Vec::new(),
            },
        );

        // Stand the WS bridge up now that the call is recorded (so a dispatch can find its route). On
        // any failure (no codec, redirect install, or dial), tear the half-built call back down.
        if let Some(ws_uri) = ws_uri {
            if let Err(reason) = self
                .setup_ws_bridge(
                    &call_id,
                    &ws_uri,
                    near_rtp,
                    info.remote_rtp,
                    near_codec.as_ref(),
                    bridge_source_filter(profile, info.remote_rtp),
                )
                .await
            {
                self.teardown_call(&call_id).await;
                return error_result("ws bridge", &reason);
            }
        }

        ok_sdp(rewritten.sdp, None)
    }

    /// Stand up the WebSocket bridge for leg A: install `Redirect` on A's RTP endpoint, dial the WS
    /// server as a client, build a [`BridgeSession`] on a [`MediaLeg`] in A's codec, and spawn the
    /// bridge + the rtp_out→datapath drain task, registering both in the [`WsRegistry`]. The bridge's
    /// `rtp_in` is fed by the redirect dispatcher (gated by `accepted_source` — RTPBleed defence,
    /// `Redirect` skips the datapath gate). `ws://` only for v1 (`wss://` is a follow-up).
    async fn setup_ws_bridge(
        &self,
        call_id: &str,
        ws_uri: &str,
        endpoint_a: Endpoint,
        a_rtp: std::net::SocketAddr,
        codec: Option<&CodecSpec>,
        accepted_source: SourceFilter,
    ) -> Result<(), String> {
        let Some(codec) = codec else {
            return Err("offer carried no usable audio codec for the WS bridge".to_string());
        };
        // Build A's codec pair for the leg: decode A's RTP → L16 uplink; encode L16 downlink → A's RTP.
        let decoder = factory::decoder_for(codec).map_err(|error| error.to_string())?;
        let encoder = factory::encoder_for(codec).map_err(|error| error.to_string())?;
        let ptime = std::time::Duration::from_millis(u64::from(codec.ptime_ms.max(1)));

        // Redirect A's RTP so the dispatcher routes it here (the WS bridge owns leg A's media).
        self.datapath
            .install_flow(endpoint_a.id, FlowAction::Redirect)
            .map_err(|error| format!("install WS bridge redirect: {error}"))?;

        // Dial the WS server as a client (ws:// for v1). connect_async returns the stream + the HTTP
        // upgrade response; we keep only the stream.
        let (socket, _response) = tokio_tungstenite::connect_async(ws_uri)
            .await
            .map_err(|error| format!("dial {ws_uri}: {error}"))?;

        // A jitter buffer shallow enough for low-latency voice-AI (target 1, cap 16 — the bridge
        // pops one frame per ptime tick, the consumer's cadence being the sample-tick clock).
        // The WS uplink PCM is at the codec's *native* sample rate (what the decoder emits), which is
        // not the RTP clock for G.722 (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2). Capture it
        // before the decoder is moved into the leg.
        let bridge_pcm_rate = decoder.params().sample_rate_hz;
        let leg = MediaLeg::new(
            decoder,
            encoder,
            JitterBuffer::new(1, 16),
            random_ssrc(),
            codec.payload_type,
        );
        // The WS media format advertised in `start`: L16 at the leg's native PCM rate, mono, LE.
        let format = MediaFormat {
            encoding: siphon_rtp_media::bridge::protocol::Encoding::L16,
            sample_rate: bridge_pcm_rate,
            channels: 1,
            bit_depth: 16,
            endianness: siphon_rtp_media::bridge::protocol::Endianness::Little,
            ptime: codec.ptime_ms.max(1),
        };
        let session = BridgeSession::new(
            leg,
            format,
            format!("ws-{call_id}"),
            call_id.to_string(),
            WsDirection::Duplex,
            8, // playout cap (drop-oldest): late audio is worthless
        );

        let (rtp_in_tx, rtp_in_rx) = flume::bounded::<bytes::Bytes>(1024);
        let (rtp_out_tx, rtp_out_rx) = flume::bounded::<bytes::Bytes>(1024);

        // The bridge: pump A's RTP (rtp_in) ↔ WS, render WS downlink to RTP (rtp_out).
        let bridge_task = tokio::spawn(async move {
            if let Err(error) = run_bridge(socket, session, rtp_in_rx, rtp_out_tx, ptime).await {
                tracing::debug!(%error, "ws bridge exited with error");
            }
        });
        // The drain: forward each rendered downlink RTP packet out A's endpoint toward A.
        let datapath = self.datapath.clone();
        let drain_endpoint = endpoint_a.id;
        let drain_task = tokio::spawn(async move {
            while let Ok(packet) = rtp_out_rx.recv_async().await {
                if let Err(error) = datapath.send(drain_endpoint, a_rtp, &packet).await {
                    tracing::debug!(%error, "ws bridge downlink send failed");
                }
            }
        });

        self.ws.register(
            call_id.to_string(),
            endpoint_a.id,
            accepted_source,
            rtp_in_tx,
            bridge_task,
            drain_task,
        );
        Ok(())
    }

    /// Tear down a call's datapath + slow-path state without an ownership check (an internal cleanup
    /// for a half-built call). Frees the sockets and drops any bridge / media / WS registration.
    async fn teardown_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            let endpoints: Vec<EndpointId> = call
                .near
                .endpoint_ids()
                .chain(call.far.endpoint_ids())
                .collect();
            // Free any SIPREC subscriptions first (detach forks, abort drains, free subscriber ports)
            // before the media actor is deregistered.
            self.drop_subscriptions(call_id).await;
            self.bridge.deregister(endpoints.iter().copied());
            self.media.deregister(call_id);
            self.ws.deregister(call_id);
            for endpoint in endpoints {
                self.datapath.remove_endpoint(endpoint).await;
                self.endpoint_calls.remove(&endpoint);
            }
            self.release_client_call(call.owner);
        }
    }

    async fn answer(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        to_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        // Snapshot the leg endpoints under the guard, then release it. Only the owning client may
        // answer (A3 — docs/security-and-nat.md §5); to anyone else the call is unknown.
        let (near, far, ice_creds, far_local_crypto, near_codec, near_telephone_event, offer_pipeline) =
            match self.calls.get(call_id) {
                Some(call) if call.owner == client => {
                    if call.from_tag != from_tag {
                        return CmdResult::Error {
                            reason: "from_tag mismatch on answer".to_string(),
                        };
                    }
                    (
                        call.near,
                        call.far,
                        call.ice.clone(),
                        call.far_local_crypto,
                        call.near_codec.clone(),
                        call.near_telephone_event,
                        call.pipeline,
                    )
                }
                _ => return unknown_call(call_id),
            };
        // The owner's async event sink (DTMF events flow here from the media actor), if registered.
        let owner_events = self.events.get(&client).map(|sink| sink.value().clone());

        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer SDP parse failed: {error}"),
                }
            }
        };

        // The rewritten answer is delivered to A, so it advertises the `near` leg.
        let engine = EngineMedia {
            rtp: near.rtp.local_addr,
            rtcp: near.rtcp.map(|endpoint| endpoint.local_addr),
        };
        let advert = ice_creds.as_ref().map(|creds| sdp::IceAdvertisement {
            ufrag: creds.ufrag.as_str(),
            pwd: creds.pwd.as_str(),
        });
        // The answer to A advertises the near leg; on an SRTP bridge that side is plain (RTP/AVP), so
        // force AVP and strip crypto. A plain relay leaves transport/crypto untouched.
        let security = far_local_crypto.map(|_| SecurityAdvertisement::Plain);
        let rewritten = match sdp::rewrite(sdp, engine, advert, security) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer SDP rewrite failed: {error}"),
                }
            }
        };

        // WebSocket bridge: if this call is (or is now being) bridged to a WS media server, leg A's
        // audio is already (or now) pumped to the WS — the A↔B relay/transcode path is deliberately
        // not wired (the WS server is A's far side). The bridge is normally stood up at offer; honour
        // `ws_uri` arriving first at answer too (set it up against A's stored codec/address).
        let already_ws = offer_pipeline == PipelineKind::Ws;
        if already_ws || profile.ws_uri.is_some() {
            if !already_ws {
                let Some(a_rtp) = near.remote_rtp else {
                    return error_result("ws bridge", &"near leg has no signalled address");
                };
                if let Some(ws_uri) = profile.ws_uri.clone() {
                    if let Err(reason) = self
                        .setup_ws_bridge(
                            call_id,
                            &ws_uri,
                            near.rtp,
                            a_rtp,
                            near_codec.as_ref(),
                            bridge_source_filter(profile, a_rtp),
                        )
                        .await
                    {
                        return error_result("ws bridge", &reason);
                    }
                }
            }
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.to_tag = Some(to_tag.clone());
                call.far.remote_rtp = Some(info.remote_rtp);
                call.far.remote_rtcp = Some(info.remote_rtcp);
                call.pipeline = PipelineKind::Ws;
            }
            return ok_sdp(rewritten.sdp, Some(to_tag));
        }

        // ICE applies to a leg only when both ends use it: `near` faces A (which offered ICE iff we
        // minted creds), `far` faces B (ICE iff its answer carries ICE).
        let near_ice = ice_creds.is_some();
        let far_ice = ice_creds.is_some() && info.is_ice();

        // Resolve how this call's media is carried: an SRTP bridge (secure far leg), the userspace
        // media slow path (transcode / record), or the in-datapath plain relay.
        let pipeline = resolve_pipeline(near_codec.as_ref(), &info, profile, far_local_crypto);
        // For a passthrough relay, remember the installed forward actions so `block` can flip the
        // endpoints to `Drop` and `unblock` can restore them.
        let mut relay_flows: Vec<(EndpointId, FlowAction)> = Vec::new();

        if pipeline == PipelineKind::Srtp {
            let far_local = far_local_crypto.expect("Srtp pipeline ⇒ far_local_crypto is set");
            // Secure far (B) leg → userspace SRTP bridge: terminate SRTP/SRTCP on B and relay
            // plaintext on A. B's answer must carry its SDES key to key the inbound contexts.
            let Some(far_remote) = info.crypto.first().copied() else {
                return error_result("SAVP answer", &"missing a=crypto in the answer");
            };
            let (Some(a_rtp), Some(a_rtcp)) = (near.remote_rtp, near.remote_rtcp) else {
                return error_result("SRTP bridge", &"near leg has no signalled address");
            };
            // Redirect every leg endpoint so the bridge sees (and crypts) both directions.
            for endpoint in near.endpoint_ids().chain(far.endpoint_ids()) {
                if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                    return error_result("install SRTP bridge redirect", &error);
                }
            }
            let mut flows = vec![
                // A (plain) ingress → encrypt for B → out the far endpoint toward B.
                BridgeFlowPlan {
                    endpoint: near.rtp.id,
                    op: BridgeOp::Encrypt,
                    accepted_source: bridge_source_filter(profile, a_rtp),
                    out_endpoint: far.rtp.id,
                    out_dst: info.remote_rtp,
                },
                // B (secure) ingress → decrypt for A → out the near endpoint toward A.
                BridgeFlowPlan {
                    endpoint: far.rtp.id,
                    op: BridgeOp::Decrypt,
                    accepted_source: bridge_source_filter(profile, info.remote_rtp),
                    out_endpoint: near.rtp.id,
                    out_dst: a_rtp,
                },
            ];
            if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
                flows.push(BridgeFlowPlan {
                    endpoint: near_rtcp.id,
                    op: BridgeOp::Encrypt,
                    accepted_source: bridge_source_filter(profile, a_rtcp),
                    out_endpoint: far_rtcp.id,
                    out_dst: info.remote_rtcp,
                });
                flows.push(BridgeFlowPlan {
                    endpoint: far_rtcp.id,
                    op: BridgeOp::Decrypt,
                    accepted_source: bridge_source_filter(profile, info.remote_rtcp),
                    out_endpoint: near_rtcp.id,
                    out_dst: a_rtcp,
                });
            }
            self.bridge.register(BridgeCallPlan {
                leg: SecureLeg::new(&far_local.key, &far_remote.key),
                flows,
            });
        } else if pipeline == PipelineKind::Media {
            // Userspace media slow path: redirect both RTP legs to a per-call transcode/record/DTMF
            // actor. A's codec is the offer's primary codec; B's is the answer's. RTCP (non-mux)
            // still relays in-datapath — it is not transcoded.
            let Some(a_rtp) = near.remote_rtp else {
                return error_result("media pipeline", &"near leg has no signalled address");
            };
            let Some(near_codec) = near_codec.clone() else {
                return error_result("media pipeline", &"offer carried no usable audio codec");
            };
            let Some(far_codec) = info.primary_codec() else {
                return error_result("media pipeline", &"answer carried no usable audio codec");
            };
            let record_path = profile
                .record_call
                .then(|| profile.record_path.clone())
                .flatten();

            // Build the two transcode directions (decode ingress codec → encode peer's codec).
            let a_to_b = match build_direction(
                near.rtp.id,
                bridge_source_filter(profile, a_rtp),
                far.rtp.id,
                info.remote_rtp,
                &near_codec,
                &far_codec,
                near_telephone_event,
                info.telephone_event_payload_type(),
                record_path.as_deref(),
            ) {
                Ok(direction) => direction,
                Err(reason) => return error_result("media pipeline (A→B)", &reason),
            };
            let b_to_a = match build_direction(
                far.rtp.id,
                bridge_source_filter(profile, info.remote_rtp),
                near.rtp.id,
                a_rtp,
                &far_codec,
                &near_codec,
                info.telephone_event_payload_type(),
                near_telephone_event,
                record_path.as_deref(),
            ) {
                Ok(direction) => direction,
                Err(reason) => return error_result("media pipeline (B→A)", &reason),
            };

            // Redirect the RTP legs to the actor (mux ⇒ RTCP rides these; the actor relays it).
            for endpoint in [near.rtp.id, far.rtp.id] {
                if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                    return error_result("install media redirect", &error);
                }
            }
            // Relay companion RTCP in-datapath when not muxed (RTCP is never transcoded).
            if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
                let _ = self.datapath.install_flow(
                    near_rtcp.id,
                    FlowAction::Forward(ingress_rule(
                        far_rtcp.id,
                        Some(info.remote_rtcp),
                        near.remote_rtcp,
                        profile,
                        near_ice,
                    )),
                );
                let _ = self.datapath.install_flow(
                    far_rtcp.id,
                    FlowAction::Forward(ingress_rule(
                        near_rtcp.id,
                        near.remote_rtcp,
                        Some(info.remote_rtcp),
                        profile,
                        far_ice,
                    )),
                );
            }

            let latch = !profile.flags.iter().any(|flag| flag == "no-latch");
            let call = MediaCall::new(
                call_id.to_string(),
                from_tag.to_string(),
                Some(to_tag.clone()),
                a_to_b,
                b_to_a,
                latch,
                record_path,
            );
            self.media.register(call, self.datapath.clone(), owner_events);
        } else {
            // Plain relay: the in-datapath Forward fast path. Each endpoint's rule gates its ingress
            // to the SDP-signalled peer and latches per policy (RTPBleed fix —
            // docs/security-and-nat.md §4): `near` receives from A (`near.remote_rtp`); `far` from B
            // (`info.remote_rtp`).
            let near_action = FlowAction::Forward(ingress_rule(
                far.rtp.id,
                Some(info.remote_rtp),
                near.remote_rtp,
                profile,
                near_ice,
            ));
            if let Err(error) = self.datapath.install_flow(near.rtp.id, near_action) {
                return error_result("install near->far RTP flow", &error);
            }
            relay_flows.push((near.rtp.id, near_action));
            let far_action = FlowAction::Forward(ingress_rule(
                near.rtp.id,
                near.remote_rtp,
                Some(info.remote_rtp),
                profile,
                far_ice,
            ));
            if let Err(error) = self.datapath.install_flow(far.rtp.id, far_action) {
                return error_result("install far->near RTP flow", &error);
            }
            relay_flows.push((far.rtp.id, far_action));

            // Companion RTCP relay when not muxed. (Under mux, RTCP rides the RTP endpoints already.)
            if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
                let near_rtcp_action = FlowAction::Forward(ingress_rule(
                    far_rtcp.id,
                    Some(info.remote_rtcp),
                    near.remote_rtcp,
                    profile,
                    near_ice,
                ));
                if let Err(error) = self.datapath.install_flow(near_rtcp.id, near_rtcp_action) {
                    return error_result("install near->far RTCP flow", &error);
                }
                relay_flows.push((near_rtcp.id, near_rtcp_action));
                let far_rtcp_action = FlowAction::Forward(ingress_rule(
                    near_rtcp.id,
                    near.remote_rtcp,
                    Some(info.remote_rtcp),
                    profile,
                    far_ice,
                ));
                if let Err(error) = self.datapath.install_flow(far_rtcp.id, far_rtcp_action) {
                    return error_result("install far->near RTCP flow", &error);
                }
                relay_flows.push((far_rtcp.id, far_rtcp_action));
            }
        }

        // Enable the ICE connectivity-check responder on the RTP endpoints facing an ICE peer; the
        // datapath then answers checks and adopts the validated source (RFC 8445).
        if let Some(creds) = &ice_creds {
            let config = IceConfig {
                local_ufrag: creds.ufrag.clone(),
                local_pwd: creds.pwd.clone(),
            };
            // `near` faces A (which offered ICE); enable the responder on its RTP and, under
            // non-mux, its companion RTCP endpoint.
            for endpoint in near.endpoint_ids() {
                self.datapath.set_ice(endpoint, Some(config.clone()));
            }
            // `far` faces B; enable only when B also offered ICE.
            if info.is_ice() {
                for endpoint in far.endpoint_ids() {
                    self.datapath.set_ice(endpoint, Some(config.clone()));
                }
            }
        }

        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.to_tag = Some(to_tag.clone());
            call.far.remote_rtp = Some(info.remote_rtp);
            call.far.remote_rtcp = Some(info.remote_rtcp);
            call.far_codec = info.primary_codec();
            call.pipeline = pipeline;
            call.relay_flows = relay_flows;
        }
        ok_sdp(rewritten.sdp, Some(to_tag))
    }

    async fn delete(&self, client: ClientId, call_id: &str) -> CmdResult {
        // Only the client that created the call may tear it down (A3 — docs §5). A non-owner (or a
        // missing call) gets `unknown_call`, so it cannot even probe for a call's existence.
        match self.calls.remove_if(call_id, |_, call| call.owner == client) {
            Some((_, call)) => {
                let endpoints: Vec<EndpointId> = call
                    .near
                    .endpoint_ids()
                    .chain(call.far.endpoint_ids())
                    .collect();
                // Drop any SIPREC subscriptions (detach forks, abort drains, free subscriber ports),
                // then any SRTP-bridge, media-pipeline, or WS-bridge flows (a no-op for a plain
                // relay), then free the sockets. `media.deregister` aborts the call's actor and
                // flushes any recording; `ws.deregister` aborts the bridge + drain tasks (closing the
                // WS connection).
                self.drop_subscriptions(call_id).await;
                self.bridge.deregister(endpoints.iter().copied());
                self.media.deregister(call_id);
                self.ws.deregister(call_id);
                for endpoint in endpoints {
                    self.datapath.remove_endpoint(endpoint).await;
                    self.endpoint_calls.remove(&endpoint);
                }
                self.release_client_call(call.owner);
                CmdResult::Ok {
                    sdp: None,
                    duration_ms: None,
                    to_tag: None,
                    stats: None,
                }
            }
            None => unknown_call(call_id),
        }
    }

    fn query(&self, client: ClientId, call_id: &str) -> CmdResult {
        let Some(call) = self.calls.get(call_id) else {
            return unknown_call(call_id);
        };
        // A call is invisible to clients that do not own it (A3 — docs §5).
        if call.owner != client {
            return unknown_call(call_id);
        }
        let mut stats = SessionStats::default();
        for endpoint in call.near.endpoint_ids().chain(call.far.endpoint_ids()) {
            let leg = self.datapath.stats(endpoint).unwrap_or_default();
            stats.packets_in += leg.packets_in;
            stats.packets_out += leg.packets_out;
            stats.bytes_in += leg.bytes_in;
            stats.bytes_out += leg.bytes_out;
            stats.packets_lost += leg.packets_dropped;
        }
        CmdResult::Ok {
            sdp: None,
            duration_ms: None,
            to_tag: None,
            stats: Some(stats),
        }
    }

    /// Drop (`block = true`) or resume (`block = false`) a call's media. A media-processing call
    /// flips its actor's egress; a plain relay flips its datapath flows to `Drop` and back. Only the
    /// owning client may control the call (A3 — docs §5).
    async fn set_block(&self, client: ClientId, call_id: &str, block: bool) -> CmdResult {
        let Some(relay_flows) = self.owned_call(client, call_id, |call| call.relay_flows.clone())
        else {
            return unknown_call(call_id);
        };
        if self.media.is_media_call(call_id) {
            self.media.control(call_id, MediaControl::Block(block));
            return ok_empty();
        }
        if relay_flows.is_empty() {
            return error_result(
                "block",
                &"call is not answered as a plain relay (SRTP-bridge block is not supported)",
            );
        }
        // Plain relay: flip each endpoint to Drop, or restore its stored forward action.
        for (endpoint, action) in &relay_flows {
            let next = if block { FlowAction::Drop } else { *action };
            if let Err(error) = self.datapath.install_flow(*endpoint, next) {
                return error_result("block: install flow", &error);
            }
        }
        ok_empty()
    }

    /// Replace a call's egress audio with comfort silence (`silence = true`) or resume it. Requires a
    /// media-processing call (decode/re-encode); a plain relay forwards opaque payloads and cannot
    /// synthesize silence. Only the owning client may control the call.
    fn set_silence(&self, client: ClientId, call_id: &str, silence: bool) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // Silence synthesizes comfort noise in the egress codec — a transcoding call only. A promoted
        // relay-only call (SIPREC on a passthrough relay) forwards opaque payloads and cannot.
        if self.media.is_transcoding_call(call_id)
            && self.media.control(call_id, MediaControl::Silence(silence))
        {
            ok_empty()
        } else {
            error_result(
                "silence",
                &"call is not a media-processing call (transcode/record/stream required)",
            )
        }
    }

    /// Run `f` against a call the client owns, or `None` if the call is unknown or owned by another
    /// client (A3 — a call is invisible to non-owners, docs §5).
    fn owned_call<T>(&self, client: ClientId, call_id: &str, f: impl FnOnce(&Call) -> T) -> Option<T> {
        let call = self.calls.get(call_id)?;
        (call.owner == client).then(|| f(&call))
    }

    /// Inject a prompt / announcement toward a leg ([`Command::PlayMedia`]). Requires a
    /// media-processing call (the actor owns the egress codec). The source is a WAV file/blob.
    async fn play_media(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        source: PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
    ) -> CmdResult {
        let Some((call_from, call_to)) =
            self.owned_call(client, call_id, |call| (call.from_tag.clone(), call.to_tag.clone()))
        else {
            return unknown_call(call_id);
        };
        if !self.media.is_transcoding_call(call_id) {
            return error_result(
                "play_media",
                &"requires a media-processing call (transcode/record/stream)",
            );
        }
        let bytes = match source {
            PlayMediaSource::Blob { data } => data,
            PlayMediaSource::File { path } => match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(error) => return error_result("play_media: read file", &error),
            },
            PlayMediaSource::DbId { .. } => {
                return error_result("play_media", &"db-id media source is not supported")
            }
        };
        let wav = match WavSource::parse(&bytes) {
            Ok(wav) => wav,
            Err(error) => return error_result("play_media: parse WAV", &error),
        };
        // `repeat_times` is the total play count; 0/None plays once (PcmPlayer treats 0/1 alike).
        let repeat = repeat_times.unwrap_or(0).min(u64::from(u32::MAX)) as u32;
        let start = start_pos_ms.unwrap_or(0).min(u64::from(u32::MAX)) as u32;
        let player = PcmPlayer::new(&wav, repeat, start);
        let toward_a = resolve_toward_a(from_tag, &call_from, call_to.as_deref());
        self.media.control(
            call_id,
            MediaControl::PlayAudio {
                toward_a,
                player: Box::new(player),
            },
        );
        ok_empty()
    }

    /// Stop any prompt / DTMF playback on a call ([`Command::StopMedia`]).
    fn stop_media(&self, client: ClientId, call_id: &str, _from_tag: &str) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        if self.media.control(call_id, MediaControl::StopPlay) {
            ok_empty()
        } else {
            error_result("stop_media", &"call has no active media playback")
        }
    }

    /// Inject an RFC 4733 DTMF burst toward a leg ([`Command::PlayDtmf`]). Requires a media-processing
    /// call with a negotiated telephone-event payload type on the target leg.
    fn play_dtmf(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
    ) -> CmdResult {
        let Some((call_from, call_to)) =
            self.owned_call(client, call_id, |call| (call.from_tag.clone(), call.to_tag.clone()))
        else {
            return unknown_call(call_id);
        };
        if !self.media.is_transcoding_call(call_id) {
            return error_result("play_dtmf", &"requires a media-processing call");
        }
        let Some(digit) = code.chars().next() else {
            return error_result("play_dtmf", &"empty DTMF code");
        };
        let duration = duration_ms.unwrap_or(250).min(u64::from(u32::MAX)) as u32;
        // `volume_dbm0` is a (negative) dBm0 power level; the generator takes its magnitude (0..=63).
        let volume = volume_dbm0
            .map(|value| value.unsigned_abs().min(63) as u8)
            .unwrap_or(10);
        let toward_a = resolve_toward_a(from_tag, &call_from, call_to.as_deref());
        if self.media.control(
            call_id,
            MediaControl::PlayDtmf {
                toward_a,
                digit,
                duration_ms: duration,
                volume,
            },
        ) {
            ok_empty()
        } else {
            error_result("play_dtmf", &"call is not a media-processing call")
        }
    }

    /// SIPREC / monitor `subscribe_request` (RFC 7866): the engine **offers** one or more source
    /// legs' media to a send-only subscriber (a Session Recording Server, SRS). It resolves the source
    /// legs from `from_tags` (an MPTY subscription taps every named leg), allocates one subscriber
    /// endpoint, advertises the (first) source leg's negotiated codec in the offer's `a=rtpmap`
    /// (RFC 4566 §6) with `a=sendonly` (RFC 3264 §5.1), records a *pending* subscription, and returns
    /// the offer. No media flows until `subscribe_answer` brings the SRS's address.
    ///
    /// The tee copies the source leg's **original ingress RTP byte-for-byte** — its negotiated codec,
    /// no re-encode — so it works on **any** call: a plain G.711 relay, a transcoding call, and a
    /// codec the engine cannot encode (AMR-WB). A plain passthrough relay (the in-kernel `Forward`
    /// fast path) is **promoted** to userspace here so the tee has somewhere to attach; a secure
    /// (SRTP-bridge) or WS-bridge call cannot be tee'd yet and is rejected.
    ///
    /// MPTY: each named leg becomes a separate tap into the one subscription. A true N-way *mix* into
    /// a single stream is a later feature — for now the SRS receives each leg's stream interleaved on
    /// the one subscriber endpoint (distinguishable by SSRC, RFC 3550).
    async fn subscribe_request(
        &self,
        client: ClientId,
        call_id: &str,
        from_tags: &[String],
        sdp: Option<&str>,
        _profile: &ProfileFlags,
    ) -> CmdResult {
        // The controller offers media to the SRS — it sends no SDP on the request. (An SDP-bearing
        // request, i.e. the SRS offering to the engine, is a follow-up; reject it clearly for now.)
        if sdp.is_some() {
            return error_result(
                "subscribe_request",
                &"SDP-offer-from-subscriber is not supported (the engine offers; send sdp: null)",
            );
        }
        // Snapshot the leg identity/codecs/pipeline under the ownership guard (A3 — docs §5).
        let Some((call_to, near_codec, far_codec, pipeline, family)) =
            self.owned_call(client, call_id, |call| {
                (
                    call.to_tag.clone(),
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.pipeline,
                    // The subscriber endpoint binds the call's address family (RFC 4566 §5.7), so a
                    // v6 call's SIPREC tee is offered to the SRS on a v6 endpoint (`c=IN IP6`).
                    AddressFamily::of(call.near.rtp.local_addr.ip()),
                )
            })
        else {
            return unknown_call(call_id);
        };
        // A secure (SRTP-bridge) or WS-bridge leg cannot be raw-tee'd: the on-the-wire bytes are
        // encrypted / off to a WS server, not the leg's clear negotiated codec. Reject clearly.
        if matches!(pipeline, PipelineKind::Srtp | PipelineKind::Ws) {
            return error_result(
                "subscribe_request",
                &"SIPREC on a secure (SRTP) or WebSocket-bridged call is not supported yet",
            );
        }

        // Resolve each named leg to a tap selector (`true` ⇒ leg A, `false` ⇒ leg B). An empty
        // `from_tags` defaults to leg A. Duplicate / unknown tags collapse to leg A (the offerer).
        let taps: Vec<bool> = if from_tags.is_empty() {
            vec![true]
        } else {
            let mut taps = Vec::with_capacity(from_tags.len());
            for tag in from_tags {
                // The call's to_tag ⇒ leg B; anything else (the from_tag, or unknown) ⇒ leg A.
                let source_a = !matches!(call_to.as_deref(), Some(to_tag) if to_tag == *tag);
                if !taps.contains(&source_a) {
                    taps.push(source_a);
                }
            }
            taps
        };

        // The codec advertised in the offer = the (first tapped) source leg's negotiated codec.
        let first_tap_source_a = taps.first().copied().unwrap_or(true);
        let codec = if first_tap_source_a {
            near_codec
        } else {
            far_codec
        };
        let Some(codec) = codec else {
            return error_result(
                "subscribe_request",
                &"the source leg has no negotiated codec to advertise",
            );
        };

        // Promote a plain passthrough relay to userspace so the tee has an actor to attach to.
        // Idempotent across subscriptions on the same call: a second subscribe finds it already a
        // media call and skips. On a call that already runs in the media slow path (transcode/record)
        // this is a no-op.
        if pipeline == PipelineKind::Passthrough && !self.media.is_media_call(call_id) {
            if let Err(reason) = self.promote_passthrough(call_id).await {
                return error_result("subscribe_request: promote relay", &reason);
            }
        }

        // Allocate the single send-only subscriber endpoint in the call's address family.
        let subscriber_endpoint = match self.alloc_endpoints(1, family).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return error_result("subscribe_request", &reason),
        };

        // The subscription id (returned as the UAS to-tag) names this subscription for answer/teardown.
        let subscription_id = subscription_tag();
        let offer = subscriber_offer_sdp(subscriber_endpoint.local_addr, &codec);

        self.subscriptions
            .entry(call_id.to_string())
            .or_default()
            .push(Subscription {
                subscription_id: subscription_id.clone(),
                taps,
                subscriber_endpoint,
                srs_rtp: None,
            });

        CmdResult::Ok {
            sdp: Some(offer),
            duration_ms: None,
            to_tag: Some(subscription_id),
            stats: None,
        }
    }

    /// Promote a plain passthrough relay (the in-kernel `FlowAction::Forward` fast path) to a
    /// userspace **relay-only** [`MediaCall`], so a SIPREC raw tee has an actor to attach to. The
    /// in-kernel `Forward` path has no userspace tap; here we switch each RTP endpoint from `Forward`
    /// to `Redirect`, and run a lightweight raw relay that re-enforces the exact same source gate +
    /// symmetric latch the `Forward` rule did (RTPBleed defence — `Redirect` bypasses the datapath
    /// gate, docs/security-and-nat.md §4) and forwards each packet verbatim to the original peer, plus
    /// the raw tee. Reconstructs both relay directions from the call's stored `relay_flows`.
    async fn promote_passthrough(&self, call_id: &str) -> Result<(), String> {
        // Read the two RTP forward rules + leg identity out of the stored relay flows. `relay_flows`
        // for a passthrough call is [near.rtp, far.rtp, (near.rtcp, far.rtcp)] — we tee/relay only RTP.
        let Some((from_tag, to_tag, relay_flows)) = self.owned_call_internal(call_id, |call| {
            (call.from_tag.clone(), call.to_tag.clone(), call.relay_flows.clone())
        }) else {
            return Err("call no longer exists".to_string());
        };

        // The first two entries are the RTP rules (near, then far) — see `answer`'s passthrough arm.
        let rtp_flows: Vec<(EndpointId, ForwardRule)> = relay_flows
            .iter()
            .filter_map(|(endpoint, action)| match action {
                FlowAction::Forward(rule) => Some((*endpoint, *rule)),
                _ => None,
            })
            .collect();
        let [(near_endpoint, near_rule), (far_endpoint, far_rule)] = rtp_flows.as_slice()[..2]
            .try_into()
            .map_err(|_| "passthrough call has no installed RTP relay flows".to_string())?;

        // `near_rule` is installed on near.rtp: it gates A's source and forwards toward far/out_dst (B).
        // Build the relay-only directions: A→B forwards out far's endpoint to B; B→A out near's to A.
        let Some(b_dst) = near_rule.out_dst else {
            return Err("passthrough relay has no destination toward B".to_string());
        };
        let Some(a_dst) = far_rule.out_dst else {
            return Err("passthrough relay has no destination toward A".to_string());
        };
        let a_to_b = RelayConfig {
            ingress_endpoint: near_endpoint,
            accepted_source: near_rule.accepted_source,
            egress_endpoint: near_rule.out_endpoint,
            egress_dst: b_dst,
        };
        let b_to_a = RelayConfig {
            ingress_endpoint: far_endpoint,
            accepted_source: far_rule.accepted_source,
            egress_endpoint: far_rule.out_endpoint,
            egress_dst: a_dst,
        };
        // Latch when either side's policy latches (the passthrough default is SignalledOnly/Symmetric).
        let latch = near_rule.latch != LatchPolicy::Off || far_rule.latch != LatchPolicy::Off;

        // Switch both RTP endpoints to Redirect so the dispatcher routes them to the media actor.
        for endpoint in [near_endpoint, far_endpoint] {
            self.datapath
                .install_flow(endpoint, FlowAction::Redirect)
                .map_err(|error| format!("install relay redirect: {error}"))?;
        }
        let call = MediaCall::new_relay(call_id.to_string(), from_tag, to_tag, a_to_b, b_to_a, latch);
        self.media.register(call, self.datapath.clone(), None);

        // Record the promotion on the Call so demotion can restore the in-kernel Forward rules.
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Media;
        }
        Ok(())
    }

    /// Demote a promoted passthrough relay back to the in-kernel `FlowAction::Forward` fast path once
    /// its last SIPREC subscription is gone: deregister the relay-only [`MediaCall`] actor and
    /// reinstall the stored `Forward` rules (the same ones promotion redirected away from). Best-effort
    /// — on any install error the call is left redirected (still relaying through the actor), which is
    /// correct if slower, and logged.
    async fn demote_to_passthrough(&self, call_id: &str) {
        let Some(relay_flows) =
            self.owned_call_internal(call_id, |call| call.relay_flows.clone())
        else {
            return;
        };
        // Tear down the relay-only actor (drops its routes), then restore the kernel Forward rules.
        self.media.deregister(call_id);
        for (endpoint, action) in &relay_flows {
            if let Err(error) = self.datapath.install_flow(*endpoint, *action) {
                tracing::warn!(%error, call_id, "demote: failed to reinstall Forward rule; leg stays redirected");
                return;
            }
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Passthrough;
        }
    }

    /// Run `f` against a call by id without an ownership check (an internal helper for promotion /
    /// demotion, which already validated ownership via the public verb). Returns `None` if unknown.
    fn owned_call_internal<T>(&self, call_id: &str, f: impl FnOnce(&Call) -> T) -> Option<T> {
        self.calls.get(call_id).map(|call| f(&call))
    }

    /// SIPREC `subscribe_answer` (RFC 7866): the SRS's answer brings its RTP address. Parse it, then
    /// install a raw-RTP tee on each tapped source leg of the call's [`MediaCall`], copying the leg's
    /// original ingress RTP byte-for-byte out the subscriber endpoint toward the SRS. The subscriber is
    /// send-only — the engine installs no inbound flow on `subscriber_endpoint`, so no RTPBleed surface
    /// exists (docs/security-and-nat.md §4).
    async fn subscribe_answer(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: &str,
        sdp: &str,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return error_result("subscribe_answer: parse SRS SDP", &error);
            }
        };
        let srs_rtp = info.remote_rtp;

        // Locate the pending subscription named by `to_tag` and read its taps + subscriber endpoint.
        let (taps, subscriber_endpoint) = {
            let Some(subscriptions) = self.subscriptions.get(call_id) else {
                return error_result("subscribe_answer", &"no subscription for this call");
            };
            let Some(subscription) = subscriptions
                .iter()
                .find(|subscription| subscription.subscription_id == to_tag)
            else {
                return error_result("subscribe_answer", &format!("unknown subscription {to_tag}"));
            };
            if subscription.srs_rtp.is_some() {
                return error_result("subscribe_answer", &"subscription is already answered");
            }
            (subscription.taps.clone(), subscription.subscriber_endpoint)
        };

        // Install a raw tee on each tapped leg of the running media actor (no encoder — the leg's
        // original ingress RTP is copied byte-for-byte toward the SRS, RFC 7866 §6). If the actor is
        // gone (call torn down between the ownership check and here), free the endpoint and report it.
        let tee = RawTee {
            subscriber_endpoint: subscriber_endpoint.id,
            srs_dst: srs_rtp,
        };
        let mut attached = false;
        for source_a in &taps {
            if self.media.control(call_id, MediaControl::AddRawTee {
                source_a: *source_a,
                tee,
            }) {
                attached = true;
            }
        }
        if !attached {
            self.datapath.remove_endpoint(subscriber_endpoint.id).await;
            return error_result("subscribe_answer", &"media call is no longer active");
        }

        // Record the now-active subscription (the SRS address) for unsubscribe / teardown.
        if let Some(mut subscriptions) = self.subscriptions.get_mut(call_id) {
            if let Some(subscription) = subscriptions
                .iter_mut()
                .find(|subscription| subscription.subscription_id == to_tag)
            {
                subscription.srs_rtp = Some(srs_rtp);
            }
        }
        ok_empty()
    }

    /// SIPREC `unsubscribe` (RFC 7866): detach the raw tee from every tapped leg of the media actor,
    /// free the subscriber endpoint, drop the subscription record, and — if this was the last
    /// subscription on a promoted passthrough relay — demote the call back to the in-kernel `Forward`
    /// fast path. Only the owning client may.
    async fn unsubscribe(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: &str,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // Remove the named subscription from the call's list, noting whether the list is now empty.
        let (removed, none_remain) = {
            let Some(mut subscriptions) = self.subscriptions.get_mut(call_id) else {
                return error_result("unsubscribe", &"no subscription for this call");
            };
            let Some(position) = subscriptions
                .iter()
                .position(|subscription| subscription.subscription_id == to_tag)
            else {
                return error_result("unsubscribe", &format!("unknown subscription {to_tag}"));
            };
            let removed = subscriptions.remove(position);
            (removed, subscriptions.is_empty())
        };
        self.subscriptions.remove_if(call_id, |_, list| list.is_empty());
        self.detach_subscription(call_id, removed).await;
        // Once no subscription remains on a relay we promoted for SIPREC, demote it back to the
        // in-kernel Forward fast path (the relay leg keeps flowing throughout). `is_relay_call` keeps
        // this scoped to promoted passthrough relays — a genuine transcoding call is never demoted.
        if none_remain && self.media.is_relay_call(call_id) {
            self.demote_to_passthrough(call_id).await;
        }
        ok_empty()
    }

    /// Tear one subscription down: remove its raw tee from every tapped leg (if the actor is still
    /// alive) and free its subscriber endpoint. Shared by `unsubscribe` and call teardown. (No drain
    /// task to abort — the raw tee emits through the actor's own send path.)
    async fn detach_subscription(&self, call_id: &str, subscription: Subscription) {
        for source_a in &subscription.taps {
            self.media.control(call_id, MediaControl::RemoveRawTee {
                source_a: *source_a,
                subscriber_endpoint: subscription.subscriber_endpoint.id,
            });
        }
        self.datapath
            .remove_endpoint(subscription.subscriber_endpoint.id)
            .await;
    }

    /// Free every subscription on a call (delete / reap / half-built teardown). Detaches each tee and
    /// frees its subscriber endpoint. (No demotion here — the whole call, including any promoted relay
    /// actor, is being torn down by the caller.)
    async fn drop_subscriptions(&self, call_id: &str) {
        if let Some((_, subscriptions)) = self.subscriptions.remove(call_id) {
            for subscription in subscriptions {
                self.detach_subscription(call_id, subscription).await;
            }
        }
    }

    /// Reap calls whose media has been idle (no accepted packet) for at least `idle_ticks`, freeing
    /// their ports/FDs and registry/quota slots, and return the reaped call ids. Deterministic: it
    /// reads the datapath's logical clock, so tests drive it via `advance_clock` rather than wall
    /// time (never `Instant::now()`). (docs/security-and-nat.md §4 layer 6.)
    pub async fn reap_idle(&self, idle_ticks: u64) -> Vec<String> {
        let now = self.datapath.now_ticks();
        // First pass (no `.await`, so holding the shard guards is fine): find the idle calls.
        let mut stale = Vec::new();
        for entry in self.calls.iter() {
            let call = entry.value();
            let mut last_activity = call.created_tick;
            for endpoint in call.near.endpoint_ids().chain(call.far.endpoint_ids()) {
                if let Some(seen) = self.datapath.last_activity(endpoint) {
                    last_activity = last_activity.max(seen);
                }
            }
            if now.saturating_sub(last_activity) >= idle_ticks {
                stale.push(entry.key().clone());
            }
        }
        // Second pass: tear each idle call down (no map guard held across the awaits).
        let mut reaped = Vec::new();
        for call_id in stale {
            if let Some((_, call)) = self.calls.remove(&call_id) {
                let endpoints: Vec<EndpointId> =
                    call.near.endpoint_ids().chain(call.far.endpoint_ids()).collect();
                self.drop_subscriptions(&call_id).await;
                self.bridge.deregister(endpoints.iter().copied());
                self.media.deregister(&call_id);
                self.ws.deregister(&call_id);
                for endpoint in endpoints {
                    self.datapath.remove_endpoint(endpoint).await;
                    self.endpoint_calls.remove(&endpoint);
                }
                self.release_client_call(call.owner);
                self.push_event(
                    call.owner,
                    Event::MediaTimeout {
                        call_id: call_id.clone(),
                        from_tag: call.from_tag,
                    },
                );
                reaped.push(call_id);
            }
        }
        reaped
    }

    /// The call-id owning `endpoint`, if any — RTCP-telemetry correlation.
    #[must_use]
    pub fn call_for_endpoint(&self, endpoint: EndpointId) -> Option<String> {
        self.endpoint_calls
            .get(&endpoint)
            .map(|entry| entry.value().clone())
    }

    /// Drain observed relayed RTCP and export each datagram as a HEP capture to `exporter` (a
    /// VoIPmonitor / Homer collector), correlated by call-id. Runs until the datapath's observation
    /// stream closes; fire-and-forget — export errors are logged, never propagated, so telemetry
    /// never disturbs the media path.
    pub async fn run_rtcp_export(self: Arc<Self>, exporter: HepExporter, capture_agent_id: u32) {
        let observations = self.datapath.observe_rtcp();
        while let Ok(observed) = observations.recv_async().await {
            let Some(call_id) = self.call_for_endpoint(observed.endpoint) else {
                continue;
            };
            let (timestamp_secs, timestamp_micros) = wall_clock_now();
            let capture = rtcp_capture(
                &observed,
                call_id,
                capture_agent_id,
                timestamp_secs,
                timestamp_micros,
            );
            if let Err(error) = exporter.export(&capture).await {
                tracing::debug!(%error, "HEP RTCP export failed");
            }
        }
    }
}

/// Build a HEP RTCP capture from an observed relayed RTCP datagram (`protocol_type` = RTCP).
fn rtcp_capture(
    observed: &ObservedRtcp,
    call_id: String,
    capture_agent_id: u32,
    timestamp_secs: u32,
    timestamp_micros: u32,
) -> Capture {
    Capture {
        src: observed.source,
        dst: observed.destination,
        timestamp_secs,
        timestamp_micros,
        protocol_type: protocol_type::RTCP,
        capture_agent_id,
        correlation_id: Some(call_id),
        payload: observed.payload.to_vec(),
    }
}

/// Wall-clock seconds + microseconds since the Unix epoch, for HEP capture timestamps (a genuine
/// real-time capture stamp — distinct from the logical media-timeout clock).
fn wall_clock_now() -> (u32, u32) {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (elapsed.as_secs() as u32, elapsed.subsec_micros()),
        Err(_) => (0, 0),
    }
}

fn ok_sdp(sdp: String, to_tag: Option<String>) -> CmdResult {
    CmdResult::Ok {
        sdp: Some(sdp),
        duration_ms: None,
        to_tag,
        stats: None,
    }
}

/// A bare success (no SDP/stats) — the reply to control verbs like block/silence.
fn ok_empty() -> CmdResult {
    CmdResult::Ok {
        sdp: None,
        duration_ms: None,
        to_tag: None,
        stats: None,
    }
}

/// Decide how a call's media is carried once answered: an SRTP bridge (secure far leg), the
/// userspace media slow path (transcode requested or recording on), or the in-datapath plain relay.
fn resolve_pipeline(
    near_codec: Option<&CodecSpec>,
    info: &sdp::MediaInfo,
    profile: &ProfileFlags,
    far_local_crypto: Option<CryptoAttribute>,
) -> PipelineKind {
    if far_local_crypto.is_some() {
        return PipelineKind::Srtp;
    }
    // Transcode when the two legs' primary codecs differ in encoding or clock rate.
    let transcode = match (near_codec, info.primary_codec()) {
        (Some(near), Some(far)) => {
            !near.encoding_name.eq_ignore_ascii_case(&far.encoding_name)
                || near.clock_rate_hz != far.clock_rate_hz
        }
        _ => false,
    };
    if profile.record_call || transcode {
        PipelineKind::Media
    } else {
        PipelineKind::Passthrough
    }
}

/// Build one transcode direction's config: decode the ingress codec, encode the egress codec, and
/// (when recording) capture the decoded ingress audio. Fails if either codec is unimplemented.
#[allow(clippy::too_many_arguments)]
fn build_direction(
    ingress_endpoint: EndpointId,
    accepted_source: SourceFilter,
    egress_endpoint: EndpointId,
    egress_dst: std::net::SocketAddr,
    ingress_codec: &CodecSpec,
    egress_codec: &CodecSpec,
    telephone_event_in: Option<u8>,
    telephone_event_out: Option<u8>,
    record_path: Option<&str>,
) -> Result<DirectionConfig, String> {
    let decoder = factory::decoder_for(ingress_codec).map_err(|error| error.to_string())?;
    let encoder = factory::encoder_for(egress_codec).map_err(|error| error.to_string())?;
    // Record at the codec's *native* PCM rate (what the decoder emits), not the RTP clock — they
    // differ for G.722 (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2), and a clock-rate WAV header
    // would replay the recording at the wrong pitch.
    let recorder = record_path.map(|_| WavRecorder::new(decoder.params().sample_rate_hz, 1));
    Ok(DirectionConfig {
        ingress_endpoint,
        accepted_source,
        egress_endpoint,
        egress_dst,
        decoder,
        encoder,
        egress_ssrc: random_ssrc(),
        egress_payload_type: egress_codec.payload_type,
        telephone_event_in,
        telephone_event_out,
        recorder,
    })
}

/// Which party a play/DTMF verb targets: the leg named by `from_tag`. Matching the call's `to_tag`
/// (party B) plays toward B; otherwise toward A (the offerer) — the default.
fn resolve_toward_a(from_tag: &str, _call_from: &str, call_to: Option<&str>) -> bool {
    !matches!(call_to, Some(to_tag) if to_tag == from_tag)
}

/// A fresh SSRC for a synthesized (transcoded) egress stream, from the OS CSPRNG (RFC 3550 §8 wants
/// a random SSRC). Falls back to a fixed value if the CSPRNG is unavailable — never panics.
fn random_ssrc() -> u32 {
    let mut bytes = [0u8; 4];
    if getrandom::getrandom(&mut bytes).is_err() {
        return 0x5310_0000; // "SIP0" — a stable fallback when the CSPRNG is unavailable
    }
    u32::from_be_bytes(bytes)
}

/// A fresh subscription identity, returned to the controller as the SIPREC UAS to-tag and used to
/// name the subscription on answer / unsubscribe. Random hex from the CSPRNG (a stable fallback when
/// it is unavailable — never panics), prefixed so it is recognisable in logs.
fn subscription_tag() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "sub-00000000".to_string();
    }
    format!("sub-{}", hex_lower(&bytes))
}

/// Lowercase-hex encode a byte slice (no external dependency; used for the subscription tag).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build the SIPREC subscriber SDP **offer** (engine → SRS): a minimal send-only audio stream
/// advertising the engine's subscriber endpoint + the fork codec (RFC 4566 §5 line order
/// `v= o= s= c= t= m=`; RFC 3264 §5.1 `a=sendonly` — the engine only transmits to the SRS, which is
/// the RTPBleed-safe posture: no inbound media is accepted on this endpoint).
fn subscriber_offer_sdp(local_addr: std::net::SocketAddr, codec: &CodecSpec) -> String {
    let payload_type = codec.payload_type;
    let mut sdp = String::new();
    use std::fmt::Write as _;
    // RFC 4566 §5: mandatory lines in order. o= uses a fixed session id/version (one offer per
    // subscription); s=- is the standard "no name"; t=0 0 is an unbounded session.
    // RFC 4566 §5.7: the addrtype (`IP4`/`IP6`) follows the subscriber endpoint's own family, so a
    // v6 SIPREC tee is offered to the SRS as `c=IN IP6`.
    let addrtype = if local_addr.is_ipv6() { "IP6" } else { "IP4" };
    let _ = write!(
        sdp,
        "v=0\r\n\
         o=- 0 0 IN {addrtype} {ip}\r\n\
         s=siphon-rtp-siprec\r\n\
         c=IN {addrtype} {ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP {payload_type}\r\n\
         a=rtpmap:{payload_type} {name}/{clock}{channels}\r\n\
         a=sendonly\r\n",
        ip = local_addr.ip(),
        port = local_addr.port(),
        name = codec.encoding_name,
        clock = codec.clock_rate_hz,
        // RFC 4566 §6: the optional /channels suffix is emitted only for multi-channel codecs.
        channels = if codec.channels > 1 {
            format!("/{}", codec.channels)
        } else {
            String::new()
        },
    );
    sdp
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Offer { .. } => "offer",
        Command::Answer { .. } => "answer",
        Command::Delete { .. } => "delete",
        Command::Query { .. } => "query",
        Command::Ping => "ping",
        Command::PlayMedia { .. } => "play_media",
        Command::StopMedia { .. } => "stop_media",
        Command::PlayDtmf { .. } => "play_dtmf",
        Command::SilenceMedia { .. } => "silence_media",
        Command::UnsilenceMedia { .. } => "unsilence_media",
        Command::BlockMedia { .. } => "block_media",
        Command::UnblockMedia { .. } => "unblock_media",
        Command::SubscribeRequest { .. } => "subscribe_request",
        Command::SubscribeAnswer { .. } => "subscribe_answer",
        Command::Unsubscribe { .. } => "unsubscribe",
        Command::Authenticate { .. } => "authenticate",
    }
}

fn unknown_call(call_id: &str) -> CmdResult {
    CmdResult::Error {
        reason: format!("unknown call: {call_id}"),
    }
}

fn error_result(context: &str, error: &dyn std::fmt::Display) -> CmdResult {
    CmdResult::Error {
        reason: format!("{context}: {error}"),
    }
}

/// Build the relay rule for one ingress endpoint: gate its incoming source to the SDP-signalled
/// peer and latch `SignalledOnly` by default, or accept-any + `Symmetric` when the `symmetric`
/// profile flag is set (or the peer address is not yet known). The RTPBleed-safe default —
/// see `docs/security-and-nat.md` §4.7.
fn ingress_rule(
    out_endpoint: EndpointId,
    out_dst: Option<std::net::SocketAddr>,
    expected_source: Option<std::net::SocketAddr>,
    profile: &ProfileFlags,
    ice: bool,
) -> ForwardRule {
    if ice {
        // ICE validates the source via STUN connectivity checks (the datapath responder adopts the
        // validated candidate), so accept any source and latch it.
        return ForwardRule::symmetric(out_endpoint, out_dst);
    }
    let symmetric = profile.flags.iter().any(|flag| flag == "symmetric");
    let Some(addr) = expected_source.filter(|_| !symmetric) else {
        // Symmetric leg, or the peer's address is not yet known: accept any source and latch.
        return ForwardRule::symmetric(out_endpoint, out_dst);
    };
    // Default: exact source-IP gate (the tightest RTPBleed defence). `subnet-source` loosens it to
    // the signalled IP's /24 (v4) or /64 (v6) for carriers that re-NAT or split RTP/RTCP within a
    // block (docs/security-and-nat.md §9).
    let accepted_source = if profile.flags.iter().any(|flag| flag == "subnet-source") {
        let prefix = if addr.is_ipv4() { 24 } else { 64 };
        SourceFilter::Subnet(addr.ip(), prefix)
    } else {
        SourceFilter::Exact(addr.ip())
    };
    ForwardRule {
        out_endpoint,
        out_dst,
        accepted_source,
        latch: LatchPolicy::SignalledOnly,
    }
}

/// The source-address gate for an SRTP-bridge leg, mirroring [`ingress_rule`]'s policy: an exact
/// source-IP gate by default (the tightest RTPBleed defence), the signalled /24 (v4) or /64 (v6)
/// under `subnet-source`, or any source under `symmetric`. The bridge enforces this itself because
/// the `Redirect` path bypasses the datapath's Forward-path source gate (docs/security-and-nat.md
/// §4 layer 2).
fn bridge_source_filter(profile: &ProfileFlags, addr: std::net::SocketAddr) -> SourceFilter {
    if profile.flags.iter().any(|flag| flag == "symmetric") {
        SourceFilter::Any
    } else if profile.flags.iter().any(|flag| flag == "subnet-source") {
        let prefix = if addr.is_ipv4() { 24 } else { 64 };
        SourceFilter::Subnet(addr.ip(), prefix)
    } else {
        SourceFilter::Exact(addr.ip())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    /// The default control client for tests that don't exercise per-client isolation.
    const CLIENT: ClientId = ClientId(1);

    async fn phone() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        (socket, addr)
    }

    /// A two-port SDP: RTP at `addr`, RTCP at `addr`+1 (default), optional `a=rtcp-mux`. The
    /// addrtype (RFC 4566 §5.7) follows `rtp`'s family, so this builds an `IN IP6` offer for a v6
    /// socket and `IN IP4` for a v4 one.
    fn sdp_for(rtp: SocketAddr, mux: bool) -> String {
        let mux_line = if mux { "a=rtcp-mux\r\n" } else { "" };
        let addrtype = if rtp.is_ipv6() { "IP6" } else { "IP4" };
        format!(
            "v=0\r\no=- 1 1 IN {addrtype} {ip}\r\ns=-\r\nc=IN {addrtype} {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n{mux_line}",
            ip = rtp.ip(),
            port = rtp.port()
        )
    }

    /// A test "phone" bound to IPv6 loopback (`::1`) — the v6 counterpart of [`phone`].
    async fn phone_v6() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind v6");
        let addr = socket.local_addr().expect("v6 addr");
        (socket, addr)
    }

    fn ok_sdp_text(result: &CmdResult) -> String {
        match result {
            CmdResult::Ok { sdp: Some(sdp), .. } => sdp.clone(),
            other => panic!("expected Ok with sdp, got {other:?}"),
        }
    }

    async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0u8; 2048];
        let (len, from) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv");
        (buffer[..len].to_vec(), from)
    }

    /// A `RTP/SAVP` answer SDP at `addr` carrying `crypto` (rtcp-mux, so it is a single port).
    fn savp_answer_sdp(addr: SocketAddr, crypto: &CryptoAttribute) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={crypto_line}\r\n",
            ip = addr.ip(),
            port = addr.port(),
            crypto_line = crypto.to_attribute_value(),
        )
    }

    fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"amr-wb-frame----");
        packet
    }

    #[tokio::test]
    async fn ping_pongs() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        assert_eq!(engine.handle(CLIENT, Command::Ping).await, CmdResult::Pong);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn savp_bridge_relays_avp_plaintext_to_savp_srtp_both_ways() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use siphon_rtp_srtp::SrtpContext;

        // Scenario 1: A is plain RTP/AVP, the control asks for a secure RTP/SAVP far leg, and the
        // engine bridges the two — SRTP terminated on B, plaintext relayed to A. Driven end-to-end
        // through the control plane with the redirect dispatcher live.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), engine.media(), engine.ws(), None));

        let (phone_a, addr_a) = phone().await; // plain (AVP) caller A
        let (phone_b, addr_b) = phone().await; // secure (SAVP) callee B

        // A offers plaintext RTP/AVP; the profile asks for a secure far leg (rtpengine model).
        let profile = ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        };
        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "savp-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            })
            .await;
        let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("parse offer reply");
        assert!(offer_reply.secure, "the engine offers RTP/SAVP to B");
        let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
        let far_addr = offer_reply.remote_rtp; // the engine's B-facing endpoint

        // B answers RTP/SAVP with its own SDES key.
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "savp-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            })
            .await;
        let answer_reply = sdp::parse(&ok_sdp_text(&answer)).expect("parse answer reply");
        assert!(!answer_reply.secure, "the answer to A is plaintext RTP/AVP");
        assert!(answer_reply.crypto.is_empty(), "no crypto leaks to the plain leg");
        let near_addr = answer_reply.remote_rtp; // the engine's A-facing endpoint

        // A → engine(near) → bridge encrypts → B receives SRTP, decryptable with the engine's key.
        let from_a = rtp_packet(100, 0x0A0A_0A0A);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (srtp, from) = recv(&phone_b).await;
        assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
        assert_ne!(srtp, from_a, "B receives SRTP, not plaintext");
        let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
        let mut recovered = Vec::new();
        b_decrypt.unprotect(&srtp, &mut recovered).expect("B decrypts the engine's SRTP");
        assert_eq!(recovered, from_a);

        // B → engine(far) as SRTP (B's key) → bridge decrypts → A receives plaintext.
        let from_b = rtp_packet(200, 0x0B0B_0B0B);
        let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
        let mut srtp_b = Vec::new();
        b_encrypt.protect(&from_b, &mut srtp_b).expect("B encrypts");
        phone_b.send_to(&srtp_b, far_addr).await.expect("b send");
        let (recovered_a, from) = recv(&phone_a).await;
        assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
        assert_eq!(recovered_a, from_b, "A receives the decrypted plaintext");
    }

    /// A G.711 RTP packet (160-sample frame) for transcode tests.
    fn g711_rtp(payload_type: u8, sequence: u16, ssrc: u32, payload_byte: u8) -> Vec<u8> {
        let mut packet = vec![0x80, payload_type];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[payload_byte; 160]);
        packet
    }

    /// An SDP advertising a single static audio codec (mux), for transcode answers.
    fn sdp_single_codec(rtp: SocketAddr, payload_type: u8, name: &str) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {pt}\r\na=rtpmap:{pt} {name}/8000\r\na=rtcp-mux\r\n",
            ip = rtp.ip(),
            port = rtp.port(),
            pt = payload_type,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_transcodes_ulaw_to_alaw_end_to_end() {
        // A offers PCMU (µ-law); B answers PCMA (A-law). The differing codecs resolve to the media
        // slow path, which redirects both legs to a transcoding actor — proven end-to-end through the
        // control plane with the redirect dispatcher live.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), engine.media(), engine.ws(), None));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // A's offer advertises PCMU as its primary codec (the `sdp_for` fixture: `0 8`, rtpmap PCMU).
        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            })
            .await;
        let far_addr = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply").remote_rtp;

        // B answers PCMA only → near=PCMU, far=PCMA → transcode.
        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            })
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer)).expect("answer reply").remote_rtp;

        // A → engine(near) → transcode → B receives A-law (PT 8), not the original µ-law.
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (transcoded, from) = recv(&phone_b).await;
        assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&transcoded).expect("parse");
        assert_eq!(parsed.payload_type, 8, "B receives A-law (PT 8)");
        assert_eq!(parsed.payload.len(), 160);
        assert_ne!(parsed.payload, &from_a[12..], "payload genuinely transcoded");

        // B → engine(far) → transcode → A receives µ-law (PT 0).
        let from_b = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
        phone_b.send_to(&from_b, far_addr).await.expect("b send");
        let (back, from) = recv(&phone_a).await;
        assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&back).expect("parse");
        assert_eq!(parsed.payload_type, 0, "A receives µ-law (PT 0)");

        // The call is a media-processing call; block then unblock via the control plane.
        assert!(engine.media().is_media_call("xcode-1"));
        let blocked = engine
            .handle(CLIENT, Command::BlockMedia {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
            })
            .await;
        assert!(matches!(blocked, CmdResult::Ok { .. }));

        // Teardown frees the media actor and routes.
        let deleted = engine
            .handle(CLIENT, Command::Delete {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert!(!engine.media().is_media_call("xcode-1"), "media call deregistered");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn siprec_subscribe_forks_leg_a_to_an_srs_then_unsubscribe_and_delete() {
        // SIPREC end-to-end (RFC 7866): a transcoding media call, then subscribe_request offers leg
        // A's media to a Session Recording Server, subscribe_answer points the fork at the SRS, A's
        // RTP is forked there, unsubscribe stops it, and delete tears the call (and subscription) down.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), engine.media(), engine.ws(), None));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let (srs, srs_addr) = phone().await; // the Session Recording Server's media socket

        // A offers PCMU, B answers PCMA → a transcoding media call (so there is decoded PCM to fork).
        engine
            .handle(CLIENT, Command::Offer {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            })
            .await;
        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            })
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer)).expect("answer reply").remote_rtp;
        assert!(engine.media().is_media_call("siprec-1"));

        // subscribe_request: the engine offers leg A's media to the SRS and returns an SDP offer + a
        // subscription to-tag. Leg A's negotiated codec is PCMU (PT 0).
        let subscribe = engine
            .handle(CLIENT, Command::SubscribeRequest {
                call_id: "siprec-1".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            })
            .await;
        let (offer_sdp, subscription_tag) = match subscribe {
            CmdResult::Ok { sdp: Some(sdp), to_tag: Some(to_tag), .. } => (sdp, to_tag),
            other => panic!("expected an SDP offer + to_tag, got {other:?}"),
        };
        let offer_info = sdp::parse(&offer_sdp).expect("parse subscriber offer");
        assert_eq!(offer_info.primary_codec().expect("codec").encoding_name, "PCMU");
        assert!(offer_sdp.contains("a=sendonly"), "subscriber stream is send-only (RFC 3264)");

        // subscribe_answer: the SRS answers with its own media address. The fork attaches to leg A.
        let srs_answer_sdp = sdp_single_codec(srs_addr, 0, "PCMU");
        let answered = engine
            .handle(CLIENT, Command::SubscribeAnswer {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag.clone(),
                sdp: srs_answer_sdp,
                profile: Default::default(),
            })
            .await;
        assert!(matches!(answered, CmdResult::Ok { .. }), "subscribe_answer ok: {answered:?}");

        // A sends µ-law RTP through the engine; B gets the A-law transcode AND the SRS gets leg A's
        // RAW ingress RTP byte-for-byte (the raw tee, not a re-encode): same SSRC, sequence, payload.
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (to_b, _) = recv(&phone_b).await; // the normal transcoded leg is undisturbed
        let (forked, from) = recv(&srs).await;
        assert_eq!(from, offer_info.remote_rtp, "fork leaves the engine's subscriber port");
        assert_eq!(forked, from_a, "SRS receives leg A's ORIGINAL RTP byte-for-byte (raw tee)");
        assert_ne!(to_b, from_a, "B still gets the genuinely transcoded A-law stream");

        // unsubscribe: the fork stops; A's media still transcodes to B.
        let unsubscribed = engine
            .handle(CLIENT, Command::Unsubscribe {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag,
            })
            .await;
        assert!(matches!(unsubscribed, CmdResult::Ok { .. }));

        // Drain any already-in-flight forked packets, then prove no more arrive after unsubscribe.
        let mut drain = [0u8; 2048];
        while srs.try_recv_from(&mut drain).is_ok() {}
        phone_a.send_to(&g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF), near_addr).await.expect("a send");
        let (_to_b_again, _) = recv(&phone_b).await; // B still receives transcoded media
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(200), srs.recv_from(&mut scratch)).await.is_err(),
            "no more forked packets reach the SRS after unsubscribe"
        );

        // delete: tears the call down cleanly (the subscription is already gone).
        let deleted = engine
            .handle(CLIENT, Command::Delete {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert!(!engine.media().is_media_call("siprec-1"), "media call deregistered");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn siprec_subscription_is_freed_when_the_parent_call_is_deleted() {
        // A subscription left open at delete must be torn down with the call (raw tees detached,
        // subscriber port freed) — no orphaned task or leaked endpoint.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), engine.media(), engine.ws(), None));

        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let (_srs, srs_addr) = phone().await;

        engine
            .handle(CLIENT, Command::Offer {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            })
            .await;
        engine
            .handle(CLIENT, Command::Answer {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            })
            .await;
        let subscribe = engine
            .handle(CLIENT, Command::SubscribeRequest {
                call_id: "siprec-2".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            })
            .await;
        let subscription_tag = match subscribe {
            CmdResult::Ok { to_tag: Some(to_tag), .. } => to_tag,
            other => panic!("expected a to_tag, got {other:?}"),
        };
        engine
            .handle(CLIENT, Command::SubscribeAnswer {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag,
                sdp: sdp_single_codec(srs_addr, 0, "PCMU"),
                profile: Default::default(),
            })
            .await;

        // Delete the call without unsubscribing first: teardown must drain the subscription too.
        let deleted = engine
            .handle(CLIENT, Command::Delete {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert_eq!(engine.session_count(), 0, "the call drained from the registry");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn siprec_subscribe_forks_a_plain_passthrough_relay_to_an_srs() {
        // The headline: SIPREC on a PLAIN G.711 RELAY (same codec both sides → Passthrough, the
        // in-kernel Forward fast path). subscribe_request promotes the relay to userspace, the raw tee
        // copies leg A's ORIGINAL RTP to the SRS byte-for-byte (no re-encode), AND the original peer B
        // keeps receiving the relayed RTP. Then unsubscribe stops the SRS feed (B still flows) and
        // demotes back to the kernel path; delete tears it down.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), engine.media(), engine.ws(), None));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let (srs, srs_addr) = phone().await;

        // A offers PCMU, B answers PCMU → same codec → a plain Passthrough relay (no media actor).
        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            })
            .await;
        let far_addr = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply").remote_rtp;
        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: Default::default(),
            })
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer)).expect("answer reply").remote_rtp;
        assert!(!engine.media().is_media_call("siprec-relay"), "a plain relay has no media actor");

        // subscribe_request: the engine offers leg A's media + promotes the relay to userspace.
        let subscribe = engine
            .handle(CLIENT, Command::SubscribeRequest {
                call_id: "siprec-relay".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            })
            .await;
        let (offer_sdp, subscription_tag) = match subscribe {
            CmdResult::Ok { sdp: Some(sdp), to_tag: Some(to_tag), .. } => (sdp, to_tag),
            other => panic!("expected an SDP offer + to_tag, got {other:?}"),
        };
        let offer_info = sdp::parse(&offer_sdp).expect("parse subscriber offer");
        assert_eq!(
            offer_info.primary_codec().expect("codec").encoding_name,
            "PCMU",
            "offer advertises the source leg's actual codec (RFC 4566)"
        );
        assert!(offer_sdp.contains("a=sendonly"), "subscriber stream is send-only (RFC 3264)");
        assert!(engine.media().is_relay_call("siprec-relay"), "the relay was promoted to userspace");

        // subscribe_answer: the SRS answers with its media address; the raw tee attaches to leg A.
        let answered = engine
            .handle(CLIENT, Command::SubscribeAnswer {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag.clone(),
                sdp: sdp_single_codec(srs_addr, 0, "PCMU"),
                profile: Default::default(),
            })
            .await;
        assert!(matches!(answered, CmdResult::Ok { .. }), "subscribe_answer ok: {answered:?}");

        // A sends RTP: (1) B still receives the relayed RTP, (2) the SRS receives the byte-identical
        // original RTP (raw tee, not re-encoded).
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (to_b, from_b_engine) = recv(&phone_b).await;
        assert_eq!(from_b_engine, far_addr, "B's media leaves the engine's far port");
        assert_eq!(to_b, from_a, "B still receives the relayed RTP verbatim");
        let (forked, from) = recv(&srs).await;
        assert_eq!(from, offer_info.remote_rtp, "tee leaves the engine's subscriber port");
        assert_eq!(forked, from_a, "SRS receives leg A's ORIGINAL RTP byte-for-byte (raw tee)");

        // unsubscribe: the SRS feed stops; B still flows; the call demotes back to the kernel path.
        let unsubscribed = engine
            .handle(CLIENT, Command::Unsubscribe {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag,
            })
            .await;
        assert!(matches!(unsubscribed, CmdResult::Ok { .. }));
        assert!(!engine.media().is_media_call("siprec-relay"), "demoted: no media actor remains");

        let mut drain = [0u8; 2048];
        while srs.try_recv_from(&mut drain).is_ok() {}
        phone_a.send_to(&g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF), near_addr).await.expect("a send");
        let (to_b_again, _) = recv(&phone_b).await; // B still relays after demotion
        assert_eq!(to_b_again, g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF), "B keeps relaying post-demote");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(200), srs.recv_from(&mut scratch)).await.is_err(),
            "no more tee'd packets reach the SRS after unsubscribe"
        );

        let deleted = engine
            .handle(CLIENT, Command::Delete {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert_eq!(engine.session_count(), 0, "the call drained from the registry");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_request_rejects_a_secure_call() {
        // SIPREC on an SRTP-bridge leg is not supported (the wire bytes are ciphertext, not the leg's
        // clear codec) — subscribe_request must reject it clearly rather than tee garbage.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), engine.media(), engine.ws(), None));

        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        let profile = ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        };
        engine
            .handle(CLIENT, Command::Offer {
                call_id: "savp-siprec".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            })
            .await;
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        engine
            .handle(CLIENT, Command::Answer {
                call_id: "savp-siprec".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            })
            .await;

        let result = engine
            .handle(CLIENT, Command::SubscribeRequest {
                call_id: "savp-siprec".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            })
            .await;
        assert!(matches!(result, CmdResult::Error { .. }), "SIPREC on a secure call is rejected");
    }

    /// A µ-law (PCMU, PT 0) RTP packet: a 160-sample / 20 ms frame carrying `payload_byte`.
    fn ulaw_rtp_packet(sequence: u16, ssrc: u32, payload_byte: u8) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[payload_byte; 160]);
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_attaches_leg_a_to_a_websocket_server_end_to_end() {
        // The mod_audio_stream headline: a control client sets `ws_uri`, the engine dials that WS
        // server and bridges leg A's audio to it. Driven end-to-end through the control plane with the
        // redirect dispatcher live; proves the start handshake, the uplink, the downlink, and teardown.
        use crate::srtp_bridge::run_redirect_dispatcher;
        use futures_util::{SinkExt, StreamExt};
        use siphon_rtp_media::bridge::pcm_to_l16_le;
        use siphon_rtp_media::bridge::protocol::ControlMessage;
        use tokio_tungstenite::tungstenite::Message;

        // Stand up a local WebSocket server: it relays each received frame out `ws_rx`, and forwards a
        // downlink frame requested via `down_tx` into the socket toward the engine.
        let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind ws");
        let ws_addr = ws_listener.local_addr().expect("ws addr");
        let (ws_tx, ws_rx) = flume::unbounded::<Message>();
        let (down_tx, down_rx) = flume::unbounded::<Vec<u8>>();
        tokio::spawn(async move {
            let (stream, _) = ws_listener.accept().await.expect("accept ws");
            let socket = tokio_tungstenite::accept_async(stream).await.expect("ws handshake");
            let (mut sink, mut source) = socket.split();
            loop {
                tokio::select! {
                    incoming = source.next() => match incoming {
                        Some(Ok(message)) => {
                            if ws_tx.send(message).is_err() {
                                break;
                            }
                        }
                        _ => break,
                    },
                    downlink = down_rx.recv_async() => match downlink {
                        Ok(bytes) => {
                            if sink.send(Message::Binary(bytes)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                }
            }
        });

        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;

        // A offers PCMU with `ws_uri` set → the engine dials the WS and bridges leg A to it.
        let profile = ProfileFlags {
            ws_uri: Some(format!("ws://{ws_addr}/stream")),
            ..Default::default()
        };
        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "ws-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            })
            .await;
        assert!(matches!(offer, CmdResult::Ok { .. }), "ws offer succeeds");
        assert!(engine.ws().is_ws_call("ws-1"), "the call is a WS-bridge call");

        // An answer (B answers PCMU too) returns the engine's A-facing endpoint without wiring A↔B.
        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "ws-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            })
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer)).expect("answer reply").remote_rtp;

        // 1. The WS server receives a `start` text frame first (the mod_audio_stream handshake).
        let first = timeout(Duration::from_secs(3), ws_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        match first {
            Message::Text(text) => assert!(
                matches!(ControlMessage::from_json(&text), Ok(ControlMessage::Start(_))),
                "first WS frame is `start`"
            ),
            other => panic!("expected start text frame, got {other:?}"),
        }

        // 2. Uplink: phone A sends µ-law RTP to the engine's A-facing port; the WS server gets an L16
        //    binary uplink frame (8 kHz / 20 ms = 320 bytes).
        phone_a
            .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        let mut got_uplink = false;
        for _ in 0..30 {
            let frame = timeout(Duration::from_secs(2), ws_rx.recv_async())
                .await
                .expect("no timeout")
                .expect("a frame");
            if let Message::Binary(bytes) = frame {
                assert_eq!(bytes.len(), 320, "8k/20ms L16 uplink");
                got_uplink = true;
                break;
            }
        }
        assert!(got_uplink, "expected an uplink L16 binary frame on the WS");

        // 3. Downlink: the WS server sends a binary L16 frame; phone A receives an RTP packet (the
        //    bridge encodes it in A's codec and the drain task sends it toward A).
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[2000i16; 160], &mut l16);
        down_tx.send(l16.to_vec()).expect("queue downlink");
        let mut got_downlink = false;
        for _ in 0..30 {
            let mut buffer = [0u8; 2048];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
            {
                let packet =
                    siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse rtp");
                assert_eq!(packet.payload_type, 0, "downlink encoded in A's codec (µ-law)");
                assert_eq!(packet.payload.len(), 160, "8k/20ms µ-law frame");
                got_downlink = true;
                break;
            }
        }
        assert!(got_downlink, "expected a downlink RTP packet toward phone A");

        // 4. Teardown: delete frees the WS bridge (route + tasks).
        let deleted = engine
            .handle(CLIENT, Command::Delete {
                call_id: "ws-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert!(!engine.ws().is_ws_call("ws-1"), "WS call deregistered on delete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn play_dtmf_emits_telephone_events_on_a_media_call() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), engine.media(), engine.ws(), None));

        let (phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        // A offers PCMU + telephone-event 101; B answers PCMA + telephone-event 101 → a transcoding
        // media call where A's leg carries DTMF.
        let offer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
            ip = addr_a.ip(),
            port = addr_a.port(),
        );
        let answer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
            ip = addr_b.ip(),
            port = addr_b.port(),
        );
        engine
            .handle(CLIENT, Command::Offer {
                call_id: "dtmf-1".into(),
                from_tag: "tag-a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            })
            .await;
        engine
            .handle(CLIENT, Command::Answer {
                call_id: "dtmf-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            })
            .await;
        assert!(engine.media().is_media_call("dtmf-1"));

        // Play DTMF '7' toward A; the actor's playout clock injects RFC 4733 events out A's socket.
        let played = engine
            .handle(CLIENT, Command::PlayDtmf {
                call_id: "dtmf-1".into(),
                from_tag: "tag-a".into(),
                code: "7".into(),
                duration_ms: Some(120),
                volume_dbm0: Some(-10),
                pause_ms: None,
                to_tag: None,
            })
            .await;
        assert!(matches!(played, CmdResult::Ok { .. }));

        // The first telephone-event packet (PT 96) reaches A within a few playout ticks.
        let mut saw_event = false;
        for _ in 0..20 {
            let mut buffer = [0u8; 256];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(100), phone_a.recv_from(&mut buffer)).await
            {
                let packet =
                    siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse");
                if packet.payload_type == 101 {
                    assert_eq!(packet.payload[0], 7, "RFC 4733 event code for '7'");
                    saw_event = true;
                    break;
                }
            }
        }
        assert!(saw_event, "expected a telephone-event packet toward A");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silence_on_a_passthrough_call_is_rejected() {
        // A plain relay (same codec both sides) is not a media-processing call; silence needs decode.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(CLIENT, Command::Offer {
                call_id: "relay-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            })
            .await;
        engine
            .handle(CLIENT, Command::Answer {
                call_id: "relay-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            })
            .await;
        let result = engine
            .handle(CLIENT, Command::SilenceMedia {
                call_id: "relay-1".into(),
                from_tag: "tag-a".into(),
            })
            .await;
        assert!(matches!(result, CmdResult::Error { .. }), "silence needs a media call");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_relays_rtp_then_query_and_delete() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            })
            .await;
        let far_rtp = sdp::parse(&ok_sdp_text(&offer)).expect("parse far").remote_rtp;

        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            })
            .await;
        let near_rtp = sdp::parse(&ok_sdp_text(&answer)).expect("parse near").remote_rtp;

        phone_a
            .send_to(&rtp(0x0A0A_0A0A), near_rtp)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A));
        assert_eq!(from, far_rtp);

        phone_b
            .send_to(&rtp(0x0B0B_0B0B), far_rtp)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, rtp(0x0B0B_0B0B));
        assert_eq!(from, near_rtp);

        // Stats: poll for packets_out to settle (counted after the forwarding send).
        let mut stats = SessionStats::default();
        for _ in 0..50 {
            if let CmdResult::Ok { stats: Some(s), .. } = engine
                .handle(CLIENT, Command::Query {
                    call_id: "call-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                })
                .await
            {
                stats = s;
            }
            if stats.packets_out == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(stats.packets_in, 2);
        assert_eq!(stats.packets_out, 2);

        let delete = engine
            .handle(CLIENT, Command::Delete {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_relays_rtp_over_ipv6_loopback() {
        // End-to-end on IPv6 (RFC 4566 §5.7 `c=IN IP6`): an `IN IP6 ::1` offer/answer must allocate
        // v6 engine endpoints, advertise `c=IN IP6`, and relay RTP between two `::1` phones. Mirrors
        // `offer_answer_relays_rtp_then_query_and_delete` on v6 loopback. `::1` binds in this
        // environment (verified), so this test runs unconditionally; it would only need gating on a
        // host without an IPv6 loopback.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone_v6().await;
        let (phone_b, addr_b) = phone_v6().await;

        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "call-v6".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            })
            .await;
        let offer_sdp = ok_sdp_text(&offer);
        assert!(offer_sdp.contains("c=IN IP6 ::1"), "v6 offer rewrite: {offer_sdp}");
        let far_rtp = sdp::parse(&offer_sdp).expect("parse far").remote_rtp;
        assert!(far_rtp.is_ipv6(), "the far engine endpoint is v6");

        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "call-v6".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            })
            .await;
        let answer_sdp = ok_sdp_text(&answer);
        assert!(answer_sdp.contains("c=IN IP6 ::1"), "v6 answer rewrite: {answer_sdp}");
        let near_rtp = sdp::parse(&answer_sdp).expect("parse near").remote_rtp;
        assert!(near_rtp.is_ipv6(), "the near engine endpoint is v6");

        // A -> engine -> B over v6 loopback.
        phone_a
            .send_to(&rtp(0x0A0A_0A0A), near_rtp)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A));
        assert_eq!(from, far_rtp);

        // B -> engine -> A over v6 loopback.
        phone_b
            .send_to(&rtp(0x0B0B_0B0B), far_rtp)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, rtp(0x0B0B_0B0B));
        assert_eq!(from, near_rtp);

        let delete = engine
            .handle(CLIENT, Command::Delete {
                call_id: "call-v6".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn companion_rtcp_relays_on_separate_ports() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        // RTP + RTCP sockets per phone (RTCP is the RTP port's logical +1 peer; here just sockets).
        let (rtp_a, addr_rtp_a) = phone().await;
        let (rtcp_a, addr_rtcp_a) = phone().await;
        let (rtp_b, addr_rtp_b) = phone().await;
        let (rtcp_b, addr_rtcp_b) = phone().await;

        // Build offers whose a=rtcp points at the dedicated RTCP socket.
        let offer_sdp = format!(
            "v=0\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=rtcp:{}\r\n",
            addr_rtp_a.port(),
            addr_rtcp_a.port()
        );
        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "rtcp-call".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            })
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        assert_ne!(far.remote_rtcp.port(), far.remote_rtp.port() + 1, "engine RTCP is its own port");

        let answer_sdp = format!(
            "v=0\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=rtcp:{}\r\n",
            addr_rtp_b.port(),
            addr_rtcp_b.port()
        );
        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "rtcp-call".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            })
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // RTP relays on the RTP ports.
        rtp_a.send_to(&rtp(0x0A0A_0A0A), near.remote_rtp).await.expect("rtp a");
        assert_eq!(recv(&rtp_b).await.0, rtp(0x0A0A_0A0A));

        // RTCP relays on the dedicated RTCP ports (RTCP SR, first byte 0x80 / PT 200).
        let rtcp_sr = vec![0x80u8, 0xC8, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44];
        rtcp_a.send_to(&rtcp_sr, near.remote_rtcp).await.expect("rtcp a");
        let (data, from) = recv(&rtcp_b).await;
        assert_eq!(data, rtcp_sr);
        assert_eq!(from, far.remote_rtcp, "B's RTCP arrives from the engine far-RTCP port");

        let _ = (addr_rtcp_a, addr_rtcp_b);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtcp_mux_relays_both_on_one_port() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "mux".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            })
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        assert!(far.rtcp_mux);
        assert!(!ok_sdp_text(&offer).contains("a=rtcp:"), "no companion port advertised under mux");

        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "mux".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            })
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // Both an RTP-looking and an RTCP-looking datagram relay over the single muxed port.
        phone_a.send_to(b"\x80\x00rtp", near.remote_rtp).await.expect("rtp");
        assert_eq!(recv(&phone_b).await.0, b"\x80\x00rtp");
        phone_b.send_to(b"\x80\xc8rtcp", far.remote_rtp).await.expect("rtcp");
        assert_eq!(recv(&phone_a).await.0, b"\x80\xc8rtcp");
    }

    #[tokio::test]
    async fn answer_and_delete_unknown_call_error() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "nope".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5000 RTP/AVP 0\r\n".into(),
                profile: Default::default(),
            })
            .await;
        assert!(matches!(answer, CmdResult::Error { .. }));

        let delete = engine
            .handle(CLIENT, Command::Delete {
                call_id: "nope".into(),
                from_tag: "a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(delete, CmdResult::Error { .. }));
    }

    #[tokio::test]
    async fn unsupported_command_reports_error() {
        // `authenticate` is handled by the control server, not the session engine, so the engine's
        // dispatcher reports it as unsupported and names it in the error. (SubscribeRequest is now a
        // wired SIPREC verb — see the subscribe_* tests below.)
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let result = engine
            .handle(CLIENT, Command::Authenticate {
                token: "s3cret".into(),
            })
            .await;
        match result {
            CmdResult::Error { reason } => assert!(reason.contains("authenticate")),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_request_on_a_passthrough_call_promotes_and_offers() {
        // A plain relay (same codec both sides) IS now subscribable: subscribe_request promotes it to
        // userspace and returns a send-only SDP offer advertising the source leg's codec (raw tee).
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(CLIENT, Command::Offer {
                call_id: "fork-relay".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            })
            .await;
        engine
            .handle(CLIENT, Command::Answer {
                call_id: "fork-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            })
            .await;
        assert!(!engine.media().is_media_call("fork-relay"), "starts as a plain relay");
        let result = engine
            .handle(CLIENT, Command::SubscribeRequest {
                call_id: "fork-relay".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            })
            .await;
        match result {
            CmdResult::Ok { sdp: Some(sdp), to_tag: Some(_), .. } => {
                assert!(sdp.contains("a=sendonly"), "send-only subscriber offer (RFC 3264)");
                assert!(sdp.contains("PCMU"), "advertises the source leg's codec (RFC 4566)");
            }
            other => panic!("expected an SDP offer, got {other:?}"),
        }
        assert!(engine.media().is_relay_call("fork-relay"), "the relay was promoted to userspace");
    }

    #[tokio::test]
    async fn subscribe_request_on_an_unknown_call_is_unknown() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let result = engine
            .handle(CLIENT, Command::SubscribeRequest {
                call_id: "nope".into(),
                from_tags: vec!["f".into()],
                sdp: None,
                profile: Default::default(),
            })
            .await;
        assert!(matches!(result, CmdResult::Error { .. }), "unknown call ⇒ error");
    }

    #[tokio::test]
    async fn stop_media_on_unknown_call_errors() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let result = engine
            .handle(CLIENT, Command::StopMedia {
                call_id: "nope".into(),
                from_tag: "f".into(),
            })
            .await;
        assert!(matches!(result, CmdResult::Error { .. }), "unknown call ⇒ error");
    }

    /// A test phone bound to a specific loopback address, so the engine's signalled-source gate can
    /// be exercised with distinct peers (127.0.0.0/8 is all loopback on Linux).
    async fn phone_at(ip: Ipv4Addr) -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((ip, 0)).await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        (socket, addr)
    }

    /// A minimal RTP packet (V=2, PT=0/PCMU) carrying `ssrc` (RFC 3550 §5.1).
    fn rtp(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"audio");
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_gates_out_an_off_path_rtpbleed_source() {
        // End-to-end: the engine must install a signalled-source gate from the SDP, so an attacker
        // on another address cannot latch the media even if it sprays the port first.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;

        let offer = engine
            .handle(CLIENT, Command::Offer {
                call_id: "rtpbleed".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            })
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");

        let answer = engine
            .handle(CLIENT, Command::Answer {
                call_id: "rtpbleed".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            })
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // Attacker sprays the A-facing port first — gated out, never reaches B.
        attacker
            .send_to(&rtp(0xAAAA_AAAA), near.remote_rtp)
            .await
            .expect("attacker send");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(150), phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "off-path attacker must be gated out end-to-end (RTPBleed)"
        );

        // The signalled peer A flows to B.
        phone_a
            .send_to(&rtp(0x1234_5678), near.remote_rtp)
            .await
            .expect("peer send");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x1234_5678));
        assert_eq!(from, far.remote_rtp, "B sees media from the engine far-RTP port");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_fails_cleanly_when_port_pool_exhausted_and_frees_on_delete() {
        // A non-mux call needs four endpoints (RTP + RTCP per leg); cap the pool at exactly four.
        let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(4));
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        let first = engine
            .handle(CLIENT, Command::Offer {
                call_id: "c1".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            })
            .await;
        assert!(matches!(first, CmdResult::Ok { .. }), "first offer fits the pool");

        let second = engine
            .handle(CLIENT, Command::Offer {
                call_id: "c2".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            })
            .await;
        assert!(
            matches!(second, CmdResult::Error { .. }),
            "an exhausted pool is a clean error, not a host-FD blowout"
        );

        // Tearing down the first call frees its four ports; the second offer now fits.
        let delete = engine
            .handle(CLIENT, Command::Delete {
                call_id: "c1".into(),
                from_tag: "a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
        let retry = engine
            .handle(CLIENT, Command::Offer {
                call_id: "c2".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            })
            .await;
        assert!(matches!(retry, CmdResult::Ok { .. }), "freed pool admits the call");
    }

    #[tokio::test]
    async fn a_call_is_private_to_its_creating_client() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let owner = ClientId(10);
        let intruder = ClientId(20);

        let offer = engine
            .handle(
                owner,
                Command::Offer {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(matches!(offer, CmdResult::Ok { .. }));

        // The intruder cannot see the call: both query and delete report it as unknown.
        let query = engine
            .handle(
                intruder,
                Command::Query {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(query, CmdResult::Error { .. }),
            "non-owner query is rejected"
        );
        let delete = engine
            .handle(
                intruder,
                Command::Delete {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(delete, CmdResult::Error { .. }),
            "non-owner delete is rejected"
        );

        // The intruder's delete did nothing — the owner still has its call.
        let owner_query = engine
            .handle(
                owner,
                Command::Query {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(owner_query, CmdResult::Ok { .. }),
            "owner still sees its call"
        );
    }

    #[tokio::test]
    async fn per_client_call_quota_is_enforced_and_freed_on_delete() {
        let engine = Engine::with_max_calls_per_client(UdpLoopbackDatapath::new(), 1);
        let client = ClientId(7);
        let (_a, addr_a) = phone().await;
        let (_b, addr_b) = phone().await;

        let first = engine
            .handle(
                client,
                Command::Offer {
                    call_id: "q1".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(matches!(first, CmdResult::Ok { .. }));

        let second = engine
            .handle(
                client,
                Command::Offer {
                    call_id: "q2".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(second, CmdResult::Error { .. }),
            "over quota is rejected"
        );

        // Freeing the first call returns the quota slot.
        let delete = engine
            .handle(
                client,
                Command::Delete {
                    call_id: "q1".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
        let retry = engine
            .handle(
                client,
                Command::Offer {
                    call_id: "q2".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(retry, CmdResult::Ok { .. }),
            "freed quota admits the call"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_calls_are_reaped_and_active_ones_survive() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "c".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        let _far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "c".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");
        assert_eq!(engine.session_count(), 1);

        // Advance to tick 4 (within the 5-tick window) and send media — stamps activity at tick 4.
        engine.datapath().advance_clock(4);
        phone_a
            .send_to(&rtp(0x1234_5678), near.remote_rtp)
            .await
            .expect("send");
        let _ = recv(&phone_b).await;

        // Tick 8: idle since the packet (tick 4) is 4 < 5 → recent media keeps the call alive.
        engine.datapath().advance_clock(4);
        assert!(
            engine.reap_idle(5).await.is_empty(),
            "recent media defers reaping"
        );
        assert_eq!(engine.session_count(), 1);

        // Tick 13: idle since tick 4 is 9 >= 5 → the silent call is reaped and its ports freed.
        engine.datapath().advance_clock(5);
        assert_eq!(engine.reap_idle(5).await, vec!["c".to_string()]);
        assert_eq!(engine.session_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaping_pushes_a_media_timeout_event_to_the_owner() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let client = ClientId(3);
        let events = engine.register_client(client);
        let (_phone, addr) = phone().await;

        engine
            .handle(
                client,
                Command::Offer {
                    call_id: "gone".into(),
                    from_tag: "ft".into(),
                    sdp: sdp_for(addr, false),
                    profile: Default::default(),
                },
            )
            .await;

        engine.datapath().advance_clock(10);
        assert_eq!(engine.reap_idle(5).await, vec!["gone".to_string()]);

        let event = events.try_recv().expect("a media-timeout event was pushed");
        assert_eq!(
            event,
            Event::MediaTimeout {
                call_id: "gone".into(),
                from_tag: "ft".into()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_offer_advertises_lite_and_the_endpoint_answers_checks() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        // A offers ICE.
        let offer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:AAAAAA\r\na=ice-pwd:apasswordapasswordapas\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
            ip = addr_a.ip(),
            port = addr_a.port()
        );
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ice".into(),
                    from_tag: "a".into(),
                    sdp: offer_sdp,
                    profile: Default::default(),
                },
            )
            .await;
        let offer_out = ok_sdp_text(&offer);
        assert!(offer_out.contains("a=ice-lite"), "engine offers ICE-lite to B");
        // The engine's advertised credentials (the same identity it installs on the endpoints).
        let advertised = sdp::parse(&offer_out).expect("parse engine offer");
        let engine_ufrag = advertised.ice_ufrag.clone().expect("engine ufrag");
        let engine_pwd = advertised.ice_pwd.clone().expect("engine pwd");

        // B answers with plain RTP (non-ICE).
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ice".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        let answer_out = ok_sdp_text(&answer);
        assert!(answer_out.contains("a=ice-lite"), "engine offers ICE-lite to A");
        let near = sdp::parse(&answer_out).expect("parse engine answer");

        // A runs a valid connectivity check against the engine's A-facing endpoint, signed with the
        // engine's advertised password.
        let username = format!("{engine_ufrag}:AAAAAA");
        let check = siphon_rtp_stun::binding_request(&[7u8; 12], &username, engine_pwd.as_bytes());
        phone_a
            .send_to(&check, near.remote_rtp)
            .await
            .expect("send check");

        // The endpoint answers with a Binding success response we can verify with the engine pwd.
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv response");
        let response = siphon_rtp_stun::parse(&buffer[..len]).expect("parse response");
        assert_eq!(response.message_type, siphon_rtp_stun::BINDING_SUCCESS);
        assert!(siphon_rtp_stun::verify_message_integrity(
            &buffer[..len],
            engine_pwd.as_bytes()
        ));
    }

    /// An SDP whose `c=` claims `ip` (not necessarily where its media actually arrives from).
    fn sdp_claiming(ip: &str, port: u16) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subnet_source_flag_admits_a_same_24_source() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        // A is signalled as 127.0.0.2 but its media actually arrives from 127.0.0.50 (same /24, e.g.
        // a carrier that re-NATs within a block); B is signalled at its real address.
        let (phone_a, _addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 50)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 51)).await;
        let profile = ProfileFlags {
            flags: vec!["subnet-source".to_string()],
            ..Default::default()
        };

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "subnet".into(),
                    from_tag: "a".into(),
                    sdp: sdp_claiming("127.0.0.2", 5000),
                    profile: profile.clone(),
                },
            )
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");

        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "subnet".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile,
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // 127.0.0.50 shares 127.0.0.0/24 with the signalled 127.0.0.2, so the subnet gate accepts it
        // (an exact gate would reject) and A's media relays to B.
        phone_a
            .send_to(&rtp(0x00AB_00AB), near.remote_rtp)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x00AB_00AB));
        assert_eq!(from, far.remote_rtp);
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relayed_rtcp_is_exported_to_the_hep_collector() {
        let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));

        // Stand in for VoIPmonitor's HEP input with a loopback UDP socket.
        let collector = UdpSocket::bind("127.0.0.1:0").await.expect("bind collector");
        let collector_addr = collector.local_addr().expect("collector addr");
        let exporter = HepExporter::connect(collector_addr).await.expect("connect");
        tokio::spawn(engine.clone().run_rtcp_export(exporter, 7));
        // Let the export task enable the RTCP observation tap before any media flows.
        tokio::task::yield_now().await;

        // A muxed call (RTCP rides the RTP port), so one send exercises the path.
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "qos".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let _far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "qos".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // A sends an RTCP SR through the relay (mux: on the near RTP port).
        let report = vec![0x80u8, 200, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44];
        phone_a
            .send_to(&report, near.remote_rtp)
            .await
            .expect("send rtcp");
        assert_eq!(recv(&phone_b).await.0, report, "RTCP relays to B");

        // The HEP collector receives a HEP3 packet carrying the RTCP, correlated by call-id.
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(2), collector.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv hep");
        let packet = &buffer[..len];
        assert_eq!(&packet[..4], b"HEP3");
        assert!(contains_bytes(packet, &report), "HEP carries the relayed RTCP");
        assert!(contains_bytes(packet, b"qos"), "HEP correlation id = call-id");
    }
}
