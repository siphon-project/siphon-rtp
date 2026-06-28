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
    Datapath, Endpoint, EndpointId, FlowAction, ForwardRule, IceConfig, LatchPolicy, ObservedRtcp,
    SourceFilter,
};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_hep::{protocol_type, Capture};
use siphon_rtp_proto::{CmdResult, Command, Event, ProfileFlags, SessionStats};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};

use crate::ice::{self, IceCredentials};
use crate::sdp::{self, EngineMedia, SecurityAdvertisement};
use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, BridgeOp, SrtpBridge};

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
}

/// The session engine, generic over a [`Datapath`] backend.
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
}

impl<D: Datapath> Engine<D> {
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
        }
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
    pub async fn handle(&self, client: ClientId, command: Command) -> CmdResult {
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
            other => CmdResult::Error {
                reason: format!("unsupported command: {}", command_name(&other)),
            },
        }
    }

    /// Allocate `count` endpoints, rolling back all of them if any allocation fails.
    async fn alloc_endpoints(&self, count: usize) -> Result<Vec<Endpoint>, String> {
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            match self.datapath.alloc_endpoint().await {
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

        // Two RTP endpoints, plus two companion RTCP endpoints unless the stream is muxed.
        let count = if info.rtcp_mux { 2 } else { 4 };
        let endpoints = match self.alloc_endpoints(count).await {
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

        *self.client_calls.entry(client).or_insert(0) += 1;
        // Index this call's endpoints so observed RTCP can be correlated back to the call-id.
        for endpoint in [Some(near_rtp), near_rtcp, Some(far_rtp), far_rtcp]
            .into_iter()
            .flatten()
        {
            self.endpoint_calls.insert(endpoint.id, call_id.clone());
        }
        self.calls.insert(
            call_id,
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
            },
        );
        ok_sdp(rewritten.sdp, None)
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
        let (near, far, ice_creds, far_local_crypto) = match self.calls.get(call_id) {
            Some(call) if call.owner == client => {
                if call.from_tag != from_tag {
                    return CmdResult::Error {
                        reason: "from_tag mismatch on answer".to_string(),
                    };
                }
                (call.near, call.far, call.ice.clone(), call.far_local_crypto)
            }
            _ => return unknown_call(call_id),
        };

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

        // ICE applies to a leg only when both ends use it: `near` faces A (which offered ICE iff we
        // minted creds), `far` faces B (ICE iff its answer carries ICE).
        let near_ice = ice_creds.is_some();
        let far_ice = ice_creds.is_some() && info.is_ice();

        if let Some(far_local) = far_local_crypto {
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
        } else {
            // Plain relay: the in-datapath Forward fast path. Each endpoint's rule gates its ingress
            // to the SDP-signalled peer and latches per policy (RTPBleed fix —
            // docs/security-and-nat.md §4): `near` receives from A (`near.remote_rtp`); `far` from B
            // (`info.remote_rtp`).
            if let Err(error) = self.datapath.install_flow(
                near.rtp.id,
                FlowAction::Forward(ingress_rule(
                    far.rtp.id,
                    Some(info.remote_rtp),
                    near.remote_rtp,
                    profile,
                    near_ice,
                )),
            ) {
                return error_result("install near->far RTP flow", &error);
            }
            if let Err(error) = self.datapath.install_flow(
                far.rtp.id,
                FlowAction::Forward(ingress_rule(
                    near.rtp.id,
                    near.remote_rtp,
                    Some(info.remote_rtp),
                    profile,
                    far_ice,
                )),
            ) {
                return error_result("install far->near RTP flow", &error);
            }

            // Companion RTCP relay when not muxed. (Under mux, RTCP rides the RTP endpoints already.)
            if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
                if let Err(error) = self.datapath.install_flow(
                    near_rtcp.id,
                    FlowAction::Forward(ingress_rule(
                        far_rtcp.id,
                        Some(info.remote_rtcp),
                        near.remote_rtcp,
                        profile,
                        near_ice,
                    )),
                ) {
                    return error_result("install near->far RTCP flow", &error);
                }
                if let Err(error) = self.datapath.install_flow(
                    far_rtcp.id,
                    FlowAction::Forward(ingress_rule(
                        near_rtcp.id,
                        near.remote_rtcp,
                        Some(info.remote_rtcp),
                        profile,
                        far_ice,
                    )),
                ) {
                    return error_result("install far->near RTCP flow", &error);
                }
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
                // Drop any SRTP-bridge flows first (a no-op for a plain relay), then free the sockets.
                self.bridge.deregister(endpoints.iter().copied());
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
                for endpoint in call.near.endpoint_ids().chain(call.far.endpoint_ids()) {
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

    /// A two-port SDP: RTP at `addr`, RTCP at `addr`+1 (default), optional `a=rtcp-mux`.
    fn sdp_for(rtp: SocketAddr, mux: bool) -> String {
        let mux_line = if mux { "a=rtcp-mux\r\n" } else { "" };
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n{mux_line}",
            ip = rtp.ip(),
            port = rtp.port()
        )
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
        tokio::spawn(run_redirect_dispatcher(rx, engine.bridge(), None));

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
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let result = engine
            .handle(CLIENT, Command::StopMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
            })
            .await;
        match result {
            CmdResult::Error { reason } => assert!(reason.contains("stop_media")),
            other => panic!("expected error, got {other:?}"),
        }
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
