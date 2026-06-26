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
use siphon_rtp_datapath::{Datapath, Endpoint, EndpointId, FlowAction, ForwardRule};
use siphon_rtp_proto::{CmdResult, Command, ProfileFlags, SessionStats};

use crate::sdp::{self, EngineMedia};

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
    from_tag: String,
    to_tag: Option<String>,
    near: Leg,
    far: Leg,
}

/// The session engine, generic over a [`Datapath`] backend.
pub struct Engine<D: Datapath> {
    datapath: D,
    calls: DashMap<String, Call>,
    /// Maximum concurrent calls per control client; `usize::MAX` is unbounded.
    max_calls_per_client: usize,
    /// Live call count per client, for the per-client quota.
    client_calls: DashMap<ClientId, usize>,
}

impl<D: Datapath> Engine<D> {
    /// Create an engine over `datapath` with no per-client call quota.
    pub fn new(datapath: D) -> Self {
        Self::with_max_calls_per_client(datapath, usize::MAX)
    }

    /// Create an engine that admits at most `max_calls_per_client` concurrent calls per control
    /// client — a soft DoS quota (the datapath media-port pool is the hard cap).
    pub fn with_max_calls_per_client(datapath: D, max_calls_per_client: usize) -> Self {
        Self {
            datapath,
            calls: DashMap::new(),
            max_calls_per_client,
            client_calls: DashMap::new(),
        }
    }

    /// Borrow the underlying datapath (used by tests and, later, the media pipeline).
    pub fn datapath(&self) -> &D {
        &self.datapath
    }

    /// Number of live calls in the session registry.
    ///
    /// Used by the memory-leak soak to confirm the registry drains on teardown, and (later) by the
    /// metrics surface as the `sessions` gauge.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.calls.len()
    }

    /// Handle one control command from `client`, producing the result to return to the caller.
    pub async fn handle(&self, client: ClientId, command: Command) -> CmdResult {
        match command {
            Command::Ping => CmdResult::Pong,
            Command::Offer {
                call_id,
                from_tag,
                sdp,
                ..
            } => self.offer(client, call_id, from_tag, &sdp).await,
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
        let rewritten = match sdp::rewrite(sdp, engine) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                self.free(&endpoints).await;
                return CmdResult::Error {
                    reason: format!("offer SDP rewrite failed: {error}"),
                };
            }
        };

        *self.client_calls.entry(client).or_insert(0) += 1;
        self.calls.insert(
            call_id,
            Call {
                owner: client,
                created_tick: self.datapath.now_ticks(),
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
        let (near, far) = match self.calls.get(call_id) {
            Some(call) if call.owner == client => {
                if call.from_tag != from_tag {
                    return CmdResult::Error {
                        reason: "from_tag mismatch on answer".to_string(),
                    };
                }
                (call.near, call.far)
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
        let rewritten = match sdp::rewrite(sdp, engine) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer SDP rewrite failed: {error}"),
                }
            }
        };

        // Install the bidirectional RTP relay. Each endpoint's rule gates its ingress to the
        // SDP-signalled peer and latches per policy (RTPBleed fix — docs/security-and-nat.md §4):
        // `near` receives from A (`near.remote_rtp`); `far` receives from B (`info.remote_rtp`).
        if let Err(error) = self.datapath.install_flow(
            near.rtp.id,
            FlowAction::Forward(ingress_rule(
                far.rtp.id,
                Some(info.remote_rtp),
                near.remote_rtp,
                profile,
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
                )),
            ) {
                return error_result("install far->near RTCP flow", &error);
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
                for endpoint in call.near.endpoint_ids().chain(call.far.endpoint_ids()) {
                    self.datapath.remove_endpoint(endpoint).await;
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
                }
                self.release_client_call(call.owner);
                reaped.push(call_id);
            }
        }
        reaped
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
) -> ForwardRule {
    let symmetric = profile.flags.iter().any(|flag| flag == "symmetric");
    match (symmetric, expected_source) {
        (false, Some(addr)) => ForwardRule::signalled(out_endpoint, out_dst, addr.ip()),
        // Symmetric leg, or the peer's address is not yet known: accept any source and latch.
        _ => ForwardRule::symmetric(out_endpoint, out_dst),
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

    #[tokio::test]
    async fn ping_pongs() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        assert_eq!(engine.handle(CLIENT, Command::Ping).await, CmdResult::Pong);
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
}
