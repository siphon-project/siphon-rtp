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
use siphon_rtp_proto::{CmdResult, Command, SessionStats};

use crate::sdp::{self, EngineMedia};

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

/// A negotiated (or half-negotiated) call: its two legs.
#[derive(Debug)]
struct Call {
    from_tag: String,
    to_tag: Option<String>,
    near: Leg,
    far: Leg,
}

/// The session engine, generic over a [`Datapath`] backend.
pub struct Engine<D: Datapath> {
    datapath: D,
    calls: DashMap<String, Call>,
}

impl<D: Datapath> Engine<D> {
    /// Create an engine over `datapath`.
    pub fn new(datapath: D) -> Self {
        Self {
            datapath,
            calls: DashMap::new(),
        }
    }

    /// Borrow the underlying datapath (used by tests and, later, the media pipeline).
    pub fn datapath(&self) -> &D {
        &self.datapath
    }

    /// Handle one control command, producing the result to return to the caller.
    pub async fn handle(&self, command: Command) -> CmdResult {
        match command {
            Command::Ping => CmdResult::Pong,
            Command::Offer {
                call_id,
                from_tag,
                sdp,
                ..
            } => self.offer(call_id, from_tag, &sdp).await,
            Command::Answer {
                call_id,
                from_tag,
                to_tag,
                sdp,
                ..
            } => self.answer(&call_id, &from_tag, to_tag, &sdp).await,
            Command::Delete { call_id, .. } => self.delete(&call_id).await,
            Command::Query { call_id, .. } => self.query(&call_id),
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

    async fn offer(&self, call_id: String, from_tag: String, sdp: &str) -> CmdResult {
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

        self.calls.insert(
            call_id,
            Call {
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

    async fn answer(&self, call_id: &str, from_tag: &str, to_tag: String, sdp: &str) -> CmdResult {
        // Snapshot the leg endpoints + near remotes under the guard, then release it.
        let (near, far) = match self.calls.get(call_id) {
            Some(call) => {
                if call.from_tag != from_tag {
                    return CmdResult::Error {
                        reason: "from_tag mismatch on answer".to_string(),
                    };
                }
                (call.near, call.far)
            }
            None => return unknown_call(call_id),
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

        // Install the bidirectional RTP relay (latching; the configured remote is the fallback).
        if let Err(error) = self.datapath.install_flow(
            near.rtp.id,
            FlowAction::Forward(ForwardRule::latching(far.rtp.id, Some(info.remote_rtp))),
        ) {
            return error_result("install near->far RTP flow", &error);
        }
        if let Err(error) = self.datapath.install_flow(
            far.rtp.id,
            FlowAction::Forward(ForwardRule::latching(near.rtp.id, near.remote_rtp)),
        ) {
            return error_result("install far->near RTP flow", &error);
        }

        // Companion RTCP relay when not muxed. (Under mux, RTCP rides the RTP endpoints already.)
        if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
            if let Err(error) = self.datapath.install_flow(
                near_rtcp.id,
                FlowAction::Forward(ForwardRule::latching(far_rtcp.id, Some(info.remote_rtcp))),
            ) {
                return error_result("install near->far RTCP flow", &error);
            }
            if let Err(error) = self.datapath.install_flow(
                far_rtcp.id,
                FlowAction::Forward(ForwardRule::latching(near_rtcp.id, near.remote_rtcp)),
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

    async fn delete(&self, call_id: &str) -> CmdResult {
        match self.calls.remove(call_id) {
            Some((_, call)) => {
                for endpoint in call.near.endpoint_ids().chain(call.far.endpoint_ids()) {
                    self.datapath.remove_endpoint(endpoint).await;
                }
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

    fn query(&self, call_id: &str) -> CmdResult {
        let Some(call) = self.calls.get(call_id) else {
            return unknown_call(call_id);
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

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
        assert_eq!(engine.handle(Command::Ping).await, CmdResult::Pong);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_relays_rtp_then_query_and_delete() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(Command::Offer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            })
            .await;
        let far_rtp = sdp::parse(&ok_sdp_text(&offer)).expect("parse far").remote_rtp;

        let answer = engine
            .handle(Command::Answer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            })
            .await;
        let near_rtp = sdp::parse(&ok_sdp_text(&answer)).expect("parse near").remote_rtp;

        phone_a.send_to(b"rtp-a", near_rtp).await.expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, b"rtp-a");
        assert_eq!(from, far_rtp);

        phone_b.send_to(b"rtp-b", far_rtp).await.expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, b"rtp-b");
        assert_eq!(from, near_rtp);

        // Stats: poll for packets_out to settle (counted after the forwarding send).
        let mut stats = SessionStats::default();
        for _ in 0..50 {
            if let CmdResult::Ok { stats: Some(s), .. } = engine
                .handle(Command::Query {
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
            .handle(Command::Delete {
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
            .handle(Command::Offer {
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
            .handle(Command::Answer {
                call_id: "rtcp-call".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            })
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // RTP relays on the RTP ports.
        rtp_a.send_to(b"rtp", near.remote_rtp).await.expect("rtp a");
        assert_eq!(recv(&rtp_b).await.0, b"rtp");

        // RTCP relays on the dedicated RTCP ports.
        rtcp_a.send_to(b"rtcp-sr", near.remote_rtcp).await.expect("rtcp a");
        let (data, from) = recv(&rtcp_b).await;
        assert_eq!(data, b"rtcp-sr");
        assert_eq!(from, far.remote_rtcp, "B's RTCP arrives from the engine far-RTCP port");

        let _ = (addr_rtcp_a, addr_rtcp_b);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtcp_mux_relays_both_on_one_port() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(Command::Offer {
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
            .handle(Command::Answer {
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
            .handle(Command::Answer {
                call_id: "nope".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5000 RTP/AVP 0\r\n".into(),
                profile: Default::default(),
            })
            .await;
        assert!(matches!(answer, CmdResult::Error { .. }));

        let delete = engine
            .handle(Command::Delete {
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
            .handle(Command::StopMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
            })
            .await;
        match result {
            CmdResult::Error { reason } => assert!(reason.contains("stop_media")),
            other => panic!("expected error, got {other:?}"),
        }
    }
}
