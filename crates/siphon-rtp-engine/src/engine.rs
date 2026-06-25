//! The session engine: maps control [`Command`]s onto datapath endpoints and relay flows.
//!
//! The port model mirrors rtpengine. A call owns two engine endpoints:
//! - `near` — the socket the **offerer** (A) transmits to;
//! - `far` — the socket the **answerer** (B) transmits to.
//!
//! `offer` allocates both, records A's media address, and returns SDP advertising `far` (the
//! address B will send to). `answer` records B's media address, returns SDP advertising `near`
//! (the address A will send to), and installs the two relay flows. Each flow latches, so once a
//! party's packets are seen the relay replies to their observed source (symmetric RTP / NAT).
//!
//! The per-call **actor** (flume mailbox + owned media pipeline) arrives with the slow-path media
//! work; for plain relay the datapath's per-endpoint receive tasks are the data-plane workers, so
//! the engine here is a synchronous-ish session map over the async datapath.

use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, Endpoint, FlowAction, ForwardRule};
use siphon_rtp_proto::{CmdResult, Command, SessionStats};

use crate::sdp;

/// A negotiated (or half-negotiated) call: its two engine endpoints and learned remote addresses.
#[derive(Debug)]
struct Call {
    from_tag: String,
    to_tag: Option<String>,
    /// Endpoint the offerer (A) sends to.
    near: Endpoint,
    /// Endpoint the answerer (B) sends to.
    far: Endpoint,
    /// A's media address (forward target toward A), learned from the offer.
    remote_near: Option<std::net::SocketAddr>,
    /// B's media address (forward target toward B), learned from the answer.
    remote_far: Option<std::net::SocketAddr>,
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
            } => self.answer(&call_id, &from_tag, to_tag, &sdp),
            Command::Delete { call_id, .. } => self.delete(&call_id).await,
            Command::Query { call_id, .. } => self.query(&call_id),
            other => CmdResult::Error {
                reason: format!("unsupported command: {}", command_name(&other)),
            },
        }
    }

    async fn offer(&self, call_id: String, from_tag: String, sdp: &str) -> CmdResult {
        let near = match self.datapath.alloc_endpoint().await {
            Ok(endpoint) => endpoint,
            Err(error) => return error_result("alloc near endpoint", &error),
        };
        let far = match self.datapath.alloc_endpoint().await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                self.datapath.remove_endpoint(near.id).await;
                return error_result("alloc far endpoint", &error);
            }
        };

        // The rewritten offer is delivered to B, so it must advertise `far` (where B sends).
        let rewritten = match sdp::rewrite(sdp, far.local_addr) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                self.datapath.remove_endpoint(near.id).await;
                self.datapath.remove_endpoint(far.id).await;
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
                near,
                far,
                remote_near: Some(rewritten.remote),
                remote_far: None,
            },
        );
        CmdResult::Ok {
            sdp: Some(rewritten.sdp),
            duration_ms: None,
            to_tag: None,
            stats: None,
        }
    }

    fn answer(&self, call_id: &str, from_tag: &str, to_tag: String, sdp: &str) -> CmdResult {
        // Extract the immutable endpoint handles + remote_near under the guard, then drop it
        // before touching the datapath flow table.
        let (near, far, remote_near) = match self.calls.get(call_id) {
            Some(call) => {
                if call.from_tag != from_tag {
                    return CmdResult::Error {
                        reason: "from_tag mismatch on answer".to_string(),
                    };
                }
                (call.near, call.far, call.remote_near)
            }
            None => return unknown_call(call_id),
        };

        // The rewritten answer is delivered to A, so it must advertise `near` (where A sends).
        let rewritten = match sdp::rewrite(sdp, near.local_addr) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer SDP rewrite failed: {error}"),
                }
            }
        };
        let remote_far = rewritten.remote;

        // Install the bidirectional relay. Latching means the configured remote is a fallback
        // until the party's first packet is observed.
        if let Err(error) = self.datapath.install_flow(
            near.id,
            FlowAction::Forward(ForwardRule::latching(far.id, Some(remote_far))),
        ) {
            return error_result("install near->far flow", &error);
        }
        if let Err(error) = self.datapath.install_flow(
            far.id,
            FlowAction::Forward(ForwardRule::latching(near.id, remote_near)),
        ) {
            return error_result("install far->near flow", &error);
        }

        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.to_tag = Some(to_tag.clone());
            call.remote_far = Some(remote_far);
        }
        CmdResult::Ok {
            sdp: Some(rewritten.sdp),
            duration_ms: None,
            to_tag: Some(to_tag),
            stats: None,
        }
    }

    async fn delete(&self, call_id: &str) -> CmdResult {
        match self.calls.remove(call_id) {
            Some((_, call)) => {
                self.datapath.remove_endpoint(call.near.id).await;
                self.datapath.remove_endpoint(call.far.id).await;
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
        let near = self.datapath.stats(call.near.id).unwrap_or_default();
        let far = self.datapath.stats(call.far.id).unwrap_or_default();
        let stats = SessionStats {
            packets_in: near.packets_in + far.packets_in,
            packets_out: near.packets_out + far.packets_out,
            bytes_in: near.bytes_in + far.bytes_in,
            bytes_out: near.bytes_out + far.bytes_out,
            packets_lost: near.packets_dropped + far.packets_dropped,
        };
        CmdResult::Ok {
            sdp: None,
            duration_ms: None,
            to_tag: None,
            stats: Some(stats),
        }
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

    fn sdp_for(addr: SocketAddr) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n",
            ip = addr.ip(),
            port = addr.port()
        )
    }

    fn ok_sdp(result: &CmdResult) -> String {
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
    async fn offer_answer_relays_both_ways_then_query_and_delete() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // Offer from A. The rewritten SDP advertises the engine's far (B-facing) port.
        let offer_result = engine
            .handle(Command::Offer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a),
                profile: Default::default(),
            })
            .await;
        let far_addr = sdp::rewrite(&ok_sdp(&offer_result), "127.0.0.1:1".parse().unwrap())
            .expect("parse far")
            .remote;

        // Answer from B. The rewritten SDP advertises the engine's near (A-facing) port.
        let answer_result = engine
            .handle(Command::Answer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b),
                profile: Default::default(),
            })
            .await;
        let near_addr = sdp::rewrite(&ok_sdp(&answer_result), "127.0.0.1:1".parse().unwrap())
            .expect("parse near")
            .remote;

        // A -> near -> B.
        phone_a.send_to(b"rtp-from-a", near_addr).await.expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, b"rtp-from-a");
        assert_eq!(from, far_addr, "B sees media from the engine far port");

        // B -> far -> A.
        phone_b.send_to(b"rtp-from-b", far_addr).await.expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, b"rtp-from-b");
        assert_eq!(from, near_addr, "A sees media from the engine near port");

        // Query aggregates both legs. `packets_in` is counted before forwarding (so it is exact
        // once both datagrams are delivered); `packets_out` is counted just after the forwarding
        // send returns, so poll briefly for it to settle.
        let mut stats = SessionStats::default();
        for _ in 0..50 {
            let query = engine
                .handle(Command::Query {
                    call_id: "call-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                })
                .await;
            match query {
                CmdResult::Ok { stats: Some(snapshot), .. } => stats = snapshot,
                other => panic!("expected stats, got {other:?}"),
            }
            if stats.packets_out == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(stats.packets_in, 2, "one datagram received on each leg");
        assert_eq!(stats.packets_out, 2, "one datagram forwarded out of each leg");

        // Delete tears the call down.
        let delete = engine
            .handle(Command::Delete {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
        let requery = engine
            .handle(Command::Query {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(requery, CmdResult::Error { .. }), "call is gone");
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
