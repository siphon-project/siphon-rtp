//! The userspace SRTP bridge — the `Redirect` slow path that terminates SRTP/SRTCP on a secure
//! (`RTP/SAVP`) leg and relays plaintext on the insecure (`RTP/AVP`) leg (Scenario 1: an AMR-WB
//! `RTP/AVP` ↔ `RTP/SAVP` bridge, codec passthrough).
//!
//! Where the datapath `Forward` fast path re-emits a datagram untouched, a secure-bridge call sets
//! **every** leg endpoint to [`FlowAction::Redirect`](siphon_rtp_datapath::FlowAction::Redirect): the
//! redirect dispatcher routes each packet here by [`EndpointId`], and this bridge applies the
//! per-direction crypto and forwards via [`Datapath::send`]. Because `Redirect` bypasses the
//! datapath's signalled-source gate, the bridge re-enforces it (RTPBleed defence,
//! docs/security-and-nat.md §4 layer 2) before doing any crypto.
//!
//! One [`SecureLeg`] (the secure side's four SRTP/SRTCP contexts) is shared by both directions of a
//! call: the plain→secure flow `protect`s with it, the secure→plain flow `unprotect`s with it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_srtp::leg::SecureLeg;

/// The crypto a bridge flow applies to ingress before forwarding it out the peer endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOp {
    /// Plain ingress → encrypt for the secure peer (`SecureLeg::protect`).
    Encrypt,
    /// Secure ingress → decrypt for the plain peer (`SecureLeg::unprotect`).
    Decrypt,
}

/// One redirected endpoint's plan: how to gate it, what crypto to apply, and where to forward.
#[derive(Debug, Clone, Copy)]
pub struct BridgeFlowPlan {
    /// The redirected endpoint this flow handles ingress for.
    pub endpoint: EndpointId,
    /// Crypto applied to each accepted datagram before forwarding.
    pub op: BridgeOp,
    /// Signalled-source gate — only this source may drive the flow (RTPBleed defence).
    pub accepted_source: SourceFilter,
    /// The endpoint to transmit the transformed datagram from (the peer-facing socket).
    pub out_endpoint: EndpointId,
    /// Where to transmit it (the peer's negotiated address).
    pub out_dst: SocketAddr,
}

/// A whole call's bridge plan: the shared secure leg and its 2 (muxed) or 4 endpoint flows.
pub struct BridgeCallPlan {
    /// The secure side's SRTP/SRTCP contexts, shared by both directions.
    pub leg: SecureLeg,
    /// One flow per redirected endpoint (near.rtp/far.rtp, plus the RTCP pair when not muxed).
    pub flows: Vec<BridgeFlowPlan>,
}

/// An installed bridge flow: a plan plus the shared secure-leg handle.
struct Flow {
    op: BridgeOp,
    accepted_source: SourceFilter,
    out_endpoint: EndpointId,
    out_dst: SocketAddr,
    leg: Arc<Mutex<SecureLeg>>,
}

/// The bridge registry: redirected endpoint → its `Flow`. Shared (`Arc`) between the control path
/// (which registers/deregisters per call) and the redirect dispatcher (which calls [`Self::handle`]).
pub struct SrtpBridge<D: Datapath> {
    datapath: D,
    flows: DashMap<EndpointId, Flow>,
}

impl<D: Datapath> SrtpBridge<D> {
    /// Create an empty bridge over `datapath` (a clone of the engine's datapath, used to transmit).
    #[must_use]
    pub fn new(datapath: D) -> Self {
        Self {
            datapath,
            flows: DashMap::new(),
        }
    }

    /// Register a call's bridge flows, all sharing one [`SecureLeg`]. The caller installs
    /// `FlowAction::Redirect` on each endpoint and tears them down on delete via [`Self::deregister`].
    pub fn register(&self, plan: BridgeCallPlan) {
        let leg = Arc::new(Mutex::new(plan.leg));
        for flow in plan.flows {
            self.flows.insert(
                flow.endpoint,
                Flow {
                    op: flow.op,
                    accepted_source: flow.accepted_source,
                    out_endpoint: flow.out_endpoint,
                    out_dst: flow.out_dst,
                    leg: leg.clone(),
                },
            );
        }
    }

    /// Drop the flows for `endpoints` (a call's endpoints) — the bridge half of call teardown.
    pub fn deregister(&self, endpoints: impl IntoIterator<Item = EndpointId>) {
        for endpoint in endpoints {
            self.flows.remove(&endpoint);
        }
    }

    /// Whether this bridge owns `endpoint` — the dispatcher's routing predicate (bridge vs TURN).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.flows.contains_key(&endpoint)
    }

    /// Handle one redirected datagram: gate the source, apply the flow's crypto, and forward it.
    /// Anything that fails to gate or transform is dropped (never forwarded into the void).
    pub async fn handle(&self, packet: RxPacket) {
        // Snapshot the flow and release the map guard before any crypto or `.await`.
        let Some((op, accepted_source, out_endpoint, out_dst, leg)) =
            self.flows.get(&packet.endpoint).map(|flow| {
                (
                    flow.op,
                    flow.accepted_source,
                    flow.out_endpoint,
                    flow.out_dst,
                    flow.leg.clone(),
                )
            })
        else {
            return; // not a bridge endpoint (dispatcher should have routed it elsewhere)
        };

        // RTPBleed gate: Redirect skips the datapath's source check, so re-enforce it here.
        if !accepted_source.accepts(packet.source.ip()) {
            tracing::debug!(
                endpoint = ?packet.endpoint,
                source = %packet.source,
                "bridge dropped packet from unsignalled source"
            );
            return;
        }

        let mut out = Vec::new();
        let transformed = {
            let Ok(mut leg) = leg.lock() else {
                tracing::error!("bridge secure-leg mutex poisoned; dropping packet");
                return;
            };
            match op {
                BridgeOp::Encrypt => leg.protect(&packet.data, &mut out),
                BridgeOp::Decrypt => leg.unprotect(&packet.data, &mut out),
            }
        };
        if let Err(error) = transformed {
            tracing::debug!(?error, ?op, "bridge crypto failed; dropping packet");
            return;
        }
        if let Err(error) = self.datapath.send(out_endpoint, out_dst, &out).await {
            tracing::debug!(%error, "bridge forward send failed");
        }
    }
}

/// Run the redirect dispatcher: drain the datapath's shared Redirect stream and route each datagram
/// by [`EndpointId`] — bridge-owned endpoints to the [`SrtpBridge`], media-owned endpoints to the
/// per-call media actor ([`crate::media_pipeline::MediaRegistry`]), WebSocket-bridged endpoints to
/// the [`crate::ws_bridge::WsRegistry`], conference-owned endpoints to the
/// [`crate::conference::ConferenceRegistry`], and everything else to the TURN relay sink (when TURN
/// is running). This is the single owner of `datapath.rx()` the datapath design calls for ("a single
/// dispatcher should own it and route each RxPacket to the owning subsystem by EndpointId"). Routing
/// order is bridge → media → ws → conference → turn. Runs until the redirect stream closes.
pub async fn run_redirect_dispatcher<D: Datapath>(
    redirect_rx: flume::Receiver<RxPacket>,
    bridge: Arc<SrtpBridge<D>>,
    media: Arc<crate::media_pipeline::MediaRegistry>,
    ws: Arc<crate::ws_bridge::WsRegistry>,
    conference: Arc<crate::conference::ConferenceRegistry>,
    turn_relay: Option<flume::Sender<RxPacket>>,
) {
    while let Ok(packet) = redirect_rx.recv_async().await {
        if bridge.owns(packet.endpoint) {
            bridge.handle(packet).await;
        } else if media.owns(packet.endpoint) {
            media.dispatch(packet);
        } else if ws.owns(packet.endpoint) {
            ws.dispatch(packet);
        } else if conference.owns(packet.endpoint) {
            conference.dispatch(packet);
        } else if let Some(turn) = &turn_relay {
            // Drop-newest on a full TURN mailbox — late media is worthless.
            if turn.try_send(packet).is_err() {
                tracing::trace!("TURN relay sink full or closed; dropping redirected datagram");
            }
        } else {
            tracing::debug!(
                endpoint = ?packet.endpoint,
                "redirected datagram with no consumer; dropped"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use siphon_rtp_datapath::FlowAction;
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
    use siphon_rtp_srtp::SrtpContext;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    const SHORT: Duration = Duration::from_secs(1);
    const NEGATIVE: Duration = Duration::from_millis(150);

    fn key(seed: u8) -> SrtpKeyMaterial {
        SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30 bytes")
    }

    fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"amr-wb-frame----");
        packet
    }

    async fn phone(ip: Ipv4Addr) -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((ip, 0)).await.expect("bind phone");
        let addr = socket.local_addr().expect("addr");
        (socket, addr)
    }

    async fn recv(socket: &UdpSocket) -> Vec<u8> {
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(SHORT, socket.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv");
        buffer[..len].to_vec()
    }

    /// A live bridge over a loopback datapath: plain (AVP) endpoint facing phone A, secure (SAVP)
    /// endpoint facing phone B, with a dispatcher draining the redirect stream into the bridge.
    struct Harness {
        // Kept alive: dropping the datapath aborts the endpoint receive tasks.
        _datapath: UdpLoopbackDatapath,
        _bridge: Arc<SrtpBridge<UdpLoopbackDatapath>>,
        /// Engine's plain endpoint — phone A sends RTP here.
        plain_addr: SocketAddr,
        /// Engine's secure endpoint — phone B sends SRTP here.
        secure_addr: SocketAddr,
        /// Engine's offered key (the secure peer decrypts engine→peer media with it).
        local: SrtpKeyMaterial,
        /// Secure peer's answered key (the peer encrypts peer→engine media with it).
        remote: SrtpKeyMaterial,
    }

    /// Build the full live bridge with the two phones wired in, returning everything a test drives.
    async fn live_bridge() -> (Harness, (UdpSocket, SocketAddr), (UdpSocket, SocketAddr)) {
        let datapath = UdpLoopbackDatapath::new();
        let plain = datapath.alloc_endpoint().await.expect("alloc plain");
        let secure = datapath.alloc_endpoint().await.expect("alloc secure");
        let (phone_a, addr_a) = phone(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone(Ipv4Addr::new(127, 0, 0, 3)).await;

        datapath.install_flow(plain.id, FlowAction::Redirect).expect("redirect plain");
        datapath.install_flow(secure.id, FlowAction::Redirect).expect("redirect secure");

        let local = key(0xAA);
        let remote = key(0xBB);
        let bridge = Arc::new(SrtpBridge::new(datapath.clone()));
        bridge.register(BridgeCallPlan {
            leg: SecureLeg::new(&local, &remote),
            flows: vec![
                BridgeFlowPlan {
                    endpoint: plain.id,
                    op: BridgeOp::Encrypt,
                    accepted_source: SourceFilter::Exact(addr_a.ip()),
                    out_endpoint: secure.id,
                    out_dst: addr_b,
                },
                BridgeFlowPlan {
                    endpoint: secure.id,
                    op: BridgeOp::Decrypt,
                    accepted_source: SourceFilter::Exact(addr_b.ip()),
                    out_endpoint: plain.id,
                    out_dst: addr_a,
                },
            ],
        });

        let rx = datapath.rx();
        let dispatch = bridge.clone();
        tokio::spawn(async move {
            while let Ok(packet) = rx.recv_async().await {
                dispatch.handle(packet).await;
            }
        });

        let harness = Harness {
            plain_addr: plain.local_addr,
            secure_addr: secure.local_addr,
            local,
            remote,
            _datapath: datapath,
            _bridge: bridge,
        };
        (harness, (phone_a, addr_a), (phone_b, addr_b))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_to_secure_is_encrypted_for_the_peer() {
        let (harness, (phone_a, _), (phone_b, _)) = live_bridge().await;
        let plaintext = rtp(1000, 0x1111_1111);

        // Phone A (plain) → engine plain endpoint → bridge encrypts → secure endpoint → phone B.
        phone_a.send_to(&plaintext, harness.plain_addr).await.expect("send a");
        let srtp = recv(&phone_b).await;
        assert_ne!(srtp, plaintext, "phone B receives SRTP, not plaintext");

        // Phone B holds the engine's offered (local) key and decrypts it back to the original.
        let mut decrypt = SrtpContext::from_key_material(&harness.local);
        let mut recovered = Vec::new();
        decrypt.unprotect(&srtp, &mut recovered).expect("peer decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn secure_to_plain_is_decrypted_for_the_peer() {
        let (harness, (phone_a, _), (phone_b, _)) = live_bridge().await;
        let plaintext = rtp(2000, 0x2222_2222);

        // Phone B encrypts with its answered (remote) key and sends SRTP to the secure endpoint.
        let mut encrypt = SrtpContext::from_key_material(&harness.remote);
        let mut srtp = Vec::new();
        encrypt.protect(&plaintext, &mut srtp).expect("peer encrypt");
        phone_b.send_to(&srtp, harness.secure_addr).await.expect("send b");

        // Bridge decrypts → plain endpoint → phone A receives the original plaintext.
        let recovered = recv(&phone_a).await;
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn off_source_packet_is_gated_out() {
        let (harness, _phone_a, (phone_b, _)) = live_bridge().await;
        // An attacker on a different IP sprays the plain endpoint — the bridge's source gate drops
        // it before any crypto/forward (RTPBleed defence on the Redirect path).
        let (attacker, _) = phone(Ipv4Addr::new(127, 0, 0, 9)).await;
        attacker.send_to(&rtp(1, 0xDEAD), harness.plain_addr).await.expect("attacker send");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(NEGATIVE, phone_b.recv_from(&mut scratch)).await.is_err(),
            "an off-source packet must never reach the peer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn garbage_on_the_secure_leg_fails_auth_and_is_dropped() {
        let (harness, (phone_a, _), (phone_b, _)) = live_bridge().await;
        // A forged/unauthenticated datagram from the signalled secure peer fails SRTP auth → dropped.
        phone_b.send_to(&rtp(1, 0x3333), harness.secure_addr).await.expect("send garbage");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(NEGATIVE, phone_a.recv_from(&mut scratch)).await.is_err(),
            "an unauthenticated SRTP packet must not be forwarded to the plain leg"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatcher_routes_owned_to_bridge_and_rest_to_turn() {
        let datapath = UdpLoopbackDatapath::new();
        let owned = datapath.alloc_endpoint().await.expect("alloc");
        let bridge = Arc::new(SrtpBridge::new(datapath));
        bridge.register(BridgeCallPlan {
            leg: SecureLeg::new(&key(1), &key(2)),
            flows: vec![BridgeFlowPlan {
                endpoint: owned.id,
                op: BridgeOp::Decrypt,
                accepted_source: SourceFilter::Any,
                out_endpoint: owned.id,
                out_dst: owned.local_addr,
            }],
        });

        let (feed, redirect_rx) = flume::unbounded();
        let (turn_tx, turn_rx) = flume::bounded(16);
        let media = Arc::new(crate::media_pipeline::MediaRegistry::default());
        let ws = Arc::new(crate::ws_bridge::WsRegistry::default());
        let conference = Arc::new(crate::conference::ConferenceRegistry::default());
        tokio::spawn(run_redirect_dispatcher(
            redirect_rx,
            bridge.clone(),
            media,
            ws,
            conference,
            Some(turn_tx),
        ));

        // A datagram for an endpoint the bridge does not own is routed to the TURN sink.
        let other = EndpointId(987_654);
        feed.send(RxPacket {
            endpoint: other,
            source: "127.0.0.1:5000".parse().expect("addr"),
            data: Bytes::from_static(b"turn-relay-data"),
        })
        .expect("feed");
        let routed = timeout(SHORT, turn_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(routed.endpoint, other);

        // A datagram for a bridge-owned endpoint is consumed by the bridge (it fails crypto and is
        // dropped here, but it must never be misrouted to TURN).
        feed.send(RxPacket {
            endpoint: owned.id,
            source: "127.0.0.1:5001".parse().expect("addr"),
            data: Bytes::from_static(b"not-a-valid-srtp-packet"),
        })
        .expect("feed");
        assert!(
            timeout(NEGATIVE, turn_rx.recv_async()).await.is_err(),
            "a bridge-owned datagram must not be routed to TURN"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deregister_stops_owning_the_endpoints() {
        let (harness, (_phone_a, _), _phone_b) = live_bridge().await;
        let _ = &harness;
        // owns() reflects registration; after deregister the dispatcher routes elsewhere.
        // (Exercised via the public predicate on a fresh bridge to avoid racing the live dispatcher.)
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        let bridge = SrtpBridge::new(datapath);
        bridge.register(BridgeCallPlan {
            leg: SecureLeg::new(&key(1), &key(2)),
            flows: vec![BridgeFlowPlan {
                endpoint: endpoint.id,
                op: BridgeOp::Decrypt,
                accepted_source: SourceFilter::Any,
                out_endpoint: endpoint.id,
                out_dst: endpoint.local_addr,
            }],
        });
        assert!(bridge.owns(endpoint.id));
        bridge.deregister([endpoint.id]);
        assert!(!bridge.owns(endpoint.id));
    }
}
