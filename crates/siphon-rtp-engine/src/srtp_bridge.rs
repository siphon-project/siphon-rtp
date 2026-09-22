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
//! A call carries up to two [`SecureLeg`]s — one per party that negotiated SRTP — and each flow says
//! which of them decrypts what arrives and which encrypts what leaves. A one-sided bridge names a
//! single leg and pays for one transform per datagram: the plain→secure flow `protect`s with it, the
//! secure→plain flow `unprotect`s with it. A **transcrypt** (RFC 4568 SDES on both legs, under two
//! different keys, which is what two SRTP-only desk phones negotiate) names both and runs
//! `unprotect` then `protect` — the payload is never decoded, so any codec crosses, including ones
//! the engine cannot decode. The plaintext in between is a stack buffer that never reaches a socket.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_srtp::leg::{SecureLeg, SecureLegRollover};

use crate::dtls_bridge::DtlsBridge;
use crate::x3::X3Tap;

/// Which of a call's two parties owns the SRTP/SRTCP contexts one side of a bridge flow reaches for.
///
/// A one-sided bridge has a single leg and could leave it implicit, which is what the crypto op used
/// to do. A **transcrypt** cannot: each of its two flows decrypts with one party's contexts and
/// re-encrypts with the *other's*, so "which key" is not derivable from "which direction". Naming the
/// leg per side makes all three shapes one mechanism rather than two ops plus a special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeLeg {
    /// The near (A, offerer-facing) party's contexts.
    Near,
    /// The far (B, answerer-facing) party's contexts.
    Far,
}

/// One redirected endpoint's plan: how to gate it, which key decrypts what arrives and which
/// encrypts what leaves, and where to forward.
///
/// The three shapes this expresses, all as the same two fields:
/// - **plain → secure** (`Srtp` toward B): `ingress_leg: None`, `egress_leg: Some(Far)`;
/// - **secure → plain** (`SrtpOfferer`, A's endpoint): `ingress_leg: Some(Near)`, `egress_leg: None`;
/// - **transcrypt** (both parties SDES, A's endpoint): `ingress_leg: Some(Near)`,
///   `egress_leg: Some(Far)` — the plaintext exists only as an intermediate buffer inside
///   [`SrtpBridge::handle`] and never reaches a socket.
#[derive(Debug, Clone, Copy)]
pub struct BridgeFlowPlan {
    /// The redirected endpoint this flow handles ingress for.
    pub endpoint: EndpointId,
    /// Decrypt each accepted datagram with this party's leg; `None` when the ingress is plaintext.
    pub ingress_leg: Option<BridgeLeg>,
    /// Encrypt each forwarded datagram with this party's leg; `None` when the egress is plaintext.
    pub egress_leg: Option<BridgeLeg>,
    /// Signalled-source gate — only this source may drive the flow (RTPBleed defence).
    pub accepted_source: SourceFilter,
    /// The endpoint to transmit the transformed datagram from (the peer-facing socket).
    pub out_endpoint: EndpointId,
    /// Where to transmit it (the peer's negotiated address).
    pub out_dst: SocketAddr,
}

/// A whole call's bridge plan: whichever parties are secure, and its 2 (muxed) or 4 endpoint flows.
///
/// At least one leg is always present — a bridge with neither is a plain relay, which belongs on the
/// datapath's `Forward` fast path, not here. Both are present exactly for a transcrypt.
pub struct BridgeCallPlan {
    /// The near (A) party's SRTP/SRTCP contexts, when A is the secure side.
    pub near_leg: Option<SecureLeg>,
    /// The far (B) party's contexts, when B is the secure side.
    pub far_leg: Option<SecureLeg>,
    /// One flow per redirected endpoint (near.rtp/far.rtp, plus the RTCP pair when not muxed).
    pub flows: Vec<BridgeFlowPlan>,
}

/// One side of an installed flow's key: which party owns it, and that party's shared contexts. The
/// party is kept beside the handle because the handle alone cannot say whose key it is, and the HA
/// export ([`SrtpBridge::flow_plans`]) has to reproduce the plan it was built from.
#[derive(Clone)]
struct FlowLeg {
    party: BridgeLeg,
    leg: Arc<Mutex<SecureLeg>>,
}

/// An installed bridge flow: a plan with its leg references resolved to the call's shared handles.
struct Flow {
    accepted_source: SourceFilter,
    out_endpoint: EndpointId,
    out_dst: SocketAddr,
    /// Decrypts this endpoint's ingress; `None` when it arrives in the clear.
    ingress_leg: Option<FlowLeg>,
    /// Encrypts what is forwarded; `None` when it leaves in the clear.
    egress_leg: Option<FlowLeg>,
    /// Lawful-interception content tap for this endpoint's ingress (ETSI TS 103 221-2 X3).
    ///
    /// A crypto bridge never reaches the media pipeline, so without this a **same-codec WebRTC or
    /// SDES call would be silently uninterceptable** — and that is the ordinary app-client shape,
    /// not a corner case. The tap fires on the plaintext between the two transforms, which is also
    /// after the authentication decision: a failed `unprotect` returns before it. On a transcrypt
    /// that intermediate is the *only* plaintext there is, so the tap is what keeps a
    /// secure-to-secure call interceptable at all.
    x3: Option<X3Tap>,
}

/// The bridge registry: redirected endpoint → its `Flow`. Shared (`Arc`) between the control path
/// (which registers/deregisters per call) and the redirect dispatcher (which calls [`Self::handle`]).
///
/// It also owns the sibling [`DtlsBridge`] (the DTLS-SRTP `Redirect` path). Both terminate a secure
/// leg on the redirect stream, so the dispatcher routes through this one entry point: [`Self::owns`],
/// [`Self::handle`], and [`Self::deregister`] cover DTLS endpoints too, keeping the dispatcher (and its
/// many call sites) unchanged. Reach the DTLS bridge directly for registration via [`Self::dtls`].
pub struct SrtpBridge<D: Datapath> {
    datapath: D,
    flows: DashMap<EndpointId, Flow>,
    dtls: Arc<DtlsBridge<D>>,
}

impl<D: Datapath + Clone + 'static> SrtpBridge<D> {
    /// Create an empty bridge over `datapath` (a clone of the engine's datapath, used to transmit).
    #[must_use]
    pub fn new(datapath: D) -> Self {
        Self {
            dtls: Arc::new(DtlsBridge::new(datapath.clone())),
            datapath,
            flows: DashMap::new(),
        }
    }

    /// The sibling DTLS-SRTP bridge, for the control path to register/query DTLS legs.
    #[must_use]
    pub fn dtls(&self) -> Arc<DtlsBridge<D>> {
        self.dtls.clone()
    }

    /// Register a call's bridge flows over whichever of its two [`SecureLeg`]s the plan carries. The
    /// caller installs `FlowAction::Redirect` on each endpoint and tears them down on delete via
    /// [`Self::deregister`].
    ///
    /// A flow naming a leg the plan does not carry would be installed with that side unkeyed, which
    /// means forwarding a peer's ciphertext onward verbatim or putting the other party's plaintext on
    /// a wire that negotiated encryption. Rather than install it that way, the whole call is rejected
    /// with an `error!` and **no** flow is installed: the endpoints then belong to nobody, the
    /// dispatcher finds no owner and the datagrams are dropped. Fail closed, and loudly — a partially
    /// installed bridge is worse than an absent one.
    pub fn register(&self, plan: BridgeCallPlan) {
        let near = plan.near_leg.map(|leg| Arc::new(Mutex::new(leg)));
        let far = plan.far_leg.map(|leg| Arc::new(Mutex::new(leg)));
        let resolve = |which: Option<BridgeLeg>| match which {
            None => Ok(None),
            Some(party) => {
                let handle = match party {
                    BridgeLeg::Near => near.clone(),
                    BridgeLeg::Far => far.clone(),
                };
                handle.map(|leg| Some(FlowLeg { party, leg })).ok_or(party)
            }
        };
        let mut resolved = Vec::with_capacity(plan.flows.len());
        for flow in plan.flows {
            let (Ok(ingress_leg), Ok(egress_leg)) =
                (resolve(flow.ingress_leg), resolve(flow.egress_leg))
            else {
                tracing::error!(
                    endpoint = ?flow.endpoint,
                    "bridge flow names a secure leg the call plan does not carry; \
                     refusing to install the call's flows"
                );
                return;
            };
            resolved.push((flow.endpoint, ingress_leg, egress_leg, flow));
        }
        for (endpoint, ingress_leg, egress_leg, flow) in resolved {
            self.flows.insert(
                endpoint,
                Flow {
                    accepted_source: flow.accepted_source,
                    out_endpoint: flow.out_endpoint,
                    out_dst: flow.out_dst,
                    ingress_leg,
                    egress_leg,
                    x3: None,
                },
            );
        }
    }

    /// Drop the flows for `endpoints` (a call's endpoints) — the bridge half of call teardown. Also
    /// deregisters any DTLS-bridge flows for the same endpoints (aborting their handshake tasks).
    pub fn deregister(&self, endpoints: impl IntoIterator<Item = EndpointId>) {
        let endpoints: Vec<EndpointId> = endpoints.into_iter().collect();
        for endpoint in &endpoints {
            self.flows.remove(endpoint);
        }
        self.dtls.deregister(endpoints);
    }

    /// Whether this (or the sibling DTLS) bridge owns `endpoint` — the dispatcher's routing predicate.
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.flows.contains_key(&endpoint) || self.dtls.owns(endpoint)
    }

    /// Export a **one-sided** bridge's single secure-leg rollover for an HA checkpoint, reached via
    /// any one of its endpoints: on such a call every flow references that one leg, from whichever
    /// side faces the secure peer, so taking the ingress leg or else the egress one always finds it.
    /// `None` if the endpoint is not bridged, carries no leg, or the mutex is poisoned.
    ///
    /// Deliberately *not* for a transcrypt, where the two sides are different parties and this would
    /// silently pick one. `checkpoint` refuses a transcrypt call before reaching here; a
    /// renegotiation wants both and uses [`Self::rollover_snapshots`].
    #[must_use]
    pub fn rollover_snapshot(&self, endpoint: EndpointId) -> Option<SecureLegRollover> {
        let flow = self.flows.get(&endpoint)?;
        let side = flow
            .ingress_leg
            .clone()
            .or_else(|| flow.egress_leg.clone())?;
        let guard = side.leg.lock().ok()?;
        Some(guard.rollover_snapshot())
    }

    /// Both of a call's secure-leg rollovers as `(near, far)`, reached through its **near** (A-facing)
    /// RTP endpoint — what a renegotiation seeds the rebuilt legs with so neither restarts its counter
    /// at 0 while the peer's keeps counting (RFC 3711 §3.3.1).
    ///
    /// That one flow names both parties whichever shape the call is, because it faces A on ingress and
    /// B on egress: its `ingress_leg` is A's contexts (`SrtpOfferer`, transcrypt) or absent (A plain),
    /// and its `egress_leg` is B's (`Srtp`, transcrypt) or absent (B plain). Either element is `None`
    /// for a party that is not secure, for an unbridged endpoint, or for a poisoned mutex — a caller
    /// seeds only what it gets back.
    #[must_use]
    pub fn rollover_snapshots(
        &self,
        near_endpoint: EndpointId,
    ) -> (Option<SecureLegRollover>, Option<SecureLegRollover>) {
        let Some(flow) = self.flows.get(&near_endpoint) else {
            return (None, None);
        };
        let snapshot = |side: Option<&FlowLeg>| Some(side?.leg.lock().ok()?.rollover_snapshot());
        (
            snapshot(flow.ingress_leg.as_ref()),
            snapshot(flow.egress_leg.as_ref()),
        )
    }

    /// Export the installed bridge flow plans for a call's `endpoints` (which side carries which
    /// party's key / source-gate / destination), so an HA restore can reinstall them verbatim.
    /// Entries follow `endpoints`; an endpoint the bridge does not own is skipped.
    #[must_use]
    pub fn flow_plans(&self, endpoints: &[EndpointId]) -> Vec<BridgeFlowPlan> {
        endpoints
            .iter()
            .filter_map(|endpoint| {
                self.flows.get(endpoint).map(|flow| BridgeFlowPlan {
                    endpoint: *endpoint,
                    ingress_leg: flow.ingress_leg.as_ref().map(|side| side.party),
                    egress_leg: flow.egress_leg.as_ref().map(|side| side.party),
                    accepted_source: flow.accepted_source,
                    out_endpoint: flow.out_endpoint,
                    out_dst: flow.out_dst,
                })
            })
            .collect()
    }

    /// Install a lawful-interception content tap on one bridged endpoint's ingress, replacing any
    /// tap already there. Returns whether the endpoint is bridged here; a DTLS endpoint is delegated
    /// to the sibling bridge.
    ///
    /// The caller decides which endpoint gets which tap, because only it knows which leg the warrant
    /// names — the direction on a PDU is target-relative, and the bridge's own keying says which
    /// sides are encrypted, not which party is the target.
    pub fn set_x3_tap(&self, endpoint: EndpointId, tap: X3Tap) -> bool {
        if let Some(mut flow) = self.flows.get_mut(&endpoint) {
            flow.x3 = Some(tap);
            return true;
        }
        self.dtls.set_x3_tap(endpoint, tap)
    }

    /// Remove the lawful-interception tap from one bridged endpoint. Idempotent.
    pub fn clear_x3_tap(&self, endpoint: EndpointId) {
        if let Some(mut flow) = self.flows.get_mut(&endpoint) {
            flow.x3 = None;
        }
        self.dtls.clear_x3_tap(endpoint);
    }

    /// Handle one redirected datagram: gate the source, apply the flow's crypto, and forward it.
    /// Anything that fails to gate or transform is dropped (never forwarded into the void).
    pub async fn handle(&self, packet: RxPacket) {
        // A DTLS-bridge endpoint (handshake or DTLS-keyed SRTP) routes to the sibling bridge.
        if self.dtls.owns(packet.endpoint) {
            self.dtls.handle(packet).await;
            return;
        }
        // Snapshot the flow and release the map guard before any crypto or `.await`.
        let Some((accepted_source, out_endpoint, out_dst, ingress_leg, egress_leg, x3)) =
            self.flows.get(&packet.endpoint).map(|flow| {
                (
                    flow.accepted_source,
                    flow.out_endpoint,
                    flow.out_dst,
                    flow.ingress_leg.clone(),
                    flow.egress_leg.clone(),
                    flow.x3.clone(),
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

        // Decrypt what arrived (if this side faces a secure peer), then encrypt what leaves (if the
        // other side does). One sequence covers all three shapes: a one-sided bridge leaves one of
        // the two `None` and pays for a single transform, and a **transcrypt** runs both, under two
        // different parties' keys. The plaintext between them is a stack buffer that never reaches a
        // socket — on a transcrypt it is the only plaintext the call ever has.
        let mut decrypted = Vec::new();
        let plaintext: &[u8] = if let Some(side) = &ingress_leg {
            let transformed = {
                let Ok(mut leg) = side.leg.lock() else {
                    tracing::error!("bridge secure-leg mutex poisoned; dropping packet");
                    return;
                };
                leg.unprotect(&packet.data, &mut decrypted)
            };
            if let Err(error) = transformed {
                tracing::debug!(
                    ?error,
                    party = ?side.party,
                    "bridge ingress decrypt failed; dropping packet"
                );
                return;
            }
            &decrypted
        } else {
            &packet.data
        };

        let mut sealed = Vec::new();
        let out: &[u8] = if let Some(side) = &egress_leg {
            let transformed = {
                let Ok(mut leg) = side.leg.lock() else {
                    tracing::error!("bridge secure-leg mutex poisoned; dropping packet");
                    return;
                };
                leg.protect(plaintext, &mut sealed)
            };
            if let Err(error) = transformed {
                tracing::debug!(
                    ?error,
                    party = ?side.party,
                    "bridge egress encrypt failed; dropping packet"
                );
                return;
            }
            &sealed
        } else {
            plaintext
        };

        // Accepted: past the source gate and past the crypto. Stamp the endpoint's liveness for the
        // engine's idle sweep (docs/security-and-nat.md §4 layer 6). The `Redirect` arm never touches
        // the datapath's `last_seen`, so a bridged call — whose legs are both `Redirect` and so has no
        // `Forward` rule stamping anywhere — would otherwise be reaped at the media timeout however
        // much audio was crossing it. Placed after the crypto so a forged or replayed packet, which
        // returns above, can never hold a dead call open.
        self.datapath.note_activity(packet.endpoint);

        // Lawful-interception content (ETSI TS 103 221-2 X3), taken from between the two transforms,
        // which is the one place the datagram is plaintext whichever shape the flow is: an `Encrypt`
        // flow was handed it, a `Decrypt` flow produced it, and a transcrypt holds it only here.
        // Reached only after the source gate above and after the crypto succeeded, so a forged or
        // replayed packet — which returns above — is never delivered.
        if let Some(x3) = &x3 {
            x3.deliver(packet.source, packet.arrival, plaintext);
        }

        if let Err(error) = self.datapath.send(out_endpoint, out_dst, out).await {
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
/// order is bridge → media → text → ws → conference → turn. Runs until the redirect stream closes.
///
/// This convenience form does not route the RFC 4103 text-observability slow path (it stands up an
/// empty [`crate::text_pipeline::TextRegistry`]); it exists so the test harnesses that predate text
/// observability keep compiling. Production ([`crate::daemon`]) uses [`run_redirect_dispatcher_with_text`]
/// with the engine's real text registry.
pub async fn run_redirect_dispatcher<D: Datapath + Clone + 'static>(
    redirect_rx: flume::Receiver<RxPacket>,
    bridge: Arc<SrtpBridge<D>>,
    media: Arc<crate::media_pipeline::MediaRegistry>,
    ws: Arc<crate::ws_bridge::WsRegistry>,
    conference: Arc<crate::conference::ConferenceRegistry>,
    turn_relay: Option<flume::Sender<RxPacket>>,
) {
    run_redirect_dispatcher_with_text(
        redirect_rx,
        bridge,
        media,
        Arc::new(crate::text_pipeline::TextRegistry::default()),
        ws,
        conference,
        turn_relay,
    )
    .await;
}

/// The full redirect dispatcher, routing bridge → media → **text** → ws → conference → turn. The text
/// slow path ([`crate::text_pipeline::TextRegistry`]) carries a promoted RFC 4103 `m=text` stream's
/// datagrams to its per-call observer. Runs until the redirect stream closes.
#[allow(clippy::too_many_arguments)]
pub async fn run_redirect_dispatcher_with_text<D: Datapath + Clone + 'static>(
    redirect_rx: flume::Receiver<RxPacket>,
    bridge: Arc<SrtpBridge<D>>,
    media: Arc<crate::media_pipeline::MediaRegistry>,
    text: Arc<crate::text_pipeline::TextRegistry>,
    ws: Arc<crate::ws_bridge::WsRegistry>,
    conference: Arc<crate::conference::ConferenceRegistry>,
    turn_relay: Option<flume::Sender<RxPacket>>,
) {
    while let Ok(packet) = redirect_rx.recv_async().await {
        if bridge.owns(packet.endpoint) {
            bridge.handle(packet).await;
        } else if media.owns(packet.endpoint) {
            media.dispatch(packet);
        } else if text.owns(packet.endpoint) {
            text.dispatch(packet);
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
        bridge: Arc<SrtpBridge<UdpLoopbackDatapath>>,
        /// Engine's plain endpoint — phone A sends RTP here.
        plain_addr: SocketAddr,
        /// Engine's secure endpoint — phone B sends SRTP here.
        secure_addr: SocketAddr,
        /// The two redirected endpoint ids, so a test can install a lawful-interception tap on the
        /// same flows the dispatcher drives.
        plain_endpoint: EndpointId,
        secure_endpoint: EndpointId,
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

        datapath
            .install_flow(plain.id, FlowAction::Redirect)
            .expect("redirect plain");
        datapath
            .install_flow(secure.id, FlowAction::Redirect)
            .expect("redirect secure");

        let local = key(0xAA);
        let remote = key(0xBB);
        let bridge = Arc::new(SrtpBridge::new(datapath.clone()));
        bridge.register(BridgeCallPlan {
            near_leg: None,
            far_leg: Some(SecureLeg::new(&local, &remote)),
            flows: vec![
                BridgeFlowPlan {
                    endpoint: plain.id,
                    ingress_leg: None,
                    egress_leg: Some(BridgeLeg::Far),
                    accepted_source: SourceFilter::Exact(addr_a.ip()),
                    out_endpoint: secure.id,
                    out_dst: addr_b,
                },
                BridgeFlowPlan {
                    endpoint: secure.id,
                    ingress_leg: Some(BridgeLeg::Far),
                    egress_leg: None,
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
            plain_endpoint: plain.id,
            secure_endpoint: secure.id,
            local,
            remote,
            _datapath: datapath,
            bridge,
        };
        (harness, (phone_a, addr_a), (phone_b, addr_b))
    }

    /// A live **transcrypt** bridge: both phones negotiated SDES-SRTP, under key pairs that have
    /// nothing to do with each other, and the engine is the cryptographic far side of each.
    struct Transcrypt {
        _datapath: UdpLoopbackDatapath,
        bridge: Arc<SrtpBridge<UdpLoopbackDatapath>>,
        a_addr: SocketAddr,
        b_addr: SocketAddr,
        a_endpoint: EndpointId,
        b_endpoint: EndpointId,
        /// Engine's key toward A — A decrypts engine→A media with it.
        a_local: SrtpKeyMaterial,
        /// A's own answered key — A encrypts A→engine media with it.
        a_remote: SrtpKeyMaterial,
        /// Engine's key toward B.
        b_local: SrtpKeyMaterial,
        /// B's own answered key.
        b_remote: SrtpKeyMaterial,
    }

    async fn live_transcrypt() -> (Transcrypt, (UdpSocket, SocketAddr), (UdpSocket, SocketAddr)) {
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let (phone_a, addr_a) = phone(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone(Ipv4Addr::new(127, 0, 0, 3)).await;
        for endpoint in [near.id, far.id] {
            datapath
                .install_flow(endpoint, FlowAction::Redirect)
                .expect("redirect");
        }

        // Four distinct keys: the engine offered its own to each party and each answered its own.
        let (a_local, a_remote) = (key(0xA1), key(0xA2));
        let (b_local, b_remote) = (key(0xB1), key(0xB2));
        let bridge = Arc::new(SrtpBridge::new(datapath.clone()));
        bridge.register(BridgeCallPlan {
            near_leg: Some(SecureLeg::new(&a_local, &a_remote)),
            far_leg: Some(SecureLeg::new(&b_local, &b_remote)),
            flows: vec![
                BridgeFlowPlan {
                    endpoint: near.id,
                    ingress_leg: Some(BridgeLeg::Near),
                    egress_leg: Some(BridgeLeg::Far),
                    accepted_source: SourceFilter::Exact(addr_a.ip()),
                    out_endpoint: far.id,
                    out_dst: addr_b,
                },
                BridgeFlowPlan {
                    endpoint: far.id,
                    ingress_leg: Some(BridgeLeg::Far),
                    egress_leg: Some(BridgeLeg::Near),
                    accepted_source: SourceFilter::Exact(addr_b.ip()),
                    out_endpoint: near.id,
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

        let harness = Transcrypt {
            a_addr: near.local_addr,
            b_addr: far.local_addr,
            a_endpoint: near.id,
            b_endpoint: far.id,
            a_local,
            a_remote,
            b_local,
            b_remote,
            _datapath: datapath,
            bridge,
        };
        (harness, (phone_a, addr_a), (phone_b, addr_b))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transcrypt_re_encrypts_each_direction_under_the_other_partys_key() {
        let (harness, (phone_a, _), (phone_b, _)) = live_transcrypt().await;

        // A → B. A seals under its own key; B must receive something it can open with the key the
        // engine advertised to *B*, which is a different key entirely.
        let from_a = rtp(1000, 0x1111_1111);
        let mut a_out = SrtpContext::from_key_material(&harness.a_remote);
        let mut a_sealed = Vec::new();
        a_out.protect(&from_a, &mut a_sealed).expect("A encrypts");
        phone_a
            .send_to(&a_sealed, harness.a_addr)
            .await
            .expect("send a");

        let at_b = recv(&phone_b).await;
        assert_ne!(at_b, from_a, "B receives ciphertext, never the plaintext");
        // The load-bearing assertion: the bridge did not pass A's datagram through. If it had, B
        // would be holding bytes sealed under A's key, which it has no way to open.
        assert_ne!(
            at_b, a_sealed,
            "B receives a re-encrypted datagram, not A's own ciphertext relayed verbatim"
        );
        let mut b_in = SrtpContext::from_key_material(&harness.b_local);
        let mut recovered = Vec::new();
        b_in.unprotect(&at_b, &mut recovered)
            .expect("B authenticates under the key the engine advertised to B");
        assert_eq!(recovered, from_a, "and it is exactly what A sent");

        // B → A, the mirror.
        let from_b = rtp(2000, 0x2222_2222);
        let mut b_out = SrtpContext::from_key_material(&harness.b_remote);
        let mut b_sealed = Vec::new();
        b_out.protect(&from_b, &mut b_sealed).expect("B encrypts");
        phone_b
            .send_to(&b_sealed, harness.b_addr)
            .await
            .expect("send b");

        let at_a = recv(&phone_a).await;
        assert_ne!(at_a, from_b);
        assert_ne!(at_a, b_sealed, "re-encrypted, not relayed verbatim");
        let mut a_in = SrtpContext::from_key_material(&harness.a_local);
        let mut recovered = Vec::new();
        a_in.unprotect(&at_a, &mut recovered)
            .expect("A authenticates under the key the engine advertised to A");
        assert_eq!(recovered, from_b);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transcrypt_drops_a_frame_that_fails_the_ingress_key() {
        let (harness, (phone_a, _), (phone_b, _)) = live_transcrypt().await;
        // Sealed under B's key but sent to A's endpoint: authentic SRTP, wrong party. It must fail
        // the ingress decrypt and be dropped — never re-encrypted onward, which would launder an
        // attacker's frame into something B's key opens.
        let forged = rtp(1, 0x3333_3333);
        let mut wrong = SrtpContext::from_key_material(&harness.b_remote);
        let mut sealed = Vec::new();
        wrong.protect(&forged, &mut sealed).expect("seal");
        phone_a
            .send_to(&sealed, harness.a_addr)
            .await
            .expect("send");

        let mut buffer = [0u8; 2048];
        assert!(
            timeout(NEGATIVE, phone_b.recv_from(&mut buffer))
                .await
                .is_err(),
            "a frame that fails A's key never reaches B under B's"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transcrypt_x3_delivers_the_only_plaintext_the_call_has() {
        // Both sides of the wire are ciphertext under different keys, so the intermediate between
        // the two transforms is the only plaintext that exists anywhere. Without the tap there, a
        // secure-to-secure call would be silently uninterceptable.
        let (harness, (phone_a, addr_a), (phone_b, _)) = live_transcrypt().await;
        let (factory, delivery) = crate::x3::x3_channel(64);
        let (from_target, to_target) = crate::x3::ingress_directions(true);
        assert!(harness
            .bridge
            .set_x3_tap(harness.a_endpoint, factory.tap(harness.a_addr, from_target)));
        assert!(harness
            .bridge
            .set_x3_tap(harness.b_endpoint, factory.tap(harness.b_addr, to_target)));

        let from_a = rtp(7, 0x4444_4444);
        let mut a_out = SrtpContext::from_key_material(&harness.a_remote);
        let mut sealed = Vec::new();
        a_out.protect(&from_a, &mut sealed).expect("A encrypts");
        phone_a
            .send_to(&sealed, harness.a_addr)
            .await
            .expect("send");
        let on_wire = recv(&phone_b).await;
        assert_ne!(on_wire, from_a, "B really did receive ciphertext");

        let delivered = timeout(SHORT, delivery.packets.recv_async())
            .await
            .expect("no timeout")
            .expect("delivered");
        assert_eq!(
            delivered.payload, from_a,
            "X3 delivers the plaintext between the two transforms"
        );
        assert_eq!(delivered.direction, from_target);
        assert_eq!(delivered.source, addr_a);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flow_naming_an_absent_leg_installs_nothing_rather_than_an_unkeyed_side() {
        // A plan whose flow reaches for a leg the plan does not carry would install that side
        // unkeyed — forwarding a peer's ciphertext onward verbatim, or putting the other party's
        // plaintext on a wire that negotiated encryption. The whole call is refused instead, so the
        // endpoints belong to nobody and the datagrams are dropped.
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        let bridge = SrtpBridge::new(datapath);
        bridge.register(BridgeCallPlan {
            near_leg: None,
            far_leg: Some(SecureLeg::new(&key(1), &key(2))),
            flows: vec![BridgeFlowPlan {
                endpoint: endpoint.id,
                // Names the near party, which this plan has no leg for.
                ingress_leg: Some(BridgeLeg::Near),
                egress_leg: Some(BridgeLeg::Far),
                accepted_source: SourceFilter::Any,
                out_endpoint: endpoint.id,
                out_dst: endpoint.local_addr,
            }],
        });
        assert!(
            !bridge.owns(endpoint.id),
            "no flow is installed, so nothing forwards"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_to_secure_is_encrypted_for_the_peer() {
        let (harness, (phone_a, _), (phone_b, _)) = live_bridge().await;
        let plaintext = rtp(1000, 0x1111_1111);

        // Phone A (plain) → engine plain endpoint → bridge encrypts → secure endpoint → phone B.
        phone_a
            .send_to(&plaintext, harness.plain_addr)
            .await
            .expect("send a");
        let srtp = recv(&phone_b).await;
        assert_ne!(srtp, plaintext, "phone B receives SRTP, not plaintext");

        // Phone B holds the engine's offered (local) key and decrypts it back to the original.
        let mut decrypt = SrtpContext::from_key_material(&harness.local);
        let mut recovered = Vec::new();
        decrypt
            .unprotect(&srtp, &mut recovered)
            .expect("peer decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn secure_to_plain_is_decrypted_for_the_peer() {
        let (harness, (phone_a, _), (phone_b, _)) = live_bridge().await;
        let plaintext = rtp(2000, 0x2222_2222);

        // Phone B encrypts with its answered (remote) key and sends SRTP to the secure endpoint.
        let mut encrypt = SrtpContext::from_key_material(&harness.remote);
        let mut srtp = Vec::new();
        encrypt
            .protect(&plaintext, &mut srtp)
            .expect("peer encrypt");
        phone_b
            .send_to(&srtp, harness.secure_addr)
            .await
            .expect("send b");

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
        attacker
            .send_to(&rtp(1, 0xDEAD), harness.plain_addr)
            .await
            .expect("attacker send");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(NEGATIVE, phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "an off-source packet must never reach the peer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn garbage_on_the_secure_leg_fails_auth_and_is_dropped() {
        let (harness, (phone_a, _), (phone_b, _)) = live_bridge().await;
        // A forged/unauthenticated datagram from the signalled secure peer fails SRTP auth → dropped.
        phone_b
            .send_to(&rtp(1, 0x3333), harness.secure_addr)
            .await
            .expect("send garbage");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(NEGATIVE, phone_a.recv_from(&mut scratch))
                .await
                .is_err(),
            "an unauthenticated SRTP packet must not be forwarded to the plain leg"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatcher_routes_owned_to_bridge_and_rest_to_turn() {
        let datapath = UdpLoopbackDatapath::new();
        let owned = datapath.alloc_endpoint().await.expect("alloc");
        let bridge = Arc::new(SrtpBridge::new(datapath));
        bridge.register(BridgeCallPlan {
            near_leg: None,
            far_leg: Some(SecureLeg::new(&key(1), &key(2))),
            flows: vec![BridgeFlowPlan {
                endpoint: owned.id,
                ingress_leg: Some(BridgeLeg::Far),
                egress_leg: None,
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
            arrival: 0,
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
            arrival: 0,
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
            near_leg: None,
            far_leg: Some(SecureLeg::new(&key(1), &key(2))),
            flows: vec![BridgeFlowPlan {
                endpoint: endpoint.id,
                ingress_leg: Some(BridgeLeg::Far),
                egress_leg: None,
                accepted_source: SourceFilter::Any,
                out_endpoint: endpoint.id,
                out_dst: endpoint.local_addr,
            }],
        });
        assert!(bridge.owns(endpoint.id));
        bridge.deregister([endpoint.id]);
        assert!(!bridge.owns(endpoint.id));
    }

    // --- Lawful-interception content delivery (ETSI TS 103 221-2 X3) --------------------------
    //
    // A crypto bridge relays without ever reaching the media pipeline, so a same-codec SDES or
    // WebRTC call — the ordinary app-client shape — has no pipeline tap to fire. These pin that the
    // bridge itself delivers, on plaintext, and only for packets it accepted.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn x3_on_a_bridged_call_delivers_plaintext_in_both_directions() {
        let (harness, (phone_a, addr_a), (phone_b, addr_b)) = live_bridge().await;
        let (factory, delivery) = crate::x3::x3_channel(64);
        // Target on the plain leg: its own ingress is "from the target", the secure peer's is
        // "to the target".
        let (from_target, to_target) = crate::x3::ingress_directions(true);
        assert!(harness.bridge.set_x3_tap(
            harness.plain_endpoint,
            factory.tap(harness.plain_addr, from_target)
        ));
        assert!(harness.bridge.set_x3_tap(
            harness.secure_endpoint,
            factory.tap(harness.secure_addr, to_target)
        ));

        // Plain leg → secure peer. The bridge encrypts, but the intercepted copy is the plaintext
        // ingress, not the ciphertext it emitted.
        let plain = rtp(1, 0x1111_1111);
        phone_a
            .send_to(&plain, harness.plain_addr)
            .await
            .expect("send plain");
        let on_wire = recv(&phone_b).await;
        assert_ne!(on_wire, plain, "the peer really did receive ciphertext");

        let delivered = timeout(SHORT, delivery.packets.recv_async())
            .await
            .expect("no timeout")
            .expect("delivered");
        assert_eq!(
            delivered.payload, plain,
            "X3 delivers the plaintext ingress"
        );
        assert_eq!(delivered.direction, from_target);
        assert_eq!(delivered.source, addr_a);
        assert_eq!(delivered.destination, harness.plain_addr);

        // Secure peer → plain leg. Here the ciphertext is the ingress, so the intercepted copy must
        // be what the bridge *decrypted*.
        // Phone B encrypts with its answered (remote) key, as the peer does on the wire.
        let mut peer = SrtpContext::from_key_material(&harness.remote);
        let peer_plain = rtp(2, 0x2222_2222);
        let mut sealed = Vec::new();
        peer.protect(&peer_plain, &mut sealed)
            .expect("peer encrypt");
        assert_ne!(sealed, peer_plain);
        phone_b
            .send_to(&sealed, harness.secure_addr)
            .await
            .expect("send secure");
        let _ = recv(&phone_a).await;

        let delivered = timeout(SHORT, delivery.packets.recv_async())
            .await
            .expect("no timeout")
            .expect("delivered");
        assert_eq!(
            delivered.payload, peer_plain,
            "X3 delivers the decrypted RTP, never the wire ciphertext"
        );
        assert_eq!(delivered.direction, to_target);
        assert_eq!(delivered.source, addr_b);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn x3_on_a_bridged_call_delivers_nothing_for_a_packet_that_fails_authentication() {
        let (harness, _phone_a, (phone_b, _)) = live_bridge().await;
        let (factory, delivery) = crate::x3::x3_channel(64);
        harness.bridge.set_x3_tap(
            harness.secure_endpoint,
            factory.tap(
                harness.secure_addr,
                siphon_rtp_li::PayloadDirection::FromTarget,
            ),
        );

        // Never SRTP-protected, so `unprotect` fails and the bridge drops it before the tap.
        phone_b
            .send_to(&rtp(1, 0x3333_3333), harness.secure_addr)
            .await
            .expect("send forged");

        assert!(
            timeout(NEGATIVE, delivery.packets.recv_async())
                .await
                .is_err(),
            "a packet failing SRTP authentication must never be delivered as target content"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn x3_on_a_bridged_call_delivers_nothing_from_an_unsignalled_source() {
        let (harness, _phone_a, _phone_b) = live_bridge().await;
        let (factory, delivery) = crate::x3::x3_channel(64);
        harness.bridge.set_x3_tap(
            harness.plain_endpoint,
            factory.tap(
                harness.plain_addr,
                siphon_rtp_li::PayloadDirection::FromTarget,
            ),
        );

        // The bridge's RTPBleed gate runs before the tap, so an injected stream is not attributed
        // to the target.
        let (attacker, _) = phone(Ipv4Addr::new(127, 0, 0, 9)).await;
        attacker
            .send_to(&rtp(1, 0x4444_4444), harness.plain_addr)
            .await
            .expect("send");

        assert!(
            timeout(NEGATIVE, delivery.packets.recv_async())
                .await
                .is_err(),
            "a packet from an unsignalled source must not be delivered"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clearing_the_x3_tap_stops_bridged_delivery() {
        let (harness, (phone_a, _), (phone_b, _)) = live_bridge().await;
        let (factory, delivery) = crate::x3::x3_channel(64);
        harness.bridge.set_x3_tap(
            harness.plain_endpoint,
            factory.tap(
                harness.plain_addr,
                siphon_rtp_li::PayloadDirection::FromTarget,
            ),
        );

        phone_a
            .send_to(&rtp(1, 0x5555_5555), harness.plain_addr)
            .await
            .expect("send");
        let _ = recv(&phone_b).await;
        assert!(timeout(SHORT, delivery.packets.recv_async()).await.is_ok());

        harness.bridge.clear_x3_tap(harness.plain_endpoint);
        harness.bridge.clear_x3_tap(harness.plain_endpoint); // idempotent

        phone_a
            .send_to(&rtp(2, 0x5555_5555), harness.plain_addr)
            .await
            .expect("send");
        let _ = recv(&phone_b).await; // the call keeps relaying
        assert!(
            timeout(NEGATIVE, delivery.packets.recv_async())
                .await
                .is_err(),
            "no content is delivered after the interception is detached"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tapping_an_endpoint_this_bridge_does_not_own_reports_failure() {
        // The engine unwinds on this rather than reporting an interception that taps nothing.
        let (harness, _phone_a, _phone_b) = live_bridge().await;
        let (factory, _delivery) = crate::x3::x3_channel(4);
        assert!(!harness.bridge.set_x3_tap(
            EndpointId(9_999),
            factory.tap(
                harness.plain_addr,
                siphon_rtp_li::PayloadDirection::FromTarget
            ),
        ));
    }
}
