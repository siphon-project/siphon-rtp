//! The WebSocket-bridge slow path: attach a call leg's audio to an external WebSocket media server
//! (the mod_audio_stream / voice-AI integration).
//!
//! Where the datapath `Forward` fast path relays an opaque datagram untouched, the
//! [`crate::srtp_bridge`] terminates SRTP, and the [`crate::media_pipeline`] transcodes between two
//! legs, a **WebSocket-bridged** call sets leg A's RTP endpoint to
//! [`FlowAction::Redirect`](siphon_rtp_datapath::FlowAction::Redirect) and the redirect dispatcher
//! routes each of A's datagrams to this registry. The engine dials the WS server as a *client*
//! ([`tokio_tungstenite::connect_async`]) and runs [`siphon_rtp_media::bridge::run_bridge`], which:
//!
//! - decodes A's RTP to L16 and sends it uplink (call → server) as a WS binary frame, and
//! - encodes inbound WS binary frames (server → call) to RTP toward A.
//!
//! The WS server is leg A's far side, so the A↔B transcode/relay path is **not** wired in this mode
//! (B may still be allocated by offer/answer; its media is simply not bridged here).
//!
//! Like the SRTP bridge and media pipeline, this registry re-enforces the signalled-source gate
//! before feeding a datagram to the bridge — `Redirect` bypasses the datapath's Forward-path gate, so
//! the RTPBleed defence (docs/security-and-nat.md §4 layer 2) is applied here.
//!
//! ## Secure (SRTP) takeover legs
//!
//! When the *offerer* is a secure leg — SDES-SRTP (RFC 4568, `RTP/SAVP` + `a=crypto`) or DTLS-SRTP
//! (RFC 5764, `UDP/TLS/RTP/SAVPF`) — the engine is the peer's cryptographic far side, so the leg
//! carries a [`WsSecureLeg`]: A's ingress is SRTP-`unprotect`ed here before it reaches the decoder,
//! and the bridge's rendered downlink is SRTP-`protect`ed before it leaves. Both directions of one
//! leg share the crypto (the RFC 3711 inbound and outbound contexts live in the same
//! [`SecureLeg`]), exactly as [`crate::srtp_bridge`] and [`crate::dtls_bridge`] share theirs — and
//! like them, this module is the only place a WS leg's crypto is touched, so there is one owner of
//! the SRTP state rather than two half-owners.
//!
//! It is **fail-closed** in both directions: an unkeyed leg (a DTLS handshake that has not finished)
//! or a packet that fails SRTP authentication is dropped, and egress on a secure leg is *never*
//! emitted in the clear — a plaintext RTP packet toward a peer that negotiated SRTP is both an audio
//! failure and a confidentiality break, so it is dropped instead.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use bytes::Bytes;
use dashmap::DashMap;

use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_srtp::leg::{is_rtcp, SecureLeg};

/// The SRTP (RFC 3711) crypto of one secure WebSocket-takeover leg: the engine's own key material
/// against the offerer's.
///
/// `None` inside means **not keyed yet**. An SDES leg is keyed at registration (the answer carries
/// the engine's `a=crypto`, so both keys are known synchronously); a DTLS-SRTP leg is keyed only
/// when the RFC 5764 handshake completes, which is after the control command has returned — until
/// then every packet in both directions is dropped.
pub struct WsSecureLeg {
    leg: Mutex<Option<SecureLeg>>,
    /// Mirrors `leg.is_some()` without taking the lock, for the cheap gate on the drop path.
    keyed: AtomicBool,
}

impl WsSecureLeg {
    /// A leg keyed up front — the SDES-SRTP case (RFC 4568).
    #[must_use]
    pub fn keyed(leg: SecureLeg) -> Self {
        Self {
            leg: Mutex::new(Some(leg)),
            keyed: AtomicBool::new(true),
        }
    }

    /// An unkeyed leg — the DTLS-SRTP case (RFC 5764), keyed later by [`Self::attach`].
    #[must_use]
    pub fn pending() -> Self {
        Self {
            leg: Mutex::new(None),
            keyed: AtomicBool::new(false),
        }
    }

    /// Whether the leg holds key material yet.
    #[must_use]
    pub fn is_keyed(&self) -> bool {
        self.keyed.load(Ordering::SeqCst)
    }

    /// Install the key material a completed DTLS-SRTP handshake produced. Returns `false` if the
    /// mutex is poisoned, in which case the leg stays unkeyed and keeps dropping.
    pub fn attach(&self, leg: SecureLeg) -> bool {
        let Ok(mut guard) = self.leg.lock() else {
            tracing::error!("ws secure-leg mutex poisoned; the leg stays unkeyed");
            return false;
        };
        *guard = Some(leg);
        // Published after the key is in place, so `is_keyed` never advertises a leg that cannot crypt.
        self.keyed.store(true, Ordering::SeqCst);
        true
    }

    /// Decrypt one inbound datagram for the bridge. `None` means **drop it**: the leg is not keyed,
    /// the packet is SRTCP (the takeover bridge consumes no RTCP), or it failed SRTP authentication
    /// — which is exactly the RFC 3711 §3.3 check that stops an injected packet reaching the decoder.
    fn unprotect_ingress(&self, packet: &[u8]) -> Option<Bytes> {
        // RFC 5761 §4 demux on the clear header byte: SRTCP on a muxed takeover port has no consumer
        // (the bridge speaks PCM to the WS server, not RTCP), so it is dropped before the crypto
        // rather than decrypted and thrown away.
        if is_rtcp(packet) {
            return None;
        }
        let mut plain = Vec::with_capacity(packet.len());
        {
            let Ok(mut guard) = self.leg.lock() else {
                tracing::error!("ws secure-leg mutex poisoned; dropping ingress");
                return None;
            };
            let leg = guard.as_mut()?; // not keyed yet — drop, never hand ciphertext to the decoder
            if let Err(error) = leg.unprotect(packet, &mut plain) {
                tracing::debug!(?error, "ws secure leg failed to decrypt ingress; dropping");
                return None;
            }
        }
        Some(Bytes::from(plain))
    }

    /// Encrypt one rendered downlink RTP packet for the offerer. `false` means **do not send it**:
    /// there is no key yet, or the crypto failed. The caller must not fall back to plaintext.
    pub fn protect_egress(&self, packet: &[u8], out: &mut Vec<u8>) -> bool {
        let Ok(mut guard) = self.leg.lock() else {
            tracing::error!("ws secure-leg mutex poisoned; dropping egress");
            return false;
        };
        let Some(leg) = guard.as_mut() else {
            return false; // unkeyed: dropping is the only safe option, plaintext is not
        };
        match leg.protect(packet, out) {
            Ok(_) => true,
            Err(error) => {
                tracing::debug!(?error, "ws secure leg failed to encrypt egress; dropping");
                false
            }
        }
    }
}

/// One WS-bridged call's datapath route: the bridge's RTP-in mailbox plus the source gate to apply
/// before feeding it (the `Redirect` path skips the datapath's gate — RTPBleed defence).
struct WsRoute {
    /// Signalled-source gate — only this source may drive the bridge.
    accepted_source: SourceFilter,
    /// RFC 8445: a full ICE agent runs on this leg and has not selected a pair yet. The gate above is
    /// deliberately open while that is true (a connectivity check legitimately arrives from a
    /// peer-reflexive transport the SDP never carried, §7.3.1.3), so **nothing** is forwarded until
    /// the agent decides — at which point [`WsRegistry::ice_selected`] narrows the gate to the
    /// selected pair and clears this.
    ice_pending: bool,
    /// Leg A's RTP, forwarded (decrypted, on a secure leg) into the bridge for decode → WS uplink.
    rtp_in: flume::Sender<Bytes>,
    /// SRTP crypto for a secure takeover leg; `None` on a plaintext one.
    secure: Option<Arc<WsSecureLeg>>,
    /// Where the bridge's rendered downlink is sent. A [`tokio::sync::watch`] because ICE may
    /// re-point it mid-call (RFC 8445 §8.1.1) — the drain task reads it per packet.
    egress: Arc<tokio::sync::watch::Sender<SocketAddr>>,
}

/// Everything the registry needs to route and tear down one running WS-bridge call.
pub struct WsCallPlan {
    /// The call this bridge belongs to.
    pub call_id: String,
    /// Leg A's RTP endpoint — the redirected endpoint this call owns.
    pub endpoint_a: EndpointId,
    /// Signalled-source gate for leg A's ingress (RTPBleed defence).
    pub accepted_source: SourceFilter,
    /// A full ICE agent runs on this leg and has not selected a pair yet (see [`WsRoute::ice_pending`]).
    pub ice_pending: bool,
    /// SRTP crypto for a secure (SDES or DTLS) takeover leg; `None` on a plaintext one.
    pub secure: Option<Arc<WsSecureLeg>>,
    /// Where the drain task sends the rendered downlink, shared so ICE can re-point it.
    pub egress: Arc<tokio::sync::watch::Sender<SocketAddr>>,
    /// The bridge's RTP-in mailbox.
    pub rtp_in: flume::Sender<Bytes>,
    /// The bridge task (`run_bridge` over the dialed WS connection).
    pub bridge_task: tokio::task::JoinHandle<()>,
    /// The drain task pumping the bridge's `rtp_out` to the datapath toward A.
    pub drain_task: tokio::task::JoinHandle<()>,
}

/// A handle to a running WS-bridge call: its endpoint(s) and the two tasks to abort on teardown.
struct WsCallHandle {
    /// Leg A's RTP endpoint — the redirected endpoint this call owns.
    endpoint_a: EndpointId,
    /// The bridge task ([`run_bridge`] over the dialed WS connection).
    bridge_task: tokio::task::JoinHandle<()>,
    /// The drain task pumping the bridge's `rtp_out` to the datapath toward A.
    drain_task: tokio::task::JoinHandle<()>,
}

/// The registry of WebSocket-bridged calls: routes leg A's redirected datagrams to the owning
/// bridge's RTP-in mailbox and holds each call's task handles for teardown. Mirrors the
/// [`crate::media_pipeline::MediaRegistry`] / [`crate::srtp_bridge::SrtpBridge`] "registry +
/// dispatcher" shape so the single redirect dispatcher can route by [`EndpointId`].
#[derive(Default)]
pub struct WsRegistry {
    /// Endpoint → the owning bridge's RTP-in route (the dispatcher's routing table).
    routes: DashMap<EndpointId, WsRoute>,
    /// Call-id → the running bridge's task handles + endpoint, for teardown.
    calls: DashMap<String, WsCallHandle>,
}

impl WsRegistry {
    /// Register a running WS bridge: route the plan's endpoint to its RTP-in mailbox (gated by the
    /// plan's source filter, and by its SRTP crypto on a secure leg), and keep the bridge + drain
    /// tasks so teardown can abort them. The caller installs `FlowAction::Redirect` on the endpoint
    /// and tears down via [`Self::deregister`].
    pub fn register(&self, plan: WsCallPlan) {
        self.routes.insert(
            plan.endpoint_a,
            WsRoute {
                accepted_source: plan.accepted_source,
                ice_pending: plan.ice_pending,
                rtp_in: plan.rtp_in,
                secure: plan.secure,
                egress: plan.egress,
            },
        );
        self.calls.insert(
            plan.call_id,
            WsCallHandle {
                endpoint_a: plan.endpoint_a,
                bridge_task: plan.bridge_task,
                drain_task: plan.drain_task,
            },
        );
    }

    /// Whether this registry routes datagrams for `endpoint` (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Whether `call_id` is a WS-bridged call.
    #[must_use]
    pub fn is_ws_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Whether `call_id`'s takeover leg terminates SRTP (a secure offerer), and whether its crypto is
    /// keyed yet — `None` for an unknown or plaintext call. Observability + tests.
    #[must_use]
    pub fn secure_state(&self, call_id: &str) -> Option<bool> {
        let endpoint = self.calls.get(call_id)?.endpoint_a;
        let route = self.routes.get(&endpoint)?;
        route.secure.as_ref().map(|secure| secure.is_keyed())
    }

    /// Key a DTLS-SRTP takeover leg once the RFC 5764 handshake has produced its material. Returns
    /// `false` when the call is gone or was never a secure takeover, in which case the caller must
    /// leave the leg unkeyed so media keeps being dropped rather than reaching an unkeyed consumer.
    pub fn attach_secure_leg(&self, call_id: &str, leg: SecureLeg) -> bool {
        let Some(endpoint) = self.calls.get(call_id).map(|handle| handle.endpoint_a) else {
            return false;
        };
        let Some(route) = self.routes.get(&endpoint) else {
            return false;
        };
        let Some(secure) = route.secure.as_ref() else {
            return false; // a plaintext leg has nowhere to put a key
        };
        secure.attach(leg)
    }

    /// Tell a takeover leg which transport address ICE selected (RFC 8445 §8.1.1): re-point the
    /// bridge's downlink at the chosen pair and narrow the ingress gate to it.
    ///
    /// A takeover leg is not a relay leg — the bridge's drain task, not a datapath forward rule, owns
    /// its egress — so `Datapath::adopt_source` alone is not enough: without this the downlink would
    /// keep going to the signalled `c=` address, which for a NATed ICE peer is one it cannot receive
    /// on. A no-op for an endpoint this registry does not own.
    pub fn ice_selected(&self, endpoint: EndpointId, remote: SocketAddr) -> bool {
        let Some(mut route) = self.routes.get_mut(&endpoint) else {
            return false;
        };
        route.ice_pending = false;
        // The selected pair is now the only source this leg accepts (docs/security-and-nat.md §4
        // layer 4) — the open window an ICE seat starts with closes here.
        route.accepted_source = SourceFilter::Exact(remote.ip());
        let _ = route.egress.send(remote);
        true
    }

    /// Route a redirected datagram (leg A's RTP) to its owning bridge's RTP-in mailbox. The source is
    /// re-gated here (RTPBleed defence — `Redirect` bypasses the datapath gate); an off-source or
    /// unowned datagram is dropped (never fed into the bridge / forwarded into the void). On a secure
    /// leg the datagram is SRTP-decrypted first, and dropped if that fails.
    pub fn dispatch(&self, packet: RxPacket) {
        let Some(route) = self.routes.get(&packet.endpoint) else {
            return; // not a WS endpoint (the dispatcher should have routed it elsewhere)
        };
        if route.ice_pending {
            // RFC 8445 §12: nothing crosses the leg until the agent has chosen a pair.
            tracing::trace!(
                endpoint = ?packet.endpoint,
                "ws-bridge dropped media on a leg whose ICE agent has not selected a pair yet"
            );
            return;
        }
        if !route.accepted_source.accepts(packet.source.ip()) {
            tracing::debug!(
                endpoint = ?packet.endpoint,
                source = %packet.source,
                "ws-bridge dropped packet from unsignalled source"
            );
            return;
        }
        // A secure takeover leg terminates SRTP here (RFC 3711): the bridge below speaks clear RTP,
        // and anything that fails to authenticate never reaches it.
        let payload = match route.secure.as_ref() {
            None => packet.data,
            Some(secure) => match secure.unprotect_ingress(&packet.data) {
                Some(plain) => plain,
                None => return,
            },
        };
        // Drop on a full or closed mailbox — late audio is worthless, and a closed channel means the
        // bridge task has already exited.
        if route.rtp_in.try_send(payload).is_err() {
            tracing::trace!(
                "ws-bridge rtp-in mailbox full or closed; dropping redirected datagram"
            );
        }
    }

    /// Tear a WS-bridge call down: drop its route and abort the bridge + drain tasks (closing the WS
    /// connection and the RTP-out drain). The WS half of call teardown.
    pub fn deregister(&self, call_id: &str) {
        if let Some((_, handle)) = self.calls.remove(call_id) {
            self.routes.remove(&handle.endpoint_a);
            handle.bridge_task.abort();
            handle.drain_task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
    use std::net::Ipv4Addr;

    fn endpoint(id: u64) -> EndpointId {
        EndpointId(id)
    }

    fn rx(endpoint_id: u64, source: &str, data: &[u8]) -> RxPacket {
        RxPacket {
            endpoint: endpoint(endpoint_id),
            source: source.parse().expect("addr"),
            arrival: 0,
            data: Bytes::copy_from_slice(data),
        }
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    /// Spawn two no-op tasks to stand in for the bridge + drain tasks the registry owns.
    fn idle_tasks() -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        (
            tokio::spawn(std::future::pending()),
            tokio::spawn(std::future::pending()),
        )
    }

    /// A registration plan with the plaintext defaults; individual tests override what they exercise.
    fn plan(
        call_id: &str,
        endpoint_a: EndpointId,
        accepted_source: SourceFilter,
        rtp_in: flume::Sender<Bytes>,
    ) -> WsCallPlan {
        let (bridge_task, drain_task) = idle_tasks();
        WsCallPlan {
            call_id: call_id.to_string(),
            endpoint_a,
            accepted_source,
            ice_pending: false,
            secure: None,
            egress: Arc::new(tokio::sync::watch::Sender::new(address("127.0.0.2:5000"))),
            rtp_in,
            bridge_task,
            drain_task,
        }
    }

    /// A minimal 12-byte RTP header + payload (PT 0, µ-law), enough for SRTP to protect.
    fn rtp_packet(sequence: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0xFFu8; 160]);
        packet
    }

    /// A minimal RTCP receiver report (PT 201) — RFC 5761 §4 demuxes it by the second header byte.
    fn rtcp_packet() -> Vec<u8> {
        let mut packet = vec![0x80, 201, 0x00, 0x01];
        packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
        packet
    }

    fn key(seed: u8) -> SrtpKeyMaterial {
        SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30 bytes")
    }

    /// The engine's leg (`local` = ours, `remote` = the peer's) and the peer's mirror of it.
    fn secure_pair() -> (SecureLeg, SecureLeg) {
        let engine_key = key(0x11);
        let peer_key = key(0x22);
        (
            SecureLeg::new(&engine_key, &peer_key),
            SecureLeg::new(&peer_key, &engine_key),
        )
    }

    #[tokio::test]
    async fn dispatch_forwards_accepted_source_to_the_bridge() {
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        registry.register(plan(
            "call-1",
            endpoint(1),
            SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            rtp_in_tx,
        ));

        assert!(registry.owns(endpoint(1)));
        assert!(registry.is_ws_call("call-1"));

        registry.dispatch(rx(1, "127.0.0.2:5000", b"rtp-frame"));
        let received = rtp_in_rx.try_recv().expect("forwarded to the bridge");
        assert_eq!(&received[..], b"rtp-frame");

        registry.deregister("call-1");
    }

    #[tokio::test]
    async fn dispatch_gates_out_an_off_source_packet() {
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        registry.register(plan(
            "call-1",
            endpoint(1),
            SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            rtp_in_tx,
        ));

        // An attacker on a different IP sprays the endpoint — gated out before any bridge feed.
        registry.dispatch(rx(1, "127.0.0.9:5000", b"attacker"));
        assert!(
            rtp_in_rx.try_recv().is_err(),
            "off-source packet must not reach the bridge"
        );

        registry.deregister("call-1");
    }

    #[tokio::test]
    async fn dispatch_for_an_unowned_endpoint_is_a_noop() {
        let registry = WsRegistry::default();
        // No panic, no route — a datagram for an unknown endpoint is simply dropped.
        registry.dispatch(rx(999, "127.0.0.2:5000", b"orphan"));
        assert!(!registry.owns(endpoint(999)));
    }

    #[tokio::test]
    async fn deregister_stops_owning_and_aborts_the_tasks() {
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        let mut registration = plan("call-1", endpoint(1), SourceFilter::Any, rtp_in_tx);
        let bridge_abort = registration.bridge_task.abort_handle();
        let drain_abort = registration.drain_task.abort_handle();
        registration.ice_pending = false;
        registry.register(registration);
        assert!(registry.owns(endpoint(1)));

        registry.deregister("call-1");
        assert!(!registry.owns(endpoint(1)), "route dropped");
        assert!(!registry.is_ws_call("call-1"), "call dropped");
        // The tasks were aborted (pending() never completes otherwise). `abort()` schedules
        // cancellation asynchronously, so yield until the runtime finalizes both handles.
        for _ in 0..100 {
            if bridge_abort.is_finished() && drain_abort.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(bridge_abort.is_finished(), "bridge task aborted");
        assert!(drain_abort.is_finished(), "drain task aborted");
    }

    #[tokio::test]
    async fn deregister_unknown_call_is_a_noop() {
        let registry = WsRegistry::default();
        registry.deregister("nope"); // must not panic
    }

    // ---- secure (SRTP) takeover legs ------------------------------------------------------------

    #[tokio::test]
    async fn a_secure_leg_decrypts_ingress_before_it_reaches_the_bridge() {
        // RFC 3711: the bridge below speaks clear RTP, so the SRTP termination has to happen on the
        // way in. Feeding it the ciphertext (what a plaintext route would do) hands the decoder noise.
        let (engine_leg, mut peer_leg) = secure_pair();
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let mut registration = plan(
            "secure",
            endpoint(1),
            SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            rtp_in_tx,
        );
        registration.secure = Some(Arc::new(WsSecureLeg::keyed(engine_leg)));
        registry.register(registration);

        let clear = rtp_packet(7, 0x0A0A_0A0A);
        let mut sealed = Vec::new();
        peer_leg.protect(&clear, &mut sealed).expect("peer protect");
        assert_ne!(sealed, clear, "the fixture really is encrypted");

        registry.dispatch(rx(1, "127.0.0.2:5000", &sealed));
        let received = rtp_in_rx.try_recv().expect("decrypted and forwarded");
        assert_eq!(&received[..], &clear[..], "the bridge sees clear RTP");

        registry.deregister("secure");
    }

    #[tokio::test]
    async fn an_unkeyed_secure_leg_forwards_nothing_and_emits_nothing() {
        // The DTLS-SRTP window before the handshake completes. Ciphertext must not reach the decoder,
        // and — the half that actually leaks — the downlink must not fall back to plaintext.
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let pending = Arc::new(WsSecureLeg::pending());
        let mut registration = plan("pending", endpoint(1), SourceFilter::Any, rtp_in_tx);
        registration.secure = Some(pending.clone());
        registry.register(registration);

        assert!(!pending.is_keyed());
        assert_eq!(registry.secure_state("pending"), Some(false));

        registry.dispatch(rx(1, "127.0.0.2:5000", &rtp_packet(1, 1)));
        assert!(
            rtp_in_rx.try_recv().is_err(),
            "an unkeyed leg feeds the bridge nothing"
        );

        let mut out = Vec::new();
        assert!(
            !pending.protect_egress(&rtp_packet(1, 2), &mut out),
            "an unkeyed leg must refuse egress rather than send it in the clear"
        );
        assert!(out.is_empty(), "and must not have produced a datagram");

        registry.deregister("pending");
    }

    #[tokio::test]
    async fn attaching_the_handshake_key_opens_a_pending_secure_leg() {
        // What `PipelineTarget::Ws` does when the RFC 5764 handshake finishes.
        let (engine_leg, mut peer_leg) = secure_pair();
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let mut registration = plan("dtls", endpoint(1), SourceFilter::Any, rtp_in_tx);
        registration.secure = Some(Arc::new(WsSecureLeg::pending()));
        registry.register(registration);

        assert!(registry.attach_secure_leg("dtls", engine_leg), "keyed");
        assert_eq!(registry.secure_state("dtls"), Some(true));

        let clear = rtp_packet(9, 0x0B0B_0B0B);
        let mut sealed = Vec::new();
        peer_leg.protect(&clear, &mut sealed).expect("peer protect");
        registry.dispatch(rx(1, "127.0.0.2:5000", &sealed));
        assert_eq!(
            &rtp_in_rx.try_recv().expect("forwarded")[..],
            &clear[..],
            "media flows once the handshake keys the leg"
        );

        registry.deregister("dtls");
    }

    #[tokio::test]
    async fn attaching_a_key_to_a_plaintext_or_unknown_call_is_refused() {
        // A key with nowhere to go must report failure, so the DTLS bridge leaves the leg dropping
        // rather than believing it opened one.
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        registry.register(plan("plain", endpoint(1), SourceFilter::Any, rtp_in_tx));
        let (leg, _peer) = secure_pair();
        assert!(!registry.attach_secure_leg("plain", leg));
        assert_eq!(registry.secure_state("plain"), None, "not a secure leg");
        let (leg, _peer) = secure_pair();
        assert!(!registry.attach_secure_leg("nope", leg));
        registry.deregister("plain");
    }

    #[tokio::test]
    async fn a_secure_leg_drops_a_forged_packet_and_srtcp() {
        // RFC 3711 §3.3: authentication is what stops an injected packet reaching the decoder. And
        // SRTCP on a muxed takeover port has no consumer, so it is dropped rather than mis-parsed.
        let (engine_leg, _peer) = secure_pair();
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let mut registration = plan("forge", endpoint(1), SourceFilter::Any, rtp_in_tx);
        registration.secure = Some(Arc::new(WsSecureLeg::keyed(engine_leg)));
        registry.register(registration);

        // Plaintext RTP from the gated source: authenticates against nothing, so it is dropped.
        registry.dispatch(rx(1, "127.0.0.2:5000", &rtp_packet(4, 0x0C0C_0C0C)));
        assert!(rtp_in_rx.try_recv().is_err(), "unauthenticated RTP dropped");

        registry.dispatch(rx(1, "127.0.0.2:5000", &rtcp_packet()));
        assert!(rtp_in_rx.try_recv().is_err(), "SRTCP has no consumer");

        registry.deregister("forge");
    }

    #[tokio::test]
    async fn an_ice_pending_leg_forwards_nothing_until_a_pair_is_selected() {
        // RFC 8445 §12 / §7.3.1.3: the gate starts open so a peer-reflexive check can be validated,
        // which is only safe because nothing crosses the leg until the agent decides. Selection then
        // narrows the gate to the chosen pair and re-points the downlink at it (§8.1.1).
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let egress = Arc::new(tokio::sync::watch::Sender::new(address("192.0.2.7:30000")));
        let mut watcher = egress.subscribe();
        let mut registration = plan("ice", endpoint(1), SourceFilter::Any, rtp_in_tx);
        registration.ice_pending = true;
        registration.egress = egress;
        registry.register(registration);

        registry.dispatch(rx(1, "127.0.0.2:5000", b"early"));
        assert!(
            rtp_in_rx.try_recv().is_err(),
            "no media crosses a leg whose ICE agent has not selected"
        );

        let selected = address("203.0.113.9:41000");
        assert!(registry.ice_selected(endpoint(1), selected));
        assert_eq!(
            *watcher.borrow_and_update(),
            selected,
            "the downlink follows the selected pair, not the signalled c="
        );

        registry.dispatch(rx(1, "203.0.113.9:41000", b"selected"));
        assert_eq!(
            &rtp_in_rx.try_recv().expect("forwarded")[..],
            b"selected",
            "the selected pair's media flows"
        );
        registry.dispatch(rx(1, "198.51.100.4:5000", b"other"));
        assert!(
            rtp_in_rx.try_recv().is_err(),
            "and the gate is now narrowed to that pair"
        );

        assert!(
            !registry.ice_selected(endpoint(2), selected),
            "a selection for an endpoint this registry does not own is a no-op"
        );
        registry.deregister("ice");
    }

    #[tokio::test]
    async fn a_keyed_secure_leg_round_trips_egress_to_the_peer() {
        // The engine encrypts with its OWN key and the peer decrypts with it (RFC 4568 key direction).
        let (engine_leg, mut peer_leg) = secure_pair();
        let secure = WsSecureLeg::keyed(engine_leg);
        let clear = rtp_packet(3, 0x0D0D_0D0D);
        let mut sealed = Vec::new();
        assert!(secure.protect_egress(&clear, &mut sealed));
        assert_ne!(sealed, clear, "egress really is encrypted");
        let mut recovered = Vec::new();
        peer_leg
            .unprotect(&sealed, &mut recovered)
            .expect("the peer decrypts our egress with the key we advertised");
        assert_eq!(recovered, clear);
    }
}
