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

use crate::media_pipeline::{rtp_source_ssrc, SymmetricLatch};

/// The SRTP (RFC 3711) crypto of one secure WebSocket-takeover leg: the engine's own key material
/// against the offerer's.
///
/// `None` inside means **not keyed yet**. An SDES leg is keyed at registration (the answer carries
/// the engine's `a=crypto`, so both keys are known synchronously); a DTLS-SRTP leg is keyed only
/// when the RFC 5764 handshake completes, which is after the control command has returned — until
/// then every packet in both directions is dropped.
pub struct WsSecureLeg {
    leg: Mutex<Option<SecureLeg>>,
    /// Mirrors `leg.is_some()` so the control plane can ask whether the handshake has landed without
    /// contending with the per-packet crypto for the mutex. Published only *after* the key is in
    /// place, so it never advertises a leg that cannot crypt. Not consulted on the packet path —
    /// there the `Option` check happens under the lock the crypto needs anyway.
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
    pub fn unprotect_ingress(&self, packet: &[u8]) -> Option<Bytes> {
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

/// Where one takeover leg's downlink is sent, plus the symmetric-RTP latch that steers it.
///
/// One object rather than two fields because the destination and the thing that moves it are a
/// single piece of **leg A** state. A re-point that carried one and not the other would either aim
/// the replacement bridge at the pre-latch address or blind-latch its next packet — the same class
/// of mistake the [`WsRouteState`] doc describes for carrying the egress across a re-point.
///
/// A takeover leg gets none of this from the datapath. It has no reverse relay direction, so no
/// `ForwardRule` faces it and `Datapath::adopt_source` never reaches its egress: this drain
/// destination is the *only* one the leg has. That is why the latch matters more here than on a
/// relay leg, where a wrong initial destination is corrected on the peer's first accepted packet —
/// here nothing corrects it, and the call spends its whole life aimed at the wrong address
/// (docs/security-and-nat.md §4 layer 3).
pub struct WsEgress {
    /// The live downlink destination, read by the drain task per packet. A [`tokio::sync::watch`]
    /// because both the latch below and an ICE selection re-point it mid-call.
    destination: tokio::sync::watch::Sender<SocketAddr>,
    /// The SSRC-consistent symmetric-RTP latch (docs/security-and-nat.md §4 layer 3; RFC 3550 §8),
    /// shared with [`crate::media_pipeline`] so the two userspace `Redirect` paths cannot drift on
    /// what counts as a genuine NAT rebind and what counts as a hijack spray.
    latch: Mutex<SymmetricLatch>,
    /// A full RFC 8445 agent owns this leg's remote transport. Media then never moves the
    /// destination — an authenticated connectivity check is the only thing that may (§4 layer 4;
    /// RFC 8445 §7.3.1.3), which is the same posture the datapath takes by installing
    /// `LatchPolicy::Off` on an ICE relay leg. Fixed for the life of the leg, so it is carried across
    /// a re-point rather than re-derived from `ice_pending`, which a landed selection has cleared.
    ice_managed: bool,
}

impl WsEgress {
    /// A leg's egress, aimed at the address the negotiation seeded — the peer's `received-from`
    /// public IP paired with its signalled media port when the control plane supplied that hint, else
    /// its signalled `c=` address. `ice_managed` marks a leg whose transport an RFC 8445 agent owns.
    #[must_use]
    pub fn new(destination: SocketAddr, ice_managed: bool) -> Self {
        Self {
            destination: tokio::sync::watch::Sender::new(destination),
            latch: Mutex::new(SymmetricLatch::default()),
            ice_managed,
        }
    }

    /// A receiver for the bridge's drain task, which reads the destination once per downlink packet.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<SocketAddr> {
        self.destination.subscribe()
    }

    /// The address the downlink is currently aimed at (observability + tests).
    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        *self.destination.borrow()
    }

    /// Re-point at the pair ICE selected (RFC 8445 §8.1.1). Authoritative: it overrides whatever the
    /// negotiation seeded, and on an `ice_managed` leg it is the only thing that ever moves this.
    fn ice_selected(&self, remote: SocketAddr) {
        // `send_replace`, not `send`: `send` fails and leaves the value untouched once every receiver
        // is gone, which happens the moment a bridge's drain task exits. The watch outlives that task
        // — a re-point reuses it — so a selection landing on a leg whose bridge has died must still be
        // recorded, or the replacement bridge would start out aimed at the pre-ICE address.
        let _ = self.destination.send_replace(remote);
    }

    /// Offer one **accepted** ingress datagram to the symmetric-RTP latch, re-pointing the downlink at
    /// the source the leg's media actually arrives from (docs/security-and-nat.md §4 layer 3).
    ///
    /// `data` must be the plaintext the bridge will consume: the caller applies the source gate and,
    /// on a secure leg, SRTP `unprotect` first, so a forged packet that fails authentication can never
    /// move the destination — the same ordering [`crate::media_pipeline`] enforces. A datagram that is
    /// not RTP media yields no SSRC and is ignored, which is the RFC 7983 layer-1 guard in passing: a
    /// STUN or DTLS record on a muxed takeover port cannot steer the downlink.
    ///
    /// A rejected source only fails to *move* the latch; the packet itself is not dropped, matching
    /// the media pipeline. The gate is the security boundary and this packet has already cleared it.
    fn observe_ingress(&self, source: SocketAddr, data: &[u8]) {
        if self.ice_managed {
            return;
        }
        let Some(ssrc) = rtp_source_ssrc(data) else {
            return;
        };
        // Scoped so the latch is released before the watch is touched — the two are never nested.
        let adopted = {
            let Ok(mut latch) = self.latch.lock() else {
                tracing::error!(
                    "ws egress latch mutex poisoned; the downlink keeps its destination"
                );
                return;
            };
            match latch.observe(source, ssrc) {
                Some(adopted) => adopted,
                None => return, // a new source carrying a different SSRC: keep the current latch
            }
        };
        // Steady state — the latch is already where this packet came from. Skip the watch write so
        // the per-packet path does not mark it changed on every single frame.
        if self.destination.borrow().eq(&adopted) {
            return;
        }
        let previous = self.destination.send_replace(adopted);
        tracing::info!(
            target: "siphon_rtp::media",
            %previous,
            %adopted,
            "ws bridge latched its downlink to the observed media source"
        );
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
    /// Where the bridge's rendered downlink is sent, and the latch that steers it — moved by this
    /// leg's own accepted media (symmetric RTP) or, on an ICE leg, by the agent's selection.
    egress: Arc<WsEgress>,
}

/// The per-leg state a **re-point** ([`Command::AttachWsBridge`](siphon_rtp_proto::Command) on a
/// call that already has a bridge) must carry across from the connection being replaced.
///
/// None of it belongs to the WebSocket: the endpoint, the RTPBleed source gate, the SRTP keying and
/// the egress (its destination and the latch that steers it) are all properties of *leg A*, which
/// does not renegotiate just because its far side moved. Rebuilding them instead of carrying them
/// would silently reopen the source gate, drop a secure leg's keys, and send the new downlink to the
/// signalled `c=` address rather than the address the leg had actually reached the peer on — the
/// pair ICE selected (RFC 8445 §8.1.1), or the source its media latched to. For a NATed peer, both
/// are addresses it cannot receive on.
pub struct WsRouteState {
    /// Leg A's RTP endpoint — already redirected to this registry.
    pub endpoint_a: EndpointId,
    /// The live RTPBleed source gate (narrowed to the selected pair if ICE has chosen one).
    pub accepted_source: SourceFilter,
    /// Whether a full ICE agent still owes this leg a selection.
    pub ice_pending: bool,
    /// The secure leg's SRTP state, shared so the replacement bridge keeps the same keying (and, on
    /// DTLS, the same handle a completing handshake keys).
    pub secure: Option<Arc<WsSecureLeg>>,
    /// The egress destination + its symmetric-RTP latch — carried so a selection or a latch that
    /// already landed still points the new bridge's downlink where the peer is actually reachable,
    /// and so the replacement does not blind-latch its first packet.
    pub egress: Arc<WsEgress>,
}

/// Everything the registry needs to route and tear down one running WS-bridge call.
pub struct WsCallPlan {
    /// The call this bridge belongs to.
    pub call_id: String,
    /// Leg A's RTP endpoint — the redirected endpoint this call owns.
    pub endpoint_a: EndpointId,
    /// Signalled-source gate for leg A's ingress (RTPBleed defence).
    pub accepted_source: SourceFilter,
    /// A full RFC 8445 agent runs on this leg and has not selected a pair yet: the source gate is
    /// open for peer-reflexive checks (§7.3.1.3), so **all** media is dropped until the selection
    /// lands and [`WsRegistry::ice_selected`] narrows the gate to the chosen pair.
    pub ice_pending: bool,
    /// SRTP crypto for a secure (SDES or DTLS) takeover leg; `None` on a plaintext one.
    pub secure: Option<Arc<WsSecureLeg>>,
    /// Where the drain task sends the rendered downlink, shared so the latch and ICE can re-point it.
    pub egress: Arc<WsEgress>,
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
        route.egress.ice_selected(remote);
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
        // Symmetric-RTP latch (docs/security-and-nat.md §4 layer 3): aim the downlink at the source
        // this leg's media actually arrives from. Offered after the gate above and after SRTP auth,
        // so only an authentic packet from an accepted source can move it, and skipped entirely on an
        // ICE leg where the agent's selection owns the transport (§4 layer 4).
        //
        // Nothing else corrects this destination. A relay leg is aimed by its `ForwardRule` and
        // re-aimed by the datapath's own latch on the peer's first accepted packet; a takeover leg has
        // no reverse relay direction and no forward rule, so a destination the signalling got wrong
        // stays wrong for the life of the call unless it is fixed here.
        route.egress.observe_ingress(packet.source, &payload);
        // Drop on a full or closed mailbox — late audio is worthless, and a closed channel means the
        // bridge task has already exited.
        if route.rtp_in.try_send(payload).is_err() {
            tracing::trace!(
                "ws-bridge rtp-in mailbox full or closed; dropping redirected datagram"
            );
        }
    }

    /// The live per-leg state of `call_id`'s bridge, for standing a replacement up on the same leg
    /// (see [`WsRouteState`]). `None` when this call has no bridge.
    #[must_use]
    pub fn route_state(&self, call_id: &str) -> Option<WsRouteState> {
        let endpoint_a = self.calls.get(call_id)?.endpoint_a;
        let route = self.routes.get(&endpoint_a)?;
        Some(WsRouteState {
            endpoint_a,
            accepted_source: route.accepted_source,
            ice_pending: route.ice_pending,
            secure: route.secure.clone(),
            egress: route.egress.clone(),
        })
    }

    /// Tear a WS-bridge call down: drop its route and abort the bridge + drain tasks (closing the WS
    /// connection and the RTP-out drain). The WS half of call teardown.
    ///
    /// Returns the two aborted task handles so the caller can **await** them. `abort()` only
    /// schedules cancellation, so a caller that returns here leaves the WebSocket socket, the
    /// bridge's codec state and the drain's buffers alive for an unbounded moment — the same reason
    /// [`crate::engine`]'s tee teardown awaits its transport. It matters more here than for a tee: a
    /// re-point stands a *replacement* bridge up on the same endpoint, and the outgoing drain task
    /// must be gone before the new one starts writing, or two drains briefly interleave RTP (two
    /// sequence-number and timestamp series, RFC 3550 §5.1) toward the same peer. A no-op returning
    /// `None` for a call this registry does not hold.
    pub fn deregister(&self, call_id: &str) -> Option<WsCallTasks> {
        let (_, handle) = self.calls.remove(call_id)?;
        self.routes.remove(&handle.endpoint_a);
        handle.bridge_task.abort();
        handle.drain_task.abort();
        Some(WsCallTasks {
            bridge_task: handle.bridge_task,
            drain_task: handle.drain_task,
        })
    }
}

/// The two aborted tasks of a torn-down bridge, handed back by [`WsRegistry::deregister`] so the
/// caller can await their cancellation rather than racing it.
pub struct WsCallTasks {
    bridge_task: tokio::task::JoinHandle<()>,
    drain_task: tokio::task::JoinHandle<()>,
}

impl WsCallTasks {
    /// Wait for both aborted tasks to actually finish. Each resolves promptly with
    /// `JoinError::Cancelled` — both are cancel-safe select loops.
    pub async fn joined(self) {
        let _ = self.bridge_task.await;
        let _ = self.drain_task.await;
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
            egress: Arc::new(WsEgress::new(address("127.0.0.2:5000"), false)),
            rtp_in,
            bridge_task,
            drain_task,
        }
    }

    /// Where the registry would currently send `call_id`'s downlink.
    fn downlink(registry: &WsRegistry, call_id: &str) -> SocketAddr {
        registry
            .route_state(call_id)
            .expect("the call has a route")
            .egress
            .destination()
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

    /// A STUN Binding request's first byte (RFC 7983 demux class 0..=3), padded to RTP length so the
    /// only thing keeping it away from the latch is the demux, not the length check.
    fn stun_shaped_packet() -> Vec<u8> {
        let mut packet = vec![0x00, 0x01, 0x00, 0x08];
        packet.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        packet.extend_from_slice(&[0x11u8; 16]);
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

        let _ = registry.deregister("call-1");
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

        let _ = registry.deregister("call-1");
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

        let _ = registry.deregister("call-1");
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
        assert!(
            registry.deregister("nope").is_none(),
            "an unknown call yields no tasks to await, and must not panic"
        );
        assert!(registry.route_state("nope").is_none());
    }

    #[tokio::test]
    async fn route_state_hands_a_re_point_the_leg_state_it_must_not_rebuild() {
        // What a re-point carries across. The egress watch and the SRTP leg are shared *handles*, not
        // copies: an ICE selection that lands between the two bridges still steers the new downlink,
        // and a DTLS handshake completing in the same window still keys the leg. Rebuilding either
        // would send the replacement bridge's audio to the signalled address the NATed peer cannot
        // receive on, or leave a secure leg dropping every packet.
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        let (bridge_task, drain_task) = idle_tasks();
        let egress = Arc::new(WsEgress::new(address("127.0.0.2:5000"), true));
        let secure = Arc::new(WsSecureLeg::pending());
        registry.register(WsCallPlan {
            call_id: "call-1".to_string(),
            endpoint_a: endpoint(1),
            accepted_source: SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            ice_pending: true,
            secure: Some(secure.clone()),
            egress: egress.clone(),
            rtp_in: rtp_in_tx,
            bridge_task,
            drain_task,
        });

        // ICE selects a pair: the gate narrows and the watch is re-pointed.
        assert!(registry.ice_selected(endpoint(1), address("203.0.113.9:40000")));

        let state = registry.route_state("call-1").expect("a live route");
        assert_eq!(state.endpoint_a, endpoint(1));
        assert!(!state.ice_pending, "the selection cleared the pending flag");
        assert_eq!(
            state.accepted_source,
            SourceFilter::Exact(Ipv4Addr::new(203, 0, 113, 9).into()),
            "the narrowed gate, not the one the SDP signalled"
        );
        assert_eq!(
            state.egress.destination(),
            address("203.0.113.9:40000"),
            "the selected pair, carried on the same egress"
        );
        assert!(
            Arc::ptr_eq(&state.egress, &egress),
            "the very same egress, so a later selection reaches the replacement bridge too"
        );
        assert!(
            Arc::ptr_eq(state.secure.as_ref().expect("a secure leg"), &secure),
            "the very same SRTP leg, so a completing DTLS handshake still keys it"
        );

        let tasks = registry.deregister("call-1").expect("the two tasks");
        tasks.joined().await;
        assert!(!registry.owns(endpoint(1)));
        assert!(registry.route_state("call-1").is_none());
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

        let _ = registry.deregister("secure");
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

        let _ = registry.deregister("pending");
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

        let _ = registry.deregister("dtls");
    }

    #[tokio::test]
    async fn the_first_accepted_packet_latches_the_downlink_to_its_observed_source() {
        // R5: a takeover leg has no reverse relay direction, so no `ForwardRule` and no datapath
        // latch face it — this registry is the only thing that can correct a downlink the signalling
        // aimed at an address the peer cannot receive on. Without it a NATed caller hears nothing for
        // the entire call, not merely until something latches.
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        registry.register(plan(
            "latch",
            endpoint(1),
            SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            rtp_in_tx,
        ));
        assert_eq!(
            downlink(&registry, "latch"),
            address("127.0.0.2:5000"),
            "before any media, the downlink sits on the address the negotiation seeded"
        );

        // The caller's media actually arrives from a different port than its `c=` advertised.
        registry.dispatch(rx(1, "127.0.0.2:41000", &rtp_packet(1, 0x0A0A_0A0A)));
        assert_eq!(
            downlink(&registry, "latch"),
            address("127.0.0.2:41000"),
            "the downlink follows the source the media actually came from"
        );

        let _ = registry.deregister("latch");
    }

    #[tokio::test]
    async fn a_same_ssrc_rebind_moves_the_downlink_but_a_different_ssrc_spray_does_not() {
        // docs/security-and-nat.md §4 layer 3 / RFC 3550 §8, matching the datapath's `update_latch`
        // and the media pipeline's `SymmetricLatch`: follow a genuine NAT rebind, resist a spray.
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        registry.register(plan(
            "rebind",
            endpoint(1),
            SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            rtp_in_tx,
        ));

        registry.dispatch(rx(1, "127.0.0.2:41000", &rtp_packet(1, 0x0A0A_0A0A)));
        assert_eq!(downlink(&registry, "rebind"), address("127.0.0.2:41000"));

        // Same stream, new port: the NAT rebound. Follow it.
        registry.dispatch(rx(1, "127.0.0.2:41001", &rtp_packet(2, 0x0A0A_0A0A)));
        assert_eq!(
            downlink(&registry, "rebind"),
            address("127.0.0.2:41001"),
            "a same-SSRC rebind re-points the downlink"
        );

        // An attacker on the same address (it passed the gate) spraying its own stream must not be
        // able to steal the downlink — that is the RTPbleed shape this rule exists for.
        registry.dispatch(rx(1, "127.0.0.2:41002", &rtp_packet(3, 0xDEAD_BEEF)));
        assert_eq!(
            downlink(&registry, "rebind"),
            address("127.0.0.2:41001"),
            "a new source carrying a different SSRC never moves the downlink"
        );

        let _ = registry.deregister("rebind");
    }

    #[tokio::test]
    async fn only_rtp_media_can_move_the_downlink() {
        // The RFC 7983 layer-1 guard, in passing: on a muxed takeover port a STUN check, a DTLS
        // record, RTCP or a runt must not be able to steer where the call's audio goes.
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        registry.register(plan("demux", endpoint(1), SourceFilter::Any, rtp_in_tx));

        for (label, datagram) in [
            ("stun", stun_shaped_packet()),
            ("rtcp", rtcp_packet()),
            ("runt", vec![0x80, 0x00, 0x00, 0x01]),
            ("dtls", vec![0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ] {
            registry.dispatch(rx(1, "127.0.0.9:41000", &datagram));
            assert_eq!(
                downlink(&registry, "demux"),
                address("127.0.0.2:5000"),
                "a {label} datagram must not move the downlink"
            );
        }

        // …and real RTP from the same source still does, so the guard is the demux and not inertia.
        registry.dispatch(rx(1, "127.0.0.9:41000", &rtp_packet(1, 0x0A0A_0A0A)));
        assert_eq!(downlink(&registry, "demux"), address("127.0.0.9:41000"));

        let _ = registry.deregister("demux");
    }

    #[tokio::test]
    async fn an_ice_leg_takes_its_downlink_only_from_the_agent_never_from_media() {
        // docs/security-and-nat.md §4 layer 4 / RFC 8445 §7.3.1.3: on an ICE leg the authenticated
        // connectivity check is the only thing that adopts a transport, so media must not latch —
        // the same posture the datapath takes by installing `LatchPolicy::Off` on an ICE relay leg.
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        let mut registration = plan("ice", endpoint(1), SourceFilter::Any, rtp_in_tx);
        registration.ice_pending = true;
        registration.egress = Arc::new(WsEgress::new(address("127.0.0.2:5000"), true));
        registry.register(registration);

        assert!(registry.ice_selected(endpoint(1), address("127.0.0.2:6000")));
        assert_eq!(
            downlink(&registry, "ice"),
            address("127.0.0.2:6000"),
            "the agent's selection is what aims an ICE leg"
        );

        // Media from another port on the selected address passes the narrowed gate, and still must
        // not move the downlink.
        registry.dispatch(rx(1, "127.0.0.2:7000", &rtp_packet(1, 0x0A0A_0A0A)));
        assert_eq!(
            downlink(&registry, "ice"),
            address("127.0.0.2:6000"),
            "media never re-points an ICE leg"
        );

        let _ = registry.deregister("ice");
    }

    #[tokio::test]
    async fn a_secure_leg_latches_only_on_a_packet_that_authenticates() {
        // Ordering: gate, then SRTP auth, then latch. A forged packet that fails RFC 3711 §3.3
        // authentication must not be able to redirect a secure call's audio at an attacker.
        let (engine_leg, mut peer_leg) = secure_pair();
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        let mut registration = plan("secure-latch", endpoint(1), SourceFilter::Any, rtp_in_tx);
        registration.secure = Some(Arc::new(WsSecureLeg::keyed(engine_leg)));
        registry.register(registration);

        // Plaintext RTP from a fresh source: it clears the (open) gate and fails to decrypt.
        registry.dispatch(rx(1, "127.0.0.3:41000", &rtp_packet(1, 0x0A0A_0A0A)));
        assert_eq!(
            downlink(&registry, "secure-latch"),
            address("127.0.0.2:5000"),
            "a packet that fails SRTP authentication never reaches the latch"
        );

        // The real peer, from the same source: authentic, so it does latch.
        let mut sealed = Vec::new();
        peer_leg
            .protect(&rtp_packet(2, 0x0B0B_0B0B), &mut sealed)
            .expect("peer protect");
        registry.dispatch(rx(1, "127.0.0.3:41000", &sealed));
        assert_eq!(
            downlink(&registry, "secure-latch"),
            address("127.0.0.3:41000"),
            "an authentic stream latches the downlink toward it"
        );

        let _ = registry.deregister("secure-latch");
    }

    #[tokio::test]
    async fn a_re_point_carries_the_latch_so_the_replacement_does_not_blind_latch() {
        // `WsRouteState` exists so a replacement bridge inherits leg A's state rather than rebuilding
        // it. The latch is part of that: carry the destination but not the latch and the replacement
        // adopts whatever source speaks first, which is exactly the blind latch the SSRC rule forbids.
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        registry.register(plan("repoint", endpoint(1), SourceFilter::Any, rtp_in_tx));
        registry.dispatch(rx(1, "127.0.0.2:41000", &rtp_packet(1, 0x0A0A_0A0A)));

        let carried = registry.route_state("repoint").expect("route state").egress;
        assert_eq!(carried.destination(), address("127.0.0.2:41000"));
        let _ = registry.deregister("repoint");

        // Stand the replacement up on the carried state, exactly as `start_ws_bridge` does.
        let (rtp_in_tx, _rtp_in_rx2) = flume::unbounded::<Bytes>();
        let mut registration = plan("repoint", endpoint(1), SourceFilter::Any, rtp_in_tx);
        registration.egress = carried;
        registry.register(registration);

        assert_eq!(
            downlink(&registry, "repoint"),
            address("127.0.0.2:41000"),
            "the replacement starts where the leg had actually reached the peer"
        );
        registry.dispatch(rx(1, "127.0.0.2:41009", &rtp_packet(2, 0xDEAD_BEEF)));
        assert_eq!(
            downlink(&registry, "repoint"),
            address("127.0.0.2:41000"),
            "and it still knows the stream's SSRC, so a spray cannot steal it"
        );

        let _ = registry.deregister("repoint");
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
        let _ = registry.deregister("plain");
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

        let _ = registry.deregister("forge");
    }

    #[tokio::test]
    async fn an_ice_pending_leg_forwards_nothing_until_a_pair_is_selected() {
        // RFC 8445 §12 / §7.3.1.3: the gate starts open so a peer-reflexive check can be validated,
        // which is only safe because nothing crosses the leg until the agent decides. Selection then
        // narrows the gate to the chosen pair and re-points the downlink at it (§8.1.1).
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let egress = Arc::new(WsEgress::new(address("192.0.2.7:30000"), true));
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
        assert_eq!(
            *watcher.borrow_and_update(),
            selected,
            "and it does not move the downlink — on an ICE leg only the agent may (§4 layer 4)"
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
        let _ = registry.deregister("ice");
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
