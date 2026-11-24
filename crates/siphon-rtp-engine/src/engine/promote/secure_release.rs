//! Giving a held crypto-bridged call back to its bridge, and keeping it held across a re-offer.
//!
//! **Release mirrors the hold.** The bridge's flows are registered *first*, refusing everything until
//! they know where each stream stands; the dispatcher checks the bridge before the media registry, so
//! the endpoints have an owner throughout. Only then is the actor stopped, its final stream positions,
//! gates, destinations and taps read, and the flows told, which starts them forwarding. If the actor
//! cannot report, the flows still start, under a fresh SSRC with the peer's own numbering (never the old SSRC, which the actor may have run ahead on): the call keeps a working
//! media path, and a stream that changes SSRC is legitimate (RFC 3550 §8.2). A DTLS key is taken out
//! of its shared handle by swapping, never by unwrapping the handle, so no other holder can make the
//! release fail.
//!
//! **A re-offer answered while held** stops the old actor *first* ([`Engine::carry_held_actor`]) and
//! hands its live `SecureLeg`s, final stream positions and taps to the replacement, rather than
//! snapshotting counters off a running actor and rebuilding: two contexts under one key would both
//! number the same SRTCP index, and a restarted replay window would accept what the old one refused
//! (RFC 3711 §3.3.2, §9.1).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use siphon_rtp_datapath::{Datapath, EndpointId, SourceFilter};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::{CryptoAttribute, SrtpKeyMaterial};

use crate::dtls_bridge::hold::DtlsGiveBack;
use crate::dtls_bridge::PlainRtcp;
use crate::media_pipeline::{HeldBack, HeldEgress, HeldResume, HeldTaps, MediaCall, MediaControl};
use crate::srtp_bridge::hold::{CarriedFlow, FinishedFlow, SharedBridgePlan};
use crate::srtp_bridge::{BridgeFlowPlan, BridgeLeg};

use super::super::{Engine, Leg, PipelineKind};
use super::secure_hold::{HeldDirections, SdesRtcp, SecureHold};

/// What an actor stopped for a re-offer's answer leaves its replacement.
#[derive(Clone)]
pub(in crate::engine) struct HeldCarry {
    near_leg: Option<Arc<Mutex<SecureLeg>>>,
    far_leg: Option<Arc<Mutex<SecureLeg>>>,
    /// Each direction's final stream position, destination and taps, when the actor reported them.
    held: Option<[HeldBack; 2]>,
    rtcp: Vec<(EndpointId, SourceFilter, SocketAddr)>,
}

/// What an answer to a re-offer did to a split's hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::engine) enum HeldAnswer {
    /// The call was not held; it takes the kind the answer resolved.
    Unheld(PipelineKind),
    /// The call stays held, on the actor's kind.
    Kept(PipelineKind),
    /// A DTLS re-handshake ended the hold (the call is back on its bridge); the answer installs its
    /// resolved kind. What a later change turns into an event.
    ReleasedForRekey(PipelineKind),
}

impl HeldAnswer {
    /// The kind the answer installs.
    pub(in crate::engine) fn pipeline(self) -> PipelineKind {
        match self {
            Self::Unheld(kind) | Self::Kept(kind) | Self::ReleasedForRekey(kind) => kind,
        }
    }
}

/// The `SecureLeg` inside a shared handle, taken out by swapping in an inert placeholder (keys of
/// zero, which authenticates nothing real). It cannot fail for want of being the last holder, and a
/// holder that outlives the release finds a leg that refuses everything instead of one that shares
/// the index space of the real one.
pub(super) fn take_leg(shared: &Arc<Mutex<SecureLeg>>) -> Option<SecureLeg> {
    let inert = SrtpKeyMaterial::from_inline_bytes(&[0u8; 30]).ok()?;
    let mut guard = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Some(std::mem::replace(
        &mut *guard,
        SecureLeg::new(&inert, &inert),
    ))
}

/// The leg a replacement actor uses for one party: the very object the old actor held, with only the
/// key(s) that changed replaced (`changed` is `(sending key, receiving key)`), so the send window
/// of a key that stays is never forgotten (RFC 3711 §9.1).
pub(in crate::engine) fn carried_leg(
    carried: Option<&Arc<Mutex<SecureLeg>>>,
    changed: (bool, bool),
    (local, remote): (&CryptoAttribute, &CryptoAttribute),
) -> Option<Arc<Mutex<SecureLeg>>> {
    let live = carried?;
    if changed.0 || changed.1 {
        let mut leg = live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        leg.rekey(
            changed.0.then_some(&local.key),
            changed.1.then_some(&remote.key),
        );
    }
    Some(live.clone())
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Give a held call back to its crypto bridge. Registers the bridge's side first, then stops the
    /// actor and starts the bridge from where the actor left each stream. On a failure before the
    /// bridge is registered the call stays held, with its actor running.
    pub(in crate::engine) async fn release_secure_hold(&self, call_id: &str) -> Result<(), String> {
        let Some((hold, near, far)) = self
            .owned_call_internal(call_id, |call| {
                Some((call.secure_hold.clone()?, call.near, call.far?))
            })
            .flatten()
        else {
            return Ok(());
        };
        if !hold.original.is_crypto_bridge() {
            // A re-offer made the call one that needs the decoded audio whatever the split does: the
            // actor is the call's own pipeline now, and there is no bridge to give back.
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.secure_hold = None;
            }
            return Ok(());
        }
        match hold.original {
            PipelineKind::Srtp | PipelineKind::SrtpOfferer | PipelineKind::SrtpTranscrypt => {
                self.release_sdes_bridge(call_id, &hold, near, far).await?;
            }
            _ => self.release_dtls_bridge(call_id, &hold, near, far).await?,
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = hold.original;
            call.secure_hold = None;
        }
        // What was attached to the call rides the path it is on now: a tee or a recording that
        // followed a re-offer onto the actor's sinks is put back on the bridge's taps.
        self.carry_holds_across_answer(call_id).await;
        Ok(())
    }

    async fn release_sdes_bridge(
        &self,
        call_id: &str,
        hold: &SecureHold,
        near: Leg,
        far: Leg,
    ) -> Result<(), String> {
        let (near_side, far_side) = match hold.original {
            PipelineKind::Srtp => (None, Some(BridgeLeg::Far)),
            PipelineKind::SrtpOfferer => (Some(BridgeLeg::Near), None),
            _ => (Some(BridgeLeg::Near), Some(BridgeLeg::Far)),
        };
        let (near_leg, far_leg) = self.media.secure_legs(call_id);
        if (near_side.is_some() && near_leg.is_none()) || (far_side.is_some() && far_leg.is_none())
        {
            return Err("the held call's actor holds no SRTP leg to give back".to_string());
        }
        let plan = |endpoint: EndpointId| {
            hold.plans
                .iter()
                .find(|plan| plan.endpoint == endpoint)
                .copied()
        };
        // Each flow starts from the gate and destination it had; the actor's own, which a latch or an
        // ICE selection may have moved, replace them once it has stopped.
        let flow = |endpoint: EndpointId,
                    (ingress_leg, egress_leg): (Option<BridgeLeg>, Option<BridgeLeg>),
                    latch: bool,
                    out_endpoint: EndpointId,
                    (own, other): (Option<SocketAddr>, Option<SocketAddr>)| {
            let known = plan(endpoint);
            Some(BridgeFlowPlan {
                endpoint,
                ingress_leg,
                egress_leg,
                accepted_source: known
                    .map(|known| known.accepted_source)
                    .or_else(|| own.map(|own| SourceFilter::Exact(own.ip())))?,
                latch,
                out_endpoint,
                out_dst: known.map(|known| known.out_dst).or(other)?,
            })
        };
        let missing = || "the held call has no address to give its bridge".to_string();
        let mut flows = vec![
            flow(
                near.rtp.id,
                (near_side, far_side),
                hold.latch.0,
                far.rtp.id,
                (near.remote_rtp, far.remote_rtp),
            )
            .ok_or_else(missing)?,
            flow(
                far.rtp.id,
                (far_side, near_side),
                hold.latch.1,
                near.rtp.id,
                (far.remote_rtp, near.remote_rtp),
            )
            .ok_or_else(missing)?,
        ];
        if let Some((near_rtcp, far_rtcp)) = near.rtcp.zip(far.rtcp) {
            flows.extend(
                [
                    flow(
                        near_rtcp.id,
                        (near_side, far_side),
                        hold.latch.0,
                        far_rtcp.id,
                        (near.remote_rtcp, far.remote_rtcp),
                    ),
                    flow(
                        far_rtcp.id,
                        (far_side, near_side),
                        hold.latch.1,
                        near_rtcp.id,
                        (far.remote_rtcp, near.remote_rtcp),
                    ),
                ]
                .into_iter()
                .flatten(),
            );
        }
        let carried = [near.rtp.id, far.rtp.id]
            .into_iter()
            .map(|endpoint| CarriedFlow {
                endpoint,
                resume: None,
                awaiting: true,
                taps: HeldTaps::default(),
            })
            .collect();
        // Registered first: from here the bridge owns the endpoints and forwards nothing.
        self.bridge.register_shared(SharedBridgePlan {
            near_leg,
            far_leg,
            flows,
            carried,
        });
        let surrendered = self.media.surrender(call_id).await;
        if surrendered.is_none() {
            tracing::error!(
                target: "siphon_rtp::media",
                call_id,
                "the held call's actor did not report its streams; the bridge carries on from the \
                 peers' own numbering under a fresh SSRC"
            );
        }
        let held = |index: usize| surrendered.as_ref().map(|state| &state.held[index]);
        for (endpoint, index) in [(near.rtp.id, 0), (far.rtp.id, 1)] {
            self.bridge.finish_release(FinishedFlow {
                endpoint,
                gate: held(index).map(|back| back.ingress.1),
                destination: held(index).map(|back| back.destination),
                next: held(index).map(|back| back.next),
                lost: surrendered.is_none(),
                taps: held(index).map(|back| back.taps.clone()),
            });
        }
        for (endpoint, gate, destination) in surrendered.iter().flat_map(|state| state.rtcp.iter())
        {
            self.bridge.finish_release(FinishedFlow {
                endpoint: *endpoint,
                gate: Some(*gate),
                destination: Some(*destination),
                next: None,
                lost: false,
                taps: None,
            });
        }
        Ok(())
    }

    async fn release_dtls_bridge(
        &self,
        call_id: &str,
        hold: &SecureHold,
        near: Leg,
        far: Leg,
    ) -> Result<(), String> {
        let secure_is_near = hold.original == PipelineKind::DtlsOfferer;
        let (secure, plain) = if secure_is_near {
            (near, far)
        } else {
            (far, near)
        };
        let (plain_gate, plain_dst, plain_rtcp) = hold
            .plain
            .ok_or_else(|| "the held DTLS call has no plain side to give back".to_string())?;
        let dtls = self.dtls_bridge();
        // Registered first: the plain endpoint belongs to the bridge from here, forwarding nothing.
        dtls.release_begin(secure.rtp.id, plain.rtp.id, plain_gate, plain_rtcp)
            .map_err(str::to_string)?;
        let surrendered = self.media.surrender(call_id).await;
        if surrendered.is_none() {
            tracing::error!(
                target: "siphon_rtp::media",
                call_id,
                "the held call's actor did not report its streams; the bridge carries on from the \
                 peers' own numbering under a fresh SSRC"
            );
        }
        let retained = dtls.take_retained(secure.rtp.id);
        let leg = retained
            .as_ref()
            .and_then(take_leg)
            .ok_or_else(|| "the held DTLS leg is no longer retained".to_string())?;
        // The stream toward each party is the other direction's egress.
        let [near_back, far_back] = match &surrendered {
            Some(state) => [Some(&state.held[0]), Some(&state.held[1])],
            None => [None, None],
        };
        let (secure_back, plain_back) = if secure_is_near {
            (near_back, far_back)
        } else {
            (far_back, near_back)
        };
        let toward_plain = if secure_is_near { near_back } else { far_back };
        let toward_secure = if secure_is_near { far_back } else { near_back };
        let give = DtlsGiveBack {
            leg,
            plain_endpoint: plain.rtp.id,
            plain_gate: plain_back.map_or(plain_gate, |back| back.ingress.1),
            plain_dst: if secure_is_near {
                near_back.map_or(plain_dst, |back| back.destination)
            } else {
                far_back.map_or(plain_dst, |back| back.destination)
            },
            plain_rtcp,
            positions_lost: surrendered.is_none(),
            next_toward_plain: toward_plain.map(|back| back.next),
            next_toward_secure: toward_secure.map(|back| back.next),
            secure_taps: secure_back
                .map(|back| back.taps.clone())
                .unwrap_or_default(),
            plain_taps: plain_back.map(|back| back.taps.clone()).unwrap_or_default(),
        };
        dtls.release(secure.rtp.id, give).map_err(str::to_string)
    }

    // ---- A re-offer while held -----------------------------------------------------------------

    /// What the answer to a re-offer resolved to, for a call that may be held: while a split is held
    /// the call stays on the actor's kind, so the answer rebuilds the **actor**. A DTLS re-handshake
    /// (a changed peer certificate, RFC 8842 §3.1) cannot be kept: the new association keys a leg the
    /// actor does not have, so the hold is released first, cleanly back onto its bridge, and the
    /// answer then installs the new association the ordinary way, so there is never a half-keyed leg.
    pub(in crate::engine) async fn settle_held_pipeline(
        &self,
        call_id: &str,
        resolved: PipelineKind,
        fingerprints: (
            Option<&crate::sdp::Fingerprint>,
            Option<&crate::sdp::Fingerprint>,
        ),
    ) -> HeldAnswer {
        let Some((hold, near, far)) = self
            .owned_call_internal(call_id, |call| {
                Some((call.secure_hold.clone()?, call.near, call.far?))
            })
            .flatten()
        else {
            return HeldAnswer::Unheld(resolved);
        };
        let (secure, changed) = match hold.original {
            PipelineKind::Dtls => (far.rtp.id, fingerprints.0),
            PipelineKind::DtlsOfferer => (near.rtp.id, fingerprints.1),
            _ => (far.rtp.id, None),
        };
        let rekeyed = changed.is_some_and(|fingerprint| {
            self.dtls_bridge().fingerprint_differs(
                secure,
                &fingerprint.hash_function,
                &fingerprint.bytes,
            )
        });
        if rekeyed {
            tracing::info!(
                target: "siphon_rtp::media",
                call_id,
                "a DTLS re-handshake ends the hold: the call goes back to its bridge first"
            );
            if let Err(reason) = self.release_secure_hold(call_id).await {
                tracing::error!(target: "siphon_rtp::media", call_id, reason, "held call could not go back to its bridge");
            }
            return HeldAnswer::ReleasedForRekey(resolved);
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(held) = call.secure_hold.as_mut() {
                held.original = resolved;
            }
        }
        HeldAnswer::Kept(resolved.held_twin().unwrap_or(resolved))
    }

    /// Stop the actor of a held call that an answer is about to replace, and keep what it leaves: its
    /// live legs, its final stream positions and its taps ([`Self::hold_carry`]). Called right before
    /// the answer installs the replacement, so the endpoints are without an actor for as short as
    /// the install takes; [`Self::restore_held_actor`] covers an install that fails.
    pub(in crate::engine) async fn carry_held_actor(&self, call_id: &str) {
        if !self.is_secure_held(call_id) || !self.media.is_media_call(call_id) {
            return;
        }
        let (near_leg, far_leg) = self.media.secure_legs(call_id);
        let surrendered = self.media.surrender(call_id).await;
        if surrendered.is_none() {
            tracing::error!(
                target: "siphon_rtp::media",
                call_id,
                "the held call's actor did not report its streams; the replacement numbers its own"
            );
        }
        let carry = HeldCarry {
            near_leg,
            far_leg,
            held: surrendered.as_ref().map(|state| state.held.clone()),
            rtcp: surrendered.map(|state| state.rtcp).unwrap_or_default(),
        };
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(held) = call.secure_hold.as_mut() {
                held.carry = Some(Box::new(carry));
            }
        }
    }

    /// What [`Self::carry_held_actor`] kept, for the install that replaces the actor.
    pub(in crate::engine) fn hold_carry(&self, call_id: &str) -> Option<HeldCarry> {
        self.owned_call_internal(call_id, |call| {
            call.secure_hold
                .as_ref()
                .and_then(|hold| hold.carry.as_deref().cloned())
        })
        .flatten()
    }

    /// The answer has installed its replacement: what it carried is no longer needed.
    pub(in crate::engine) fn clear_hold_carry(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(held) = call.secure_hold.as_mut() {
                held.carry = None;
            }
        }
    }

    /// The live SDES leg a replacement actor takes over for `party`, or `None` when nothing was
    /// carried. `recorded` is what the call last negotiated for that party and `now` what this answer
    /// does; unchanged keys keep the object, new ones get a leg that carries its counters.
    pub(in crate::engine) fn carried_sdes_leg(
        &self,
        call_id: &str,
        far: bool,
        now: (&CryptoAttribute, &CryptoAttribute),
    ) -> Option<Arc<Mutex<SecureLeg>>> {
        let carry = self.hold_carry(call_id)?;
        let (recorded_local, recorded_remote) = self.owned_call_internal(call_id, |call| {
            if far {
                (call.far_local_crypto, call.far_remote_crypto)
            } else {
                (call.near_local_crypto, call.near_remote_crypto)
            }
        })?;
        let live = if far { &carry.far_leg } else { &carry.near_leg };
        carried_leg(
            live.as_ref(),
            (
                recorded_local != Some(*now.0),
                recorded_remote != Some(*now.1),
            ),
            now,
        )
    }

    /// Put the stream positions, taps and (on a DTLS leg whose plain peer keeps RTCP on a port of its
    /// own) the RTCP relay a stopped actor left onto its replacement, before the replacement is
    /// registered, so its first packet already continues what the old one sent. `dtls` names the DTLS
    /// leg's endpoint and destination, and whether it is A.
    pub(in crate::engine) fn apply_hold_carry(
        &self,
        call_id: &str,
        mut call: MediaCall,
        dtls: Option<(EndpointId, SocketAddr, bool, Option<PlainRtcp>)>,
        signalled: (Option<SocketAddr>, Option<SocketAddr>),
    ) -> MediaCall {
        let Some((carry, previous)) = self
            .owned_call_internal(call_id, |call| {
                call.secure_hold
                    .as_ref()
                    .map(|hold| (hold.carry.as_deref().cloned(), hold.signalled))
            })
            .flatten()
        else {
            return call;
        };
        if let Some(mut record) = self.calls.get_mut(call_id) {
            if let Some(hold) = record.secure_hold.as_mut() {
                hold.signalled = signalled;
            }
        }
        // The plain peer's RTCP routing comes from the answer being installed, not from what the hold
        // recorded: a re-offer may have moved it (RFC 5761 §5.1.1).
        if let Some((_, _, _, new_rtcp)) = dtls {
            if let Some(mut held) = self.calls.get_mut(call_id) {
                if let Some(hold) = held.secure_hold.as_mut() {
                    if let Some((_, _, rtcp)) = hold.plain.as_mut() {
                        *rtcp = new_rtcp;
                    }
                }
            }
        }
        let rtcp = match (dtls.and_then(|(_, _, _, rtcp)| rtcp), dtls) {
            (Some(rtcp), Some((secure_endpoint, secure_destination, secure_is_near, _))) => {
                call = call.with_rtcp_relays(vec![Self::plain_rtcp_relay(
                    &rtcp,
                    secure_endpoint,
                    secure_destination,
                )]);
                Some(((rtcp.endpoint, rtcp.dst), secure_is_near))
            }
            _ => None,
        };
        // The plain peer is the one RTCP goes to its own port for: toward A when A is the plain one.
        let rtcp_a = rtcp.and_then(|(out, secure_is_near)| (!secure_is_near).then_some(out));
        let rtcp_b = rtcp.and_then(|(out, secure_is_near)| secure_is_near.then_some(out));
        let held = carry.and_then(|carry| carry.held);
        if held.is_none() && rtcp.is_none() {
            return call;
        }
        // A latch is what was learned from a source the peer signalled. A peer that moved to another
        // address in this re-offer is a new peer to the latch: carrying the old one would refuse it,
        // and an open one would let a stranger win the first packet, so it starts from the gate the
        // new SDP draws, as any re-offer does.
        let kept = |was: Option<SocketAddr>, now: Option<SocketAddr>, taps: &HeldTaps| {
            let mut taps = taps.clone();
            if was != now {
                taps.latch = Default::default();
            }
            taps
        };
        let (toward_a, toward_b, taps_a, taps_b) = match &held {
            Some([a_to_b, b_to_a]) => (
                Some(b_to_a.next),
                Some(a_to_b.next),
                kept(previous.0, signalled.0, &a_to_b.taps),
                kept(previous.1, signalled.1, &b_to_a.taps),
            ),
            None => (None, None, HeldTaps::default(), HeldTaps::default()),
        };
        call.resume_held(HeldResume {
            toward_a: HeldEgress {
                next: toward_a,
                rtcp: rtcp_a,
                ..HeldEgress::default()
            },
            toward_b: HeldEgress {
                next: toward_b,
                rtcp: rtcp_b,
                ..HeldEgress::default()
            },
            taps_a,
            taps_b,
            ungate: false,
        });
        call
    }

    /// An answer that could not install its replacement leaves a held call without an actor: build
    /// one again from what the old one left, so the call keeps a working media path.
    pub(in crate::engine) async fn restore_held_actor(&self, call_id: &str) {
        if !self.is_secure_held(call_id) || self.media.is_media_call(call_id) {
            return;
        }
        if let Err(reason) = self.rebuild_held_actor(call_id).await {
            tracing::error!(
                target: "siphon_rtp::media",
                call_id,
                reason,
                "the held call could not get its actor back after a failed install"
            );
        }
    }

    async fn rebuild_held_actor(&self, call_id: &str) -> Result<(), String> {
        let hold = self
            .owned_call_internal(call_id, |call| call.secure_hold.clone())
            .flatten()
            .ok_or_else(|| "the call is not held".to_string())?;
        let carry = hold
            .carry
            .as_deref()
            .cloned()
            .ok_or_else(|| "no carried state to rebuild from".to_string())?;
        let [a_to_b, b_to_a] = carry
            .held
            .clone()
            .ok_or_else(|| "the old actor reported no state".to_string())?;
        let inputs = self.hold_inputs(call_id)?;
        let directions = HeldDirections {
            near_gate: a_to_b.ingress.1,
            far_gate: b_to_a.ingress.1,
            near_dst: b_to_a.destination,
            far_dst: a_to_b.destination,
        };
        let resume = HeldResume {
            toward_a: HeldEgress {
                next: Some(b_to_a.next),
                ..HeldEgress::default()
            },
            toward_b: HeldEgress {
                next: Some(a_to_b.next),
                ..HeldEgress::default()
            },
            taps_a: a_to_b.taps,
            taps_b: b_to_a.taps,
            ungate: matches!(
                hold.original,
                PipelineKind::Srtp | PipelineKind::SrtpOfferer | PipelineKind::SrtpTranscrypt
            ),
        };
        match hold.original {
            PipelineKind::Srtp | PipelineKind::SrtpOfferer | PipelineKind::SrtpTranscrypt => {
                let relay = |endpoint: Option<EndpointId>| {
                    carry
                        .rtcp
                        .iter()
                        .find(|(ingress, _, _)| Some(*ingress) == endpoint)
                        .map(|(_, gate, destination)| (*gate, *destination))
                };
                let rtcp: Option<SdesRtcp> = relay(inputs.near.rtcp.map(|rtcp| rtcp.id))
                    .zip(relay(inputs.far.rtcp.map(|rtcp| rtcp.id)));
                let call = self.sdes_actor(
                    call_id,
                    &inputs,
                    &directions,
                    hold.latch.0 || hold.latch.1,
                    (carry.near_leg.clone(), carry.far_leg.clone()),
                    rtcp,
                )?;
                self.media
                    .register(call, self.datapath.clone(), self.event_sink(inputs.owner));
                if self
                    .media
                    .control(call_id, MediaControl::ResumeHeld(Box::new(resume)))
                {
                    Ok(())
                } else {
                    Err("media actor unavailable".to_string())
                }
            }
            _ => {
                let secure_is_near = hold.original == PipelineKind::DtlsOfferer;
                let secure = if secure_is_near {
                    inputs.near
                } else {
                    inputs.far
                };
                let leg = self
                    .dtls_bridge()
                    .retained(secure.rtp.id)
                    .ok_or_else(|| "the DTLS leg is no longer retained".to_string())?;
                let mut call = self
                    .held_media_call(call_id, &inputs, &directions, true)?
                    .with_app_events(self.call_app_queue(call_id))
                    .gated_for_hold();
                if let Some((_, _, Some(rtcp))) = hold.plain {
                    call = call.with_rtcp_relays(vec![Self::plain_rtcp_relay(
                        &rtcp,
                        secure.rtp.id,
                        if secure_is_near {
                            directions.near_dst
                        } else {
                            directions.far_dst
                        },
                    )]);
                }
                self.media
                    .register(call, self.datapath.clone(), self.event_sink(inputs.owner));
                let attach = if secure_is_near {
                    MediaControl::AttachCallerSecureLeg { leg }
                } else {
                    MediaControl::AttachSecureLeg { leg }
                };
                if self
                    .media
                    .control(call_id, MediaControl::ResumeHeld(Box::new(resume)))
                    && self.media.control(call_id, attach)
                {
                    Ok(())
                } else {
                    Err("media actor unavailable".to_string())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_srtp::sdes::CryptoSuite;

    fn packet(sequence: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
        packet.extend_from_slice(&[0xAA; 20]);
        packet
    }

    #[test]
    fn taking_a_leg_gives_back_the_working_leg_and_leaves_an_inert_one_behind() {
        let (ours, theirs) = (
            SrtpKeyMaterial::from_inline_bytes(&[1; 30]).expect("key"),
            SrtpKeyMaterial::from_inline_bytes(&[2; 30]).expect("key"),
        );
        let shared = Arc::new(Mutex::new(SecureLeg::new(&ours, &theirs)));
        let mut peer = SecureLeg::new(&theirs, &ours);
        let mut sealed = Vec::new();
        peer.protect(&packet(1), &mut sealed).expect("protect");
        let mut taken = take_leg(&shared).expect("a leg");
        let mut clear = Vec::new();
        assert!(
            taken.unprotect(&sealed, &mut clear).is_ok(),
            "the real leg comes out"
        );
        // Whoever still holds the handle finds a leg that authenticates nothing real.
        let mut sealed = Vec::new();
        peer.protect(&packet(2), &mut sealed).expect("protect");
        assert!(shared
            .lock()
            .expect("lock")
            .unprotect(&sealed, &mut clear)
            .is_err());
    }

    #[test]
    fn a_carried_leg_is_always_the_same_object_and_keeps_the_send_window_of_a_key_that_stays() {
        let key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        let other = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        let third = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        let live = Arc::new(Mutex::new(SecureLeg::new(&key.key, &other.key)));
        let mut wire = Vec::new();
        for sequence in [99u16, 100] {
            live.lock()
                .expect("lock")
                .protect(&packet(sequence), &mut wire)
                .expect("sent");
        }
        // Only the peer's key changed (what it sends under); the sending key, and with it the record of
        // what was sent, stay.
        let kept = carried_leg(Some(&live), (false, true), (&key, &third)).expect("kept");
        assert!(Arc::ptr_eq(&kept, &live));
        let mut different = packet(99);
        different[20] ^= 0xFF;
        assert!(
            kept.lock()
                .expect("lock")
                .protect(&different, &mut wire)
                .is_err(),
            "99 was sent under this very key; different bytes there would reuse its keystream"
        );
        assert!(carried_leg(None, (false, false), (&key, &other)).is_none());
    }
}
