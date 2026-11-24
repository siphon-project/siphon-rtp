//! Holding a crypto-bridged call in the decoding media actor.
//!
//! A call on a crypto bridge (`Srtp`, `SrtpOfferer`, `SrtpTranscrypt`, `Dtls`, `DtlsOfferer`) relays
//! SRTP without decoding it, so nothing that needs the audio can attach to it. Holding it moves the
//! two legs' media into a [`MediaCall`] **without a re-INVITE and without rebuilding any crypto
//! state**: the actor takes the very `SecureLeg`s the bridge held (master keys, rollover counters,
//! replay windows and SRTCP index untouched; the DTLS association never leaves the bridge), continues
//! each egress stream under the SSRC, with the next sequence number and a timestamp that has moved on
//! by the elapsed clock, so the party receiving it sees one stream (RFC 3711 §3.3.1, RFC 3550 §5.1),
//! and takes over the taps the bridge flows carried. Releasing is the reverse, in
//! [`secure_release`](super::secure_release).
//!
//! The actor is registered **before** the bridge lets go and starts gated, so there is no instant at
//! which an endpoint has no owner (docs/security-and-nat.md §4). A plain `Passthrough` relay has no
//! such state to carry: a kernel `Forward` cannot renumber a stream, so its actor numbers its own
//! under a fresh SSRC and releasing returns the carrier's stream verbatim, which is a legitimate SSRC
//! change (RFC 3550 §8.2) and is handled by [`Engine::promote_to_processing`].

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{Datapath, EndpointId, SourceFilter};
use siphon_rtp_srtp::leg::SecureLeg;

use crate::dtls_bridge::hold::{DtlsGiveBack, DtlsHeld};
use crate::dtls_bridge::{KeyedParty, PipelineTarget, PlainRtcp};
use crate::media_pipeline::{
    EchoProfile, HeldEgress, HeldResume, HeldTaps, MediaCall, MediaControl, RtcpRelay, SecureLegs,
    SecureSide,
};
use crate::srtp_bridge::hold::{CarriedFlow, SharedBridgePlan};
use crate::srtp_bridge::BridgeFlowPlan;

use super::super::negotiate::{
    build_transcode_pair, secure_rtcp_relays, RtcpKeying, TranscodePair,
};
use super::super::{Engine, Leg, PipelineKind, PromotionReason};
use super::secure_release::HeldCarry;
use crate::engine::ClientId;

/// The refusal token for a call whose leg is seated in a conference room.
pub(in crate::engine) const SEATED: &str = "ws-split-seated";
/// The refusal token for a call the engine answered itself (`answer_local`).
pub(in crate::engine) const ANSWER_LOCAL: &str = "ws-split-answer-local";
/// The refusal token for a call that already has a WebSocket takeover or a split on it.
pub(in crate::engine) const ALREADY_BRIDGED: &str = "ws-split-already-bridged";
/// The refusal token for a call with no far party answered yet.
pub(in crate::engine) const NOT_ANSWERED: &str = "ws-split-not-answered";

/// What a call remembers while a crypto bridge is held in the decoding actor.
#[derive(Clone)]
pub(in crate::engine) struct SecureHold {
    /// The crypto-bridge kind the call goes back to on release. Updated by a re-offer answered while
    /// held, which may resolve to another bridge kind.
    pub(in crate::engine) original: PipelineKind,
    /// Whether the near and far RTP flows latched to the peer's observed source before the hold.
    pub(super) latch: (bool, bool),
    /// An SDES bridge's flows as they were, which release registers again (their gate and destination
    /// are corrected from the actor once it has stopped).
    pub(super) plans: Vec<BridgeFlowPlan>,
    /// A DTLS bridge's plain side as it was: its gate, where decrypted media went, and its separate
    /// RTCP port when it has one.
    pub(super) plain: Option<(SourceFilter, SocketAddr, Option<PlainRtcp>)>,
    /// The state of an actor stopped for a re-offer's answer, until the replacement has taken it.
    pub(super) carry: Option<Box<HeldCarry>>,
    /// The addresses the two parties signalled (A's, B's) when the actor last took over the call. A
    /// latch learned from a source is only carried while the address it was signalled from stays.
    pub(super) signalled: (Option<SocketAddr>, Option<SocketAddr>),
}

impl std::fmt::Debug for SecureHold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the legs, whose contexts hold key material.
        formatter
            .debug_struct("SecureHold")
            .field("original", &self.original)
            .finish_non_exhaustive()
    }
}

impl PipelineKind {
    /// The transcoding kind that carries a crypto bridge's call in the media actor — what the call is
    /// while it is held, and what an answer to a re-offer resolves to while it stays held.
    pub(in crate::engine) fn held_twin(self) -> Option<Self> {
        Some(match self {
            Self::Srtp => Self::SrtpMedia,
            Self::SrtpOfferer => Self::SrtpOffererMedia,
            Self::SrtpTranscrypt => Self::SrtpTranscryptMedia,
            Self::Dtls => Self::DtlsMedia,
            Self::DtlsOfferer => Self::DtlsOffererMedia,
            _ => return None,
        })
    }
}

/// Everything a hold reads off the call record, taken in one pass so the rest runs without the map.
pub(super) struct HoldInputs {
    pub(super) owner: ClientId,
    pub(super) from_tag: String,
    pub(super) to_tag: String,
    pub(super) pipeline: PipelineKind,
    pub(super) near: Leg,
    pub(super) far: Leg,
    near_codec: CodecSpec,
    far_codec: CodecSpec,
    near_telephone_event: Option<u8>,
    far_telephone_event: Option<u8>,
}

/// The two parties' media addresses and gates a hold builds the actor's directions from.
pub(super) struct HeldDirections {
    pub(super) near_gate: SourceFilter,
    pub(super) far_gate: SourceFilter,
    /// Where each party is now.
    pub(super) near_dst: SocketAddr,
    pub(super) far_dst: SocketAddr,
}

/// An SDES bridge's companion RTCP, as `(gate, destination)` of A's relay then B's: A's is gated to
/// A's source and forwards to B's RTCP address, B's the mirror.
pub(super) type SdesRtcp = ((SourceFilter, SocketAddr), (SourceFilter, SocketAddr));

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The refusals of a split: a call that is not a plain answered two-party call, or that already
    /// has one of the things a split would collide with. Each carries its token first so a controller
    /// can match on it.
    pub(in crate::engine) fn ws_split_refusal(&self, call_id: &str) -> Result<(), String> {
        let refused = self
            .owned_call_internal(call_id, |call| {
                if call.pipeline == PipelineKind::Seated || call.seat.is_some() || call.seating {
                    Some((SEATED, "the call's leg is seated in a conference room"))
                } else if call.local_answer.is_some() {
                    Some((ANSWER_LOCAL, "the engine answered this call itself"))
                } else if call.pipeline == PipelineKind::Ws
                    || call.promotion_reasons.contains(&PromotionReason::WsSplit)
                {
                    Some((
                        ALREADY_BRIDGED,
                        "the call already has a WebSocket takeover or a split",
                    ))
                } else if call.is_single_leg() || call.far_codec.is_none() {
                    Some((NOT_ANSWERED, "the call has no answered far party"))
                } else {
                    None
                }
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        match refused {
            Some((token, reason)) => Err(format!("{token}: {reason}")),
            None => Ok(()),
        }
    }

    /// Whether `call_id` is a crypto-bridged call currently held in the decoding actor.
    pub(in crate::engine) fn is_secure_held(&self, call_id: &str) -> bool {
        self.owned_call_internal(call_id, |call| call.secure_hold.is_some())
            .unwrap_or(false)
    }

    pub(super) fn hold_inputs(&self, call_id: &str) -> Result<HoldInputs, String> {
        self.owned_call_internal(call_id, |call| {
            Some(HoldInputs {
                owner: call.owner,
                from_tag: call.from_tag.clone(),
                to_tag: call.to_tag.clone()?,
                pipeline: call.pipeline,
                near: call.near,
                far: call.far?,
                near_codec: call.near_codec.clone()?,
                far_codec: call.far_codec.clone()?,
                near_telephone_event: call.near_telephone_event.map(|event| event.payload_type),
                far_telephone_event: call.far_telephone_event,
            })
        })
        .ok_or_else(|| "call no longer exists".to_string())?
        .ok_or_else(|| format!("{NOT_ANSWERED}: the call has no answered far party"))
    }

    /// The actor's two directions, each built for the codec its party sends and the other receives.
    pub(super) fn held_media_call(
        &self,
        call_id: &str,
        inputs: &HoldInputs,
        directions: &HeldDirections,
        latch: bool,
    ) -> Result<MediaCall, String> {
        let (a_to_b, b_to_a) = build_transcode_pair(&TranscodePair {
            near_endpoint: inputs.near.rtp.id,
            near_source: directions.near_gate,
            near_dst: directions.near_dst,
            far_endpoint: inputs.far.rtp.id,
            far_source: directions.far_gate,
            far_dst: directions.far_dst,
            near_codec: &inputs.near_codec,
            far_codec: &inputs.far_codec,
            near_telephone_event: inputs.near_telephone_event,
            far_telephone_event: inputs.far_telephone_event,
            // A call that needed any of these would not have resolved to a crypto bridge.
            noise_suppression: false,
            echo: EchoProfile::default(),
            beep_detection: false,
            beep_cadence_guard_ms: None,
        })
        .map_err(|(direction, reason)| {
            format!("cannot decode the held call ({direction}): {reason}")
        })?;
        Ok(MediaCall::new(
            call_id.to_string(),
            inputs.from_tag.clone(),
            Some(inputs.to_tag.clone()),
            a_to_b,
            b_to_a,
            latch,
        ))
    }

    /// Hold a crypto-bridged call in the decoding media actor ([`PromotionReason::WsSplit`]). The
    /// caller has validated ownership and the refusals; nothing is changed when this fails.
    pub(in crate::engine) async fn hold_secure(&self, call_id: &str) -> Result<(), String> {
        let inputs = self.hold_inputs(call_id)?;
        match inputs.pipeline {
            PipelineKind::Srtp | PipelineKind::SrtpOfferer | PipelineKind::SrtpTranscrypt => {
                self.hold_sdes_bridge(call_id, inputs).await
            }
            PipelineKind::Dtls | PipelineKind::DtlsOfferer => {
                self.hold_dtls_bridge(call_id, inputs).await
            }
            other => Err(format!("a {other:?} call is not on a crypto bridge")),
        }
    }

    fn record_hold(&self, call_id: &str, hold: SecureHold) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(twin) = hold.original.held_twin() {
                call.pipeline = twin;
            }
            call.secure_hold = Some(hold);
        }
    }

    // ---- SDES-SRTP bridges ---------------------------------------------------------------------

    /// The actor of a held SDES call: the two directions with the bridge's own legs threaded in as the
    /// kind says, the companion RTCP relays keyed on the same legs (RFC 3711, RFC 5761 §5.1.1), and
    /// gated until it is told where each stream stands.
    pub(super) fn sdes_actor(
        &self,
        call_id: &str,
        inputs: &HoldInputs,
        directions: &HeldDirections,
        latch: bool,
        legs: SecureLegs,
        rtcp: Option<SdesRtcp>,
    ) -> Result<MediaCall, String> {
        let kind = inputs.pipeline;
        let missing = |party: &str| format!("the call's bridge holds no {party} SRTP leg");
        let (near_leg, far_leg) = legs;
        let call = self.held_media_call(call_id, inputs, directions, latch)?;
        let call = match kind {
            PipelineKind::Srtp => {
                call.with_far_secure_leg(far_leg.clone().ok_or_else(|| missing("far"))?)
            }
            PipelineKind::SrtpOfferer => {
                call.with_near_secure_leg(near_leg.clone().ok_or_else(|| missing("near"))?)
            }
            _ => call.with_both_secure_legs(
                near_leg.clone().ok_or_else(|| missing("near"))?,
                far_leg.clone().ok_or_else(|| missing("far"))?,
            ),
        };
        let mut relays = Vec::new();
        if let (Some((near_rtcp, far_rtcp)), Some(((near_gate, far_dst), (far_gate, near_dst)))) =
            (inputs.near.rtcp.zip(inputs.far.rtcp), rtcp)
        {
            let keying = match kind {
                PipelineKind::Srtp => RtcpKeying::Leg(far_leg.ok_or_else(|| missing("far"))?),
                PipelineKind::SrtpOfferer => {
                    RtcpKeying::NearLeg(near_leg.ok_or_else(|| missing("near"))?)
                }
                _ => RtcpKeying::BothLegs {
                    near: near_leg.ok_or_else(|| missing("near"))?,
                    far: far_leg.ok_or_else(|| missing("far"))?,
                },
            };
            relays = secure_rtcp_relays(
                near_rtcp.id,
                near_gate,
                far_dst,
                far_rtcp.id,
                far_gate,
                near_dst,
                &keying,
            );
        }
        Ok(call
            .with_rtcp_relays(relays)
            .with_app_events(self.call_app_queue(call_id))
            .gated_for_hold())
    }

    async fn hold_sdes_bridge(&self, call_id: &str, inputs: HoldInputs) -> Result<(), String> {
        let (near, far) = (inputs.near, inputs.far);
        // A's RTP endpoint first: its flow names both parties, which is how the bridge reads both legs.
        let mut endpoints = vec![near.rtp.id, far.rtp.id];
        let rtcp = near.rtcp.zip(far.rtcp);
        endpoints.extend(rtcp.into_iter().flat_map(|(near, far)| [near.id, far.id]));
        let Some(view) = self.bridge.hold_view(&endpoints) else {
            return Err("the call's SRTP bridge has no flows to hold".to_string());
        };
        let plan = |endpoint: EndpointId| view.plans.iter().find(|plan| plan.endpoint == endpoint);
        let latched = |endpoint: EndpointId| {
            view.latched
                .iter()
                .find(|(latched, _)| *latched == endpoint)
                .map(|(_, source)| *source)
        };
        let (Some(near_plan), Some(far_plan)) = (plan(near.rtp.id), plan(far.rtp.id)) else {
            return Err("the call's SRTP bridge has no RTP flows to hold".to_string());
        };
        let directions = HeldDirections {
            near_gate: near_plan.accepted_source,
            far_gate: far_plan.accepted_source,
            // Where each party is: the source its flow latched, else the address it signalled.
            near_dst: latched(near.rtp.id).unwrap_or(far_plan.out_dst),
            far_dst: latched(far.rtp.id).unwrap_or(near_plan.out_dst),
        };
        let latch = (near_plan.latch, far_plan.latch);
        let sdes_rtcp = match rtcp {
            Some((near_rtcp, far_rtcp)) => {
                let (near_plan, far_plan) = (
                    plan(near_rtcp.id).ok_or("the call's SRTP bridge lost an RTCP flow")?,
                    plan(far_rtcp.id).ok_or("the call's SRTP bridge lost an RTCP flow")?,
                );
                Some((
                    (near_plan.accepted_source, near_plan.out_dst),
                    (far_plan.accepted_source, far_plan.out_dst),
                ))
            }
            None => None,
        };
        let call = self.sdes_actor(
            call_id,
            &inputs,
            &directions,
            latch.0 || latch.1,
            (view.near_leg.clone(), view.far_leg.clone()),
            sdes_rtcp,
        )?;
        // Registered first: the endpoints are still the bridge's, so nothing reaches the actor yet,
        // and the instant the bridge lets go the actor is there to take the next datagram.
        self.media
            .register(call, self.datapath.clone(), self.event_sink(inputs.owner));

        let held = self.bridge.hold(&endpoints);
        let flow = |endpoint: EndpointId| held.iter().find(|flow| flow.endpoint == endpoint);
        let resume = HeldResume {
            toward_a: HeldEgress {
                last: flow(far.rtp.id).and_then(|flow| flow.last),
                destination: Some(directions.near_dst),
                ..HeldEgress::default()
            },
            toward_b: HeldEgress {
                last: flow(near.rtp.id).and_then(|flow| flow.last),
                destination: Some(directions.far_dst),
                ..HeldEgress::default()
            },
            taps_a: flow(near.rtp.id)
                .map(|flow| flow.taps.clone())
                .unwrap_or_default(),
            taps_b: flow(far.rtp.id)
                .map(|flow| flow.taps.clone())
                .unwrap_or_default(),
            ungate: true,
        };
        if !self
            .media
            .control(call_id, MediaControl::ResumeHeld(Box::new(resume)))
        {
            // The actor cannot be reached, so it cannot be left owning the call: put the bridge back
            // as it was (nothing was sent by the actor, so no stream needs continuing).
            self.media.stop(call_id).await;
            self.bridge.register_shared(SharedBridgePlan {
                near_leg: view.near_leg,
                far_leg: view.far_leg,
                flows: view.plans,
                carried: held
                    .into_iter()
                    .map(|flow| CarriedFlow {
                        endpoint: flow.endpoint,
                        resume: None,
                        awaiting: false,
                        taps: flow.taps,
                    })
                    .collect(),
            });
            return Err("media actor unavailable".to_string());
        }
        self.record_hold(
            call_id,
            SecureHold {
                original: inputs.pipeline,
                latch,
                plans: view.plans,
                plain: None,
                carry: None,
                signalled: (near.remote_rtp, far.remote_rtp),
            },
        );
        Ok(())
    }

    // ---- DTLS-SRTP bridges ---------------------------------------------------------------------

    /// The relay that carries a DTLS leg's plain peer's separate RTCP port toward the DTLS peer, as
    /// SRTCP on the leg's key once it is delivered (RFC 5761 §5.1.1: the plain peer keeps RTCP on a
    /// port of its own; the DTLS peer multiplexes).
    pub(super) fn plain_rtcp_relay(
        plain_rtcp: &PlainRtcp,
        secure_endpoint: EndpointId,
        secure_destination: SocketAddr,
    ) -> RtcpRelay {
        RtcpRelay::new(
            plain_rtcp.endpoint,
            plain_rtcp.source,
            secure_endpoint,
            secure_destination,
        )
        .with_pending_secure(SecureSide::Egress)
    }

    async fn hold_dtls_bridge(&self, call_id: &str, inputs: HoldInputs) -> Result<(), String> {
        let (near, far) = (inputs.near, inputs.far);
        let kind = inputs.pipeline;
        // The DTLS party is B on a `Dtls` call and A on a `DtlsOfferer` one.
        let (secure, plain, secure_is_near) = if kind == PipelineKind::Dtls {
            (far, near, false)
        } else {
            (near, far, true)
        };
        let dtls = self.dtls_bridge();
        let view = dtls
            .hold_view(secure.rtp.id, plain.rtp.id)
            .map_err(str::to_string)?;
        let secure_destination = view
            .secure_destination
            .or(secure.remote_rtp)
            .ok_or_else(|| "the DTLS leg has no destination yet".to_string())?;
        let directions = if secure_is_near {
            HeldDirections {
                near_gate: view.secure_gate,
                far_gate: view.plain_gate,
                near_dst: secure_destination,
                far_dst: view.plain_dst,
            }
        } else {
            HeldDirections {
                near_gate: view.plain_gate,
                far_gate: view.secure_gate,
                near_dst: view.plain_dst,
                far_dst: secure_destination,
            }
        };
        let mut call = self
            .held_media_call(call_id, &inputs, &directions, true)?
            .with_app_events(self.call_app_queue(call_id))
            .gated_for_hold();
        if let Some(rtcp) = &view.plain_rtcp {
            call = call.with_rtcp_relays(vec![Self::plain_rtcp_relay(
                rtcp,
                secure.rtp.id,
                secure_destination,
            )]);
        }
        self.media
            .register(call, self.datapath.clone(), self.event_sink(inputs.owner));

        let party = if secure_is_near {
            KeyedParty::Caller
        } else {
            KeyedParty::Callee
        };
        let held = match dtls.hold(
            secure.rtp.id,
            plain.rtp.id,
            PipelineTarget::Call {
                media: self.media.clone(),
                call_id: call_id.to_string(),
                party,
            },
        ) {
            Ok(held) => held,
            Err(reason) => {
                self.media.stop(call_id).await;
                return Err(reason.to_string());
            }
        };
        let DtlsHeld {
            leg,
            toward_plain,
            toward_secure,
            secure_taps,
            plain_taps,
        } = held;
        let (toward_a, toward_b, taps_a, taps_b) = if secure_is_near {
            (toward_secure, toward_plain, secure_taps, plain_taps)
        } else {
            (toward_plain, toward_secure, plain_taps, secure_taps)
        };
        let rtcp_out = view.plain_rtcp.map(|rtcp| (rtcp.endpoint, rtcp.dst));
        let resume = HeldResume {
            toward_a: HeldEgress {
                last: toward_a,
                destination: Some(directions.near_dst),
                // RTCP toward the plain peer goes to the port it keeps RTCP on.
                rtcp: if secure_is_near { None } else { rtcp_out },
                ..HeldEgress::default()
            },
            toward_b: HeldEgress {
                last: toward_b,
                destination: Some(directions.far_dst),
                rtcp: if secure_is_near { rtcp_out } else { None },
                ..HeldEgress::default()
            },
            taps_a,
            taps_b,
            // The key follows, and lifts the gate itself.
            ungate: false,
        };
        let attach = if secure_is_near {
            MediaControl::AttachCallerSecureLeg { leg: leg.clone() }
        } else {
            MediaControl::AttachSecureLeg { leg: leg.clone() }
        };
        let delivered = self
            .media
            .control(call_id, MediaControl::ResumeHeld(Box::new(resume)))
            && self.media.control(call_id, attach);
        if !delivered {
            // Hand the leg back to the bridge it came from; nothing was sent, so no stream moved.
            self.media.stop(call_id).await;
            self.restore_dtls_untouched(
                &plain,
                secure.rtp.id,
                (view.plain_gate, view.plain_dst, view.plain_rtcp),
                &leg,
            );
            return Err("media actor unavailable".to_string());
        }
        // An ICE leg follows the pair its agent selected (RFC 8445 §8.1.1).
        if self.datapath.watch_ice_validated(secure.rtp.id).is_some() {
            if let Some(selected) = view.secure_destination {
                self.media.control(
                    call_id,
                    MediaControl::IceSelected {
                        endpoint: secure.rtp.id,
                        remote: selected,
                    },
                );
            }
        }
        self.record_hold(
            call_id,
            SecureHold {
                original: kind,
                latch: (false, false),
                plans: Vec::new(),
                plain: Some((view.plain_gate, view.plain_dst, view.plain_rtcp)),
                carry: None,
                signalled: (near.remote_rtp, far.remote_rtp),
            },
        );
        Ok(())
    }

    /// Put a DTLS leg back after a hold whose actor could not be reached: the actor never ran, and the
    /// leg is taken out of its shared handle whoever else still holds it.
    fn restore_dtls_untouched(
        &self,
        plain: &Leg,
        secure: EndpointId,
        (gate, dst, rtcp): (SourceFilter, SocketAddr, Option<PlainRtcp>),
        leg: &Arc<Mutex<SecureLeg>>,
    ) {
        let dtls = self.dtls_bridge();
        let _ = dtls.take_retained(secure);
        let Some(leg) = super::secure_release::take_leg(leg) else {
            tracing::error!(
                target: "siphon_rtp::media",
                "a DTLS leg could not be taken back from a hold whose actor was unreachable"
            );
            return;
        };
        let give = DtlsGiveBack {
            leg,
            plain_endpoint: plain.rtp.id,
            plain_gate: gate,
            plain_dst: dst,
            plain_rtcp: rtcp,
            positions_lost: false,
            next_toward_plain: None,
            next_toward_secure: None,
            secure_taps: HeldTaps::default(),
            plain_taps: HeldTaps::default(),
        };
        if let Err(reason) = dtls.release(secure, give) {
            tracing::error!(target: "siphon_rtp::media", reason, "DTLS leg restore failed");
        }
    }
}
