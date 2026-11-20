//! Lawful interception (ETSI TS 103 221-2 X3) on a WebSocket-takeover call.
//!
//! The leg's two taps live in its [`crate::ws_bridge::WsEgress`] ([`crate::ws_x3`]), so they ride a
//! re-point with the rest of leg A's state. This module installs them from the sessions of the call,
//! taps a bridge the moment it is registered on an intercepted call, and answers the two questions
//! a takeover of an intercepted call asks: what else holds the call's media path, and was it the
//! interception that promoted a plain relay.

use siphon_rtp_datapath::Datapath;

use crate::engine::intercept::X3TapSource;
use crate::engine::{Engine, PipelineKind, PromotionReason};
use crate::media_pipeline::MediaCall;
use crate::ws_x3::WsTapSet;
use crate::x3::{ingress_directions, X3Taps};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Put the taps of every delivery in `sources` on `call_id`'s takeover leg, as the whole set.
    ///
    /// The WebSocket stands in for the callee, so the directions are the single-leg ones: the ingress
    /// tap is [`ingress_directions`]'s first, the egress tap its second (TS 103 221-2 §5.2.6). The
    /// address of each tap is the engine endpoint the leg talks to.
    pub(in crate::engine) fn install_ws_x3(
        &self,
        call_id: &str,
        sources: &[X3TapSource],
    ) -> Result<(), String> {
        let (Some(endpoint), Some(leg)) =
            (self.ws.endpoint_of(call_id), self.ws.egress_of(call_id))
        else {
            return Err("the call's WebSocket bridge is no longer installed".to_string());
        };
        let Some(local) = self
            .owned_call_internal(call_id, |call| {
                std::iter::once(call.near)
                    .chain(call.far)
                    .find(|candidate| candidate.rtp.id == endpoint)
                    .map(|candidate| candidate.rtp.local_addr)
            })
            .flatten()
        else {
            return Err("the call's takeover leg is not one of its endpoints".to_string());
        };
        let mut ingress = Vec::with_capacity(sources.len());
        let mut egress = Vec::with_capacity(sources.len());
        for source in sources {
            let (ingress_direction, egress_direction) = ingress_directions(source.target_is_caller);
            ingress.push(source.factory.tap(local, ingress_direction));
            egress.push(source.factory.tap(local, egress_direction));
        }
        leg.taps().set(WsTapSet {
            ingress: X3Taps::new(ingress),
            egress: X3Taps::new(egress),
        });
        Ok(())
    }

    /// Tap a bridge that has just been registered on a call that is intercepted: the deliveries
    /// belong to the call, so the leg is tapped from its first packet rather than once the controller
    /// verb that stood the bridge up returns and carries the set across. A failure is logged and
    /// left to that carry, which holds the lock and ends the deliveries loudly if it fails too.
    pub(in crate::engine) fn tap_new_bridge(&self, call_id: &str) {
        let sources = self.x3_tap_sources(call_id);
        if sources.is_empty() {
            return;
        }
        if let Err(reason) = self.install_ws_x3(call_id, &sources) {
            tracing::error!(
                target: "siphon_rtp::li",
                call_id,
                reason,
                "the new WebSocket bridge could not be tapped on registration; the carry that \
                 follows retries and ends the deliveries if it fails too"
            );
        }
    }

    /// A takeover of an intercepted relay failed after the relay's actor was released: the relay is
    /// back on the kernel path, so put its interception back on a pipeline. If that cannot be done the
    /// deliveries end loudly, never left attached and deaf.
    pub(super) async fn rehold_relay_for_x3(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Passthrough;
        }
        self.carry_x3_across_answer(call_id).await;
    }

    /// Tap a relay's [`MediaCall`] with the call's deliveries **before** it is registered, so the
    /// actor's first packet is already tapped. Installing by control message afterwards would let the
    /// dispatcher queue packets ahead of it (an actor that takes a leg from a bridge owns the leg the
    /// moment it is registered). A no-op on a call that is not intercepted.
    pub(in crate::engine) fn pretap_relay(&self, call_id: &str, call: &mut MediaCall) {
        let sources = self.x3_tap_sources(call_id);
        if sources.is_empty() {
            return;
        }
        let Some((a_local, b_local)) = self.owned_call_internal(call_id, |call| {
            (
                call.near.rtp.local_addr,
                call.far
                    .as_ref()
                    .map_or(call.caller_leg().rtp.local_addr, |far| far.rtp.local_addr),
            )
        }) else {
            return;
        };
        call.start_x3(super::super::intercept::tap_pairs(
            &sources, a_local, b_local,
        ));
    }

    /// [`Self::pretap_relay`] for the engine's own single-leg pipeline: the caller's ingress and the
    /// engine's egress.
    pub(in crate::engine) fn pretap_single_leg(&self, call_id: &str, call: &mut MediaCall) {
        let sources = self.x3_tap_sources(call_id);
        if sources.is_empty() {
            return;
        }
        let Some(caller) =
            self.owned_call_internal(call_id, |call| call.caller_leg().rtp.local_addr)
        else {
            return;
        };
        call.start_x3_single_leg(super::super::intercept::tap_pairs(&sources, caller, caller));
    }

    /// Whether anything besides a lawful interception holds `call_id` in the userspace pipeline: a
    /// WebSocket tee, a SIPREC subscription, a recording, a DTMF block or echo. Those taps would be
    /// stopped silently by a takeover; an interception is carried onto the bridge instead.
    pub(super) fn held_beyond_x3(&self, call_id: &str) -> bool {
        self.ws_tees.contains_key(call_id)
            || self
                .subscriptions
                .get(call_id)
                .is_some_and(|list| !list.is_empty())
            || self.calls.get(call_id).is_some_and(|call| {
                call.promotion_reasons
                    .iter()
                    .any(|reason| *reason != PromotionReason::X3)
            })
    }

    /// Whether `call_id` is a plain two-party relay that an interception alone moved into the
    /// userspace pipeline (relay-only), which a takeover may therefore take over: the interception is
    /// carried onto the bridge and the relay it came from is what a detach gives back.
    pub(super) fn is_relay_held_for_x3(&self, call_id: &str) -> bool {
        self.x3_sessions.contains_key(call_id)
            && self.media.is_relay_call(call_id)
            && self
                .owned_call_internal(call_id, |call| {
                    call.pipeline == PipelineKind::Media && !call.relay_flows.is_empty()
                })
                .unwrap_or(false)
    }
}
