//! Delivering the far party's out-of-band H.264 parameter sets to an `answer_local` caller
//! (RFC 6184 §8.1): arming the first-IDR injector on the far-to-caller video flow, and the sweep
//! that returns the stream to the kernel fast path once it has done its work. The mechanism is
//! [`crate::video_injector`]; the security posture is docs/security-and-nat.md, "Video on a
//! two-party call".

use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction, ForwardRule, LatchPolicy};
use std::sync::Arc;

use super::Engine;
use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan};
use crate::video_injector::{Tick, VideoInjector};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The injector a negotiation that has just installed `rule` for the far party's video endpoint
    /// should arm, or `None`: the call is a locally answered one whose far answer carried usable
    /// `sprop-parameter-sets`, its far-to-caller direction is open, the caller has not been handed
    /// the sets already and the rule has a destination.
    ///
    /// Decided *before* the endpoint's flow is installed, so an armed endpoint never gets a `Forward`
    /// rule first: a far party that is already sending would have its first IDR, or the sequence
    /// numbers the injector uses, relayed in the gap.
    pub(super) fn plan_video_injector(
        &self,
        call_id: &str,
        rule: &ForwardRule,
        far_to_near: bool,
    ) -> Option<Arc<VideoInjector>> {
        rule.out_dst?;
        let sets = self.calls.get(call_id).and_then(|call| {
            (call.local_answer.is_some() && !call.video.sprop_spent && far_to_near)
                .then(|| call.video.far_sprop.clone())
                .flatten()
        })?;
        Some(Arc::new(VideoInjector::new(sets)))
    }

    /// Put a planned `injector` on the far video endpoint `endpoint`, whose `Forward` rule `rule` the
    /// call already records but which has not been installed: the bridge flow is registered and the
    /// injector attached before the endpoint is redirected, so the first redirected datagram already
    /// finds its owner and its source gate (see `redirect_after_register`), and the `Redirect` is the
    /// first rule the endpoint is given. On failure the endpoint falls back to the recorded `Forward`.
    pub(super) fn activate_video_injector(
        &self,
        call_id: &str,
        endpoint: EndpointId,
        rule: ForwardRule,
        injector: Arc<VideoInjector>,
    ) {
        let Some(out_dst) = rule.out_dst else {
            return;
        };
        self.bridge.register(BridgeCallPlan {
            near_leg: None,
            far_leg: None,
            flows: vec![BridgeFlowPlan {
                endpoint,
                ingress_leg: None,
                egress_leg: None,
                accepted_source: rule.accepted_source,
                latch: rule.latch != LatchPolicy::Off,
                out_endpoint: rule.out_endpoint,
                out_dst,
            }],
        });
        self.bridge
            .attach_video_injector(endpoint, injector.clone());
        if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
            self.bridge.deregister([endpoint]);
            tracing::warn!(
                target: "siphon_rtp::media",
                %call_id, %error,
                "could not redirect the far video for parameter-set injection; it relays as before"
            );
            if let Err(error) = self
                .datapath
                .install_flow(endpoint, FlowAction::Forward(rule))
            {
                tracing::error!(target: "siphon_rtp::media", %call_id, %error, "could not install the far video relay");
            }
            return;
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.injector = Some(injector);
        }
    }

    /// Forget an armed injector without touching the datapath (the caller is about to replace the
    /// endpoints' flows, or free them).
    pub(super) fn disarm_video_injector(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.injector = None;
        }
    }

    /// One once-a-second sweep over the armed injectors: an injector that has delivered the sets
    /// (or run out of time) puts the far video endpoint back on its `Forward` rule, the next sweep
    /// lets the bridge flow go (so a datagram already queued for the dispatcher is still relayed),
    /// and one that ran out of time, or whose IDR could not be sent, asks the far party for another
    /// keyframe. The same demotion shape as a text stream returning to the kernel
    /// (`demote_text_to_kernel`).
    pub fn sweep_video_injectors(&self) {
        let armed: Vec<(String, Arc<VideoInjector>)> = self
            .calls
            .iter()
            .filter_map(|entry| {
                let injector = entry.value().video.injector.clone()?;
                Some((entry.key().clone(), injector))
            })
            .collect();
        for (call_id, injector) in armed {
            self.sweep_video_injector(&call_id, &injector);
        }
    }

    /// One injector's sweep, the whole of it under the call's map entry (no `.await`, the datapath
    /// and bridge calls are synchronous): the check that `injector` is still the call's, the read of
    /// the recorded `Forward` rule and its reinstall, and the bridge deregistration are one step. A
    /// renegotiation or a park that replaced the flow in between has replaced the injector, and the
    /// check, made under the same lock they take, stops this sweep from overwriting the new flow or
    /// removing its bridge entry.
    fn sweep_video_injector(&self, call_id: &str, injector: &Arc<VideoInjector>) {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return;
        };
        if !Self::is_current(&call, injector) {
            return;
        }
        let tick = injector.tick();
        if injector.take_retry() {
            // The IDR could not be delivered with its sets: RFC 4585 §6.3.1, ask for another.
            let asked = call.video.far_picture_loss;
            call.video.keyframe.ask_far_again(asked);
        }
        self.act_on_tick(call_id, &mut call, injector, tick);
    }

    fn is_current(call: &super::Call, injector: &Arc<VideoInjector>) -> bool {
        call.video
            .injector
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, injector))
    }

    /// Do what `tick` says about `injector` on `call`, which the caller holds locked. A stale
    /// injector (replaced since it was read) is left alone.
    pub(super) fn act_on_tick(
        &self,
        call_id: &str,
        call: &mut super::Call,
        injector: &Arc<VideoInjector>,
        tick: Tick,
    ) {
        if !Self::is_current(call, injector) {
            return;
        }
        let Some(far) = call
            .far
            .as_ref()
            .and_then(|leg| leg.video)
            .map(|video| video.rtp.id)
        else {
            return;
        };
        match tick {
            Tick::Pending => {}
            Tick::Retire => {
                self.bridge.deregister([far]);
                call.video.injector = None;
            }
            Tick::Demote { timed_out } => {
                let Some(action) = call
                    .video
                    .flows
                    .iter()
                    .find_map(|(endpoint, action)| (*endpoint == far).then_some(*action))
                else {
                    return;
                };
                // On an install error the endpoint stays redirected (it still relays, through the
                // bridge) and the next sweep tries again.
                if let Err(error) = self.datapath.install_flow(far, action) {
                    tracing::warn!(
                        target: "siphon_rtp::media",
                        %call_id, %error,
                        "could not return the far video to the kernel path; it stays on the bridge"
                    );
                    return;
                }
                injector.mark_demoted();
                call.video.sprop_spent = true;
                if timed_out {
                    // RFC 4585 §6.3.1: one more Picture Loss Indication, in case the first was lost.
                    let asked = call.video.far_picture_loss;
                    call.video.keyframe.ask_far_again(asked);
                }
                tracing::info!(
                    target: "siphon_rtp::media",
                    %call_id, timed_out,
                    "far video injector finished; the stream is back on the kernel path"
                );
            }
        }
    }
}
