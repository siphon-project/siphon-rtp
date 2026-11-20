//! Lawful-interception content delivery (ETSI TS 103 221-2 X3) on a single-leg call: an
//! engine-answered caller (`answer_local`, an IVR, an announcement, a call growing a far leg).
//!
//! The engine answering the call stands in for the callee, so the warrant's `target_leg` applies as on
//! two parties (TS 103 221-2 §5.2.6): with the caller as the target what it sends is `from_target`
//! and what the engine sends it `to_target`; with the callee as the target the two mirror. The two taps
//! live in the media actor ([`crate::media_pipeline`]'s single-leg shape); this module installs them
//! and carries the interception across the rebuilds that change the call's shape.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::X3EndReason;
use std::sync::atomic::Ordering;

use crate::media_pipeline::MediaControl;
use crate::x3::{ingress_directions, X3Taps};

use super::intercept::X3TapSource;

use super::{Call, ClientId, Engine, PipelineKind, PromoteMode, PromotionReason};

impl Call {
    /// Whether the engine is this call's far side: an `answer_local` call (its answer is kept, so
    /// `offer_far` can grow it) with no far party answered yet, a far leg that is merely offered
    /// included. Its media is the engine's own single-leg pipeline.
    pub(super) fn is_single_leg_answer(&self) -> bool {
        self.local_answer.is_some() && self.to_tag.is_none()
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Put the ingress and egress taps of every delivery in `sources` on a single-leg call's media
    /// actor, as the whole set.
    ///
    /// The actor must be the call's own pipeline: a call whose pipeline is being rebuilt (between
    /// `offer_far`'s answer and the relay it installs) is refused with a reason, never accepted with
    /// no taps behind it.
    pub(super) async fn install_single_leg_x3(
        &self,
        call_id: &str,
        sources: &[X3TapSource],
    ) -> Result<(), String> {
        let Some((pipeline, caller)) = self.owned_call_internal(call_id, |call| {
            (call.pipeline, call.caller_leg().rtp.local_addr)
        }) else {
            return Err("call no longer exists".to_string());
        };
        if pipeline != PipelineKind::Media || !self.media.is_media_call(call_id) {
            return Err(
                "the call's local media pipeline is being rebuilt; retry the attach once it is up"
                    .to_string(),
            );
        }
        // The address of the engine endpoint the caller talks to: the PDU's destination for what
        // the caller sends and its source for what the engine sends.
        // TS 103 221-2 §5.2.6 is target-relative, and the engine answering the call stands in for
        // the callee. The caller's ingress is leg A's and the engine's egress is what the far side
        // sends it, so the one mapping of [`ingress_directions`] serves here as it does for two
        // parties, and the directions stay the same when `offer_far`'s party takes the callee over.
        let mut ingress = Vec::with_capacity(sources.len());
        let mut egress = Vec::with_capacity(sources.len());
        for source in sources {
            let (ingress_direction, egress_direction) = ingress_directions(source.target_is_caller);
            ingress.push(source.factory.tap(caller, ingress_direction));
            egress.push(source.factory.tap(caller, egress_direction));
        }
        let (ingress, egress) = (X3Taps::new(ingress), X3Taps::new(egress));
        // Recorded so the call's media is not demoted from under the interception. The actor is the
        // call's processing pipeline already, so this promotes nothing.
        self.hold_in_userspace(call_id, PromotionReason::X3, PromoteMode::RelayOnly)
            .await?;
        if !self.media.control(
            call_id,
            MediaControl::StartX3SingleLeg(Box::new((ingress, egress))),
        ) {
            self.release_x3_hold_if_unused(call_id).await;
            return Err("media actor unavailable".to_string());
        }
        Ok(())
    }

    /// End the interception of a call whose new media path cannot carry it, loudly: `x3_ended` with
    /// `transport_error` (the nearest reason there is) and an `error!`, rather than an interception
    /// that is attached and delivers nothing. A no-op on a call that is not intercepted.
    pub(super) async fn end_x3_unservable(&self, call_id: &str, why: &str) {
        if !self.x3_sessions.contains_key(call_id) {
            return;
        }
        tracing::error!(
            target: "siphon_rtp::li",
            call_id,
            why,
            "the call's media path cannot carry its lawful interception; ending it rather than \
             leaving it silently deaf"
        );
        self.stop_x3(call_id, X3EndReason::TransportError).await;
    }

    /// Mark the interceptions of a single-leg call that a re-answer of the **same dialog** (same
    /// call-id, from-tag and owner) is about to replace, so the replacement inherits them instead of
    /// ending them. The caller is the same party in the same dialog: an interception that ended here
    /// would leave the target's content flowing unintercepted (TS 103 221-2 clause 6: the delivery
    /// is tied to the call's X2 records, which do not change).
    ///
    /// The sessions stay in the map for the whole hand-over, marked, so nothing can miss them: the
    /// old call's teardown leaves them alone ([`Self::stop_x3`]) and a `detach_x3` that lands meanwhile
    /// is recorded per delivery and honoured by [`Self::settle_x3_hand_over`]. Returns whether any is
    /// being handed over. Any other replacement is a new call, and the interceptions end with the
    /// old one.
    pub(super) fn begin_x3_hand_over(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
    ) -> bool {
        let Some(sessions) = self.x3_sessions.get(call_id) else {
            return false;
        };
        let mut handing_over = false;
        for session in sessions
            .iter()
            .filter(|session| session.owner == client && session.from_tag == from_tag)
        {
            session.handing_over.store(true, Ordering::SeqCst);
            handing_over = true;
        }
        handing_over
    }

    /// The replacement call is registered: the hand-over is over. A withdrawal that arrived meanwhile
    /// ends that delivery now, `detached`, with exactly one `x3_ended`; the others carry on.
    pub(super) async fn settle_x3_hand_over(&self, call_id: &str) {
        let _changing = self.x3_sessions.lock.lock().await;
        if let Some(sessions) = self.x3_sessions.get(call_id) {
            for session in sessions.iter() {
                session.handing_over.store(false, Ordering::SeqCst);
            }
        }
        self.end_x3_where(
            call_id,
            |session| session.detach_requested.load(Ordering::SeqCst),
            |_| X3EndReason::Detached,
        )
        .await;
    }

    /// The re-answer failed with nothing to replace the call: the interceptions end with it, a
    /// delivery whose withdrawal had arrived as `detached`, the rest as `call_ended`.
    pub(super) async fn abandon_x3_hand_over(&self, call_id: &str) {
        let _changing = self.x3_sessions.lock.lock().await;
        if let Some(sessions) = self.x3_sessions.get(call_id) {
            for session in sessions.iter() {
                session.handing_over.store(false, Ordering::SeqCst);
            }
        }
        self.end_x3_where(
            call_id,
            |_| true,
            |session| {
                if session.detach_requested.load(Ordering::SeqCst) {
                    X3EndReason::Detached
                } else {
                    X3EndReason::CallEnded
                }
            },
        )
        .await;
    }
}
