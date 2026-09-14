//! Per-call media controls: blocking media or DTMF, silence, echo, and DTMF injection (RFC 4733).

use siphon_rtp_datapath::{Datapath, FlowAction};
use siphon_rtp_proto::CmdResult;

use crate::media_pipeline::{MediaControl, PlayDtmfOutcome};

use super::{
    error_result, ok_empty, unknown_call, ClientId, Engine, PipelineKind, PromoteMode,
    PromotionReason,
};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Drop (`block = true`) or resume (`block = false`) a call's media. A media-processing call
    /// flips its actor's egress; a plain relay flips its datapath flows to `Drop` and back. Only the
    /// owning client may control the call (A3 — docs §5).
    pub(super) async fn set_block(
        &self,
        client: ClientId,
        call_id: &str,
        block: bool,
    ) -> CmdResult {
        let Some((relay_flows, pipeline)) = self.owned_call(client, call_id, |call| {
            (call.relay_flows.clone(), call.pipeline)
        }) else {
            return unknown_call(call_id);
        };
        if pipeline == PipelineKind::Ws {
            // A takeover call's on-the-wire bytes are not the two-party media (the same reason
            // recording, SIPREC and the tee refuse it). It matters doubly once a bridge can be
            // *attached* to a live relay: that call still carries the displaced relay's `Forward`
            // rules for its detach, and reinstalling one here would take leg A's media back off the
            // bridge without telling anyone. Silence it by detaching or re-pointing the bridge.
            return error_result(
                "block",
                &"a WebSocket-takeover call's media cannot be blocked at the datapath; detach the \
                  bridge (detach_ws_bridge) or tear the call down",
            );
        }
        if self.media.is_media_call(call_id) {
            self.media.control(call_id, MediaControl::Block(block));
            return ok_empty();
        }
        if relay_flows.is_empty() {
            return error_result(
                "block",
                &"call is not answered as a plain relay (SRTP-bridge block is not supported)",
            );
        }
        // Plain relay: flip each endpoint to Drop, or restore its stored forward action.
        for (endpoint, action) in &relay_flows {
            let next = if block { FlowAction::Drop } else { *action };
            if let Err(error) = self.datapath.install_flow(*endpoint, next) {
                return error_result("block: install flow", &error);
            }
        }
        ok_empty()
    }

    /// Block (`blocked = true`) or resume (`blocked = false`) relaying one leg's RFC 4733
    /// telephone-events (DTMF) to the peer (`block DTMF` / `unblock DTMF`). The named leg's
    /// telephone-events are still detected (the controller sees the digit as an `Event::Dtmf`) but not
    /// forwarded — v1 = drop mode (rtpengine's replace-with-tone/PCM modes are a follow-up).
    ///
    /// A plain relay (`Passthrough`) is promoted to the userspace media pipeline so the actor can gate
    /// the telephone-event PT per direction; a transcode / secure-transcode call already has an actor.
    /// A plain SRTP bridge (`Srtp`) or WebSocket-bridged call (`Ws`) is rejected — its DTMF is not
    /// carried as clear telephone-events (mirrors `subscribe_request` / recording). Only the owning
    /// client may. `source_a` (which leg is blocked) is resolved from the tags the same way
    /// `subscribe_request` does: `to_tag` matching the call's to-tag ⇒ leg B.
    pub(super) async fn block_dtmf(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: Option<&str>,
        blocked: bool,
    ) -> CmdResult {
        // Snapshot the pipeline + the call's to-tag under the ownership guard (A3 — docs §5).
        let Some((pipeline, call_to)) =
            self.owned_call(client, call_id, |call| (call.pipeline, call.to_tag.clone()))
        else {
            return unknown_call(call_id);
        };
        // A plain SRTP bridge / WS-bridge leg's DTMF is not clear telephone-events — reject clearly.
        // (A secure *transcode* call — SrtpMedia — decrypts to clear RTP in the actor, so it is fine.)
        if matches!(pipeline, PipelineKind::Srtp | PipelineKind::Ws) {
            return error_result(
                "block_dtmf",
                &"blocking DTMF on a secure (SRTP) or WebSocket-bridged call is not supported",
            );
        }
        // Resolve which leg is blocked: the call's to_tag ⇒ leg B (source_a = false); else leg A.
        let source_a = !matches!((call_to.as_deref(), to_tag), (Some(to), Some(tag)) if to == tag);
        // A plain relay is promoted to userspace (and held) so its actor can gate the telephone-event
        // PT; a transcode / SrtpMedia call already has an actor. Holding on block, releasing on unblock.
        if blocked {
            if let Err(reason) = self
                .hold_in_userspace(call_id, PromotionReason::DtmfBlock, PromoteMode::RelayOnly)
                .await
            {
                return error_result("block_dtmf: promote relay", &reason);
            }
            if !self.media.control(
                call_id,
                MediaControl::BlockDtmf {
                    source_a,
                    blocked: true,
                },
            ) {
                // The actor vanished between promote and control — release the hold and report.
                self.release_userspace_hold(call_id, PromotionReason::DtmfBlock)
                    .await;
                return error_result("block_dtmf", &"media actor unavailable");
            }
            ok_empty()
        } else {
            // Unblock: clear the actor's gate first (no-op if no actor / never promoted), then release
            // the hold, which demotes a plain relay back to the fast path if nothing else holds it.
            self.media.control(
                call_id,
                MediaControl::BlockDtmf {
                    source_a,
                    blocked: false,
                },
            );
            self.release_userspace_hold(call_id, PromotionReason::DtmfBlock)
                .await;
            ok_empty()
        }
    }

    /// Replace a call's egress audio with comfort silence (`silence = true`) or resume it. Requires a
    /// media-processing call (decode/re-encode); a plain relay forwards opaque payloads and cannot
    /// synthesize silence. Only the owning client may control the call.
    pub(super) fn set_silence(&self, client: ClientId, call_id: &str, silence: bool) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // Silence synthesizes comfort noise in the egress codec — a transcoding call only. A promoted
        // relay-only call (SIPREC on a passthrough relay) forwards opaque payloads and cannot.
        if self.media.is_transcoding_call(call_id)
            && self.media.control(call_id, MediaControl::Silence(silence))
        {
            ok_empty()
        } else {
            error_result(
                "silence",
                &"call is not a media-processing call (transcode/record/stream required)",
            )
        }
    }

    /// Enable or disable echo-test mode on a call ([`Command::Echo`]): each party's ingress audio is
    /// decoded and re-emitted straight back to itself. A single-leg IVR/echo call is a plain
    /// passthrough relay, so — like `block_dtmf` / `start_recording` — echo promotes it into the
    /// userspace media pipeline first, but into a **processing** (decode → re-encode) `MediaCall`, not a
    /// relay-only one (a relay forwards opaque payloads to the peer and cannot loop them home). An
    /// already-transcoding call is used as-is. On disable the hold is released, demoting a promoted
    /// relay back to the `Forward` fast path once nothing else holds it. Only the owning client may
    /// control the call; `from_tag` is accepted for protocol symmetry (echo applies to the whole call).
    pub(super) async fn set_echo(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: Option<&str>,
        enabled: bool,
    ) -> CmdResult {
        let Some(call_to) = self.owned_call(client, call_id, |call| call.to_tag.clone()) else {
            return unknown_call(call_id);
        };
        // Echo is a whole-call operation (each party hears itself), so `from_tag` / `to_tag` are
        // dialog-scoping keys, not per-leg selectors. Honour `to_tag` by validating that, when given,
        // it names this call's UAS (to-tag) leg — a mismatched to-tag is a clean client error, never a
        // silently-ignored knob (RFC 3264 dialog identity; pre-public-review B18).
        if let Some(to_tag) = to_tag {
            if call_to.as_deref() != Some(to_tag) {
                return error_result("echo", &"to_tag does not match this call's to-tag");
            }
        }
        if enabled {
            // Promote a plain relay into a processing MediaCall (idempotent on an already-promoted /
            // transcoding call) and hold it, then turn echo on.
            if let Err(reason) = self
                .hold_in_userspace(call_id, PromotionReason::Echo, PromoteMode::Processing)
                .await
            {
                return error_result("echo: promote relay", &reason);
            }
            if !self.media.control(call_id, MediaControl::Echo(true)) {
                // The actor vanished between promote and control — release the hold and report.
                self.release_userspace_hold(call_id, PromotionReason::Echo)
                    .await;
                return error_result("echo", &"media actor unavailable");
            }
            ok_empty()
        } else {
            // Disable: clear the actor's echo flag (a no-op if never promoted), then release the hold,
            // which demotes a promoted relay back to the fast path if nothing else holds it.
            self.media.control(call_id, MediaControl::Echo(false));
            self.release_userspace_hold(call_id, PromotionReason::Echo)
                .await;
            ok_empty()
        }
    }

    /// Inject an RFC 4733 DTMF sequence toward a leg ([`Command::PlayDtmf`]). Requires a
    /// media-processing call with a negotiated telephone-event payload type on the target leg. The
    /// whole `code` is played as one telephone-event per digit, each `duration_ms` long, separated by
    /// `pause_ms` of inter-digit silence (RFC 4733). The target leg is resolved from `from_tag` /
    /// `to_tag` the same way `block_dtmf` resolves its source leg.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn play_dtmf(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> CmdResult {
        let Some(call_to) = self.owned_call(client, call_id, |call| call.to_tag.clone()) else {
            return unknown_call(call_id);
        };
        if !self.media.is_transcoding_call(call_id) {
            return error_result("play_dtmf", &"requires a media-processing call");
        }
        // Validate the whole code up front: an empty code or a non-DTMF character is a clean client
        // error, never a silent truncation to the first digit (RFC 4733 §3.2 event codes).
        if code.is_empty() {
            return error_result("play_dtmf", &"empty DTMF code");
        }
        if let Some(bad) = code
            .chars()
            .find(|digit| siphon_rtp_media::dtmf::digit_to_event_code(*digit).is_none())
        {
            return error_result(
                "play_dtmf",
                &format!("unsupported DTMF digit {bad:?} in code {code:?}"),
            );
        }
        let duration = duration_ms.unwrap_or(250).min(u64::from(u32::MAX)) as u32;
        let pause = pause_ms
            .map(|value| value.min(u64::from(u32::MAX)) as u32)
            .unwrap_or(siphon_rtp_media::dtmf::DEFAULT_DTMF_PAUSE_MS);
        // `volume_dbm0` is a (negative) dBm0 power level; the generator takes its magnitude (0..=63).
        let volume = volume_dbm0
            .map(|value| value.unsigned_abs().min(63) as u8)
            .unwrap_or(10);
        let toward_a = resolve_toward_a(from_tag, call_to.as_deref(), to_tag);
        // Await the actor's verdict rather than answering from whether the mailbox accepted the
        // message. Only the actor knows whether this leg negotiated a `telephone-event` payload type
        // to carry the digits on, and answering `ok` without one sends nothing — which, on a PBX
        // forwarding a feature code to a carrier or navigating a remote menu, reads as the far end
        // ignoring the digits. Same shape as `stop_media` / `set_play_gain`.
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if !self.media.control(
            call_id,
            MediaControl::PlayDtmf {
                toward_a,
                digits: code.to_string(),
                duration_ms: duration,
                volume,
                pause_ms: pause,
                reply: sender,
            },
        ) {
            return error_result("play_dtmf", &"call is not a media-processing call");
        }
        match receiver.await {
            Ok(PlayDtmfOutcome::Started) => ok_empty(),
            Ok(PlayDtmfOutcome::NoTelephoneEvent) => error_result(
                "play_dtmf",
                &"no telephone-event payload type negotiated toward this leg",
            ),
            // Unreachable through the control plane — the code is validated above — but a hollow
            // success here would be the same defect one layer down.
            Ok(PlayDtmfOutcome::InvalidDigits) => {
                error_result("play_dtmf", &format!("unusable DTMF code {code:?}"))
            }
            Err(_) => error_result(
                "play_dtmf",
                &"media actor closed before the DTMF sequence started",
            ),
        }
    }
}

/// Which party a per-leg play/DTMF verb targets, as `toward_a` (`true` ⇒ play toward leg A, the
/// offerer). A request names leg B when either its `to_tag` or its `from_tag` matches the call's
/// to-tag (rtpengine / RFC 3264 identify a dialog side by its to-tag); otherwise leg A, the default.
/// This mirrors `block_dtmf`'s to-tag resolution while keeping the historical `from_tag` selection
/// working, so `to_tag` is honoured on `play_media` / `play_dtmf` rather than silently ignored
/// (pre-public-review B18).
pub(super) fn resolve_toward_a(
    from_tag: &str,
    call_to: Option<&str>,
    to_tag: Option<&str>,
) -> bool {
    let names_leg_b = |tag: Option<&str>| matches!((call_to, tag), (Some(to), Some(t)) if to == t);
    !(names_leg_b(Some(from_tag)) || names_leg_b(to_tag))
}
