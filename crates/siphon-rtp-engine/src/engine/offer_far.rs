//! The `offer_far` verb: grow a single-leg `answer_local` call into a relay toward a far party, and
//! the `answer` and `delete` that complete it or take it back.
//!
//! The shape it serves is a pre-call announcement. A controller answers the caller's INVITE in early
//! media with `answer_local` (the engine plays a prompt), then dials the callee and connects the two.
//! The caller already holds an answer, and RFC 3261 §13.2.1 has it ignore any SDP that follows in
//! responses to the same INVITE, while RFC 3264 §8 lets an answer change only through a new offer.
//! So the caller's session must not move: its socket, its codec and the answer it was given stay as
//! they are, and the engine re-points the media behind them.
//!
//! `offer_far` binds the far leg and returns an offer for it, while the local pipeline keeps
//! playing. The far party's `answer` stops that pipeline and wires the two legs (a plain relay when
//! they share the caller's codec, the transcoder when they do not), and returns the caller's original
//! answer unchanged. A `delete` with a `to_tag` drops the far leg and puts the local pipeline back, so
//! the controller can play another prompt or dial someone else.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{AddressFamily, Datapath, FlowAction};
use siphon_rtp_proto::{
    CmdResult, PlayEndReason, ProfileFlags, RecordingEndReason, WsTeeEndReason, X3EndReason,
};

use crate::media_pipeline::MediaControl;
use crate::sdp::{self, IceRewrite, ImageRewrite, TextRewrite};

use super::negotiate::{
    cannot_bridge, describe_codec, parse_codec_flags, present_leg, resolve_rtcp_mux, same_codec,
    CodecPresentation, LegPresentation, SourcePosture,
};
use super::offer::far_address_family;
use super::{
    error_result, ok_empty, ok_sdp, unknown_call, Call, ClientId, Engine, Leg, PipelineKind,
    PromoteMode, PromotionReason,
};

const CRLF: &str = "\r\n";

/// What a single-leg `answer_local` call keeps so it can grow a far leg and give it back: the
/// caller's offer and the answer it was sent, and the media state the local pipeline runs on.
#[derive(Debug, Clone)]
pub(super) struct LocalAnswer {
    /// The caller's own offer, which the far offer is built from.
    offer_sdp: String,
    /// The answer the caller holds, returned unchanged when the far party answers.
    answer_sdp: String,
    /// The one codec the caller was answered with. It never changes for the life of the call.
    codec: CodecSpec,
    /// The telephone-event payload type that went with it.
    telephone_event: Option<sdp::TelephoneEvent>,
    /// The comfort-noise payload type the local pipeline idles on.
    comfort_noise_payload_type: Option<u8>,
    /// The audio codecs the current far offer listed; empty while there is none.
    far_offered_codecs: Vec<CodecSpec>,
}

impl Call {
    /// Record what `answer_local` answered the caller with, from the codec, telephone-event and
    /// comfort noise it settled on the call, so `offer_far` can grow the call later.
    pub(super) fn keep_local_answer(&mut self, offer_sdp: &str, answer_sdp: &str) {
        let Some(codec) = self.near_codec.clone() else {
            return;
        };
        self.local_answer = Some(Box::new(LocalAnswer {
            offer_sdp: offer_sdp.to_string(),
            answer_sdp: answer_sdp.to_string(),
            codec,
            telephone_event: self.near_telephone_event,
            comfort_noise_payload_type: self.comfort_noise_payload_type,
            far_offered_codecs: Vec::new(),
        }));
    }

    /// Whether this is an `answer_local` call with a far leg offered and not yet answered.
    pub(super) fn far_offer_pending(&self) -> bool {
        self.local_answer.is_some() && self.far.is_some() && self.to_tag.is_none()
    }
}

/// Why `offer_far` cannot grow `call`, or `None` when it can.
fn far_offer_refusal(call: &Call) -> Option<&'static str> {
    if call.local_answer.is_none() {
        return Some(
            "offer_far: not-a-local-answer: offer_far grows a call the engine answered itself with \
             answer_local (and not a WebSocket takeover)",
        );
    }
    if call.far.is_some() {
        return Some(
            "offer_far: far-leg-exists: the call already has a far leg; delete it (delete with the \
             far to_tag) before offering another",
        );
    }
    // The caller's keying and ICE live on the local pipeline (a single-leg secure leg, an agent on
    // its one endpoint), and the two-party wiring cannot take them over mid-stream without re-keying
    // or re-checking. Refused rather than relayed in the clear or to an unvalidated address.
    if call.near_secure {
        return Some(
            "offer_far: near-leg-not-plain: the caller is on SRTP, and only a plain RTP caller can \
             be grown into a relay",
        );
    }
    if call.caller_source_posture == SourcePosture::Ice {
        return Some(
            "offer_far: near-leg-not-plain: the caller runs ICE, and only a plain RTP caller can be \
             grown into a relay",
        );
    }
    None
}

/// Why the far party's answer cannot complete the relay, or `None` when it can.
///
/// RFC 3264 §6.1: an answer selects from the formats its offer listed. The caller keeps its codec
/// whatever the far party picks, so a codec the far offer did not list could only be met by a
/// transcoder nobody negotiated. A plain relay also forwards the payload type as received, so the
/// caller's own codec under another number would reach the caller on a payload type it was never
/// told about (RFC 3551 §3).
fn far_answer_refusal(
    info: &sdp::MediaInfo,
    codec: &CodecSpec,
    offered: &[CodecSpec],
) -> Option<CmdResult> {
    let answered = info.primary_codec()?;
    if !offered.iter().any(|listed| same_codec(listed, &answered)) {
        return Some(CmdResult::Error {
            reason: format!(
                "answer: codec-not-offered: the far party answered {}, which the far offer did not \
                 list (RFC 3264 §6.1)",
                describe_codec(&answered)
            ),
        });
    }
    if same_codec(&answered, codec) && answered.payload_type != codec.payload_type {
        return Some(CmdResult::Error {
            reason: format!(
                "answer: renumbered-near-codec: the far party answered the caller's codec as {}, \
                 but the caller was answered with {}; a relay would forward a payload type the \
                 caller never agreed",
                describe_codec(&answered),
                describe_codec(codec)
            ),
        });
    }
    None
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// [`Command::OfferFar`](siphon_rtp_proto::Command::OfferFar): bind a far leg on a single-leg
    /// `answer_local` call and return the SDP offer for it. The caller's leg and the local pipeline
    /// are left exactly as they are.
    pub(super) async fn offer_far(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        if let Err(reason) = crate::media_pipeline::validate_profile(profile) {
            return error_result("offer_far", &reason);
        }
        if profile.ws_uri.is_some() || profile.fax_passthrough {
            return error_result(
                "offer_far",
                &"the far leg is a relay toward an RTP party; ws_uri and fax_passthrough do not \
                  apply to it",
            );
        }
        let (offer_sdp, codec) = match self.calls.get(call_id) {
            Some(call) if call.admits(client, call_id) => {
                if call.from_tag != from_tag {
                    return error_result("offer_far", &"from_tag mismatch");
                }
                if let Some(reason) = far_offer_refusal(&call) {
                    return CmdResult::Error {
                        reason: reason.to_string(),
                    };
                }
                match call.local_answer.as_deref() {
                    Some(local) => (local.offer_sdp.clone(), local.codec.clone()),
                    None => return unknown_call(call_id),
                }
            }
            _ => return unknown_call(call_id),
        };
        let info = match sdp::parse(&offer_sdp) {
            Ok(info) => info,
            Err(error) => return error_result("offer_far: the caller's offer", &error),
        };

        // The far leg as `offer` binds one: the `address family` flag's family (else the caller's),
        // `direction[1]`'s interface, and RFC 5761 multiplexing as the caller offered it unless a
        // `rtcp-mux` directive says otherwise.
        let far_family =
            far_address_family(profile).unwrap_or_else(|| AddressFamily::of(info.remote_rtp.ip()));
        let (_, far_mux) = resolve_rtcp_mux(info.rtcp_mux, &profile.rtcp_mux);
        let (_, far_interface) = self.interfaces.resolve_direction(&profile.direction);
        let (far_bind, far_advertised_override) = Self::leg_binding(far_interface, far_family);
        let far_endpoints = match self
            .alloc_endpoints(if far_mux { 1 } else { 2 }, far_family, far_bind)
            .await
        {
            Ok(endpoints) => endpoints,
            Err(reason) => return CmdResult::Error { reason },
        };
        let far_rtp = far_endpoints[0];
        let far = Leg {
            rtp: far_rtp,
            rtcp: (!far_mux).then(|| far_endpoints[1]),
            remote_rtp: None,
            remote_rtcp: None,
            advertised_ip: far_advertised_override.unwrap_or_else(|| far_rtp.local_addr.ip()),
            // The caller's answer declined text and fax, so neither is offered on.
            text: None,
            text_remote_rtp: None,
            image: None,
            image_remote: None,
            floor: None,
            floor_remote: None,
        };
        let far_sdp =
            match far_offer_sdp(&offer_sdp, &info, &far, far_mux, &codec, profile, call_id) {
                Ok(far_sdp) => far_sdp,
                Err(reason) => {
                    self.free(&far_endpoints).await;
                    return error_result("offer_far: SDP rewrite failed", &reason);
                }
            };
        let far_offered_codecs = sdp::parse(&far_sdp)
            .map(|offered| offered.audio_codecs())
            .unwrap_or_default();

        // Recorded only if the call is still the one checked above: a `delete` or a second
        // `offer_far` may have run while the far ports were bound.
        let recorded = match self.calls.get_mut(call_id) {
            Some(mut call) if call.from_tag == from_tag && far_offer_refusal(&call).is_none() => {
                call.far = Some(far);
                // The caller is held on the codec it was answered with, whatever the far party picks:
                // `answer` adopts the far party's codec only when it is this one, and otherwise
                // engages the transcoder, as `codec-mask` holds a near codec.
                call.near_offered_codecs = vec![codec.clone()];
                call.near_codec_withheld = false;
                let mut telephone_events = Vec::new();
                if let Some(local) = call.local_answer.as_deref_mut() {
                    telephone_events.extend(local.telephone_event);
                    local.far_offered_codecs = far_offered_codecs;
                }
                call.near_offered_telephone_events = telephone_events;
                call.far_sip_call_id = None;
                true
            }
            _ => false,
        };
        if !recorded {
            self.free(&far_endpoints).await;
            return error_result(
                "offer_far",
                &"the call changed while the far leg was being bound",
            );
        }
        for endpoint in far.all_endpoint_ids() {
            self.endpoint_calls.insert(endpoint, call_id.to_string());
        }
        self.watch_for_media([far.rtp.id]);
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            far_local = %far.rtp.local_addr,
            codec = %codec.encoding_name,
            "far leg offered on a locally answered call"
        );
        ok_sdp(far_sdp, None)
    }

    /// [`Command::Answer`], routed here first: the far party answering a leg `offer_far` offered
    /// stops the local pipeline, wires the relay through [`Self::answer`], and returns the caller's
    /// original answer. Any other call goes straight to [`Self::answer`].
    pub(super) async fn answer_or_complete_far(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        to_tag: String,
        sdp_text: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        let pending = self.calls.get(call_id).and_then(|call| {
            (call.admits(client, call_id) && call.from_tag == from_tag && call.far_offer_pending())
                .then(|| call.local_answer.as_deref().cloned())
                .flatten()
        });
        let Some(local) = pending else {
            return self
                .answer(client, call_id, from_tag, to_tag, sdp_text, profile)
                .await;
        };
        match sdp::parse(sdp_text) {
            Ok(info) => {
                if let Some(refusal) =
                    far_answer_refusal(&info, &local.codec, &local.far_offered_codecs)
                {
                    return refusal;
                }
            }
            Err(error) => return error_result("answer SDP parse failed", &error),
        }
        self.stop_call_pipeline(call_id).await;
        match self
            .answer(client, call_id, from_tag, to_tag, sdp_text, profile)
            .await
        {
            // The caller already holds its answer and must not be handed another (RFC 3261
            // §13.2.1, RFC 6337 §3.1.1): the same bytes go back, whatever the relay looks like.
            CmdResult::Ok { to_tag, .. } => {
                tracing::info!(
                    target: "siphon_rtp::media",
                    call_id = %call_id,
                    "far party answered; the locally answered caller is relayed to it"
                );
                ok_sdp(local.answer_sdp, to_tag)
            }
            refusal => {
                // The far leg stays offered, so the controller can still delete it; the caller goes
                // back to the local pipeline rather than to silence.
                if let Err(reason) = self.resume_local_pipeline(call_id, &local).await {
                    tracing::warn!(target: "siphon_rtp::media", call_id = %call_id, %reason, "could not resume the local pipeline after a refused far answer");
                }
                refusal
            }
        }
    }

    /// [`Command::Delete`] with a `to_tag`: on a call grown by `offer_far`, drop the far leg and put
    /// the caller back on the local pipeline. `None` for any other call, which `delete` tears down
    /// whole as it always has.
    pub(super) async fn delete_far_leg(
        &self,
        client: ClientId,
        call_id: &str,
        to_tag: &str,
    ) -> Option<CmdResult> {
        let (local, far) = {
            let mut call = self.calls.get_mut(call_id)?;
            if !call.admits(client, call_id) || call.far.is_none() {
                return None;
            }
            let local = call.local_answer.as_deref().cloned()?;
            if call
                .to_tag
                .as_deref()
                .is_some_and(|answered| answered != to_tag)
            {
                return Some(error_result(
                    "delete",
                    &format!("to_tag {to_tag} names no far leg of this call"),
                ));
            }
            (local, call.far.take()?)
        };
        self.stop_call_pipeline(call_id).await;
        let endpoints: Vec<_> = far.all_endpoint_ids().collect();
        self.bridge.deregister(endpoints.iter().copied());
        for endpoint in endpoints {
            self.datapath.remove_endpoint(endpoint).await;
            self.endpoint_calls.remove(&endpoint);
            self.awaiting_media.remove(&endpoint);
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            forget_far_party(&mut call);
        }
        if let Err(reason) = self.resume_local_pipeline(call_id, &local).await {
            self.teardown_call(call_id).await;
            return Some(error_result("delete: resume the local pipeline", &reason));
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            "far leg released; the caller is back on the local pipeline"
        );
        Some(ok_empty())
    }

    /// Stop whatever carries the call's media now (the local pipeline, or the relay a far party's
    /// answer installed), ending what rides it with a reason its controller sees, and leave the
    /// caller's endpoint dropping until the next pipeline is installed.
    async fn stop_call_pipeline(&self, call_id: &str) {
        self.cancel_pending_fetches_for_call(call_id, PlayEndReason::Stopped);
        self.media.control(call_id, MediaControl::StopPlay);
        self.drop_subscriptions(call_id).await;
        self.stop_ws_tee(call_id, WsTeeEndReason::Detached).await;
        self.stop_wav_recordings_for_call(call_id, RecordingEndReason::Stopped)
            .await;
        self.stop_x3(call_id, X3EndReason::Detached).await;
        // Awaited, so the old actor never sends on the caller's endpoint beside the new one.
        self.media.stop(call_id).await;
        let near = self.calls.get(call_id).map(|call| call.near);
        if let Some(near) = near {
            self.bridge.deregister(near.endpoint_ids());
            for endpoint in near.endpoint_ids() {
                if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Drop) {
                    tracing::warn!(target: "siphon_rtp::media", call_id = %call_id, %error, "could not park the caller's endpoint");
                }
            }
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Passthrough;
            call.relay_flows.clear();
            call.promotion_reasons.clear();
            call.far_codec = None;
            call.comfort_noise_payload_type = None;
        }
    }

    /// Put the caller back on the single-leg local pipeline `answer_local` set up: the same codec,
    /// telephone-event and comfort noise, on the same endpoint.
    async fn resume_local_pipeline(
        &self,
        call_id: &str,
        local: &LocalAnswer,
    ) -> Result<(), String> {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.near_codec = Some(local.codec.clone());
            call.near_telephone_event = local.telephone_event;
            call.comfort_noise_payload_type = local.comfort_noise_payload_type;
            // The single-leg arm of the promotion reads `far_codec == None`.
            call.far_codec = None;
            call.pipeline = PipelineKind::Passthrough;
        }
        self.hold_in_userspace(call_id, PromotionReason::MediaOp, PromoteMode::Processing)
            .await?;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.far_codec = Some(local.codec.clone());
            call.pipeline = PipelineKind::Media;
        }
        Ok(())
    }
}

/// Clear what a far party's offer and answer recorded on `call`, now that its leg is gone.
fn forget_far_party(call: &mut Call) {
    call.to_tag = None;
    call.far_rtcp_fallback = false;
    call.far_local_candidates.clear();
    call.far_remote_ice = None;
    call.far_remote_crypto = None;
    call.far_telephone_event = None;
    call.far_direction = sdp::MediaDirection::default();
    call.far_received_from = None;
    call.far_sip_call_id = None;
    call.far_media_started_at_unix_ms = None;
    call.pending_far_reoffer = None;
    call.near_offered_codecs.clear();
    if let Some(local) = call.local_answer.as_deref_mut() {
        local.far_offered_codecs.clear();
    }
}

/// The SDP offer for the far leg: the caller's offer presented on the far leg's endpoints, with the
/// codec list rebuilt around the codec the caller was answered with.
///
/// The order is the caller's codec, then the caller's other offered codecs the engine can transcode
/// to it, then the profile's `codec-transcode-X` additions, then telephone-event (RFC 3264 §5.1: the
/// first format is the preferred one). The profile's other codec flags apply as they do to `offer`'s
/// far offer; they shape what the far party may pick, never what the caller is held on. Text, fax and
/// any other stream the caller's answer declined are offered declined (port 0, RFC 3264 §5.1).
fn far_offer_sdp(
    offer_sdp: &str,
    info: &sdp::MediaInfo,
    far: &Leg,
    far_mux: bool,
    codec: &CodecSpec,
    profile: &ProfileFlags,
    call_id: &str,
) -> Result<String, String> {
    let presentation = LegPresentation {
        engine: far.engine_media(),
        // The caller's ICE describes the caller, never the far leg.
        ice: if info.is_ice() {
            IceRewrite::Strip
        } else {
            IceRewrite::Keep
        },
        // A plain caller only (`far_offer_refusal`), so the transport passes through as RTP/AVP.
        security: None,
        floor: far.floor_rewrite(None),
        mux_override: (!profile.rtcp_mux.is_empty()).then_some(far_mux),
        text: if info.text.is_some() {
            TextRewrite::Decline
        } else {
            TextRewrite::None
        },
        image: if info.image.is_some() {
            ImageRewrite::Decline
        } else {
            ImageRewrite::None
        },
        codec: CodecPresentation::AsReceived,
    };
    let presented = present_leg(offer_sdp, presentation, &profile.replace, call_id)
        .map_err(|error| error.to_string())?;
    let presented = sdp::decline_unanswered_media(presented, false);
    // The caller's codec under any other payload type (AMR in its other payload format) and every
    // codec the engine cannot transcode to it would let the far party pick something the caller can
    // never be connected to.
    let unusable: Vec<u8> = info
        .audio_codecs()
        .iter()
        .filter(|offered| {
            if same_codec(offered, codec) {
                offered.payload_type != codec.payload_type
            } else {
                cannot_bridge(codec, offered).is_some()
            }
        })
        .map(|offered| offered.payload_type)
        .collect();
    let presented = drop_audio_formats(&presented, &unusable);
    let policy = parse_codec_flags(&profile.flags);
    let presented = sdp::apply_codec_policy(&presented, &policy);
    let events: Vec<u8> = sdp::parse(&presented)
        .map_err(|error| error.to_string())?
        .telephone_events()
        .iter()
        .map(|event| event.payload_type)
        .collect();
    Ok(order_audio_formats(&presented, codec.payload_type, &events))
}

/// The index of the first `m=audio` line in `lines`, and the end of its media section.
fn audio_section(lines: &[&str]) -> Option<(usize, usize)> {
    let start = lines.iter().position(|line| line.starts_with("m=audio "))?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| line.starts_with("m="))
        .map_or(lines.len(), |(index, _)| index);
    Some((start, end))
}

/// The payload type an `a=rtpmap:` or `a=fmtp:` line describes.
fn attribute_payload_type(line: &str) -> Option<u8> {
    line.strip_prefix("a=rtpmap:")
        .or_else(|| line.strip_prefix("a=fmtp:"))?
        .split(|character: char| character.is_whitespace())
        .next()?
        .parse()
        .ok()
}

/// Split SDP text into lines without their line ending, and remember whether it ended in one.
fn split_lines(sdp_text: &str) -> (Vec<&str>, bool) {
    let trailing = sdp_text.ends_with('\n');
    let lines = sdp_text
        .trim_end_matches(['\r', '\n'])
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    (lines, trailing)
}

fn join_lines(lines: &[String], trailing: bool) -> String {
    let mut joined = lines.join(CRLF);
    if trailing {
        joined.push_str(CRLF);
    }
    joined
}

/// Remove `dropped` from the first `m=audio` line's formats, with their `a=rtpmap`/`a=fmtp` lines.
/// The last audio format is never removed, since an `m=` line needs one (RFC 4566 §5.14).
fn drop_audio_formats(sdp_text: &str, dropped: &[u8]) -> String {
    if dropped.is_empty() {
        return sdp_text.to_string();
    }
    let (lines, trailing) = split_lines(sdp_text);
    let Some((start, end)) = audio_section(&lines) else {
        return sdp_text.to_string();
    };
    let fields: Vec<&str> = lines[start].split(' ').collect();
    if fields.len() < 4 {
        return sdp_text.to_string();
    }
    let kept: Vec<&str> = fields[3..]
        .iter()
        .copied()
        .filter(|format| !format.parse::<u8>().is_ok_and(|pt| dropped.contains(&pt)))
        .collect();
    if kept.is_empty() {
        return sdp_text.to_string();
    }
    let mut out = Vec::with_capacity(lines.len());
    for (index, line) in lines.iter().enumerate() {
        if index == start {
            out.push(format!("{} {}", fields[..3].join(" "), kept.join(" ")));
        } else if (start..end).contains(&index)
            && attribute_payload_type(line).is_some_and(|pt| dropped.contains(&pt))
        {
            continue;
        } else {
            out.push((*line).to_string());
        }
    }
    join_lines(&out, trailing)
}

/// Reorder the first `m=audio` line's formats: `lead` first, the other codecs in their order, and
/// the telephone-event payload types last.
fn order_audio_formats(sdp_text: &str, lead: u8, events: &[u8]) -> String {
    let (lines, trailing) = split_lines(sdp_text);
    let Some((start, _)) = audio_section(&lines) else {
        return sdp_text.to_string();
    };
    let fields: Vec<&str> = lines[start].split(' ').collect();
    if fields.len() < 4 {
        return sdp_text.to_string();
    }
    let mut formats: Vec<&str> = fields[3..].to_vec();
    formats.sort_by_key(|format| match format.parse::<u8>() {
        Ok(pt) if pt == lead => 0,
        Ok(pt) if events.contains(&pt) => 2,
        _ => 1,
    });
    let mut out: Vec<String> = lines.iter().map(|line| (*line).to_string()).collect();
    out[start] = format!("{} {}", fields[..3].join(" "), formats.join(" "));
    join_lines(&out, trailing)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\n\
        t=0 0\r\nm=audio 4000 RTP/AVP 8 0 101 18\r\na=rtpmap:8 PCMA/8000\r\n\
        a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n\
        a=rtpmap:18 G729/8000\r\na=fmtp:18 annexb=no\r\n";

    #[test]
    fn dropping_formats_removes_their_attributes_and_keeps_the_rest() {
        let dropped = drop_audio_formats(OFFER, &[18]);
        assert!(
            dropped.contains("m=audio 4000 RTP/AVP 8 0 101\r\n"),
            "{dropped}"
        );
        assert!(!dropped.contains("G729"), "{dropped}");
        assert!(!dropped.contains("annexb"), "{dropped}");
        assert!(dropped.contains("a=fmtp:101 0-15\r\n"), "{dropped}");
        assert!(dropped.ends_with("\r\n"));
    }

    #[test]
    fn dropping_every_format_leaves_the_line_alone() {
        let all = drop_audio_formats(OFFER, &[8, 0, 101, 18]);
        assert_eq!(all, OFFER);
    }

    #[test]
    fn ordering_leads_with_the_held_codec_and_ends_with_telephone_event() {
        let ordered = order_audio_formats(OFFER, 0, &[101]);
        assert!(
            ordered.contains("m=audio 4000 RTP/AVP 0 8 18 101\r\n"),
            "{ordered}"
        );
        assert_eq!(ordered.len(), OFFER.len());
    }

    #[test]
    fn an_sdp_without_audio_is_left_alone() {
        let video = "v=0\r\nm=video 4002 RTP/AVP 96\r\n";
        assert_eq!(drop_audio_formats(video, &[96]), video);
        assert_eq!(order_audio_formats(video, 96, &[]), video);
    }

    #[test]
    fn a_far_answer_outside_the_offer_or_renumbering_the_caller_is_refused() {
        let pcmu = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        let pcma = CodecSpec::new(8, "PCMA", 8000, 1, 20);
        let offered = vec![pcmu.clone(), pcma.clone()];
        let answer = |line: &str| {
            sdp::parse(&format!(
                "v=0\r\no=- 2 2 IN IP4 192.0.2.20\r\ns=-\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\n{line}"
            ))
            .expect("parse")
        };
        assert!(
            far_answer_refusal(&answer("m=audio 5000 RTP/AVP 0\r\n"), &pcmu, &offered).is_none()
        );
        assert!(
            far_answer_refusal(&answer("m=audio 5000 RTP/AVP 8\r\n"), &pcmu, &offered).is_none()
        );
        let refused = far_answer_refusal(&answer("m=audio 5000 RTP/AVP 9\r\n"), &pcmu, &offered);
        assert!(
            matches!(&refused, Some(CmdResult::Error { reason }) if reason.contains("codec-not-offered")),
            "{refused:?}"
        );
        let renumbered = far_answer_refusal(
            &answer("m=audio 5000 RTP/AVP 96\r\na=rtpmap:96 PCMU/8000\r\n"),
            &pcmu,
            &offered,
        );
        assert!(
            matches!(&renumbered, Some(CmdResult::Error { reason }) if reason.contains("renumbered-near-codec")),
            "{renumbered:?}"
        );
    }
}
