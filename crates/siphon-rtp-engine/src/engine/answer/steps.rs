//! The steps of `answer` that sit after the pipeline is chosen: the streams beside the audio, the
//! pipeline resolution, and the reply.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, ProfileFlags};
use siphon_rtp_srtp::sdes::CryptoAttribute;

use crate::engine::install::{AnswerText, AnswerWiring, AnsweredText};
use crate::engine::negotiate::{
    resolve_pipeline, resolve_pipeline_kind, settle_secure_offerer, NearDtlsAnswer,
};
use crate::engine::promote::secure_release::HeldAnswer;
use crate::engine::{Engine, Leg, PipelineKind};
use crate::sdp;

use super::{lead_with_codec, log_answer_applied, negotiated_near_codec, ReversedAnswer};

/// What an applied answer still needs to settle, log and present.
pub(super) struct AnswerFinish<'a> {
    pub(super) call_id: &'a str,
    pub(super) to_tag: &'a str,
    pub(super) sdp: &'a str,
    pub(super) profile: &'a ProfileFlags,
    pub(super) reversed: Option<&'a ReversedAnswer>,
    pub(super) near: &'a Leg,
    pub(super) info: &'a sdp::MediaInfo,
    pub(super) near_codec: Option<&'a CodecSpec>,
    pub(super) pipeline: PipelineKind,
    pub(super) pinned: Option<crate::engine::record_call::PinnedRecordings>,
}

/// What [`Engine::install_answer_streams`] brought up beside the audio.
pub(super) struct AnsweredStreams {
    pub(super) text: AnsweredText,
    /// B's signalled UDPTL address, when a T.38 stream was relayed. `None` otherwise.
    pub(super) far_image_remote: Option<std::net::SocketAddr>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The streams beside the audio, installed after its pipeline: the text stream, the T.38 fax
    /// relay and the MCPTT floor stream. `reply` is the answer SDP the controller sent and whether
    /// it is the reversed answer (A answering B's re-offer).
    pub(super) fn install_answer_streams(
        &self,
        wiring: &AnswerWiring<'_>,
        reply: (&str, bool),
        text: &AnswerText<'_>,
        secure_text_events_sink: Option<flume::Sender<siphon_rtp_proto::Event>>,
    ) -> Result<AnsweredStreams, Box<CmdResult>> {
        let text_installed = self.install_answer_text(text, secure_text_events_sink)?;

        // The T.38 fax relay, if both legs anchored one and B accepted it. It is installed after the
        // audio/text wiring and independently of it: a fax stream is its own inbound surface with its
        // own gate and latch, and a failure to bring it up must not fail the call's audio.
        let far_image_remote = self.install_answer_image(
            text.call_id,
            text.profile,
            text.info,
            &text.near,
            &text.far,
            text.offer_received_from,
        );

        // The MCPTT floor stream is terminated on both parties' endpoints.
        self.install_answer_floor(wiring, reply.0, reply.1);
        Ok(AnsweredStreams {
            text: text_installed,
            far_image_remote,
        })
    }

    /// The end of an applied answer: the pinned recordings settled, the answer logged, and the video
    /// stream (see `call_video`) settled, installed and presented, then the reply to the controller.
    pub(super) async fn finish_answer(
        &self,
        finish: AnswerFinish<'_>,
        (presented, answer_to_tag): (String, String),
    ) -> CmdResult {
        let AnswerFinish {
            call_id,
            to_tag,
            sdp,
            profile,
            reversed,
            near,
            info,
            near_codec,
            pipeline,
            pinned,
        } = finish;
        self.settle_answered_media(call_id, pinned, profile).await;
        log_answer_applied(call_id, to_tag, reversed, near, info, near_codec, pipeline);
        self.video_reply(
            call_id,
            (sdp, profile, reversed.is_some()),
            (presented, answer_to_tag),
        )
        .await
    }

    /// How this call's media is carried (an SRTP bridge for a secure leg, the userspace media slow
    /// path for transcode or record, or the in-datapath plain relay), resolved before the SDP is
    /// presented because a transcoding call presents each party only its own codec; and, where a
    /// pipeline carries a secure offerer's keying, that offerer's settled DTLS answer (see
    /// `settle_secure_offerer`).
    pub(super) async fn resolve_answer_pipeline(
        &self,
        call_id: &str,
        near_codec: Option<&CodecSpec>,
        (info, profile, reversed): (&sdp::MediaInfo, &ProfileFlags, bool),
        (far_local_crypto, near_local_crypto, far_dtls): (
            Option<CryptoAttribute>,
            Option<CryptoAttribute>,
            bool,
        ),
        near_dtls: Option<&crate::engine::NearDtls>,
    ) -> Result<(PipelineKind, Option<NearDtlsAnswer>), Box<CmdResult>> {
        let resolved = resolve_pipeline_kind(
            near_codec,
            info,
            profile,
            far_local_crypto,
            near_local_crypto,
            far_dtls,
            near_dtls.is_some(),
        );
        // Ahead of everything this answer would change: the reversed exchange refused already, before
        // it wrote A's answer (`refuse_reversed_switch`).
        if !reversed {
            let current = self.calls.get(call_id).map(|call| call.pipeline);
            refuse_transcrypt_switch(current, resolved)?;
        }
        let pipeline = resolve_pipeline(
            near_codec,
            info,
            profile,
            far_local_crypto,
            near_local_crypto,
            far_dtls,
            near_dtls.is_some(),
        )
        .map_err(|reason| {
            Box::new(CmdResult::Error {
                reason: format!("answer: {reason}"),
            })
        })?;
        // A call held for a split stays on the actor's kind (promote/secure_hold.rs).
        let held = self
            .settle_held_pipeline(
                call_id,
                pipeline,
                (
                    info.fingerprint.as_ref(),
                    near_dtls.map(|keying| &keying.peer_fingerprint),
                ),
            )
            .await;
        if matches!(held, HeldAnswer::SplitRefusesRekey(_)) {
            return Err(Box::new(CmdResult::Error {
                reason: "answer: ws-split-renegotiation: a DTLS re-handshake cannot be followed \
                         while a split holds the call (the parties stay isolated); send \
                         detach_ws_split first"
                    .to_string(),
            }));
        }
        let pipeline = held.pipeline();
        // A split on a call that was plain when it began cannot go back to a crypto bridge because
        // the re-offer made a leg secure: the bridge would relay one party to the other.
        let pipeline = self.keep_split_on_actor(call_id, pipeline);
        let settled = settle_secure_offerer(
            pipeline,
            (near_local_crypto.is_some(), near_dtls),
            far_dtls || far_local_crypto.is_some(),
            (reversed, profile, self.engine_fingerprint()),
        )?;
        Ok((pipeline, settled))
    }
}

/// Refuse an answer that would move a live DTLS caller bridged to an SDES callee between its crypto
/// bridge and its transcode twin (secure-transcrypt-renegotiation-unsupported). The kept
/// association's flows either relay or feed an actor, and the callee's SDES leg lives in the bridge
/// or in the actor accordingly; moving both together is not carried. A pure comparison of the live
/// kind with the one the answer resolves to, so it can run ahead of every side effect of the answer
/// (ICE, the call record) and leave the call as it was.
fn refuse_transcrypt_switch(
    current: Option<PipelineKind>,
    resolved: PipelineKind,
) -> Result<(), Box<CmdResult>> {
    use PipelineKind::{DtlsOffererTranscrypt as Relay, DtlsOffererTranscryptMedia as Twin};
    if matches!(
        (current, resolved),
        (Some(Relay), Twin) | (Some(Twin), Relay)
    ) {
        return Err(Box::new(CmdResult::Error {
            reason: "answer: secure-transcrypt-renegotiation-unsupported: the answer would move a \
                     live DTLS caller bridged to an SDES callee between the crypto bridge and the \
                     media pipeline"
                .to_string(),
        }));
    }
    Ok(())
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// A re-offer from the far party being answered by A: each party stays on the codec it
    /// negotiated. On a relay both share one, and it is the one A's answer selected from B's list
    /// (RFC 3264 §6.1); on a transcode A was shown only its own codec, so B's is the one B already
    /// had. Leading B's list with it lets the codec machinery read it as B's primary, so the pipeline
    /// decision does not move on a renegotiation that changes no codec.
    pub(super) fn lead_far_reoffer(
        &self,
        call_id: &str,
        answered: &sdp::MediaInfo,
        far: &mut sdp::MediaInfo,
    ) {
        let Some((transcoding, stored)) = self
            .calls
            .get(call_id)
            .map(|call| (call.pipeline.is_transcode(), call.far_codec.clone()))
        else {
            return;
        };
        let far_codec = match answered.primary_codec() {
            Some(selected)
                if !transcoding
                    && far.audio_codecs().iter().any(|offered| {
                        crate::engine::negotiate::same_codec(offered, &selected)
                    }) =>
            {
                Some(selected)
            }
            _ => stored,
        };
        if let Some(far_codec) = far_codec.as_ref() {
            lead_with_codec(far, far_codec);
        }
    }

    /// [`refuse_transcrypt_switch`] for A's answer to B's re-offer, predicted from what the answer
    /// would settle (A's codec as `negotiated_near_codec` would pick it from A's answered list), before
    /// that answer is written to the call.
    pub(super) fn refuse_reversed_switch(
        &self,
        call_id: &str,
        answered: &sdp::MediaInfo,
        far: &sdp::MediaInfo,
        profile: &ProfileFlags,
    ) -> Result<(), Box<CmdResult>> {
        let Some(call) = self.calls.get(call_id) else {
            return Ok(());
        };
        let answered_codecs = answered.audio_codecs();
        let offered = if answered_codecs.is_empty() {
            call.near_offered_codecs.clone()
        } else {
            answered_codecs
        };
        // A codec the answer cannot settle is refused later, with its own reason.
        let Ok(near_codec) = negotiated_near_codec(
            &offered,
            call.near_codec.clone(),
            far.primary_codec().as_ref(),
            call.near_codec_withheld,
        ) else {
            return Ok(());
        };
        let resolved = resolve_pipeline_kind(
            near_codec.as_ref(),
            far,
            profile,
            call.far_local_crypto,
            call.near_local_crypto,
            call.far_dtls,
            call.near_dtls.is_some(),
        );
        refuse_transcrypt_switch(Some(call.pipeline), resolved)
    }
}
