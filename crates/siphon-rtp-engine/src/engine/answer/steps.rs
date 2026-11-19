//! The steps of `answer` that sit after the pipeline is chosen: the streams beside the audio, the
//! pipeline resolution, and the reply.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, ProfileFlags};
use siphon_rtp_srtp::sdes::CryptoAttribute;

use crate::engine::install::{AnswerText, AnswerWiring, AnsweredText};
use crate::engine::negotiate::{resolve_pipeline, settle_secure_offerer, NearDtlsAnswer};
use crate::engine::{Engine, Leg, PipelineKind};
use crate::sdp;

use super::{log_answer_applied, ReversedAnswer};

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
    pub(super) fn resolve_answer_pipeline(
        &self,
        near_codec: Option<&CodecSpec>,
        (info, profile, reversed): (&sdp::MediaInfo, &ProfileFlags, bool),
        (far_local_crypto, near_local_crypto, far_dtls): (
            Option<CryptoAttribute>,
            Option<CryptoAttribute>,
            bool,
        ),
        near_dtls: Option<&crate::engine::NearDtls>,
    ) -> Result<(PipelineKind, Option<NearDtlsAnswer>), Box<CmdResult>> {
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
        let settled = settle_secure_offerer(
            pipeline,
            (near_local_crypto.is_some(), near_dtls),
            far_dtls || far_local_crypto.is_some(),
            (reversed, profile, self.engine_fingerprint()),
        )?;
        Ok((pipeline, settled))
    }
}
