//! Anchored video on a call the engine answered itself (`answer_local`, then `offer_far`).
//!
//! The caller's answer is frozen once `answer_local` returns (RFC 3264 §8; see [`super::offer_far`]),
//! so a video stream the caller offered is accepted up front or not at all. With
//! `video_relay: anchor` the engine answers it on its own endpoints, with the caller's formats
//! untouched (the two parties' payload types go end to end, nothing is transcoded) and the
//! complement direction, and drops the caller's video until a far party answers: an answerer that
//! sends nothing is allowed (RFC 3264 §6.1), and nothing is relayed to an address nobody confirmed.
//! The far party is then offered the same formats on a far video leg, and its answer, when it keeps
//! them, installs the ordinary two-party video relay ([`super::call_video`]) between the two legs.
//!
//! When the relay goes live each side that sends and accepts Picture Loss Indication is asked for a
//! keyframe once, so the decoder behind it starts on a picture it can decode (RFC 4585 §6.3.1, RFC 6184
//! §1.1). Plain RTP callers only: a secure, ICE or WebSocket-bridged caller is refused, see
//! docs/security-and-nat.md, "Video on a two-party call".

use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction};
use siphon_rtp_media::rtcp;
use siphon_rtp_proto::{CmdResult, ProfileFlags, VideoRelay};
use std::net::{IpAddr, SocketAddr};

use super::call_video::VideoLeg;
use super::negotiate::random_ssrc;
use super::{Engine, Party};
use crate::sdp::{self, VideoStream};

/// How many once-a-second sweeps a keyframe request waits for the stream it is about may be named.
/// The media SSRC of a PLI is the stream the receiver of the request sends (RFC 4585 §6.1), known
/// only once that stream has been seen on the relay, so a request whose sender never sends is dropped
/// after this long rather than retried for the life of the call.
pub(super) const KEYFRAME_SWEEPS: u8 = 30;

/// The longest feedback compound the engine writes: an empty report, a source description with its
/// CNAME, and one Picture Loss Indication.
const KEYFRAME_COMPOUND_CAPACITY: usize = 64;

/// The keyframe requests still to send for a call whose relay went live.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct KeyframeRequests {
    /// The SSRC the requests are sent from, minted for the call (RFC 3550 §8).
    pub(super) sender_ssrc: u32,
    /// The near party is to be asked for a keyframe.
    pub(super) near: bool,
    /// The far party is to be asked for a keyframe.
    pub(super) far: bool,
    /// Sweeps left to find the media SSRC in.
    pub(super) sweeps_left: u8,
}

impl KeyframeRequests {
    /// Requests toward the parties that send and accept PLI, `sender` being the engine's own SSRC.
    pub(super) fn new(sender_ssrc: u32, near: bool, far: bool) -> Self {
        Self {
            sender_ssrc,
            near,
            far,
            sweeps_left: if near || far { KEYFRAME_SWEEPS } else { 0 },
        }
    }

    /// Ask the far party once more, after the first request went unanswered: `accepted` is whether
    /// its video section accepted Picture Loss Indication. Keeps the request already pending for the
    /// near party, and the call's engine SSRC.
    pub(super) fn ask_far_again(&mut self, accepted: bool) {
        if !accepted {
            return;
        }
        if self.sender_ssrc == 0 {
            self.sender_ssrc = random_ssrc();
        }
        self.far = true;
        self.sweeps_left = KEYFRAME_SWEEPS;
    }

    fn pending(&self) -> bool {
        self.sweeps_left > 0 && (self.near || self.far)
    }
}

/// What a caller's video stream gets from `answer_local`.
#[derive(Debug)]
pub(super) enum LocalVideo {
    /// No video is asked for or offered: the stream, if any, is answered with port 0.
    Absent,
    /// The stream is declined, with the reason the controller is told.
    Declined(String),
    /// The stream is answered on the engine's own endpoints.
    Anchor(Box<VideoStream>),
}

/// Decide what `answer_local` does with the caller's video stream.
///
/// # Errors
/// The caller is not a plain RTP one while video is asked for: SRTP, DTLS, ICE and a WebSocket
/// takeover each carry the leg in a way the two-party video relay cannot take over once the answer
/// is out, and relaying the picture in the clear or to an unvalidated address is never an option.
pub(super) fn local_video_decision(
    offer: &str,
    profile: &ProfileFlags,
    plain_caller: bool,
) -> Result<LocalVideo, String> {
    if profile.video_relay != VideoRelay::Anchor {
        return Ok(LocalVideo::Absent);
    }
    let Some(stream) = sdp::parse_video_stream(offer) else {
        return Ok(LocalVideo::Absent);
    };
    if !plain_caller || profile.ws_uri.is_some() {
        return Err(
            "answer_local: video-needs-a-plain-caller: video_relay anchor on a locally answered \
             call needs a plain RTP caller (no SRTP, DTLS-SRTP, ICE or ws_uri takeover): the answer \
             to the caller's video cannot change once sent, and the video would otherwise be \
             relayed unkeyed or to an unvalidated address"
                .to_string(),
        );
    }
    if !stream.is_plain() {
        return Ok(LocalVideo::Declined(format!(
            "video transport {} is not carried on a locally answered call: plain RTP only",
            stream.transport
        )));
    }
    Ok(LocalVideo::Anchor(Box::new(stream)))
}

/// Why the far party's answer cannot carry the video stream the caller was answered, or `None` when
/// it can (or answers no live video, which is a decline and not a fault).
///
/// The caller was answered exactly one format, the first it offered (RFC 3264 §6.1 lets an answerer
/// select a subset), and the far party was offered only it, so the answer must carry that payload
/// type and no other: the relay forwards each payload type as it arrives (RFC 3550 §5.1), and a
/// second format the far party accepted would reach the caller as something it was never told it
/// may receive. The payload type must keep its meaning (RFC 3551 §3), and its format parameters must
/// let each party decode the other ([`sdp::video::relay_fmtp_problem`]). The stream is declined alone,
/// and the audio stays.
pub(super) fn far_video_answer_problem(offer: &str, answer: &str) -> Option<String> {
    let answered = sdp::parse_video_stream(answer)?;
    let offered = sdp::parse_video_stream(offer)?;
    let chosen = sdp::first_video_format(offer)?;
    if let Some(other) = answered
        .payload_types
        .iter()
        .find(|payload_type| **payload_type != chosen)
    {
        return Some(format!(
            "the far party answered video payload type {other}, but only {chosen} was offered \
             (RFC 3264 §6.1)"
        ));
    }
    if !answered.payload_types.contains(&chosen) {
        return Some(format!(
            "the far party answered no video payload type, but {chosen} was offered (RFC 3264 §6.1)"
        ));
    }
    let meaning = |rtpmaps: &[(u8, String)]| {
        rtpmaps
            .iter()
            .find(|(number, _)| *number == chosen)
            .map(|(_, encoding)| encoding.clone())
    };
    let (asked, chosen_encoding) = (meaning(&offered.rtpmaps), meaning(&answered.rtpmaps));
    if let (Some(asked), Some(chosen_encoding)) = (&asked, &chosen_encoding) {
        if asked != chosen_encoding {
            return Some(format!(
                "the far party answered video payload type {chosen} as {chosen_encoding}, but the \
                 caller was answered {asked}: a relay would forward a payload type the caller \
                 never agreed (RFC 3551 §3)"
            ));
        }
    }
    let parameters = |stream: &VideoStream| {
        stream
            .fmtps
            .iter()
            .find(|(number, _)| *number == chosen)
            .map(|(_, parameters)| parameters.clone())
            .unwrap_or_default()
    };
    let encoding = asked.as_deref().unwrap_or_default();
    let name = encoding.split('/').next().unwrap_or_default();
    sdp::video::relay_fmtp_problem(name, &parameters(&offered), &parameters(&answered))
}

/// The complement of RFC 4585 §3.1 compound rules: a report, the source's CNAME (RFC 3550 §6.1: every
/// compound carries one), and the Picture Loss Indication, whatever RTCP profile was negotiated.
/// Returns the bytes and their length, or `None` when they do not fit.
pub(super) fn keyframe_compound(
    sender_ssrc: u32,
    media_ssrc: u32,
) -> Option<([u8; KEYFRAME_COMPOUND_CAPACITY], usize)> {
    let mut buffer = [0u8; KEYFRAME_COMPOUND_CAPACITY];
    let cname = format!("engine-{sender_ssrc:08x}");
    let mut length = rtcp::write_empty_receiver_report(sender_ssrc, &mut buffer)?;
    length += rtcp::write_sdes_cname(sender_ssrc, &cname, &mut buffer[length..])?;
    length += rtcp::write_pli(sender_ssrc, media_ssrc, &mut buffer[length..])?;
    Some((buffer, length))
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Bind the near video endpoints a locally answered call answers its caller's video on, on
    /// `bind`'s interface. RTCP is muxed when the caller offered it so (RFC 5761 §5.1.1: the answer
    /// confirms the offerer's choice).
    pub(super) async fn alloc_local_video(
        &self,
        stream: &VideoStream,
        bind: IpAddr,
    ) -> Result<VideoLeg, String> {
        self.alloc_video_endpoints(AddressFamily::of(bind), bind, stream.rtcp_mux)
            .await
    }

    /// Bind the endpoints `decision` calls for on `bind`'s interface and add them to `endpoints`, so
    /// a later refusal frees them with the rest. Returns the anchored stream, and the reason a
    /// declined one was (a bind failure declines the stream, it never fails the call).
    pub(super) async fn bind_local_video(
        &self,
        decision: LocalVideo,
        bind: IpAddr,
        endpoints: &mut Vec<Endpoint>,
    ) -> (Option<(VideoLeg, VideoStream)>, Option<String>) {
        match decision {
            LocalVideo::Anchor(stream) => match self.alloc_local_video(&stream, bind).await {
                Ok(leg) => {
                    endpoints.push(leg.rtp);
                    endpoints.extend(leg.rtcp);
                    (Some((leg, *stream)), None)
                }
                Err(reason) => (None, Some(format!("video endpoints: {reason}"))),
            },
            LocalVideo::Declined(reason) => (None, Some(reason)),
            LocalVideo::Absent => (None, None),
        }
    }

    /// [`Self::install_local_video`] for the stream [`Self::bind_local_video`] anchored, if any; a
    /// call that cannot park it is torn down with the reason.
    pub(super) async fn install_anchored_video(
        &self,
        call_id: &str,
        anchored: &Option<(VideoLeg, VideoStream)>,
    ) -> Result<(), Box<CmdResult>> {
        let Some((leg, stream)) = anchored else {
            return Ok(());
        };
        if let Err(reason) = self.install_local_video(call_id, *leg, stream) {
            self.teardown_call(call_id).await;
            return Err(Box::new(super::error_result(
                "answer_local: video",
                &reason,
            )));
        }
        Ok(())
    }

    /// Record the video a locally answered call anchored for its caller and drop everything it
    /// receives until a far party answers.
    ///
    /// # Errors
    /// The datapath refused to install a drop on an endpoint: the call must not stand with a video
    /// port that forwards by default.
    pub(super) fn install_local_video(
        &self,
        call_id: &str,
        mut video: VideoLeg,
        stream: &VideoStream,
    ) -> Result<(), String> {
        video.remote_rtp = Some(stream.remote_rtp);
        video.remote_rtcp = Some(stream.remote_rtcp);
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return Err("the call is gone".to_string());
        };
        call.near.video = Some(video);
        call.video.mode = VideoRelay::Anchor;
        call.video.near_direction = stream.direction;
        call.video.near_picture_loss = stream.picture_loss;
        call.video.near_ssrc = stream.ssrc;
        drop(call);
        for endpoint in video.endpoint_ids() {
            self.endpoint_calls.insert(endpoint, call_id.to_string());
        }
        self.park_video(call_id)
    }

    /// Install a drop on every video endpoint of the call and record them as its video flows: before
    /// a far party answers, while the far leg is gone, and while a controller resumes the local
    /// pipeline, no video is relayed.
    ///
    /// # Errors
    /// The datapath refused a drop; the endpoints parked before it stay parked.
    pub(super) fn park_video(&self, call_id: &str) -> Result<(), String> {
        let endpoints: Vec<_> = self
            .calls
            .get(call_id)
            .map(|call| {
                call.near
                    .video
                    .iter()
                    .chain(call.far.as_ref().and_then(|far| far.video.as_ref()))
                    .flat_map(VideoLeg::endpoint_ids)
                    .collect()
            })
            .unwrap_or_default();
        let far_endpoints: Vec<_> = self
            .calls
            .get(call_id)
            .and_then(|call| call.far.as_ref().and_then(|far| far.video))
            .map(|video| video.endpoint_ids().collect())
            .unwrap_or_default();
        let mut flows = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            self.datapath
                .install_flow(endpoint, FlowAction::Drop)
                .map_err(|error| format!("park video endpoint: {error}"))?;
            flows.push((endpoint, FlowAction::Drop));
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.flows = flows;
            call.video.bridged.clear();
        }
        // Whatever armed injector carried the far video is cancelled with it: its flow leaves the
        // bridge and no parameter set is sent to a far party that is gone or not answering.
        let armed = self
            .calls
            .get(call_id)
            .is_some_and(|call| call.video.injector.is_some());
        if armed {
            self.disarm_video_injector(call_id);
            self.bridge.deregister(far_endpoints);
        }
        Ok(())
    }

    /// Free the video that was declined while the caller's frozen answer still holds its own
    /// endpoints: with no far party settled yet only the far leg's endpoints go, and the caller's
    /// stay, dropping, so its answered port never lands on another call (RFC 3264 §8). Everything
    /// else frees the call's video whole.
    pub(super) async fn release_declined_video(&self, call_id: &str) {
        let keeps_near = self
            .calls
            .get(call_id)
            .is_some_and(|call| call.local_answer.is_some() && call.near.video.is_some());
        if !keeps_near {
            self.free_call_video(call_id).await;
            return;
        }
        let mut freed = Vec::new();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(video) = call.far.as_mut().and_then(|far| far.video.take()) {
                freed.extend(video.endpoint_ids());
            }
            call.video.keys = super::call_video_secure::VideoKeys::default();
            call.video.far_direction = sdp::MediaDirection::default();
            call.video.far_picture_loss = false;
            call.video.far_ssrc = None;
            call.video.keyframe = KeyframeRequests::default();
        }
        self.drop_dtls_video(call_id);
        self.bridge.deregister(freed.iter().copied());
        for endpoint in freed {
            self.endpoint_calls.remove(&endpoint);
            self.awaiting_media.remove(&endpoint);
            self.release_endpoint(endpoint).await;
        }
        if let Err(reason) = self.park_video(call_id) {
            tracing::error!(target: "siphon_rtp::media", %call_id, %reason, "could not park the caller's video after the far video was declined");
        }
    }

    /// Arm the one keyframe request each sending party that accepts PLI gets when the relay goes
    /// live: only on a call grown from a local answer, whose caller was handed video it has not
    /// been sent a picture on yet. Ordinary two-party calls ask for nothing.
    pub(super) fn arm_keyframe_requests(
        &self,
        call_id: &str,
        near_to_far: bool,
        far_to_near: bool,
    ) {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return;
        };
        if call.local_answer.is_none() {
            return;
        }
        let (near, far) = (
            near_to_far && call.video.near_picture_loss,
            far_to_near && call.video.far_picture_loss,
        );
        call.video.keyframe = KeyframeRequests::new(random_ssrc(), near, far);
    }

    /// Send the keyframe requests that are due: each pending party is sent one Picture Loss
    /// Indication (RFC 4585 §6.3.1) about the stream it sends, from the engine's video RTCP endpoint
    /// for that party to where its video is sent. The media SSRC is the one the relay latched from the
    /// party's own packets (`Datapath::latched_ssrc`), so nothing is sent about a stream not seen yet:
    /// the request waits for a later sweep, and is dropped after thirty of them. Driven by
    /// the daemon's once-a-second sweep. A backend that keeps no per-endpoint SSRC (the XDP kernel
    /// latch) never names one, so it sends none.
    pub async fn request_video_keyframes(&self) {
        let mut due: Vec<(
            Endpoint,
            SocketAddr,
            [u8; KEYFRAME_COMPOUND_CAPACITY],
            usize,
        )> = Vec::new();
        for mut entry in self.calls.iter_mut() {
            let call = entry.value_mut();
            if !call.video.keyframe.pending() {
                continue;
            }
            let requests = &mut call.video.keyframe;
            requests.sweeps_left -= 1;
            let sender_ssrc = requests.sender_ssrc;
            let (near_pending, far_pending) = (requests.near, requests.far);
            let (near_declared, far_declared) = (call.video.near_ssrc, call.video.far_ssrc);
            let far_video = call.far.as_ref().and_then(|far| far.video);
            let flows = call.video.flows.clone();
            let mut sent = [false; 2];
            for (party, pending, video) in [
                (Party::Near, near_pending, call.near.video),
                (Party::Far, far_pending, far_video),
            ] {
                let Some(video) = video.filter(|_| pending) else {
                    continue;
                };
                // The SSRC the party declared (RFC 5576 §4.1), else the one the relay latched.
                let declared = match party {
                    Party::Near => near_declared,
                    Party::Far => far_declared,
                };
                // A far endpoint carried by the first-IDR injector is a bridge flow, whose own latch
                // learned the stream the datapath's never sees.
                let Some(media_ssrc) = declared
                    .or_else(|| self.datapath.latched_ssrc(video.rtp.id))
                    .or_else(|| self.bridge.latched_ssrc(video.rtp.id))
                else {
                    continue;
                };
                // Where the relay sends this party's video: the rule that forwards out of its
                // feedback endpoint, kept current by the latch sweep.
                let feedback = video.rtcp.unwrap_or(video.rtp);
                let Some(destination) = flows.iter().find_map(|(_, action)| match action {
                    FlowAction::Forward(rule) if rule.out_endpoint == feedback.id => rule.out_dst,
                    _ => None,
                }) else {
                    continue;
                };
                let Some((compound, length)) = keyframe_compound(sender_ssrc, media_ssrc) else {
                    continue;
                };
                due.push((feedback, destination, compound, length));
                sent[usize::from(party == Party::Far)] = true;
            }
            let requests = &mut call.video.keyframe;
            requests.near &= !sent[0];
            requests.far &= !sent[1];
        }
        for (endpoint, destination, compound, length) in due {
            match self
                .datapath
                .send(endpoint.id, destination, &compound[..length])
                .await
            {
                Ok(_) => tracing::debug!(
                    target: "siphon_rtp::media",
                    endpoint = ?endpoint.id,
                    %destination,
                    "video keyframe requested (PLI)"
                ),
                Err(error) => tracing::warn!(
                    target: "siphon_rtp::media",
                    endpoint = ?endpoint.id,
                    %destination,
                    %error,
                    "could not send a video keyframe request"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor_profile() -> ProfileFlags {
        ProfileFlags {
            video_relay: VideoRelay::Anchor,
            ..ProfileFlags::default()
        }
    }

    const OFFER: &str = concat!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n",
        "m=audio 4000 RTP/AVP 0\r\n",
        "m=video 4002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
    );

    #[test]
    fn the_keyframe_compound_is_a_report_a_cname_and_a_pli_by_rfc_4585() {
        // RFC 3550 §6.4.2 empty RR, §6.5.1 CNAME chunk, RFC 4585 §6.1 / §6.3.1 PLI (PT 206, FMT 1,
        // length 2 words, sender SSRC then media SSRC, no FCI), each word written out by hand.
        let (bytes, length) = keyframe_compound(0x0102_0304, 0x0A0B_0C0D).expect("fits");
        let mut expected = vec![0x80, 201, 0, 1, 0x01, 0x02, 0x03, 0x04];
        // SDES: V=2 SC=1 PT=202, 6 words after the header, SSRC, CNAME item "engine-01020304".
        expected.extend_from_slice(&[0x81, 202, 0, 6, 0x01, 0x02, 0x03, 0x04, 1, 15]);
        expected.extend_from_slice(b"engine-01020304");
        expected.extend_from_slice(&[0, 0, 0]);
        expected.extend_from_slice(&[
            0x81, 206, 0, 2, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x0B, 0x0C, 0x0D,
        ]);
        assert_eq!(&bytes[..length], &expected[..]);
        assert_eq!(length % 4, 0, "whole 32-bit words (RFC 3550 §6.4.1)");
    }

    #[test]
    fn a_plain_caller_with_video_is_anchored_and_everything_else_is_decided_loudly() {
        assert!(matches!(
            local_video_decision(OFFER, &anchor_profile(), true),
            Ok(LocalVideo::Anchor(_))
        ));
        assert!(matches!(
            local_video_decision(OFFER, &ProfileFlags::default(), true),
            Ok(LocalVideo::Absent)
        ));
        let no_video = OFFER.split("m=video").next().unwrap_or(OFFER);
        assert!(matches!(
            local_video_decision(no_video, &anchor_profile(), false),
            Ok(LocalVideo::Absent)
        ));
        let refused = local_video_decision(OFFER, &anchor_profile(), false);
        assert!(
            matches!(&refused, Err(reason) if reason.contains("plain RTP caller")),
            "{refused:?}"
        );
        let secure_video = OFFER.replace("RTP/AVP 96", "RTP/SAVP 96");
        assert!(matches!(
            local_video_decision(&secure_video, &anchor_profile(), true),
            Ok(LocalVideo::Declined(reason)) if reason.contains("plain RTP only")
        ));
    }

    #[test]
    fn requests_are_armed_for_the_parties_that_send_and_expire() {
        assert_eq!(KeyframeRequests::new(1, false, false).sweeps_left, 0);
        let requests = KeyframeRequests::new(1, true, false);
        assert!(requests.pending() && requests.sweeps_left == KEYFRAME_SWEEPS);
        assert!(!KeyframeRequests::default().pending());
    }

    #[test]
    fn a_far_answer_keeps_the_one_answered_format_or_is_a_problem() {
        let offer =
            format!("{OFFER}a=rtpmap:97 VP8/90000\r\n").replace("RTP/AVP 96", "RTP/AVP 96 97");
        let answer = |line: &str| format!("v=0\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\n{line}");
        assert_eq!(
            far_video_answer_problem(
                &offer,
                &answer("m=video 5000 RTP/AVP 96\r\na=rtpmap:96 h264/90000\r\n")
            ),
            None,
            "the encoding name is case-insensitive (RFC 4566 §6)"
        );
        assert_eq!(
            far_video_answer_problem(&offer, &answer("m=video 0 RTP/AVP 96\r\n")),
            None
        );
        assert_eq!(
            far_video_answer_problem(&offer, &answer("m=audio 5000 RTP/AVP 0\r\n")),
            None
        );
        // Only the first format was offered and answered to the caller: another one, or both, would
        // let the caller send what the far party never accepted.
        let other = far_video_answer_problem(&offer, &answer("m=video 5000 RTP/AVP 97\r\n"));
        assert_eq!(
            other.as_deref(),
            Some("the far party answered video payload type 97, but only 96 was offered (RFC 3264 §6.1)")
        );
        let both = far_video_answer_problem(&offer, &answer("m=video 5000 RTP/AVP 96 97\r\n"));
        assert!(
            matches!(&both, Some(reason) if reason.contains("payload type 97")),
            "{both:?}"
        );
        let renumbered = far_video_answer_problem(
            &offer,
            &answer("m=video 5000 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n"),
        );
        assert!(
            matches!(&renumbered, Some(reason) if reason.contains("as VP8/90000")),
            "{renumbered:?}"
        );
        let lower_level = far_video_answer_problem(
            &offer.replace("a=rtpmap:96 H264/90000\r\n", "a=rtpmap:96 H264/90000\r\na=fmtp:96 profile-level-id=42e01f\r\n"),
            &answer("m=video 5000 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 profile-level-id=42e015\r\n"),
        );
        assert!(
            matches!(&lower_level, Some(reason) if reason.contains("level")),
            "{lower_level:?}"
        );
    }
}
