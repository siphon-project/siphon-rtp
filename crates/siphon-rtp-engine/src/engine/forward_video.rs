//! Video in a translating forwarding room (3GPP TS 24.281 §6.2): the endpoint a seat's `m=video`
//! lands on, and the decision whether a seat's video is carried at all.
//!
//! Video is opaque to the room, so the decision is about format and transport, never about codecs
//! the engine could convert. A seat's video is carried when its offer fits the room
//! ([`sdp::video::choose_video`]: plain RTP/AVP or RTP/AVPF, H264/90000, the room's
//! `packetization-mode` and `profile-level-id`) and the seat is a plain RTP one in a translating
//! room. Otherwise the seat joins audio-only and the result says why (`video_declined`), so a
//! controller never has to parse the answer to find out.
//!
//! SRTP, SDES and DTLS video and preserve-room video are not carried yet: a plain answer to a secure
//! offer would send the seat video it cannot decrypt, and a preserve room forwards SRTP the engine
//! holds no key for (3GPP TS 33.180 §7.5.2 NOTE 3).

use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction, SourceFilter};
use siphon_rtp_proto::{CmdResult, ForwardMedia, ProfileFlags};

use crate::forward::VideoConfig;
use crate::sdp::video::{
    choose_answered_video, choose_video, parse_video, video_offer_section, RoomVideoFormat,
    VideoAnswer, VideoChoice,
};
use crate::sdp::{self, EngineMedia, OwnSsrc};

use super::negotiate::{peer_media_address, random_ssrc};
use super::seat_transport::SeatTransport;
use super::{boxed_error_result, ok_empty, ok_sdp, Engine};

/// Why a video stream is declined when the profile did not ask for video.
const NOT_ENABLED: &str = "video is not enabled (profile.video is absent)";

/// A seat's video, as far as it got.
pub(super) enum VideoSeat {
    /// The offer carries no live video stream.
    Absent,
    /// The offer carries video that the seat does not take, and why.
    Declined(String),
    /// The seat's video endpoint is open.
    Open(Box<OpenVideo>),
}

/// A seat's open video endpoint and what its offer settled.
pub(super) struct OpenVideo {
    pub(super) endpoint: Endpoint,
    pub(super) choice: VideoChoice,
    pub(super) config: VideoConfig,
}

impl VideoSeat {
    pub(super) fn endpoint(&self) -> Option<Endpoint> {
        match self {
            Self::Open(open) => Some(open.endpoint),
            _ => None,
        }
    }

    pub(super) fn declined(&self) -> Option<String> {
        match self {
            Self::Declined(reason) => Some(reason.clone()),
            _ => None,
        }
    }
}

/// What a join decides a seat's video from.
pub(super) struct JoinVideo<'a> {
    pub(super) transport: &'a SeatTransport,
    /// The seat's audio, parsed: how the seat is keyed.
    pub(super) info: &'a sdp::MediaInfo,
    pub(super) offer: &'a str,
    pub(super) profile: &'a ProfileFlags,
    pub(super) media: ForwardMedia,
    /// The format in force: the room's, or the controller's `video.fmtp`.
    pub(super) fixed: Option<&'a RoomVideoFormat>,
    /// The CNAME the answer gives the seat's streams (RFC 7022 §4), which the room writes in the
    /// source description of the keyframe requests it sends the seat.
    pub(super) cname: &'a str,
}

/// What a `forward_offer` decides about the video of the seat it offers.
pub(super) struct VideoOffer<'a> {
    pub(super) room_id: &'a str,
    pub(super) profile: &'a ProfileFlags,
    pub(super) media: ForwardMedia,
    /// The offer is a WebRTC one.
    pub(super) want_webrtc: bool,
    pub(super) family: AddressFamily,
    pub(super) bind: Option<std::net::IpAddr>,
    pub(super) advertised_override: Option<std::net::IpAddr>,
}

/// What a `forward_offer` wrote for video.
pub(super) enum OfferedVideo {
    /// The profile asked for none.
    None,
    /// The profile asked for video and the offer carries none, and why.
    Declined(String),
    /// The video endpoint and the offer section on it.
    Section { endpoint: Endpoint, section: String },
}

/// Check the profile's video settings before anything is allocated.
///
/// # Errors
/// The reason the controller's `video` is refused: a line break in `fmtp`, a zero bandwidth, or an
/// `fmtp` naming a packetization mode the room does not carry.
pub(super) fn validate_video_profile(profile: &ProfileFlags) -> Result<(), String> {
    let Some(video) = &profile.video else {
        return Ok(());
    };
    video.validate().map_err(|error| error.to_string())?;
    if let Some(fmtp) = &video.fmtp {
        RoomVideoFormat::from_fmtp(fmtp)?;
    }
    Ok(())
}

/// Why a seat that reached the room cannot carry video at all, whatever its offer says.
fn refuse_video_seat(
    media: ForwardMedia,
    info: &sdp::MediaInfo,
    transport: &SeatTransport,
) -> Option<&'static str> {
    if media == ForwardMedia::Preserve {
        return Some(
            "video is carried by translate rooms only (preserve-room video is not carried yet)",
        );
    }
    if info.secure
        || info.dtls
        || info.fingerprint.is_some()
        || !info.crypto.is_empty()
        || transport.secure.is_some()
        || transport.dtls_pending()
        || transport.ice_pending
    {
        return Some("the seat's media is SRTP, and secure video is not carried yet");
    }
    None
}

/// The streams a seat's answer carries live, in the order of the offer.
pub(super) fn answered_streams(floor: bool, video: bool) -> Vec<String> {
    let mut streams = vec!["audio".to_string()];
    if video {
        streams.push("video".to_string());
    }
    if floor {
        streams.push("floor".to_string());
    }
    streams
}

/// A success carrying what a forwarding seat's answer settled: the SDP (when the verb writes one),
/// the streams answered live, and why the video was declined.
pub(super) fn ok_forward_seat(
    sdp: Option<String>,
    to_tag: Option<String>,
    streams: Vec<String>,
    video_declined: Option<String>,
) -> CmdResult {
    let mut result = match sdp {
        Some(sdp) => ok_sdp(sdp, to_tag),
        None => ok_empty(),
    };
    if let CmdResult::Ok {
        streams: answered,
        video_declined: declined,
        ..
    } = &mut result
    {
        *answered = streams;
        *declined = video_declined;
    }
    result
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Free every endpoint a seat that was not seated holds.
    pub(super) async fn free_seat_endpoints(
        &self,
        audio: Endpoint,
        floor: Option<Endpoint>,
        video: Option<Endpoint>,
    ) {
        for endpoint in std::iter::once(audio).chain(floor).chain(video) {
            self.free(&[endpoint]).await;
        }
    }

    /// The video format in force for a seat joining `room_id`: the room's once a seat with video
    /// fixed it, else the controller's `video.fmtp`, else none (the seat's own offer fixes it).
    ///
    /// # Errors
    /// The reason the controller's `video.fmtp` is refused.
    pub(super) fn video_format_in_force(
        &self,
        room_id: &str,
        profile: &ProfileFlags,
    ) -> Result<Option<RoomVideoFormat>, String> {
        if let Some(format) = self.conference.forward().room_video_format(room_id) {
            return Ok(Some(format));
        }
        profile
            .video
            .as_ref()
            .and_then(|video| video.fmtp.as_deref())
            .map(RoomVideoFormat::from_fmtp)
            .transpose()
    }

    /// Decide whether a joining seat's `m=video` is carried and, when it is, open its endpoint: its
    /// own redirected socket, gated by the signalled video address (or the `received_from` hint),
    /// with the SSRC-consistent latch the room runs on it (docs/security-and-nat.md §4 layer 5c-ii).
    /// A video stream in another address family than the seat's audio is declined rather than bound
    /// on a second interface.
    pub(super) async fn open_video_endpoint(
        &self,
        join: JoinVideo<'_>,
    ) -> Result<VideoSeat, Box<CmdResult>> {
        let Some(offered) = parse_video(join.offer) else {
            return Ok(VideoSeat::Absent);
        };
        if join.profile.video.is_none() {
            return Ok(VideoSeat::Declined(NOT_ENABLED.to_string()));
        }
        if let Some(reason) = refuse_video_seat(join.media, join.info, join.transport) {
            return Ok(VideoSeat::Declined(reason.to_string()));
        }
        let choice = match choose_video(&offered, join.fixed) {
            Ok(choice) => choice,
            Err(reason) => return Ok(VideoSeat::Declined(reason)),
        };
        if AddressFamily::of(choice.remote.ip()) != join.transport.family {
            return Ok(VideoSeat::Declined(
                "the video stream is in another address family than the seat's audio".to_string(),
            ));
        }
        let endpoint = match self
            .alloc_endpoints(1, join.transport.family, join.transport.bind)
            .await
        {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return Err(boxed_error_result("forward_join: video stream", &reason)),
        };
        if let Err(error) = self
            .datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
        {
            self.free(&[endpoint]).await;
            return Err(boxed_error_result(
                "forward_join: install video redirect",
                &error,
            ));
        }
        let destination = peer_media_address(choice.remote, join.profile.received_from);
        let config = video_config(
            endpoint,
            &choice,
            destination,
            video_source_filter(join.profile, destination),
            join.cname.to_string(),
        );
        Ok(VideoSeat::Open(Box::new(OpenVideo {
            endpoint,
            choice,
            config,
        })))
    }

    /// Anchor an answer's video section on the seat's video endpoint: the engine's own port and
    /// address, the room's format, the complement direction and the SSRC the room sends the seat's
    /// video under. A seat without open video leaves the answer as it is.
    pub(super) fn anchor_seat_video(
        &self,
        answer: String,
        video: &VideoSeat,
        transport: &SeatTransport,
        profile: &ProfileFlags,
        audio: &OwnSsrc,
    ) -> String {
        let VideoSeat::Open(open) = video else {
            return answer;
        };
        sdp::video::anchor_video(
            &answer,
            &VideoAnswer {
                engine: EngineMedia {
                    rtp: open.endpoint.local_addr,
                    rtcp: None,
                    advertised_ip: transport.advertised,
                },
                choice: &open.choice,
                bandwidth_kbps: profile
                    .video
                    .as_ref()
                    .and_then(|video| video.bandwidth_kbps),
                // One CNAME ties a seat's streams together (RFC 7022 §4).
                own: &OwnSsrc {
                    ssrc: open.config.egress_ssrc,
                    cname: audio.cname.clone(),
                },
            },
        )
    }

    /// Allocate the video endpoint a `forward_offer` offers, and write its offer section; or say
    /// why no video is offered.
    ///
    /// # Errors
    /// The datapath has no endpoint to give.
    pub(super) async fn offer_video(
        &self,
        request: VideoOffer<'_>,
    ) -> Result<OfferedVideo, String> {
        let Some(video) = &request.profile.video else {
            return Ok(OfferedVideo::None);
        };
        if request.media == ForwardMedia::Preserve {
            return Ok(OfferedVideo::Declined(
                "video is carried by translate rooms only (preserve-room video is not carried yet)"
                    .to_string(),
            ));
        }
        if request.want_webrtc {
            return Ok(OfferedVideo::Declined(
                "browser video is not carried yet (a WebRTC seat has no video stream)".to_string(),
            ));
        }
        let endpoint = match self.alloc_endpoints(1, request.family, request.bind).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return Err(reason.to_string()),
        };
        // The room's format when it has one, else the controller's, else the member's answer fixes it.
        let fmtp = match self.conference.forward().room_video_format(request.room_id) {
            Some(format) => format.fmtp,
            None => video.fmtp.clone(),
        };
        let advertised = request
            .advertised_override
            .unwrap_or_else(|| endpoint.local_addr.ip());
        let section = video_offer_section(
            endpoint.local_addr.port(),
            advertised,
            fmtp.as_deref(),
            video.bandwidth_kbps,
        );
        Ok(OfferedVideo::Section { endpoint, section })
    }

    /// Read a member's answer to an offered video stream: its video config when it accepted a stream
    /// that fits the room, else the reason it did not.
    pub(super) fn negotiate_video(
        &self,
        room_id: &str,
        answer: &str,
        received_from: Option<std::net::IpAddr>,
        profile: &ProfileFlags,
        endpoint: Endpoint,
        gate: impl Fn(std::net::SocketAddr) -> SourceFilter,
    ) -> Result<VideoConfig, String> {
        let offered = parse_video(answer)
            .ok_or_else(|| "the answer declined the video stream (port 0)".to_string())?;
        let fixed = self.video_format_in_force(room_id, profile)?;
        let choice = choose_answered_video(&offered, fixed.as_ref())?;
        if AddressFamily::of(choice.remote.ip()) != AddressFamily::of(endpoint.local_addr.ip()) {
            return Err(
                "the video stream is in another address family than the seat's audio".to_string(),
            );
        }
        let destination = peer_media_address(choice.remote, received_from);
        // The offer carried no CNAME for the seat's streams: the room gives them one of its own.
        let cname = sdp::OwnSsrc::with_random_cname(0).cname;
        Ok(video_config(
            endpoint,
            &choice,
            destination,
            gate(destination),
            cname,
        ))
    }
}

/// The video gate of a plain seat: the signalled address only, unless the profile is `symmetric`
/// (docs/security-and-nat.md §4 layer 2).
fn video_source_filter(profile: &ProfileFlags, destination: std::net::SocketAddr) -> SourceFilter {
    if profile.flags.iter().any(|flag| flag == "symmetric") {
        SourceFilter::Any
    } else {
        SourceFilter::Exact(destination.ip())
    }
}

/// The room's config for a seat's video: its own payload type, direction and egress stream
/// (RFC 3550 §5.1: the SSRC and the initial sequence number and timestamp are random).
fn video_config(
    endpoint: Endpoint,
    choice: &VideoChoice,
    destination: std::net::SocketAddr,
    accepted_source: SourceFilter,
    cname: String,
) -> VideoConfig {
    VideoConfig {
        endpoint: endpoint.id,
        destination,
        accepted_source,
        payload_type: choice.payload_type,
        direction: choice.direction,
        egress_ssrc: random_ssrc(),
        initial_sequence: random_ssrc() as u16,
        initial_timestamp: random_ssrc(),
        format: choice.format.clone(),
        feedback: choice.feedback,
        cname,
    }
}
