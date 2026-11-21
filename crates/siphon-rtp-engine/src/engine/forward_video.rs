//! Video in a forwarding room (3GPP TS 24.281 §6.2): the endpoint a seat's `m=video` lands on, and the
//! decision whether a seat's video is carried at all.
//!
//! Video is opaque to the room, so the decision is about format and transport, never about codecs
//! the engine could convert. A seat's video is carried when its offer fits the room
//! ([`sdp::video::choose_video`]: plain RTP/AVP or RTP/AVPF, H264/90000, the room's
//! `packetization-mode` and `profile-level-id`) and the seat is a plain RTP one in a translating
//! room (a preserve room's seat may be SRTP, below). Otherwise the seat joins audio-only and the result says why (`video_declined`), so a
//! controller never has to parse the answer to find out.
//!
//! A preserve room carries video too ([`sdp::video::choose_preserved_video`]): `RTP/SAVP[F]` or plain,
//! on an endpoint of its own, with no key of the engine's (3GPP TS 33.180 §7.5.2: the UEs key it
//! between themselves and the room hands the SRTP on unchanged), and in the one payload type the
//! room's talker sends (RFC 3550 §7.1).
//!
//! A browser seat (`UDP/TLS/RTP/SAVPF`) carries its video bundled with its audio on the seat's one
//! ICE/DTLS transport (RFC 8843): the video has no endpoint of its own, and what the seat sends and
//! is sent travels on the seat's endpoint under the seat's DTLS-SRTP key. A video section on a
//! transport of its own is declined, and so is SDES-SRTP video: a plain answer to a secure offer
//! would send the seat video it cannot decrypt.

use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction, SourceFilter};
use siphon_rtp_proto::{CmdResult, ForwardMedia, ProfileFlags};

use crate::forward::VideoConfig;
use crate::sdp::video::{
    choose_answered_preserved_video, choose_answered_video, choose_preserved_video, choose_video,
    parse_video, video_offer_section, RoomVideoFormat, VideoAnswer, VideoChoice,
    OFFER_PAYLOAD_TYPE, WEBRTC_VIDEO_TRANSPORT,
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
    /// The video's own endpoint; `None` for a bundled video, which rides the seat's audio endpoint.
    pub(super) endpoint: Option<Endpoint>,
    pub(super) choice: VideoChoice,
    pub(super) config: VideoConfig,
}

impl VideoSeat {
    pub(super) fn endpoint(&self) -> Option<Endpoint> {
        match self {
            Self::Open(open) => open.endpoint,
            _ => None,
        }
    }

    /// The seat's video is carried, on an endpoint of its own or bundled with the audio.
    pub(super) fn is_open(&self) -> bool {
        matches!(self, Self::Open(_))
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
    pub(super) room_id: &'a str,
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
    /// The video endpoint and the offer section on it: `RTP/AVPF`, or `RTP/SAVPF` with no key of the
    /// engine's in a preserve room that signals `key_mgmt`.
    Section {
        endpoint: Endpoint,
        section: String,
        /// The payload type the section offers, which the member's answer must keep (RFC 3264 §6.1).
        payload_type: u8,
    },
    /// A WebRTC offer's video: a section of the audio's own transport (RFC 8843), written with the
    /// rest of the offer, so there is no endpoint to allocate.
    Bundled {
        fmtp: Option<String>,
        bandwidth_kbps: Option<u32>,
    },
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
///
/// A WebRTC seat (DTLS-SRTP audio, whose handshake and ICE run on the seat's endpoint) carries video
/// bundled with its audio (RFC 8843), so it is not refused here; the offer's video section must then
/// be a bundled `UDP/TLS/RTP/SAVPF` one ([`choose_video`] says so). Every other secure seat is.
///
/// A seat of a preserve room is never refused here: the engine holds no key for its SRTP, which the
/// UEs agree between themselves (3GPP TS 33.180 §7.5.2), and a seat the engine would have to key
/// (`a=crypto`, DTLS-SRTP) was refused at the join (`refuse_seat_keying`).
fn refuse_video_seat(
    media: ForwardMedia,
    info: &sdp::MediaInfo,
    transport: &SeatTransport,
) -> Option<&'static str> {
    if media == ForwardMedia::Preserve {
        return None;
    }
    if is_webrtc_seat(info, transport) {
        return None;
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

/// Whether the seat is a browser: DTLS-SRTP audio keyed by a handshake on its endpoint.
fn is_webrtc_seat(info: &sdp::MediaInfo, transport: &SeatTransport) -> bool {
    info.dtls && info.crypto.is_empty() && transport.dtls_pending() && transport.secure.is_none()
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
        let chosen = match join.media {
            ForwardMedia::Preserve => choose_preserved_video(&offered, join.fixed),
            ForwardMedia::Translate => choose_video(&offered, join.fixed),
        };
        let choice = match chosen {
            Ok(choice) => choice,
            Err(reason) => return Ok(VideoSeat::Declined(reason)),
        };
        if join.media == ForwardMedia::Preserve {
            if let Err(reason) = self.check_room_video_payload_type(join.room_id, &choice) {
                return Ok(VideoSeat::Declined(reason));
            }
        }
        // RFC 3264 §6: the answer keeps the offer's transport, so a browser seat's video must be a
        // browser's, and a plain seat's must not be.
        let webrtc_seat = is_webrtc_seat(join.info, join.transport);
        let webrtc_video = choice
            .transport
            .eq_ignore_ascii_case(WEBRTC_VIDEO_TRANSPORT);
        if webrtc_seat != webrtc_video {
            return Ok(VideoSeat::Declined(
                if webrtc_seat {
                    "the seat's audio is DTLS-SRTP, so its video must be UDP/TLS/RTP/SAVPF bundled with it (RFC 8843); plain video on a secure seat is not carried"
                } else {
                    "UDP/TLS/RTP/SAVPF video needs the seat's audio keyed by DTLS-SRTP on the same transport (RFC 8843)"
                }
                .to_string(),
            ));
        }
        if webrtc_seat {
            // RFC 8843 §8: one transport. The video has no endpoint, latch or key of its own: it
            // arrives on the seat's endpoint after the seat's gate and SRTP, and leaves under the
            // seat's key to the seat's latched destination.
            let config =
                bundled_video_config(join.transport.endpoint, &choice, join.cname.to_string());
            return Ok(VideoSeat::Open(Box::new(OpenVideo {
                endpoint: None,
                choice,
                config,
            })));
        }
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
            endpoint: Some(endpoint),
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
                    // A bundled video is anchored on the audio's transport, which `anchor_video`
                    // reads from the answer.
                    rtp: open
                        .endpoint
                        .map_or(transport.endpoint.local_addr, |own| own.local_addr),
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
        // The room's format when it has one, else the controller's, else the member's answer fixes it.
        let fmtp = match self.conference.forward().room_video_format(request.room_id) {
            Some(format) => format.fmtp,
            None => video.fmtp.clone(),
        };
        if request.want_webrtc {
            return Ok(OfferedVideo::Bundled {
                fmtp,
                bandwidth_kbps: video.bandwidth_kbps,
            });
        }
        let endpoint = match self.alloc_endpoints(1, request.family, request.bind).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return Err(reason.to_string()),
        };
        let advertised = request
            .advertised_override
            .unwrap_or_else(|| endpoint.local_addr.ip());
        // A preserve room forwards the talker's packets unchanged (RFC 3550 §7.1), so the member must
        // read the number the talker sends; and a room signalling end-to-end SRTP (`key_mgmt`,
        // RFC 4567) offers `RTP/SAVPF` with no key of the engine's, as it does for the audio.
        let preserve = request.media == ForwardMedia::Preserve;
        let payload_type = preserve
            .then(|| {
                self.conference
                    .forward()
                    .room_video_payload_type(request.room_id)
            })
            .flatten()
            .unwrap_or(OFFER_PAYLOAD_TYPE);
        let section = video_offer_section(
            endpoint.local_addr.port(),
            advertised,
            fmtp.as_deref(),
            video.bandwidth_kbps,
            payload_type,
            preserve && request.profile.key_mgmt.is_some(),
        );
        Ok(OfferedVideo::Section {
            endpoint,
            section,
            payload_type,
        })
    }

    /// A preserve room forwards the talker's packets unchanged (RFC 3550 §7.1), so a seat's video
    /// must be in the payload type the room's first video seat fixed.
    ///
    /// # Errors
    /// The reason, when the seat's number differs.
    fn check_room_video_payload_type(
        &self,
        room_id: &str,
        choice: &VideoChoice,
    ) -> Result<(), String> {
        match self.conference.forward().room_video_payload_type(room_id) {
            Some(room) if room != choice.payload_type => Err(format!(
                "video payload type {} where the preserve room forwards payload type {room} unchanged",
                choice.payload_type
            )),
            _ => Ok(()),
        }
    }

    /// Read a browser member's answer to the bundled video section of a WebRTC `forward_offer`: the
    /// seat's video config when it kept the section, bundled, in a format that fits the room, else
    /// the reason it did not.
    pub(super) fn negotiate_bundled_video(
        &self,
        room_id: &str,
        answer: &str,
        profile: &ProfileFlags,
        endpoint: Endpoint,
    ) -> Result<VideoConfig, String> {
        let offered = parse_video(answer)
            .ok_or_else(|| "the answer declined the video stream (port 0)".to_string())?;
        let fixed = self.video_format_in_force(room_id, profile)?;
        let choice = choose_answered_video(&offered, fixed.as_ref())?;
        if !choice
            .transport
            .eq_ignore_ascii_case(WEBRTC_VIDEO_TRANSPORT)
        {
            return Err(format!(
                "the answer's video is {}, but the offer's was {WEBRTC_VIDEO_TRANSPORT} (RFC 3264 §6)",
                choice.transport
            ));
        }
        // The offer carried no CNAME for the seat's streams: the room gives them one of its own.
        let cname = sdp::OwnSsrc::with_random_cname(0).cname;
        Ok(bundled_video_config(endpoint, &choice, cname))
    }

    /// Read a member's answer to an offered video stream: its video config when it accepted a stream
    /// that fits the room, else the reason it did not.
    #[allow(
        clippy::too_many_arguments,
        reason = "the answer and its context: the room, the media mode and the endpoint offered"
    )]
    pub(super) fn negotiate_video(
        &self,
        room_id: &str,
        media: ForwardMedia,
        offered_payload_type: u8,
        answer: &str,
        received_from: Option<std::net::IpAddr>,
        profile: &ProfileFlags,
        endpoint: Endpoint,
        gate: impl Fn(std::net::SocketAddr) -> SourceFilter,
    ) -> Result<VideoConfig, String> {
        let offered = parse_video(answer)
            .ok_or_else(|| "the answer declined the video stream (port 0)".to_string())?;
        let fixed = self.video_format_in_force(room_id, profile)?;
        let choice = if media == ForwardMedia::Preserve {
            let choice = choose_answered_preserved_video(&offered, fixed.as_ref())?;
            // RFC 3264 §6: the answer keeps the offer's transport.
            let expected = if profile.key_mgmt.is_some() {
                "RTP/SAVPF"
            } else {
                "RTP/AVPF"
            };
            if !choice.transport.eq_ignore_ascii_case(expected) {
                return Err(format!(
                    "the answer's video is {}, but the offer's was {expected} (RFC 3264 §6)",
                    choice.transport
                ));
            }
            choice
        } else {
            choose_answered_video(&offered, fixed.as_ref())?
        };
        // The answer is to the offer that was sent: its number first (RFC 3264 §6.1), then the room as
        // it stands now, which a join since the offer may have changed.
        if choice.payload_type != offered_payload_type {
            return Err(format!(
                "the answer's video payload type {} is not the offered {offered_payload_type} (RFC 3264 §6.1)",
                choice.payload_type
            ));
        }
        if media == ForwardMedia::Preserve {
            self.check_room_video_payload_type(room_id, &choice)?;
        }
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

/// The room's config for a browser seat's bundled video: the seat's own endpoint, and no destination,
/// source gate or key of its own, because the room uses the seat's (`VideoConfig::bundled`).
fn bundled_video_config(endpoint: Endpoint, choice: &VideoChoice, cname: String) -> VideoConfig {
    let mut config = video_config(
        endpoint,
        choice,
        std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0),
        SourceFilter::Any,
        cname,
    );
    config.bundled = true;
    config
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
        bundled: false,
    }
}
