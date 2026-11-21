//! The video stream of a forwarding seat: `m=video <port> RTP/AVP <pt>` carrying H.264
//! (3GPP TS 24.281 §6.2 puts an `m=video` beside the `m=audio` and the transmission control stream;
//! 3GPP TS 26.281 §4.1.1 makes H.264 the mandatory codec, Constrained High Profile level 3.1 being
//! `profile-level-id=640c1f`).
//!
//! Video is opaque to the engine: the room never transcodes it, so every seat in a room must speak
//! the same H.264 flavour. [`RoomVideoFormat`] is that flavour, and [`choose_video`] decides whether
//! one seat's offer fits it. The format is two parameters of RFC 6184 §8.1, the ones a receiver
//! cannot decode a stream without: `packetization-mode` (the engine carries 0, single NAL unit, and
//! 1, non-interleaved; 2, interleaved, needs reordering a translator does not do) and
//! `profile-level-id`.
//!
//! Kept apart from [`super::rewrite`], which copies an `m=video` section through untouched: this pass
//! re-originates the section on the finished answer, as the control stream module does for the control stream.

mod h264_profile;

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use h264_profile::{max_recv_level, Level, ProfileLevel};

use super::data_channel::{is_shared_transport_line, locate_audio, mid_of};
use super::floor::split_lines;
use super::{addrtype, parse_connection_addr, EngineMedia, MediaDirection, OwnSsrc, CRLF};

/// The RTP clock of video: 90 kHz (RFC 6184 §8.2.1 for H.264, RFC 3551 §5 for video in general).
pub const VIDEO_CLOCK_RATE_HZ: u32 = 90_000;

/// The payload type a `forward_offer` gives its H.264 stream: dynamic (RFC 3551 §6), and outside the
/// range the audio candidates use, so the offer never lists one number in two sections.
pub const OFFER_PAYLOAD_TYPE: u8 = 126;

/// The transport token of a browser's video: DTLS-SRTP with RTCP feedback (RFC 5764 §4.1.2,
/// RFC 8829 §5.2.1). The room carries it only bundled with the seat's audio (RFC 8843).
pub const WEBRTC_VIDEO_TRANSPORT: &str = "UDP/TLS/RTP/SAVPF";

/// The packetization modes the room carries (RFC 6184 §5.2): single NAL unit and non-interleaved.
const CARRIED_MODES: [u8; 2] = [0, 1];

/// The H.264 flavour every seat of a room speaks (RFC 6184 §8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomVideoFormat {
    /// `packetization-mode`: 0 or 1.
    pub packetization_mode: u8,
    /// `profile-level-id`, lower case, as the format fixed it. A format that named none is Baseline
    /// at Level 1, `42000a` (RFC 6184 §8.1), so it compares equal to one that names that value.
    /// `None` only for a controller `video.fmtp` that names none.
    pub profile_level_id: Option<String>,
    /// The parameters of the `a=fmtp` line the room writes: the controller's, verbatim, or when the
    /// first seat fixed the format, just the two parameters above (a seat's `sprop-parameter-sets`
    /// and size limits describe that seat's own stream, and are never handed to another).
    pub fmtp: Option<String>,
}

/// The RTCP feedback (RFC 4585 §4.2) a video stream accepted. The room supports exactly these
/// three, and answers with the intersection of them and what the offer listed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VideoFeedback {
    /// `a=rtcp-fb:<pt> nack`: Generic NACK (RFC 4585 §6.2.1), served from the room's history.
    pub nack: bool,
    /// `a=rtcp-fb:<pt> nack pli`: Picture Loss Indication (RFC 4585 §6.3.1).
    pub pli: bool,
    /// `a=rtcp-fb:<pt> ccm fir`: Full Intra Request (RFC 5104 §4.3.1).
    pub fir: bool,
}

impl VideoFeedback {
    /// Everything the room supports: what a `forward_offer` offers.
    pub const SUPPORTED: Self = Self {
        nack: true,
        pli: true,
        fir: true,
    };

    /// The `a=rtcp-fb` lines for `payload_type`, in the order RFC 4585 §4.2 examples list them.
    fn lines(self, payload_type: u8) -> impl Iterator<Item = String> {
        [
            (self.nack, "nack"),
            (self.pli, "nack pli"),
            (self.fir, "ccm fir"),
        ]
        .into_iter()
        .filter(|(accepted, _)| *accepted)
        .map(move |(_, kind)| format!("a=rtcp-fb:{payload_type} {kind}"))
    }

    /// What the section's `a=rtcp-fb` lines list for `payload_type`, `*` (every payload type of the
    /// section, RFC 4585 §4.2) included. Types the room does not support are ignored.
    fn of_payload(section: &[&str], payload_type: u8) -> Self {
        let mut feedback = Self::default();
        for line in section {
            let Some(rest) = line.strip_prefix("a=rtcp-fb:") else {
                continue;
            };
            let mut words = rest.split_whitespace();
            let Some(target) = words.next() else {
                continue;
            };
            if target != "*" && target.parse::<u8>().ok() != Some(payload_type) {
                continue;
            }
            match (words.next(), words.next()) {
                (Some(kind), None) if kind.eq_ignore_ascii_case("nack") => feedback.nack = true,
                (Some(kind), Some(parameter))
                    if kind.eq_ignore_ascii_case("nack")
                        && parameter.eq_ignore_ascii_case("pli") =>
                {
                    feedback.pli = true;
                }
                (Some(kind), Some(parameter))
                    if kind.eq_ignore_ascii_case("ccm")
                        && parameter.eq_ignore_ascii_case("fir") =>
                {
                    feedback.fir = true;
                }
                _ => {}
            }
        }
        feedback
    }
}

/// One payload type a video section offers, as far as H.264 is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedVideoPayload {
    pub payload_type: u8,
    /// The feedback the section lists for it, supported types only.
    pub feedback: VideoFeedback,
    /// The `a=rtpmap` encoding name and clock, when the section maps the payload type.
    pub encoding: Option<(String, u32)>,
    /// The `a=fmtp` parameters, when it carries any.
    pub fmtp: Option<String>,
}

/// The live video stream an SDP offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoOffer {
    /// Where the peer sends and receives video: its media-level `c=` (else the session `c=`) with the
    /// `m=video` port.
    pub remote: SocketAddr,
    /// The transport token of the `m=` line, which the answer echoes (RFC 3264 §6).
    pub transport: String,
    /// The direction the section declares for itself, else the session's, else `sendrecv`
    /// (RFC 4566 §6).
    pub direction: MediaDirection,
    /// The section carries `a=rtcp-mux` (RFC 5761).
    pub rtcp_mux: bool,
    /// The payload types, in the `m=` line's order.
    pub payloads: Vec<OfferedVideoPayload>,
    /// The section's `a=mid` (RFC 5888 §4), which a BUNDLEd answer echoes.
    pub mid: Option<String>,
    /// The section is in the same `a=group:BUNDLE` as the first live audio section (RFC 8843 §7.2),
    /// so it shares that section's transport.
    pub bundled: bool,
    /// The keying line, when the stream is keyed by the engine: an SDES `a=crypto` (RFC 4568) or a
    /// DTLS `a=fingerprint` (RFC 5763), at the section or the session. A preserve room has no key of
    /// its own to hold, so it cannot carry such a stream.
    pub engine_keying: Option<&'static str>,
}

/// What a seat's offer settled for its video.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoChoice {
    pub remote: SocketAddr,
    pub transport: String,
    pub direction: MediaDirection,
    pub rtcp_mux: bool,
    /// The seat's own payload type for the room's format.
    pub payload_type: u8,
    /// The room's format: the existing one, or the one this seat fixed.
    pub format: RoomVideoFormat,
    /// The RTCP feedback the seat accepted: what the offer listed for the chosen payload type, and
    /// only on `RTP/AVPF` (RFC 4585 §4.2; `RTP/AVP` has no feedback).
    pub feedback: VideoFeedback,
    /// The parameters of the answer's `a=fmtp` line for this seat: the room's, with the seat's own
    /// `profile-level-id` spelling at the level the seat is answered at (RFC 6184 §8.2.2). `None`
    /// writes no `a=fmtp` line.
    pub answer_fmtp: Option<String>,
    /// The section's `a=mid`, echoed by a BUNDLEd answer.
    pub mid: Option<String>,
    /// The section is bundled with the audio's transport.
    pub bundled: bool,
}

impl RoomVideoFormat {
    /// The format the controller's `video.fmtp` fixes.
    ///
    /// # Errors
    /// The reason when it names a `packetization-mode` the room does not carry.
    pub fn from_fmtp(parameters: &str) -> Result<Self, String> {
        let mode = packetization_mode(parameters);
        if !CARRIED_MODES.contains(&mode) {
            return Err(format!(
                "video.fmtp names packetization-mode {mode}; the room carries modes 0 and 1"
            ));
        }
        if let Some(value) = parameter(parameters, "profile-level-id") {
            if ProfileLevel::parse(&value).is_none() {
                return Err(format!(
                    "video.fmtp names profile-level-id {value}, which is not six hexadecimal digits (RFC 6184 §8.1)"
                ));
            }
        }
        Ok(Self {
            packetization_mode: mode,
            profile_level_id: profile_level_id(parameters),
            fmtp: (!parameters.is_empty()).then(|| parameters.to_string()),
        })
    }

    /// The format a seat's payload fixes: its two decisive parameters and nothing else.
    fn of_payload(mode: u8, level: Option<String>) -> Self {
        let fmtp = match &level {
            Some(level) => format!("profile-level-id={level};packetization-mode={mode}"),
            None => format!("packetization-mode={mode}"),
        };
        Self {
            packetization_mode: mode,
            profile_level_id: level,
            fmtp: Some(fmtp),
        }
    }
}

/// The value of the fmtp parameter `name` (RFC 6184 §8.1: `;`-separated `name=value`), name matched
/// without regard to case.
fn parameter(parameters: &str, name: &str) -> Option<String> {
    parameters.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// `packetization-mode`, which is 0 when the stream names none (RFC 6184 §8.1).
fn packetization_mode(parameters: &str) -> u8 {
    parameter(parameters, "packetization-mode")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// The `profile-level-id` RFC 6184 §8.1 infers when none is present: "the Baseline profile, without
/// additional constraints at Level 1" (profile_idc 66, profile-iop 0, level_idc 10).
const INFERRED_PROFILE_LEVEL_ID: &str = "42000a";

/// `profile-level-id` in lower case, so two spellings of one value compare equal; the inferred
/// Baseline Level 1 when the parameters name none (RFC 6184 §8.1).
fn profile_level_id(parameters: &str) -> Option<String> {
    Some(parameter(parameters, "profile-level-id").map_or_else(
        || INFERRED_PROFILE_LEVEL_ID.to_string(),
        |value| value.to_ascii_lowercase(),
    ))
}

/// The first live `m=video` section of `sdp`, with the transport and the H.264 facts of it. `None`
/// when there is none, or every one is at port 0 (declined by its offerer).
#[must_use]
pub fn parse_video(sdp: &str) -> Option<VideoOffer> {
    let lines = split_lines(sdp);
    let (start, end, port) = locate(&lines)?;
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(0);
    let connection = |range: std::ops::Range<usize>| -> Option<IpAddr> {
        lines[range]
            .iter()
            .find_map(|line| parse_connection_addr(line.strip_prefix("c=")?))
    };
    let section = &lines[start + 1..end];
    let address = connection(start + 1..end).or_else(|| connection(0..first_media))?;
    let direction_of = |scope: &[&str]| {
        scope
            .iter()
            .find_map(|line| MediaDirection::parse(line.strip_prefix("a=")?))
    };
    let direction = direction_of(section)
        .or_else(|| direction_of(&lines[..first_media]))
        .unwrap_or_default();
    let mut fields = lines[start]
        .strip_prefix("m=")
        .unwrap_or_default()
        .split_whitespace();
    let transport = fields.nth(2)?.to_string();
    let payloads = fields
        .filter_map(|field| field.parse::<u8>().ok())
        .map(|payload_type| OfferedVideoPayload {
            payload_type,
            feedback: VideoFeedback::of_payload(section, payload_type),
            encoding: attribute(section, "rtpmap", payload_type).and_then(|body| {
                let (name, rest) = body.split_once('/')?;
                let clock = rest.split('/').next()?.trim().parse().ok()?;
                Some((name.trim().to_string(), clock))
            }),
            fmtp: attribute(section, "fmtp", payload_type).map(str::to_string),
        })
        .collect();
    Some(VideoOffer {
        remote: SocketAddr::new(address, port),
        transport,
        direction,
        rtcp_mux: section.contains(&"a=rtcp-mux"),
        payloads,
        mid: mid_line(section),
        bundled: bundled_with_audio(&lines, section),
        engine_keying: engine_keying(&lines[..first_media], section),
    })
}

/// The keying line (`a=crypto` or `a=fingerprint`) the session region or the video `section` carries.
fn engine_keying(session: &[&str], section: &[&str]) -> Option<&'static str> {
    session.iter().chain(section).find_map(|line| {
        if line.starts_with("a=crypto:") {
            Some("a=crypto")
        } else if line.starts_with("a=fingerprint:") {
            Some("a=fingerprint")
        } else {
            None
        }
    })
}

/// The section's `a=mid` (RFC 5888 §4).
fn mid_line(section: &[&str]) -> Option<String> {
    section
        .iter()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .map(|mid| mid.trim().to_string())
        .filter(|mid| !mid.is_empty())
}

/// Whether the video `section` and the first live audio section are in one `a=group:BUNDLE` line
/// (RFC 8843 §7.2): the section then travels on the audio's transport.
fn bundled_with_audio(lines: &[&str], section: &[&str]) -> bool {
    let Some(video_mid) = mid_line(section) else {
        return false;
    };
    let Some((audio_start, audio_end)) = locate_audio(lines) else {
        return false;
    };
    let Some(audio_mid) = mid_of(lines, audio_start, audio_end) else {
        return false;
    };
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(lines.len());
    lines[..first_media]
        .iter()
        .filter_map(|line| line.strip_prefix("a=group:BUNDLE"))
        .any(|group| {
            let mids: Vec<&str> = group.split_whitespace().collect();
            mids.contains(&video_mid.as_str()) && mids.contains(&audio_mid.as_str())
        })
}

/// Where the first live video section is: its `m=` line index, the exclusive end of the section and
/// its port. A section at port 0 was declined by its offerer.
fn locate(lines: &[&str]) -> Option<(usize, usize, u16)> {
    let mut found: Option<(usize, u16)> = None;
    for (index, line) in lines.iter().enumerate() {
        let Some(value) = line.strip_prefix("m=") else {
            continue;
        };
        if let Some((start, port)) = found {
            return Some((start, index, port));
        }
        let mut fields = value.split_whitespace();
        if fields.next() == Some("video") {
            found = fields
                .next()
                .and_then(|field| field.split('/').next())
                .and_then(|field| field.parse::<u16>().ok())
                .filter(|port| *port != 0)
                .map(|port| (index, port));
        }
    }
    found.map(|(start, port)| (start, lines.len(), port))
}

/// The body of the section's `a=<name>:<payload type> <body>` line.
fn attribute<'a>(section: &[&'a str], name: &str, payload_type: u8) -> Option<&'a str> {
    section.iter().find_map(|line| {
        let rest = line
            .strip_prefix("a=")?
            .strip_prefix(name)?
            .strip_prefix(':')?;
        let (number, body) = rest.split_once(' ')?;
        (number.trim().parse::<u8>().ok()? == payload_type).then_some(body.trim())
    })
}

/// Decide whether `offer` fits the room: the seat's own payload type for the room's format, and the
/// parameters the answer gives the seat.
///
/// `fixed` is the format already in force: the room's, or the controller's `video.fmtp`. With none,
/// the first H.264 payload carrying a mode the room carries fixes it (RFC 3264 §6.1 order).
///
/// With a format in force, a payload fits when its packetization mode is the room's, its
/// sub-profile is the room's (RFC 6184 §8.2.2: the profile part is used symmetrically; Table 5
/// spellings of one sub-profile are one), and, when the seat receives video, it decodes the room's
/// level. The room's sources never send above the room's level, so a receiver must decode at least
/// that; a seat that only sends may be lower, since every receiver decodes all lower levels
/// (RFC 6184 §8.1). The level part of the answer is changed per seat (RFC 6184 §8.2.2).
///
/// # Errors
/// The reason the seat's video is declined and it joins audio-only: a transport the engine does not
/// carry video on, no H.264/90000 payload, only a packetization mode it does not carry, a malformed
/// `profile-level-id`, another mode or sub-profile than the room's, or a level the seat cannot
/// receive the room's video at.
pub fn choose_video(
    offer: &VideoOffer,
    fixed: Option<&RoomVideoFormat>,
) -> Result<VideoChoice, String> {
    choose(offer, fixed, Asymmetry::AsSignalled, Carriage::Translate)
}

/// [`choose_video`] for a preserve room (`media: preserve`): the room forwards the talker's SRTP
/// unchanged, so the stream may be `RTP/SAVP` or `RTP/SAVPF` as well as plain, provided the UEs key
/// it between themselves (3GPP TS 33.180 §7.5.2): a section with an `a=crypto` or an `a=fingerprint`
/// would have the engine terminate it, and a video that shares the audio's transport (RFC 8843)
/// would need the engine's key, so both are declined. The answer keeps the offer's transport
/// (RFC 3264 §6) and its feedback.
///
/// # Errors
/// As [`choose_video`], and the reasons above.
pub fn choose_preserved_video(
    offer: &VideoOffer,
    fixed: Option<&RoomVideoFormat>,
) -> Result<VideoChoice, String> {
    choose(offer, fixed, Asymmetry::AsSignalled, Carriage::Preserve)
}

/// [`choose_answered_video`] for a member's answer to a preserve room's offer.
///
/// # Errors
/// As [`choose_preserved_video`].
pub fn choose_answered_preserved_video(
    answer: &VideoOffer,
    fixed: Option<&RoomVideoFormat>,
) -> Result<VideoChoice, String> {
    choose(answer, fixed, Asymmetry::NotAllowed, Carriage::Preserve)
}

/// [`choose_video`] for a member's answer to the engine's own offer (`forward_offer`). The engine's
/// offer never carries `level-asymmetry-allowed`, so it is 0 for the pair whatever the answer says
/// (RFC 6184 §8.1: "The value of 0 in either the offer or the answer indicates that level
/// asymmetry is not allowed").
///
/// # Errors
/// As [`choose_video`].
pub fn choose_answered_video(
    answer: &VideoOffer,
    fixed: Option<&RoomVideoFormat>,
) -> Result<VideoChoice, String> {
    choose(answer, fixed, Asymmetry::NotAllowed, Carriage::Translate)
}

/// Whether the room terminates the seat's media or forwards it as it came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carriage {
    /// A translating room: plain RTP on an endpoint of its own, or a browser's bundled DTLS-SRTP.
    Translate,
    /// A preserving room: SRTP between the UEs passes through, unread.
    Preserve,
}

/// Whether the other side of the exchange allows level asymmetry (RFC 6184 §8.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asymmetry {
    /// The engine answers: asymmetry holds when the offer signals it, and the answer echoes it.
    AsSignalled,
    /// The engine offered without it.
    NotAllowed,
}

/// One H.264 payload of a section: its number, `packetization-mode` and `a=fmtp` parameters.
struct H264Payload<'a> {
    payload_type: u8,
    mode: u8,
    parameters: &'a str,
}

fn choose(
    offer: &VideoOffer,
    fixed: Option<&RoomVideoFormat>,
    asymmetry: Asymmetry,
    carriage: Carriage,
) -> Result<VideoChoice, String> {
    // RFC 3264 §6: the answer keeps the offer's transport. Plain RTP is carried on an endpoint of its
    // own, DTLS-SRTP only bundled with the audio; SDES video is not carried yet, and a plain answer
    // to a secure offer would send the seat video it cannot decrypt.
    let webrtc = offer.transport.eq_ignore_ascii_case(WEBRTC_VIDEO_TRANSPORT);
    if carriage == Carriage::Preserve {
        check_preserved_transport(offer)?;
    } else if !webrtc
        && !["RTP/AVP", "RTP/AVPF"]
            .iter()
            .any(|carried| offer.transport.eq_ignore_ascii_case(carried))
    {
        return Err(format!(
            "video over {} is not carried yet (plain RTP/AVP, RTP/AVPF and bundled UDP/TLS/RTP/SAVPF only)",
            offer.transport
        ));
    }
    if webrtc && !offer.bundled {
        return Err(
            "video over UDP/TLS/RTP/SAVPF is carried only bundled with the audio (a=group:BUNDLE, \
             RFC 8843): a video transport of its own is not run"
                .to_string(),
        );
    }
    let feedback_of = |payload_type: u8| {
        // RFC 4585 §4.2: feedback is for the AVPF profile, `RTP/SAVPF` and `UDP/TLS/RTP/SAVPF`
        // included.
        if webrtc
            || ["RTP/AVPF", "RTP/SAVPF"]
                .iter()
                .any(|feedback| offer.transport.eq_ignore_ascii_case(feedback))
        {
            offer
                .payloads
                .iter()
                .find(|payload| payload.payload_type == payload_type)
                .map(|payload| payload.feedback)
                .unwrap_or_default()
        } else {
            VideoFeedback::default()
        }
    };
    let h264: Vec<H264Payload<'_>> = offer
        .payloads
        .iter()
        .filter(|payload| {
            payload.encoding.as_ref().is_some_and(|(name, clock)| {
                name.eq_ignore_ascii_case("H264") && *clock == VIDEO_CLOCK_RATE_HZ
            })
        })
        .map(|payload| {
            let parameters = payload.fmtp.as_deref().unwrap_or_default();
            H264Payload {
                payload_type: payload.payload_type,
                mode: packetization_mode(parameters),
                parameters,
            }
        })
        .collect();
    let Some(first_h264) = h264.first() else {
        return Err(
            "the offer has no H264/90000 video payload (RFC 6184); the room carries H.264 only"
                .to_string(),
        );
    };
    let carried: Vec<&H264Payload<'_>> = h264
        .iter()
        .filter(|payload| CARRIED_MODES.contains(&payload.mode))
        .collect();
    if carried.is_empty() {
        return Err(format!(
            "only H264 packetization-mode {} is offered; the room carries modes 0 and 1",
            first_h264.mode
        ));
    }
    let (payload_type, format, answer_fmtp) = match fixed {
        Some(room) => {
            let (payload_type, answer_fmtp) = fit_room(room, &carried, offer.direction, asymmetry)?;
            (payload_type, room.clone(), answer_fmtp)
        }
        None => {
            let (payload, level) = carried
                .iter()
                .find_map(|payload| {
                    let level = profile_level_id(payload.parameters)?;
                    ProfileLevel::parse(&level).map(|_| (payload, level))
                })
                .ok_or_else(|| {
                    format!(
                        "the offered H264 profile-level-id {} is not six hexadecimal digits (RFC 6184 §8.1)",
                        parameter(carried[0].parameters, "profile-level-id").unwrap_or_default()
                    )
                })?;
            let format = RoomVideoFormat::of_payload(payload.mode, Some(level));
            let answer_fmtp = format.fmtp.clone();
            (payload.payload_type, format, answer_fmtp)
        }
    };
    Ok(VideoChoice {
        remote: offer.remote,
        transport: offer.transport.clone(),
        direction: offer.direction,
        rtcp_mux: offer.rtcp_mux,
        payload_type,
        format,
        feedback: feedback_of(payload_type),
        answer_fmtp,
        mid: offer.mid.clone(),
        bundled: offer.bundled,
    })
}

/// Whether a preserve room can carry the video of `offer`: the transports of RFC 3711 and RFC 4585
/// with no keying of the engine's.
fn check_preserved_transport(offer: &VideoOffer) -> Result<(), String> {
    if !["RTP/AVP", "RTP/AVPF", "RTP/SAVP", "RTP/SAVPF"]
        .iter()
        .any(|carried| offer.transport.eq_ignore_ascii_case(carried))
    {
        return Err(format!(
            "video over {} is not carried by a preserve room (RTP/AVP, RTP/AVPF, RTP/SAVP and RTP/SAVPF only; \
             a room that forwards end-to-end SRTP holds no DTLS-SRTP key)",
            offer.transport
        ));
    }
    if offer.bundled {
        return Err(
            "a preserve room carries video on a transport of its own: video bundled with the audio \
             (a=group:BUNDLE, RFC 8843) would need the engine's key"
                .to_string(),
        );
    }
    if let Some(keying) = offer.engine_keying {
        return Err(format!(
            "the video carries {keying}, which would have the engine terminate SRTP that a preserve \
             room forwards end to end (3GPP TS 33.180 §7.5.2); the UEs key it with a=key-mgmt"
        ));
    }
    Ok(())
}

/// The first of `carried` that fits `room`, with the answer's `a=fmtp` parameters for it.
fn fit_room(
    room: &RoomVideoFormat,
    carried: &[&H264Payload<'_>],
    direction: MediaDirection,
    asymmetry: Asymmetry,
) -> Result<(u8, Option<String>), String> {
    let room_level_id = room
        .profile_level_id
        .as_deref()
        .unwrap_or(INFERRED_PROFILE_LEVEL_ID);
    let room_profile = ProfileLevel::parse(room_level_id).ok_or_else(|| {
        format!("the room's profile-level-id {room_level_id} is not six hexadecimal digits")
    })?;
    let room_level = room_profile.level();
    // Whether the seat is sent the room's video (RFC 3264 §6.1: it receives unless it said
    // `sendonly` or `inactive`).
    let receives = matches!(
        direction,
        MediaDirection::SendRecv | MediaDirection::RecvOnly
    );
    let mut level_refusal = None;
    for payload in carried
        .iter()
        .filter(|payload| payload.mode == room.packetization_mode)
    {
        let Some(seat) =
            profile_level_id(payload.parameters).and_then(|level| ProfileLevel::parse(&level))
        else {
            continue;
        };
        if seat.sub_profile() != room_profile.sub_profile() {
            continue;
        }
        // RFC 6184 §8.2.2: asymmetry holds only when both offer and answer say 1.
        let asymmetric = asymmetry == Asymmetry::AsSignalled
            && parameter(payload.parameters, "level-asymmetry-allowed").as_deref() == Some("1");
        let sends_at = seat.level();
        // RFC 6184 §8.1: max-recv-level raises what a seat receives above its default level. It
        // only counts with asymmetry: without it one level applies both ways (§8.2.2).
        let receives_at = if asymmetric {
            parameter(payload.parameters, "max-recv-level")
                .as_deref()
                .and_then(max_recv_level)
                .map_or(sends_at, |level| level.max(sends_at))
        } else {
            sends_at
        };
        if receives && receives_at < room_level {
            level_refusal.get_or_insert_with(|| {
                format!(
                    "the seat receives H264 up to level {receives_at}, below the room's level {room_level} (RFC 6184 §8.1)"
                )
            });
            continue;
        }
        // RFC 6184 §8.2.2: with asymmetry the answer's level is the highest the engine receives,
        // the room's; without it the answer never upgrades the offer's level.
        let answered: Level = if asymmetric {
            room_level
        } else {
            sends_at.min(room_level)
        };
        let answer_fmtp = answer_parameters(room, &seat.with_level(answered), asymmetric);
        return Ok((payload.payload_type, answer_fmtp));
    }
    Err(level_refusal.unwrap_or_else(|| {
        format!(
            "the room's video is H264 packetization-mode {} with profile-level-id {room_level_id}, which the seat did not offer",
            room.packetization_mode,
        )
    }))
}

/// The answer's `a=fmtp` parameters for a seat answered with `profile_level_id`: the room's
/// parameters (a controller's other parameters kept verbatim) with `profile-level-id` replaced, and
/// `level-asymmetry-allowed=1` exactly when the pair allows it.
fn answer_parameters(
    room: &RoomVideoFormat,
    profile_level_id: &str,
    asymmetric: bool,
) -> Option<String> {
    let unchanged = room.profile_level_id.as_deref() == Some(profile_level_id);
    let Some(parameters) = room.fmtp.as_deref() else {
        if unchanged && !asymmetric {
            return None;
        }
        let mut written = format!(
            "profile-level-id={profile_level_id};packetization-mode={}",
            room.packetization_mode
        );
        if asymmetric {
            written.push_str(";level-asymmetry-allowed=1");
        }
        return Some(written);
    };
    let mut named = false;
    let mut kept: Vec<String> = Vec::new();
    for pair in parameters.split(';') {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key).trim();
        if key.eq_ignore_ascii_case("level-asymmetry-allowed") {
            continue;
        }
        if key.eq_ignore_ascii_case("profile-level-id") {
            named = true;
            let lead = &pair[..pair.len() - pair.trim_start().len()];
            kept.push(format!("{lead}profile-level-id={profile_level_id}"));
        } else {
            kept.push(pair.to_string());
        }
    }
    // A format that names no profile-level-id is Baseline Level 1 (RFC 6184 §8.1): it needs naming
    // only when the answer says something else.
    if !named && !unchanged {
        kept.push(format!("profile-level-id={profile_level_id}"));
    }
    if asymmetric {
        kept.push("level-asymmetry-allowed=1".to_string());
    }
    Some(kept.join(";"))
}

/// What an answer's video section says.
#[derive(Debug, Clone, Copy)]
pub struct VideoAnswer<'a> {
    /// The engine's video endpoint and the address advertised for it.
    pub engine: EngineMedia,
    pub choice: &'a VideoChoice,
    /// `b=AS` in kilobits per second.
    pub bandwidth_kbps: Option<u32>,
    /// The SSRC the room sends this seat's video under, and the CNAME of the seat.
    pub own: &'a OwnSsrc,
}

/// Replace the first live `m=video` section of `sdp` with the engine's answer to it.
///
/// A bundled section (RFC 8843, `choice.bundled`) is written on the audio's transport instead of the
/// engine's video endpoint, which it has none of: the audio section's port, connection line, ICE
/// credentials, candidates, fingerprint and `a=setup` (RFC 8843 §7.3: one transport, so the
/// transport attributes are the audio's), and the offered `a=mid` echoed (RFC 5888 §4).
#[must_use]
pub fn anchor_video(sdp: &str, answer: &VideoAnswer<'_>) -> String {
    let lines = split_lines(sdp);
    let Some((start, end, _)) = locate(&lines) else {
        return sdp.to_string();
    };
    let choice = answer.choice;
    let payload_type = choice.payload_type;
    let advertised = answer.engine.advertised_ip;
    // The section is written whole rather than edited. The offerer's own lines describe the
    // offerer: its address, its `a=ssrc` (RFC 5576 §4.1), its `a=extmap` (the translator strips
    // header extensions, RFC 3550 §5.3.1), its `sprop-parameter-sets`, its other codecs, and the
    // feedback the room does not serve (`transport-cc`, `goog-remb`).
    let bundled = if choice.bundled {
        let Some(transport) = BundledTransport::of(&lines) else {
            return sdp.to_string();
        };
        Some(transport)
    } else {
        None
    };
    let mut section = Vec::new();
    match &bundled {
        Some(transport) => {
            section.push(format!(
                "m=video {} {} {payload_type}",
                transport.port, choice.transport
            ));
            section.extend(transport.connection.map(str::to_string));
        }
        None => {
            section.push(format!(
                "m=video {} {} {payload_type}",
                answer.engine.rtp.port(),
                choice.transport
            ));
            section.push(format!("c=IN {} {advertised}", addrtype(advertised)));
        }
    }
    if let Some(kbps) = answer.bandwidth_kbps {
        section.push(format!("b=AS:{kbps}"));
    }
    if let Some(transport) = &bundled {
        section.extend(choice.mid.iter().map(|mid| format!("a=mid:{mid}")));
        section.extend(transport.attributes.iter().map(|line| (*line).to_string()));
    }
    section.push(format!(
        "a=rtpmap:{payload_type} H264/{VIDEO_CLOCK_RATE_HZ}"
    ));
    if let Some(parameters) = choice.answer_fmtp.as_deref() {
        section.push(format!("a=fmtp:{payload_type} {parameters}"));
    }
    section.extend(choice.feedback.lines(payload_type));
    // RFC 3264 §6.1: the answer's direction is the complement of the offer's.
    section.push(format!("a={}", choice.direction.answered().token()));
    if choice.rtcp_mux {
        section.push("a=rtcp-mux".to_string());
    }
    section.push(format!(
        "a=ssrc:{} cname:{}",
        answer.own.ssrc, answer.own.cname
    ));
    // The last element of an SDP that ends in CRLF is the empty remainder: it stays last.
    let trailing = if end == lines.len() {
        lines[start + 1..end]
            .iter()
            .rev()
            .take_while(|line| line.is_empty())
            .count()
    } else {
        0
    };
    let mut out: Vec<&str> = lines[..start].to_vec();
    out.extend(section.iter().map(String::as_str));
    out.extend(std::iter::repeat_n("", trailing));
    out.extend(&lines[end..]);
    out.join(CRLF)
}

/// What a bundled section takes from the audio section it shares a transport with (RFC 8843 §7.3).
struct BundledTransport<'a> {
    port: u16,
    connection: Option<&'a str>,
    /// ICE credentials, candidates, fingerprint and `a=setup`.
    attributes: Vec<&'a str>,
}

impl<'a> BundledTransport<'a> {
    fn of(lines: &[&'a str]) -> Option<Self> {
        let (start, end) = locate_audio(lines)?;
        let port = lines[start]
            .strip_prefix("m=")?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        let audio = &lines[start + 1..end];
        Some(Self {
            port,
            connection: audio.iter().copied().find(|line| line.starts_with("c=")),
            attributes: audio
                .iter()
                .copied()
                .filter(|line| is_shared_transport_line(line))
                .collect(),
        })
    }
}

/// Remove from the `a=group:BUNDLE` line of an answer the sections it declined (port 0 without
/// `a=bundle-only`, RFC 8843 §7.3.3: a rejected section is not in the group). The m-lines and mids
/// stay where they are; a group left empty is dropped. An answer that declines nothing is returned as
/// it is.
#[must_use]
pub fn drop_declined_from_bundle(answer: &str) -> String {
    let lines = split_lines(answer);
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(lines.len());
    let mut declined: Vec<String> = Vec::new();
    for (index, line) in lines.iter().enumerate().skip(first_media) {
        let Some(value) = line.strip_prefix("m=") else {
            continue;
        };
        let live = value
            .split_whitespace()
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0);
        let end = lines[index + 1..]
            .iter()
            .position(|line| line.starts_with("m="))
            .map_or(lines.len(), |offset| index + 1 + offset);
        if !live && !lines[index + 1..end].contains(&"a=bundle-only") {
            declined.extend(mid_of(&lines, index, end));
        }
    }
    if declined.is_empty() {
        return answer.to_string();
    }
    let mut changed = false;
    let rewritten: Vec<String> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let Some(group) = line
                .strip_prefix("a=group:BUNDLE")
                .filter(|_| index < first_media)
            else {
                return Some((*line).to_string());
            };
            let kept: Vec<&str> = group
                .split_whitespace()
                .filter(|mid| !declined.iter().any(|gone| gone == mid))
                .collect();
            if kept.len() == group.split_whitespace().count() {
                return Some((*line).to_string());
            }
            changed = true;
            (!kept.is_empty()).then(|| format!("a=group:BUNDLE {}", kept.join(" ")))
        })
        .collect();
    if changed {
        rewritten.join(CRLF)
    } else {
        answer.to_string()
    }
}

/// The `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` lines of the one payload type the engine offers.
pub(super) fn write_offered_format(section: &mut String, fmtp: Option<&str>, payload_type: u8) {
    let _ = write!(
        section,
        "a=rtpmap:{payload_type} H264/{VIDEO_CLOCK_RATE_HZ}{CRLF}"
    );
    if let Some(parameters) = fmtp.filter(|parameters| !parameters.is_empty()) {
        let _ = write!(section, "a=fmtp:{payload_type} {parameters}{CRLF}");
    }
    // RFC 4585 §4.2: everything the room supports, so the member's answer can accept any of it.
    for line in VideoFeedback::SUPPORTED.lines(payload_type) {
        let _ = write!(section, "{line}{CRLF}");
    }
}

/// The video section of an offer the engine writes (a `forward_offer`), under `payload_type`
/// ([`OFFER_PAYLOAD_TYPE`], or the number a preserve room's talker already sends, since the room
/// forwards its packets unchanged). `secure` offers `RTP/SAVPF` with no key of the engine's: the UEs
/// key the stream between themselves (RFC 4567 `a=key-mgmt`, 3GPP TS 33.180 §7.5.2).
#[must_use]
pub fn video_offer_section(
    rtp_port: u16,
    advertised: IpAddr,
    fmtp: Option<&str>,
    bandwidth_kbps: Option<u32>,
    payload_type: u8,
    secure: bool,
) -> String {
    let profile = if secure { "RTP/SAVPF" } else { "RTP/AVPF" };
    let mut section = format!(
        "m=video {rtp_port} {profile} {payload_type}{CRLF}c=IN {} {advertised}{CRLF}",
        addrtype(advertised)
    );
    if let Some(kbps) = bandwidth_kbps {
        let _ = write!(section, "b=AS:{kbps}{CRLF}");
    }
    write_offered_format(&mut section, fmtp, payload_type);
    // RFC 5761 §5.1.1: the seat is one muxed endpoint, as the audio is.
    section.push_str("a=sendrecv\r\na=rtcp-mux\r\n");
    section
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    const HEADER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 20100 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
    );

    const VIDEO: &str = concat!(
        "m=video 20200 RTP/AVP 99 100\r\n",
        "c=IN IP4 192.0.2.11\r\n",
        "a=rtpmap:99 H264/90000\r\n",
        "a=fmtp:99 profile-level-id=640C1F;packetization-mode=1;sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPA8YMZYA==\r\n",
        "a=rtpmap:100 VP8/90000\r\n",
        "a=sendrecv\r\n",
        "a=rtcp-mux\r\n",
        "a=extmap:1 urn:ietf:params:rtp-hdrext:toffset\r\n",
        "a=ssrc:1111 cname:offerer\r\n",
    );

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn offer(video: &str) -> String {
        format!("{HEADER}{video}")
    }

    fn engine() -> EngineMedia {
        EngineMedia {
            rtp: "198.51.100.7:30004".parse().unwrap(),
            rtcp: None,
            advertised_ip: "198.51.100.7".parse().unwrap(),
        }
    }

    fn fixed(mode: u8, level: Option<&str>) -> RoomVideoFormat {
        RoomVideoFormat {
            packetization_mode: mode,
            profile_level_id: level.map(str::to_string),
            fmtp: None,
        }
    }

    #[test]
    fn parses_the_section_with_its_media_level_address_and_h264_payloads() {
        let parsed = parse_video(&offer(VIDEO)).unwrap();
        assert_eq!(parsed.remote, address("192.0.2.11:20200"));
        assert_eq!(parsed.transport, "RTP/AVP");
        assert_eq!(parsed.direction, MediaDirection::SendRecv);
        assert!(parsed.rtcp_mux);
        assert_eq!(parsed.payloads.len(), 2);
        assert_eq!(parsed.payloads[0].payload_type, 99);
        assert_eq!(
            parsed.payloads[0].encoding,
            Some(("H264".to_string(), 90_000))
        );
        assert!(parsed.payloads[0]
            .fmtp
            .as_deref()
            .unwrap()
            .starts_with("profile-level-id=640C1F"));
        assert_eq!(parsed.payloads[1].payload_type, 100);
    }

    #[test]
    fn the_session_level_address_and_direction_apply_when_the_section_has_none() {
        let sdp = concat!(
            "v=0\r\ns=-\r\nc=IN IP4 192.0.2.10\r\na=recvonly\r\nt=0 0\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "m=video 20200 RTP/AVP 99\r\na=rtpmap:99 H264/90000\r\n",
        );
        let parsed = parse_video(sdp).unwrap();
        assert_eq!(parsed.remote, address("192.0.2.10:20200"));
        assert_eq!(parsed.direction, MediaDirection::RecvOnly);
        assert!(!parsed.rtcp_mux);
    }

    #[test]
    fn a_section_direction_beats_the_session_one() {
        let sdp = concat!(
            "v=0\r\ns=-\r\nc=IN IP4 192.0.2.10\r\na=recvonly\r\nt=0 0\r\n",
            "m=video 20200 RTP/AVP 99\r\na=rtpmap:99 H264/90000\r\na=sendonly\r\n",
        );
        assert_eq!(
            parse_video(sdp).unwrap().direction,
            MediaDirection::SendOnly
        );
    }

    #[test]
    fn a_declined_or_absent_video_section_is_none() {
        assert_eq!(parse_video(HEADER), None);
        assert_eq!(parse_video(&offer("m=video 0 RTP/AVP 99\r\n")), None);
        // The first live one is the one read, a declined first section is skipped.
        let two = offer(&format!("m=video 0 RTP/AVP 99\r\n{VIDEO}"));
        assert_eq!(
            parse_video(&two).unwrap().remote,
            address("192.0.2.11:20200")
        );
    }

    #[test]
    fn a_section_without_any_address_is_none() {
        let sdp = "v=0\r\ns=-\r\nt=0 0\r\nm=video 20200 RTP/AVP 99\r\na=rtpmap:99 H264/90000\r\n";
        assert_eq!(parse_video(sdp), None);
    }

    #[test]
    fn the_first_h264_payload_fixes_the_format_without_the_seats_own_parameters() {
        let choice = choose_video(&parse_video(&offer(VIDEO)).unwrap(), None).unwrap();
        assert_eq!(choice.payload_type, 99);
        assert_eq!(choice.format.packetization_mode, 1);
        assert_eq!(choice.format.profile_level_id.as_deref(), Some("640c1f"));
        // RFC 6184 §8.1: only the two parameters a receiver cannot decode without. The seat's
        // sprop-parameter-sets describe its own stream.
        assert_eq!(
            choice.format.fmtp.as_deref(),
            Some("profile-level-id=640c1f;packetization-mode=1")
        );
        assert_eq!(choice.remote, address("192.0.2.11:20200"));
        assert_eq!(choice.direction, MediaDirection::SendRecv);
    }

    #[test]
    fn an_absent_packetization_mode_is_zero() {
        // RFC 6184 §8.1: not present means 0.
        let sdp = offer("m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\na=fmtp:99 profile-level-id=42e01f\r\n");
        let choice = choose_video(&parse_video(&sdp).unwrap(), None).unwrap();
        assert_eq!(choice.format.packetization_mode, 0);
        assert_eq!(
            choice.format.fmtp.as_deref(),
            Some("profile-level-id=42e01f;packetization-mode=0")
        );
    }

    #[test]
    fn an_absent_profile_level_id_is_baseline_level_1() {
        // RFC 6184 §8.1: "If no profile-level-id is present, the Baseline profile, without
        // additional constraints at Level 1, MUST be inferred" (42000a).
        let bare = offer("m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\na=fmtp:99 packetization-mode=1\r\n");
        let choice = choose_video(&parse_video(&bare).unwrap(), None).unwrap();
        assert_eq!(choice.format.profile_level_id.as_deref(), Some("42000a"));
        assert_eq!(
            choice.format.fmtp.as_deref(),
            Some("profile-level-id=42000a;packetization-mode=1")
        );
        // A seat naming 42000a joins a room fixed by one that named nothing, and the other way round.
        let named = offer("m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\na=fmtp:99 profile-level-id=42000A;packetization-mode=1\r\n");
        assert!(choose_video(&parse_video(&named).unwrap(), Some(&choice.format)).is_ok());
        let room = fixed(1, Some("42000a"));
        assert!(choose_video(&parse_video(&bare).unwrap(), Some(&room)).is_ok());
    }

    #[test]
    fn interleaved_mode_is_refused_with_its_reason() {
        let sdp = offer("m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\na=fmtp:99 packetization-mode=2\r\n");
        let reason = choose_video(&parse_video(&sdp).unwrap(), None).unwrap_err();
        assert!(reason.contains("packetization-mode 2"), "{reason}");
    }

    #[test]
    fn a_mode_two_payload_is_skipped_for_a_carried_one() {
        let sdp = offer(concat!(
            "m=video 20200 RTP/AVP 98 99\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:98 H264/90000\r\na=fmtp:98 packetization-mode=2\r\n",
            "a=rtpmap:99 H264/90000\r\na=fmtp:99 packetization-mode=1\r\n",
        ));
        assert_eq!(
            choose_video(&parse_video(&sdp).unwrap(), None)
                .unwrap()
                .payload_type,
            99
        );
    }

    #[test]
    fn a_section_without_h264_is_refused() {
        let sdp =
            offer("m=video 20200 RTP/AVP 100\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:100 VP8/90000\r\n");
        let reason = choose_video(&parse_video(&sdp).unwrap(), None).unwrap_err();
        assert!(reason.contains("H264/90000"), "{reason}");
        // H.264 at another clock is not RFC 6184's.
        let odd =
            offer("m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/48000\r\n");
        assert!(choose_video(&parse_video(&odd).unwrap(), None).is_err());
    }

    #[test]
    fn an_encoding_name_is_matched_without_regard_to_case() {
        let sdp =
            offer("m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 h264/90000\r\n");
        assert_eq!(
            choose_video(&parse_video(&sdp).unwrap(), None)
                .unwrap()
                .payload_type,
            99
        );
    }

    #[test]
    fn a_later_seat_must_match_the_rooms_mode_and_profile_level() {
        let room = fixed(1, Some("640c1f"));
        // The seat's own number for the matching payload, whichever one it is.
        let sdp = offer(concat!(
            "m=video 20200 RTP/AVP 97 98\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:97 H264/90000\r\na=fmtp:97 profile-level-id=42e01f;packetization-mode=1\r\n",
            "a=rtpmap:98 H264/90000\r\na=fmtp:98 profile-level-id=640C1F;packetization-mode=1\r\n",
        ));
        let choice = choose_video(&parse_video(&sdp).unwrap(), Some(&room)).unwrap();
        assert_eq!(choice.payload_type, 98);
        assert_eq!(choice.format, room);
        let mismatch = offer(concat!(
            "m=video 20200 RTP/AVP 97\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:97 H264/90000\r\na=fmtp:97 profile-level-id=42e01f;packetization-mode=1\r\n",
        ));
        let reason = choose_video(&parse_video(&mismatch).unwrap(), Some(&room)).unwrap_err();
        assert!(
            reason.contains("640c1f") && reason.contains("packetization-mode 1"),
            "{reason}"
        );
        let other_mode = offer(concat!(
            "m=video 20200 RTP/AVP 97\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:97 H264/90000\r\na=fmtp:97 profile-level-id=640c1f;packetization-mode=0\r\n",
        ));
        assert!(choose_video(&parse_video(&other_mode).unwrap(), Some(&room)).is_err());
    }

    #[test]
    fn the_controllers_fmtp_fixes_the_format_and_is_written_as_given() {
        let format =
            RoomVideoFormat::from_fmtp("packetization-mode=1; profile-level-id=640C1F").unwrap();
        assert_eq!(format.packetization_mode, 1);
        assert_eq!(format.profile_level_id.as_deref(), Some("640c1f"));
        assert_eq!(
            format.fmtp.as_deref(),
            Some("packetization-mode=1; profile-level-id=640C1F")
        );
        assert_eq!(
            RoomVideoFormat::from_fmtp("").unwrap().packetization_mode,
            0
        );
        let reason = RoomVideoFormat::from_fmtp("packetization-mode=2").unwrap_err();
        assert!(reason.contains("packetization-mode 2"), "{reason}");
    }

    #[test]
    fn video_on_a_secure_transport_is_refused() {
        // SRTP, SDES and DTLS-SRTP video are steps of their own; the reason says so.
        for transport in ["RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVPF"] {
            let sdp = offer(&format!(
                "m=video 20200 {transport} 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\n"
            ));
            let reason = choose_video(&parse_video(&sdp).unwrap(), None).unwrap_err();
            assert!(reason.contains(transport), "{reason}");
        }
    }

    #[test]
    fn plain_avpf_is_carried_and_echoed() {
        let sdp =
            offer("m=video 20200 RTP/AVPF 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\n");
        let choice = choose_video(&parse_video(&sdp).unwrap(), None).unwrap();
        assert_eq!(choice.transport, "RTP/AVPF");
    }

    fn answered(video: &str, direction_bandwidth: Option<u32>) -> String {
        let offered = offer(video);
        let choice = choose_video(&parse_video(&offered).unwrap(), None).unwrap();
        let own = OwnSsrc {
            ssrc: 0x3fae_627b,
            cname: "seat-cname".to_string(),
        };
        anchor_video(
            &offered,
            &VideoAnswer {
                engine: engine(),
                choice: &choice,
                bandwidth_kbps: direction_bandwidth,
                own: &own,
            },
        )
    }

    #[test]
    fn the_answer_section_is_the_engines_own() {
        let answer = answered(VIDEO, Some(1200));
        let section = answer.split("m=video").nth(1).unwrap();
        assert_eq!(
            format!("m=video{section}"),
            concat!(
                "m=video 30004 RTP/AVP 99\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "b=AS:1200\r\n",
                "a=rtpmap:99 H264/90000\r\n",
                "a=fmtp:99 profile-level-id=640c1f;packetization-mode=1\r\n",
                "a=sendrecv\r\n",
                "a=rtcp-mux\r\n",
                "a=ssrc:1068393083 cname:seat-cname\r\n",
            )
        );
        // The audio section and the session lines are as they were.
        assert!(answer.starts_with(HEADER), "{answer}");
    }

    #[test]
    fn the_answer_never_echoes_what_describes_the_offerer() {
        let answer = answered(VIDEO, None);
        for gone in [
            "extmap",
            "1111",
            "offerer",
            "192.0.2.11",
            "VP8",
            "sprop",
            "b=AS",
        ] {
            assert!(!answer.contains(gone), "{gone}: {answer}");
        }
        assert!(answer.contains("a=ssrc:1068393083 cname:seat-cname"));
    }

    #[test]
    fn the_answer_direction_is_the_complement_of_the_offered_one() {
        // RFC 3264 §6.1.
        for (offered, answer) in [
            ("sendrecv", "sendrecv"),
            ("recvonly", "sendonly"),
            ("sendonly", "recvonly"),
            ("inactive", "inactive"),
        ] {
            let video = format!(
                "m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\na={offered}\r\n"
            );
            let section = answered(&video, None);
            assert!(
                section.contains(&format!("a={answer}\r\n"))
                    && !section.contains(&format!("a={offered}\r\n")) | (offered == answer),
                "{offered} -> {answer}: {section}"
            );
        }
    }

    #[test]
    fn only_the_first_live_video_section_is_anchored() {
        let two = format!("{VIDEO}m=video 20300 RTP/AVP 99\r\na=rtpmap:99 H264/90000\r\n");
        let answer = answered(&two, None);
        assert!(answer.contains("m=video 30004 RTP/AVP 99\r\n"));
        assert!(
            answer.contains("m=video 20300 RTP/AVP 99\r\n"),
            "left for the decline pass: {answer}"
        );
    }

    #[test]
    fn a_section_after_the_video_one_is_kept() {
        let tail = format!("{VIDEO}m=application 20400 udp MCVideo\r\nc=IN IP4 192.0.2.11\r\n");
        let answer = answered(&tail, None);
        assert!(
            answer.ends_with("m=application 20400 udp MCVideo\r\nc=IN IP4 192.0.2.11\r\n"),
            "{answer}"
        );
    }

    #[test]
    fn an_sdp_without_live_video_is_returned_as_it_was() {
        let offered = offer("m=video 0 RTP/AVP 99\r\n");
        let choice = VideoChoice {
            remote: address("192.0.2.11:20200"),
            transport: "RTP/AVP".to_string(),
            direction: MediaDirection::SendRecv,
            rtcp_mux: false,
            payload_type: 99,
            format: fixed(1, None),
            feedback: VideoFeedback::default(),
            answer_fmtp: None,
            mid: None,
            bundled: false,
        };
        let own = OwnSsrc {
            ssrc: 1,
            cname: "c".to_string(),
        };
        let answer = anchor_video(
            &offered,
            &VideoAnswer {
                engine: engine(),
                choice: &choice,
                bandwidth_kbps: None,
                own: &own,
            },
        );
        assert_eq!(answer, offered);
    }

    #[test]
    fn the_offer_section_names_the_engines_endpoint_and_its_format() {
        let section = video_offer_section(
            30004,
            "198.51.100.7".parse().unwrap(),
            Some("profile-level-id=640c1f;packetization-mode=1"),
            Some(900),
            OFFER_PAYLOAD_TYPE,
            false,
        );
        assert_eq!(
            section,
            concat!(
                "m=video 30004 RTP/AVPF 126\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "b=AS:900\r\n",
                "a=rtpmap:126 H264/90000\r\n",
                "a=fmtp:126 profile-level-id=640c1f;packetization-mode=1\r\n",
                "a=rtcp-fb:126 nack\r\n",
                "a=rtcp-fb:126 nack pli\r\n",
                "a=rtcp-fb:126 ccm fir\r\n",
                "a=sendrecv\r\n",
                "a=rtcp-mux\r\n",
            )
        );
        let v6 = video_offer_section(
            30004,
            "2001:db8::7".parse().unwrap(),
            None,
            None,
            OFFER_PAYLOAD_TYPE,
            false,
        );
        assert!(
            v6.contains("c=IN IP6 2001:db8::7\r\n") && !v6.contains("fmtp") && !v6.contains("b=AS")
        );
    }

    const AVPF_VIDEO: &str = concat!(
        "m=video 20200 RTP/AVPF 99 100\r\n",
        "c=IN IP4 192.0.2.11\r\n",
        "a=rtpmap:99 H264/90000\r\n",
        "a=fmtp:99 profile-level-id=640C1F;packetization-mode=1\r\n",
        "a=rtcp-fb:99 nack\r\n",
        "a=rtcp-fb:99 nack pli\r\n",
        "a=rtcp-fb:99 ccm fir\r\n",
        "a=rtcp-fb:99 ccm tmmbr\r\n",
        "a=rtcp-fb:99 goog-remb\r\n",
        "a=rtcp-fb:100 nack\r\n",
        "a=rtpmap:100 VP8/90000\r\n",
        "a=sendrecv\r\n",
        "a=rtcp-mux\r\n",
    );

    const ALL_FEEDBACK: VideoFeedback = VideoFeedback {
        nack: true,
        pli: true,
        fir: true,
    };

    #[test]
    fn an_avpf_offer_is_answered_with_the_feedback_it_offers_for_the_chosen_payload() {
        let choice = choose_video(&parse_video(&offer(AVPF_VIDEO)).unwrap(), None).unwrap();
        assert_eq!(choice.payload_type, 99);
        assert_eq!(choice.feedback, ALL_FEEDBACK);
        let answer = answered(AVPF_VIDEO, None);
        let section = answer.split("m=video").nth(1).unwrap();
        // RFC 4585 §4.2: only what the offer listed and the room supports; tmmbr and remb are not.
        assert_eq!(
            format!("m=video{section}"),
            concat!(
                "m=video 30004 RTP/AVPF 99\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "a=rtpmap:99 H264/90000\r\n",
                "a=fmtp:99 profile-level-id=640c1f;packetization-mode=1\r\n",
                "a=rtcp-fb:99 nack\r\n",
                "a=rtcp-fb:99 nack pli\r\n",
                "a=rtcp-fb:99 ccm fir\r\n",
                "a=sendrecv\r\n",
                "a=rtcp-mux\r\n",
                "a=ssrc:1068393083 cname:seat-cname\r\n",
            )
        );
    }

    #[test]
    fn a_wildcard_feedback_line_applies_to_the_payload_and_a_payload_line_adds_to_it() {
        // RFC 4585 §4.2: `*` is every payload type of the section.
        let sdp = offer(concat!(
            "m=video 20200 RTP/AVPF 99\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:99 H264/90000\r\n",
            "a=rtcp-fb:* nack pli\r\n",
            "a=rtcp-fb:99 ccm fir\r\n",
        ));
        let choice = choose_video(&parse_video(&sdp).unwrap(), None).unwrap();
        assert_eq!(
            choice.feedback,
            VideoFeedback {
                nack: false,
                pli: true,
                fir: true
            }
        );
    }

    #[test]
    fn feedback_of_another_payload_type_does_not_count() {
        let sdp = offer(concat!(
            "m=video 20200 RTP/AVPF 99 100\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:99 H264/90000\r\na=rtpmap:100 VP8/90000\r\n",
            "a=rtcp-fb:100 nack pli\r\n",
        ));
        let choice = choose_video(&parse_video(&sdp).unwrap(), None).unwrap();
        assert_eq!(choice.feedback, VideoFeedback::default());
    }

    #[test]
    fn an_unknown_feedback_type_is_ignored_and_a_bare_nack_is_generic_nack_only() {
        let sdp = offer(concat!(
            "m=video 20200 RTP/AVPF 99\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:99 H264/90000\r\n",
            "a=rtcp-fb:99 nack\r\n",
            "a=rtcp-fb:99 nack sli\r\n",
            "a=rtcp-fb:99 nack rpsi\r\n",
            "a=rtcp-fb:99 ccm tmmbr\r\n",
            "a=rtcp-fb:99 trr-int 100\r\n",
            "a=rtcp-fb:99 transport-cc\r\n",
        ));
        let choice = choose_video(&parse_video(&sdp).unwrap(), None).unwrap();
        assert_eq!(
            choice.feedback,
            VideoFeedback {
                nack: true,
                pli: false,
                fir: false
            }
        );
    }

    #[test]
    fn an_avp_offer_gets_no_feedback_even_when_it_lists_some() {
        // RFC 4585 §4.2 defines the attribute for RTP/AVPF; an RTP/AVP offer has none to accept.
        let sdp = offer(concat!(
            "m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:99 H264/90000\r\na=rtcp-fb:99 nack pli\r\n",
        ));
        let choice = choose_video(&parse_video(&sdp).unwrap(), None).unwrap();
        assert_eq!(choice.feedback, VideoFeedback::default());
        assert!(!answered(
            "m=video 20200 RTP/AVP 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\na=rtcp-fb:99 nack pli\r\n",
            None
        )
        .contains("rtcp-fb"));
    }

    #[test]
    fn an_avpf_offer_with_no_feedback_lines_gets_none_back() {
        let choice = choose_video(
            &parse_video(&offer(
                "m=video 20200 RTP/AVPF 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\n",
            ))
            .unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(choice.feedback, VideoFeedback::default());
    }

    #[test]
    fn the_offer_section_lists_all_three_feedback_types() {
        let section = video_offer_section(
            30004,
            "198.51.100.7".parse().unwrap(),
            None,
            None,
            OFFER_PAYLOAD_TYPE,
            false,
        );
        for line in [
            "m=video 30004 RTP/AVPF 126\r\n",
            "a=rtcp-fb:126 nack\r\n",
            "a=rtcp-fb:126 nack pli\r\n",
            "a=rtcp-fb:126 ccm fir\r\n",
        ] {
            assert!(section.contains(line), "{line}: {section}");
        }
        // The answer to that offer is read like any other: all three accepted.
        let answer = format!("{HEADER}{section}");
        let choice = choose_video(&parse_video(&answer).unwrap(), None).unwrap();
        assert_eq!(choice.feedback, ALL_FEEDBACK);
    }

    /// A one-payload H.264 offer with `parameters` as its fmtp and `direction` as its attribute.
    fn h264(parameters: &str, direction: &str) -> VideoOffer {
        parse_video(&offer(&format!(
            "m=video 20200 RTP/AVP 97\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:97 H264/90000\r\na=fmtp:97 {parameters}\r\na={direction}\r\n"
        )))
        .unwrap()
    }

    #[test]
    fn a_seat_at_a_higher_level_is_answered_at_the_rooms_level_in_its_own_spelling() {
        // RFC 6184 §8.2.2: the level part is changeable and an answer never upgrades it; the
        // profile octets stay the seat's own (42c0 is Constrained Baseline as 42e0 is, Table 5).
        let room = fixed(1, Some("42e01f"));
        let choice = choose_video(
            &h264("profile-level-id=42C028;packetization-mode=1", "sendrecv"),
            Some(&room),
        )
        .unwrap();
        assert_eq!(choice.payload_type, 97);
        assert_eq!(choice.format, room, "the room's format is unchanged");
        assert_eq!(
            choice.answer_fmtp.as_deref(),
            Some("profile-level-id=42c01f;packetization-mode=1")
        );
    }

    #[test]
    fn a_seat_at_the_rooms_level_is_answered_with_the_rooms_parameters() {
        let room = fixed(1, Some("640c1f"));
        let room = RoomVideoFormat {
            fmtp: Some("profile-level-id=640c1f;packetization-mode=1".to_string()),
            ..room
        };
        let choice = choose_video(
            &h264("profile-level-id=640C1F;packetization-mode=1", "sendrecv"),
            Some(&room),
        )
        .unwrap();
        assert_eq!(choice.answer_fmtp, room.fmtp);
    }

    #[test]
    fn a_receiving_seat_below_the_rooms_level_is_declined_naming_both_levels() {
        // A seat cannot decode what the room's sources send above its level (RFC 6184 §8.1).
        let room = fixed(1, Some("640c28"));
        for direction in ["sendrecv", "recvonly"] {
            let reason = choose_video(
                &h264("profile-level-id=640c1f;packetization-mode=1", direction),
                Some(&room),
            )
            .unwrap_err();
            assert!(
                reason.contains("level 3.1") && reason.contains("level 4"),
                "{direction}: {reason}"
            );
        }
    }

    #[test]
    fn a_sending_only_seat_below_the_rooms_level_is_answered_at_its_own_level() {
        // Every receiver decodes the room's level and so every level below it (RFC 6184 §8.1).
        let room = fixed(1, Some("640c28"));
        let choice = choose_video(
            &h264("profile-level-id=640c1f;packetization-mode=1", "sendonly"),
            Some(&room),
        )
        .unwrap();
        assert_eq!(
            choice.answer_fmtp.as_deref(),
            Some("profile-level-id=640c1f;packetization-mode=1")
        );
    }

    #[test]
    fn level_asymmetry_lets_a_seat_receive_up_to_its_max_recv_level() {
        // RFC 6184 §8.2.2: with level-asymmetry-allowed=1 in offer and answer, the engine sends
        // the seat up to the highest level it receives, and the seat sends at the answer's level.
        let room = fixed(1, Some("640c28"));
        let choice = choose_video(
            &h264(
                "profile-level-id=640c1f;packetization-mode=1;level-asymmetry-allowed=1;max-recv-level=0c28",
                "sendrecv",
            ),
            Some(&room),
        )
        .unwrap();
        assert_eq!(
            choice.answer_fmtp.as_deref(),
            Some("profile-level-id=640c28;packetization-mode=1;level-asymmetry-allowed=1")
        );
    }

    #[test]
    fn max_recv_level_without_asymmetry_does_not_raise_what_the_seat_receives() {
        // Without level-asymmetry-allowed one level applies both ways (RFC 6184 §8.2.2).
        let room = fixed(1, Some("640c28"));
        let reason = choose_video(
            &h264(
                "profile-level-id=640c1f;packetization-mode=1;max-recv-level=0c28",
                "sendrecv",
            ),
            Some(&room),
        )
        .unwrap_err();
        assert!(reason.contains("level 3.1"), "{reason}");
    }

    #[test]
    fn a_seat_in_another_profile_is_declined_whatever_its_level() {
        let room = fixed(1, Some("42e01f"));
        let reason = choose_video(
            &h264("profile-level-id=640c28;packetization-mode=1", "sendrecv"),
            Some(&room),
        )
        .unwrap_err();
        assert!(reason.contains("42e01f"), "{reason}");
    }

    #[test]
    fn a_controllers_pin_keeps_its_parameters_and_only_the_level_is_rewritten() {
        let room =
            RoomVideoFormat::from_fmtp("profile-level-id=640c1f;packetization-mode=1;max-fs=3600")
                .unwrap();
        let choice = choose_video(
            &h264("profile-level-id=640c28;packetization-mode=1", "sendrecv"),
            Some(&room),
        )
        .unwrap();
        assert_eq!(
            choice.answer_fmtp.as_deref(),
            Some("profile-level-id=640c1f;packetization-mode=1;max-fs=3600")
        );
    }

    #[test]
    fn a_malformed_profile_level_id_is_declined() {
        let reason = choose_video(
            &h264("profile-level-id=640c1;packetization-mode=1", "sendrecv"),
            None,
        )
        .unwrap_err();
        assert!(reason.contains("profile-level-id"), "{reason}");
        let room = fixed(1, Some("640c1f"));
        assert!(choose_video(
            &h264("profile-level-id=xyz;packetization-mode=1", "sendrecv"),
            Some(&room)
        )
        .is_err());
    }

    #[test]
    fn the_answer_writes_the_seats_own_parameters() {
        let room = fixed(1, Some("42e01f"));
        let offered = offer(concat!(
            "m=video 20200 RTP/AVP 97\r\nc=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:97 H264/90000\r\na=fmtp:97 profile-level-id=42c028;packetization-mode=1\r\n",
        ));
        let choice = choose_video(&parse_video(&offered).unwrap(), Some(&room)).unwrap();
        let own = OwnSsrc {
            ssrc: 1,
            cname: "seat-cname".to_string(),
        };
        let answer = anchor_video(
            &offered,
            &VideoAnswer {
                engine: engine(),
                choice: &choice,
                bandwidth_kbps: None,
                own: &own,
            },
        );
        assert!(
            answer.contains("a=fmtp:97 profile-level-id=42c01f;packetization-mode=1\r\n"),
            "{answer}"
        );
    }

    #[test]
    fn an_answer_to_the_engines_offer_ignores_asymmetry_the_offer_never_allowed() {
        // forward_offer does not offer level-asymmetry-allowed, so it is 0 in the pair.
        let room = fixed(1, Some("640c28"));
        let answer = h264(
            "profile-level-id=640c1f;packetization-mode=1;level-asymmetry-allowed=1;max-recv-level=0c28",
            "sendrecv",
        );
        assert!(choose_answered_video(&answer, Some(&room)).is_err());
        let sending_only = h264("profile-level-id=640c1f;packetization-mode=1", "sendonly");
        assert!(choose_answered_video(&sending_only, Some(&room)).is_ok());
    }

    // ---- a browser's video, bundled with its audio (RFC 8843) ----

    /// A browser offer: audio and video in one BUNDLE group, the video's payload types in the order
    /// libwebrtc lists them (Baseline first), transport-cc and REMB among the feedback.
    fn bundled(group: &str, video_mid: &str) -> String {
        format!(
            concat!(
                "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE {group}\r\n",
                "m=audio 9 UDP/TLS/RTP/SAVPF 0\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n",
                "a=ice-ufrag:abcd\r\na=ice-pwd:0123456789012345678901\r\n",
                "a=fingerprint:sha-256 {print}\r\na=setup:actpass\r\na=rtpmap:0 PCMU/8000\r\n",
                "m=video 9 UDP/TLS/RTP/SAVPF 96 98\r\nc=IN IP4 0.0.0.0\r\na=mid:{video_mid}\r\n",
                "a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
                "a=sendrecv\r\na=rtcp-mux\r\n",
                "a=rtpmap:96 H264/90000\r\na=rtcp-fb:96 goog-remb\r\na=rtcp-fb:96 transport-cc\r\n",
                "a=rtcp-fb:96 ccm fir\r\na=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\n",
                "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n",
                "a=rtpmap:98 H264/90000\r\na=rtcp-fb:98 nack\r\n",
                "a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n",
            ),
            group = group,
            video_mid = video_mid,
            print = "AA:".repeat(31) + "AA",
        )
    }

    #[test]
    fn a_browsers_video_reads_its_mid_and_whether_it_is_bundled_with_the_audio() {
        let parsed = parse_video(&bundled("0 1", "1")).unwrap();
        assert_eq!(parsed.transport, "UDP/TLS/RTP/SAVPF");
        assert_eq!(parsed.mid.as_deref(), Some("1"));
        assert!(parsed.bundled);
        // Not in the audio's group: a transport of its own.
        assert!(!parse_video(&bundled("0", "1")).unwrap().bundled);
        // No mid at all: nothing to echo, so not bundled.
        let nameless = bundled("0 1", "1").replace("a=mid:1\r\n", "");
        assert!(!parse_video(&nameless).unwrap().bundled);
        // A plain section is never bundled.
        assert!(!parse_video(&offer(VIDEO)).unwrap().bundled);
    }

    #[test]
    fn a_browsers_offer_picks_the_rooms_payload_and_accepts_only_what_the_room_serves() {
        let offered = parse_video(&bundled("0 1", "1")).unwrap();
        // No format yet: the first carried H.264 payload fixes it.
        let first = choose_video(&offered, None).unwrap();
        assert_eq!(first.payload_type, 96);
        assert_eq!(
            first.feedback, ALL_FEEDBACK,
            "nack, pli and fir; not transport-cc or REMB"
        );
        assert!(first.bundled);
        assert_eq!(first.mid.as_deref(), Some("1"));
        // A room fixed to Constrained Baseline takes the payload that is one, with its own feedback.
        let room =
            RoomVideoFormat::from_fmtp("profile-level-id=42e01f;packetization-mode=1").unwrap();
        let chosen = choose_video(&offered, Some(&room)).unwrap();
        assert_eq!(chosen.payload_type, 98);
        assert_eq!(
            chosen.feedback,
            VideoFeedback {
                nack: true,
                pli: false,
                fir: false
            }
        );
    }

    #[test]
    fn a_browsers_video_on_a_transport_of_its_own_is_declined_naming_the_bundle() {
        let reason = choose_video(&parse_video(&bundled("0", "1")).unwrap(), None).unwrap_err();
        assert!(
            reason.contains("BUNDLE") && reason.contains("RFC 8843"),
            "{reason}"
        );
    }

    #[test]
    fn sdes_video_is_still_declined() {
        let sdes = bundled("0 1", "1").replace("UDP/TLS/RTP/SAVPF 96 98", "RTP/SAVP 96 98");
        let reason = choose_video(&parse_video(&sdes).unwrap(), None).unwrap_err();
        assert!(reason.contains("RTP/SAVP"), "{reason}");
    }

    #[test]
    fn the_answer_to_a_browser_is_written_on_the_audios_transport_and_whole() {
        let offer = bundled("0 1", "1");
        let choice = choose_video(
            &parse_video(&offer).unwrap(),
            Some(
                &RoomVideoFormat::from_fmtp("profile-level-id=42e01f;packetization-mode=1")
                    .unwrap(),
            ),
        )
        .unwrap();
        let own = OwnSsrc {
            ssrc: 77,
            cname: "room".to_string(),
        };
        // The answer as the audio pass wrote it: the engine's port and credentials in the audio
        // section, the browser's own video section still in place.
        let written = offer
            .replace("m=audio 9 ", "m=audio 30000 ")
            .replace(
                "c=IN IP4 0.0.0.0\r\na=mid:0",
                "c=IN IP4 198.51.100.7\r\na=mid:0",
            )
            .replace("abcd", "ENGU");
        let answered = anchor_video(
            &written,
            &VideoAnswer {
                engine: engine(),
                choice: &choice,
                bandwidth_kbps: Some(900),
                own: &own,
            },
        );
        // The offer signalled level asymmetry, so the answer echoes it (RFC 6184 §8.2.2).
        assert_eq!(
            choice.answer_fmtp.as_deref(),
            Some("profile-level-id=42e01f;packetization-mode=1;level-asymmetry-allowed=1")
        );
        let lines: Vec<&str> = answered.split("\r\n").collect();
        let video = lines
            .iter()
            .position(|line| line.starts_with("m=video"))
            .unwrap();
        assert_eq!(
            lines[video..],
            [
                "m=video 30000 UDP/TLS/RTP/SAVPF 98",
                "c=IN IP4 198.51.100.7",
                "b=AS:900",
                "a=mid:1",
                "a=ice-ufrag:ENGU",
                "a=ice-pwd:0123456789012345678901",
                &format!("a=fingerprint:sha-256 {}", "AA:".repeat(31) + "AA"),
                "a=setup:actpass",
                "a=rtpmap:98 H264/90000",
                &format!("a=fmtp:98 {}", choice.answer_fmtp.clone().unwrap()),
                "a=rtcp-fb:98 nack",
                "a=sendrecv",
                "a=rtcp-mux",
                "a=ssrc:77 cname:room",
                "",
            ]
        );
    }

    fn declined_pass(answer: &str) -> String {
        drop_declined_from_bundle(&answer.replace('\n', "\r\n").replace("\r\r", "\r"))
    }

    #[test]
    fn a_declined_section_leaves_the_bundle_group_and_a_live_or_bundle_only_one_stays() {
        let base =
            "v=0\ns=-\nt=0 0\na=group:BUNDLE 0 1 2\nm=audio 9 UDP/TLS/RTP/SAVPF 0\na=mid:0\n";
        let declined = declined_pass(&format!("{base}m=video 0 UDP/TLS/RTP/SAVPF 96\na=mid:1\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=mid:2\n"));
        assert!(declined.contains("a=group:BUNDLE 0 2\r\n"), "{declined}");
        // Port 0 with a=bundle-only is an accepted bundled section (RFC 8843 §6).
        let bundle_only = format!("{base}m=video 0 UDP/TLS/RTP/SAVPF 96\na=mid:1\na=bundle-only\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=mid:2\n");
        assert_eq!(
            declined_pass(&bundle_only),
            bundle_only.replace('\n', "\r\n")
        );
        // Nothing declined: returned as it came.
        let live = format!("{base}m=video 9 UDP/TLS/RTP/SAVPF 96\na=mid:1\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=mid:2\n");
        assert_eq!(declined_pass(&live), live.replace('\n', "\r\n"));
        // A group left with nothing in it is dropped.
        let alone = "v=0\ns=-\nt=0 0\na=group:BUNDLE 1\nm=video 0 UDP/TLS/RTP/SAVPF 96\na=mid:1\n";
        assert!(
            !declined_pass(alone).contains("a=group"),
            "{}",
            declined_pass(alone)
        );
    }

    /// A one-payload H.264 video section on `transport`, with `extra` lines before the direction.
    fn on_transport(transport: &str, extra: &str) -> String {
        offer(&format!(
            "m=video 20200 {transport} 99\r\nc=IN IP4 192.0.2.11\r\na=rtpmap:99 H264/90000\r\n\
             a=fmtp:99 profile-level-id=640c1f;packetization-mode=1\r\n\
             a=rtcp-fb:99 nack\r\na=rtcp-fb:99 nack pli\r\na=rtcp-fb:99 ccm fir\r\n{extra}a=sendrecv\r\na=rtcp-mux\r\n"
        ))
    }

    #[test]
    fn a_preserve_room_carries_srtp_video_with_no_key_of_the_engines() {
        for (transport, feedback) in [
            ("RTP/SAVP", VideoFeedback::default()),
            ("RTP/SAVPF", ALL_FEEDBACK),
            ("RTP/AVP", VideoFeedback::default()),
            ("RTP/AVPF", ALL_FEEDBACK),
        ] {
            let offered = parse_video(&on_transport(transport, "")).unwrap();
            let choice = choose_preserved_video(&offered, None).unwrap();
            assert_eq!(
                choice.transport, transport,
                "the answer keeps the offer's transport"
            );
            assert_eq!(choice.feedback, feedback, "{transport}");
            assert!(!choice.bundled);
            // A translating room still refuses the secure ones: it would have to terminate them.
            let translate = choose_video(&offered, None);
            assert_eq!(
                translate.is_ok(),
                !transport.contains("SAVP"),
                "{transport}"
            );
        }
    }

    #[test]
    fn a_preserve_room_refuses_video_the_engine_would_have_to_key() {
        // SDES: the engine would hold a key for media the room forwards end to end.
        let crypto = on_transport(
            "RTP/SAVP",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd\r\n",
        );
        let reason = choose_preserved_video(&parse_video(&crypto).unwrap(), None).unwrap_err();
        assert!(reason.contains("a=crypto"), "{reason}");
        // DTLS-SRTP, with the fingerprint at the section or the session.
        let fingerprint = on_transport("RTP/SAVPF", "a=fingerprint:sha-256 AA:BB\r\n");
        let reason = choose_preserved_video(&parse_video(&fingerprint).unwrap(), None).unwrap_err();
        assert!(reason.contains("a=fingerprint"), "{reason}");
        let session = format!(
            "v=0\r\na=fingerprint:sha-256 AA:BB\r\n{}",
            on_transport("RTP/SAVPF", "").replacen("v=0\r\n", "", 1)
        );
        assert!(choose_preserved_video(&parse_video(&session).unwrap(), None).is_err());
        // A browser's transport, and any video that shares the audio's.
        let webrtc = on_transport("UDP/TLS/RTP/SAVPF", "");
        let reason = choose_preserved_video(&parse_video(&webrtc).unwrap(), None).unwrap_err();
        assert!(reason.contains("UDP/TLS/RTP/SAVPF"), "{reason}");
        let mut bundled = parse_video(&on_transport("RTP/SAVPF", "")).unwrap();
        bundled.bundled = true;
        let reason = choose_preserved_video(&bundled, None).unwrap_err();
        assert!(reason.contains("BUNDLE"), "{reason}");
    }

    #[test]
    fn a_preserve_room_answers_the_offered_transport_and_its_feedback() {
        let sdp = on_transport("RTP/SAVPF", "");
        let choice = choose_preserved_video(&parse_video(&sdp).unwrap(), None).unwrap();
        let answer = anchor_video(
            &sdp,
            &VideoAnswer {
                engine: engine(),
                choice: &choice,
                bandwidth_kbps: None,
                own: &OwnSsrc {
                    ssrc: 77,
                    cname: "room".to_string(),
                },
            },
        );
        let section = answer.split("m=video").nth(1).unwrap();
        assert!(section.starts_with(" 30004 RTP/SAVPF 99\r\n"), "{section}");
        for line in [
            "a=rtcp-fb:99 nack\r\n",
            "a=rtcp-fb:99 nack pli\r\n",
            "a=rtcp-fb:99 ccm fir\r\n",
        ] {
            assert!(section.contains(line), "{line}: {section}");
        }
        assert!(!section.contains("a=crypto") && !section.contains("a=fingerprint"));
    }

    #[test]
    fn a_member_that_answers_a_preserve_offer_keeps_the_offered_secure_transport() {
        let answer = on_transport("RTP/SAVPF", "");
        let choice = choose_answered_preserved_video(&parse_video(&answer).unwrap(), None).unwrap();
        assert_eq!(choice.transport, "RTP/SAVPF");
        assert_eq!(choice.feedback, ALL_FEEDBACK);
        let keyed = on_transport("RTP/SAVPF", "a=crypto:1 X inline:Y\r\n");
        assert!(choose_answered_preserved_video(&parse_video(&keyed).unwrap(), None).is_err());
    }

    #[test]
    fn the_offer_of_a_preserve_room_is_savpf_when_keyed_by_the_ues_and_names_the_rooms_payload_type(
    ) {
        let secure =
            video_offer_section(30004, "198.51.100.7".parse().unwrap(), None, None, 99, true);
        assert!(
            secure.starts_with("m=video 30004 RTP/SAVPF 99\r\n"),
            "{secure}"
        );
        assert!(secure.contains("a=rtpmap:99 H264/90000\r\n"));
        assert!(secure.contains("a=rtcp-fb:99 nack pli\r\n"));
        assert!(!secure.contains("a=crypto"));
        let plain = video_offer_section(
            30004,
            "198.51.100.7".parse().unwrap(),
            None,
            None,
            126,
            false,
        );
        assert!(
            plain.starts_with("m=video 30004 RTP/AVPF 126\r\n"),
            "{plain}"
        );
    }
}
