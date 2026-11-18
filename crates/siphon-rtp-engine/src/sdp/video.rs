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

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use super::floor::split_lines;
use super::{addrtype, parse_connection_addr, EngineMedia, MediaDirection, OwnSsrc, CRLF};

/// The RTP clock of video: 90 kHz (RFC 6184 §8.2.1 for H.264, RFC 3551 §5 for video in general).
pub const VIDEO_CLOCK_RATE_HZ: u32 = 90_000;

/// The payload type a `forward_offer` gives its H.264 stream: dynamic (RFC 3551 §6), and outside the
/// range the audio candidates use, so the offer never lists one number in two sections.
pub const OFFER_PAYLOAD_TYPE: u8 = 126;

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

/// Decide whether `offer` fits the room: the seat's own payload type for the room's format.
///
/// `fixed` is the format already in force: the room's, or the controller's `video.fmtp`. With none,
/// the first H.264 payload carrying a mode the room carries fixes it (RFC 3264 §6.1 order).
///
/// # Errors
/// The reason the seat's video is declined and it joins audio-only: a transport the engine does not
/// carry video on, no H.264/90000 payload, only a packetization mode it does not carry, or a
/// `profile-level-id` or mode other than the room's.
pub fn choose_video(
    offer: &VideoOffer,
    fixed: Option<&RoomVideoFormat>,
) -> Result<VideoChoice, String> {
    // RFC 3264 §6: the answer keeps the offer's transport. SRTP, SDES and DTLS video are not carried
    // yet, and a plain answer to one would send the seat video it cannot decrypt.
    if !["RTP/AVP", "RTP/AVPF"]
        .iter()
        .any(|carried| offer.transport.eq_ignore_ascii_case(carried))
    {
        return Err(format!(
            "video over {} is not carried yet (plain RTP/AVP and RTP/AVPF only)",
            offer.transport
        ));
    }
    let feedback_of = |payload_type: u8| {
        if offer.transport.eq_ignore_ascii_case("RTP/AVPF") {
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
    let h264: Vec<(u8, u8, Option<String>)> = offer
        .payloads
        .iter()
        .filter(|payload| {
            payload.encoding.as_ref().is_some_and(|(name, clock)| {
                name.eq_ignore_ascii_case("H264") && *clock == VIDEO_CLOCK_RATE_HZ
            })
        })
        .map(|payload| {
            let parameters = payload.fmtp.as_deref().unwrap_or_default();
            (
                payload.payload_type,
                packetization_mode(parameters),
                profile_level_id(parameters),
            )
        })
        .collect();
    if h264.is_empty() {
        return Err(
            "the offer has no H264/90000 video payload (RFC 6184); the room carries H.264 only"
                .to_string(),
        );
    }
    let carried: Vec<&(u8, u8, Option<String>)> = h264
        .iter()
        .filter(|(_, mode, _)| CARRIED_MODES.contains(mode))
        .collect();
    let Some(first) = carried.first() else {
        return Err(format!(
            "only H264 packetization-mode {} is offered; the room carries modes 0 and 1",
            h264[0].1
        ));
    };
    let (payload_type, format) = match fixed {
        Some(room) => {
            let matching = carried.iter().find(|(_, mode, level)| {
                *mode == room.packetization_mode && *level == room.profile_level_id
            });
            let Some((payload_type, _, _)) = matching else {
                return Err(format!(
                    "the room's video is H264 packetization-mode {} with {}, which the seat did not offer",
                    room.packetization_mode,
                    room.profile_level_id.as_deref().map_or_else(
                        || "no profile-level-id".to_string(),
                        |level| format!("profile-level-id {level}")
                    ),
                ));
            };
            (*payload_type, room.clone())
        }
        None => (
            first.0,
            RoomVideoFormat::of_payload(first.1, first.2.clone()),
        ),
    };
    Ok(VideoChoice {
        remote: offer.remote,
        transport: offer.transport.clone(),
        direction: offer.direction,
        rtcp_mux: offer.rtcp_mux,
        payload_type,
        format,
        feedback: feedback_of(payload_type),
    })
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
    // header extensions, RFC 3550 §5.3.1), its `sprop-parameter-sets`, its other codecs.
    let mut section = vec![
        format!(
            "m=video {} {} {payload_type}",
            answer.engine.rtp.port(),
            choice.transport
        ),
        format!("c=IN {} {advertised}", addrtype(advertised)),
    ];
    if let Some(kbps) = answer.bandwidth_kbps {
        section.push(format!("b=AS:{kbps}"));
    }
    section.push(format!(
        "a=rtpmap:{payload_type} H264/{VIDEO_CLOCK_RATE_HZ}"
    ));
    if let Some(parameters) = choice.format.fmtp.as_deref() {
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

/// The video section of an offer the engine writes (a `forward_offer`).
#[must_use]
pub fn video_offer_section(
    rtp_port: u16,
    advertised: IpAddr,
    fmtp: Option<&str>,
    bandwidth_kbps: Option<u32>,
) -> String {
    let mut section = format!(
        "m=video {rtp_port} RTP/AVPF {OFFER_PAYLOAD_TYPE}{CRLF}c=IN {} {advertised}{CRLF}",
        addrtype(advertised)
    );
    if let Some(kbps) = bandwidth_kbps {
        let _ = write!(section, "b=AS:{kbps}{CRLF}");
    }
    let _ = write!(
        section,
        "a=rtpmap:{OFFER_PAYLOAD_TYPE} H264/{VIDEO_CLOCK_RATE_HZ}{CRLF}"
    );
    if let Some(parameters) = fmtp.filter(|parameters| !parameters.is_empty()) {
        let _ = write!(section, "a=fmtp:{OFFER_PAYLOAD_TYPE} {parameters}{CRLF}");
    }
    // RFC 4585 §4.2: everything the room supports, so the member's answer can accept any of it.
    for line in VideoFeedback::SUPPORTED.lines(OFFER_PAYLOAD_TYPE) {
        let _ = write!(section, "{line}{CRLF}");
    }
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
        let v6 = video_offer_section(30004, "2001:db8::7".parse().unwrap(), None, None);
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
        let section = video_offer_section(30004, "198.51.100.7".parse().unwrap(), None, None);
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
}
