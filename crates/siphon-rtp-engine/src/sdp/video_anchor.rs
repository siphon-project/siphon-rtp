//! A two-party call's `m=video` stream, anchored like its audio one (RFC 3264 §6, RFC 3550 §11): the
//! stream's rewrite pass, its direction rules, and the connection line a passed-through section keeps.
//!
//! [`super::rewrite`] points the session `c=` at the engine for the audio stream. A video section
//! with no `c=` of its own inherits the session one (RFC 4566 §5.7), so it would read the engine's
//! address with the phone's own port. [`keep_passthrough_connection`] gives such a section the
//! offerer's original connection line, a separate pass over the finished SDP as the floor and
//! forwarding-room video passes are, so the audio rewrite is untouched.

use std::net::SocketAddr;

use super::floor::split_lines;
use super::{addrtype, parse_connection_addr, EngineMedia, MediaDirection, CRLF};

/// Whether `line` is a live (non-zero port) video `m=` line.
fn is_live_video(line: &str) -> bool {
    let mut fields = line
        .strip_prefix("m=")
        .unwrap_or_default()
        .split_whitespace();
    fields.next() == Some("video")
        && fields
            .next()
            .and_then(|field| field.split('/').next())
            .and_then(|field| field.parse::<u16>().ok())
            .is_some_and(|port| port != 0)
}

/// The session-level `c=` address of `lines` (before the first `m=`).
fn session_connection(lines: &[&str]) -> Option<std::net::IpAddr> {
    lines
        .iter()
        .take_while(|line| !line.starts_with("m="))
        .find_map(|line| parse_connection_addr(line.strip_prefix("c=")?))
}

/// The `m=` line indices of the live video sections of `lines` with no `c=` of their own.
fn inheriting_video_sections(lines: &[&str]) -> Vec<usize> {
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("m="))
        .map(|(index, _)| index)
        .collect();
    starts
        .iter()
        .enumerate()
        .filter(|(position, start)| {
            let end = starts.get(position + 1).copied().unwrap_or(lines.len());
            is_live_video(lines[**start])
                && !lines[**start..end].iter().any(|l| l.starts_with("c="))
        })
        .map(|(_, start)| *start)
        .collect()
}

/// `rewritten` (`original` after [`super::rewrite`]) with every live `m=video` section that has no
/// `c=` of its own given `original`'s session connection address. The line goes behind the
/// section's `i=` (RFC 4566 §5 order). Nothing changes when `original` has no session address or no
/// video section inherits it.
#[must_use]
pub fn keep_passthrough_connection(original: &str, rewritten: &str) -> String {
    let original_lines = split_lines(original);
    let lines = split_lines(rewritten);
    let Some(address) = session_connection(&original_lines) else {
        return rewritten.to_string();
    };
    let inheriting = inheriting_video_sections(&lines);
    if inheriting.is_empty() {
        return rewritten.to_string();
    }
    let connection = format!("c=IN {} {address}", addrtype(address));
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + inheriting.len());
    let mut pending = false;
    for (index, line) in lines.iter().enumerate() {
        if pending && !line.starts_with("i=") {
            out.push(connection.clone());
            pending = false;
        }
        pending = pending || inheriting.contains(&index);
        out.push((*line).to_string());
    }
    if pending {
        out.push(connection);
    }
    out.join(CRLF)
}

/// What the engine reads of the first live `m=video` section of an SDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoStream {
    /// Where the party receives RTP: the section's `c=` (else the session's) and the `m=` port.
    pub remote_rtp: SocketAddr,
    /// Where the party receives RTCP: the `a=rtcp` port (RFC 3605) when stated, else the RTP port
    /// (RFC 5761 §5.1.1) under `a=rtcp-mux`, else the RTP port + 1 (RFC 3550 §11).
    pub remote_rtcp: SocketAddr,
    /// The party's own direction for the stream (RFC 3264 §6.1); absent means `sendrecv`.
    pub direction: MediaDirection,
    /// The stream offers `a=rtcp-mux` (RFC 5761).
    pub rtcp_mux: bool,
    /// The transport profile, third field of the `m=` line.
    pub transport: String,
}

impl VideoStream {
    /// Whether the engine carries this transport: plain RTP (`RTP/AVP`, `RTP/AVPF`). A secure
    /// profile is declined until the engine keys video per leg, never relayed through unkeyed.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        matches!(
            self.transport.to_ascii_uppercase().as_str(),
            "RTP/AVP" | "RTP/AVPF"
        )
    }
}

/// Whether `direction` lets its party send.
#[must_use]
pub fn sends(direction: MediaDirection) -> bool {
    matches!(
        direction,
        MediaDirection::SendRecv | MediaDirection::SendOnly
    )
}

/// Whether `direction` lets its party receive.
#[must_use]
pub fn receives(direction: MediaDirection) -> bool {
    matches!(
        direction,
        MediaDirection::SendRecv | MediaDirection::RecvOnly
    )
}

/// Which way video may flow between two parties, from each one's own stated direction (RFC 3264
/// §6.1, §8.4): near to far needs the near party to send and the far one to receive, and the other
/// way round. Returns `(near_to_far, far_to_near)`.
#[must_use]
pub fn flow_directions(near: MediaDirection, far: MediaDirection) -> (bool, bool) {
    (sends(near) && receives(far), sends(far) && receives(near))
}

/// The first live (non-zero port) video section: `m=` line index, exclusive end, port.
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

/// Whether the SDP has an `m=video` line at all, live or declined.
#[must_use]
pub fn offers_video(sdp: &str) -> bool {
    split_lines(sdp)
        .iter()
        .any(|line| line.starts_with("m=video "))
}

/// The first live video section of `sdp`, or `None` when there is none or every one is at port 0.
#[must_use]
pub fn parse_video_stream(sdp: &str) -> Option<VideoStream> {
    let lines = split_lines(sdp);
    let (start, end, port) = locate(&lines)?;
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(0);
    let connection = |range: std::ops::Range<usize>| {
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
    let rtcp_mux = section.contains(&"a=rtcp-mux");
    let rtcp_port = section.iter().find_map(|line| {
        line.strip_prefix("a=rtcp:")?
            .split_whitespace()
            .next()?
            .parse::<u16>()
            .ok()
    });
    let rtcp_port = if rtcp_mux {
        port
    } else {
        rtcp_port.unwrap_or_else(|| port.saturating_add(1))
    };
    let transport = lines[start]
        .strip_prefix("m=")?
        .split_whitespace()
        .nth(2)?
        .to_string();
    Some(VideoStream {
        remote_rtp: SocketAddr::new(address, port),
        remote_rtcp: SocketAddr::new(address, rtcp_port),
        direction,
        rtcp_mux,
        transport,
    })
}

/// How a presented SDP treats its video stream, beside [`super::TextRewrite`] and
/// [`super::ImageRewrite`].
#[derive(Debug, Clone, Copy, Default)]
pub enum VideoRewrite {
    /// Leave the section as it arrived (the two parties exchange video directly).
    #[default]
    Passthrough,
    /// Anchor the first live video section on the engine's video endpoints; any further live video
    /// section is declined (RFC 3264 §6).
    Anchor(EngineMedia),
    /// Decline every live video section (port 0, RFC 3264 §6).
    Decline,
}

impl VideoRewrite {
    /// Apply the directive to a presented SDP.
    #[must_use]
    pub fn apply(self, presented: &str) -> String {
        match self {
            Self::Passthrough => presented.to_string(),
            Self::Anchor(engine) => anchor_video(presented, engine),
            Self::Decline => decline_video(presented),
        }
    }
}

/// `line`, an `m=` line, with its port field replaced.
fn with_port(line: &str, port: u16) -> String {
    line.split(' ')
        .enumerate()
        .map(|(position, field)| {
            if position == 1 {
                port.to_string()
            } else {
                field.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decline every live video section.
#[must_use]
pub fn decline_video(sdp: &str) -> String {
    let lines = split_lines(sdp);
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for line in &lines {
        if is_live_video(line) {
            out.push(with_port(line, 0));
        } else {
            out.push((*line).to_string());
        }
    }
    out.join(CRLF)
}

/// An ICE or key attribute of the peer's own, which never describes an engine endpoint.
fn is_peer_transport_attribute(line: &str) -> bool {
    line.starts_with("a=candidate:")
        || line.starts_with("a=ice-")
        || line == "a=end-of-candidates"
        || line.starts_with("a=remote-candidates")
}

/// Anchor the first live video section on `engine`: its port, a media-level `c=` of the engine's
/// advertised address (RFC 4566 §5.7), and the `a=rtcp` port (RFC 3605) unless muxed. Every other
/// line, the codecs, `fmtp`, `rtcp-fb` and the direction included, is copied verbatim. A further
/// live video section is declined.
#[must_use]
pub fn anchor_video(sdp: &str, engine: EngineMedia) -> String {
    let lines = split_lines(sdp);
    let first = locate(&lines);
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 3);
    let mut in_anchored = false;
    let mut pending_connection = false;
    let flush_connection = |out: &mut Vec<String>| {
        out.push(format!(
            "c=IN {} {}",
            addrtype(engine.advertised_ip),
            engine.advertised_ip
        ));
    };
    let finish_section = |out: &mut Vec<String>, pending: &mut bool| {
        if *pending {
            flush_connection(out);
            *pending = false;
        }
        if let Some(rtcp) = engine.rtcp {
            if engine.rtp.port().checked_add(1) != Some(rtcp.port()) {
                out.push(format!("a=rtcp:{}", rtcp.port()));
            }
        }
    };
    for (index, line) in lines.iter().enumerate() {
        if line.starts_with("m=") {
            if in_anchored {
                finish_section(&mut out, &mut pending_connection);
                in_anchored = false;
            }
            if Some(index) == first.map(|(start, _, _)| start) {
                in_anchored = true;
                pending_connection = true;
                out.push(with_port(line, engine.rtp.port()));
            } else if is_live_video(line) {
                out.push(with_port(line, 0));
            } else {
                out.push((*line).to_string());
            }
            continue;
        }
        if in_anchored {
            if pending_connection && !line.starts_with("i=") {
                flush_connection(&mut out);
                pending_connection = false;
            }
            if line.starts_with("c=")
                || line.starts_with("a=rtcp:")
                || is_peer_transport_attribute(line)
            {
                continue;
            }
        }
        // An empty trailing element is the SDP's final line break; keep it.
        out.push((*line).to_string());
    }
    if in_anchored {
        // The last section: its closing lines go before the SDP's trailing empty element.
        let trailing_empty = out.last().is_some_and(String::is_empty);
        if trailing_empty {
            out.pop();
        }
        finish_section(&mut out, &mut pending_connection);
        if trailing_empty {
            out.push(String::new());
        }
    }
    out.join(CRLF)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 20100 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "m=video 6000 RTP/AVPF 96\r\n",
        "c=IN IP4 192.0.2.11\r\n",
        "a=rtpmap:96 H264/90000\r\n",
        "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\n",
        "a=rtcp-fb:96 nack pli\r\n",
        "a=rtcp:6005\r\n",
        "a=sendonly\r\n",
    );

    fn engine(rtcp: Option<u16>) -> EngineMedia {
        EngineMedia::new(
            "198.51.100.5:30000".parse().expect("addr"),
            rtcp.map(|port| SocketAddr::from(([198, 51, 100, 5], port))),
        )
    }

    fn video_lines(sdp: &str) -> Vec<String> {
        sdp.split("\r\n")
            .skip_while(|line| !line.starts_with("m=video"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn parses_the_stream_address_rtcp_port_and_direction() {
        let stream = parse_video_stream(OFFER).expect("video");
        assert_eq!(
            stream.remote_rtp,
            "192.0.2.11:6000".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(
            stream.remote_rtcp,
            "192.0.2.11:6005".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(stream.direction, MediaDirection::SendOnly);
        assert!(!stream.rtcp_mux);
        assert!(stream.is_plain());
    }

    #[test]
    fn rtcp_defaults_to_the_next_port_and_to_the_rtp_port_under_mux() {
        let plain = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 7000 RTP/AVP 96\r\n";
        let stream = parse_video_stream(plain).expect("video");
        assert_eq!(stream.remote_rtcp.port(), 7001);
        let muxed = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 7000 RTP/AVP 96\r\na=rtcp-mux\r\n";
        assert_eq!(
            parse_video_stream(muxed).expect("video").remote_rtcp.port(),
            7000
        );
    }

    #[test]
    fn a_secure_profile_is_not_plain_and_a_declined_section_is_not_live() {
        let secure = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 7000 RTP/SAVP 96\r\n";
        assert!(!parse_video_stream(secure).expect("video").is_plain());
        let declined = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 0 RTP/AVP 96\r\n";
        assert!(parse_video_stream(declined).is_none());
        assert!(offers_video(declined));
    }

    #[test]
    fn anchoring_moves_port_connection_and_rtcp_and_keeps_the_rest_verbatim() {
        let anchored = anchor_video(OFFER, engine(Some(30003)));
        assert_eq!(
            video_lines(&anchored),
            vec![
                "m=video 30000 RTP/AVPF 96",
                "c=IN IP4 198.51.100.5",
                "a=rtpmap:96 H264/90000",
                "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1",
                "a=rtcp-fb:96 nack pli",
                "a=sendonly",
                "a=rtcp:30003",
                "",
            ],
            "{anchored}"
        );
        assert!(
            anchored.contains("m=audio 20100 RTP/AVP 0"),
            "audio untouched"
        );
        assert!(
            anchored.contains("c=IN IP4 192.0.2.10"),
            "session c= untouched"
        );
    }

    #[test]
    fn anchoring_a_muxed_stream_writes_no_rtcp_line_and_an_adjacent_port_needs_none() {
        let muxed = anchor_video(OFFER, engine(None));
        assert!(!video_lines(&muxed)
            .iter()
            .any(|line| line.starts_with("a=rtcp:")));
        let adjacent = anchor_video(OFFER, engine(Some(30001)));
        assert!(!video_lines(&adjacent)
            .iter()
            .any(|line| line.starts_with("a=rtcp:")));
    }

    #[test]
    fn anchoring_inherits_nothing_when_the_section_has_no_connection_of_its_own() {
        let sdp = concat!(
            "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "m=video 6000 RTP/AVP 96\r\ni=door\r\na=rtpmap:96 H264/90000\r\n",
        );
        let anchored = anchor_video(sdp, engine(None));
        assert_eq!(
            video_lines(&anchored),
            vec![
                "m=video 30000 RTP/AVP 96",
                "i=door",
                "c=IN IP4 198.51.100.5",
                "a=rtpmap:96 H264/90000",
                "",
            ]
        );
    }

    #[test]
    fn anchoring_drops_the_peers_ice_lines_and_declines_a_second_video_section() {
        let sdp = concat!(
            "v=0\r\nc=IN IP4 192.0.2.10\r\n",
            "m=video 6000 RTP/AVP 96\r\na=ice-ufrag:abcd\r\na=candidate:1 1 udp 1 192.0.2.10 6000 typ host\r\n",
            "a=rtpmap:96 H264/90000\r\n",
            "m=video 6002 RTP/AVP 97\r\na=rtpmap:97 VP8/90000\r\n",
        );
        let anchored = anchor_video(sdp, engine(None));
        assert!(!anchored.contains("ice-ufrag") && !anchored.contains("candidate"));
        assert!(anchored.contains("m=video 0 RTP/AVP 97"), "{anchored}");
    }

    #[test]
    fn declining_zeroes_every_live_video_section_and_keeps_the_formats() {
        let declined = decline_video(OFFER);
        assert!(declined.contains("m=video 0 RTP/AVPF 96"), "{declined}");
        assert!(declined.contains("m=audio 20100 RTP/AVP 0"));
    }

    #[test]
    fn passthrough_returns_the_sdp_unchanged() {
        assert_eq!(VideoRewrite::Passthrough.apply(OFFER), OFFER);
    }

    #[test]
    fn a_door_station_stream_flows_one_way_only() {
        // A sendonly camera answered recvonly: only the camera's direction forwards.
        assert_eq!(
            flow_directions(MediaDirection::SendOnly, MediaDirection::RecvOnly),
            (true, false)
        );
        assert_eq!(
            flow_directions(MediaDirection::SendRecv, MediaDirection::SendRecv),
            (true, true)
        );
        assert_eq!(
            flow_directions(MediaDirection::SendRecv, MediaDirection::Inactive),
            (false, false)
        );
        assert_eq!(
            flow_directions(MediaDirection::RecvOnly, MediaDirection::SendOnly),
            (false, true)
        );
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;

    const ORIGINAL: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 20100 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "m=video 6000 RTP/AVP 96\r\n",
        "i=door camera\r\n",
        "a=rtpmap:96 H264/90000\r\n",
        "a=sendonly\r\n",
    );

    fn engine_pointed(sdp: &str) -> String {
        sdp.replace("c=IN IP4 192.0.2.10", "c=IN IP4 198.51.100.5")
    }

    #[test]
    fn a_video_section_with_no_connection_keeps_the_original_one_behind_its_i_line() {
        let kept = keep_passthrough_connection(ORIGINAL, &engine_pointed(ORIGINAL));
        let section: Vec<&str> = kept
            .split("\r\n")
            .skip_while(|line| !line.starts_with("m=video"))
            .collect();
        assert_eq!(
            section,
            vec![
                "m=video 6000 RTP/AVP 96",
                "i=door camera",
                "c=IN IP4 192.0.2.10",
                "a=rtpmap:96 H264/90000",
                "a=sendonly",
                "",
            ],
            "{kept}"
        );
        assert!(
            kept.contains("c=IN IP4 198.51.100.5"),
            "audio stays anchored"
        );
    }

    #[test]
    fn a_video_section_with_its_own_connection_is_left_alone() {
        let own = ORIGINAL.replace(
            "i=door camera\r\n",
            "i=door camera\r\nc=IN IP4 192.0.2.77\r\n",
        );
        let rewritten = engine_pointed(&own);
        assert_eq!(keep_passthrough_connection(&own, &rewritten), rewritten);
    }

    #[test]
    fn nothing_changes_when_the_section_is_declined_or_there_is_no_session_address() {
        let no_session = ORIGINAL.replace("c=IN IP4 192.0.2.10\r\n", "");
        assert_eq!(
            keep_passthrough_connection(&no_session, &no_session),
            no_session
        );
        let declined = ORIGINAL.replace("m=video 6000", "m=video 0");
        let rewritten = engine_pointed(&declined);
        assert_eq!(
            keep_passthrough_connection(&declined, &rewritten),
            rewritten
        );
    }
}
