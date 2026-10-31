//! The MCPTT floor-control stream: `m=application <port> udp MCPTT` (3GPP TS 24.379 / TS 24.380).
//!
//! The floor stream carries only RTCP APP packets (TS 24.380 §8), so unlike audio there is nothing
//! to transcode, nothing to key (the stream is plain in this build) and no payload type to rewrite.
//! The engine terminates it: this module reads the offered section's transport and writes the
//! answer's, anchored on an engine endpoint with the controller's `a=fmtp:MCPTT` line.
//!
//! Kept apart from [`super::rewrite`], which scopes its edits by the media kinds it scans for audio,
//! text and image: the floor section is an `Other` section to it and is copied through, and this
//! pass then re-originates it on the finished answer.

use std::net::{IpAddr, SocketAddr};

use super::{addrtype, parse_connection_addr, rewrite_media_line, EngineMedia, CRLF};

/// The format token of the floor-control media line (TS 24.380 §14, the example SDP).
const FLOOR_FORMAT: &str = "MCPTT";

/// Why a floor `a=fmtp` could not be put into an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FloorFmtpError {
    /// The parameters carry a CR or LF, which would end the SDP line and let the controller's text
    /// inject further lines.
    #[error("floor_fmtp must not contain a line break")]
    LineBreak,
}

/// Check the controller's `floor_fmtp` before anything is allocated for it.
///
/// # Errors
/// [`FloorFmtpError::LineBreak`] when it contains CR or LF.
pub fn validate_floor_fmtp(fmtp: &str) -> Result<(), FloorFmtpError> {
    if fmtp.contains(['\r', '\n']) {
        Err(FloorFmtpError::LineBreak)
    } else {
        Ok(())
    }
}

/// The floor stream an SDP offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorMediaInfo {
    /// Where the peer sends and receives floor control: its media-level `c=` (else the session `c=`)
    /// with the `m=application` port.
    pub remote: SocketAddr,
}

/// Whether the body of an `m=` line (after `m=`) is the floor-control stream, whatever its port:
/// `application <port> udp MCPTT`. The transport token is matched case-insensitively (RFC 4566 §5.14
/// leaves its case open); the format is the literal `MCPTT` of TS 24.380 §14.
pub(super) fn is_floor_media_line(value: &str) -> bool {
    let mut fields = value.split_whitespace();
    fields.next() == Some("application")
        && fields.next().is_some()
        && fields
            .next()
            .is_some_and(|transport| transport.eq_ignore_ascii_case("udp"))
        && fields.next() == Some(FLOOR_FORMAT)
}

/// The SDP split into lines with their CRs removed.
fn split_lines(sdp: &str) -> Vec<&str> {
    sdp.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

/// Where the first live floor section is: the line index of its `m=` line, the exclusive end of its
/// section, and its port. A section at port 0 was declined by its offerer and is not live.
fn locate(lines: &[&str]) -> Option<(usize, usize, u16)> {
    let mut found: Option<(usize, u16)> = None;
    for (index, line) in lines.iter().enumerate() {
        let Some(value) = line.strip_prefix("m=") else {
            continue;
        };
        if let Some((start, port)) = found {
            return Some((start, index, port));
        }
        if is_floor_media_line(value) {
            found = value
                .split_whitespace()
                .nth(1)
                .and_then(|field| field.parse::<u16>().ok())
                .filter(|port| *port != 0)
                .map(|port| (index, port));
        }
    }
    found.map(|(start, port)| (start, lines.len(), port))
}

/// The floor stream `sdp` offers, if it offers a live one the engine can answer: the first
/// `m=application … udp MCPTT` section with a non-zero port and a connection address.
#[must_use]
pub fn parse_floor(sdp: &str) -> Option<FloorMediaInfo> {
    let lines = split_lines(sdp);
    let (start, end, port) = locate(&lines)?;
    let connection = |range: std::ops::Range<usize>| -> Option<IpAddr> {
        lines[range]
            .iter()
            .find_map(|line| parse_connection_addr(line.strip_prefix("c=")?))
    };
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(0);
    let address = connection(start + 1..end).or_else(|| connection(0..first_media))?;
    Some(FloorMediaInfo {
        remote: SocketAddr::new(address, port),
    })
}

/// Anchor the first live floor section of an answer on `engine` (TS 24.380 §14.3.1: the answerer
/// includes a media description for the media plane control channel).
///
/// The port becomes `engine.rtp`'s, the transport (`udp`) and format (`MCPTT`) stay as offered, and
/// the section gets its own media-level `c=` with the engine's advertised address (RFC 4566 §5.7),
/// so the offerer's private address is never echoed whichever level its own `c=` was at. The
/// offerer's own `a=fmtp:MCPTT` is dropped (an answer states the answerer's capabilities, §14.3.1),
/// and `fmtp` is written in its place, verbatim, as `a=fmtp:MCPTT <fmtp>`; `None` (or an empty
/// string) writes none. Every other attribute is copied as it came. An answer without a floor
/// section is returned unchanged.
#[must_use]
pub fn anchor_floor(sdp: &str, engine: EngineMedia, fmtp: Option<&str>) -> String {
    let lines = split_lines(sdp);
    let Some((start, end, _)) = locate(&lines) else {
        return sdp.to_string();
    };
    let mut out: Vec<String> = lines[..start]
        .iter()
        .map(|line| (*line).to_string())
        .collect();
    out.push(rewrite_media_line(lines[start], engine.rtp.port(), None));
    let mut body: Vec<&str> = lines[start + 1..end].to_vec();
    // The last element of an SDP that ends in CRLF is the empty remainder: it stays last.
    let mut trailing = 0;
    if end == lines.len() {
        while body.last().is_some_and(|line| line.is_empty()) {
            body.pop();
            trailing += 1;
        }
    }
    // RFC 4566 §5 order: `i=`, then `c=`, then the rest.
    let information = body
        .iter()
        .take_while(|line| line.starts_with("i="))
        .count();
    out.extend(body[..information].iter().map(|line| (*line).to_string()));
    out.push(format!(
        "c=IN {} {}",
        addrtype(engine.advertised_ip),
        engine.advertised_ip
    ));
    let rest: Vec<&str> = body[information..]
        .iter()
        .copied()
        .filter(|line| !line.starts_with("c=") && !is_floor_fmtp(line))
        .collect();
    let fmtp_line = fmtp
        .filter(|parameters| !parameters.is_empty())
        .map(|parameters| format!("a=fmtp:{FLOOR_FORMAT} {parameters}"));
    let at = rest
        .iter()
        .position(|line| line.starts_with("a="))
        .unwrap_or(rest.len());
    out.extend(rest[..at].iter().map(|line| (*line).to_string()));
    out.extend(fmtp_line);
    out.extend(rest[at..].iter().map(|line| (*line).to_string()));
    out.extend(std::iter::repeat_n(String::new(), trailing));
    out.extend(lines[end..].iter().map(|line| (*line).to_string()));
    out.join(CRLF)
}

/// How a presented SDP treats its MCPTT floor-control section, beside [`super::TextRewrite`] and
/// [`super::ImageRewrite`]. There is no pass-through: an unanchored section would hand the other party
/// the offerer's own, often private, floor address, so the section is anchored or declined.
#[derive(Debug, Clone, Copy)]
pub enum FloorRewrite<'a> {
    /// Anchor the section on the engine's floor endpoint, with `a=fmtp:MCPTT <fmtp>` ([`anchor_floor`]).
    Anchor {
        /// The engine floor endpoint and the address advertised for it.
        engine: EngineMedia,
        /// The controller's floor parameters, verbatim.
        fmtp: Option<&'a str>,
    },
    /// The leg has no floor endpoint: decline the section ([`decline_floor`]).
    Decline,
}

impl FloorRewrite<'_> {
    /// Apply the directive to a presented SDP.
    #[must_use]
    pub fn apply(self, presented: &str) -> String {
        match self {
            Self::Anchor { engine, fmtp } => anchor_floor(presented, engine, fmtp),
            Self::Decline => decline_floor(presented),
        }
    }
}

/// Decline every live floor section of `sdp` (port 0, RFC 3264 §6), for a section the engine cannot
/// anchor, such as one a party adds mid-call to a leg that has no floor endpoint. Passing it through
/// instead would hand the other party the offerer's own, often private, floor address.
#[must_use]
pub fn decline_floor(sdp: &str) -> String {
    let mut changed = false;
    let lines: Vec<String> = split_lines(sdp)
        .into_iter()
        .map(|line| match line.strip_prefix("m=") {
            Some(value)
                if is_floor_media_line(value) && value.split_whitespace().nth(1) != Some("0") =>
            {
                changed = true;
                rewrite_media_line(line, 0, None)
            }
            _ => line.to_string(),
        })
        .collect();
    if changed {
        lines.join(CRLF)
    } else {
        sdp.to_string()
    }
}

/// Whether `line` is an `a=fmtp` for the floor format.
fn is_floor_fmtp(line: &str) -> bool {
    line.strip_prefix("a=fmtp:")
        .and_then(|rest| rest.split_whitespace().next())
        == Some(FLOOR_FORMAT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn engine() -> EngineMedia {
        EngineMedia {
            rtp: "198.51.100.7:30002".parse().unwrap(),
            rtcp: None,
            advertised_ip: "198.51.100.7".parse().unwrap(),
        }
    }

    #[test]
    fn recognises_the_floor_media_line() {
        assert!(is_floor_media_line("application 20032 udp MCPTT"));
        assert!(is_floor_media_line("application 0 UDP MCPTT"));
        assert!(!is_floor_media_line("application 20032 udp t38"));
        assert!(!is_floor_media_line("application 20032 TCP/MRCPv2 MCPTT"));
        assert!(!is_floor_media_line("audio 20032 udp MCPTT"));
        assert!(!is_floor_media_line("application"));
    }

    #[test]
    fn reads_the_offered_floor_transport_from_the_section_connection() {
        let offer = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "t=0 0\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "m=application 20032 udp MCPTT\r\n",
            "c=IN IP4 192.0.2.77\r\n",
            "a=fmtp:MCPTT mc_queueing\r\n",
        );
        assert_eq!(
            parse_floor(offer),
            Some(FloorMediaInfo {
                remote: "192.0.2.77:20032".parse().unwrap()
            })
        );
    }

    #[test]
    fn falls_back_to_the_session_connection() {
        let offer = concat!(
            "v=0\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "t=0 0\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "m=application 20032 udp MCPTT\r\n",
        );
        assert_eq!(
            parse_floor(offer).map(|info| info.remote),
            Some("192.0.2.10:20032".parse().unwrap())
        );
    }

    #[test]
    fn a_declined_or_absent_floor_section_is_not_offered() {
        let declined = concat!(
            "v=0\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "m=application 0 udp MCPTT\r\n",
        );
        assert_eq!(parse_floor(declined), None);
        assert_eq!(
            parse_floor("v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 1 RTP/AVP 0\r\n"),
            None
        );
    }

    #[test]
    fn anchors_the_section_and_writes_the_controllers_fmtp_verbatim() {
        let answer = concat!(
            "v=0\r\n",
            "c=IN IP4 198.51.100.7\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "m=application 20032 udp MCPTT\r\n",
            "c=IN IP4 192.0.2.77\r\n",
            "a=fmtp:MCPTT mc_queueing;mc_priority=9\r\n",
            "a=sendrecv\r\n",
        );
        let anchored = anchor_floor(
            answer,
            engine(),
            Some("mc_queueing;mc_priority=5;mc_granted"),
        );
        assert_eq!(
            anchored,
            concat!(
                "v=0\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 0\r\n",
                "m=application 30002 udp MCPTT\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_granted\r\n",
                "a=sendrecv\r\n",
            )
        );
    }

    #[test]
    fn writes_no_fmtp_line_without_floor_fmtp_and_drops_the_offerers() {
        let answer = concat!(
            "v=0\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "m=application 20032 udp MCPTT\r\n",
            "a=fmtp:MCPTT mc_queueing\r\n",
        );
        let expected = concat!(
            "v=0\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "m=application 30002 udp MCPTT\r\n",
            "c=IN IP4 198.51.100.7\r\n",
        );
        assert_eq!(anchor_floor(answer, engine(), None), expected);
        assert_eq!(anchor_floor(answer, engine(), Some("")), expected);
    }

    #[test]
    fn a_session_level_connection_is_not_echoed_for_the_floor_section() {
        // The floor section has no `c=` of its own, so it would inherit the session one, which here
        // is still the offerer's private address.
        let answer = concat!(
            "v=0\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "c=IN IP4 198.51.100.7\r\n",
            "m=application 20032 udp MCPTT\r\n",
        );
        let anchored = anchor_floor(answer, engine(), Some("mc_granted"));
        assert!(anchored.ends_with(concat!(
            "m=application 30002 udp MCPTT\r\n",
            "c=IN IP4 198.51.100.7\r\n",
            "a=fmtp:MCPTT mc_granted\r\n",
        )));
    }

    #[test]
    fn only_the_first_floor_section_is_anchored_and_other_media_is_untouched() {
        let answer = concat!(
            "v=0\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "m=application 20032 udp MCPTT\r\n",
            "a=fmtp:MCPTT x\r\n",
            "m=application 20034 udp MCPTT\r\n",
            "a=fmtp:MCPTT y\r\n",
        );
        let anchored = anchor_floor(answer, engine(), Some("z"));
        assert_eq!(
            anchored,
            concat!(
                "v=0\r\n",
                "c=IN IP4 192.0.2.10\r\n",
                "m=audio 30000 RTP/AVP 0\r\n",
                "m=application 30002 udp MCPTT\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "a=fmtp:MCPTT z\r\n",
                "m=application 20034 udp MCPTT\r\n",
                "a=fmtp:MCPTT y\r\n",
            )
        );
    }

    #[test]
    fn declining_zeroes_every_live_floor_section_and_nothing_else() {
        let offer = concat!(
            "v=0\r\nc=IN IP4 192.0.2.10\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "m=application 20032 udp MCPTT\r\na=fmtp:MCPTT x\r\n",
            "m=application 20034 udp t38\r\n",
            "m=application 0 udp MCPTT\r\n",
        );
        assert_eq!(
            decline_floor(offer),
            concat!(
                "v=0\r\nc=IN IP4 192.0.2.10\r\n",
                "m=audio 20100 RTP/AVP 0\r\n",
                "m=application 0 udp MCPTT\r\na=fmtp:MCPTT x\r\n",
                "m=application 20034 udp t38\r\n",
                "m=application 0 udp MCPTT\r\n",
            )
        );
        let none = "v=0\r\nm=audio 1 RTP/AVP 0\r\n";
        assert_eq!(decline_floor(none), none);
    }

    #[test]
    fn an_answer_without_a_floor_section_is_unchanged() {
        let answer = "v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 30000 RTP/AVP 0\r\n";
        assert_eq!(anchor_floor(answer, engine(), Some("x")), answer);
    }

    #[test]
    fn an_ipv6_engine_is_advertised_as_ip6() {
        let engine = EngineMedia {
            rtp: "[2001:db8::7]:30002".parse().unwrap(),
            rtcp: None,
            advertised_ip: "2001:db8::7".parse().unwrap(),
        };
        let answer = "v=0\r\nc=IN IP6 2001:db8::1\r\nm=application 1 udp MCPTT\r\n";
        assert_eq!(
            anchor_floor(answer, engine, None),
            concat!(
                "v=0\r\nc=IN IP6 2001:db8::1\r\n",
                "m=application 30002 udp MCPTT\r\nc=IN IP6 2001:db8::7\r\n"
            )
        );
    }

    #[test]
    fn refuses_a_fmtp_with_a_line_break() {
        assert_eq!(validate_floor_fmtp("mc_granted"), Ok(()));
        assert_eq!(
            validate_floor_fmtp("mc_granted\r\na=sendrecv"),
            Err(FloorFmtpError::LineBreak)
        );
        assert_eq!(validate_floor_fmtp("a\nb"), Err(FloorFmtpError::LineBreak));
        assert_eq!(validate_floor_fmtp("a\rb"), Err(FloorFmtpError::LineBreak));
    }
}
