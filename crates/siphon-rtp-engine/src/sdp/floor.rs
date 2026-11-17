//! The transmission control stream: `m=application <port> udp MCPTT` (the MCPTT floor-control
//! stream, 3GPP TS 24.379 / TS 24.380 §14) or `m=application <port> udp MCVideo` (the MCVideo
//! transmission control stream, 3GPP TS 24.581 §4.3.3.1 table 4.3.3.1-1). Both are the same shape,
//! so one module serves them, told apart by [`ControlFormat`].
//!
//! The stream carries only RTCP APP packets (TS 24.380 §8, TS 24.581 §9), so unlike audio there is
//! nothing to transcode and no payload type to rewrite. The engine terminates it: this module reads
//! the offered section's transport and writes the answer's, anchored on an engine endpoint with the
//! controller's `a=fmtp:<token>` line.
//!
//! Kept apart from [`super::rewrite`], which scopes its edits by the media kinds it scans for audio,
//! text and image: the floor section is an `Other` section to it and is copied through, and this
//! pass then re-originates it on the finished answer.

use std::net::{IpAddr, SocketAddr};

use siphon_rtp_proto::ControlFormat;

use super::{addrtype, parse_connection_addr, rewrite_media_line, EngineMedia, CRLF};

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
    /// The format token the section carries, which the answer echoes (RFC 3264 §6).
    pub format: ControlFormat,
}

/// Which transmission control stream the body of an `m=` line (after `m=`) is, whatever its port:
/// `application <port> udp MCPTT` or `application <port> udp MCVideo`. The transport token is
/// matched case-insensitively (RFC 4566 §5.14 leaves its case open); the format is the literal
/// token of TS 24.380 §14 or TS 24.581 §4.3.3.1. Either is recognised so that neither is ever
/// passed through to the other party, whatever the profile accepts.
pub(super) fn is_floor_media_line(value: &str) -> Option<ControlFormat> {
    let mut fields = value.split_whitespace();
    if fields.next() != Some("application") || fields.next().is_none() {
        return None;
    }
    if !fields
        .next()
        .is_some_and(|transport| transport.eq_ignore_ascii_case("udp"))
    {
        return None;
    }
    fields.next().and_then(ControlFormat::from_token)
}

/// The SDP split into lines with their CRs removed.
fn split_lines(sdp: &str) -> Vec<&str> {
    sdp.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

/// Where the first live floor section of an accepted format is: the line index of its `m=` line,
/// the exclusive end of its section, its port and its format. A section at port 0 was declined by
/// its offerer and is not live; one of a format not in `accepted` is not the engine's to answer.
fn locate(
    lines: &[&str],
    accepted: &[ControlFormat],
) -> Option<(usize, usize, u16, ControlFormat)> {
    let mut found: Option<(usize, u16, ControlFormat)> = None;
    for (index, line) in lines.iter().enumerate() {
        let Some(value) = line.strip_prefix("m=") else {
            continue;
        };
        if let Some((start, port, format)) = found {
            return Some((start, index, port, format));
        }
        if let Some(format) = is_floor_media_line(value).filter(|format| accepted.contains(format))
        {
            found = value
                .split_whitespace()
                .nth(1)
                .and_then(|field| field.parse::<u16>().ok())
                .filter(|port| *port != 0)
                .map(|port| (index, port, format));
        }
    }
    found.map(|(start, port, format)| (start, lines.len(), port, format))
}

/// The transmission control stream `sdp` offers, if it offers a live one the engine can answer: the
/// first `m=application … udp <token>` section with a non-zero port and a connection address whose
/// token is one of `accepted` (the profile's [`ControlFormat`]s).
#[must_use]
pub fn parse_floor(sdp: &str, accepted: &[ControlFormat]) -> Option<FloorMediaInfo> {
    let lines = split_lines(sdp);
    let (start, end, port, format) = locate(&lines, accepted)?;
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
        format,
    })
}

/// Anchor the first live floor section of an answer on `engine` (TS 24.380 §14.3.1: the answerer
/// includes a media description for the media plane control channel; TS 24.581 §4.3.3.1 likewise).
///
/// Only a section whose format is in `accepted` is anchored; every other live control section
/// (a format the profile does not accept) is declined at port 0 (RFC 3264 §6), never passed
/// through, because passing it would hand the other party the offerer's own, often private, address.
///
/// The port becomes `engine.rtp`'s, the transport (`udp`) and format (`MCPTT` or `MCVideo`) stay as
/// offered (RFC 3264 §6: the answer echoes the offered format), and the section gets its own
/// media-level `c=` with the engine's advertised address (RFC 4566 §5.7), so the offerer's private
/// address is never echoed whichever level its own `c=` was at. The offerer's own `a=fmtp:<token>`
/// is dropped (an answer states the answerer's capabilities, TS 24.380 §14.3.1), and `fmtp` is
/// written in its place, verbatim, as `a=fmtp:<token> <fmtp>`; `None` (or an empty string) writes
/// none. Every other attribute is copied as it came. An answer without an acceptable floor section
/// is returned with only its unaccepted control sections declined.
#[must_use]
pub fn anchor_floor(
    sdp: &str,
    engine: EngineMedia,
    fmtp: Option<&str>,
    accepted: &[ControlFormat],
) -> String {
    let declined = decline_unaccepted(sdp, accepted);
    let lines = split_lines(&declined);
    let Some((start, end, _, format)) = locate(&lines, accepted) else {
        return declined;
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
        .filter(|line| !line.starts_with("c=") && !is_floor_fmtp(line, format))
        .collect();
    let fmtp_line = fmtp
        .filter(|parameters| !parameters.is_empty())
        .map(|parameters| format!("a=fmtp:{} {parameters}", format.token()));
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

/// The control section of an offer the engine writes (a `forward_offer`): `m=application <port>
/// udp <token>` on the engine's floor endpoint, with its own media-level `c=` (RFC 4566 §5.7) so
/// the session-level address stays the audio's, and the controller's `a=fmtp:<token> <fmtp>`
/// verbatim (TS 24.380 §14, TS 24.581 §4.3.3.1; the answerer accepts the stream by answering it
/// with a port, or declines it with port 0, RFC 3264 §6). `None` or an empty `fmtp` writes no fmtp
/// line. The caller has validated `fmtp` ([`validate_floor_fmtp`]).
#[must_use]
pub fn floor_offer_section(
    rtp_port: u16,
    advertised: IpAddr,
    fmtp: Option<&str>,
    format: ControlFormat,
) -> String {
    let token = format.token();
    let mut section = format!(
        "m=application {rtp_port} udp {token}{CRLF}c=IN {} {advertised}{CRLF}",
        addrtype(advertised)
    );
    if let Some(parameters) = fmtp.filter(|parameters| !parameters.is_empty()) {
        section.push_str(&format!("a=fmtp:{token} {parameters}{CRLF}"));
    }
    section
}

/// How a presented SDP treats its transmission control section, beside [`super::TextRewrite`] and
/// [`super::ImageRewrite`]. There is no pass-through: an unanchored section would hand the other party
/// the offerer's own, often private, floor address, so the section is anchored or declined.
#[derive(Debug, Clone, Copy)]
pub enum FloorRewrite<'a> {
    /// Anchor the section on the engine's floor endpoint, with `a=fmtp:<token> <fmtp>`
    /// ([`anchor_floor`]); a section of a format outside `accepted` is declined.
    Anchor {
        /// The engine floor endpoint and the address advertised for it.
        engine: EngineMedia,
        /// The controller's floor parameters, verbatim.
        fmtp: Option<&'a str>,
        /// The formats the profile accepts.
        accepted: &'a [ControlFormat],
    },
    /// The leg has no floor endpoint: decline the section ([`decline_floor`]).
    Decline,
}

impl FloorRewrite<'_> {
    /// Apply the directive to a presented SDP.
    #[must_use]
    pub fn apply(self, presented: &str) -> String {
        match self {
            Self::Anchor {
                engine,
                fmtp,
                accepted,
            } => anchor_floor(presented, engine, fmtp, accepted),
            Self::Decline => decline_floor(presented),
        }
    }
}

/// Decline every live transmission control section of `sdp`, of either format (port 0, RFC 3264
/// §6), for a section the engine cannot anchor, such as one a party adds mid-call to a leg that has
/// no floor endpoint. Passing it through instead would hand the other party the offerer's own,
/// often private, floor address.
#[must_use]
pub fn decline_floor(sdp: &str) -> String {
    decline_where(sdp, |_| true)
}

/// Decline every live control section whose format is not in `accepted`.
fn decline_unaccepted(sdp: &str, accepted: &[ControlFormat]) -> String {
    decline_where(sdp, |format| !accepted.contains(&format))
}

/// Set the port of every live control section whose format satisfies `select` to 0.
fn decline_where(sdp: &str, select: impl Fn(ControlFormat) -> bool) -> String {
    let mut changed = false;
    let lines: Vec<String> = split_lines(sdp)
        .into_iter()
        .map(|line| match line.strip_prefix("m=") {
            Some(value)
                if is_floor_media_line(value).is_some_and(&select)
                    && value.split_whitespace().nth(1) != Some("0") =>
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

/// Whether `line` is an `a=fmtp` for the control format `format`.
fn is_floor_fmtp(line: &str, format: ControlFormat) -> bool {
    line.strip_prefix("a=fmtp:")
        .and_then(|rest| rest.split_whitespace().next())
        == Some(format.token())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    const MCPTT: &[ControlFormat] = &[ControlFormat::Mcptt];
    const MCVIDEO: &[ControlFormat] = &[ControlFormat::Mcvideo];
    const BOTH: &[ControlFormat] = &[ControlFormat::Mcptt, ControlFormat::Mcvideo];

    fn engine() -> EngineMedia {
        EngineMedia {
            rtp: "198.51.100.7:30002".parse().unwrap(),
            rtcp: None,
            advertised_ip: "198.51.100.7".parse().unwrap(),
        }
    }

    #[test]
    fn recognises_the_floor_media_line() {
        let mcptt = Some(ControlFormat::Mcptt);
        let mcvideo = Some(ControlFormat::Mcvideo);
        assert_eq!(is_floor_media_line("application 20032 udp MCPTT"), mcptt);
        assert_eq!(is_floor_media_line("application 0 UDP MCPTT"), mcptt);
        assert_eq!(
            is_floor_media_line("application 20032 udp MCVideo"),
            mcvideo
        );
        assert_eq!(is_floor_media_line("application 0 UDP MCVideo"), mcvideo);
        assert_eq!(is_floor_media_line("application 20032 udp mcvideo"), None);
        assert_eq!(is_floor_media_line("application 20032 udp t38"), None);
        assert_eq!(
            is_floor_media_line("application 20032 TCP/MRCPv2 MCPTT"),
            None
        );
        assert_eq!(
            is_floor_media_line("application 20032 TCP/MRCPv2 MCVideo"),
            None
        );
        assert_eq!(is_floor_media_line("audio 20032 udp MCPTT"), None);
        assert_eq!(is_floor_media_line("video 20032 udp MCVideo"), None);
        assert_eq!(is_floor_media_line("application"), None);
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
            parse_floor(offer, MCPTT),
            Some(FloorMediaInfo {
                remote: "192.0.2.77:20032".parse().unwrap(),
                format: ControlFormat::Mcptt,
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
            parse_floor(offer, MCPTT).map(|info| info.remote),
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
        assert_eq!(parse_floor(declined, MCPTT), None);
        assert_eq!(
            parse_floor(
                "v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 1 RTP/AVP 0\r\n",
                MCPTT
            ),
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
            MCPTT,
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
        assert_eq!(anchor_floor(answer, engine(), None, MCPTT), expected);
        assert_eq!(anchor_floor(answer, engine(), Some(""), MCPTT), expected);
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
        let anchored = anchor_floor(answer, engine(), Some("mc_granted"), MCPTT);
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
        let anchored = anchor_floor(answer, engine(), Some("z"), MCPTT);
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
        assert_eq!(anchor_floor(answer, engine(), Some("x"), MCPTT), answer);
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
            anchor_floor(answer, engine, None, MCPTT),
            concat!(
                "v=0\r\nc=IN IP6 2001:db8::1\r\n",
                "m=application 30002 udp MCPTT\r\nc=IN IP6 2001:db8::7\r\n"
            )
        );
    }

    #[test]
    fn the_offered_section_is_anchored_with_its_own_connection_and_the_fmtp_verbatim() {
        let section = floor_offer_section(
            30002,
            "198.51.100.7".parse().unwrap(),
            Some("mc_queueing;mc_priority=5;mc_granted"),
            ControlFormat::Mcptt,
        );
        assert_eq!(
            section,
            concat!(
                "m=application 30002 udp MCPTT\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_granted\r\n",
            )
        );
        // The engine's own parser reads it back as a live floor section on that address.
        let offer = format!("v=0\r\nc=IN IP4 198.51.100.7\r\nm=audio 30000 RTP/AVP 0\r\n{section}");
        assert_eq!(
            parse_floor(&offer, MCPTT).unwrap().remote,
            "198.51.100.7:30002".parse::<SocketAddr>().unwrap()
        );
        let bare = floor_offer_section(
            30002,
            "2001:db8::7".parse().unwrap(),
            None,
            ControlFormat::Mcptt,
        );
        assert_eq!(
            bare, "m=application 30002 udp MCPTT\r\nc=IN IP6 2001:db8::7\r\n",
            "no fmtp line without parameters"
        );
        assert_eq!(
            floor_offer_section(
                30002,
                "198.51.100.7".parse().unwrap(),
                Some(""),
                ControlFormat::Mcptt
            ),
            "m=application 30002 udp MCPTT\r\nc=IN IP4 198.51.100.7\r\n"
        );
    }

    const MCVIDEO_ANSWER: &str = concat!(
        "v=0\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 30000 RTP/AVP 0\r\n",
        "m=application 20032 udp MCVideo\r\n",
        "c=IN IP4 192.0.2.77\r\n",
        "a=fmtp:MCVideo mc_queueing;mc_priority=9\r\n",
        "a=sendrecv\r\n",
    );

    #[test]
    fn an_accepted_mcvideo_section_is_anchored_and_answered_with_its_own_token() {
        // TS 24.581 §4.3.3.1: media application, port the RTCP port, protocol udp, format MCVideo.
        assert_eq!(
            anchor_floor(
                MCVIDEO_ANSWER,
                engine(),
                Some("mc_queueing;mc_priority=5;mc_granted;mc_transmission_ssrc=12345678"),
                MCVIDEO
            ),
            concat!(
                "v=0\r\n",
                "c=IN IP4 192.0.2.10\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 0\r\n",
                "m=application 30002 udp MCVideo\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "a=fmtp:MCVideo mc_queueing;mc_priority=5;mc_granted;mc_transmission_ssrc=12345678\r\n",
                "a=sendrecv\r\n",
            )
        );
        assert_eq!(
            parse_floor(MCVIDEO_ANSWER, MCVIDEO).map(|info| (info.remote, info.format)),
            Some(("192.0.2.77:20032".parse().unwrap(), ControlFormat::Mcvideo))
        );
        // Both accepted: the format found is the one reported.
        assert_eq!(
            parse_floor(MCVIDEO_ANSWER, BOTH).map(|info| info.format),
            Some(ControlFormat::Mcvideo)
        );
    }

    #[test]
    fn an_mcvideo_section_under_the_default_profile_is_declined_never_passed_through() {
        assert_eq!(parse_floor(MCVIDEO_ANSWER, MCPTT), None);
        let anchored = anchor_floor(MCVIDEO_ANSWER, engine(), Some("mc_granted"), MCPTT);
        assert_eq!(
            anchored,
            concat!(
                "v=0\r\n",
                "c=IN IP4 192.0.2.10\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 0\r\n",
                "m=application 0 udp MCVideo\r\n",
                "c=IN IP4 192.0.2.77\r\n",
                "a=fmtp:MCVideo mc_queueing;mc_priority=9\r\n",
                "a=sendrecv\r\n",
            )
        );
        // With no endpoint at all the section is declined too, whatever its format.
        assert!(decline_floor(MCVIDEO_ANSWER).contains("m=application 0 udp MCVideo\r\n"));
    }

    #[test]
    fn a_later_unaccepted_section_is_declined_while_the_accepted_one_is_anchored() {
        let answer = concat!(
            "v=0\r\nc=IN IP4 192.0.2.10\r\n",
            "m=application 20032 udp MCVideo\r\n",
            "m=application 20034 udp MCPTT\r\n",
        );
        assert_eq!(
            anchor_floor(answer, engine(), None, MCVIDEO),
            concat!(
                "v=0\r\nc=IN IP4 192.0.2.10\r\n",
                "m=application 30002 udp MCVideo\r\nc=IN IP4 198.51.100.7\r\n",
                "m=application 0 udp MCPTT\r\n",
            )
        );
    }

    #[test]
    fn an_mcptt_offer_answers_byte_for_byte_as_before() {
        let answer = concat!(
            "v=0\r\n",
            "c=IN IP4 198.51.100.7\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "m=application 20032 udp MCPTT\r\n",
            "c=IN IP4 192.0.2.77\r\n",
            "a=fmtp:MCPTT mc_queueing;mc_priority=9\r\n",
            "a=fmtp:MCVideo not_ours\r\n",
            "a=sendrecv\r\n",
        );
        let expected = concat!(
            "v=0\r\n",
            "c=IN IP4 198.51.100.7\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "m=application 30002 udp MCPTT\r\n",
            "c=IN IP4 198.51.100.7\r\n",
            "a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_granted\r\n",
            "a=fmtp:MCVideo not_ours\r\n",
            "a=sendrecv\r\n",
        );
        for accepted in [MCPTT, BOTH] {
            assert_eq!(
                anchor_floor(
                    answer,
                    engine(),
                    Some("mc_queueing;mc_priority=5;mc_granted"),
                    accepted
                ),
                expected
            );
        }
    }

    #[test]
    fn the_offered_section_carries_the_requested_token() {
        let section = floor_offer_section(
            30002,
            "198.51.100.7".parse().unwrap(),
            Some("mc_queueing;mc_granted"),
            ControlFormat::Mcvideo,
        );
        assert_eq!(
            section,
            concat!(
                "m=application 30002 udp MCVideo\r\n",
                "c=IN IP4 198.51.100.7\r\n",
                "a=fmtp:MCVideo mc_queueing;mc_granted\r\n",
            )
        );
        let offer = format!("v=0\r\nc=IN IP4 198.51.100.7\r\nm=audio 30000 RTP/AVP 0\r\n{section}");
        assert_eq!(
            parse_floor(&offer, MCVIDEO).map(|info| info.format),
            Some(ControlFormat::Mcvideo)
        );
        assert_eq!(parse_floor(&offer, MCPTT), None);
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
