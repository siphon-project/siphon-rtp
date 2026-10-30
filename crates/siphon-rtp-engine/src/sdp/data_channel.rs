//! The WebRTC data channel section: `m=application <port> UDP/DTLS/SCTP webrtc-datachannel`
//! (RFC 8841).
//!
//! A browser cannot send RTCP APP, so the MCPTT floor control of a browser seat rides a data channel
//! (docs/control/json.md, "Floor control over a WebRTC data channel"). The engine answers the section
//! only when it can honour it:
//!
//! * the audio it answers is DTLS-SRTP (`UDP/TLS/RTP/SAVPF`): SCTP rides the **same DTLS association**
//!   (RFC 8261 §5, RFC 8841 §6), so a leg without DTLS cannot carry a channel and the caller declines
//!   the section;
//! * the offer **bundles** the section with the audio (`a=group:BUNDLE`, RFC 8843): the engine has one
//!   transport per seat, so the section is answered on the audio's own port, ICE credentials,
//!   fingerprint and setup role. An offer that keeps the data channel on a transport of its own is
//!   not answered.
//!
//! The section is re-originated on the finished answer, the way [`super::floor`] re-originates the
//! floor section: [`super::rewrite`] copies an unknown section through, and this pass then replaces
//! everything transport-related in it with the audio section's.

use super::{rewrite_media_line, CRLF};

/// The SCTP port the engine advertises (`a=sctp-port`, RFC 8841 §5). Both ends of a WebRTC data
/// channel use 5000 (RFC 8831 §6.2); the number is signalled, not demultiplexed on, because the
/// association rides a DTLS association that already identifies the peer.
pub const DATA_CHANNEL_SCTP_PORT: u16 = 5000;

/// The largest SCTP user message the engine accepts and advertises (`a=max-message-size`,
/// RFC 8841 §5). Must equal `siphon_rtp_dtls::MAX_MESSAGE_SIZE`, which the SCTP stack enforces.
const MAX_MESSAGE_SIZE: usize = siphon_rtp_dtls::MAX_MESSAGE_SIZE;

/// The transport and format tokens of the data channel section (RFC 8841 §5).
const TRANSPORT: &str = "UDP/DTLS/SCTP";
const FORMAT: &str = "webrtc-datachannel";

/// A data channel section the offer carries and the engine can answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChannelMedia {
    /// The section's `a=mid` (RFC 5888 §4), which the answer echoes.
    pub mid: String,
}

/// Whether the body of an `m=` line (after `m=`) is a data channel section, whatever its port:
/// `application <port> UDP/DTLS/SCTP webrtc-datachannel` (RFC 8841 §5). The legacy
/// `DTLS/SCTP` transport of the pre-standard drafts is not this.
pub(super) fn is_data_channel_media_line(value: &str) -> bool {
    let mut fields = value.split_whitespace();
    fields.next() == Some("application")
        && fields.next().is_some()
        && fields
            .next()
            .is_some_and(|transport| transport.eq_ignore_ascii_case(TRANSPORT))
        && fields.next() == Some(FORMAT)
}

/// The SDP split into lines with their CRs removed.
fn split_lines(sdp: &str) -> Vec<&str> {
    sdp.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

/// The exclusive end of the section whose `m=` line is at `start`.
fn section_end(lines: &[&str], start: usize) -> usize {
    lines[start + 1..]
        .iter()
        .position(|line| line.starts_with("m="))
        .map_or(lines.len(), |offset| start + 1 + offset)
}

/// `a=mid` of the section `lines[start..end]`.
fn mid_of(lines: &[&str], start: usize, end: usize) -> Option<String> {
    lines[start + 1..end]
        .iter()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .map(|mid| mid.trim().to_string())
        .filter(|mid| !mid.is_empty())
}

/// The mids of the session's `a=group:BUNDLE` lines (RFC 8843 §7.1), in order.
fn bundled_mids<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(lines.len());
    lines[..first_media]
        .iter()
        .filter_map(|line| line.strip_prefix("a=group:BUNDLE"))
        .flat_map(str::split_whitespace)
        .collect()
}

/// Where the first live data channel section is: its `m=` line index and exclusive end. Live is a
/// non-zero port, or port 0 with `a=bundle-only` (RFC 8843 §6), which an answerer may accept.
fn locate_data_channel(lines: &[&str]) -> Option<(usize, usize)> {
    for (index, line) in lines.iter().enumerate() {
        let Some(value) = line.strip_prefix("m=") else {
            continue;
        };
        if !is_data_channel_media_line(value) {
            continue;
        }
        let end = section_end(lines, index);
        let port = value
            .split_whitespace()
            .nth(1)
            .and_then(|field| field.parse::<u16>().ok());
        let bundle_only = lines[index + 1..end]
            .iter()
            .any(|line| line.trim() == "a=bundle-only");
        if port.is_some_and(|port| port != 0) || (port == Some(0) && bundle_only) {
            return Some((index, end));
        }
    }
    None
}

/// The first live `m=audio` section: its `m=` line index and exclusive end.
fn locate_audio(lines: &[&str]) -> Option<(usize, usize)> {
    lines.iter().enumerate().find_map(|(index, line)| {
        let value = line.strip_prefix("m=")?;
        let mut fields = value.split_whitespace();
        (fields.next() == Some("audio")
            && fields
                .next()
                .and_then(|port| port.parse::<u16>().ok())
                .is_some_and(|port| port != 0))
        .then(|| (index, section_end(lines, index)))
    })
}

/// The data channel section an offer carries that the engine can answer: a live section with an
/// `a=mid` that the offer bundles with its audio section (RFC 8843). `None` when there is none, or
/// it is not bundled with the audio (a transport of its own, which the engine does not run), and the
/// section is then declined with port 0 (RFC 3264 §6).
#[must_use]
pub fn parse_data_channel(offer: &str) -> Option<DataChannelMedia> {
    let lines = split_lines(offer);
    let (start, end) = locate_data_channel(&lines)?;
    let mid = mid_of(&lines, start, end)?;
    let (audio_start, audio_end) = locate_audio(&lines)?;
    let audio_mid = mid_of(&lines, audio_start, audio_end)?;
    let bundled = bundled_mids(&lines);
    (bundled.contains(&mid.as_str()) && bundled.contains(&audio_mid.as_str()))
        .then_some(DataChannelMedia { mid })
}

/// Whether `line` is a transport attribute that the data channel section shares with the audio
/// section it is bundled with (RFC 8843 §7.3: the transport-related attributes are identical across
/// a bundle), and so is copied from the audio section.
fn is_shared_transport_line(line: &str) -> bool {
    [
        "a=ice-ufrag:",
        "a=ice-pwd:",
        "a=ice-options:",
        "a=ice-lite",
        "a=candidate:",
        "a=end-of-candidates",
        "a=fingerprint:",
        "a=setup:",
        "a=tls-id:",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

/// Re-originate the first live data channel section of `answer` (the answer the engine wrote from
/// the offer, which still carries the offerer's own copy of the section) as RFC 8841 requires:
///
/// * the same port as the audio section it is bundled with (RFC 8843 §8.2: one transport) and the
///   audio's own connection line, never the offerer's address;
/// * the audio section's ICE credentials, candidates, fingerprint and `a=setup` (the DTLS role is
///   the association's, RFC 8841 §6), so the two sections agree as RFC 8843 requires;
/// * `a=mid` echoed, `a=sctp-port:5000` and `a=max-message-size:65536` (RFC 8841 §5), with the
///   offerer's own values for those, `a=sctpmap` and everything else dropped.
///
/// An answer with no live data channel section, or no audio section to share a transport with, is
/// returned unchanged.
#[must_use]
pub fn anchor_data_channel(answer: &str) -> String {
    let lines = split_lines(answer);
    let (Some((start, end)), Some((audio_start, audio_end))) =
        (locate_data_channel(&lines), locate_audio(&lines))
    else {
        return answer.to_string();
    };
    let audio_port = lines[audio_start]
        .strip_prefix("m=")
        .and_then(|value| value.split_whitespace().nth(1))
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(0);
    let Some(mid) = mid_of(&lines, start, end) else {
        return answer.to_string();
    };
    let shared: Vec<&str> = lines[audio_start + 1..audio_end]
        .iter()
        .copied()
        .filter(|line| is_shared_transport_line(line))
        .collect();
    let connection = lines[audio_start + 1..audio_end]
        .iter()
        .copied()
        .find(|line| line.starts_with("c="));

    // The last element of an SDP that ends in CRLF is the empty remainder: it stays last.
    let mut trailing = 0;
    if end == lines.len() {
        trailing = lines[start + 1..end]
            .iter()
            .rev()
            .take_while(|line| line.is_empty())
            .count();
    }
    let mut out: Vec<String> = lines[..start]
        .iter()
        .map(|line| (*line).to_string())
        .collect();
    out.push(rewrite_media_line(lines[start], audio_port, None));
    out.extend(connection.map(str::to_string));
    out.push(format!("a=mid:{mid}"));
    out.extend(shared.iter().map(|line| (*line).to_string()));
    out.push(format!("a=sctp-port:{DATA_CHANNEL_SCTP_PORT}"));
    out.push(format!("a=max-message-size:{MAX_MESSAGE_SIZE}"));
    out.extend(std::iter::repeat_n(String::new(), trailing));
    out.extend(lines[end..].iter().map(|line| (*line).to_string()));
    out.join(CRLF)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Chrome-shaped offer: audio and a data channel, bundled, with ICE and DTLS on both.
    const OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE 0 1\r\n",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=ice-ufrag:browser\r\n",
        "a=ice-pwd:browserpassword0123456789\r\n",
        "a=fingerprint:sha-256 AA:BB\r\n",
        "a=setup:actpass\r\n",
        "a=mid:0\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:111 opus/48000/2\r\n",
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=ice-ufrag:browser\r\n",
        "a=ice-pwd:browserpassword0123456789\r\n",
        "a=fingerprint:sha-256 AA:BB\r\n",
        "a=setup:actpass\r\n",
        "a=mid:1\r\n",
        "a=sctp-port:5000\r\n",
        "a=max-message-size:262144\r\n",
    );

    /// The answer the engine wrote for [`OFFER`] before this pass: audio re-originated, the data
    /// channel section still the offerer's own copy.
    const ANSWER_BEFORE: &str = concat!(
        "v=0\r\n",
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE 0 1\r\n",
        "m=audio 40000 UDP/TLS/RTP/SAVPF 111\r\n",
        "c=IN IP4 198.51.100.9\r\n",
        "a=ice-ufrag:engine\r\n",
        "a=ice-pwd:enginepassword0123456789\r\n",
        "a=candidate:1 1 UDP 2130706431 198.51.100.9 40000 typ host\r\n",
        "a=fingerprint:sha-256 CC:DD\r\n",
        "a=setup:passive\r\n",
        "a=mid:0\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:111 opus/48000/2\r\n",
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=ice-ufrag:browser\r\n",
        "a=ice-pwd:browserpassword0123456789\r\n",
        "a=fingerprint:sha-256 AA:BB\r\n",
        "a=setup:actpass\r\n",
        "a=mid:1\r\n",
        "a=sctp-port:5000\r\n",
        "a=max-message-size:262144\r\n",
    );

    #[test]
    fn a_bundled_data_channel_section_is_recognised_with_its_mid() {
        assert_eq!(
            parse_data_channel(OFFER),
            Some(DataChannelMedia { mid: "1".into() })
        );
    }

    #[test]
    fn the_legacy_dtls_sctp_transport_is_not_a_data_channel() {
        let offer = OFFER.replace("UDP/DTLS/SCTP webrtc-datachannel", "DTLS/SCTP 5000");
        assert_eq!(parse_data_channel(&offer), None);
    }

    #[test]
    fn a_data_channel_outside_the_bundle_is_not_answerable() {
        // The engine runs one transport per seat: a section on a transport of its own is declined.
        let offer = OFFER.replace("a=group:BUNDLE 0 1", "a=group:BUNDLE 0");
        assert_eq!(parse_data_channel(&offer), None);
        let no_group = OFFER.replace("a=group:BUNDLE 0 1\r\n", "");
        assert_eq!(parse_data_channel(&no_group), None);
    }

    #[test]
    fn a_data_channel_without_a_mid_is_not_answerable() {
        let offer = OFFER.replace("a=mid:1\r\n", "");
        assert_eq!(parse_data_channel(&offer), None);
    }

    #[test]
    fn a_declined_data_channel_is_not_live() {
        let offer = OFFER.replace(
            "m=application 9 UDP/DTLS/SCTP",
            "m=application 0 UDP/DTLS/SCTP",
        );
        assert_eq!(parse_data_channel(&offer), None);
    }

    #[test]
    fn a_bundle_only_data_channel_at_port_zero_is_live() {
        // RFC 8843 §6: port 0 with a=bundle-only is a section the answerer may accept.
        let offer = OFFER
            .replace(
                "m=application 9 UDP/DTLS/SCTP",
                "m=application 0 UDP/DTLS/SCTP",
            )
            .replace("a=mid:1\r\n", "a=mid:1\r\na=bundle-only\r\n");
        assert_eq!(
            parse_data_channel(&offer),
            Some(DataChannelMedia { mid: "1".into() })
        );
    }

    #[test]
    fn the_answer_section_shares_the_audio_transport_and_states_sctp_parameters() {
        let answer = anchor_data_channel(ANSWER_BEFORE);
        let expected = concat!(
            "v=0\r\n",
            "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "a=group:BUNDLE 0 1\r\n",
            "m=audio 40000 UDP/TLS/RTP/SAVPF 111\r\n",
            "c=IN IP4 198.51.100.9\r\n",
            "a=ice-ufrag:engine\r\n",
            "a=ice-pwd:enginepassword0123456789\r\n",
            "a=candidate:1 1 UDP 2130706431 198.51.100.9 40000 typ host\r\n",
            "a=fingerprint:sha-256 CC:DD\r\n",
            "a=setup:passive\r\n",
            "a=mid:0\r\n",
            "a=rtcp-mux\r\n",
            "a=rtpmap:111 opus/48000/2\r\n",
            "m=application 40000 UDP/DTLS/SCTP webrtc-datachannel\r\n",
            "c=IN IP4 198.51.100.9\r\n",
            "a=mid:1\r\n",
            "a=ice-ufrag:engine\r\n",
            "a=ice-pwd:enginepassword0123456789\r\n",
            "a=candidate:1 1 UDP 2130706431 198.51.100.9 40000 typ host\r\n",
            "a=fingerprint:sha-256 CC:DD\r\n",
            "a=setup:passive\r\n",
            "a=sctp-port:5000\r\n",
            "a=max-message-size:65536\r\n",
        );
        assert_eq!(answer, expected);
    }

    #[test]
    fn an_answer_without_a_data_channel_section_is_unchanged() {
        let audio_only = ANSWER_BEFORE
            .split("m=application")
            .next()
            .expect("audio part")
            .to_string();
        assert_eq!(anchor_data_channel(&audio_only), audio_only);
    }

    #[test]
    fn anchoring_is_idempotent() {
        let once = anchor_data_channel(ANSWER_BEFORE);
        assert_eq!(anchor_data_channel(&once), once);
    }

    #[test]
    fn a_section_followed_by_another_keeps_its_place() {
        let answer = format!("{ANSWER_BEFORE}m=video 9 UDP/TLS/RTP/SAVPF 96\r\n");
        let anchored = anchor_data_channel(&answer);
        assert!(
            anchored.ends_with("a=max-message-size:65536\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n")
        );
    }

    #[test]
    fn the_max_message_size_matches_the_sctp_stack_limit() {
        assert_eq!(MAX_MESSAGE_SIZE, 65_536);
    }
}
