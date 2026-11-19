//! A video stream on a relayed call: the connection line a passed-through `m=video` section keeps.
//!
//! [`super::rewrite`] points the session `c=` at the engine for the audio stream. A video section
//! with no `c=` of its own inherits the session one (RFC 4566 §5.7), so it would read the engine's
//! address with the phone's own port. [`keep_passthrough_connection`] gives such a section the
//! offerer's original connection line, a separate pass over the finished SDP as the floor and
//! forwarding-room video passes are, so the audio rewrite is untouched.

use super::floor::split_lines;
use super::{addrtype, parse_connection_addr, CRLF};

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

#[cfg(test)]
mod tests {
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
