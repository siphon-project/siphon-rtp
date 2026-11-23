//! The direction an answerer declares back to an offer (RFC 3264 §6.1).
//!
//! When the engine *relays* an offer it passes the party's direction through untouched, because the
//! far party is the one answering. When the engine **is** the answerer (`answer_local`) it has to
//! answer the complement: an offer of `sendonly` is answered `recvonly`, `recvonly` is answered
//! `sendonly`, `inactive` stays `inactive` and `sendrecv` stays `sendrecv`. Echoing the offer's own
//! attribute back — what passing it through does — tells the offerer the engine will send to a
//! party that said it will not receive, which is a SIPREC recording stream (RFC 7866 §6) answered
//! the wrong way round.

use super::MediaDirection;

impl MediaDirection {
    /// The direction to answer a stream offered with `self` (RFC 3264 §6.1).
    #[must_use]
    pub fn answered(self) -> Self {
        match self {
            MediaDirection::SendOnly => MediaDirection::RecvOnly,
            MediaDirection::RecvOnly => MediaDirection::SendOnly,
            other => other,
        }
    }

    /// Whether the party that wrote this attribute will **receive** media — whether anything may be
    /// sent to it at all.
    #[must_use]
    pub fn receives(self) -> bool {
        matches!(self, MediaDirection::SendRecv | MediaDirection::RecvOnly)
    }
}

/// Rewrite the direction attributes of an answer the engine wrote itself to the complement of the
/// `offered` direction: every direction attribute at session level and in the audio section is
/// replaced. Sections other than audio are left alone — an engine-written answer declines them with
/// port 0, where a direction attribute means nothing.
#[must_use]
pub fn answer_direction(sdp: &str, offered: MediaDirection) -> String {
    let answered = offered.answered();
    let token = format!("a={}", answered.token());
    let mut in_scope = true;
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\r', '\n']);
        if let Some(media) = bare.strip_prefix("m=") {
            in_scope = media.starts_with("audio ") || media == "audio";
        }
        let is_direction = bare
            .strip_prefix("a=")
            .and_then(MediaDirection::parse)
            .is_some();
        if in_scope && is_direction {
            out.push_str(&token);
            out.push_str(&line[bare.len()..]);
        } else {
            out.push_str(line);
        }
    }
    out
}

/// [`answer_direction`] for the first live `m=video` section of an answer the engine wrote itself:
/// the section carries an explicit media-level direction, the complement of the `offered` one
/// (RFC 3264 §6.1, RFC 4566 §6), whether the offer stated it there or inherited it from the session
/// level (the audio's rewrite changes the session attribute, so an inheriting section would otherwise
/// read the wrong one). `sendrecv` stays `sendrecv`: an answer of `recvonly` or `inactive` to it would
/// forbid the far party's video for the whole call (RFC 3264 §8). Session level, audio and any
/// further video section are left alone.
#[must_use]
pub fn answer_video_direction(sdp: &str, offered: MediaDirection) -> String {
    let token = format!("a={}", offered.answered().token());
    let lines: Vec<&str> = sdp.split_inclusive('\n').collect();
    let live = |line: &str| {
        let mut fields = line
            .strip_prefix("m=")
            .unwrap_or_default()
            .split_whitespace();
        fields.next() == Some("video")
            && fields
                .next()
                .and_then(|port| port.split('/').next()?.parse::<u16>().ok())
                .is_some_and(|port| port != 0)
    };
    let Some(start) = lines.iter().position(|line| live(line.trim_end())) else {
        return sdp.to_string();
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| line.starts_with("m="))
        .map_or(lines.len(), |(index, _)| index);
    let is_direction = |line: &str| {
        line.trim_end_matches(['\r', '\n'])
            .strip_prefix("a=")
            .and_then(MediaDirection::parse)
            .is_some()
    };
    let ending = if sdp.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(sdp.len() + token.len() + 2);
    let mut written = false;
    for (index, line) in lines.iter().enumerate() {
        if index == end && !written {
            out.push_str(&token);
            out.push_str(ending);
            written = true;
        }
        if (start + 1..end).contains(&index) && is_direction(line) {
            let bare = line.trim_end_matches(['\r', '\n']);
            out.push_str(&token);
            out.push_str(&line[bare.len()..]);
            written = true;
        } else {
            out.push_str(line);
        }
    }
    if !written {
        if !out.ends_with('\n') {
            out.push_str(ending);
        }
        out.push_str(&token);
        out.push_str(ending);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_offered_direction_is_answered_with_its_complement() {
        // RFC 3264 §6.1.
        for (offered, answered) in [
            (MediaDirection::SendRecv, MediaDirection::SendRecv),
            (MediaDirection::SendOnly, MediaDirection::RecvOnly),
            (MediaDirection::RecvOnly, MediaDirection::SendOnly),
            (MediaDirection::Inactive, MediaDirection::Inactive),
        ] {
            assert_eq!(offered.answered(), answered, "{offered:?}");
        }
    }

    #[test]
    fn only_a_party_that_receives_may_be_sent_to() {
        assert!(MediaDirection::SendRecv.receives());
        assert!(MediaDirection::RecvOnly.receives());
        assert!(!MediaDirection::SendOnly.receives());
        assert!(!MediaDirection::Inactive.receives());
    }

    #[test]
    fn a_sendonly_audio_section_is_answered_recvonly_and_other_sections_are_left_alone() {
        let answer = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.1\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.1\r\n",
            "t=0 0\r\n",
            "m=audio 4000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=sendonly\r\n",
            "m=video 0 RTP/AVP 96\r\n",
            "a=sendonly\r\n",
        );
        let rewritten = answer_direction(answer, MediaDirection::SendOnly);
        assert_eq!(
            rewritten,
            concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 192.0.2.1\r\n",
                "s=-\r\n",
                "c=IN IP4 192.0.2.1\r\n",
                "t=0 0\r\n",
                "m=audio 4000 RTP/AVP 0\r\n",
                "a=rtpmap:0 PCMU/8000\r\n",
                "a=recvonly\r\n",
                "m=video 0 RTP/AVP 96\r\n",
                "a=sendonly\r\n",
            )
        );
    }

    #[test]
    fn a_session_level_direction_is_answered_too() {
        let answer = "v=0\r\ns=-\r\na=sendonly\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
        assert_eq!(
            answer_direction(answer, MediaDirection::SendOnly),
            "v=0\r\ns=-\r\na=recvonly\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
        );
    }

    #[test]
    fn an_answer_with_no_direction_is_unchanged() {
        let answer = "v=0\r\ns=-\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=rtcp-mux\r\n";
        assert_eq!(answer_direction(answer, MediaDirection::SendRecv), answer);
    }

    #[test]
    fn a_video_section_is_answered_with_the_complement_and_sendrecv_stays_sendrecv() {
        // RFC 3264 §6.1: sendonly -> recvonly, recvonly -> sendonly, inactive -> inactive; and a
        // sendrecv offer is answered sendrecv, never recvonly.
        for (offered, answered) in [
            (MediaDirection::SendRecv, "a=sendrecv"),
            (MediaDirection::SendOnly, "a=recvonly"),
            (MediaDirection::RecvOnly, "a=sendonly"),
            (MediaDirection::Inactive, "a=inactive"),
        ] {
            let answer = concat!(
                "v=0\r\ns=-\r\nt=0 0\r\n",
                "m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n",
                "m=video 4002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=sendrecv\r\n",
                "m=video 4004 RTP/AVP 97\r\na=sendrecv\r\n",
            );
            let rewritten = answer_video_direction(answer, offered);
            let expected = format!(
                "m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\nm=video 4002 RTP/AVP 96\r\n\
                 a=rtpmap:96 H264/90000\r\n{answered}\r\nm=video 4004 RTP/AVP 97\r\na=sendrecv\r\n"
            );
            assert!(rewritten.contains(&expected), "{offered:?}: {rewritten}");
        }
    }

    #[test]
    fn a_declined_video_section_and_the_session_level_are_left_alone_by_the_video_direction() {
        let answer = concat!(
            "v=0\r\na=sendonly\r\nt=0 0\r\n",
            "m=video 0 RTP/AVP 96\r\na=sendonly\r\n",
        );
        assert_eq!(
            answer_video_direction(answer, MediaDirection::SendOnly),
            answer
        );
    }

    #[test]
    fn a_video_section_with_no_direction_of_its_own_is_answered_with_an_explicit_one() {
        // RFC 3264 §6.1, RFC 4566 §6: the section inherits the session direction in the offer, but the
        // answer writes the complement at media level, whatever the audio section says.
        let answer = concat!(
            "v=0\r\na=recvonly\r\nt=0 0\r\n",
            "m=audio 4000 RTP/AVP 0\r\na=recvonly\r\n",
            "m=video 4002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
            "m=video 4004 RTP/AVP 97\r\n",
        );
        let rewritten = answer_video_direction(answer, MediaDirection::SendOnly);
        assert!(
            rewritten.contains(
                "m=video 4002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=recvonly\r\nm=video 4004"
            ),
            "{rewritten}"
        );
        let last = answer_video_direction("m=video 4002 RTP/AVP 96\r\n", MediaDirection::SendRecv);
        assert_eq!(last, "m=video 4002 RTP/AVP 96\r\na=sendrecv\r\n");
    }
}
