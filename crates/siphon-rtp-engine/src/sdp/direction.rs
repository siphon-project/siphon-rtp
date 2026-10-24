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
}
