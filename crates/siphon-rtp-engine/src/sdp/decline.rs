//! Declining, in an answer the engine writes itself, the streams it does not carry.
//!
//! Separate from the relay rewrite in the parent module because it is the opposite rule. A relay
//! copies a section it does not handle through line for line and lets the far party answer it. An
//! answerer has no far party, so the same copy would hand the offer's own section back as the answer
//! to it.

use super::{parse_media_line, rewrite_media_line, MediaKind, TextRewrite, CRLF};

impl TextRewrite {
    /// Whether the text section is anchored to the engine, which is what makes it a stream the
    /// engine answers rather than one it declines or leaves alone.
    #[must_use]
    pub fn is_anchored(&self) -> bool {
        self.anchor_engine().is_some()
    }
}

/// Decline every media stream of an **answer** that the engine did not answer itself, by setting its
/// `m=` port to `0` (RFC 3264 §6). The m-line keeps its place, its transport and its formats, so the
/// answer still carries one m-line per offered one, in the offer's order.
///
/// For the answers the engine writes as the answerer — a single-leg local answer and a conference
/// seat — where there is no far party whose own answer could be relayed. [`super::rewrite`] copies a
/// section it does not handle through line for line, which is right when it relays an SDP between
/// two parties and wrong here: a copy of the offer's own section is not an answer to it. It names
/// the offerer's own port as the port to send to, and it mirrors the offerer's direction back at it,
/// so a `recvonly` offer is answered `recvonly` where RFC 3264 §6.1 allows only `sendonly` or
/// `inactive`.
///
/// The engine answers the first `m=audio` section, and the first `m=text` one when `text_answered`
/// says it anchored it. "First" is the first whose port parses, which is the section the scan
/// captures and [`super::rewrite`] therefore anchored. Everything else is declined: `m=video`,
/// `m=application`, any further audio or text section, and `m=image`, which neither of these answers
/// relays. A section already at port 0 is left as it is, and an answer with nothing to decline is
/// returned untouched without being copied.
///
/// Only the port moves. A declined section's attributes are ignored by the offerer (RFC 3264 §6),
/// so they are left in place rather than edited.
#[must_use]
pub fn decline_unanswered_media(sdp: String, text_answered: bool) -> String {
    let mut audio_seen = false;
    let mut text_seen = false;
    // Each line to replace, with its replacement. Empty, and so unallocated, for an audio-only answer.
    let mut declined: Vec<(usize, String)> = Vec::new();
    for (index, raw_line) in sdp.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let Some(value) = line.strip_prefix("m=") else {
            continue;
        };
        let (kind, port) = parse_media_line(value);
        let answered = match kind {
            MediaKind::Audio if !audio_seen && port.is_some() => {
                audio_seen = true;
                true
            }
            MediaKind::Text if !text_seen && port.is_some() => {
                text_seen = true;
                text_answered
            }
            _ => false,
        };
        if answered || port == Some(0) {
            continue;
        }
        // Compared against the line as well as the port, so a malformed m-line that already reads
        // as declined is not rewritten a second time and the pass stays idempotent.
        let replacement = rewrite_media_line(line, 0, Option::None);
        if replacement != line {
            declined.push((index, replacement));
        }
    }
    if declined.is_empty() {
        return sdp;
    }
    let mut replacements = declined.into_iter().peekable();
    let lines: Vec<String> = sdp
        .split('\n')
        .enumerate()
        .map(|(index, raw_line)| {
            match replacements.next_if(|(declined_index, _)| *declined_index == index) {
                Some((_, replacement)) => replacement,
                None => raw_line.strip_suffix('\r').unwrap_or(raw_line).to_string(),
            }
        })
        .collect();
    lines.join(CRLF)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use siphon_rtp_srtp::sdes::CryptoAttribute;

    use super::super::EngineMedia;
    use super::*;

    /// Every `m=` line of `sdp`, in order.
    fn media_lines(sdp: &str) -> Vec<&str> {
        sdp.lines().filter(|line| line.starts_with("m=")).collect()
    }

    /// An audio offer followed by `sections`, each a complete media description.
    fn offer_with_sections(sections: &[&str]) -> String {
        let mut sdp = String::from(concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "t=0 0\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        ));
        for section in sections {
            sdp.push_str(section);
        }
        sdp
    }

    #[test]
    fn an_active_video_stream_is_declined_with_its_formats_intact() {
        // RFC 3264 §6: a stream the answerer will not carry is answered with port 0, and the m-line
        // keeps its place, its transport and its formats.
        let offer = offer_with_sections(&[concat!(
            "m=video 49550 RTP/SAVP 96 97 98\r\n",
            "a=rtpmap:96 H264/90000\r\n",
            "a=recvonly\r\n",
        )]);
        let answer = decline_unanswered_media(offer, false);
        assert_eq!(
            media_lines(&answer),
            vec!["m=audio 20100 RTP/AVP 0", "m=video 0 RTP/SAVP 96 97 98"],
            "{answer}"
        );
        assert!(answer.ends_with("\r\n"), "{answer:?}");
    }

    #[test]
    fn an_audio_only_answer_is_returned_as_it_was() {
        let offer = offer_with_sections(&[]);
        assert_eq!(decline_unanswered_media(offer.clone(), false), offer);
    }

    #[test]
    fn a_stream_the_offerer_already_declined_is_left_alone() {
        let offer = offer_with_sections(&["m=video 0 RTP/SAVP 0\r\n"]);
        assert_eq!(decline_unanswered_media(offer.clone(), false), offer);
    }

    #[test]
    fn every_unhandled_media_type_is_declined_in_place() {
        // RFC 3264 §6: the answer carries one m-line per offered one, in the offer's order.
        let offer = offer_with_sections(&[
            "m=video 49550 RTP/AVP 96\r\n",
            "m=application 49560 UDP/DTLS/SCTP webrtc-datachannel\r\n",
            "m=message 49570 TCP/MSRP *\r\n",
        ]);
        let answer = decline_unanswered_media(offer, false);
        assert_eq!(
            media_lines(&answer),
            vec![
                "m=audio 20100 RTP/AVP 0",
                "m=video 0 RTP/AVP 96",
                "m=application 0 UDP/DTLS/SCTP webrtc-datachannel",
                "m=message 0 TCP/MSRP *",
            ],
            "{answer}"
        );
    }

    #[test]
    fn a_second_audio_stream_is_declined_and_the_first_kept() {
        // The engine anchors one audio stream, the first. A second one was copied back at the
        // offerer with the offerer's own port, exactly as a video section was.
        let offer = offer_with_sections(&["m=audio 20200 RTP/AVP 8\r\n"]);
        let answer = decline_unanswered_media(offer, false);
        assert_eq!(
            media_lines(&answer),
            vec!["m=audio 20100 RTP/AVP 0", "m=audio 0 RTP/AVP 8"],
            "{answer}"
        );
    }

    #[test]
    fn a_text_stream_is_kept_only_when_the_engine_answered_it() {
        let offer =
            offer_with_sections(&["m=text 20300 RTP/AVP 98\r\n", "m=text 20400 RTP/AVP 98\r\n"]);
        let anchored = decline_unanswered_media(offer.clone(), true);
        assert_eq!(
            media_lines(&anchored),
            vec![
                "m=audio 20100 RTP/AVP 0",
                "m=text 20300 RTP/AVP 98",
                "m=text 0 RTP/AVP 98",
            ],
            "only the first text stream is ever anchored: {anchored}"
        );
        let unanchored = decline_unanswered_media(offer, false);
        assert_eq!(
            media_lines(&unanchored),
            vec![
                "m=audio 20100 RTP/AVP 0",
                "m=text 0 RTP/AVP 98",
                "m=text 0 RTP/AVP 98",
            ],
            "{unanchored}"
        );
    }

    #[test]
    fn a_fax_stream_beside_a_single_leg_answer_is_declined() {
        let offer = offer_with_sections(&["m=image 20500 udptl t38\r\n"]);
        let answer = decline_unanswered_media(offer, false);
        assert_eq!(
            media_lines(&answer),
            vec!["m=audio 20100 RTP/AVP 0", "m=image 0 udptl t38"],
            "{answer}"
        );
    }

    #[test]
    fn a_port_range_is_declined_whole() {
        // RFC 4566 §5.14 `<port>/<number of ports>`: the whole field goes, not just its first half.
        let offer = offer_with_sections(&["m=video 49550/2 RTP/AVP 96\r\n"]);
        let answer = decline_unanswered_media(offer, false);
        assert_eq!(
            media_lines(&answer),
            vec!["m=audio 20100 RTP/AVP 0", "m=video 0 RTP/AVP 96"],
            "{answer}"
        );
    }

    #[test]
    fn declining_leaves_every_other_line_byte_identical() {
        let offer = offer_with_sections(&[concat!(
            "m=video 49550 RTP/AVP 96\r\n",
            "c=IN IP4 192.0.2.11\r\n",
            "a=rtpmap:96 H264/90000\r\n",
        )]);
        let answer = decline_unanswered_media(offer.clone(), false);
        assert_eq!(
            answer,
            offer.replace("m=video 49550 ", "m=video 0 "),
            "only the port moves"
        );
    }

    #[test]
    fn only_an_anchoring_text_rewrite_answers_the_text_stream() {
        use siphon_rtp_srtp::sdes::CryptoSuite;
        let engine = EngineMedia::new("127.0.0.1:40002".parse::<SocketAddr>().unwrap(), None);
        let crypto = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        assert!(TextRewrite::Anchor(engine).is_anchored());
        assert!(TextRewrite::AnchorSecure { engine, crypto }.is_anchored());
        assert!(!TextRewrite::Decline.is_anchored());
        assert!(!TextRewrite::None.is_anchored());
    }

    #[test]
    fn a_malformed_media_line_is_declined_once() {
        // Found by the property test below. An m-line with no media type reads back, once declined,
        // as one whose port does not parse, so the port alone cannot say it is already declined.
        let once = decline_unanswered_media("m=\n\r\r".to_string(), false);
        assert_eq!(once, "m= 0 RTP/AVP\r\n\r");
        assert_eq!(decline_unanswered_media(once.clone(), false), once);
    }

    proptest::proptest! {
        #[test]
        fn declining_arbitrary_text_never_panics_and_is_idempotent(text in "[ -~\r\n\t]{0,400}") {
            let once = decline_unanswered_media(text, false);
            proptest::prop_assert_eq!(decline_unanswered_media(once.clone(), false), once);
        }
    }
}
