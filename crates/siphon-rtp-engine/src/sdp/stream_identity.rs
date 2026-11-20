//! The stream identity in an answer the engine writes itself (`answer_local`, a conference seat).
//!
//! Those answers are built by rewriting the *offer*, and an offer describes its sender: `a=ssrc`
//! (RFC 5576 §4.1) names the SSRCs the offerer will send, `a=msid` / `a=msid-semantic` (RFC 8830
//! §2) the media streams those belong to, and `a=extmap` (RFC 8285 §5) the header extensions it
//! offers to use. Echoed back, they tell the offerer the engine sends with the offerer's own SSRC.
//! A WebRTC receiver then builds its receive stream for that SSRC. An m-section with a signalled
//! SSRC gets no unsignalled-stream fallback, so every packet the engine actually sends (under its
//! own SSRC, with no header extension to demux on) is dropped before decode: a participant that
//! everyone hears, and that hears nothing.
//!
//! So an engine-written answer drops all of them and, where the engine knows the SSRC it will send,
//! names that one. `a=mid` and `a=group:BUNDLE` stay: the answerer echoes those (RFC 8843 §7.3).

/// The SSRC an engine-written answer advertises for its own audio, and the CNAME that RFC 5576
/// §6.1 requires beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnSsrc {
    pub ssrc: u32,
    pub cname: String,
}

impl OwnSsrc {
    /// `ssrc` with a fresh random CNAME: 96 random bits, in hex (RFC 7022 §4.2: a short-term
    /// persistent identifier of at least 96 bits, which is all a CNAME that ties one seat's
    /// streams together needs).
    #[must_use]
    pub fn with_random_cname(ssrc: u32) -> Self {
        let mut bytes = [0u8; 12];
        // A CNAME is an identifier, not a secret: a randomness failure falls back to one derived
        // from the SSRC, which is still unique per seat.
        if getrandom::fill(&mut bytes).is_err() {
            bytes[..4].copy_from_slice(&ssrc.to_be_bytes());
        }
        Self {
            ssrc,
            cname: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        }
    }
}

/// Whether `line` (without its line ending) describes the offerer's own streams or the header
/// extensions it offered — what an engine-written answer must not echo.
fn describes_the_offerer(line: &str) -> bool {
    [
        "a=ssrc:",
        "a=ssrc-group:",
        "a=msid:",
        "a=msid-semantic:",
        "a=extmap:",
        "a=extmap-allow-mixed",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

/// Strip the offerer's stream identity and header extensions from an answer the engine wrote from
/// that offer, drop the RTCP feedback it offered on the audio and text the engine terminates, and, with `own`, name the SSRC the engine sends in the audio section. Every section
/// is stripped (they all describe the offerer); only the first audio section gains `own`, after
/// its RFC 4566 §5 prelude (`i=`, `c=`, `b=`, `k=`), where an attribute belongs.
#[must_use]
pub fn own_stream_identity(sdp: &str, own: Option<&OwnSsrc>) -> String {
    let lines: Vec<&str> = sdp.split_inclusive('\n').collect();
    let bare = |line: &str| line.trim_end_matches(['\r', '\n']).to_string();
    let audio = lines.iter().position(|line| {
        let line = bare(line);
        line.starts_with("m=audio ") || line == "m=audio"
    });
    // The line after which `own` is written: the audio section's last prelude line, else its m=.
    let anchor = audio.map(|media| {
        lines
            .iter()
            .enumerate()
            .skip(media + 1)
            .take_while(|(_, line)| !bare(line).starts_with("m="))
            .filter(|(_, line)| {
                let line = bare(line);
                ["i=", "c=", "b=", "k="]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
            })
            .map(|(index, _)| index)
            .last()
            .unwrap_or(media)
    });
    let ending = if sdp.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(sdp.len());
    let mut terminated_section = false;
    for (index, line) in lines.iter().enumerate() {
        let text = bare(line);
        if let Some(media) = text.strip_prefix("m=") {
            terminated_section = media.starts_with("audio") || media.starts_with("text");
        }
        // RFC 4585 §4.2: an answer lists only the feedback the answerer implements. The engine
        // terminates the audio and text it answers here and sends Sender and Receiver Reports only,
        // so the offer's `a=rtcp-fb` there (transport-cc, nack, goog-remb) is not answered. A video
        // section is written by the engine with the feedback the room serves, and keeps it.
        let unserved_feedback = terminated_section && text.starts_with("a=rtcp-fb:");
        if !describes_the_offerer(&text) && !unserved_feedback {
            out.push_str(line);
            if !line.ends_with('\n') && Some(index) == anchor {
                out.push_str(ending);
            }
        }
        if Some(index) == anchor {
            if let Some(own) = own {
                out.push_str(&format!("a=ssrc:{} cname:{}{ending}", own.ssrc, own.cname));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A browser offer as libwebrtc writes one (Unified Plan, BUNDLE, one audio and one video
    /// m-section), on RFC 5737 addresses.
    const BROWSER_OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 4611731400430051336 2 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE 0 1\r\n",
        "a=extmap-allow-mixed\r\n",
        "a=msid-semantic: WMS stream-a\r\n",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "a=mid:0\r\n",
        "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n",
        "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
        "a=sendrecv\r\n",
        "a=msid:stream-a track-a\r\n",
        "a=rtpmap:111 opus/48000/2\r\n",
        "a=ssrc:2712110744 cname:offerer-cname\r\n",
        "a=ssrc:2712110744 msid:stream-a track-a\r\n",
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "a=mid:1\r\n",
        "a=ssrc-group:FID 1111 2222\r\n",
        "a=ssrc:1111 cname:offerer-cname\r\n",
    );

    fn own() -> OwnSsrc {
        OwnSsrc {
            ssrc: 0x3fae_627b,
            cname: "engine-cname".into(),
        }
    }

    #[test]
    fn audio_and_text_feedback_the_engine_does_not_serve_is_not_answered() {
        // RFC 4585 §4.2: an answer lists only the feedback the answerer implements. The engine
        // terminates the audio and text of these answers and sends Sender and Receiver Reports
        // only, so a browser's transport-cc, nack or goog-remb on them would be a promise it never
        // keeps. A video section keeps its own: the engine writes it with what the room serves.
        let offer = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "a=rtpmap:111 opus/48000/2\r\n",
            "a=rtcp-fb:111 transport-cc\r\n",
            "a=rtcp-fb:111 nack\r\n",
            "m=text 9 RTP/AVPF 98\r\n",
            "a=rtpmap:98 t140/1000\r\n",
            "a=rtcp-fb:* nack\r\n",
            "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n",
            "a=rtpmap:96 H264/90000\r\n",
            "a=rtcp-fb:96 nack pli\r\n",
            "a=rtcp-fb:96 ccm fir\r\n",
        );
        let answer = own_stream_identity(offer, None);
        let (audio_and_text, video) = answer.split_once("m=video").expect("video");
        assert!(!audio_and_text.contains("rtcp-fb"), "{answer}");
        assert!(video.contains("a=rtcp-fb:96 nack pli\r\n"), "{answer}");
        assert!(video.contains("a=rtcp-fb:96 ccm fir\r\n"), "{answer}");
        assert!(answer.contains("a=rtpmap:111 opus/48000/2\r\n"));
    }

    #[test]
    fn nothing_that_describes_the_offerer_survives() {
        let answer = own_stream_identity(BROWSER_OFFER, Some(&own()));
        for gone in [
            "2712110744",
            "1111",
            "msid",
            "extmap",
            "ssrc-group",
            "offerer-cname",
        ] {
            assert!(!answer.contains(gone), "{gone} survived:\n{answer}");
        }
    }

    #[test]
    fn the_answer_names_exactly_the_engines_ssrc_after_the_audio_prelude() {
        let answer = own_stream_identity(BROWSER_OFFER, Some(&own()));
        let ssrc_lines: Vec<&str> = answer
            .lines()
            .filter(|line| line.starts_with("a=ssrc:"))
            .collect();
        assert_eq!(ssrc_lines, ["a=ssrc:1068393083 cname:engine-cname"]);
        let lines: Vec<&str> = answer.lines().collect();
        let media = lines
            .iter()
            .position(|line| line.starts_with("m=audio"))
            .expect("audio");
        assert_eq!(lines[media + 1], "c=IN IP4 192.0.2.10");
        assert_eq!(lines[media + 2], "a=ssrc:1068393083 cname:engine-cname");
    }

    #[test]
    fn bundle_and_mid_are_kept_because_the_answerer_echoes_them() {
        let answer = own_stream_identity(BROWSER_OFFER, None);
        assert!(answer.contains("a=group:BUNDLE 0 1\r\n"));
        assert!(answer.contains("a=mid:0\r\n"));
        assert!(answer.contains("a=mid:1\r\n"));
        assert!(answer.contains("a=rtpmap:111 opus/48000/2\r\n"));
    }

    #[test]
    fn without_an_own_ssrc_the_answer_names_none() {
        let answer = own_stream_identity(BROWSER_OFFER, None);
        assert!(!answer.contains("a=ssrc"), "{answer}");
    }

    #[test]
    fn it_is_idempotent_once_the_engine_ssrc_is_in() {
        let once = own_stream_identity(BROWSER_OFFER, Some(&own()));
        let stripped_again = own_stream_identity(&once, None);
        assert!(!stripped_again.contains("a=ssrc"));
        assert_eq!(
            own_stream_identity(&own_stream_identity(BROWSER_OFFER, None), None),
            own_stream_identity(BROWSER_OFFER, None)
        );
    }

    #[test]
    fn an_answer_with_no_audio_section_gains_nothing() {
        let sdp = "v=0\r\ns=-\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=ssrc:1 cname:x\r\n";
        assert_eq!(
            own_stream_identity(sdp, Some(&own())),
            "v=0\r\ns=-\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\n"
        );
    }

    #[test]
    fn a_last_line_without_an_ending_still_gets_a_well_formed_ssrc_line() {
        let sdp = "v=0\r\ns=-\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0";
        assert_eq!(
            own_stream_identity(sdp, Some(&own())),
            "v=0\r\ns=-\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=ssrc:1068393083 cname:engine-cname\r\n"
        );
    }

    #[test]
    fn a_random_cname_carries_96_bits_and_differs_per_seat() {
        let first = OwnSsrc::with_random_cname(7);
        let second = OwnSsrc::with_random_cname(7);
        assert_eq!(first.cname.len(), 24, "12 bytes in hex");
        assert!(first.cname.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first.cname, second.cname);
    }

    proptest::proptest! {
        #[test]
        fn never_panics_and_never_leaves_an_offerer_line(text in "\\PC*") {
            let out = own_stream_identity(&text, None);
            for line in out.lines() {
                proptest::prop_assert!(!describes_the_offerer(line.trim_end_matches('\r')));
            }
        }
    }
}
