//! The `a=key-mgmt` line of an SDP the engine writes (RFC 4567).
//!
//! MCPTT secures media end to end with keys the UEs agree on outside the engine (3GPP TS 33.180
//! §7.5.2), signalled by `a=key-mgmt:mikey ...`. That line belongs to the controller: it is the
//! controller's `profile.key_mgmt`, written verbatim, and nothing else.
//!
//! * The engine never **echoes** the line of the SDP it rewrites. An engine-written SDP is made by
//!   rewriting the other side's, and a key-management message names the party that wrote it; the
//!   other side's would tell the peer to key its stream with material that was never meant for it.
//! * The engine never **invents** one.
//! * The engine never **drops** the controller's.
//!
//! So every `a=key-mgmt` of the rewritten SDP is removed (session level, where RFC 4567 §4 lets it
//! apply to every stream, and the audio section) and the controller's line, when it has one, is
//! written at the end of the first audio section.

/// Remove every `a=key-mgmt` line from the session region and the audio sections of `sdp`, and write
/// `key_mgmt` (the part after `a=key-mgmt:`) at the end of the first audio section when given. An
/// audio section the answer declines (port 0) gets none: there is no stream to key.
#[must_use]
pub fn apply_key_mgmt(sdp: &str, key_mgmt: Option<&str>) -> String {
    let bare = |line: &str| line.trim_end_matches(['\r', '\n']).to_string();
    let line_ending = if sdp.contains("\r\n") { "\r\n" } else { "\n" };
    let mut kept: Vec<&str> = Vec::new();
    // Which region each line is in: the session region before the first `m=`, then one media section.
    let mut in_session = true;
    let mut in_audio = false;
    let mut seen_audio = false;
    let mut first_audio_live = false;
    // Index in `kept` the first audio section ends at.
    let mut first_audio_end: Option<usize> = None;
    for line in sdp.split_inclusive('\n') {
        let text = bare(line);
        if text.starts_with("m=") {
            if in_audio && first_audio_end.is_none() {
                first_audio_end = Some(kept.len());
            }
            in_session = false;
            in_audio = text.starts_with("m=audio ") || text == "m=audio";
            if in_audio && !seen_audio {
                seen_audio = true;
                // A declined stream carries port 0 (RFC 3264 §6).
                first_audio_live = text.split_whitespace().nth(1) != Some("0");
            }
        }
        if (in_session || in_audio) && text.starts_with("a=key-mgmt:") {
            continue;
        }
        kept.push(line);
    }
    if in_audio && first_audio_end.is_none() {
        first_audio_end = Some(kept.len());
    }
    let (Some(value), Some(end), true) = (key_mgmt, first_audio_end, first_audio_live) else {
        return kept.concat();
    };
    let mut out = String::with_capacity(sdp.len() + value.len() + 16);
    for (index, line) in kept.iter().enumerate() {
        if index == end {
            out.push_str(&format!("a=key-mgmt:{value}{line_ending}"));
        }
        out.push_str(line);
    }
    if end == kept.len() {
        if out.ends_with('\n') {
            out.push_str(&format!("a=key-mgmt:{value}{line_ending}"));
        } else {
            // The SDP's last line has no ending of its own; neither does the one written after it.
            out.push_str(&format!("{line_ending}a=key-mgmt:{value}"));
        }
    }
    out
}

/// Whether the first audio section (or the session region) keys the stream itself: an SDES
/// `a=crypto` (RFC 4568) or a DTLS `a=fingerprint` (RFC 5763). Used to refuse a controller's
/// `a=key-mgmt` beside the engine's own keying.
#[must_use]
pub fn terminates_keying(sdp: &str) -> bool {
    let mut in_audio_or_session = true;
    sdp.lines().any(|line| {
        if line.starts_with("m=") {
            in_audio_or_session = line.starts_with("m=audio");
        }
        in_audio_or_session && (line.starts_with("a=crypto:") || line.starts_with("a=fingerprint:"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = concat!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n",
        "m=audio 4000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        "a=key-mgmt:mikey PEER\r\n",
        "m=application 4002 udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n",
    );

    fn key_lines(sdp: &str) -> Vec<&str> {
        sdp.lines()
            .filter(|line| line.starts_with("a=key-mgmt:"))
            .collect()
    }

    #[test]
    fn the_offerers_line_is_not_echoed_without_a_controller_line() {
        let out = apply_key_mgmt(OFFER, None);
        assert!(key_lines(&out).is_empty(), "{out}");
        assert!(out.contains("a=rtpmap:0 PCMU/8000\r\n") && out.contains("m=application"));
    }

    #[test]
    fn exactly_the_controllers_line_replaces_the_offerers() {
        let out = apply_key_mgmt(OFFER, Some("mikey OWN"));
        assert_eq!(key_lines(&out), vec!["a=key-mgmt:mikey OWN"]);
        // At the end of the audio section, before the next m=.
        let audio = out.find("m=audio").unwrap();
        let line = out.find("a=key-mgmt:mikey OWN").unwrap();
        let application = out.find("m=application").unwrap();
        assert!(audio < line && line < application, "{out}");
        assert!(out.ends_with("a=fmtp:MCPTT mc_queueing\r\n"));
    }

    #[test]
    fn an_audio_section_that_ends_the_sdp_gets_the_line_last() {
        let sdp = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let out = apply_key_mgmt(sdp, Some("mikey OWN"));
        assert!(
            out.ends_with("a=rtpmap:0 PCMU/8000\r\na=key-mgmt:mikey OWN\r\n"),
            "{out}"
        );
        let bare = "v=0\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000";
        let out = apply_key_mgmt(bare, Some("mikey OWN"));
        assert!(
            out.ends_with("a=rtpmap:0 PCMU/8000\r\na=key-mgmt:mikey OWN"),
            "{out}"
        );
    }

    #[test]
    fn a_session_level_line_is_removed_too() {
        let sdp = "v=0\r\na=key-mgmt:mikey PEER\r\nm=audio 4000 RTP/AVP 0\r\n";
        assert!(key_lines(&apply_key_mgmt(sdp, None)).is_empty());
        assert_eq!(
            key_lines(&apply_key_mgmt(sdp, Some("mikey OWN"))),
            vec!["a=key-mgmt:mikey OWN"]
        );
    }

    #[test]
    fn a_declined_audio_stream_is_not_keyed() {
        let sdp = "v=0\r\nm=audio 0 RTP/AVP 0\r\n";
        assert!(key_lines(&apply_key_mgmt(sdp, Some("mikey OWN"))).is_empty());
    }

    #[test]
    fn a_line_in_another_section_is_left_alone() {
        let sdp = "v=0\r\nm=audio 4000 RTP/AVP 0\r\nm=video 5000 RTP/AVP 96\r\na=key-mgmt:mikey VIDEO\r\n";
        let out = apply_key_mgmt(sdp, None);
        assert_eq!(key_lines(&out), vec!["a=key-mgmt:mikey VIDEO"]);
    }

    #[test]
    fn bare_newlines_are_kept() {
        let sdp = "v=0\nm=audio 4000 RTP/AVP 0\na=rtpmap:0 PCMU/8000\n";
        let out = apply_key_mgmt(sdp, Some("mikey OWN"));
        assert_eq!(
            out,
            "v=0\nm=audio 4000 RTP/AVP 0\na=rtpmap:0 PCMU/8000\na=key-mgmt:mikey OWN\n"
        );
    }

    #[test]
    fn engine_keying_is_detected_in_the_audio_section_only() {
        assert!(terminates_keying(
            "v=0\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:x\r\n"
        ));
        assert!(terminates_keying(
            "v=0\r\na=fingerprint:sha-256 AA\r\nm=audio 4000 UDP/TLS/RTP/SAVPF 0\r\n"
        ));
        assert!(!terminates_keying(OFFER));
        assert!(!terminates_keying(
            "v=0\r\nm=audio 4000 RTP/AVP 0\r\nm=text 5000 RTP/SAVP 98\r\na=crypto:1 X inline:x\r\n"
        ));
    }
}
