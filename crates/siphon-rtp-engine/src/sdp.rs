//! Minimal SDP parse + connection/port rewrite for the relay walking skeleton.
//!
//! This is **not** a full SDP engine — it does exactly what offer/answer relay needs: find the
//! audio stream's remote RTP/RTCP transport addresses (its `c=` connection line, `m=audio` port,
//! `a=rtcp-mux` / `a=rtcp:` attributes per RFC 5761 / RFC 3605) and rewrite them to engine-
//! allocated endpoints. The richer SDP surface (ICE, DTLS fingerprints, multiple m-lines,
//! bandwidth, direction) layers on later.
//!
//! IPv4 only for now (VoLTE/PSTN media is IPv4); an IPv6 `c=IN IP6` path is a later addition.

use std::net::{IpAddr, SocketAddr};

/// Errors from SDP parsing/rewrite.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SdpError {
    /// No `m=audio` media line was present.
    #[error("no audio media line in SDP")]
    NoAudioMedia,
    /// The `m=audio` line's port field was missing or not a number.
    #[error("malformed m=audio port")]
    MediaPort,
    /// No usable `c=IN IP4 <addr>` connection line applied to the audio stream.
    #[error("no IPv4 connection address for audio stream")]
    ConnectionAddress,
}

/// Line ending emitted by the rewriter (SDP mandates CRLF; RFC 4566 §5).
const CRLF: &str = "\r\n";

/// The remote audio transport advertised by an SDP, plus its RTCP multiplexing intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaInfo {
    /// Remote RTP address (the audio `c=`/`m=audio` transport).
    pub remote_rtp: SocketAddr,
    /// Remote RTCP address: the `a=rtcp:` port if present, else RTP port + 1 (RFC 3550); equal to
    /// `remote_rtp` when `rtcp_mux` is set.
    pub remote_rtcp: SocketAddr,
    /// Whether the stream offered `a=rtcp-mux` (RTP and RTCP share one port, RFC 5761).
    pub rtcp_mux: bool,
}

/// The engine endpoints to advertise in a rewritten SDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineMedia {
    /// The engine's RTP endpoint (advertised in `c=`/`m=audio`).
    pub rtp: SocketAddr,
    /// The engine's RTCP endpoint, when not multiplexed (advertised as `a=rtcp:`). `None` ⇒
    /// rtcp-mux (any `a=rtcp:` line is dropped; RTCP rides the RTP port).
    pub rtcp: Option<SocketAddr>,
}

/// A rewritten SDP plus the remote media info parsed from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewritten {
    /// The rewritten SDP advertising the engine endpoints.
    pub sdp: String,
    /// The remote audio info parsed from the input SDP.
    pub media: MediaInfo,
}

/// Indices and values located in one scan of an SDP's audio stream.
struct AudioScan {
    session_conn: Option<(usize, IpAddr)>,
    audio_media: Option<(usize, u16)>,
    audio_conn: Option<(usize, IpAddr)>,
    rtcp_mux: bool,
    /// `a=rtcp:` line within the audio section: (line index, port).
    audio_rtcp: Option<(usize, u16)>,
}

fn parse_connection_addr(value: &str) -> Option<IpAddr> {
    let mut parts = value.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("IN"), Some("IP4"), Some(addr)) => addr.parse::<IpAddr>().ok().filter(IpAddr::is_ipv4),
        _ => None,
    }
}

fn parse_media_port(value: &str) -> Option<u16> {
    let mut parts = value.split_whitespace();
    match parts.next() {
        Some("audio") => parts.next().and_then(|port| port.parse::<u16>().ok()),
        _ => None,
    }
}

/// Parse the port from an `a=rtcp:<port> [...]` attribute body (`rtcp:<port> ...`).
fn parse_rtcp_attr(value: &str) -> Option<u16> {
    value
        .strip_prefix("rtcp:")?
        .split_whitespace()
        .next()
        .and_then(|port| port.parse::<u16>().ok())
}

/// Scan the SDP once, recording the audio stream's connection, port, and RTCP attributes.
fn scan(sdp: &str) -> AudioScan {
    let mut scan = AudioScan {
        session_conn: None,
        audio_media: None,
        audio_conn: None,
        rtcp_mux: false,
        audio_rtcp: None,
    };
    let mut seen_media = false;
    let mut in_audio = false;

    for (index, raw_line) in sdp.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "m" => {
                if scan.audio_media.is_none() {
                    if let Some(port) = parse_media_port(value) {
                        scan.audio_media = Some((index, port));
                        in_audio = true;
                        seen_media = true;
                        continue;
                    }
                }
                in_audio = false;
                seen_media = true;
            }
            "c" => {
                if let Some(addr) = parse_connection_addr(value) {
                    if !seen_media {
                        scan.session_conn = Some((index, addr));
                    } else if in_audio && scan.audio_conn.is_none() {
                        scan.audio_conn = Some((index, addr));
                    }
                }
            }
            "a" if in_audio => {
                if value == "rtcp-mux" {
                    scan.rtcp_mux = true;
                } else if let Some(port) = parse_rtcp_attr(value) {
                    scan.audio_rtcp = Some((index, port));
                }
            }
            _ => {}
        }
    }
    scan
}

/// Resolve the parsed [`MediaInfo`] from a scan.
fn media_info(scan: &AudioScan) -> Result<MediaInfo, SdpError> {
    let (_, rtp_port) = scan.audio_media.ok_or(SdpError::NoAudioMedia)?;
    let (_, ip) = scan
        .audio_conn
        .or(scan.session_conn)
        .ok_or(SdpError::ConnectionAddress)?;
    let remote_rtp = SocketAddr::new(ip, rtp_port);
    let remote_rtcp = if scan.rtcp_mux {
        remote_rtp
    } else {
        let rtcp_port = scan
            .audio_rtcp
            .map(|(_, port)| port)
            .unwrap_or(rtp_port.wrapping_add(1));
        SocketAddr::new(ip, rtcp_port)
    };
    Ok(MediaInfo {
        remote_rtp,
        remote_rtcp,
        rtcp_mux: scan.rtcp_mux,
    })
}

/// Parse the remote audio transport info from an SDP without rewriting it.
pub fn parse(sdp: &str) -> Result<MediaInfo, SdpError> {
    media_info(&scan(sdp))
}

/// Rewrite the audio stream's RTP/RTCP transport to `engine`, returning the new SDP and the remote
/// media info parsed from the input.
///
/// The connection line applying to the audio stream (media-level `c=` else session-level) and the
/// `m=audio` port are rewritten to `engine.rtp`. For non-mux (`engine.rtcp = Some`), an `a=rtcp:`
/// line is rewritten or inserted for the engine RTCP port; for mux (`engine.rtcp = None`), any
/// `a=rtcp:` line is dropped (RTCP rides the RTP port).
pub fn rewrite(sdp: &str, engine: EngineMedia) -> Result<Rewritten, SdpError> {
    let scan = scan(sdp);
    let media = media_info(&scan)?;
    let (media_index, _) = scan.audio_media.ok_or(SdpError::NoAudioMedia)?;
    let (conn_index, _) = scan
        .audio_conn
        .or(scan.session_conn)
        .ok_or(SdpError::ConnectionAddress)?;
    let rtcp_index = scan.audio_rtcp.map(|(index, _)| index);

    let mut lines: Vec<String> = Vec::new();
    for (index, raw_line) in sdp.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if index == media_index {
            lines.push(rewrite_media_line(line, engine.rtp.port()));
            // Insert a fresh a=rtcp line only if there is no existing one to rewrite in place.
            if let Some(rtcp) = engine.rtcp {
                if rtcp_index.is_none() {
                    lines.push(format!("a=rtcp:{}", rtcp.port()));
                }
            }
        } else if index == conn_index {
            lines.push(format!("c=IN IP4 {}", engine.rtp.ip()));
        } else if Some(index) == rtcp_index {
            match engine.rtcp {
                Some(rtcp) => lines.push(format!("a=rtcp:{}", rtcp.port())),
                None => { /* mux: drop the explicit a=rtcp line */ }
            }
        } else {
            lines.push(line.to_string());
        }
    }

    Ok(Rewritten {
        sdp: lines.join(CRLF),
        media,
    })
}

/// Replace the port (2nd field) of an `m=audio <port> ...` line, preserving the rest.
fn rewrite_media_line(line: &str, port: u16) -> String {
    let body = line.strip_prefix("m=").unwrap_or(line);
    let mut fields = body.split(' ');
    let media = fields.next().unwrap_or("audio");
    let _old_port = fields.next();
    let rest: Vec<&str> = fields.collect();
    if rest.is_empty() {
        format!("m={media} {port}")
    } else {
        format!("m={media} {port} {}", rest.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(addr: &str, port: u16) -> String {
        format!(
            "v=0\r\n\
             o=alice 2890844526 2890844526 IN IP4 host.invalid\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0 8 96\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:96 telephone-event/8000\r\n"
        )
    }

    #[test]
    fn parse_defaults_rtcp_to_rtp_plus_one() {
        let info = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert_eq!(info.remote_rtp, "203.0.113.7:49170".parse().unwrap());
        assert_eq!(info.remote_rtcp, "203.0.113.7:49171".parse().unwrap());
        assert!(!info.rtcp_mux);
    }

    #[test]
    fn parse_honors_explicit_rtcp_attribute() {
        let mut sdp = offer("203.0.113.7", 49170);
        sdp.push_str("a=rtcp:53000\r\n");
        let info = parse(&sdp).expect("parse");
        assert_eq!(info.remote_rtcp, "203.0.113.7:53000".parse().unwrap());
    }

    #[test]
    fn parse_detects_rtcp_mux() {
        let mut sdp = offer("203.0.113.7", 49170);
        sdp.push_str("a=rtcp-mux\r\n");
        let info = parse(&sdp).expect("parse");
        assert!(info.rtcp_mux);
        assert_eq!(info.remote_rtcp, info.remote_rtp, "mux shares the RTP port");
    }

    #[test]
    fn rewrites_rtp_and_inserts_rtcp_for_non_mux() {
        let sdp = offer("203.0.113.7", 49170);
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: Some("127.0.0.1:40001".parse().unwrap()),
        };
        let result = rewrite(&sdp, engine).expect("rewrite");
        assert_eq!(result.media.remote_rtp, "203.0.113.7:49170".parse().unwrap());
        assert!(result.sdp.contains("c=IN IP4 127.0.0.1"));
        assert!(result.sdp.contains("m=audio 40000 RTP/AVP 0 8 96"));
        assert!(result.sdp.contains("a=rtcp:40001"), "engine RTCP port advertised");
        assert!(!result.sdp.contains("203.0.113.7"));
        let reparsed = parse(&result.sdp).expect("reparse");
        assert_eq!(reparsed.remote_rtp, engine.rtp);
        assert_eq!(reparsed.remote_rtcp, "127.0.0.1:40001".parse().unwrap());
    }

    #[test]
    fn rewrites_existing_rtcp_attribute_in_place() {
        let mut sdp = offer("203.0.113.7", 49170);
        sdp.push_str("a=rtcp:53000\r\n");
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: Some("127.0.0.1:40001".parse().unwrap()),
        };
        let result = rewrite(&sdp, engine).expect("rewrite");
        assert!(result.sdp.contains("a=rtcp:40001"));
        assert!(!result.sdp.contains("53000"));
        assert_eq!(result.sdp.matches("a=rtcp:").count(), 1, "no duplicate a=rtcp");
    }

    #[test]
    fn mux_drops_rtcp_attribute_and_keeps_mux_flag() {
        let mut sdp = offer("203.0.113.7", 49170);
        sdp.push_str("a=rtcp:53000\r\n");
        sdp.push_str("a=rtcp-mux\r\n");
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: None,
        };
        let result = rewrite(&sdp, engine).expect("rewrite");
        assert!(!result.sdp.contains("a=rtcp:"), "explicit a=rtcp dropped under mux");
        assert!(result.sdp.contains("a=rtcp-mux"), "mux flag preserved");
    }

    #[test]
    fn media_level_connection_overrides_session_level() {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP4 198.51.100.9\r\n";
        let engine = EngineMedia {
            rtp: "127.0.0.1:41000".parse().unwrap(),
            rtcp: None,
        };
        let result = rewrite(sdp, engine).expect("rewrite");
        assert_eq!(result.media.remote_rtp, "198.51.100.9:5000".parse().unwrap());
        assert!(result.sdp.contains("c=IN IP4 10.0.0.1"));
        assert!(result.sdp.contains("c=IN IP4 127.0.0.1"));
        assert!(!result.sdp.contains("198.51.100.9"));
    }

    #[test]
    fn rejects_missing_audio_and_connection() {
        assert_eq!(
            parse("v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 5000 RTP/AVP 96\r\n"),
            Err(SdpError::NoAudioMedia)
        );
        assert_eq!(
            parse("v=0\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n"),
            Err(SdpError::ConnectionAddress)
        );
    }

    use proptest::prelude::*;

    proptest! {
        /// Arbitrary text (the SDP comes off the signalling path) must decode-or-error, never panic.
        /// `(?s)` lets `.` match newlines so line-structured garbage is exercised too.
        #[test]
        fn parsers_never_panic(text in "(?s).{0,400}") {
            let _ = parse(&text);
            let engine = EngineMedia {
                rtp: "192.0.2.1:10000".parse().expect("addr"),
                rtcp: None,
            };
            let _ = rewrite(&text, engine);
        }
    }
}
