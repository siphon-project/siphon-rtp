//! Minimal SDP connection/port rewrite for the relay walking skeleton.
//!
//! This is **not** a full SDP engine — it does exactly what offer/answer relay needs: find the
//! audio media stream's remote transport address (its `c=` connection line + `m=audio` port) and
//! rewrite both to point at an engine-allocated endpoint. The richer SDP surface (ICE, DTLS
//! fingerprints, multiple m-lines, bandwidth, direction attributes) layers on later; this keeps
//! the rewrite small, allocation-light, and exhaustively testable.
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

/// Parse the dotted-quad address from a `c=IN IP4 <addr>` line body (`IN IP4 <addr>`).
fn parse_connection_addr(value: &str) -> Option<IpAddr> {
    let mut parts = value.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("IN"), Some("IP4"), Some(addr)) => addr.parse::<IpAddr>().ok().filter(IpAddr::is_ipv4),
        _ => None,
    }
}

/// Parse the port from an `m=audio <port> <proto> <fmt...>` line body (`audio <port> ...`).
fn parse_media_port(value: &str) -> Option<u16> {
    let mut parts = value.split_whitespace();
    match parts.next() {
        Some("audio") => parts.next().and_then(|port| port.parse::<u16>().ok()),
        _ => None,
    }
}

/// The result of a rewrite: the new SDP text and the *original* audio transport address (the
/// remote the engine must forward toward).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewritten {
    /// The rewritten SDP, advertising the engine endpoint.
    pub sdp: String,
    /// The remote audio address parsed from the input SDP.
    pub remote: SocketAddr,
}

/// Rewrite the audio stream's connection address and port to `engine`, returning the new SDP and
/// the remote audio address that was advertised in the input.
///
/// The connection line that applies to the audio stream is the media-level `c=` if present,
/// otherwise the session-level `c=`. That line and the `m=audio` port are rewritten to `engine`.
pub fn rewrite(sdp: &str, engine: SocketAddr) -> Result<Rewritten, SdpError> {
    // Locate the session-level c= (before any m=) and the audio m= line + its media-level c=.
    let mut session_conn: Option<(usize, IpAddr)> = None;
    let mut audio_media: Option<(usize, u16)> = None;
    let mut audio_conn: Option<(usize, IpAddr)> = None;
    let mut seen_any_media = false;
    let mut audio_is_current_media = false;

    for (index, raw_line) in sdp.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "m" => {
                let is_audio = audio_media.is_none() && parse_media_port(value).is_some();
                if is_audio {
                    let port = parse_media_port(value).ok_or(SdpError::MediaPort)?;
                    audio_media = Some((index, port));
                    audio_is_current_media = true;
                } else {
                    audio_is_current_media = false;
                }
                seen_any_media = true;
            }
            "c" => {
                if let Some(addr) = parse_connection_addr(value) {
                    if !seen_any_media {
                        session_conn = Some((index, addr));
                    } else if audio_is_current_media && audio_conn.is_none() {
                        audio_conn = Some((index, addr));
                    }
                }
            }
            _ => {}
        }
    }

    let (media_index, remote_port) = audio_media.ok_or(SdpError::NoAudioMedia)?;
    let (conn_index, remote_ip) = audio_conn
        .or(session_conn)
        .ok_or(SdpError::ConnectionAddress)?;
    let remote = SocketAddr::new(remote_ip, remote_port);

    // Rebuild the SDP, rewriting only the audio m= port and the applicable c= address.
    let mut out = String::with_capacity(sdp.len() + 16);
    for (index, raw_line) in sdp.split('\n').enumerate() {
        // Drop a synthetic trailing empty element from a final '\n' without duplicating it.
        if index > 0 {
            out.push_str(CRLF);
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if index == media_index {
            out.push_str(&rewrite_media_line(line, engine.port()));
        } else if index == conn_index {
            out.push_str(&format!("c=IN IP4 {}", engine.ip()));
        } else {
            out.push_str(line);
        }
    }

    Ok(Rewritten { sdp: out, remote })
}

/// Replace the port (2nd field) of an `m=audio <port> ...` line, preserving the rest.
fn rewrite_media_line(line: &str, port: u16) -> String {
    // line == "m=audio <port> <proto> <fmt...>"
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
    fn rewrites_session_level_connection_and_port() {
        let sdp = offer("203.0.113.7", 49170);
        let engine: SocketAddr = "127.0.0.1:40000".parse().expect("engine addr");
        let result = rewrite(&sdp, engine).expect("rewrite");

        assert_eq!(result.remote, "203.0.113.7:49170".parse().expect("remote"));
        // The rewritten SDP now advertises the engine endpoint.
        assert!(result.sdp.contains("c=IN IP4 127.0.0.1"));
        assert!(result.sdp.contains("m=audio 40000 RTP/AVP 0 8 96"));
        // The original remote address is gone.
        assert!(!result.sdp.contains("203.0.113.7"));
        // Untouched lines survive verbatim.
        assert!(result.sdp.contains("a=rtpmap:0 PCMU/8000"));
        // Re-parsing the rewritten SDP yields the engine transport address.
        let reparsed = rewrite(&result.sdp, "127.0.0.1:1".parse().expect("x")).expect("reparse");
        assert_eq!(reparsed.remote, engine);
    }

    #[test]
    fn media_level_connection_overrides_session_level() {
        let sdp = "v=0\r\n\
                   c=IN IP4 10.0.0.1\r\n\
                   t=0 0\r\n\
                   m=audio 5000 RTP/AVP 0\r\n\
                   c=IN IP4 198.51.100.9\r\n";
        let engine: SocketAddr = "127.0.0.1:41000".parse().expect("engine");
        let result = rewrite(sdp, engine).expect("rewrite");
        // Media-level c= is the audio stream's address.
        assert_eq!(result.remote, "198.51.100.9:5000".parse().expect("remote"));
        // Only the media-level c= is rewritten; the session-level c= is left intact.
        assert!(result.sdp.contains("c=IN IP4 10.0.0.1"));
        assert!(result.sdp.contains("c=IN IP4 127.0.0.1"));
        assert!(!result.sdp.contains("198.51.100.9"));
    }

    #[test]
    fn preserves_line_count_and_order() {
        let sdp = offer("192.0.2.1", 6000);
        let result = rewrite(&sdp, "127.0.0.1:7000".parse().expect("e")).expect("rewrite");
        assert_eq!(
            sdp.lines().count(),
            result.sdp.lines().count(),
            "rewrite must not add or drop lines"
        );
    }

    #[test]
    fn rejects_missing_audio() {
        let sdp = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 5000 RTP/AVP 96\r\n";
        assert_eq!(rewrite(sdp, "127.0.0.1:1".parse().unwrap()), Err(SdpError::NoAudioMedia));
    }

    #[test]
    fn rejects_missing_connection() {
        let sdp = "v=0\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n";
        assert_eq!(
            rewrite(sdp, "127.0.0.1:1".parse().unwrap()),
            Err(SdpError::ConnectionAddress)
        );
    }
}
