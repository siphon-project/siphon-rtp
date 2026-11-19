//! A two-party call's `m=video` stream, anchored like its audio one (RFC 3264 §6, RFC 3550 §11): the
//! stream's rewrite pass, its direction rules, and the connection line a passed-through section keeps.
//!
//! [`super::rewrite`] points the session `c=` at the engine for the audio stream. A video section
//! with no `c=` of its own inherits the session one (RFC 4566 §5.7), so it would read the engine's
//! address with the phone's own port. [`keep_passthrough_connection`] gives such a section the
//! offerer's original connection line, a separate pass over the finished SDP as the floor and
//! forwarding-room video passes are, so the audio rewrite is untouched.

use std::net::SocketAddr;

use siphon_rtp_srtp::sdes::CryptoAttribute;

use super::data_channel::{bundled_mids, locate_audio, mid_of};
use super::floor::split_lines;
use super::{
    addrtype, parse_connection_addr, EngineMedia, Fingerprint, MediaDirection, Setup, CRLF,
};

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

/// What the engine reads of the first live `m=video` section of an SDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoStream {
    /// Where the party receives RTP: the section's `c=` (else the session's) and the `m=` port.
    pub remote_rtp: SocketAddr,
    /// Where the party receives RTCP: the `a=rtcp` port (RFC 3605) when stated, else the RTP port
    /// (RFC 5761 §5.1.1) under `a=rtcp-mux`, else the RTP port + 1 (RFC 3550 §11).
    pub remote_rtcp: SocketAddr,
    /// The party's own direction for the stream (RFC 3264 §6.1); absent means `sendrecv`.
    pub direction: MediaDirection,
    /// The stream offers `a=rtcp-mux` (RFC 5761).
    pub rtcp_mux: bool,
    /// The transport profile, third field of the `m=` line.
    pub transport: String,
    /// The keyable `a=crypto` lines of the section, in order (RFC 4568 §5.1.2: the first is the one
    /// accepted). A line whose suite the SRTP context does not run is skipped (RFC 4568 §7.1.1).
    pub crypto: Vec<CryptoAttribute>,
    /// The section's `a=mid` (RFC 5888 §4).
    pub mid: Option<String>,
    /// The section and the first live audio section are in one `a=group:BUNDLE` line (RFC 8843 §7.2),
    /// so the stream rides the audio's transport: its port, its ICE and its DTLS association.
    pub bundled: bool,
    /// The first live audio section's `a=mid`, which the bundle's answer must carry too.
    pub audio_mid: Option<String>,
    /// A payload type of the video `m=` line is also the audio's: inside a bundle the two could not be
    /// told apart (RFC 8843 §9.2).
    pub payload_collision: bool,
    /// The payload types of the `m=` line, which tell the stream's RTP from the audio's inside a
    /// bundle (RFC 8843 §9.2: a payload type is unique across the bundle).
    pub payload_types: Vec<u8>,
    /// The DTLS certificate fingerprint of the section, else the session's (RFC 8122 §5).
    pub fingerprint: Option<Fingerprint>,
    /// The `a=setup` role of the section, else the session's (RFC 4145 §4, RFC 5763 §5).
    pub setup: Option<Setup>,
    /// The section carries ICE of its own (`a=ice-ufrag` or `a=candidate`), or the session's ICE
    /// applies to it (RFC 8839 §4): with no bundle, ICE would run per `m=` line.
    pub ice: bool,
}

impl VideoStream {
    /// Whether this is plain RTP (`RTP/AVP`, `RTP/AVPF`).
    #[must_use]
    pub fn is_plain(&self) -> bool {
        matches!(
            self.transport.to_ascii_uppercase().as_str(),
            "RTP/AVP" | "RTP/AVPF"
        )
    }

    /// Whether this is SDES-SRTP (`RTP/SAVP`, `RTP/SAVPF`, RFC 4568): keyed by `a=crypto`.
    #[must_use]
    pub fn is_sdes(&self) -> bool {
        matches!(
            self.transport.to_ascii_uppercase().as_str(),
            "RTP/SAVP" | "RTP/SAVPF"
        )
    }

    /// Whether this is DTLS-SRTP (`UDP/TLS/RTP/SAVP[F]`, RFC 5764), which the engine does not carry
    /// for video yet.
    #[must_use]
    pub fn is_dtls(&self) -> bool {
        self.transport.to_ascii_uppercase().starts_with("UDP/TLS/")
    }

    /// Whether the transport carries the RFC 4585 feedback profile (`AVPF`, `SAVPF`).
    #[must_use]
    pub fn is_feedback_profile(&self) -> bool {
        self.transport.to_ascii_uppercase().ends_with('F')
    }
}

/// Whether `direction` lets its party send.
#[must_use]
pub fn sends(direction: MediaDirection) -> bool {
    matches!(
        direction,
        MediaDirection::SendRecv | MediaDirection::SendOnly
    )
}

/// Whether `direction` lets its party receive.
#[must_use]
pub fn receives(direction: MediaDirection) -> bool {
    matches!(
        direction,
        MediaDirection::SendRecv | MediaDirection::RecvOnly
    )
}

/// Which way video may flow between two parties, from each one's own stated direction (RFC 3264
/// §6.1, §8.4): near to far needs the near party to send and the far one to receive, and the other
/// way round. Returns `(near_to_far, far_to_near)`.
#[must_use]
pub fn flow_directions(near: MediaDirection, far: MediaDirection) -> (bool, bool) {
    (sends(near) && receives(far), sends(far) && receives(near))
}

/// The first live (non-zero port) video section: `m=` line index, exclusive end, port.
fn locate(lines: &[&str]) -> Option<(usize, usize, u16)> {
    let mut found: Option<(usize, u16)> = None;
    for (index, line) in lines.iter().enumerate() {
        let Some(value) = line.strip_prefix("m=") else {
            continue;
        };
        if let Some((start, port)) = found {
            return Some((start, index, port));
        }
        let mut fields = value.split_whitespace();
        if fields.next() == Some("video") {
            found = fields
                .next()
                .and_then(|field| field.split('/').next())
                .and_then(|field| field.parse::<u16>().ok())
                .filter(|port| *port != 0)
                .map(|port| (index, port));
        }
    }
    found.map(|(start, port)| (start, lines.len(), port))
}

/// Whether the SDP has an `m=video` line at all, live or declined.
#[must_use]
pub fn offers_video(sdp: &str) -> bool {
    split_lines(sdp)
        .iter()
        .any(|line| line.starts_with("m=video "))
}

/// The first live video section of `sdp`, or `None` when there is none or every one is at port 0.
#[must_use]
pub fn parse_video_stream(sdp: &str) -> Option<VideoStream> {
    let lines = split_lines(sdp);
    let (start, end, port) = locate(&lines)?;
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(0);
    let connection = |range: std::ops::Range<usize>| {
        lines[range]
            .iter()
            .find_map(|line| parse_connection_addr(line.strip_prefix("c=")?))
    };
    let section = &lines[start + 1..end];
    let address = connection(start + 1..end).or_else(|| connection(0..first_media))?;
    let direction_of = |scope: &[&str]| {
        scope
            .iter()
            .find_map(|line| MediaDirection::parse(line.strip_prefix("a=")?))
    };
    let direction = direction_of(section)
        .or_else(|| direction_of(&lines[..first_media]))
        .unwrap_or_default();
    let rtcp_mux = section.contains(&"a=rtcp-mux");
    let rtcp_port = section.iter().find_map(|line| {
        line.strip_prefix("a=rtcp:")?
            .split_whitespace()
            .next()?
            .parse::<u16>()
            .ok()
    });
    let rtcp_port = if rtcp_mux {
        port
    } else {
        rtcp_port.unwrap_or_else(|| port.saturating_add(1))
    };
    let transport = lines[start]
        .strip_prefix("m=")?
        .split_whitespace()
        .nth(2)?
        .to_string();
    // RFC 4568 §6.1: the SDES key of this section, scoped to it as the text stream's is.
    let crypto = section
        .iter()
        .filter_map(|line| CryptoAttribute::parse_keyable(line.strip_prefix("a=")?))
        .collect();
    let mid = mid_of(&lines, start, end);
    // RFC 8843 §7.2: bundled when one `a=group:BUNDLE` line names this section's mid and the audio's.
    let bundled = mid.as_deref().is_some_and(|video_mid| {
        let audio_mid = locate_audio(&lines).and_then(|(from, to)| mid_of(&lines, from, to));
        let group = bundled_mids(&lines);
        audio_mid.is_some_and(|audio_mid| {
            group.contains(&video_mid) && group.contains(&audio_mid.as_str())
        })
    });
    let audio_section = locate_audio(&lines);
    let audio_mid = audio_section.and_then(|(from, to)| mid_of(&lines, from, to));
    let payload_types: Vec<u8> = lines[start]
        .split_whitespace()
        .skip(3)
        .filter_map(|field| field.parse().ok())
        .collect();
    let payload_collision = audio_section.is_some_and(|(from, _)| {
        lines[from]
            .split_whitespace()
            .skip(3)
            .filter_map(|field| field.parse::<u8>().ok())
            .any(|number| payload_types.contains(&number))
    });
    // RFC 8122 §5, RFC 4145 §4: the section's own attribute, else the session's.
    let attribute = |name: &str| {
        section
            .iter()
            .find_map(|line| line.strip_prefix(name))
            .or_else(|| {
                lines[..first_media]
                    .iter()
                    .find_map(|line| line.strip_prefix(name))
            })
    };
    let fingerprint = attribute("a=fingerprint:")
        .and_then(|value| Fingerprint::parse(&format!("fingerprint:{value}")));
    let setup = attribute("a=setup:").and_then(|value| Setup::parse(&format!("setup:{value}")));
    // RFC 8839 §4: ICE credentials at the session level apply to every `m=` line.
    let ice = attribute("a=ice-ufrag:").is_some()
        || section.iter().any(|line| line.starts_with("a=candidate:"));
    Some(VideoStream {
        remote_rtp: SocketAddr::new(address, port),
        remote_rtcp: SocketAddr::new(address, rtcp_port),
        direction,
        rtcp_mux,
        transport,
        crypto,
        mid,
        bundled,
        audio_mid,
        payload_collision,
        payload_types,
        fingerprint,
        setup,
        ice,
    })
}

/// How the anchored video section is keyed toward the party it is presented to.
#[derive(Debug, Clone)]
pub enum VideoKeying {
    /// Plain RTP: the transport is written as `RTP/AVP[F]` and the peer's `a=crypto` is dropped.
    Plain,
    /// SDES-SRTP (RFC 4568): the transport is written as `RTP/SAVP[F]`, the peer's `a=crypto` is
    /// dropped and this key, the engine's own for the leg, is advertised in its place.
    Sdes(CryptoAttribute),
    /// DTLS-SRTP on an association of the video endpoint's own (RFC 5764): the transport is written
    /// as `UDP/TLS/RTP/SAVP[F]`, the peer's `a=fingerprint`, `a=setup` and `a=tls-id` are dropped and
    /// the engine's own fingerprint and role are advertised in their place (RFC 5763 §5).
    Dtls {
        /// The engine certificate's fingerprint (`a=fingerprint`, RFC 8122).
        fingerprint: Fingerprint,
        /// The engine's DTLS role for the section (`a=setup`).
        setup: Setup,
    },
    /// DTLS-SRTP on the transport the party's audio already runs (RFC 8843): the section takes the
    /// audio's port and connection, carries no transport attribute of its own (the audio section's
    /// fingerprint, `a=setup` and ICE are the bundle's, RFC 8843 §7.3), keeps its `a=mid` and joins
    /// the `a=group:BUNDLE` line.
    Bundled {
        /// The party's audio section `a=mid`.
        audio_mid: String,
        /// The party's video section `a=mid`.
        video_mid: String,
    },
}

/// How a presented SDP treats its video stream, beside [`super::TextRewrite`] and
/// [`super::ImageRewrite`].
#[derive(Debug, Clone, Default)]
pub enum VideoRewrite {
    /// Leave the section as it arrived (the two parties exchange video directly).
    #[default]
    Passthrough,
    /// Anchor the first live video section on the engine's video endpoints, keyed as `keying` says;
    /// any further live video section is declined (RFC 3264 §6).
    Anchor {
        /// The engine endpoints the section advertises.
        engine: EngineMedia,
        /// How the section is keyed toward the party it is presented to.
        keying: VideoKeying,
    },
    /// Decline every live video section (port 0, RFC 3264 §6).
    Decline,
}

impl VideoRewrite {
    /// Apply the directive to a presented SDP.
    #[must_use]
    pub fn apply(self, presented: &str) -> String {
        match self {
            Self::Passthrough => presented.to_string(),
            Self::Anchor { engine, keying } => anchor_video(presented, engine, keying),
            Self::Decline => decline_video(presented),
        }
    }
}

/// `line`, an `m=` line, with its transport profile written for `keying`: `RTP/SAVP[F]` for SDES,
/// `RTP/AVP[F]` for plain, keeping the feedback `F` of the original (RFC 4585 §4.2).
fn with_transport(line: &str, keying: &VideoKeying) -> String {
    line.split(' ')
        .enumerate()
        .map(|(position, field)| {
            if position != 2 {
                return field.to_string();
            }
            let feedback = field.to_ascii_uppercase().ends_with('F');
            let profile = match (keying, feedback) {
                (VideoKeying::Plain, false) => "RTP/AVP",
                (VideoKeying::Plain, true) => "RTP/AVPF",
                // RFC 5764 §8: the DTLS-SRTP transport profiles.
                (VideoKeying::Dtls { .. } | VideoKeying::Bundled { .. }, false) => {
                    "UDP/TLS/RTP/SAVP"
                }
                (VideoKeying::Dtls { .. } | VideoKeying::Bundled { .. }, true) => {
                    "UDP/TLS/RTP/SAVPF"
                }
                (VideoKeying::Sdes(_), false) => "RTP/SAVP",
                (VideoKeying::Sdes(_), true) => "RTP/SAVPF",
            };
            profile.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `line`, an `m=` line, with its port field replaced.
fn with_port(line: &str, port: u16) -> String {
    line.split(' ')
        .enumerate()
        .map(|(position, field)| {
            if position == 1 {
                port.to_string()
            } else {
                field.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decline every live video section.
#[must_use]
pub fn decline_video(sdp: &str) -> String {
    let lines = split_lines(sdp);
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for line in &lines {
        if is_live_video(line) {
            out.push(with_port(line, 0));
        } else {
            out.push((*line).to_string());
        }
    }
    out.join(CRLF)
}

/// An ICE or key attribute of the peer's own, which never describes an engine endpoint.
fn is_peer_transport_attribute(line: &str) -> bool {
    line.starts_with("a=candidate:")
        || line.starts_with("a=ice-")
        || line == "a=end-of-candidates"
        || line.starts_with("a=remote-candidates")
}

/// Anchor the first live video section on `engine`: its port, a media-level `c=` of the engine's
/// advertised address (RFC 4566 §5.7), the `a=rtcp` port (RFC 3605) unless muxed, and the transport
/// profile and key `keying` names (the peer's own `a=crypto` is never copied). Every other
/// line, the codecs, `fmtp`, `rtcp-fb` and the direction included, is copied verbatim. A further
/// live video section is declined.
#[must_use]
pub fn anchor_video(sdp: &str, engine: EngineMedia, keying: VideoKeying) -> String {
    let lines = split_lines(sdp);
    let first = locate(&lines);
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 3);
    let mut in_anchored = false;
    let mut pending_connection = false;
    let flush_connection = |out: &mut Vec<String>| {
        out.push(format!(
            "c=IN {} {}",
            addrtype(engine.advertised_ip),
            engine.advertised_ip
        ));
    };
    let finish_section = |out: &mut Vec<String>, pending: &mut bool| {
        if *pending {
            flush_connection(out);
            *pending = false;
        }
        if let Some(rtcp) = engine.rtcp {
            if engine.rtp.port().checked_add(1) != Some(rtcp.port()) {
                out.push(format!("a=rtcp:{}", rtcp.port()));
            }
        }
        // RFC 4568 §5.1: the engine's own key for the leg, advertised in place of the peer's.
        match &keying {
            VideoKeying::Sdes(crypto) => out.push(format!("a={}", crypto.to_attribute_value())),
            // RFC 5763 §5: the engine's own fingerprint and role for the section's association.
            VideoKeying::Dtls { fingerprint, setup } => {
                out.push(format!("a={}", fingerprint.to_attribute_value()));
                out.push(format!("a=setup:{}", setup.token()));
            }
            // RFC 5888 §4: the mid the party offered, echoed.
            VideoKeying::Bundled { video_mid, .. } => out.push(format!("a=mid:{video_mid}")),
            VideoKeying::Plain => {}
        }
    };
    for (index, line) in lines.iter().enumerate() {
        if line.starts_with("m=") {
            if in_anchored {
                finish_section(&mut out, &mut pending_connection);
                in_anchored = false;
            }
            if Some(index) == first.map(|(start, _, _)| start) {
                in_anchored = true;
                pending_connection = true;
                out.push(with_transport(&with_port(line, engine.rtp.port()), &keying));
            } else if is_live_video(line) {
                out.push(with_port(line, 0));
            } else {
                out.push((*line).to_string());
            }
            continue;
        }
        if in_anchored {
            if pending_connection && !line.starts_with("i=") {
                flush_connection(&mut out);
                pending_connection = false;
            }
            // The peer's own keying never describes the engine's: its SDES key, and its DTLS
            // fingerprint, role and association id (RFC 8842 §4). A bundled section's mid is written
            // by the keying, as it is the party's own.
            if line.starts_with("c=")
                || line.starts_with("a=rtcp:")
                || line.starts_with("a=crypto:")
                || line.starts_with("a=fingerprint:")
                || line.starts_with("a=setup:")
                || line.starts_with("a=tls-id:")
                || (matches!(keying, VideoKeying::Bundled { .. }) && line.starts_with("a=mid:"))
                || is_peer_transport_attribute(line)
            {
                continue;
            }
        }
        // An empty trailing element is the SDP's final line break; keep it.
        out.push((*line).to_string());
    }
    if in_anchored {
        // The last section: its closing lines go before the SDP's trailing empty element.
        let trailing_empty = out.last().is_some_and(String::is_empty);
        if trailing_empty {
            out.pop();
        }
        finish_section(&mut out, &mut pending_connection);
        if trailing_empty {
            out.push(String::new());
        }
    }
    let anchored = out.join(CRLF);
    match keying {
        VideoKeying::Bundled {
            audio_mid,
            video_mid,
        } => join_bundle(&anchored, &audio_mid, &video_mid),
        _ => match first.and_then(|(start, end, _)| mid_of(&lines, start, end)) {
            Some(video_mid) => leave_bundle(&anchored, &video_mid),
            None => anchored,
        },
    }
}

/// `sdp` with `video_mid` in its `a=group:BUNDLE` line beside `audio_mid`, the group written when it
/// has none, and the audio section's `a=mid` written when it has none (RFC 8843 §7.3: an answer's
/// group names the mids the offer carried, and every bundled section has its mid, RFC 5888 §4).
fn join_bundle(sdp: &str, audio_mid: &str, video_mid: &str) -> String {
    let lines = split_lines(sdp);
    let Some((audio_start, audio_end)) = locate_audio(&lines) else {
        return sdp.to_string();
    };
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(lines.len());
    let group_at = lines[..first_media]
        .iter()
        .position(|line| line.starts_with("a=group:BUNDLE"));
    let has_audio_mid = mid_of(&lines, audio_start, audio_end).is_some();
    // The audio section's `a=mid` ends its attributes, before the empty remainder of an SDP that ends
    // in CRLF.
    let mut mid_at = audio_end;
    while mid_at > audio_start + 1 && lines[mid_at - 1].is_empty() {
        mid_at -= 1;
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 2);
    for (index, line) in lines.iter().enumerate() {
        if index == mid_at && !has_audio_mid {
            out.push(format!("a=mid:{audio_mid}"));
        }
        if Some(index) == group_at {
            let mut mids: Vec<&str> = line["a=group:BUNDLE".len()..].split_whitespace().collect();
            for wanted in [audio_mid, video_mid] {
                if !mids.contains(&wanted) {
                    mids.push(wanted);
                }
            }
            out.push(format!("a=group:BUNDLE {}", mids.join(" ")));
            continue;
        }
        if group_at.is_none() && index == first_media {
            out.push(format!("a=group:BUNDLE {audio_mid} {video_mid}"));
        }
        out.push((*line).to_string());
    }
    out.join(CRLF)
}

/// `sdp` with `video_mid` out of its `a=group:BUNDLE` lines: the video section now travels on a
/// transport of its own, which the offerer's group would deny (RFC 8843 §7.3.3). A group left with
/// one mid or none is dropped.
fn leave_bundle(sdp: &str, video_mid: &str) -> String {
    let lines = split_lines(sdp);
    let first_media = lines
        .iter()
        .position(|line| line.starts_with("m="))
        .unwrap_or(lines.len());
    let mut changed = false;
    let kept: Vec<String> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let Some(group) = line
                .strip_prefix("a=group:BUNDLE")
                .filter(|_| index < first_media)
            else {
                return Some((*line).to_string());
            };
            let mids: Vec<&str> = group
                .split_whitespace()
                .filter(|mid| *mid != video_mid)
                .collect();
            if mids.len() == group.split_whitespace().count() {
                return Some((*line).to_string());
            }
            changed = true;
            (mids.len() > 1).then(|| format!("a=group:BUNDLE {}", mids.join(" ")))
        })
        .collect();
    if changed {
        kept.join(CRLF)
    } else {
        sdp.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 20100 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "m=video 6000 RTP/AVPF 96\r\n",
        "c=IN IP4 192.0.2.11\r\n",
        "a=rtpmap:96 H264/90000\r\n",
        "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\n",
        "a=rtcp-fb:96 nack pli\r\n",
        "a=rtcp:6005\r\n",
        "a=sendonly\r\n",
    );

    fn engine(rtcp: Option<u16>) -> EngineMedia {
        EngineMedia::new(
            "198.51.100.5:30000".parse().expect("addr"),
            rtcp.map(|port| SocketAddr::from(([198, 51, 100, 5], port))),
        )
    }

    fn video_lines(sdp: &str) -> Vec<String> {
        sdp.split("\r\n")
            .skip_while(|line| !line.starts_with("m=video"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn parses_the_stream_address_rtcp_port_and_direction() {
        let stream = parse_video_stream(OFFER).expect("video");
        assert_eq!(
            stream.remote_rtp,
            "192.0.2.11:6000".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(
            stream.remote_rtcp,
            "192.0.2.11:6005".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(stream.direction, MediaDirection::SendOnly);
        assert!(!stream.rtcp_mux);
        assert!(stream.is_plain());
    }

    #[test]
    fn rtcp_defaults_to_the_next_port_and_to_the_rtp_port_under_mux() {
        let plain = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 7000 RTP/AVP 96\r\n";
        let stream = parse_video_stream(plain).expect("video");
        assert_eq!(stream.remote_rtcp.port(), 7001);
        let muxed = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 7000 RTP/AVP 96\r\na=rtcp-mux\r\n";
        assert_eq!(
            parse_video_stream(muxed).expect("video").remote_rtcp.port(),
            7000
        );
    }

    #[test]
    fn a_secure_profile_is_not_plain_and_a_declined_section_is_not_live() {
        let secure = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 7000 RTP/SAVP 96\r\n";
        assert!(!parse_video_stream(secure).expect("video").is_plain());
        let declined = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 0 RTP/AVP 96\r\n";
        assert!(parse_video_stream(declined).is_none());
        assert!(offers_video(declined));
    }

    #[test]
    fn anchoring_moves_port_connection_and_rtcp_and_keeps_the_rest_verbatim() {
        let anchored = anchor_video(OFFER, engine(Some(30003)), VideoKeying::Plain);
        assert_eq!(
            video_lines(&anchored),
            vec![
                "m=video 30000 RTP/AVPF 96",
                "c=IN IP4 198.51.100.5",
                "a=rtpmap:96 H264/90000",
                "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1",
                "a=rtcp-fb:96 nack pli",
                "a=sendonly",
                "a=rtcp:30003",
                "",
            ],
            "{anchored}"
        );
        assert!(
            anchored.contains("m=audio 20100 RTP/AVP 0"),
            "audio untouched"
        );
        assert!(
            anchored.contains("c=IN IP4 192.0.2.10"),
            "session c= untouched"
        );
    }

    #[test]
    fn anchoring_a_muxed_stream_writes_no_rtcp_line_and_an_adjacent_port_needs_none() {
        let muxed = anchor_video(OFFER, engine(None), VideoKeying::Plain);
        assert!(!video_lines(&muxed)
            .iter()
            .any(|line| line.starts_with("a=rtcp:")));
        let adjacent = anchor_video(OFFER, engine(Some(30001)), VideoKeying::Plain);
        assert!(!video_lines(&adjacent)
            .iter()
            .any(|line| line.starts_with("a=rtcp:")));
    }

    #[test]
    fn anchoring_inherits_nothing_when_the_section_has_no_connection_of_its_own() {
        let sdp = concat!(
            "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n",
            "m=audio 20100 RTP/AVP 0\r\n",
            "m=video 6000 RTP/AVP 96\r\ni=door\r\na=rtpmap:96 H264/90000\r\n",
        );
        let anchored = anchor_video(sdp, engine(None), VideoKeying::Plain);
        assert_eq!(
            video_lines(&anchored),
            vec![
                "m=video 30000 RTP/AVP 96",
                "i=door",
                "c=IN IP4 198.51.100.5",
                "a=rtpmap:96 H264/90000",
                "",
            ]
        );
    }

    #[test]
    fn anchoring_drops_the_peers_ice_lines_and_declines_a_second_video_section() {
        let sdp = concat!(
            "v=0\r\nc=IN IP4 192.0.2.10\r\n",
            "m=video 6000 RTP/AVP 96\r\na=ice-ufrag:abcd\r\na=candidate:1 1 udp 1 192.0.2.10 6000 typ host\r\n",
            "a=rtpmap:96 H264/90000\r\n",
            "m=video 6002 RTP/AVP 97\r\na=rtpmap:97 VP8/90000\r\n",
        );
        let anchored = anchor_video(sdp, engine(None), VideoKeying::Plain);
        assert!(!anchored.contains("ice-ufrag") && !anchored.contains("candidate"));
        assert!(anchored.contains("m=video 0 RTP/AVP 97"), "{anchored}");
    }

    #[test]
    fn declining_zeroes_every_live_video_section_and_keeps_the_formats() {
        let declined = decline_video(OFFER);
        assert!(declined.contains("m=video 0 RTP/AVPF 96"), "{declined}");
        assert!(declined.contains("m=audio 20100 RTP/AVP 0"));
    }

    #[test]
    fn passthrough_returns_the_sdp_unchanged() {
        assert_eq!(VideoRewrite::Passthrough.apply(OFFER), OFFER);
    }

    #[test]
    fn a_door_station_stream_flows_one_way_only() {
        // A sendonly camera answered recvonly: only the camera's direction forwards.
        assert_eq!(
            flow_directions(MediaDirection::SendOnly, MediaDirection::RecvOnly),
            (true, false)
        );
        assert_eq!(
            flow_directions(MediaDirection::SendRecv, MediaDirection::SendRecv),
            (true, true)
        );
        assert_eq!(
            flow_directions(MediaDirection::SendRecv, MediaDirection::Inactive),
            (false, false)
        );
        assert_eq!(
            flow_directions(MediaDirection::RecvOnly, MediaDirection::SendOnly),
            (false, true)
        );
    }
}

#[cfg(test)]
mod keying_tests {
    use super::*;
    use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};

    const KEY_A: &str =
        "crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0e";
    const KEY_B: &str =
        "crypto:2 AES_CM_128_HMAC_SHA1_32 inline:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0e";

    fn secure_offer() -> String {
        format!(
            concat!(
                "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n",
                "m=audio 20100 RTP/SAVP 0\r\na=crypto:9 AES_CM_128_HMAC_SHA1_80 inline:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0e\r\n",
                "m=video 6000 RTP/SAVPF 96\r\na=rtpmap:96 H264/90000\r\na={b}\r\na={a}\r\n",
            ),
            a = KEY_A,
            b = KEY_B
        )
    }

    fn engine() -> EngineMedia {
        EngineMedia::new("198.51.100.5:30000".parse().expect("addr"), None)
    }

    fn minted(tag: u32) -> CryptoAttribute {
        CryptoAttribute::generate(tag, CryptoSuite::AesCm128HmacSha1_80).expect("key")
    }

    #[test]
    fn a_secure_video_section_carries_its_own_keyable_crypto_lines_in_order() {
        let stream = parse_video_stream(&secure_offer()).expect("video");
        assert!(stream.is_sdes() && !stream.is_plain() && !stream.is_dtls());
        // The `_32` line is recognised but cannot be keyed, so only the keyable one is offered on.
        assert_eq!(stream.crypto.len(), 1, "{:?}", stream.crypto);
        assert_eq!(stream.crypto[0].tag, 1);
        // The audio section's key (tag 9) is not the video's.
        assert!(stream.crypto.iter().all(|crypto| crypto.tag != 9));
    }

    #[test]
    fn a_dtls_video_section_is_neither_plain_nor_sdes() {
        let dtls = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=video 7000 UDP/TLS/RTP/SAVPF 96\r\n";
        let stream = parse_video_stream(dtls).expect("video");
        assert!(stream.is_dtls() && !stream.is_plain() && !stream.is_sdes());
    }

    #[test]
    fn anchoring_a_secure_stream_secure_replaces_the_peers_key_with_the_engines_own() {
        let key = minted(1);
        let anchored = VideoRewrite::Anchor {
            engine: engine(),
            keying: VideoKeying::Sdes(key),
        }
        .apply(&secure_offer());
        let section: Vec<String> = anchored
            .split("\r\n")
            .skip_while(|line| !line.starts_with("m=video"))
            .map(str::to_string)
            .collect();
        assert_eq!(section[0], "m=video 30000 RTP/SAVPF 96");
        let crypto: Vec<&String> = section
            .iter()
            .filter(|line| line.starts_with("a=crypto:"))
            .collect();
        assert_eq!(crypto.len(), 1, "{anchored}");
        assert_eq!(*crypto[0], format!("a={}", key.to_attribute_value()));
        assert!(!anchored.contains("WVNfX19z") || crypto[0].contains(&key.to_attribute_value()));
        assert!(
            anchored.contains("a=crypto:9 "),
            "the audio section keeps its own key line"
        );
    }

    #[test]
    fn anchoring_a_plain_stream_toward_a_secure_party_writes_savp_and_the_engines_key() {
        let plain =
            "v=0\r\nc=IN IP4 192.0.2.10\r\nm=video 6000 RTP/AVPF 96\r\na=rtpmap:96 H264/90000\r\n";
        let key = minted(1);
        let anchored = VideoRewrite::Anchor {
            engine: engine(),
            keying: VideoKeying::Sdes(key),
        }
        .apply(plain);
        assert!(
            anchored.contains("m=video 30000 RTP/SAVPF 96"),
            "{anchored}"
        );
        assert!(anchored.contains(&format!("a={}", key.to_attribute_value())));
    }

    #[test]
    fn anchoring_a_secure_stream_toward_a_plain_party_writes_avp_and_no_key() {
        let anchored = VideoRewrite::Anchor {
            engine: engine(),
            keying: VideoKeying::Plain,
        }
        .apply(&secure_offer());
        let section = anchored
            .split("m=video")
            .nth(1)
            .expect("video section")
            .to_string();
        assert!(section.starts_with(" 30000 RTP/AVPF 96"), "{anchored}");
        assert!(!section.contains("a=crypto:"), "{anchored}");
    }
}

#[cfg(test)]
mod connection_tests {
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

#[cfg(test)]
mod dtls_tests {
    use super::*;
    use crate::sdp::{rewrite, IceRewrite, ImageRewrite, SecurityAdvertisement, TextRewrite};

    /// A browser-shaped offer: audio and video bundled on one transport (RFC 8843), ICE and DTLS on
    /// both sections.
    const BUNDLED_OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE 0 1\r\n",
        "m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "a=mid:0\r\n",
        "a=ice-ufrag:abcd\r\n",
        "a=ice-pwd:efghefghefghefghefghefgh\r\n",
        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n",
        "a=setup:actpass\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "a=mid:1\r\n",
        "a=ice-ufrag:abcd\r\n",
        "a=ice-pwd:efghefghefghefghefghefgh\r\n",
        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n",
        "a=setup:actpass\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:96 H264/90000\r\n",
        "a=rtpmap:97 rtx/90000\r\n",
        "a=fmtp:97 apt=96\r\n",
        "a=sendrecv\r\n",
    );

    /// The same shape with no bundle and no ICE: a phone with DTLS-SRTP on a port of its own per stream.
    const UNBUNDLED_OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 20100 UDP/TLS/RTP/SAVPF 0\r\n",
        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n",
        "a=setup:actpass\r\n",
        "a=rtcp-mux\r\n",
        "m=video 6000 UDP/TLS/RTP/SAVPF 96\r\n",
        "a=fingerprint:sha-256 EE:FF:00:11\r\n",
        "a=setup:actpass\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:96 H264/90000\r\n",
    );

    fn engine_fingerprint() -> Fingerprint {
        Fingerprint {
            hash_function: "sha-256".to_string(),
            bytes: vec![0x11, 0x22, 0x33, 0x44],
        }
    }

    fn engine_audio() -> EngineMedia {
        EngineMedia::new("198.51.100.5:40000".parse().expect("addr"), None)
    }

    fn lines(sdp: &str) -> Vec<&str> {
        sdp.split("\r\n").collect()
    }

    fn section<'a>(sdp: &'a str, kind: &str) -> Vec<&'a str> {
        let all = lines(sdp);
        let prefix = format!("m={kind} ");
        let start = all.iter().position(|line| line.starts_with(&prefix));
        let Some(start) = start else {
            return Vec::new();
        };
        let end = all[start + 1..]
            .iter()
            .position(|line| line.starts_with("m="))
            .map_or(all.len(), |offset| start + 1 + offset);
        all[start..end].to_vec()
    }

    #[test]
    fn a_bundled_video_section_is_read_with_its_mid_payload_types_and_transport_state() {
        let stream = parse_video_stream(BUNDLED_OFFER).expect("video");
        assert!(stream.is_dtls());
        assert!(stream.bundled, "mids 0 and 1 are in one BUNDLE group");
        assert_eq!(stream.mid.as_deref(), Some("1"));
        assert_eq!(stream.payload_types, vec![96, 97]);
        assert_eq!(stream.setup, Some(Setup::Actpass));
        assert_eq!(
            stream.fingerprint.as_ref().map(|print| print.bytes.clone()),
            Some(vec![0xAA, 0xBB, 0xCC, 0xDD])
        );
        assert!(stream.ice);
    }

    #[test]
    fn a_video_section_left_out_of_the_bundle_group_is_not_bundled() {
        let offer = BUNDLED_OFFER.replace("a=group:BUNDLE 0 1", "a=group:BUNDLE 0");
        let stream = parse_video_stream(&offer).expect("video");
        assert!(!stream.bundled);
        assert!(stream.ice, "unbundled with ICE is what the engine declines");
    }

    #[test]
    fn an_unbundled_phone_carries_its_own_fingerprint_and_no_ice() {
        let stream = parse_video_stream(UNBUNDLED_OFFER).expect("video");
        assert!(stream.is_dtls() && !stream.bundled && !stream.ice);
        assert_eq!(
            stream.fingerprint.as_ref().map(|print| print.bytes.clone()),
            Some(vec![0xEE, 0xFF, 0x00, 0x11]),
            "the section's own fingerprint wins over the audio's"
        );
    }

    #[test]
    fn the_session_level_fingerprint_and_setup_apply_to_a_section_without_its_own() {
        let offer = concat!(
            "v=0\r\nc=IN IP4 192.0.2.10\r\na=fingerprint:sha-256 AA:BB\r\na=setup:passive\r\nt=0 0\r\n",
            "m=video 6000 UDP/TLS/RTP/SAVPF 96\r\n",
        );
        let stream = parse_video_stream(offer).expect("video");
        assert_eq!(stream.setup, Some(Setup::Passive));
        assert!(stream.fingerprint.is_some());
    }

    #[test]
    fn the_answer_to_a_bundled_party_keeps_the_group_and_mids_and_writes_the_engines_fingerprint_once(
    ) {
        // What the engine presents the DTLS party: the audio section the audio rewrite wrote (the
        // engine's own fingerprint and role), built from the callee's plain answer, and that answer's
        // video section, which the video pass then anchors on the audio's transport.
        let callee_answer = concat!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.20\r\ns=-\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
            "m=video 30002 RTP/AVPF 96\r\na=rtpmap:96 H264/90000\r\na=rtcp-mux\r\na=sendrecv\r\n",
        );
        let audio = rewrite(
            callee_answer,
            engine_audio(),
            IceRewrite::Keep,
            Some(SecurityAdvertisement::Dtls {
                fingerprint: engine_fingerprint(),
                setup: Setup::Active,
                tls_id: None,
            }),
            None,
            TextRewrite::None,
            ImageRewrite::None,
        )
        .expect("rewrite")
        .sdp;
        let presented = VideoRewrite::Anchor {
            engine: engine_audio(),
            keying: VideoKeying::Bundled {
                audio_mid: "0".to_string(),
                video_mid: "1".to_string(),
            },
        }
        .apply(&audio);
        let all = lines(&presented);
        let first_media = all
            .iter()
            .position(|line| line.starts_with("m="))
            .expect("m=");
        assert!(
            all[..first_media].contains(&"a=group:BUNDLE 0 1"),
            "{presented}"
        );
        let audio_section = section(&presented, "audio");
        assert!(audio_section.contains(&"a=mid:0"), "{presented}");
        let video_section = section(&presented, "video");
        assert_eq!(
            video_section[0], "m=video 40000 UDP/TLS/RTP/SAVPF 96",
            "the audio's port and the DTLS profile: {presented}"
        );
        assert!(video_section.contains(&"a=mid:1"), "{presented}");
        assert!(video_section.contains(&"c=IN IP4 198.51.100.5"));
        assert!(
            !video_section
                .iter()
                .any(|line| line.starts_with("a=fingerprint:")
                    || line.starts_with("a=setup:")
                    || line.starts_with("a=ice-")),
            "a bundled section carries no transport attribute of its own: {presented}"
        );
        assert_eq!(
            all.iter()
                .filter(|line| line.starts_with("a=fingerprint:"))
                .count(),
            1,
            "the engine's fingerprint is written once: {presented}"
        );
        assert_eq!(
            all.iter()
                .filter(|line| line.starts_with("a=setup:"))
                .count(),
            1,
            "{presented}"
        );
    }

    #[test]
    fn presenting_a_bundled_offer_to_a_plain_party_leaves_the_bundle_and_the_dtls_lines_behind() {
        let anchored = anchor_video(
            BUNDLED_OFFER,
            EngineMedia::new("198.51.100.5:30002".parse().expect("addr"), None),
            VideoKeying::Plain,
        );
        assert!(
            !anchored.contains("a=group:BUNDLE"),
            "the video leaves the group and a group of one is dropped: {anchored}"
        );
        let video_section = section(&anchored, "video");
        assert_eq!(
            video_section[0], "m=video 30002 RTP/AVPF 96 97",
            "{anchored}"
        );
        assert!(
            !video_section
                .iter()
                .any(|line| line.starts_with("a=fingerprint:")
                    || line.starts_with("a=setup:")
                    || line.starts_with("a=ice-")),
            "{anchored}"
        );
        assert!(video_section.contains(&"a=mid:1"), "mids stay (RFC 5888)");
    }

    #[test]
    fn an_unbundled_dtls_section_gets_its_own_setup_and_fingerprint() {
        let anchored = anchor_video(
            UNBUNDLED_OFFER,
            EngineMedia::new("198.51.100.5:30002".parse().expect("addr"), None),
            VideoKeying::Dtls {
                fingerprint: engine_fingerprint(),
                setup: Setup::Passive,
            },
        );
        let video_section = section(&anchored, "video");
        assert_eq!(
            video_section[0], "m=video 30002 UDP/TLS/RTP/SAVPF 96",
            "{anchored}"
        );
        assert_eq!(
            video_section
                .iter()
                .filter(|line| line.starts_with("a=fingerprint:"))
                .collect::<Vec<_>>(),
            vec![&"a=fingerprint:sha-256 11:22:33:44"],
            "the engine's, once, not the phone's: {anchored}"
        );
        assert_eq!(
            video_section
                .iter()
                .filter(|line| line.starts_with("a=setup:"))
                .collect::<Vec<_>>(),
            vec![&"a=setup:passive"],
            "{anchored}"
        );
        assert!(
            section(&anchored, "audio").contains(&"a=fingerprint:sha-256 AA:BB:CC:DD"),
            "the audio section is not this pass's to touch"
        );
    }
}
