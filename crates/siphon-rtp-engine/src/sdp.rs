//! Minimal SDP parse + connection/port rewrite for the relay walking skeleton.
//!
//! This is **not** a full SDP engine — it does exactly what offer/answer relay needs: find the
//! audio stream's remote RTP/RTCP transport addresses (its `c=` connection line, `m=audio` port,
//! `a=rtcp-mux` / `a=rtcp:` attributes per RFC 5761 / RFC 3605) and rewrite them to engine-
//! allocated endpoints. The richer SDP surface (ICE, DTLS fingerprints, multiple m-lines,
//! bandwidth, direction) layers on later.
//!
//! Both IPv4 (`c=IN IP4`) and IPv6 (`c=IN IP6`) connection lines are recognised (RFC 4566 §5.7);
//! the rewriter emits the addrtype of the engine endpoint's own family, so a v6 call is advertised
//! as `c=IN IP6` and a v4 call as `c=IN IP4`. VoLTE/IMS deployments run IPv6-only access networks,
//! so the relay must follow `IN IP6` end to end.

use std::net::{IpAddr, SocketAddr};

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_srtp::sdes::CryptoAttribute;

/// Default packetization when the SDP carries no `a=ptime` (RFC 3551: 20 ms for telephony codecs).
const DEFAULT_PTIME_MS: u8 = 20;

/// Errors from SDP parsing/rewrite.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SdpError {
    /// No `m=audio` media line was present.
    #[error("no audio media line in SDP")]
    NoAudioMedia,
    /// The `m=audio` line's port field was missing or not a number.
    #[error("malformed m=audio port")]
    MediaPort,
    /// No usable `c=IN IP4`/`c=IN IP6 <addr>` connection line applied to the audio stream
    /// (RFC 4566 §5.7).
    #[error("no connection address for audio stream")]
    ConnectionAddress,
}

/// Line ending emitted by the rewriter (SDP mandates CRLF; RFC 4566 §5).
const CRLF: &str = "\r\n";

/// The remote audio transport advertised by an SDP, plus its RTCP multiplexing intent and any ICE
/// credentials it offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaInfo {
    /// Remote RTP address (the audio `c=`/`m=audio` transport).
    pub remote_rtp: SocketAddr,
    /// Remote RTCP address: the `a=rtcp:` port if present, else RTP port + 1 (RFC 3550); equal to
    /// `remote_rtp` when `rtcp_mux` is set.
    pub remote_rtcp: SocketAddr,
    /// Whether the stream offered `a=rtcp-mux` (RTP and RTCP share one port, RFC 5761).
    pub rtcp_mux: bool,
    /// Whether the `m=audio` transport is a secure profile (`RTP/SAVP` or `RTP/SAVPF`) — an SRTP stream.
    pub secure: bool,
    /// The `a=crypto` lines offered (RFC 4568 SDES), in order — the peer's SRTP key candidates.
    pub crypto: Vec<CryptoAttribute>,
    /// The peer's ICE username fragment (`a=ice-ufrag`), if it offered ICE (RFC 8445).
    pub ice_ufrag: Option<String>,
    /// The peer's ICE password (`a=ice-pwd`), if it offered ICE.
    pub ice_pwd: Option<String>,
    /// The `m=audio` payload-type list, in offered order (the codec priority order).
    pub payload_types: Vec<u8>,
    /// `a=rtpmap` entries for the audio stream (payload type → encoding name / clock / channels).
    pub rtpmaps: Vec<RtpMap>,
    /// `a=fmtp` `mode-set` constraints (payload type → allowed AMR speech modes), for variable-rate
    /// codecs (RFC 4867 §8.1). The engine clamps its egress encode mode into this set so it never
    /// sends a mode the peer disallowed. Empty when no `mode-set` was offered.
    pub mode_sets: Vec<(u8, Vec<u8>)>,
    /// The stream's `a=ptime` in milliseconds, if present (else the 20 ms telephony default).
    pub ptime_ms: u8,
}

/// One `a=rtpmap:<pt> <encoding>/<clock>[/<channels>]` entry (RFC 4566 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpMap {
    /// The dynamic or static payload type this maps.
    pub payload_type: u8,
    /// The encoding name (e.g. `PCMU`, `AMR-WB`, `telephone-event`).
    pub encoding_name: String,
    /// The RTP clock rate in Hz.
    pub clock_rate_hz: u32,
    /// Channel count (defaults to 1 when the optional `/channels` suffix is absent).
    pub channels: u8,
}

impl MediaInfo {
    /// Whether the peer offered ICE (carries an `a=ice-ufrag`).
    #[must_use]
    pub fn is_ice(&self) -> bool {
        self.ice_ufrag.is_some()
    }

    /// The negotiated audio codecs, in offered order, excluding telephone-event. Each payload type is
    /// resolved via its `a=rtpmap` or, failing that, the RFC 3551 static table; types that resolve to
    /// neither are skipped (the engine can only build codecs it knows).
    #[must_use]
    pub fn audio_codecs(&self) -> Vec<CodecSpec> {
        self.payload_types
            .iter()
            .filter_map(|&payload_type| self.codec_spec(payload_type))
            .filter(|spec| !spec.is_telephone_event())
            .collect()
    }

    /// The first negotiated audio codec the engine can build (the primary codec for the stream).
    #[must_use]
    pub fn primary_codec(&self) -> Option<CodecSpec> {
        self.audio_codecs().into_iter().next()
    }

    /// The RFC 4733 telephone-event payload type negotiated on this stream, if any.
    #[must_use]
    pub fn telephone_event_payload_type(&self) -> Option<u8> {
        self.rtpmaps
            .iter()
            .find(|map| map.encoding_name.eq_ignore_ascii_case("telephone-event"))
            .map(|map| map.payload_type)
    }

    /// Resolve a payload type to a [`CodecSpec`] via its rtpmap, else the static table.
    fn codec_spec(&self, payload_type: u8) -> Option<CodecSpec> {
        if let Some(map) = self
            .rtpmaps
            .iter()
            .find(|map| map.payload_type == payload_type)
        {
            let spec = CodecSpec::new(
                payload_type,
                &map.encoding_name,
                map.clock_rate_hz,
                map.channels,
                self.ptime_ms,
            );
            // Honour an AMR-WB `mode-set` (RFC 4867 §8.1) by clamping the egress encode mode into
            // the allowed set, so the engine never sends the peer a mode it disallowed.
            if spec.encoding_name == "AMR-WB" {
                if let Some((_, modes)) =
                    self.mode_sets.iter().find(|(pt, _)| *pt == payload_type)
                {
                    return Some(spec.with_encode_mode(choose_amr_wb_mode(modes)));
                }
            }
            return Some(spec);
        }
        CodecSpec::from_static_payload_type(payload_type, self.ptime_ms)
    }
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
    /// The `m=audio` transport profile (the third field, e.g. `RTP/AVP` or `RTP/SAVP`).
    transport: Option<String>,
    /// The `m=audio` payload-type list (fields after the transport), in offered order.
    payload_types: Vec<u8>,
    /// `a=rtpmap` entries in the audio section.
    rtpmaps: Vec<RtpMap>,
    /// `a=fmtp` `mode-set` constraints in the audio section (payload type → allowed AMR modes).
    fmtp_mode_sets: Vec<(u8, Vec<u8>)>,
    /// The audio stream's `a=ptime`, if present.
    ptime_ms: Option<u8>,
    /// Parsed `a=crypto` lines in the audio section, in order (RFC 4568).
    crypto: Vec<CryptoAttribute>,
    /// Peer ICE credentials (`a=ice-ufrag` / `a=ice-pwd`), session- or media-level.
    ice_ufrag: Option<String>,
    ice_pwd: Option<String>,
}

/// Parse an `a=rtpmap` attribute body (`rtpmap:<pt> <encoding>/<clock>[/<channels>]`).
fn parse_rtpmap(value: &str) -> Option<RtpMap> {
    let body = value.strip_prefix("rtpmap:")?;
    let (payload_type, rest) = body.split_once(char::is_whitespace)?;
    let payload_type = payload_type.parse::<u8>().ok()?;
    let mut fields = rest.trim().split('/');
    let encoding_name = fields.next()?.trim().to_string();
    let clock_rate_hz = fields.next()?.trim().parse::<u32>().ok()?;
    let channels = fields
        .next()
        .and_then(|count| count.trim().parse::<u8>().ok())
        .unwrap_or(1);
    Some(RtpMap {
        payload_type,
        encoding_name,
        clock_rate_hz,
        channels,
    })
}

/// Parse an `a=fmtp:<pt> ...mode-set=<m0,m1,...>...` body into `(payload_type, allowed_modes)`.
/// Returns `None` when the line carries no parseable payload type or no `mode-set` parameter — the
/// engine only acts on `mode-set`; every other fmtp parameter is passed through untouched.
fn parse_fmtp_mode_set(value: &str) -> Option<(u8, Vec<u8>)> {
    let body = value.strip_prefix("fmtp:")?;
    let (payload_type, params) = body.split_once(char::is_whitespace)?;
    let payload_type = payload_type.trim().parse::<u8>().ok()?;
    // fmtp params are `;`-separated `key=value` pairs in any order (RFC 4867 §8.1).
    let modes_field = params
        .split(';')
        .map(str::trim)
        .find_map(|param| param.strip_prefix("mode-set="))?;
    let modes: Vec<u8> = modes_field
        .split(',')
        .filter_map(|token| token.trim().parse::<u8>().ok())
        .filter(|&mode| mode <= 8)
        .collect();
    (!modes.is_empty()).then_some((payload_type, modes))
}

/// Choose the AMR-WB egress encode mode from an `allowed` `mode-set`: the engine default (mode 2 /
/// 12.65 kbit/s) when permitted, else the highest allowed mode below it, else the lowest allowed —
/// always a member of the set, so the engine never emits a mode the peer disallowed.
fn choose_amr_wb_mode(allowed: &[u8]) -> Option<u8> {
    const DEFAULT_MODE: u8 = 2;
    if allowed.is_empty() {
        return None;
    }
    if allowed.contains(&DEFAULT_MODE) {
        return Some(DEFAULT_MODE);
    }
    allowed
        .iter()
        .copied()
        .filter(|&mode| mode < DEFAULT_MODE)
        .max()
        .or_else(|| allowed.iter().copied().min())
}

/// Parse a `c=` connection line body (`IN IP4 <addr>` or `IN IP6 <addr>`, RFC 4566 §5.7). The
/// addrtype declares the family, so the parsed address must match it — an `IP6` line carrying an
/// IPv4 literal (or vice versa) is rejected rather than silently mis-typed. Multicast TTL/count
/// suffixes (`<addr>/<ttl>`) are not split here; unicast media (the relay's only case) carries a
/// bare address.
fn parse_connection_addr(value: &str) -> Option<IpAddr> {
    let mut parts = value.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("IN"), Some("IP4"), Some(addr)) => {
            addr.parse::<IpAddr>().ok().filter(IpAddr::is_ipv4)
        }
        (Some("IN"), Some("IP6"), Some(addr)) => {
            addr.parse::<IpAddr>().ok().filter(IpAddr::is_ipv6)
        }
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
        transport: None,
        payload_types: Vec::new(),
        rtpmaps: Vec::new(),
        fmtp_mode_sets: Vec::new(),
        ptime_ms: None,
        crypto: Vec::new(),
        ice_ufrag: None,
        ice_pwd: None,
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
                        // `audio <port> <proto> <pt> <pt> …`: the transport is field 2, payload types
                        // follow it (the codec priority order).
                        let mut fields = value.split_whitespace();
                        scan.transport = fields.nth(2).map(str::to_string);
                        scan.payload_types = fields
                            .filter_map(|field| field.parse::<u8>().ok())
                            .collect();
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
            "a" => {
                // ICE credentials may be session- or media-level; media-level overrides.
                if let Some(ufrag) = value.strip_prefix("ice-ufrag:") {
                    if in_audio || scan.ice_ufrag.is_none() {
                        scan.ice_ufrag = Some(ufrag.trim().to_string());
                    }
                } else if let Some(pwd) = value.strip_prefix("ice-pwd:") {
                    if in_audio || scan.ice_pwd.is_none() {
                        scan.ice_pwd = Some(pwd.trim().to_string());
                    }
                } else if in_audio {
                    if value == "rtcp-mux" {
                        scan.rtcp_mux = true;
                    } else if let Some(port) = parse_rtcp_attr(value) {
                        scan.audio_rtcp = Some((index, port));
                    } else if value.starts_with("crypto:") {
                        // RFC 4568 SDES key; ignore lines we cannot parse (unknown suite, bad key).
                        if let Ok(crypto) = CryptoAttribute::parse(value) {
                            scan.crypto.push(crypto);
                        }
                    } else if value.starts_with("rtpmap:") {
                        if let Some(rtpmap) = parse_rtpmap(value) {
                            scan.rtpmaps.push(rtpmap);
                        }
                    } else if value.starts_with("fmtp:") {
                        if let Some(mode_set) = parse_fmtp_mode_set(value) {
                            scan.fmtp_mode_sets.push(mode_set);
                        }
                    } else if let Some(ptime) = value.strip_prefix("ptime:") {
                        scan.ptime_ms = ptime.trim().parse::<u8>().ok();
                    }
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
        // A secure profile is any `RTP/SAVP` variant (SDES today; DTLS-SRTP `UDP/TLS/...` later).
        secure: scan
            .transport
            .as_deref()
            .is_some_and(|transport| transport.contains("SAVP")),
        crypto: scan.crypto.clone(),
        ice_ufrag: scan.ice_ufrag.clone(),
        ice_pwd: scan.ice_pwd.clone(),
        payload_types: scan.payload_types.clone(),
        rtpmaps: scan.rtpmaps.clone(),
        mode_sets: scan.fmtp_mode_sets.clone(),
        ptime_ms: scan.ptime_ms.unwrap_or(DEFAULT_PTIME_MS),
    })
}

/// Parse the remote audio transport info from an SDP without rewriting it.
pub fn parse(sdp: &str) -> Result<MediaInfo, SdpError> {
    media_info(&scan(sdp))
}

/// ICE-lite credentials to advertise in a rewritten SDP: `a=ice-lite` (session-level) plus
/// `a=ice-ufrag` / `a=ice-pwd` and a host `a=candidate` for the engine's media address.
#[derive(Debug, Clone, Copy)]
pub struct IceAdvertisement<'a> {
    /// The engine's local ICE username fragment.
    pub ufrag: &'a str,
    /// The engine's local ICE password.
    pub pwd: &'a str,
}

/// How to advertise the audio stream's security on rewrite (RFC 3264 transport + RFC 4568 SDES).
#[derive(Debug, Clone, Copy)]
pub enum SecurityAdvertisement {
    /// Plaintext `RTP/AVP`: force the transport profile and strip any `a=crypto` lines.
    Plain,
    /// Secure `RTP/SAVP`: force the transport, strip the peer's `a=crypto`, and advertise this one
    /// (the engine's own offered SDES key for the leg).
    Secure(CryptoAttribute),
}

impl SecurityAdvertisement {
    /// The `m=audio` transport profile to advertise.
    fn transport(self) -> &'static str {
        match self {
            SecurityAdvertisement::Plain => "RTP/AVP",
            SecurityAdvertisement::Secure(_) => "RTP/SAVP",
        }
    }
}

/// Host-candidate priority (RFC 8445 §5.1.2): type-pref 126, local-pref 65535, component 1 (RTP).
const HOST_CANDIDATE_PRIORITY: u32 = (126 << 24) | (65535 << 8) | 255;

/// The SDP `addrtype` token for an IP address family (RFC 4566 §5.7): `IP4` for IPv4, `IP6` for
/// IPv6. Used to emit the `c=` connection line (and the ICE `a=candidate`) in the family of the
/// engine endpoint we advertise — so a v6 engine endpoint is signalled as `c=IN IP6`.
fn addrtype(ip: IpAddr) -> &'static str {
    if ip.is_ipv6() {
        "IP6"
    } else {
        "IP4"
    }
}

/// Whether `line` is an ICE attribute we re-originate (so the peer's copy is dropped on rewrite).
fn is_ice_attribute(line: &str) -> bool {
    line == "a=ice-lite"
        || line.starts_with("a=ice-ufrag:")
        || line.starts_with("a=ice-pwd:")
        || line.starts_with("a=ice-options:")
        || line.starts_with("a=candidate:")
        || line.starts_with("a=remote-candidates:")
        || line.starts_with("a=end-of-candidates")
}

/// Rewrite the audio stream's RTP/RTCP transport to `engine`, returning the new SDP and the remote
/// media info parsed from the input.
///
/// The connection line applying to the audio stream (media-level `c=` else session-level) and the
/// `m=audio` port are rewritten to `engine.rtp`. For non-mux (`engine.rtcp = Some`), an `a=rtcp:`
/// line is rewritten or inserted for the engine RTCP port; for mux (`engine.rtcp = None`), any
/// `a=rtcp:` line is dropped (RTCP rides the RTP port).
///
/// When `ice` is `Some`, the engine re-originates ICE as ICE-lite: the peer's ICE attributes are
/// dropped and replaced with `a=ice-lite` plus the engine's own `a=ice-ufrag`/`a=ice-pwd` and a host
/// `a=candidate` for the engine RTP address (RFC 8445).
pub fn rewrite(
    sdp: &str,
    engine: EngineMedia,
    ice: Option<IceAdvertisement<'_>>,
    security: Option<SecurityAdvertisement>,
) -> Result<Rewritten, SdpError> {
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
        // Re-originating ICE: drop the peer's ICE attributes; we advertise our own below.
        if ice.is_some() && is_ice_attribute(line) {
            continue;
        }
        // Re-originating SRTP keying: drop the peer's `a=crypto`; we advertise our own (or none).
        if security.is_some() && line.starts_with("a=crypto:") {
            continue;
        }
        if index == media_index {
            // `a=ice-lite` is session-level — emit it just before the media line (end of session).
            if ice.is_some() {
                lines.push("a=ice-lite".to_string());
            }
            lines.push(rewrite_media_line(
                line,
                engine.rtp.port(),
                security.map(SecurityAdvertisement::transport),
            ));
            // Insert a fresh a=rtcp line only if there is no existing one to rewrite in place.
            if let Some(rtcp) = engine.rtcp {
                if rtcp_index.is_none() {
                    lines.push(format!("a=rtcp:{}", rtcp.port()));
                }
            }
            // Advertise the engine's SDES key on a secure leg (RFC 4568).
            if let Some(SecurityAdvertisement::Secure(crypto)) = security {
                lines.push(format!("a={}", crypto.to_attribute_value()));
            }
            if let Some(ice) = ice {
                lines.push(format!("a=ice-ufrag:{}", ice.ufrag));
                lines.push(format!("a=ice-pwd:{}", ice.pwd));
                // RFC 8839 §5.1: the candidate's connection-address is a bare IP literal in either
                // family — `IpAddr`'s Display emits a v6 literal without brackets, exactly as the
                // `a=candidate` grammar requires (brackets are an `m=`/`c=`-line concern only).
                lines.push(format!(
                    "a=candidate:1 1 UDP {HOST_CANDIDATE_PRIORITY} {} {} typ host",
                    engine.rtp.ip(),
                    engine.rtp.port()
                ));
            }
        } else if index == conn_index {
            // RFC 4566 §5.7: emit the addrtype of the engine endpoint's own family (`IP4`/`IP6`),
            // so a v6 engine endpoint is advertised as `c=IN IP6` and a v4 one as `c=IN IP4`.
            let ip = engine.rtp.ip();
            lines.push(format!("c=IN {} {}", addrtype(ip), ip));
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

/// Replace the port (2nd field) of an `m=audio <port> <proto> <fmt...>` line and, when `transport`
/// is `Some`, the transport profile (3rd field), preserving the media type and format list.
fn rewrite_media_line(line: &str, port: u16, transport: Option<&str>) -> String {
    let body = line.strip_prefix("m=").unwrap_or(line);
    let mut fields = body.split(' ');
    let media = fields.next().unwrap_or("audio");
    let _old_port = fields.next();
    let proto = fields.next();
    let formats: Vec<&str> = fields.collect();
    let proto = transport.or(proto).unwrap_or("RTP/AVP");
    if formats.is_empty() {
        format!("m={media} {port} {proto}")
    } else {
        format!("m={media} {port} {proto} {}", formats.join(" "))
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

    /// An AMR-WB offer (PT 96, 16 kHz) at `addr`, optionally carrying an `a=fmtp` `mode-set`.
    fn amr_wb_offer(mode_set: Option<&str>) -> String {
        let fmtp = match mode_set {
            Some(modes) => format!("a=fmtp:96 mode-set={modes};octet-align=1\r\n"),
            None => String::new(),
        };
        format!(
            "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n\
             m=audio 5004 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n{fmtp}"
        )
    }

    fn amr_wb_encode_mode(mode_set: Option<&str>) -> Option<u8> {
        parse(&amr_wb_offer(mode_set))
            .expect("parse")
            .primary_codec()
            .expect("amr-wb codec")
            .encode_mode
    }

    #[test]
    fn amr_wb_mode_set_clamps_the_egress_encode_mode() {
        // The mode-set is parsed onto the stream.
        let info = parse(&amr_wb_offer(Some("0,1,2"))).expect("parse");
        assert_eq!(info.mode_sets, vec![(96u8, vec![0u8, 1, 2])]);

        // Default mode 2 allowed ⇒ encode at 2.
        assert_eq!(amr_wb_encode_mode(Some("0,1,2")), Some(2));
        // Order-independent and whitespace-tolerant.
        assert_eq!(amr_wb_encode_mode(Some("2, 1, 0")), Some(2));
        // Restricted below the default ⇒ the highest allowed below 2.
        assert_eq!(amr_wb_encode_mode(Some("0,1")), Some(1));
        // Entirely above the default ⇒ the lowest allowed (never a disallowed mode).
        assert_eq!(amr_wb_encode_mode(Some("7,4")), Some(4));
        // A single allowed mode is honoured exactly.
        assert_eq!(amr_wb_encode_mode(Some("8")), Some(8));
        // No mode-set ⇒ no constraint (the codec default, mode 2, applies downstream).
        assert_eq!(amr_wb_encode_mode(None), None);
        // Out-of-range tokens are ignored; an all-invalid set leaves no constraint.
        assert_eq!(amr_wb_encode_mode(Some("9,42")), None);
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
        let result = rewrite(&sdp, engine, None, None).expect("rewrite");
        assert_eq!(
            result.media.remote_rtp,
            "203.0.113.7:49170".parse().unwrap()
        );
        assert!(result.sdp.contains("c=IN IP4 127.0.0.1"));
        assert!(result.sdp.contains("m=audio 40000 RTP/AVP 0 8 96"));
        assert!(
            result.sdp.contains("a=rtcp:40001"),
            "engine RTCP port advertised"
        );
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
        let result = rewrite(&sdp, engine, None, None).expect("rewrite");
        assert!(result.sdp.contains("a=rtcp:40001"));
        assert!(!result.sdp.contains("53000"));
        assert_eq!(
            result.sdp.matches("a=rtcp:").count(),
            1,
            "no duplicate a=rtcp"
        );
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
        let result = rewrite(&sdp, engine, None, None).expect("rewrite");
        assert!(
            !result.sdp.contains("a=rtcp:"),
            "explicit a=rtcp dropped under mux"
        );
        assert!(result.sdp.contains("a=rtcp-mux"), "mux flag preserved");
    }

    #[test]
    fn media_level_connection_overrides_session_level() {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP4 198.51.100.9\r\n";
        let engine = EngineMedia {
            rtp: "127.0.0.1:41000".parse().unwrap(),
            rtcp: None,
        };
        let result = rewrite(sdp, engine, None, None).expect("rewrite");
        assert_eq!(
            result.media.remote_rtp,
            "198.51.100.9:5000".parse().unwrap()
        );
        assert!(result.sdp.contains("c=IN IP4 10.0.0.1"));
        assert!(result.sdp.contains("c=IN IP4 127.0.0.1"));
        assert!(!result.sdp.contains("198.51.100.9"));
    }

    /// An IPv6 offer (RFC 4566 §5.7 `c=IN IP6`) at both session and media level.
    fn offer_v6(addr: &str, port: u16) -> String {
        format!(
            "v=0\r\n\
             o=alice 2890844526 2890844526 IN IP6 host.invalid\r\n\
             s=-\r\n\
             c=IN IP6 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0 8 96\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:96 telephone-event/8000\r\n"
        )
    }

    #[test]
    fn parse_recognizes_ipv6_session_connection() {
        // RFC 4566 §5.7: `c=IN IP6 <addr>` carries the remote v6 transport; remote_rtp/rtcp become v6.
        let info = parse(&offer_v6("2001:db8::1", 49170)).expect("parse v6");
        assert_eq!(info.remote_rtp, "[2001:db8::1]:49170".parse().unwrap());
        assert_eq!(info.remote_rtcp, "[2001:db8::1]:49171".parse().unwrap());
        assert!(info.remote_rtp.is_ipv6());
        assert!(!info.rtcp_mux);
    }

    #[test]
    fn parse_recognizes_ipv6_media_level_connection() {
        // A media-level `c=IN IP6` overrides a session-level one, exactly as for IPv4.
        let sdp = "v=0\r\nc=IN IP6 2001:db8::a\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP6 2001:db8::b\r\n";
        let info = parse(sdp).expect("parse v6 media-level");
        assert_eq!(info.remote_rtp, "[2001:db8::b]:5000".parse().unwrap());
    }

    #[test]
    fn parse_rejects_addrtype_family_mismatch() {
        // RFC 4566 §5.7: the addrtype declares the family. An `IP6` line carrying an IPv4 literal
        // (or `IP4` carrying a v6 literal) is not a usable connection address.
        let sdp = "v=0\r\nc=IN IP6 192.0.2.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n";
        assert_eq!(parse(sdp), Err(SdpError::ConnectionAddress));
        let sdp = "v=0\r\nc=IN IP4 2001:db8::1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n";
        assert_eq!(parse(sdp), Err(SdpError::ConnectionAddress));
    }

    #[test]
    fn rewrite_to_v6_engine_emits_ip6_connection_and_media() {
        // RFC 4566 §5.7: rewriting to a v6 engine endpoint must emit `c=IN IP6` (addrtype follows the
        // engine endpoint's family), the engine's v6 address, and the engine ports.
        let sdp = offer_v6("2001:db8::1", 49170);
        let engine = EngineMedia {
            rtp: "[::1]:40000".parse().unwrap(),
            rtcp: Some("[::1]:40001".parse().unwrap()),
        };
        let result = rewrite(&sdp, engine, None, None).expect("rewrite v6");
        assert_eq!(
            result.media.remote_rtp,
            "[2001:db8::1]:49170".parse().unwrap()
        );
        assert!(result.sdp.contains("c=IN IP6 ::1"), "{}", result.sdp);
        assert!(
            result.sdp.contains("m=audio 40000 RTP/AVP 0 8 96"),
            "{}",
            result.sdp
        );
        assert!(
            result.sdp.contains("a=rtcp:40001"),
            "engine v6 RTCP port advertised"
        );
        assert!(!result.sdp.contains("2001:db8::1"), "peer address removed");
        assert!(
            !result.sdp.contains("IP4"),
            "no IPv4 addrtype on a v6 rewrite"
        );
        // The rewritten SDP reparses to the v6 engine transport.
        let reparsed = parse(&result.sdp).expect("reparse v6");
        assert_eq!(reparsed.remote_rtp, engine.rtp);
        assert_eq!(reparsed.remote_rtcp, "[::1]:40001".parse().unwrap());
    }

    #[test]
    fn rewrite_v6_re_originates_ice_with_v6_candidate() {
        // RFC 8839 §5.1: the host candidate's connection-address is a bare v6 literal (no brackets).
        let sdp = "v=0\r\no=- 1 1 IN IP6 host.invalid\r\ns=-\r\nc=IN IP6 2001:db8::7\r\nt=0 0\r\n\
             a=ice-ufrag:PEERUF\r\na=ice-pwd:peerpassword01234567\r\n\
             m=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let engine = EngineMedia {
            rtp: "[::1]:40000".parse().unwrap(),
            rtcp: None,
        };
        let advert = IceAdvertisement {
            ufrag: "ENGUF",
            pwd: "engpassword01234567",
        };
        let result = rewrite(sdp, engine, Some(advert), None).expect("rewrite v6 ice");
        assert!(result.sdp.contains("c=IN IP6 ::1"));
        assert!(
            result
                .sdp
                .contains("a=candidate:1 1 UDP 2130706431 ::1 40000 typ host"),
            "v6 host candidate as a bare literal: {}",
            result.sdp
        );
        assert!(
            !result.sdp.contains("2001:db8::7"),
            "peer v6 address removed"
        );
    }

    #[test]
    fn ipv4_rewrite_is_unchanged_after_v6_support() {
        // Regression: a v4 engine endpoint must still emit `c=IN IP4` (addrtype follows the family),
        // proving the addrtype is picked from the endpoint, not hardcoded either way.
        let sdp = offer("203.0.113.7", 49170);
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: None,
        };
        let result = rewrite(&sdp, engine, None, None).expect("rewrite v4");
        assert!(result.sdp.contains("c=IN IP4 127.0.0.1"));
        assert!(
            !result.sdp.contains("IP6"),
            "no IPv6 addrtype on a v4 rewrite"
        );
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
            let _ = rewrite(&text, engine, None, None);
        }
    }

    fn ice_offer(addr: &str, port: u16) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {addr}\r\nt=0 0\r\n\
             a=ice-ufrag:PEERUF\r\na=ice-pwd:peerpassword01234567\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=candidate:1 1 UDP 2130706431 {addr} {port} typ host\r\n"
        )
    }

    #[test]
    fn parse_extracts_ice_credentials() {
        let info = parse(&ice_offer("203.0.113.7", 49170)).expect("parse");
        assert!(info.is_ice());
        assert_eq!(info.ice_ufrag.as_deref(), Some("PEERUF"));
        assert_eq!(info.ice_pwd.as_deref(), Some("peerpassword01234567"));
    }

    #[test]
    fn non_ice_offer_has_no_credentials() {
        let info = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert!(!info.is_ice());
        assert!(info.ice_ufrag.is_none());
    }

    #[test]
    fn rewrite_re_originates_ice_as_ice_lite() {
        let sdp = ice_offer("203.0.113.7", 49170);
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: None,
        };
        let advert = IceAdvertisement {
            ufrag: "ENGUF",
            pwd: "engpassword01234567",
        };
        let result = rewrite(&sdp, engine, Some(advert), None).expect("rewrite");

        // Our credentials and posture are advertised.
        assert!(result.sdp.contains("a=ice-lite"));
        assert!(result.sdp.contains("a=ice-ufrag:ENGUF"));
        assert!(result.sdp.contains("a=ice-pwd:engpassword01234567"));
        assert!(result
            .sdp
            .contains("a=candidate:1 1 UDP 2130706431 127.0.0.1 40000 typ host"));
        // The peer's ICE attributes are gone.
        assert!(!result.sdp.contains("PEERUF"));
        assert!(!result.sdp.contains("peerpassword01234567"));
        assert!(!result.sdp.contains("203.0.113.7"));
        // The parsed media still reflects the peer's transport + ICE creds.
        assert_eq!(result.media.ice_ufrag.as_deref(), Some("PEERUF"));
    }

    #[test]
    fn rewrite_without_ice_leaves_no_ice_lines() {
        let sdp = offer("203.0.113.7", 49170);
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: None,
        };
        let result = rewrite(&sdp, engine, None, None).expect("rewrite");
        assert!(!result.sdp.contains("a=ice-lite"));
        assert!(!result.sdp.contains("a=ice-ufrag"));
    }

    /// An `RTP/SAVP` (SDES) offer carrying one RFC 4568 `a=crypto` line.
    fn savp_offer(addr: &str, port: u16) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {addr}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR\r\n"
        )
    }

    #[test]
    fn parse_detects_savp_and_crypto() {
        let info = parse(&savp_offer("203.0.113.7", 49170)).expect("parse");
        assert!(info.secure, "RTP/SAVP is a secure profile");
        assert_eq!(info.crypto.len(), 1);
        assert_eq!(info.crypto[0].tag, 1);
        // A plaintext offer is not secure and carries no crypto.
        let plain = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert!(!plain.secure);
        assert!(plain.crypto.is_empty());
    }

    #[test]
    fn rewrite_secure_advertises_savp_and_our_crypto() {
        use siphon_rtp_srtp::sdes::CryptoSuite;
        // Bridge an AVP offer up to SAVP: force the transport and advertise the engine's key.
        let sdp = offer("203.0.113.7", 49170);
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: None,
        };
        let ours = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let result = rewrite(
            &sdp,
            engine,
            None,
            Some(SecurityAdvertisement::Secure(ours)),
        )
        .expect("rewrite");
        assert!(
            result.sdp.contains("m=audio 40000 RTP/SAVP 0 8 96"),
            "{}",
            result.sdp
        );
        assert!(result
            .sdp
            .contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"));
    }

    #[test]
    fn rewrite_plain_forces_avp_and_strips_crypto() {
        // Bridge a SAVP answer down to AVP: force the transport and drop the peer's a=crypto.
        let sdp = savp_offer("203.0.113.7", 49170);
        let engine = EngineMedia {
            rtp: "127.0.0.1:40000".parse().unwrap(),
            rtcp: None,
        };
        let result =
            rewrite(&sdp, engine, None, Some(SecurityAdvertisement::Plain)).expect("rewrite");
        assert!(
            result.sdp.contains("m=audio 40000 RTP/AVP 0 8"),
            "{}",
            result.sdp
        );
        assert!(
            !result.sdp.contains("a=crypto:"),
            "peer crypto stripped: {}",
            result.sdp
        );
        // The parsed input still reports the peer's secure profile + key.
        assert!(result.media.secure);
        assert_eq!(result.media.crypto.len(), 1);
    }

    #[test]
    fn parse_extracts_payload_types_in_offered_order() {
        let info = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert_eq!(info.payload_types, vec![0, 8, 96]);
    }

    #[test]
    fn parse_resolves_audio_codecs_excluding_telephone_event() {
        let info = parse(&offer("203.0.113.7", 49170)).expect("parse");
        let codecs = info.audio_codecs();
        assert_eq!(codecs.len(), 2, "PCMU + PCMA, telephone-event excluded");
        assert_eq!(codecs[0].encoding_name, "PCMU");
        assert_eq!(codecs[0].payload_type, 0);
        assert_eq!(codecs[1].encoding_name, "PCMA");
        let primary = info.primary_codec().expect("primary");
        assert_eq!(
            primary.encoding_name, "PCMU",
            "first offered codec is primary"
        );
    }

    #[test]
    fn parse_finds_telephone_event_payload_type() {
        let info = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert_eq!(info.telephone_event_payload_type(), Some(96));
    }

    #[test]
    fn parse_uses_ptime_when_present_else_default() {
        let info = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert_eq!(info.ptime_ms, DEFAULT_PTIME_MS, "no a=ptime → 20 ms");
        let mut sdp = offer("203.0.113.7", 49170);
        sdp.push_str("a=ptime:30\r\n");
        let info = parse(&sdp).expect("parse");
        assert_eq!(info.ptime_ms, 30);
        assert_eq!(info.primary_codec().expect("primary").ptime_ms, 30);
    }

    #[test]
    fn parse_resolves_static_payload_type_without_rtpmap() {
        // A bare static offer (PCMA, PT 8) with no a=rtpmap still resolves via RFC 3551.
        let sdp = "v=0\r\n\
             o=- 0 0 IN IP4 host.invalid\r\n\
             s=-\r\n\
             c=IN IP4 203.0.113.9\r\n\
             t=0 0\r\n\
             m=audio 5000 RTP/AVP 8\r\n";
        let info = parse(sdp).expect("parse");
        let primary = info.primary_codec().expect("static PCMA resolves");
        assert_eq!(primary.encoding_name, "PCMA");
        assert_eq!(primary.clock_rate_hz, 8000);
    }

    #[test]
    fn parse_handles_l16_rtpmap_with_clock_rate() {
        let sdp = "v=0\r\n\
             o=- 0 0 IN IP4 host.invalid\r\n\
             s=-\r\n\
             c=IN IP4 203.0.113.9\r\n\
             t=0 0\r\n\
             m=audio 5000 RTP/AVP 96\r\n\
             a=rtpmap:96 L16/16000\r\n";
        let info = parse(sdp).expect("parse");
        let primary = info.primary_codec().expect("L16 resolves");
        assert_eq!(primary.encoding_name, "L16");
        assert_eq!(primary.clock_rate_hz, 16000);
        assert_eq!(primary.channels, 1, "no /channels suffix → mono");
    }
}
