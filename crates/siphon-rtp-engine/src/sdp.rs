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

use siphon_rtp_codec::factory::{CodecSpec, OpusParams, OPUS_MAX_PTIME_MS};
use siphon_rtp_ice::{Candidate, IceOptions, END_OF_CANDIDATES_ATTRIBUTE, ICE_MISMATCH_ATTRIBUTE};
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
    /// The peer's DTLS certificate fingerprint (`a=fingerprint`, RFC 8122), present on a DTLS-SRTP
    /// (`UDP/TLS/RTP/SAVP[F]`) offer/answer — it binds the handshake identity to the SDP (RFC 5763 §5).
    pub fingerprint: Option<Fingerprint>,
    /// The peer's DTLS role (`a=setup`, RFC 4145 / RFC 5763) — who initiates the DTLS handshake.
    pub setup: Option<Setup>,
    /// Whether the `m=audio` transport is a DTLS-keyed profile (`UDP/TLS/RTP/SAVP[F]`, RFC 5764): SRTP
    /// keyed by the DTLS handshake (`a=fingerprint`), not by SDES `a=crypto`. Implies [`Self::secure`].
    pub dtls: bool,
    /// The peer's ICE username fragment (`a=ice-ufrag`), if it offered ICE (RFC 8445).
    pub ice_ufrag: Option<String>,
    /// The peer's ICE password (`a=ice-pwd`), if it offered ICE.
    pub ice_pwd: Option<String>,
    /// The peer's ICE candidates for the audio stream (RFC 8839 §5.1), in offered order.
    /// Unresolvable (mDNS `.local`) and malformed lines are skipped rather than failing the parse,
    /// so one bad candidate never costs us the peer's whole list.
    pub candidates: Vec<Candidate>,
    /// The peer's `a=ice-options` tokens (RFC 8839 §5.6); `trickle` (RFC 8838) is the one that
    /// changes behaviour.
    pub ice_options: IceOptions,
    /// Whether the peer declared its candidate list complete with `a=end-of-candidates`
    /// (RFC 8838 §14). False means more candidates may still trickle in.
    pub end_of_candidates: bool,
    /// Whether the peer advertised `a=ice-lite` (RFC 8839 §5.2). A full agent facing a lite peer is
    /// always the **controlling** agent (RFC 8445 §6.1.1).
    pub ice_lite: bool,
    /// Whether the peer sent `a=ice-mismatch` (RFC 8839 §5.3) — it saw our offer's ICE as altered in
    /// transit, so ICE must not be used on this stream and both sides fall back to the signalled
    /// address.
    pub ice_mismatch: bool,
    /// The `m=audio` payload-type list, in offered order (the codec priority order).
    pub payload_types: Vec<u8>,
    /// `a=rtpmap` entries for the audio stream (payload type → encoding name / clock / channels).
    pub rtpmaps: Vec<RtpMap>,
    /// `a=fmtp` `mode-set` constraints (payload type → allowed AMR speech modes), for variable-rate
    /// codecs (RFC 4867 §8.1). The engine clamps its egress encode mode into this set so it never
    /// sends a mode the peer disallowed. Empty when no `mode-set` was offered.
    pub mode_sets: Vec<(u8, Vec<u8>)>,
    /// `a=fmtp` Opus parameters (payload type → RFC 7587 §6.1 parameter set), for each payload type
    /// whose fmtp carried at least one recognised Opus parameter. Only read for a payload type that
    /// resolves to Opus; an Opus stream that declared no fmtp is absent here and reads the RFC
    /// defaults ([`OpusParams::default`]).
    pub opus_params: Vec<(u8, OpusParams)>,
    /// The stream's `a=ptime` in milliseconds, if present (else the 20 ms telephony default).
    pub ptime_ms: u8,
    /// The stream's `a=maxptime` in milliseconds, if present (RFC 4566 §6): the longest packet the
    /// peer will accept. Caps every codec's egress `ptime_ms` on this stream.
    pub maxptime_ms: Option<u8>,
}

/// A DTLS certificate fingerprint (RFC 8122), carried in `a=fingerprint`. In DTLS-SRTP the SDP does
/// not carry keys (as SDES does); it carries the hash of the peer's self-signed certificate, and the
/// handshake is only trusted if the presented certificate hashes to this value (RFC 5763 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The hash-function token, lowercased (RFC 8122 §5 registers `sha-256`, `sha-1`, …). Kept as a
    /// string so an unknown-but-well-formed algorithm still round-trips through the rewriter.
    pub hash_function: String,
    /// The certificate-hash octets (the `:`-separated hex pairs, decoded).
    pub bytes: Vec<u8>,
}

impl Fingerprint {
    /// Parse an `a=fingerprint:<hash-func> <hex:hex:…>` attribute body (RFC 8122 §5). Returns `None`
    /// for a missing prefix, a missing hash/value, or a non-hex octet.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let body = value.strip_prefix("fingerprint:")?;
        let (hash_function, hex) = body.trim().split_once(char::is_whitespace)?;
        let bytes = hex
            .trim()
            .split(':')
            .map(|octet| u8::from_str_radix(octet.trim(), 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        if hash_function.is_empty() || bytes.is_empty() {
            return None;
        }
        Some(Fingerprint {
            hash_function: hash_function.to_ascii_lowercase(),
            bytes,
        })
    }

    /// The `fingerprint:<hash-func> <HEX:HEX:…>` attribute value (without the leading `a=`), uppercase
    /// hex per RFC 8122 §5.
    #[must_use]
    pub fn to_attribute_value(&self) -> String {
        let hex: Vec<String> = self
            .bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();
        format!("fingerprint:{} {}", self.hash_function, hex.join(":"))
    }
}

/// The DTLS role from `a=setup` (RFC 4145 §4, applied to DTLS-SRTP by RFC 5763 §5): which endpoint
/// initiates the DTLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    /// `active` — this endpoint starts the handshake (the DTLS client).
    Active,
    /// `passive` — this endpoint waits for the handshake (the DTLS server).
    Passive,
    /// `actpass` — offer-only: willing to be either; the answerer chooses (RFC 5763 §5).
    Actpass,
    /// `holdconn` — the connection is on hold; do not establish it yet (RFC 4145 §4).
    Holdconn,
}

impl Setup {
    /// Parse an `a=setup:<role>` attribute body (RFC 4145 §4). Returns `None` for an unknown role.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.strip_prefix("setup:")?.trim() {
            "active" => Some(Setup::Active),
            "passive" => Some(Setup::Passive),
            "actpass" => Some(Setup::Actpass),
            "holdconn" => Some(Setup::Holdconn),
            _ => None,
        }
    }

    /// The `a=setup` role token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Setup::Active => "active",
            Setup::Passive => "passive",
            Setup::Actpass => "actpass",
            Setup::Holdconn => "holdconn",
        }
    }
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

    /// The RFC 3389 comfort-noise (`CN`) payload type offered on this stream at `clock_rate_hz`, if
    /// any — so a single-leg local answer can send comfort noise the caller renders during idle gaps.
    /// A CN payload is clock-rate-specific (RFC 3389 §2), so only a match at the media's own RTP clock
    /// is usable: a `CN` `a=rtpmap` at that rate, else static payload type 13 (`CN/8000`, RFC 3551 §6)
    /// offered without an rtpmap when `clock_rate_hz == 8000`.
    #[must_use]
    pub fn comfort_noise_payload_type(&self, clock_rate_hz: u32) -> Option<u8> {
        if let Some(map) = self.rtpmaps.iter().find(|map| {
            map.encoding_name.eq_ignore_ascii_case("CN") && map.clock_rate_hz == clock_rate_hz
        }) {
            return Some(map.payload_type);
        }
        // Static PT 13 = CN/8000 (RFC 3551 §6), commonly offered bare (no rtpmap). Only honour it when
        // no rtpmap re-purposed 13 to something else at another rate.
        if clock_rate_hz == 8000
            && self.payload_types.contains(&13)
            && !self.rtpmaps.iter().any(|map| map.payload_type == 13)
        {
            return Some(13);
        }
        None
    }

    /// The egress packetization for this stream: the negotiated `a=ptime`, capped by `a=maxptime`
    /// when the peer set one (RFC 4566 §6 — `maxptime` is "the maximum amount of media that can be
    /// encapsulated in each packet", so sending a longer packet is sending one the peer said it
    /// would not take). Applies to every codec; RFC 7587 §7 is what makes it matter for Opus, whose
    /// frame durations range up to 120 ms.
    fn effective_ptime_ms(&self) -> u8 {
        match self.maxptime_ms {
            Some(maxptime) if maxptime >= 1 => self.ptime_ms.min(maxptime),
            _ => self.ptime_ms,
        }
    }

    /// Resolve a payload type to a [`CodecSpec`] via its rtpmap, else the static table.
    fn codec_spec(&self, payload_type: u8) -> Option<CodecSpec> {
        let ptime_ms = self.effective_ptime_ms();
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
                ptime_ms,
            );
            // Honour an AMR-WB `mode-set` (RFC 4867 §8.1) by clamping the egress encode mode into
            // the allowed set, so the engine never sends the peer a mode it disallowed. The full set
            // is carried through so per-frame RFC 4867 CMR adaptation stays within it too.
            if spec.encoding_name == "AMR-WB" {
                if let Some((_, modes)) = self.mode_sets.iter().find(|(pt, _)| *pt == payload_type)
                {
                    return Some(
                        spec.with_encode_mode(choose_amr_wb_mode(modes))
                            .with_allowed_modes(modes.clone()),
                    );
                }
            }
            // Carry the peer's RFC 7587 §6.1 Opus parameters onto the spec: `sprop-stereo` decides
            // the ingress channel layout the decoder is built for, `maxptime` caps the egress ptime,
            // and the rest are the rate-control/FEC/DTX limits the Opus encoder honours. An `a=maxptime`
            // attribute (RFC 7587 §7 maps `maxptime` to it, not to fmtp) overrides an fmtp copy.
            if spec.is_opus() {
                let mut params = self
                    .opus_params
                    .iter()
                    .find(|(pt, _)| *pt == payload_type)
                    .map(|(_, params)| *params);
                if let Some(maxptime) = self.maxptime_ms {
                    let mut resolved = params.unwrap_or_default();
                    resolved.max_ptime_ms = OpusParams::clamp_ptime_ms(maxptime);
                    params = Some(resolved);
                }
                return Some(spec.with_opus_params(params));
            }
            return Some(spec);
        }
        CodecSpec::from_static_payload_type(payload_type, ptime_ms)
    }
}

/// The engine endpoints to advertise in a rewritten SDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineMedia {
    /// The engine's RTP endpoint (its bound `local_addr`). The **port** is advertised in `m=audio`;
    /// the IP is *not* — [`Self::advertised_ip`] is (they differ behind 1:1 NAT / a named interface).
    pub rtp: SocketAddr,
    /// The engine's RTCP endpoint, when not multiplexed (advertised as `a=rtcp:`). `None` ⇒
    /// rtcp-mux (any `a=rtcp:` line is dropped; RTCP rides the RTP port). Only its port is advertised.
    pub rtcp: Option<SocketAddr>,
    /// The IP advertised in `c=`/`o=`/ICE-candidate lines — the named interface's advertised (public)
    /// address, which equals `rtp.ip()` when no interface overrides it. Decoupling the advertised IP
    /// from the bound IP is what lets the engine bind a private/wildcard address yet hand peers a
    /// routable one; it is presentation-only and never feeds the source gate or latch.
    pub advertised_ip: IpAddr,
}

impl EngineMedia {
    /// Advertise the engine's *bound* address — `advertised_ip` = the RTP endpoint's own IP. The
    /// common case with no named-interface / advertised-IP override; the engine sets `advertised_ip`
    /// explicitly (via the struct literal) when an interface decouples the advertised IP from the bound
    /// one. Its family always matches `rtp`, so `c=`/`a=candidate` stay well-formed.
    #[must_use]
    pub fn new(rtp: SocketAddr, rtcp: Option<SocketAddr>) -> Self {
        Self {
            rtp,
            rtcp,
            advertised_ip: rtp.ip(),
        }
    }
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
    /// `a=fmtp` RFC 7587 Opus parameters in the audio section (payload type → parameter set).
    fmtp_opus: Vec<(u8, OpusParams)>,
    /// The audio stream's `a=ptime`, if present.
    ptime_ms: Option<u8>,
    /// The audio stream's `a=maxptime`, if present (RFC 4566 §6).
    maxptime_ms: Option<u8>,
    /// Parsed `a=crypto` lines in the audio section, in order (RFC 4568).
    crypto: Vec<CryptoAttribute>,
    /// The peer's DTLS fingerprint / setup role (`a=fingerprint` / `a=setup`), session- or media-level.
    fingerprint: Option<Fingerprint>,
    setup: Option<Setup>,
    /// Peer ICE credentials (`a=ice-ufrag` / `a=ice-pwd`), session- or media-level.
    ice_ufrag: Option<String>,
    ice_pwd: Option<String>,
    /// The peer's `a=candidate` lines for the audio stream (RFC 8839 §5.1), in offered order.
    candidates: Vec<Candidate>,
    /// The peer's `a=ice-options` tokens (RFC 8839 §5.6) — `trickle` above all.
    ice_options: IceOptions,
    /// Whether the peer sent `a=end-of-candidates` (RFC 8838 §14).
    end_of_candidates: bool,
    /// Whether the peer advertised `a=ice-lite` (RFC 8839 §5.2).
    ice_lite: bool,
    /// Whether the peer sent `a=ice-mismatch` (RFC 8839 §5.3).
    ice_mismatch: bool,
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

/// Split an `a=fmtp:<pt> <params>` attribute body into its payload type and its parameter list.
/// `None` when the prefix, the payload type, or the parameter list is missing. Shared by every fmtp
/// parser so the payload-type split lives in one place (RFC 4566 §6).
fn split_fmtp(value: &str) -> Option<(u8, &str)> {
    let body = value.strip_prefix("fmtp:")?;
    let (payload_type, params) = body.split_once(char::is_whitespace)?;
    Some((payload_type.trim().parse::<u8>().ok()?, params))
}

/// Look up one `key=value` fmtp parameter (case-insensitive key, `;`-separated list in any order —
/// RFC 4566 §6). Returns the trimmed value, or `None` when the key is absent.
fn fmtp_param<'a>(params: &'a str, key: &str) -> Option<&'a str> {
    params.split(';').map(str::trim).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim().eq_ignore_ascii_case(key).then(|| value.trim())
    })
}

/// Parse an RFC 7587 §6.1 `0`/`1` fmtp flag. Any other token (including an empty value or a
/// non-numeric one) leaves the RFC default in place rather than guessing — a garbled flag must not
/// silently turn a feature on.
fn fmtp_flag(params: &str, key: &str, default: bool) -> bool {
    match fmtp_param(params, key) {
        Some("1") => true,
        Some("0") => false,
        _ => default,
    }
}

/// Parse an `a=fmtp:<pt> ...mode-set=<m0,m1,...>...` body into `(payload_type, allowed_modes)`.
/// Returns `None` when the line carries no parseable payload type or no `mode-set` parameter — the
/// engine only acts on `mode-set`; every other fmtp parameter is passed through untouched.
fn parse_fmtp_mode_set(value: &str) -> Option<(u8, Vec<u8>)> {
    let (payload_type, params) = split_fmtp(value)?;
    // fmtp params are `;`-separated `key=value` pairs in any order (RFC 4867 §8.1).
    let modes_field = fmtp_param(params, "mode-set")?;
    let modes: Vec<u8> = modes_field
        .split(',')
        .filter_map(|token| token.trim().parse::<u8>().ok())
        .filter(|&mode| mode <= 8)
        .collect();
    (!modes.is_empty()).then_some((payload_type, modes))
}

/// Parse an `a=fmtp:<pt> …` body into `(payload_type, OpusParams)` (RFC 7587 §6.1).
///
/// Returns `None` when the line has no parseable payload type, or when it carries **no** recognised
/// Opus parameter — an fmtp for some other codec (an AMR `mode-set`, say) must not be recorded as an
/// all-defaults Opus parameter set. Every parameter is independently optional: an absent, empty, or
/// malformed value leaves the RFC 7587 §6.1 default in place, and an out-of-range numeric value is
/// clamped into the range the RFC permits. Nothing here can panic — the whole body is untrusted.
fn parse_fmtp_opus(value: &str) -> Option<(u8, OpusParams)> {
    const KEYS: [&str; 8] = [
        "maxaveragebitrate",
        "maxplaybackrate",
        "maxptime",
        "stereo",
        "sprop-stereo",
        "cbr",
        "useinbandfec",
        "usedtx",
    ];
    let (payload_type, params) = split_fmtp(value)?;
    if !KEYS.iter().any(|key| fmtp_param(params, key).is_some()) {
        return None;
    }
    let default = OpusParams::default();
    let parsed = OpusParams {
        max_average_bitrate: fmtp_param(params, "maxaveragebitrate")
            .and_then(|value| value.parse::<u32>().ok())
            .map(OpusParams::clamp_average_bitrate),
        max_playback_rate_hz: fmtp_param(params, "maxplaybackrate")
            .and_then(|value| value.parse::<u32>().ok())
            .map_or(default.max_playback_rate_hz, |rate| {
                OpusParams::clamp_playback_rate_hz(rate)
            }),
        // RFC 7587 §7 maps `maxptime` to the SDP `a=maxptime` attribute; some UAs also put it in the
        // fmtp (§6.1 registers it as a media-type parameter, so it is legal there for non-SDP
        // transports). Accept both — `MediaInfo::codec_spec` lets the attribute win.
        max_ptime_ms: fmtp_param(params, "maxptime")
            .and_then(|value| value.parse::<u16>().ok())
            .map_or(default.max_ptime_ms, |ptime| {
                OpusParams::clamp_ptime_ms(u8::try_from(ptime).unwrap_or(u8::MAX))
            }),
        stereo: fmtp_flag(params, "stereo", default.stereo),
        sprop_stereo: fmtp_flag(params, "sprop-stereo", default.sprop_stereo),
        cbr: fmtp_flag(params, "cbr", default.cbr),
        use_inband_fec: fmtp_flag(params, "useinbandfec", default.use_inband_fec),
        use_dtx: fmtp_flag(params, "usedtx", default.use_dtx),
    };
    Some((payload_type, parsed))
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
        candidates: Vec::new(),
        ice_options: IceOptions::default(),
        end_of_candidates: false,
        ice_lite: false,
        ice_mismatch: false,
        payload_types: Vec::new(),
        rtpmaps: Vec::new(),
        fmtp_mode_sets: Vec::new(),
        fmtp_opus: Vec::new(),
        ptime_ms: None,
        maxptime_ms: None,
        crypto: Vec::new(),
        fingerprint: None,
        setup: None,
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
                } else if value == "ice-lite" {
                    // RFC 8839 §5.2: the peer is an ICE-lite agent. A full agent facing a lite peer
                    // is always the controlling one (RFC 8445 §6.1.1), so this drives role selection.
                    scan.ice_lite = true;
                } else if value.starts_with("ice-options:") {
                    // RFC 8839 §5.6, session- or media-level; media-level wins (like the credentials).
                    if in_audio || scan.ice_options.is_empty() {
                        scan.ice_options = IceOptions::parse(value);
                    }
                } else if value.starts_with("ice-mismatch") {
                    // RFC 8839 §5.3: the peer could not use our ICE because the SDP was rewritten
                    // in transit (a SIP ALG). Session- or media-level.
                    scan.ice_mismatch = true;
                } else if value.starts_with("end-of-candidates") {
                    // RFC 8838 §14: the peer's candidate list is complete — no more will trickle in.
                    scan.end_of_candidates = true;
                } else if let Some(candidate) = value.strip_prefix("candidate:") {
                    // RFC 8839 §5.1. Only the audio stream's candidates matter to us (one m= section
                    // is anchored per leg), and a candidate is skipped — never fatal — when it names
                    // something we cannot use: an mDNS `.local` name (we do not resolve those;
                    // connectivity still succeeds via peer-reflexive discovery from the peer's own
                    // checks, RFC 8445 §7.3.1.3) or a malformed line from a broken UA.
                    if in_audio {
                        match Candidate::parse(value) {
                            Ok(candidate) => scan.candidates.push(candidate),
                            Err(error) if error.is_unresolved_hostname() => {
                                tracing::debug!(
                                    target: "siphon_rtp::control",
                                    candidate = %candidate.trim(),
                                    "skipping mDNS ICE candidate (not resolved)"
                                );
                            }
                            Err(error) => {
                                tracing::debug!(
                                    target: "siphon_rtp::control",
                                    candidate = %candidate.trim(),
                                    %error,
                                    "skipping malformed ICE candidate"
                                );
                            }
                        }
                    }
                } else if value.starts_with("fingerprint:") {
                    // RFC 8122 `a=fingerprint` — session- or media-level; media-level wins (like ICE).
                    if in_audio || scan.fingerprint.is_none() {
                        if let Some(fingerprint) = Fingerprint::parse(value) {
                            scan.fingerprint = Some(fingerprint);
                        }
                    }
                } else if value.starts_with("setup:") {
                    // RFC 4145 `a=setup` — session- or media-level; media-level wins.
                    if in_audio || scan.setup.is_none() {
                        if let Some(setup) = Setup::parse(value) {
                            scan.setup = Some(setup);
                        }
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
                        // One fmtp line can only belong to one codec, but the codec it belongs to is
                        // not known until the rtpmaps are resolved (SDP attribute order is free —
                        // RFC 4566 §5), so parse it for every parameter set the engine understands
                        // and let `MediaInfo::codec_spec` pick the one its codec cares about.
                        if let Some(mode_set) = parse_fmtp_mode_set(value) {
                            scan.fmtp_mode_sets.push(mode_set);
                        }
                        if let Some(opus) = parse_fmtp_opus(value) {
                            scan.fmtp_opus.push(opus);
                        }
                    } else if let Some(maxptime) = value.strip_prefix("maxptime:") {
                        // RFC 4566 §6 / RFC 7587 §7: the longest packet the peer will accept.
                        scan.maxptime_ms = maxptime.trim().parse::<u8>().ok();
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
        // A secure profile is any `RTP/SAVP` variant: SDES (`RTP/SAVP[F]`) or DTLS (`UDP/TLS/RTP/SAVP[F]`).
        secure: scan
            .transport
            .as_deref()
            .is_some_and(|transport| transport.contains("SAVP")),
        crypto: scan.crypto.clone(),
        // DTLS-SRTP: the transport is `UDP/TLS/RTP/SAVP[F]` (RFC 5764), keyed by the handshake, not SDES.
        dtls: scan
            .transport
            .as_deref()
            .is_some_and(|transport| transport.contains("UDP/TLS")),
        fingerprint: scan.fingerprint.clone(),
        setup: scan.setup,
        ice_ufrag: scan.ice_ufrag.clone(),
        ice_pwd: scan.ice_pwd.clone(),
        candidates: scan.candidates.clone(),
        ice_options: scan.ice_options.clone(),
        end_of_candidates: scan.end_of_candidates,
        ice_lite: scan.ice_lite,
        ice_mismatch: scan.ice_mismatch,
        payload_types: scan.payload_types.clone(),
        rtpmaps: scan.rtpmaps.clone(),
        mode_sets: scan.fmtp_mode_sets.clone(),
        opus_params: scan.fmtp_opus.clone(),
        ptime_ms: scan.ptime_ms.unwrap_or(DEFAULT_PTIME_MS),
        maxptime_ms: scan.maxptime_ms,
    })
}

/// Parse the remote audio transport info from an SDP without rewriting it.
pub fn parse(sdp: &str) -> Result<MediaInfo, SdpError> {
    media_info(&scan(sdp))
}

/// The engine's ICE identity to advertise in a rewritten SDP: `a=ice-lite` (session-level) plus
/// `a=ice-ufrag` / `a=ice-pwd` and the **gathered** candidate set.
#[derive(Debug, Clone, Copy)]
pub struct IceAdvertisement<'a> {
    /// The engine's local ICE username fragment.
    pub ufrag: &'a str,
    /// The engine's local ICE password.
    pub pwd: &'a str,
    /// The candidates gathered for this leg (RFC 8445 §5.1.1), emitted in order as `a=candidate`
    /// lines. Always at least the host candidate — gathering produces that without touching the
    /// network — plus a server-reflexive one per STUN server that answered.
    pub candidates: &'a [Candidate],
}

/// How [`rewrite`] treats the audio stream's ICE attributes (RFC 8445 / RFC 8839 §5). Decouples the
/// two ICE actions that used to be one `Option`: dropping the peer's ICE and re-originating our own.
#[derive(Debug, Clone, Copy, Default)]
pub enum IceRewrite<'a> {
    /// Leave the peer's ICE attributes untouched — a plain relay passes them through (the default).
    #[default]
    Keep,
    /// Strip the peer's ICE attributes (`a=ice-ufrag`/`a=ice-pwd`/`a=candidate`/…) without advertising
    /// our own — the rewritten SDP carries no ICE at all (rtpengine `ICE=remove`, RFC 8839 §5). The
    /// leg then falls back to the signalled media address rather than ICE connectivity checks.
    Strip,
    /// Strip the peer's ICE and re-originate ICE-lite with the engine's own credentials plus a host
    /// `a=candidate` (rtpengine `ICE=force`, or mirroring a peer's ICE offer; RFC 8445 §2.7 ICE-lite).
    Reoriginate(IceAdvertisement<'a>),
    /// Strip the peer's ICE and advertise `a=ice-mismatch` (RFC 8839 §5.3): its offer carried
    /// candidates but its default destination matched none of them, so the SDP was altered in transit
    /// and ICE cannot be used on this stream. The leg falls back to the signalled address.
    Mismatch,
}

/// How to advertise the audio stream's security on rewrite (RFC 3264 transport + RFC 4568 SDES /
/// RFC 5764 DTLS-SRTP). Not `Copy` — the DTLS variant carries a variable-length fingerprint.
#[derive(Debug, Clone)]
pub enum SecurityAdvertisement {
    /// Plaintext `RTP/AVP`: force the transport profile and strip any `a=crypto`/`a=fingerprint`.
    Plain,
    /// SDES-secure `RTP/SAVP`: force the transport, strip the peer's keying, and advertise this
    /// `a=crypto` (the engine's own offered SDES key for the leg, RFC 4568).
    Secure(CryptoAttribute),
    /// DTLS-secure `UDP/TLS/RTP/SAVPF`: force the transport, strip the peer's keying, and advertise the
    /// engine's certificate fingerprint and DTLS role (RFC 5764 / RFC 5763). The key is derived by the
    /// DTLS handshake, not carried in SDP.
    Dtls {
        /// The engine certificate's fingerprint to advertise (`a=fingerprint`, RFC 8122).
        fingerprint: Fingerprint,
        /// The engine's DTLS role (`a=setup`): `Actpass` in an offer, `Passive`/`Active` in an answer.
        setup: Setup,
    },
}

impl SecurityAdvertisement {
    /// The `m=audio` transport profile to advertise.
    fn transport(&self) -> &'static str {
        match self {
            SecurityAdvertisement::Plain => "RTP/AVP",
            SecurityAdvertisement::Secure(_) => "RTP/SAVP",
            SecurityAdvertisement::Dtls { .. } => "UDP/TLS/RTP/SAVPF",
        }
    }
}

/// Host-candidate priority (RFC 8445 §5.1.2): type-pref 126, local-pref 65535, component 1 (RTP).
/// Shared with the consent driver, whose checks must advertise the same PRIORITY they would carry in
/// a connectivity check for this candidate (RFC 8445 §7.1.1) — one definition, not two.
pub(crate) const HOST_CANDIDATE_PRIORITY: u32 = (126 << 24) | (65535 << 8) | 255;

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

/// Whether `line` is an ICE attribute the engine drops on rewrite when stripping or re-originating
/// (RFC 8839 §5) — the peer's copy is removed so it is not forwarded verbatim.
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
/// `mux_override` controls the generated `a=rtcp-mux` attribute (RFC 5761): `Some(true)` forces the
/// stream to advertise mux (an `a=rtcp-mux` line is emitted, any duplicate dropped); `Some(false)`
/// strips `a=rtcp-mux` so the far side demuxes RTCP onto its own port; `None` mirrors the input
/// (the default — the offered mux intent is passed through). This lets the controller's rtpengine
/// `rtcp-mux` directive drive the far/near presentation independently of what the peer offered.
///
/// `ice` selects the ICE handling (RFC 8445 / RFC 8839 §5): [`IceRewrite::Keep`] passes the peer's
/// ICE through; [`IceRewrite::Strip`] drops it without re-originating (rtpengine `ICE=remove`);
/// [`IceRewrite::Reoriginate`] drops the peer's ICE and re-originates ICE-lite with `a=ice-lite`
/// plus the engine's own `a=ice-ufrag`/`a=ice-pwd` and a host `a=candidate` for the engine RTP
/// address (rtpengine `ICE=force` / mirroring a peer's ICE offer).
pub fn rewrite(
    sdp: &str,
    engine: EngineMedia,
    ice: IceRewrite<'_>,
    security: Option<SecurityAdvertisement>,
    mux_override: Option<bool>,
) -> Result<Rewritten, SdpError> {
    let scan = scan(sdp);
    let media = media_info(&scan)?;
    let (media_index, _) = scan.audio_media.ok_or(SdpError::NoAudioMedia)?;
    let (conn_index, _) = scan
        .audio_conn
        .or(scan.session_conn)
        .ok_or(SdpError::ConnectionAddress)?;
    let rtcp_index = scan.audio_rtcp.map(|(index, _)| index);

    // `Strip`, `Reoriginate` and `Mismatch` all drop the peer's ICE attributes; only `Reoriginate`
    // re-adds ours, and only `Mismatch` says why they are gone (RFC 8839 §5.3).
    let strip_peer_ice = matches!(
        ice,
        IceRewrite::Strip | IceRewrite::Reoriginate(_) | IceRewrite::Mismatch
    );
    let mut lines: Vec<String> = Vec::new();
    for (index, raw_line) in sdp.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        // Drop the peer's ICE attributes when stripping or re-originating (RFC 8839 §5); we advertise
        // our own below only when re-originating.
        if strip_peer_ice && is_ice_attribute(line) {
            continue;
        }
        // Re-originating secure keying: drop the peer's `a=crypto` (SDES) and `a=fingerprint`/`a=setup`
        // (DTLS); we advertise our own below (or none, for a plaintext downgrade).
        if security.is_some()
            && (line.starts_with("a=crypto:")
                || line.starts_with("a=fingerprint:")
                || line.starts_with("a=setup:"))
        {
            continue;
        }
        // RFC 5761 rtcp-mux override: strip the peer's `a=rtcp-mux` when forcing demux
        // (`Some(false)`) or when forcing mux (`Some(true)` — we re-emit exactly one after the media
        // line, so drop any input copy to avoid a duplicate). `None` leaves the line untouched.
        if line == "a=rtcp-mux" && matches!(mux_override, Some(false) | Some(true)) {
            continue;
        }
        if index == media_index {
            // `a=ice-lite` is session-level — emit it just before the media line (end of session).
            if matches!(ice, IceRewrite::Reoriginate(_)) {
                lines.push("a=ice-lite".to_string());
            }
            lines.push(rewrite_media_line(
                line,
                engine.rtp.port(),
                security.as_ref().map(SecurityAdvertisement::transport),
            ));
            // RFC 5761: force `a=rtcp-mux` when the controller directs it (`Some(true)`), regardless
            // of whether the input offered it.
            if mux_override == Some(true) {
                lines.push("a=rtcp-mux".to_string());
            }
            // Insert a fresh a=rtcp line only if there is no existing one to rewrite in place.
            if let Some(rtcp) = engine.rtcp {
                if rtcp_index.is_none() {
                    lines.push(format!("a=rtcp:{}", rtcp.port()));
                }
            }
            // Advertise the engine's own keying on a secure leg: the SDES `a=crypto` (RFC 4568) or the
            // DTLS `a=fingerprint` + `a=setup` (RFC 5764 / RFC 5763).
            match &security {
                Some(SecurityAdvertisement::Secure(crypto)) => {
                    lines.push(format!("a={}", crypto.to_attribute_value()));
                }
                Some(SecurityAdvertisement::Dtls { fingerprint, setup }) => {
                    lines.push(format!("a={}", fingerprint.to_attribute_value()));
                    lines.push(format!("a=setup:{}", setup.token()));
                }
                Some(SecurityAdvertisement::Plain) | None => {}
            }
            if matches!(ice, IceRewrite::Mismatch) {
                // RFC 8839 §5.3: say why ICE is absent rather than silently dropping it, so the
                // offerer knows its SDP was rewritten and does not keep waiting for checks.
                lines.push(ICE_MISMATCH_ATTRIBUTE.to_string());
            }
            if let IceRewrite::Reoriginate(ice) = ice {
                lines.push(format!("a=ice-ufrag:{}", ice.ufrag));
                lines.push(format!("a=ice-pwd:{}", ice.pwd));
                // RFC 8839 §5.1: the candidate's connection-address is a bare IP literal in either
                // family — `IpAddr`'s Display emits a v6 literal without brackets, exactly as the
                // `a=candidate` grammar requires (brackets are an `m=`/`c=`-line concern only).
                for candidate in ice.candidates {
                    lines.push(candidate.to_attribute_line());
                }
                // RFC 8838 §14: our list is complete before the SDP is built (gathering runs to
                // completion, or to its deadline, on the control path), so say so — a trickle-capable
                // peer can stop waiting for more instead of holding its checklist open.
                lines.push(END_OF_CANDIDATES_ATTRIBUTE.to_string());
            }
        } else if index == conn_index {
            // RFC 4566 §5.7: emit the addrtype of the engine endpoint's own family (`IP4`/`IP6`),
            // so a v6 engine endpoint is advertised as `c=IN IP6` and a v4 one as `c=IN IP4`. The IP
            // is the interface's advertised (public) address, not the bound one — same family.
            let ip = engine.advertised_ip;
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

/// Resolved rtpengine codec-manipulation policy for the SDP offered to the far side
/// (`docs/ng_control_protocol.md`, the `codec` dictionary). Built from the `codec-<op>-<NAME>`
/// profile flags by [`crate::engine`] and applied by [`apply_codec_policy`].
///
/// Note on `strip` vs `mask`/`consume`: rtpengine distinguishes them by whether the codec stays
/// usable for transcoding on the *offering* side. This engine derives the offering (near) leg's
/// codec from the offerer's own **unmodified** offer — independent of what is stripped/masked from
/// the SDP sent onward — so the near side always keeps its codec regardless. The three therefore
/// collapse to the same far-offer edit here (`mask`/`consume` on the near leg's own codec engage the
/// transcoder automatically, because the near/far primaries then differ). Encoding names are stored
/// uppercased for case-insensitive matching (SDP names are case-insensitive — RFC 4566 §6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodecPolicy {
    /// Encoding names removed from the far offer — the union of `strip`, `mask` and `consume`.
    pub remove: Vec<String>,
    /// Remove every far-offer audio codec except the keep-list — `strip`/`mask` with the special
    /// value `all` / `full`.
    pub remove_all: bool,
    /// Names never removed — the union of `except` and `accept` (the keep-list exception to
    /// `remove` / `remove_all`).
    pub keep: Vec<String>,
    /// Explicit far-offer codec order (`offer`): a whitelist that also sets priority — only these
    /// codecs (of those already offered) are kept, in this order. Empty ⇒ the offered order is kept.
    pub order: Vec<String>,
    /// Codecs appended to the far offer (`transcode` targets), so the far side may select one and
    /// engage the transcoder.
    pub add: Vec<CodecSpec>,
}

impl CodecPolicy {
    /// Whether the policy edits the SDP at all (else the far offer is passed through untouched).
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.remove.is_empty() && !self.remove_all && self.order.is_empty() && self.add.is_empty()
    }
}

/// Rewrite the audio `m=` codec list to honour rtpengine `codec-strip-X` / `codec-transcode-X`
/// flags: drop every payload type whose encoding name is in `strip` (case-insensitive, matched via
/// `a=rtpmap` or the RFC 3551 static table) and append each codec in `add`. Thin wrapper over
/// [`apply_codec_policy`] retained for the simple strip/add call sites and their tests.
#[must_use]
pub fn rewrite_codec_list(sdp: &str, strip: &[String], add: &[CodecSpec]) -> String {
    apply_codec_policy(
        sdp,
        &CodecPolicy {
            remove: strip.iter().map(|s| s.to_ascii_uppercase()).collect(),
            add: add.to_vec(),
            ..CodecPolicy::default()
        },
    )
}

/// Apply a resolved [`CodecPolicy`] to the SDP offered to the far side (rtpengine
/// `docs/ng_control_protocol.md` codec manipulation): remove/mask/whitelist/reorder the audio `m=`
/// codec list — dropping each removed payload type's `a=rtpmap`/`a=fmtp` lines — and append the
/// `add` (transcode) codecs (payload type on the `m=` line plus a fresh `a=rtpmap`).
///
/// Best-effort and conservative: returns the SDP unchanged when it has no `m=audio` line; never
/// removes the **last** remaining audio codec (an empty `m=` list is invalid, RFC 4566 §5.14); and
/// skips an `add` codec whose payload type is already present. Telephone-event (RFC 4733 DTMF) is
/// preserved unless explicitly named in `remove` (it is never swept by `remove_all` / `order`).
#[must_use]
pub fn apply_codec_policy(sdp: &str, policy: &CodecPolicy) -> String {
    if policy.is_noop() {
        return sdp.to_string();
    }
    let lines: Vec<&str> = sdp.split('\n').map(|l| l.trim_end_matches('\r')).collect();

    // Locate the audio `m=` line and parse its payload-type list.
    let Some(media_index) = lines
        .iter()
        .position(|l| l.starts_with("m=audio ") || *l == "m=audio")
    else {
        return sdp.to_string();
    };
    let media_fields: Vec<&str> = lines[media_index]
        .strip_prefix("m=")
        .unwrap_or(lines[media_index])
        .split(' ')
        .collect();
    // m=audio <port> <proto> <pt...>
    if media_fields.len() < 3 {
        return sdp.to_string();
    }
    let payload_types: Vec<u8> = media_fields[3..]
        .iter()
        .filter_map(|f| f.parse::<u8>().ok())
        .collect();

    // Resolve each payload type to its encoding name (uppercased), via `a=rtpmap` then the static table.
    let name_of = |payload_type: u8| -> Option<String> {
        for line in &lines {
            if let Some(map) = line
                .strip_prefix("a=rtpmap:")
                .and_then(|body| body.split_once(char::is_whitespace))
            {
                if map.0.trim().parse::<u8>().ok() == Some(payload_type) {
                    return map
                        .1
                        .split('/')
                        .next()
                        .map(|n| n.trim().to_ascii_uppercase());
                }
            }
        }
        CodecSpec::from_static_payload_type(payload_type, DEFAULT_PTIME_MS)
            .map(|spec| spec.encoding_name)
    };
    let is_telephone_event = |name: &Option<String>| name.as_deref() == Some("TELEPHONE-EVENT");

    // Decide which payload types to remove from the far offer.
    let mut removed: Vec<u8> = payload_types
        .iter()
        .copied()
        .filter(|&pt| {
            let name = name_of(pt);
            let explicitly_removed = name.as_ref().is_some_and(|n| policy.remove.contains(n));
            // Telephone-event survives every sweep (remove_all / whitelist) unless named outright.
            if is_telephone_event(&name) {
                return explicitly_removed;
            }
            // The keep-list (`except` / `accept`) exempts a codec from any removal.
            if name.as_ref().is_some_and(|n| policy.keep.contains(n)) {
                return false;
            }
            if !policy.order.is_empty() {
                // `offer` is a whitelist: remove anything not named in the explicit offer order.
                return !name.as_ref().is_some_and(|n| policy.order.contains(n));
            }
            if policy.remove_all {
                return true;
            }
            explicitly_removed
        })
        .collect();

    // Never empty the audio codec list: if every audio codec would go, keep the first one.
    let audio_types: Vec<u8> = payload_types
        .iter()
        .copied()
        .filter(|&pt| !is_telephone_event(&name_of(pt)))
        .collect();
    if !audio_types.is_empty() && audio_types.iter().all(|pt| removed.contains(pt)) {
        if let Some(&first) = audio_types.first() {
            removed.retain(|pt| *pt != first);
        }
    }

    // Survivors, in the requested order (`offer`) or the original order otherwise.
    let mut present: Vec<u8> = payload_types
        .iter()
        .copied()
        .filter(|pt| !removed.contains(pt))
        .collect();
    if !policy.order.is_empty() {
        // Stable sort by the offer order; telephone-event / unlisted survivors sort last, in place.
        present.sort_by_key(|&pt| {
            name_of(pt)
                .and_then(|n| policy.order.iter().position(|o| *o == n))
                .map_or(usize::MAX, |index| index)
        });
    }
    let reordered = present
        != payload_types
            .iter()
            .copied()
            .filter(|pt| !removed.contains(pt))
            .collect::<Vec<_>>();

    // Codecs to append (skip any already present after removal).
    let added: Vec<&CodecSpec> = policy
        .add
        .iter()
        .filter(|spec| !present.contains(&spec.payload_type))
        .collect();
    if removed.is_empty() && added.is_empty() && !reordered {
        return sdp.to_string();
    }

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + added.len());
    for (index, line) in lines.iter().enumerate() {
        if index == media_index {
            let mut formats: Vec<String> = present
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            formats.extend(added.iter().map(|spec| spec.payload_type.to_string()));
            out.push(format!(
                "m={} {} {} {}",
                media_fields[0],
                media_fields[1],
                media_fields[2],
                formats.join(" ")
            ));
            // Insert `a=rtpmap` for each added codec right after the media line (RFC 4566 — order-free).
            // Emitted through the shared `rtpmap_line`, so an added Opus codec gets the mandatory
            // `/2` channel suffix (RFC 7587 §7) rather than the illegal bare `opus/48000`.
            for spec in &added {
                out.push(rtpmap_line(spec));
            }
            continue;
        }
        // Drop `a=rtpmap`/`a=fmtp` for removed payload types.
        let attr_pt = line
            .strip_prefix("a=rtpmap:")
            .or_else(|| line.strip_prefix("a=fmtp:"))
            .and_then(|body| body.split(|c: char| c.is_whitespace() || c == '/').next())
            .and_then(|pt| pt.trim().parse::<u8>().ok());
        if let Some(pt) = attr_pt {
            if removed.contains(&pt) {
                continue;
            }
        }
        // Preserve the trailing empty line if the input ended with CRLF.
        if !(index == lines.len() - 1 && line.is_empty()) {
            out.push((*line).to_string());
        }
    }
    let mut rewritten = out.join(CRLF);
    if sdp.ends_with('\n') {
        rewritten.push_str(CRLF);
    }
    rewritten
}

/// The optional `/<channels>` suffix of an `a=rtpmap` line (RFC 4566 §6), or an empty string when it
/// is omitted. **The** source of truth for the suffix — every rtpmap the engine emits goes through
/// it, so the Opus rule below cannot be honoured in one emitter and forgotten in another.
///
/// RFC 4566 §6 makes the suffix optional and defaults it to 1, so mono telephony omits it. Opus is
/// the exception: RFC 7587 §7 requires `opus/48000/2` **unconditionally**, mono included, because the
/// count names the *RTP* channel count rather than the audio channel count (mono is signalled by the
/// fmtp `stereo` / `sprop-stereo` parameters instead). `opus/48000` is therefore not a legal line.
/// `CodecSpec::new` pins an Opus spec's `channels` at 2 (`OPUS_RTPMAP_CHANNELS`), so the single
/// `> 1` test covers Opus as well as genuine multi-channel audio.
pub(crate) fn rtpmap_channel_suffix(codec: &CodecSpec) -> String {
    if codec.channels > 1 {
        format!("/{}", codec.channels)
    } else {
        String::new()
    }
}

/// The `a=rtpmap` line for a codec (`a=rtpmap:<pt> <name>/<clock>[/<channels>]`, RFC 4566 §6), with
/// the channel suffix decided by [`rtpmap_channel_suffix`].
fn rtpmap_line(codec: &CodecSpec) -> String {
    format!(
        "a=rtpmap:{} {}/{}{}",
        codec.payload_type,
        codec.encoding_name,
        codec.clock_rate_hz,
        rtpmap_channel_suffix(codec)
    )
}

/// The `a=fmtp` line describing the engine's egress framing for a codec that needs one, or `None`.
///
/// **AMR-WB:** the engine's encoder emits **octet-aligned** single-frame payloads (RFC 4867 §4.4 —
/// see `siphon_rtp_codec::amr`), so the answer must advertise `octet-align=1`; when a `mode-set` was
/// negotiated it also advertises the single mode the engine actually sends (RFC 4867 §8.1).
/// (Bandwidth-efficient AMR-WB egress is a separate follow-up.)
///
/// **Opus:** every RFC 7587 §6.1 parameter is *declarative and unidirectional* (§7.1) — there is no
/// negotiation, each side states its own posture — so this line is the **engine's** statement, not an
/// echo of the peer's. The engine's media path is mono end to end, so it declares exactly that, in
/// both directions the RFC gives it a parameter for:
///
/// - `stereo=0` — receive-only (§6.1): "do not send me stereo". True, and it saves the peer the
///   bitrate: a stereo ingress would be folded to mono at the codec trait boundary anyway.
/// - `sprop-stereo=0` — sender-only (§6.1): "what I send you is mono". Emitted explicitly even
///   though 0 is the default, because `a=rtpmap:… opus/48000/2` invites the opposite assumption.
///
/// The remaining receive-only parameters (`maxaveragebitrate`, `maxplaybackrate`, `cbr`,
/// `useinbandfec`, `usedtx`) are deliberately **omitted**, which per §6.1 declares their defaults —
/// no bitrate cap, full-band, VBR, no FEC, no DTX. That is the engine's true posture today: it places
/// no constraint on the peer's encoder and its own decoder is not yet in the factory. When the Opus
/// decoder lands with in-band FEC (LBRR), `useinbandfec=1` belongs here.
///
/// `maxptime` is not an fmtp parameter in SDP — RFC 7587 §7 maps it to the `a=maxptime` attribute,
/// which [`force_answer_codec`] emits alongside `a=ptime`.
fn egress_fmtp_line(codec: &CodecSpec) -> Option<String> {
    if codec.is_opus() {
        // RFC 7587 §6.1 / §7.1 — the engine's own declaration; see the doc comment above.
        return Some(format!(
            "a=fmtp:{} stereo=0;sprop-stereo=0",
            codec.payload_type
        ));
    }
    if codec.encoding_name != "AMR-WB" {
        return None;
    }
    let mut params = String::from("octet-align=1");
    if let Some(mode) = codec.encode_mode {
        params.push_str(&format!(";mode-set={mode}"));
    }
    Some(format!("a=fmtp:{} {params}", codec.payload_type))
}

/// The `a=maxptime` line the engine advertises for a codec, or `None` when it advertises none.
///
/// Only Opus needs one: it is the only codec here whose frame duration is variable and can exceed the
/// engine's scratch ceiling, and RFC 7587 §7 maps its `maxptime` parameter to this attribute (RFC
/// 4566 §6). The advertised value is the engine's real ceiling — [`OPUS_MAX_PTIME_MS`], which is both
/// the RFC 7587 §6.1 maximum and the duration the media path's frame buffers are sized for — so it is
/// a statement the engine can keep. Fixed-frame codecs (G.711 at any ptime, AMR's native 20 ms)
/// advertise nothing, exactly as before.
fn egress_maxptime_line(codec: &CodecSpec) -> Option<String> {
    codec
        .is_opus()
        .then(|| format!("a=maxptime:{OPUS_MAX_PTIME_MS}"))
}

/// Force an answer SDP's audio codec presentation to `primary` (plus the negotiated `telephone_event`
/// payload type, if any) — used on a **transcoding** call so the answer relayed back to a leg
/// advertises *that leg's own* codec, never the far side's.
///
/// On a transcoded call the engine decodes the peer's codec and re-encodes into this leg's negotiated
/// codec, so the codec this leg will actually receive is `primary` (its offer's primary codec), not
/// whatever the peer answered. Relaying the peer's codec list would offer the recipient a codec it
/// never offered (RFC 3264 §6 — an answer must contain only formats from the recipient's own offer).
///
/// Rewrites the audio `m=` format list to `[primary.payload_type]` (+ the telephone-event PT), drops
/// every other codec's `a=rtpmap`/`a=fmtp`, and re-emits a fresh `a=rtpmap` for `primary` (plus, for
/// AMR-WB, the egress `a=fmtp`) and a `telephone-event/8000` rtpmap. Best-effort and conservative:
/// returns the SDP unchanged when it has no `m=audio` line.
#[must_use]
pub fn force_answer_codec(sdp: &str, primary: &CodecSpec, telephone_event: Option<u8>) -> String {
    let lines: Vec<&str> = sdp.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let Some(media_index) = lines
        .iter()
        .position(|l| l.starts_with("m=audio ") || *l == "m=audio")
    else {
        return sdp.to_string();
    };
    let media_fields: Vec<&str> = lines[media_index]
        .strip_prefix("m=")
        .unwrap_or(lines[media_index])
        .split(' ')
        .collect();
    // m=audio <port> <proto> <pt...>
    if media_fields.len() < 3 {
        return sdp.to_string();
    }

    // The payload types the answer keeps, in order: the leg's own audio codec, then telephone-event.
    let mut kept: Vec<u8> = vec![primary.payload_type];
    if let Some(te) = telephone_event {
        if te != primary.payload_type {
            kept.push(te);
        }
    }

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 2);
    for (index, line) in lines.iter().enumerate() {
        if index == media_index {
            let formats: Vec<String> = kept.iter().map(u8::to_string).collect();
            out.push(format!(
                "m={} {} {} {}",
                media_fields[0],
                media_fields[1],
                media_fields[2],
                formats.join(" ")
            ));
            // Re-emit our own codec attributes right after the media line (RFC 4566 is order-free).
            out.push(rtpmap_line(primary));
            if let Some(fmtp) = egress_fmtp_line(primary) {
                out.push(fmtp);
            }
            if let Some(te) = telephone_event {
                out.push(format!("a=rtpmap:{te} telephone-event/8000"));
            }
            // Advertise the packetization the engine will actually send to this side (RFC 4566 §6):
            // the leg's negotiated ptime or a `ptime=<N>` control override. The transcode datapath
            // re-frames the egress to exactly this (the repacketizer), so the SDP must present our own
            // ptime, never leak the far side's.
            out.push(format!("a=ptime:{}", primary.ptime_ms));
            // …and, for a codec with a variable frame duration (Opus), the longest packet the engine
            // will accept back (RFC 7587 §7 maps `maxptime` here, not into fmtp).
            if let Some(maxptime) = egress_maxptime_line(primary) {
                out.push(maxptime);
            }
            continue;
        }
        // Drop the far side's `a=ptime` / `a=maxptime` — we re-emit our own effective ptime and our
        // own frame-duration ceiling above. Leaking the far side's would advertise a packetization
        // this leg never receives.
        if line.starts_with("a=ptime:") || line.starts_with("a=maxptime:") {
            continue;
        }
        // Drop the far side's per-payload-type codec attributes; we re-emit our own above.
        let is_codec_attr = line
            .strip_prefix("a=rtpmap:")
            .or_else(|| line.strip_prefix("a=fmtp:"))
            .and_then(|body| body.split(|c: char| c.is_whitespace() || c == '/').next())
            .and_then(|pt| pt.trim().parse::<u8>().ok())
            .is_some();
        if is_codec_attr {
            continue;
        }
        // Preserve the trailing empty line if the input ended with CRLF.
        if !(index == lines.len() - 1 && line.is_empty()) {
            out.push((*line).to_string());
        }
    }
    let mut rewritten = out.join(CRLF);
    if sdp.ends_with('\n') {
        rewritten.push_str(CRLF);
    }
    rewritten
}

/// Add an RFC 3389 comfort-noise payload type to an answer's `m=audio` format list and emit its
/// `a=rtpmap:<pt> CN/<clock>` — so a single-leg local answer advertises the CN the engine will send
/// during idle gaps (the caller's own generator renders it), instead of looping the caller's audio
/// back. Applied *after* [`force_answer_codec`] on the offer-only `answer_local` path only; the 2-leg
/// answer path never carries it. Best-effort and idempotent: returns the SDP unchanged when it has no
/// `m=audio` line or already lists `payload_type`.
#[must_use]
pub fn add_comfort_noise(sdp: &str, payload_type: u8, clock_rate_hz: u32) -> String {
    let lines: Vec<&str> = sdp.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let Some(media_index) = lines
        .iter()
        .position(|l| l.starts_with("m=audio ") || *l == "m=audio")
    else {
        return sdp.to_string();
    };
    // Already listed in the format list (fields after `m=audio <port> <proto>`)? Idempotent no-op.
    let already_listed = lines[media_index]
        .split(' ')
        .skip(3)
        .any(|field| field.parse::<u8>().ok() == Some(payload_type));
    if already_listed {
        return sdp.to_string();
    }

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 1);
    for (index, line) in lines.iter().enumerate() {
        if index == media_index {
            // Append the CN payload type to the format list, then its rtpmap (RFC 4566 is order-free).
            out.push(format!("{line} {payload_type}"));
            out.push(format!("a=rtpmap:{payload_type} CN/{clock_rate_hz}"));
            continue;
        }
        // Preserve the trailing empty line if the input ended with CRLF.
        if !(index == lines.len() - 1 && line.is_empty()) {
            out.push((*line).to_string());
        }
    }
    let mut rewritten = out.join(CRLF);
    if sdp.ends_with('\n') {
        rewritten.push_str(CRLF);
    }
    rewritten
}

/// Rewrite the session origin (`o=`) unicast-address to the engine's advertised `address`, honouring
/// rtpengine's `replace: [origin]` so the far side never sees the originator's real IP (topology
/// hiding). Replaces the `<addrtype> <unicast-address>` fields (matching `address`'s family) and
/// keeps the username / session-id / session-version. Best-effort: returns the SDP unchanged if it
/// has no well-formed 6-field `o=` line (RFC 4566 §5.2).
#[must_use]
pub fn rewrite_origin(sdp: &str, address: IpAddr) -> String {
    let mut changed = false;
    let lines: Vec<String> = sdp
        .split('\n')
        .map(|line| {
            let stripped = line.trim_end_matches('\r');
            if let Some(body) = stripped.strip_prefix("o=") {
                let fields: Vec<&str> = body.split(' ').collect();
                // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
                if fields.len() == 6 {
                    changed = true;
                    return format!(
                        "o={} {} {} IN {} {}",
                        fields[0],
                        fields[1],
                        fields[2],
                        addrtype(address),
                        address
                    );
                }
            }
            stripped.to_string()
        })
        .collect();
    if changed {
        lines.join(CRLF)
    } else {
        sdp.to_string()
    }
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

    #[test]
    fn parses_the_peers_ice_candidates_and_options() {
        // Until now the engine recognised `a=candidate` only in order to strip it. Pairing needs the
        // parsed list, so an offer's candidates, options, lite posture, and end-of-candidates marker
        // all have to survive the scan (RFC 8839 §5.1/§5.2/§5.6, RFC 8838 §14).
        let sdp = concat!(
            "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n",
            "a=ice-lite\r\n",
            "a=ice-ufrag:PEERUF\r\na=ice-pwd:peerpassword01234567\r\n",
            "a=ice-options:trickle ice2\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ host\r\n",
            "a=candidate:2 1 UDP 1694498815 198.51.100.7 45000 typ srflx raddr 10.0.0.5 rport 45000\r\n",
            "a=end-of-candidates\r\n",
        );
        let info = parse(sdp).expect("parse");
        assert!(info.is_ice());
        assert!(info.ice_lite, "the peer advertised a=ice-lite");
        assert!(info.ice_options.supports_trickle());
        assert!(info.ice_options.has("ice2"));
        assert!(info.end_of_candidates);
        assert_eq!(info.candidates.len(), 2);
        assert_eq!(info.candidates[0].kind, siphon_rtp_ice::CandidateKind::Host);
        assert_eq!(info.candidates[0].priority, 2_130_706_431);
        assert_eq!(
            info.candidates[1].kind,
            siphon_rtp_ice::CandidateKind::ServerReflexive
        );
        assert_eq!(
            info.candidates[1].related,
            Some("10.0.0.5:45000".parse().expect("addr")),
            "the srflx base survives"
        );
    }

    #[test]
    fn an_unusable_candidate_never_costs_the_peers_whole_list() {
        // A browser mixes mDNS candidates in with routable ones, and a broken UA can emit a garbage
        // line. Either must be skipped individually — dropping the rest would leave us unable to pair
        // with a peer we *can* reach.
        let sdp = concat!(
            "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n",
            "a=ice-ufrag:PEERUF\r\na=ice-pwd:peerpassword01234567\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=candidate:1 1 UDP 2130706431 f3b1e2c4-0000-4000-8000-abcdefabcdef.local 30000 typ host\r\n",
            "a=candidate:2 1 UDP not-a-number 203.0.113.7 30001 typ host\r\n",
            "a=candidate:3 1 UDP 2130706430 203.0.113.7 30002 typ host\r\n",
        );
        let info = parse(sdp).expect("parse");
        assert_eq!(
            info.candidates.len(),
            1,
            "only the usable candidate is kept"
        );
        assert_eq!(info.candidates[0].address.port(), 30002);
        assert!(!info.end_of_candidates, "none was signalled");
        assert!(!info.ice_lite);
        assert!(info.ice_options.is_empty());
    }

    #[test]
    fn session_level_ice_options_are_overridden_by_the_media_level() {
        // RFC 8839 §5.4: media-level ICE attributes take precedence over session-level ones — the
        // same rule the credentials already follow.
        let sdp = concat!(
            "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n",
            "a=ice-options:ice2\r\n",
            "a=ice-ufrag:SESSUF\r\na=ice-pwd:sessionpassword012345\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=ice-ufrag:MEDIAUF\r\na=ice-pwd:mediapassword01234567\r\n",
            "a=ice-options:trickle\r\n",
        );
        let info = parse(sdp).expect("parse");
        assert_eq!(info.ice_ufrag.as_deref(), Some("MEDIAUF"));
        assert!(info.ice_options.supports_trickle());
        assert!(
            !info.ice_options.has("ice2"),
            "the media-level list replaces the session-level one"
        );
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

    /// An Opus offer (PT 111, RFC 7587 `opus/48000/2`) at 203.0.113.9, with optional `a=fmtp` /
    /// `a=ptime` / `a=maxptime` attribute lines appended verbatim.
    fn opus_offer(attributes: &str) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n\
             m=audio 5004 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\n{attributes}"
        )
    }

    fn opus_codec(attributes: &str) -> CodecSpec {
        parse(&opus_offer(attributes))
            .expect("parse")
            .primary_codec()
            .expect("opus codec")
    }

    #[test]
    fn opus_fmtp_parses_every_rfc_7587_parameter() {
        // RFC 7587 §6.1, in the order of the §7 example, plus `cbr` (which that example omits).
        let spec = opus_codec(
            "a=fmtp:111 maxplaybackrate=16000;maxaveragebitrate=20000;stereo=1;\
             sprop-stereo=1;cbr=1;useinbandfec=1;usedtx=1\r\n",
        );
        let params = spec.opus_params();
        assert_eq!(params.max_playback_rate_hz, 16_000);
        assert_eq!(params.max_average_bitrate, Some(20_000));
        assert!(params.stereo);
        assert!(params.sprop_stereo);
        assert!(params.cbr);
        assert!(params.use_inband_fec);
        assert!(params.use_dtx);
        // `sprop-stereo=1` is the one that reaches a codec constructor: the peer sends stereo, so
        // the decoder is built 2-channel; the engine's own egress stays mono.
        assert_eq!(spec.decode_channels(), 2);
        assert_eq!(spec.encode_channels(), 1);
    }

    #[test]
    fn opus_fmtp_tolerates_whitespace_case_and_reordering() {
        // RFC 4566 §6: the parameter list is `;`-separated in any order; RFC 7587's own §7 example
        // puts a space after each `;`. Parameter names are matched case-insensitively.
        let params = opus_codec(
            "a=fmtp:111 UseInbandFEC=1; STEREO=0; maxaveragebitrate = 32000 ;usedtx=1\r\n",
        )
        .opus_params();
        assert!(params.use_inband_fec);
        assert!(!params.stereo);
        assert_eq!(params.max_average_bitrate, Some(32_000));
        assert!(params.use_dtx);
    }

    #[test]
    fn opus_fmtp_absent_leaves_the_rfc_7587_defaults() {
        // No fmtp at all: every parameter reads its RFC 7587 §6.1 default, and nothing panics.
        let spec = opus_codec("");
        assert_eq!(spec.opus, None, "nothing was declared");
        assert_eq!(
            spec.opus_params(),
            siphon_rtp_codec::factory::OpusParams::default()
        );
        assert_eq!(spec.decode_channels(), 1, "sprop-stereo defaults to mono");
    }

    #[test]
    fn opus_fmtp_garbage_never_panics_and_keeps_the_defaults() {
        let default = siphon_rtp_codec::factory::OpusParams::default();
        // Non-numeric, empty, negative, overflowing, and value-less parameters are all ignored
        // (an unparseable flag must not be read as "on").
        let params = opus_codec(
            "a=fmtp:111 stereo=yes;usedtx=;maxaveragebitrate=-1;maxplaybackrate=99999999999;\
             useinbandfec;cbr=2\r\n",
        )
        .opus_params();
        assert!(!params.stereo);
        assert!(!params.use_dtx);
        assert!(!params.use_inband_fec);
        assert!(!params.cbr);
        assert_eq!(params.max_average_bitrate, None);
        assert_eq!(params.max_playback_rate_hz, default.max_playback_rate_hz);
        // Out-of-range but parseable values are clamped into the RFC 7587 §6.1 ranges.
        let clamped = opus_codec("a=fmtp:111 maxplaybackrate=4000;maxaveragebitrate=999999\r\n")
            .opus_params();
        assert_eq!(clamped.max_playback_rate_hz, 8000);
        assert_eq!(clamped.max_average_bitrate, Some(510_000));
        // A body with no recognised Opus parameter is not recorded as an all-defaults Opus set.
        let info = parse(&opus_offer("a=fmtp:111 octet-align=1\r\n")).expect("parse");
        assert!(info.opus_params.is_empty());
    }

    #[test]
    fn opus_fmtp_on_another_payload_type_is_not_applied() {
        // The fmtp names PT 96, the Opus stream is PT 111 — the parameters must not leak across.
        let spec = opus_codec("a=fmtp:96 stereo=1;sprop-stereo=1\r\n");
        assert_eq!(spec.opus, None);
        assert_eq!(spec.decode_channels(), 1);
    }

    #[test]
    fn opus_rtpmap_out_of_spec_clock_and_channels_are_corrected() {
        // RFC 7587 §4.1/§7.1 pin the clock at 48000 and §7 pins the rtpmap channel count at 2. A
        // peer signalling otherwise is out of spec — the spec wins (a believed 16 kHz clock would
        // mis-scale every RTP timestamp and the RFC 3550 §6.4.1 jitter estimate).
        let sdp = "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n\
                   m=audio 5004 RTP/AVP 111\r\na=rtpmap:111 opus/16000\r\n";
        let spec = parse(sdp)
            .expect("parse")
            .primary_codec()
            .expect("opus codec");
        assert_eq!(spec.clock_rate_hz, 48_000);
        assert_eq!(spec.channels, 2);
    }

    #[test]
    fn maxptime_caps_the_negotiated_ptime() {
        // RFC 4566 §6 / RFC 7587 §7: `a=maxptime` is the longest packet the peer will accept, so an
        // advertised 60 ms ptime against `maxptime:40` must produce a 40 ms egress frame.
        let capped = opus_codec("a=ptime:60\r\na=maxptime:40\r\n");
        assert_eq!(capped.ptime_ms, 40);
        assert_eq!(capped.opus_params().max_ptime_ms, 40);
        // A maxptime above the ptime is a ceiling, not a target — the ptime stands.
        let uncapped = opus_codec("a=ptime:60\r\na=maxptime:120\r\n");
        assert_eq!(uncapped.ptime_ms, 60);
        assert_eq!(uncapped.opus_params().max_ptime_ms, 120);
        // The `a=maxptime` attribute wins over an fmtp copy (RFC 7587 §7 maps it to the attribute).
        let attribute_wins = opus_codec("a=fmtp:111 maxptime=120;stereo=0\r\na=maxptime:40\r\n");
        assert_eq!(attribute_wins.opus_params().max_ptime_ms, 40);
        assert_eq!(
            attribute_wins.ptime_ms, 20,
            "no a=ptime ⇒ the 20 ms default"
        );
        // It applies to every codec, not just Opus (RFC 4566 §6 is codec-independent).
        let g711 = "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n\
                    m=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=ptime:40\r\n\
                    a=maxptime:20\r\n";
        assert_eq!(
            parse(g711)
                .expect("parse")
                .primary_codec()
                .expect("pcmu")
                .ptime_ms,
            20
        );
    }

    #[test]
    fn opus_ptime_60_survives_negotiation() {
        // The 60 ms case the media path's frame ceiling used to truncate: 48 kHz × 60 ms = 2880
        // samples. It must reach the spec intact, since the egress frame size is derived from it.
        let spec = opus_codec("a=ptime:60\r\n");
        assert_eq!(spec.ptime_ms, 60);
        assert_eq!(spec.clock_rate_hz, 48_000);
    }

    #[test]
    fn opus_rtpmap_always_carries_the_channel_count() {
        // RFC 7587 §7: `a=rtpmap:<pt> opus/48000/2` is mandatory, mono included — `opus/48000` is
        // not a legal line. Assert the exact bytes emitted, from both emitters.
        let opus = CodecSpec::new(111, "opus", 48_000, 2, 20);
        assert_eq!(rtpmap_line(&opus), "a=rtpmap:111 OPUS/48000/2");
        // …even when the spec was built from a peer's non-conformant mono rtpmap.
        let from_mono = CodecSpec::new(111, "opus", 48_000, 1, 20);
        assert_eq!(rtpmap_line(&from_mono), "a=rtpmap:111 OPUS/48000/2");
        // Mono telephony still omits the suffix (RFC 4566 §6 defaults it to 1).
        assert_eq!(
            rtpmap_line(&CodecSpec::new(0, "PCMU", 8000, 1, 20)),
            "a=rtpmap:0 PCMU/8000"
        );

        // `apply_codec_policy`'s added-codec rtpmap goes through the same emitter.
        let sdp = "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n\
                   m=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let rewritten = rewrite_codec_list(sdp, &[], std::slice::from_ref(&opus));
        assert!(
            rewritten.contains("a=rtpmap:111 OPUS/48000/2"),
            "added Opus codec must carry /2: {rewritten}"
        );
        assert!(
            !rewritten.contains("a=rtpmap:111 OPUS/48000\r"),
            "the illegal bare form must not be emitted: {rewritten}"
        );
    }

    #[test]
    fn opus_answer_declares_the_engine_mono_posture() {
        // RFC 7587 §6.1/§7.1: the fmtp is declarative and unidirectional, so the answer states the
        // engine's own posture — mono in, mono out — rather than echoing the peer's.
        let opus = CodecSpec::new(111, "opus", 48_000, 2, 20);
        assert_eq!(
            egress_fmtp_line(&opus).as_deref(),
            Some("a=fmtp:111 stereo=0;sprop-stereo=0")
        );
        assert_eq!(
            egress_maxptime_line(&opus).as_deref(),
            Some("a=maxptime:120")
        );
        // The peer's own parameters do not change what the engine declares about itself.
        let with_peer_params = opus.clone().with_opus_params(Some(OpusParams {
            stereo: true,
            sprop_stereo: true,
            use_dtx: true,
            ..OpusParams::default()
        }));
        assert_eq!(
            egress_fmtp_line(&with_peer_params).as_deref(),
            Some("a=fmtp:111 stereo=0;sprop-stereo=0")
        );
        // Non-Opus codecs are untouched: AMR-WB keeps its own line, G.711 has none, and neither
        // advertises a maxptime (their frame duration is fixed).
        let g711 = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        assert_eq!(egress_fmtp_line(&g711), None);
        assert_eq!(egress_maxptime_line(&g711), None);
        let amr = CodecSpec::new(96, "AMR-WB", 16_000, 1, 20).with_encode_mode(Some(2));
        assert_eq!(
            egress_fmtp_line(&amr).as_deref(),
            Some("a=fmtp:96 octet-align=1;mode-set=2")
        );
        assert_eq!(egress_maxptime_line(&amr), None);
    }

    #[test]
    fn force_answer_codec_emits_the_full_opus_attribute_set() {
        // The whole answer presentation for an Opus leg, byte for byte: the mandatory `/2` rtpmap
        // (RFC 7587 §7), the engine's declarative fmtp, our own ptime, and our maxptime ceiling.
        let answer =
            "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n\
             m=audio 5004 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=ptime:20\r\na=maxptime:40\r\n";
        let opus = CodecSpec::new(111, "opus", 48_000, 2, 60);
        let forced = force_answer_codec(answer, &opus, None);
        assert!(forced.contains("m=audio 5004 RTP/AVP 111\r\n"), "{forced}");
        assert!(forced.contains("a=rtpmap:111 OPUS/48000/2\r\n"), "{forced}");
        assert!(
            forced.contains("a=fmtp:111 stereo=0;sprop-stereo=0\r\n"),
            "{forced}"
        );
        assert!(forced.contains("a=ptime:60\r\n"), "{forced}");
        assert!(forced.contains("a=maxptime:120\r\n"), "{forced}");
        // The far side's own ptime/maxptime are dropped, not leaked.
        assert!(!forced.contains("a=ptime:20\r\n"), "{forced}");
        assert!(!forced.contains("a=maxptime:40\r\n"), "{forced}");
        assert!(!forced.contains("PCMA"), "{forced}");
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
        let engine = EngineMedia::new(
            "127.0.0.1:40000".parse().unwrap(),
            Some("127.0.0.1:40001".parse().unwrap()),
        );
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, None).expect("rewrite");
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
        let engine = EngineMedia::new(
            "127.0.0.1:40000".parse().unwrap(),
            Some("127.0.0.1:40001".parse().unwrap()),
        );
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, None).expect("rewrite");
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
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, None).expect("rewrite");
        assert!(
            !result.sdp.contains("a=rtcp:"),
            "explicit a=rtcp dropped under mux"
        );
        assert!(result.sdp.contains("a=rtcp-mux"), "mux flag preserved");
    }

    #[test]
    fn mux_override_true_forces_rtcp_mux_when_the_offer_had_none() {
        // RFC 5761: `mux_override = Some(true)` emits `a=rtcp-mux` even though the offer carried none.
        let sdp = offer("203.0.113.7", 49170); // no a=rtcp-mux
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, Some(true)).expect("rewrite");
        assert_eq!(
            result.sdp.matches("a=rtcp-mux").count(),
            1,
            "exactly one a=rtcp-mux emitted: {}",
            result.sdp
        );
        assert!(parse(&result.sdp).expect("reparse").rtcp_mux);
    }

    #[test]
    fn mux_override_true_does_not_duplicate_an_existing_mux_line() {
        // The offer already advertised mux; forcing mux must not produce a duplicate `a=rtcp-mux`.
        let mut sdp = offer("203.0.113.7", 49170);
        sdp.push_str("a=rtcp-mux\r\n");
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, Some(true)).expect("rewrite");
        assert_eq!(
            result.sdp.matches("a=rtcp-mux").count(),
            1,
            "no duplicate a=rtcp-mux: {}",
            result.sdp
        );
    }

    #[test]
    fn mux_override_false_strips_rtcp_mux_and_advertises_the_rtcp_port() {
        // RFC 5761: `mux_override = Some(false)` demuxes — the offered `a=rtcp-mux` is dropped and the
        // engine's separate RTCP port is advertised.
        let mut sdp = offer("203.0.113.7", 49170);
        sdp.push_str("a=rtcp-mux\r\n");
        let engine = EngineMedia::new(
            "127.0.0.1:40000".parse().unwrap(),
            Some("127.0.0.1:40001".parse().unwrap()),
        );
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, Some(false)).expect("rewrite");
        assert!(
            !result.sdp.contains("a=rtcp-mux"),
            "a=rtcp-mux stripped under demux: {}",
            result.sdp
        );
        assert!(result.sdp.contains("a=rtcp:40001"), "{}", result.sdp);
        let reparsed = parse(&result.sdp).expect("reparse");
        assert!(!reparsed.rtcp_mux);
    }

    #[test]
    fn mux_override_none_mirrors_the_offer() {
        // `None` is the default: the offer's `a=rtcp-mux` intent passes through untouched.
        let mut muxed = offer("203.0.113.7", 49170);
        muxed.push_str("a=rtcp-mux\r\n");
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        assert!(rewrite(&muxed, engine, IceRewrite::Keep, None, None)
            .expect("rewrite")
            .sdp
            .contains("a=rtcp-mux"));
        // A non-muxed offer stays non-muxed under `None`.
        let plain = offer("203.0.113.7", 49170);
        let engine = EngineMedia::new(
            "127.0.0.1:40000".parse().unwrap(),
            Some("127.0.0.1:40001".parse().unwrap()),
        );
        assert!(!rewrite(&plain, engine, IceRewrite::Keep, None, None)
            .expect("rewrite")
            .sdp
            .contains("a=rtcp-mux"));
    }

    #[test]
    fn media_level_connection_overrides_session_level() {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP4 198.51.100.9\r\n";
        let engine = EngineMedia::new("127.0.0.1:41000".parse().unwrap(), None);
        let result = rewrite(sdp, engine, IceRewrite::Keep, None, None).expect("rewrite");
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
        let engine = EngineMedia::new(
            "[::1]:40000".parse().unwrap(),
            Some("[::1]:40001".parse().unwrap()),
        );
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, None).expect("rewrite v6");
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
        let engine = EngineMedia::new("[::1]:40000".parse().unwrap(), None);
        let candidates = gathered_host_candidates("[::1]:40000");
        let advert = IceAdvertisement {
            ufrag: "ENGUF",
            pwd: "engpassword01234567",
            candidates: &candidates,
        };
        let result = rewrite(sdp, engine, IceRewrite::Reoriginate(advert), None, None)
            .expect("rewrite v6 ice");
        assert!(result.sdp.contains("c=IN IP6 ::1"));
        let emitted = result
            .sdp
            .lines()
            .find(|line| line.starts_with("a=candidate:"))
            .expect("a candidate line");
        assert!(
            emitted.contains(" ::1 40000 typ host"),
            "v6 host candidate as a bare literal: {emitted}"
        );
        assert_eq!(
            Candidate::parse(emitted).expect("parses").address,
            "[::1]:40000".parse::<SocketAddr>().expect("addr")
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
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, None).expect("rewrite v4");
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
            let engine = EngineMedia::new("192.0.2.1:10000".parse().expect("addr"), None);
            let _ = rewrite(&text, engine, IceRewrite::Keep, None, None);
            let _ = force_answer_codec(&text, &CodecSpec::new(0, "PCMU", 8000, 1, 20), Some(96));
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

    /// The candidate set a host-only gather produces for `address` — what the engine now hands the
    /// rewriter instead of a hardcoded line.
    fn gathered_host_candidates(address: &str) -> Vec<Candidate> {
        let address: SocketAddr = address.parse().expect("addr");
        let mut gatherer =
            siphon_rtp_ice::Gatherer::new(siphon_rtp_ice::GatherConfig::host_only(address), 0);
        let _ = gatherer.poll(0);
        gatherer.candidates().to_vec()
    }

    #[test]
    fn rewrite_re_originates_ice_as_ice_lite() {
        let sdp = ice_offer("203.0.113.7", 49170);
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let candidates = gathered_host_candidates("127.0.0.1:40000");
        let advert = IceAdvertisement {
            ufrag: "ENGUF",
            pwd: "engpassword01234567",
            candidates: &candidates,
        };
        let result =
            rewrite(&sdp, engine, IceRewrite::Reoriginate(advert), None, None).expect("rewrite");

        // Our credentials and posture are advertised.
        assert!(result.sdp.contains("a=ice-lite"));
        assert!(result.sdp.contains("a=ice-ufrag:ENGUF"));
        assert!(result.sdp.contains("a=ice-pwd:engpassword01234567"));
        // The host candidate is emitted from the gathered set. Its foundation is now derived per
        // RFC 8445 §5.1.1.3 (an arbitrary string that tracks type/base/protocol/server) rather than
        // the literal `1` every candidate used to carry, so assert the fields the spec constrains.
        let emitted = result
            .sdp
            .lines()
            .find(|line| line.starts_with("a=candidate:"))
            .expect("a candidate line");
        let candidate = Candidate::parse(emitted).expect("our own candidate parses");
        assert_eq!(candidate.component, 1);
        assert_eq!(candidate.kind, siphon_rtp_ice::CandidateKind::Host);
        assert_eq!(candidate.priority, 2_130_706_431);
        assert_eq!(candidate.address, "127.0.0.1:40000".parse().expect("addr"));
        // Gathering is complete before the SDP is written, so we say so (RFC 8838 §14).
        assert!(result.sdp.contains("a=end-of-candidates"));
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
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, None).expect("rewrite");
        assert!(!result.sdp.contains("a=ice-lite"));
        assert!(!result.sdp.contains("a=ice-ufrag"));
    }

    #[test]
    fn rewrite_keep_passes_peer_ice_through() {
        // `IceRewrite::Keep` (a plain relay) forwards the peer's ICE attributes untouched — it is the
        // decoupled counterpart of `Strip`, which removes them.
        let sdp = ice_offer("203.0.113.7", 49170);
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(&sdp, engine, IceRewrite::Keep, None, None).expect("rewrite");
        assert!(result.sdp.contains("a=ice-ufrag:PEERUF"));
        assert!(result.sdp.contains("a=ice-pwd:peerpassword01234567"));
        assert!(result.sdp.contains("typ host"), "peer candidate preserved");
        assert!(
            !result.sdp.contains("a=ice-lite"),
            "we add nothing of our own"
        );
    }

    #[test]
    fn rewrite_strip_removes_peer_ice_without_re_originating() {
        // rtpengine `ICE=remove` (RFC 8839 §5): strip the offerer's ICE lines and advertise none of
        // our own — the leg falls back to the signalled media address.
        let sdp = ice_offer("203.0.113.7", 49170);
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(&sdp, engine, IceRewrite::Strip, None, None).expect("rewrite");
        // The peer's ICE attributes are gone.
        assert!(!result.sdp.contains("a=ice-ufrag"), "{}", result.sdp);
        assert!(!result.sdp.contains("a=ice-pwd"), "{}", result.sdp);
        assert!(!result.sdp.contains("a=candidate"), "{}", result.sdp);
        assert!(!result.sdp.contains("PEERUF"));
        // And, unlike `Reoriginate`, we add nothing of our own.
        assert!(!result.sdp.contains("a=ice-lite"), "no ICE re-originated");
        // The parsed media still records what the peer offered.
        assert_eq!(result.media.ice_ufrag.as_deref(), Some("PEERUF"));
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

    /// A WebRTC-style DTLS-SRTP (`UDP/TLS/RTP/SAVPF`) offer: fingerprint + setup + ICE, no `a=crypto`.
    fn dtls_offer(addr: &str, port: u16) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {addr}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 0 8\r\na=rtpmap:0 PCMU/8000\r\n\
             a=setup:actpass\r\n\
             a=fingerprint:sha-256 \
             AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n\
             a=ice-ufrag:PEERUF\r\na=ice-pwd:peerpassword01234567\r\n"
        )
    }

    #[test]
    fn parse_detects_dtls_srtp_offer() {
        let info = parse(&dtls_offer("203.0.113.7", 49170)).expect("parse");
        assert!(info.dtls, "UDP/TLS/RTP/SAVPF is a DTLS-keyed profile");
        assert!(info.secure, "and still a secure (SAVP) profile");
        assert!(info.crypto.is_empty(), "DTLS-SRTP carries no SDES a=crypto");
        assert_eq!(info.setup, Some(Setup::Actpass));
        let fingerprint = info.fingerprint.expect("fingerprint present");
        assert_eq!(fingerprint.hash_function, "sha-256");
        assert_eq!(fingerprint.bytes.len(), 32, "SHA-256 is 32 bytes");
        assert_eq!(fingerprint.bytes[0], 0xAB);
    }

    #[test]
    fn sdes_and_plain_offers_carry_no_dtls_state() {
        let sdes = parse(&savp_offer("203.0.113.7", 49170)).expect("parse");
        assert!(!sdes.dtls, "RTP/SAVP is SDES-keyed, not DTLS");
        assert!(sdes.fingerprint.is_none());
        assert!(sdes.setup.is_none());
        let plain = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert!(!plain.dtls);
        assert!(plain.fingerprint.is_none());
    }

    #[test]
    fn fingerprint_round_trips_through_parse_and_format() {
        let value = "fingerprint:sha-256 AB:CD:EF:01:23:45:67:89";
        let parsed = Fingerprint::parse(value).expect("parse");
        assert_eq!(parsed.hash_function, "sha-256");
        assert_eq!(
            parsed.bytes,
            vec![0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]
        );
        assert_eq!(parsed.to_attribute_value(), value);
    }

    #[test]
    fn fingerprint_normalises_case() {
        // A peer may send an uppercase algorithm token and lowercase hex; normalise for comparison.
        let parsed = Fingerprint::parse("fingerprint:SHA-256 ab:cd:ef").expect("parse");
        assert_eq!(parsed.hash_function, "sha-256");
        assert_eq!(parsed.bytes, vec![0xAB, 0xCD, 0xEF]);
        assert_eq!(parsed.to_attribute_value(), "fingerprint:sha-256 AB:CD:EF");
    }

    #[test]
    fn fingerprint_rejects_malformed() {
        assert!(
            Fingerprint::parse("fingerprint:sha-256 ").is_none(),
            "no value"
        );
        assert!(
            Fingerprint::parse("fingerprint:sha-256 GG:HH").is_none(),
            "non-hex octet"
        );
        assert!(
            Fingerprint::parse("fingerprint:sha-256").is_none(),
            "no value field"
        );
        assert!(
            Fingerprint::parse("crypto:1 whatever").is_none(),
            "wrong attribute"
        );
    }

    #[test]
    fn setup_parses_all_roles_and_rejects_unknown() {
        assert_eq!(Setup::parse("setup:active"), Some(Setup::Active));
        assert_eq!(Setup::parse("setup:passive"), Some(Setup::Passive));
        assert_eq!(Setup::parse("setup:actpass"), Some(Setup::Actpass));
        assert_eq!(Setup::parse("setup:holdconn"), Some(Setup::Holdconn));
        assert_eq!(Setup::parse("setup:bogus"), None);
        assert_eq!(Setup::parse("nonsense"), None);
        assert_eq!(Setup::Active.token(), "active");
        assert_eq!(Setup::Actpass.token(), "actpass");
    }

    #[test]
    fn dtls_fingerprint_and_setup_may_be_session_level() {
        // RFC 8122 / RFC 4145 permit session-level a=fingerprint / a=setup; the parser must catch them.
        let sdp = "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n\
             a=setup:passive\r\na=fingerprint:sha-1 01:02:03:04\r\n\
             m=audio 49170 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let info = parse(sdp).expect("parse");
        assert_eq!(info.setup, Some(Setup::Passive));
        assert_eq!(
            info.fingerprint.expect("session fingerprint").hash_function,
            "sha-1"
        );
    }

    #[test]
    fn rewrite_dtls_advertises_fingerprint_setup_and_savpf() {
        // Answer a DTLS-SRTP leg: force `UDP/TLS/RTP/SAVPF`, advertise the engine's fingerprint + role,
        // and re-originate (strip) the peer's `a=fingerprint`/`a=setup`.
        let sdp = dtls_offer("203.0.113.7", 49170);
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let fingerprint = Fingerprint {
            hash_function: "sha-256".to_string(),
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let result = rewrite(
            &sdp,
            engine,
            IceRewrite::Keep,
            Some(SecurityAdvertisement::Dtls {
                fingerprint,
                setup: Setup::Passive,
            }),
            None,
        )
        .expect("rewrite");
        assert!(
            result.sdp.contains("m=audio 40000 UDP/TLS/RTP/SAVPF"),
            "{}",
            result.sdp
        );
        assert!(
            result.sdp.contains("a=fingerprint:sha-256 DE:AD:BE:EF"),
            "{}",
            result.sdp
        );
        assert!(result.sdp.contains("a=setup:passive"));
        // The peer's own keying is re-originated, not forwarded.
        assert!(
            !result.sdp.contains("AB:CD:EF:01"),
            "peer fingerprint must be stripped"
        );
        assert!(
            !result.sdp.contains("a=setup:actpass"),
            "peer setup must be stripped"
        );
    }

    #[test]
    fn rewrite_secure_advertises_savp_and_our_crypto() {
        use siphon_rtp_srtp::sdes::CryptoSuite;
        // Bridge an AVP offer up to SAVP: force the transport and advertise the engine's key.
        let sdp = offer("203.0.113.7", 49170);
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let ours = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let result = rewrite(
            &sdp,
            engine,
            IceRewrite::Keep,
            Some(SecurityAdvertisement::Secure(ours)),
            None,
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
        let engine = EngineMedia::new("127.0.0.1:40000".parse().unwrap(), None);
        let result = rewrite(
            &sdp,
            engine,
            IceRewrite::Keep,
            Some(SecurityAdvertisement::Plain),
            None,
        )
        .expect("rewrite");
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

    #[test]
    fn codec_list_strips_a_named_codec_and_its_rtpmap() {
        // m=audio 5004 RTP/AVP 0 8 96 (PCMU/PCMA/telephone-event); codec-strip-PCMA drops PT 8.
        let out = rewrite_codec_list(&offer("203.0.113.9", 5004), &["PCMA".to_string()], &[]);
        assert!(
            out.contains("m=audio 5004 RTP/AVP 0 96"),
            "PT 8 removed from m= line: {out}"
        );
        assert!(!out.contains("a=rtpmap:8 PCMA/8000"), "PCMA rtpmap removed");
        assert!(out.contains("a=rtpmap:0 PCMU/8000"), "PCMU kept");
        assert!(
            out.contains("a=rtpmap:96 telephone-event/8000"),
            "telephone-event kept"
        );
    }

    #[test]
    fn codec_list_adds_a_transcode_codec_with_rtpmap() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n\
                   t=0 0\r\nm=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let g722 = CodecSpec::new(9, "G722", 8000, 1, 20);
        let out = rewrite_codec_list(sdp, &[], std::slice::from_ref(&g722));
        assert!(
            out.contains("m=audio 5004 RTP/AVP 0 9"),
            "G722 PT appended: {out}"
        );
        assert!(out.contains("a=rtpmap:9 G722/8000"), "G722 rtpmap added");
    }

    #[test]
    fn codec_list_strips_a_static_codec_without_rtpmap() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n\
                   t=0 0\r\nm=audio 5004 RTP/AVP 0 8\r\n";
        let out = rewrite_codec_list(sdp, &["PCMA".to_string()], &[]);
        assert!(
            out.contains("m=audio 5004 RTP/AVP 0"),
            "PT 8 stripped via the static table (no rtpmap): {out}"
        );
        assert!(
            !out.contains(" 8\r\n") && !out.ends_with(" 8"),
            "no dangling PT 8"
        );
    }

    #[test]
    fn codec_list_never_empties_the_codec_list() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n\
                   t=0 0\r\nm=audio 5004 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n";
        let out = rewrite_codec_list(sdp, &["PCMU".to_string(), "PCMA".to_string()], &[]);
        assert!(
            out.contains("m=audio 5004 RTP/AVP 0"),
            "the first codec is kept rather than emptying the list: {out}"
        );
        assert!(out.contains("a=rtpmap:0 PCMU/8000"));
    }

    #[test]
    fn codec_list_is_a_noop_when_nothing_changes() {
        let sdp = offer("203.0.113.9", 5004);
        assert_eq!(
            rewrite_codec_list(&sdp, &[], &[]),
            sdp,
            "no flags → identity"
        );
        assert_eq!(
            rewrite_codec_list(&sdp, &["OPUS".to_string()], &[]),
            sdp,
            "stripping an absent codec → identity"
        );
    }

    #[test]
    fn codec_policy_mask_removes_from_the_far_offer_like_strip() {
        // m=audio 5004 RTP/AVP 0 8 96; masking PCMA drops PT 8 from the offer to B — the same SDP
        // edit as strip (the two differ only in near-side transcodability, which this engine keeps).
        let policy = CodecPolicy {
            remove: vec!["PCMA".to_string()],
            ..CodecPolicy::default()
        };
        let out = apply_codec_policy(&offer("203.0.113.9", 5004), &policy);
        assert!(out.contains("m=audio 5004 RTP/AVP 0 96"), "{out}");
        assert!(!out.contains("a=rtpmap:8 PCMA/8000"), "PCMA rtpmap removed");
        assert_eq!(
            out,
            rewrite_codec_list(&offer("203.0.113.9", 5004), &["PCMA".to_string()], &[]),
            "mask == strip at the SDP layer"
        );
    }

    #[test]
    fn codec_policy_except_keeps_a_codec_from_remove_all() {
        // strip-all with an `except` keep-list: only PCMU (+ telephone-event) survive.
        let policy = CodecPolicy {
            remove_all: true,
            keep: vec!["PCMU".to_string()],
            ..CodecPolicy::default()
        };
        let out = apply_codec_policy(&offer("203.0.113.9", 5004), &policy);
        assert!(
            out.contains("m=audio 5004 RTP/AVP 0 96"),
            "PCMU + telephone-event kept: {out}"
        );
        assert!(!out.contains("PCMA"), "PCMA swept by remove_all: {out}");
        assert!(
            out.contains("a=rtpmap:96 telephone-event/8000"),
            "telephone-event survives remove_all"
        );
    }

    #[test]
    fn codec_policy_remove_all_keeps_the_first_audio_codec_without_a_keep_list() {
        // strip-all and nothing excepted: the never-empty guard keeps the first audio codec.
        let policy = CodecPolicy {
            remove_all: true,
            ..CodecPolicy::default()
        };
        let out = apply_codec_policy(&offer("203.0.113.9", 5004), &policy);
        assert!(
            out.contains("m=audio 5004 RTP/AVP 0 96"),
            "first audio codec (PCMU) kept: {out}"
        );
    }

    #[test]
    fn codec_policy_offer_whitelists_and_reorders() {
        // `offer` PCMA then PCMU: only those (PCMA preferred), telephone-event kept and last.
        let policy = CodecPolicy {
            order: vec!["PCMA".to_string(), "PCMU".to_string()],
            ..CodecPolicy::default()
        };
        let out = apply_codec_policy(&offer("203.0.113.9", 5004), &policy);
        let media = out
            .lines()
            .find(|line| line.starts_with("m=audio"))
            .expect("m=audio");
        assert_eq!(
            media, "m=audio 5004 RTP/AVP 8 0 96",
            "reordered to PCMA, PCMU with telephone-event last: {media}"
        );
    }

    #[test]
    fn codec_policy_offer_drops_a_codec_absent_from_the_whitelist() {
        // `offer` PCMU only: PCMA is not whitelisted, so it is dropped from the far offer.
        let policy = CodecPolicy {
            order: vec!["PCMU".to_string()],
            ..CodecPolicy::default()
        };
        let out = apply_codec_policy(&offer("203.0.113.9", 5004), &policy);
        assert!(out.contains("m=audio 5004 RTP/AVP 0 96"), "{out}");
        assert!(!out.contains("PCMA"), "non-whitelisted PCMA dropped: {out}");
    }

    /// A far-side answer SDP the engine has already transport-rewritten toward A, carrying B's
    /// codec (PCMA) plus telephone-event — what A would wrongly see relayed on a transcoded call.
    fn far_answer(codecs: &str) -> String {
        format!(
            "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio 40000 RTP/AVP {codecs}\r\na=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:96 telephone-event/8000\r\na=fmtp:96 0-15\r\n"
        )
    }

    #[test]
    fn force_answer_codec_presents_the_legs_own_codec_not_the_far_sides() {
        // A offered PCMU (PT 0); the engine transcodes PCMA↔PCMU. The answer to A must advertise
        // PCMU + telephone-event, never B's PCMA.
        let pcmu = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        let out = force_answer_codec(&far_answer("8 96"), &pcmu, Some(96));
        assert!(
            out.contains("m=audio 40000 RTP/AVP 0 96"),
            "m= collapses to PCMU + telephone-event: {out}"
        );
        assert!(out.contains("a=rtpmap:0 PCMU/8000"), "PCMU rtpmap emitted");
        assert!(
            out.contains("a=rtpmap:96 telephone-event/8000"),
            "telephone-event preserved"
        );
        assert!(!out.contains("PCMA"), "B's PCMA no longer leaked: {out}");
        // The result reparses to the leg's own primary codec.
        assert_eq!(
            parse(&out)
                .expect("reparse")
                .primary_codec()
                .expect("codec")
                .encoding_name,
            "PCMU"
        );
    }

    #[test]
    fn force_answer_codec_amr_wb_advertises_octet_align_and_mode_set() {
        // The engine encodes octet-aligned AMR-WB at the mode-set-resolved mode; the answer must say so.
        let amr = CodecSpec::new(96, "AMR-WB", 16000, 1, 20).with_encode_mode(Some(1));
        let far = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                   m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let out = force_answer_codec(far, &amr, None);
        assert!(out.contains("m=audio 40000 RTP/AVP 96"), "{out}");
        assert!(out.contains("a=rtpmap:96 AMR-WB/16000"));
        assert!(
            out.contains("a=fmtp:96 octet-align=1;mode-set=1"),
            "octet-align + negotiated mode advertised: {out}"
        );
        assert!(!out.contains("PCMU"), "B's PCMU dropped: {out}");
    }

    #[test]
    fn force_answer_codec_advertises_the_legs_effective_ptime_not_the_far_sides() {
        // B's answer carries a=ptime:20; the engine transcodes to A at a 40 ms override, so the answer
        // to A must advertise a=ptime:40 (what A will receive), and B's a=ptime:20 must be dropped.
        let far = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                   m=audio 40000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=ptime:20\r\n";
        let pcmu_40ms = CodecSpec::new(0, "PCMU", 8000, 1, 40);
        let out = force_answer_codec(far, &pcmu_40ms, None);
        assert!(
            out.contains("a=ptime:40"),
            "engine's effective 40 ms ptime advertised: {out}"
        );
        assert!(
            !out.contains("a=ptime:20"),
            "far side's 20 ms ptime dropped: {out}"
        );
        assert_eq!(
            parse(&out).expect("reparse").ptime_ms,
            40,
            "the answer reparses to the overridden ptime"
        );
    }

    #[test]
    fn force_answer_codec_without_telephone_event_keeps_only_the_audio_codec() {
        let pcmu = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        let out = force_answer_codec(&far_answer("8 96"), &pcmu, None);
        assert!(out.contains("m=audio 40000 RTP/AVP 0"), "{out}");
        assert!(
            !out.contains("telephone-event"),
            "no telephone-event when the leg negotiated none: {out}"
        );
    }

    #[test]
    fn force_answer_codec_is_identity_without_audio_media() {
        let sdp = "v=0\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=video 5000 RTP/AVP 96\r\n";
        let pcmu = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        assert_eq!(force_answer_codec(sdp, &pcmu, Some(96)), sdp);
    }

    #[test]
    fn comfort_noise_payload_type_finds_static_pt13() {
        // A bare offer of static PT 13 (no rtpmap) is CN/8000 (RFC 3551 §6).
        let sdp = "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n\
                   m=audio 40000 RTP/AVP 0 13 101\r\na=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:101 telephone-event/8000\r\n";
        let info = parse(sdp).expect("parse");
        assert_eq!(info.comfort_noise_payload_type(8000), Some(13));
        // CN is clock-rate specific: no 16 kHz CN was offered.
        assert_eq!(info.comfort_noise_payload_type(16000), None);
    }

    #[test]
    fn comfort_noise_payload_type_finds_dynamic_cn_rtpmap_at_matching_clock() {
        // A dynamic CN payload type at 16 kHz (for a wideband leg) is matched only at 16 kHz.
        let sdp = "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n\
                   m=audio 40000 RTP/AVP 96 100\r\na=rtpmap:96 AMR-WB/16000\r\n\
                   a=rtpmap:100 CN/16000\r\n";
        let info = parse(sdp).expect("parse");
        assert_eq!(info.comfort_noise_payload_type(16000), Some(100));
        assert_eq!(info.comfort_noise_payload_type(8000), None);
    }

    #[test]
    fn comfort_noise_payload_type_absent_when_not_offered() {
        let info = parse(&offer("203.0.113.7", 49170)).expect("parse");
        assert_eq!(info.comfort_noise_payload_type(8000), None);
    }

    #[test]
    fn add_comfort_noise_lists_pt_and_rtpmap() {
        let answer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                      m=audio 40000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
                      a=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n";
        let out = add_comfort_noise(answer, 13, 8000);
        assert!(
            out.contains("m=audio 40000 RTP/AVP 0 101 13"),
            "CN appended to the format list: {out}"
        );
        assert!(
            out.contains("a=rtpmap:13 CN/8000"),
            "CN rtpmap emitted: {out}"
        );
        // It reparses cleanly and still resolves PCMU as the primary audio codec (CN is not audio).
        let info = parse(&out).expect("reparse");
        assert_eq!(info.primary_codec().expect("codec").encoding_name, "PCMU");
        assert_eq!(info.comfort_noise_payload_type(8000), Some(13));
    }

    #[test]
    fn add_comfort_noise_is_idempotent_and_identity_without_audio() {
        let answer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                      m=audio 40000 RTP/AVP 0 13\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:13 CN/8000\r\n";
        // Already listed ⇒ unchanged.
        assert_eq!(add_comfort_noise(answer, 13, 8000), answer);
        // No m=audio ⇒ unchanged.
        let video = "v=0\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=video 5000 RTP/AVP 96\r\n";
        assert_eq!(add_comfort_noise(video, 13, 8000), video);
    }

    #[test]
    fn origin_is_rewritten_to_the_engine_address() {
        let sdp = "v=0\r\no=alice 2890 2890 IN IP4 10.0.0.7\r\ns=-\r\n\
                   c=IN IP4 10.0.0.7\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
        let engine_ip: IpAddr = "203.0.113.5".parse().unwrap();
        let out = rewrite_origin(sdp, engine_ip);
        assert!(
            out.contains("o=alice 2890 2890 IN IP4 203.0.113.5"),
            "o= unicast-address rewritten (session-id/version kept): {out}"
        );
        assert!(
            out.contains("c=IN IP4 10.0.0.7"),
            "c= is left to rewrite() — rewrite_origin only touches o="
        );
    }

    #[test]
    fn origin_rewrite_switches_addrtype_for_an_ipv6_engine() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 10.0.0.7\r\ns=-\r\nt=0 0\r\n";
        let out = rewrite_origin(sdp, "2001:db8::1".parse().unwrap());
        assert!(
            out.contains("o=- 1 1 IN IP6 2001:db8::1"),
            "addrtype switched to IP6 for a v6 engine: {out}"
        );
    }

    #[test]
    fn origin_rewrite_is_a_noop_without_a_wellformed_o_line() {
        let sdp = "v=0\r\ns=-\r\nt=0 0\r\n";
        assert_eq!(rewrite_origin(sdp, "203.0.113.5".parse().unwrap()), sdp);
    }
}
