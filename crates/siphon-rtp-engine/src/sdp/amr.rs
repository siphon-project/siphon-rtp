//! AMR and AMR-WB in SDP: reading the RFC 4867 `a=fmtp` parameters of an offer or an answer, and
//! writing the ones the engine answers and offers with.
//!
//! The rules are RFC 4867 §8.3.1, which sorts the parameters into three kinds:
//!
//! - **The payload format configuration**: `octet-align`, `crc`, `robust-sorting`, `interleaving`
//!   and the channel count. "An SDP answerer MUST include, in the SDP answer for a payload type,
//!   the following parameters unmodified from the SDP offer (unless it removes the payload type)",
//!   and both sides "MUST generate AMR or AMR-WB packets as described by these parameters". The
//!   engine implements the two basic formats, one channel; a payload type that asks for more is
//!   not selected (`CodecSpec::amr_unsupported`), so the answer falls to the next one.
//! - **`mode-set`**: "If a mode set was supplied in the offer, the answerer SHALL return the
//!   mode-set unmodified or reject the payload type", and it "applies to media both to be received
//!   and sent".
//! - **Declarative ones**, each side stating its own: `mode-change-period` and
//!   `mode-change-neighbor` are what a party requires of the stream it *receives*, so the engine
//!   obeys the peer's when it sends and declares none of its own (it accepts a mode change on any
//!   frame, to any mode); `mode-change-capability` is what a party can do when it sends, and the
//!   engine can restrict itself to every second frame, so it says 2.
//!
//! "Any unknown parameter in an offer SHALL be removed in the answer."

use std::sync::atomic::{AtomicU8, Ordering};

use siphon_rtp_codec::factory::{AmrParams, CodecSpec};

use super::split_fmtp;

/// The longest packet the engine accepts for AMR, as `a=maxptime`: twelve frames. 3GPP TS 26.114
/// §7.5.2.1.2.3: a client "shall accept any number of frames per RTP packet up to the maximum
/// limit of 12 speech frames per RTP packet", and Table 6.4 has the answer carry `maxptime` 240.
pub(super) const MAXPTIME_MS: u16 = 240;

/// The RFC 4867 parameters of one `a=fmtp` line: the mode set, and everything else.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmrFmtp {
    /// `mode-set`, in the order the line listed it; empty when absent.
    pub mode_set: Vec<u8>,
    /// Every other parameter, as written.
    pub params: AmrParams,
}

/// The fmtp parameters RFC 4867 §8.1 defines (`ptime`, `maxptime` and `channels` live elsewhere in
/// SDP, §8.3).
const KEYS: [&str; 9] = [
    "octet-align",
    "mode-set",
    "mode-change-period",
    "mode-change-capability",
    "mode-change-neighbor",
    "crc",
    "robust-sorting",
    "interleaving",
    "max-red",
];

/// The `;`-separated `name=value` items of an fmtp parameter list.
///
/// One tolerance: 3GPP TS 26.114 Annex A prints several of its own examples with a comma where a
/// semicolon belongs (`mode-change-period=2, mode-change-neighbor=1`, Table A.2.1), and a `mode-set`
/// value is itself a comma-separated list. A comma followed by a parameter name is therefore read
/// as a separator, and any other comma as part of the value.
fn items(params: &str) -> impl Iterator<Item = (&str, &str)> {
    params.split(';').flat_map(|item| {
        let mut pieces = Vec::new();
        let mut rest = item;
        while let Some((name, value)) = rest.split_once('=') {
            let next_name = value
                .char_indices()
                .filter(|&(_, character)| character == ',')
                .find(|&(index, _)| {
                    let after = value[index + 1..].trim_start();
                    let name = after.trim_start_matches(|character: char| {
                        character.is_ascii_alphabetic() || character == '-'
                    });
                    name.len() < after.len() && name.trim_start().starts_with('=')
                })
                .map(|(index, _)| index);
            match next_name {
                Some(index) => {
                    pieces.push((name.trim(), value[..index].trim()));
                    rest = &value[index + 1..];
                }
                None => {
                    pieces.push((name.trim(), value.trim()));
                    break;
                }
            }
        }
        pieces
    })
}

/// Parse an `a=fmtp:<pt> ...` body into `(payload_type, AmrFmtp)`.
///
/// `None` when the line has no parseable payload type or carries none of the RFC 4867 parameters,
/// so that the fmtp of another codec is not recorded as an AMR one. A parameter with a value the
/// RFC does not permit marks the set [`AmrParams::malformed`] rather than being guessed at: the
/// engine could not return it unmodified and honour it. Unknown parameters are dropped. Nothing
/// here can panic: the whole body is untrusted.
pub(super) fn parse_fmtp(value: &str) -> Option<(u8, AmrFmtp)> {
    let (payload_type, params) = split_fmtp(value)?;
    if !items(params).any(|(name, _)| KEYS.iter().any(|key| name.eq_ignore_ascii_case(key))) {
        return None;
    }
    let mut parsed = AmrFmtp::default();
    let flag = |value: &str, malformed: &mut bool| match value {
        "0" => Some(false),
        "1" => Some(true),
        _ => {
            *malformed = true;
            None
        }
    };
    let one_or_two = |value: &str, malformed: &mut bool| match value {
        "1" => Some(1),
        "2" => Some(2),
        _ => {
            *malformed = true;
            None
        }
    };
    for (name, value) in items(params) {
        let malformed = &mut parsed.params.malformed;
        match name.to_ascii_lowercase().as_str() {
            "octet-align" => parsed.params.octet_align = flag(value, malformed),
            "crc" => parsed.params.crc = flag(value, malformed),
            "robust-sorting" => parsed.params.robust_sorting = flag(value, malformed),
            "mode-change-neighbor" => parsed.params.mode_change_neighbor = flag(value, malformed),
            "mode-change-period" => parsed.params.mode_change_period = one_or_two(value, malformed),
            "mode-change-capability" => {
                parsed.params.mode_change_capability = one_or_two(value, malformed);
            }
            // Its presence alone turns interleaving on (RFC 4867 §8.1), whatever the value.
            "interleaving" => parsed.params.interleaving = Some(value.parse().unwrap_or(0)),
            "max-red" => match value.parse::<u16>() {
                Ok(max_red) => parsed.params.max_red = Some(max_red),
                Err(_) => *malformed = true,
            },
            "mode-set" => {
                for token in value.split(',') {
                    match token.trim().parse::<u8>() {
                        Ok(mode) if !parsed.mode_set.contains(&mode) => parsed.mode_set.push(mode),
                        Ok(_) => {}
                        Err(_) => *malformed = true,
                    }
                }
                if parsed.mode_set.is_empty() {
                    *malformed = true;
                }
            }
            _ => {}
        }
    }
    Some((payload_type, parsed))
}

/// The engine-wide AMR settings, from the daemon's configuration: the highest mode each codec
/// sends, and the codec mode request it puts in what it sends. 255 is "not set".
static MAX_MODE: [AtomicU8; 2] = [AtomicU8::new(u8::MAX), AtomicU8::new(u8::MAX)];
static MODE_REQUEST: [AtomicU8; 2] = [AtomicU8::new(u8::MAX), AtomicU8::new(u8::MAX)];

/// What the operator chose for one of the two codecs. `None` leaves the default in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AmrPolicy {
    /// The highest mode sent. Default: the highest mode of the negotiated mode set (3GPP TS 26.114
    /// §7.5.2.1.2.1), which with no mode set is 12.2 kbit/s for AMR and 23.85 kbit/s for AMR-WB.
    pub max_mode: Option<u8>,
    /// The codec mode request sent to the peer in every payload. Default: 15, no request.
    pub mode_request: Option<u8>,
}

/// Set the engine-wide policy for AMR (`wideband` false) or AMR-WB (true). Applies to streams
/// negotiated from here on.
pub fn set_policy(wideband: bool, policy: AmrPolicy) {
    let index = usize::from(wideband);
    MAX_MODE[index].store(policy.max_mode.unwrap_or(u8::MAX), Ordering::Relaxed);
    MODE_REQUEST[index].store(policy.mode_request.unwrap_or(u8::MAX), Ordering::Relaxed);
}

fn policy(wideband: bool) -> AmrPolicy {
    let index = usize::from(wideband);
    let read = |cell: &AtomicU8| Some(cell.load(Ordering::Relaxed)).filter(|&mode| mode != u8::MAX);
    AmrPolicy {
        max_mode: read(&MAX_MODE[index]),
        mode_request: read(&MODE_REQUEST[index]),
    }
}

/// Put what an AMR or AMR-WB payload type negotiated onto its spec, with the engine's own policy.
pub(super) fn negotiated(spec: CodecSpec, fmtp: Option<&AmrFmtp>) -> CodecSpec {
    let policy = policy(spec.encoding_name == "AMR-WB");
    with_policy(
        spec,
        fmtp.map(|fmtp| fmtp.params),
        fmtp.map(|fmtp| fmtp.mode_set.clone()).unwrap_or_default(),
        policy,
    )
}

fn with_policy(
    spec: CodecSpec,
    params: Option<AmrParams>,
    mode_set: Vec<u8>,
    policy: AmrPolicy,
) -> CodecSpec {
    let params = match policy.mode_request {
        Some(request) => Some(AmrParams {
            mode_request: Some(request),
            ..params.unwrap_or_default()
        }),
        None => params,
    };
    spec.with_encode_mode(policy.max_mode)
        .with_allowed_modes(mode_set)
        .with_amr_params(params)
}

/// The two payload types the engine offers for one of the codecs, bandwidth-efficient first.
///
/// GSMA IR.92 §3.2.5: an entity that terminates the user plane "must request the use of
/// bandwidth-efficient format of the AMR and AMR-WB payload format when originating a session".
/// 3GPP TS 26.114 Table A.1.2 offers each codec in both formats, the bandwidth-efficient payload
/// type ahead of the octet-aligned one, each with `mode-change-capability=2` (Tables 6.1, 6.2) and
/// no `mode-set`. `max-red=0` because the engine sends no redundant frames (RFC 4867 §8.3.1: "if
/// no redundancy will be used ... \"max-red\" is set to 0").
pub(crate) fn offered(
    payload_types: [u8; 2],
    encoding_name: &str,
    clock_rate_hz: u32,
) -> [CodecSpec; 2] {
    let spec = |payload_type, octet_align| {
        let params = AmrParams {
            octet_align,
            mode_change_capability: Some(2),
            max_red: Some(0),
            ..AmrParams::default()
        };
        with_policy(
            CodecSpec::new(payload_type, encoding_name, clock_rate_hz, 1, 20),
            Some(params),
            Vec::new(),
            policy(encoding_name == "AMR-WB"),
        )
    };
    [
        spec(payload_types[0], None),
        spec(payload_types[1], Some(true)),
    ]
}

/// The `a=fmtp` line the engine writes for an AMR or AMR-WB payload type, `None` for another codec.
///
/// For a payload type taken from a peer's offer this is the answer: its payload format parameters
/// and `mode-set` exactly as offered, then the engine's own declarations. `max-red` is returned as
/// offered (RFC 4867 §8.3.1: the answerer "is RECOMMENDED to use the same limitation as the offer
/// declares"); the engine sends no redundant frames, which is inside any limit. For a payload type
/// the engine offers itself it is that offer.
pub(super) fn fmtp_line(codec: &CodecSpec) -> Option<String> {
    if !codec.is_amr() {
        return None;
    }
    let params = codec.amr.unwrap_or_default();
    let flag =
        |name: &str, value: Option<bool>| value.map(|set| format!("{name}={}", u8::from(set)));
    let mode_set = (!codec.allowed_modes.is_empty()).then(|| {
        let modes: Vec<String> = codec.allowed_modes.iter().map(u8::to_string).collect();
        format!("mode-set={}", modes.join(","))
    });
    let items: Vec<String> = [
        flag("octet-align", params.octet_align),
        mode_set,
        // RFC 4867 §8.3.1: "The mode-change-capability SHOULD be included in answers."
        Some("mode-change-capability=2".to_owned()),
        flag("crc", params.crc),
        flag("robust-sorting", params.robust_sorting),
        params.max_red.map(|max_red| format!("max-red={max_red}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    Some(format!("a=fmtp:{} {}", codec.payload_type, items.join(";")))
}

/// The codecs the engine adds to an offer, each on a payload type the offer does not use yet.
///
/// `present` is the offer's payload types with their encoding names. A codec the offer already
/// carries, by its static payload type or by name, is left out. A dynamic payload type (RFC 3551
/// §3: 96 to 127) that the offer uses for something else moves to the lowest free dynamic number,
/// so that the bandwidth-efficient payload type of a pair is not lost to a collision while its
/// octet-aligned twin survives.
pub(super) fn place_added(add: &[CodecSpec], present: &[(u8, Option<String>)]) -> Vec<CodecSpec> {
    let mut taken: Vec<u8> = present.iter().map(|(number, _)| *number).collect();
    let mut placed = Vec::with_capacity(add.len());
    for spec in add {
        let offered_already = present.iter().any(|(number, name)| {
            name.as_deref() == Some(spec.encoding_name.as_str())
                || (*number < 96 && *number == spec.payload_type)
        });
        if offered_already {
            continue;
        }
        let mut spec = spec.clone();
        if taken.contains(&spec.payload_type) {
            let Some(free) = (96..=127).find(|number| !taken.contains(number)) else {
                continue;
            };
            spec.payload_type = free;
        }
        taken.push(spec.payload_type);
        placed.push(spec);
    }
    placed
}

#[cfg(test)]
mod tests;
