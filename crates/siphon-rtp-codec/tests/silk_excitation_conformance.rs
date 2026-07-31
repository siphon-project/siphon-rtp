//! SILK LTP + excitation conformance: decode **every SILK frame of every packet** of the local
//! SILK-only oracle streams and diff the pitch, LTP and excitation state against libopus' own decode
//! of the same bits, field by field.
//!
//! A SILK frame's bitstream is exactly `silk_decode_indices` followed by `silk_decode_pulses`
//! (`decode_frame.c:80-89`) — nothing else in the layer reads a bit — and every symbol in that span
//! is decoded here for real. (Until the NLSF phase landed, this harness replayed the `(fl, fh)` of
//! each normalized-LSF symbol from the dump to get past it; that crutch is gone, and the NLSF indices
//! are decoded like everything else. The dump still records them, since removing a field group from
//! the shared trace patch would break the sibling harnesses that do consume it.)
//!
//! # What is checked, per SILK frame
//!
//! * **pitch** — the primary lag index (absolute *and* delta coded), the contour index, the
//!   periodicity index, all four filter indices, and the LTP scaling index (§4.2.7.6);
//! * **seed** — the §4.2.7.7 LCG seed;
//! * **excitation** — the rate level, the per-shell-block pulse count and LSB-shift count, and an
//!   FNV-1a hash plus checksum of the whole signed pulse signal (§4.2.7.8.1-5);
//! * **reconstruction** — the same hash and checksum over the Q14 excitation (§4.2.7.8.6);
//! * **range-coder state** — `rng` and `tell()` at the *end* of the frame's bitstream. That is the
//!   layer's own `final_range` check, at per-frame rather than per-packet resolution: an exact 32-bit
//!   value plus the bit position, so a single mis-ordered or missing symbol is caught on the frame it
//!   happened in rather than three packets later.
//!
//! LBRR frames are decoded too (they interleave with the regular frames and cost bits), so a packet
//! carrying in-band FEC is followed to its end like any other.
//!
//! Skips gracefully when the vectors or `.trace` dumps are absent, and refuses to pass vacuously:
//! with vectors present it demands a non-trivial packet, frame, shell-block and voiced-frame tally.
//! Recipe for regenerating the dumps is in CONTRIBUTING.md.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::packet::{self, Mode};
use siphon_rtp_codec::opus::range_coder::RangeDecoder;
use siphon_rtp_codec::opus::silk::decoder::{ChannelState, SilkDecoder, MID_CHANNEL, SIDE_CHANNEL};
use siphon_rtp_codec::opus::silk::excitation::{self, PULSE_BUFFER_LENGTH};
use siphon_rtp_codec::opus::silk::frame_type::decode_frame_type;
use siphon_rtp_codec::opus::silk::gains::decode_gain_indices;
use siphon_rtp_codec::opus::silk::ltp;
use siphon_rtp_codec::opus::silk::nlsf;
use siphon_rtp_codec::opus::silk::stereo_pred::{
    decode_mid_only, decode_stereo_weights, mid_only_flag_is_coded,
};
use siphon_rtp_codec::opus::silk::types::{
    CondCoding, InternalRate, SignalType, SubframeLayout, MAX_FRAME_LENGTH,
};

/// The rate the reference decode ran at (`dump_silk_trace.sh` uses `opus_demo -d 48000 2`).
const REFERENCE_RATE_HZ: u32 = 48_000;

/// One packet of an `opus_demo` `.bit` file: `[u32 BE len][u32 BE final_range][payload]`.
struct BitPacket {
    payload: Vec<u8>,
    /// The encoder's whole-packet range-coder final value. Not asserted here: for a SILK-only packet
    /// with spare bits libopus reads a redundancy flag and a CELT redundancy frame after the SILK
    /// layer (`opus_decoder.c:452-480`), and folds that decode into the reported value
    /// (`rangeFinal = dec.rng ^ redundant_rng`). This harness stops at the end of the SILK layer, so
    /// it asserts the per-frame `rng`/`tell` the trace records instead — a strictly finer check of
    /// the same property, for the part of the packet this phase owns.
    #[allow(dead_code)]
    final_range: u32,
}

fn parse_bit_stream(bytes: &[u8]) -> Result<Vec<BitPacket>, String> {
    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if offset + 8 > bytes.len() {
            return Err(format!("truncated packet header at offset {offset}"));
        }
        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        let final_range = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;
        if length > 1 << 20 || offset + length > bytes.len() {
            return Err(format!(
                "implausible packet length {length} at offset {offset}"
            ));
        }
        packets.push(BitPacket {
            payload: bytes[offset..offset + length].to_vec(),
            final_range,
        });
        offset += length;
    }
    Ok(packets)
}

/// Everything the instrumented libopus reports for one SILK frame ("unit"), keyed by the `u=`
/// counter it increments once per `silk_decode_indices` call.
#[derive(Debug, Default, Clone)]
struct FrameTrace {
    /// `PITCH` — absent for an unvoiced frame, which codes no LTP data at all.
    pitch: Option<PitchTrace>,
    /// `SEED` — the §4.2.7.7 LCG seed and whether the frame was voiced.
    seed: Option<(u8, bool)>,
    /// `PULSES` — rate level, per-block counts and LSB shifts, and the pulse signal's checksum.
    pulses: Option<PulseTrace>,
    /// `RC` — the range-coder state at the end of the frame's bitstream.
    range_state: Option<(u32, i32)>,
    /// `EXC` — the reconstructed Q14 excitation. Absent for an LBRR frame (`silk_decode_core` only
    /// runs for regular frames).
    excitation: Option<ExcitationTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PitchTrace {
    lag_index: i32,
    contour_index: i32,
    periodicity_index: i32,
    ltp_scale_index: i32,
    filter_indices: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PulseTrace {
    rate_level: usize,
    block_count: usize,
    counts: Vec<u32>,
    lsb_shifts: Vec<u32>,
    sample_count: usize,
    sum: i64,
    hash: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExcitationTrace {
    sample_count: usize,
    seed: u8,
    sum: i64,
    hash: u32,
}

/// libopus' geometry for a packet, from the existing `HDR` line — used to cross-check our own view
/// of the internal rate and subframe layout before a single symbol is compared.
#[derive(Debug, Clone, Copy)]
struct HeaderTrace {
    frames_per_packet: usize,
    subframe_count: usize,
    rate_khz: usize,
}

#[derive(Debug, Default)]
struct PacketTrace {
    header: Option<HeaderTrace>,
    frames: BTreeMap<usize, FrameTrace>,
}

fn field<'a>(token: Option<&'a str>, key: &str) -> Result<&'a str, String> {
    let token = token.ok_or_else(|| format!("missing field {key}"))?;
    token
        .strip_prefix(&format!("{key}="))
        .ok_or_else(|| format!("expected {key}=..., got {token}"))
}

fn number(text: &str) -> Result<i64, String> {
    text.parse::<i64>()
        .map_err(|error| format!("not a number: {text} ({error})"))
}

fn unsigned(text: &str) -> Result<u32, String> {
    text.parse::<u32>()
        .map_err(|error| format!("not an unsigned number: {text} ({error})"))
}

fn list(text: &str) -> Result<Vec<u32>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',').map(unsigned).collect()
}

fn signed_list(text: &str) -> Result<Vec<i32>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|part| number(part).map(|value| value as i32))
        .collect()
}

/// Parse the dump. Only the event kinds this harness consumes are decoded; the LP-layer kinds the
/// sibling `silk_header_conformance` harness owns (`LBRRFLAGS`, `STEREO`, `MIDONLY`, `TYPE`,
/// `GAINIDX`, `GAINS`) are skipped rather than rejected, so one dump serves both.
fn parse_trace(text: &str) -> Result<BTreeMap<usize, PacketTrace>, String> {
    let mut packets: BTreeMap<usize, PacketTrace> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let index_token = tokens.next().ok_or("empty line")?;
        let packet_index: usize = index_token
            .strip_prefix('P')
            .ok_or_else(|| format!("expected P<n>, got {index_token}"))?
            .parse()
            .map_err(|_| format!("bad packet index: {index_token}"))?;
        let kind = tokens.next().ok_or("missing event kind")?;
        let packet = packets.entry(packet_index).or_default();

        match kind {
            "HDR" => {
                let channel = number(field(tokens.next(), "ch")?)?;
                let frames_per_packet = number(field(tokens.next(), "nframes")?)? as usize;
                let subframe_count = number(field(tokens.next(), "nsubfr")?)? as usize;
                let rate_khz = number(field(tokens.next(), "fskhz")?)? as usize;
                if channel == 0 {
                    packet.header = Some(HeaderTrace {
                        frames_per_packet,
                        subframe_count,
                        rate_khz,
                    });
                }
            }
            "PITCH" => {
                let unit = number(field(tokens.next(), "u")?)? as usize;
                let _lbrr = field(tokens.next(), "lbrr")?;
                let _frame = field(tokens.next(), "frame")?;
                let lag_index = number(field(tokens.next(), "lag")?)? as i32;
                let contour_index = number(field(tokens.next(), "contour")?)? as i32;
                let periodicity_index = number(field(tokens.next(), "per")?)? as i32;
                let ltp_scale_index = number(field(tokens.next(), "scale")?)? as i32;
                let filter_indices = signed_list(field(tokens.next(), "idx")?)?;
                packet.frames.entry(unit).or_default().pitch = Some(PitchTrace {
                    lag_index,
                    contour_index,
                    periodicity_index,
                    ltp_scale_index,
                    filter_indices,
                });
            }
            "SEED" => {
                let unit = number(field(tokens.next(), "u")?)? as usize;
                let voiced = number(field(tokens.next(), "voiced")?)? != 0;
                let seed = number(tokens.next().ok_or("missing seed value")?)? as u8;
                packet.frames.entry(unit).or_default().seed = Some((seed, voiced));
            }
            "PULSES" => {
                let unit = number(field(tokens.next(), "u")?)? as usize;
                let rate_level = number(field(tokens.next(), "rate")?)? as usize;
                let block_count = number(field(tokens.next(), "iter")?)? as usize;
                let counts = list(field(tokens.next(), "cnt")?)?;
                let lsb_shifts = list(field(tokens.next(), "lsh")?)?;
                let sample_count = number(field(tokens.next(), "n")?)? as usize;
                let sum = number(field(tokens.next(), "sum")?)?;
                let hash = unsigned(field(tokens.next(), "hash")?)?;
                packet.frames.entry(unit).or_default().pulses = Some(PulseTrace {
                    rate_level,
                    block_count,
                    counts,
                    lsb_shifts,
                    sample_count,
                    sum,
                    hash,
                });
            }
            "RC" => {
                let unit = number(field(tokens.next(), "u")?)? as usize;
                let rng = unsigned(field(tokens.next(), "rng")?)?;
                let tell = number(field(tokens.next(), "tell")?)? as i32;
                packet.frames.entry(unit).or_default().range_state = Some((rng, tell));
            }
            "EXC" => {
                let unit = number(field(tokens.next(), "u")?)? as usize;
                let sample_count = number(field(tokens.next(), "n")?)? as usize;
                let seed = number(field(tokens.next(), "seed")?)? as u8;
                let sum = number(field(tokens.next(), "sum")?)?;
                let hash = unsigned(field(tokens.next(), "hash")?)?;
                packet.frames.entry(unit).or_default().excitation = Some(ExcitationTrace {
                    sample_count,
                    seed,
                    sum,
                    hash,
                });
            }
            // Every other event kind belongs to a different SILK stage's harness. The `.trace` dump
            // is one shared, append-only stream that several harnesses read, so an unrecognised kind
            // is ignored rather than rejected: a closed allow-list here means any stage that adds an
            // event to `silk_trace.patch` breaks every sibling harness the next time the dumps are
            // regenerated. Nothing is lost by ignoring — a typo in an event this harness *does* own
            // surfaces as a missing-field or coverage-zero failure instead.
            _ => {}
        }
    }
    Ok(packets)
}

/// FNV-1a over the little-endian bytes of an `i16` array — the exact function
/// `silk_trace_hash16` computes in the instrumented libopus.
fn hash16(values: &[i16]) -> u32 {
    let mut hash = 2_166_136_261u32;
    for &value in values {
        let bits = value as u16;
        for shift in [0u32, 8] {
            hash ^= u32::from((bits >> shift) as u8);
            hash = hash.wrapping_mul(16_777_619);
        }
    }
    hash
}

/// FNV-1a over the little-endian bytes of an `i32` array — `silk_trace_hash32`.
fn hash32(values: &[i32]) -> u32 {
    let mut hash = 2_166_136_261u32;
    for &value in values {
        let bits = value as u32;
        for shift in [0u32, 8, 16, 24] {
            hash ^= u32::from((bits >> shift) as u8);
            hash = hash.wrapping_mul(16_777_619);
        }
    }
    hash
}

/// What one stream's comparison exercised, so the run can prove it was not vacuous.
#[derive(Default, Debug)]
struct Coverage {
    packets: usize,
    frames: usize,
    lbrr_frames: usize,
    voiced_frames: usize,
    delta_lag_frames: usize,
    ltp_scaling_frames: usize,
    shell_blocks: usize,
    pulses: u64,
    lsb_blocks: usize,
    excitation_samples: usize,
    range_states: usize,
    stereo_frames: usize,
    ten_ms_frames: usize,
}

impl Coverage {
    fn absorb(&mut self, other: &Coverage) {
        self.packets += other.packets;
        self.frames += other.frames;
        self.lbrr_frames += other.lbrr_frames;
        self.voiced_frames += other.voiced_frames;
        self.delta_lag_frames += other.delta_lag_frames;
        self.ltp_scaling_frames += other.ltp_scaling_frames;
        self.shell_blocks += other.shell_blocks;
        self.pulses += other.pulses;
        self.lsb_blocks += other.lsb_blocks;
        self.excitation_samples += other.excitation_samples;
        self.range_states += other.range_states;
        self.stereo_frames += other.stereo_frames;
        self.ten_ms_frames += other.ten_ms_frames;
    }
}

/// Scratch buffers, allocated once per stream — the decode path itself allocates nothing.
struct Scratch {
    pulses: [i16; PULSE_BUFFER_LENGTH],
    excitation_q14: [i32; MAX_FRAME_LENGTH],
}

/// Decode one SILK frame's side info and excitation, and diff every field against the dump.
///
/// Mirrors `silk_decode_frame` (`decode_frame.c:70-89`): indices then pulses, nothing else.
#[allow(clippy::too_many_arguments)]
fn check_frame(
    decoder: &mut RangeDecoder<'_>,
    silk: &mut SilkDecoder,
    scratch: &mut Scratch,
    channel_index: usize,
    active: bool,
    is_lbrr: bool,
    cond_coding: CondCoding,
    rate: InternalRate,
    layout: SubframeLayout,
    trace: &FrameTrace,
    label: &str,
    coverage: &mut Coverage,
) -> Result<(), String> {
    // ── Frame type (§4.2.7.3) ─────────────────────────────────────────────────────────────────
    let frame_type =
        decode_frame_type(decoder, active).map_err(|e| format!("{label}: frame type: {e:?}"))?;
    let signal_type = frame_type.signal_type();
    let quant_offset_type = frame_type.quant_offset_type();

    // ── Subframe gains (§4.2.7.4) ─────────────────────────────────────────────────────────────
    // An LBRR frame's indices are read but never dequantized (`dec_API.c:274-277` calls
    // decode_indices + decode_pulses only), so `LastGainIndex` must not move for it.
    if is_lbrr {
        decode_gain_indices(decoder, signal_type, cond_coding, layout.subframe_count)
            .map_err(|e| format!("{label}: lbrr gain indices: {e:?}"))?;
    } else {
        silk.decode_subframe_gains(decoder, channel_index, signal_type, cond_coding)
            .map_err(|e| format!("{label}: gains: {e:?}"))?;
    }

    // ── NLSF (§4.2.7.5) ───────────────────────────────────────────────────────────────────────
    // Only the *indices* are read here, never dequantized: this harness owns the LTP and excitation
    // stages, and `silk_decode_parameters` — which is what would move the NLSF interpolation anchor —
    // is not part of the bitstream. `silk_nlsf_conformance` checks the values themselves.
    nlsf::decode_indices(decoder, rate, signal_type, layout.subframe_count)
        .map_err(|e| format!("{label}: nlsf indices: {e:?}"))?;

    // ── LTP (§4.2.7.6) ────────────────────────────────────────────────────────────────────────
    let previous_signal_type = silk
        .channel(channel_index)
        .map_err(|e| format!("{label}: channel: {e:?}"))?
        .ec_prev_signal_type;
    let previous_lag_index = silk
        .channel(channel_index)
        .map_err(|e| format!("{label}: channel: {e:?}"))?
        .ec_prev_lag_index;

    let indices = if signal_type == SignalType::Voiced {
        ltp::decode_indices(
            decoder,
            rate,
            layout,
            cond_coding,
            previous_signal_type,
            previous_lag_index,
        )
    } else {
        ltp::LtpIndices::unvoiced(layout.subframe_count)
    };

    match (&trace.pitch, signal_type) {
        (Some(reference), SignalType::Voiced) => {
            if i32::from(indices.lag_index) != reference.lag_index {
                return Err(format!(
                    "{label}: pitch lag index {} != libopus {}",
                    indices.lag_index, reference.lag_index
                ));
            }
            if i32::from(indices.contour_index) != reference.contour_index {
                return Err(format!(
                    "{label}: contour index {} != libopus {}",
                    indices.contour_index, reference.contour_index
                ));
            }
            if i32::from(indices.periodicity_index) != reference.periodicity_index {
                return Err(format!(
                    "{label}: periodicity index {} != libopus {}",
                    indices.periodicity_index, reference.periodicity_index
                ));
            }
            if i32::from(indices.ltp_scale_index) != reference.ltp_scale_index {
                return Err(format!(
                    "{label}: LTP scale index {} != libopus {}",
                    indices.ltp_scale_index, reference.ltp_scale_index
                ));
            }
            let ours: Vec<i32> = indices.filter_indices[..layout.subframe_count]
                .iter()
                .map(|&value| i32::from(value))
                .collect();
            if ours != reference.filter_indices {
                return Err(format!(
                    "{label}: LTP filter indices {ours:?} != libopus {:?}",
                    reference.filter_indices
                ));
            }
            // The dequantized form synthesis consumes has to be in range too.
            let parameters = ltp::dequantize(&indices, rate);
            for &lag in &parameters.pitch_lags[..layout.subframe_count] {
                if !(ltp::min_lag(rate)..=ltp::max_lag(rate)).contains(&lag) {
                    return Err(format!("{label}: pitch lag {lag} outside the legal range"));
                }
            }
            if parameters.scale_q14 != ltp::LTP_SCALES_Q14[usize::from(indices.ltp_scale_index)] {
                return Err(format!("{label}: LTP scale mismatch after dequantisation"));
            }
            coverage.voiced_frames += 1;
            if cond_coding == CondCoding::Conditionally
                && previous_signal_type == SignalType::Voiced
            {
                coverage.delta_lag_frames += 1;
            }
            if cond_coding == CondCoding::Independently {
                coverage.ltp_scaling_frames += 1;
            }
        }
        (None, SignalType::Voiced) => {
            return Err(format!("{label}: voiced frame but libopus logged no PITCH"));
        }
        (Some(_), _) => {
            return Err(format!(
                "{label}: unvoiced frame but libopus logged a PITCH event"
            ));
        }
        (None, _) => {}
    }

    // Entropy context for the next frame (`decode_indices.c:121,145`).
    {
        let channel = silk
            .channel_mut(channel_index)
            .map_err(|e| format!("{label}: channel: {e:?}"))?;
        if signal_type == SignalType::Voiced {
            channel.ec_prev_lag_index = indices.lag_index;
        }
        channel.ec_prev_signal_type = signal_type;
    }

    // ── LCG seed (§4.2.7.7) ───────────────────────────────────────────────────────────────────
    let seed = excitation::decode_seed(decoder);
    match trace.seed {
        Some((reference_seed, reference_voiced)) => {
            if seed != reference_seed {
                return Err(format!("{label}: seed {seed} != libopus {reference_seed}"));
            }
            if reference_voiced != (signal_type == SignalType::Voiced) {
                return Err(format!(
                    "{label}: signal type {signal_type:?} disagrees with libopus' voiced={reference_voiced}"
                ));
            }
        }
        None => return Err(format!("{label}: no SEED event")),
    }

    // ── Excitation (§4.2.7.8) ─────────────────────────────────────────────────────────────────
    let frame_length = layout.frame_length(rate);
    let summary = excitation::decode(
        decoder,
        signal_type,
        quant_offset_type,
        frame_length,
        seed,
        &mut scratch.pulses,
        &mut scratch.excitation_q14[..frame_length],
    )
    .map_err(|e| format!("{label}: excitation: {e:?}"))?;

    let reference = trace
        .pulses
        .as_ref()
        .ok_or_else(|| format!("{label}: no PULSES event"))?;
    if summary.rate_level != reference.rate_level {
        return Err(format!(
            "{label}: rate level {} != libopus {}",
            summary.rate_level, reference.rate_level
        ));
    }
    if summary.block_count != reference.block_count {
        return Err(format!(
            "{label}: {} shell blocks != libopus {}",
            summary.block_count, reference.block_count
        ));
    }
    let counts: Vec<u32> = summary.pulse_counts[..summary.block_count]
        .iter()
        .map(|&value| u32::from(value))
        .collect();
    if counts != reference.counts {
        return Err(format!(
            "{label}: pulse counts {counts:?} != libopus {:?}",
            reference.counts
        ));
    }
    let shifts: Vec<u32> = summary.lsb_shifts[..summary.block_count]
        .iter()
        .map(|&value| u32::from(value))
        .collect();
    if shifts != reference.lsb_shifts {
        return Err(format!(
            "{label}: LSB shifts {shifts:?} != libopus {:?}",
            reference.lsb_shifts
        ));
    }
    let padded = summary.block_count * 16;
    if padded != reference.sample_count {
        return Err(format!(
            "{label}: padded length {padded} != libopus {}",
            reference.sample_count
        ));
    }
    let pulse_sum: i64 = scratch.pulses[..padded]
        .iter()
        .map(|&value| i64::from(value))
        .sum();
    if pulse_sum != reference.sum {
        return Err(format!(
            "{label}: pulse checksum {pulse_sum} != libopus {}",
            reference.sum
        ));
    }
    let pulse_hash = hash16(&scratch.pulses[..padded]);
    if pulse_hash != reference.hash {
        return Err(format!(
            "{label}: pulse signal hash {pulse_hash} != libopus {} \
             (counts and LSB shifts agree, so this is a placement or sign error)",
            reference.hash
        ));
    }
    coverage.shell_blocks += summary.block_count;
    coverage.pulses += u64::from(summary.total_pulses());
    coverage.lsb_blocks += shifts.iter().filter(|&&shift| shift > 0).count();

    // ── Reconstruction (§4.2.7.8.6) — regular frames only; the C never runs decode_core for LBRR ──
    if let Some(reference) = &trace.excitation {
        if is_lbrr {
            return Err(format!("{label}: libopus logged an EXC for an LBRR frame"));
        }
        if reference.sample_count != frame_length {
            return Err(format!(
                "{label}: excitation length {frame_length} != libopus {}",
                reference.sample_count
            ));
        }
        if reference.seed != seed {
            return Err(format!(
                "{label}: reconstruction seed {seed} != libopus {}",
                reference.seed
            ));
        }
        let sum: i64 = scratch.excitation_q14[..frame_length]
            .iter()
            .map(|&value| i64::from(value))
            .sum();
        if sum != reference.sum {
            return Err(format!(
                "{label}: excitation checksum {sum} != libopus {}",
                reference.sum
            ));
        }
        let hash = hash32(&scratch.excitation_q14[..frame_length]);
        if hash != reference.hash {
            return Err(format!(
                "{label}: Q14 excitation hash {hash} != libopus {} \
                 (the pulses match, so this is a §4.2.7.8.6 reconstruction error)",
                reference.hash
            ));
        }
        coverage.excitation_samples += frame_length;
    } else if !is_lbrr {
        return Err(format!("{label}: no EXC event for a regular frame"));
    }

    // ── The frame's bitstream ends here: the range coder must be where libopus left it ─────────
    match trace.range_state {
        Some((rng, tell)) => {
            if decoder.rng() != rng || decoder.tell() != tell {
                return Err(format!(
                    "{label}: range coder at (rng={}, tell={}) != libopus (rng={rng}, tell={tell}) \
                     — the frame consumed the wrong symbols",
                    decoder.rng(),
                    decoder.tell()
                ));
            }
            coverage.range_states += 1;
        }
        None => return Err(format!("{label}: no RC event")),
    }

    coverage.frames += 1;
    if is_lbrr {
        coverage.lbrr_frames += 1;
    }
    if layout.subframe_count == 2 {
        coverage.ten_ms_frames += 1;
    }
    Ok(())
}

/// Decode one stream end to end, mirroring `silk_Decode` (`dec_API.c:228-370`).
fn check_stream(
    packets: &[BitPacket],
    trace: &BTreeMap<usize, PacketTrace>,
) -> Result<Coverage, String> {
    let mut silk = SilkDecoder::new(REFERENCE_RATE_HZ, 2).map_err(|e| format!("new: {e:?}"))?;
    let mut coverage = Coverage::default();
    let mut scratch = Scratch {
        pulses: [0; PULSE_BUFFER_LENGTH],
        excitation_q14: [0; MAX_FRAME_LENGTH],
    };

    for (index, bit_packet) in packets.iter().enumerate() {
        if bit_packet.payload.is_empty() {
            continue; // DTX / dropped packet: libopus emits no side info for it.
        }
        let packet_trace = trace
            .get(&index)
            .ok_or_else(|| format!("packet {index}: no trace events"))?;
        let parsed =
            packet::parse(&bit_packet.payload).map_err(|e| format!("packet {index}: {e:?}"))?;
        if parsed.toc.mode() != Mode::Silk {
            return Err(format!(
                "packet {index}: not SILK-only (mode {:?}) — the generator must only produce SILK",
                parsed.toc.mode()
            ));
        }
        if parsed.frame_count() != 1 {
            return Err(format!(
                "packet {index}: {} Opus frames; the SILK-only generator emits one per packet",
                parsed.frame_count()
            ));
        }
        let frame = parsed.frames()[0];
        if frame.is_empty() {
            continue;
        }

        let channel_count = usize::from(parsed.toc.channels());
        let rate = InternalRate::from_bandwidth(parsed.toc.bandwidth());
        let duration_ms =
            parsed.toc.samples_per_frame(REFERENCE_RATE_HZ) / (REFERENCE_RATE_HZ as usize / 1000);
        let layout = SubframeLayout::from_duration_ms(duration_ms)
            .map_err(|e| format!("packet {index}: duration {duration_ms} ms: {e:?}"))?;

        if let Some(header) = packet_trace.header {
            if header.rate_khz != rate.khz()
                || header.frames_per_packet != layout.frames_per_packet
                || header.subframe_count != layout.subframe_count
            {
                return Err(format!(
                    "packet {index}: geometry {}kHz {}x{} != libopus {}kHz {}x{}",
                    rate.khz(),
                    layout.frames_per_packet,
                    layout.subframe_count,
                    header.rate_khz,
                    header.frames_per_packet,
                    header.subframe_count
                ));
            }
        }

        silk.configure(channel_count, rate, duration_ms)
            .map_err(|e| format!("packet {index}: configure: {e:?}"))?;
        let mut decoder = RangeDecoder::new(frame);

        // ── LP-layer header (§4.2.3-4) ────────────────────────────────────────────────────────
        let header = silk
            .decode_lp_layer_header(&mut decoder)
            .map_err(|e| format!("packet {index}: header: {e:?}"))?;
        let mut flag_table = [([false; 3], [false; 3]); 2];
        for (channel, slot) in flag_table.iter_mut().enumerate().take(channel_count) {
            let flags = header
                .channel(channel)
                .map_err(|e| format!("packet {index}: channel {channel}: {e:?}"))?;
            *slot = (flags.vad_flags, flags.lbrr_flags);
        }
        // Accessors rather than direct indexing: the loops below walk channels and 20 ms intervals,
        // and indexing a slice by the loop variable is exactly what `needless_range_loop` rejects.
        let vad = |channel: usize, interval: usize| flag_table[channel].0[interval];
        let lbrr = |channel: usize, interval: usize| flag_table[channel].1[interval];

        // `u` counts SILK frames in decode order: every LBRR frame first, then the regular ones.
        let mut unit = 0usize;
        let next_trace = |unit: usize, label: &str| -> Result<&FrameTrace, String> {
            packet_trace
                .frames
                .get(&unit)
                .ok_or_else(|| format!("{label}: no trace unit u={unit}"))
        };

        // ── LBRR frames (§4.2.4-5; dec_API.c:252-280) ─────────────────────────────────────────
        for interval in 0..layout.frames_per_packet {
            for channel in 0..channel_count {
                if !lbrr(channel, interval) {
                    continue;
                }
                if channel_count == 2 && channel == MID_CHANNEL {
                    let _ = decode_stereo_weights(&mut decoder);
                    if !lbrr(SIDE_CHANNEL, interval) {
                        let _ = decode_mid_only(&mut decoder);
                    }
                }
                let cond_coding = if interval > 0 && lbrr(channel, interval - 1) {
                    CondCoding::Conditionally
                } else {
                    CondCoding::Independently
                };
                let label = format!("packet {index} lbrr ch{channel} interval {interval} u={unit}");
                let frame_trace = next_trace(unit, &label)?.clone();
                check_frame(
                    &mut decoder,
                    &mut silk,
                    &mut scratch,
                    channel,
                    // An LBRR frame is always active (`decode_indices.c:51`).
                    true,
                    true,
                    cond_coding,
                    rate,
                    layout,
                    &frame_trace,
                    &label,
                    &mut coverage,
                )?;
                unit += 1;
            }
        }

        // ── Regular frames (§4.2.6; dec_API.c:283-370) ────────────────────────────────────────
        for interval in 0..layout.frames_per_packet {
            // Stereo prediction weights and the mid-only flag, per SILK frame (§4.2.7.1-2).
            let mut decode_only_middle = false;
            if channel_count == 2 {
                let _ = decode_stereo_weights(&mut decoder);
                if mid_only_flag_is_coded(vad(SIDE_CHANNEL, interval)) {
                    decode_only_middle = decode_mid_only(&mut decoder);
                }
                coverage.stereo_frames += 1;
            }
            let has_side = !decode_only_middle;

            for channel in 0..channel_count {
                if channel != MID_CHANNEL && !has_side {
                    continue;
                }
                // dec_API.c:341-355. Note the side channel's frame index is one *behind*, so the
                // second SILK frame of a 40 ms packet is still independently coded for it.
                let previous_frame_coded = interval > channel;
                let cond_coding = ChannelState::cond_coding(
                    if previous_frame_coded {
                        interval - channel
                    } else {
                        0
                    },
                    previous_frame_coded,
                    channel > MID_CHANNEL && silk.prev_decode_only_middle(),
                );
                let label = format!("packet {index} ch{channel} frame {interval} u={unit}");
                let frame_trace = next_trace(unit, &label)?.clone();
                check_frame(
                    &mut decoder,
                    &mut silk,
                    &mut scratch,
                    channel,
                    vad(channel, interval),
                    false,
                    cond_coding,
                    rate,
                    layout,
                    &frame_trace,
                    &label,
                    &mut coverage,
                )?;
                unit += 1;
            }
            silk.set_decode_only_middle(decode_only_middle);
        }

        if unit != packet_trace.frames.len() {
            return Err(format!(
                "packet {index}: decoded {unit} SILK frames, libopus logged {}",
                packet_trace.frames.len()
            ));
        }
        coverage.packets += 1;
    }

    Ok(coverage)
}

/// `reference/opus/silk_only`, if present.
fn vector_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_only");
    dir.is_dir().then_some(dir)
}

#[test]
fn silk_ltp_and_excitation_match_libopus() {
    let Some(dir) = vector_dir() else {
        eprintln!("silk excitation conformance: vectors not present — skipping");
        return;
    };
    let mut bit_files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "bit"))
                .collect()
        })
        .unwrap_or_default();
    bit_files.sort();
    if bit_files.is_empty() {
        eprintln!(
            "silk excitation conformance: no .bit files in {} — skipping",
            dir.display()
        );
        return;
    }

    let mut passed: Vec<String> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut coverage = Coverage::default();

    for bit_path in &bit_files {
        let name = bit_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let trace_path = bit_path.with_extension("trace");
        let Ok(bytes) = std::fs::read(bit_path) else {
            skipped.push((name, "unreadable .bit".to_string()));
            continue;
        };
        let Ok(trace_text) = std::fs::read_to_string(&trace_path) else {
            skipped.push((
                name,
                "no .trace — run reference/opus/dump_silk_trace.sh".to_string(),
            ));
            continue;
        };
        // A dump made by the pre-LTP instrumentation has none of the field groups this harness owns;
        // treat it as a missing dump rather than a failure, so an out-of-date reference tree skips
        // instead of lying.
        if !trace_text.contains(" PULSES ") {
            skipped.push((
                name,
                "stale .trace (no PULSES) — rebuild reference/opus/build-trace".to_string(),
            ));
            continue;
        }
        let packets = match parse_bit_stream(&bytes) {
            Ok(packets) => packets,
            Err(error) => {
                failed.push((name, error));
                continue;
            }
        };
        let trace = match parse_trace(&trace_text) {
            Ok(trace) => trace,
            Err(error) => {
                failed.push((name, format!("trace: {error}")));
                continue;
            }
        };
        match check_stream(&packets, &trace) {
            Ok(stream_coverage) => {
                coverage.absorb(&stream_coverage);
                passed.push(name);
            }
            Err(reason) => failed.push((name, reason)),
        }
    }

    eprintln!(
        "silk excitation conformance: {} passed, {} skipped, {} failed",
        passed.len(),
        skipped.len(),
        failed.len()
    );
    eprintln!("  coverage: {coverage:?}");
    if !skipped.is_empty() {
        eprintln!("  skipped: {skipped:?}");
    }
    assert!(
        failed.is_empty(),
        "silk excitation: {} stream(s) failed: {failed:?}",
        failed.len()
    );
    assert!(
        !passed.is_empty(),
        "silk excitation: {} stream(s) present but none scored — are the .trace dumps built? skipped={skipped:?}",
        bit_files.len()
    );
    // Vectors were present, so the run must not have been vacuous. Every one of these numbers is a
    // distinct code path: without them a harness that silently stopped after the first packet, or
    // never met a voiced frame, would still report "passed".
    assert!(
        coverage.packets > 10_000,
        "expected the full vector set to score >10k packets, got {}",
        coverage.packets
    );
    assert!(
        coverage.frames > coverage.packets,
        "multi-frame packets were never followed: {} frames over {} packets",
        coverage.frames,
        coverage.packets
    );
    assert!(
        coverage.range_states == coverage.frames,
        "every frame must end on a verified range-coder state: {} of {}",
        coverage.range_states,
        coverage.frames
    );
    assert!(
        coverage.voiced_frames > 1_000,
        "expected >1k voiced frames to exercise the LTP path, got {}",
        coverage.voiced_frames
    );
    assert!(
        coverage.delta_lag_frames > 0,
        "the delta pitch-lag path was never taken"
    );
    assert!(
        coverage.ltp_scaling_frames > 0,
        "the LTP scaling symbol was never decoded"
    );
    assert!(
        coverage.shell_blocks > 100_000,
        "expected >100k shell blocks, got {}",
        coverage.shell_blocks
    );
    assert!(
        coverage.pulses > 100_000,
        "expected >100k pulses, got {}",
        coverage.pulses
    );
    assert!(
        coverage.excitation_samples > 1_000_000,
        "expected >1M reconstructed excitation samples, got {}",
        coverage.excitation_samples
    );
    assert!(
        coverage.ten_ms_frames > 0,
        "no 10 ms frame scored — the two-subframe contour codebooks were never exercised"
    );
    assert!(
        coverage.lbrr_frames > 0,
        "no LBRR frame scored — the in-band FEC frames were never followed"
    );
    assert!(
        coverage.stereo_frames > 0,
        "no stereo frame scored — the side-channel conditional-coding path was never exercised"
    );
    // Rare but real: the §4.2.7.8.2 escape only fires on a very loud block. It is thin coverage on
    // its own, which is why the LSB path also has directed unit tests in `silk::excitation`.
    assert!(
        coverage.lsb_blocks > 0,
        "the pulse-count escape / LSB path was never taken across the whole vector set"
    );
}
