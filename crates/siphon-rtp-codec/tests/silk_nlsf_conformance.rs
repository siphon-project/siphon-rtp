//! SILK NLSF conformance: decode the normalized-LSF stage of real libopus streams and diff every
//! intermediate against libopus' own decode of the same bits, packet by packet.
//!
//! The final acceptance gate for SILK is per-packet range-coder `final_range` equality followed by
//! the RFC 6716 §6 `opus_compare` metric, and neither can run until a whole SILK frame decodes.
//! This stage stops mid-frame — the next symbol after the NLSF interpolation factor is a pitch lag,
//! which belongs to another phase. So the check available at this depth is the strongest one that
//! does not need the packet to finish: an **instrumented libopus** that prints the NLSF stage's own
//! intermediate state (`reference/opus/silk_trace.patch`, `reference/opus/dump_silk_trace.sh`;
//! recipe in CONTRIBUTING.md).
//!
//! Six field groups are compared for every scored frame, which is what makes a mismatch localise:
//!
//! | Trace line | What it pins down |
//! |---|---|
//! | `NLSFIDX`  | the stage-1 codebook index, all stage-2 residual indices, the coded interpolation factor |
//! | `NLSFRES`  | the dequantized Q10 residual, **plus** the unpacked prediction weights and entropy-table indices |
//! | `NLSFRAW`  | the reconstructed NLSFs *before* stabilisation |
//! | `NLSF`     | the stabilised NLSFs |
//! | `NLSF0`    | the interpolated first-half NLSFs (present only when the frame interpolates) |
//! | `LPC0`/`LPC1` | both halves' Q12 LPC coefficients |
//!
//! Splitting `NLSFRAW` from `NLSF` matters: a reconstruction bug and a stabiliser bug look identical
//! in the final vector, and the stabiliser only alters about 5 % of frames, so a broken stabiliser
//! would otherwise hide behind the 95 % that need no repair.
//!
//! **Scope.** Per packet the harness reproduces the LP-layer header for both channels, then the
//! *first* SILK frame's stereo, frame-type, gain and NLSF symbols for the mid channel. It stops at
//! the pitch lag. Consequences, all of them stated rather than papered over:
//!
//! * A packet carrying LBRR data is skipped after the header — LBRR frames interleave excitation
//!   data this phase cannot step over — and both cross-frame anchors (the running log-gain and the
//!   previous NLSF vector) are re-seeded from the dump so the next packet still starts aligned.
//! * A 40/60 ms packet's frames 1.. are not decoded, so its anchors are re-seeded the same way.
//! * A single-frame packet without LBRR re-seeds **nothing**: the harness asserts that the previous
//!   NLSF vector it carried forward on its own already equals libopus'. That is what turns the
//!   interpolation anchor into a real cross-packet check rather than a per-packet one.
//!
//! Skips gracefully when the vectors or the dumps are absent, and refuses to pass vacuously: with
//! vectors present it requires a non-trivial number of scored packets, interpolated frames, frames
//! the stabiliser actually modified, and both codebook orders.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::packet::{self, Mode};
use siphon_rtp_codec::opus::range_coder::RangeDecoder;
use siphon_rtp_codec::opus::silk::decoder::{SilkDecoder, MID_CHANNEL, SIDE_CHANNEL};
use siphon_rtp_codec::opus::silk::frame_type::decode_frame_type;
use siphon_rtp_codec::opus::silk::nlsf::{
    decode_indices, interpolate, nlsf_indices_to_lpc, residual_dequant, stabilize, unpack,
    NO_INTERPOLATION_Q2,
};
use siphon_rtp_codec::opus::silk::nlsf_tables::NlsfCodebook;
use siphon_rtp_codec::opus::silk::stereo_pred::{
    decode_mid_only, decode_stereo_weights, mid_only_flag_is_coded,
};
use siphon_rtp_codec::opus::silk::types::{
    CondCoding, InternalRate, SubframeLayout, MAX_LPC_ORDER,
};

/// The rate the reference decode ran at (`dump_silk_trace.sh` uses `opus_demo -d 48000 2`).
const REFERENCE_RATE_HZ: u32 = 48_000;

/// One packet of an `opus_demo` `.bit` file: `[u32 BE len][u32 BE final_range][payload]`.
struct BitPacket {
    payload: Vec<u8>,
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
        offset += 8;
        if length > 1 << 20 || offset + length > bytes.len() {
            return Err(format!(
                "implausible packet length {length} at offset {offset}"
            ));
        }
        packets.push(BitPacket {
            payload: bytes[offset..offset + length].to_vec(),
        });
        offset += length;
    }
    Ok(packets)
}

/// One `key=value ... values...` line of the dump, kept in the loose form the comparisons need.
#[derive(Debug, Clone, Default)]
struct TraceLine {
    keys: BTreeMap<String, String>,
    values: Vec<i32>,
}

impl TraceLine {
    fn key(&self, name: &str) -> Result<&str, String> {
        self.keys
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("trace line has no {name}="))
    }

    fn number(&self, name: &str) -> Result<i32, String> {
        self.key(name)?
            .parse::<i32>()
            .map_err(|error| format!("{name}: {error}"))
    }

    /// A comma-separated `key=a,b,c` list.
    fn list(&self, name: &str) -> Result<Vec<i32>, String> {
        self.key(name)?
            .split(',')
            .map(|part| {
                part.parse::<i32>()
                    .map_err(|error| format!("{name}: {error}"))
            })
            .collect()
    }
}

/// Parse the dump into `packet index -> (event kind -> lines, in order)`.
type Trace = BTreeMap<usize, BTreeMap<String, Vec<TraceLine>>>;

fn parse_trace(text: &str) -> Result<Trace, String> {
    let mut trace: Trace = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let index_token = tokens.next().ok_or("empty line")?;
        let index: usize = index_token
            .strip_prefix('P')
            .ok_or_else(|| format!("expected P<n>, got {index_token}"))?
            .parse()
            .map_err(|_| format!("bad packet index: {index_token}"))?;
        let kind = tokens.next().ok_or("missing event kind")?.to_string();
        let mut parsed = TraceLine::default();
        for token in tokens {
            if let Some((key, value)) = token.split_once('=') {
                parsed.keys.insert(key.to_string(), value.to_string());
            } else if let Ok(number) = token.parse::<i32>() {
                parsed.values.push(number);
            }
        }
        trace
            .entry(index)
            .or_default()
            .entry(kind)
            .or_default()
            .push(parsed);
    }
    Ok(trace)
}

/// The single line of `kind` whose `u=` field is `unit`.
fn unit_line<'a>(
    events: &'a BTreeMap<String, Vec<TraceLine>>,
    kind: &str,
    unit: i32,
) -> Option<&'a TraceLine> {
    events
        .get(kind)?
        .iter()
        .find(|line| line.number("u").ok() == Some(unit))
}

/// The last `NLSF` line of the packet — what libopus carries into the next packet as `prevNLSF_Q15`.
fn final_nlsf(events: &BTreeMap<String, Vec<TraceLine>>) -> Option<&TraceLine> {
    events.get("NLSF")?.last()
}

/// The running log-gain libopus was left holding after this packet.
fn final_last_gain_index(events: &BTreeMap<String, Vec<TraceLine>>) -> Option<i32> {
    events.get("GAINS")?.last()?.number("last").ok()
}

/// What the run actually exercised, so the harness can prove it was not vacuous.
#[derive(Default, Debug)]
struct Coverage {
    packets: usize,
    nlsf_frames: usize,
    interpolated_frames: usize,
    stabiliser_changed_frames: usize,
    extension_symbols: usize,
    narrowband_frames: usize,
    mediumband_frames: usize,
    wideband_frames: usize,
    chained_anchor_packets: usize,
    lbrr_packets: usize,
}

impl Coverage {
    fn absorb(&mut self, other: &Coverage) {
        self.packets += other.packets;
        self.nlsf_frames += other.nlsf_frames;
        self.interpolated_frames += other.interpolated_frames;
        self.stabiliser_changed_frames += other.stabiliser_changed_frames;
        self.extension_symbols += other.extension_symbols;
        self.narrowband_frames += other.narrowband_frames;
        self.mediumband_frames += other.mediumband_frames;
        self.wideband_frames += other.wideband_frames;
        self.chained_anchor_packets += other.chained_anchor_packets;
        self.lbrr_packets += other.lbrr_packets;
    }
}

fn compare(label: &str, ours: &[i32], theirs: &[i32]) -> Result<(), String> {
    if ours == theirs {
        return Ok(());
    }
    let first = ours
        .iter()
        .zip(theirs.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| ours.len().min(theirs.len()));
    Err(format!(
        "{label}: first difference at index {first} — ours {ours:?} != libopus {theirs:?}"
    ))
}

/// Decode one stream's NLSF stage and compare it, packet by packet, against the dump.
fn check_stream(packets: &[BitPacket], trace: &Trace) -> Result<Coverage, String> {
    let mut silk = SilkDecoder::new(REFERENCE_RATE_HZ, 2).map_err(|e| format!("new: {e:?}"))?;
    let mut coverage = Coverage::default();

    for (index, bit_packet) in packets.iter().enumerate() {
        if bit_packet.payload.is_empty() {
            continue; // DTX / dropped packet: libopus emits no side info for it.
        }
        let events = trace
            .get(&index)
            .ok_or_else(|| format!("packet {index}: no trace events"))?;
        let parsed =
            packet::parse(&bit_packet.payload).map_err(|e| format!("packet {index}: {e:?}"))?;
        if parsed.toc.mode() != Mode::Silk {
            return Err(format!(
                "packet {index}: not SILK-only (mode {:?})",
                parsed.toc.mode()
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
            .map_err(|e| format!("packet {index}: {duration_ms} ms: {e:?}"))?;
        silk.configure(channel_count, rate, duration_ms)
            .map_err(|e| format!("packet {index}: configure: {e:?}"))?;

        let mut decoder = RangeDecoder::new(frame);

        // ── LP-layer header (§4.2.3-4) ────────────────────────────────────────────────────────
        let header = silk
            .decode_lp_layer_header(&mut decoder)
            .map_err(|e| format!("packet {index}: header: {e:?}"))?;
        coverage.packets += 1;

        if header.any_lbrr() {
            // LBRR frames interleave excitation data this phase cannot skip. Re-seed both anchors
            // from the dump so the following packets stay aligned, and score nothing here.
            coverage.lbrr_packets += 1;
            if let Some(last) = final_last_gain_index(events) {
                silk.channel_mut(MID_CHANNEL)
                    .map_err(|e| format!("packet {index}: mid: {e:?}"))?
                    .last_gain_index = last as i8;
            }
            reseed_anchor(&mut silk, index, events)?;
            continue;
        }

        // ── Stereo prediction weights and mid-only flag (§4.2.7.1-2) ──────────────────────────
        if channel_count == 2 {
            let _ = decode_stereo_weights(&mut decoder);
            let side_coded = header
                .channel(SIDE_CHANNEL)
                .map_err(|e| format!("packet {index}: side: {e:?}"))?
                .vad_flags[0];
            if mid_only_flag_is_coded(side_coded) {
                let _ = decode_mid_only(&mut decoder);
            }
        }

        // ── Frame type (§4.2.7.3) and subframe gains (§4.2.7.4) ───────────────────────────────
        let active = header
            .channel(MID_CHANNEL)
            .map_err(|e| format!("packet {index}: mid: {e:?}"))?
            .is_active(0, false);
        let frame_type = decode_frame_type(&mut decoder, active)
            .map_err(|e| format!("packet {index}: frame type: {e:?}"))?;
        let signal_type = frame_type.signal_type();
        // Frame 0 of a packet is always independently coded (dec_API.c:342-345).
        silk.decode_subframe_gains(
            &mut decoder,
            MID_CHANNEL,
            signal_type,
            CondCoding::Independently,
        )
        .map_err(|e| format!("packet {index}: gains: {e:?}"))?;

        // ── NLSF indices (§4.2.7.5.1-2, §4.2.7.5.5) ───────────────────────────────────────────
        let codebook = NlsfCodebook::for_rate(rate);
        let order = codebook.order;
        let indices = decode_indices(&mut decoder, rate, signal_type, layout.subframe_count)
            .map_err(|e| format!("packet {index}: nlsf indices: {e:?}"))?;

        let reference = unit_line(events, "NLSFIDX", 0)
            .ok_or_else(|| format!("packet {index}: no NLSFIDX event for unit 0"))?;
        if reference
            .number("order")
            .map_err(|e| format!("packet {index}: {e}"))?
            != order as i32
        {
            return Err(format!(
                "packet {index}: order {order}, libopus used {}",
                reference.key("order").unwrap_or("?")
            ));
        }
        let ours: Vec<i32> = std::iter::once(indices.stage1_index() as i32)
            .chain(indices.stage2_residuals().iter().map(|&r| i32::from(r)))
            .collect();
        compare(
            &format!("packet {index}: NLSF indices"),
            &ours,
            &reference.values,
        )?;
        let reference_interpolation = reference
            .number("interp")
            .map_err(|e| format!("packet {index}: {e}"))?;
        if i32::from(indices.interpolation_factor_q2) != reference_interpolation {
            return Err(format!(
                "packet {index}: coded interpolation factor {} != libopus {reference_interpolation}",
                indices.interpolation_factor_q2
            ));
        }
        coverage.extension_symbols += indices
            .stage2_residuals()
            .iter()
            .filter(|&&residual| residual.abs() > 4)
            .count();

        // ── The unpacked entropy/prediction selection and the dequantized residual (§4.2.7.5.3) ─
        let unpacked = unpack(codebook, indices.stage1_index());
        let reference = unit_line(events, "NLSFRES", 0)
            .ok_or_else(|| format!("packet {index}: no NLSFRES event"))?;
        let ours: Vec<i32> = unpacked.prediction_q8[..order]
            .iter()
            .map(|&weight| i32::from(weight))
            .collect();
        compare(
            &format!("packet {index}: unpacked prediction weights"),
            &ours,
            &reference
                .list("pred")
                .map_err(|e| format!("packet {index}: {e}"))?,
        )?;
        // The C stores `ec_ix[i]` as a byte offset into the flat table, i.e. pdf_index * 9.
        let ours: Vec<i32> = unpacked.pdf_index[..order]
            .iter()
            .map(|&pdf| pdf as i32 * 9)
            .collect();
        compare(
            &format!("packet {index}: unpacked entropy table indices"),
            &ours,
            &reference
                .list("ecix")
                .map_err(|e| format!("packet {index}: {e}"))?,
        )?;

        let mut residual_q10 = [0i16; MAX_LPC_ORDER];
        residual_dequant(
            &mut residual_q10[..order],
            indices.stage2_residuals(),
            &unpacked.prediction_q8[..order],
            codebook.quant_step_size_q16,
        );
        let ours: Vec<i32> = residual_q10[..order]
            .iter()
            .map(|&r| i32::from(r))
            .collect();
        compare(
            &format!("packet {index}: dequantized NLSF residual"),
            &ours,
            &reference.values,
        )?;

        // ── Reconstruction, before and after stabilisation (§4.2.7.5.3-4) ─────────────────────
        // Re-run the two halves separately so a reconstruction bug and a stabiliser bug cannot
        // hide behind one another.
        let raw_nlsf_q15 = nlsf_reconstruct_only(codebook, &indices, &residual_q10[..order]);
        let reference = unit_line(events, "NLSFRAW", 0)
            .ok_or_else(|| format!("packet {index}: no NLSFRAW event"))?;
        let ours: Vec<i32> = raw_nlsf_q15[..order]
            .iter()
            .map(|&n| i32::from(n))
            .collect();
        compare(
            &format!("packet {index}: reconstructed NLSFs (pre-stabilisation)"),
            &ours,
            &reference.values,
        )?;

        let mut nlsf_q15 = raw_nlsf_q15;
        stabilize(&mut nlsf_q15[..order], codebook.delta_min_q15);
        if nlsf_q15[..order] != raw_nlsf_q15[..order] {
            coverage.stabiliser_changed_frames += 1;
        }
        let reference =
            unit_line(events, "NLSF", 0).ok_or_else(|| format!("packet {index}: no NLSF event"))?;
        let ours: Vec<i32> = nlsf_q15[..order].iter().map(|&n| i32::from(n)).collect();
        compare(
            &format!("packet {index}: stabilised NLSFs"),
            &ours,
            &reference.values,
        )?;

        // ── Interpolation and NLSF → LPC (§4.2.7.5.5, §4.2.7.5.8) ─────────────────────────────
        let (first_frame_after_reset, previous_nlsf) = {
            let channel = silk
                .channel(MID_CHANNEL)
                .map_err(|e| format!("packet {index}: mid: {e:?}"))?;
            (channel.first_frame_after_reset, channel.prev_nlsf_q15)
        };
        let effective_factor = if first_frame_after_reset {
            NO_INTERPOLATION_Q2
        } else {
            indices.interpolation_factor_q2
        };
        if effective_factor < NO_INTERPOLATION_Q2 {
            let mut interpolated = [0i16; MAX_LPC_ORDER];
            interpolate(
                &mut interpolated[..order],
                &previous_nlsf[..order],
                &nlsf_q15[..order],
                effective_factor,
            );
            let reference = unit_line(events, "NLSF0", 0).ok_or_else(|| {
                format!("packet {index}: interpolating with factor {effective_factor} but libopus emitted no NLSF0")
            })?;
            let ours: Vec<i32> = interpolated[..order]
                .iter()
                .map(|&n| i32::from(n))
                .collect();
            compare(
                &format!("packet {index}: interpolated NLSFs"),
                &ours,
                &reference.values,
            )?;
            coverage.interpolated_frames += 1;
        } else if unit_line(events, "NLSF0", 0).is_some() {
            return Err(format!(
                "packet {index}: libopus interpolated but our effective factor is {effective_factor}"
            ));
        }

        // The full stage, driven through the same entry point the synthesis phase will call.
        let coefficients = {
            let channel = silk
                .channel_mut(MID_CHANNEL)
                .map_err(|e| format!("packet {index}: mid: {e:?}"))?;
            nlsf_indices_to_lpc(
                &indices,
                rate,
                &mut channel.prev_nlsf_q15,
                channel.first_frame_after_reset,
                channel.loss_count != 0,
            )
        };
        for (half, coefficients_q12) in [
            ("LPC0", &coefficients.first_half_q12),
            ("LPC1", &coefficients.second_half_q12),
        ] {
            let reference = unit_line(events, half, 0)
                .ok_or_else(|| format!("packet {index}: no {half} event"))?;
            if reference
                .number("loss")
                .map_err(|e| format!("packet {index}: {e}"))?
                != 0
            {
                return Err(format!(
                    "packet {index}: libopus reports a concealed frame; these streams have no loss"
                ));
            }
            let ours: Vec<i32> = coefficients_q12[..order]
                .iter()
                .map(|&c| i32::from(c))
                .collect();
            compare(
                &format!("packet {index}: {half} coefficients"),
                &ours,
                &reference.values,
            )?;
        }
        coverage.nlsf_frames += 1;
        match rate {
            InternalRate::Narrow8k => coverage.narrowband_frames += 1,
            InternalRate::Medium12k => coverage.mediumband_frames += 1,
            InternalRate::Wide16k => coverage.wideband_frames += 1,
        }

        // libopus clears `first_frame_after_reset` at the end of every decoded frame
        // (decode_frame.c:130). That belongs to the synthesis phase, so the harness does it here.
        silk.channel_mut(MID_CHANNEL)
            .map_err(|e| format!("packet {index}: mid: {e:?}"))?
            .first_frame_after_reset = false;

        // Cross-packet anchor. A single-frame packet's anchor is already exactly libopus' (no later
        // frame touched it), so verify instead of overwriting — that is what makes the interpolation
        // anchor a real cross-packet check. A multi-frame packet's frames 1.. were not decoded, so
        // re-seed from the dump's final NLSF line.
        if layout.frames_per_packet == 1 {
            let reference =
                final_nlsf(events).ok_or_else(|| format!("packet {index}: no final NLSF event"))?;
            let ours: Vec<i32> = silk
                .channel(MID_CHANNEL)
                .map_err(|e| format!("packet {index}: mid: {e:?}"))?
                .prev_nlsf_q15[..order]
                .iter()
                .map(|&n| i32::from(n))
                .collect();
            compare(
                &format!("packet {index}: carried interpolation anchor"),
                &ours,
                &reference.values,
            )?;
            coverage.chained_anchor_packets += 1;
        } else {
            reseed_anchor(&mut silk, index, events)?;
        }
    }

    Ok(coverage)
}

/// Reconstruction only (`NLSF_decode.c:83-89`), without the stabilisation `silk_NLSF_decode` runs
/// straight afterwards. The library deliberately exposes only the combined `nlsf::decode`, because a
/// half-stabilised vector has no legitimate use on the decode path; the harness rebuilds it here
/// from the public pieces so a reconstruction bug and a stabiliser bug stay distinguishable.
fn nlsf_reconstruct_only(
    codebook: &NlsfCodebook,
    indices: &siphon_rtp_codec::opus::silk::nlsf::NlsfIndices,
    residual_q10: &[i16],
) -> [i16; MAX_LPC_ORDER] {
    let vector_q8 = codebook.cb1_vector_q8(indices.stage1_index());
    let weights_q9 = codebook.cb1_weights_q9(indices.stage1_index());
    let mut out = [0i16; MAX_LPC_ORDER];
    for coefficient in 0..codebook.order {
        let scaled =
            (i32::from(residual_q10[coefficient]) << 14) / i32::from(weights_q9[coefficient]);
        let value = scaled + (i32::from(vector_q8[coefficient]) << 7);
        out[coefficient] = value.clamp(0, 32_767) as i16;
    }
    out
}

/// Copy libopus' end-of-packet NLSF vector into our channel state, for the packets the harness could
/// not follow to the end.
fn reseed_anchor(
    silk: &mut SilkDecoder,
    index: usize,
    events: &BTreeMap<String, Vec<TraceLine>>,
) -> Result<(), String> {
    let Some(reference) = final_nlsf(events) else {
        return Ok(());
    };
    let channel = silk
        .channel_mut(MID_CHANNEL)
        .map_err(|e| format!("packet {index}: mid: {e:?}"))?;
    for (slot, &value) in channel
        .prev_nlsf_q15
        .iter_mut()
        .zip(reference.values.iter())
    {
        *slot = value as i16;
    }
    channel.first_frame_after_reset = false;
    Ok(())
}

/// `reference/opus/silk_only`, if present.
fn vector_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_only");
    dir.is_dir().then_some(dir)
}

#[test]
fn silk_nlsf_matches_libopus() {
    let Some(dir) = vector_dir() else {
        eprintln!("silk NLSF conformance: vectors not present — skipping");
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
            "silk NLSF conformance: no .bit files in {} — skipping",
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
        let Ok(bytes) = std::fs::read(bit_path) else {
            skipped.push((name, "unreadable .bit".to_string()));
            continue;
        };
        let Ok(trace_text) = std::fs::read_to_string(bit_path.with_extension("trace")) else {
            skipped.push((
                name,
                "no .trace — run reference/opus/dump_silk_trace.sh".to_string(),
            ));
            continue;
        };
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
        // A dump from an instrumented build that predates the NLSF field group proves nothing here.
        if !trace.values().any(|events| events.contains_key("NLSFIDX")) {
            skipped.push((
                name,
                "trace has no NLSF field group — rebuild reference/opus/build-trace".to_string(),
            ));
            continue;
        }
        match check_stream(&packets, &trace) {
            Ok(stream_coverage) => {
                coverage.absorb(&stream_coverage);
                passed.push(name);
            }
            Err(reason) => failed.push((name, reason)),
        }
    }

    eprintln!(
        "silk NLSF conformance: {} passed, {} skipped, {} failed",
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
        "silk NLSF: {} stream(s) failed: {failed:?}",
        failed.len()
    );
    assert!(
        !passed.is_empty(),
        "silk NLSF: {} stream(s) present but none scored — are the .trace dumps rebuilt? skipped={skipped:?}",
        bit_files.len()
    );

    // Non-vacuous: the run must have exercised every branch of the stage, not merely executed.
    assert!(
        coverage.nlsf_frames > 5_000,
        "expected >5k NLSF frames scored, got {}",
        coverage.nlsf_frames
    );
    assert!(
        coverage.interpolated_frames > 100,
        "expected >100 interpolated frames — the §4.2.7.5.5 path was barely exercised ({})",
        coverage.interpolated_frames
    );
    assert!(
        coverage.stabiliser_changed_frames > 100,
        "expected >100 frames the stabiliser actually modified; got {} — §4.2.7.5.4 is untested",
        coverage.stabiliser_changed_frames
    );
    assert!(
        coverage.extension_symbols > 0,
        "no stage-2 extension symbol was ever decoded — the ±4 saturation path is untested"
    );
    assert!(
        coverage.chained_anchor_packets > 1_000,
        "expected >1k packets to verify the carried interpolation anchor, got {}",
        coverage.chained_anchor_packets
    );
    assert!(
        coverage.narrowband_frames > 0 && coverage.wideband_frames > 0,
        "both NLSF codebooks must be exercised: {coverage:?}"
    );
    assert!(
        coverage.mediumband_frames > 0,
        "mediumband uses the order-10 codebook at 12 kHz and was never scored: {coverage:?}"
    );
}
