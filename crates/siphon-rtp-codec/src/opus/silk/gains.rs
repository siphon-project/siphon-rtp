//! Subframe quantization gains (RFC 6716 §4.2.7.4) — libopus `decode_indices.c:59-75` for the index
//! decode and `gain_quant.c:94-125` (`silk_gains_dequant`) for the dequantisation.
//!
//! One gain per 5 ms subframe, uniformly quantized to 6 bits on a log scale: ~1.369 dB per step over
//! roughly 1.94 dB to 88.21 dB. The gain sets the excitation quantizer's step size, so it is the single
//! biggest lever on a subframe's loudness — and it is coded **differentially**, which makes
//! [`super::decoder::ChannelState::last_gain_index`] a piece of state that has to be right across
//! frames as well as within them.
//!
//! Two coding modes (RFC 6716 §4.2.7.4):
//!
//! * **Independent** — first subframe of a SILK frame that has no usable predecessor of the same type
//!   (regular or LBRR) in this Opus frame. 3 MSBs from a signal-type-dependent PDF plus 3 raw-ish LSBs
//!   from a flat PDF, then a floor at `previous - 16` so the gain cannot drop more than ~21.8 dB in one
//!   step.
//! * **Delta** — every other subframe, and the first subframe of a conditionally coded frame. One
//!   symbol in 0..=40, applied relative to the previous subframe's log-gain with a *doubled* step size
//!   once the increment would otherwise be unable to reach the top of the range.
//!
//! The step doubling is the subtle part. The C writes it as a threshold comparison
//! (`gain_quant.c:113-118`); RFC 6716 §4.2.7.4 writes the same thing as
//! `clamp(0, max(2*delta - 16, previous + delta - 4), 63)`. Both forms are implemented — one in the
//! code, one in the tests — and required to agree over every reachable `(previous, delta)` pair.

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::decoder::SilkDecoder;
use crate::opus::silk::fixed::{limit_int, log2lin, smulwb};
use crate::opus::silk::tables::{DELTA_GAIN_ICDF, GAIN_ICDF, UNIFORM8_ICDF};
use crate::opus::silk::types::{
    CondCoding, SignalType, MAX_DELTA_GAIN_QUANT, MAX_NB_SUBFR, MAX_QGAIN_DB, MIN_DELTA_GAIN_QUANT,
    MIN_QGAIN_DB, N_LEVELS_QGAIN,
};
use crate::CodecError;

/// `ftb` for every SILK ICDF symbol: total frequency 256.
const ICDF_FTB: u32 = 8;

/// How far the 3 MSBs are shifted up to make room for the 3 LSBs (`decode_indices.c:68`).
const GAIN_MSB_SHIFT: usize = 3;

/// Largest downward jump an independently coded gain may make, in index steps
/// (`gain_quant.c:106-107`): "Gain index is not allowed to go down more than 16 steps (~21.8 dB)".
const MAX_INDEPENDENT_GAIN_DECREASE: i32 = 16;

/// `OFFSET` from `gain_quant.c:34` — `(MIN_QGAIN_DB * 128) / 6 + 16 * 128`, i.e. 2090 in Q7. RFC 6716
/// §4.2.7.4 states the same constant as a literal.
const GAIN_OFFSET_Q7: i32 = (MIN_QGAIN_DB * 128) / 6 + 16 * 128;

/// `INV_SCALE_Q16` from `gain_quant.c:36` —
/// `(65536 * (((MAX_QGAIN_DB - MIN_QGAIN_DB) * 128) / 6)) / (N_LEVELS_QGAIN - 1)`, i.e. 1907825. RFC
/// 6716 §4.2.7.4 writes it as the hex literal `0x1D1C71`. Note the inner `/ 6` truncates *before* the
/// multiply, so the constant is not simply `86 * 128 / 6 * 65536 / 63`.
const INV_SCALE_Q16: i32 =
    (65536 * (((MAX_QGAIN_DB - MIN_QGAIN_DB) * 128) / 6)) / (N_LEVELS_QGAIN - 1);

/// Cap on the Q7 log-gain handed to `silk_log2lin` (`gain_quant.c:123`, "3967 = 31 in Q7"). Unreachable
/// on the decode path — the largest index, 63, only reaches 3923 — but ported because it is what bounds
/// `log2lin` away from its saturating branch.
const MAX_LOG_GAIN_Q7: i32 = 3967;

/// The gain indices read from the bitstream, before dequantisation (libopus
/// `SideInfoIndices.GainsIndices`).
///
/// Index 0 means different things in the two coding modes: an absolute 6-bit log-gain when the frame is
/// independently coded, or a delta symbol in 0..=40 when it is conditionally coded. Indices 1.. are
/// always delta symbols. [`dequantize_gains`] is what resolves the distinction, so the two must be
/// given the same `conditional` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GainIndices {
    /// Per-subframe indices; only `0..count` are meaningful.
    pub indices: [i8; MAX_NB_SUBFR],
    /// Number of 5 ms subframes coded — `nb_subfr`, 2 or 4.
    pub count: usize,
    /// Whether index 0 was delta-coded (the C's `condCoding == CODE_CONDITIONALLY`).
    pub conditional: bool,
}

/// The dequantized subframe gains (libopus `silk_decoder_control.Gains_Q16`, `structs.h:345`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubframeGains {
    /// Linear gain per subframe in Q16; only `0..count` are meaningful. Always in
    /// 81920..=1686110208 (RFC 6716 §4.2.7.4).
    pub gains_q16: [i32; MAX_NB_SUBFR],
    /// The 6-bit log-gain index each subframe resolved to, 0..=63. Kept because the excitation decode
    /// and the noise-shaping quantiser reason in the log domain.
    pub log_gains: [i8; MAX_NB_SUBFR],
    /// The raw coded indices these gains came from ([`GainIndices::indices`]), carried through so a
    /// caller can compare against a reference decoder's side info without re-deriving them.
    pub indices: [i8; MAX_NB_SUBFR],
    /// Number of 5 ms subframes.
    pub count: usize,
}

/// Decode the per-subframe gain indices (RFC 6716 §4.2.7.4; libopus `decode_indices.c:59-75`).
///
/// `signal_type` comes from the frame type decoded immediately before (§4.2.7.3) and selects the MSB
/// PDF; getting it wrong reads the right number of symbols but the wrong values. `subframe_count` is
/// `nb_subfr` — 2 for a 10 ms Opus frame, 4 otherwise.
pub fn decode_gain_indices(
    decoder: &mut RangeDecoder<'_>,
    signal_type: SignalType,
    cond_coding: CondCoding,
    subframe_count: usize,
) -> Result<GainIndices, CodecError> {
    if subframe_count == 0 || subframe_count > MAX_NB_SUBFR {
        return Err(CodecError::Unsupported(
            "silk: subframe count must be 1..=4",
        ));
    }
    let conditional = cond_coding.is_conditional();
    let mut indices = [0i8; MAX_NB_SUBFR];

    // First subframe: delta, or absolute in two pieces (MSBs then LSBs).
    indices[0] = if conditional {
        decoder.dec_icdf(&DELTA_GAIN_ICDF, ICDF_FTB) as i8
    } else {
        let msb = decoder.dec_icdf(&GAIN_ICDF[signal_type.index()], ICDF_FTB);
        let lsb = decoder.dec_icdf(&UNIFORM8_ICDF, ICDF_FTB);
        // (msb << 3) + lsb is 0..=63, so it always fits i8 (decode_indices.c:68-69).
        ((msb << GAIN_MSB_SHIFT) + lsb) as i8
    };

    // Remaining subframes: always delta-coded (decode_indices.c:73-75).
    for slot in indices.iter_mut().take(subframe_count).skip(1) {
        *slot = decoder.dec_icdf(&DELTA_GAIN_ICDF, ICDF_FTB) as i8;
    }

    Ok(GainIndices {
        indices,
        count: subframe_count,
        conditional,
    })
}

/// Turn a single 6-bit log-gain index into a linear Q16 gain (`gain_quant.c:122-123`; RFC 6716
/// §4.2.7.4 `gain_Q16[k] = silk_log2lin((0x1D1C71*log_gain>>16) + 2090)`).
///
/// `log_gain` must be 0..=63; anything outside is clamped, matching the `silk_LIMIT_int` the C applies
/// immediately before this line.
#[must_use]
pub fn log_gain_to_q16(log_gain: i32) -> i32 {
    let log_gain = limit_int(log_gain, 0, N_LEVELS_QGAIN - 1);
    log2lin(
        smulwb(INV_SCALE_Q16, log_gain)
            .saturating_add(GAIN_OFFSET_Q7)
            .min(MAX_LOG_GAIN_Q7),
    )
}

/// Dequantize the gain indices (libopus `silk_gains_dequant`, `gain_quant.c:94-125`).
///
/// `last_gain_index` is the running log-gain — the C's `psDec->LastGainIndex` — and is updated in
/// place, because every subsequent subframe *and* the next frame's first delta are measured against it.
pub fn dequantize_gains(indices: &GainIndices, last_gain_index: &mut i8) -> SubframeGains {
    let mut gains_q16 = [0i32; MAX_NB_SUBFR];
    let mut log_gains = [0i8; MAX_NB_SUBFR];

    for subframe in 0..indices.count {
        let index = i32::from(indices.indices[subframe]);
        let mut running = i32::from(*last_gain_index);

        if subframe == 0 && !indices.conditional {
            // Absolute, floored at 16 steps below the previous gain (gain_quant.c:106-107). After a
            // reset `LastGainIndex` is seeded to 10, so the floor is -6 and this is automatically inert
            // — which is how libopus satisfies RFC 6716 §4.2.7.4's "the clamping is skipped after a
            // decoder reset" without a special case.
            running = index.max(running - MAX_INDEPENDENT_GAIN_DECREASE);
        } else {
            // Delta. `ind_tmp` is the signed increment; `threshold` is the point past which the step
            // size doubles so the top of the range stays reachable (gain_quant.c:110-118).
            let increment = index + MIN_DELTA_GAIN_QUANT;
            let threshold = 2 * MAX_DELTA_GAIN_QUANT - N_LEVELS_QGAIN + running;
            running += if increment > threshold {
                (increment << 1) - threshold
            } else {
                increment
            };
        }

        let running = limit_int(running, 0, N_LEVELS_QGAIN - 1);
        // 0..=63 always fits i8.
        *last_gain_index = running as i8;
        log_gains[subframe] = running as i8;
        gains_q16[subframe] = log_gain_to_q16(running);
    }

    SubframeGains {
        gains_q16,
        log_gains,
        indices: indices.indices,
        count: indices.count,
    }
}

impl SilkDecoder {
    /// Decode and dequantize one SILK frame's subframe gains for `channel_index`, advancing that
    /// channel's running log-gain — the `silk_decode_indices` + `silk_gains_dequant` pair, wired to the
    /// state they actually mutate (`decode_parameters.c:46-47`).
    ///
    /// Uses the channel's configured `nb_subfr`, so it cannot disagree with the frame geometry.
    pub fn decode_subframe_gains(
        &mut self,
        decoder: &mut RangeDecoder<'_>,
        channel_index: usize,
        signal_type: SignalType,
        cond_coding: CondCoding,
    ) -> Result<SubframeGains, CodecError> {
        let subframe_count = self.channel(channel_index)?.subframe_count();
        let indices = decode_gain_indices(decoder, signal_type, cond_coding, subframe_count)?;
        let channel = self.channel_mut(channel_index)?;
        Ok(dequantize_gains(&indices, &mut channel.last_gain_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;
    use crate::opus::silk::types::InternalRate;

    /// RFC 6716 §4.2.7.4's delta formula, written out independently of the implementation:
    /// `log_gain = clamp(0, max(2*delta_gain_index - 16, previous_log_gain + delta_gain_index - 4), 63)`.
    fn reference_delta_log_gain(previous: i32, delta: i32) -> i32 {
        (2 * delta - 16)
            .max(previous + delta - 4)
            .clamp(0, N_LEVELS_QGAIN - 1)
    }

    fn encode_gain_indices(
        signal_type: SignalType,
        conditional: bool,
        indices: &[i32],
        buffer: &mut [u8],
    ) {
        let mut encoder = RangeEncoder::new(buffer);
        if conditional {
            encoder.enc_icdf(indices[0] as usize, &DELTA_GAIN_ICDF, ICDF_FTB);
        } else {
            let absolute = indices[0] as usize;
            encoder.enc_icdf(
                absolute >> GAIN_MSB_SHIFT,
                &GAIN_ICDF[signal_type.index()],
                ICDF_FTB,
            );
            encoder.enc_icdf(absolute & 0x7, &UNIFORM8_ICDF, ICDF_FTB);
        }
        for &index in &indices[1..] {
            encoder.enc_icdf(index as usize, &DELTA_GAIN_ICDF, ICDF_FTB);
        }
        encoder.done();
        assert!(!encoder.error());
    }

    #[test]
    fn derived_constants_match_the_c_and_the_rfc() {
        // gain_quant.c:34-36, and RFC 6716 §4.2.7.4's literals.
        assert_eq!(GAIN_OFFSET_Q7, 2090);
        assert_eq!(INV_SCALE_Q16, 0x1D_1C71);
        assert_eq!(INV_SCALE_Q16, 1_907_825);
        // The inner truncation is real: rounding it instead gives a different constant.
        assert_eq!(((MAX_QGAIN_DB - MIN_QGAIN_DB) * 128) / 6, 1834);
        assert_eq!(MAX_LOG_GAIN_Q7, 3967);
    }

    /// The 64-entry gain ladder, end to end. RFC 6716 §4.2.7.4 states the range as
    /// 81920..=1686110208 in Q16 and the resolution as ~1.369 dB per step; both are checked here, which
    /// pins the whole log-gain → Q16 path (offset, scale, `smulwb` truncation, `log2lin`).
    #[test]
    fn the_full_gain_ladder_spans_the_rfc_range_monotonically() {
        let ladder: Vec<i32> = (0..N_LEVELS_QGAIN).map(log_gain_to_q16).collect();
        assert_eq!(ladder[0], 81_920, "minimum gain, ~1.25 in Q16");
        assert_eq!(
            ladder[(N_LEVELS_QGAIN - 1) as usize],
            1_686_110_208,
            "maximum gain, ~25728 in Q16"
        );
        for index in 1..ladder.len() {
            assert!(
                ladder[index] > ladder[index - 1],
                "gain ladder must be strictly increasing at {index}"
            );
        }
        // ~1.369 dB per step: 63 steps must span 20*log10(1686110208 / 81920) ≈ 86.27 dB.
        let span_db = 20.0 * (f64::from(ladder[63]) / f64::from(ladder[0])).log10();
        assert!(
            (86.0..87.0).contains(&span_db),
            "gain ladder spans {span_db} dB, expected ~86.3"
        );
    }

    #[test]
    fn log_gain_to_q16_clamps_out_of_range_input() {
        assert_eq!(log_gain_to_q16(-1), log_gain_to_q16(0));
        assert_eq!(log_gain_to_q16(64), log_gain_to_q16(63));
        assert_eq!(log_gain_to_q16(i32::MAX), log_gain_to_q16(63));
        assert_eq!(log_gain_to_q16(i32::MIN), log_gain_to_q16(0));
    }

    /// The whole delta space: 64 previous log-gains × 41 delta symbols, checked against the RFC's
    /// independently written `max`/`clamp` formula. This is where the step-size doubling lives, and it
    /// is the one place the C's threshold form and the RFC's max form could plausibly disagree.
    #[test]
    fn delta_coding_matches_the_rfc_formula_over_the_whole_space() {
        for previous in 0..N_LEVELS_QGAIN {
            for delta in 0..DELTA_GAIN_ICDF.len() as i32 {
                let indices = GainIndices {
                    indices: [delta as i8, 0, 0, 0],
                    count: 1,
                    conditional: true,
                };
                let mut last = previous as i8;
                let gains = dequantize_gains(&indices, &mut last);
                let expected = reference_delta_log_gain(previous, delta);
                assert_eq!(
                    i32::from(gains.log_gains[0]),
                    expected,
                    "previous={previous} delta={delta}"
                );
                assert_eq!(i32::from(last), expected, "running index must be updated");
                assert_eq!(gains.gains_q16[0], log_gain_to_q16(expected));
            }
        }
    }

    /// The doubling threshold really does engage, and only above it. `threshold = 8 + previous`, so for
    /// `previous = 0` a delta symbol above 12 doubles.
    #[test]
    fn the_step_size_doubles_only_past_the_threshold() {
        // delta = 12 -> increment 8, threshold 8: not greater, so plain accumulation.
        assert_eq!(reference_delta_log_gain(0, 12), 8);
        // delta = 13 -> increment 9 > 8: doubled, 2*13 - 16 = 10, not 9.
        assert_eq!(reference_delta_log_gain(0, 13), 10);
        // The maximum symbol must be able to reach the top of the range from the bottom.
        assert_eq!(reference_delta_log_gain(0, 40), 63);
        for previous in 0..N_LEVELS_QGAIN {
            assert_eq!(
                reference_delta_log_gain(previous, 40),
                63,
                "delta 40 must always reach the maximum gain"
            );
        }
    }

    /// An independently coded gain is absolute, but floored 16 steps below the previous one
    /// (`gain_quant.c:106-107`).
    #[test]
    fn independent_coding_floors_at_sixteen_steps_down() {
        for (previous, index, expected) in [
            (63i32, 63i32, 63i32),
            (63, 0, 47),  // floor: 63 - 16
            (63, 47, 47), // exactly the floor
            (63, 48, 48), // above the floor, so the coded value wins
            (10, 0, 0),   // the reset seed makes the floor -6, i.e. inert
            (10, 5, 5),
            (0, 0, 0),
        ] {
            let indices = GainIndices {
                indices: [index as i8, 0, 0, 0],
                count: 1,
                conditional: false,
            };
            let mut last = previous as i8;
            let gains = dequantize_gains(&indices, &mut last);
            assert_eq!(
                i32::from(gains.log_gains[0]),
                expected,
                "previous={previous} index={index}"
            );
        }
    }

    /// The reset seed of 10 makes the independent-coding floor unreachable, which is exactly RFC 6716
    /// §4.2.7.4's "the clamping is skipped after a decoder reset" — libopus needs no special case.
    #[test]
    fn the_reset_seed_makes_the_independent_floor_inert() {
        for index in 0..N_LEVELS_QGAIN {
            let indices = GainIndices {
                indices: [index as i8, 0, 0, 0],
                count: 1,
                conditional: false,
            };
            let mut last = 10i8; // ChannelState's LAST_GAIN_INDEX_RESET
            let gains = dequantize_gains(&indices, &mut last);
            assert_eq!(
                i32::from(gains.log_gains[0]),
                index,
                "a fresh decoder must decode the coded index verbatim"
            );
        }
    }

    #[test]
    fn independent_index_is_msbs_then_lsbs() {
        for signal_type in [
            SignalType::Inactive,
            SignalType::Unvoiced,
            SignalType::Voiced,
        ] {
            for absolute in [0i32, 1, 7, 8, 31, 32, 62, 63] {
                let mut buffer = [0u8; 64];
                encode_gain_indices(signal_type, false, &[absolute], &mut buffer);
                let mut decoder = RangeDecoder::new(&buffer);
                let indices =
                    decode_gain_indices(&mut decoder, signal_type, CondCoding::Independently, 1)
                        .expect("valid");
                assert_eq!(
                    i32::from(indices.indices[0]),
                    absolute,
                    "{signal_type:?} index {absolute}"
                );
                assert!(!indices.conditional);
            }
        }
    }

    /// Every signal type uses a different MSB PDF, so the same bitstream decodes to different indices —
    /// which is why the frame type must be decoded first.
    #[test]
    fn the_signal_type_selects_the_msb_pdf() {
        let mut buffer = [0u8; 64];
        encode_gain_indices(SignalType::Voiced, false, &[40], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let correct = decode_gain_indices(
            &mut decoder,
            SignalType::Voiced,
            CondCoding::Independently,
            1,
        )
        .expect("valid");
        assert_eq!(correct.indices[0], 40);

        let mut decoder = RangeDecoder::new(&buffer);
        let wrong = decode_gain_indices(
            &mut decoder,
            SignalType::Inactive,
            CondCoding::Independently,
            1,
        )
        .expect("total pdf");
        assert_ne!(
            wrong.indices[0], 40,
            "the inactive PDF must not decode the voiced stream the same way"
        );
    }

    /// A conditionally coded frame delta-codes even its *first* subframe — one symbol, not two
    /// (`decode_indices.c:63-65`).
    #[test]
    fn conditional_coding_reads_one_symbol_for_the_first_subframe() {
        let mut independent_buffer = [0u8; 64];
        encode_gain_indices(SignalType::Voiced, false, &[40], &mut independent_buffer);
        let mut conditional_buffer = [0u8; 64];
        encode_gain_indices(SignalType::Voiced, true, &[20], &mut conditional_buffer);

        let mut decoder = RangeDecoder::new(&conditional_buffer);
        let indices = decode_gain_indices(
            &mut decoder,
            SignalType::Voiced,
            CondCoding::Conditionally,
            1,
        )
        .expect("valid");
        assert_eq!(indices.indices[0], 20);
        assert!(indices.conditional);

        // The two independent-ish regimes both code an absolute first gain.
        for cond_coding in [
            CondCoding::Independently,
            CondCoding::IndependentlyNoLtpScaling,
        ] {
            let mut decoder = RangeDecoder::new(&independent_buffer);
            let indices = decode_gain_indices(&mut decoder, SignalType::Voiced, cond_coding, 1)
                .expect("valid");
            assert_eq!(indices.indices[0], 40, "{cond_coding:?}");
            assert!(!indices.conditional);
        }
    }

    #[test]
    fn all_four_subframes_are_decoded_in_order() {
        let mut buffer = [0u8; 64];
        encode_gain_indices(SignalType::Unvoiced, false, &[35, 4, 40, 0], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let indices = decode_gain_indices(
            &mut decoder,
            SignalType::Unvoiced,
            CondCoding::Independently,
            4,
        )
        .expect("valid");
        assert_eq!(indices.indices, [35, 4, 40, 0]);
        assert_eq!(indices.count, 4);

        // ...and the gains chain: subframe 0 absolute at 35, then three deltas off it.
        let mut last = 10i8;
        let gains = dequantize_gains(&indices, &mut last);
        assert_eq!(gains.count, 4);
        let mut expected_previous = 35i32;
        assert_eq!(i32::from(gains.log_gains[0]), expected_previous);
        for (subframe, delta) in [(1usize, 4i32), (2, 40), (3, 0)] {
            expected_previous = reference_delta_log_gain(expected_previous, delta);
            assert_eq!(
                i32::from(gains.log_gains[subframe]),
                expected_previous,
                "subframe {subframe}"
            );
        }
        assert_eq!(i32::from(last), expected_previous);
    }

    /// A 10 ms frame has two subframes, so only two gains are coded — reading four would consume two
    /// symbols that belong to the NLSF stage.
    #[test]
    fn a_two_subframe_frame_reads_only_two_gains() {
        let mut buffer = [0u8; 64];
        encode_gain_indices(SignalType::Voiced, false, &[20, 6], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let two = decode_gain_indices(
            &mut decoder,
            SignalType::Voiced,
            CondCoding::Independently,
            2,
        )
        .expect("valid");
        assert_eq!(two.count, 2);
        assert_eq!(two.indices[..2], [20, 6]);
        assert_eq!(two.indices[2..], [0, 0], "untouched slots stay zero");
        let after_two = decoder.tell_frac();

        let mut decoder = RangeDecoder::new(&buffer);
        let _ = decode_gain_indices(
            &mut decoder,
            SignalType::Voiced,
            CondCoding::Independently,
            4,
        )
        .expect("valid");
        assert!(
            decoder.tell_frac() > after_two,
            "four subframes must consume strictly more of the stream"
        );
    }

    #[test]
    fn rejects_an_illegal_subframe_count() {
        let buffer = [0u8; 8];
        let mut decoder = RangeDecoder::new(&buffer);
        assert!(decode_gain_indices(
            &mut decoder,
            SignalType::Voiced,
            CondCoding::Independently,
            0
        )
        .is_err());
        assert!(decode_gain_indices(
            &mut decoder,
            SignalType::Voiced,
            CondCoding::Independently,
            5
        )
        .is_err());
    }

    /// Whatever the payload, every decoded gain is a legal Q16 gain inside the RFC's range and the
    /// running index stays in 0..=63 — no panic, no out-of-range state.
    #[test]
    fn arbitrary_payloads_yield_legal_gains_without_panicking() {
        for seed in 0u32..1500 {
            let length = seed % 6;
            let payload: Vec<u8> = (0..length)
                .map(|k| (seed.wrapping_mul(2_654_435_761).wrapping_add(k) >> 7) as u8)
                .collect();
            for conditional in [false, true] {
                let cond_coding = if conditional {
                    CondCoding::Conditionally
                } else {
                    CondCoding::Independently
                };
                let mut decoder = RangeDecoder::new(&payload);
                let indices = decode_gain_indices(
                    &mut decoder,
                    SignalType::Voiced,
                    cond_coding,
                    MAX_NB_SUBFR,
                )
                .expect("legal geometry");
                let mut last = 10i8;
                let gains = dequantize_gains(&indices, &mut last);
                assert!((0..=63).contains(&last));
                for subframe in 0..gains.count {
                    assert!((0..=63).contains(&gains.log_gains[subframe]));
                    assert!(
                        (81_920..=1_686_110_208).contains(&gains.gains_q16[subframe]),
                        "gain {} out of the RFC range",
                        gains.gains_q16[subframe]
                    );
                }
            }
        }
    }

    /// The decoder-level wrapper must carry the running log-gain across frames: a delta-coded frame
    /// following an absolute one has to see the previous frame's last index.
    #[test]
    fn the_running_log_gain_carries_across_frames() {
        let mut silk = SilkDecoder::new(48_000, 1).expect("decoder");
        silk.configure(1, InternalRate::Wide16k, 20).expect("20 ms");
        assert_eq!(
            silk.channel(0).expect("mid").last_gain_index,
            10,
            "seeded by set_internal_rate"
        );

        let mut buffer = [0u8; 64];
        encode_gain_indices(SignalType::Voiced, false, &[50, 4, 4, 4], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let first = silk
            .decode_subframe_gains(
                &mut decoder,
                0,
                SignalType::Voiced,
                CondCoding::Independently,
            )
            .expect("valid");
        assert_eq!(i32::from(first.log_gains[0]), 50);
        let carried = first.log_gains[3];
        assert_eq!(silk.channel(0).expect("mid").last_gain_index, carried);

        // Next frame, conditionally coded: its first gain is a delta off `carried`.
        let mut buffer = [0u8; 64];
        encode_gain_indices(SignalType::Voiced, true, &[6, 4, 4, 4], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let second = silk
            .decode_subframe_gains(
                &mut decoder,
                0,
                SignalType::Voiced,
                CondCoding::Conditionally,
            )
            .expect("valid");
        assert_eq!(
            i32::from(second.log_gains[0]),
            reference_delta_log_gain(i32::from(carried), 6)
        );
    }

    /// A 10 ms configuration makes the wrapper read two gains, driven purely by the channel's
    /// configured geometry.
    #[test]
    fn the_wrapper_follows_the_configured_subframe_count() {
        let mut silk = SilkDecoder::new(16_000, 1).expect("decoder");
        silk.configure(1, InternalRate::Narrow8k, 10)
            .expect("10 ms");
        let mut buffer = [0u8; 64];
        encode_gain_indices(SignalType::Inactive, false, &[12, 8], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let gains = silk
            .decode_subframe_gains(
                &mut decoder,
                0,
                SignalType::Inactive,
                CondCoding::Independently,
            )
            .expect("valid");
        assert_eq!(gains.count, 2);
        assert_eq!(i32::from(gains.log_gains[0]), 12);
    }

    /// Each channel keeps its own running log-gain — the mid channel's gains must not perturb the
    /// side channel's, or a stereo stream drifts apart.
    #[test]
    fn the_two_channels_track_their_gains_independently() {
        let mut silk = SilkDecoder::new(48_000, 2).expect("decoder");
        silk.configure(2, InternalRate::Wide16k, 20).expect("20 ms");
        let mut buffer = [0u8; 64];
        encode_gain_indices(SignalType::Voiced, false, &[60, 4, 4, 4], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let _ = silk
            .decode_subframe_gains(
                &mut decoder,
                0,
                SignalType::Voiced,
                CondCoding::Independently,
            )
            .expect("valid");
        assert_ne!(silk.channel(0).expect("mid").last_gain_index, 10);
        assert_eq!(
            silk.channel(1).expect("side").last_gain_index,
            10,
            "side channel untouched"
        );
    }
}
