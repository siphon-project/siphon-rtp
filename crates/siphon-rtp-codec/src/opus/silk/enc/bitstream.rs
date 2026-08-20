//! The SILK bitstream **writer** — `silk_encode_indices` (`silk/encode_indices.c`) and
//! `silk_encode_pulses` (`silk/encode_pulses.c`, `silk/shell_coder.c`, `silk/code_signs.c`).
//!
//! Everything here is the exact inverse of the decoder's parse, symbol for symbol and in the same
//! order, so the tables are **imported from the decoder** rather than duplicated: a divergent copy
//! of `silk_pulses_per_block_iCDF` would be a bug that no round-trip test could see, because both
//! halves would agree with each other and with nothing else. RFC 6716 §4.2.7 Table 5 is the running
//! order and the decoder side ([`crate::opus::silk::frame`]) is the reference for what "same order"
//! means.
//!
//! # Two halves
//!
//! * [`encode_indices`] writes the side info — frame type, gains, NLSFs, pitch, LTP, LTP scaling,
//!   seed. It is pure table lookup driven by the analysis' decisions, with one piece of *encoder*
//!   logic in it: the pitch lag is delta-coded against the previous frame whenever the delta fits
//!   in the 21-symbol alphabet, and absolutely otherwise (`encode_indices.c:118-138`). That
//!   decision has to be made here, because it is the only place that knows what the entropy context
//!   holds.
//! * [`encode_pulses`] writes the excitation, and carries the two decisions RFC 6716 §4.2.7.8
//!   leaves to the encoder: **how many LSBs to strip** off each shell block so its pulse sum fits
//!   the shell coder's alphabet (§4.2.7.8.2's escape), and **which rate level** codes those sums
//!   most cheaply. The second is a real search over all nine levels using libopus' precomputed Q5
//!   bit costs — not a heuristic — because the level is coded once per frame and paid for by every
//!   block.
//!
//! # Why the writer never fails
//!
//! Neither function returns a `Result`. Every value it writes came from the analysis and is already
//! inside its alphabet, and the range encoder itself reports overflow through
//! [`RangeEncoder::error`] rather than by refusing a symbol — which is what the rate-control loop
//! reads. A `debug_assert` guards each alphabet so a wrong value shows up as a test failure rather
//! than as a silently mis-coded frame.

use crate::opus::range_coder::RangeEncoder;
use crate::opus::silk::enc::frame::SideIndices;
use crate::opus::silk::excitation::{
    pulse_count_icdf, shell_block_count, LSB_ICDF, MAX_LSB_SHIFTS, MAX_PULSES, MAX_SHELL_BLOCKS,
    RATE_LEVELS_ICDF, RATE_LEVEL_COUNT, SEED_ICDF, SHELL_BLOCK_LENGTH, SHELL_CODE_TABLE0,
    SHELL_CODE_TABLE1, SHELL_CODE_TABLE2, SHELL_CODE_TABLE3, SHELL_CODE_TABLE_OFFSETS, SIGN_ICDF,
};
use crate::opus::silk::ltp::{
    lag_low_bits_icdf, LtpFilterCodebook, PitchContourCodebook, LTP_PERIODICITY_ICDF,
    LTP_SCALE_ICDF, PITCH_DELTA_ICDF, PITCH_LAG_ICDF,
};
use crate::opus::silk::nlsf::unpack;
use crate::opus::silk::nlsf_tables::{
    NlsfCodebook, NLSF_EXT_ICDF, NLSF_INTERPOLATION_FACTOR_ICDF, NLSF_QUANT_MAX_AMPLITUDE,
};
use crate::opus::silk::tables::{
    DELTA_GAIN_ICDF, GAIN_ICDF, TYPE_OFFSET_NO_VAD_ICDF, TYPE_OFFSET_VAD_ICDF, UNIFORM8_ICDF,
};
use crate::opus::silk::types::{
    CondCoding, InternalRate, QuantOffsetType, SignalType, MAX_NB_SUBFR,
};

/// `ftb` for every SILK ICDF symbol: total frequency 256.
const ICDF_FTB: u32 = 8;

/// `silk_max_pulses_table` (`tables_pulses_per_block.c:34`) — the largest pulse sum each level of
/// the shell tree can code, from pairs up to whole 16-sample blocks. A block whose sums exceed any
/// of these has to shed a bit.
const MAX_PULSES_TABLE: [i32; 4] = [8, 10, 12, 16];

/// `silk_rate_levels_BITS_Q5` (`tables_pulses_per_block.c:151`) — the cost in Q5 bits of coding
/// each rate level, per folded signal type. Encoder-only: it is the constant term of the search.
const RATE_LEVELS_BITS_Q5: [[u8; 9]; 2] = [
    [131, 74, 141, 79, 80, 138, 95, 104, 134],
    [95, 99, 91, 125, 93, 76, 123, 115, 123],
];

/// `silk_pulses_per_block_BITS_Q5` (`tables_pulses_per_block.c:91`) — the cost in Q5 bits of coding
/// each pulse-sum symbol at each rate level. The last column (index 17) is the escape's cost, which
/// is what a block that had to shed bits is charged.
const PULSES_PER_BLOCK_BITS_Q5: [[u8; 18]; RATE_LEVEL_COUNT - 1] = [
    [
        31, 57, 107, 160, 205, 205, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ],
    [
        69, 47, 67, 111, 166, 205, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ],
    [
        82, 74, 79, 95, 109, 128, 145, 160, 173, 205, 205, 205, 224, 255, 255, 224, 255, 224,
    ],
    [
        125, 74, 59, 69, 97, 141, 182, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ],
    [
        173, 115, 85, 73, 76, 92, 115, 145, 173, 205, 224, 224, 255, 255, 255, 255, 255, 255,
    ],
    [
        166, 134, 113, 102, 101, 102, 107, 118, 125, 138, 145, 155, 166, 182, 192, 192, 205, 150,
    ],
    [
        224, 182, 134, 101, 83, 79, 85, 97, 120, 145, 173, 205, 224, 255, 255, 255, 255, 255,
    ],
    [
        255, 224, 192, 150, 120, 101, 92, 89, 93, 102, 118, 134, 160, 182, 192, 224, 224, 224,
    ],
    [
        255, 224, 224, 182, 155, 134, 118, 109, 104, 102, 106, 111, 118, 131, 145, 160, 173, 131,
    ],
];

/// The entropy *context* the pitch lag and frame type are coded against — libopus'
/// `ec_prevSignalType` / `ec_prevLagIndex` (`structs.h:239-240`).
///
/// It crosses frames and is **not** the same as the analysis' `previous_signal_type`: it is updated
/// by the writer, at the moment a symbol is written, and the rate-control loop rolls it back on
/// every retried iteration (`encode_frame_FLP.c:179-180`, `:192-193`). Keeping it here rather than
/// on the analysis state is what makes that rollback a two-field copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyContext {
    /// `ec_prevSignalType` — updated on **every** frame (`encode_indices.c:172`).
    pub previous_signal_type: SignalType,
    /// `ec_prevLagIndex` — updated only on a voiced frame (`encode_indices.c:139`).
    pub previous_lag_index: i16,
}

impl Default for EntropyContext {
    /// `silk_init_encoder` clears the whole state, so both start at zero.
    fn default() -> Self {
        Self {
            previous_signal_type: SignalType::Inactive,
            previous_lag_index: 0,
        }
    }
}

/// Write one SILK frame's side information (RFC 6716 §4.2.7, Table 5; libopus
/// `silk_encode_indices`, `encode_indices.c:35-181`).
///
/// `seed` is the `Seed` symbol — the *winning* seed the noise-shaping quantiser reports
/// ([`super::nsq::quantize`]), not the frame counter, because the delayed-decision search may have
/// preferred a different one.
///
/// `is_lbrr` selects the frame-type alphabet: an LBRR frame is only ever coded for an *active*
/// frame, so it always uses the four-symbol VAD table even when the signal type says inactive
/// (`encode_indices.c:60-64`).
pub fn encode_indices(
    encoder: &mut RangeEncoder<'_>,
    indices: &SideIndices,
    seed: u8,
    rate: InternalRate,
    subframe_count: usize,
    cond_coding: CondCoding,
    is_lbrr: bool,
    context: &mut EntropyContext,
) {
    // ── Frame type (§4.2.7.3, Table 10) ────────────────────────────────────────────────────────
    let type_offset = 2 * indices.signal_type.index()
        + usize::from(indices.quant_offset_type == QuantOffsetType::High);
    if is_lbrr || type_offset >= 2 {
        debug_assert!(type_offset >= 2, "silk: an LBRR frame is never inactive");
        encoder.enc_icdf(
            type_offset.saturating_sub(2),
            &TYPE_OFFSET_VAD_ICDF,
            ICDF_FTB,
        );
    } else {
        encoder.enc_icdf(type_offset, &TYPE_OFFSET_NO_VAD_ICDF, ICDF_FTB);
    }

    // ── Subframe gains (§4.2.7.4) ──────────────────────────────────────────────────────────────
    let first = indices.gains_indices[0];
    if cond_coding == CondCoding::Conditionally {
        debug_assert!((0..DELTA_GAIN_ICDF.len() as i8).contains(&first));
        encoder.enc_icdf(first as usize, &DELTA_GAIN_ICDF, ICDF_FTB);
    } else {
        // Independent: 3 MSBs from a signal-type-dependent table, then 3 LSBs uniform.
        debug_assert!((0..64).contains(&first));
        encoder.enc_icdf(
            (first >> 3) as usize,
            &GAIN_ICDF[indices.signal_type.index()],
            ICDF_FTB,
        );
        encoder.enc_icdf((first & 7) as usize, &UNIFORM8_ICDF, ICDF_FTB);
    }
    for &index in indices.gains_indices.iter().take(subframe_count).skip(1) {
        debug_assert!((0..DELTA_GAIN_ICDF.len() as i8).contains(&index));
        encoder.enc_icdf(index as usize, &DELTA_GAIN_ICDF, ICDF_FTB);
    }

    // ── NLSFs (§4.2.7.5.1-2) ───────────────────────────────────────────────────────────────────
    let codebook = NlsfCodebook::for_rate(rate);
    let stage1 = indices.nlsf.indices[0] as usize;
    encoder.enc_icdf(
        stage1,
        codebook.stage1_icdf(indices.signal_type.index()),
        ICDF_FTB,
    );
    let unpacked = unpack(codebook, stage1);
    for coefficient in 0..codebook.order {
        let residual = i32::from(indices.nlsf.indices[coefficient + 1]);
        let icdf = codebook.stage2_icdf(unpacked.pdf_index[coefficient]);
        if residual >= NLSF_QUANT_MAX_AMPLITUDE {
            // Saturate the ±4 alphabet, then code the excess with the extension table.
            encoder.enc_icdf((2 * NLSF_QUANT_MAX_AMPLITUDE) as usize, icdf, ICDF_FTB);
            encoder.enc_icdf(
                (residual - NLSF_QUANT_MAX_AMPLITUDE) as usize,
                &NLSF_EXT_ICDF,
                ICDF_FTB,
            );
        } else if residual <= -NLSF_QUANT_MAX_AMPLITUDE {
            encoder.enc_icdf(0, icdf, ICDF_FTB);
            encoder.enc_icdf(
                (-residual - NLSF_QUANT_MAX_AMPLITUDE) as usize,
                &NLSF_EXT_ICDF,
                ICDF_FTB,
            );
        } else {
            encoder.enc_icdf(
                (residual + NLSF_QUANT_MAX_AMPLITUDE) as usize,
                icdf,
                ICDF_FTB,
            );
        }
    }

    // ── NLSF interpolation weight (§4.2.7.5.5) — four-subframe frames only ─────────────────────
    if subframe_count == MAX_NB_SUBFR {
        let factor = indices.nlsf.interpolation_factor_q2;
        debug_assert!((0..5).contains(&factor));
        encoder.enc_icdf(factor as usize, &NLSF_INTERPOLATION_FACTOR_ICDF, ICDF_FTB);
    }

    if indices.signal_type == SignalType::Voiced {
        // ── Primary pitch lag (§4.2.7.6.1) ─────────────────────────────────────────────────────
        let mut encode_absolute = true;
        if cond_coding == CondCoding::Conditionally
            && context.previous_signal_type == SignalType::Voiced
        {
            let delta = i32::from(indices.lag_index) - i32::from(context.previous_lag_index);
            // Symbol 0 is "out of range, an absolute lag follows"; 1..=20 map to a delta of -8..=11.
            let symbol = if (-8..=11).contains(&delta) {
                encode_absolute = false;
                delta + 9
            } else {
                0
            };
            encoder.enc_icdf(symbol as usize, &PITCH_DELTA_ICDF, ICDF_FTB);
        }
        if encode_absolute {
            let scale = i32::from(crate::opus::silk::ltp::lag_scale(rate));
            let high = i32::from(indices.lag_index) / scale;
            let low = i32::from(indices.lag_index) - high * scale;
            debug_assert!(high < 32 && low < scale);
            encoder.enc_icdf(high as usize, &PITCH_LAG_ICDF, ICDF_FTB);
            encoder.enc_icdf(low as usize, lag_low_bits_icdf(rate), ICDF_FTB);
        }
        context.previous_lag_index = indices.lag_index;

        // ── Pitch contour (§4.2.7.6.1) ─────────────────────────────────────────────────────────
        let contour = PitchContourCodebook::select(rate, subframe_count);
        debug_assert!((indices.contour_index as usize) < contour.len());
        encoder.enc_icdf(indices.contour_index as usize, contour.icdf(), ICDF_FTB);

        // ── LTP filter (§4.2.7.6.2) ────────────────────────────────────────────────────────────
        debug_assert!((0..3).contains(&indices.periodicity_index));
        encoder.enc_icdf(
            indices.periodicity_index as usize,
            &LTP_PERIODICITY_ICDF,
            ICDF_FTB,
        );
        let filters = LtpFilterCodebook::select(indices.periodicity_index as u8);
        for &index in indices.ltp_indices.iter().take(subframe_count) {
            debug_assert!((index as usize) < filters.len());
            encoder.enc_icdf(index as usize, filters.icdf(), ICDF_FTB);
        }

        // ── LTP scaling (§4.2.7.6.3) — independently coded frames only ─────────────────────────
        if cond_coding == CondCoding::Independently {
            debug_assert!((0..3).contains(&indices.ltp_scale_index));
            encoder.enc_icdf(indices.ltp_scale_index as usize, &LTP_SCALE_ICDF, ICDF_FTB);
        }
        debug_assert!(
            cond_coding == CondCoding::Independently || indices.ltp_scale_index == 0,
            "silk: a conditionally coded frame must not carry an LTP scale"
        );
    }

    context.previous_signal_type = indices.signal_type;

    // ── LCG seed (§4.2.7.7) ────────────────────────────────────────────────────────────────────
    debug_assert!(seed < 4);
    encoder.enc_icdf(usize::from(seed & 3), &SEED_ICDF, ICDF_FTB);
}

/// How each shell block will be coded: the sum of its (possibly downscaled) pulse magnitudes, and
/// how many low bits were stripped to get there.
///
/// This is the encoder's half of RFC 6716 §4.2.7.8.2's escape mechanism, and it is a real decision
/// rather than bookkeeping: the shell coder can only place at most 8/10/12/16 pulses per tree level,
/// so a loud block must shed low bits until it fits, and each shed bit is then coded literally per
/// sample (§4.2.7.8.4).
#[derive(Debug, Clone, Copy)]
struct BlockPlan {
    /// `sum_pulses[i]` — the pulse sum after downscaling, 0..=16.
    sum: [i32; MAX_SHELL_BLOCKS],
    /// `nRshifts[i]` — how many bits were stripped, 0..=10.
    shifts: [i32; MAX_SHELL_BLOCKS],
    /// `iter` — how many shell blocks the frame has.
    blocks: usize,
}

/// `combine_and_check` folding a partition level onto itself (`encode_pulses.c:39-58` with
/// `pulses_in == pulses_comb`) — pairwise-sum the first `2 * len` entries into the first `len`,
/// stopping at the first sum the level cannot code.
///
/// The C aliases input and output here, which is safe because the write index `k` never overtakes
/// the read index `2k`; a single `&mut` reproduces that exactly.
fn fold_level(buffer: &mut [i32; 8], len: usize, max_pulses: i32) -> bool {
    for index in 0..len {
        let sum = buffer[2 * index] + buffer[2 * index + 1];
        if sum > max_pulses {
            return true;
        }
        buffer[index] = sum;
    }
    false
}

/// Decide the per-block downscaling (`encode_pulses.c:105-133`).
///
/// `magnitudes` is scratch holding `|pulses|`, and is downscaled in place — the LSBs are coded from
/// the *original* pulses afterwards, so the caller keeps both.
fn plan_blocks(magnitudes: &mut [i32], blocks: usize) -> BlockPlan {
    let mut plan = BlockPlan {
        sum: [0; MAX_SHELL_BLOCKS],
        shifts: [0; MAX_SHELL_BLOCKS],
        blocks,
    };
    let mut combined = [0i32; 8];
    for block in 0..blocks {
        let window = &mut magnitudes[block * SHELL_BLOCK_LENGTH..][..SHELL_BLOCK_LENGTH];
        loop {
            // 1+1 -> 2, then 2+2 -> 4, 4+4 -> 8 and 8+8 -> 16 in place, each against its own
            // ceiling. `|=` rather than `||`: the C sums all four verdicts, so every level runs.
            let mut overflowed = false;
            for (slot, pair) in combined.iter_mut().zip(window.as_chunks::<2>().0) {
                let sum = pair[0] + pair[1];
                if sum > MAX_PULSES_TABLE[0] {
                    overflowed = true;
                    break;
                }
                *slot = sum;
            }
            overflowed |= fold_level(&mut combined, 4, MAX_PULSES_TABLE[1]);
            overflowed |= fold_level(&mut combined, 2, MAX_PULSES_TABLE[2]);
            let total = combined[0] + combined[1];
            overflowed |= total > MAX_PULSES_TABLE[3];

            if !overflowed {
                plan.sum[block] = total;
                break;
            }
            plan.shifts[block] += 1;
            for magnitude in window.iter_mut() {
                *magnitude >>= 1;
            }
        }
    }
    plan
}

/// Pick the rate level that codes this frame's pulse sums in the fewest bits
/// (`encode_pulses.c:137-158`).
///
/// A real search over all nine signalled levels, scored with libopus' precomputed Q5 bit costs. A
/// block that had to shed bits is charged the escape symbol's cost rather than its sum's, because
/// that is what it will actually code.
fn choose_rate_level(plan: &BlockPlan, signal_type: SignalType) -> usize {
    let mut best_bits = i32::MAX;
    let mut best_level = 0usize;
    for (level, costs) in PULSES_PER_BLOCK_BITS_Q5.iter().enumerate() {
        let mut bits = i32::from(RATE_LEVELS_BITS_Q5[signal_type.index() >> 1][level]);
        for block in 0..plan.blocks {
            bits += if plan.shifts[block] > 0 {
                i32::from(costs[MAX_PULSES + 1])
            } else {
                i32::from(costs[plan.sum[block] as usize])
            };
        }
        if bits < best_bits {
            best_bits = bits;
            best_level = level;
        }
    }
    best_level
}

/// `encode_split` (`shell_coder.c:48-57`) — the left child's share of a partition, coded only when
/// the partition holds pulses at all.
fn encode_split(encoder: &mut RangeEncoder<'_>, left: i32, parent: i32, table: &'static [u8; 152]) {
    if parent > 0 {
        let start = SHELL_CODE_TABLE_OFFSETS[parent as usize] as usize;
        let icdf = &table[start..start + parent as usize + 1];
        encoder.enc_icdf(left as usize, icdf, ICDF_FTB);
    }
}

/// `silk_shell_encoder` (`shell_coder.c:78-151`) — place one block's 16 pulses by recursively
/// coding each split's left share (RFC 6716 §4.2.7.8.3, Tables 47-50).
///
/// The traversal order is preorder over the binary tree and is part of the bitstream, so it is
/// written out flat exactly as the C does rather than as a recursion whose order could drift.
fn encode_shell_block(encoder: &mut RangeEncoder<'_>, magnitudes: &[i32]) {
    debug_assert_eq!(magnitudes.len(), SHELL_BLOCK_LENGTH);
    let mut level1 = [0i32; 8];
    let mut level2 = [0i32; 4];
    let mut level3 = [0i32; 2];
    for (slot, pair) in level1.iter_mut().zip(magnitudes.as_chunks::<2>().0) {
        *slot = pair[0] + pair[1];
    }
    for (slot, pair) in level2.iter_mut().zip(level1.as_chunks::<2>().0) {
        *slot = pair[0] + pair[1];
    }
    for (slot, pair) in level3.iter_mut().zip(level2.as_chunks::<2>().0) {
        *slot = pair[0] + pair[1];
    }
    let total = level3[0] + level3[1];

    encode_split(encoder, level3[0], total, &SHELL_CODE_TABLE3);

    encode_split(encoder, level2[0], level3[0], &SHELL_CODE_TABLE2);
    encode_split(encoder, level1[0], level2[0], &SHELL_CODE_TABLE1);
    encode_split(encoder, magnitudes[0], level1[0], &SHELL_CODE_TABLE0);
    encode_split(encoder, magnitudes[2], level1[1], &SHELL_CODE_TABLE0);
    encode_split(encoder, level1[2], level2[1], &SHELL_CODE_TABLE1);
    encode_split(encoder, magnitudes[4], level1[2], &SHELL_CODE_TABLE0);
    encode_split(encoder, magnitudes[6], level1[3], &SHELL_CODE_TABLE0);

    encode_split(encoder, level2[2], level3[1], &SHELL_CODE_TABLE2);
    encode_split(encoder, level1[4], level2[2], &SHELL_CODE_TABLE1);
    encode_split(encoder, magnitudes[8], level1[4], &SHELL_CODE_TABLE0);
    encode_split(encoder, magnitudes[10], level1[5], &SHELL_CODE_TABLE0);
    encode_split(encoder, level1[6], level2[3], &SHELL_CODE_TABLE1);
    encode_split(encoder, magnitudes[12], level1[6], &SHELL_CODE_TABLE0);
    encode_split(encoder, magnitudes[14], level1[7], &SHELL_CODE_TABLE0);
}

/// `silk_encode_signs` (`code_signs.c:39-71`) — one sign per non-zero sample, with the PDF chosen
/// per block by signal type, quantisation offset type and the block's **pulse count**.
///
/// A block that shed bits always has a non-zero sum — shedding is only triggered by a sum above 8,
/// and halving sixteen magnitudes cannot take such a sum to zero — so the encoder's `sum > 0` test
/// and the decoder's `sum | (shifts << 5)` marker (`decode_pulses.c:107`) agree on every block.
fn encode_signs(
    encoder: &mut RangeEncoder<'_>,
    pulses: &[i8],
    plan: &BlockPlan,
    signal_type: SignalType,
    quant_offset_type: QuantOffsetType,
) {
    let offset_column = usize::from(quant_offset_type == QuantOffsetType::High);
    // silk_SMULBB( 7, silk_ADD_LSHIFT( quantOffsetType, signalType, 1 ) ) (code_signs.c:57).
    let row = 7 * (offset_column + (signal_type.index() << 1));

    for (block, chunk) in pulses
        .as_chunks::<SHELL_BLOCK_LENGTH>()
        .0
        .iter()
        .enumerate()
        .take(plan.blocks)
    {
        let sum = plan.sum[block];
        if sum <= 0 {
            continue;
        }
        let icdf = [SIGN_ICDF[row + (sum as usize & 0x1F).min(6)], 0];
        for &pulse in chunk {
            if pulse != 0 {
                // silk_enc_map(a) = (a >> 15) + 1: 0 for a negative pulse, 1 for a positive one.
                encoder.enc_icdf(usize::from(pulse > 0), &icdf, ICDF_FTB);
            }
        }
    }
}

/// Write one SILK frame's excitation (RFC 6716 §4.2.7.8; libopus `silk_encode_pulses`,
/// `encode_pulses.c:60-206`).
///
/// `pulses` is the quantiser's output and must be at least `shell_block_count(frame_length) * 16`
/// long: a 10 ms mediumband frame is 120 samples but codes 8 whole shell blocks, and the 8 padding
/// samples are **zeroed here** and then coded like any other (`encode_pulses.c:88-91`). The decoder
/// parses and discards them, so they cost bits but cannot be skipped.
pub fn encode_pulses(
    encoder: &mut RangeEncoder<'_>,
    signal_type: SignalType,
    quant_offset_type: QuantOffsetType,
    pulses: &mut [i8],
    frame_length: usize,
) {
    let blocks = shell_block_count(frame_length);
    let padded = blocks * SHELL_BLOCK_LENGTH;
    debug_assert!(pulses.len() >= padded);
    pulses[frame_length..padded].fill(0);

    let mut magnitudes = [0i32; MAX_SHELL_BLOCKS * SHELL_BLOCK_LENGTH];
    for (slot, &pulse) in magnitudes.iter_mut().zip(pulses[..padded].iter()) {
        *slot = i32::from(pulse).abs();
    }

    let plan = plan_blocks(&mut magnitudes[..padded], blocks);

    // ── Rate level (§4.2.7.8.1) ────────────────────────────────────────────────────────────────
    let rate_level = choose_rate_level(&plan, signal_type);
    encoder.enc_icdf(
        rate_level,
        &RATE_LEVELS_ICDF[signal_type.index() >> 1],
        ICDF_FTB,
    );

    // ── Pulse sums, all blocks before any block's content (§4.2.7.8.2) ─────────────────────────
    let escape = MAX_PULSES + 1;
    for block in 0..blocks {
        if plan.shifts[block] == 0 {
            encoder.enc_icdf(
                plan.sum[block] as usize,
                pulse_count_icdf(rate_level),
                ICDF_FTB,
            );
        } else {
            // One escape at the frame's rate level, then one per further shed bit at level 9, then
            // the actual sum. Ten escapes is the hard maximum, which is why the loop is bounded.
            debug_assert!(plan.shifts[block] <= i32::from(MAX_LSB_SHIFTS));
            encoder.enc_icdf(escape, pulse_count_icdf(rate_level), ICDF_FTB);
            for _ in 0..plan.shifts[block] - 1 {
                encoder.enc_icdf(escape, pulse_count_icdf(RATE_LEVEL_COUNT - 1), ICDF_FTB);
            }
            encoder.enc_icdf(
                plan.sum[block] as usize,
                pulse_count_icdf(RATE_LEVEL_COUNT - 1),
                ICDF_FTB,
            );
        }
    }

    // ── Pulse locations (§4.2.7.8.3) ───────────────────────────────────────────────────────────
    for block in 0..blocks {
        if plan.sum[block] > 0 {
            encode_shell_block(
                encoder,
                &magnitudes[block * SHELL_BLOCK_LENGTH..][..SHELL_BLOCK_LENGTH],
            );
        }
    }

    // ── LSBs (§4.2.7.8.4) — every sample of a block that shed bits, MSB first ──────────────────
    for block in 0..blocks {
        if plan.shifts[block] == 0 {
            continue;
        }
        let stripped = plan.shifts[block] - 1;
        for &pulse in &pulses[block * SHELL_BLOCK_LENGTH..][..SHELL_BLOCK_LENGTH] {
            let magnitude = i32::from(pulse).abs();
            for bit in (0..=stripped).rev() {
                encoder.enc_icdf(((magnitude >> bit) & 1) as usize, &LSB_ICDF, ICDF_FTB);
            }
        }
    }

    // ── Signs (§4.2.7.8.5) ─────────────────────────────────────────────────────────────────────
    encode_signs(
        encoder,
        &pulses[..padded],
        &plan,
        signal_type,
        quant_offset_type,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeDecoder;
    use crate::opus::silk::excitation::{decode_pulses, PULSE_BUFFER_LENGTH};
    use crate::opus::silk::gains::decode_gain_indices;
    use crate::opus::silk::ltp::decode_indices as decode_ltp_indices;
    use crate::opus::silk::nlsf::{decode_indices as decode_nlsf_indices, NlsfIndices};
    use crate::opus::silk::types::SubframeLayout;

    fn indices(signal_type: SignalType) -> SideIndices {
        SideIndices {
            signal_type,
            quant_offset_type: QuantOffsetType::High,
            gains_indices: [31, 5, 2, 9],
            nlsf: NlsfIndices {
                indices: [17, 1, -2, 4, -4, 0, 3, -1, 2, -3, 1, 0, 0, 0, 0, 0, 0],
                order: 16,
                interpolation_factor_q2: 2,
            },
            lag_index: 41,
            contour_index: 7,
            periodicity_index: 2,
            ltp_indices: [3, 17, 30, 1],
            ltp_scale_index: 1,
        }
    }

    /// The whole side-info block must round-trip through the landed decoder, symbol for symbol.
    /// This is the strongest statement available about the writer at this level: the decoder is
    /// bit-exact against libopus over 64 streams, so agreeing with it is agreeing with libopus.
    #[test]
    fn side_info_round_trips_through_the_decoder() {
        for signal_type in [
            SignalType::Inactive,
            SignalType::Unvoiced,
            SignalType::Voiced,
        ] {
            for cond in [
                CondCoding::Independently,
                CondCoding::IndependentlyNoLtpScaling,
                CondCoding::Conditionally,
            ] {
                let mut side = indices(signal_type);
                if cond != CondCoding::Independently {
                    side.ltp_scale_index = 0;
                }
                let mut buffer = [0u8; 256];
                let mut context = EntropyContext::default();
                let mut encoder = RangeEncoder::new(&mut buffer);
                encode_indices(
                    &mut encoder,
                    &side,
                    3,
                    InternalRate::Wide16k,
                    4,
                    cond,
                    false,
                    &mut context,
                );
                // The payload length is `(ec_tell + 7) >> 3` (`encode_frame_FLP.c:373`), not the
                // encoder's front-byte count: the flush can leave the last symbol's bits in a byte
                // the front cursor has not reached yet.
                let used = (encoder.tell() as usize).div_ceil(8);
                encoder.done();
                assert!(!encoder.error());

                let mut decoder = RangeDecoder::new(&buffer[..used.max(1)]);
                let frame_type = crate::opus::silk::frame_type::decode_frame_type(
                    &mut decoder,
                    signal_type != SignalType::Inactive,
                )
                .expect("frame type");
                assert_eq!(frame_type.signal_type(), signal_type);
                assert_eq!(frame_type.quant_offset_type(), side.quant_offset_type);

                let gains = decode_gain_indices(&mut decoder, signal_type, cond, 4).expect("gains");
                assert_eq!(gains.indices[..4], side.gains_indices[..4]);

                let nlsf = decode_nlsf_indices(&mut decoder, InternalRate::Wide16k, signal_type, 4)
                    .expect("nlsf");
                assert_eq!(nlsf.indices, side.nlsf.indices, "{signal_type:?} {cond:?}");
                assert_eq!(
                    nlsf.interpolation_factor_q2,
                    side.nlsf.interpolation_factor_q2
                );

                // §4.2.7.6 applies to voiced frames only; the decoder's integrator gates the call
                // the same way, and reading "just in case" would eat the seed's bits.
                if signal_type == SignalType::Voiced {
                    let ltp = decode_ltp_indices(
                        &mut decoder,
                        InternalRate::Wide16k,
                        SubframeLayout::from_duration_ms(20).expect("20 ms"),
                        cond,
                        SignalType::Inactive,
                        0,
                    );
                    assert_eq!(ltp.lag_index, side.lag_index);
                    assert_eq!(u8::try_from(side.contour_index), Ok(ltp.contour_index));
                    assert_eq!(
                        u8::try_from(side.periodicity_index),
                        Ok(ltp.periodicity_index)
                    );
                    for subframe in 0..4 {
                        assert_eq!(
                            i8::try_from(ltp.filter_indices[subframe]),
                            Ok(side.ltp_indices[subframe])
                        );
                    }
                    assert_eq!(i8::try_from(ltp.ltp_scale_index), Ok(side.ltp_scale_index));
                }

                let seed = crate::opus::silk::excitation::decode_seed(&mut decoder);
                assert_eq!(seed, 3, "{signal_type:?} {cond:?}");
                assert!(!decoder.error());
            }
        }
    }

    /// A delta-coded pitch lag must survive the round trip, and a delta outside the 21-symbol
    /// alphabet must fall back to the absolute form rather than being coded wrong.
    #[test]
    fn a_pitch_lag_delta_falls_back_to_absolute_when_it_does_not_fit() {
        for (previous, current) in [(40i16, 45i16), (40, 32), (40, 120), (40, 0)] {
            let mut side = indices(SignalType::Voiced);
            side.lag_index = current;
            side.ltp_scale_index = 0;
            let mut buffer = [0u8; 256];
            let mut context = EntropyContext {
                previous_signal_type: SignalType::Voiced,
                previous_lag_index: previous,
            };
            let mut encoder = RangeEncoder::new(&mut buffer);
            encode_indices(
                &mut encoder,
                &side,
                1,
                InternalRate::Wide16k,
                4,
                CondCoding::Conditionally,
                false,
                &mut context,
            );
            let used = (encoder.tell() as usize).div_ceil(8);
            encoder.done();

            let mut decoder = RangeDecoder::new(&buffer[..used.max(1)]);
            let _ = crate::opus::silk::frame_type::decode_frame_type(&mut decoder, true)
                .expect("frame type");
            let _ = decode_gain_indices(
                &mut decoder,
                SignalType::Voiced,
                CondCoding::Conditionally,
                4,
            )
            .expect("gains");
            let _ = decode_nlsf_indices(&mut decoder, InternalRate::Wide16k, SignalType::Voiced, 4)
                .expect("nlsf");
            let ltp = decode_ltp_indices(
                &mut decoder,
                InternalRate::Wide16k,
                SubframeLayout::from_duration_ms(20).expect("20 ms"),
                CondCoding::Conditionally,
                SignalType::Voiced,
                previous,
            );
            assert_eq!(ltp.lag_index, current, "{previous} -> {current}");
            assert_eq!(context.previous_lag_index, current);
        }
    }

    /// Pulses must round-trip through the decoder's shell parser exactly — magnitudes *and* signs,
    /// including a block loud enough to force the LSB escape.
    #[test]
    fn pulses_round_trip_through_the_shell_decoder() {
        let mut source = [0i8; 320];
        let mut state = 13_579u32;
        for (index, slot) in source.iter_mut().enumerate() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            // Block 3 gets loud enough to need two escapes; the rest stay in the plain alphabet.
            let scale = if (48..64).contains(&index) { 26 } else { 3 };
            *slot = (((state >> 22) as i32 % scale) - scale / 2) as i8;
        }

        for frame_length in [80usize, 160, 320, 120] {
            let mut pulses = source;
            let mut buffer = [0u8; 1024];
            let mut encoder = RangeEncoder::new(&mut buffer);
            encode_pulses(
                &mut encoder,
                SignalType::Voiced,
                QuantOffsetType::Low,
                &mut pulses[..],
                frame_length,
            );
            let used = (encoder.tell() as usize).div_ceil(8);
            encoder.done();
            assert!(!encoder.error());

            let mut decoder = RangeDecoder::new(&buffer[..used.max(1)]);
            let mut decoded = [0i16; PULSE_BUFFER_LENGTH];
            let excitation = decode_pulses(
                &mut decoder,
                SignalType::Voiced,
                QuantOffsetType::Low,
                frame_length,
                &mut decoded,
            )
            .expect("decode");
            assert!(!decoder.error());

            let padded = shell_block_count(frame_length) * SHELL_BLOCK_LENGTH;
            for sample in 0..padded {
                assert_eq!(
                    i32::from(decoded[sample]),
                    i32::from(pulses[sample]),
                    "frame {frame_length} sample {sample}"
                );
            }
            assert_eq!(excitation.block_count, shell_block_count(frame_length));
        }
    }

    /// A 10 ms mediumband frame is 120 samples but codes 8 shell blocks: the writer must zero the
    /// 8 padding samples rather than leaking whatever the quantiser left there.
    #[test]
    fn the_mediumband_padding_samples_are_zeroed_before_coding() {
        let mut pulses = [7i8; 320];
        let mut buffer = [0u8; 1024];
        let mut encoder = RangeEncoder::new(&mut buffer);
        encode_pulses(
            &mut encoder,
            SignalType::Unvoiced,
            QuantOffsetType::Low,
            &mut pulses[..],
            120,
        );
        assert_eq!(&pulses[120..128], &[0i8; 8]);
    }

    /// Silence must cost only the rate level and eight "zero pulses" symbols — a couple of bytes,
    /// which is what makes an inactive frame cheap.
    #[test]
    fn a_silent_frame_costs_almost_nothing() {
        let mut pulses = [0i8; 320];
        let mut buffer = [0u8; 1024];
        let mut encoder = RangeEncoder::new(&mut buffer);
        encode_pulses(
            &mut encoder,
            SignalType::Inactive,
            QuantOffsetType::Low,
            &mut pulses[..],
            320,
        );
        assert!(encoder.tell() < 40, "silence cost {} bits", encoder.tell());
    }

    /// The rate level really is chosen, not fixed: two frames with very different pulse
    /// distributions must select different levels.
    #[test]
    fn the_rate_level_search_responds_to_the_pulse_distribution() {
        let mut quiet = [0i32; MAX_SHELL_BLOCKS * SHELL_BLOCK_LENGTH];
        quiet[0] = 1;
        let quiet_plan = plan_blocks(&mut quiet[..320], 20);
        let mut loud = [3i32; MAX_SHELL_BLOCKS * SHELL_BLOCK_LENGTH];
        let loud_plan = plan_blocks(&mut loud[..320], 20);
        assert_ne!(
            choose_rate_level(&quiet_plan, SignalType::Voiced),
            choose_rate_level(&loud_plan, SignalType::Voiced)
        );
    }

    /// A block whose magnitudes cannot fit the shell alphabet must shed exactly as many bits as it
    /// takes and no more, and the resulting sum must always be codable.
    #[test]
    fn the_escape_sheds_the_minimum_number_of_bits() {
        for magnitude in [1i32, 4, 8, 20, 60, 127] {
            let mut block = [magnitude; MAX_SHELL_BLOCKS * SHELL_BLOCK_LENGTH];
            let plan = plan_blocks(&mut block[..16], 1);
            assert!(plan.sum[0] > 0, "magnitude {magnitude}");
            assert!(plan.sum[0] <= MAX_PULSES as i32, "magnitude {magnitude}");
            assert!(plan.shifts[0] <= i32::from(MAX_LSB_SHIFTS));
            // One fewer shift would not have fitted.
            if plan.shifts[0] > 0 {
                let retry = [magnitude >> (plan.shifts[0] - 1); 16];
                let sum: i32 = retry.iter().sum();
                assert!(
                    sum > MAX_PULSES as i32,
                    "magnitude {magnitude} shed one bit too many"
                );
            }
        }
    }
}
