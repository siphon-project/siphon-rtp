//! Excitation — the LCG seed (RFC 6716 §4.2.7.7) and the pulse/shell coder (§4.2.7.8).
//!
//! This is the last and largest part of a SILK frame's bitstream, and the part where a one-symbol
//! mistake is most visible: everything after it desynchronises. It is a modified Pyramid Vector
//! Quantizer — the frame is cut into 16-sample **shell blocks**, each block codes how many pulses it
//! holds, and the pulses are placed by recursively splitting the block 16 → 8 → 4 → 2 → 1 and coding
//! how many fell on the left of each split (§4.2.7.8.3).
//!
//! Bitstream order, all of it ported from libopus `decode_pulses.c` / `shell_coder.c` /
//! `code_signs.c` / `decode_core.c:70-88`:
//!
//! ```text
//!   seed              §4.2.7.7   2 bits, uniform — read at the *end* of the side info, before this
//!   rate level        §4.2.7.8.1 one symbol, PDF chosen by signal type
//!   pulse counts      §4.2.7.8.2 one per shell block, all blocks before any block's content
//!   pulse locations   §4.2.7.8.3 the recursive splits, per block
//!   LSBs              §4.2.7.8.4 per block that asked for them, every sample, MSB first
//!   signs             §4.2.7.8.5 one per non-zero sample
//!   reconstruction    §4.2.7.8.6 quantization offset + pseudorandom inversion driven by the LCG
//! ```
//!
//! # Details that are easy to get wrong
//!
//! * **The escape is a loop, not a flag.** A pulse count of 17 means "one more LSB per sample, and
//!   read the count again" — using rate level 9's PDF, not the frame's. After ten 17s the eleventh
//!   read uses rate level 10, whose PDF cannot produce 17, which is what bounds the LSB count at 10
//!   (`decode_pulses.c:72-77`). Rate level 10's table is not stored: it is rate level 9's table
//!   advanced by one byte, which is exactly what [`pulse_count_icdf`] returns.
//! * **A block with zero pulses but non-zero LSB shifts still codes signs.** The C marks it by
//!   folding the shift count into the pulse count (`sum_pulses[i] |= nLS << 5`,
//!   `decode_pulses.c:107`), so the `p > 0` test in the sign decoder passes while `p & 0x1F` still
//!   reports zero pulses and selects the strongly positive-skewed "0 pulses" PDF. RFC 6716 §4.2.7.8.5
//!   describes this as a deliberate encoder trick; dropping it loses a symbol per sample.
//! * **10 ms mediumband frames are 120 samples, not a multiple of 16.** They code 8 shell blocks
//!   (128 samples) and the last 8 samples are parsed and then ignored (RFC 6716 §4.2.7.8). The pulse
//!   buffer therefore has to be the *padded* length while the excitation is the frame length.
//! * **`sign()` of zero is zero.** The quantization step adjustment is only applied to a non-zero
//!   sample, so a zero sample reconstructs to the bare offset (RFC 6716 §4.2.7.8.6).
//!
//! # Q14 or Q23?
//!
//! RFC 6716 §4.2.7.8.6 writes the reconstructed excitation as `e_Q23`, libopus as `exc_Q14`
//! (`decode_core.c:74`). They are the same signal: every term of the RFC's formula is 64× smaller
//! than libopus', so `exc_Q14[i] == e_Q23[i] * 64` **exactly**, with no rounding. This module
//! produces the Q14 form, because that is what [`super::decoder::ChannelState::excitation_q14`] and
//! §4.2.7.9 synthesis consume; `reconstruction_matches_the_rfc_q23_formula` implements the RFC's
//! formula independently and proves the two agree over the whole reachable input range.

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::types::{QuantOffsetType, SignalType, MAX_FRAME_LENGTH};
use crate::CodecError;

/// `ftb` for every SILK ICDF symbol: total frequency 256.
const ICDF_FTB: u32 = 8;

/// `SHELL_CODEC_FRAME_LENGTH` (`define.h:168`) — samples per shell block.
pub const SHELL_BLOCK_LENGTH: usize = 16;

/// `MAX_NB_SHELL_BLOCKS` (`define.h:170`) — `MAX_FRAME_LENGTH / SHELL_CODEC_FRAME_LENGTH` = 20, the
/// 20 ms wideband case (RFC 6716 Table 44).
pub const MAX_SHELL_BLOCKS: usize = MAX_FRAME_LENGTH / SHELL_BLOCK_LENGTH;

/// Length a pulse buffer must have: every shell block is decoded in full, including the padding
/// samples of a 10 ms mediumband frame (RFC 6716 §4.2.7.8).
pub const PULSE_BUFFER_LENGTH: usize = MAX_SHELL_BLOCKS * SHELL_BLOCK_LENGTH;

/// `SILK_MAX_PULSES` (`define.h:176`) — the largest pulse count a shell block can hold.
pub const MAX_PULSES: usize = 16;

/// The escape symbol: "this block has one more LSB per sample" (`decode_pulses.c:72`).
const PULSE_COUNT_ESCAPE: usize = MAX_PULSES + 1;

/// `N_RATE_LEVELS` (`define.h:173`) — 9 signalled rate levels plus the escape level 9. Level 10 is
/// derived from level 9 rather than stored (see [`pulse_count_icdf`]).
pub const RATE_LEVEL_COUNT: usize = 10;

/// The most LSBs a block can carry — after ten escapes the PDF can no longer produce another
/// (`decode_pulses.c:74-76`; RFC 6716 §4.2.7.8.2).
pub const MAX_LSB_SHIFTS: u8 = 10;

/// `QUANT_LEVEL_ADJUST_Q10` (`define.h:135`) — pulled back off the magnitude of every non-zero
/// sample so the reconstruction sits at the centroid of the quantization cell rather than its edge.
/// RFC 6716 §4.2.7.8.6 writes the same constant as `20` in Q23, which is `80 >> 2`.
const QUANT_LEVEL_ADJUST_Q10: i32 = 80;

/// `RAND_MULTIPLIER` (`SigProc_FIX.h:599`) — the LCG multiplier of RFC 6716 §4.2.7.8.6.
const RAND_MULTIPLIER: i32 = 196_314_165;
/// `RAND_INCREMENT` (`SigProc_FIX.h:600`) — the LCG increment of RFC 6716 §4.2.7.8.6.
const RAND_INCREMENT: i32 = 907_633_515;

// ── LCG seed (RFC 6716 §4.2.7.7, Table 43) ──────────────────────────────────────────────────────

/// LCG seed — a uniform 4-way choice (libopus `silk_uniform4_iCDF`, used at `decode_indices.c:150`;
/// RFC 6716 Table 43). Shared with the 8 kHz pitch-lag low bits, hence the re-export.
pub use super::ltp::UNIFORM4_ICDF as SEED_ICDF;

// ── Rate level (RFC 6716 §4.2.7.8.1, Table 45) ──────────────────────────────────────────────────

/// Rate level, one row per *folded* signal type (libopus `silk_rate_levels_iCDF`,
/// `tables_pulses_per_block.c:137`; RFC 6716 Table 45). Row 0 covers inactive **and** unvoiced, row 1
/// voiced — the C's `signalType >> 1`, the same fold [`QuantOffsetType::offset_q10`] uses.
pub const RATE_LEVELS_ICDF: [[u8; 9]; 2] = [
    [241, 190, 178, 132, 87, 74, 41, 14, 0],
    [223, 193, 157, 140, 106, 57, 39, 18, 0],
];

// ── Pulse counts (RFC 6716 §4.2.7.8.2, Table 46) ────────────────────────────────────────────────

/// Pulses per shell block, one row per rate level (libopus `silk_pulses_per_block_iCDF`,
/// `tables_pulses_per_block.c:38`; RFC 6716 Table 46, rows 0-9). Row 9 is the escape level; RFC
/// Table 46's row 10 is this row advanced by one entry — see [`pulse_count_icdf`].
pub const PULSES_PER_BLOCK_ICDF: [[u8; 18]; RATE_LEVEL_COUNT] = [
    [
        125, 51, 26, 18, 15, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ],
    [
        198, 105, 45, 22, 15, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ],
    [
        213, 162, 116, 83, 59, 43, 32, 24, 18, 15, 12, 9, 7, 6, 5, 3, 2, 0,
    ],
    [
        239, 187, 116, 59, 28, 16, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ],
    [
        250, 229, 188, 135, 86, 51, 30, 19, 13, 10, 8, 6, 5, 4, 3, 2, 1, 0,
    ],
    [
        249, 235, 213, 185, 156, 128, 103, 83, 66, 53, 42, 33, 26, 21, 17, 13, 10, 0,
    ],
    [
        254, 249, 235, 206, 164, 118, 77, 46, 27, 16, 10, 7, 5, 4, 3, 2, 1, 0,
    ],
    [
        255, 253, 249, 239, 220, 191, 156, 119, 85, 57, 37, 23, 15, 10, 6, 4, 2, 0,
    ],
    [
        255, 253, 251, 246, 237, 223, 203, 179, 152, 124, 98, 75, 55, 40, 29, 21, 15, 0,
    ],
    [
        255, 254, 253, 247, 220, 162, 106, 67, 42, 28, 18, 12, 9, 6, 4, 3, 2, 0,
    ],
];

// ── Pulse locations (RFC 6716 §4.2.7.8.3, Tables 47-50) ─────────────────────────────────────────

/// Where the sub-table for pulse count `p` starts inside a shell-code table (libopus
/// `silk_shell_code_table_offsets`, `tables_pulses_per_block.c:243`). The sub-table for `p` has
/// `p + 1` entries — one per possible left-child count 0..=p — so the offsets are the running sum.
pub const SHELL_CODE_TABLE_OFFSETS: [u8; MAX_PULSES + 1] = [
    0, 0, 2, 5, 9, 14, 20, 27, 35, 44, 54, 65, 77, 90, 104, 119, 135,
];

/// Splits of a **2-sample** partition (libopus `silk_shell_code_table0`; RFC 6716 Table 50). The
/// deepest level of the recursion, so it is also the most frequently used table.
pub const SHELL_CODE_TABLE0: [u8; 152] = [
    128, 0, 214, 42, 0, 235, 128, 21, //
    0, 244, 184, 72, 11, 0, 248, 214, //
    128, 42, 7, 0, 248, 225, 170, 80, //
    25, 5, 0, 251, 236, 198, 126, 54, //
    18, 3, 0, 250, 238, 211, 159, 82, //
    35, 15, 5, 0, 250, 231, 203, 168, //
    128, 88, 53, 25, 6, 0, 252, 238, //
    216, 185, 148, 108, 71, 40, 18, 4, //
    0, 253, 243, 225, 199, 166, 128, 90, //
    57, 31, 13, 3, 0, 254, 246, 233, //
    212, 183, 147, 109, 73, 44, 23, 10, //
    2, 0, 255, 250, 240, 223, 198, 166, //
    128, 90, 58, 33, 16, 6, 1, 0, //
    255, 251, 244, 231, 210, 181, 146, 110, //
    75, 46, 25, 12, 5, 1, 0, 255, //
    253, 248, 238, 221, 196, 164, 128, 92, //
    60, 35, 18, 8, 3, 1, 0, 255, //
    253, 249, 242, 229, 208, 180, 146, 110, //
    76, 48, 27, 14, 7, 3, 1, 0,
];

/// Splits of a **4-sample** partition (libopus `silk_shell_code_table1`; RFC 6716 Table 49).
pub const SHELL_CODE_TABLE1: [u8; 152] = [
    129, 0, 207, 50, 0, 236, 129, 20, //
    0, 245, 185, 72, 10, 0, 249, 213, //
    129, 42, 6, 0, 250, 226, 169, 87, //
    27, 4, 0, 251, 233, 194, 130, 62, //
    20, 4, 0, 250, 236, 207, 160, 99, //
    47, 17, 3, 0, 255, 240, 217, 182, //
    131, 81, 41, 11, 1, 0, 255, 254, //
    233, 201, 159, 107, 61, 20, 2, 1, //
    0, 255, 249, 233, 206, 170, 128, 86, //
    50, 23, 7, 1, 0, 255, 250, 238, //
    217, 186, 148, 108, 70, 39, 18, 6, //
    1, 0, 255, 252, 243, 226, 200, 166, //
    128, 90, 56, 30, 13, 4, 1, 0, //
    255, 252, 245, 231, 209, 180, 146, 110, //
    76, 47, 25, 11, 4, 1, 0, 255, //
    253, 248, 237, 219, 194, 163, 128, 93, //
    62, 37, 19, 8, 3, 1, 0, 255, //
    254, 250, 241, 226, 205, 177, 145, 111, //
    79, 51, 30, 15, 6, 2, 1, 0,
];

/// Splits of an **8-sample** partition (libopus `silk_shell_code_table2`; RFC 6716 Table 48).
pub const SHELL_CODE_TABLE2: [u8; 152] = [
    129, 0, 203, 54, 0, 234, 129, 23, //
    0, 245, 184, 73, 10, 0, 250, 215, //
    129, 41, 5, 0, 252, 232, 173, 86, //
    24, 3, 0, 253, 240, 200, 129, 56, //
    15, 2, 0, 253, 244, 217, 164, 94, //
    38, 10, 1, 0, 253, 245, 226, 189, //
    132, 71, 27, 7, 1, 0, 253, 246, //
    231, 203, 159, 105, 56, 23, 6, 1, //
    0, 255, 248, 235, 213, 179, 133, 85, //
    47, 19, 5, 1, 0, 255, 254, 243, //
    221, 194, 159, 117, 70, 37, 12, 2, //
    1, 0, 255, 254, 248, 234, 208, 171, //
    128, 85, 48, 22, 8, 2, 1, 0, //
    255, 254, 250, 240, 220, 189, 149, 107, //
    67, 36, 16, 6, 2, 1, 0, 255, //
    254, 251, 243, 227, 201, 166, 128, 90, //
    55, 29, 13, 5, 2, 1, 0, 255, //
    254, 252, 246, 234, 213, 183, 147, 109, //
    73, 43, 22, 10, 4, 2, 1, 0,
];

/// Splits of a **16-sample** partition (libopus `silk_shell_code_table3`; RFC 6716 Table 47) — the
/// first split of a whole shell block.
pub const SHELL_CODE_TABLE3: [u8; 152] = [
    130, 0, 200, 58, 0, 231, 130, 26, //
    0, 244, 184, 76, 12, 0, 249, 214, //
    130, 43, 6, 0, 252, 232, 173, 87, //
    24, 3, 0, 253, 241, 203, 131, 56, //
    14, 2, 0, 254, 246, 221, 167, 94, //
    35, 8, 1, 0, 254, 249, 232, 193, //
    130, 65, 23, 5, 1, 0, 255, 251, //
    239, 211, 162, 99, 45, 15, 4, 1, //
    0, 255, 251, 243, 223, 186, 131, 74, //
    33, 11, 3, 1, 0, 255, 252, 245, //
    230, 202, 158, 105, 57, 24, 8, 2, //
    1, 0, 255, 253, 247, 235, 214, 179, //
    132, 84, 44, 19, 7, 2, 1, 0, //
    255, 254, 250, 240, 223, 196, 159, 112, //
    69, 36, 15, 6, 2, 1, 0, 255, //
    254, 253, 245, 231, 209, 176, 136, 93, //
    55, 27, 11, 3, 2, 1, 0, 255, //
    254, 253, 252, 239, 221, 194, 158, 117, //
    76, 42, 18, 4, 3, 2, 1, 0,
];

// ── LSBs and signs (RFC 6716 §4.2.7.8.4-5, Tables 51-52) ────────────────────────────────────────

/// One excitation LSB (libopus `silk_lsb_iCDF`, `tables_other.c:64`; RFC 6716 Table 51).
pub const LSB_ICDF: [u8; 2] = [120, 0];

/// Excitation signs (libopus `silk_sign_iCDF`, `tables_pulses_per_block.c:249`; RFC 6716 Table 52),
/// as six 7-entry rows indexed `7 * (2 * signal_type + quant_offset_type)` and then by
/// `min(pulse_count, 6)`. Only the *first* entry of the two-symbol ICDF is stored; the second is
/// always 0 (`code_signs.c:81`, `icdf[1] = 0`).
pub const SIGN_ICDF: [u8; 42] = [
    254, 49, 67, 77, 82, 93, 99, //
    198, 11, 18, 24, 31, 36, 45, //
    255, 46, 66, 78, 87, 94, 104, //
    208, 14, 21, 32, 42, 51, 66, //
    255, 94, 104, 109, 112, 115, 118, //
    248, 53, 69, 80, 88, 95, 102,
];

/// Number of shell blocks a frame of `frame_length` samples uses (libopus `decode_pulses.c:57-61`;
/// RFC 6716 Table 44). Rounded **up**, which only bites for the 120-sample 10 ms mediumband frame.
#[must_use]
pub fn shell_block_count(frame_length: usize) -> usize {
    frame_length.div_ceil(SHELL_BLOCK_LENGTH)
}

/// The pulse-count ICDF for a rate level (RFC 6716 Table 46).
///
/// Levels 0..=9 are stored rows. Level 10 is level 9's row advanced by one byte — the C writes it as
/// `silk_pulses_per_block_iCDF[N_RATE_LEVELS - 1] + (nLshifts == 10)` (`decode_pulses.c:75-76`).
/// Dropping the leading entry removes symbol 17 from the alphabet entirely, which is what makes ten
/// LSB shifts the hard maximum. Anything above 10 is treated as 10 (unreachable from the bitstream).
#[must_use]
pub fn pulse_count_icdf(rate_level: usize) -> &'static [u8] {
    match rate_level {
        level if level < RATE_LEVEL_COUNT => &PULSES_PER_BLOCK_ICDF[level][..],
        _ => &PULSES_PER_BLOCK_ICDF[RATE_LEVEL_COUNT - 1][1..],
    }
}

/// The split ICDF for a partition holding `pulse_count` pulses, from the table for the partition's
/// size (RFC 6716 Tables 47-50; libopus `&shell_table[silk_shell_code_table_offsets[p]]`).
///
/// Returns an empty slice for `pulse_count == 0` or above [`MAX_PULSES`]; a zero-pulse partition is
/// never split, and the decoder never asks for a larger one.
#[must_use]
fn split_icdf(table: &'static [u8; 152], pulse_count: usize) -> &'static [u8] {
    if pulse_count == 0 || pulse_count > MAX_PULSES {
        return &[];
    }
    let start = SHELL_CODE_TABLE_OFFSETS[pulse_count] as usize;
    &table[start..start + pulse_count + 1]
}

/// What the excitation decode read, beyond the pulses themselves — the side info a conformance diff
/// against a reference decoder needs, and the shape RFC 6716 §4.2.7.8.2 describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Excitation {
    /// `RateLevelIndex` (§4.2.7.8.1) — 0..=8.
    pub rate_level: usize,
    /// `iter` — shell blocks in this frame, 5..=20 (RFC 6716 Table 44).
    pub block_count: usize,
    /// `sum_pulses[i]` **before** the LSB-shift marker is folded in — the pulse count of each block,
    /// 0..=16. Only `0..block_count` are meaningful.
    pub pulse_counts: [u8; MAX_SHELL_BLOCKS],
    /// `nLshifts[i]` — extra LSBs coded per sample in each block, 0..=10.
    pub lsb_shifts: [u8; MAX_SHELL_BLOCKS],
}

impl Excitation {
    /// Total pulses across the frame, i.e. `Σ sum_pulses[i]` — a cheap summary for a conformance
    /// tally and a natural sanity bound (a frame can never exceed `16 * block_count`).
    #[must_use]
    pub fn total_pulses(&self) -> u32 {
        self.pulse_counts[..self.block_count]
            .iter()
            .map(|&count| u32::from(count))
            .sum()
    }
}

/// Decode the LCG seed (RFC 6716 §4.2.7.7, Table 43; `decode_indices.c:150`).
///
/// It is a **per-frame** symbol read immediately after the LTP parameters and immediately before the
/// excitation, not decoder state: on the normal decode path the generator is re-seeded every frame.
#[must_use]
pub fn decode_seed(decoder: &mut RangeDecoder<'_>) -> u8 {
    decoder.dec_icdf(&SEED_ICDF, ICDF_FTB) as u8
}

/// Decode one shell block's 16 pulse positions (RFC 6716 §4.2.7.8.3; libopus `silk_shell_decoder`,
/// `shell_coder.c:118-151`).
///
/// The recursion is written out flat, exactly as the C does, because the *order* of the splits is
/// part of the bitstream: preorder over the binary tree, left child before right, and a partition
/// with no pulses codes nothing at all.
fn decode_shell_block(decoder: &mut RangeDecoder<'_>, total_pulses: u16, pulses: &mut [i16]) {
    debug_assert!(pulses.len() >= SHELL_BLOCK_LENGTH);

    /// `decode_split` (`shell_coder.c:60-75`): read the left child's share, the right child gets the
    /// rest. A zero-pulse partition codes nothing.
    fn split(decoder: &mut RangeDecoder<'_>, parent: u16, table: &'static [u8; 152]) -> (u16, u16) {
        if parent == 0 {
            return (0, 0);
        }
        let icdf = split_icdf(table, usize::from(parent));
        // `parent` is 1..=16 here: a decoded split can never exceed its parent, and the top-level
        // count is capped at 16 by its own PDF. So `icdf` is non-empty.
        if icdf.is_empty() {
            return (0, 0);
        }
        let left = decoder.dec_icdf(icdf, ICDF_FTB) as u16;
        (left, parent - left.min(parent))
    }

    let mut level1 = [0u16; 8];
    let mut level2 = [0u16; 4];
    let mut level3 = [0u16; 2];

    (level3[0], level3[1]) = split(decoder, total_pulses, &SHELL_CODE_TABLE3);

    (level2[0], level2[1]) = split(decoder, level3[0], &SHELL_CODE_TABLE2);

    (level1[0], level1[1]) = split(decoder, level2[0], &SHELL_CODE_TABLE1);
    let (a, b) = split(decoder, level1[0], &SHELL_CODE_TABLE0);
    (pulses[0], pulses[1]) = (a as i16, b as i16);
    let (a, b) = split(decoder, level1[1], &SHELL_CODE_TABLE0);
    (pulses[2], pulses[3]) = (a as i16, b as i16);

    (level1[2], level1[3]) = split(decoder, level2[1], &SHELL_CODE_TABLE1);
    let (a, b) = split(decoder, level1[2], &SHELL_CODE_TABLE0);
    (pulses[4], pulses[5]) = (a as i16, b as i16);
    let (a, b) = split(decoder, level1[3], &SHELL_CODE_TABLE0);
    (pulses[6], pulses[7]) = (a as i16, b as i16);

    (level2[2], level2[3]) = split(decoder, level3[1], &SHELL_CODE_TABLE2);

    (level1[4], level1[5]) = split(decoder, level2[2], &SHELL_CODE_TABLE1);
    let (a, b) = split(decoder, level1[4], &SHELL_CODE_TABLE0);
    (pulses[8], pulses[9]) = (a as i16, b as i16);
    let (a, b) = split(decoder, level1[5], &SHELL_CODE_TABLE0);
    (pulses[10], pulses[11]) = (a as i16, b as i16);

    (level1[6], level1[7]) = split(decoder, level2[3], &SHELL_CODE_TABLE1);
    let (a, b) = split(decoder, level1[6], &SHELL_CODE_TABLE0);
    (pulses[12], pulses[13]) = (a as i16, b as i16);
    let (a, b) = split(decoder, level1[7], &SHELL_CODE_TABLE0);
    (pulses[14], pulses[15]) = (a as i16, b as i16);
}

/// Decode the excitation's pulse magnitudes and signs into `pulses` (RFC 6716 §4.2.7.8.1-5; libopus
/// `silk_decode_pulses`, `decode_pulses.c:37-115`).
///
/// `pulses` is caller-owned and must hold at least `shell_block_count(frame_length) * 16` samples —
/// the *padded* length, since every shell block is decoded in full even when the frame stops inside
/// the last one. [`PULSE_BUFFER_LENGTH`] is always large enough.
///
/// On return `pulses[..padded]` holds signed pulse amplitudes; §4.2.7.8.6's reconstruction is
/// [`reconstruct`].
pub fn decode_pulses(
    decoder: &mut RangeDecoder<'_>,
    signal_type: SignalType,
    quant_offset_type: QuantOffsetType,
    frame_length: usize,
    pulses: &mut [i16],
) -> Result<Excitation, CodecError> {
    if frame_length == 0 || frame_length > MAX_FRAME_LENGTH {
        return Err(CodecError::Malformed(
            "silk: excitation frame length out of range",
        ));
    }
    let block_count = shell_block_count(frame_length);
    let padded = block_count * SHELL_BLOCK_LENGTH;
    if pulses.len() < padded {
        return Err(CodecError::Unsupported(
            "silk: pulse buffer shorter than the padded frame length",
        ));
    }
    let pulses = &mut pulses[..padded];

    // ── Rate level (§4.2.7.8.1) ───────────────────────────────────────────────────────────────
    // signalType >> 1 folds inactive and unvoiced onto the same row (decode_pulses.c:53).
    let rate_level = decoder.dec_icdf(&RATE_LEVELS_ICDF[signal_type.index() >> 1], ICDF_FTB);

    // ── Pulse counts, all blocks before any block's content (§4.2.7.8.2) ──────────────────────
    let mut pulse_counts = [0u8; MAX_SHELL_BLOCKS];
    let mut lsb_shifts = [0u8; MAX_SHELL_BLOCKS];
    for block in 0..block_count {
        let mut count = decoder.dec_icdf(pulse_count_icdf(rate_level), ICDF_FTB);
        let mut shifts = 0u8;
        while count == PULSE_COUNT_ESCAPE {
            shifts += 1;
            // Rate level 9 for the first ten escapes, then rate level 10, whose PDF cannot code the
            // escape — so this loop is bounded at MAX_LSB_SHIFTS by construction.
            count = decoder.dec_icdf(
                pulse_count_icdf(RATE_LEVEL_COUNT - 1 + usize::from(shifts == MAX_LSB_SHIFTS)),
                ICDF_FTB,
            );
            if shifts >= MAX_LSB_SHIFTS {
                // Defensive: a corrupt stream that somehow re-entered here would otherwise spin.
                // The PDF makes it unreachable; this is the "never spin" guarantee made explicit.
                break;
            }
        }
        pulse_counts[block] = count.min(MAX_PULSES) as u8;
        lsb_shifts[block] = shifts;
    }

    // ── Pulse locations (§4.2.7.8.3) ──────────────────────────────────────────────────────────
    for (block, chunk) in pulses.chunks_exact_mut(SHELL_BLOCK_LENGTH).enumerate() {
        if pulse_counts[block] > 0 {
            decode_shell_block(decoder, u16::from(pulse_counts[block]), chunk);
        } else {
            chunk.fill(0);
        }
    }

    // ── LSBs (§4.2.7.8.4) ─────────────────────────────────────────────────────────────────────
    // Read for *every* sample of a block that asked for them, including samples with no pulses and
    // the padding samples of a 10 ms mediumband frame.
    for (block, chunk) in pulses.chunks_exact_mut(SHELL_BLOCK_LENGTH).enumerate() {
        if lsb_shifts[block] == 0 {
            continue;
        }
        for sample in chunk.iter_mut() {
            let mut magnitude = i32::from(*sample);
            for _ in 0..lsb_shifts[block] {
                magnitude = (magnitude << 1) + decoder.dec_icdf(&LSB_ICDF, ICDF_FTB) as i32;
            }
            // 16 pulses shifted 10 times plus 10 LSBs is 17407, well inside i16.
            *sample = magnitude as i16;
        }
    }

    // ── Signs (§4.2.7.8.5) ────────────────────────────────────────────────────────────────────
    decode_signs(
        decoder,
        signal_type,
        quant_offset_type,
        &pulse_counts,
        &lsb_shifts,
        pulses,
    );

    Ok(Excitation {
        rate_level,
        block_count,
        pulse_counts,
        lsb_shifts,
    })
}

/// Attach signs to every non-zero sample (RFC 6716 §4.2.7.8.5; libopus `silk_decode_signs`,
/// `code_signs.c:73-115`).
///
/// The PDF is chosen per block by signal type, quantization offset type and the block's **pulse
/// count** — LSBs excluded, exactly as RFC 6716 §4.2.7.8.5 states. A block with zero pulses but a
/// non-zero LSB shift still codes signs, because the C's marker (`sum_pulses |= nLS << 5`) makes its
/// `p > 0` test pass while `p & 0x1F` still reads back zero.
fn decode_signs(
    decoder: &mut RangeDecoder<'_>,
    signal_type: SignalType,
    quant_offset_type: QuantOffsetType,
    pulse_counts: &[u8; MAX_SHELL_BLOCKS],
    lsb_shifts: &[u8; MAX_SHELL_BLOCKS],
    pulses: &mut [i16],
) {
    let offset_column = match quant_offset_type {
        QuantOffsetType::Low => 0usize,
        QuantOffsetType::High => 1,
    };
    // silk_SMULBB(7, silk_ADD_LSHIFT(quantOffsetType, signalType, 1)) (code_signs.c:90).
    let row = 7 * (offset_column + (signal_type.index() << 1));

    for (block, chunk) in pulses.chunks_exact_mut(SHELL_BLOCK_LENGTH).enumerate() {
        // The C's `p = sum_pulses[i]` after `sum_pulses[i] |= nLS << 5`.
        if pulse_counts[block] == 0 && lsb_shifts[block] == 0 {
            continue;
        }
        let icdf = [SIGN_ICDF[row + usize::from(pulse_counts[block]).min(6)], 0];
        for sample in chunk.iter_mut() {
            if *sample > 0 {
                // silk_dec_map(x) = 2x - 1: symbol 0 negates, symbol 1 leaves it positive.
                *sample *= 2 * decoder.dec_icdf(&icdf, ICDF_FTB) as i16 - 1;
            }
        }
    }
}

/// Reconstruct the excitation in Q14 from the signed pulses (RFC 6716 §4.2.7.8.6; libopus
/// `decode_core.c:70-88`).
///
/// Three steps per sample, in this order — the order matters, because the LCG advances between the
/// offset and the sign inversion and again after it:
///
/// 1. scale the pulse to Q14 and pull the magnitude back by `QUANT_LEVEL_ADJUST_Q10` (only when the
///    sample is non-zero — `sign(0) == 0`), then add the signal-type/offset-type quantization offset;
/// 2. advance the LCG and negate the sample when the new seed is negative;
/// 3. advance the LCG again by the *signed pulse* value.
///
/// `excitation_q14` is caller-owned and must hold at least `frame_length` samples; only
/// `pulses[..frame_length]` is read, so the padding samples of a 10 ms mediumband frame are parsed
/// and then ignored, as RFC 6716 §4.2.7.8 requires.
pub fn reconstruct(
    pulses: &[i16],
    signal_type: SignalType,
    quant_offset_type: QuantOffsetType,
    seed: u8,
    excitation_q14: &mut [i32],
) -> Result<(), CodecError> {
    let frame_length = excitation_q14.len();
    if pulses.len() < frame_length {
        return Err(CodecError::Unsupported(
            "silk: pulse buffer shorter than the excitation buffer",
        ));
    }
    let offset_q14 = i32::from(quant_offset_type.offset_q10(signal_type)) << 4;
    let adjust_q14 = QUANT_LEVEL_ADJUST_Q10 << 4;
    let mut seed = i32::from(seed);

    for (sample, &pulse) in excitation_q14.iter_mut().zip(pulses.iter()) {
        seed = RAND_INCREMENT.wrapping_add(seed.wrapping_mul(RAND_MULTIPLIER));
        let mut value = i32::from(pulse) << 14;
        // sign(0) == 0, so a zero sample gets no adjustment (RFC 6716 §4.2.7.8.6).
        if value > 0 {
            value -= adjust_q14;
        } else if value < 0 {
            value += adjust_q14;
        }
        value += offset_q14;
        *sample = if seed < 0 { -value } else { value };
        seed = seed.wrapping_add(i32::from(pulse));
    }
    Ok(())
}

/// The whole §4.2.7.7-8 excitation stage: pulses, then reconstruction.
///
/// `seed` comes from [`decode_seed`], which the caller reads at the end of the side info (before the
/// rate level). Both buffers are caller-owned: `pulses` must hold the padded length
/// (`shell_block_count(frame_length) * 16`, at most [`PULSE_BUFFER_LENGTH`]) and `excitation_q14` is
/// written for exactly `frame_length` samples — pass
/// `&mut channel.excitation_q14[..frame_length]`.
pub fn decode(
    decoder: &mut RangeDecoder<'_>,
    signal_type: SignalType,
    quant_offset_type: QuantOffsetType,
    frame_length: usize,
    seed: u8,
    pulses: &mut [i16],
    excitation_q14: &mut [i32],
) -> Result<Excitation, CodecError> {
    if excitation_q14.len() < frame_length {
        return Err(CodecError::Unsupported(
            "silk: excitation buffer shorter than the frame",
        ));
    }
    let excitation = decode_pulses(
        decoder,
        signal_type,
        quant_offset_type,
        frame_length,
        pulses,
    )?;
    reconstruct(
        pulses,
        signal_type,
        quant_offset_type,
        seed,
        &mut excitation_q14[..frame_length],
    )?;
    Ok(excitation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;
    use proptest::prelude::*;

    const FT: u16 = 256;

    fn pdf_from_icdf(icdf: &[u8]) -> Vec<u16> {
        let mut pdf = Vec::with_capacity(icdf.len());
        let mut previous = FT;
        for &entry in icdf {
            let entry = u16::from(entry);
            assert!(entry <= previous, "icdf must be non-increasing: {icdf:?}");
            pdf.push(previous - entry);
            previous = entry;
        }
        pdf
    }

    fn assert_well_formed(name: &str, icdf: &[u8]) {
        assert!(!icdf.is_empty(), "{name}: empty");
        assert_eq!(*icdf.last().unwrap(), 0, "{name}: must terminate at 0");
        assert_eq!(
            pdf_from_icdf(icdf)
                .iter()
                .map(|&p| u32::from(p))
                .sum::<u32>(),
            u32::from(FT),
            "{name}: probabilities must sum to 256"
        );
    }

    #[test]
    fn constants_match_the_c_defines() {
        assert_eq!(SHELL_BLOCK_LENGTH, 16);
        assert_eq!(MAX_SHELL_BLOCKS, 20);
        assert_eq!(PULSE_BUFFER_LENGTH, 320);
        assert_eq!(MAX_PULSES, 16);
        assert_eq!(RATE_LEVEL_COUNT, 10);
        assert_eq!(MAX_LSB_SHIFTS, 10);
        assert_eq!(QUANT_LEVEL_ADJUST_Q10, 80);
        assert_eq!(RAND_MULTIPLIER, 196_314_165);
        assert_eq!(RAND_INCREMENT, 907_633_515);
    }

    /// RFC 6716 Table 44 in full: the shell-block count for every (bandwidth, frame size) pair.
    #[test]
    fn shell_block_counts_match_rfc_table_44() {
        // (frame_length at the internal rate, expected blocks) — NB/MB/WB at 10 ms then 20 ms.
        for (frame_length, blocks) in [
            (80usize, 5usize),
            (120, 8),
            (160, 10),
            (160, 10),
            (240, 15),
            (320, 20),
        ] {
            assert_eq!(shell_block_count(frame_length), blocks, "{frame_length}");
        }
        // 10 ms MB is the only case that rounds up, and it pads by exactly 8 samples.
        assert_eq!(shell_block_count(120) * SHELL_BLOCK_LENGTH, 128);
    }

    #[test]
    fn every_excitation_table_is_a_well_formed_icdf() {
        for (index, row) in RATE_LEVELS_ICDF.iter().enumerate() {
            assert_well_formed(&format!("RATE_LEVELS_ICDF[{index}]"), row);
        }
        for level in 0..=RATE_LEVEL_COUNT {
            assert_well_formed(
                &format!("pulse_count_icdf({level})"),
                pulse_count_icdf(level),
            );
        }
        assert_well_formed("LSB_ICDF", &LSB_ICDF);
        for (name, table) in [
            ("SHELL_CODE_TABLE0", &SHELL_CODE_TABLE0),
            ("SHELL_CODE_TABLE1", &SHELL_CODE_TABLE1),
            ("SHELL_CODE_TABLE2", &SHELL_CODE_TABLE2),
            ("SHELL_CODE_TABLE3", &SHELL_CODE_TABLE3),
        ] {
            for pulse_count in 1..=MAX_PULSES {
                assert_well_formed(
                    &format!("{name}[p={pulse_count}]"),
                    split_icdf(table, pulse_count),
                );
            }
        }
        // The sign tables are two-symbol ICDFs assembled at decode time.
        for entry in SIGN_ICDF {
            assert!(
                entry > 0,
                "a sign ICDF entry of 0 would make both symbols impossible"
            );
        }
    }

    #[test]
    fn table_lengths_match_the_c_declarations() {
        assert_eq!(RATE_LEVELS_ICDF.len(), 2);
        assert_eq!(RATE_LEVELS_ICDF[0].len(), RATE_LEVEL_COUNT - 1);
        assert_eq!(PULSES_PER_BLOCK_ICDF.len(), RATE_LEVEL_COUNT);
        assert_eq!(PULSES_PER_BLOCK_ICDF[0].len(), MAX_PULSES + 2);
        assert_eq!(SHELL_CODE_TABLE_OFFSETS.len(), MAX_PULSES + 1);
        assert_eq!(SHELL_CODE_TABLE0.len(), 152);
        assert_eq!(SHELL_CODE_TABLE1.len(), 152);
        assert_eq!(SHELL_CODE_TABLE2.len(), 152);
        assert_eq!(SHELL_CODE_TABLE3.len(), 152);
        assert_eq!(SIGN_ICDF.len(), 42);
        assert_eq!(LSB_ICDF.len(), 2);
        // The offsets are the running sum of the (p + 1)-entry sub-tables, and the last sub-table
        // ends exactly at 152.
        let mut running = 0usize;
        for (pulse_count, &offset) in SHELL_CODE_TABLE_OFFSETS.iter().enumerate().skip(1) {
            assert_eq!(offset as usize, running, "offset for p={pulse_count}");
            running += pulse_count + 1;
        }
        assert_eq!(running, 152);
    }

    /// RFC 6716 Table 45.
    #[test]
    fn rate_level_pdfs_match_rfc_table_45() {
        assert_eq!(
            pdf_from_icdf(&RATE_LEVELS_ICDF[0]),
            vec![15, 51, 12, 46, 45, 13, 33, 27, 14]
        );
        assert_eq!(
            pdf_from_icdf(&RATE_LEVELS_ICDF[1]),
            vec![33, 30, 36, 17, 34, 49, 18, 21, 18]
        );
        // Inactive and unvoiced share row 0; only voiced selects row 1.
        assert_eq!(SignalType::Inactive.index() >> 1, 0);
        assert_eq!(SignalType::Unvoiced.index() >> 1, 0);
        assert_eq!(SignalType::Voiced.index() >> 1, 1);
    }

    /// RFC 6716 Table 46, all eleven rows including the derived rate level 10.
    #[test]
    fn pulse_count_pdfs_match_rfc_table_46() {
        let expected: [&[u16]; 11] = [
            &[131, 74, 25, 8, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            &[58, 93, 60, 23, 7, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            &[43, 51, 46, 33, 24, 16, 11, 8, 6, 3, 3, 3, 2, 1, 1, 2, 1, 2],
            &[17, 52, 71, 57, 31, 12, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            &[6, 21, 41, 53, 49, 35, 21, 11, 6, 3, 2, 2, 1, 1, 1, 1, 1, 1],
            &[
                7, 14, 22, 28, 29, 28, 25, 20, 17, 13, 11, 9, 7, 5, 4, 4, 3, 10,
            ],
            &[2, 5, 14, 29, 42, 46, 41, 31, 19, 11, 6, 3, 2, 1, 1, 1, 1, 1],
            &[
                1, 2, 4, 10, 19, 29, 35, 37, 34, 28, 20, 14, 8, 5, 4, 2, 2, 2,
            ],
            &[
                1, 2, 2, 5, 9, 14, 20, 24, 27, 28, 26, 23, 20, 15, 11, 8, 6, 15,
            ],
            &[1, 1, 1, 6, 27, 58, 56, 39, 25, 14, 10, 6, 3, 3, 2, 1, 1, 2],
            // Rate level 10: the same distribution shifted, with symbol 17 impossible.
            &[2, 1, 6, 27, 58, 56, 39, 25, 14, 10, 6, 3, 3, 2, 1, 1, 2],
        ];
        for (level, &row) in expected.iter().enumerate() {
            assert_eq!(
                pdf_from_icdf(pulse_count_icdf(level)),
                row,
                "rate level {level}"
            );
        }
        // Level 10 codes 17 symbols (0..=16), so the escape is unreachable — the bound on LSBs.
        assert_eq!(pulse_count_icdf(10).len(), MAX_PULSES + 1);
        assert_eq!(pulse_count_icdf(9).len(), MAX_PULSES + 2);
    }

    /// RFC 6716 Tables 47-50: the split PDFs for 16, 8, 4 and 2 sample partitions. libopus numbers
    /// its tables the other way round (table0 is the *smallest* partition), which is exactly the kind
    /// of off-by-one this test exists to catch.
    #[test]
    fn split_pdfs_match_rfc_tables_47_to_50() {
        // Table 47 — 16-sample partitions, libopus silk_shell_code_table3.
        let table_47: [&[u16]; 16] = [
            &[126, 130],
            &[56, 142, 58],
            &[25, 101, 104, 26],
            &[12, 60, 108, 64, 12],
            &[7, 35, 84, 87, 37, 6],
            &[4, 20, 59, 86, 63, 21, 3],
            &[3, 12, 38, 72, 75, 42, 12, 2],
            &[2, 8, 25, 54, 73, 59, 27, 7, 1],
            &[2, 5, 17, 39, 63, 65, 42, 18, 4, 1],
            &[1, 4, 12, 28, 49, 63, 54, 30, 11, 3, 1],
            &[1, 4, 8, 20, 37, 55, 57, 41, 22, 8, 2, 1],
            &[1, 3, 7, 15, 28, 44, 53, 48, 33, 16, 6, 1, 1],
            &[1, 2, 6, 12, 21, 35, 47, 48, 40, 25, 12, 5, 1, 1],
            &[1, 1, 4, 10, 17, 27, 37, 47, 43, 33, 21, 9, 4, 1, 1],
            &[1, 1, 1, 8, 14, 22, 33, 40, 43, 38, 28, 16, 8, 1, 1, 1],
            &[1, 1, 1, 1, 13, 18, 27, 36, 41, 41, 34, 24, 14, 1, 1, 1, 1],
        ];
        // Table 48 — 8-sample partitions, libopus silk_shell_code_table2.
        let table_48: [&[u16]; 16] = [
            &[127, 129],
            &[53, 149, 54],
            &[22, 105, 106, 23],
            &[11, 61, 111, 63, 10],
            &[6, 35, 86, 88, 36, 5],
            &[4, 20, 59, 87, 62, 21, 3],
            &[3, 13, 40, 71, 73, 41, 13, 2],
            &[3, 9, 27, 53, 70, 56, 28, 9, 1],
            &[3, 8, 19, 37, 57, 61, 44, 20, 6, 1],
            &[3, 7, 15, 28, 44, 54, 49, 33, 17, 5, 1],
            &[1, 7, 13, 22, 34, 46, 48, 38, 28, 14, 4, 1],
            &[1, 1, 11, 22, 27, 35, 42, 47, 33, 25, 10, 1, 1],
            &[1, 1, 6, 14, 26, 37, 43, 43, 37, 26, 14, 6, 1, 1],
            &[1, 1, 4, 10, 20, 31, 40, 42, 40, 31, 20, 10, 4, 1, 1],
            &[1, 1, 3, 8, 16, 26, 35, 38, 38, 35, 26, 16, 8, 3, 1, 1],
            &[1, 1, 2, 6, 12, 21, 30, 36, 38, 36, 30, 21, 12, 6, 2, 1, 1],
        ];
        // Table 49 — 4-sample partitions, libopus silk_shell_code_table1.
        let table_49: [&[u16]; 16] = [
            &[127, 129],
            &[49, 157, 50],
            &[20, 107, 109, 20],
            &[11, 60, 113, 62, 10],
            &[7, 36, 84, 87, 36, 6],
            &[6, 24, 57, 82, 60, 23, 4],
            &[5, 18, 39, 64, 68, 42, 16, 4],
            &[6, 14, 29, 47, 61, 52, 30, 14, 3],
            &[1, 15, 23, 35, 51, 50, 40, 30, 10, 1],
            &[1, 1, 21, 32, 42, 52, 46, 41, 18, 1, 1],
            &[1, 6, 16, 27, 36, 42, 42, 36, 27, 16, 6, 1],
            &[1, 5, 12, 21, 31, 38, 40, 38, 31, 21, 12, 5, 1],
            &[1, 3, 9, 17, 26, 34, 38, 38, 34, 26, 17, 9, 3, 1],
            &[1, 3, 7, 14, 22, 29, 34, 36, 34, 29, 22, 14, 7, 3, 1],
            &[1, 2, 5, 11, 18, 25, 31, 35, 35, 31, 25, 18, 11, 5, 2, 1],
            &[1, 1, 4, 9, 15, 21, 28, 32, 34, 32, 28, 21, 15, 9, 4, 1, 1],
        ];
        // Table 50 — 2-sample partitions, libopus silk_shell_code_table0.
        let table_50: [&[u16]; 16] = [
            &[128, 128],
            &[42, 172, 42],
            &[21, 107, 107, 21],
            &[12, 60, 112, 61, 11],
            &[8, 34, 86, 86, 35, 7],
            &[8, 23, 55, 90, 55, 20, 5],
            &[5, 15, 38, 72, 72, 36, 15, 3],
            &[6, 12, 27, 52, 77, 47, 20, 10, 5],
            &[6, 19, 28, 35, 40, 40, 35, 28, 19, 6],
            &[4, 14, 22, 31, 37, 40, 37, 31, 22, 14, 4],
            &[3, 10, 18, 26, 33, 38, 38, 33, 26, 18, 10, 3],
            &[2, 8, 13, 21, 29, 36, 38, 36, 29, 21, 13, 8, 2],
            &[1, 5, 10, 17, 25, 32, 38, 38, 32, 25, 17, 10, 5, 1],
            &[1, 4, 7, 13, 21, 29, 35, 36, 35, 29, 21, 13, 7, 4, 1],
            &[1, 2, 5, 10, 17, 25, 32, 36, 36, 32, 25, 17, 10, 5, 2, 1],
            &[1, 2, 4, 7, 13, 21, 28, 34, 36, 34, 28, 21, 13, 7, 4, 2, 1],
        ];

        for (table, expected, label) in [
            (&SHELL_CODE_TABLE3, table_47, "Table 47 (16 samples)"),
            (&SHELL_CODE_TABLE2, table_48, "Table 48 (8 samples)"),
            (&SHELL_CODE_TABLE1, table_49, "Table 49 (4 samples)"),
            (&SHELL_CODE_TABLE0, table_50, "Table 50 (2 samples)"),
        ] {
            for pulse_count in 1..=MAX_PULSES {
                assert_eq!(
                    pdf_from_icdf(split_icdf(table, pulse_count)),
                    expected[pulse_count - 1],
                    "{label}, pulse count {pulse_count}"
                );
            }
        }
    }

    /// RFC 6716 Table 51.
    #[test]
    fn lsb_pdf_matches_rfc_table_51() {
        assert_eq!(pdf_from_icdf(&LSB_ICDF), vec![136, 120]);
    }

    /// RFC 6716 Table 52 in full — 6 (signal type, offset type) rows x 7 pulse-count columns.
    #[test]
    fn sign_pdfs_match_rfc_table_52() {
        let expected: [(SignalType, QuantOffsetType, [[u16; 2]; 7]); 6] = [
            (
                SignalType::Inactive,
                QuantOffsetType::Low,
                [
                    [2, 254],
                    [207, 49],
                    [189, 67],
                    [179, 77],
                    [174, 82],
                    [163, 93],
                    [157, 99],
                ],
            ),
            (
                SignalType::Inactive,
                QuantOffsetType::High,
                [
                    [58, 198],
                    [245, 11],
                    [238, 18],
                    [232, 24],
                    [225, 31],
                    [220, 36],
                    [211, 45],
                ],
            ),
            (
                SignalType::Unvoiced,
                QuantOffsetType::Low,
                [
                    [1, 255],
                    [210, 46],
                    [190, 66],
                    [178, 78],
                    [169, 87],
                    [162, 94],
                    [152, 104],
                ],
            ),
            (
                SignalType::Unvoiced,
                QuantOffsetType::High,
                [
                    [48, 208],
                    [242, 14],
                    [235, 21],
                    [224, 32],
                    [214, 42],
                    [205, 51],
                    [190, 66],
                ],
            ),
            (
                SignalType::Voiced,
                QuantOffsetType::Low,
                [
                    [1, 255],
                    [162, 94],
                    [152, 104],
                    [147, 109],
                    [144, 112],
                    [141, 115],
                    [138, 118],
                ],
            ),
            (
                SignalType::Voiced,
                QuantOffsetType::High,
                [
                    [8, 248],
                    [203, 53],
                    [187, 69],
                    [176, 80],
                    [168, 88],
                    [161, 95],
                    [154, 102],
                ],
            ),
        ];
        for (signal_type, offset_type, rows) in expected {
            let column = match offset_type {
                QuantOffsetType::Low => 0usize,
                QuantOffsetType::High => 1,
            };
            let row = 7 * (column + (signal_type.index() << 1));
            for (pulse_count, expected_pdf) in rows.iter().enumerate() {
                let icdf = [SIGN_ICDF[row + pulse_count], 0];
                assert_eq!(
                    pdf_from_icdf(&icdf),
                    expected_pdf.to_vec(),
                    "{signal_type:?}/{offset_type:?}, {pulse_count} pulses"
                );
            }
        }
    }

    // ── Decode tests driven by our own range encoder ───────────────────────────────────────────

    /// A symbol list to encode: `(symbol, icdf)`.
    fn encode(symbols: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let mut buffer = vec![0u8; 4096];
        let written = {
            let mut encoder = RangeEncoder::new(&mut buffer);
            for (symbol, icdf) in symbols {
                encoder.enc_icdf(*symbol, icdf, ICDF_FTB);
            }
            encoder.done() as usize
        };
        buffer.truncate(written.max(1));
        buffer
    }

    /// libopus' `silk_shell_encoder` (`shell_coder.c:78-115`), written here so the decoder is tested
    /// against the *encoder's* symbol order rather than against itself.
    fn shell_encode_symbols(block: &[u16; SHELL_BLOCK_LENGTH], out: &mut Vec<(usize, Vec<u8>)>) {
        let combine = |input: &[u16]| -> Vec<u16> {
            input
                .chunks_exact(2)
                .map(|pair| pair[0] + pair[1])
                .collect()
        };
        let level0: Vec<u16> = block.to_vec();
        let level1 = combine(&level0);
        let level2 = combine(&level1);
        let level3 = combine(&level2);
        let level4 = combine(&level3);

        let mut push = |child: u16, parent: u16, table: &'static [u8; 152]| {
            if parent > 0 {
                out.push((
                    usize::from(child),
                    split_icdf(table, usize::from(parent)).to_vec(),
                ));
            }
        };
        push(level3[0], level4[0], &SHELL_CODE_TABLE3);
        push(level2[0], level3[0], &SHELL_CODE_TABLE2);
        push(level1[0], level2[0], &SHELL_CODE_TABLE1);
        push(level0[0], level1[0], &SHELL_CODE_TABLE0);
        push(level0[2], level1[1], &SHELL_CODE_TABLE0);
        push(level1[2], level2[1], &SHELL_CODE_TABLE1);
        push(level0[4], level1[2], &SHELL_CODE_TABLE0);
        push(level0[6], level1[3], &SHELL_CODE_TABLE0);
        push(level2[2], level3[1], &SHELL_CODE_TABLE2);
        push(level1[4], level2[2], &SHELL_CODE_TABLE1);
        push(level0[8], level1[4], &SHELL_CODE_TABLE0);
        push(level0[10], level1[5], &SHELL_CODE_TABLE0);
        push(level1[6], level2[3], &SHELL_CODE_TABLE1);
        push(level0[12], level1[6], &SHELL_CODE_TABLE0);
        push(level0[14], level1[7], &SHELL_CODE_TABLE0);
    }

    /// Round-trip a single shell block through the encoder's symbol order: the decoder must place
    /// every pulse back exactly where it came from, for the whole of RFC 6716 §4.2.7.8.3's freedom
    /// (all pulses in one sample, one per sample, and everything between).
    #[test]
    fn shell_blocks_round_trip_through_the_encoder_symbol_order() {
        let cases: [[u16; SHELL_BLOCK_LENGTH]; 6] = [
            // All 16 in one place — the codebook's extreme.
            [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16],
            // One per sample.
            [1; SHELL_BLOCK_LENGTH],
            // Lopsided.
            [3, 0, 1, 0, 0, 5, 0, 0, 2, 0, 0, 0, 4, 0, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        for block in cases {
            let total: u16 = block.iter().sum();
            let mut symbols = Vec::new();
            shell_encode_symbols(&block, &mut symbols);
            let bytes = encode(&symbols);
            let mut decoder = RangeDecoder::new(&bytes);
            let mut decoded = [0i16; SHELL_BLOCK_LENGTH];
            decode_shell_block(&mut decoder, total, &mut decoded);
            let expected: Vec<i16> = block.iter().map(|&value| value as i16).collect();
            assert_eq!(decoded.to_vec(), expected, "block {block:?}");
        }
    }

    /// Every pulse count 1..=16, placed in every single position, round-trips. This walks all 16
    /// sub-tables of all four levels, which is what proves the split tables are paired with the right
    /// partition sizes.
    #[test]
    fn every_pulse_count_in_every_position_round_trips() {
        for total in 1..=MAX_PULSES as u16 {
            for position in 0..SHELL_BLOCK_LENGTH {
                let mut block = [0u16; SHELL_BLOCK_LENGTH];
                block[position] = total;
                let mut symbols = Vec::new();
                shell_encode_symbols(&block, &mut symbols);
                let bytes = encode(&symbols);
                let mut decoder = RangeDecoder::new(&bytes);
                let mut decoded = [0i16; SHELL_BLOCK_LENGTH];
                decode_shell_block(&mut decoder, total, &mut decoded);
                for (index, &value) in decoded.iter().enumerate() {
                    let expected = if index == position { total as i16 } else { 0 };
                    assert_eq!(
                        value, expected,
                        "{total} pulses at {position}, sample {index}"
                    );
                }
            }
        }
    }

    /// Build the full §4.2.7.8 symbol stream for one frame, the way an encoder would, then decode it.
    /// `blocks` gives each block's pulses and how many extra LSBs it carries.
    #[allow(clippy::type_complexity)]
    fn encode_frame(
        signal_type: SignalType,
        quant_offset_type: QuantOffsetType,
        rate_level: usize,
        blocks: &[(
            [u16; SHELL_BLOCK_LENGTH],
            u8,
            [u16; SHELL_BLOCK_LENGTH],
            [bool; SHELL_BLOCK_LENGTH],
        )],
    ) -> Vec<u8> {
        let mut symbols: Vec<(usize, Vec<u8>)> = Vec::new();
        symbols.push((
            rate_level,
            RATE_LEVELS_ICDF[signal_type.index() >> 1].to_vec(),
        ));
        for (block, shifts, _, _) in blocks {
            let total: u16 = block.iter().sum();
            for shift in 0..*shifts {
                symbols.push((
                    PULSE_COUNT_ESCAPE,
                    pulse_count_icdf(if shift == 0 {
                        rate_level
                    } else {
                        RATE_LEVEL_COUNT - 1
                    })
                    .to_vec(),
                ));
            }
            let count_icdf = if *shifts == 0 {
                pulse_count_icdf(rate_level)
            } else {
                pulse_count_icdf(RATE_LEVEL_COUNT - 1)
            };
            symbols.push((usize::from(total), count_icdf.to_vec()));
        }
        for (block, _, _, _) in blocks {
            if block.iter().sum::<u16>() > 0 {
                shell_encode_symbols(block, &mut symbols);
            }
        }
        for (_, shifts, lsbs, _) in blocks {
            if *shifts == 0 {
                continue;
            }
            for &lsb_word in lsbs.iter() {
                for bit in (0..*shifts).rev() {
                    symbols.push((usize::from((lsb_word >> bit) & 1), LSB_ICDF.to_vec()));
                }
            }
        }
        let column = match quant_offset_type {
            QuantOffsetType::Low => 0usize,
            QuantOffsetType::High => 1,
        };
        let row = 7 * (column + (signal_type.index() << 1));
        for (block, shifts, lsbs, signs) in blocks {
            let count: u16 = block.iter().sum();
            if count == 0 && *shifts == 0 {
                continue;
            }
            let icdf = vec![SIGN_ICDF[row + usize::from(count).min(6)], 0];
            for sample in 0..SHELL_BLOCK_LENGTH {
                let magnitude = if *shifts == 0 {
                    u32::from(block[sample])
                } else {
                    (u32::from(block[sample]) << *shifts) + u32::from(lsbs[sample])
                };
                if magnitude > 0 {
                    symbols.push((usize::from(signs[sample]), icdf.clone()));
                }
            }
        }
        encode(&symbols)
    }

    /// A full 20 ms wideband frame: 20 shell blocks, a mix of empty and populated, decoded back to
    /// the exact signed pulses.
    #[test]
    fn a_full_frame_round_trips_pulses_and_signs() {
        let mut blocks = Vec::new();
        for block in 0..20usize {
            let mut pulses = [0u16; SHELL_BLOCK_LENGTH];
            if block % 3 != 0 {
                pulses[block % SHELL_BLOCK_LENGTH] = (block % 5) as u16 + 1;
                pulses[(block * 7) % SHELL_BLOCK_LENGTH] += 1;
            }
            let mut signs = [true; SHELL_BLOCK_LENGTH];
            signs[block % SHELL_BLOCK_LENGTH] = block % 2 == 0;
            blocks.push((pulses, 0u8, [0u16; SHELL_BLOCK_LENGTH], signs));
        }
        let bytes = encode_frame(SignalType::Voiced, QuantOffsetType::High, 4, &blocks);
        let mut decoder = RangeDecoder::new(&bytes);
        let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
        let excitation = decode_pulses(
            &mut decoder,
            SignalType::Voiced,
            QuantOffsetType::High,
            320,
            &mut pulses,
        )
        .expect("decode");
        assert_eq!(excitation.rate_level, 4);
        assert_eq!(excitation.block_count, 20);
        for (block, (expected, _, _, signs)) in blocks.iter().enumerate() {
            assert_eq!(
                u16::from(excitation.pulse_counts[block]),
                expected.iter().sum::<u16>(),
                "block {block} pulse count"
            );
            for sample in 0..SHELL_BLOCK_LENGTH {
                let magnitude = expected[sample] as i16;
                let signed = if magnitude == 0 {
                    0
                } else if signs[sample] {
                    magnitude
                } else {
                    -magnitude
                };
                assert_eq!(
                    pulses[block * SHELL_BLOCK_LENGTH + sample],
                    signed,
                    "block {block} sample {sample}"
                );
            }
        }
        assert_eq!(
            excitation.total_pulses(),
            blocks
                .iter()
                .map(|b| u32::from(b.0.iter().sum::<u16>()))
                .sum::<u32>()
        );
    }

    /// The escape path: a block that codes extra LSBs doubles the magnitude per LSB and reads one for
    /// *every* sample, including samples with no pulses (RFC 6716 §4.2.7.8.4).
    #[test]
    fn lsb_escape_doubles_the_magnitude_and_covers_every_sample() {
        let mut pulses_in = [0u16; SHELL_BLOCK_LENGTH];
        pulses_in[0] = 3;
        pulses_in[9] = 1;
        let mut lsbs = [0u16; SHELL_BLOCK_LENGTH];
        // Two extra LSBs: magnitudes become (pulse << 2) + lsb.
        lsbs[0] = 0b10;
        lsbs[5] = 0b11; // a sample with no pulses but non-zero LSBs
        lsbs[9] = 0b01;
        let signs = [true; SHELL_BLOCK_LENGTH];
        let blocks = vec![
            (pulses_in, 2u8, lsbs, signs),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
        ];
        let bytes = encode_frame(SignalType::Unvoiced, QuantOffsetType::Low, 0, &blocks);
        let mut decoder = RangeDecoder::new(&bytes);
        let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
        let excitation = decode_pulses(
            &mut decoder,
            SignalType::Unvoiced,
            QuantOffsetType::Low,
            80,
            &mut pulses,
        )
        .expect("decode");
        assert_eq!(excitation.lsb_shifts[0], 2);
        assert_eq!(excitation.pulse_counts[0], 4, "the count excludes the LSBs");
        assert_eq!(pulses[0], (3 << 2) + 0b10);
        assert_eq!(pulses[5], 0b11, "a sample with LSBs but no pulses");
        assert_eq!(pulses[9], (1 << 2) + 0b01);
        assert_eq!(pulses[1], 0);
    }

    /// A block with **zero** pulses but non-zero LSB shifts still codes signs, using the strongly
    /// positive-skewed "0 pulses" PDF (`decode_pulses.c:107` + `code_signs.c:97`).
    #[test]
    fn a_zero_pulse_block_with_lsbs_still_codes_signs() {
        let mut lsbs = [0u16; SHELL_BLOCK_LENGTH];
        lsbs[3] = 1;
        lsbs[4] = 1;
        let mut signs = [true; SHELL_BLOCK_LENGTH];
        signs[3] = false;
        let blocks = vec![
            ([0u16; SHELL_BLOCK_LENGTH], 1u8, lsbs, signs),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0,
                [0; SHELL_BLOCK_LENGTH],
                signs,
            ),
        ];
        let bytes = encode_frame(SignalType::Inactive, QuantOffsetType::Low, 2, &blocks);
        let mut decoder = RangeDecoder::new(&bytes);
        let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
        let excitation = decode_pulses(
            &mut decoder,
            SignalType::Inactive,
            QuantOffsetType::Low,
            80,
            &mut pulses,
        )
        .expect("decode");
        assert_eq!(excitation.pulse_counts[0], 0);
        assert_eq!(excitation.lsb_shifts[0], 1);
        assert_eq!(
            pulses[3], -1,
            "sign was coded even though the block has 0 pulses"
        );
        assert_eq!(pulses[4], 1);
    }

    /// A 10 ms mediumband frame parses 8 shell blocks (128 samples) for a 120-sample frame, and the
    /// last 8 samples are parsed but never reach the excitation (RFC 6716 §4.2.7.8).
    #[test]
    fn ten_millisecond_mediumband_parses_the_padding_block() {
        let mut tail = [0u16; SHELL_BLOCK_LENGTH];
        tail[15] = 2; // lands in the discarded padding
        tail[0] = 1; // lands in sample 112, which is kept
        let signs = [true; SHELL_BLOCK_LENGTH];
        let mut blocks = vec![
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0u8,
                [0; SHELL_BLOCK_LENGTH],
                signs
            );
            7
        ];
        blocks.push((tail, 0, [0; SHELL_BLOCK_LENGTH], signs));
        let bytes = encode_frame(SignalType::Unvoiced, QuantOffsetType::Low, 1, &blocks);
        let mut decoder = RangeDecoder::new(&bytes);
        let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
        let mut excitation_q14 = [0i32; 120];
        let summary = decode(
            &mut decoder,
            SignalType::Unvoiced,
            QuantOffsetType::Low,
            120,
            0,
            &mut pulses,
            &mut excitation_q14,
        )
        .expect("decode");
        assert_eq!(summary.block_count, 8);
        assert_eq!(pulses[112], 1);
        assert_eq!(pulses[127], 2, "parsed even though it is discarded");
        assert_eq!(excitation_q14.len(), 120);
    }

    /// RFC 6716 §4.2.7.8.6, implemented straight from the spec text in Q23, must agree with the
    /// libopus-shaped Q14 implementation for every reachable input.
    #[test]
    fn reconstruction_matches_the_rfc_q23_formula() {
        /// The RFC's Table 53 offsets, in Q23. Independent of `QuantOffsetType::offset_q10`.
        fn offset_q23(signal_type: SignalType, quant_offset_type: QuantOffsetType) -> i32 {
            match (signal_type, quant_offset_type) {
                (SignalType::Voiced, QuantOffsetType::Low) => 8,
                (SignalType::Voiced, QuantOffsetType::High) => 25,
                (_, QuantOffsetType::Low) => 25,
                (_, QuantOffsetType::High) => 60,
            }
        }
        /// The RFC's procedure verbatim, in 32-bit wrapping arithmetic.
        fn rfc_reconstruct(
            pulses: &[i16],
            signal_type: SignalType,
            quant_offset_type: QuantOffsetType,
            seed: u8,
            out: &mut [i32],
        ) {
            let mut state = u32::from(seed);
            for (sample, &raw) in out.iter_mut().zip(pulses) {
                let raw = i32::from(raw);
                let sign = match raw.cmp(&0) {
                    std::cmp::Ordering::Greater => 1,
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                };
                let mut value = (raw << 8) - sign * 20 + offset_q23(signal_type, quant_offset_type);
                state = 196_314_165u32.wrapping_mul(state).wrapping_add(907_633_515);
                if state & 0x8000_0000 != 0 {
                    value = -value;
                }
                state = state.wrapping_add(raw as u32);
                *sample = value;
            }
        }

        let mut pulses = [0i16; 64];
        for (index, slot) in pulses.iter_mut().enumerate() {
            // A spread of magnitudes and signs, including zeros and the extremes.
            *slot = match index % 8 {
                0 => 0,
                1 => 1,
                2 => -1,
                3 => 16,
                4 => -16,
                5 => 17407, // 16 pulses with 10 LSB shifts, the largest magnitude possible
                6 => -17407,
                _ => (index as i16) - 32,
            };
        }
        for signal_type in [
            SignalType::Inactive,
            SignalType::Unvoiced,
            SignalType::Voiced,
        ] {
            for offset_type in [QuantOffsetType::Low, QuantOffsetType::High] {
                for seed in 0u8..4 {
                    let mut ours = [0i32; 64];
                    reconstruct(&pulses, signal_type, offset_type, seed, &mut ours).expect("q14");
                    let mut theirs = [0i32; 64];
                    rfc_reconstruct(&pulses, signal_type, offset_type, seed, &mut theirs);
                    for (index, (&q14, &q23)) in ours.iter().zip(theirs.iter()).enumerate() {
                        assert_eq!(
                            q14,
                            q23 * 64,
                            "{signal_type:?}/{offset_type:?} seed {seed} sample {index}: \
                             exc_Q14 must be exactly 64x the RFC's e_Q23"
                        );
                    }
                }
            }
        }
    }

    /// The quantization offset is added to *every* sample including zeros, and `sign(0) == 0` means a
    /// zero sample never gets the `QUANT_LEVEL_ADJUST_Q10` correction (RFC 6716 §4.2.7.8.6).
    #[test]
    fn zero_samples_get_the_offset_but_no_step_adjustment() {
        let pulses = [0i16, 1, -1];
        let mut out = [0i32; 3];
        // Seed 0: the first LCG output is 907633515 (positive), so sample 0 is not inverted.
        reconstruct(
            &pulses,
            SignalType::Voiced,
            QuantOffsetType::Low,
            0,
            &mut out,
        )
        .expect("reconstruct");
        // offset_Q10 for voiced/low is 32, i.e. 512 in Q14.
        assert_eq!(out[0].abs(), 32 << 4);
        // A magnitude-1 pulse: (1 << 14) - 1280 + 512 = 15616.
        assert_eq!(out[1].abs(), (1 << 14) - 1280 + 512);
        // A magnitude-(-1) pulse: -(1 << 14) + 1280 + 512 = -14592.
        assert_eq!(out[2].abs(), (1 << 14) - 1280 - 512);
    }

    /// The LCG is the RFC's, bit for bit, including the wrap.
    #[test]
    fn lcg_matches_the_rfc_recurrence() {
        let mut seed = 3i32;
        let mut reference = 3u32;
        for step in 0..1000 {
            seed = RAND_INCREMENT.wrapping_add(seed.wrapping_mul(RAND_MULTIPLIER));
            reference = 196_314_165u32
                .wrapping_mul(reference)
                .wrapping_add(907_633_515);
            assert_eq!(seed as u32, reference, "step {step}");
        }
    }

    #[test]
    fn buffers_that_are_too_small_are_rejected_not_panicked() {
        let bytes = [0u8; 8];
        let mut decoder = RangeDecoder::new(&bytes);
        let mut pulses = [0i16; 16];
        assert!(decode_pulses(
            &mut decoder,
            SignalType::Voiced,
            QuantOffsetType::Low,
            320,
            &mut pulses
        )
        .is_err());
        let mut decoder = RangeDecoder::new(&bytes);
        let mut big = [0i16; PULSE_BUFFER_LENGTH];
        assert!(decode_pulses(
            &mut decoder,
            SignalType::Voiced,
            QuantOffsetType::Low,
            0,
            &mut big
        )
        .is_err());
        let mut decoder = RangeDecoder::new(&bytes);
        assert!(decode_pulses(
            &mut decoder,
            SignalType::Voiced,
            QuantOffsetType::Low,
            MAX_FRAME_LENGTH + 1,
            &mut big
        )
        .is_err());
        let mut out = [0i32; 4];
        assert!(reconstruct(
            &[0i16; 2],
            SignalType::Voiced,
            QuantOffsetType::Low,
            0,
            &mut out
        )
        .is_err());
    }

    /// Decoding one frame allocates nothing on the heap: everything is caller-owned or on the stack.
    #[test]
    fn decode_writes_only_into_caller_owned_buffers() {
        let signs = [true; SHELL_BLOCK_LENGTH];
        let blocks = vec![
            (
                [0u16; SHELL_BLOCK_LENGTH],
                0u8,
                [0; SHELL_BLOCK_LENGTH],
                signs
            );
            10
        ];
        let bytes = encode_frame(SignalType::Inactive, QuantOffsetType::Low, 0, &blocks);
        let mut decoder = RangeDecoder::new(&bytes);
        let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
        let mut excitation_q14 = [0i32; MAX_FRAME_LENGTH];
        let summary = decode(
            &mut decoder,
            SignalType::Inactive,
            QuantOffsetType::Low,
            160,
            3,
            &mut pulses,
            &mut excitation_q14[..160],
        )
        .expect("decode");
        assert_eq!(summary.block_count, 10);
        assert_eq!(summary.total_pulses(), 0);
        // Every sample is the bare offset, sign-inverted by the LCG.
        for &sample in &excitation_q14[..160] {
            assert_eq!(sample.abs(), 100 << 4);
        }
        // Nothing was written past the frame.
        assert!(excitation_q14[160..].iter().all(|&value| value == 0));
    }

    proptest! {
        /// Arbitrary bytes decoded as an excitation must never panic, never spin and never leave a
        /// pulse count or LSB shift outside its legal range. The range decoder reads zeros past the
        /// end of a truncated buffer, so this also covers truncation.
        #[test]
        fn arbitrary_payloads_never_panic_and_stay_in_range(
            bytes in proptest::collection::vec(any::<u8>(), 0..200),
            signal in 0usize..3,
            offset in 0usize..2,
            frame_index in 0usize..6,
            seed in 0u8..4,
        ) {
            let signal_type = [SignalType::Inactive, SignalType::Unvoiced, SignalType::Voiced][signal];
            let quant_offset_type = [QuantOffsetType::Low, QuantOffsetType::High][offset];
            let frame_length = [80usize, 120, 160, 160, 240, 320][frame_index];
            let mut decoder = RangeDecoder::new(&bytes);
            let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
            let mut excitation_q14 = [0i32; MAX_FRAME_LENGTH];
            let summary = decode(
                &mut decoder,
                signal_type,
                quant_offset_type,
                frame_length,
                seed,
                &mut pulses,
                &mut excitation_q14[..frame_length],
            ).expect("a legal frame length and large enough buffers always decode");
            prop_assert_eq!(summary.block_count, shell_block_count(frame_length));
            prop_assert!(summary.rate_level < RATE_LEVEL_COUNT - 1);
            for block in 0..summary.block_count {
                prop_assert!(summary.pulse_counts[block] as usize <= MAX_PULSES);
                prop_assert!(summary.lsb_shifts[block] <= MAX_LSB_SHIFTS);
            }
            // Every block's magnitudes sum back to its pulse count once the LSBs are stripped.
            for block in 0..summary.block_count {
                let shifts = summary.lsb_shifts[block];
                let sum: u32 = pulses
                    [block * SHELL_BLOCK_LENGTH..(block + 1) * SHELL_BLOCK_LENGTH]
                    .iter()
                    .map(|&value| (value.unsigned_abs() as u32) >> shifts)
                    .sum();
                prop_assert_eq!(sum, u32::from(summary.pulse_counts[block]));
            }
        }

        /// A pulse buffer shorter than the padded frame length is an error, never a panic.
        #[test]
        fn short_buffers_error_instead_of_panicking(
            bytes in proptest::collection::vec(any::<u8>(), 0..64),
            capacity in 0usize..320,
        ) {
            let mut decoder = RangeDecoder::new(&bytes);
            let mut pulses = vec![0i16; capacity];
            let result = decode_pulses(
                &mut decoder,
                SignalType::Voiced,
                QuantOffsetType::High,
                320,
                &mut pulses,
            );
            prop_assert!(result.is_err());
        }
    }
}
