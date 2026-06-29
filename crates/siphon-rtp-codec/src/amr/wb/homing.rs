//! AMR-WB decoder homing (3GPP TS 26.173 `homing.c` / `homing.tab`), ported bit-exact for all 9
//! speech modes.
//!
//! The codec defines a **decoder homing frame** (DHF): a fixed parameter pattern per mode that, when
//! received, drives the decoder to a known reset state. The reference test vectors begin with two
//! such homing frames; while homed, the decoder emits the constant [`EHF_MASK`] (`0x0008`) instead
//! of synthesised speech, and resets after the homing frame. [`homing_frame_test`] /
//! [`homing_frame_test_first`] check a frame's serial bits against the mode's DHF pattern.

use super::bitstream::{NB_BITS, SerialBits};
use crate::amr::basic_ops::{shl, shr};

/// Encoder/decoder homing-frame output mask (`EHF_MASK`, `0x0008`).
pub const EHF_MASK: i16 = 0x0008;

/// First-subframe parameter bit counts per speech mode (`prmnofsf`).
const PRMNOFSF: [i16; 9] = [63, 81, 100, 108, 116, 128, 136, 152, 156];

/// Per-mode decoder homing frame patterns (`dfh_M*`), as 15-bit parameter groups (`homing.tab`).
/// Indexed by speech mode 0..=8.
const DHF: [&[i16]; 9] = [
    &[3168, 29954, 29213, 16121, 64, 13440, 30624, 16430, 19008],
    &[
        3168, 31665, 9943, 9123, 15599, 4358, 20248, 2048, 17040, 27787, 16816, 13888,
    ],
    &[
        3168, 31665, 9943, 9128, 3647, 8129, 30930, 27926, 18880, 12319, 496, 1042, 4061, 20446,
        25629, 28069, 13948,
    ],
    &[
        3168, 31665, 9943, 9131, 24815, 655, 26616, 26764, 7238, 19136, 6144, 88, 4158, 25733,
        30567, 30494, 221, 20321, 17823,
    ],
    &[
        3168, 31665, 9943, 9131, 24815, 700, 3824, 7271, 26400, 9528, 6594, 26112, 108, 2068, 12867,
        16317, 23035, 24632, 7528, 1752, 6759, 24576,
    ],
    &[
        3168, 31665, 9943, 9135, 14787, 14423, 30477, 24927, 25345, 30154, 916, 5728, 18978, 2048,
        528, 16449, 2436, 3581, 23527, 29479, 8237, 16810, 27091, 19052, 0,
    ],
    &[
        3168, 31665, 9943, 9129, 8637, 31807, 24646, 736, 28643, 2977, 2566, 25564, 12930, 13960,
        2048, 834, 3270, 4100, 26920, 16237, 31227, 17667, 15059, 20589, 30249, 29123, 0,
    ],
    &[
        3168, 31665, 9943, 9132, 16748, 3202, 28179, 16317, 30590, 15857, 19960, 8818, 21711, 21538,
        4260, 16690, 20224, 3666, 4194, 9497, 16320, 15388, 5755, 31551, 14080, 3574, 15932, 50,
        23392, 26053, 31216,
    ],
    &[
        3168, 31665, 9943, 9134, 24776, 5857, 18475, 28535, 29662, 14321, 16725, 4396, 29353, 10003,
        17068, 20504, 720, 0, 8465, 12581, 28863, 24774, 9709, 26043, 7941, 27649, 13965, 15236,
        18026, 22047, 16681, 3968,
    ],
];

/// Mode 8 (23.85 kbit/s) is identical to mode 8's own DHF; the homing test masks the HF-energy bits
/// out of four specific 15-bit groups (`homing.c` `dhf_test` MODE_24k branch).
const MODE_24K: u8 = 8;

/// Check whether `bits` (a frame's serial bits, encoder order) matches the decoder homing frame for
/// `mode` over its first `nparms` bits (`homing.c` `dhf_test`). Modes 0..=7 use the generic
/// 15-bit-group compare with a masked partial tail; mode 8 (24k) takes the HF-energy-masked path.
fn dhf_test(bits: &[i16], mode: u8, nparms: i16) -> bool {
    let pattern = DHF[mode as usize];

    if mode == MODE_24K {
        return dhf_test_24k(bits, pattern);
    }

    let mut prms = SerialBits::new(bits);
    let mut param = [0i16; 32];
    let mut j = 0i16;
    let mut full = 0usize; // number of full 15-bit groups read

    // Read whole 15-bit groups until the next would exceed nparms.
    let tmp = nparms - 15;
    while tmp > j {
        param[full] = prms.read(15);
        j += 15;
        full += 1;
    }
    // Final partial group, left-shifted into the 15-bit field.
    let rem = nparms - j;
    param[full] = prms.read(rem);
    let shift = 15 - rem;
    param[full] = shl(param[full], shift);

    // Compare the full groups; `idx` survives as the early-break index, or == `full` if all matched.
    let mut diff = 0i16;
    let mut idx = full;
    for k in 0..full {
        diff = param[k] ^ pattern[k];
        if diff != 0 {
            idx = k;
            break;
        }
    }

    // Masked compare of the (possibly partial) group at `idx`.
    let mut mask = 0x7fffi16;
    mask = shr(mask, shift);
    mask = shl(mask, shift);
    let masked = pattern[idx] & mask;
    let tail = param[idx] ^ masked;
    diff |= tail;

    diff == 0
}

/// Mode-8 (23.85 kbit/s) homing test: the full 477-bit frame is read as 31×15 bits + a final 8-bit
/// group (shifted left by 7), with the HF-band-energy bits masked out of groups 10, 17, 24 and 31
/// (`homing.c` `dhf_test` MODE_24k branch). `shift` is 0 here, so the post-loop tail compare is
/// against the unmasked pattern word.
fn dhf_test_24k(bits: &[i16], pattern: &[i16]) -> bool {
    let mut prms = SerialBits::new(bits);
    let mut param = [0i16; 32];

    for value in param.iter_mut().take(10) {
        *value = prms.read(15);
    }
    param[10] = prms.read(15) & 0x61FF;
    for value in param.iter_mut().take(17).skip(11) {
        *value = prms.read(15);
    }
    param[17] = prms.read(15) & 0xE0FF_u16 as i16;
    for value in param.iter_mut().take(24).skip(18) {
        *value = prms.read(15);
    }
    param[24] = prms.read(15) & 0x7F0F;
    for value in param.iter_mut().take(31).skip(25) {
        *value = prms.read(15);
    }
    let tmp = prms.read(8);
    param[31] = shl(tmp, 7);

    // The loop runs i over 0..32 (tmp = i = 32 after the reads); compare all 32 groups, with the
    // post-loop masked tail compare at idx == 32 reading param[32]/pattern[32] which are 0 (shift=0).
    let mut diff = 0i16;
    let mut idx = 32usize;
    for k in 0..32 {
        diff = param[k] ^ pattern[k];
        if diff != 0 {
            idx = k;
            break;
        }
    }
    // shift = 0: mask = 0x7fff; pattern[idx] & mask; param[idx] ^ that. At idx==32 both are 0.
    let pat = if idx < pattern.len() { pattern[idx] } else { 0 };
    let par = if idx < param.len() { param[idx] } else { 0 };
    let tail = par ^ (pat & 0x7fff);
    diff |= tail;

    diff == 0
}

/// Whole-frame decoder homing test for `mode` (`decoder_homing_frame_test`).
#[must_use]
pub fn homing_frame_test(bits: &[i16], mode: u8) -> bool {
    dhf_test(bits, mode, NB_BITS[mode as usize] as i16)
}

/// First-subframe-only decoder homing test for `mode` (`decoder_homing_frame_test_first`).
#[must_use]
pub fn homing_frame_test_first(bits: &[i16], mode: u8) -> bool {
    dhf_test(bits, mode, PRMNOFSF[mode as usize])
}

#[cfg(test)]
mod tests {
    use super::super::bitstream::{BIT_0, BIT_1};
    use super::*;

    /// Reproduce the full serial frame from a 15-bit-group parameter array (MSB-first), padded to
    /// `nbits` with `BIT_0`, so the test exercises the exact comparison path.
    fn pattern_bits(params: &[i16], nbits: usize) -> Vec<i16> {
        let mut out = Vec::new();
        for &p in params {
            for shift in (0..15).rev() {
                out.push(if (p >> shift) & 1 == 1 { BIT_1 } else { BIT_0 });
            }
        }
        out.truncate(nbits);
        while out.len() < nbits {
            out.push(BIT_0);
        }
        out
    }

    #[test]
    fn matching_pattern_is_a_homing_frame_for_modes_0_to_7() {
        for mode in 0u8..=7 {
            let nbits = NB_BITS[mode as usize];
            let bits = pattern_bits(DHF[mode as usize], nbits);
            assert!(homing_frame_test(&bits, mode), "mode {mode} full-frame homing");
            assert!(
                homing_frame_test_first(&bits, mode),
                "mode {mode} first-subframe homing"
            );
        }
    }

    #[test]
    fn altered_pattern_is_not_a_homing_frame() {
        for mode in 0u8..=8 {
            let nbits = NB_BITS[mode as usize];
            let mut bits = pattern_bits(DHF[mode as usize], nbits);
            bits[0] = if bits[0] == BIT_1 { BIT_0 } else { BIT_1 };
            assert!(!homing_frame_test(&bits, mode), "mode {mode}");
        }
    }
}
