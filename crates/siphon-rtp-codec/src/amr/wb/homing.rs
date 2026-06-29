//! AMR-WB decoder homing (3GPP TS 26.173 `homing.c` / `homing.tab`), ported bit-exact.
//!
//! The codec defines a **decoder homing frame** (DHF): a fixed parameter pattern per mode that, when
//! received, drives the decoder to a known reset state. The reference test vectors begin with two
//! such homing frames; while homed, the decoder emits the constant [`EHF_MASK`] (`0x0008`) instead
//! of synthesised speech, and resets after the homing frame. [`homing_frame_test`] /
//! [`homing_frame_test_first`] check a frame's serial bits against the mode's DHF pattern.

use super::bitstream::SerialBits;

/// Encoder/decoder homing-frame output mask (`EHF_MASK`, `0x0008`).
pub const EHF_MASK: i16 = 0x0008;

/// First-subframe parameter bit counts per speech mode (`prmnofsf`).
const PRMNOFSF: [i16; 9] = [63, 81, 100, 108, 116, 128, 136, 152, 156];

/// Mode-0 (6.60 kbit/s) decoder homing frame pattern, 9 × 15-bit params (`dfh_M7k`).
const DFH_M7K: [i16; 9] = [3168, 29954, 29213, 16121, 64, 13440, 30624, 16430, 19008];

/// Total speech bits for mode 0.
const NBBITS_7K: i16 = 132;

/// Check whether `bits` (a mode-0 frame's serial bits, encoder order) matches the decoder homing
/// frame over its first `nparms` bits (`dhf_test`). Mirrors the reference's 15-bit-group compare,
/// including the index that survives the early-break loop and the masked partial-group compare.
fn dhf_test(bits: &[i16], nparms: i16) -> bool {
    use crate::amr::basic_ops::{shl, shr};

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
        diff = param[k] ^ DFH_M7K[k];
        if diff != 0 {
            idx = k;
            break;
        }
    }

    // Masked compare of the (possibly partial) group at `idx`.
    let mut mask = 0x7fffi16;
    mask = shr(mask, shift);
    mask = shl(mask, shift);
    let masked = DFH_M7K[idx] & mask;
    let tail = param[idx] ^ masked;
    diff |= tail;

    diff == 0
}

/// Whole-frame decoder homing test for mode 0 (`decoder_homing_frame_test`).
#[must_use]
pub fn homing_frame_test(bits: &[i16]) -> bool {
    dhf_test(bits, NBBITS_7K)
}

/// First-subframe-only decoder homing test for mode 0 (`decoder_homing_frame_test_first`).
#[must_use]
pub fn homing_frame_test_first(bits: &[i16]) -> bool {
    dhf_test(bits, PRMNOFSF[0])
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
    fn matching_pattern_is_a_homing_frame() {
        // The mode-0 DHF pattern, expanded to 132 bits, must test positive on both checks.
        let bits = pattern_bits(&DFH_M7K, 132);
        assert!(homing_frame_test(&bits), "full-frame homing test");
        assert!(homing_frame_test_first(&bits), "first-subframe homing test");
    }

    #[test]
    fn altered_pattern_is_not_a_homing_frame() {
        let mut bits = pattern_bits(&DFH_M7K, 132);
        bits[0] = if bits[0] == BIT_1 { BIT_0 } else { BIT_1 };
        assert!(!homing_frame_test(&bits));
    }
}
