//! AMR-WB algebraic (fixed) codebook decoders (3GPP TS 26.173), ported bit-exact.
//!
//! The fixed codebook places a small number of unit pulses (±1) on interleaved tracks of the
//! 64-sample subframe; the bitstream index encodes each pulse's position and sign. Mode 0 (6.60
//! kbit/s) uses the 2-pulse decoder [`dec_acelp_2t64`]; the higher modes use the 4-track decoder
//! (`d4t64` / `q_pulse`, a later tier). Output is Q9 (±512 = ±1.0).

use crate::amr::basic_ops::{add, shl, shr};

/// Codevector length (one subframe).
const L_CODE: usize = 64;
/// Positions per track (also the sign-bit mask value, `0x20`).
const NB_POS: i16 = 32;

/// Decode the 12-bit 2-pulse algebraic codebook index into a Q9 codevector (`DEC_ACELP_2t64_fx`):
/// two ±1 pulses, one on the even-position track and one on the odd-position track, 32 positions
/// each. `code` must be at least 64 samples; it is fully overwritten.
pub fn dec_acelp_2t64(index: i16, code: &mut [i16]) {
    for value in code.iter_mut().take(L_CODE) {
        *value = 0;
    }

    // Pulse 0 on the even track, pulse 1 on the odd track.
    let i0 = (shr(index, 5) & 0x003E) as usize;
    let i1 = add(shl(index & 0x001F, 1), 1) as usize;

    code[i0] = if (shr(index, 6) & NB_POS) == 0 { 512 } else { -512 };
    code[i1] = if (index & NB_POS) == 0 { 512 } else { -512 };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pulses(code: &[i16]) -> Vec<(usize, i16)> {
        code.iter()
            .enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, &v)| (i, v))
            .collect()
    }

    #[test]
    fn index_zero_places_two_positive_pulses() {
        let mut code = [0i16; 64];
        dec_acelp_2t64(0, &mut code);
        assert_eq!(pulses(&code), vec![(0, 512), (1, 512)]);
    }

    #[test]
    fn sign_bits_flip_the_pulse_amplitudes() {
        // index 0x20: bit5 set → pulse 1 negative; pulse positions still 0 and 1.
        let mut code = [0i16; 64];
        dec_acelp_2t64(0x20, &mut code);
        assert_eq!(pulses(&code), vec![(0, 512), (1, -512)]);

        // index 0x800: bit11 set → pulse 0 negative.
        let mut code = [0i16; 64];
        dec_acelp_2t64(0x800, &mut code);
        assert_eq!(pulses(&code), vec![(0, -512), (1, 512)]);
    }

    #[test]
    fn position_bits_move_the_even_track_pulse() {
        // index 0x80: (0x80>>5)&0x3E = 4 → pulse 0 at position 4; pulse 1 stays at 1.
        let mut code = [0i16; 64];
        dec_acelp_2t64(0x80, &mut code);
        assert_eq!(pulses(&code), vec![(1, 512), (4, 512)]);
    }

    #[test]
    fn pulses_are_always_on_their_track_parity() {
        // Every index yields exactly one even-track and one odd-track pulse, both ±512.
        for index in 0..4096i16 {
            let mut code = [0i16; 64];
            dec_acelp_2t64(index, &mut code);
            let found = pulses(&code);
            assert_eq!(found.len(), 2, "two pulses for {index}");
            let positions: Vec<usize> = found.iter().map(|(p, _)| *p).collect();
            assert!(positions.iter().any(|p| p % 2 == 0), "even pulse for {index}");
            assert!(positions.iter().any(|p| p % 2 == 1), "odd pulse for {index}");
            assert!(found.iter().all(|(_, v)| v.abs() == 512));
        }
    }
}
