//! The 12-bit and 7-bit algebraic codebooks of the 7.2/8.0 kbit/s ACELP core (TS 26.442
//! `lib_dec/dec2t32_fx.c`; TS 26.445 §5.2.3.1.5, §6.1.1.2.2).

use crate::evs::cnst::{L_SUBFR, NB_POS_FCB_2T};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::tools::set16;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, shl, shr, sub};

/// `dec_acelp_2t32_fx`: 12 bits, 2 tracks x 32 positions, one ±1 pulse per track, into `code`
/// (Q9 amplitude 512, `L_SUBFR` samples).
pub fn dec_acelp_2t32(st: &mut DecoderState, code: &mut [i16]) {
    let index = get_next_indice(st, 12) as i16;

    set16(code, 0, L_SUBFR);

    // decode the positions and signs of pulses and build the codeword
    let i0 = shl(shr(index, 6) & (NB_POS_FCB_2T - 1), 1);
    let i1 = add(shl(index & (NB_POS_FCB_2T - 1), 1), 1);

    // Both positions are 5-bit fields doubled (plus one), so within the 64-sample subframe.
    code[i0 as usize] = -512;
    if index & 0x800 == 0 {
        code[i0 as usize] = 512;
    }

    code[i1 as usize] = -512;
    if index & 0x20 == 0 {
        code[i1 as usize] = 512;
    }
}

/// `dec_acelp_1t64_fx`: 7 bits, one ±1 pulse over 64 positions, into `code` (`L_SUBFR` samples).
pub fn dec_acelp_1t64(st: &mut DecoderState, code: &mut [i16]) {
    // decode the positions and signs of pulses and build the codeword
    let mut pos = get_next_indice(st, 7) as i16;

    let mut sgn: i16 = -512;
    if sub(pos, L_SUBFR) >= 0 {
        pos = sub(pos, L_SUBFR);
        sgn = 512;
    }
    set16(code, 0, L_SUBFR);
    // A 7-bit value less 64 when it is at least 64: always inside the subframe.
    code[pos as usize] = sgn;
}
