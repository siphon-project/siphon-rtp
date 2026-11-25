//! `tcx_hm_decode` of TS 26.442 `lib_dec/ari_hm_dec.c`.
//!
//! `Overflow` and `Carry`: nothing here reads them.

use crate::evs::cnst::{GENERIC, KSMALLERLAGSTARGETBITSTHRESHOLD, KTCXHMNUMGAINBITS, VOICED};
use crate::evs::com::ari_hm::envelope::tcx_hm_modify_envelope;
use crate::evs::com::ari_hm::{count_index_bits, tcx_hm_render, unmap_index};
use crate::evs::dec::ari_hm_dec::tcx_hm_dequantize_gain;
use crate::itu::basic_ops::{add, sub};

/// `tcx_hm_decode`: shape the envelope `env` (Q16, `l_frame` lines) with the harmonic model
/// described by `prm_hm` (`[flag, periodicity index, gain index]`). `hm_bits` receives the bits the
/// model took, or -1 for a bit error (an unusable coder type, lag or gain).
pub fn tcx_hm_decode(
    l_frame: i16,
    env: &mut [i32],
    target_bits: i16,
    coder_type: i16,
    prm_hm: &[i16],
    ltp_pitch_lag: i16,
    hm_bits: &mut i16,
) {
    let mut fract_res: i16 = 0;
    let mut lag: i32 = 0;
    let mut gain: i16 = 0;
    let mut p = [0_i16; 9];

    *hm_bits = 0;

    let l_frame_m_256 = sub(l_frame, 256);

    if !(sub(coder_type, VOICED) == 0 || sub(coder_type, GENERIC) == 0) {
        // A bit error was encountered
        *hm_bits = -1;
        return;
    }

    let mut num_target_bits = count_index_bits(i16::from(l_frame_m_256 >= 0), prm_hm[1]);

    num_target_bits = add(num_target_bits, target_bits);

    if sub(coder_type, VOICED) == 0 {
        num_target_bits = add(num_target_bits, KTCXHMNUMGAINBITS);
    }

    *hm_bits = add(sub(num_target_bits, target_bits), 1);

    // Convert the index to lag
    unmap_index(
        prm_hm[1],
        i8::from(l_frame_m_256 >= 0),
        ltp_pitch_lag,
        i8::from(sub(num_target_bits, KSMALLERLAGSTARGETBITSTHRESHOLD) <= 0 || l_frame_m_256 < 0),
        &mut fract_res,
        &mut lag,
    );

    // Render the harmonic model
    if tcx_hm_render(lag, fract_res, &mut p) {
        // A bit error was encountered
        *hm_bits = -1;
        return;
    }

    // Dequantize gain
    if tcx_hm_dequantize_gain(
        i16::from(sub(coder_type, VOICED) == 0),
        prm_hm[2],
        &mut gain,
    ) {
        // A bit error was encountered
        *hm_bits = -1;
        return;
    }

    tcx_hm_modify_envelope(gain, lag, fract_res, &p, env, l_frame);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unusable_coder_type_is_a_bit_error() {
        let mut env = [65536_i32; 64];
        let mut hm_bits = 5;
        tcx_hm_decode(64, &mut env, 100, 0, &[1, 0, 0], -1, &mut hm_bits);
        assert_eq!(hm_bits, -1);
        assert_eq!(env, [65536; 64]);
    }

    #[test]
    fn a_gain_index_out_of_range_is_a_bit_error() {
        let mut env = [65536_i32; 64];
        let mut hm_bits = 0;
        tcx_hm_decode(64, &mut env, 100, GENERIC, &[1, 100, 9], -1, &mut hm_bits);
        assert_eq!(hm_bits, -1);
    }
}
