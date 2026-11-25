//! Arithmetic decoding of the TCX spectrum from its LPC envelope (TS 26.442
//! `lib_dec/arith_coder_dec.c`; TS 26.445 §6.2.2.2.4).
//!
//! `Overflow`: nothing in this file reads it. `Carry`: `tcx_arith_decode` accumulates the noise
//! filling seed with `L_macNs`, which consumes the carry an earlier call left behind, so it takes
//! the decoder's [`StlFlags`] (`DecoderState::stl`).

pub mod envelope;
use crate::evs::cnst::SPEC_EXP_DEC;
use crate::evs::com::arith_coder::expfp;
use crate::evs::dec::ari_dec::{
    ari_decode_14bits_pow, ari_decode_14bits_sign, ari_decode_overflow,
    ari_start_decoding_14bits_prm,
};
use crate::evs::dec::state::TastatDec;
use crate::itu::basic_ops::{extract_l, l_deposit_l, l_mult, round_word, sub};
use crate::itu::stl2009::{l_mac_ns, StlFlags};

/// `tcx_arith_decode`: decode `l_frame` lines of the spectrum from the parameter bits `prm`
/// (one per word) against the scaled envelope `envelope` (Q15-e, exponent `envelope_e`) within
/// `target_bits`. Writes the quantised spectrum (Q31-e, exponent [`SPEC_EXP_DEC`]) and the
/// noise-filling seed. Returns the bits consumed, or -1 for a bit error (a zero envelope line or
/// an arithmetic decoder that ran dry early), in which case the spectrum is zero.
pub fn tcx_arith_decode(
    l_frame: i16,
    envelope: &[i16],
    envelope_e: i16,
    target_bits: i16,
    prm: &[i16],
    q_spectrum: &mut [i32],
    q_spectrum_e: &mut i16,
    nf_seed: &mut i16,
    flags: &mut StlFlags,
) -> i16 {
    let mut as_ = TastatDec::zeroed();
    let mut bp = ari_start_decoding_14bits_prm(prm, 0, &mut as_);

    let tmp = sub(envelope_e, 1 + 15);
    let mut l_tmp = l_deposit_l(0);
    let lines = l_frame.max(0) as usize;
    let mut k: usize = 0;
    while k < lines {
        if envelope[k] == 0 {
            // safety check in case of bit errors
            q_spectrum[..lines].fill(0);
            return -1;
        }
        let exp_k = round_word(expfp(envelope[k], tmp));
        // decode line magnitude
        let mut q: i16 = 0;
        bp = ari_decode_14bits_pow(prm, bp, target_bits, &mut q, &mut as_, exp_k);

        if q == 0 {
            q_spectrum[k] = l_deposit_l(0);
        }
        if q != 0 {
            // line is non-zero, decode sign
            let mut s: i16 = 0;
            bp = ari_decode_14bits_sign(prm, bp, target_bits, &mut s, &mut as_);

            l_tmp = l_mac_ns(l_tmp, q, k as i16, flags);

            let mut big_q = l_mult(q, -(1 << (30 - SPEC_EXP_DEC)));
            if s == 0 {
                big_q = l_mult(q, 1 << (30 - SPEC_EXP_DEC));
            }
            q_spectrum[k] = big_q;
        }

        if ari_decode_overflow(&as_) {
            if sub(bp, target_bits) < 0 {
                // safety check in case of bit errors
                bp = -1;
            }
            break; // no bits left, so exit loop
        }
        k += 1;
    }
    *q_spectrum_e = SPEC_EXP_DEC;

    q_spectrum[k..lines].fill(0);

    // noise filling seed
    *nf_seed = extract_l(l_tmp);

    bp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_envelope_line_is_a_bit_error() {
        let mut q_spectrum = [5_i32; 8];
        let (mut exponent, mut seed) = (0, 0);
        let mut flags = StlFlags::default();
        let bits = tcx_arith_decode(
            4,
            &[100, 0, 100, 100],
            1,
            50,
            &[0; 70],
            &mut q_spectrum,
            &mut exponent,
            &mut seed,
            &mut flags,
        );
        assert_eq!(bits, -1);
        assert_eq!(q_spectrum, [0, 0, 0, 0, 5, 5, 5, 5]);
    }

    #[test]
    fn a_stream_of_zeros_decodes_negative_lines_up_to_the_end_of_the_range() {
        let mut q_spectrum = [9_i32; 6];
        let (mut exponent, mut seed) = (0, 99);
        let mut flags = StlFlags::default();
        let bits = tcx_arith_decode(
            6,
            &[20000; 6],
            1,
            60,
            &[0; 70],
            &mut q_spectrum,
            &mut exponent,
            &mut seed,
            &mut flags,
        );
        assert!(bits >= 0);
        assert_eq!(exponent, SPEC_EXP_DEC);
        // value 0 sits at the bottom of every interval: magnitude 8, negative sign.
        assert_eq!(q_spectrum[0], -16384);
        assert!(bits <= 60);
    }
}
