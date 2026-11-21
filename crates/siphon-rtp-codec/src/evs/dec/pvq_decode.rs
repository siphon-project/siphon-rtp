//! PVQ sub-vector decoding (TS 26.442 `lib_dec/pvq_decode_fx.c`; TS 26.445 §6.2.2.3.4).

use crate::evs::cnst::KMAX_NON_DIRECT_FX;
use crate::evs::com::index_pvq_opt::{get_size_mpvq_calc_offset, mpvq_decode_vec};
use crate::evs::com::math_op::isqrt;
use crate::evs::dec::range_dec::{rc_dec_bits, rc_dec_uniform};
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, l_mac, l_negate, l_shr, l_sub, norm_s, round_word, shl, sub};
use crate::itu::stl2009::mpy_32_16_ss;

/// `pvq_decode_fx`: read one PVQ codeword of `k_val` pulses over `dim` coefficients from the
/// range coder, giving the integer pulse vector `y` and its gain-scaled, unit-energy version `xq`
/// (Q15). `neg_gain` is the gain negated (so that 1.0 fits in Q15 as -1.0); a zero gain zeroes
/// `xq`.
///
/// An index at or above the codebook size (a bit error) is replaced by 0 and flags both
/// `ber_occured_in_pvq` and `BER_detect`; once flagged, every later index in the frame is 0.
pub fn pvq_decode(
    st: &mut DecoderState,
    xq: &mut [i16],
    y: &mut [i16],
    k_val: i16,
    dim: i16,
    neg_gain: i16,
) {
    // allocate max offset memory for dim 6
    let mut h_mem = [0u32; 1 + KMAX_NON_DIRECT_FX as usize + 1];

    // get size & prepare H (adaptive table for entry.size = N_MPVQ(dim, k_val))
    let mut entry = get_size_mpvq_calc_offset(dim, k_val, &mut h_mem);

    if sub(dim, 1) != 0 {
        entry.lead_sign_ind = rc_dec_bits(st, 1) as i16;
        entry.index = rc_dec_uniform(st, entry.size);

        // safety check in case of bit errors; the reference compares the unsigned index and size
        // through the signed, saturating L_sub
        if l_sub(entry.index as i32, entry.size as i32) >= 0 || st.ber_occured_in_pvq != 0 {
            st.ber_occured_in_pvq = 1;
            st.ber_detect = 1;
            entry.index = 0; // a zero index will essentially disable PVQ index decompostion complexity
        }
    } else {
        entry.lead_sign_ind = rc_dec_bits(st, 1) as i16; // always a single sign bit
        entry.index = 0;
    }

    mpvq_decode_vec(&entry, &mut h_mem, y);

    let dim = dim.max(0) as usize;
    if neg_gain == 0 {
        xq[..dim].fill(0);
    } else {
        let mut l_yy: i32 = 0;
        for &value in &y[..dim] {
            l_yy = l_mac(l_yy, value, value); // Q1
        }

        let mut l_isqrt = isqrt(l_shr(l_yy, 1)); // Q31; one single gain fac as in flt not computed for now

        let shift_num = norm_s(k_val); // account for max possible pulseamp in y
        let shift_den = norm_s(neg_gain); // account for downscaling shift
        let neg_gain_norm = shl(neg_gain, shift_den); // 10 db loss in minSNR without this in L_qx, at HQ128 FB
        let shift_tot = sub(add(shift_num, shift_den), 15);

        l_isqrt = l_negate(l_isqrt);
        for (out, &value) in xq.iter_mut().zip(&y[..dim]) {
            // upshifted y[i] used
            let (l_tmp, _) = mpy_32_16_ss(l_isqrt, shl(value, shift_num)); // Q31*Q(0+x) *2
            let (l_tmp, _) = mpy_32_16_ss(l_tmp, neg_gain_norm); // Q31*Q(0+x) *Q15 *2
            *out = round_word(l_shr(l_tmp, shift_tot)); // Q15
        }
    }
}
