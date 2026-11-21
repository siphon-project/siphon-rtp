//! Gaussian-codebook decoding of unvoiced subframes (TS 26.442 `lib_dec/gaus_dec_fx.c`;
//! TS 26.445 §6.1.1.2.7). `gaus_L2_dec` (MODE2) is not ported here: it needs `cb_shape_fx`.

use crate::evs::cnst::{L_FRAME, L_SUBFR, UNVOICED};
use crate::evs::com::bitstream::{bit_alloc_idx, get_next_indice};
use crate::evs::com::math_op::{dot_product12, i_mult2, isqrt_lc};
use crate::evs::com::scale_mem::rescale_exc;
use crate::evs::dec::gain_dec::{gain_dec_gaus, lp_gain_updt};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{FCB_BITS_TBL, GAIN_BITS_TBL, GAUS_DICO_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_deposit_h, l_mult, l_shl, mult, mult_r, negate, round_word, shl, shr,
    sub,
};
use crate::itu::stl2009::{mac_r, msu_r};

/// Size of the Gaussian codebook `gaus_dico_fx`.
const GAUS_DICO_LEN: usize = 190;

/// The row of the bit-allocation tables for an unvoiced subframe: `BIT_ALLOC_IDX_fx(core_brate,
/// UNVOICED, i_subfr, TC_SUBFR2IDX_fx(-1))`, with the `TC_SUBFR2IDX_fx` macro written out
/// (`add(s_min(3, s_max(0, sub(-1, 1))), mac_r(1024, -1, 512))` = 0).
fn unvoiced_bit_alloc_row(core_brate: i32, i_subfr: i16) -> usize {
    let tc = add(sub(-1, 1).clamp(0, 3), mac_r(1024, -1, 512));
    bit_alloc_idx(core_brate, UNVOICED, i_subfr, tc).max(0) as usize
}

/// `gaus_dec_fx`: decode the Gaussian excitation of the unvoiced subframe `i_subfr` and its gain,
/// write the innovation `code`, and rebuild `exc` (adaptive part zeroed) and `exc2` (zeroed) for
/// it.
///
/// The reference's `lp_gainp`, `lp_gainc`, `tilt_code`, `sQ_exc` and `sQsubfr` arguments are
/// pointers into `st` at its only call site (`decod_unvoiced_fx`), so they are read and written in
/// `st` here (`lp_gainp`, `lp_gainc`, `tilt_code`, `q_exc`, `q_subfr`).
///
/// `exc[exc_at]` is the frame's first excitation sample (at least `L_EXC_MEM_DEC` of history in
/// front of it), `exc2` the frame's second excitation, `bwe_exc[bwe_exc_at]` the frame's first
/// BWE excitation sample (with `2·PIT16k_MAX` of history).
pub fn gaus_dec(
    st: &mut DecoderState,
    core_brate: i32,
    i_subfr: i16,
    code: &mut [i16],
    l_norm_gain_code: &mut i32,
    inv_gain_inov: &mut i16,
    voice_fac: &mut i16,
    gain_pit: &mut i16,
    pt_pitch_1: &mut i16,
    exc: &mut [i16],
    exc_at: usize,
    l_gain_code: &mut i32,
    exc2: &mut [i16],
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
) {
    // Decode gaussian excitation
    let row = unvoiced_bit_alloc_row(core_brate, i_subfr);
    let nb_bits = FCB_BITS_TBL.get(row).copied().unwrap_or(0);
    gaus_dec2v(st, code, L_SUBFR, shr(nb_bits, 1));

    // Decode gain of gaussian excitation and normalized energy
    let mut exp: i16 = 0;
    let mut l_tmp = dot_product12(code, code, L_SUBFR, &mut exp);
    exp = sub(exp, 18 + 6); // exp: -18 (code in Q9), -6 (L_subfr = 64)
    l_tmp = isqrt_lc(l_tmp, &mut exp);
    *inv_gain_inov = extract_h(l_shl(l_tmp, sub(exp, 3))); // inv_gain_inov in Q12

    let nb_bits = GAIN_BITS_TBL.get(row).copied().unwrap_or(0);
    let mut idx = get_next_indice(st, nb_bits) as i16;
    // safety check in case of bit errors
    if sub(idx, 78) > 0 {
        idx = 78;
        st.ber_detect = 1;
    }

    *l_gain_code = gain_dec_gaus(idx, nb_bits, -30, 190, *inv_gain_inov, l_norm_gain_code);

    // update LP filtered gains for the case of frame erasures
    lp_gain_updt(
        i_subfr,
        0,
        *l_norm_gain_code,
        &mut st.lp_gainp,
        &mut st.lp_gainc,
        L_FRAME,
    );
    st.tilt_code = 0; // purely unvoiced
    *voice_fac = -32768; // purely unvoiced
    *gain_pit = 0;
    *pt_pitch_1 = 4096; // floating pitch buffer

    // Construct scaled excitation
    let subfr = L_SUBFR as usize;
    let i_subfr_at = i_subfr.max(0) as usize;
    exc[exc_at + i_subfr_at..exc_at + i_subfr_at + subfr].fill(0);
    exc2[i_subfr_at..i_subfr_at + subfr].fill(0);

    // The bwe_exc subframe starts i_subfr·5/2 (12.8 kHz core) or i_subfr·2 (16 kHz) into it.
    let (bwe_subfr_at, lg32) = if sub(st.l_frame, L_FRAME) == 0 {
        (i_subfr_at * 5 / 2, L_SUBFR * 5 / 2)
    } else {
        (i_subfr_at * 2, L_SUBFR * 2)
    };
    let mut q_exc = st.q_exc;
    let mut q_subfr = st.q_subfr;
    rescale_exc(
        Some(&mut st.dct_post_old_exc),
        exc,
        exc_at + i_subfr_at,
        Some((bwe_exc, bwe_exc_at + bwe_subfr_at)),
        Some(&mut st.last_exc_dct_in),
        L_SUBFR,
        lg32,
        *l_gain_code,
        &mut q_exc,
        &mut q_subfr,
        Some(exc2),
        i_subfr,
        UNVOICED,
    );
    st.q_exc = q_exc;
    st.q_subfr = q_subfr;

    let gain_code = round_word(l_shl(*l_gain_code, st.q_exc));
    for i in 0..subfr {
        let l_tmp = l_shl(l_mult(gain_code, code[i]), 6);
        exc[exc_at + i_subfr_at + i] = round_word(l_tmp);
    }
}

/// `gaus_dec2v_fx`: decode a 2-vector Gaussian codevector of `lg` samples (Q9) with `nb_bits`
/// bits per vector position, plus a sign bit and a 3-bit decorrelation `delta`.
pub fn gaus_dec2v(st: &mut DecoderState, code: &mut [i16], lg: i16, nb_bits: i16) {
    let mut gaus_dico2 = [0i16; GAUS_DICO_LEN];

    let step = shr(0x80, nb_bits);

    let idx = get_next_indice(st, add(shl(nb_bits, 1), 1)) as i16;
    let index_delta = get_next_indice(st, 3) as i16;

    let (ind1, ind2, sign1, sign2) = dec_2pos(idx, nb_bits);

    let delta = shl(index_delta, 11); // delta in Q15
    let delta2 = mac_r(16384 * 65536, shr(delta, 1), delta); // delta2 in Q15
    let inv_delta = div_s(16384, delta2); // inv_delta in Q15

    if delta > 0 {
        // shift the vectors
        gaus_dico2[0] = GAUS_DICO_FX[0];
        for i in 1..GAUS_DICO_LEN {
            // ((1-delta)*gaus_dico[i] - delta*gaus_dico[i-1]) / (1-delta+delta^2)
            let tmp16 = msu_r(l_deposit_h(GAUS_DICO_FX[i]), delta, GAUS_DICO_FX[i - 1]);
            gaus_dico2[i] = mult_r(tmp16, inv_delta);
        }
    } else {
        gaus_dico2 = GAUS_DICO_FX;
    }

    // With the bit counts the tables give (at most 6 per position), both vectors stay inside the
    // codebook; a sample past its end (only from an inconsistent nb_bits) reads as 0.
    let pt1 = i_mult2(ind1, step) as usize;
    let pt2 = i_mult2(ind2, step) as usize;
    let at = |offset: usize| gaus_dico2.get(offset).copied().unwrap_or(0);
    for (i, out) in code.iter_mut().take(lg.max(0) as usize).enumerate() {
        *out = add(mult(at(pt1 + i), sign1), mult(at(pt2 + i), sign2));
    }
}

/// `dec_2pos_fx`: split the 2-position Gaussian index (sign bit first) into the two positions and
/// their signs (Q12); the second sign is inverted when the first position is the larger.
fn dec_2pos(index: i16, log2_n: i16) -> (i16, i16, i16, i16) {
    let i = index & 1;
    let mut sign1: i16 = -32768;
    if i == 0 {
        sign1 = 0x7fff;
    }
    sign1 = shr(sign1, 3); // sign in Q12

    let index = shr(index, 1);
    let ind1 = shr(index, log2_n);
    let ind2 = sub(index, shl(ind1, log2_n));
    let mut sign2 = sign1;
    if sub(ind1, ind2) > 0 {
        sign2 = negate(sign1);
    }
    (ind1, ind2, sign1, sign2)
}
