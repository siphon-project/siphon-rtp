//! NELP (noise-excited linear prediction) excitation decoding of an unvoiced frame (TS 26.442
//! `lib_dec/nelp_dec_fx.c`; TS 26.445 §6.1.2.4). The ten sub-frame gains come from the bit
//! stream, from a channel-aware partial copy, or, for a lost frame, from the energy of the last
//! decoded subframe; the sparse noise they scale is band-passed and, at WB, spectrally shaped.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ACELP_MODE_MAX, BP1_COEF_NB_QF_ORDER7, BP1_COEF_WB_QF, SHAPE1_COEF_QF, SHAPE2_COEF_QF,
    SHAPE3_COEF_QF,
};
use crate::evs::cnst::{L_FRAME, L_SUBFR, NB, NB_SUBFR16K, SWB, UNVOICED, WB};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::nelp::{dequantize_uvg, generate_nelp_excitation};
use crate::evs::com::tools::{
    copy, pz_filter_dp, pz_filter_sp, scale_sig, scale_sig32, set16, set32,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    BP1_DEN_COEF_NB_FX_ORDER7, BP1_DEN_COEF_WB_FX, BP1_NUM_COEF_NB_FX_ORDER7, BP1_NUM_COEF_WB_FX,
    SHAPE1_DEN_COEF_FX, SHAPE1_NUM_COEF_FX, SHAPE2_DEN_COEF_FX, SHAPE2_NUM_COEF_FX,
    SHAPE3_DEN_COEF_FX, SHAPE3_NUM_COEF_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_add, l_deposit_h, l_deposit_l, l_shl, l_shr, norm_l, norm_s,
    round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// `RF_NELP` (`ACELP_MODE_MAX + 3`): the channel-aware frame type of a NELP partial copy.
const RF_NELP: i16 = ACELP_MODE_MAX + 3;
/// `L_FRAME` as an index.
const FRAME: usize = L_FRAME as usize;

/// `normalize_arr`: scale `arr[0..size]` up so its largest magnitude keeps `hdr` bits of
/// headroom; the applied left shift into `qf` (15 - `hdr` for an all-zero array). The shift may
/// saturate an element whose magnitude is not the largest one's.
pub fn normalize_arr(arr: &mut [i16], qf: &mut i16, size: i16, hdr: i16) {
    let n = size.max(0) as usize;
    let mut max_s: i16 = 0;
    for &value in &arr[..n] {
        max_s = max_s.max(abs_s(value));
    }

    *qf = norm_s(max_s);
    if *qf == 0 && max_s == 0 {
        *qf = 15;
    }

    *qf = qf.wrapping_sub(hdr);

    for value in &mut arr[..n] {
        *value = shl(*value, *qf); // saturation can occur here
    }
}

/// `nelp_decoder_fx`: the NELP excitation `exc_nelp` (`L_FRAME` samples, Q`q_exc`) of the
/// current frame. For a good frame (`bfi == 0`) the gain indices are read from the bit stream
/// (or the RF partial copy) and `q_exc` becomes the gains' Q; for a lost one the gains are the
/// RMS of the last subframe of the past excitation `exc[exc_at - L_SUBFR..exc_at]` (Q`q_exc`) and
/// `q_exc` becomes 0, except at NB, where low-level excitation is scaled up and `q_exc` raised
/// by the shift. Updates the filter memories and the noise seed; zeroes `gain_buf`.
pub fn nelp_decoder(
    st: &mut DecoderState,
    exc_nelp: &mut [i16],
    exc: &[i16],
    exc_at: usize,
    q_exc: &mut i16,
    bfi: i16,
    coder_type: i16,
    gain_buf: &mut [i16],
) {
    let mut fid: i16 = 0;
    let mut ptr = [0i16; FRAME];
    let mut gains = [0i16; 10]; // Q0
    let mut ptr_tmp = [0i16; FRAME]; // Q0
    let mut q_gain: i16 = 0;

    if sub(st.last_nelp_mode_dec, 1) == 0 && sub(st.bwidth, st.last_bwidth) != 0 {
        st.last_nelp_mode_dec = 0;
    }

    let unvoiced_wb =
        sub(coder_type, UNVOICED) == 0 && (sub(st.bwidth, WB) == 0 || sub(st.bwidth, SWB) == 0);
    if sub(coder_type, UNVOICED) == 0 && sub(st.bwidth, NB) == 0 {
        if sub(st.last_nelp_mode_dec, 1) != 0 {
            let bp1_order: i16 = 7;
            set32(&mut st.bp1_filt_mem_nb_dec, 0, bp1_order * 2);
        }
    } else if unvoiced_wb {
        let bp1_order: i16 = 4;
        if sub(st.last_nelp_mode_dec, 1) != 0 {
            set16(&mut st.bp1_filt_mem_wb_dec, 0, bp1_order * 2);
        }
    }

    if sub(st.last_nelp_mode_dec, 1) != 0 {
        set16(&mut st.shape1_filt_mem_dec, 0, 10);
        set16(&mut st.shape2_filt_mem_dec, 0, 10);
        set16(&mut st.shape3_filt_mem_dec, 0, 10);
    }

    if bfi == 0 {
        let partial_copy = sub(st.rf_frame_type, RF_NELP) == 0 && sub(st.use_partial_copy, 1) == 0;
        let mut i_g2 = [0i16; 2];
        let i_g1: i16;
        if partial_copy {
            i_g1 = st.rf_indx_nelp_i_g1;
            i_g2[0] = st.rf_indx_nelp_i_g2[0];
            i_g2[1] = st.rf_indx_nelp_i_g2[1];
        } else {
            // Do Unvoiced/NELP Decoding
            i_g1 = get_next_indice(st, 5) as i16;
            i_g2[0] = get_next_indice(st, 6) as i16;
            i_g2[1] = get_next_indice(st, 6) as i16;
        }

        if unvoiced_wb {
            if partial_copy {
                fid = st.rf_indx_nelp_fid;
            } else {
                fid = get_next_indice(st, 2) as i16;
            }
        }

        *q_exc = dequantize_uvg(i_g1, &i_g2, &mut gains, st.bwidth, 1); // Gains - Q0/Q3
    } else {
        let tmp = nelp_decoder_lost_gain(exc, exc_at, *q_exc);
        set16(&mut gains, tmp, 10);
        *q_exc = 0;
    }

    let mut gain_fac: i16 = 22446; // 1.37f - Q14
    if unvoiced_wb {
        gain_fac = 19005; // 1.16f - Q14
    }

    if sub(st.bwidth, WB) == 0 || sub(st.bwidth, SWB) == 0 {
        // Normalize Gains[10] with headroom 4, qGain is the new Q value os Gains, not Q0. This
        // is done to avoid internal overflow observed in the wb bp filter below, similar to
        // encoder
        normalize_arr(&mut gains, &mut q_gain, 10, 4);
    }

    generate_nelp_excitation(&mut st.nelp_dec_seed, &gains, &mut ptr, gain_fac);
    // o: ptr = nelp_exc in Q=qGain, qGain = 0 always for NB

    if unvoiced_wb {
        let bp1_order: i16 = 4;
        // bring filter prev memory from Q0 to qGain
        scale_sig(&mut st.bp1_filt_mem_wb_dec, 2 * bp1_order, q_gain);
        pz_filter_sp(
            &BP1_NUM_COEF_WB_FX,
            &BP1_DEN_COEF_WB_FX,
            &ptr,
            &mut ptr_tmp,
            &mut st.bp1_filt_mem_wb_dec,
            bp1_order,
            bp1_order,
            L_FRAME,
            sub(16, BP1_COEF_WB_QF),
        );
        // bring filter prev memory from qGain to Q0
        scale_sig(
            &mut st.bp1_filt_mem_wb_dec,
            2 * bp1_order,
            q_gain.wrapping_neg(),
        );
        scale_sig(&mut ptr_tmp, L_FRAME, q_gain.wrapping_neg()); // bring nelp_exc to Q0
        copy(&ptr_tmp, &mut ptr, L_FRAME);
    }

    if sub(coder_type, UNVOICED) == 0 && sub(st.bwidth, NB) == 0 {
        nelp_decoder_nb_band_pass(st, &mut ptr, &mut ptr_tmp, q_exc);
    }

    let mut e3 = l_deposit_l(1);
    for &value in &ptr {
        e3 = l_mac0(e3, value, value); // 2*Q_exc
    }

    if unvoiced_wb {
        nelp_decoder_shape(st, &mut ptr, &mut ptr_tmp, fid, e3, *q_exc);
    }

    copy(&ptr, exc_nelp, L_FRAME); // Q_exc
    set16(gain_buf, 0, NB_SUBFR16K);
}

/// The gain of a lost NELP frame: `0.8 · RMS` of the last `L_SUBFR` samples before `exc_at`
/// (Q`q_exc`), Q0; 0 for a silent subframe.
fn nelp_decoder_lost_gain(exc: &[i16], exc_at: usize, q_exc: i16) -> i16 {
    let subfr = L_SUBFR as usize;
    let mut exc_sqr = [0i32; L_SUBFR as usize];
    for i in 1..=subfr {
        exc_sqr[i - 1] = l_mult0(exc[exc_at - i], exc[exc_at - i]); // 2*Q_exc
    }
    let mut max_exc_sqr = l_deposit_l(0);
    for &value in &exc_sqr {
        max_exc_sqr = max_exc_sqr.max(value);
    }
    if max_exc_sqr == 0 {
        return 0;
    }
    let mut exp = norm_l(max_exc_sqr);
    for value in &mut exc_sqr {
        *value = l_shl(*value, exp); // Q30
    }
    exp = sub(30, add(exp, add(q_exc, q_exc)));

    let mut gain = l_deposit_l(1);
    for &value in &exc_sqr {
        gain = l_add(gain, l_shr(value, 6)); // Q24
    }
    gain = mult_32_16(gain, 20972); // Q24; 20972=sqr(0.8) in Q15
    exp = sub(exp, 6); // due to /L_SUBFR

    if exp & 1 != 0 {
        gain = l_shr(gain, 1); // Q24
        exp = add(exp, 1);
    }
    exp = shr(exp, 1);
    let mut n = norm_l(gain);
    let mut frac = round_word(l_shl(gain, n));
    n = sub(add(n, 24), 30);
    frac = div_s(16384, frac);
    gain = isqrt_lc(l_deposit_h(frac), &mut n); // Q(31-n-exp)
    round_word(l_shl(gain, sub(n.wrapping_add(exp), 15))) // Q0
}

/// The NB band-pass of an unvoiced NELP frame: a low-level excitation (and the filter's 32-bit
/// memory) is first scaled up by up to 8 bits, raising `q_exc` by the same amount.
fn nelp_decoder_nb_band_pass(
    st: &mut DecoderState,
    ptr: &mut [i16; FRAME],
    ptr_tmp: &mut [i16; FRAME],
    q_exc: &mut i16,
) {
    let bp1_order: i16 = 7;
    let mut max_val: i16 = 0;

    for &value in ptr.iter() {
        max_val = value.max(max_val);
    }
    let tmp = shl(bp1_order, 1);
    for &value in &st.bp1_filt_mem_nb_dec[..tmp as usize] {
        max_val = round_word(l_shr(value, 16)).max(max_val);
    }
    let mut norm_val = norm_s(max_val);

    norm_val = sub(norm_val, 4).max(0); // 4 bit head room
    norm_val = norm_val.min(8); // scale only for very low level signals

    if norm_val > 0 {
        scale_sig32(&mut st.bp1_filt_mem_nb_dec, shl(bp1_order, 1), norm_val);
        scale_sig(ptr, L_FRAME, norm_val);
        *q_exc = add(norm_val, *q_exc);
    }

    pz_filter_dp(
        &BP1_NUM_COEF_NB_FX_ORDER7,
        &BP1_DEN_COEF_NB_FX_ORDER7,
        ptr,
        ptr_tmp,
        &mut st.bp1_filt_mem_nb_dec,
        bp1_order,
        bp1_order,
        L_FRAME,
        sub(16, BP1_COEF_NB_QF_ORDER7),
    );

    if norm_val > 0 {
        scale_sig32(&mut st.bp1_filt_mem_nb_dec, shl(bp1_order, 1), -norm_val);
    }

    copy(ptr_tmp, ptr, L_FRAME); // Q_exc
}

/// The WB spectral shaping of an unvoiced NELP frame: the first shaping filter, then the one of
/// the transmitted filter index `fid` (both other memories still run), then the energy restored
/// to the pre-shaping energy `e3`.
fn nelp_decoder_shape(
    st: &mut DecoderState,
    ptr: &mut [i16; FRAME],
    ptr_tmp: &mut [i16; FRAME],
    fid: i16,
    e3: i32,
    q_exc: i16,
) {
    let mut filt_res = [0i16; FRAME];

    pz_filter_sp(
        &SHAPE1_NUM_COEF_FX,
        &SHAPE1_DEN_COEF_FX,
        ptr,
        ptr_tmp,
        &mut st.shape1_filt_mem_dec,
        10,
        10,
        L_FRAME,
        sub(16, SHAPE1_COEF_QF),
    );
    copy(ptr_tmp, ptr, L_FRAME); // Q_exc

    match fid {
        1 => {
            // Update other filter memory
            pz_filter_sp(
                &SHAPE3_NUM_COEF_FX,
                &SHAPE3_DEN_COEF_FX,
                ptr,
                &mut filt_res,
                &mut st.shape3_filt_mem_dec,
                10,
                10,
                L_FRAME,
                sub(16, SHAPE3_COEF_QF),
            );
            // filter the residual to desired shape
            pz_filter_sp(
                &SHAPE2_NUM_COEF_FX,
                &SHAPE2_DEN_COEF_FX,
                ptr,
                ptr_tmp,
                &mut st.shape2_filt_mem_dec,
                10,
                10,
                L_FRAME,
                sub(16, SHAPE2_COEF_QF),
            );
            copy(ptr_tmp, ptr, L_FRAME); // Q_exc
        }
        2 => {
            // Update other filter memory
            pz_filter_sp(
                &SHAPE2_NUM_COEF_FX,
                &SHAPE2_DEN_COEF_FX,
                ptr,
                &mut filt_res,
                &mut st.shape2_filt_mem_dec,
                10,
                10,
                L_FRAME,
                sub(16, SHAPE2_COEF_QF),
            );
            // filter the residual to desired shape
            pz_filter_sp(
                &SHAPE3_NUM_COEF_FX,
                &SHAPE3_DEN_COEF_FX,
                ptr,
                ptr_tmp,
                &mut st.shape3_filt_mem_dec,
                10,
                10,
                L_FRAME,
                sub(16, SHAPE3_COEF_QF),
            );
            copy(ptr_tmp, ptr, L_FRAME); // Q_exc
        }
        _ => {
            // Update other filter memory
            pz_filter_sp(
                &SHAPE2_NUM_COEF_FX,
                &SHAPE2_DEN_COEF_FX,
                ptr,
                &mut filt_res,
                &mut st.shape2_filt_mem_dec,
                10,
                10,
                L_FRAME,
                sub(16, SHAPE2_COEF_QF),
            );
            pz_filter_sp(
                &SHAPE3_NUM_COEF_FX,
                &SHAPE3_DEN_COEF_FX,
                ptr,
                &mut filt_res,
                &mut st.shape3_filt_mem_dec,
                10,
                10,
                L_FRAME,
                sub(16, SHAPE3_COEF_QF),
            );
        }
    }

    let mut e2 = l_deposit_l(1);
    for &value in ptr.iter() {
        e2 = l_mac0(e2, value, value); // 2*Q_exc
    }

    let mut exp_e3 = norm_l(e3);
    let frac_e3 = extract_h(l_shl(e3, exp_e3));
    exp_e3 = sub(30, add(exp_e3, q_exc.wrapping_mul(2)));

    let mut exp_e2 = norm_l(e2);
    let mut frac_e2 = round_word(l_shl(e2, exp_e2));
    exp_e2 = sub(30, add(exp_e2, q_exc.wrapping_mul(2)));

    let scale = shr(sub(frac_e3, frac_e2), 15);
    frac_e2 = shl(frac_e2, scale);
    exp_e2 = sub(exp_e2, scale);

    let tmp = div_s(frac_e2, frac_e3);
    let mut exp = sub(exp_e2, exp_e3);

    let l_tmp1 = isqrt_lc(l_deposit_h(tmp), &mut exp); // Q(31-exp)

    for value in ptr.iter_mut() {
        let l_tmp = mult_32_16(l_tmp1, *value); // Q(16-exp+Q_exc)
        *value = round_word(l_shl(l_tmp, exp)); // Q_exc
    }
}
