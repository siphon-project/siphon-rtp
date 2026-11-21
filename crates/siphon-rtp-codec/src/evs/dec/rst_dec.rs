//! Decoder state reset when coming out of comfort-noise generation (TS 26.442
//! `lib_dec/rst_dec_fx.c`).

use crate::evs::cnst::{L_FRAME, L_SUBFR, L_SUBFR16K, M, NB_SUBFR, NB_SUBFR16K, UNVOICED_CLAS};
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::tools::set16;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::UVWB_AVE_FX;
use crate::itu::basic_ops::{div_s, extract_h, l_deposit_h, l_shl, norm_l, round_word, sub};

/// `CNG_reset_dec_fx`: reset the LSF quantiser memories, the phase dispersion and the FEC state for
/// the first ACELP frame after CNG (`FRAME_NO_DATA` / SID), derive the FEC gain `lp_gainc` from the
/// CNG energy, and reset the pitch buffer and the voicing factors.
pub fn cng_reset_dec(st: &mut DecoderState, pitch_buf: &mut [i16], voice_factors: &mut [i16]) {
    st.mem_ar.copy_from_slice(&UVWB_AVE_FX[..M as usize]);
    set16(&mut st.mem_ma, 0, M);

    // last good received frame for FEC in ACELP
    set16(&mut st.dm.prev_gain_pit, 0, 6);
    st.dm.prev_gain_code = 0;
    st.dm.prev_state = 0;

    st.tilt_code = 0;
    st.gc_threshold = 0;

    // last good received frame for FEC in ACELP
    st.clas_dec = UNVOICED_CLAS;
    st.last_good = UNVOICED_CLAS;

    // LP-filtered pitch gain set to 0
    st.lp_gainp = 0;

    // convert the CNG energy into the CNG gain for ACELP FEC
    // lp_gainc = sqrt(lp_ener)
    st.lp_gainc = 0;

    if st.lp_ener != 0 {
        let mut exp = norm_l(st.lp_ener);
        let mut tmp = extract_h(l_shl(st.lp_ener, exp));
        exp = sub(exp, 30 - 6);

        tmp = div_s(16384, tmp);
        let mut l_tmp = l_deposit_h(tmp);
        l_tmp = isqrt_lc(l_tmp, &mut exp);

        st.lp_gainc = round_word(l_shl(l_tmp, sub(exp, 12))); // in Q3
    }

    // reset the pitch buffer in case of FRAME_NO_DATA or SID frames
    if sub(st.l_frame, L_FRAME) == 0 {
        set16(pitch_buf, L_SUBFR << 6, NB_SUBFR);
    } else {
        // st->L_frame == L_FRAME16k
        set16(pitch_buf, L_SUBFR16K << 6, NB_SUBFR16K);
    }

    set16(voice_factors, 32767, NB_SUBFR16K);

    // deactivate the bass post-filter
    st.bpf_off = 1;

    // reset the counter of non-active frames
    st.act_cnt2 = 0;
}
