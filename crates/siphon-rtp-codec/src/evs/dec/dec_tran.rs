//! Decoding of a TRANSITION (TC) frame of the MODE1 ACELP core (TS 26.442
//! `lib_dec/dec_tran_fx.c`; TS 26.445 §6.1.1.2.4): the glottal-shape codebook subframe, the
//! adaptive / fixed codebooks and gains of every subframe, the transform-domain pre-quantiser above
//! 24.4 kbit/s and the TBE excitation.

use crate::evs::cnst::{L_FRAME, L_SUBFR, M, PIT16K_MAX, Q_AVQ_OUT_DEC};
use crate::evs::com::enhancer::enhancer;
use crate::evs::com::est_tilt::est_tilt;
use crate::evs::com::scale_mem::rescale_exc;
use crate::evs::com::swb_tbe_com::prep_tbe_exc;
use crate::evs::com::tools::{acelp_dec_total_exc, scale_sig, set16};
use crate::evs::dec::dec_higher_acelp::transf_cdbk_dec;
use crate::evs::dec::gain_dec::{gain_dec_mless, gain_dec_sq, gain_dec_tc, lp_gain_updt};
use crate::evs::dec::inov_dec::inov_decode;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::transition_dec::transition_dec;
use crate::itu::basic_ops::{add, l_add, l_mult, l_shl, l_sub, round_word, sub};

const SUBFR: usize = L_SUBFR as usize;
/// `L_EXC_MEM`: the past excitation the first subframe rescales.
const L_EXC_MEM: usize = 320;

/// `decod_tran_fx`: decode the subframes of a TRANSITION frame of `l_frame` samples with the
/// glottal-shape codebook in subframe `tc_subfr` into `exc` (from `exc[exc_at]`, with
/// `L_EXC_MEM_DEC` of past excitation in front), `exc2` (the frame itself) and the BWE excitation
/// `bwe_exc` (from `bwe_exc[bwe_exc_at]`, with `2·PIT16k_MAX` in front); `pitch_buf`,
/// `voice_factors` and `gain_buf` receive the per-subframe pitch (Q6), TBE voicing and pitch gain,
/// `unbits` carries the pre-quantiser's unused bits.
pub fn decod_tran(
    st: &mut DecoderState,
    l_frame: i16,
    tc_subfr: i16,
    aq: &[i16],
    coder_type: i16,
    es_pred: i16,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
    unbits: &mut i16,
    sharp_flag: i16,
    gain_buf: &mut [i16],
) {
    let mut t0: i16 = 0;
    let mut t0_frac: i16 = 0;
    let mut t0_min: i16 = 0;
    let mut t0_max: i16 = 0;
    let mut gain_code: i32 = 0;
    let mut norm_gain_code: i32 = 0;
    let mut gain_pit: i16 = 0;
    let mut voice_fac: i16 = 0;
    let mut gain_inov: i16 = 0;
    let mut code = [0i16; SUBFR];
    let mut position: i16 = 0;
    let mut gain_pre_q: i16 = 0;
    let mut code_pre_q = [0i16; SUBFR];
    let mut norm_gain_pre_q: i32 = 0;

    // Initializations
    set16(&mut code_pre_q, 0, L_SUBFR);

    let mut pt_pitch = 0usize;
    let mut jopt_flag: i16 = 0;

    // ACELP subframe loop
    for (subframe, i_subfr) in (0..l_frame).step_by(SUBFR).enumerate() {
        if i_subfr == 0 && sub(st.q_exc, 2) > 0 {
            decod_tran_rescale_memories(st, exc, exc_at, bwe_exc, bwe_exc_at);
        }

        // TC: subframe determination; adaptive codebook search + pitch sharpening; glottal
        // codebook contribution
        transition_dec(
            st,
            st.core_brate,
            0,
            l_frame,
            i_subfr,
            coder_type,
            tc_subfr,
            &mut jopt_flag,
            exc,
            exc_at,
            &mut t0,
            &mut t0_frac,
            &mut t0_min,
            &mut t0_max,
            pitch_buf,
            &mut pt_pitch,
            &mut position,
            bwe_exc,
            bwe_exc_at,
            st.q_exc,
        );

        // Transform-domain contribution decoding (active frames)
        if l_sub(st.core_brate, 24400) > 0 {
            gain_code = 0;
            let mut mem_preemp = st.mem_preemp_pre_q;
            transf_cdbk_dec(
                st,
                st.core_brate,
                coder_type,
                0,
                i_subfr,
                tc_subfr,
                es_pred,
                gain_code,
                &mut mem_preemp,
                &mut gain_pre_q,
                &mut norm_gain_pre_q,
                &mut code_pre_q,
                unbits,
            );
            st.mem_preemp_pre_q = mem_preemp;
        }

        // ACELP codebook search + pitch sharpening
        let p_aq = &aq[subframe * (M as usize + 1)..];
        inov_decode(
            st,
            st.core_brate,
            0,
            l_frame,
            coder_type,
            sharp_flag,
            i_subfr,
            tc_subfr,
            p_aq,
            st.tilt_code,
            pitch_buf[pt_pitch],
            &mut code,
        );

        // De-quantize the codebook gain and the pitch gain
        if jopt_flag == 0 {
            // 2/3-bit decoding
            gain_dec_tc(
                st,
                st.core_brate,
                &code,
                l_frame,
                i_subfr,
                tc_subfr,
                es_pred,
                &mut gain_pit,
                &mut gain_code,
                &mut gain_inov,
                &mut norm_gain_code,
            );
        } else if l_sub(st.core_brate, 32000) > 0 {
            // 5-bit decoding
            gain_dec_sq(
                st,
                st.core_brate,
                coder_type,
                i_subfr,
                tc_subfr,
                &code,
                es_pred,
                &mut gain_pit,
                &mut gain_code,
                &mut gain_inov,
                &mut norm_gain_code,
            );
        } else {
            gain_dec_mless(
                st,
                st.core_brate,
                l_frame,
                coder_type,
                i_subfr,
                tc_subfr,
                &code,
                es_pred,
                &mut gain_pit,
                &mut gain_code,
                &mut gain_inov,
                &mut norm_gain_code,
            );
        }

        // Update the LP-filtered gains for the case of frame erasures
        lp_gain_updt(
            i_subfr,
            gain_pit,
            l_add(norm_gain_code, norm_gain_pre_q),
            &mut st.lp_gainp,
            &mut st.lp_gainc,
            l_frame,
        );

        // Estimate the spectral tilt
        let at = exc_at + i_subfr as usize;
        st.tilt_code = est_tilt(
            &exc[at..],
            gain_pit,
            &code,
            gain_code,
            &mut voice_fac,
            st.q_exc,
        );

        decod_tran_subframe_excitation(
            st,
            exc,
            exc_at,
            exc2,
            bwe_exc,
            bwe_exc_at,
            l_frame,
            i_subfr,
            coder_type,
            gain_code,
            gain_pit,
            &code,
            gain_pre_q,
            &code_pre_q,
        );

        // Prepare the TBE excitation
        prep_tbe_exc(
            l_frame,
            i_subfr,
            gain_pit,
            gain_code,
            &code,
            voice_fac,
            &mut voice_factors[subframe],
            &mut bwe_exc[bwe_exc_at..],
            gain_pre_q,
            &code_pre_q,
            st.q_exc,
            t0,
            t0_frac,
            coder_type,
            st.core_brate,
        );

        // Excitation enhancer (no enhancement above 32 kbit/s)
        let at = i_subfr as usize;
        if l_sub(st.core_brate, 32000) > 0 {
            let exc_at = exc_at + at;
            exc2[at..at + SUBFR].copy_from_slice(&exc[exc_at..exc_at + SUBFR]);
        } else {
            enhancer(
                st.core_brate,
                0,
                coder_type,
                i_subfr,
                l_frame,
                voice_fac,
                st.stab_fac,
                norm_gain_code,
                gain_inov,
                &mut st.gc_threshold,
                &mut code,
                exc2,
                gain_pit,
                &mut st.dm,
                st.q_exc,
            );
        }

        pt_pitch += 1;
        st.tilt_code_dec[subframe] = st.tilt_code;
        gain_buf[subframe] = gain_pit;
    }

    // SC-VBR
    st.prev_gain_pit_dec = gain_pit;
}

/// The first-subframe rescaling of `decod_tran_fx`: bring the past excitation, the past BWE
/// excitation and the last DCT input down to Q2 when the excitation's Q is above 2.
fn decod_tran_rescale_memories(
    st: &mut DecoderState,
    exc: &mut [i16],
    exc_at: usize,
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
) {
    let tmp16 = sub(2, st.q_exc);
    let exc_from = exc_at.saturating_sub(L_EXC_MEM); // the caller keeps L_EXC_MEM_DEC in front
    scale_sig(&mut exc[exc_from..], L_EXC_MEM as i16, tmp16);
    let bwe_len = PIT16K_MAX as usize * 2;
    let bwe_from = bwe_exc_at.saturating_sub(bwe_len);
    scale_sig(&mut bwe_exc[bwe_from..], bwe_len as i16, tmp16);
    scale_sig(&mut st.last_exc_dct_in, L_FRAME, tmp16);
    st.q_exc = add(st.q_exc, tmp16);
}

/// The excitation update of one `decod_tran_fx` subframe: rescale the excitation for the new gain,
/// build the total excitation, and add the transform-domain pre-quantiser contribution above
/// 24.4 kbit/s.
fn decod_tran_subframe_excitation(
    st: &mut DecoderState,
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
    l_frame: i16,
    i_subfr: i16,
    coder_type: i16,
    gain_code: i32,
    gain_pit: i16,
    code: &[i16],
    gain_pre_q: i16,
    code_pre_q: &[i16],
) {
    let at = i_subfr as usize;

    // Find the excitation and the total excitation
    let (bwe_subfr_at, lg32) = if sub(l_frame, L_FRAME) == 0 {
        // L_SUBFR * HIBND_ACB_L_FAC, HIBND_ACB_L_FAC = 5/2
        (at * 5 / 2, L_SUBFR * 5 / 2)
    } else {
        (at * 2, L_SUBFR * 2)
    };
    let mut q_exc = st.q_exc;
    let mut q_subfr = st.q_subfr;
    rescale_exc(
        Some(&mut st.dct_post_old_exc),
        exc,
        exc_at + at,
        Some((&mut *bwe_exc, bwe_exc_at + bwe_subfr_at)),
        Some(&mut st.last_exc_dct_in),
        L_SUBFR,
        lg32,
        gain_code,
        &mut q_exc,
        &mut q_subfr,
        Some(&mut *exc2),
        i_subfr,
        coder_type,
    );
    st.q_exc = q_exc;
    st.q_subfr = q_subfr;

    let gain_code16 = round_word(l_shl(gain_code, st.q_exc)); // Q_exc
    acelp_dec_total_exc(
        &mut exc[exc_at..],
        exc2,
        gain_code16,
        gain_pit,
        i_subfr,
        code,
    );

    // Add the ACELP pre-quantizer contribution
    if l_sub(st.core_brate, 24400) > 0 {
        let tmp1 = add(15 - Q_AVQ_OUT_DEC - 2, st.q_exc);
        for i in 0..SUBFR {
            let mut l_tmp = l_mult(gain_pre_q, code_pre_q[i]); // Q2+Q10 -> Q13
            l_tmp = l_shl(l_tmp, tmp1); // Q16+Q_exc
            let tmp = round_word(l_tmp);

            exc2[i + at] = add(exc2[i + at], tmp);
            exc[exc_at + i + at] = add(exc[exc_at + i + at], tmp);
        }
    }
}
