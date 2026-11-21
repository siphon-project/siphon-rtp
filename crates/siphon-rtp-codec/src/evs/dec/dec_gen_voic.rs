//! Excitation decoding of generic, voiced and AMR-WB IO ACELP frames (TS 26.442
//! `lib_dec/dec_gen_voic_fx.c`; TS 26.445 §6.1.1.2 and, for the FEC fast recovery, §6.1.1.3.4).

use crate::evs::cnst::{
    ACELP_24K40, ACELP_32K, ACELP_8K00, GENERIC, INACTIVE, L_EXC_MEM, L_FRAME, L_FRAME16K,
    L_INTERPOL2, L_SUBFR, M, MAXLAG_WI, MODE1, NB_SUBFR, NB_SUBFR16K, PIT_MAX, PIT_MIN,
    PIT_UP_SAMP, Q_AVQ_OUT_DEC,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::enhancer::enhancer;
use crate::evs::com::est_tilt::est_tilt;
use crate::evs::com::pred_lt4::pred_lt4;
use crate::evs::com::scale_mem::rescale_exc;
use crate::evs::com::swb_tbe_com::{interp_code_4over2, prep_tbe_exc, tbe_celp_exc};
use crate::evs::com::syn_12k8::syn_12k8;
use crate::evs::com::tools::{acelp_dec_total_exc, copy_scale_sig, rint_new};
use crate::evs::com::wi::{dtfs_new, dtfs_to_fs, get_sin_cos_tab, wi_syn};
use crate::evs::dec::dec_higher_acelp::transf_cdbk_dec;
use crate::evs::dec::gain_dec::{gain_dec_lbr, gain_dec_mless, gain_dec_sq, lp_gain_updt};
use crate::evs::dec::inov_dec::inov_decode;
use crate::evs::dec::lp_exc_d::lp_filt_exc_dec;
use crate::evs::dec::pit_dec::pit_decode;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::PITCH_INTER4_2;
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_l, l_mac, l_mult, l_shl, l_sub, norm_l, round_word,
    shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, shl_r};

const SUBFR: usize = L_SUBFR as usize;
const FRAME16K: usize = L_FRAME16K as usize;
const LAG_MAX: usize = MAXLAG_WI as usize;
/// `S_fx` / `C_fx`: the sin / cos tables of `GetSinCosTab_fx`, `PIT_MAX*4+1` entries.
const SIN_COS_LEN: usize = PIT_MAX as usize * 4 + 1;

/// `decod_gen_voic_fx`: decode the excitation of a generic (GC), voiced (VC) or AMR-WB IO frame,
/// subframe by subframe: pitch lag, adaptive codebook with its low-pass filter, transform-domain
/// pre-quantiser above 24.4 kbit/s, innovation, gains, rescaling, the total excitation and its
/// enhancement, the TBE excitation; then, after a frame erasure (`do_wi_fx`), the
/// waveform-interpolation fast recovery of the excitation.
///
/// `exc_fx[exc_at..]` and `bwe_exc_fx[bwe_exc_at..]` are where the reference's `exc_fx` and
/// `bwe_exc_fx` point (both carry history before the frame); `exc2_fx` starts at the frame.
/// `pitch_buf_fx` receives the pitch per subframe (Q6), `voice_factors_fx` the TBE voicing,
/// `gain_buf` the pitch gain per subframe; `unbits` carries the unused AVQ bits.
pub fn decod_gen_voic(
    st: &mut DecoderState,
    l_frame_fx: i16,
    sharp_flag_fx: i16,
    aq_fx: &[i16],
    coder_type_fx: i16,
    es_pred_fx: i16,
    do_wi_fx: i16,
    pitch_buf_fx: &mut [i16],
    voice_factors_fx: &mut [i16],
    exc_fx: &mut [i16],
    exc_at: usize,
    exc2_fx: &mut [i16],
    bwe_exc_fx: &mut [i16],
    bwe_exc_at: usize,
    unbits: &mut i16,
    gain_buf: &mut [i16],
) {
    let mut t0_fx: i16 = PIT_MIN;
    let mut t0_frac_fx: i16 = 0;
    let mut t0_min_fx: i16 = 0;
    let mut t0_max_fx: i16 = 0;
    let mut gain_pit_fx: i16 = 0; // pitch gain, Q14
    let mut gain_code_fx: i32 = 0; // gain/normalized gain of the algebraic excitation, Q16
    let mut norm_gain_code_fx: i32 = 0; // normalized gain of the algebraic excitation, Q16
    let mut gain_inov_fx: i16 = 0; // Innovation gain, Q12
    let mut gc_mem = [0_i32; NB_SUBFR as usize - 1]; // gain_code from previous subframes
    let mut gp_mem = [0_i16; NB_SUBFR as usize - 1]; // gain_pitch from previous subframes
    let mut voice_fac_fx: i16 = 0; // voicing factor, Q15
    let mut code_fx = [0_i16; SUBFR]; // algebraic codevector, Q12
    let mut error_fx: i16 = 0;
    let mut pitch_limit_flag_fx: i16 = 0;

    // read harmonicity flag
    let mut harm_flag_acelp: i16 = 0;
    if (l_sub(st.core_brate, i32::from(ACELP_24K40)) > 0
        && l_sub(st.core_brate, i32::from(ACELP_32K)) <= 0)
        && sub(coder_type_fx, GENERIC) == 0
    {
        harm_flag_acelp = get_next_indice(st, 1) as i16;
    }

    // ACELP subframe loop
    let mut p_aq_at: usize = 0; // pointer to interpolated LPC parameters
    let mut pt_pitch_at: usize = 0; // pointer to the pitch buffer
    let mut norm_gain_pre_q_fx: i32 = 0;
    let mut gain_pre_q_fx: i16 = 0; // Gain of prequantizer excitation
    let mut code_pre_q_fx = [0_i16; SUBFR]; // Prequantizer excitation

    let mut i_subfr_fx: i16 = 0;
    while i_subfr_fx < l_frame_fx {
        let i_subfr = i_subfr_fx as usize;

        // Decode pitch lag
        let core_brate = st.core_brate;
        pitch_buf_fx[pt_pitch_at] = pit_decode(
            st,
            core_brate,
            0,
            l_frame_fx,
            i_subfr_fx,
            coder_type_fx,
            &mut pitch_limit_flag_fx,
            &mut t0_fx,
            &mut t0_frac_fx,
            &mut t0_min_fx,
            &mut t0_max_fx,
            L_SUBFR,
        ); // Q6

        // Find the adaptive codebook vector
        pred_lt4(
            exc_fx,
            exc_at + i_subfr,
            t0_fx,
            t0_frac_fx,
            L_SUBFR + 1,
            &PITCH_INTER4_2,
            L_INTERPOL2,
            PIT_UP_SAMP,
        );
        tbe_celp_exc(
            l_frame_fx,
            i_subfr_fx,
            t0_fx,
            t0_frac_fx,
            &mut error_fx,
            bwe_exc_fx,
            bwe_exc_at,
        );

        // LP filtering of the adaptive excitation
        lp_filt_exc_dec(
            st,
            MODE1,
            core_brate,
            0,
            coder_type_fx,
            i_subfr_fx,
            L_SUBFR,
            l_frame_fx,
            0,
            exc_fx,
            exc_at,
        );

        // Transform-domain contribution decoding (active frames)
        if l_sub(st.core_brate, i32::from(ACELP_24K40)) > 0 && sub(coder_type_fx, INACTIVE) != 0 {
            gain_code_fx = 0;
            let mut mem_preemp = st.mem_preemp_pre_q;
            transf_cdbk_dec(
                st,
                core_brate,
                coder_type_fx,
                harm_flag_acelp,
                i_subfr_fx,
                -1,
                es_pred_fx,
                gain_code_fx,
                &mut mem_preemp,
                &mut gain_pre_q_fx,
                &mut norm_gain_pre_q_fx,
                &mut code_pre_q_fx,
                unbits,
            );
            st.mem_preemp_pre_q = mem_preemp;
        }

        // Innovation decoding
        let p_aq = &aq_fx[p_aq_at.min(aq_fx.len())..];
        let tilt_code = st.tilt_code;
        inov_decode(
            st,
            core_brate,
            0,
            l_frame_fx,
            coder_type_fx,
            sharp_flag_fx,
            i_subfr_fx,
            -1,
            p_aq,
            tilt_code,
            pitch_buf_fx[pt_pitch_at],
            &mut code_fx,
        );

        // Gain decoding, estimate spectrum tilt and voicing
        if l_sub(st.core_brate, i32::from(ACELP_8K00)) <= 0 {
            gain_dec_lbr(
                st,
                core_brate,
                coder_type_fx,
                i_subfr_fx,
                &code_fx,
                &mut gain_pit_fx,
                &mut gain_code_fx,
                &mut gain_inov_fx,
                &mut norm_gain_code_fx,
                &mut gc_mem,
                &mut gp_mem,
            );
        } else if l_sub(st.core_brate, i32::from(ACELP_32K)) > 0 {
            gain_dec_sq(
                st,
                core_brate,
                coder_type_fx,
                i_subfr_fx,
                -1,
                &code_fx,
                es_pred_fx,
                &mut gain_pit_fx,
                &mut gain_code_fx,
                &mut gain_inov_fx,
                &mut norm_gain_code_fx,
            );
        } else {
            gain_dec_mless(
                st,
                core_brate,
                l_frame_fx,
                coder_type_fx,
                i_subfr_fx,
                -1,
                &code_fx,
                es_pred_fx,
                &mut gain_pit_fx,
                &mut gain_code_fx,
                &mut gain_inov_fx,
                &mut norm_gain_code_fx,
            );
        }
        st.tilt_code = est_tilt(
            &exc_fx[exc_at + i_subfr..],
            gain_pit_fx,
            &code_fx,
            gain_code_fx,
            &mut voice_fac_fx,
            st.q_exc,
        );

        // Transform domain contribution decoding
        if l_sub(st.core_brate, i32::from(ACELP_24K40)) > 0 && sub(coder_type_fx, INACTIVE) == 0 {
            let mut mem_preemp = st.mem_preemp_pre_q;
            transf_cdbk_dec(
                st,
                core_brate,
                coder_type_fx,
                harm_flag_acelp,
                i_subfr_fx,
                -1,
                es_pred_fx,
                gain_code_fx,
                &mut mem_preemp,
                &mut gain_pre_q_fx,
                &mut norm_gain_pre_q_fx,
                &mut code_pre_q_fx,
                unbits,
            );
            st.mem_preemp_pre_q = mem_preemp;
        }

        // update LP filtered gains for the case of frame erasures
        lp_gain_updt(
            i_subfr_fx,
            gain_pit_fx,
            l_add(norm_gain_code_fx, norm_gain_pre_q_fx),
            &mut st.lp_gainp,
            &mut st.lp_gainc,
            l_frame_fx,
        );

        // Find the total excitation
        decod_gen_voic_total_exc(
            st,
            l_frame_fx,
            coder_type_fx,
            i_subfr_fx,
            gain_pit_fx,
            gain_code_fx,
            gain_pre_q_fx,
            &code_pre_q_fx,
            &code_fx,
            exc_fx,
            exc_at,
            exc2_fx,
            bwe_exc_fx,
            bwe_exc_at,
        );

        // Prepare TBE excitation
        prep_tbe_exc(
            l_frame_fx,
            i_subfr_fx,
            gain_pit_fx,
            gain_code_fx,
            &code_fx,
            voice_fac_fx,
            &mut voice_factors_fx[i_subfr / SUBFR],
            &mut bwe_exc_fx[bwe_exc_at..],
            gain_pre_q_fx,
            &code_pre_q_fx,
            st.q_exc,
            t0_fx,
            t0_frac_fx,
            coder_type_fx,
            st.core_brate,
        );

        // Excitation enhancements (update of total excitation signal)
        if l_sub(st.core_brate, i32::from(ACELP_32K)) > 0 || sub(coder_type_fx, INACTIVE) == 0 {
            exc2_fx[i_subfr..i_subfr + SUBFR]
                .copy_from_slice(&exc_fx[exc_at + i_subfr..exc_at + i_subfr + SUBFR]);
        } else {
            let q_exc = st.q_exc;
            enhancer(
                st.core_brate,
                0,
                coder_type_fx,
                i_subfr_fx,
                l_frame_fx,
                voice_fac_fx,
                st.stab_fac,
                norm_gain_code_fx,
                gain_inov_fx,
                &mut st.gc_threshold,
                &mut code_fx,
                exc2_fx,
                gain_pit_fx,
                &mut st.dm,
                q_exc,
            );
        }

        p_aq_at += M as usize + 1;
        pt_pitch_at += 1;
        gain_buf[i_subfr / SUBFR] = gain_pit_fx;
        i_subfr_fx += L_SUBFR;
    }

    // FEC fast recovery
    if do_wi_fx != 0 {
        decod_gen_voic_fast_recovery(
            st,
            l_frame_fx,
            aq_fx,
            do_wi_fx,
            pitch_buf_fx,
            exc_fx,
            exc_at,
            exc2_fx,
            bwe_exc_fx,
            bwe_exc_at,
        );
    }

    // SC-VBR
    st.prev_gain_pit_dec = gain_pit_fx; // Q14
    st.prev_tilt_code_dec = st.tilt_code; // Q15
}

/// The total-excitation part of `decod_gen_voic_fx`'s subframe loop: rescale the excitation
/// (`Rescale_exc`, against the code gain or, at 16 kHz, the larger of it and the pre-quantiser
/// gain), then `exc2 = gain_pit·exc` and `exc = gain_pit·exc + gain_code·code`, both with the
/// AVQ pre-quantiser contribution above 24.4 kbit/s.
fn decod_gen_voic_total_exc(
    st: &mut DecoderState,
    l_frame_fx: i16,
    coder_type_fx: i16,
    i_subfr_fx: i16,
    gain_pit_fx: i16,
    gain_code_fx: i32,
    gain_pre_q_fx: i16,
    code_pre_q_fx: &[i16],
    code_fx: &[i16],
    exc_fx: &mut [i16],
    exc_at: usize,
    exc2_fx: &mut [i16],
    bwe_exc_fx: &mut [i16],
    bwe_exc_at: usize,
) {
    let i_subfr = i_subfr_fx as usize;
    if sub(l_frame_fx, L_FRAME) == 0 {
        // Rescaling for 12.8k core; `HIBND_ACB_L_FAC` is 5/2
        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            exc_fx,
            exc_at + i_subfr,
            Some((bwe_exc_fx, bwe_exc_at + i_subfr * 5 / 2)),
            Some(&mut st.last_exc_dct_in),
            L_SUBFR,
            L_SUBFR * 5 / 2,
            gain_code_fx,
            &mut st.q_exc,
            &mut st.q_subfr,
            Some(exc2_fx),
            i_subfr_fx,
            coder_type_fx,
        );
    } else {
        // Rescaling for 16k core: the maximum of gain_code or the prequantizer excitation x4,
        // to keep some room
        let l_tmp_gc = gain_code_fx.max(l_shl(i32::from(gain_pre_q_fx), 16));
        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            exc_fx,
            exc_at + i_subfr,
            Some((bwe_exc_fx, bwe_exc_at + i_subfr * 2)),
            Some(&mut st.last_exc_dct_in),
            L_SUBFR,
            L_SUBFR * 2,
            l_tmp_gc,
            &mut st.q_exc,
            &mut st.q_subfr,
            Some(exc2_fx),
            i_subfr_fx,
            coder_type_fx,
        );
    }

    let gain_code16 = round_word(l_shl(gain_code_fx, st.q_exc)); // Q_exc

    // Add the ACELP pre-quantizer contribution
    if l_sub(st.core_brate, i32::from(ACELP_24K40)) > 0 {
        let tmp1_fx = add(15 - Q_AVQ_OUT_DEC - 2, st.q_exc);
        for i in 0..SUBFR {
            // Contribution from AVQ layer
            let mut ltmp1 = l_mult(gain_pre_q_fx, code_pre_q_fx[i]); // Q2 + Q6 -> Q9
            ltmp1 = l_shl(ltmp1, tmp1_fx); // Q16 + Q_exc

            // Compute exc2
            let mut l_tmp = l_shl(l_mult(gain_pit_fx, exc_fx[exc_at + i + i_subfr]), 1);
            exc2_fx[i + i_subfr] = round_word(l_add(l_tmp, ltmp1));

            // code in Q9, gain_pit in Q14
            l_tmp = l_mult(gain_code16, code_fx[i]);
            l_tmp = l_shl(l_tmp, 5);
            l_tmp = l_mac(l_tmp, exc_fx[exc_at + i + i_subfr], gain_pit_fx);
            l_tmp = l_shl(l_tmp, 1); // saturation can occur here

            exc_fx[exc_at + i + i_subfr] = round_word(l_add(l_tmp, ltmp1));
        }
    } else {
        acelp_dec_total_exc(
            &mut exc_fx[exc_at..],
            exc2_fx,
            gain_code16,
            gain_pit_fx,
            i_subfr_fx,
            code_fx,
        );
    }
}

/// `buffer[at..]`, or an empty slice where the reference's pointer would fall outside it (a
/// pitch beyond the buffer, which the decoder's pitch limits never produce).
fn tail(buffer: &[i16], at: i32) -> &[i16] {
    usize::try_from(at)
        .ok()
        .and_then(|at| buffer.get(at..))
        .unwrap_or(&[])
}

/// `1 + Σ x[i]²` over the first `n` samples of `x` (`L_mac0`, saturating), the energies the fast
/// recovery compares; samples past the end of `x` count as 0.
fn energy(x: &[i16], n: i16) -> i32 {
    let mut nrg = l_deposit_l(1);
    for &value in x.iter().take(n.max(0) as usize) {
        nrg = l_mac0(nrg, value, value);
    }
    nrg
}

/// The ratio `curr / prev` of two energies in Q`2·q_curr` and Q`2·q_prev`, as a mantissa and its
/// Q (the reference's `enratio` / `sp_enratio` block); `(0, 0)` for a non-positive `prev`.
fn energy_ratio(prev: i32, q_prev: i16, curr: i32, q_curr: i16) -> (i16, i16) {
    if prev <= 0 {
        return (0, 0);
    }
    let mut expa = norm_l(prev);
    let fraca = extract_h(l_shl(prev, expa));
    expa = sub(30, expa.wrapping_add(q_prev.wrapping_mul(2)));

    let mut expb = norm_l(curr);
    let mut fracb = round_word(l_shl(curr, expb));
    expb = sub(30, expb.wrapping_add(q_curr.wrapping_mul(2)));

    let scale = shr(sub(fraca, fracb), 15);
    fracb = shl(fracb, scale);
    expb = sub(expb, scale);

    let ratio = div_s(fracb, fraca);
    let exp1 = sub(expb, expa);
    (ratio, 15_i16.wrapping_sub(exp1))
}

/// The FEC fast recovery of `decod_gen_voic_fx`: after an erasure, if the residual and speech
/// energies of the last pitch cycle before and after it are compatible, replace the frame's
/// excitation by a waveform interpolation from the last good pitch cycle to the current one, and
/// rebuild the TBE excitation from it.
fn decod_gen_voic_fast_recovery(
    st: &mut DecoderState,
    l_frame_fx: i16,
    aq_fx: &[i16],
    do_wi_fx: i16,
    pitch_buf_fx: &[i16],
    exc_fx: &mut [i16],
    exc_at: usize,
    exc2_fx: &mut [i16],
    bwe_exc_fx: &mut [i16],
    bwe_exc_at: usize,
) {
    let mut mem_tmp_fx = [0_i16; M as usize];
    let mut syn_tmp_fx = [0_i16; FRAME16K];
    let mut s_fx = [0_i16; SIN_COS_LEN];
    let mut c_fx = [0_i16; SIN_COS_LEN];
    let dummy2 = [0_i16; 2];
    let mut out_fx = [0_i16; FRAME16K];
    let mut pf_temp1 = [0_i16; LAG_MAX]; // may not need more than MAXLAG_WI/2+1
    let mut pf_temp2 = [0_i16; LAG_MAX];
    let mut pf_temp = [0_i16; LAG_MAX];
    let mut pf_n2 = [0_i16; LAG_MAX];

    // shft_prev = L_EXC_MEM - rint_new_fx(st_fx->bfi_pitch_fx)
    let mut l_tmp = l_shl(l_deposit_l(st.bfi_pitch), 10); // Q16
    let rint_bfi_pitch = rint_new(l_tmp); // Q0
    let shft_prev = sub(L_EXC_MEM, rint_bfi_pitch); // Q0

    let prev_res_nrg = energy(tail(&st.old_exc2, i32::from(shft_prev)), rint_bfi_pitch); // 2*prev_Q_exc_fr
    let prev_spch_nrg = energy(tail(&st.old_syn2, i32::from(shft_prev)), rint_bfi_pitch); // 2*prev_Q_syn_fr

    mem_tmp_fx.copy_from_slice(&st.mem_syn2[..M as usize]);

    syn_12k8(
        st.l_frame,
        aq_fx,
        exc2_fx,
        &mut syn_tmp_fx,
        &mut mem_tmp_fx,
        1,
        st.q_exc,
        st.q_syn,
    );

    l_tmp = l_shl(l_deposit_l(pitch_buf_fx[NB_SUBFR16K as usize - 1]), 10); // Q16
    let rint_pitch = rint_new(l_tmp); // Q0
    let shft_curr = sub(st.l_frame, rint_pitch); // Q0

    let curr_res_nrg = energy(tail(exc2_fx, i32::from(shft_curr)), rint_pitch); // 2*Q_exc
    let curr_spch_nrg = energy(tail(&syn_tmp_fx, i32::from(shft_curr)), rint_pitch); // 2*Q_syn

    // enratio = (curr_res_nrg / prev_res_nrg)
    let (enratio, qenratio) = energy_ratio(prev_res_nrg, st.prev_q_exc_fr, curr_res_nrg, st.q_exc);
    // sp_enratio = curr_spch_nrg/prev_spch_nrg
    let (sp_enratio, qsp_enratio) =
        energy_ratio(prev_spch_nrg, st.prev_q_syn_fr, curr_spch_nrg, st.q_syn);

    if sub(shl_r(enratio, 15_i16.wrapping_sub(qenratio)), 8192) > 0 // compare with 0.25 in Q15
        && sub(shl_r(enratio, 10_i16.wrapping_sub(qenratio)), 15360) < 0 // compare with 15.0 in Q10
        && sub(shl_r(sp_enratio, 15_i16.wrapping_sub(qsp_enratio)), 4915) > 0 // compare with 0.15 in Q15
        && st.bfi_pitch < 9600 // Q6
        && pitch_buf_fx[sub(NB_SUBFR16K, 1) as usize] < 9600
    // Q6
    {
        let mut prevp = dtfs_new();
        let mut currp = dtfs_new();

        get_sin_cos_tab(rint_bfi_pitch, &mut s_fx, &mut c_fx);
        dtfs_to_fs(
            tail(&st.old_exc2, i32::from(shft_prev)),
            rint_bfi_pitch,
            &mut prevp,
            st.output_fs as i16,
            do_wi_fx,
            &s_fx,
            &c_fx,
        );
        prevp.q = add(prevp.q, st.prev_q_exc_fr);

        get_sin_cos_tab(rint_pitch, &mut s_fx, &mut c_fx);
        dtfs_to_fs(
            tail(exc2_fx, i32::from(shft_curr)),
            rint_pitch,
            &mut currp,
            st.output_fs as i16,
            do_wi_fx,
            &s_fx,
            &c_fx,
        );
        currp.q = add(currp.q, st.q_exc);

        let mut ph_offset_fx: i16 = 0;
        wi_syn(
            prevp,
            &mut currp,
            &dummy2,
            &mut ph_offset_fx,
            &mut out_fx,
            st.l_frame,
            1,
            &s_fx,
            &c_fx,
            &mut pf_temp1,
            &mut pf_temp2,
            &mut pf_temp,
            &mut pf_n2,
        );

        copy_scale_sig(&out_fx, exc2_fx, st.l_frame, st.q_exc);
        copy_scale_sig(&out_fx, &mut exc_fx[exc_at..], st.l_frame, st.q_exc);

        // update bwe_exc for SWB-TBE
        let mut i_subfr: i16 = 0;
        while i_subfr < l_frame_fx {
            let i = i_subfr as usize;
            let (exc_part, bwe_part) =
                (&exc_fx[exc_at + i..], &mut bwe_exc_fx[bwe_exc_at + i * 2..]);
            interp_code_4over2(exc_part, bwe_part, L_SUBFR);
            i_subfr += L_SUBFR;
        }
    }
}
