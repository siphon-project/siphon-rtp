//! Excitation concealment of a lost ACELP frame (TS 26.442 `lib_dec/FEC_fx.c`; TS 26.447
//! §5.4.2): `FEC_exc_estim_fx`, `gain_dec_bfi_fx` (the AMR-WB IO gain-predictor memory of a lost
//! frame) and the file-local `pulseRes_preCalc` (the conditions for resynchronising the glottal
//! pulses).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    _ALPHA_S_FX, _ALPHA_UT_FX, _ALPHA_UU_FX, _ALPHA_U_FX, _ALPHA_VT_FX, _ALPHA_V_FX, ACELP_24K40,
    AUDIO, GAIN_PRED_ORDER, GENERIC, INACTIVE_CLAS, L_FRAME, L_FRAME16K, L_SUBFR, MAX_UPD_CNT,
    MODE1_L_FIR_FER, NB_SUBFR, NB_SUBFR16K, ONSET, PIT16K_MAX, PIT16K_MIN_EXTEND, PIT_MAX,
    PIT_MIN_DOUBLEEXTEND, SIN_ONSET, TRANSITION, UNVOICED, UNVOICED_CLAS, UNVOICED_TRANSITION,
    VOICED_CLAS,
};
use crate::evs::com::basop_util::{basop_util_add_mant_exp, basop_util_divide1616_scale};
use crate::evs::com::edct::edct_16fx;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::swb_tbe_com::{interp_code_4over2, interp_code_5over2};
use crate::evs::com::tools::{copy, random, set16};
use crate::evs::dec::er_sync_exc::pulse_resynchronization;
use crate::evs::dec::gs_dec::gsc_dec;
use crate::evs::dec::pitch_extr::pitch_pred_linear_fit;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{H_HIGH_FX, MFREQ_LOC_DIV_25, SM_TABLE_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu, l_mult,
    l_negate, l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr,
    shr_r, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r, msu_r};

/// `L_FRAME16k + MODE1_L_FIR_FER - 1`: the random excitation with the FIR filter's ringing.
const EXC2_BUF: usize = (L_FRAME16K + MODE1_L_FIR_FER - 1) as usize;

/// `FEC_exc_estim_fx`: the concealed excitation of a lost ACELP frame of `l_frame` samples.
///
/// The harmonic part repeats the last pitch cycle of the past excitation (the `exc_at` samples
/// before `exc[exc_at]` are the history, Q`q_exc`), resynchronised to an extrapolated pitch and
/// faded by the class of the last good frame; after a GSC frame the last spectrum is replicated
/// instead (`exc_dct_in`). The random part is noise faded towards the comfort-noise gain and
/// high-passed. Writes the adaptive excitation `exc[exc_at..exc_at + l_frame + L_SUBFR]`, the
/// total excitation `exc2`, the subframe pitches `pitch_buf` (Q6), the voicing factors, the
/// pitch `tmp_tc` (Q6) the bass post-filter uses, the SWB TBE excitation `bwe_exc` and the noise
/// energy `tmp_noise`; updates the gain, pitch and seed memories.
///
/// `exc` must hold `l_frame + L_SUBFR` samples of history before `exc_at` (the resynchronisation
/// rebuilds the frame there).
pub fn fec_exc_estim(
    st: &mut DecoderState,
    l_frame: i16,
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    exc_dct_in: &mut [i16],
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    tmp_tc: &mut i16,
    bwe_exc: &mut [i16],
    lsf_new: &[i16],
    q_exc: i16,
    tmp_noise: &mut i16,
) {
    let mut exc2_buf = [0i16; EXC2_BUF];

    // nb_subfr = L_frame/L_SUBFR
    let nb_subfr = shr(l_frame, 6);
    let mut diff_len: i16 = 0; // to avoid compilation flags
    set16(exc_dct_in, 0, L_FRAME16K);

    let mut gain_cng: i16 = 0;
    if st.lp_ener != 0 {
        let mut exp = norm_l(st.lp_ener); // lp_ener in Q6
        let mut tmp = extract_h(l_shl(st.lp_ener, exp));
        exp = sub(exp, 30 - 6);

        tmp = div_s(16384, tmp);
        let mut l_tmp = l_deposit_h(tmp);
        l_tmp = isqrt_lc(l_tmp, &mut exp);

        gain_cng = round_word(l_shl(l_tmp, sub(exp, 12))); // In Q3
    }
    let tmp1 = shl(st.lp_gainc, 1);
    gain_cng = gain_cng.min(tmp1);
    set16(exc_dct_in, 0, L_FRAME16K);

    // pitch extrapolation
    let (tmp_old_pitch, tmp_pitmin, tmp_pitmax) = if sub(l_frame, L_FRAME) == 0 {
        (
            st.old_pitch_buf[2 * NB_SUBFR as usize - 1],
            PIT_MIN_DOUBLEEXTEND,
            PIT_MAX,
        )
    } else {
        (
            st.old_pitch_buf[2 * NB_SUBFR16K as usize - 1],
            PIT16K_MIN_EXTEND,
            PIT16K_MAX,
        )
    };
    let mut pred_pitch_lag: i32 = 0;
    let mut extrapolation_failed: i16 = 1;
    pitch_pred_linear_fit(
        st.nb_lost_cmpt,
        st.last_good,
        &st.old_pitch_buf,
        tmp_old_pitch,
        &mut pred_pitch_lag,
        tmp_pitmin,
        tmp_pitmax,
        &st.mem_pitch_gain,
        0,
        0,
        &mut extrapolation_failed,
        nb_subfr,
    );
    let new_pit = shl(round_word(pred_pitch_lag), 0); // Q0 int

    // estimate subframe pitch values for the FEC frame
    let tc = fec_exc_estim_pitch(
        st,
        l_frame,
        nb_subfr,
        new_pit,
        extrapolation_failed,
        tmp_tc,
        pitch_buf,
    );

    // estimate damping factor
    let alpha = fec_exc_estim_alpha(st);

    // construct the harmonic part of excitation
    let gsc_last = sub(st.last_coder_type, AUDIO) == 0 || sub(st.last_good, INACTIVE_CLAS) == 0;
    if (sub(st.last_good, UNVOICED_TRANSITION) >= 0 && sub(st.last_good, INACTIVE_CLAS) < 0)
        || (gsc_last && st.last_gsc_pit_band_idx > 0)
    {
        fec_exc_estim_harmonic(
            st,
            l_frame,
            nb_subfr,
            exc,
            exc_at,
            tc,
            new_pit,
            extrapolation_failed,
            alpha,
        );
        if gsc_last && st.last_gsc_pit_band_idx > 0 {
            diff_len = fec_exc_estim_gsc_pitch_band(st, exc, exc_at, exc_dct_in);
        }
    }

    // Replicate the last spectrum in case the last good frame was coded by GSC
    if sub(st.last_coder_type, AUDIO) == 0
        || (sub(st.last_good, INACTIVE_CLAS) == 0
            && l_sub(st.total_brate, i32::from(ACELP_24K40)) <= 0
            && st.opt_amr_wb == 0)
    {
        st.gsc_noisy_speech = st.last_gsc_noisy_speech_flag;
        // Replication of the last spectrum, with a slight downscaling of its dynamic
        let mut last_bin: i16 = 0;
        let pit_band_idx = st.last_gsc_pit_band_idx;
        let gsc_nb_subfr = st.l_frame / L_SUBFR;
        let last_coder_type = st.last_coder_type;
        let st_q_exc = st.q_exc;
        gsc_dec(
            st,
            exc_dct_in,
            pit_band_idx,
            diff_len,
            0,
            gsc_nb_subfr,
            last_coder_type,
            &mut last_bin,
            lsf_new,
            None,
            st_q_exc,
        );
        *tmp_noise = shr_r(st.lp_gainc, 3); // Q0
                                            // Transform back to time domain
        edct_16fx(exc_dct_in, &mut exc[exc_at..], st.l_frame, 5);
    } else {
        fec_exc_estim_random(st, l_frame, alpha, gain_cng, q_exc, &mut exc2_buf);
    }

    // Total excitation
    fec_exc_estim_total(st, l_frame, exc, exc_at, exc2, &exc2_buf);

    if sub(l_frame, L_FRAME) == 0 {
        interp_code_5over2(&exc[exc_at..], bwe_exc, l_frame);
    } else {
        interp_code_4over2(&exc[exc_at..], bwe_exc, l_frame);
    }
    let voice_factor = if gsc_last {
        32767
    } else {
        // The factor of the last subframe is propagated forward
        st.last_voice_factor
    };
    if sub(st.l_frame, L_FRAME) == 0 {
        set16(voice_factors, voice_factor, NB_SUBFR);
    } else {
        set16(voice_factors, voice_factor, NB_SUBFR16K);
    }
    if st.opt_amr_wb != 0 {
        gain_dec_bfi(&mut st.past_qua_en);
    }
    // a frame length that is not a whole number of subframes would index before pitch_buf
    st.bfi_pitch = pitch_buf[(l_frame / L_SUBFR).max(1) as usize - 1];
    st.bfi_pitch_frame = st.l_frame;
}

/// The subframe pitches `pitch_buf` (Q6) of the lost frame and the pitch `tmp_tc` (Q6): the
/// long-term pitch, or the last subframe's when it is coherent with it; moving linearly to the
/// extrapolated `new_pit` when the pulses will be resynchronised. Returns the pitch cycle `Tc`
/// (Q0) the harmonic excitation repeats.
fn fec_exc_estim_pitch(
    st: &DecoderState,
    l_frame: i16,
    nb_subfr: i16,
    new_pit: i16,
    extrapolation_failed: i16,
    tmp_tc: &mut i16,
    pitch_buf: &mut [i16],
) -> i16 {
    // initialize pitch to the long-term pitch
    *tmp_tc = st.bfi_pitch; // Q6
    let last = if sub(l_frame, L_FRAME) == 0 {
        2 * NB_SUBFR as usize - 1
    } else {
        // L_frame == L_FRAME16k
        2 * NB_SUBFR16K as usize - 1
    };
    let last_pitch = round_word(l_shl(st.old_pitch_buf[last], 6));
    if (sub(last_pitch, shl(mult(29491, st.bfi_pitch), 1)) < 0
        && sub(last_pitch, mult(19661, st.bfi_pitch)) > 0) // last pitch coherent with the past
        || sub(st.upd_cnt, MAX_UPD_CNT) >= 0
    // or last update too far in the past
    {
        // take the pitch value of last subframe of the previous frame
        *tmp_tc = last_pitch;
    }

    // convert pitch period: Tc = (short)(tmp_tc + 0.5f)
    let tc = shr_r(*tmp_tc, 6);

    // estimate pitch values for all subframes; calculate conditions for Pulse
    // resynchronization to take place
    let (mut cond1, mut cond2, mut cond3) = (0i16, 0i16, 0i32);
    pulse_res_pre_calc(&mut cond1, &mut cond2, &mut cond3, new_pit, tc, l_frame);

    let subframes = nb_subfr.max(0) as usize;
    if cond1 < 0 && new_pit > 0 && cond2 != 0 && cond3 > 0 && extrapolation_failed == 0 {
        let mut tmp16 = *tmp_tc; // Q6
        let delta = if sub(nb_subfr, 4) == 0 {
            shr(sub(shl(new_pit, 6), *tmp_tc), 2) // 4 sub-frames
        } else {
            mult_r(sub(shl(new_pit, 6), *tmp_tc), 6554) // 5 sub-frames
        };
        for value in &mut pitch_buf[..subframes] {
            // subframe pitch values: fT0 += delta
            tmp16 = add(tmp16, delta);
            // ptch_buf[i] = (short)(fT0 + 0.5)
            *value = shl(mult_r(tmp16, 512), 6);
        }
    } else {
        // subframe pitch values for bass postfilter
        for value in &mut pitch_buf[..subframes] {
            *value = *tmp_tc;
        }
    }
    tc
}

/// The damping factor of the lost frame (Q15, or the Q14 pitch gain after the first lost frame
/// of a voiced signal), by the class and coder type of the last good frame; on the first lost
/// voiced frame it also resets `lp_gainp` towards 1.
fn fec_exc_estim_alpha(st: &mut DecoderState) -> i16 {
    // rapid convergence to 0
    let mut alpha = _ALPHA_VT_FX;
    if st.last_coder_type == UNVOICED && sub(st.nb_lost_cmpt, 3) <= 0 {
        // last good frame was clearly unvoiced
        alpha = _ALPHA_UU_FX;
    } else if sub(st.last_coder_type, AUDIO) == 0 || sub(st.last_good, INACTIVE_CLAS) == 0 {
        if st.last_gsc_pit_band_idx > 0 && sub(st.nb_lost_cmpt, 1) > 0 {
            alpha = 26214;
        } else if sub(st.nb_lost_cmpt, 5) <= 0 {
            alpha = 32604;
        } else {
            alpha = 31130;
        }
    } else if sub(st.last_good, UNVOICED_CLAS) == 0 {
        if sub(st.nb_lost_cmpt, 1) <= 0 {
            // if stable, do not decrease the energy, pitch_gain = 0
            alpha = mac_r(
                (1i32 << 16) * 2 * i32::from(_ALPHA_U_FX),
                st.stab_fac,
                (32768 - 2 * i32::from(_ALPHA_U_FX)) as i16,
            ); // st_fx->stab_fac_fx in Q15
        } else if sub(st.nb_lost_cmpt, 2) == 0 {
            alpha = _ALPHA_S_FX; // ALPHA_U*1.5f = 0.6
        } else {
            alpha = _ALPHA_U_FX; // 0.4 go rapidly to CNG gain, pitch gain = 0
        }
    } else if sub(st.last_good, UNVOICED_TRANSITION) == 0 {
        alpha = _ALPHA_UT_FX;
    } else if sub(st.last_good, ONSET) == 0
        && sub(st.nb_lost_cmpt, 3) <= 0
        && (sub(st.last_coder_type, GENERIC) == 0 || sub(st.last_coder_type, TRANSITION) == 0)
    {
        alpha = 26214; // mild convergence to 0 for the first 3 erased frames 0.8 in Q15
    } else if (sub(st.last_good, VOICED_CLAS) == 0 || sub(st.last_good, ONSET) == 0)
        && sub(st.nb_lost_cmpt, 3) <= 0
    {
        alpha = _ALPHA_V_FX; // constant for the first 3 erased frames
    } else if sub(st.last_good, SIN_ONSET) == 0 {
        alpha = _ALPHA_S_FX;
    }
    if sub(st.last_good, VOICED_CLAS) >= 0
        && sub(st.last_good, INACTIVE_CLAS) < 0
        && sub(st.last_coder_type, AUDIO) != 0
    {
        if sub(st.nb_lost_cmpt, 1) == 0 {
            // if first erased frame in a block, reset harmonic gain; move pitch gain towards 1
            // for voiced to remove energy fluctuations: gain = (float)sqrt( st_fx->lp_gainp );
            st.lp_gainp = st.lp_gainp.max(1);
            let mut exp = norm_s(st.lp_gainp);
            let mut tmp = shl(st.lp_gainp, exp);
            tmp = div_s(16384, tmp);
            let mut l_tmp = l_deposit_h(tmp);
            l_tmp = isqrt_lc(l_tmp, &mut exp);

            let mut gain = extract_h(l_shl(l_tmp, exp));

            gain = gain.min(32113); // 0.98
            gain = gain.max(27853); // 0.85

            alpha = mult_r(alpha, gain);
        } else {
            // st_fx->lp_gainp_fx is in Q14 when bfi_cnt > 1 to follow floating point because
            // lp_gainp could be > than 1
            alpha = st.lp_gainp;
        }
    }
    alpha
}

/// Whether `alpha` and the gains are in the Q14 "voiced, not the first lost frame" regime.
fn fec_exc_estim_voiced_continuation(st: &DecoderState) -> bool {
    sub(st.last_good, VOICED_CLAS) >= 0
        && sub(st.last_good, INACTIVE_CLAS) < 0
        && sub(st.last_coder_type, AUDIO) != 0
        && sub(st.nb_lost_cmpt, 1) > 0
}

/// The harmonic excitation: the last pitch cycle (low-passed on the first lost frame) repeated
/// up to an extra subframe, its pulses resynchronised to `new_pit` when the conditions hold, and
/// faded linearly from the frame's start gain to the new `lp_gainp`.
fn fec_exc_estim_harmonic(
    st: &mut DecoderState,
    l_frame: i16,
    nb_subfr: i16,
    exc: &mut [i16],
    exc_at: usize,
    tc: i16,
    new_pit: i16,
    extrapolation_failed: i16,
    alpha: i16,
) {
    let tc_len = tc.max(0) as usize;
    let mut pt_exc = exc_at;
    // a pitch cycle longer than the history reads before the buffer in the reference
    let mut pt1_exc = exc_at.saturating_sub(tc_len);

    if sub(st.nb_lost_cmpt, 1) == 0 {
        // first pitch cycle is low-pass filtered
        for _ in 0..tc_len {
            // *pt_exc++ = (0.18f * pt1_exc[-1] + 0.64f * pt1_exc[0] + 0.18f * pt1_exc[1])
            let mut l_tmp = l_mult(5898, exc[pt1_exc.saturating_sub(1)]);
            l_tmp = l_mac(l_tmp, 20972, exc[pt1_exc]);
            exc[pt_exc] = mac_r(l_tmp, 5898, exc[pt1_exc + 1]);
            pt_exc += 1;
            pt1_exc += 1;
        }
    }

    // last pitch cycle of the previous frame is repeatedly copied up to an extra subframe
    let end = exc_at + (l_frame + L_SUBFR).max(0) as usize;
    while pt_exc < end {
        exc[pt_exc] = exc[pt1_exc];
        pt_exc += 1;
        pt1_exc += 1;
    }

    if new_pit > 0 {
        // calculate conditions for Pulse resynchronization to take place
        let (mut cond1, mut cond2, mut cond3) = (0i16, 0i16, 0i32);
        pulse_res_pre_calc(&mut cond1, &mut cond2, &mut cond3, new_pit, tc, l_frame);

        let len = (l_frame + L_SUBFR).max(0) as usize;
        // the rebuilt frame goes in the `l_frame + L_SUBFR` samples before `exc_at`, which every
        // caller's history holds (L_EXC_MEM_DEC = 480)
        if let (true, Some(src_at)) = (
            cond1 < 0 && new_pit > 0 && cond2 != 0 && cond3 > 0 && extrapolation_failed == 0,
            exc_at.checked_sub(len),
        ) {
            exc.copy_within(exc_at..exc_at + len, src_at);
            pulse_resynchronization(
                exc,
                src_at,
                exc_at,
                l_frame,
                nb_subfr,
                l_deposit_h(tc),      // Q0 -> 15Q16
                l_deposit_h(new_pit), // Q0 -> 15Q16
            );
        }
    }
    let gain: i16;
    let step: i16;
    if sub(st.last_good, UNVOICED_TRANSITION) == 0
        && (sub(st.last_coder_type, GENERIC) == 0 || sub(st.last_coder_type, TRANSITION) == 0)
    {
        // start of the frame gain
        gain = 0;
        // end of the frame gain
        st.lp_gainp = 0;
        step = 0;
    } else {
        // start of the frame gain
        gain = 16384;

        // end of the frame gain
        if !fec_exc_estim_voiced_continuation(st) {
            st.lp_gainp = shr(alpha, 1); // alpha in Q15
        } else {
            st.lp_gainp = alpha; // alpha in Q14
        }

        if sub(l_frame, L_FRAME) == 0 {
            step = shr(sub(gain, st.lp_gainp), 8);
        } else {
            // L_frame == L_FRAME16k: step = (1.0f/L_frame) * (gain - st_fx->lp_gainp);
            step = shr(mult_r(26214, sub(gain, st.lp_gainp)), 8); // Q14
        }
    }

    let mut gain = gain;
    for value in &mut exc[exc_at..exc_at + l_frame.max(0) as usize] {
        // exc[i] *= gain
        *value = round_word(l_shl(l_mult(*value, gain), 1)); // in Q_exc
                                                             // gain -= step
        gain = sub(gain, step);
    }
}

/// After a GSC frame with a pitch band: transform the harmonic excitation to the frequency
/// domain and keep only its band below the last pitch band (smoothed over 80 bins). Returns the
/// length of that band plus one (`Diff_len`).
fn fec_exc_estim_gsc_pitch_band(
    st: &DecoderState,
    exc: &[i16],
    exc_at: usize,
    exc_dct_in: &mut [i16],
) -> i16 {
    let band = (st.last_gsc_pit_band_idx.max(0) as usize).min(MFREQ_LOC_DIV_25.len() - 1);
    let diff_len = MFREQ_LOC_DIV_25[band];

    // Transform to frequency domain
    edct_16fx(&exc[exc_at..], exc_dct_in, st.l_frame, 5);

    // Reset unvaluable part of the adaptive (pitch) excitation contribution
    let max_len = sub(st.l_frame, diff_len);
    let len = max_len.min(80);

    let from = diff_len.max(0) as usize;
    let mut i = 0i16;
    while i < len {
        let at = from + i as usize;
        exc_dct_in[at] = mult_r(exc_dct_in[at], SM_TABLE_FX[i as usize]);
        i += 1;
    }
    while i < max_len {
        exc_dct_in[from + i as usize] = 0;
        i += 1;
    }
    add(diff_len, 1)
}

/// The random excitation `exc2_buf` (with the FIR ringing on both sides): noise scaled to unit
/// energy and faded from `lp_gainc` towards the comfort-noise gain `gain_cng`, the new
/// `lp_gainc` being the end gain.
fn fec_exc_estim_random(
    st: &mut DecoderState,
    l_frame: i16,
    alpha: i16,
    gain_cng: i16,
    q_exc: i16,
    exc2_buf: &mut [i16; EXC2_BUF],
) {
    let fir = MODE1_L_FIR_FER as usize;
    let frame = l_frame.clamp(0, L_FRAME16K) as usize;

    // generate the random part of the excitation
    for value in &mut exc2_buf[..frame + fir - 1] {
        *value = shr(random(&mut st.seed), 3); // Q-3
    }

    // start of the frame gain
    let gain = st.lp_gainc;

    if !fec_exc_estim_voiced_continuation(st) {
        // Here alpha is in Q15 and lp_gainc_fx in Q3:
        // st_fx->lp_gainc = alpha * st_fx->lp_gainc + (1.0f - alpha) * gainCNG;
        let l_tmp = l_mult(alpha, st.lp_gainc);
        st.lp_gainc = msu_r(l_tmp, add(alpha, -32768), gain_cng);
    } else {
        // Here alpha is in Q14, but lp_gainc still in Q3
        let l_tmp = l_mult(alpha, st.lp_gainc); // Q14*Q3->Q18
                                                // (Q14*Q3<<1)>>16 ->Q3
        st.lp_gainc = round_word(l_shl(l_msu(l_tmp, add(alpha, -16384), gain_cng), 1));
    }

    if sub(st.last_good, UNVOICED_TRANSITION) == 0
        && (sub(st.last_coder_type, GENERIC) == 0 || sub(st.last_coder_type, TRANSITION) == 0)
        && gain_cng > 0
    {
        st.lp_gainc = gain_cng;
    }

    // linearly attenuate the gain throughout the frame: step = (1.0f/L_FRAME) * (gain -
    // *lp_gainc); divide by L_FRAME done later
    let mut step = sub(gain, st.lp_gainc);
    if sub(l_frame, L_FRAME16K) == 0 {
        step = mult_r(step, 26214); // L_frame16k-> L_frame and division by L_frame done later
    }

    // calculate gain to normalize energy: to avoid saturation split the L_frame dot product into
    // (L_frame/L_SUBFR) dot products and scale down before adding
    // gain_inov = 1.0f / (float)sqrt( dotp( pt_exc, pt_exc, L_frame ) / L_frame + 0.01f );
    let mut pt_exc = fir / 2;
    let mut l_tmp = l_deposit_l(0);
    for _ in 0..2 {
        let mut l_tmp2 = l_mult0(exc2_buf[pt_exc], exc2_buf[pt_exc]);
        pt_exc += 1;
        for _ in 1..shr(l_frame, 1).max(1) {
            l_tmp2 = l_mac0(l_tmp2, exc2_buf[pt_exc], exc2_buf[pt_exc]); // Q-5
            pt_exc += 1;
        }
        l_tmp = l_add(l_tmp, l_shr(l_tmp2, 1)); // Q-7
    }
    if sub(l_frame, L_FRAME16K) == 0 {
        l_tmp = mult_32_16(l_tmp, 26214); // x0.8 to normalize to 256 samples
    }
    let mut exp = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, exp); // Normalize
    exp = add(exp, 8 - 7); // Q0, 8 ->divide by 256
    exp = sub(31, exp); // For Denormalization in Q31
    l_tmp = isqrt_lc(l_tmp, &mut exp); // in Q(31-exp)
    let mut gain_inov = round_word(l_tmp);

    // attenuate somewhat on unstable unvoiced
    if (sub(st.last_good, UNVOICED_CLAS) == 0 || sub(st.last_good, INACTIVE_CLAS) == 0)
        && sub(st.last_coder_type, UNVOICED) != 0
    {
        gain_inov = mult_r(gain_inov, 26214);
    }

    // scaling of the random part of excitation
    let l_step = l_shr(l_mult(gain_inov, step), 8); // here is the divide by L_FRAME
    let mut l_tmp2 = l_mult(gain_inov, gain); // Q15 * Q3 -> Q3
    let mut tmp = round_word(l_tmp2);
    exp = add(add(exp, q_exc), 15); // 3+Q_exc+15 -> Q_exc+18

    let mut pt_exc = 0usize;
    for _ in 0..fir / 2 {
        // non-causal ringing of the FIR filter: *pt_exc++ *= (gain_inov * gain);
        let l_tmp = l_mult(tmp, exc2_buf[pt_exc]); // Q_exc+18 * Q-3 -> Q_exc+16
        exc2_buf[pt_exc] = round_word(l_shl(l_tmp, exp));
        pt_exc += 1;
    }

    for _ in 0..frame {
        // the inner part of the FIR filter: *pt_exc++ *= (gain_inov * gain);
        let l_tmp = l_mult(tmp, exc2_buf[pt_exc]);
        exc2_buf[pt_exc] = round_word(l_shl(l_tmp, exp));
        pt_exc += 1;
        // gain -= step;
        l_tmp2 = l_sub(l_tmp2, l_step);
        tmp = round_word(l_tmp2);
    }

    for _ in 0..fir / 2 {
        // causal ringing of the FIR filter: *pt_exc++ *= (gain_inov * gain)
        let l_tmp = l_mult(tmp, exc2_buf[pt_exc]);
        exc2_buf[pt_exc] = round_word(l_shl(l_tmp, exp));
        pt_exc += 1;
    }
}

/// The total excitation `exc2`: the GSC excitation as is, the harmonic part plus the high-passed
/// random part for voiced and generic signals, or the unfiltered random part (also into `exc`)
/// for purely unvoiced ones.
fn fec_exc_estim_total(
    st: &DecoderState,
    l_frame: i16,
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    exc2_buf: &[i16; EXC2_BUF],
) {
    let fir = MODE1_L_FIR_FER as usize;
    let frame = l_frame.clamp(0, L_FRAME16K) as usize;
    if (sub(st.last_coder_type, AUDIO) == 0 || sub(st.last_good, INACTIVE_CLAS) == 0)
        && l_sub(st.total_brate, i32::from(ACELP_24K40)) <= 0
        && st.opt_amr_wb == 0
    {
        // For GSC - the excitation is already computed
        copy(&exc[exc_at..], exc2, st.l_frame);
    } else if sub(st.last_good, UNVOICED_TRANSITION) >= 0 && sub(st.last_good, INACTIVE_CLAS) < 0 {
        // For voiced and generic signals - prepare a HP filter for the random part of excitation
        // tmp = -(1-tilt_code) to correctly represent 1.0000
        let tmp = add(st.tilt_code, -32768);
        let mut hp_filt = [0i16; MODE1_L_FIR_FER as usize];
        for (filt, &h) in hp_filt.iter_mut().zip(&H_HIGH_FX) {
            *filt = msu_r(0, tmp, h);
        }

        // HP filter the random part of the excitation and add the adaptive part
        for i in 0..frame {
            // exc2[i] = exc[i] + dotp( &exc2_buf[i], hp_filt, MODE1_L_FIR_FER );
            let mut l_tmp = l_mult(hp_filt[0], exc2_buf[i]);
            for j in 1..fir {
                l_tmp = l_mac(l_tmp, hp_filt[j], exc2_buf[i + j]);
            }
            exc2[i] = msu_r(l_tmp, -32768, exc[exc_at + i]);
        }
    } else {
        // For purely unvoiced signals - just copy the unfiltered random part of the excitation
        copy(&exc2_buf[fir / 2..], &mut exc[exc_at..], l_frame);
        copy(&exc2_buf[fir / 2..], exc2, l_frame);
    }
}

/// `pulseRes_preCalc`: the three conditions `FEC_exc_estim_fx` checks before resynchronising
/// the pulses of the concealed excitation from the pitch `tc` to the extrapolated `new_pit`
/// (both Q0) over a frame of `l_frame`: `cond1 < 0` when `new_pit / tc` exceeds
/// `1 - 1/(L_frame/L_SUBFR + 1)`, `cond2 != 0` when the pitch changes, and `cond3 > 0` when the
/// change is under 15 % of `tc`.
pub fn pulse_res_pre_calc(
    cond1: &mut i16,
    cond2: &mut i16,
    cond3: &mut i32,
    new_pit: i16,
    tc: i16,
    l_frame: i16,
) {
    let mut tmp_pit_e: i16 = 0;
    let mut tmp_pit = basop_util_divide1616_scale(new_pit, tc, &mut tmp_pit_e); // Q15
    let mut tmp_frame = add(extract_l(l_mult0(l_frame, 64)), 4096); // Q12, 1.f/L_SUBFR Q12
    let mut tmp_frame_e: i16 = 0;
    tmp_frame = basop_util_divide1616_scale(4096, tmp_frame, &mut tmp_frame_e); // Q15
    tmp_frame = shl(tmp_frame, add(tmp_frame_e, 1));
    tmp_frame = sub(32767, tmp_frame); // Q15
                                       // To calc Q15 threshold, overflow may happen - do negation and compare with negated value to
                                       // check also highest possible value
    tmp_pit = shl(negate(tmp_pit), tmp_pit_e);
    *cond1 = sub(tmp_pit, negate(tmp_frame));

    *cond2 = sub(tc, new_pit);

    tmp_pit_e = basop_util_add_mant_exp(new_pit, 15, negate(tc), 15, &mut tmp_pit); // Q15
    tmp_pit = abs_s(tmp_pit);
    let mut tmp_pit2 = l_mult(tc, 4915); // Q16, 0.15f Q15
                                         // To calc Q15 threshold, overflow may happen - do negation and compare with negated value to
                                         // check also highest possible value
    tmp_pit2 = l_shl(l_negate(tmp_pit2), sub(15 - 16, tmp_pit_e));
    *cond3 = l_sub(l_mult0(-1, tmp_pit), tmp_pit2);
}

/// `gain_dec_bfi_fx`: shift the gain quantiser's prediction memory `past_qua_en` (Q10, 4 words)
/// for a lost frame, entering the average of the past ones lowered by 3 dB (floored at -14).
pub fn gain_dec_bfi(past_qua_en: &mut [i16]) {
    let order = GAIN_PRED_ORDER as usize;
    let mut lav_pred_en = l_mult(past_qua_en[0], 8192);
    for &value in &past_qua_en[1..order] {
        lav_pred_en = l_mac(lav_pred_en, value, 8192);
    }

    // av_pred_en = (float)(av_pred_en*(1.0f/(float)GAIN_PRED_ORDER)-3.0f);
    let mut av_pred_en = sub(round_word(lav_pred_en), 3 << 10);

    // if (av_pred_en < -14.0f)av_pred_en = -14.0f;
    av_pred_en = av_pred_en.max(-14 * (1 << 10));

    for i in (1..order).rev() {
        past_qua_en[i] = past_qua_en[i - 1];
    }

    past_qua_en[0] = av_pred_en;
}
