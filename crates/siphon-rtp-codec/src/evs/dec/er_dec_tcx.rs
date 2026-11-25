//! The time-domain TCX concealment of the MODE2 core (TS 26.442 `lib_dec/er_dec_tcx.c`;
//! TS 26.447 §5.4.3): the last pitch cycle of the pre-emphasised past synthesis repeated at the
//! extrapolated pitch as the harmonic excitation, a high-passed noise excitation faded to the
//! background level, the synthesis through an LPC filter re-estimated from the past output, and
//! the update of the overlap, TDAC and 16 kHz memories the next frame (TCX or ACELP) starts from.
//!
//! The reference keeps the excitation, the noise and the synthesis in one stack buffer (`buf`)
//! whose regions overlap deliberately, and works on `synth` with negative indices into the past
//! output (`synth[-L_frame - 1]`); the port keeps that one buffer, and takes `synth` as the whole
//! buffer plus the index `synth_at` where the reference's pointer points.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    FULL_OVERLAP, GENERIC, L_EXC_MEM, L_EXC_MEM_DEC, L_FIR_FER2, L_FRAME16K, L_FRAME_MAX, L_SUBFR,
    L_SYN_MEM, M, NB_SUBFR16K, OLD_EXC_SIZE_DEC, ONSET, RF_TCXFD, RF_TCXTD1, RF_TCXTD2, UNVOICED,
    UNVOICED_CLAS, UNVOICED_TRANSITION, VOICED_CLAS,
};
use crate::evs::com::basop_util::{
    basop_util_add_mant32_exp, basop_util_divide1616_scale, basop_util_divide3216_scale,
    basop_util_divide_mant_exp, buffer_copy_fx, dot_product_sq16_hq, imult1616, isqrt32,
    norm_ll_q31, sqrt16,
};
use crate::evs::com::deemph::deemph;
use crate::evs::com::enr_1_az::enr_1_az;
use crate::evs::com::get_gain::get_gain2;
use crate::evs::com::lag_wind::{lag_wind, LAGW_STRONG};
use crate::evs::com::lerp::{lerp, lerp_within};
use crate::evs::com::lpc_tools::{autocorr, e_lpc_lev_dur};
use crate::evs::com::preemph::{e_util_f_preemph3, preemph_copy_in_place};
use crate::evs::com::residu::residu3;
use crate::evs::com::syn_filt::e_util_synthesis;
use crate::evs::com::tcx_utils::get_inv_frame_len;
use crate::evs::com::tools::{copy, copy_scale_sig, own_random2, scale_sig, set16, set32};
use crate::evs::com::window::ham_cos_window;
use crate::evs::dec::er_scale_syn::damping_fact;
use crate::evs::dec::er_sync_exc::pulse_resynchronization;
use crate::evs::dec::er_util::{get_level_syn_deemph, high_pass_filtering};
use crate::evs::dec::pitch_extr::{get_subframe_pitch, pitch_pred_linear_fit};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{H_HIGH3_16, H_HIGH3_32};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl,
    l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac_ns, mac_r, StlFlags};

/// `OLD_EXC_SIZE_DEC + L_FRAME_MAX + L_FRAME_MAX/NB_SUBFR + 1 + L_FRAME_MAX/2`: the reference's
/// `buf`.
const BUF_LEN: usize =
    (OLD_EXC_SIZE_DEC + L_FRAME_MAX + L_FRAME_MAX / 4 + 1 + L_FRAME_MAX / 2) as usize;
/// `exc = buf + OLD_EXC_SIZE_DEC`.
const EXC_AT: usize = OLD_EXC_SIZE_DEC as usize;
/// `L_FIR_FER2` as an index.
const FIR: usize = L_FIR_FER2 as usize;

/// `calcGainc`/`calcGainc2` tail: the RMS gain (15Q16) of `2·L_subfr` samples whose energy was
/// accumulated in 64 bits into `(l_c, l_acc)`.
fn gainc_from_energy(l_c: i32, l_acc: i32, q_exc: i16, l_subfr: i16, flags: &mut StlFlags) -> i32 {
    let mut tmp_e: i16 = 0;
    let l_tmp = norm_ll_q31(l_c, l_acc, &mut tmp_e, flags); // Q3,norm,tmp_e
    tmp_e = add(tmp_e, 31 - add(shl(q_exc, 1), 1)); // L_tmp is Q31, now
    let mut tmp2_e: i16 = 0;
    let mut tmp16 = basop_util_divide3216_scale(l_tmp, shl(l_subfr, 1), &mut tmp2_e); // Q15
    tmp_e = sub(add(tmp2_e, tmp_e), 15);

    if tmp16 != 0 {
        tmp16 = sqrt16(tmp16, &mut tmp_e); // Q15,norm,tmp_e
    }
    l_shl(l_deposit_l(tmp16), add(tmp_e, 1)) // 15Q16
}

/// `calcGainc`: the gain (15Q16) of the residual of the last two subframes of the excitation
/// `buf[exc_at - 2·L_subfr..]` after removing the pitch contribution `lp_gainp` (2Q29) at the
/// lag `old_fpitch`.
fn calc_gainc(
    buf: &[i16],
    exc_at: usize,
    q_exc: i16,
    old_fpitch: i32,
    l_subfr: i16,
    lp_gainp: i32,
    flags: &mut StlFlags,
) -> i32 {
    let mut l_acc = l_deposit_l(0);
    let mut l_c = l_deposit_l(0);
    flags.overflow = false;
    flags.carry = false;

    let tmp16 = round_word(old_fpitch); // Q0
    let tmp_loop = shl(l_subfr, 1);
    // Q31->Q15, no severe saturation, because lp_gainp here is [0,1]
    let tmp16_2 = round_word(l_shl(lp_gainp, 2));

    for i in 0..tmp_loop as usize {
        let at = exc_at + i - 2 * l_subfr as usize;
        let tmp16_3 = sub(buf[at], mult_r(tmp16_2, buf[at - tmp16 as usize]));
        l_acc = l_mac_ns(l_acc, tmp16_3, tmp16_3, flags); // Q3
        flags.overflow = false;
        l_c = l_mac_ns(l_c, 0, 0, flags); // accumulate carrys
        flags.carry = false;
    }
    gainc_from_energy(l_c, l_acc, q_exc, l_subfr, flags)
}

/// `calcGainc2`: the gain (15Q16) of the last two subframes of the excitation
/// `buf[exc_at - 2·L_subfr..]`.
fn calc_gainc2(buf: &[i16], exc_at: usize, q_exc: i16, l_subfr: i16, flags: &mut StlFlags) -> i32 {
    flags.carry = false;
    flags.overflow = false;

    let mut l_c = l_deposit_l(0);
    let mut l_acc = l_deposit_l(0);

    for i in 0..shl(l_subfr, 1) as usize {
        let value = buf[exc_at + i - 2 * l_subfr as usize];
        l_acc = l_mac_ns(l_acc, value, value, flags); // Q3
        flags.overflow = false;
        l_c = l_mac_ns(l_c, 0, 0, flags); // accumulate carrys
        flags.carry = false;
    }
    gainc_from_energy(l_c, l_acc, q_exc, l_subfr, flags)
}

/// The window of the TDAC aliasing of `con_tcx`: `w[i].v.re` for the rising half and
/// `w[W12 - 1 - (i - W12)].v.im` for the falling one.
fn window_value(window: &[crate::evs::rom::types::PWord16], w12: i16, i: i16) -> i16 {
    if i < w12 {
        window[i as usize].v.re
    } else {
        window[(w12 - 1 - (i - w12)) as usize].v.im
    }
}

/// What the excitation construction hands on to the rest of `con_tcx`.
struct Excitation {
    /// The pre-emphasis scaling of the excitation (`Q_exc`).
    q_exc: i16,
    /// The damping factor (Q14).
    alpha: i16,
    /// The LPC filter of the concealed frame (Q12).
    a_local: [i16; (M + 1) as usize],
    /// The pitch of every subframe (15Q16).
    pitch_buf: [i32; NB_SUBFR16K as usize],
}

/// `con_tcx`: conceal a lost TCX frame in the time domain. `synth[synth_at..]` receives the
/// `L_frameTCX` samples of the frame, and `synth[..synth_at]` is the past output (at least
/// `2·L_frameTCX` samples), of which the pre-emphasised tail is modified as the reference does.
pub fn con_tcx(st: &mut DecoderState, synth: &mut [i16], synth_at: usize) {
    let l_frame = st.l_frame_tcx;
    let l_subfr = mult_r(st.l_frame_tcx, div_s(1, st.nb_subfr));
    let mut buf = [0i16; BUF_LEN];

    // take the previous frame last pitch
    let tc = round_word(st.old_fpitch_fb);

    // the pitch memory at the rate of this frame
    let mut s: i16 = 0;
    let c = basop_util_divide1616_scale(l_frame, st.l_frame, &mut s);
    let mut old_pitch_buf = [0i32; 2 * NB_SUBFR16K as usize + 2];
    for (slot, &value) in old_pitch_buf.iter_mut().zip(st.old_pitch_buf.iter()) {
        *slot = l_shl(mpy_32_16_1(value, c), s);
    }

    // set excitation memory
    let mut tmp_deemph = synth[synth_at - 1];
    let pre_emph_buf = synth[synth_at - 1];

    let Excitation {
        q_exc,
        alpha,
        a_local,
        pitch_buf,
    } = con_tcx_harmonic(st, synth, synth_at, &mut buf, &old_pitch_buf, l_subfr, tc);

    let noise_e = con_tcx_noise(st, &mut buf, &a_local, l_subfr, q_exc, alpha);

    // Construct the total excitation
    let half = shr(l_frame, 1);
    let frame_and_half = add(l_frame, half);
    if sub(st.last_good, UNVOICED_TRANSITION) >= 0 {
        for i in 0..frame_and_half as usize {
            buf[EXC_AT + i] = add(
                buf[EXC_AT + i],
                shl(buf[i + FIR / 2], add(q_exc, noise_e)), // Q1
            );
        }
    } else {
        let (noise_region, exc_region) = buf.split_at_mut(EXC_AT);
        buffer_copy_fx(
            &noise_region[FIR / 2..],
            exc_region,
            frame_and_half,
            0, // Q_noise
            noise_e,
            q_exc,
            0, // exc_e
        );
        copy(
            &buf[EXC_AT + l_frame as usize - 2 * l_subfr as usize..],
            &mut st.old_exc_fb,
            add(shl(l_subfr, 1), half),
        );
        con_tcx_old_exc_16k(st, &buf, EXC_AT, frame_and_half, l_frame);
        st.q_exc = q_exc;
    }

    // Update Pitch Lag memory
    let nb_subfr = st.nb_subfr as usize;
    st.old_pitch_buf.copy_within(nb_subfr..2 * nb_subfr, 0);
    st.old_pitch_buf[nb_subfr..2 * nb_subfr].copy_from_slice(&pitch_buf[..nb_subfr]);

    con_tcx_synthesis(
        st,
        synth,
        synth_at,
        &mut buf,
        &a_local,
        &pitch_buf,
        q_exc,
        &mut tmp_deemph,
    );

    synth[synth_at - 1] = pre_emph_buf;
}

/// Copy the total excitation as 16 kHz for the ACELP decoder: all of it after the first lost
/// frame (`frame_and_half` samples at `exc_at`), or the 480-sample memory shifted down and the
/// new frame appended.
fn con_tcx_old_exc_16k(
    st: &mut DecoderState,
    buf: &[i16],
    first_at: usize,
    frame_and_half: i16,
    l_frame: i16,
) {
    if sub(st.nb_lost_cmpt, 1) == 0 {
        lerp(
            &buf[first_at..],
            &mut st.old_exc,
            L_EXC_MEM_DEC,
            frame_and_half,
        );
    } else {
        st.old_exc.copy_within(
            L_FRAME16K as usize..(L_FRAME16K + L_FRAME16K / 2) as usize,
            0,
        );
        lerp(
            &buf[EXC_AT..],
            &mut st.old_exc[(L_FRAME16K / 2) as usize..],
            L_FRAME16K,
            l_frame,
        );
    }
}

/// The harmonic part of `con_tcx`: the pre-emphasis of the past output, the LPC filter and
/// gain estimated from it after the first lost frame, the last pitch cycle repeated (low-pass
/// filtered after the first loss) and resynchronised, the damping factor and the fade-out; or
/// silence for a last good frame below `UNVOICED_TRANSITION`.
fn con_tcx_harmonic(
    st: &mut DecoderState,
    synth: &mut [i16],
    synth_at: usize,
    buf: &mut [i16; BUF_LEN],
    old_pitch_buf: &[i32; 2 * NB_SUBFR16K as usize + 2],
    l_subfr: i16,
    tc: i16,
) -> Excitation {
    let l_frame = st.l_frame_tcx;
    let half = shr(l_frame, 1);
    let mut a_local = [0i16; (M + 1) as usize];
    let mut pitch_buf = [0i32; NB_SUBFR16K as usize];
    let mut pred_pitch_lag: i32 = 0;
    let mut extrapolation_failed: i16 = 1;
    let mut f_use_extrapolated_pitch = false;
    let mut offset: i16 = 0;
    let q_exc: i16;
    if sub(st.nb_lost_cmpt, 1) == 0 || st.tcx_conceal_recalc_exc != 0 {
        // apply pre-emphasis to the signal
        let len = add(add(half, st.pit_max_tcx), shl(M, 1));
        let start = synth_at - len as usize;
        let mut mem = synth[start - 1];
        q_exc = e_util_f_preemph3(&mut synth[start..], st.preemph_fac, len, &mut mem, 1);
        st.mode2_lp_gainc = l_deposit_l(0);

        let gain_x = synth_at - 2 * l_subfr as usize;
        let mut gainp = {
            let (x, y) = (&synth[gain_x..], &synth[gain_x - tc as usize..]);
            get_gain2(x, y, shl(l_subfr, 1), &mut st.stl)
        };
        gainp = gainp.max(0);
        gainp = gainp.min(65536); // 1.0f Q16
        st.mode2_lp_gainp = l_shl(gainp, 13);

        // the analysis window lives in the start of buf, as in the reference
        ham_cos_window(&mut buf[..], mult(l_frame, 24576), shr(l_frame, 2));

        // Autocorrelation
        let mut r_h = [0i16; (M + 1) as usize];
        let mut r_l = [0i16; (M + 1) as usize];
        let mut q_r: i16 = 0;
        autocorr(
            &synth[synth_at - l_frame as usize - 1..],
            M,
            &mut r_h,
            &mut r_l,
            &mut q_r,
            l_frame,
            &buf[..],
            0,
            0,
        );

        // Lag windowing
        lag_wind(&mut r_h, &mut r_l, M, st.output_fs, LAGW_STRONG);

        // Levinson Durbin
        e_lpc_lev_dur(&r_h, &r_l, &mut a_local, None, M, None);

        // copy for multiple frame loss
        st.old_aq_12_8.copy_from_slice(&a_local);

        // Residu: saturation possible in case of spiky synthesis
        let lg = add(add(add(shl(l_subfr, 1), tc), 1), M);
        residu3(
            &a_local,
            synth,
            synth_at - lg as usize,
            &mut buf[EXC_AT - lg as usize..],
            lg,
            1,
        );
    } else {
        // apply pre-emphasis to the signal
        let start = synth_at - l_frame as usize;
        let mut mem = synth[start - 1];
        q_exc = e_util_f_preemph3(&mut synth[start..], st.preemph_fac, l_frame, &mut mem, 1);
        a_local.copy_from_slice(&st.old_aq_12_8);

        offset = half;
        if sub(st.last_good, UNVOICED_TRANSITION) >= 0 {
            let tmp16 = (tc - half).max(0);
            copy_scale_sig(
                &st.old_exc_fb,
                &mut buf[EXC_AT - tmp16 as usize..],
                offset + tmp16,
                q_exc - st.q_exc,
            );
        } else {
            copy_scale_sig(
                &st.old_exc_fb,
                &mut buf[EXC_AT - 2 * l_subfr as usize..],
                2 * l_subfr + offset,
                q_exc - st.q_exc,
            );
        }
    }

    // PLC: Construct the harmonic part of excitation
    if sub(st.last_good, UNVOICED_CLAS) > 0
        && !(sub(st.last_good, UNVOICED_TRANSITION) == 0 && sub(st.core_ext_mode, GENERIC) == 0)
    {
        if sub(st.nb_lost_cmpt, 1) == 0 || st.tcx_conceal_recalc_exc != 0 {
            st.mode2_lp_gainc = calc_gainc(
                buf,
                EXC_AT,
                q_exc,
                st.old_fpitch_fb,
                l_subfr,
                st.mode2_lp_gainp,
                &mut st.stl,
            );
        }

        let tmp16: i16 = i16::from(l_sub(st.output_fs, 25600) > 0);

        if (sub(st.nb_lost_cmpt, 1) == 0 || st.tcx_conceal_recalc_exc != 0)
            && sub(st.rf_frame_type, RF_TCXFD) >= 0
            && sub(st.rf_frame_type, RF_TCXTD2) <= 0
            && st.use_partial_copy != 0
        {
            let tcxltp_pitch_tmp = l_add(
                l_deposit_h(st.tcxltp_pitch_int),
                l_shl(l_deposit_l(div_s(st.tcxltp_pitch_fr, st.pit_res_max)), 1),
            ); // 15Q16
            let scale_tmp = mult_r(st.l_frame_tcx, get_inv_frame_len(st.l_frame)); // 9Q6
            let tmp_shift = norm_s(scale_tmp);
            pred_pitch_lag = l_shl(
                mpy_32_16_1(tcxltp_pitch_tmp, shl(scale_tmp, tmp_shift)),
                sub(9, tmp_shift),
            );

            let t0 = round_word(pred_pitch_lag);

            if t0 > 0
                && sub(t0, tc) != 0
                && l_sub(l_deposit_h(abs_s(sub(t0, tc))), l_mult(4915, tc)) < 0
            {
                f_use_extrapolated_pitch = true;
            }
        } else {
            pitch_pred_linear_fit(
                st.nb_lost_cmpt,
                st.last_good,
                old_pitch_buf,
                st.old_fpitch_fb,
                &mut pred_pitch_lag,
                st.pit_min_tcx,
                st.pit_max_tcx,
                &st.mem_pitch_gain,
                tmp16,
                st.plc_use_future_lag,
                &mut extrapolation_failed,
                st.nb_subfr,
            );

            let t0 = round_word(pred_pitch_lag);
            if t0 > 0
                && sub(t0, tc) != 0
                && l_sub(l_deposit_h(abs_s(sub(t0, tc))), l_mult(4915, tc)) < 0
                && extrapolation_failed == 0
            {
                f_use_extrapolated_pitch = true;
            }
        }

        con_tcx_pitch_cycle(st, buf, offset, tc, l_subfr, f_use_extrapolated_pitch);

        if f_use_extrapolated_pitch {
            get_subframe_pitch(
                st.nb_subfr,
                st.old_fpitch,
                // predPitchLag * L_frame/st->L_frame
                l_shr(
                    mpy_32_16_1(
                        pred_pitch_lag,                                 // Q16
                        mult_r(st.l_frame, get_inv_frame_len(l_frame)), // Q6
                    ), // Q7
                    7 - 16,
                ), // Q16
                &mut pitch_buf,
            );

            pulse_resynchronization(
                buf,
                0,
                EXC_AT,
                l_frame,
                st.nb_subfr,
                st.old_fpitch_fb,
                pred_pitch_lag,
            );
        } else {
            set32(&mut pitch_buf, st.old_fpitch, st.nb_subfr);
        }

        if sub(st.nb_lost_cmpt, 1) == 0 {
            let t0 = round_word(pred_pitch_lag);
            let pt_exc = EXC_AT + l_frame as usize;
            let pt1_exc = if t0 == 0 {
                pt_exc - tc as usize
            } else {
                pt_exc - t0 as usize
            };
            for offset in 0..half as usize {
                buf[pt_exc + offset] = buf[pt1_exc + offset];
            }
        }

        if f_use_extrapolated_pitch {
            st.old_fpitch_fb = pred_pitch_lag;
        }
        st.bpf_gain_param = 0;

        // PLC: calculate damping factor
        let alpha = damping_fact(
            st.core_ext_mode,
            st.nb_lost_cmpt,
            st.last_good,
            st.stab_fac,
            &mut st.mode2_lp_gainp,
            0,
        ); // Q14

        if sub(st.nb_lost_cmpt, 1) == 0 {
            st.cummulative_damping = 32767; // 1.f Q15
        } else {
            st.cummulative_damping = shl(mult_r(st.cummulative_damping, alpha), 1);
            // Q15
        }

        let mut gain32: i32 = 2_147_483_647; // 1.f Q31
        let mut gain: i16 = 32767; // 1.f Q15
        if sub(st.rf_frame_type, RF_TCXTD1) == 0 && sub(st.use_partial_copy, 1) == 0 {
            gain32 = 1_073_741_824; // 0.5f Q31
            gain = 16384; // 0.5f Q15
        }

        // step = (1.0f/(L_frame+(L_frame/2))) * (gain - alpha);
        let mut tmp16 = shr(imult1616(3, l_frame), 1);
        let tmp_e = norm_s(tmp16);
        tmp16 = shl(tmp16, tmp_e);
        tmp16 = div_s(16384, tmp16); // Q15, 1+tmp_e-15
        let tmp16_2 = sub(shr(gain, 1), alpha); // Q14
        let step32 = l_shl(l_mult(tmp16, tmp16_2), add(1 - 14, tmp_e)); // Q31

        // PLC: Apply fade out
        let tmp_loop = shr(imult1616(l_frame, 3), 1);
        for i in offset..tmp_loop {
            buf[EXC_AT + i as usize] = mult_r(buf[EXC_AT + i as usize], round_word(gain32)); // Q1
            gain32 = l_sub(gain32, step32);
        }

        // update old exc without random part
        offset = (round_word(st.old_fpitch_fb) - half).max(0);
        copy(
            &buf[EXC_AT + l_frame as usize - offset as usize..],
            &mut st.old_exc_fb,
            half + offset,
        );
        // copy old_exc as 16kHz for acelp decoding
        con_tcx_old_exc_16k(st, buf, EXC_AT - half as usize, add(l_frame, half), l_frame);
        st.q_exc = q_exc;

        Excitation {
            q_exc,
            alpha,
            a_local,
            pitch_buf,
        }
    } else {
        // No harmonic part
        set16(&mut buf[EXC_AT..], 0, add(l_frame, half));
        if sub(st.nb_lost_cmpt, 1) == 0 {
            st.mode2_lp_gainc = calc_gainc2(buf, EXC_AT, q_exc, l_subfr, &mut st.stl);
        }
        set32(&mut pitch_buf, l_deposit_h(L_SUBFR), st.nb_subfr);
        // PLC: calculate damping factor
        let alpha = damping_fact(
            st.core_ext_mode,
            st.nb_lost_cmpt,
            st.last_good,
            st.stab_fac,
            &mut st.mode2_lp_gainp,
            0,
        ); // Q14
        Excitation {
            q_exc,
            alpha,
            a_local,
            pitch_buf,
        }
    }
}

/// The low-pass filter (11 taps, Q15) the first pitch cycle goes through after the first lost
/// frame, up to 16 kHz.
const PITCH_CYCLE_FILTER_16K: [i16; 11] = [174, 0, -1442, 0, 8641, 18022, 8641, 0, -1442, 0, 174];
/// The same above 16 kHz (32 kHz output).
const PITCH_CYCLE_FILTER_32K: [i16; 11] = [
    -174, -121, -459, 590, 8743, 16355, 8743, 590, -459, -121, -174,
];

/// The first pitch cycle of the harmonic excitation (low-pass filtered after the first loss while
/// the ISF are stable) and its repetition over the frame. Without the extrapolated pitch the
/// cycle is written after the last good excitation at `EXC_AT + offset`; with it, to the start of
/// the buffer (resynchronised into the excitation afterwards).
fn con_tcx_pitch_cycle(
    st: &DecoderState,
    buf: &mut [i16; BUF_LEN],
    offset: i16,
    tc: i16,
    l_subfr: i16,
    f_use_extrapolated_pitch: bool,
) {
    let l_frame = st.l_frame_tcx;
    let mut pt_exc = EXC_AT + offset as usize;
    let mut pt1_exc = pt_exc - tc as usize;

    if f_use_extrapolated_pitch {
        pt_exc = 0;
    }
    if sub(st.stab_fac, 32767) < 0 && sub(st.nb_lost_cmpt, 1) == 0 {
        // pitch cycle is first low-pass filtered
        let taps = if l_sub(st.output_fs, 16000) <= 0 {
            &PITCH_CYCLE_FILTER_16K
        } else {
            &PITCH_CYCLE_FILTER_32K
        };
        for _ in 0..tc {
            let mut acc = l_mult(taps[0], buf[pt1_exc - 5]);
            for k in 1..10 {
                acc = l_mac(acc, taps[k], buf[pt1_exc + k - 5]);
            }
            buf[pt_exc] = mac_r(acc, taps[10], buf[pt1_exc + 5]);
            pt_exc += 1;
            pt1_exc += 1;
        }
    } else {
        // copy the first pitch cycle without low-pass filtering
        for _ in 0..tc {
            buf[pt_exc] = buf[pt1_exc];
            pt_exc += 1;
            pt1_exc += 1;
        }
    }
    let f_low_pass_filter: i16 = 1;

    if f_use_extrapolated_pitch {
        pt1_exc = 0;
    }
    let tmp16 = add(sub(l_frame, imult1616(f_low_pass_filter, tc)), l_subfr);
    for _ in 0..tmp16.max(0) {
        buf[pt_exc] = buf[pt1_exc];
        pt_exc += 1;
        pt1_exc += 1;
    }
}

/// The random part of `con_tcx`: the noise (written from the start of `buf`), pre-emphasised for
/// a voiced last good frame, high-pass filtered, scaled to the background level (the gain fading
/// across the frame) and its energy normalised. Updates `Mode2_lp_gainc` and `Mode2_lp_gainp`.
/// Returns the exponent of the noise (`noise_e`).
fn con_tcx_noise(
    st: &mut DecoderState,
    buf: &mut [i16; BUF_LEN],
    a_local: &[i16; (M + 1) as usize],
    l_subfr: i16,
    q_exc: i16,
    alpha: i16,
) -> i16 {
    let _ = (l_subfr, q_exc);
    let l_frame = st.l_frame_tcx;
    let half = shr(l_frame, 1);
    let mut noise_e: i16 = 1; // exponent of noise

    // Construct the random part of excitation
    let mut tmp_seed = st.seed_acelp;
    let first = add(l_frame, L_FIR_FER2 - 1) as usize;
    for slot in &mut buf[..first] {
        tmp_seed = own_random2(tmp_seed);
        *slot = shr(tmp_seed, noise_e);
    }
    st.seed_acelp = tmp_seed;

    let total = add(add(l_frame, half), shl(L_FIR_FER2, 1)) as usize;
    for slot in &mut buf[first..total] {
        tmp_seed = own_random2(tmp_seed);
        *slot = shr(tmp_seed, noise_e);
    }
    if sub(st.last_good, VOICED_CLAS) == 0 || sub(st.last_good, ONSET) == 0 {
        let mut tmp16: i16 = 19661; // 0.6f Q15
        if l_sub(st.output_fs, 16000) <= 0 {
            tmp16 = 6554; // 0.2f Q15
        }

        let mut mem = buf[0];
        preemph_copy_in_place(
            &mut buf[1..],
            tmp16,
            (l_frame + l_frame / 2) + L_FIR_FER2,
            &mut mem,
        );
    }
    // high rate filter tuning
    let hp_filt: [i16; FIR] = if l_sub(st.output_fs, 16000) <= 0 {
        H_HIGH3_16
    } else {
        H_HIGH3_32
    };
    if sub(st.nb_lost_cmpt, 1) == 0 {
        high_pass_filtering(
            st.last_good,
            add(add(l_frame, half), L_FIR_FER2),
            buf,
            &hp_filt,
            L_FIR_FER2,
        );
    } else if sub(st.last_good, UNVOICED_TRANSITION) > 0 {
        let tmp_loop = add(add(l_frame, half), L_FIR_FER2);
        let gain_tmp = negate(add(-32768, st.cummulative_damping)); // Q15
        for i in 0..tmp_loop as usize {
            // noise[i] = (1-st->cummulative_damping)*noise[i]
            //          + st->cummulative_damping*dot_product(&noise[i], hp_filt, L_FIR_FER2);
            let mut l_tmp2 = 0;
            for (k, &tap) in hp_filt.iter().enumerate() {
                l_tmp2 = l_mac(l_tmp2, buf[i + k], tap);
            }

            l_tmp2 = mpy_32_16_1(l_tmp2, st.cummulative_damping); // Q0, noise_e
            buf[i] = mac_r(l_tmp2, gain_tmp, buf[i]); // Q15, noise_e
        }
    }

    // PLC: [TCX: Fade-out] retrieve background level
    let mut tmp16: i16 = 32767;
    let mut gain_synth_deemph_e: i16 = 0;
    let gain_synth_deemph = get_level_syn_deemph(
        core::slice::from_mut(&mut tmp16),
        a_local,
        M,
        shr(l_frame, 2),
        st.preemph_fac,
        1,
        &mut gain_synth_deemph_e,
    );
    let mut gain_cng: i16 = 0;
    let mut gain_cng_e: i16 = 0;
    if st.tcxonly != 0 {
        // gainCNG = st->conCngLevelBackgroundTrace/gainSynthDeemph;
        basop_util_divide_mant_exp(
            st.con_cng_level_background_trace,
            st.con_cng_level_background_trace_e,
            gain_synth_deemph,
            gain_synth_deemph_e,
            &mut gain_cng,
            &mut gain_cng_e,
        );
    } else {
        // gainCNG = st->cngTDLevel/gainSynthDeemph;
        basop_util_divide_mant_exp(
            st.cng_td_level,
            st.cng_td_level_e,
            gain_synth_deemph,
            gain_synth_deemph_e,
            &mut gain_cng,
            &mut gain_cng_e,
        );
    }

    let mut gain32 = l_add(st.mode2_lp_gainc, 0); // start-of-the-frame gain, Q16
    if sub(st.rf_frame_type, RF_TCXTD1) == 0 && sub(st.use_partial_copy, 1) == 0 {
        gain32 = mpy_32_16_1(gain32, 22938); // 0.7f Q15
    }
    let mut l_tmp = l_shl(gain32, 1);

    if l_sub(
        l_shl(l_deposit_h(gain_cng), sub(gain_cng_e, 31 - 16)), // Q16
        l_tmp,
    ) > 0
    {
        gain_cng_e = sub(15 + 1, norm_l(l_tmp));
        gain_cng = extract_l(l_shr(l_tmp, gain_cng_e)); // Q15, gainCNG_e
        gain_cng_e = sub(gain_cng_e, 1);
    }

    // st->Mode2_lp_gainc = alpha * (st->Mode2_lp_gainc) + (1.0f - alpha) * gainCNG; end-of-the-frame gain
    l_tmp = mpy_32_16_1(st.mode2_lp_gainc, alpha); // Q15
    let l_tmp2 = l_mult(sub(16384, alpha), gain_cng); // Q30, gainCNG_e
    let mut tmp_e: i16 = 0;
    st.mode2_lp_gainc =
        basop_util_add_mant32_exp(l_tmp, 31 - 15, l_tmp2, add(gain_cng_e, 31 - 30), &mut tmp_e); // Q31
    st.mode2_lp_gainc = l_shl(st.mode2_lp_gainc, sub(tmp_e, 31 - 16));

    // PLC: [TCX: Fade-out] Linearly attenuate the gain through the frame
    // step = (1.0f/L_frame) * (gain - (st->Mode2_lp_gainc));
    l_tmp = l_sub(gain32, st.mode2_lp_gainc); // Q16
    tmp_e = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, tmp_e); // Q16,-tmp_e
    let mut step32 = mpy_32_16_1(l_tmp, get_inv_frame_len(l_frame)); // Q22,-tmp_e
    step32 = l_shl(step32, sub(25 - 22, tmp_e)); // Q25

    // normalize energy: gain_inov = 1.0f / sqrt(dot_product(pt_exc, pt_exc, L_frame) / L_frame + 0.01f)
    l_tmp = dot_product_sq16_hq(0, &buf[FIR / 2..], l_frame, &mut tmp_e, &mut st.stl); // Q31, tmp_e+16+16
    l_tmp = mpy_32_16_1(l_tmp, get_inv_frame_len(l_frame)); // Q5, tmp_e
    tmp_e = add(tmp_e, 31 - 5); // --> Q31
    let mut gain_inov = round_word(isqrt32(l_tmp, &mut tmp_e)); // Q15, tmp_e
    let mut gain_inov_e = tmp_e;
    if sub(st.last_good, UNVOICED_CLAS) == 0 && sub(st.core_ext_mode, UNVOICED) != 0 {
        gain_inov = mult_r(gain_inov, 26214); // 0.8f Q15
    } else if !(sub(st.last_good, UNVOICED_CLAS) == 0
        || sub(st.last_good, UNVOICED_TRANSITION) == 0)
    {
        // gain_inov *= (1.1f- 0.75*st->lp_gainp);
        l_tmp = mpy_32_16_1(
            l_sub(590_558_016, mpy_32_16_1(st.mode2_lp_gainp, 24576)), // Q29
            gain_inov,
        ); // Q29, gain_inov_e
        tmp_e = norm_l(l_tmp);
        l_tmp = l_shl(l_tmp, tmp_e);
        gain_inov_e = add(sub(gain_inov_e, tmp_e), 31 - 29); // -> Q31
        gain_inov = round_word(l_tmp); // Q15, gain_inov_e
    }

    st.mode2_lp_gainp = l_shr(l_deposit_h(alpha), 1); // Q29

    tmp_e = norm_l(gain32);
    tmp_e = sub(tmp_e, 5); // 5 bit additional headroom for the gain - should be enough
    gain32 = l_shl(gain32, tmp_e); // Q16,-tmp_e
    l_tmp = mpy_32_16_1(gain32, gain_inov); // Q16, gain_inov_e-tmp_e

    let mut gain_tmp = round_word(l_tmp); // Q0, gain_inov_e-tmp_e

    // non-causal ringing of the FIR filter
    let mut at = 0usize;
    for _ in 0..L_FIR_FER2 / 2 {
        buf[at] = mult_r(buf[at], gain_tmp);
        at += 1;
    }
    let tmp16 = add(l_frame, L_FIR_FER2 / 2);
    let step32_tmp = l_shl(step32, sub(tmp_e, 25 - 16)); // Q16,-tmp_e
    for _ in 0..tmp16 {
        // actual filtered random part of excitation
        buf[at] = mult_r(buf[at], gain_tmp);
        at += 1;
        gain32 = l_sub(gain32, step32_tmp); // Q16,-tmp_e
        gain_tmp = mult_r(round_word(gain32), gain_inov); // Q0, gain_inov_e-tmp_e
    }
    for _ in 0..half {
        // causal ringing of the FIR filter
        buf[at] = mult_r(buf[at], gain_tmp);
        at += 1;
    }
    noise_e = add(sub(add(noise_e, gain_inov_e), tmp_e), 15); // --> noise is Q0, noise_e
    noise_e
}

/// The synthesis of `con_tcx` and the update of every memory the next frame starts from: the
/// synthesis memory at the new Q, the ACELP and 16 kHz memories, the overlap and TDAC buffers
/// with their window and aliasing, and `old_enr_LP`.
fn con_tcx_synthesis(
    st: &mut DecoderState,
    synth: &mut [i16],
    synth_at: usize,
    buf: &mut [i16; BUF_LEN],
    a_local: &[i16; (M + 1) as usize],
    pitch_buf: &[i32; NB_SUBFR16K as usize],
    q_exc: i16,
    tmp_deemph: &mut i16,
) {
    let l_frame = st.l_frame_tcx;
    let half = shr(l_frame, 1);
    let frame = l_frame as usize;
    let frame_and_half = add(l_frame, half);
    let window = st.tcx_cfg.tcx_mdct_window_fb;
    let w1 = st.tcx_cfg.tcx_mdct_window_length_fb;
    let w2 = shr(w1, 1);
    let w12 = shr(w1, 1);

    // compute the synthesis speech
    let syn_at = M as usize;
    buf[..M as usize].copy_from_slice(&synth[synth_at - M as usize..synth_at]);

    let mut new_q = sub(q_exc, 3);
    new_q = new_q.max(-1);

    let tmp16 = new_q.min(st.prev_q_syn);
    st.prev_q_syn = new_q;

    let exp_scale = sub(tmp16, q_exc - 1);
    let q_syn = tmp16;

    let mut mem_syn = [0i16; M as usize];
    copy_scale_sig(&buf[..], &mut mem_syn, M, exp_scale);

    *tmp_deemph = shl(*tmp_deemph, q_syn);
    st.q_syn = q_syn;

    {
        let (syn_region, exc_region) = buf.split_at_mut(EXC_AT);
        e_util_synthesis(
            sub(q_exc, q_syn),
            a_local,
            exc_region,
            &mut syn_region[syn_at..],
            frame_and_half,
            &mut mem_syn,
            1,
            M,
        );
    }

    let n = extract_h(l_mult(l_frame, 9216)); // N_ZERO_MDCT_NS/FRAME_SIZE_NS Q15

    // update ACELP synthesis memory
    let mem_syn_r_size_old = shr(l_frame, 4); // replace 1.25/20.0 by shr(4)
                                              // copy mem_syn as 16kHz
    let mem_syn_r_size_new = shr(L_FRAME16K, 4);

    st.mem_syn_r
        .copy_from_slice(&buf[syn_at + frame - L_SYN_MEM as usize..][..L_SYN_MEM as usize]);
    lerp_within(
        &mut st.mem_syn_r,
        (L_SYN_MEM - mem_syn_r_size_old) as usize,
        (L_SYN_MEM - mem_syn_r_size_new) as usize,
        mem_syn_r_size_new,
        mem_syn_r_size_old,
    );
    let tail = (L_SYN_MEM - M) as usize;
    st.mem_syn2
        .copy_from_slice(&st.mem_syn_r[tail..tail + M as usize]);

    // Deemphasis and output synth and ZIR
    deemph(
        &mut buf[syn_at..],
        st.preemph_fac,
        frame_and_half,
        tmp_deemph,
    );
    buffer_copy_fx(
        &buf[syn_at + frame - M as usize - 1..],
        &mut st.syn,
        1 + M,
        q_syn,
        0,
        0,
        0,
    );

    lerp(
        &buf[syn_at + frame - half as usize..],
        &mut st.old_syn_overl,
        shr(st.l_frame, 1),
        shr(l_frame, 1),
    );
    copy(
        &buf[syn_at + frame - n as usize..],
        &mut st.old_out,
        sub(l_frame, n),
    );

    for i in 0..w1 {
        let at = (i + n) as usize;
        let value = window_value(window, w12, i);
        st.old_out[at] = round_word(mpy_32_16_1(l_mult(value, value), st.old_out[at]));
    }

    set16(&mut st.old_out[(w1 + n) as usize..], 0, n);

    st.q_old_wtda = q_syn;

    // As long as there is no synth scaling factor introduced, which is given to the outside,
    // there might occur overflows here
    buffer_copy_fx(
        &buf[syn_at..],
        &mut synth[synth_at..],
        l_frame,
        q_syn,
        0,
        0,
        0,
    );

    copy_scale_sig(
        &buf[syn_at + frame..],
        &mut st.syn_overl_fb,
        shr(l_frame, 1),
        negate(q_syn),
    );

    // copy total excitation exc2 as 16kHz for acelp mode1 decoding
    lerp(&buf[EXC_AT..], &mut st.old_exc2, L_EXC_MEM, l_frame);
    lerp(&buf[syn_at..], &mut st.old_syn2, L_EXC_MEM, l_frame);
    st.bfi_pitch = round_word(l_shl(pitch_buf[st.nb_subfr as usize - 1], 6)); // Q6
    st.bfi_pitch_frame = st.l_frame;

    // create aliasing and windowing need for transition to TCX10/5
    buffer_copy_fx(
        &buf[syn_at + frame..],
        &mut st.syn_overl_tdacfb,
        shr(l_frame, 1),
        q_syn,
        0,
        -1,
        0,
    );

    for i in 0..w1 {
        buf[i as usize] = mult_r(
            st.syn_overl_tdacfb[i as usize],
            window_value(window, w12, i),
        );
    }

    for i in 0..w2 {
        st.syn_overl_tdacfb[i as usize] = add(buf[i as usize], buf[(w1 - 1 - i) as usize]);
    }

    for i in 0..w2 {
        st.syn_overl_tdacfb[(w2 + i) as usize] =
            add(buf[(w2 + i) as usize], buf[(w1 - 1 - w2 - i) as usize]);
    }

    for i in 0..w1 {
        st.syn_overl_tdacfb[i as usize] = mult_r(
            st.syn_overl_tdacfb[i as usize],
            window_value(window, w12, i),
        );
    }

    st.tcx_cfg.tcx_curr_overlap_mode = FULL_OVERLAP;

    // update memory for low band
    scale_sig(&mut st.old_syn_overl, shr(st.l_frame, 1), sub(-1, q_syn));
    lerp(
        &st.syn_overl_fb,
        &mut st.syn_overl,
        shr(st.l_frame, 1),
        shr(l_frame, 1),
    );
    lerp(
        &st.syn_overl_tdacfb,
        &mut st.syn_overl_tdac,
        shr(st.l_frame, 1),
        shr(l_frame, 1),
    );
    lerp(&st.old_out, &mut st.old_out_lb, st.l_frame, l_frame);

    st.old_enr_lp = enr_1_az(a_local, L_SUBFR); // Q3
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::rom::types::{PWord16, PWord16V};

    #[test]
    fn the_buffer_layout_matches_the_reference() {
        assert_eq!(BUF_LEN, 3143);
        assert_eq!(EXC_AT, 1462);
    }

    #[test]
    fn calc_gainc2_of_silence_is_zero() {
        let buf = [0i16; 200];
        let mut flags = StlFlags::default();
        assert_eq!(calc_gainc2(&buf, 100, 0, 40, &mut flags), 0);
        assert!(!flags.carry);
    }

    #[test]
    fn calc_gainc2_of_a_constant_is_its_rms_in_15q16() {
        // a constant excitation of 4096 at Q_exc 1 is an amplitude of 2048
        let buf = [4096i16; 400];
        let mut flags = StlFlags::default();
        let gain = calc_gainc2(&buf, 200, 1, 80, &mut flags);
        assert_eq!(gain >> 16, 2048);
    }

    #[test]
    fn calc_gainc_removes_the_pitch_contribution() {
        // a signal that repeats exactly at the lag and a pitch gain of 1 leave nothing
        let mut buf = [0i16; 600];
        for (i, value) in buf.iter_mut().enumerate() {
            *value = ((i % 50) as i16 - 25) * 100;
        }
        let mut flags = StlFlags::default();
        let gain = calc_gainc(&buf, 400, 0, 50 << 16, 64, 1 << 29, &mut flags);
        assert_eq!(gain, 0);
    }

    #[test]
    fn window_value_walks_the_table_up_then_back_down() {
        let table = [
            PWord16 {
                v: PWord16V { re: 1, im: 10 },
            },
            PWord16 {
                v: PWord16V { re: 2, im: 20 },
            },
            PWord16 {
                v: PWord16V { re: 3, im: 30 },
            },
        ];
        let samples: Vec<i16> = (0..6).map(|i| window_value(&table, 3, i)).collect();
        assert_eq!(samples, [1, 2, 3, 30, 20, 10]);
    }
}
