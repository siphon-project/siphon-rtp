//! Energy control of the synthesis after a frame erasure and on recovery (TS 26.442
//! `lib_dec/FEC_scale_syn_fx.c`; TS 26.445 §5.3.4.3 / §6.1.3.3 "energy control").
//!
//! The excitation is rescaled so the synthesis energy follows the transmitted (or concealed)
//! energy, with a smooth gain transition from `gain1` at the frame start to `gain2` at its end,
//! and the frame is re-synthesised from the saved filter memory.
//!
//! **Aliasing.** The LP tilt estimate calls `E_UTIL_synthesis(1, Aq+3*(M+1), h1, h1, L_FRAME/2,
//! &h1[M+1], 0, M)`: input, output *and* filter memory are all the one buffer `h1`. The filter
//! reads its memory (`h1[M+1..2M+1]`) only while producing the first `M` outputs, which land in
//! `h1[0..M]`, so the memory it reads is still the zeros `set16_fx` wrote; with `update == 0` it
//! never writes it. The port copies those `M` words to a local memory before filtering `h1` in
//! place, which is the same read/write order (proven by the oracle on both branches that do it).

use crate::evs::basop::{madd_32_16, mpy_32_16_1, mpy_32_32, mult_32_16};
use crate::evs::cnst::{
    ACELP_11K60, ACELP_12K15, ACELP_12K85, ACELP_13K20, ACELP_7K20, ACELP_8K00, ACELP_9K60,
    AUTO_REGRESSIVE, FRAME_NO_DATA, GENERIC, INACTIVE_CLAS, L_FRAME, M, MOVING_AVERAGE, NB_SUBFR,
    NB_SUBFR16K, ONSET, PIT_MIN, SID_1K75, SID_2K40, SIN_ONSET, TRANSITION, UNVOICED_CLAS,
    VOICED_CLAS, VOICED_TRANSITION,
};
use crate::evs::com::enr_1_az::enr_1_az;
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::get_gain::get_gain;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::syn_12k8::syn_12k8;
use crate::evs::com::syn_filt::e_util_synthesis_in_place;
use crate::evs::com::tools::{copy, set16, sqrt_ratio32};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_add, l_deposit_h, l_mac, l_mult, l_shl, l_sub, mult_r, norm_l,
    norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{mac_r, StlFlags};

/// `AGC_FX`: 0.98 in Q15, the per-sample smoothing of the gain transition.
const AGC_FX: i16 = 32113;
/// `SCLSYN_LAMBDA`: 0.3 in Q15.
const SCLSYN_LAMBDA: i16 = 9830;

/// The inputs `FEC_scale_syn_fx` only reads, grouped so the call stays legible.
#[derive(Debug, Clone, Copy)]
pub struct FecScaleSynParams {
    pub l_frame: i16,
    pub clas: i16,
    pub last_good: i16,
    pub l_enr_old: i32,
    pub l_enr_q: i32,
    pub coder_type: i16,
    pub lsf_q_prediction: i16,
    pub bfi: i16,
    pub total_brate: i32,
    pub prev_bfi: i16,
    pub last_core_brate: i32,
    pub q_exc: i16,
    pub q_syn: i16,
    pub avoid_lpc_burst_on_recovery: i16,
    pub force_scaling: i16,
}

/// The state `FEC_scale_syn_fx` reads and updates through its pointer arguments.
#[derive(Debug)]
pub struct FecScaleSynState<'a> {
    pub update_flg: &'a mut i16,
    pub scaling_flag: &'a mut i16,
    pub lp_ener_fec_av: &'a mut i32,
    pub lp_ener_fec_max: &'a mut i32,
    pub old_enr_lp: &'a mut i16,
}

/// `FEC_scale_syn_fx`: control the energy of the synthesis `synth[0..l_frame]` (Q`q_syn`) of an
/// erased frame or of the first good frames after one. When it rescales, it scales `exc` and
/// `exc2` (Q`q_exc`, from the subframe start) in place, restores `mem_syn` from `mem_tmp` and
/// re-synthesises `synth` with `aq`, setting `update_flg`. `pitch` holds the subframe pitch lags
/// (Q0). `flags` carries the STL `Carry` the energy dot products use.
pub fn fec_scale_syn(
    p: &FecScaleSynParams,
    s: &mut FecScaleSynState<'_>,
    synth: &mut [i16],
    pitch: &[i16],
    exc: &mut [i16],
    exc2: &mut [i16],
    aq: &[i16],
    mem_tmp: &[i16],
    mem_syn: &mut [i16],
    flags: &mut StlFlags,
) {
    let l_frame = p.l_frame;
    let clas = p.clas;
    let mut enr_lp: i16 = 0;
    let mut l_enr_q = p.l_enr_q;
    let mut l_enr2: i32 = 0;
    // the pitch of the last subframe
    let last_pitch = pitch[sub(shr(l_frame, 6), 1).max(0) as usize];

    *s.update_flg = 0;
    let l_enr_old = p.l_enr_old.max(1); // to avoid division by zero (*L_enr_old is always >= 0)
    let mut scaling: i16 = 16384; // Q14
    let voiced_like = |c: i16| sub(c, VOICED_TRANSITION) >= 0 && sub(c, INACTIVE_CLAS) < 0;

    // energy of the LP filter impulse response of the last subframe
    if voiced_like(clas) {
        let last_subfr = if sub(l_frame, L_FRAME) == 0 {
            NB_SUBFR
        } else {
            NB_SUBFR16K
        };
        let start = ((last_subfr - 1) * (M + 1)) as usize;
        enr_lp = enr_1_az(&aq[start..], L_FRAME / 4);
    }

    // scaling of the LSF-predictive frames after an erasure
    if p.bfi != 0 {
        *s.scaling_flag = 1; // a bad frame is always scaled
    } else if p.prev_bfi != 0 {
        if sub(p.lsf_q_prediction, AUTO_REGRESSIVE) == 0
            || sub(p.lsf_q_prediction, MOVING_AVERAGE) == 0
        {
            *s.scaling_flag = 2; // LSF prediction from a bad frame: scale this and the next frame
        } else if sub(p.coder_type, TRANSITION) != 0 {
            *s.scaling_flag = 1; // the first good frame is scaled, TC excepted
        } else {
            *s.scaling_flag = 0;
        }
        scaling = 24576; // Q14
    } else {
        if sub(p.lsf_q_prediction, AUTO_REGRESSIVE) == 0 && sub(*s.scaling_flag, 2) == 0 {
            *s.scaling_flag = 2; // continue the AR prediction scaling
        } else if *s.scaling_flag > 0 {
            // if the scaling flag was 2, one control frame covers the LSF interpolation
            *s.scaling_flag = sub(*s.scaling_flag, 1);
        }
        scaling = 32767; // Q14
    }

    // energy at the end of the current frame
    frame_ener(
        l_frame,
        clas,
        synth,
        last_pitch,
        &mut l_enr2,
        1,
        p.q_syn,
        3,
        0,
    );

    let low_rate = l_sub(p.total_brate, i32::from(ACELP_7K20)) == 0
        || l_sub(p.total_brate, i32::from(ACELP_8K00)) == 0;
    if p.bfi != 0 || low_rate {
        // at 7.2 and 8.0 kbit/s, and for erased frames at every rate
        if *s.scaling_flag > 0 {
            let (gain1, gain2, enr2) = fec_scale_syn_low_rate_gains(
                p, s, synth, pitch, aq, l_enr_old, l_enr_q, l_enr2, scaling, flags,
            );
            l_enr2 = enr2;
            fec_scale_syn_rescale(p, s, gain1, gain2, synth, exc, exc2, aq, mem_tmp, mem_syn);
        }
    } else if p.prev_bfi != 0 && sub(p.coder_type, TRANSITION) != 0 {
        // the first good frame after an erasure, at the higher rates
        l_enr_q = fec_scale_syn_recovery_target(
            p, s, aq, l_enr_old, l_enr_q, l_enr2, enr_lp, scaling, flags,
        );
        let (gain1, gain2) =
            fec_scale_syn_recovery_gains(p, s, synth, pitch, l_enr_old, l_enr_q, l_enr2, enr_lp);
        fec_scale_syn_rescale(p, s, gain1, gain2, synth, exc, exc2, aq, mem_tmp, mem_syn);
    }

    // update the long-term averages of the (pitch-synchronous) energy for the next erasure
    if p.bfi == 0 && voiced_like(clas) {
        let mut l_enr2_av: i32 = 0;
        let mut l_ener2_max: i32 = 0;
        if sub(clas, VOICED_TRANSITION) == 0 {
            l_enr2_av = l_enr2;
            frame_ener(
                l_frame,
                VOICED_CLAS,
                synth,
                last_pitch,
                &mut l_ener2_max,
                1,
                p.q_syn,
                3,
                0,
            );
        } else {
            l_ener2_max = l_enr2;
            frame_ener(
                l_frame,
                UNVOICED_CLAS,
                synth,
                last_pitch,
                &mut l_enr2_av,
                1,
                p.q_syn,
                3,
                0,
            );
        }
        *s.lp_ener_fec_av = madd_32_16(mult_32_16(*s.lp_ener_fec_av, 31130), l_enr2_av, 1638);
        *s.lp_ener_fec_max = madd_32_16(mult_32_16(*s.lp_ener_fec_max, 31130), l_ener2_max, 1638);
    }

    // memory of the LP filter energy for the next frame
    if voiced_like(clas) {
        *s.old_enr_lp = enr_lp;
    }
}

/// `gain = sqrt(num / den)` in Q14 through `Sqrt_Ratio32`, as the 7.2/8.0 kbit/s branch computes it.
fn fec_scale_syn_sqrt_ratio_gain(num: i32, den: i32) -> i16 {
    let mut exp2: i16 = 0;
    let l_tmp = sqrt_ratio32(num, 0, den, 0, &mut exp2);
    round_word(l_shl(l_tmp, sub(exp2, 1))) // in Q14
}

/// `gain = sqrt(num / den)` in Q14 by the normalise / divide / `Isqrt_lc` sequence the
/// higher-rate recovery branch writes out inline (`num`, `den` > 0).
fn fec_scale_syn_isqrt_gain(den: i32, num: i32) -> i16 {
    let exp = norm_l(den);
    let tmp = extract_h(l_shl(den, exp));
    let mut exp2 = norm_l(num);
    let mut tmp2 = extract_h(l_shl(num, exp2));
    exp2 = sub(exp, exp2); // Denormalize and substract
    let tmp3 = sub(tmp2, tmp);
    if tmp3 > 0 {
        tmp2 = shr(tmp2, 1);
        exp2 = add(exp2, 1);
    }
    let tmp = div_s(tmp2, tmp);
    let l_tmp = l_deposit_h(tmp);
    let l_tmp = isqrt_lc(l_tmp, &mut exp2);
    round_word(l_shl(l_tmp, sub(exp2, 1))) // in Q14
}

/// The tilt of the LP filter of the fourth subframe: the gain `<h[1..], h[0..]>` of its truncated
/// impulse response `h1`, Q15. See the module comment for the aliased `E_UTIL_synthesis` call.
fn fec_scale_syn_lp_tilt(aq: &[i16], flags: &mut StlFlags) -> i16 {
    const LEN: usize = (L_FRAME / 2) as usize;
    let mut h1 = [0i16; LEN];
    set16(&mut h1, 0, L_FRAME / 2);
    h1[0] = 1024;
    // mem = h1 + (M+1): copied out before h1 is overwritten; the filter only reads it while
    // writing h1[0..M], and update == 0 never writes it back.
    let mut mem = [0i16; M as usize];
    mem.copy_from_slice(&h1[(M + 1) as usize..(2 * M + 1) as usize]);
    let a_start = (3 * (M + 1)) as usize;
    e_util_synthesis_in_place(1, &aq[a_start..], &mut h1, L_FRAME / 2, &mut mem, 0, M);
    extract_h(l_shl(get_gain(&h1[1..], &h1, L_FRAME / 2 - 1, flags), 15))
}

/// The voiced-to-unvoiced / CNG-to-active recovery test both branches use for `gain1 = gain2`.
fn fec_scale_syn_onset_like_recovery(p: &FecScaleSynParams) -> bool {
    (sub(p.last_good, VOICED_TRANSITION) >= 0
        && sub(p.last_good, INACTIVE_CLAS) < 0
        && (sub(p.clas, UNVOICED_CLAS) == 0 || sub(p.clas, INACTIVE_CLAS) == 0))
        || l_sub(p.last_core_brate, i32::from(SID_1K75)) == 0
        || l_sub(p.last_core_brate, i32::from(SID_2K40)) == 0
        || l_sub(p.last_core_brate, i32::from(FRAME_NO_DATA)) == 0
}

/// The 7.2 / 8.0 kbit/s (and erased-frame) branch: the start and end gains, and the energy the
/// long-term averages are updated with (`L_enr2`, replaced by the target on a good frame).
fn fec_scale_syn_low_rate_gains(
    p: &FecScaleSynParams,
    s: &mut FecScaleSynState<'_>,
    synth: &[i16],
    pitch: &[i16],
    aq: &[i16],
    l_enr_old: i32,
    l_enr_q: i32,
    l_enr2: i32,
    scaling: i16,
    flags: &mut StlFlags,
) -> (i16, i16, i32) {
    let clas = p.clas;
    let mut l_enr2 = l_enr2.max(1);
    let mut l_enr_q = l_enr_q;
    let mut l_enr1: i32 = 0;
    let mut gain1;
    let gain2;
    if p.bfi != 0 {
        // energy at the end of the previous frame vs. that of the concealed frame
        gain2 = fec_scale_syn_sqrt_ratio_gain(l_enr_old, l_enr2).min(16384); // never increase
                                                                             // energy at the beginning of the current frame
        frame_ener(
            p.l_frame,
            clas,
            synth,
            pitch[0],
            &mut l_enr1,
            1,
            p.q_syn,
            3,
            0,
        );
        l_enr1 = l_enr1.max(1);
        gain1 = fec_scale_syn_sqrt_ratio_gain(l_enr_old, l_enr1).min(16384);
    } else {
        if l_enr_q == 0 {
            // no energy transmitted: estimate it, limited when the LP filter is resonant
            l_enr_q = l_enr2;
            let tilt = fec_scale_syn_lp_tilt(aq, flags);
            let mut pitch_dist: i16 = 0;
            let mut l_mean_pitch = l_mult(pitch[0], 8192);
            for k in 0..(NB_SUBFR - 1) as usize {
                pitch_dist = add(pitch_dist, abs_s(sub(pitch[k + 1], pitch[k])));
                l_mean_pitch = l_mac(l_mean_pitch, pitch[k + 1], 8192);
            }
            pitch_dist = mult_r(shl(pitch_dist, 4), 10923); // 1/(NB_SUBFR-1)
            let mean_pitch = extract_h(l_shl(l_mean_pitch, 4));
            if sub(tilt, 22938) > 0 // HF resonant filter
                && (sub(pitch_dist, 8 << 4) > 0 || sub(mean_pitch, PIT_MIN << 4) < 0) // pitch unstable or very short
                && (p.prev_bfi != 0
                    || (sub(p.coder_type, GENERIC) == 0
                        && sub(p.lsf_q_prediction, AUTO_REGRESSIVE) == 0))
            {
                l_enr_q = l_enr_q.min(l_shl(mult_32_16(l_enr_old, scaling), 1));
            } else {
                let mut ener_max = *s.lp_ener_fec_max;
                if sub(clas, VOICED_TRANSITION) == 0 || sub(clas, INACTIVE_CLAS) >= 0 {
                    ener_max = *s.lp_ener_fec_av;
                }
                ener_max = ener_max.max(l_enr_old);
                l_enr_q = l_enr_q.min(l_shl(mult_32_16(ener_max, scaling), 1));
            }
        }
        l_enr_q = l_enr_q.max(1);
        gain2 = fec_scale_syn_sqrt_ratio_gain(l_enr_q, l_enr2);

        if fec_scale_syn_onset_like_recovery(p) && p.prev_bfi != 0 {
            gain1 = gain2;
        } else {
            frame_ener(
                p.l_frame,
                clas,
                synth,
                pitch[0],
                &mut l_enr1,
                1,
                p.q_syn,
                3,
                0,
            );
            l_enr1 = l_enr1.max(1);
            gain1 = fec_scale_syn_sqrt_ratio_gain(l_enr_old, l_enr1).min(19661);
            if sub(clas, ONSET) == 0 && sub(gain1, gain2) > 0 && p.prev_bfi != 0 {
                // no increase of gain on an onset
                gain1 = gain2;
            }
        }
        l_enr2 = l_enr_q;
    }
    (gain1, gain2, l_enr2)
}

/// The higher-rate recovery branch: the target energy of the first good frame after an erasure,
/// estimated (and limited) when none was transmitted.
fn fec_scale_syn_recovery_target(
    p: &FecScaleSynParams,
    s: &FecScaleSynState<'_>,
    aq: &[i16],
    l_enr_old: i32,
    l_enr_q: i32,
    l_enr2: i32,
    enr_lp: i16,
    scaling: i16,
    flags: &mut StlFlags,
) -> i32 {
    let clas = p.clas;
    let mut l_enr_q = l_enr_q;
    if l_enr_q == 0 {
        l_enr_q = l_enr2.max(1);
        let tilt = fec_scale_syn_lp_tilt(aq, flags);
        let brate = p.total_brate;
        let voiced_last = sub(p.last_good, VOICED_TRANSITION) >= 0
            && sub(p.last_good, INACTIVE_CLAS) < 0
            && sub(clas, VOICED_TRANSITION) >= 0
            && sub(clas, INACTIVE_CLAS) < 0;
        if (l_sub(brate, i32::from(ACELP_13K20)) == 0
            || l_sub(brate, i32::from(ACELP_12K85)) == 0
            || l_sub(brate, i32::from(ACELP_12K15)) == 0
            || l_sub(brate, i32::from(ACELP_11K60)) == 0
            || l_sub(brate, i32::from(ACELP_9K60)) == 0)
            && sub(tilt, 22938) > 0 // HF resonant filter
            && (sub(clas, UNVOICED_CLAS) == 0 || sub(clas, INACTIVE_CLAS) == 0)
        {
            l_enr_q = l_enr_q.min(l_shl(mult_32_16(l_enr_old, scaling), 1));
        } else if voiced_last {
            // voiced segment: follow the LP filter energy
            if *s.old_enr_lp != 0 && sub(enr_lp, shl(*s.old_enr_lp, 1)) > 0 {
                // L_enr_q *= 2 * old_enr_LP / enr_LP
                let mut exp = norm_l(l_enr_q);
                let mut tmp = extract_h(l_shl(l_enr_q, exp));
                let exp2 = norm_s(enr_lp);
                let tmp2 = shl(enr_lp, exp2);
                exp = sub(exp2, exp);
                let tmp3 = sub(tmp, tmp2);
                if tmp3 > 0 {
                    tmp = shr(tmp, 1);
                    exp = add(exp, 1);
                }
                tmp = div_s(tmp, tmp2);
                l_enr_q = l_shl(l_mult(tmp, shl(*s.old_enr_lp, 1)), exp);
            } else if p.avoid_lpc_burst_on_recovery != 0 && sub(enr_lp, 160) > 0 {
                // L_enr_q *= sqrt(160 / enr_LP)
                let mut exp = norm_s(enr_lp);
                let mut tmp = shl(enr_lp, exp);
                let exp2: i16 = 7;
                let tmp2: i16 = 160 << 7;
                exp = sub(exp2, exp);
                if sub(tmp, tmp2) > 0 {
                    tmp = shr(tmp, 1);
                    exp = add(exp, 1);
                }
                tmp = div_s(tmp, tmp2);
                let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
                l_enr_q = l_shl(mpy_32_32(l_enr_q, l_tmp), exp);
            }
        }
        if (voiced_last || p.force_scaling != 0) && l_sub(l_enr_q, l_enr_old) > 0 {
            // prevent the energy from increasing on voiced
            l_enr_q = l_add(
                mpy_32_16_1(l_enr_old, 32767 - SCLSYN_LAMBDA),
                mpy_32_16_1(l_enr_q, SCLSYN_LAMBDA),
            );
        }
    }
    l_enr_q.max(1)
}

/// The higher-rate recovery branch: the start and end gains towards the target `l_enr_q`.
fn fec_scale_syn_recovery_gains(
    p: &FecScaleSynParams,
    s: &FecScaleSynState<'_>,
    synth: &[i16],
    pitch: &[i16],
    l_enr_old: i32,
    l_enr_q: i32,
    l_enr2: i32,
    enr_lp: i16,
) -> (i16, i16) {
    let clas = p.clas;
    // gain2 = sqrt(L_enr_q / L_enr2)
    let mut gain2 = fec_scale_syn_isqrt_gain(l_enr_q, l_enr2).min(19661);
    if l_sub(l_enr_q, 2) < 0 {
        gain2 = gain2.min(16384);
    }
    let gain1 = if sub(clas, SIN_ONSET) == 0 {
        shr(gain2, 1) // slow increase
    } else if fec_scale_syn_onset_like_recovery(p) {
        gain2
    } else {
        // energy at the beginning of the current frame
        let mut l_enr1: i32 = 0;
        frame_ener(
            p.l_frame,
            clas,
            synth,
            pitch[0],
            &mut l_enr1,
            0,
            p.q_syn,
            3,
            0,
        );
        // gain1 = sqrt(L_enr_old / L_enr1)
        let mut gain1 = fec_scale_syn_isqrt_gain(l_enr_old, l_enr1).min(19661);
        if p.avoid_lpc_burst_on_recovery != 0
            && sub(enr_lp, 160) > 0
            && sub(enr_lp, shl(*s.old_enr_lp, 1)) <= 0
        {
            gain1 = gain1.min(16384);
        }
        if sub(clas, ONSET) == 0 && sub(gain1, gain2) > 0 {
            gain1 = gain2; // no increase of gain on an onset
        }
        gain1
    };
    (gain1, gain2)
}

/// Scale `exc` and `exc2` by a gain moving from `gain1` towards `gain2` (Q14), then re-synthesise
/// the frame from the saved filter memory.
fn fec_scale_syn_rescale(
    p: &FecScaleSynParams,
    s: &mut FecScaleSynState<'_>,
    gain1: i16,
    gain2: i16,
    synth: &mut [i16],
    exc: &mut [i16],
    exc2: &mut [i16],
    aq: &[i16],
    mem_tmp: &[i16],
    mem_syn: &mut [i16],
) {
    let mut gain1 = gain1;
    let l_tmp = l_mult(gain2, (32768 - i32::from(AGC_FX)) as i16); // 1 - AGC
    let len = p.l_frame.max(0) as usize;
    for (e, e2) in exc[..len].iter_mut().zip(exc2[..len].iter_mut()) {
        gain1 = mac_r(l_tmp, gain1, AGC_FX); // in Q14
                                             // exc *= gain1 in Q14: x·g + x·g (Q15 + Q15 = Q14 doubled)
        *e = mac_r(l_mult(*e, gain1), *e, gain1);
        *e2 = mac_r(l_mult(*e2, gain1), *e2, gain1);
    }
    // re-synthesise from the memory saved before the frame
    copy(mem_tmp, mem_syn, M);
    syn_12k8(p.l_frame, aq, exc2, synth, mem_syn, 1, p.q_exc, p.q_syn);
    *s.update_flg = 1;
}
