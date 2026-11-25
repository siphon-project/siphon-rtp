//! The ACELP concealment of the MODE2 core (TS 26.442 `lib_dec/er_dec_acelp.c`; TS 26.447
//! §5.4.2): the last pitch cycle repeated at the extrapolated pitch with a fade-out as the
//! harmonic excitation, a randomised high-passed noise excitation scaled to the background
//! level as the unvoiced one, both synthesised through their own LPC filters and summed, and the
//! update of every memory the next frame (ACELP or TCX) starts from.
//!
//! The reference lays the noise, the old excitation, the harmonic excitation and the synthesis
//! out in one stack buffer (`buf`) whose regions overlap deliberately (the noise is written over
//! the start of the old excitation once that is saved, the synthesis over the noise); the port
//! keeps that one buffer and its offsets, so every read sees what the reference's reads see.
//! `Qf_exc` and `Qf_mem_syn` are `&st->Q_exc` and `&st->Q_syn` at the only call site, so they
//! are read and written through `st`.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    FULL_OVERLAP, GENERIC, L_EXC_MEM, L_EXC_MEM_DEC, L_FIR_FER, L_FRAME, L_FRAME16K, L_SUBFR,
    L_SYN_MEM, M, NB_SUBFR, NB_SUBFR16K, UNVOICED, UNVOICED_CLAS, UNVOICED_TRANSITION,
};
use crate::evs::com::basop_util::{
    basop_util_add_mant_exp, basop_util_divide_mant_exp, buffer_copy_fx, dot_product_sq16_hq,
    get_scale_factor16, imult1616, isqrt32,
};
use crate::evs::com::deemph::{deemph, e_util_deemph2};
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::lerp::lerp;
use crate::evs::com::scale_mem::rescale_mem_syn;
use crate::evs::com::swb_tbe_com::{interp_code_4over2, interp_code_5over2};
use crate::evs::com::syn_filt::{e_util_synthesis, e_util_synthesis_in_place};
use crate::evs::com::tools::{copy, own_random2, scale_sig, set16, set32, vr_add};
use crate::evs::dec::er_scale_syn::damping_fact;
use crate::evs::dec::er_sync_exc::pulse_resynchronization;
use crate::evs::dec::er_util::{gen_plc_filt_bw_adap, get_level_syn_deemph, high_pass_filtering};
use crate::evs::dec::fec_clas_estim::fec_clas_estim;
use crate::evs::dec::pitch_extr::{get_subframe_pitch, pitch_pred_linear_fit};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{T_256DIV_L_FRAME, T_DIV_L_FRAME};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult,
    l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_msu0, l_mult0, mac_r};

/// `L_EXC_MEM_DEC + M + L_FRAME_16k + L_FRAME_16k/2`: the reference's `buf`.
const BUF_LEN: usize = (L_EXC_MEM_DEC + M + L_FRAME16K + L_FRAME16K / 2) as usize;
/// `harmonic_exc_buf = buf + M`.
const HARMONIC_AT: usize = M as usize;
/// `exc = harmonic_exc_buf + L_EXC_MEM_DEC`.
const EXC_AT: usize = HARMONIC_AT + L_EXC_MEM_DEC as usize;
/// `syn = buf + M`.
const SYN_AT: usize = M as usize;
/// `L_FRAME_16k + L_FRAME_16k/2`.
const FRAME_AND_HALF_MAX: usize = (L_FRAME16K + L_FRAME16K / 2) as usize;

/// The gains the harmonic part leaves for the rest of the concealment.
struct HarmonicResult {
    /// The damping factor (Q14).
    alpha: i16,
    /// The pitch the frame was built from (15Q16).
    tmp_tc: i32,
}

/// `con_acelp`: conceal a lost ACELP frame. `a` holds the LPC coefficients (Q12) of the
/// subframes of the last good frame, `synth` receives `L_frame` samples; `p_t`, `pgain_t` and
/// `pitch_buffer` the pitch, pitch gain (Q14) and pitch of every subframe, `voice_factors` and
/// `bwe_exc` the BWE inputs.
pub fn con_acelp(
    a: &[i16],
    coder_type: i16,
    synth: &mut [i16],
    p_t: &mut [i16],
    pgain_t: &mut [i16],
    stab_fac: i16,
    st: &mut DecoderState,
    pitch_buffer: &mut [i16],
    voice_factors: &mut [i16],
    bwe_exc: &mut [i16],
) {
    let l_frame = st.l_frame;
    let mut buf = [0i16; BUF_LEN];
    let mut pitch_buf = [0i32; NB_SUBFR16K as usize];
    let mut exc_unv = [0i16; FRAME_AND_HALF_MAX];
    let mut syn_unv = [0i16; FRAME_AND_HALF_MAX];

    // set ACELP synthesis memory
    let mut mem_syn = [0i16; M as usize];
    mem_syn.copy_from_slice(&st.mem_syn2);

    // set excitation memory
    buf[HARMONIC_AT..HARMONIC_AT + L_EXC_MEM_DEC as usize].copy_from_slice(&st.old_exc);
    buf[EXC_AT + l_frame as usize] = 0;

    let harmonic = con_acelp_harmonic(
        st,
        coder_type,
        stab_fac,
        &mut buf,
        &mut pitch_buf,
        p_t,
        pgain_t,
        pitch_buffer,
    );
    let (alpha, tmp_tc) = (harmonic.alpha, harmonic.tmp_tc);

    let (g_e, mut s_16) = con_acelp_noise(st, coder_type, alpha, a, &mut buf);

    // total excitation: harmonic part in exc, noise in the unvoiced excitation
    let q_exc = st.q_exc;
    if st.last_good < UNVOICED_TRANSITION {
        let (noise_region, exc_region) = buf.split_at_mut(EXC_AT);
        buffer_copy_fx(
            &noise_region[(L_FIR_FER / 2) as usize..],
            exc_region,
            add(l_frame, shr(l_frame, 1)),
            0,
            q_exc,
            negate(g_e),
            0,
        ); // copy between different formats
        st.old_exc
            .copy_from_slice(&buf[HARMONIC_AT + l_frame as usize..][..L_EXC_MEM_DEC as usize]);
        let n = add(l_frame, shr(l_frame, 1)) as usize;
        exc_unv[..n].copy_from_slice(&buf[EXC_AT..EXC_AT + n]); // update exc_unv
    } else {
        // update exc_unv
        buffer_copy_fx(
            &buf[(L_FIR_FER / 2) as usize..],
            &mut exc_unv,
            add(l_frame, shr(l_frame, 1)),
            0,
            q_exc,
            negate(g_e),
            0,
        );
    }

    // compute total excitation in noisebuffer to save memories
    if st.last_good >= UNVOICED_TRANSITION {
        let (noise_region, exc_region) = buf.split_at_mut(EXC_AT);
        vr_add(exc_region, &exc_unv, noise_region, add(l_frame, 1));
    }
    {
        // the total excitation: the noise buffer, or the unvoiced excitation alone
        let total: &[i16] = if st.last_good >= UNVOICED_TRANSITION {
            &buf
        } else {
            &exc_unv
        };
        if l_frame == L_FRAME {
            interp_code_5over2(total, bwe_exc, l_frame);
            set16(voice_factors, st.last_voice_factor, NB_SUBFR);
        } else {
            interp_code_4over2(total, bwe_exc, l_frame);
            set16(voice_factors, st.last_voice_factor, NB_SUBFR16K);
        }
    }

    // compute the synthesis speech
    buf[..M as usize].copy_from_slice(&st.mem_syn2);

    let mut mem_syn_unv = [0i16; M as usize];
    if sub(st.nb_lost_cmpt, 1) == 0 {
        if st.last_good < UNVOICED_TRANSITION {
            mem_syn_unv.copy_from_slice(&st.mem_syn2);
        } else {
            set16(&mut mem_syn_unv, 0, M);
        }
    } else {
        mem_syn_unv.copy_from_slice(&st.mem_syn_unv_back);
    }

    let mut gain_lpc = [0i16; NB_SUBFR16K as usize];
    let mut gain_lpc_e = [0i16; NB_SUBFR16K as usize];

    // voiced synth
    if st.last_good >= UNVOICED_TRANSITION {
        con_acelp_voiced_synthesis(
            st,
            a,
            &mut buf,
            &mut mem_syn,
            &mut s_16,
            &mut gain_lpc,
            &mut gain_lpc_e,
        );
    }

    if sub(st.nb_lost_cmpt, 5) > 0 && s_16 > 0 {
        // scale back mem_syn, exc and synthesis
        scale_sig(&mut mem_syn, M, negate(s_16));
        scale_sig(
            &mut buf[SYN_AT..],
            add(shr(l_frame, 1), l_frame),
            negate(s_16),
        );
    }

    // unvoiced synth
    let q_syn = con_acelp_unvoiced_synthesis(
        st,
        &mut exc_unv,
        &mut syn_unv,
        &mut mem_syn_unv,
        &mut mem_syn,
        &mut s_16,
        &mut gain_lpc,
        &mut gain_lpc_e,
    );

    // add separate synthesis buffers
    if st.last_good >= UNVOICED_TRANSITION {
        for i in 0..l_frame as usize {
            buf[SYN_AT + i] = add(buf[SYN_AT + i], syn_unv[i]);
        }
    } else {
        let n = add(l_frame, shr(l_frame, 1)) as usize;
        buf[SYN_AT..SYN_AT + n].copy_from_slice(&syn_unv[..n]);
    }

    // update buffer for the classification
    {
        let mut pit16 = [0i16; NB_SUBFR16K as usize];
        for k in 0..st.nb_subfr as usize {
            pit16[k] = shl(extract_h(pitch_buf[k]), 6); // Q6
        }

        let last_core_brate = st.last_core_brate;
        fec_clas_estim(
            st,
            0,
            l_frame,
            coder_type,
            &pit16,
            &buf,
            SYN_AT,
            None,
            None,
            0,
            q_syn,
            None,
            -32768, // -1.f Q15
            0,      // CLASSIFIER_ACELP
            1,      // bfi
            last_core_brate,
        );
    }

    // update pitch lag memory
    let nb_subfr = st.nb_subfr as usize;
    st.old_pitch_buf.copy_within(nb_subfr..2 * nb_subfr, 0);
    st.old_pitch_buf[nb_subfr..2 * nb_subfr].copy_from_slice(&pitch_buf[..nb_subfr]);

    // updating enr_old parameters
    let last_good = st.last_good;
    frame_ener(
        l_frame,
        last_good,
        &buf[SYN_AT..],
        round_word(tmp_tc),
        &mut st.enr_old,
        1,
        0,
        0,
        0,
    );

    st.enr_old = l_shl(st.enr_old, shl(negate(q_syn), 1));

    con_acelp_update_memories(st, &mut buf, &mem_syn, synth, &pitch_buf);
}

/// The harmonic part of `con_acelp`: the pitch extrapolation, the damping factor, the last pitch
/// cycle repeated (low-pass filtered after the first loss) and resynchronised, and the fade-out;
/// or silence for a last good frame below `UNVOICED_TRANSITION`.
fn con_acelp_harmonic(
    st: &mut DecoderState,
    coder_type: i16,
    stab_fac: i16,
    buf: &mut [i16; BUF_LEN],
    pitch_buf: &mut [i32; NB_SUBFR16K as usize],
    p_t: &mut [i16],
    pgain_t: &mut [i16],
    pitch_buffer: &mut [i16],
) -> HarmonicResult {
    let l_frame = st.l_frame;
    let nb_subfr = st.nb_subfr;
    let mut pred_pitch_lag: i32 = 0;
    let mut extrapolation_failed: i16 = 1;
    let mut f_use_extrapolated_pitch = false;

    // PLC: [ACELP:Extrapolate Pitch Lag]. The reference first assigns T0 = guidedT0 when
    // flagGuidedAcelp is 1; the value is overwritten below before any read.
    pitch_pred_linear_fit(
        st.nb_lost_cmpt,
        st.last_good,
        &st.old_pitch_buf,
        st.old_fpitch,
        &mut pred_pitch_lag,
        st.pit_min,
        st.pit_max,
        &st.mem_pitch_gain,
        0,
        st.plc_use_future_lag,
        &mut extrapolation_failed,
        nb_subfr,
    );
    let t0 = round_word(pred_pitch_lag);

    let n_subframes: i16 = if extrapolation_failed != 0 && sub(st.flag_guided_acelp, 1) == 0 {
        // Construct adaptive codebook with T0, T0_frac, T0_res, gain_pit for 2 sub-frames
        for i in 0..shl(L_SUBFR, 1) {
            buf[EXC_AT + i as usize] = buf[(EXC_AT as i32 + sub(i, st.guided_t0) as i32) as usize];
        }
        2
    } else {
        0
    };

    let mut tmp_tc = st.old_fpitch; // take the previous frame last pitch
    if n_subframes > 0 {
        tmp_tc = l_deposit_h(st.guided_t0); // take the transmit pitch
    }

    // PLC: [ACELP: Fade-out]; calculate damping factor
    let alpha = damping_fact(
        coder_type,
        st.nb_lost_cmpt,
        st.last_good,
        stab_fac,
        &mut st.mode2_lp_gainp,
        0,
    ); // Q14
    st.cummulative_damping = shl(mult(st.cummulative_damping, alpha), 1); // shl(Q15*Q14,1) = Q15
    if sub(st.nb_lost_cmpt, 1) == 0 {
        st.cummulative_damping = 32767; // 1.f Q15
    }

    // PLC: [ACELP: adaptive codebook]; construct the harmonic part of excitation
    if sub(st.last_good, UNVOICED_TRANSITION) >= 0 {
        // Last pitch cycle of the previous frame is repeatedly copied.
        let tc = round_word(tmp_tc);
        // if this ever saturates, it doesn't matter
        let tmp = sub(
            shl(abs_s(sub(t0, tc)), 6),
            mult(19661, shl(tc, 4)), // 0.15f Q17, Q6
        );
        if t0 > 0 && sub(t0, tc) != 0 && tmp < 0 && extrapolation_failed == 0 {
            f_use_extrapolated_pitch = true;
        }

        let mut pt_exc = EXC_AT;
        if st.enable_gplc != 0 {
            pt_exc = EXC_AT + (n_subframes * L_SUBFR) as usize;
        }
        let mut pt1_exc = pt_exc - tc as usize;

        if f_use_extrapolated_pitch {
            // Required because later pt1_exc[1] used in filtering points to exc[0]. To make it
            // safe also for GPL pt_exc is used instead of exc
            buf[pt_exc] = 0;
            pt_exc = HARMONIC_AT;
        }

        if sub(st.nb_lost_cmpt, 1) == 0 {
            // pitch cycle is first low-pass filtered
            let mut lp_filt_adapt = [0i16; 3];
            gen_plc_filt_bw_adap(st.sr_core, &mut lp_filt_adapt, 0, st.cummulative_damping);
            for _ in 0..tc {
                let mut tmp_32 = l_mult(lp_filt_adapt[0], buf[pt1_exc - 1]);
                tmp_32 = l_mac(tmp_32, lp_filt_adapt[1], buf[pt1_exc]);
                buf[pt_exc] = mac_r(tmp_32, lp_filt_adapt[2], buf[pt1_exc + 1]);
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

        if f_use_extrapolated_pitch {
            pt1_exc = HARMONIC_AT;
        }

        let l = add(l_frame, sub(imult1616(L_SUBFR, sub(1, n_subframes)), tc));
        for _ in 0..l.max(0) {
            buf[pt_exc] = buf[pt1_exc];
            pt_exc += 1;
            pt1_exc += 1;
        }

        // PLC: [ACELP: adaptive codebook]; resync pulse positions.
        if n_subframes > 0 {
            pitch_buf[0] = l_deposit_h(st.guided_t0);
            pitch_buf[1] = l_deposit_h(st.guided_t0);
            pitch_buf[2] = pitch_buf[1]; // do not resync on second half of frame
            pitch_buf[3] = pitch_buf[1];
            if sub(st.nb_subfr, 5) == 0 {
                // for guided acelp cases and nSubframes=2, set pitch_buf[4] to avoid memory
                // access issues in post_decoder()
                pitch_buf[4] = pitch_buf[3];
            }
        } else if f_use_extrapolated_pitch {
            get_subframe_pitch(st.nb_subfr, st.old_fpitch, pred_pitch_lag, pitch_buf);
            pulse_resynchronization(
                buf,
                HARMONIC_AT,
                EXC_AT,
                l_frame,
                st.nb_subfr,
                st.old_fpitch,
                pred_pitch_lag,
            );
        } else {
            set32(pitch_buf, st.old_fpitch, st.nb_subfr);
        }

        // PLC: [ACELP: adaptive codebook]; create the harmonic part needed for the overlap-add.
        let pt_exc = EXC_AT + l_frame as usize;
        let pt1_exc = if t0 == 0 {
            pt_exc - tc as usize
        } else {
            pt_exc - t0 as usize
        };
        for offset in 0..shr(l_frame, 1) as usize {
            buf[pt_exc + offset] = buf[pt1_exc + offset];
        }

        // PLC: [ACELP: adaptive codebook]; update the floating point pitch for consecutive loss
        if f_use_extrapolated_pitch {
            st.old_fpitch = pred_pitch_lag;
            if sub(st.flag_guided_acelp, 1) == 0 {
                st.old_fpitch = l_deposit_h(t0);
            }
        }

        // PLC: [ACELP: adaptive BPF]; accommodate the BPF
        st.bpf_gain_param = 3; // full BPF

        // PLC: [ACELP: adaptive codebook]; calculate the initial gain and fade out step.
        // Compute pitch coherence (copied from decoder classifier)
        let mut pc = l_abs(l_sub(
            l_add(pitch_buf[3], l_sub(pitch_buf[2], pitch_buf[1])),
            pitch_buf[0],
        )); // 9Q6 > 15Q16

        // mapping: floor(( 0.824[15Q15]-x[15Q0]*0.0733[0Q15] )*4)
        let table_index = l_shr(l_msu0(54000, shr(l_frame, 5), 2402), 15 - 2);
        pc = mpy_32_16_1(
            l_shl(pc, 1), // precompensate Q14 from table
            T_256DIV_L_FRAME[table_index as usize],
        );

        let mut gain: i16;
        if sub(st.last_good, UNVOICED_TRANSITION) <= 0
            && sub(coder_type, GENERIC) == 0
            && l_sub(pc, 6 * 2 * 32768) > 0
        {
            gain = 0;
            st.mode2_lp_gainp = l_deposit_l(0);
        } else {
            gain = 0x4000; // 1 (1Q14), start-of-the-frame gain
            st.mode2_lp_gainp = l_shl(l_deposit_l(alpha), 15); // 1Q14->2Q29
        }

        let div_index = extract_l(l_shl(l_mac(-28000, l_frame, 95), 1 - 15));
        let tmp_16 = T_DIV_L_FRAME[div_index as usize];
        let mut tmp_32 = l_mult0(tmp_16, sub(gain, alpha)); // 0Q15 * 2^-7 * 1Q14 -> 2Q29 * 2^-7
        tmp_32 = l_shr(tmp_32, 6); // -> 1Q30
        let step = round_word(tmp_32); // -> 1Q14

        // PLC: [ACELP: Fade-out]; apply fade out
        let mut l: i16 = 0;
        let mut i: i16 = 0;
        for i_subfr in 0..nb_subfr {
            pgain_t[i_subfr as usize] = gain; // Q14
            i = l;
            l = add(l, L_SUBFR);
            while i < l {
                // overflow in the first iteration because gain may be 1 after the shift
                buf[EXC_AT + i as usize] = mult_r(buf[EXC_AT + i as usize], shl(gain, 1));
                gain = sub(gain, step);
                i += 1;
            }
        }

        let l = add(l_frame, shr(l_frame, 1));
        while i < l {
            buf[EXC_AT + i as usize] = mult_r(buf[EXC_AT + i as usize], shl(gain, 1));
            gain = sub(gain, step);
            i += 1;
        }

        for i in 0..nb_subfr as usize {
            p_t[i] = round_word(pitch_buf[i]); // Q0
            pitch_buffer[i] = round_word(pitch_buf[i]);
        }

        // update old exc without random part
        st.old_exc
            .copy_from_slice(&buf[HARMONIC_AT + l_frame as usize..][..L_EXC_MEM_DEC as usize]);
    } else {
        // No harmonic part
        set16(&mut buf[EXC_AT..], 0, add(l_frame, shr(l_frame, 1)));

        for i in 0..nb_subfr as usize {
            pitch_buf[i] = l_deposit_h(st.pit_max); // 15Q16
            pgain_t[i] = 0;
            p_t[i] = L_SUBFR;
            pitch_buffer[i] = L_SUBFR;
        }

        st.bpf_gain_param = 0; // no BPF
    }

    HarmonicResult { alpha, tmp_tc }
}

/// The random part of `con_acelp`: the noise excitation (written from the start of `buf`),
/// high-pass filtered, its energy normalised and the background-level gain fade applied; updates
/// `Mode2_lp_gainc` and `past_gcode`. Returns the headroom `g_e` the noise carries and the
/// exponent `s_16` the reference's gain computation leaves behind (read again by the synthesis).
fn con_acelp_noise(
    st: &mut DecoderState,
    coder_type: i16,
    alpha: i16,
    a: &[i16],
    buf: &mut [i16; BUF_LEN],
) -> (i16, i16) {
    let l_frame = st.l_frame;
    let l_fir_fer = L_FIR_FER;

    // Construct the random part of excitation (5/2 L_frame + 2L_FIR_FER - 2), in Q0
    let mut tmp_seed = st.seed_acelp;
    let n = add(l_frame, sub(l_fir_fer, 1)) as usize;
    for slot in &mut buf[..n] {
        tmp_seed = own_random2(tmp_seed);
        *slot = tmp_seed; // Q0
    }
    st.seed_acelp = tmp_seed;
    let n2 = add(add(l_frame, shr(l_frame, 1)), sub(l_fir_fer, 1)) as usize;
    for slot in &mut buf[n..n2] {
        tmp_seed = own_random2(tmp_seed);
        *slot = tmp_seed; // Q0
    }

    // get filter coefficients
    let mut hp_filt = [0i16; 3];
    gen_plc_filt_bw_adap(st.sr_core, &mut hp_filt, 1, st.cummulative_damping); // Q15

    // PLC: [ACELP: Fade-out]; retrieve background level
    let mut tmp2 = shl(div_s(l_frame, shl(L_SUBFR, 3)), 3 - 15);

    let mut tmp: i16 = 32767; // 1.0f Q15
    let mut gain_synth_deemph_e: i16 = 0;
    let gain_synth_deemph = get_level_syn_deemph(
        core::slice::from_mut(&mut tmp),
        a,
        M,
        L_SUBFR,
        st.preemph_fac,
        tmp2,
        &mut gain_synth_deemph_e,
    );

    // gainCNG = st->cngTDLevel/gainSynthDeemph;
    let mut gain_cng: i16 = 0;
    let mut gain_cng_e: i16 = 0;
    basop_util_divide_mant_exp(
        st.cng_td_level,
        st.cng_td_level_e,
        gain_synth_deemph,
        gain_synth_deemph_e,
        &mut gain_cng,
        &mut gain_cng_e,
    );
    gain_cng_e = sub(gain_cng_e, 15 - 5); // Q15->Q5
    if gain_cng == 0 {
        gain_cng_e = 0;
    }

    let gain_32 = st.mode2_lp_gainc; // 15Q16, start-of-the-frame gain

    let ftmp = round_word(l_shl(gain_32, 1)); // Q0

    // saturation is expected here
    let mut tmp_16 = sub(shl(gain_cng, sub(gain_cng_e, 5)), ftmp);
    // in case of overflow:
    if i32::from(shl(ftmp, sub(gain_cng_e, 1))) - 32767 == 0 && gain_cng == 32767 {
        tmp_16 = 1;
    }

    if tmp_16 > 0 {
        gain_cng = ftmp; // Q0
        gain_cng_e = 5; // -> Q5
        let s_16 = norm_s(gain_cng);
        gain_cng = shl(gain_cng, s_16);
        gain_cng_e = sub(gain_cng_e, s_16);
    }

    // end-of-the-frame gain:
    // st->Mode2_lp_gainc = alpha * st->Mode2_lp_gainc + (1.0f - alpha) * gainCNG;
    let mut tmp_32 = mpy_32_16_1(st.mode2_lp_gainc, alpha); // Q31-16 = Q15
    let s_32 = norm_l(tmp_32);
    tmp_32 = l_shl(tmp_32, s_32);
    tmp_16 = round_word(tmp_32);
    let mut s_16 = negate(s_32);
    s_16 = sub(s_16, -1 - 15); // -> Q15

    tmp2 = sub(16384, alpha); // 1 in Q14
    tmp2 = mult(tmp2, gain_cng); // Q14+Q5 +1 -16 = Q4
    let mut s2 = norm_s(tmp2);
    tmp2 = shl(tmp2, s2);
    s2 = add(negate(s2), gain_cng_e);
    s2 = sub(s2, 4 - 15); // -> Q15

    let mut sum_m: i16 = 0;
    s_16 = basop_util_add_mant_exp(tmp_16, s_16, tmp2, s2, &mut sum_m);
    tmp_16 = sum_m;
    st.mode2_lp_gainc = l_shl(l_deposit_l(tmp_16), add(s_16, 1));
    if sub(st.last_good, UNVOICED_TRANSITION) == 0 && sub(coder_type, GENERIC) == 0 {
        st.mode2_lp_gainc = l_deposit_h(gain_cng); // Q21
        st.mode2_lp_gainc = l_shr(st.mode2_lp_gainc, sub(5, gain_cng_e)); // 15Q16, no scaling
    }

    high_pass_filtering(
        st.last_good,
        add(l_frame, shr(l_fir_fer, 1)),
        buf,
        &hp_filt,
        l_fir_fer,
    );

    // Find the energy normalization factor
    let pt_exc = (l_fir_fer / 2) as usize;
    let mut s_32: i16 = 0;
    let mut tmp_32 = dot_product_sq16_hq(0, &buf[pt_exc..], l_frame, &mut s_32, &mut st.stl);
    s_32 = add(s_32, 31 - 1);
    // scalingfactor is twice the headroom (at noise insertion onto the buffer), -1 (because of
    // mult) +31 (Result is Q31) +s_32 (output scalingfactor of dot_product)

    let div_index = l_shl(l_mac(-28000, l_frame, 95), 1 - 15);
    let tmp_16 = T_DIV_L_FRAME[div_index as usize];
    tmp_32 = mpy_32_16_1(tmp_32, tmp_16); // Q31 * 2^s_32 * 0Q15 * 2^-7

    s_32 = sub(s_32, 7); // tmp_32 is Q31 * 2^s_32

    // assure doing Isqrt not for 0
    let mut s_gain_inov: i16;
    if tmp_32 != 0 {
        s_gain_inov = s_32;
        tmp_32 = isqrt32(tmp_32, &mut s_gain_inov);
    } else {
        s_gain_inov = 0;
        tmp_32 = 0;
    }

    let mut gain_inov = round_word(tmp_32); // inverse sqrt

    // PLC: [ACELP: Fade-out]; linearly attenuate the gain through the frame
    let mut step_32 = l_sub(gain_32, st.mode2_lp_gainc); // 15Q16
    let div_index = extract_l(l_shl(l_mac(-28000, l_frame, 95), 1 - 15));
    step_32 = mpy_32_16_1(step_32, T_DIV_L_FRAME[div_index as usize]); // 15Q16 * 2^-7
    step_32 = l_shr(step_32, 7); // 15Q16

    if sub(st.last_good, UNVOICED_CLAS) == 0 && sub(coder_type, UNVOICED) != 0 {
        // attenuate somewhat on unstable unvoiced
        gain_inov = mult_r(gain_inov, 26214); // 0.8f Q15
    }

    if sub(st.last_good, UNVOICED_TRANSITION) >= 0 {
        // tilt_code = (float)(0.10f*(1.0f + st->voice_fac));
        let tilt_code = mac_r(214_748_368, 3277, st.voice_fac); // 0.1f Q31, 0.1f Q15

        gain_inov = mult_r(gain_inov, sub(32767, tilt_code)); // Q15 * 2^s_gain_inov
    }

    // non-causal ringing of the FIR filter
    // gain_16 = gain_32 = gain_inov * gain
    let mut gain_32 = mpy_32_16_1(gain_32, gain_inov); // 15Q16 * Q15 * 2^s_gain_inov
    gain_32 = l_shl(gain_32, add(15, s_gain_inov)); // Q31
    let mut gain_16 = round_word(gain_32); // Q15

    // step_32 = gain_inov * step
    step_32 = mpy_32_16_1(step_32, gain_inov);
    step_32 = l_shl(step_32, add(15, s_gain_inov)); // Q31

    // norm_s for gain*gain_inov at the end of the following loops
    let mut g_e = norm_s(round_word(l_shl(
        mpy_32_16_1(st.mode2_lp_gainc, gain_inov),
        add(15, s_gain_inov),
    )));
    g_e = norm_s(gain_16).min(g_e);
    gain_16 = shl(gain_16, g_e);
    gain_32 = l_shl(gain_32, g_e);
    step_32 = l_shl(step_32, g_e);
    let mut at = 0usize;
    for _ in 0..shr(l_fir_fer, 1) {
        // *pt_exc++ *= (gain_inov * gain)
        buf[at] = mult_r(buf[at], gain_16); // Q0 = Q0 * Q15
        at += 1;
    }

    // gain -= step; gain is updated after the loop and inside the loop gain_16 = gain_inov * gain
    // is modified using gain_inov * (gain-step) = gain_inov * gain - gain_inov * step
    for _ in 0..l_frame {
        buf[at] = mult_r(buf[at], gain_16);
        at += 1;

        gain_32 = l_sub(gain_32, step_32);
        gain_16 = round_word(gain_32);
    }

    for _ in 0..add(shr(l_frame, 1), l_fir_fer / 2) {
        buf[at] = mult_r(buf[at], gain_16);
        at += 1;
    }

    // store st->past_gcode: at this point gain is equal to st->Mode2_lp_gainc
    st.past_gcode = st.mode2_lp_gainc; // 15Q16

    (g_e, s_16)
}

/// The impulse response level of the synthesis filter `a` followed by the de-emphasis for every
/// subframe: `gain_lpc` (mantissa) and `gain_lpc_e` (exponent) of its reciprocal. `tmp` is the
/// de-emphasis memory, which the reference carries across the subframes of the unvoiced call and
/// restarts for each subframe of the voiced one (the caller resets it there).
fn con_acelp_lpc_gains(
    st: &DecoderState,
    a: &[i16],
    reset_deemph_memory: bool,
    stl: &mut crate::itu::stl2009::StlFlags,
    gain_lpc: &mut [i16; NB_SUBFR16K as usize],
    gain_lpc_e: &mut [i16; NB_SUBFR16K as usize],
) {
    let scale_h1: i16 = 5;
    let mut h1 = [0i16; (L_FRAME16K / 4 + 1) as usize];
    let mut mem = [0i16; M as usize];
    let mut tmp: i16 = 0;
    let mut p_a = 0usize;
    let mut i_subfr = 0;
    while i_subfr < st.l_frame {
        if reset_deemph_memory {
            tmp = 0;
        }
        set16(&mut h1, 0, L_SUBFR + 1);
        set16(&mut mem, 0, M);
        h1[0] = 1024; // 1.0f/((float)(1 << scale_h1)) Q15
        e_util_synthesis_in_place(0, &a[p_a..], &mut h1, L_SUBFR, &mut mem, 0, M); // impulse response of LPC
        deemph(&mut h1, st.preemph_fac, L_SUBFR, &mut tmp); // impulse response of deemph

        // impulse response level = gain introduced by synthesis+deemphasis
        // gain_lpc[i_subfr/L_SUBFR] = 1.f/(float)sqrt(dotp( h1, h1, L_SUBFR));
        let k = (i_subfr / L_SUBFR) as usize;
        let mut exponent: i16 = 0;
        let mut tmp_32 = dot_product_sq16_hq(0, &h1, L_SUBFR, &mut exponent, stl);
        tmp_32 = tmp_32.max(1);
        exponent = add(exponent, 2 * scale_h1);
        gain_lpc[k] = round_word(isqrt32(tmp_32, &mut exponent));
        gain_lpc_e[k] = exponent;

        p_a += (M + 1) as usize; // pointer move
        i_subfr += L_SUBFR;
    }
}

/// Scale `exc[0..L_frame * 3/2]` (the excitation at `exc_at` of `buf`, or `exc_unv`) by the
/// level of the synthesis filter's response, `last_gain_syn_deemph * gain_lpc`.
fn con_acelp_scale_excitation(
    st: &DecoderState,
    exc: &mut [i16],
    gain_lpc: &[i16; NB_SUBFR16K as usize],
    gain_lpc_e: &[i16; NB_SUBFR16K as usize],
) -> i16 {
    let l_frame = st.l_frame;
    let mut g: i16 = 0;
    let mut i_subfr = 0;
    while i_subfr < l_frame {
        let k = (i_subfr / L_SUBFR) as usize;
        g = mult_r(st.last_gain_syn_deemph, gain_lpc[k]);
        let g_e = add(st.last_gain_syn_deemph_e, gain_lpc_e[k]);
        g = shl(g, g_e);
        for i in 0..L_SUBFR {
            // exc[i_subfr + i] *= st->last_gain_syn_deemph*gain_lpc[j];
            let at = (i_subfr + i) as usize;
            exc[at] = mult_r(exc[at], g);
        }
        i_subfr += L_SUBFR;
    }
    for i in l_frame..add(l_frame, shr(l_frame, 1)) {
        exc[i as usize] = mult_r(exc[i as usize], g);
    }
    g
}

/// The synthesis of the harmonic excitation: levels from the LPC filters of the last good frame
/// (`a`), the rescaled memory, `memsynPrecission` for long losses, the synthesis of the frame in
/// `buf[SYN_AT..]` and of the overlap part.
fn con_acelp_voiced_synthesis(
    st: &mut DecoderState,
    a: &[i16],
    buf: &mut [i16; BUF_LEN],
    mem_syn: &mut [i16; M as usize],
    s_16: &mut i16,
    gain_lpc: &mut [i16; NB_SUBFR16K as usize],
    gain_lpc_e: &mut [i16; NB_SUBFR16K as usize],
) {
    let l_frame = st.l_frame;
    let mut stl = st.stl;
    con_acelp_lpc_gains(st, a, true, &mut stl, gain_lpc, gain_lpc_e);
    st.stl = stl;

    con_acelp_scale_excitation(st, &mut buf[EXC_AT..], gain_lpc, gain_lpc_e);

    // rescale the synthesis memory
    let mut q_syn_new = st.q_syn;
    let mut q_syn = st.q_syn;
    rescale_mem_syn(
        st.q_exc,
        &mut q_syn_new,
        &mut q_syn,
        mem_syn,
        None,
        M,
        l_frame,
    );
    let synth_scaling = sub(st.q_exc, q_syn);

    // in case of more than 5 consecutive concealed frames, improve precision of synthesis
    mem_syn_precission(st.nb_lost_cmpt, mem_syn, &mut buf[EXC_AT..], l_frame, s_16);
    let mut p_a = 0usize;
    let mut i_subfr = 0;
    {
        let (syn_region, exc_region) = buf.split_at_mut(EXC_AT);
        while i_subfr < l_frame {
            e_util_synthesis(
                synth_scaling,
                &a[p_a..],
                &exc_region[i_subfr as usize..],
                &mut syn_region[SYN_AT + i_subfr as usize..],
                L_SUBFR,
                mem_syn,
                1,
                M,
            );
            p_a += (M + 1) as usize;
            i_subfr += L_SUBFR;
        }
        let mut mem_syn2 = *mem_syn;
        // synthesize ola
        e_util_synthesis(
            synth_scaling,
            &a[p_a - (M + 1) as usize..],
            &exc_region[i_subfr as usize..],
            &mut syn_region[SYN_AT + i_subfr as usize..],
            l_frame / 2,
            &mut mem_syn2,
            0,
            M,
        );
    }
}

/// The synthesis of the noise excitation through the comfort noise LPC filters `Aq_cng`: levels,
/// rescaling, `memsynPrecission`, synthesis of the frame (and, for a last good frame below
/// `UNVOICED_TRANSITION`, of the overlap part), and the scaling back after a long loss.
/// Returns the synthesis Q (`Qf_syn`) and stores it in `st.q_syn`.
fn con_acelp_unvoiced_synthesis(
    st: &mut DecoderState,
    exc_unv: &mut [i16; FRAME_AND_HALF_MAX],
    syn_unv: &mut [i16; FRAME_AND_HALF_MAX],
    mem_syn_unv: &mut [i16; M as usize],
    mem_syn: &mut [i16; M as usize],
    s_16: &mut i16,
    gain_lpc: &mut [i16; NB_SUBFR16K as usize],
    gain_lpc_e: &mut [i16; NB_SUBFR16K as usize],
) -> i16 {
    let l_frame = st.l_frame;
    let aq_cng = st.aq_cng;
    let mut stl = st.stl;
    // the de-emphasis memory runs on across the subframes here
    con_acelp_lpc_gains(st, &aq_cng, false, &mut stl, gain_lpc, gain_lpc_e);
    st.stl = stl;

    con_acelp_scale_excitation(st, exc_unv, gain_lpc, gain_lpc_e);

    // update Qf_syn
    let mut q_syn_new = st.q_syn;
    let mut q_syn = st.q_syn;
    rescale_mem_syn(
        st.q_exc,
        &mut q_syn_new,
        &mut q_syn,
        mem_syn_unv,
        None,
        M,
        l_frame,
    );
    let synth_scaling = sub(st.q_exc, q_syn);
    st.q_syn = q_syn;

    let mut p_a = 0usize;

    // in case of more than 5 consecutive concealed frames, improve precision of synthesis
    mem_syn_precission(st.nb_lost_cmpt, mem_syn_unv, exc_unv, l_frame, s_16);

    let mut i_subfr = 0;
    while i_subfr < l_frame {
        e_util_synthesis(
            synth_scaling,
            &aq_cng[p_a..],
            &exc_unv[i_subfr as usize..],
            &mut syn_unv[i_subfr as usize..],
            L_SUBFR,
            mem_syn_unv,
            1,
            M,
        );
        p_a += (M + 1) as usize;
        i_subfr += L_SUBFR;
    }
    st.mem_syn_unv_back.copy_from_slice(mem_syn_unv);

    if sub(st.last_good, UNVOICED_TRANSITION) < 0 {
        mem_syn.copy_from_slice(mem_syn_unv);
        // unvoiced for ola
        e_util_synthesis(
            synth_scaling,
            &aq_cng[p_a - (M + 1) as usize..],
            &exc_unv[i_subfr as usize..],
            &mut syn_unv[i_subfr as usize..],
            shr(l_frame, 1),
            mem_syn_unv,
            0,
            M,
        );
    }

    if sub(st.nb_lost_cmpt, 5) > 0 && *s_16 > 0 {
        // scale back mem_syn_unv, exc_unv and synthesis
        scale_sig(mem_syn_unv, M, negate(*s_16));
        if sub(st.last_good, UNVOICED_TRANSITION) < 0 {
            scale_sig(mem_syn, M, negate(*s_16));
            scale_sig(syn_unv, add(shr(l_frame, 1), l_frame), negate(*s_16));
        } else {
            scale_sig(syn_unv, l_frame, negate(*s_16));
        }

        scale_sig(&mut st.mem_syn_unv_back, M, negate(*s_16));
    }
    q_syn
}

/// The updates of `con_acelp` that end the frame: the memories of the synthesis, the overlap
/// buffers for the next ACELP or TCX frame (with the TDAC aliasing and window), the full band
/// copies and the 16 kHz memories of the MODE1 decoder.
fn con_acelp_update_memories(
    st: &mut DecoderState,
    buf: &mut [i16; BUF_LEN],
    mem_syn: &[i16; M as usize],
    synth: &mut [i16],
    pitch_buf: &[i32; NB_SUBFR16K as usize],
) {
    let l_frame = st.l_frame;
    let half = shr(l_frame, 1) as usize;
    let frame = l_frame as usize;

    // update ACELP synthesis memory
    st.mem_syn2.copy_from_slice(mem_syn);
    st.mem_syn_r
        .copy_from_slice(&buf[SYN_AT + frame - L_SYN_MEM as usize..][..L_SYN_MEM as usize]);

    // deemphasis and output synth
    let mut tmp_deemph = st.syn[M as usize];

    e_util_deemph2(
        st.q_syn,
        &mut buf[SYN_AT..],
        st.preemph_fac,
        add(l_frame, shr(l_frame, 1)),
        &mut tmp_deemph,
    );

    synth[..frame].copy_from_slice(&buf[SYN_AT..SYN_AT + frame]);

    buffer_copy_fx(
        &buf[SYN_AT + frame - half..],
        &mut st.old_syn_overl,
        shr(l_frame, 1),
        0,
        -1,
        0,
        0,
    );

    // save last half frame if next frame is TCX
    buffer_copy_fx(
        &buf[SYN_AT + frame..],
        &mut st.syn_overl_tdac,
        shr(l_frame, 1),
        0,
        -1,
        0,
        0,
    );
    copy(
        &buf[SYN_AT + frame - M as usize - 1..],
        &mut st.syn,
        add(1, M),
    );

    // update old_Aq: the last subframe's comfort noise LPC filter
    let last_aq = (l_frame / L_SUBFR - 1) as usize * (M + 1) as usize;
    let aq_cng = st.aq_cng;
    copy(&aq_cng[last_aq..], &mut st.old_aq_12_8, add(M, 1));

    copy(&buf[SYN_AT + frame..], &mut st.syn_overl, shr(l_frame, 1));

    // create aliasing and windowing
    let w1 = st.tcx_cfg.tcx_mdct_window_length;
    let w2 = shr(w1, 1);

    st.tcx_cfg.tcx_curr_overlap_mode = FULL_OVERLAP;

    let n = extract_h(l_mult(l_frame, 9216)); // N_ZERO_MDCT_NS/FRAME_SIZE_NS Q15

    st.q_old_wtda_lb = get_scale_factor16(&buf[SYN_AT + frame - n as usize..], sub(l_frame, n));

    buffer_copy_fx(
        &buf[SYN_AT + frame - n as usize..],
        &mut st.old_out_lb,
        sub(l_frame, n),
        0,
        0,
        st.q_old_wtda_lb,
        0,
    );
    let window = st.tcx_cfg.tcx_mdct_window;
    for i in 0..w2 {
        let at = (i + n) as usize;
        let re = window[i as usize].v.re;
        st.old_out_lb[at] = round_word(mpy_32_16_1(l_mult(re, re), st.old_out_lb[at]));
    }
    for i in w2..w1 {
        let at = (i + n) as usize;
        let im = window[(w2 - 1 - (i - w2)) as usize].v.im;
        st.old_out_lb[at] = round_word(mpy_32_16_1(l_mult(im, im), st.old_out_lb[at]));
    }
    set16(&mut st.old_out_lb[(w1 + n) as usize..], 0, n);

    st.q_old_wtda = st.q_old_wtda_lb;

    for i in 0..w2 {
        buf[i as usize] = mult_r(st.syn_overl_tdac[i as usize], window[i as usize].v.re);
    }
    for i in w2..w1 {
        buf[i as usize] = mult_r(
            st.syn_overl_tdac[i as usize],
            window[(w1 - 1 - i) as usize].v.im,
        );
    }

    for i in 0..w2 {
        st.syn_overl_tdac[i as usize] = add(buf[i as usize], buf[(w1 - 1 - i) as usize]);
        // A-D
    }
    for i in 0..w2 {
        st.syn_overl_tdac[(w2 + i) as usize] =
            add(buf[(w2 + i) as usize], buf[(w1 - 1 - w2 - i) as usize]); // B-C
    }

    for i in 0..w2 {
        st.syn_overl_tdac[i as usize] =
            mult_r(st.syn_overl_tdac[i as usize], window[i as usize].v.re);
    }
    for i in w2..w1 {
        st.syn_overl_tdac[i as usize] = mult_r(
            st.syn_overl_tdac[i as usize],
            window[(w1 - 1 - i) as usize].v.im,
        );
    }

    // update memory for full band
    lerp(
        &st.syn_overl_tdac,
        &mut st.syn_overl_tdacfb,
        shr(st.l_frame_tcx, 1),
        shr(l_frame, 1),
    );
    lerp(
        &st.syn_overl,
        &mut st.syn_overl_fb,
        shr(st.l_frame_tcx, 1),
        shr(l_frame, 1),
    );
    lerp(&st.old_out_lb, &mut st.old_out, st.l_frame_tcx, l_frame);

    // copy total excitation exc2 as 16kHz for acelp mode1 decoding
    lerp(&buf[EXC_AT..], &mut st.old_exc2, L_EXC_MEM, l_frame);
    lerp(&buf[SYN_AT..], &mut st.old_syn2, L_EXC_MEM, l_frame);
    st.bfi_pitch = shl(round_word(pitch_buf[st.nb_subfr as usize - 1]), 6);
    st.bfi_pitch_frame = l_frame;
}

/// `memsynPrecission`: after more than five lost frames (a quiet synthesis), shift the synthesis
/// memory and the excitation up by the headroom of both (less 5 bits), `s_16` bits.
fn mem_syn_precission(
    nb_lost_cmpt: i16,
    mem_syn: &mut [i16],
    exc: &mut [i16],
    len: i16,
    s_16: &mut i16,
) {
    if sub(nb_lost_cmpt, 5) > 0 {
        let mut tmp: i16 = 0;
        let mut max: i16 = 0;
        *s_16 = 0;

        // check energy of mem_syn; saturation doesn't matter
        for &value in &mem_syn[..M as usize] {
            tmp = add(tmp, abs_s(value));
        }
        // if there is energy in scale_syn, then increase precision
        if abs_s(tmp) > 0 {
            let sf_mem_syn = get_scale_factor16(mem_syn, M);
            let tmp_loop = add(shr(len, 1), len);
            for &value in &exc[..tmp_loop.max(0) as usize] {
                max = max.max(abs_s(value));
            }
            let mut sf_exc = norm_s(max);
            if max == 0 {
                sf_exc = 16;
            }
            // 5 bits of headroom, scaling not smaller than 0
            *s_16 = sub(sf_exc.min(sf_mem_syn), 5).max(0);
            scale_sig(mem_syn, M, *s_16);
            scale_sig(exc, add(shr(len, 1), len), *s_16);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_syn_precission_leaves_a_short_loss_alone() {
        let mut mem_syn = [100i16; M as usize];
        let mut exc = [200i16; 24];
        let mut s_16 = 7;
        mem_syn_precission(5, &mut mem_syn, &mut exc, 16, &mut s_16);
        assert_eq!(s_16, 7);
        assert_eq!(mem_syn, [100i16; M as usize]);
        assert_eq!(exc, [200i16; 24]);
    }

    #[test]
    fn mem_syn_precission_scales_a_quiet_synthesis_up() {
        let mut mem_syn = [10i16; M as usize];
        let mut exc = [20i16; 24];
        let mut s_16 = -1;
        mem_syn_precission(6, &mut mem_syn, &mut exc, 16, &mut s_16);
        // headroom of 20 is 10 bits, of 10 is 11; less 5 bits of reserve
        assert_eq!(s_16, 5);
        assert_eq!(mem_syn, [320i16; M as usize]);
        assert_eq!(exc, [640i16; 24]);
    }

    #[test]
    fn mem_syn_precission_without_memory_energy_sets_no_scaling() {
        let mut mem_syn = [0i16; M as usize];
        let mut exc = [20i16; 24];
        let mut s_16 = -1;
        mem_syn_precission(8, &mut mem_syn, &mut exc, 16, &mut s_16);
        assert_eq!(s_16, 0);
        assert_eq!(exc, [20i16; 24]);
    }

    #[test]
    fn the_buffer_layout_matches_the_reference() {
        assert_eq!(BUF_LEN, 976);
        assert_eq!(EXC_AT, 496);
        assert_eq!(HARMONIC_AT, 16);
    }
}
