//! `decoder_tcx_post` of TS 26.442 `lib_dec/dec_tcx.c` (TS 26.445 §6.2.4 frame loss concealment):
//! the time-domain fade-out and the LPC-gain compensation of a concealed TCX frame, the
//! background level estimate, and the memory update after every TCX frame.

use super::at;
use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{ACELP_CORE, L_FRAME_MAX, TCX_TONAL, UNVOICED_CLAS};
use crate::evs::com::basop_util::{
    basop_util_add_mant_exp, basop_util_divide_mant_exp, get_scale_factor16, sqrt16,
};
use crate::evs::com::tcx_utils::get_inv_frame_len;
use crate::evs::dec::er_util::minimum_statistics;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::tcx_utils_dec::tcx_decoder_memory_update;
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_deposit_h, l_mult, l_shl, l_sub, mult_r, negate, norm_l,
    round_word, shl, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, l_shl_r, mpy_32_32_ss};

/// `decoder_tcx_post`: finish a TCX frame whose core-rate output is `synth` and whose output-rate
/// output is `synth_fb`, with the LPC filter `a` of the frame. A concealed frame (`bfi != 0`) is
/// faded out towards the background level; the memories of the next frame are updated.
pub fn decoder_tcx_post(
    st: &mut DecoderState,
    synth: &mut [i16],
    synth_fb: &mut [i16],
    a: &[i16],
    bfi: i16,
) {
    let mut xn_buf = [0i16; L_FRAME_MAX as usize];
    let l_frame = at(i32::from(st.l_frame));

    // TCX output
    xn_buf[..l_frame].copy_from_slice(&synth[..l_frame]);

    // first TCX frame after ACELP; overwrite ltp initialization done during acelp PLC
    if st.bfi == 0 && st.prev_bfi != 0 && sub(st.last_core, ACELP_CORE) == 0 {
        st.tcxltp_last_gain_unmodified = 0;
    }
    if bfi != 0 && st.use_partial_copy == 0 {
        post_lpc_gain_compensation(st, &mut xn_buf, synth_fb);
    }

    // PLC: [TCX: Fade-out]; PLC: estimate and update CNG energy
    let (level_syn, level_syn_e) = post_level_of_synthesis(st, synth_fb, bfi);

    // PLC: [TCX: Fade-out]; PLC: fade-out in time domain
    if bfi != 0 {
        post_fade_out(st, &mut xn_buf, synth_fb, level_syn, level_syn_e);
    }

    // Memory update: update synth, exc and old_Aq
    let mut syn = st.syn;
    tcx_decoder_memory_update(&xn_buf, synth, st.l_frame, a, st, &mut syn, 0);
    st.syn = syn;

    // PLC: [TCX: Memory update]
    post_update_pitch_memories(st);
}

/// The LPC gain compensation of a concealed frame, in time domain, for the full-band output
/// (only when the waveform adjustment is not used) and the core-rate output `xn_buf`.
fn post_lpc_gain_compensation(st: &DecoderState, xn_buf: &mut [i16], synth_fb: &mut [i16]) {
    // run lpc gain compensation not for waveform adjustment
    if st.enable_plc_waveadjust == 0 || sub(st.plc_info.concealment_method, TCX_TONAL) == 0 {
        // gainHelperFB, stepCompensateFB (Q28)
        let mut tmp32_1 = l_shl_r(l_deposit_h(st.gain_helper), sub(st.gain_helper_e, 31 - 28));
        let mut tmp32_2 = l_shl_r(
            l_deposit_h(st.step_compensate),
            sub(st.step_compensate_e, 31 - 28),
        );

        let (high, _low) = mpy_32_32_ss(
            tmp32_2, // Q28
            l_shl(
                l_mult0(st.l_frame, get_inv_frame_len(st.l_frame_tcx)), // Q21
                8,
            ), // Q29
        ); // Q26
        tmp32_2 = high;

        tmp32_2 = l_shl(tmp32_2, 3 - 1); // Q28

        for sample in &mut synth_fb[..at(i32::from(st.l_frame_tcx))] {
            let tmp32 = l_shl(tmp32_1, -(28 - 15)); // 16Q15
            *sample = round_word(l_shl(mpy_32_16_1(tmp32, *sample), 16));
            tmp32_1 = l_sub(tmp32_1, tmp32_2);
        }
    }
    // gainHelper, stepCompensate (Q28)
    let mut tmp32_1 = l_shl_r(l_deposit_h(st.gain_helper), sub(st.gain_helper_e, 31 - 28));
    let tmp32_2 = l_shl_r(
        l_deposit_h(st.step_compensate),
        sub(st.step_compensate_e, 31 - 28),
    );
    for sample in &mut xn_buf[..at(i32::from(st.l_frame))] {
        let tmp32 = l_shl(tmp32_1, -(28 - 15)); // 16Q15
        *sample = extract_l(mpy_32_16_1(tmp32, *sample));
        tmp32_1 = l_sub(tmp32_1, tmp32_2);
    }
}

/// `level_syn = sqrt(dot_product(synthFB, synthFB) / L_frame)` as a mantissa and exponent, and,
/// for a good TCX-only frame of unvoiced class, the minimum statistics of the background level.
fn post_level_of_synthesis(st: &mut DecoderState, synth_fb: &[i16], bfi: i16) -> (i16, i16) {
    let frame_tcx = at(i32::from(st.l_frame_tcx));
    let mut s = sub(get_scale_factor16(synth_fb, st.l_frame_tcx), 4);
    let mut tmp32 = 0i32;
    for &sample in &synth_fb[..frame_tcx] {
        let tmp1 = shl(sample, s);
        tmp32 = l_mac0(tmp32, tmp1, tmp1);
    }
    tmp32 = mpy_32_16_1(tmp32, get_inv_frame_len(st.l_frame_tcx));
    let tmp2 = norm_l(tmp32);
    let tmp1 = round_word(l_shl(tmp32, tmp2));
    // 6: table lookup for inverse framelength
    s = sub(sub(sub(1, shl(s, 1)), 6), tmp2);
    let level_syn = sqrt16(tmp1, &mut s); // Q0

    let level_syn_e = add(s, 15);
    if bfi == 0 && st.tcxonly != 0 && sub(st.clas_dec, UNVOICED_CLAS) == 0 {
        let mut qnew_level_background_trace: i16 = 0;
        minimum_statistics(
            &mut st.con_noise_level_memory,         // Q15
            &mut st.con_noise_level_index,          // Q0
            &mut st.con_curr_level_index,           // Q0
            &mut st.con_cng_level_background_trace, // Q15
            &mut st.con_last_frame_level,           // Q15
            level_syn,                              // Q15
            &mut st.con_noise_level_memory_e,
            st.con_cng_level_background_trace_e,
            &mut qnew_level_background_trace,
            &mut st.con_last_frame_level_e,
            level_syn_e, // scaling of level_syn
        );

        // note: All parameters being different from Q0 have to have the same Q-format
        st.con_cng_level_background_trace_e = qnew_level_background_trace;
    }
    (level_syn, level_syn_e)
}

/// The fade-out of a concealed frame towards the CNG / background level.
fn post_fade_out(
    st: &mut DecoderState,
    xn_buf: &mut [i16],
    synth_fb: &mut [i16],
    level_syn: i16,
    level_syn_e: i16,
) {
    let mut gain_cng: i16 = 1;
    let mut gain_cng_e: i16 = 14 + 15 + 6; // gainCNG is 2`097`152 - should be enough in case tracinglevel =~0
    if st.tcxonly != 0 {
        // gainCNG = st->conCngLevelBackgroundTrace/(tracingLevel+0.01f);
        if level_syn != 0 {
            basop_util_divide_mant_exp(
                st.con_cng_level_background_trace,
                st.con_cng_level_background_trace_e,
                level_syn,
                level_syn_e,
                &mut gain_cng,
                &mut gain_cng_e,
            );
        }
    } else if level_syn != 0 {
        // gainCNG = st->cngTDLevel/(tracingLevel+0.01f);
        basop_util_divide_mant_exp(
            st.cng_td_level,
            st.cng_td_level_e,
            level_syn,
            level_syn_e,
            &mut gain_cng,
            &mut gain_cng_e,
        );
    }

    if sub(st.nb_lost_cmpt, 1) == 0 {
        st.conceal_eof_gain = 16384; // 1.0f Q14
    }

    // step = (conceal_eof_gain - (conceal_eof_gain * damping + gainCNG * (1 - damping))) / L_frame
    let mut tmp1: i16 = 0;
    let mut tmp2 = basop_util_add_mant_exp(
        mult_r(
            st.conceal_eof_gain, /* Q14 */
            st.damping,          /* Q14 */
        ),
        15 - 13,                                                       // -> Q15
        mult_r(gain_cng /* Q15 */, sub(0x4000, st.damping /* Q14 */)), // Q14
        add(gain_cng_e, 15 - 14),                                      // -> Q15
        &mut tmp1,
    );
    let sum = tmp1;
    tmp2 = basop_util_add_mant_exp(st.conceal_eof_gain, 15 - 14, negate(sum), tmp2, &mut tmp1);

    // Q30; 6: scaling from table lookup, 1: go to Q30
    let step = l_shl(
        l_mult(tmp1, get_inv_frame_len(st.l_frame)),
        sub(tmp2, 6 + 1),
    );
    let mut conceal_eof_gain_fb = l_deposit_h(st.conceal_eof_gain); // Q30
    let (step_fb_high, _low) = mpy_32_32_ss(
        step,
        l_shl(l_mult0(st.l_frame, get_inv_frame_len(st.l_frame_tcx)), 8),
    );
    let step_fb = l_shl(step_fb_high, 3 - 1); // Q30

    for sample in &mut synth_fb[..at(i32::from(st.l_frame_tcx))] {
        *sample = round_word(l_shl(mpy_32_16_1(conceal_eof_gain_fb, *sample), 1));
        conceal_eof_gain_fb = l_sub(conceal_eof_gain_fb, step_fb);
    }
    let mut conceal_eof_gain32 = l_deposit_h(st.conceal_eof_gain); // Q30
    for sample in &mut xn_buf[..at(i32::from(st.l_frame))] {
        *sample = round_word(l_shl(mpy_32_16_1(conceal_eof_gain32 /* Q30 */, *sample), 1));
        conceal_eof_gain32 = l_sub(conceal_eof_gain32, step);
    }
    st.conceal_eof_gain = round_word(conceal_eof_gain32); // Q14
                                                          // run lpc gain compensation not for waveform adjustment
    if st.enable_plc_waveadjust == 0 || sub(st.plc_info.concealment_method, TCX_TONAL) == 0 {
        st.plc_info.recovery_gain = extract_h(l_shl(
            mpy_32_16_1(conceal_eof_gain_fb, st.last_concealed_gain_syn_deemph),
            st.last_concealed_gain_syn_deemph_e,
        )); // Q30->Q14
    } else {
        st.plc_info.recovery_gain = extract_h(conceal_eof_gain_fb); // Q14
    }
    st.plc_info.step_concealgain = round_word(l_shl(
        l_mult0(
            round_word(step),
            round_word(l_shl(
                l_mult0(st.l_frame, get_inv_frame_len(st.l_frame_tcx)),
                8,
            )),
        ),
        3,
    )); // Q15
}

/// The pitch and pitch gain histories after a TCX frame.
fn post_update_pitch_memories(st: &mut DecoderState) {
    let nb_subfr = at(i32::from(st.nb_subfr));
    st.old_pitch_buf[0] = st.old_pitch_buf[nb_subfr];
    st.old_pitch_buf[1] = st.old_pitch_buf[nb_subfr + 1];
    // Copy32(&old_pitch_buf[nb_subfr+2], &old_pitch_buf[2], nb_subfr): forward copy
    for i in 0..nb_subfr {
        st.old_pitch_buf[2 + i] = st.old_pitch_buf[nb_subfr + 2 + i];
    }
    let old_fpitch = st.old_fpitch;
    st.old_pitch_buf[nb_subfr + 2..2 * nb_subfr + 2].fill(old_fpitch);
    st.bfi_pitch = shl(round_word(st.old_fpitch), 6);
    st.bfi_pitch_frame = st.l_frame;

    st.mem_pitch_gain[2 * nb_subfr + 1] = st.mem_pitch_gain[nb_subfr + 1];
    st.mem_pitch_gain[2 * nb_subfr] = st.mem_pitch_gain[nb_subfr];

    for i in 0..nb_subfr {
        st.mem_pitch_gain[2 * nb_subfr - 1 - i] = st.mem_pitch_gain[nb_subfr - 1 - i];
        st.mem_pitch_gain[nb_subfr - 1 - i] = st.tcxltp_last_gain_unmodified;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pitch_memories_shift_one_frame_and_refill_with_the_last_pitch() {
        let mut st = Box::new(DecoderState::zeroed());
        st.nb_subfr = 4;
        for (i, value) in st.old_pitch_buf.iter_mut().enumerate() {
            *value = i as i32 * 10;
        }
        for (i, value) in st.mem_pitch_gain.iter_mut().enumerate() {
            *value = i as i16;
        }
        st.old_fpitch = 1234;
        st.tcxltp_last_gain_unmodified = 77;
        st.l_frame = 256;
        post_update_pitch_memories(&mut st);
        assert_eq!(st.old_pitch_buf[..4], [40, 50, 60, 70]);
        assert_eq!(st.old_pitch_buf[6..10], [1234; 4]);
        assert_eq!(st.mem_pitch_gain[..4], [77; 4]);
        assert_eq!(st.mem_pitch_gain[4..8], [0, 1, 2, 3]);
        assert_eq!(st.bfi_pitch_frame, 256);
    }
}
