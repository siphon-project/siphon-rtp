//! The pitch-only excitation of the GSC (audio) coder's low band (TS 26.442
//! `lib_dec/dec_pit_exc_fx.c`; TS 26.445 §6.1.1.2.6 / §7.1.1.2.6).

use crate::evs::cnst::{L_FRAME, L_SUBFR, M};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::est_tilt::est_tilt;
use crate::evs::com::pred_lt4::pred_lt4;
use crate::evs::com::scale_mem::rescale_exc;
use crate::evs::com::tools::acelp_dec_total_exc;
use crate::evs::dec::gain_dec::{gain_dec_mless, lp_gain_updt};
use crate::evs::dec::inov_dec::inov_decode;
use crate::evs::dec::pit_dec::pit_decode;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{DIC_GP_FX, PITCH_INTER4_2};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_mult, l_shl, mult_r, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::l_mult0;

const FRAME: usize = L_FRAME as usize;
const SUBFR: usize = L_SUBFR as usize;
const LP_ORDER: usize = M as usize + 1;

/// `dec_pit_exc_fx`: decode the adaptive-codebook excitation of the frame over `nb_subfr_fx`
/// subframes of 256/`nb_subfr_fx` samples: per subframe the pitch lag and, for GSC noisy speech, a
/// 7.2 kbit/s algebraic innovation with memory-less gains, otherwise a 4-bit pitch gain alone.
/// `pitch_buf_fx` and `gain_buf` receive one value per 64-sample subframe (repeated for the longer
/// subframes); the low-pass FEC gains are updated.
///
/// `exc_fx[exc_at..]` and `bwe_exc_fx[bwe_exc_at..]` are where the reference's `exc_fx` and
/// `bwe_exc_fx` point (both carry history before the frame). `code_fx` (one 64-sample subframe)
/// receives the innovation of the last subframe.
pub fn dec_pit_exc(
    st: &mut DecoderState,
    aq_fx: &[i16],
    coder_type_fx: i16,
    es_pred_fx: i16,
    pitch_buf_fx: &mut [i16],
    code_fx: &mut [i16],
    exc_fx: &mut [i16],
    exc_at: usize,
    bwe_exc_fx: &mut [i16],
    bwe_exc_at: usize,
    nb_subfr_fx: i16,
    gain_buf: &mut [i16],
) {
    let mut t0_fx: i16 = 0;
    let mut t0_frac_fx: i16 = 0;
    let mut t0_min_fx: i16 = 0;
    let mut t0_max_fx: i16 = 0;
    let mut gain_pit_fx: i16 = 0;
    let mut gain_inov_fx: i16 = 0;
    let mut norm_gain_code_fx: i32 = 0;
    let mut voice_fac_fx: i16 = 0;
    // `exc2_bidon - i_subfr` in the reference: a scratch that `Acelp_dec_total_exc` writes at
    // `i_subfr` and nothing reads.
    let mut exc2_bidon = [0_i16; FRAME + SUBFR];

    let (local_br_fx, pitch_ct_fx, pitch_br_fx) = if sub(st.gsc_noisy_speech, 1) == 0 {
        (7200_i16, 3_i16, 7200_i16)
    } else {
        (7200, 5, extract_l(st.core_brate))
    };

    let mut gain_code_fx: i32 = 0;
    let mut pitch_limit_flag: i16 = 1; // always restrained pitch Q range in IC mode
    let l_subfr_fx = mult_r(L_FRAME, div_s(1, nb_subfr_fx));
    let mut p_aq_at: usize = 0; // pointer to interpolated LPC parameters
    let mut pt_pitch_at: usize = 0; // pointer to the pitch buffer
    let mut pt_gain_at: usize = 0; // pointer to the gain buffer

    let mut i_subfr_fx: i16 = 0;
    while i_subfr_fx < L_FRAME {
        let i_subfr = i_subfr_fx as usize;

        // Decode pitch lag
        pitch_buf_fx[pt_pitch_at] = pit_decode(
            st,
            i32::from(pitch_br_fx),
            0,
            L_FRAME,
            i_subfr_fx,
            pitch_ct_fx,
            &mut pitch_limit_flag,
            &mut t0_fx,
            &mut t0_frac_fx,
            &mut t0_min_fx,
            &mut t0_max_fx,
            l_subfr_fx,
        );

        // Find the adaptive codebook vector - ACELP long-term prediction
        pred_lt4(
            exc_fx,
            exc_at + i_subfr,
            t0_fx,
            t0_frac_fx,
            add(l_subfr_fx, 1),
            &PITCH_INTER4_2,
            16, // L_INTERPOL2
            4,  // PIT_UP_SAMP
        );

        if sub(st.gsc_noisy_speech, 1) == 0 {
            // Innovation decoding
            let p_aq = &aq_fx[p_aq_at.min(aq_fx.len())..];
            let tilt_code = st.tilt_code;
            inov_decode(
                st,
                i32::from(local_br_fx),
                0,
                L_FRAME,
                2, // LOCAL_CT = GENERIC - 1 (UNVOICED)
                1,
                i_subfr_fx,
                -1,
                p_aq,
                tilt_code,
                pitch_buf_fx[pt_pitch_at],
                code_fx,
            );
            // Gain decoding, estimate spectrum tilt and voicing
            gain_dec_mless(
                st,
                i32::from(local_br_fx),
                L_FRAME,
                2,
                i_subfr_fx,
                -1,
                code_fx,
                es_pred_fx,
                &mut gain_pit_fx,
                &mut gain_code_fx,
                &mut gain_inov_fx,
                &mut norm_gain_code_fx,
            );
            st.tilt_code = est_tilt(
                &exc_fx[exc_at + i_subfr..],
                gain_pit_fx,
                code_fx,
                gain_code_fx,
                &mut voice_fac_fx,
                0,
            );
        } else {
            let nbits: i16 = 4;
            code_fx[..SUBFR].fill(0);
            st.tilt_code = 0;

            let pit_idx_fx = get_next_indice(st, nbits) as usize;
            gain_pit_fx = add(9590, DIC_GP_FX[pit_idx_fx & 15]);
            if st.ber_detect != 0 {
                // In case of bitstream errors, take the last good pitch gain
                gain_pit_fx = st.lp_gainp;
            }
            gain_code_fx = l_mult0(sub(32767, shl(gain_pit_fx, 1)).max(16384), st.lp_gainc);
        }

        // Find the total excitation; `HIBND_ACB_L_FAC` is 5/2
        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            exc_fx,
            exc_at + i_subfr,
            Some((&mut *bwe_exc_fx, bwe_exc_at + i_subfr * 5 / 2)),
            Some(&mut st.last_exc_dct_in),
            l_subfr_fx,
            (i32::from(l_subfr_fx) * 5 / 2) as i16,
            gain_code_fx,
            &mut st.q_exc,
            &mut st.q_subfr,
            None,
            i_subfr_fx,
            coder_type_fx,
        );

        let gain_code16 = round_word(l_shl(gain_code_fx, st.q_exc)); // Q_exc

        if sub(st.gsc_noisy_speech, 1) == 0 {
            acelp_dec_total_exc(
                &mut exc_fx[exc_at..],
                &mut exc2_bidon,
                gain_code16,
                gain_pit_fx,
                i_subfr_fx,
                code_fx,
            );
        } else if norm_s(gain_pit_fx | 1) == 0 {
            for i in 0..l_subfr_fx.max(0) as usize {
                let l_tmp = l_shl(l_mult(gain_pit_fx, exc_fx[exc_at + i + i_subfr]), 1);
                exc_fx[exc_at + i + i_subfr] = round_word(l_tmp);
            }
        } else {
            let gain_pitx2 = shl(gain_pit_fx, 1);
            for i in 0..l_subfr_fx.max(0) as usize {
                let l_tmp = l_mult(gain_pitx2, exc_fx[exc_at + i + i_subfr]);
                exc_fx[exc_at + i + i_subfr] = round_word(l_tmp);
            }
        }

        if sub(l_subfr_fx, 2 * L_SUBFR) == 0 {
            // 2*L_SUBFR: two pitch and gain values per subframe
            p_aq_at += 2 * LP_ORDER;
            pt_pitch_at += 1;
            pitch_buf_fx[pt_pitch_at] = pitch_buf_fx[pt_pitch_at - 1];
            pt_pitch_at += 1;
            gain_buf[pt_gain_at] = gain_pit_fx;
            pt_gain_at += 1;
            gain_buf[pt_gain_at] = gain_buf[pt_gain_at - 1];
            pt_gain_at += 1;

            if i_subfr_fx == 0 {
                // update gains for FEC - equivalent to lp_gain_updt()
                st.lp_gainp = extract_h(l_mult(9830, gain_pit_fx));
            } else {
                st.lp_gainp = extract_h(l_mult(22938, gain_pit_fx));
            }
            st.lp_gainc = 0;
        } else if sub(l_subfr_fx, 4 * L_SUBFR) == 0 {
            // 4*L_SUBFR: the whole frame
            for _ in 0..3 {
                pt_pitch_at += 1;
                pitch_buf_fx[pt_pitch_at] = pitch_buf_fx[pt_pitch_at - 1];
            }
            pt_pitch_at += 1;
            gain_buf[pt_gain_at] = gain_pit_fx;
            for _ in 0..3 {
                pt_gain_at += 1;
                gain_buf[pt_gain_at] = gain_buf[pt_gain_at - 1];
            }
            pt_gain_at += 1;
            p_aq_at += 4 * LP_ORDER;

            // update gains for FEC - equivalent to lp_gain_updt()
            st.lp_gainp = gain_pit_fx;
            st.lp_gainc = 0;
        } else {
            p_aq_at += LP_ORDER;
            pt_pitch_at += 1;
            gain_buf[pt_gain_at] = gain_pit_fx;
            pt_gain_at += 1;

            lp_gain_updt(
                i_subfr_fx,
                gain_pit_fx,
                0,
                &mut st.lp_gainp,
                &mut st.lp_gainc,
                L_FRAME,
            );
        }

        if l_subfr_fx <= 0 {
            // `nb_subfr` outside {1, 2, 4} (never passed): the reference would not advance.
            break;
        }
        i_subfr_fx += l_subfr_fx;
    }
}
