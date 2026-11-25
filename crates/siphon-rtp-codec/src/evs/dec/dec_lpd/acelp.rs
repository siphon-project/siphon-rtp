//! The ACELP part of `decoder_LPD`: the LPC interpolation, the ACELP decoder or the concealment
//! of a lost ACELP frame (or the TCX time-domain concealment after a TCX frame).

use super::Lpd;
use crate::evs::cnst::{
    ACELP_CORE, GENERIC, INACTIVE_CLAS, L_FRAME, L_SUBFR, M, NBPSF_PIT_MAX, ONSET, PIT_MIN_16K,
    SIN_ONSET, TRANSITION, UNVOICED_CLAS, VOICED, VOICED_CLAS,
};
use crate::evs::com::enr_1_az::enr_1_az;
use crate::evs::com::guided_plc_util::rec_lpc_spec_pow_diffuse_lc;
use crate::evs::com::int_lsp::{int_lsp, int_lsp4};
use crate::evs::com::lerp::lerp;
use crate::evs::com::lsf_tools::{e_lpc_f_lsp_a_conversion, lsf_stab};
use crate::evs::com::tools::set16;
use crate::evs::dec::dec_ace::decoder_acelp;
use crate::evs::dec::er_dec_acelp::con_acelp;
use crate::evs::dec::er_dec_tcx::con_tcx;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::tonal_mdct_concealment::tonal_mdct_conceal_update_state;
use crate::evs::rom::INTERPOL_FRAC_FX;
use crate::itu::basic_ops::{add, l_shl, round_word, shr, sub};

const MU: usize = M as usize;

/// The ACELP section of `decoder_LPD` (a no-op unless the frame's core is ACELP).
pub(super) fn decode_acelp(
    st: &mut DecoderState,
    w: &mut Lpd,
    coder_type: i16,
    param: &[i16],
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    old_bwe_exc: &mut [i16],
    bwe_exc_at: usize,
) {
    // the first good voiced frame after a long loss resets the gain memories
    if st.prev_bfi != 0
        && w.bfi == 0
        && sub(coder_type, VOICED) == 0
        && sub(st.prev_nb_lost_cmpt, 4) > 0
    {
        st.dec_glr_idx = 1;
        st.reset_mem_ar = 1;
    }

    if st.core != ACELP_CORE {
        return;
    }
    let bfi = w.bfi;
    let l_frame = st.l_frame;
    let nb_subfr = st.nb_subfr.max(0) as usize;

    if st.tcxonly == 0 {
        acelp_lpc_interpolation(st, w, coder_type);
    }

    if bfi != 0 && st.last_core != ACELP_CORE {
        // PLC: [TCX: TD PLC]
        let at = w.synth_fb_at;
        con_tcx(st, &mut w.synth_buf_fb, at);
        let (synth_fb_all, synth_all) = (&w.synth_buf_fb, &mut w.synth_buf);
        lerp(
            &synth_fb_all[at..],
            &mut synth_all[w.synth_at..],
            st.l_frame,
            st.l_frame_tcx,
        );
        st.con_tcx = 1;
        let gain = round_word(l_shl(st.mode2_lp_gainp, 1));
        set16(&mut st.mem_pitch_gain[2..], gain, st.nb_subfr);
    } else {
        // ACELP decoder
        if sub(l_frame, L_FRAME) == 0 {
            st.cur_sub_aq
                .copy_from_slice(&w.aq[2 * (MU + 1)..3 * (MU + 1)]);
        } else {
            st.cur_sub_aq
                .copy_from_slice(&w.aq[3 * (MU + 1)..4 * (MU + 1)]);
        }
        let synth_at = w.synth_at;
        if bfi != 0 {
            // PLC: [ACELP: general]; use the ACELP like concealment
            con_acelp(
                &w.aq,
                st.core_ext_mode,
                &mut w.synth_buf[synth_at..],
                &mut w.pitch,
                &mut w.pit_gain,
                st.stab_fac,
                st,
                pitch_buf,
                voice_factors,
                &mut old_bwe_exc[bwe_exc_at..],
            );

            st.mem_pitch_gain.copy_within(2..2 + nb_subfr, nb_subfr + 2);
            st.mem_pitch_gain[2..2 + nb_subfr].fill(0);
        } else {
            decoder_acelp(
                st,
                coder_type,
                param,
                &w.aq,
                &mut w.synth_buf[synth_at..],
                &mut w.pitch,
                &mut w.pit_gain,
                st.stab_fac,
                pitch_buf,
                voice_factors,
                w.lsf_q_prediction,
                old_bwe_exc,
                bwe_exc_at,
            );
            if st.flag_guided_acelp > 0 {
                st.guided_t0 = add(st.t0_4th, st.guided_t0).clamp(PIT_MIN_16K, NBPSF_PIT_MAX);
            }

            for i in 0..nb_subfr {
                st.mem_pitch_gain[2 + (2 * nb_subfr - 1) - i] =
                    st.mem_pitch_gain[2 + (nb_subfr - 1) - i];
                st.mem_pitch_gain[2 + (nb_subfr - 1) - i] = w.pit_gain[i];
            }
        }
    }

    // LPC for ACELP/BBWE; a TCX-only stream concealing a frame like ACELP copies `Aq`, which
    // nothing fills there (the reference copies an uninitialised local, nothing reads it back)
    if st.narrow_band != 0 || st.sr_core == 12800 || st.sr_core == 16000 {
        let count = nb_subfr * (MU + 1);
        st.mem_aq[..count].copy_from_slice(&w.aq[..count]);
    }

    // PLC: [TCX: Tonal Concealment]; signal that this frame is not TCX
    tonal_mdct_conceal_update_state(&mut st.tonal_mdc_tconceal, 0, 0, 0, 0);

    if bfi == 0 {
        st.second_last_tns_active = st.last_tns_active;
        st.last_tns_active = 0;
        st.tcxltp_last_gain_unmodified = 0;
    }
}

/// The LPC interpolation of an ACELP frame: relaxed or diffused after a loss, with or without the
/// mid-frame LSPs.
fn acelp_lpc_interpolation(st: &mut DecoderState, w: &mut Lpd, coder_type: i16) {
    let bfi = w.bfi;
    let l_frame = st.l_frame;

    // Stability Factor
    if bfi == 0 {
        st.stab_fac = lsf_stab(&w.lsf[MU..2 * MU], &w.lsf[..MU], 0, st.l_frame);
    }

    if bfi == 0 && st.prev_bfi != 0 {
        // check if LSP interpolation can be relaxed or if LPC power can be diffused
        let mut tmp_old = [0i16; MU + 1];
        let mut tmp_new = [0i16; MU + 1];
        e_lpc_f_lsp_a_conversion(&w.lsp[..MU], &mut tmp_old, M);
        w.enr_old = enr_1_az(&tmp_old, 2 * L_SUBFR);

        e_lpc_f_lsp_a_conversion(&w.lsp[MU..2 * MU], &mut tmp_new, M);
        w.enr_new = enr_1_az(&tmp_new, 2 * L_SUBFR);
    }

    if bfi == 0
        && (sub(st.dec_glr_idx, 1) == 0
            || (st.safety_net == 0
                && shr(w.enr_new, 11) > 0
                && sub(shr(w.enr_new, 1), w.enr_old) > 0))
        && st.prev_bfi != 0
    {
        let mut reset_q = 0;
        if sub(st.dec_glr_idx, 1) == 0 {
            reset_q = 1;
        }
        {
            let (lsp_old, lsp_new) = w.lsp.split_at_mut(MU);
            let (lsf_old, lsf_new) = w.lsf.split_at_mut(MU);
            let _ = lsf_old;
            rec_lpc_spec_pow_diffuse_lc(
                &mut lsp_new[..MU],
                lsp_old,
                &mut lsf_new[..MU],
                st,
                reset_q,
            );
        }

        let lsp_new: [i16; MU] = w.lsp[MU..2 * MU].try_into().unwrap_or([0; MU]);
        let lsp_old: [i16; MU] = w.lsp[..MU].try_into().unwrap_or([0; MU]);
        int_lsp(
            l_frame,
            &lsp_old,
            &lsp_new,
            &mut w.aq,
            M,
            &INTERPOL_FRAC_FX,
            0,
        );

        let (xsf, lsf) = (&mut w.xsfnew_uw, &w.lsf);
        xsf[..MU].copy_from_slice(&lsf[MU..2 * MU]);
    } else {
        // LPC Interpolation for ACELP
        let lsp_old: [i16; MU] = w.lsp[..MU].try_into().unwrap_or([0; MU]);
        let lsp_new: [i16; MU] = w.lsp[MU..2 * MU].try_into().unwrap_or([0; MU]);
        if bfi == 0 && st.acelp_cfg.mid_lpc != 0 {
            st.relax_prev_lsf_interp = 0;
            if st.prev_bfi != 0 {
                // check if LSP interpolation can be relaxed
                if sub(w.enr_new, shr(w.enr_old, 2)) < 0 {
                    st.relax_prev_lsf_interp = -1;
                    if sub(st.clas_dec, UNVOICED_CLAS) == 0
                        || sub(st.clas_dec, SIN_ONSET) == 0
                        || sub(st.clas_dec, INACTIVE_CLAS) == 0
                        || sub(coder_type, GENERIC) == 0
                        || sub(coder_type, TRANSITION) == 0
                    {
                        st.relax_prev_lsf_interp = 1;
                    }
                }
            }

            if st.stab_fac == 0
                && st.old_bfi_cnt > 0
                && sub(st.clas_dec, VOICED_CLAS) != 0
                && sub(st.clas_dec, ONSET) != 0
                && st.relax_prev_lsf_interp == 0
            {
                st.relax_prev_lsf_interp = 2;
            }
            int_lsp4(
                l_frame,
                &lsp_old,
                &w.lspmid,
                &lsp_new,
                &mut w.aq,
                M,
                st.relax_prev_lsf_interp,
            );
        } else {
            int_lsp(
                l_frame,
                &lsp_old,
                &lsp_new,
                &mut w.aq,
                M,
                &INTERPOL_FRAC_FX,
                0,
            );
            let old_lsp_q_cng = st.old_lsp_q_cng;
            let lsp_q_cng = st.lsp_q_cng;
            int_lsp(
                l_frame,
                &old_lsp_q_cng,
                &lsp_q_cng,
                &mut st.aq_cng,
                M,
                &INTERPOL_FRAC_FX,
                0,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::TCX_20_CORE;

    #[test]
    fn a_tcx_frame_leaves_the_acelp_state_alone() {
        let mut st = Box::new(DecoderState::zeroed());
        st.core = TCX_20_CORE;
        st.mem_pitch_gain[2] = 77;
        let mut w = super::super::tests::work();
        let (mut pitch_buf, mut voice_factors) = ([0i16; 5], [0i16; 5]);
        let mut bwe_exc = [0i16; 1380];
        decode_acelp(
            &mut st,
            &mut w,
            1,
            &[0; super::super::PARAM_LPC_AT + 136],
            &mut pitch_buf,
            &mut voice_factors,
            &mut bwe_exc,
            578,
        );
        assert_eq!(st.mem_pitch_gain[2], 77);
    }

    #[test]
    fn the_first_good_voiced_frame_after_a_long_loss_resets_the_gain_memories() {
        let mut st = Box::new(DecoderState::zeroed());
        st.core = TCX_20_CORE;
        st.prev_bfi = 1;
        st.prev_nb_lost_cmpt = 5;
        let mut w = super::super::tests::work();
        let (mut pitch_buf, mut voice_factors) = ([0i16; 5], [0i16; 5]);
        let mut bwe_exc = [0i16; 1380];
        let param = [0; super::super::PARAM_LPC_AT + 136];
        decode_acelp(
            &mut st,
            &mut w,
            VOICED,
            &param,
            &mut pitch_buf,
            &mut voice_factors,
            &mut bwe_exc,
            578,
        );
        assert_eq!((st.dec_glr_idx, st.reset_mem_ar), (1, 1));
        // not after a short loss
        st.dec_glr_idx = 0;
        st.reset_mem_ar = 0;
        st.prev_nb_lost_cmpt = 4;
        decode_acelp(
            &mut st,
            &mut w,
            VOICED,
            &param,
            &mut pitch_buf,
            &mut voice_factors,
            &mut bwe_exc,
            578,
        );
        assert_eq!((st.dec_glr_idx, st.reset_mem_ar), (0, 0));
    }
}
