//! The TCX part of `decoder_LPD`: the TCX-20 and TCX-10 decoders, the waveform adjustment of a
//! concealed frame and the TCX post-processing.

use super::{Lpd, LSF_LEN};
use crate::evs::cnst::{
    DEC_NPRM_DIV, HQ_48K, L_FRAME, M, MODE2, TCX_10_CORE, TCX_20_CORE, TCX_NONTONAL,
};
use crate::evs::com::guided_plc_util::rec_lpc_spec_pow_diffuse_lc;
use crate::evs::com::int_lsp::int_lsp;
use crate::evs::com::lerp::lerp;
use crate::evs::com::lpc_tools::e_lpc_int_lpc_tcx;
use crate::evs::com::lsf_tools::{e_lpc_f_lsp_a_conversion, lsf_stab};
use crate::evs::dec::dec_tcx::{decoder_tcx, decoder_tcx_post};
use crate::evs::dec::igf_dec::igf_dec_restore_tcx10_sub_frame_data;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::tonal_mdct_concealment::tonal_mdct_conceal_save_time_signal;
use crate::evs::dec::waveadjust_fec_dec::concealment_signal_tuning_fx;
use crate::evs::rom::INTERPOL_FRAC_FX;
use crate::itu::basic_ops::{l_sub, shr, sub};

const MU: usize = M as usize;

/// The TCX-20 / TCX-10 sections of `decoder_LPD` and the processing both share.
pub(super) fn decode_tcx(st: &mut DecoderState, w: &mut Lpd, coder_type: i16, param: &mut [i16]) {
    if sub(st.core, TCX_20_CORE) == 0 {
        decode_tcx20(st, w, coder_type, param);
    }
    if sub(st.core, TCX_10_CORE) == 0 {
        decode_tcx10(st, w, coder_type, param);
    }
    if sub(st.core, TCX_10_CORE) == 0 || sub(st.core, TCX_20_CORE) == 0 {
        tcx_post(st, w);
    }
}

/// TCX20.
fn decode_tcx20(st: &mut DecoderState, w: &mut Lpd, coder_type: i16, param: &mut [i16]) {
    let bfi = w.bfi;
    let l_frame = st.l_frame;
    let l_frame_tcx = st.l_frame_tcx;

    // Stability Factor
    if bfi == 0 {
        if st.tcxonly != 0 {
            st.stab_fac = lsf_stab(&w.lsf[MU..2 * MU], &w.lsf[..MU], 0, L_FRAME);
        } else {
            st.stab_fac = lsf_stab(&w.lsf[MU..2 * MU], &w.lsf[..MU], 0, st.l_frame);
        }
    }

    let lsp_old: [i16; MU] = w.lsp[..MU].try_into().unwrap_or([0; MU]);
    let lsp_new: [i16; MU] = w.lsp[MU..2 * MU].try_into().unwrap_or([0; MU]);
    if st.enable_tcx_lpc != 0 {
        // Convert quantized xSP to A
        e_lpc_f_lsp_a_conversion(&lsp_new, &mut w.aq, M);
    } else if st.tcxonly == 0 {
        if bfi == 0 && st.prev_bfi != 0 && st.safety_net == 0 && st.rate_switching_reset != 0 {
            // diffuse LPC power on rate switching
            {
                let (old, new) = w.lsp.split_at_mut(MU);
                let (_, lsf_new) = w.lsf.split_at_mut(MU);
                rec_lpc_spec_pow_diffuse_lc(&mut new[..MU], old, &mut lsf_new[..MU], st, 0);
            }
            let lsp_old: [i16; MU] = w.lsp[..MU].try_into().unwrap_or([0; MU]);
            let lsp_new: [i16; MU] = w.lsp[MU..2 * MU].try_into().unwrap_or([0; MU]);
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
            // LPC Interpolation for TCX
            e_lpc_int_lpc_tcx(&lsp_old, &lsp_new, &mut w.aq);
        }
    } else {
        e_lpc_f_lsp_a_conversion(&lsp_new, &mut w.aq, M);
    }

    if bfi == 0 && st.tcx_lpc_shaped_ari != 0 {
        let lspind = w.lspind;
        e_lpc_f_lsp_a_conversion(&lspind, &mut w.aind, M);
    }

    // TCX decoder
    let (synth_at, synth_fb_at) = (w.synth_at, w.synth_fb_at);
    let coded_lines = st.tcx_cfg.tcx_coded_lines;
    let stab_fac = st.stab_fac;
    decoder_tcx(
        param,
        &w.aq,
        &w.aind,
        l_frame,
        l_frame_tcx,
        coded_lines,
        &mut w.synth_buf[synth_at..],
        &mut w.synth_buf_fb[synth_fb_at..],
        st,
        coder_type,
        bfi,
        0,
        stab_fac,
    );
}

/// TCX10: two half frames.
fn decode_tcx10(st: &mut DecoderState, w: &mut Lpd, coder_type: i16, param: &mut [i16]) {
    let bfi = w.bfi;
    let l_frame = st.l_frame;
    let l_frame_tcx = st.l_frame_tcx;
    for k in 0..2usize {
        // Set pointer to parameters
        let prm_at = k * DEC_NPRM_DIV as usize;

        // Stability Factor
        if bfi == 0 {
            st.stab_fac = lsf_stab(
                &w.lsf[(k + 1) * MU..(k + 2) * MU],
                &w.lsf[k * MU..(k + 1) * MU],
                0,
                L_FRAME,
            );
        }

        let lsp_k: [i16; MU] = w.lsp[(k + 1) * MU..(k + 2) * MU]
            .try_into()
            .unwrap_or([0; MU]);
        e_lpc_f_lsp_a_conversion(&lsp_k, &mut w.aq, M);

        // TCX decoder
        igf_dec_restore_tcx10_sub_frame_data(&mut st.h_igf_dec, k as i16);
        let synth_at = w.synth_at + k * l_frame.max(0) as usize / 2;
        let synth_fb_at = w.synth_fb_at + k * l_frame_tcx.max(0) as usize / 2;
        let coded_lines = shr(st.tcx_cfg.tcx_coded_lines, 1);
        let stab_fac = st.stab_fac;
        decoder_tcx(
            &mut param[prm_at..],
            &w.aq,
            &w.aind,
            shr(l_frame, 1),
            shr(l_frame_tcx, 1),
            coded_lines,
            &mut w.synth_buf[synth_at..],
            &mut w.synth_buf_fb[synth_fb_at..],
            st,
            coder_type,
            bfi,
            k as i16,
            stab_fac,
        );
    }
}

/// The waveform adjustment, the tonal concealment's time signal and the TCX post-processing.
fn tcx_post(st: &mut DecoderState, w: &mut Lpd) {
    let bfi = w.bfi;
    let l_frame = st.l_frame;
    let l_frame_tcx = st.l_frame_tcx;
    let (synth_at, synth_fb_at) = (w.synth_at, w.synth_fb_at);

    if st.enable_plc_waveadjust != 0
        || (l_sub(st.last_total_brate, HQ_48K) >= 0 && sub(st.last_codec_mode, MODE2) == 0)
    {
        // waveform adjustment
        let overlap_at = st.tonal_mdc_tconceal.second_last_pcm_out.unwrap_or(0);
        let outdata2_at = st.tonal_mdc_tconceal.last_pcm_out.unwrap_or(0);
        concealment_signal_tuning_fx(
            bfi,
            st.core,
            &mut w.synth_buf_fb[synth_fb_at..],
            &mut st.plc_info,
            st.nb_lost_cmpt,
            st.prev_bfi,
            &mut st.tonal_mdc_tconceal.time_data_buffer,
            overlap_at,
            w.past_core_mode,
            outdata2_at,
            st.enable_plc_waveadjust,
            st.last_total_brate,
            st.last_codec_mode,
        );
        if (bfi != 0 || st.prev_bfi != 0)
            && st.plc_info.pitch != 0
            && sub(st.plc_info.concealment_method, TCX_NONTONAL) == 0
        {
            let (synth_fb_all, synth_all) = (&w.synth_buf_fb, &mut w.synth_buf);
            lerp(
                &synth_fb_all[synth_fb_at..],
                &mut synth_all[synth_at..],
                l_frame,
                l_frame_tcx,
            );
            if bfi == 0 && st.prev_bfi != 0 {
                st.plc_info.pitch = 0;
            }
        }
    }

    if bfi == 0 {
        tonal_mdct_conceal_save_time_signal(
            &mut st.tonal_mdc_tconceal,
            &w.synth_buf_fb[synth_fb_at..],
            l_frame_tcx,
        );
    }
    let (synth_all, synth_fb_all) = (&mut w.synth_buf, &mut w.synth_buf_fb);
    decoder_tcx_post(
        st,
        &mut synth_all[synth_at..],
        &mut synth_fb_all[synth_fb_at..],
        &w.aq,
        bfi,
    );

    if sub(st.core, TCX_20_CORE) == 0 {
        // LPC Interpolation for BBWE/post-processing
        if st.narrow_band != 0 || st.sr_core == 12800 || st.sr_core == 16000 {
            let lspold_uw = st.lspold_uw;
            let xspnew: [i16; MU] = w.xspnew_uw[..MU].try_into().unwrap_or([0; MU]);
            int_lsp(
                l_frame,
                &lspold_uw,
                &xspnew,
                &mut w.aq,
                M,
                &INTERPOL_FRAC_FX,
                0,
            );
            let count = st.nb_subfr.max(0) as usize * (MU + 1);
            st.mem_aq[..count].copy_from_slice(&w.aq[..count]);
        }
    }
    let _ = LSF_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::ACELP_CORE;

    #[test]
    fn an_acelp_frame_runs_no_tcx_decoder() {
        let mut st = Box::new(DecoderState::zeroed());
        st.core = ACELP_CORE;
        st.stab_fac = 1234;
        let mut w = super::super::tests::work();
        decode_tcx(
            &mut st,
            &mut w,
            0,
            &mut [0; super::super::PARAM_LPC_AT + 136],
        );
        assert_eq!(st.stab_fac, 1234);
        assert!(w.synth_buf.iter().all(|&sample| sample == 0));
    }
}
