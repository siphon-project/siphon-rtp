//! The last part of `acelp_core_dec_fx`: the bass post-filter and the CLDFB resampling of the
//! synthesis to the output rate, the 6-7 kHz band extension, the TBE excitation non-linearity and
//! the memory updates.

use super::{CoreWork, BWE_EXC_AT, EXC2_AT, SYN_AT};
use crate::evs::cnst::{
    AUDIO, CLDFB_NO_COL_MAX, DEC, FB_TBE, FD_CNG, FRAME_NO_DATA, L_FRAME, L_FRAME16K, L_FRAME32K,
    MODE2, NB, NL_BUFF_OFFSET, SID_2K40, SWB_CNG, SWB_TBE, WB_BWE, WB_TBE,
};
use crate::evs::com::cldfb::{
    cldfb_analysis_filtering, cldfb_get_num_channels, cldfb_synthesis_filtering, resample_cldfb,
};
use crate::evs::com::cng_exc::cng_params_upd;
use crate::evs::com::modif_fs::{retro_interp4_5, retro_interp5_4};
use crate::evs::com::swb_tbe_com::non_linearity;
use crate::evs::com::tools::scale_sig;
use crate::evs::dec::bass_psfilter::{add_bass_post_filter, bass_psfilter, BassPsfilterState};
use crate::evs::dec::fd_cng_dec::{generate_comfort_noise_dec_hf, CldfbBuffers};
use crate::evs::dec::hf_synth::{hf_synth, hf_synth_reset};
use crate::evs::dec::state::{CldfbScaleFactor, DecoderState};
use crate::evs::dec::updt_dec::updt_dec;
use crate::itu::basic_ops::{l_deposit_l, l_sub, negate, sub};
use crate::itu::stl2009::l_mult0;

/// Resamples the post-processed synthesis to the output rate and runs the updates.
pub(super) fn resample_and_update(
    st: &mut DecoderState,
    w: &mut CoreWork,
    synth_out: &mut [i16],
    bwe_exc_extended: &mut [i32],
    voice_factors: &[i16],
    coder_type: i16,
    pitch_buf: &[i16],
) {
    let l_frame = st.l_frame;
    let output_frame = w.output_frame;
    let mut scale_factor = CldfbScaleFactor::zeroed();
    let mut bpf_error_signal = [0i16; L_FRAME16K as usize];

    // Resample to the output sampling rate (8/16/32/48 kHz); bass post-filter

    // check if the CLDFB works at the right sample rate
    if let (Some(ana), Some(bpf), Some(syn)) = (
        st.cldfb_ana.as_mut(),
        st.cldfb_bpf.as_mut(),
        st.cldfb_syn.as_mut(),
    ) {
        if sub(ana.usb.wrapping_mul(ana.no_col), l_frame) != 0 {
            // resample to the ACELP internal sampling rate
            let new_cldfb_bands = cldfb_get_num_channels(l_mult0(l_frame, 50));
            resample_cldfb(ana, new_cldfb_bands, l_frame, 0);
            resample_cldfb(bpf, new_cldfb_bands, l_frame, 0);

            if st.ini_frame > 0 {
                syn.bands_to_zero = sub(syn.no_channels, ana.no_channels);
            }
        }
    }

    if sub(l_frame, st.last_l_frame) != 0 && sub(st.last_codec_mode, MODE2) != 0 {
        if sub(l_frame, L_FRAME) == 0 {
            retro_interp5_4(&mut st.pst_old_syn);
        } else if sub(l_frame, L_FRAME16K) == 0 {
            retro_interp4_5(&w.syn_fx_tmp[SYN_AT..], &mut st.pst_old_syn);
        }
    }

    {
        let (opt_amr_wb, bpf_off, stab_fac, q_syn) =
            (st.opt_amr_wb, st.bpf_off, st.stab_fac, st.q_syn);
        let mut memories = BassPsfilterState {
            old_syn: &mut st.pst_old_syn,
            mem_deemph_err: &mut st.pst_mem_deemp_err,
            lp_ener: &mut st.pst_lp_ener,
            v_stab_smooth: &mut st.stab_fac_smooth,
            mem_mean_pit: &mut st.mem_mean_pit,
            track_on_hist: &mut st.track_on_hist,
            vibrato_hist: &mut st.vibrato_hist,
            psf_att: &mut st.psf_att,
        };
        bass_psfilter(
            opt_amr_wb,
            &w.syn_fx_tmp[SYN_AT..],
            l_frame,
            Some(pitch_buf),
            &mut memories,
            bpf_off,
            stab_fac,
            coder_type,
            q_syn,
            &mut bpf_error_signal,
        );
    }

    let (Some(ana), Some(bpf), Some(syn)) = (
        st.cldfb_ana.as_mut(),
        st.cldfb_bpf.as_mut(),
        st.cldfb_syn.as_mut(),
    ) else {
        return;
    };

    // analysis of the synthesis at the internal sampling rate
    cldfb_analysis_filtering(
        ana,
        &mut w.real_buffer,
        &mut w.imag_buffer,
        &mut scale_factor,
        &w.syn_fx_tmp[SYN_AT..],
        negate(st.q_syn),
        CLDFB_NO_COL_MAX,
    );

    scale_factor.hb_scale = scale_factor.lb_scale;

    // analysis and add the BPF error signal
    let mut i: i16 = 0;
    if st.bpf_off == 0 {
        i = CLDFB_NO_COL_MAX;
    }
    add_bass_post_filter(
        &bpf_error_signal,
        &mut w.real_buffer,
        &mut w.imag_buffer,
        bpf,
        negate(st.q_syn),
        i,
        ana.no_col,
        ana.no_channels,
        &mut scale_factor,
    );

    // set the output mask for upsampling
    if sub(st.bwidth, NB) == 0 {
        // set the NB mask for upsampling
        syn.bands_to_zero = sub(syn.no_channels, 10);
    } else if sub(syn.bands_to_zero, sub(syn.no_channels, ana.no_channels)) != 0 {
        // in case of BW switching, re-init to default
        syn.bands_to_zero = sub(syn.no_channels, ana.no_channels);
    }

    // WB/SWB-FD_CNG
    scale_factor.hb_scale = scale_factor.lb_scale;

    let ana_channels = ana.no_channels;
    let syn_channels = syn.no_channels;
    let num_core_bands = st
        .h_fd_cng_dec
        .as_ref()
        .and_then(|fd| fd.h_fd_cng_com.as_ref())
        .map_or(0, |com| com.num_core_bands);
    if (l_sub(st.core_brate, i32::from(FRAME_NO_DATA)) == 0
        || l_sub(st.core_brate, i32::from(SID_2K40)) == 0)
        && sub(st.cng_type, FD_CNG) == 0
        && sub(num_core_bands, syn_channels) < 0
    {
        let mut hb_scale = scale_factor.hb_scale;
        generate_comfort_noise_dec_hf(
            CldfbBuffers {
                real: &mut w.real_buffer,
                imag: &mut w.imag_buffer,
                scale: Some(&mut hb_scale),
            },
            st,
        );
        scale_factor.hb_scale = hb_scale;

        let regular_stop_band = st
            .h_fd_cng_dec
            .as_ref()
            .and_then(|fd| fd.h_fd_cng_com.as_ref())
            .map_or(0, |com| com.regular_stop_band);
        if let Some(syn) = st.cldfb_syn.as_mut() {
            syn.bands_to_zero = 0;
            if sub(regular_stop_band, syn.no_channels) < 0 {
                syn.bands_to_zero = sub(syn.no_channels, regular_stop_band);
            }
            syn.lsb = ana_channels;
        }
    }

    // synthesis of the combined signal
    st.q_syn2 = st.q_syn;
    if let Some(syn) = st.cldfb_syn.as_mut() {
        cldfb_synthesis_filtering(
            syn,
            &w.real_buffer,
            &w.imag_buffer,
            &scale_factor,
            synth_out,
            negate(st.q_syn2),
            CLDFB_NO_COL_MAX,
        );
    }

    // Bring the CLDFB output to Q0
    scale_sig(synth_out, output_frame, negate(st.q_syn2));
    st.q_syn2 = 0;

    // save the synthesis - needed in case of core switching
    let output = output_frame as usize;
    st.previoussynth[..output].copy_from_slice(&synth_out[..output]);

    band_extension_and_updates(
        st,
        w,
        synth_out,
        bwe_exc_extended,
        voice_factors,
        coder_type,
        pitch_buf,
    );
}

/// The 6-7 kHz band extension of 16 kHz input signals, the TBE parameters, `updt_dec_fx` and the
/// CNG parameter update.
fn band_extension_and_updates(
    st: &mut DecoderState,
    w: &mut CoreWork,
    synth_out: &mut [i16],
    bwe_exc_extended: &mut [i32],
    voice_factors: &[i16],
    coder_type: i16,
    pitch_buf: &[i16],
) {
    let l_frame = st.l_frame;
    let output_frame = w.output_frame;

    // Bandwidth extension 6 kHz - 7 kHz (only for 16 kHz input signals)
    if sub(l_frame, L_FRAME) == 0
        && sub(st.bwidth, NB) != 0
        && sub(output_frame, L_FRAME16K) >= 0
        && (sub(st.extl, -1) == 0
            || sub(st.extl, SWB_CNG) == 0
            || (sub(st.extl, WB_BWE) == 0 && st.extl_brate == 0 && sub(coder_type, AUDIO) != 0))
    {
        hf_synth(
            st.core_brate,
            output_frame,
            &w.aq,
            &w.old_exc2[EXC2_AT..],
            &mut w.syn_fx_tmp[SYN_AT..],
            synth_out,
            &mut st.seed2,
            &mut st.mem_hp400,
            &mut st.mem_syn_hf,
            &mut st.mem_hf,
            st.q_exc,
            st.q_syn2,
            &mut st.delay_syn_hf,
            &mut st.mem_exp1,
            &mut st.mem_hp_interp,
            st.extl,
            st.cng_mode,
        );
    } else {
        hf_synth_reset(
            &mut st.seed2,
            &mut st.mem_hf,
            &mut st.mem_syn_hf,
            &mut st.mem_hp400,
            &mut st.mem_hp_interp,
            &mut st.delay_syn_hf,
        );
    }

    // Populate the parameters for the SWB TBE: apply a non-linearity to the SHB excitation
    let tbe =
        |extl: i16| sub(extl, SWB_TBE) == 0 || sub(extl, WB_TBE) == 0 || sub(extl, FB_TBE) == 0;
    if (st.bfi == 0 && st.prev_bfi != 0)
        || (sub(st.last_vbr_hw_bwe_disable_dec, 1) == 0 && st.vbr_hw_bwe_disable_dec == 0)
        || (tbe(st.extl)
            && sub(st.last_extl, SWB_TBE) != 0
            && sub(st.last_extl, WB_TBE) != 0
            && sub(st.last_extl, FB_TBE) != 0)
    {
        st.bwe_non_lin_prev_scale = l_deposit_l(0);
        st.old_bwe_exc_extended[..NL_BUFF_OFFSET as usize].fill(0);
    }

    if st.ppp_mode_dec == 0 {
        non_linearity(
            &w.old_bwe_exc[BWE_EXC_AT..],
            bwe_exc_extended,
            L_FRAME32K,
            &mut st.bwe_non_lin_prev_scale,
            st.q_exc,
            coder_type,
            voice_factors,
            l_frame,
        );
    }

    if l_sub(st.core_brate, i32::from(FRAME_NO_DATA)) == 0
        || l_sub(st.core_brate, i32::from(SID_2K40)) == 0
    {
        st.bwe_non_lin_prev_scale = l_deposit_l(0);
    }

    // Updates
    updt_dec(
        st,
        l_frame,
        coder_type,
        &w.old_exc,
        pitch_buf,
        w.es_pred,
        &w.aq,
        &w.lsf_new,
        &w.lsp_new,
        voice_factors,
        &w.old_bwe_exc,
        &w.gain_buf,
    );

    if l_sub(st.core_brate, i32::from(SID_2K40)) > 0 {
        // update the CNG parameters in active frames
        cng_params_upd(
            &w.lsp_new,
            &w.old_exc[EXC_AT_CNG..],
            l_frame,
            &mut st.ho_circ_ptr,
            &mut st.ho_ener_circ,
            &mut st.ho_circ_size,
            &mut st.ho_lsp_circ,
            st.q_exc,
            DEC,
            &mut st.ho_env_circ,
            &mut 0,
            &mut [],
            &mut [],
            &mut [],
            st.last_active_brate,
        );

        // Set the 16k LSP flag for the CNG buffer
        st.ho_16k_lsp[st.ho_circ_ptr as usize] = 0;
        if sub(l_frame, L_FRAME) != 0 {
            st.ho_16k_lsp[st.ho_circ_ptr as usize] = 1;
        }
    }
}

/// Where `exc_fx` points in `old_exc` (`cng_params_upd_fx` is given the excitation, not `exc2`).
const EXC_AT_CNG: usize = super::EXC_AT;
