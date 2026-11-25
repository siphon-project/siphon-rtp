//! The bass post-filter and the CLDFB resampling of the synthesis of `amr_wb_dec_fx` to the
//! output rate, the average frame energy and the 6 - 8 kHz band extension.

use super::{AmrWork, SYN_AT};
use crate::evs::cnst::{CLDFB_NO_COL_MAX, GENERIC, INT_FS_FX, L_FRAME, L_FRAME16K};
use crate::evs::com::cldfb::{
    cldfb_analysis_filtering, cldfb_get_num_channels, cldfb_synthesis_filtering, resample_cldfb,
};
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::tools::scale_sig;
use crate::evs::dec::bass_psfilter::{add_bass_post_filter, bass_psfilter, BassPsfilterState};
use crate::evs::dec::hf_synth::{hf_synth_amr_wb, hf_synth_amr_wb_reset, HfSynthAmrWbState};
use crate::evs::dec::post_dec::cldfb_synth_set_bands_to_zero;
use crate::evs::dec::state::{CldfbScaleFactor, DecoderState};
use crate::itu::basic_ops::{l_mac, l_mult, l_shl, mult_r, negate, norm_l, sub};
use crate::itu::stl2009::mac_r;

/// The resampling of the synthesis to the output rate (with the bass post-filter), the average
/// frame energy of the noise gate and the band extension.
pub(super) fn resample_and_band_extension(st: &mut DecoderState, w: &mut AmrWork) {
    let output_frame = w.output_frame;
    let mut scale_factor = CldfbScaleFactor::zeroed();
    let mut bpf_error_signal = [0i16; L_FRAME as usize];

    // Change the sampling frequency to 8/16/32 kHz; bass post-filter

    // check if the CLDFB works at the right sample rate
    if let (Some(ana), Some(bpf), Some(syn)) = (
        st.cldfb_ana.as_mut(),
        st.cldfb_bpf.as_mut(),
        st.cldfb_syn.as_mut(),
    ) {
        if sub(ana.usb.wrapping_mul(ana.no_col), L_FRAME) != 0 {
            // resample to the ACELP internal sampling rate
            let new_cldfb_bands = cldfb_get_num_channels(i32::from(INT_FS_FX));

            resample_cldfb(ana, new_cldfb_bands, L_FRAME, 0);
            resample_cldfb(bpf, new_cldfb_bands, L_FRAME, 0);

            if st.ini_frame > 0 {
                syn.bands_to_zero = sub(syn.no_channels, ana.no_channels);
            }
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
            &w.syn_tmp[SYN_AT..],
            L_FRAME,
            Some(&w.pitch_buf),
            &mut memories,
            bpf_off,
            stab_fac,
            GENERIC,
            q_syn,
            &mut bpf_error_signal,
        );
    }

    {
        let (Some(ana), Some(bpf), Some(syn)) = (
            st.cldfb_ana.as_mut(),
            st.cldfb_bpf.as_mut(),
            st.cldfb_syn.as_mut(),
        ) else {
            return;
        };

        cldfb_analysis_filtering(
            ana,
            &mut w.real_buffer,
            &mut w.imag_buffer,
            &mut scale_factor,
            &w.syn_tmp[SYN_AT..],
            negate(st.q_syn),
            CLDFB_NO_COL_MAX,
        );

        scale_factor.hb_scale = scale_factor.lb_scale;

        // CLDFB analysis and add the BPF error signal
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
        st.q_syn2 = st.q_syn;

        if sub(syn.bands_to_zero, sub(syn.no_channels, ana.no_channels)) != 0 {
            // in case of BW switching, re-init to default
            syn.bands_to_zero = sub(syn.no_channels, ana.no_channels);
        }
    }

    cldfb_synth_set_bands_to_zero(
        st,
        &w.real_buffer,
        &w.imag_buffer,
        CLDFB_NO_COL_MAX,
        &scale_factor,
    );
    // CLDFB synthesis of the combined signal
    if let Some(syn) = st.cldfb_syn.as_mut() {
        cldfb_synthesis_filtering(
            syn,
            &w.real_buffer,
            &w.imag_buffer,
            &scale_factor,
            &mut w.synth_out,
            negate(st.q_syn2),
            CLDFB_NO_COL_MAX,
        );
    }

    // Bring the CLDFB output to Q-1
    scale_sig(&mut w.synth_out, output_frame, negate(st.q_syn2));
    st.q_syn2 = 0;

    // save the synthesis - needed in case of core switching
    let output = output_frame as usize;
    st.previoussynth[..output].copy_from_slice(&w.synth_out[..output]);
    st.q_syn2 = 0;

    average_frame_energy(st, w);
    band_extension(st, w);
}

/// The average frame energy, optimised for NO_S@-26dBov with street noise @ SNR=25dB, and its
/// smoothed value `Ng_ener_ST` the band extension uses as its noise gate.
fn average_frame_energy(st: &mut DecoderState, w: &mut AmrWork) {
    let mut l_ng_ener: i32 = 0;
    frame_ener(
        L_FRAME,
        st.clas_dec,
        &w.syn_tmp[SYN_AT..],
        mult_r(w.pitch_buf[3], 512),
        &mut l_ng_ener,
        L_FRAME,
        st.q_syn,
        3,
        0,
    );

    // ng_ener = 10.0f * (float)log10(ng_ener + 0.01f) - 90.3087f + 15
    l_ng_ener = l_ng_ener.max(1);
    let mut tmp16 = norm_l(l_ng_ener);
    let exp2 = log2_norm_lc(l_shl(l_ng_ener, tmp16));
    tmp16 = sub(30, tmp16);
    let ng_ener = mac_r(l_shl(l_mac(-1_233_858, tmp16, 24660), 8 + 2), exp2, 771);
    // st_fx->ng_ener_ST = 0.7f * st_fx->ng_ener_ST + 0.3f * ng_ener
    st.ng_ener_st = mac_r(l_mult(st.ng_ener_st, 22938), ng_ener, 9830);
}

/// The bandwidth extension 6 kHz - 8 kHz (for outputs of 16 kHz and up, unless the narrowband
/// mask is on), or the reset of its memories.
fn band_extension(st: &mut DecoderState, w: &mut AmrWork) {
    let output_frame = w.output_frame;
    let narrow_mask = st
        .cldfb_syn
        .as_ref()
        .is_some_and(|syn| sub(syn.bands_to_zero, sub(syn.no_channels, 10)) == 0);
    if crate::itu::basic_ops::sub(output_frame, L_FRAME16K) >= 0
        && (!narrow_mask || sub(st.last_flag_filter_nb, 1) != 0)
    {
        let (core_brate, ng_ener_st, q_exc, q_syn2) =
            (st.core_brate, st.ng_ener_st, st.q_exc, st.q_syn2);
        let (_, mut state) = HfSynthAmrWbState::of(st);
        hf_synth_amr_wb(
            core_brate,
            output_frame,
            &w.aq,
            &w.exc2,
            &mut w.syn_tmp[SYN_AT..],
            &mut state,
            w.amr_io_class,
            &mut w.synth_out,
            w.class_para,
            &w.hf_gain,
            &w.voice_factors,
            &w.pitch_buf,
            ng_ener_st,
            &w.lsf_new,
            q_exc,
            q_syn2,
        );
    } else {
        let (seed2, mut state) = HfSynthAmrWbState::of(st);
        hf_synth_amr_wb_reset(seed2, &mut state);
    }
}
