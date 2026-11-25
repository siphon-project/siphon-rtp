//! The CLDFB-domain post-processing of the MODE2 part of `evs_dec_fx`: FD-CNG on the core rate
//! synthesis, the analysis, the bass post-filter, the TEC / TFA gain, and the synthesis to the
//! output rate.

use super::super::FrameWork;
use crate::evs::cnst::{
    ACELP_32K, ACELP_CORE, ACTIVE_FRAME, AMR_WB_CORE, AUDIO, CLDFB_NO_COL_MAX, L_FRAME16K,
    L_FRAME_MAX, NB, TCX_20_CORE,
};
use crate::evs::com::basop_util::get_scale_factor16;
use crate::evs::com::cldfb::{
    cldfb_analysis_filtering, cldfb_get_num_channels, cldfb_synthesis_filtering, resample_cldfb,
    CLDFB_ROW,
};
use crate::evs::com::tec_com::calc_gain_temp_tbe;
use crate::evs::com::tools::{scale_sig, set16};
use crate::evs::dec::bass_psfilter::add_bass_post_filter;
use crate::evs::dec::fd_cng_dec::{
    apply_fd_cng, generate_masking_noise, noisy_speech_detection, CldfbBuffers,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::updt_dec::update_decoder_lpd_cng;
use crate::evs::error::EvsError;
use crate::itu::basic_ops::{add, l_sub, mult_r, negate, sub};
use crate::itu::stl2009::l_mult0;

/// The subband buffers of a frame (`realBufferTmp` / `imagBufferTmp`).
struct Subbands {
    real: [[i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
    imag: [[i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
}

const NOT_INITIALISED: EvsError = EvsError::Malformed("MODE2 decoder without CLDFB banks");

/// Whether the previous frame leaves a comfort noise tail to add: the 16 kHz core after an ACELP
/// (not AUDIO), TCX-20 or AMR-WB IO frame with comfort noise on.
fn olap_tail_applies(st: &DecoderState) -> bool {
    st.flag_cna == 0
        && sub(st.l_frame, L_FRAME16K) == 0
        && sub(i16::from(st.last_flag_cna), 1) == 0
        && ((sub(st.last_core, ACELP_CORE) == 0 && sub(st.last_coder_type, AUDIO) != 0)
            || sub(st.last_core, TCX_20_CORE) == 0
            || sub(st.last_core, AMR_WB_CORE) == 0)
}

/// `output_sp[i] += olapBufferSynth2[i + 5 * L_frame / 4]` over half a frame.
fn add_olap_tail(st: &DecoderState, signal: &mut [i16]) {
    let half = (st.l_frame / 2).max(0) as usize;
    let at = (5 * i32::from(st.l_frame) / 4) as usize;
    if let Some(dec) = st.h_fd_cng_dec.as_deref() {
        for i in 0..half {
            signal[i] = add(signal[i], dec.olap_buffer_synth2[i + at]);
        }
    }
}

/// The post-processing: returns the exponent `timeIn_e` of the synthesis output (in `output_sp`).
pub(super) fn postproc(
    st: &mut DecoderState,
    w: &mut FrameWork,
    output_sp: &mut [i16],
    pcm_buf_fb: &mut [i16; L_FRAME_MAX as usize],
    conceal_whole_frame: i16,
) -> Result<i16, EvsError> {
    let mut bands = Subbands {
        real: [[0; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
        imag: [[0; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
    };
    let (Some(ana), Some(syn)) = (st.cldfb_ana.as_deref_mut(), st.cldfb_syn.as_deref_mut()) else {
        return Err(NOT_INITIALISED);
    };
    let nab = ana.no_channels.min(syn.no_channels);
    syn.lsb = ana.no_channels.min(syn.no_channels);
    syn.usb = syn.no_channels;
    ana.lsb = ana.no_channels;
    ana.usb = ana.no_channels;

    if st.h_fd_cng_dec.is_some()
        && (l_sub(st.sr_core, 8000) == 0
            || l_sub(st.sr_core, 12800) == 0
            || l_sub(st.sr_core, 16000) == 0)
        && l_sub(st.total_brate, i32::from(ACELP_32K)) <= 0
    {
        fd_cng_active(st, output_sp, &mut bands, conceal_whole_frame);
    }

    if olap_tail_applies(st) {
        add_olap_tail(st, output_sp);
    }

    let mut time_in_e: i16;
    if sub(st.m_frame_type, ACTIVE_FRAME) == 0 {
        time_in_e = sub(get_scale_factor16(output_sp, st.l_frame), 3).max(0);
        if sub(st.core, ACELP_CORE) != 0 {
            time_in_e = sub(get_scale_factor16(pcm_buf_fb, st.l_frame_tcx), 3)
                .min(time_in_e)
                .max(0);
        }
        scale_sig(output_sp, st.l_frame, time_in_e);
        time_in_e = negate(time_in_e);
        let (Some(ana), scale_factor) = (st.cldfb_ana.as_deref_mut(), &mut st.scale_factor) else {
            return Err(NOT_INITIALISED);
        };
        cldfb_analysis_filtering(
            ana,
            &mut bands.real,
            &mut bands.imag,
            scale_factor,
            output_sp,
            time_in_e,
            CLDFB_NO_COL_MAX,
        );
        st.scale_factor.hb_scale = st.scale_factor.lb_scale;
    } else {
        time_in_e = inactive_analysis(st, w, &mut bands)?;
    }

    if st.flag_cna == 0 {
        if let Some(dec) = st.h_fd_cng_dec.as_deref_mut() {
            let fftlen = dec.h_fd_cng_com.as_deref().map_or(0, |com| com.fftlen);
            set16(&mut dec.olap_buffer_synth2, 0, fftlen);
        }
    }

    if st.p_bpf_noise_buf.is_some() {
        add_bass_filter(st, &mut bands, time_in_e)?;
    }

    if l_sub(st.output_fs, 8000) > 0 {
        st.tec_dec.cldfb_exp = add(15, st.scale_factor.lb_scale);
        let (Some(ana), tec) = (st.cldfb_ana.as_deref(), &mut st.tec_dec) else {
            return Err(NOT_INITIALISED);
        };
        calc_gain_temp_tbe(
            &bands.real,
            &bands.imag,
            tec.cldfb_exp,
            &mut tec.lo_buffer,
            0,
            ana.no_col,
            ana.no_channels,
            &mut tec.p_gain_temp_m,
            &mut tec.p_gain_temp_e,
            st.tec_flag,
        );
    }

    // set high band buffers to zero. Covering the current frame and the overlap area
    if sub(st.m_frame_type, ACTIVE_FRAME) == 0 {
        let syn_channels = st.cldfb_syn.as_deref().map_or(0, |bank| bank.no_channels);
        let from = nab.max(0) as usize;
        let to = syn_channels.max(0) as usize;
        for i in 0..16 {
            bands.real[i][from..to].fill(0);
            bands.imag[i][from..to].fill(0);
        }
    }

    time_in_e = 0i16.min(add(time_in_e, 2));
    let (Some(syn), scale_factor) = (st.cldfb_syn.as_deref_mut(), &st.scale_factor) else {
        return Err(NOT_INITIALISED);
    };
    cldfb_synthesis_filtering(
        syn,
        &bands.real,
        &bands.imag,
        scale_factor,
        output_sp,
        time_in_e,
        CLDFB_NO_COL_MAX,
    );
    // CLDFB output always in timeIn_e
    Ok(time_in_e)
}

/// FD-CNG of an active or inactive frame: the noise estimate, the CNG itself and the masking
/// noise.
fn fd_cng_active(
    st: &mut DecoderState,
    output_sp: &mut [i16],
    bands: &mut Subbands,
    conceal_whole_frame: i16,
) {
    // In CLDFB domain: perform noise estimation during active frames, do CNG during inactive
    // frames
    let vad = i16::from(st.vad != 0 && sub(st.m_frame_type, ACTIVE_FRAME) == 0);
    let l_frame = st.l_frame;
    if let Some(dec) = st.h_fd_cng_dec.as_deref_mut() {
        if let Some(com) = dec.h_fd_cng_com.as_deref_mut() {
            noisy_speech_detection(
                vad,
                output_sp,
                l_frame,
                0,
                &dec.ms_noise_est,
                dec.ms_noise_est_exp,
                &dec.psize_shaping_norm,
                dec.psize_shaping_norm_exp,
                dec.n_ff_tpart_shaping,
                &mut dec.lp_noise,
                &mut dec.lp_speech,
                &mut com.flag_noisy_speech,
            );

            com.likelihood_noisy_speech = mult_r(com.likelihood_noisy_speech, 32440); // 0.99 Q15
            if com.flag_noisy_speech != 0 {
                com.likelihood_noisy_speech = add(com.likelihood_noisy_speech, 328);
                // 0.01 Q15
            }
        }
        st.lp_noise = dec.lp_noise;
    }

    let mut hb_scale = st.scale_factor.hb_scale;
    let m_frame_type = st.m_frame_type;
    apply_fd_cng(
        output_sp,
        0,
        Some(CldfbBuffers {
            real: &mut bands.real,
            imag: &mut bands.imag,
            scale: Some(&mut hb_scale),
        }),
        m_frame_type,
        st,
        conceal_whole_frame,
        0,
    );
    st.scale_factor.hb_scale = hb_scale;

    // Generate additional comfort noise to mask potential coding artefacts
    if sub(st.m_frame_type, ACTIVE_FRAME) == 0 && st.flag_cna != 0 {
        if let Some(dec) = st.h_fd_cng_dec.as_deref_mut() {
            if let Some(com) = dec.h_fd_cng_com.as_deref_mut() {
                let frame_size = com.frame_size;
                generate_masking_noise(
                    output_sp,
                    0,
                    com,
                    &mut dec.olap_buffer_synth2,
                    frame_size,
                    0,
                );
            }
        }
    }
}

/// An inactive frame: the comfort noise of the LP-CNG synthesised in the time domain and
/// analysed. Returns `timeIn_e`.
fn inactive_analysis(
    st: &mut DecoderState,
    w: &mut FrameWork,
    bands: &mut Subbands,
) -> Result<i16, EvsError> {
    let l_frame = st.l_frame;
    let frame = l_frame.max(0) as usize;
    let mut time_domain_buffer = [0i16; L_FRAME16K as usize];
    let mut a = [0i16; 17];
    let (mut regular_stop_band, mut have_cng) = (0, false);
    if let Some(com) = st
        .h_fd_cng_dec
        .as_deref()
        .and_then(|dec| dec.h_fd_cng_com.as_deref())
    {
        time_domain_buffer[..frame].copy_from_slice(&com.time_domain_buffer[..frame]);
        a.copy_from_slice(&com.a_cng);
        regular_stop_band = com.regular_stop_band;
        have_cng = true;
    }
    if !have_cng {
        return Err(NOT_INITIALISED);
    }

    let mut bpf_noise_buf = st.bpf_noise_buf;
    update_decoder_lpd_cng(
        st,
        w.coder_type,
        &mut time_domain_buffer,
        &a,
        &mut bpf_noise_buf,
    );
    st.bpf_noise_buf = bpf_noise_buf;

    // Generate additional comfort noise to mask potential coding artefacts
    if st.flag_cna != 0 {
        if let Some(dec) = st.h_fd_cng_dec.as_deref_mut() {
            if let Some(com) = dec.h_fd_cng_com.as_deref_mut() {
                let frame_size = com.frame_size;
                generate_masking_noise(
                    &mut time_domain_buffer,
                    0,
                    com,
                    &mut dec.olap_buffer_synth2,
                    frame_size,
                    0,
                );
            }
        }
    } else if olap_tail_applies(st) {
        add_olap_tail(st, &mut time_domain_buffer);
    }

    // check if the CLDFB works on the right sample rate
    let (Some(ana), Some(bpf)) = (st.cldfb_ana.as_deref_mut(), st.cldfb_bpf.as_deref_mut()) else {
        return Err(NOT_INITIALISED);
    };
    if sub(ana.no_channels.wrapping_mul(ana.no_col), l_frame) != 0 {
        let new_cldfb_bands = cldfb_get_num_channels(l_mult0(l_frame, 50));
        resample_cldfb(ana, new_cldfb_bands, l_frame, 0);
        resample_cldfb(bpf, new_cldfb_bands, l_frame, 0);
    }

    let Some(syn) = st.cldfb_syn.as_deref_mut() else {
        return Err(NOT_INITIALISED);
    };
    syn.bands_to_zero = 0;
    if sub(st.bwidth, NB) == 0 && sub(syn.no_channels, 10) > 0 {
        syn.bands_to_zero = sub(syn.no_channels, 10);
    } else if regular_stop_band < syn.no_channels {
        syn.bands_to_zero = syn.no_channels - regular_stop_band;
    }

    let mut time_in_e: i16 = 2;
    scale_sig(&mut time_domain_buffer, l_frame, time_in_e);
    if st.p_bpf_noise_buf.is_some() {
        scale_sig(&mut st.bpf_noise_buf, l_frame, time_in_e);
    }

    time_in_e = negate(time_in_e);
    let (Some(ana), scale_factor) = (st.cldfb_ana.as_deref_mut(), &mut st.scale_factor) else {
        return Err(NOT_INITIALISED);
    };
    cldfb_analysis_filtering(
        ana,
        &mut bands.real,
        &mut bands.imag,
        scale_factor,
        &time_domain_buffer,
        time_in_e,
        CLDFB_NO_COL_MAX,
    );
    Ok(time_in_e)
}

/// The bass post-filter's harmonic signal added in the CLDFB domain.
fn add_bass_filter(
    st: &mut DecoderState,
    bands: &mut Subbands,
    time_in_e: i16,
) -> Result<(), EvsError> {
    let mut time_in_bpf_e = time_in_e;
    if sub(st.m_frame_type, ACTIVE_FRAME) == 0 {
        time_in_bpf_e = 0;
    }

    let (Some(ana), Some(bpf)) = (st.cldfb_ana.as_deref(), st.cldfb_bpf.as_deref_mut()) else {
        return Err(NOT_INITIALISED);
    };
    add_bass_post_filter(
        &st.bpf_noise_buf,
        &mut bands.real,
        &mut bands.imag,
        bpf,
        time_in_bpf_e,
        CLDFB_NO_COL_MAX,
        ana.no_col,
        ana.no_channels,
        &mut st.scale_factor,
    );

    if sub(st.m_frame_type, ACTIVE_FRAME) != 0 {
        scale_sig(&mut st.bpf_noise_buf, st.l_frame, time_in_e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decoder_without_cldfb_banks_is_refused() {
        let mut st = DecoderState::zeroed();
        let mut w = FrameWork::new();
        let mut output = [0i16; 960];
        let mut pcm = [0i16; L_FRAME_MAX as usize];
        assert!(postproc(&mut st, &mut w, &mut output, &mut pcm, 0).is_err());
    }
}
