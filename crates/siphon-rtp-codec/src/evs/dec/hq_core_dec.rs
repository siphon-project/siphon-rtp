//! HQ core decoder (TS 26.442 `lib_dec/hq_core_dec_fx.c`; TS 26.445 §6.2): the transform-domain
//! decoding of a good frame (low or high rate), the concealment of a lost one, the inverse
//! transform with overlap-add and pre-echo reduction, and the memories the concealment and the
//! ACELP switching read.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ALDO_WINDOW, DELAY_CLDFB_NS, DIM_FB, FRAMECTTOSTART_MDCT, FULL_OVERLAP, HQ_48K, HQ_CORE,
    LOW_RATE_HQ_CORE, L_FRAME, L_FRAME16K, L_FRAME32K, L_FRAME48K, L_FRAME8K, L_SUBFR, MAX_SB_NB,
    MINIMUM_RATE_TO_ENCODE_VOICING_FLAG, MODE1, MODE2, NB_SFM, NORM_MDCT_FACTOR,
    NUM_TIME_SWITCHING_BLOCKS, N_NS2W_FRAMES, N_ZERO_NB, SWB_FENV, TCX_10_CORE, TCX_20_CORE,
    TCX_NONTONAL,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::tools::{copy, copy_scale_sig, copy_scale_sig_32_16, set16, set32};
use crate::evs::com::trans_inv::{inverse_transform, preecho_sb, PreechoState};
use crate::evs::com::window_ola::window_ola;
use crate::evs::dec::core_switching_dec::core_switching_hq_prepare_dec;
use crate::evs::dec::fec_hq_core::{hq_fec_mem_update, hq_fec_processing, time_domain_fec_hq};
use crate::evs::dec::fec_hq_phase_ecu::hq_ecu;
use crate::evs::dec::hq_conf_fec::hq_configure_bfi;
use crate::evs::dec::hq_hr_dec::hq_hr_dec;
use crate::evs::dec::hq_lr_dec::hq_lr_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::waveadjust_fec_dec::waveform_adj2_fix;
use crate::evs::macros::ns2sa_fx2;
use crate::evs::rom::{HQ_NOMINAL_SCALING_INV, INNER_FRAME_TBL, INNER_FRAME_TBL_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_l, l_add, l_shl, l_shr, l_sub, mult, mult_r, negate, shl, sub,
};
use crate::itu::stl2009::{i_mult, lshr, mpy_32_16_ss};

/// The locals of `hq_core_dec_fx` that its stages share.
struct HqWork {
    /// `t_audio_q`: the decoded (or concealed) spectrum, Q12.
    t_audio_q: [i32; L_FRAME48K as usize],
    /// `wtda_audio`: the inverse transform output.
    wtda_audio: [i32; 2 * L_FRAME48K as usize],
    /// `gapsynth_fx`: the pitch-based concealment's gap synthesis.
    gapsynth: [i16; L_FRAME48K as usize],
    ynrm: [i16; NB_SFM as usize],
    num_bands_p: [i16; MAX_SB_NB as usize],
    normq: [i32; NB_SFM as usize],
    swb_fenv: [i16; (SWB_FENV + DIM_FB) as usize],
    is_transient: i16,
    hqswb_clas: i16,
    inner_frame: i16,
    num_bits: i16,
    mean_en_high: i16,
    q_audio: i16,
    nb_sfm: i16,
    num_sb: i16,
    sfm_start: &'static [i16],
    sfm_end: &'static [i16],
}

/// `hq_core_dec_fx`: decode one HQ core frame into `synth` (`output_frame` samples, Q`*q_synth`).
/// `hq_core_type` is the low- or high-rate core, `core_switching_flag` marks an ACELP -> HQ
/// switching frame.
pub fn hq_core_dec(
    st: &mut DecoderState,
    synth: &mut [i16],
    q_synth: &mut i16,
    output_frame: i16,
    hq_core_type: i16,
    core_switching_flag: i16,
) {
    let mut w = HqWork {
        t_audio_q: [0; L_FRAME48K as usize],
        wtda_audio: [0; 2 * L_FRAME48K as usize],
        gapsynth: [0; L_FRAME48K as usize],
        ynrm: [39; NB_SFM as usize],
        num_bands_p: [0; MAX_SB_NB as usize],
        normq: [0; NB_SFM as usize],
        swb_fenv: [0; (SWB_FENV + DIM_FB) as usize],
        is_transient: 0,
        hqswb_clas: 0,
        inner_frame: 0,
        num_bits: 0,
        mean_en_high: 0,
        q_audio: 12,
        nb_sfm: 0,
        num_sb: 0,
        sfm_start: &[],
        sfm_end: &[],
    };

    hq_core_dec_setup(st, &mut w, output_frame, core_switching_flag);
    if st.bfi == 1 {
        hq_core_dec_conceal(st, &mut w, output_frame);
    } else {
        hq_core_dec_transform(st, &mut w, output_frame, hq_core_type, core_switching_flag);
    }
    hq_core_dec_bandwidth_switching(st, &mut w);
    hq_core_dec_synthesis(st, &mut w, synth, q_synth, output_frame);
    hq_core_dec_recovery(st, synth, *q_synth);
    hq_core_dec_update(st, &w, synth, *q_synth, output_frame);
}

/// Initialisations and the bit budget of `hq_core_dec_fx`.
fn hq_core_dec_setup(
    st: &mut DecoderState,
    w: &mut HqWork,
    output_frame: i16,
    core_switching_flag: i16,
) {
    st.tcx_cfg.tcx_last_overlap_mode = st.tcx_cfg.tcx_curr_overlap_mode;
    if sub(st.tcx_cfg.tcx_curr_overlap_mode, FULL_OVERLAP) == 0 {
        st.tcx_cfg.tcx_last_overlap_mode = ALDO_WINDOW;
    }
    st.tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;

    // Find the number of bits for transform-domain coding: the total bit-budget
    // num_bits = total_brate / 50; 5243 is 1/50 in Q18 (0+18-15=3)
    let (l_tmp, _lsb) = mpy_32_16_ss(st.total_brate, 5243);
    w.num_bits = extract_l(l_shr(l_tmp, 3)); // Q0

    if st.bfi == 0 {
        if sub(core_switching_flag, 1) == 0 {
            core_switching_hq_prepare_dec(st, &mut w.num_bits, output_frame);

            // During ACELP->HQ core switching, limit the HQ core bitrate to 48kbps
            if sub(w.num_bits, (HQ_48K / 50) as i16) > 0 {
                w.num_bits = (HQ_48K / 50) as i16;
            }
        }

        // subtract signalling bits
        w.num_bits = sub(w.num_bits, st.next_bit_pos);

        // set FEC parameters; the reference's flag_uv (1 - HqVoicing) is only read again by the
        // lost-frame path, which overwrites it

        // subtract the number of bits for pitch & gain at higher bitrates
        if core_switching_flag == 0 && l_sub(st.core_brate, MINIMUM_RATE_TO_ENCODE_VOICING_FLAG) > 0
        {
            st.hq_voicing = get_next_indice(st, 1) as i16;
            w.num_bits = sub(w.num_bits, 1);
        } else {
            st.hq_voicing = 0;
            if l_sub(st.core_brate, MINIMUM_RATE_TO_ENCODE_VOICING_FLAG) > 0 {
                st.hq_voicing = 1;
            }
        }
    }

    // set inner frame (== coded bandwidth) length
    w.inner_frame = INNER_FRAME_TBL
        .get(usize::try_from(st.bwidth).unwrap_or(0))
        .copied()
        .unwrap_or(L_FRAME8K);

    if st.bfi == 0 {
        st.ph_ecu_hq_voicing = 0;
        if sub(output_frame, L_FRAME16K) >= 0 {
            st.ph_ecu_hq_voicing = st.hq_voicing;
        }
    }

    if sub(output_frame, L_FRAME8K) == 0 {
        let mut sfmsize: &'static [i16] = &[];
        hq_configure_bfi(
            &mut w.nb_sfm,
            &mut w.num_sb,
            &mut w.num_bands_p,
            &mut sfmsize,
            &mut w.sfm_start,
            &mut w.sfm_end,
        );
    }
}

/// The transform-domain decoding of a lost frame: the phase ECU (wideband and up) or the
/// frequency-domain concealment (8 kHz output), and the HQ -> ACELP safety state.
fn hq_core_dec_conceal(st: &mut DecoderState, w: &mut HqWork, output_frame: i16) {
    w.is_transient = st.old_is_transient[0];
    if sub(output_frame, L_FRAME16K) >= 0 {
        // Apply phase ecu for WB, SWB and FB; ecu_rec sent to OLA, env_stab passed in ph_ecu_st
        hq_ecu(st, &mut w.t_audio_q, &mut w.gapsynth, output_frame);
    } else {
        hq_fec_processing(
            st,
            &mut w.t_audio_q,
            w.is_transient,
            w.num_sb,
            w.nb_sfm,
            &w.num_bands_p,
            output_frame,
            w.sfm_start,
            w.sfm_end,
        );
    }

    st.old_is_transient[2] = st.old_is_transient[1];
    st.old_is_transient[1] = st.old_is_transient[0];

    if sub(output_frame, L_FRAME16K) >= 0 {
        // keep st->previoussynth updated as in FEC_HQ_pitch_analysis but no LP analysis
        let delay_comp = ns2sa_fx2(st.output_fs, DELAY_CLDFB_NS);
        let (output, delay) = (output_frame as usize, delay_comp as usize);
        st.previoussynth.copy_within(delay..output, 0);
        st.previoussynth[output - delay..output].copy_from_slice(&st.delay_buf_out[..delay]);

        // flag_uv = 1: disable costly pitch out synthesis in bfi frame
        st.hq_voicing = sub(1, 1); // safety setting for HQ->ACELP switch logic
                                   // safety, create a known signal state for HQ->ACELP switch logic
        set16(&mut st.fer_samples, 0, L_FRAME48K);
    }
}

/// The transform-domain decoding of a good frame: the low- or high-rate HQ decoder and the scaling
/// to the nominal level, then the concealment memory update.
fn hq_core_dec_transform(
    st: &mut DecoderState,
    w: &mut HqWork,
    output_frame: i16,
    hq_core_type: i16,
    core_switching_flag: i16,
) {
    if sub(hq_core_type, LOW_RATE_HQ_CORE) == 0 {
        if sub(st.prev_bfi, 1) == 0 {
            set32(&mut st.last_ni_gain, 0, crate::evs::cnst::BANDS_MAX);
            set16(&mut st.last_env, 0, crate::evs::cnst::BANDS_MAX);
            st.last_max_pos_pulse = 0;
        }

        // HQ low rate decoder
        hq_lr_dec(
            st,
            &mut w.t_audio_q,
            w.inner_frame,
            w.num_bits,
            &mut w.is_transient,
        );

        w.hqswb_clas = w.is_transient;
        w.q_audio = 12;
    } else {
        // HQ high rate decoder
        hq_hr_dec(
            st,
            &mut w.t_audio_q,
            w.inner_frame,
            w.num_bits,
            &mut w.ynrm,
            &mut w.is_transient,
            &mut w.hqswb_clas,
            &mut w.swb_fenv,
        );
        w.q_audio = 12;
    }

    // scaling (coefficients are in nominal level)
    if sub(output_frame, NORM_MDCT_FACTOR) != 0 {
        if sub(output_frame, L_FRAME32K) == 0 {
            w.q_audio = sub(w.q_audio, 1); // Multiply by 2
        } else {
            let index = mult_r(output_frame, 410 / 2); // 1/8000 in Q15
            let ener_match = HQ_NOMINAL_SCALING_INV
                .get(usize::try_from(index).unwrap_or(0))
                .copied()
                .unwrap_or(0);
            for i in 0..w.inner_frame.max(0) as usize {
                // t_audio_q[i] *= ener_match; 12+13-15=10
                let (l_tmp, lsb) = mpy_32_16_ss(w.t_audio_q[i], ener_match);
                w.t_audio_q[i] = l_add(l_shl(l_tmp, 2), i32::from(lshr(lsb as i16, 14)));
                // Q12
            }
        }
    }

    hq_fec_mem_update(
        st,
        &w.t_audio_q,
        &mut w.normq,
        &mut w.ynrm,
        &w.num_bands_p,
        w.is_transient,
        w.hqswb_clas,
        core_switching_flag,
        w.nb_sfm,
        w.num_sb,
        &mut w.mean_en_high,
        hq_core_type,
        output_frame,
    );
}

/// Attenuate HFs in case of band-width switching (from higher BW to lower BW), then keep the
/// last lines of the spectrum for the WB/SWB bandwidth switching.
fn hq_core_dec_bandwidth_switching(st: &mut DecoderState, w: &mut HqWork) {
    if st.bws_cnt1 > 0 {
        let ener_match = if sub(st.bws_cnt1, N_NS2W_FRAMES) == 0 {
            32767 // Q15
        } else {
            div_s(st.bws_cnt1, N_NS2W_FRAMES) // Q15
        };
        let low_edge = INNER_FRAME_TBL_FX
            .get(usize::try_from(sub(st.bwidth, 1)).unwrap_or(0))
            .copied()
            .unwrap_or(0);

        if w.is_transient != 0 {
            for i in 0..NUM_TIME_SWITCHING_BLOCKS {
                let tmp_loop = mult(w.inner_frame, 8192);
                let mut j = mult(low_edge, 8192);
                while j < tmp_loop {
                    let tmp = mult(i_mult(i, w.inner_frame), 8192); // Q0
                    let index = add(tmp, j) as usize;
                    w.t_audio_q[index] = mult_32_16(w.t_audio_q[index], ener_match); // Q12
                    j += 1;
                }
            }
        } else {
            for i in low_edge..w.inner_frame {
                let index = i as usize;
                w.t_audio_q[index] = mult_32_16(w.t_audio_q[index], ener_match);
                // Q12
            }
        }
    }

    // WB/SWB bandwidth switching
    if w.is_transient != 0 {
        copy_scale_sig_32_16(&w.t_audio_q[240..], &mut st.t_audio_q, 80, -13);
    } else {
        copy_scale_sig_32_16(&w.t_audio_q, &mut st.t_audio_q, L_FRAME, -13);
    }
}

/// Inverse transform, overlap-add and pre-echo reduction.
fn hq_core_dec_synthesis(
    st: &mut DecoderState,
    w: &mut HqWork,
    synth: &mut [i16],
    q_synth: &mut i16,
    output_frame: i16,
) {
    if sub(output_frame, L_FRAME8K) == 0 || st.bfi == 0 {
        if sub(w.inner_frame, output_frame) != 0 && sub(st.bfi, 1) == 0 {
            inverse_transform(
                &w.t_audio_q,
                &mut w.q_audio,
                &mut w.wtda_audio,
                w.is_transient,
                output_frame,
                output_frame,
            );
        } else {
            inverse_transform(
                &w.t_audio_q,
                &mut w.q_audio,
                &mut w.wtda_audio,
                w.is_transient,
                output_frame,
                w.inner_frame,
            );
        }
        *q_synth = w.q_audio;
    }

    if sub(output_frame, L_FRAME8K) == 0 {
        hq_core_dec_synthesis_nb(st, w, synth, q_synth, output_frame);
    } else {
        if sub(st.bfi, 1) == 0 && sub(output_frame, L_FRAME16K) >= 0 {
            // PHASE_ECU active
            w.q_audio = 15;
            window_ola(
                &w.t_audio_q,
                synth,
                &mut w.q_audio,
                &mut st.old_out,
                &mut st.q_old_wtda,
                output_frame,
                ALDO_WINDOW,
                ALDO_WINDOW,
                i16::from(st.prev_bfi != 0 && st.ph_ecu_active == 0),
                st.old_hq_voicing,
                Some(&mut st.oldgapsynth),
            );
            *q_synth = w.q_audio;
        } else {
            // no BFI or baseline PLC active
            window_ola(
                &w.wtda_audio,
                synth,
                q_synth,
                &mut st.old_out,
                &mut st.q_old_wtda,
                output_frame,
                st.tcx_cfg.tcx_last_overlap_mode,
                st.tcx_cfg.tcx_curr_overlap_mode,
                i16::from(st.prev_bfi != 0 && st.ph_ecu_active == 0),
                st.old_hq_voicing,
                Some(&mut st.oldgapsynth),
            );
        }

        hq_core_dec_preecho(st, w, synth, *q_synth, output_frame);
    }
}

/// The 8 kHz output branch of the synthesis: the time-domain concealment around losses or the
/// plain overlap-add, then the pre-echo reduction.
fn hq_core_dec_synthesis_nb(
    st: &mut DecoderState,
    w: &mut HqWork,
    synth: &mut [i16],
    q_synth: &mut i16,
    output_frame: i16,
) {
    if st.bfi == 0 && st.prev_bfi == 0 {
        copy_scale_sig(
            &st.old_out[N_ZERO_NB as usize..],
            &mut st.prev_oldau_out,
            sub(output_frame, N_ZERO_NB),
            negate(st.q_old_wtda),
        );
    } else if sub(st.prev_bfi, 1) == 0 {
        set16(&mut st.prev_oldau_out, 0, output_frame);
    }

    if (sub(st.prev_bfi, 1) == 0 || sub(st.bfi, 1) == 0)
        && st.old_is_transient[2] == 0
        && sub(st.last_core, HQ_CORE) == 0
        && sub(st.last_codec_mode, MODE1) == 0
    {
        time_domain_fec_hq(
            st,
            &w.wtda_audio,
            synth,
            w.mean_en_high,
            output_frame,
            q_synth,
        );
    } else {
        window_ola(
            &w.wtda_audio,
            synth,
            q_synth,
            &mut st.old_out,
            &mut st.q_old_wtda,
            output_frame,
            st.tcx_cfg.tcx_last_overlap_mode,
            st.tcx_cfg.tcx_curr_overlap_mode,
            st.prev_bfi,
            st.old_hq_voicing,
            Some(&mut st.oldgapsynth),
        );
        st.phase_mat_next = 0;
    }

    hq_core_dec_preecho(st, w, synth, *q_synth, output_frame);
}

/// `preecho_sb_fx` of the synthesis, run on good frames or below wideband output.
fn hq_core_dec_preecho(
    st: &mut DecoderState,
    w: &HqWork,
    synth: &mut [i16],
    q_synth: i16,
    output_frame: i16,
) {
    if (st.bfi == 0 && st.prev_bfi == 0) || sub(output_frame, L_FRAME16K) < 0 {
        let mut state = PreechoState {
            memfilt_lb: &mut st.memfilt_lb,
            mean_prev_hb: &mut st.mean_prev_hb,
            smoothmem: &mut st.smoothmem,
            mean_prev: &mut st.mean_prev,
            mean_prev_nc: &mut st.mean_prev_nc,
            wmold_hb: &mut st.wmold_hb,
            prevflag: &mut st.prevflag,
            pastpre: &mut st.pastpre,
        };
        preecho_sb(
            st.core_brate,
            &w.wtda_audio,
            w.q_audio,
            synth,
            q_synth,
            output_frame,
            &mut state,
            st.bwidth,
        );
    }
}

/// Recovery from a MODE2 (TCX) concealment: the waveform adjustment (`waveform_adj2_fix`) of the
/// first good frame, from the periodic extension of the last concealed one.
fn hq_core_dec_recovery(st: &mut DecoderState, synth: &mut [i16], q_synth: i16) {
    if st.bfi == 0
        && st.prev_bfi != 0
        && l_sub(st.last_total_brate, HQ_48K) >= 0
        && sub(st.last_codec_mode, MODE2) == 0
        && (sub(st.last_core_bfi, TCX_20_CORE) == 0 || sub(st.last_core_bfi, TCX_10_CORE) == 0)
        && st.plc_info.concealment_method == TCX_NONTONAL
        && st.plc_info.nb_lost_cmpt < 4
    {
        st.plc_info.recovery_gain = shl(st.plc_info.recovery_gain, q_synth);
        let overlap_at = st.tonal_mdc_tconceal.second_last_pcm_out.unwrap_or(0);
        waveform_adj2_fix(
            &mut st.tonal_mdc_tconceal.time_data_buffer[overlap_at..],
            synth,
            &mut st.plc_info.data_noise,
            &mut st.plc_info.outx_new_n1,
            &mut st.plc_info.nsapp_gain,
            &mut st.plc_info.nsapp_gain_n,
            &mut st.plc_info.recovery_gain,
            st.plc_info.step_concealgain,
            st.plc_info.pitch,
            st.plc_info.frame_size,
            0,
            add(extract_l(st.plc_info.nb_lost_cmpt), 1),
            st.bfi,
        );
    }
}

/// The HQ voicing memory, the 8 kHz history buffers and the pitch memories at the end of
/// `hq_core_dec_fx`.
fn hq_core_dec_update(
    st: &mut DecoderState,
    w: &HqWork,
    synth: &[i16],
    q_synth: i16,
    output_frame: i16,
) {
    if sub(output_frame, L_FRAME16K) >= 0 {
        if sub(st.ph_ecu_hq_voicing, 1) == 0 {
            st.old_hq_voicing = 1;
            copy(&w.gapsynth, &mut st.oldgapsynth, L_FRAME48K);
        } else {
            st.old_hq_voicing = 0;
        }
    } else {
        st.old_hq_voicing = 0;
    }

    if sub(st.nb_lost_cmpt, FRAMECTTOSTART_MDCT) == 0 {
        st.hq_voicing = 0;
    }

    if sub(output_frame, L_FRAME8K) == 0 {
        let half = (L_FRAME8K / 2) as usize;
        st.old_imdc_tout[..half].copy_from_slice(&w.wtda_audio[..half]);
        let frame = output_frame as usize;
        st.old_au_out_2fr.copy_within(frame..2 * frame, 0);
        copy_scale_sig(
            synth,
            &mut st.old_au_out_2fr[frame..],
            output_frame,
            negate(q_synth),
        );
    }

    // prepare synthesis output buffer (as recent as possible) for HQ FEC
    let mut nbsubfr: i16 = 4;
    if sub(st.l_frame, 320) == 0 {
        nbsubfr = 5;
    }
    let count = nbsubfr as usize;

    // update buffer of old subframe pitch values
    if sub(st.last_core, HQ_CORE) == 0 && sub(st.l_frame, st.last_l_frame) != 0 {
        set32(
            &mut st.old_pitch_buf[count..],
            i32::from(L_SUBFR) << 16,
            nbsubfr,
        );
    }
    st.old_pitch_buf.copy_within(count..2 * count, 0);
    set32(
        &mut st.old_pitch_buf[count..],
        i32::from(L_SUBFR) << 16,
        nbsubfr,
    );
    st.mem_pitch_gain.copy_within(2..2 + count, count + 2);
    set16(&mut st.mem_pitch_gain[2..], 0, nbsubfr);
}
