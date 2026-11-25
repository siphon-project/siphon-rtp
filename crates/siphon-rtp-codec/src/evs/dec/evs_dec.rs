//! The per-frame decoder dispatcher (TS 26.442 `lib_dec/evs_dec_fx.c`): decision matrix, ACELP or
//! HQ core, core and bandwidth switching, bandwidth extension, delay alignment of the
//! extension layers, high-pass filtering, output conversion and the end-of-frame updates, for the
//! MODE1 (ACELP / HQ) frames, and for MODE2 (TCX / LPD) frames the `ELSE /* MODE2 PART */` block
//! (`mode2`: the LPD core, IGF / TBE interface and the CLDFB post-processing) followed by the
//! same tail. A frame that needs AMR-WB IO is refused with [`EvsError::Unsupported`]; it never
//! produces audio.

mod mode2;

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_CORE, AMR_WB_CORE, AUDIO, BUF_DEC_RATE, DELAY_BWE_TOTAL_NS, DELAY_CLDFB_NS,
    DELAY_SWB_TBE_12K8_NS, DELAY_SWB_TBE_16K_NS, FB_BWE, FB_BWE_HIGHRATE, FB_TBE, FRAME_NO_DATA,
    HQ_48K, HQ_CORE, HQ_DELAY_COMP, HQ_DELTA_MAX, INACTIVE, LG10, LP_CNG, L_FRAME, L_FRAME16K,
    L_FRAME32K, L_FRAME48K, MAX_DELAY_TBE_NS, MIN_ACT_CNG_UPD, MODE1, MODE2, NB, NB_SUBFR,
    NB_SUBFR16K, NL_BUFF_OFFSET, N_ZERO_MDCT_NS, PH_ECU_LOOKAHEAD_NS, PH_ECU_MEM_NS,
    POST_HQ_DELAY_NS, RF_NO_DATA, RF_TCXFD, RF_TCXTD2, SID_2K40, SWB_BWE, SWB_BWE_HIGHRATE,
    SWB_CNG, SWB_TBE, TCXLTP_DELAY_NS, TCX_10_CORE, TCX_20_CORE, TCX_NONTONAL, WB_BWE, WB_TBE,
};
use crate::evs::com::basop_util::idiv1616;
use crate::evs::com::bitstream::{get_partial_copy_info, FRAMEMODE_MISSING};
use crate::evs::com::core_com_config::{get_tcxonly, sr2fscale};
use crate::evs::com::hp50::hp20;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::tcx_ltp::tcx_ltp_post;
use crate::evs::com::tools::{add_vec, copy_scale_sig, random, scale_sig, scale_sig32, set16};
use crate::evs::dec::acelp_core_dec::acelp_core_dec;
use crate::evs::dec::cng_dec::swb_cng_dec;
use crate::evs::dec::core_switching_dec::{
    bandwidth_switching_detect, bw_switching_pre_proc, core_switching_post_dec,
    core_switching_pre_dec,
};
use crate::evs::dec::dec_acelp_tcx_main::DEC_CONCEALMENT_EXT;
use crate::evs::dec::decision_matrix_dec::decision_matrix_dec;
use crate::evs::dec::hq_core_dec::hq_core_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_bwe_dec::{swb_bwe_dec, wb_bwe_dec};
use crate::evs::dec::swb_bwe_dec_hr::swb_bwe_dec_hr;
use crate::evs::dec::swb_tbe_dec::{fb_tbe_dec, swb_tbe_dec, wb_tbe_dec};
use crate::evs::dec::syn_outp::syn_output;
use crate::evs::dec::updt_dec::{updt_bw_switching, updt_dec_common};
use crate::evs::dec::waveadjust_fec_dec::{concealment_update2_x, waveform_adj2_fix};
use crate::evs::error::{EvsError, UnsupportedMode};
use crate::evs::macros::ns2sa_fx2;
use crate::evs::rom::SIN_TABLE256_FX;
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_deposit_l, l_mac, l_mult, l_shl, l_shr_r, mult, mult_r, negate,
    norm_l, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::{i_mult, l_mult0};

/// `RF_NELP` = `ACELP_MODE_MAX + 3`.
const RF_NELP: i16 = crate::evs::cnst::ACELP_MODE_MAX + 3;

/// `Qpostd`-independent size of `synth_fx`: `L_FRAME48k + HQ_DELTA_MAX*HQ_DELAY_COMP`.
const SYNTH_LEN: usize = L_FRAME48K as usize + (HQ_DELTA_MAX * HQ_DELAY_COMP) as usize;

/// The locals of `evs_dec_fx` the MODE1 stages share.
struct FrameWork {
    bwe_exc_extended: [i32; L_FRAME32K as usize + NL_BUFF_OFFSET as usize],
    voice_factors: [i16; NB_SUBFR16K as usize],
    hb_synth: [i16; L_FRAME48K as usize],
    hb_synth_exp: i16,
    tmp_buffer: [i16; L_FRAME48K as usize],
    synth: [i16; SYNTH_LEN],
    pitch_buf: [i16; NB_SUBFR16K as usize],
    old_syn_12k8_16k: [i16; L_FRAME16K as usize],
    sid_bw: i16,
    unbits: i16,
    /// The FB TBE excitation `swb_tbe_dec` hands `fb_tbe_dec` (`fb_exc_fx`), and its Q.
    fb_exc: [i16; L_FRAME16K as usize],
    q_fb_exc: i16,
    coder_type: i16,
    sharp_flag: i16,
    hq_core_type: i16,
    core_switching_flag: i16,
    qpostd: i16,
    qpostd_prev: i16,
    output_frame: i16,
}

impl FrameWork {
    /// The locals of `evs_dec_fx` at the start of a frame.
    fn new() -> Self {
        Self {
            bwe_exc_extended: [0; L_FRAME32K as usize + NL_BUFF_OFFSET as usize],
            voice_factors: [0; NB_SUBFR16K as usize],
            hb_synth: [0; L_FRAME48K as usize],
            hb_synth_exp: 0,
            tmp_buffer: [0; L_FRAME48K as usize],
            synth: [0; SYNTH_LEN],
            pitch_buf: [0; NB_SUBFR16K as usize],
            old_syn_12k8_16k: [0; L_FRAME16K as usize],
            sid_bw: -1,
            unbits: 0,
            fb_exc: [0; L_FRAME16K as usize],
            q_fb_exc: 0,
            coder_type: INACTIVE,
            sharp_flag: 0,
            hq_core_type: -1,
            core_switching_flag: 0,
            qpostd: 0,
            qpostd_prev: 0,
            output_frame: 0,
        }
    }
}

/// `sin_table256_fx[index]`; the index is a multiple of the interpolation step below 256.
fn sin_table256(index: i16) -> i16 {
    SIN_TABLE256_FX
        .get(usize::try_from(index).unwrap_or(0))
        .copied()
        .unwrap_or(0)
}

/// `evs_dec_fx`: decode the frame the decoder state holds (`st.bfi`, the indices and bit stream
/// read by `read_indices`) into `output_sp` (`output_frame` samples at the output rate, Q0).
/// `frame_mode` is `FRAMEMODE_NORMAL` or `FRAMEMODE_MISSING`.
///
/// # Errors
/// [`EvsError::Unsupported`] for a frame that needs AMR-WB IO, which this port does not run yet;
/// the state is then mid-frame and the decoder must not be used further.
pub fn evs_dec(
    st: &mut DecoderState,
    output_sp: &mut [i16],
    frame_mode: i16,
) -> Result<(), EvsError> {
    let mut w = FrameWork::new();

    if st.bfi == 0 {
        st.extl = -1;
    }
    w.output_frame = st.output_frame;
    st.use_partial_copy = 0;
    st.rf_flag = 0;
    w.qpostd_prev = st.qprev_synth_buffer;

    if sub(st.bfi, 1) == 0 {
        w.hq_core_type = st.last_hq_core_type;
        w.coder_type = st.last_coder_type;
    }

    // PLC: [TCX: Fade-out-recovery]: the first good frame after a TCX concealment; the
    // overlapping part needs to be attenuated
    if st.bfi == 0
        && st.prev_bfi != 0
        && sub(st.last_codec_mode, MODE2) == 0
        && (sub(st.last_core_bfi, TCX_20_CORE) == 0 || sub(st.last_core_bfi, TCX_10_CORE) == 0)
    {
        evs_dec_fade_out_recovery(st);
    }

    st.rate_switching_reset = 0;
    if st.bfi == 0 {
        st.flag_guided_acelp = 0;
    }

    // Updates in case of AMR-WB IO mode -> EVS primary switching
    if sub(st.last_core, AMR_WB_CORE) == 0 {
        return Err(EvsError::Unsupported {
            mode: UnsupportedMode::AmrWbIo,
            reference_call: "updt_IO_switch_dec_fx",
        });
    }

    let mut frame_mode = frame_mode;
    if sub(frame_mode, FRAMEMODE_MISSING) != 0 {
        // frame mode normal or future frame
        get_partial_copy_info(st, &mut w.coder_type, &mut w.sharp_flag);
        frame_mode = st.bfi;
    }
    evs_dec_partial_copy(st, &mut frame_mode);

    if sub(st.codec_mode, MODE1) != 0 {
        // MODE2 PART
        let conceal_whole_frame = mode2::evs_dec_mode2(st, &mut w, output_sp, &mut frame_mode)?;
        return evs_dec_finish(st, &mut w, output_sp, frame_mode, conceal_whole_frame);
    }

    // Decision matrix (selection of technologies)
    if sub(st.bfi, 1) != 0 {
        decision_matrix_dec(
            st,
            &mut w.coder_type,
            &mut w.sharp_flag,
            &mut w.hq_core_type,
            &mut w.core_switching_flag,
        );
        if sub(st.bfi, 1) != 0 {
            st.sr_core = i32::from(i_mult(st.l_frame, 50));
            st.fscale_old = st.fscale;
            st.fscale = sr2fscale(st.sr_core);
        }
    }

    evs_dec_core(st, &mut w)?;
    evs_dec_extension(st, &mut w)?;
    evs_dec_delay_alignment(st, &mut w);
    evs_dec_add_extension(st, &mut w)?;
    evs_dec_postfilter(st, &mut w);
    evs_dec_finish(st, &mut w, output_sp, frame_mode, false)
}

/// The first good frame after a TCX concealment: the overlap and the PLC memories are faded by
/// the recovery gain, and, if no ALDO window is used, the overlap buffers by the concealment
/// end-of-frame gain.
fn evs_dec_fade_out_recovery(st: &mut DecoderState) {
    let recovery_gain = st.plc_info.recovery_gain;
    for sample in &mut st.old_out[..st.l_frame_tcx.max(0) as usize] {
        *sample = shl(mult_r(*sample, recovery_gain), 1);
    }
    for sample in &mut st.old_out_lb[..st.l_frame.max(0) as usize] {
        *sample = shl(mult_r(*sample, recovery_gain), 1);
    }
    // attenuate PLC buffers, if no aldo window is used and if no sid or zero frame is received
    if st.tcx_cfg.last_aldo == 0 {
        // Q14
        let f = l_deposit_l(st.conceal_eof_gain);
        let mut s = sub(16, norm_l(f));
        let mut factor = extract_l(l_shr_r(f, s));
        for sample in &mut st.syn_overl_fb[..st.tcx_cfg.tcx_mdct_window_length_fb.max(0) as usize] {
            *sample = shl(mult(factor, *sample), add(s, 1));
        }
        s = sub(16, norm_l(f));
        factor = extract_l(l_shr_r(f, s));
        for sample in &mut st.syn_overl[..st.tcx_cfg.tcx_mdct_window_length.max(0) as usize] {
            *sample = shl(mult(factor, *sample), s);
        }
    }
}

/// The partial-copy (channel-aware) preamble of `evs_dec_fx`: a partial copy that cannot be used
/// is dropped and the frame concealed.
fn evs_dec_partial_copy(st: &mut DecoderState, frame_mode: &mut i16) {
    if sub(st.rf_frame_type, RF_NO_DATA) == 0 && sub(st.use_partial_copy, 1) == 0 {
        // the partial copy is a RF FRAME_NO_DATA frame and should follow the concealment path
        st.bfi = 1;
        st.codec_mode = st.last_codec_mode;
        *frame_mode = FRAMEMODE_MISSING;
        st.use_partial_copy = 0;
    }

    // if previous frame was concealed via ACELP, drop TCX partial copy info and continue ACELP
    // concealment
    if sub(st.use_partial_copy, 1) == 0
        && sub(st.core, TCX_20_CORE) == 0
        && sub(st.prev_bfi, 1) == 0
        && sub(st.last_core, ACELP_CORE) == 0
    {
        st.bfi = 1;
        st.codec_mode = st.last_codec_mode;
        *frame_mode = FRAMEMODE_MISSING;
        st.use_partial_copy = 0;
        st.core = ACELP_CORE;
    }

    // if previous frame was HQ Core or TCX10, drop partial copy info and continue HQ Core/TCX10
    // concealment
    if st.use_partial_copy != 0
        && (sub(st.last_core, HQ_CORE) == 0
            || sub(st.last_core, TCX_10_CORE) == 0
            || (sub(st.last_core, TCX_20_CORE) == 0 && get_tcxonly(st.last_total_brate) != 0))
    {
        st.bfi = 1;
        st.codec_mode = st.last_codec_mode;
        *frame_mode = FRAMEMODE_MISSING;
        st.use_partial_copy = 0;
        st.core = st.last_core;
    }
}

/// Initialisation, bandwidth-switching detection, core-switching preparation, the ACELP or HQ
/// core decoding and the switching post-processing.
fn evs_dec_core(st: &mut DecoderState, w: &mut FrameWork) -> Result<(), EvsError> {
    if sub(st.bfi, 1) == 0 {
        st.nb_lost_cmpt = add(st.nb_lost_cmpt, 1);
    } else {
        st.nb_lost_cmpt = 0;
    }
    st.enable_plc_waveadjust = 0;

    // Detect bandwidth switching
    bandwidth_switching_detect(st);

    // Preprocessing (preparing) for ACELP/HQ core switching
    core_switching_pre_dec(st, w.output_frame);

    // ACELP core decoding, HQ core decoding
    if sub(st.core, ACELP_CORE) == 0 {
        acelp_core_dec(
            st,
            &mut w.synth,
            &mut w.bwe_exc_extended,
            &mut w.voice_factors,
            &mut w.old_syn_12k8_16k,
            w.coder_type,
            w.sharp_flag,
            &mut w.pitch_buf,
            &mut w.unbits,
            &mut w.sid_bw,
        );
        w.qpostd = st.q_syn2;
    } else {
        let mut q_synth = 0;
        hq_core_dec(
            st,
            &mut w.synth,
            &mut q_synth,
            w.output_frame,
            w.hq_core_type,
            w.core_switching_flag,
        );
        w.qpostd = q_synth;
    }

    // Postprocessing for ACELP/HQ core switching
    core_switching_post_dec(
        st,
        &mut w.synth,
        w.output_frame,
        w.core_switching_flag,
        w.coder_type,
        &mut w.qpostd,
    );

    // Pre-processing for bandwidth switching
    bw_switching_pre_proc(&w.old_syn_12k8_16k, st);
    Ok(())
}

/// The WB / SWB / FB bandwidth-extension decoders, the smoothing after a lost HQ frame and the
/// SHB comfort noise.
fn evs_dec_extension(st: &mut DecoderState, w: &mut FrameWork) -> Result<(), EvsError> {
    if sub(st.extl, WB_TBE) == 0 {
        // WB TBE decoder
        let q_exc = st.q_exc;
        wb_tbe_dec(
            st,
            w.coder_type,
            &w.bwe_exc_extended,
            q_exc,
            &w.voice_factors,
            &mut w.hb_synth,
            &mut w.hb_synth_exp,
        );
    } else if sub(st.extl, WB_BWE) == 0 && st.bws_cnt == 0 {
        // WB BWE decoder
        w.hb_synth_exp = wb_bwe_dec(
            &mut w.synth,
            &mut w.hb_synth,
            w.output_frame,
            w.coder_type,
            &w.voice_factors,
            &w.pitch_buf,
            st,
            &mut w.qpostd,
        );
    }

    // SWB TBE decoding, SWB BWE decoding, FB TBE decoding
    let shb_bws = sub(w.coder_type, AUDIO) != 0
        && sub(w.coder_type, INACTIVE) != 0
        && st.core_brate > i32::from(SID_2K40)
        && sub(st.core, ACELP_CORE) == 0
        && st.output_fs >= 32000
        && sub(st.bwidth, NB) > 0
        && st.bws_cnt > 0
        && st.ppp_mode_dec == 0
        && !(sub(st.nelp_mode_dec, 1) == 0 && sub(st.bfi, 1) == 0);
    if sub(st.extl, SWB_TBE) == 0 || sub(st.extl, FB_TBE) == 0 || shb_bws {
        let q_exc = st.q_exc;
        swb_tbe_dec(
            st,
            w.coder_type,
            &w.bwe_exc_extended,
            q_exc,
            &w.voice_factors,
            &w.old_syn_12k8_16k,
            &mut w.fb_exc,
            &mut w.q_fb_exc,
            &mut w.hb_synth,
            &mut w.hb_synth_exp,
            &w.pitch_buf,
        );

        // FB TBE decoder / synthesis
        if sub(w.output_frame, L_FRAME48K) == 0 && sub(st.extl, FB_TBE) == 0 {
            fb_tbe_dec(st, &w.fb_exc, w.q_fb_exc, &mut w.hb_synth, w.hb_synth_exp);
        }
    } else if sub(st.extl, SWB_BWE) == 0
        || sub(st.extl, FB_BWE) == 0
        || (st.output_fs >= 32000
            && sub(st.core, ACELP_CORE) == 0
            && sub(st.bwidth, NB) > 0
            && st.bws_cnt > 0
            && st.ppp_mode_dec == 0
            && !(sub(st.nelp_mode_dec, 1) == 0 && sub(st.bfi, 1) == 0))
    {
        // SWB BWE decoder
        w.hb_synth_exp = swb_bwe_dec(
            st,
            &mut w.synth,
            &mut w.hb_synth,
            w.output_frame,
            &mut w.qpostd,
            w.coder_type,
        );
    } else if sub(st.extl, SWB_BWE_HIGHRATE) == 0 || sub(st.extl, FB_BWE_HIGHRATE) == 0 {
        w.hb_synth_exp = swb_bwe_dec_hr(
            st,
            &w.old_syn_12k8_16k,
            w.qpostd,
            &mut w.hb_synth,
            w.output_frame,
            w.unbits,
            &w.pitch_buf,
        );
    }

    // FEC - recovery after lost HQ core (smoothing of the BWE component)
    if st.prev_bfi != 0 && sub(st.last_core, HQ_CORE) == 0 && sub(st.extl, -1) != 0 {
        // tmp = FRAC_BWE_SMOOTH/output_frame
        let mut step = shr(410, shr(w.output_frame, 8));
        if sub(w.output_frame, L_FRAME48K) == 0 {
            step = 68;
        }
        // output_frame/FRAC_BWE_SMOOTH
        let half = shr(w.output_frame, 1);
        let mut ramp = 0;
        for sample in &mut w.hb_synth[..half.max(0) as usize] {
            // hb_synth[i] *= (i*tmp)
            *sample = mult_r(*sample, ramp);
            ramp = add(ramp, step);
        }
    }

    // SWB CNG
    if sub(w.output_frame, L_FRAME32K) >= 0 {
        // SHB CNG decoder
        swb_cng_dec(st, &w.synth, &mut w.hb_synth, w.sid_bw, w.qpostd);
        if st.core_brate <= i32::from(SID_2K40) && st.bws_cnt == 0 {
            w.hb_synth_exp = 3;
        }
    }
    Ok(())
}

/// Delay the ACELP core synthesis to be synchronised with the components of the bandwidth
/// extension layers.
fn evs_dec_delay_alignment(st: &mut DecoderState, w: &mut FrameWork) {
    let output = w.output_frame as usize;
    if sub(w.output_frame, L_FRAME16K) >= 0 {
        let tmps = ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS);
        let delay = tmps as usize;

        let exp = w.qpostd.min(st.qprev_synth_buffer);
        scale_sig(&mut w.synth, w.output_frame, sub(exp, w.qpostd));
        w.qpostd = exp;
        scale_sig(
            &mut st.prev_synth_buffer,
            tmps,
            sub(exp, st.qprev_synth_buffer),
        );
        st.qprev_synth_buffer = exp;
        w.tmp_buffer[..output].copy_from_slice(&w.synth[..output]);
        w.synth[..delay].copy_from_slice(&st.prev_synth_buffer[..delay]);
        w.synth[delay..output].copy_from_slice(&w.tmp_buffer[..output - delay]);
        st.prev_synth_buffer[..delay].copy_from_slice(&w.tmp_buffer[output - delay..output]);
    } else {
        let exp = w.qpostd.min(st.qprev_synth_buffer);
        scale_sig(&mut w.synth, w.output_frame, sub(exp, w.qpostd));
        w.qpostd = exp;
        st.qprev_synth_buffer = exp;
    }

    // waveform adjustment after a TCX concealment (MODE2 recovery)
    if sub(st.core, ACELP_CORE) == 0
        && st.bfi == 0
        && st.prev_bfi != 0
        && st.last_total_brate >= HQ_48K
        && sub(st.last_codec_mode, MODE2) == 0
        && (sub(st.last_core_bfi, TCX_20_CORE) == 0 || sub(st.last_core_bfi, TCX_10_CORE) == 0)
        && st.plc_info.concealment_method == TCX_NONTONAL
        && st.plc_info.nb_lost_cmpt < 4
    {
        let tmps = if sub(w.output_frame, L_FRAME16K) >= 0 {
            ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS)
        } else {
            0
        };
        let overlap_at = st.tonal_mdc_tconceal.second_last_pcm_out.unwrap_or(0);
        waveform_adj2_fix(
            &mut st.tonal_mdc_tconceal.time_data_buffer[overlap_at..],
            &mut w.synth[tmps.max(0) as usize..],
            &mut st.plc_info.data_noise,
            &mut st.plc_info.outx_new_n1,
            &mut st.plc_info.nsapp_gain,
            &mut st.plc_info.nsapp_gain_n,
            &mut st.plc_info.recovery_gain,
            st.plc_info.step_concealgain,
            st.plc_info.pitch,
            st.plc_info.frame_size,
            tmps,
            add(extract_l(st.plc_info.nb_lost_cmpt), 1),
            st.bfi,
        );
        st.plc_info.pitch = 0;
    }
}

/// Addition of the bandwidth-extension components to the ACELP core synthesis: delay and
/// cross-fade of the extension layer, then the sum.
fn evs_dec_add_extension(st: &mut DecoderState, w: &mut FrameWork) -> Result<(), EvsError> {
    if sub(st.extl, -1) != 0 || (st.bws_cnt > 0 && sub(st.core, ACELP_CORE) == 0) {
        evs_dec_add_extension_delay(st, w);

        if (st.ppp_mode_dec != 0 || (sub(st.nelp_mode_dec, 1) == 0 && sub(st.bfi, 1) == 0))
            && sub(st.l_frame, st.last_l_frame) == 0
            && (st.bws_cnt > 1 || st.last_extl != -1)
        {
            let output = w.output_frame as usize;
            w.hb_synth[..output].copy_from_slice(&st.old_hb_synth[..output]);
            if sub(st.prev_hb_synth_fx_exp, 14) < 0 {
                w.hb_synth_exp = add(st.prev_hb_synth_fx_exp, 1);
            } else {
                w.hb_synth_exp = 14;
            }
        } else {
            let output = w.output_frame as usize;
            st.old_hb_synth[..output].copy_from_slice(&w.hb_synth[..output]);
        }

        // add_vec_fx( synth, Qpostd, hb_synth, hb_synth_exp, synth, Qpostd, output_frame ): the
        // sum is per sample, so a copy of the input stands in for the aliased argument
        let output = w.output_frame as usize;
        w.tmp_buffer[..output].copy_from_slice(&w.synth[..output]);
        add_vec(
            &w.tmp_buffer,
            w.qpostd,
            &w.hb_synth,
            w.hb_synth_exp,
            &mut w.synth,
            w.qpostd,
            w.output_frame,
        );

        // SWB CNG/DTX - calculate SHB energy
        if sub(w.output_frame, L_FRAME32K) >= 0 && sub(st.extl, SWB_CNG) > 0 {
            evs_dec_shb_energy(st, w);
        }
    }
    st.prev_hb_synth_fx_exp = w.hb_synth_exp;
    Ok(())
}

/// The delay of the extension layer to the core synthesis and the smooth transition when the
/// technology (or the delay) changes.
fn evs_dec_add_extension_delay(st: &mut DecoderState, w: &mut FrameWork) {
    let output = w.output_frame as usize;
    // Calculate an additional delay of extension layer components to be synchronized with ACELP
    // synthesis
    let tmps: i16 = if sub(st.l_frame, L_FRAME) == 0 {
        // TBE on top of ACELP@12.8kHz
        ns2sa_fx2(st.output_fs, MAX_DELAY_TBE_NS - DELAY_SWB_TBE_12K8_NS)
    } else if sub(st.extl, SWB_BWE_HIGHRATE) == 0 || sub(st.extl, FB_BWE_HIGHRATE) == 0 {
        // HR SWB BWE on top of ACELP@16kHz
        ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS)
    } else {
        // TBE on top of ACELP@16kHz
        ns2sa_fx2(st.output_fs, MAX_DELAY_TBE_NS - DELAY_SWB_TBE_16K_NS)
    };
    let delay = tmps as usize;
    let old_delay = st.old_bwe_delay.max(0) as usize;

    // Smooth transitions when switching between different technologies
    if (sub(st.extl, st.last_extl) != 0
        || (sub(st.extl, st.last_extl) == 0 && sub(st.core ^ st.last_core, HQ_CORE) == 0))
        && !(sub(st.extl, SWB_CNG) == 0 && sub(st.last_extl, SWB_TBE) == 0)
    {
        // incr = (short) ( L_FRAME / (tmps + 0.5f) )
        let incr = idiv1616(L_FRAME * 2, add(shl(tmps, 1), 1));
        let mut phase = 0;
        for sample in &mut w.hb_synth[..delay] {
            *sample = mult_r(*sample, sin_table256(phase));
            phase = add(phase, incr);
        }
        set16(&mut st.hb_prev_synth_buffer, 0, tmps);
    } else if sub(tmps, st.old_bwe_delay) < 0 {
        // the previous frame was TBE on top of ACELP@16kHz and the current frame is TBE on top of
        // ACELP@12.8kHz
        let incr = idiv1616(L_FRAME * 2, add(shl(tmps, 1), 1));
        let mut phase = 0;
        for i in 0..delay {
            w.tmp_buffer[i] = round_word(l_mac(
                l_mult(st.hb_prev_synth_buffer[i], sin_table256(sub(255, phase))),
                st.hb_prev_synth_buffer[old_delay - 1 - i],
                sin_table256(phase),
            ));
            phase = add(phase, incr);
        }
        st.hb_prev_synth_buffer[..delay].copy_from_slice(&w.tmp_buffer[..delay]);
    } else if sub(tmps, st.old_bwe_delay) > 0 {
        // the previous frame was TBE on top of ACELP@12.8kHz and the current frame is TBE on top
        // of ACELP@16kHz
        let incr = idiv1616(L_FRAME * 2, add(shl(st.old_bwe_delay, 1), 1));
        let mut phase = 0;
        let mut i = 0;
        while i < old_delay {
            w.tmp_buffer[i] = mult_r(st.hb_prev_synth_buffer[i], sin_table256(sub(255, phase)));
            phase = add(phase, incr);
            i += 1;
        }
        while i < delay {
            w.tmp_buffer[i] = 0;
            i += 1;
        }
        phase = 0;
        for i in 0..old_delay {
            // tmp_buffer[tmps - 1 - i] += hb_prev_synth_buffer[old_bwe_delay - 1 - i] * sin_table256[i * incr]
            w.tmp_buffer[delay - 1 - i] = round_word(l_mac(
                l_mult(w.tmp_buffer[delay - 1 - i], 32767),
                st.hb_prev_synth_buffer[old_delay - 1 - i],
                sin_table256(phase),
            ));
            phase = add(phase, incr);
        }
        st.hb_prev_synth_buffer[..delay].copy_from_slice(&w.tmp_buffer[..delay]);
    }

    // Delay hb_synth
    let exponent_change = sub(w.hb_synth_exp, st.prev_hb_synth_fx_exp);
    if exponent_change != 0 {
        scale_sig(&mut st.hb_prev_synth_buffer, tmps, exponent_change);
    }
    w.tmp_buffer[..output].copy_from_slice(&w.hb_synth[..output]);
    w.hb_synth[..delay].copy_from_slice(&st.hb_prev_synth_buffer[..delay]);
    w.hb_synth[delay..output].copy_from_slice(&w.tmp_buffer[..output - delay]);
    st.hb_prev_synth_buffer[..delay].copy_from_slice(&w.tmp_buffer[output - delay..output]);

    st.old_bwe_delay = tmps;
}

/// SWB CNG/DTX: the energy of the high band, kept for the comfort noise.
fn evs_dec_shb_energy(st: &mut DecoderState, w: &FrameWork) {
    let scale: i16 = match w.output_frame {
        160 => 205, // Q15
        320 => 102, // Q15
        640 => 51,  // Q15
        _ => 34,    // Q15
    };
    let mut l_tmp = l_deposit_l(1); // Q2*hb_synth_fx_exp
    for &sample in &w.hb_synth[..w.output_frame as usize] {
        l_tmp = l_add(l_tmp, mpy_32_16_1(l_mult0(sample, sample), scale));
    }
    let exp = norm_l(l_tmp);
    let fra = log2_norm_lc(l_shl(l_tmp, exp));
    let exp = sub(sub(30, shl(w.hb_synth_exp, 1)), exp);
    let l_tmp = mpy_32_16(exp, fra, LG10);
    st.last_shb_ener = round_word(l_shl(l_tmp, 10)); // Q8
}

/// TCX-LTP postfilter (memories only in MODE1), the synthesis history for the HQ concealment, and
/// the high-pass filter.
fn evs_dec_postfilter(st: &mut DecoderState, w: &mut FrameWork) {
    let output = w.output_frame;
    // TCX-LTP Postfilter: used in MODE1 to update memories and to avoid discontinuities when the
    // past frame was TCX
    let delta = ns2sa_fx2(st.output_fs, TCXLTP_DELAY_NS);
    let rescale = sub(w.qpostd, w.qpostd_prev);
    scale_sig(&mut st.tcxltp_mem_in, delta, rescale);
    scale_sig(&mut st.tcxltp_mem_out, output, rescale);
    tcx_ltp_post(
        st.tcxltp,
        ACELP_CORE,
        output,
        st.l_frame_past,
        0,
        &mut w.synth,
        None,
        delta,
        0,
        0,
        0,
        0,
        &mut st.tcxltp_pitch_int_post_prev,
        &mut st.tcxltp_pitch_fr_post_prev,
        &mut st.tcxltp_gain_post_prev,
        &mut st.tcxltp_filt_idx_prev,
        st.pit_res_max,
        &mut st.pit_res_max_past,
        0,
        0,
        &mut st.tcxltp_mem_in,
        &mut st.tcxltp_mem_out,
        st.total_brate,
    );
}

/// Save the synthesis for the HQ concealment (`synth_history` / `old_synthFB`).
fn evs_dec_save_synthesis(st: &mut DecoderState, w: &FrameWork) {
    let output = w.output_frame;
    let frame = output as usize;
    let post_hq_delay = ns2sa_fx2(st.output_fs, POST_HQ_DELAY_NS);
    let fb = st.old_synth_fb;
    let delay_bwe = ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS) as usize;
    let delay_cldfb = ns2sa_fx2(st.output_fs, DELAY_CLDFB_NS);
    let count = sub(output, post_hq_delay) + ns2sa_fx2(st.output_fs, PH_ECU_MEM_NS);

    st.synth_history
        .copy_within(frame..frame + count as usize, 0);
    copy_scale_sig(
        &w.synth,
        &mut st.synth_history[fb + frame - post_hq_delay as usize..],
        output,
        negate(w.qpostd),
    ); // output_sp not initialized yet
       // reset the remaining buffer, which is read in TCX concealment; the necessary samples to fill
       // this buffer are not available for all cases, the impact on the output is limited
    set16(
        &mut st.synth_history[fb + 2 * frame - post_hq_delay as usize..],
        0,
        post_hq_delay,
    );

    if sub(output, L_FRAME16K) >= 0 {
        copy_scale_sig(
            &st.prev_synth_buffer,
            &mut st.synth_history[fb + 2 * frame - delay_bwe..],
            ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS),
            negate(st.qprev_synth_buffer),
        );
    }
    if sub(st.core, ACELP_CORE) != 0 {
        let look_ahead = ns2sa_fx2(st.output_fs, PH_ECU_LOOKAHEAD_NS);
        let zero_mdct = ns2sa_fx2(st.output_fs, N_ZERO_MDCT_NS) as usize;
        if sub(output, L_FRAME16K) >= 0 {
            copy_scale_sig(
                &w.synth[frame..],
                &mut st.synth_history[fb + 2 * frame - delay_cldfb as usize..],
                delay_cldfb,
                negate(w.qpostd),
            );
            copy_scale_sig(
                &st.old_out[zero_mdct..],
                &mut st.synth_history[fb + 2 * frame..],
                look_ahead,
                negate(st.q_old_wtda),
            );
        } else {
            copy_scale_sig(
                &w.synth[frame..],
                &mut st.synth_history[fb + 2 * frame - delay_bwe..],
                delay_cldfb,
                negate(w.qpostd),
            );
            let at = fb + 2 * frame
                - ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS) as usize;
            copy_scale_sig(
                &st.old_out[zero_mdct..],
                &mut st.synth_history[at..],
                look_ahead,
                negate(st.q_old_wtda),
            );
        }
    }
}

/// The tail of `evs_dec_fx`: synthesis history, high-pass filtering, output conversion and the
/// end-of-frame updates.
fn evs_dec_finish(
    st: &mut DecoderState,
    w: &mut FrameWork,
    output_sp: &mut [i16],
    frame_mode: i16,
    conceal_whole_frame: bool,
) -> Result<(), EvsError> {
    let output = w.output_frame;
    let frame = output as usize;
    // final output of synthesis signal
    output_sp[..frame].copy_from_slice(&w.synth[..frame]);

    // Save synthesis for HQ FEC
    if sub(st.codec_mode, MODE1) == 0 {
        evs_dec_save_synthesis(st, w);
    }

    // HP filtering
    st.qprev_synth_buffer = w.qpostd;
    scale_sig32(&mut st.l_mem_hp_out, 4, sub(w.qpostd, w.qpostd_prev));
    hp20(
        &mut w.synth,
        1,
        output,
        &mut st.l_mem_hp_out,
        l_mult0(output, 50),
    );

    // Synthesis output
    if sub(st.codec_mode, MODE1) == 0 {
        // final output of synthesis signal
        syn_output(st.codec_mode, &w.synth, output, output_sp, w.qpostd);
    } else {
        output_sp[..frame].copy_from_slice(&w.synth[..frame]);
    }

    // Updates
    if st.last_is_cng == 0 && sub(st.codec_mode, MODE2) == 0 {
        st.bfi = 0;
        if st.use_partial_copy != 0
            && sub(st.rf_frame_type, RF_TCXFD) >= 0
            && sub(st.rf_frame_type, RF_TCXTD2) <= 0
        {
            if sub(frame_mode, FRAMEMODE_MISSING) == 0 {
                st.bfi = 1;
            }
        } else if sub(st.m_decode_mode, DEC_CONCEALMENT_EXT) == 0 {
            st.bfi = 1;
        }
        updt_dec_common(st, -1, output_sp);
    } else {
        if sub(st.codec_mode, MODE2) == 0 {
            st.bfi = 0;
        }
        updt_dec_common(st, w.hq_core_type, output_sp);
    }
    if sub(st.codec_mode, MODE2) == 0 {
        st.last_nelp_mode_dec =
            i16::from(sub(st.use_partial_copy, 1) == 0 && sub(st.rf_frame_type, RF_NELP) == 0);
    }

    st.prev_use_partial_copy = st.use_partial_copy;
    st.prev_tilt_code_dec = 0;
    st.prev_q_exc = st.q_exc;

    let mut l_tmp = l_mult(st.tilt_code_dec[0], 4096);
    for &tilt in &st.tilt_code_dec[1..NB_SUBFR as usize] {
        l_tmp = l_mac(l_tmp, tilt, 4096);
    }
    st.prev_tilt_code_dec = round_word(l_tmp);

    st.prev_coder_type = w.coder_type;
    if sub(st.core, HQ_CORE) == 0 {
        st.prev_coder_type = crate::evs::cnst::GENERIC;
    }

    if st.core_brate > i32::from(SID_2K40) && sub(st.first_cng, 1) == 0 {
        if sub(st.act_cnt, BUF_DEC_RATE) >= 0 {
            st.act_cnt = 0;
        }
        st.act_cnt = add(st.act_cnt, 1);
        if sub(st.act_cnt, BUF_DEC_RATE) == 0 && st.ho_hist_size > 0 {
            st.ho_hist_size = sub(st.ho_hist_size, 1);
        }
        st.act_cnt2 = add(st.act_cnt2, 1);
        if sub(st.act_cnt2, MIN_ACT_CNG_UPD) >= 0 {
            st.act_cnt2 = MIN_ACT_CNG_UPD;
        }
    }

    if st.core_brate <= i32::from(SID_2K40) && st.first_cng == 0 && sub(st.cng_type, LP_CNG) == 0 {
        st.first_cng = 1;
    }

    // update bandwidth switching parameters
    if sub(st.codec_mode, MODE1) == 0 {
        updt_bw_switching(st, &w.synth, w.qpostd);
    } else {
        st.last_bwidth = st.bwidth;
    }

    // synchronisation of CNG seeds
    if st.bfi != 0
        || (st.core_brate != i32::from(FRAME_NO_DATA) && st.core_brate != i32::from(SID_2K40))
    {
        random(&mut st.cng_seed);
        random(&mut st.cng_ener_seed);
    }

    if st.enable_plc_waveadjust != 0 && !conceal_whole_frame {
        // update the parameters used in waveform adjustment
        concealment_update2_x(output_sp, &mut st.plc_info, st.l_frame_tcx);
    }

    st.last_total_brate_ber = st.total_brate;
    if st.bfi == 0 {
        st.last_total_brate = st.total_brate;
    }
    st.last_flag_cna = st.flag_cna;
    if let Some(com) = st
        .h_fd_cng_dec
        .as_deref_mut()
        .and_then(|dec| dec.h_fd_cng_com.as_deref_mut())
    {
        com.frame_type_previous = st.m_frame_type;
    }
    st.prev_bws_cnt = st.bws_cnt;
    Ok(())
}
