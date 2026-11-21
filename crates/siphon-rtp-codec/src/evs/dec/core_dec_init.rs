//! Initialisation of the LPD (MODE2: ACELP / TCX) decoder state (TS 26.442
//! `lib_dec/core_dec_init.c`; TS 26.445 §6.9). Also run on every switch into the LPD core and on
//! every core sampling rate change, which is where most of its branches live.

use crate::evs::basop::{mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{
    ACELP_16K40, ACELP_24K40, ACELP_32K, ACELP_CORE, ALDO_WINDOW, AMR_WB_CORE, DEC, DECMEM_RES2,
    FDNS_NPTS, GAMMA1, GAMMA16K, GAMMA16K_INV, GAMMA1_INV, GENERIC, HQ_48K, HQ_CORE, LPC_SHB_ORDER,
    LPROT32K, L_EXC_MEM_DEC, L_FRAME16K, L_FRAME32K, L_FRAME48K, L_FRAME_MAX, L_SUBFR, L_SYN_MEM,
    M, MODE1, MODE2, NB, NBPSF_PIT_MAX, NB_SUBFR, NB_SUBFR16K, OLD_SYNTH_INTERNAL_DEC,
    PLC_MIN_CNG_LEV, PLC_MIN_STAT_BUFF_SIZE, PREEMPH_FAC, PREEMPH_FAC_16K, PREEMPH_FAC_SWB,
    SID_FRAME, SWB, TCXLTP_MAX_DELAY, TCX_20_CORE, TCX_IMDCT_HEADROOM, TILT_CODE, UNVOICED_CLAS,
};
use crate::evs::com::cldfb::cldfb_reset_memory;
use crate::evs::com::core_com_config::{
    get_core_samplerate_mode2, get_ctx_hm, get_num_tcx_coded_lines, get_resq, get_tcx_bandwidth,
    get_tcx_lpc_shaped_ari, get_tcx_ltp, get_tcxonly, get_tns_allowed, init_pitch_lag_parameters,
    sr2fscale,
};
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::lerp::{lerp, lerp_in_place, lerp_within};
use crate::evs::com::lsf_tools::{
    e_lpc_f_lsp_a_conversion, e_lpc_lsf_lsp_conversion, e_lpc_lsp_lsf_conversion, lsp2lsf,
};
use crate::evs::com::lsp_conv_poly::lsp_convert_poly;
use crate::evs::com::syn_filt::synth_mem_updt2;
use crate::evs::com::tcx_utils::{get_inv_frame_len, init_tcx_config, init_tns_configs};
use crate::evs::com::tec_com::reset_tec_dec;
use crate::evs::com::tools::{copy_scale_sig, scale_sig};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::tonal_mdct_concealment::tonal_mdct_conceal_init;
use crate::evs::dec::waveadjust_fec_dec::concealment_init_x;
use crate::evs::macros::{ns2sa, ns2sa_fx2};
use crate::evs::rom::{BWMODE2FS, GEWB2_AVE_FX, GEWB_AVE_FX};
use crate::itu::basic_ops::{
    add, extract_l, l_deposit_h, l_mult, l_shl, l_shr, l_sub, mult_r, negate, round_word, shl, shr,
    sub,
};

/// `N_ZERO_MDCT_NS` (lib_com/cnst_fx.h): the zeros at either end of the MDCT window, in ns.
const N_ZERO_MDCT_NS: i32 = 5_625_000;
/// `DELAY_CLDFB_NS` (lib_com/cnst_fx.h).
const DELAY_CLDFB_NS: i32 = 1_250_000;
/// `Lprot48k` = `Lprot32k * 3/2` (an operator outside parentheses, so written out here).
const LPROT48K: usize = LPROT32K as usize * 3 / 2;

/// `open_decoder_LPD`: (re)initialises the LPD core for `bit_rate` and the coded bandwidth
/// `bandwidth_mode`: frame lengths and core rate, pitch limits, TCX / TNS / TCX-LTP configuration,
/// and, unless this is the very first frame (`ini_frame == 0`, which clears everything), the
/// memories carried across a codec switch from MODE1 or a core sampling rate change.
pub fn open_decoder_lpd(st: &mut DecoderState, bit_rate: i32, bandwidth_mode: i16) {
    let fscale_fb = open_decoder_lpd_core_config(st, bit_rate, bandwidth_mode);
    open_decoder_lpd_tcx_config(st, fscale_fb);

    let (mem_syn_r_size_old, mem_syn_r_size_new) = if st.ini_frame == 0 {
        open_decoder_lpd_clear_static_vectors(st);
        (0, 0) // just to avoid MSVC warnings
    } else {
        open_decoder_lpd_switching(st)
    };

    if sub(st.last_bwidth, NB) == 0 && sub(st.bwidth, NB) != 0 && st.ini_frame != 0 {
        st.rate_switching_reset = 1;
    }

    st.old_synth_len = shl(st.l_frame, 1);
    st.old_synth_len_fb = shl(st.l_frame_tcx, 1);

    // bass pf reset
    st.bpf_gain_param = 0;
    st.pst_old_syn[..NBPSF_PIT_MAX as usize].fill(0);

    open_decoder_lpd_formant_postfilter(st, mem_syn_r_size_old, mem_syn_r_size_new);
    open_decoder_lpd_concealment(st);
    open_decoder_lpd_tcx_tools(st, bandwidth_mode);
}

/// The frame lengths, core rate, pitch limits, pre-emphasis, perceptual weighting and LPC
/// quantiser choice of `open_decoder_LPD`. Returns `fscaleFB`.
fn open_decoder_lpd_core_config(st: &mut DecoderState, bit_rate: i32, bandwidth_mode: i16) -> i16 {
    st.total_brate = bit_rate;
    st.fscale_old = st.fscale;
    st.sr_core = get_core_samplerate_mode2(st.total_brate, bandwidth_mode, st.rf_flag);
    st.fscale = sr2fscale(st.sr_core);
    let fscale_fb = sr2fscale(st.output_fs);

    // initializing variables for frame lengths etc. right in the beginning
    st.l_frame = extract_l(mult_32_16(st.sr_core, 0x0290));
    st.l_frame_tcx = extract_l(mult_32_16(st.output_fs, 0x0290));

    if st.ini_frame == 0 {
        st.l_frame_past = st.l_frame;
        st.last_l_frame = st.l_frame;
        st.l_frame_tcx_past = st.l_frame_tcx;
    }

    st.tcxonly = get_tcxonly(st.total_brate);

    // the TD TCX PLC in MODE1 still runs with 80ms subframes
    st.nb_subfr = NB_SUBFR;
    if (sub(st.l_frame, L_FRAME16K) == 0 && l_sub(st.total_brate, 32000) <= 0)
        || (st.tcxonly != 0 && (l_sub(st.sr_core, 32000) == 0 || l_sub(st.sr_core, 16000) == 0))
    {
        st.nb_subfr = NB_SUBFR16K;
    }

    // (float)st->L_frame/(float)st->fscale * (float)FSCALE_DENOM/128.0f * (float)st->total_brate_fx
    // 20972 = 0.01 * 64 * 32768
    st.bits_frame = extract_l(l_shr(mpy_32_16_1(l_shl(st.total_brate, 1), 20972), 6));

    st.tcx_bandwidth = get_tcx_bandwidth(bandwidth_mode);
    st.narrow_band = 0;
    if sub(bandwidth_mode, NB) == 0 {
        st.narrow_band = 1;
    }

    let pitch = init_pitch_lag_parameters(st.sr_core);
    st.pit_min = pitch.pit_min;
    st.pit_fr1 = pitch.pit_fr1;
    st.pit_fr1b = pitch.pit_fr1b;
    st.pit_fr2 = pitch.pit_fr2;
    st.pit_max = pitch.pit_max;
    st.pit_res_max = pitch.pit_res_max;
    if st.ini_frame == 0 {
        st.pit_res_max_past = st.pit_res_max;
    }
    let i = mult_r(st.l_frame_tcx, get_inv_frame_len(st.l_frame));
    st.pit_max_tcx = extract_l(l_shr(l_mult(st.pit_max, i), 7));
    st.pit_min_tcx = extract_l(l_shr(l_mult(st.pit_min, i), 7));

    // Preemphasis param
    st.preemph_fac = PREEMPH_FAC_SWB; // SWB
    if sub(st.fscale, 640 /* (16000*FSCALE_DENOM)/12800 */) < 0 {
        st.preemph_fac = PREEMPH_FAC; // WB
    } else if sub(st.fscale, 960 /* (24000*FSCALE_DENOM)/12800 */) < 0 {
        st.preemph_fac = PREEMPH_FAC_16K; // WB
    }

    st.gamma = GAMMA1;
    st.inv_gamma = GAMMA1_INV;
    if l_sub(st.sr_core, 16000) == 0 {
        st.gamma = GAMMA16K;
        st.inv_gamma = GAMMA16K_INV;
    }

    // LPC quantization
    st.lpc_quantization = 0;
    if st.tcxonly == 0 && l_sub(st.sr_core, 16000) <= 0 {
        st.lpc_quantization = 1;
    }

    st.numlpc = 2;
    if st.tcxonly == 0 {
        st.numlpc = 1;
    }

    // Initialize TBE
    st.prev_coder_type = GENERIC;
    st.prev_lsf_diff[..(LPC_SHB_ORDER - 2) as usize].fill(16384);
    st.prev_tilt_para = 0;
    st.cur_sub_aq[..(M + 1) as usize].fill(0);

    fscale_fb
}

/// The TCX configuration of `open_decoder_LPD`: windows, offsets, FAC lengths, coded lines, TNS,
/// the TEC reset and the CNA flag.
fn open_decoder_lpd_tcx_config(st: &mut DecoderState, fscale_fb: i16) {
    // TCX config
    st.tcx_cfg.preemph_fac = st.preemph_fac;
    st.tcx_cfg.tcx_mdct_window_length_old = st.tcx_cfg.tcx_mdct_window_length;

    init_tcx_config(
        &mut st.tcx_cfg,
        st.l_frame,
        st.fscale,
        st.l_frame_tcx,
        fscale_fb,
    );

    if st.ini_frame == 0 {
        st.tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;
        st.tcx_cfg.tcx_last_overlap_mode = ALDO_WINDOW;
    }

    // TCX Offset
    st.tcx_cfg.tcx_offset = shr(st.tcx_cfg.tcx_mdct_window_delay, 1);
    st.tcx_cfg.tcx_offset_fb = shr(st.tcx_cfg.tcx_mdct_window_delay_fb, 1);

    // Initialize FAC
    st.tcx_cfg.lfac_next = sub(st.tcx_cfg.tcx_offset, shr(st.l_frame, 2));
    st.tcx_cfg.lfac_next_fb = sub(st.tcx_cfg.tcx_offset_fb, shr(st.l_frame_tcx, 2));

    // set number of coded lines
    st.tcx_cfg.tcx_coded_lines = get_num_tcx_coded_lines(st.bwidth);

    // TNS in TCX
    st.tcx_cfg.p_current_tns_config = None;
    st.tcx_cfg.f_is_tns_allowed = get_tns_allowed(st.total_brate, st.igf);

    if st.tcx_cfg.f_is_tns_allowed != 0 {
        // `bwMode2fs[st->bwidth_fx]`: the bandwidth is one of NB..FB.
        let sample_rate = usize::try_from(st.bwidth)
            .ok()
            .and_then(|bwidth| BWMODE2FS.get(bwidth))
            .copied()
            .unwrap_or(BWMODE2FS[0]);
        init_tns_configs(
            sample_rate,
            st.tcx_cfg.tcx_coded_lines,
            &mut st.tcx_cfg.tns_config,
            st.h_igf_dec.info_igf_stop_freq,
            st.total_brate,
        );
    }

    reset_tec_dec(&mut st.tec_dec);

    // Initialize decoder delay
    // Constraint for adaptive BPF, otherwise parameter estimation and post-processing not time
    // aligned: the reference asserts lfacNext <= 0 when not tcxonly.

    st.flag_cna = 0;
    if st.ini_frame == 0 {
        st.last_flag_cna = 0;
    }
}

/// `open_decoder_LPD` on the first frame: the static vectors to zero.
fn open_decoder_lpd_clear_static_vectors(st: &mut DecoderState) {
    st.last_is_cng = 0;

    st.rate_switching_reset = 0;
    st.old_syn_overl[..(L_FRAME32K / 2) as usize].fill(0);

    st.syn_overl_tdac[..(L_FRAME32K / 2) as usize].fill(0);
    st.syn_overl_fb[..(L_FRAME_MAX / 2) as usize].fill(0);
    st.syn_overl_tdacfb[..(L_FRAME_MAX / 2) as usize].fill(0);

    st.syn_overl[..(L_FRAME32K / 2) as usize].fill(0);

    st.old_synth[..OLD_SYNTH_INTERNAL_DEC as usize].fill(0);
    st.synth_history[..LPROT48K + L_FRAME_MAX as usize].fill(0);

    st.syn[..(M + 1) as usize].fill(0);

    st.mem_syn_r[..L_SYN_MEM as usize].fill(0);

    st.con_tcx = 0;
}

/// `open_decoder_LPD` on a later frame: the memories carried across a codec switch (MODE1 ->
/// MODE2) or a change of core sampling rate. Returns the old and new LPC synthesis memory sizes
/// (`mem_syn_r_size_old`, `mem_syn_r_size_new`).
fn open_decoder_lpd_switching(st: &mut DecoderState) -> (i16, i16) {
    // Reset old_synth in case of core sampling rate switching and codec switching
    if sub(st.l_frame, st.last_l_frame) != 0 || sub(st.last_codec_mode, MODE1) == 0 {
        st.old_synth[..OLD_SYNTH_INTERNAL_DEC as usize].fill(0);
    }

    // Size of LPC syn memory
    // 1.25/20.0 = 1.0/16.0 -> shift 4 to the right.
    let mem_syn_r_size_old = shr(st.last_l_frame, 4);
    let mem_syn_r_size_new = shr(st.l_frame, 4);

    // Reset LPC mem
    if sub(st.l_frame, st.last_l_frame) != 0
        || sub(st.last_core, AMR_WB_CORE) == 0
        || sub(st.last_core, HQ_CORE) == 0
    {
        // LPC quant. mem
        st.mem_ma[..M as usize].fill(0);
        if l_sub(st.sr_core, 16000) == 0 {
            st.mem_ar.copy_from_slice(&GEWB2_AVE_FX[..M as usize]);
        } else {
            st.mem_ar.copy_from_slice(&GEWB_AVE_FX[..M as usize]);
        }
    }

    // Codec switching
    if sub(st.last_codec_mode, MODE1) == 0 {
        st.lspold_uw.copy_from_slice(&st.lsp_old);
        st.lsfold_uw.copy_from_slice(&st.lsf_old);
        st.syn[..M as usize].fill(0);
    }
    if sub(st.last_core, AMR_WB_CORE) == 0 {
        st.last_core = ACELP_CORE;
        st.last_core_bfi = ACELP_CORE;
    }

    // Codec switching from ACELP-A
    if sub(st.last_codec_mode, MODE1) == 0 && sub(st.last_core, ACELP_CORE) == 0 {
        st.last_core_bfi = ACELP_CORE;

        // PLC
        if st.prev_bfi != 0 {
            open_decoder_lpd_acelp_plc_overlap(st);
        }
    }

    if sub(st.last_codec_mode, MODE2) == 0
        && sub(st.l_frame, st.last_l_frame) != 0
        && ((sub(st.m_frame_type, SID_FRAME) == 0 && sub(st.last_core, ACELP_CORE) > 0)
            || (sub(st.last_core, ACELP_CORE) > 0 && sub(st.core, ACELP_CORE) > 0)
            || st.prev_bfi != 0)
    {
        lerp_in_place(&mut st.old_out_lb, st.l_frame, st.last_l_frame);
    }

    open_decoder_lpd_rate_switching(st, mem_syn_r_size_old, mem_syn_r_size_new);

    (mem_syn_r_size_old, mem_syn_r_size_new)
}

/// The overlap buffers of `open_decoder_LPD` after a concealed MODE1 ACELP frame: the TCX overlap
/// is rebuilt from the concealment's `fer_samples` (ACELP(bfi) -> TCX(rect)).
fn open_decoder_lpd_acelp_plc_overlap(st: &mut DecoderState) {
    let w1 = st.tcx_cfg.tcx_mdct_window_length_fb;
    let w2 = shr(st.tcx_cfg.tcx_mdct_window_length_fb, 1);
    let w = st.tcx_cfg.tcx_mdct_window_fb;

    let mut nz = ns2sa_fx2(st.output_fs, N_ZERO_MDCT_NS).max(0) as usize;
    let delay_comp = ns2sa_fx2(st.output_fs, DELAY_CLDFB_NS).max(0) as usize; // CLDFB delay

    let half_tcx = shr(st.l_frame_tcx, 1).max(0) as usize;
    st.syn_overl_fb[..half_tcx].copy_from_slice(&st.fer_samples[delay_comp..delay_comp + half_tcx]);

    // Q0: ACELP(bfi)->TCX(rect)
    lerp(
        &st.fer_samples[delay_comp..],
        &mut st.syn_overl,
        shr(st.l_frame, 1),
        shr(st.l_frame_tcx, 1),
    );

    // old_out needed for MODE1 routine and syn_Overl_TDAC for MODE2 routine
    st.q_old_wtda = -1;
    st.old_out[..nz].fill(0);
    copy_scale_sig(
        &st.fer_samples[delay_comp..],
        &mut st.old_out[nz..],
        w1,
        st.q_old_wtda,
    ); // Q-1

    let w1_len = w1.max(0) as usize;
    let w2_len = w2.max(0) as usize;
    let rising = w2_len.min(w1_len);
    for (sample, wi) in st.old_out[nz..nz + rising].iter_mut().zip(&w[..rising]) {
        let re = wi.v.re;
        *sample = round_word(mpy_32_16_1(l_mult(re, re), *sample));
    }
    for i in w2_len..w1_len {
        let im = w[w2_len - 1 - (i - w2_len)].v.im;
        st.old_out[i + nz] = round_word(mpy_32_16_1(l_mult(im, im), st.old_out[i + nz]));
    }
    st.old_out[w1_len + nz..w1_len + 2 * nz].fill(0);

    lerp(&st.old_out, &mut st.old_out_lb, st.l_frame, st.l_frame_tcx);

    st.syn_overl_tdacfb[..half_tcx].copy_from_slice(&st.old_out[nz..nz + half_tcx]);
    nz = ns2sa_fx2(st.sr_core, N_ZERO_MDCT_NS).max(0) as usize;
    let half = shr(st.l_frame, 1).max(0) as usize;
    st.syn_overl_tdac[..half].copy_from_slice(&st.old_out_lb[nz..nz + half]);
    st.q_old_wtda_lb = st.q_old_wtda;
}

/// The rate switching of `open_decoder_LPD`: from the MDCT core (HQ) of MODE1, between the
/// 12.8 and 16 kHz ACELP cores, between TCX-only rates, or into the 16 kHz core from above
/// 32 kbit/s.
fn open_decoder_lpd_rate_switching(
    st: &mut DecoderState,
    mem_syn_r_size_old: i16,
    mem_syn_r_size_new: i16,
) {
    if sub(st.last_codec_mode, MODE1) == 0 && sub(st.last_core, HQ_CORE) == 0 {
        // Codec switching from MDCT

        // Reset of ACELP memories
        st.rate_switching_reset = 1;
        st.tilt_code = TILT_CODE;
        st.old_exc[..L_EXC_MEM_DEC as usize].fill(0);
        st.syn[..(1 + M) as usize].fill(0);
        st.mem_syn2[..M as usize].fill(0);

        // OLA -> zero
        st.old_syn_overl[..(L_FRAME32K / 2) as usize].fill(0); // HQ-CORE(bfi)->TCX don't need it
        st.syn_overl_tdac[..(L_FRAME32K / 2) as usize].fill(0); // HQ-CORE(bfi)->TCX don't need it
        st.syn_overl_tdacfb[..(L_FRAME_MAX / 2) as usize].fill(0); // HQ-CORE(bfi)->TCX don't need it
        st.syn_overl[..(L_FRAME32K / 2) as usize].fill(0); // HQ-CORE(bfi)->TCX don't need it

        let start = ns2sa(st.output_fs, N_ZERO_MDCT_NS).max(0) as usize;
        copy_scale_sig(
            &st.old_out[start..],
            &mut st.syn_overl_fb,
            st.tcx_cfg.tcx_mdct_window_length_fb,
            negate(add(st.q_old_wtda, TCX_IMDCT_HEADROOM)),
        );

        st.tcx_cfg.last_aldo = 1; // It was previously ALDO
        st.tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;
        // OLA for MDCT-LB always reset in codec switching cases
        let l_frame = st.l_frame.max(0) as usize;
        st.old_out_lb[..l_frame].fill(0);
        st.last_core_bfi = TCX_20_CORE;

        st.pfstat.on = 0;
        // reset CLDFB memories
        for bank in [&mut st.cldfb_ana, &mut st.cldfb_bpf, &mut st.cldfb_syn]
            .into_iter()
            .flatten()
        {
            cldfb_reset_memory(bank);
        }
    } else if sub(st.l_frame, st.last_l_frame) != 0
        && sub(st.l_frame, L_FRAME16K) <= 0
        && sub(st.last_l_frame, L_FRAME16K) <= 0
    {
        // Rate switching between 12.8 and 16 kHz

        // Interpolation of ACELP memories

        // convert quantized LSP vector
        st.rate_switching_reset = lsp_convert_poly(&mut st.lsp_old, st.l_frame, 0);
        if st.tcxonly == 0 {
            lsp2lsf(&st.lsp_old, &mut st.lsf_old, M, st.sr_core);
        } else {
            e_lpc_lsp_lsf_conversion(&st.lsp_old, &mut st.lsf_old, M);
        }
        e_lpc_f_lsp_a_conversion(&st.lsp_old, &mut st.old_aq_12_8, M);

        st.lspold_uw.copy_from_slice(&st.lsp_old);
        st.lsfold_uw.copy_from_slice(&st.lsf_old);

        if st.last_con_tcx == 0 {
            synth_mem_updt2(
                st.l_frame,
                st.last_l_frame,
                &mut st.old_exc,
                &mut st.mem_syn_r,
                &mut st.mem_syn2,
                None,
                DEC,
            );
        }

        // mem of deemphasis stayed unchanged.
    } else if sub(st.l_frame, st.last_l_frame) != 0 {
        // Rate switching involving TCX only modes

        // Partial reset of ACELP memories
        st.rate_switching_reset = 1;

        // reset partly some memories
        st.tilt_code = TILT_CODE;
        if st.last_con_tcx == 0 {
            st.old_exc[..L_EXC_MEM_DEC as usize].fill(0);
        }
        st.old_aq_12_8[..(M + 1) as usize].fill(0);

        // Resamp others memories
        // Size of LPC syn memory
        lerp_within(
            &mut st.mem_syn_r,
            (L_SYN_MEM - mem_syn_r_size_old).max(0) as usize,
            (L_SYN_MEM - mem_syn_r_size_new).max(0) as usize,
            mem_syn_r_size_new,
            mem_syn_r_size_old,
        );
        let tail = (L_SYN_MEM - M) as usize;
        st.mem_syn2[..M as usize].copy_from_slice(&st.mem_syn_r[tail..tail + M as usize]);

        // Untouched memories : st->syn
    } else if st.tcxonly == 0
        && sub(st.l_frame, L_FRAME16K) == 0
        && l_sub(st.last_total_brate, i32::from(ACELP_32K)) > 0
    {
        lsp2lsf(&st.lsp_old, &mut st.lsf_old, M, st.sr_core);
    }
}

/// `lerp` of the tail of a post-filter memory from `old` to `new` samples
/// (`mem + L_SYN_MEM - old` -> `mem + L_SYN_MEM - new`).
fn resample_tail(mem: &mut [i16], new: i16, old: i16) {
    lerp_within(
        mem,
        (L_SYN_MEM - old).max(0) as usize,
        (L_SYN_MEM - new).max(0) as usize,
        new,
        old,
    );
}

/// The formant post-filter memories of `open_decoder_LPD`: resampled within MODE2, reset (or
/// rescaled from the MODE1 synthesis scaling) on a codec switch.
fn open_decoder_lpd_formant_postfilter(
    st: &mut DecoderState,
    mem_syn_r_size_old: i16,
    mem_syn_r_size_new: i16,
) {
    if st.ini_frame == 0 {
        // do nothing
    } else if sub(st.last_codec_mode, MODE2) == 0 {
        if st.tcxonly == 0 {
            if st.pfstat.on != 0 {
                resample_tail(
                    &mut st.pfstat.mem_stp,
                    mem_syn_r_size_new,
                    mem_syn_r_size_old,
                );
                resample_tail(
                    &mut st.pfstat.mem_pf_in,
                    mem_syn_r_size_new,
                    mem_syn_r_size_old,
                );
            } else {
                st.pfstat.mem_stp[..L_SYN_MEM as usize].fill(0);
                st.pfstat.mem_pf_in[..L_SYN_MEM as usize].fill(0);
                st.pfstat.reset = 1;
                st.pfstat.gain_prec = 16384;
            }
        } else if st.pfstat.on != 0 {
            resample_tail(
                &mut st.pfstat.mem_stp,
                mem_syn_r_size_new,
                mem_syn_r_size_old,
            );
            resample_tail(
                &mut st.pfstat.mem_pf_in,
                mem_syn_r_size_new,
                mem_syn_r_size_old,
            );
        }
    } else {
        // codec switching
        // reset post-filter except for Narrowband
        let q = negate(st.q_syn);
        if l_sub(st.output_fs, 8000) != 0 {
            st.pfstat.reset = 1;
            if st.pfstat.on != 0 {
                st.pfstat.reset = 0;
                scale_sig(&mut st.pfstat.mem_pf_in, L_SUBFR, q); // WB post_filter mem
                scale_sig(&mut st.pfstat.mem_stp, L_SUBFR, q); // WB post_filter mem
                resample_tail(
                    &mut st.pfstat.mem_stp,
                    mem_syn_r_size_new,
                    mem_syn_r_size_old,
                );
                resample_tail(
                    &mut st.pfstat.mem_pf_in,
                    mem_syn_r_size_new,
                    mem_syn_r_size_old,
                );
            }
        } else {
            scale_sig(&mut st.pfstat.mem_pf_in, L_SUBFR, q); // NB post_filter mem
            scale_sig(&mut st.pfstat.mem_res2, DECMEM_RES2, q); // NB post_filter mem
            scale_sig(&mut st.pfstat.mem_stp, L_SUBFR, q); // NB post_filter mem
                                                           // feed last value old_synth as it is used for pre-emphasis mem
            let last = (st.old_synth_len - 1).clamp(0, OLD_SYNTH_INTERNAL_DEC - 1) as usize;
            st.old_synth[last] = st.syn[M as usize];
            st.pst_old_syn[(NBPSF_PIT_MAX - 1) as usize] = st.syn[M as usize];
        }
    }
}

/// The LSF / CNG / concealment state of `open_decoder_LPD`.
fn open_decoder_lpd_concealment(st: &mut DecoderState) {
    // lsf and lsp initialization
    if st.ini_frame == 0 {
        st.lspold_uw.copy_from_slice(&st.lsp_old);
        st.lsfold_uw.copy_from_slice(&st.lsf_old);

        st.lsf_cng[..M as usize].fill(0);
    }

    st.seed_tcx_plc = 21845;
    st.past_gpit = 0;
    st.past_gcode = 0;
    st.gc_threshold = 0;

    e_lpc_lsf_lsp_conversion(&st.lsf_cng, &mut st.lspold_cng, M);
    e_lpc_f_lsp_a_conversion(&st.lspold_cng, &mut st.aq_cng, M);
    st.plc_background_noise_updated = 0;
    st.lsf_q_cng.copy_from_slice(&st.lsf_old);
    st.old_lsf_q_cng.copy_from_slice(&st.lsf_old);
    st.lsp_q_cng.copy_from_slice(&st.lsp_old);
    st.old_lsp_q_cng.copy_from_slice(&st.lsp_old);
    st.mem_syn_unv_back[..M as usize].fill(0);

    st.last_gain_syn_deemph = 16384; // 32768/2
    st.last_gain_syn_deemph_e = 1;
    if sub(st.last_codec_mode, MODE1) == 0 || st.ini_frame == 0 {
        // this assumes that MODE1 fades out in the frequency domain -
        // otherwise some data from MODE1 would be needed here
        st.last_concealed_gain_syn_deemph = 16384; // 32768/2
        st.last_concealed_gain_syn_deemph_e = 1;
        st.conceal_eof_gain = 16384; // 32768/2 // Q14
    }

    // Post processing
    st.mem_aq[..(NB_SUBFR16K * (M + 1)) as usize].fill(0);
    st.lp_ener_fer = 15360; // 60 in Q8
    if st.ini_frame == 0 {
        st.prev_bfi = 0;
        st.last_core_bfi = -1;
    }
    st.prev_old_bfi = 0;

    st.lsf_adaptive_mean.copy_from_slice(&st.lsf_old);
    st.lsfoldbfi0.copy_from_slice(&st.lsf_old);
    st.lsfoldbfi1.copy_from_slice(&st.lsf_old);

    st.clas_dec = UNVOICED_CLAS;
    if st.last_con_tcx == 0 {
        st.old_enr_lp = 0; // LP filter E of last good voiced frame or local LP filter E in TD TCX PLC
    }

    if st.prev_bfi != 0 {
        // calculate energy at the end of the previous frame
        if sub(st.core, ACELP_CORE) == 0 && sub(st.last_core, HQ_CORE) == 0 {
            frame_ener(
                st.output_frame,
                UNVOICED_CLAS,
                &st.previoussynth,
                -1,
                &mut st.enr_old,
                1,
                0,
                0,
                0,
            );
        }
    } else {
        st.last_good = UNVOICED_CLAS; // last good received frame for concealment
        st.enr_old = 0; // energy at the end of the previous frame
    }
    st.mode2_lp_gainc = 0;
    st.mode2_lp_gainp = 0;

    st.prev_widow_left_rect = 0;

    st.con_cng_level_background_trace = PLC_MIN_CNG_LEV; // Q15
    st.con_noise_level_index = PLC_MIN_STAT_BUFF_SIZE - 1;
    st.con_curr_level_index = 0;
    st.con_last_frame_level = PLC_MIN_CNG_LEV; // Q15
    st.con_noise_level_memory[..PLC_MIN_STAT_BUFF_SIZE as usize].fill(PLC_MIN_CNG_LEV); // Q15
    st.con_noise_level_memory_e[..PLC_MIN_STAT_BUFF_SIZE as usize].fill(0);
    st.con_last_frame_level_e = 0;
    st.con_cng_level_background_trace_e = 0;

    st.cummulative_damping_tcx = 32767; // 1.0f Q15
    st.cummulative_damping = 32767; // 1.0f Q15

    let pit_min = l_deposit_h(st.pit_min);
    st.old_pitch_buf[..(2 * NB_SUBFR16K + 2) as usize].fill(pit_min);
    st.mem_pitch_gain[..(2 * NB_SUBFR16K + 2) as usize].fill(16384); // 1.f Q14

    st.old_fpitch = l_deposit_h(st.pit_min);
    st.old_fpitch_fb = l_deposit_h(st.pit_min_tcx);

    st.rate_switching_init = 1;

    st.reset_mem_ar = 0;

    // For phase dispersion
    st.dm.prev_gain_code = 0;
    st.dm.prev_gain_pit.fill(0);
    st.dm.prev_state = 0;

    st.voice_fac = -1; // purely unvoiced
}

/// The TCX-LTP, context coding, TEC/TFA, guided-ACELP, waveform-adjustment and tonal MDCT
/// concealment state of `open_decoder_LPD`.
fn open_decoder_lpd_tcx_tools(st: &mut DecoderState, bandwidth_mode: i16) {
    // TCX-LTP
    st.tcxltp = get_tcx_ltp(st.sr_core);

    if st.ini_frame == 0 || sub(st.last_codec_mode, MODE1) == 0 {
        st.tcxltp_pitch_int = st.pit_max;
        st.tcxltp_pitch_fr = 0;
        st.tcxltp_last_gain_unmodified = 0;
        if st.ini_frame == 0 {
            st.tcxltp_mem_in[..TCXLTP_MAX_DELAY as usize].fill(0);
            st.tcxltp_mem_out[..L_FRAME48K as usize].fill(0);
            st.tcxltp_pitch_int_post_prev = 0;
            st.tcxltp_pitch_fr_post_prev = 0;
            st.tcxltp_gain_post_prev = 0;
            st.tcxltp_filt_idx_prev = -1;
        }
    }

    // in floating point implementation, different buffers are used: lp_error_ener <->
    // pst_lp_ener, mem_error <-> pst_mem_deemp_err
    // convert from 7Q8 10*log10 -> 15Q16, log2
    st.lp_error_ener = mpy_32_16_1(l_shl(i32::from(st.pst_lp_ener), 8), 0x2a86);
    st.mem_error = 0;
    st.tcx_cfg.ctx_hm = get_ctx_hm(st.total_brate, st.rf_flag);
    st.last_ctx_hm_enabled = 0;

    st.tcx_cfg.resq = get_resq(st.total_brate);

    // deadzone of 1.25->rounding=1-1.25/2 (No deadzone=0.5)
    st.tcx_cfg.sq_rounding = 12288; // 0.375f Q15

    st.tcx_lpc_shaped_ari = get_tcx_lpc_shaped_ari(st.total_brate, bandwidth_mode, st.rf_flag);

    st.env_weighted = 0;

    st.p_bpf_noise_buf = None;
    if st.tcxonly == 0 {
        st.p_bpf_noise_buf = Some(0);
    }

    st.tec_tfa = 0;
    if sub(bandwidth_mode, SWB) == 0
        && (l_sub(st.total_brate, i32::from(ACELP_16K40)) == 0
            || l_sub(st.total_brate, i32::from(ACELP_24K40)) == 0)
    {
        st.tec_tfa = 1;
    }

    st.tec_flag = 0;
    st.tfa_flag = 0;

    st.enable_gplc = 0;

    st.flag_guided_acelp = 0;
    st.t0_4th = L_SUBFR;
    st.guided_t0 = st.t0_4th;

    st.enable_plc_waveadjust = 0;
    if l_sub(st.total_brate, 48000) >= 0 {
        st.enable_plc_waveadjust = 1;
        if st.ini_frame == 0
            || l_sub(st.last_total_brate, HQ_48K) < 0
            || sub(st.last_codec_mode, MODE1) == 0
            || st.force_lpd_reset != 0
        {
            concealment_init_x(st.l_frame_tcx, &mut st.plc_info);
        }
    }

    // PLC: [TCX: Tonal Concealment]
    st.tonal_mdc_tconceal.n_scale_factors = 0;
    st.tonal_mdc_tconceal.n_samples = 0;
    st.tonal_mdc_tconceal.last_pcm_out = None;
    st.tonal_mdc_tconceal
        .last_block_data
        .tonal_concealment_active = 0;
    st.tonal_mdc_tconceal.last_block_data.n_samples = 0;

    // The reference ignores the status; it only fails for more than L_FRAME_MAX samples, which no
    // output rate gives.
    let _ = tonal_mdct_conceal_init(
        &mut st.tonal_mdc_tconceal,
        st.l_frame_tcx,
        st.l_frame,
        FDNS_NPTS,
    );

    st.last_tns_active = 0;
    st.second_last_tns_active = 0;
    st.second_last_core = -1;
    st.tcxltp_second_last_pitch = st.old_fpitch;
    st.tcxltp_third_last_pitch = st.old_fpitch;

    st.dec_glr = 0;
    if l_sub(st.total_brate, 9600) == 0
        || l_sub(st.total_brate, 16400) == 0
        || l_sub(st.total_brate, 24400) == 0
    {
        st.dec_glr = 1;
    }
    st.dec_glr_idx = 0;

    st.enable_tcx_lpc = 1;
    st.vad = 0;
    st.old_gaintcx_bfi = 0;
    st.old_gaintcx_bfi_e = 0;
    st.tcx_cfg.na_scale = 32767; // 1.0f Q15
    st.tcx_hm_ltp_pitch_lag = -1;
    st.tcxltp_gain = 0;
}
