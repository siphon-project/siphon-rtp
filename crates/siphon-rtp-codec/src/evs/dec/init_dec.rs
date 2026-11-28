//! Initialisation and release of the decoder state (TS 26.442 `lib_dec/init_dec_fx.c`).
//!
//! `init_decoder_fx` turns a zeroed [`DecoderState`] (the reference's `calloc`) whose `output_fs`
//! and `output_frame` the caller has set into a working decoder: every core's memories, the CLDFB
//! banks, the FD-CNG state and, through `open_decoder_LPD`, the MODE2 core. Init time only; the
//! handles are the only allocations.

use crate::evs::basop::l_extract_lc;
use crate::evs::cnst::{
    ACELP_7K20, ACELP_CORE, ACELP_LOOK_NS, ACTIVE_FRAME, ALLPASSSECTIONS_STEEP, BANDS_MAX,
    BETA_MUTE_FAC_INI, CLDFB_ANALYSIS, CLDFB_SYNTHESIS, DCT_L_POST, DELAY_BWE_TOTAL_NS,
    DELAY_CLDFB_NS, DELAY_FD_BWE_ENC_NS, END_FREQ_BWE_FULL_FB, E_MIN_Q15, FRAME_SIZE_NS,
    GAIN_PRED_ORDER, GENERIC, GE_SHIFT, HO_HIST_SIZE, HQ_DELAY_COMP, HQ_DELTA_MAX, HQ_FEC_SIGN_SFM,
    HQ_NORMAL, INTERP_3_1_MEM_LEN, INTERP_3_2_MEM_LEN, INT_FS_FX, INV_NUM_ENV_STAB_PLC_STATES,
    LGW_MAX, LPC_SHB_ORDER, L_EXC_MEM, L_EXC_MEM_DEC, L_FRAME, L_FRAME32K, L_FRAME48K, L_FRAME8K,
    L_HQ_WB_BWE, L_Q_MEM, L_SUBFR, L_SUBFR_Q6, L_SYN_MEM_CLAS_ESTIM, L_TRACK_HIST, M, MAXLAG_WI,
    MAX_32, MAX_LT, MAX_PGF, MAX_ROW, MAX_SB_NB, MAX_UPD_CNT, MBANDS_GN, MBANDS_GN_LD, MODE1, NB,
    NB_SUBFR16K, NB_SWB_SUBBANDS, NOISE_LEVEL_SP0, NORMAL, NUM_ENV_CNG, NUM_ENV_STAB_PLC_STATES,
    NUM_ERB_WB, NUM_NONTRANS_START_FREQ_COEF, NUM_TIME_SWITCHING_BLOCKS, N_LEAD_NB, N_NS2W_FRAMES,
    N_WS2N_FRAMES, OFFSET2, PH_ECU_LOOKAHEAD_NS, PH_ECU_MEM_NS, PH_ECU_SPEC_SIZE, RANDOM_INITSEED,
    SFM_N_ENV_STAB, SFM_N_NB, SFM_N_WB, SPT_SHORTEN_SBNUM, SWB_FENV, TH_0_MIN_FX, TH_1_MIN_FX,
    TH_2_MIN_FX, TH_3_MIN_FX, UNVOICED_CLAS, VOIC_BINS_HR,
};
use crate::evs::com::cldfb::{cldfb_get_num_channels, delete_cldfb, open_cldfb, resample_cldfb};
use crate::evs::com::lsf_tools::lsf2lsp;
use crate::evs::com::math_op::pow2;
use crate::evs::com::mslvq_com::init_lvq;
use crate::evs::com::tools::{copy, set16, set32};
use crate::evs::dec::bass_psfilter::bass_psfilter_init;
use crate::evs::dec::core_dec_init::open_decoder_lpd;
use crate::evs::dec::dec_post::init_post_filter;
use crate::evs::dec::fd_cng_dec::{create_fd_cng_dec, delete_fd_cng_dec, init_fd_cng_dec};
use crate::evs::dec::hf_synth::{hf_synth_amr_wb_init, hf_synth_init};
use crate::evs::dec::state::{DecoderState, IgfdecInstance};
use crate::evs::dec::swb_tbe_dec::{init_swb_dec_buffer, reset_shb_buffer_dec};
use crate::evs::macros::{ns2sa, ns2sa_fx2};
use crate::evs::rom::{GEWB_AVE_FX, LSP_SHB_PREV_TBL_FX, SWB_LSP_PREV_INTERP_INIT};
use crate::itu::basic_ops::{add, extract_l, l_mult, l_shr, shl, shr};
use crate::itu::stl2009::l_mult0;

/// `DEC_NO_FRAM_LOSS` of the `DEC_MODE` enum (lib_dec/stat_dec_fx.h); an enumerator, so the
/// constant generator, which reads `#define`s, does not carry it.
const DEC_NO_FRAM_LOSS: i16 = 0;

/// `init_decoder_fx`: initialise every static variable of the decoder for the output rate
/// `st.output_fs` / frame length `st.output_frame` the caller has set, open the CLDFB banks and
/// the FD-CNG state, and open the LPD (MODE2) core at the initial 8 kbit/s narrowband
/// configuration.
pub fn init_decoder(st: &mut DecoderState) {
    st.total_num_bits = -1;

    init_decoder_acelp(st);
    init_decoder_fec_and_cng(st);
    init_decoder_hq(st);
    init_decoder_bwe(st);
    init_decoder_postfilters_and_tools(st);
}

/// ACELP core parameters, LSF, HF synthesis, GSC and the NB post-filter.
fn init_decoder_acelp(st: &mut DecoderState) {
    // ACELP core parameters
    st.codec_mode = MODE1;
    st.last_codec_mode = MODE1;
    st.core = ACELP_CORE;
    st.l_frame = L_FRAME;
    st.extl = -1;
    st.total_brate = 8000;
    st.last_total_brate = -1;
    st.last_total_brate_ber = -1;
    st.core_brate = 8000;
    st.ini_frame = 0;
    st.bwidth = NB;
    st.extl_brate = 0;
    st.last_coder_type = GENERIC;
    st.last_l_frame = st.l_frame;
    st.last_core_brate = st.core_brate;
    st.last_core = -1;
    st.prev_last_core = -1;
    st.last_extl = st.extl;
    st.last_hq_core_type = -1;

    // LSF initilaizations
    copy(&GEWB_AVE_FX, &mut st.mem_ar, M);
    init_lvq(
        &mut st.offset_scale1,
        &mut st.offset_scale2,
        &mut st.offset_scale1_p,
        &mut st.offset_scale2_p,
        &mut st.no_scales,
        &mut st.no_scales_p,
    );
    set16(&mut st.mem_ma, 0, M);

    st.dm.prev_state = 0; // This corresponds to st_fx->dispMem in FLP
    st.dm.prev_gain_code = 0;
    for i in 2..8 {
        st.dm.prev_gain_pit[i - 2] = 0;
    }

    // HF synth init
    hf_synth_amr_wb_init(
        &mut st.prev_r,
        &mut st.fmerit_w_sm,
        &mut st.mem_syn_hf,
        &mut st.frame_count,
        &mut st.ne_min,
        &mut st.fmerit_m_sm,
        &mut st.voice_fac_amr_wb_hf,
        &mut st.unvoicing,
        &mut st.unvoicing_sm,
        &mut st.unvoicing_flag,
        &mut st.voicing_flag,
        &mut st.start_band_old,
        &mut st.opt_crit_old,
    );
    hf_synth_init(&mut st.mem_hp400, &mut st.mem_hf);
    set16(&mut st.mem_hp_interp, 0, INTERP_3_1_MEM_LEN);
    set16(&mut st.delay_syn_hf, 0, ns2sa_fx2(16000, DELAY_CLDFB_NS));

    st.tilt_code = 0;
    st.gc_threshold = 0;
    st.last_good = UNVOICED_CLAS;
    st.clas_dec = UNVOICED_CLAS;
    st.lp_gainp = 0;
    st.lp_gainc = 0;

    set16(&mut st.old_exc, 0, L_EXC_MEM_DEC);

    // AVQ pre-quantizer memory
    st.mem_preemp_pre_q = 0;
    st.last_nq_pre_q = 0;
    st.use_acelp_preq = 0;

    st.mem_deemph = 0;
    set16(&mut st.mem_syn1, 0, M);
    st.mem_deemph_old_syn = 0;
    set16(&mut st.mem_syn2, 0, M);
    st.stab_fac = 0;
    st.stab_fac_smooth = 0;
    set16(&mut st.agc_mem, 0, 2);
    set32(&mut st.l_mem_hp_out, 0, 5);
    set16(&mut st.mem_syn3, 0, M);

    // Q10; gain quantization memory (used also in AMR-WB IO mode)
    st.past_qua_en[..GAIN_PRED_ORDER as usize].fill(-14336);

    copy(&GEWB_AVE_FX, &mut st.lsf_old, M);
    lsf2lsp(&st.lsf_old, &mut st.lsp_old, M, i32::from(INT_FS_FX));

    st.mid_lsf_int = 0;
    st.safety_net = 0;

    // parameters for AC mode (GSC)
    st.seed_tcx = 15687;
    st.gsc_noisy_speech = 0;
    st.last_gsc_noisy_speech_flag = 0;
    st.cor_strong_limit = 1;
    set16(&mut st.old_y_gain, 0, MBANDS_GN);
    st.noise_lev = NOISE_LEVEL_SP0;
    set16(&mut st.last_gsc_spectrum, 0, L_FRAME);
    st.last_gsc_pit_band_idx = 0;
    set16(&mut st.lt_ener_per_band, 4096, MBANDS_GN); // Q12
    set16(&mut st.last_exc_dct_in, 0, L_FRAME);
    st.last_ener = 0;
    set16(&mut st.last_bitallocation_band, 0, 6);

    // NB post-filter
    init_post_filter(&mut st.pfstat);
    st.psf_lp_noise = 0;
}

/// FEC, fast recovery, the LD music post-filter, CNG and DTX.
fn init_decoder_fec_and_cng(st: &mut DecoderState) {
    // FEC
    st.scaling_flag = 0;
    st.lp_ener_fec_av = 500_000;
    st.lp_ener_fec_max = 500_000;
    st.prev_bfi = 0;
    st.lp_ener_fer = 15360; // 60 in Q8
    st.old_enr_lp = 0;
    st.lp_ener = 0;
    st.enr_old = 0;
    st.bfi_pitch = L_SUBFR_Q6;
    st.bfi_pitch_frame = L_SUBFR;
    set16(&mut st.mem_syn_clas_estim, 0, L_SYN_MEM_CLAS_ESTIM);
    st.classifier_q_mem_syn = 0;
    st.last_con_tcx = 0;

    st.old_pitch_buf[..2 * NB_SUBFR16K as usize].fill(i32::from(L_SUBFR) << 16); // 15Q16
    st.upd_cnt = MAX_UPD_CNT;
    copy(&GEWB_AVE_FX, &mut st.lsfoldbfi0, M);
    copy(&GEWB_AVE_FX, &mut st.lsfoldbfi1, M);
    copy(&GEWB_AVE_FX, &mut st.lsf_adaptive_mean, M);
    st.seed_acelp = RANDOM_INITSEED;
    st.seed = RANDOM_INITSEED;
    st.nb_lost_cmpt = 0;
    st.decision_hyst = 0;

    // fast recovery
    set16(&mut st.old_exc2, 0, L_EXC_MEM);
    set16(&mut st.old_syn2, 0, L_EXC_MEM);

    // Stationary noise UV modification
    st.unv_cnt = 0;
    st.ge_sm = 640; // Q(GE_SHIFT)
    st.uv_count = 0;
    st.act_count = 3;
    let lsp_old = st.lsp_old;
    copy(&lsp_old, &mut st.lspold_s, M);
    st.noimix_seed = RANDOM_INITSEED;
    st.min_alpha = 32767; // 1; Q15
    st.exc_pe = 0;

    st.cng_ener_seed1 = RANDOM_INITSEED;
    set32(&mut st.lp_env, 0, NUM_ENV_CNG);
    set16(&mut st.exc_mem, 0, 24);
    set16(&mut st.exc_mem1, 0, 30);
    set32(&mut st.old_env, 0, NUM_ENV_CNG);

    // LD music post-filter
    set16(&mut st.dct_post_old_exc, 0, DCT_L_POST - OFFSET2);
    // st->LDm_enh_min_ns_gain = (float)pow(10.0f, -12/20.0f);
    let mut l_tmp = l_mult(-12 * 256, 5443); // *0.166096 in Q15 -> Q24
    l_tmp = l_shr(l_tmp, 8); // From Q24 to Q16
    let (mut e_db, mut f_db) = l_extract_lc(l_tmp); // Extract exponent
    f_db = extract_l(pow2(14, f_db)); // Put 14 as exponent so that
    e_db = add(e_db, 15 - 14);
    f_db = add(f_db, shr(1, add(e_db, 1)));
    st.l_dm_enh_min_ns_gain = shl(f_db, e_db);
    st.l_dm_last_music_flag = 0;
    set16(&mut st.l_dm_lt_diff_etot, 0, MAX_LT);
    st.l_dm_thres[0] = TH_0_MIN_FX;
    st.l_dm_thres[1] = TH_1_MIN_FX;
    st.l_dm_thres[2] = TH_2_MIN_FX;
    st.l_dm_thres[3] = TH_3_MIN_FX;

    st.l_dm_nb_thr_1 = 0;
    st.l_dm_nb_thr_3 = 0;
    st.l_dm_mem_etot = 0;

    for i in 0..VOIC_BINS_HR as usize {
        st.l_dm_enh_lp_gbin[i] = 16384;
        st.l_dm_enh_lf_eo[i] = 328;
    }

    st.l_dm_bckr_noise[..MBANDS_GN_LD as usize].fill(i32::from(E_MIN_Q15));

    set16(&mut st.filt_lf_e, 4096, DCT_L_POST);
    st.last_nonfull_music = 0;
    st.old_ener_q = 0;

    // CNG and DTX
    st.cng = 0; // RTXDTX handler CNG=1  nonCNG= 0
    st.prev_ft_speech = 1; // previous frametype flag for G.192 format AMRWB SID_FIRST detection
    st.cng_seed = RANDOM_INITSEED;
    st.cng_ener_seed = RANDOM_INITSEED;
    st.old_enr_index = -1;
    st.enew = 0;
    st.first_cng = 0;
    copy(&lsp_old, &mut st.lsp_cng, M);
    st.last_allow_cn_step = 0;
    st.shb_cng_ener = -1541;
    st.wb_cng_ener = -1541;
    st.last_wb_cng_ener = -1541;
    st.last_shb_cng_ener = -1541;
    st.swb_cng_seed = RANDOM_INITSEED;
    st.ho_hist_ptr = -1;
    st.ho_sid_bw = 0;
    set16(&mut st.ho_lsp_hist, 0, HO_HIST_SIZE * M);
    set32(&mut st.ho_ener_hist, 0, HO_HIST_SIZE);
    set32(&mut st.ho_env_hist, 0, HO_HIST_SIZE * NUM_ENV_CNG);
    st.ho_hist_size = 0;
    st.act_cnt = 0;
    st.ho_circ_ptr = -1;
    set16(&mut st.ho_lsp_circ, 0, HO_HIST_SIZE * M);
    set32(&mut st.ho_ener_circ, 0, HO_HIST_SIZE);
    set32(&mut st.ho_env_circ, 0, HO_HIST_SIZE * NUM_ENV_CNG);
    st.ho_circ_size = 0;

    set16(&mut st.ho_16k_lsp, 0, HO_HIST_SIZE);
    st.cng_mode = -1;
    st.last_active_brate = i32::from(ACELP_7K20);
    st.last_cng_l_frame = L_FRAME;
    st.act_cnt2 = 0;
    st.num_ho = 0;
    st.cng_type = -1;
    st.last_cng_type = -1;

    for (i, &lsp) in LSP_SHB_PREV_TBL_FX[..LPC_SHB_ORDER as usize]
        .iter()
        .enumerate()
    {
        st.lsp_shb_prev[i] = lsp;
        st.lsp_shb_prev_prev[i] = st.lsp_shb_prev[i];
    }

    st.shb_dtx_count = 0;
    st.last_vad = 0;
    st.trans_cnt = 0;
    st.burst_cnt = 0;
    st.last_shb_ener = 0;

    // HF (6-7kHz) BWE
    st.seed2 = RANDOM_INITSEED;
    st.q_stat_noise_ge = GE_SHIFT;
    st.cng_td_level = 0;
    st.cng_td_level_e = 0;

    // HR SWB BWE parameters
    set16(
        &mut st.t_audio_prev,
        0,
        (2 * i32::from(END_FREQ_BWE_FULL_FB) / 50) as i16 - NUM_NONTRANS_START_FREQ_COEF, // C int arithmetic
    );
    set16(&mut st.t_audio_prev_fx_exp, 0, NUM_TIME_SWITCHING_BLOCKS); // one exp per switching block
    st.old_is_transient_hr_bwe = 0;
    st.bwe_highrate_seed = 12345;

    st.l_mem_energy_lt = 16384 << 16;
    st.mem_energy_lt_fx_exp = 40; // set to a high exponent
}

/// HQ core parameters, pre-echo reduction and the HQ FEC.
fn init_decoder_hq(st: &mut DecoderState) {
    // HQ core parameters
    set16(&mut st.old_out, 0, L_FRAME48K);
    set16(&mut st.old_out_lb, 0, L_FRAME32K);
    set32(&mut st.old_coeffs, 0, L_FRAME8K);
    st.q_old_wtda = 15;
    st.q_old_postdec = 0;
    st.qprev_synth_buffer = 15;
    set16(&mut st.old_is_transient, 0, 3);
    st.old_bfi_cnt = 0;
    set16(&mut st.old_au_out_2fr, 0, L_FRAME8K * 2);
    set16(&mut st.old_out_pha[0], 0, N_LEAD_NB);
    set16(&mut st.old_out_pha[1], 0, N_LEAD_NB);
    st.prev_old_bfi = 0;
    st.phase_mat_flag = 0;
    st.phase_mat_next = 0;
    st.old_min_ind = 0;
    st.diff_energy = 0;
    set32(&mut st.old_imdc_tout, 0, L_FRAME8K / 2);
    set16(&mut st.prev_oldau_out, 0, L_FRAME8K);
    st.stat_mode_out = 0;
    st.stat_mode_old = 0;
    st.old_hq_voicing = 0;

    for i in 0..MAX_SB_NB as usize {
        st.ynrm_values[i][..MAX_PGF as usize].fill(0);
        st.r_p_values[i][..MAX_ROW as usize].fill(0);
    }
    set16(&mut st.norm_gain, 1, SFM_N_NB); // check if it is in Q0
    set16(&mut st.energy_ma_curr, 100, 2); // check if it is in Q0
    st.hq_fec_seed = RANDOM_INITSEED;
    set16(&mut st.delay_buf_out, 0, HQ_DELTA_MAX * HQ_DELAY_COMP);
    set16(&mut st.previoussynth, 0, L_FRAME48K);
    set16(
        &mut st.old_synth_sw,
        0,
        ns2sa(48000, FRAME_SIZE_NS - ACELP_LOOK_NS - DELAY_BWE_TOTAL_NS),
    );
    set16(&mut st.prev_noise_level, 0, 2);
    st.prev_R = 0;
    set32(&mut st.prev_coeff_out, 0, L_HQ_WB_BWE);
    set16(&mut st.prev_swb_peak_pos, 0, SPT_SHORTEN_SBNUM);

    // HQ GENERIC
    st.hq_generic_seed = RANDOM_INITSEED;

    st.mem_norm[0] = 31;
    set16(&mut st.mem_norm[1..], 39, SFM_N_ENV_STAB - 1);
    st.mem_env_delta = 0;
    st.no_att_hangover = 0;
    st.energy_lt = 2_457_600; // 300 in Q13

    st.hq_voicing = 0;
    set16(&mut st.fer_samples, 0, L_FRAME48K);
    set32(&mut st.prev_env, 0, SFM_N_WB);
    set32(&mut st.prev_normq, 0, SFM_N_WB);
    st.prev_hqswb_clas = HQ_NORMAL;

    // LRMDCT_DELTA_NOISE_INJECT_FX
    set32(&mut st.last_ni_gain, 0, BANDS_MAX);
    set16(&mut st.last_env, 0, BANDS_MAX);
    st.last_max_pos_pulse = 0;

    st.prev_frm_hfe2 = 0;
    st.prev_stab_hfe2 = 0;
    st.prev_ni_ratio = 16384; // 0.5
    set16(&mut st.prev_en_sb, 0, NB_SWB_SUBBANDS);

    // pre-echo reduction
    reset_preecho_dec(st);

    // HQ FEC
    st.old_synth_fb = ns2sa_fx2(st.output_fs, PH_ECU_MEM_NS).max(0) as usize;
    st.prev_good_synth =
        st.old_synth_fb + ns2sa_fx2(st.output_fs, PH_ECU_LOOKAHEAD_NS).max(0) as usize;
    set16(&mut st.x_sav, 0, PH_ECU_SPEC_SIZE);
    st.q_x_sav = 0;
    st.num_p = 0;
    st.ph_ecu_active = 0;
    st.ni_seed_forfec = 0;
    st.last_fec = 0;
    st.ph_ecu_hq_voicing = 0;
    set16(&mut st.oldgapsynth, 0, L_FRAME48K);
    st.env_stab = 0x6000; // 0.75 (Q15)
    st.mem_norm_hqfec[0] = 31;
    set16(&mut st.mem_norm_hqfec[1..], 39, SFM_N_ENV_STAB - 1);
    st.mem_env_delta_hqfec = 0;
    st.env_stab_plc = 0;
    set16(
        &mut st.env_stab_state_p,
        INV_NUM_ENV_STAB_PLC_STATES,
        NUM_ENV_STAB_PLC_STATES,
    );
    st.envstabplc_hocnt = 0;

    set16(&mut st.mag_chg_1st, 32767, LGW_MAX);
    set16(&mut st.xavg, 0, LGW_MAX);
    st.beta_mute = BETA_MUTE_FAC_INI;

    set16(&mut st.prev_sign_switch, 0, HQ_FEC_SIGN_SFM);
    set16(&mut st.prev_sign_switch_2, 0, HQ_FEC_SIGN_SFM);
    st.time_offs = 0;
    st.ber_occured_in_pvq = 0;
}

/// SWB BWE, TBE and the WB/SWB bandwidth switching parameters.
fn init_decoder_bwe(st: &mut DecoderState) {
    // SWB BWE parameters
    st.old_wtda_wb_fx_exp = 0;
    set16(
        &mut st.old_syn_12k8_16k,
        0,
        ns2sa(16000, DELAY_FD_BWE_ENC_NS),
    );
    set16(&mut st.l_old_wtda_swb, 0, L_FRAME48K);
    st.old_wtda_swb_fx_exp = 0;
    st.mem_imdct_exp = 0;

    st.prev_mode = NORMAL;
    set16(&mut st.prev_swb_fenv, 0, SWB_FENV);
    st.prev_energy = 0;
    st.prev_l_swb_norm = 8;
    st.Seed = 21211;
    st.prev_frica_flag = 0;
    set16(&mut st.mem_imdct, 0, L_FRAME48K);
    st.prev_td_energy = 0;
    st.prev_weight = 6554; // 0.2 in Q15
    st.prev_flag = 0;
    st.prev_coder_type = GENERIC;
    st.last_wb_bwe_ener = 0;
    st.prev_hb_synth_fx_exp = 0;
    st.tilt_wb = 0;
    st.prev_energy_wb = 0;

    // TBE parameters
    init_swb_dec_buffer(st);
    reset_shb_buffer_dec(st);

    if st.output_fs == 48000 {
        set32(&mut st.fbbwe_hpf_mem[0], 0, 4);
        set32(&mut st.fbbwe_hpf_mem[1], 0, 4);
        set32(&mut st.fbbwe_hpf_mem[2], 0, 4);
        set32(&mut st.fbbwe_hpf_mem[3], 0, 4);
        set16(&mut st.fbbwe_hpf_mem_fx_q, 0, 4);
    }
    set16(&mut st.mem_resamp_hb, 0, INTERP_3_1_MEM_LEN);
    set16(&mut st.mem_resamp_hb_32k, 0, 2 * ALLPASSSECTIONS_STEEP + 1);
    set16(
        &mut st.prev_synth_buffer,
        0,
        ns2sa_fx2(48000, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS),
    );
    set16(
        &mut st.hb_prev_synth_buffer,
        0,
        ns2sa_fx2(48000, DELAY_BWE_TOTAL_NS),
    );
    st.old_bwe_delay = -1; // Q0

    st.tilt_mem = 0;
    set16(&mut st.prev_lsf_diff, 16384, LPC_SHB_ORDER - 2);
    st.prev_tilt_para = 0;
    set16(&mut st.cur_sub_aq, 0, M + 1);
    set16(&mut st.int_3_over_2_tbemem_dec, 0, INTERP_3_2_MEM_LEN);
    set16(&mut st.interpol_3_2_cng_dec, 0, INTERP_3_2_MEM_LEN);

    // TD BWE post-processing
    st.ptr_mem_stp_swb = LPC_SHB_ORDER as usize - 1;
    set16(&mut st.mem_zero_swb, 0, LPC_SHB_ORDER);

    st.swb_lsp_prev_interp[..LPC_SHB_ORDER as usize]
        .copy_from_slice(&SWB_LSP_PREV_INTERP_INIT[..LPC_SHB_ORDER as usize]);

    st.prev1_shb_ener_sf = 32767; // Q15
    st.prev2_shb_ener_sf = 32767; // Q15
    st.prev3_shb_ener_sf = 32767; // Q15
    st.prev_res_shb_gshape = 8192; // 0.125 in Q14
    st.prev_mix_factors = 16384; // 0.5 in Q15
    st.prev_gain_shape = 0;
    st.prev_q_bwe_exc_fb = 51;
    set16(&mut st.fb_state_lpc_syn, 0, LPC_SHB_ORDER);
    st.fb_tbe_demph = 0;

    // WB/SWB bandwidth switching parameters
    st.tilt_swb = 0;
    st.prev_ener = 0;
    st.prev_ener_shb = 0;
    st.prev_ener_lh = 0;
    st.ener_lh = 0;
    st.ener_ll = 0;
    st.prev_ener_ll = 0;
    st.prev_fractive = 0;
    st.prev_bws_cnt = 0;
    st.bws_cnt = N_WS2N_FRAMES;
    st.bws_cnt1 = N_NS2W_FRAMES;
    st.attenu = 3277;
    st.last_inner_frame = L_FRAME8K;
    st.last_bwidth = 0;
    st.prev_weight1 = 16384;
}

/// Channel-aware mode, AMR-WB IO, the post-filters, the CLDFB banks, SC-VBR, IGF, the LPD core,
/// FD-CNG and the Q values.
fn init_decoder_postfilters_and_tools(st: &mut DecoderState) {
    // channel-aware mode parameters
    set16(&mut st.tilt_code_dec, 0, NB_SUBFR16K);

    st.use_partial_copy = 0;
    st.prev_use_partial_copy = 0;
    st.rf_flag = 0;
    st.rf_flag_last = 0;
    st.prev_rf_frame_type = 0;
    st.next_coder_type = 0;

    st.rf_target_bits = 0;

    st.rf_indx_nelp_fid = 0;
    st.rf_indx_nelp_i_g1 = 0;
    st.rf_indx_nelp_i_g2[0] = 0;
    st.rf_indx_nelp_i_g2[1] = 0;
    st.rf_indx_tbe_gain_fr = 0;

    // Improvement of unvoiced and audio signals in AMR-WB IO mode parameters
    st.uv_cnt = 30;
    st.lt_uv_cnt = 60 << 6;
    set16(&mut st.lt_diff_etot, 0, MAX_LT);
    st.Last_ener = 0;
    set16(&mut st.old_aq, 0, 4 * (M + 1));
    let m1 = M as usize + 1;
    st.old_aq[0] = 16384;
    st.old_aq[m1] = 16384;
    st.old_aq[2 * m1] = 16384;
    st.old_aq[3 * m1] = 16384;
    st.lt_voice_fac = 0;

    // Postfilters
    bass_psfilter_init(
        &mut st.pst_old_syn,
        &mut st.pst_mem_deemp_err,
        &mut st.pst_lp_ener,
    );
    st.bpf_off = 0;
    set16(&mut st.track_on_hist, 0, L_TRACK_HIST);
    set16(&mut st.vibrato_hist, 0, L_TRACK_HIST);
    set16(&mut st.mem_mean_pit, 80, L_TRACK_HIST);
    st.psf_att = 32767;

    // FD BPF & resampling tools parameters
    // open analysis for max. SR 48kHz
    open_cldfb(
        &mut st.cldfb_ana,
        CLDFB_ANALYSIS,
        cldfb_get_num_channels(48000),
        320,
    );
    // open analysis BPF for max. SR 16kHz
    open_cldfb(
        &mut st.cldfb_bpf,
        CLDFB_ANALYSIS,
        cldfb_get_num_channels(16000),
        320,
    );
    // open synthesis for output SR
    open_cldfb(
        &mut st.cldfb_syn,
        CLDFB_SYNTHESIS,
        cldfb_get_num_channels(st.output_fs),
        st.output_frame,
    );

    st.last_active_bands_to_zero_bwdec = 0;
    st.flag_nb_bwddec = 0;
    st.perc_bwddec = 0;
    st.last_flag_filter_nb = 0;
    st.active_frame_cnt_bwddec = 0;
    st.total_frame_cnt_bwddec = 0;
    set16(&mut st.flag_buffer, 0, 20);
    st.avg_nrg_lt = 0;

    st.ng_ener_st = -13056; // -51 IN Q8
    st.last_frame_ener = MAX_32;
    st.old_es_pred = 0;
    set16(&mut st.old_aq_12_8[1..], 0, M);
    st.old_aq_12_8[0] = 4096; // 1 in Q12

    // SC-VBR
    st.fade_scale = 32767; // Q15
    st.last_ppp_mode_dec = 0;
    st.old_ppp_mode = 0;
    st.ppp_mode_dec = 0;
    st.last_nelp_mode_dec = 0;
    st.nelp_mode_dec = 0;
    st.nelp_dec_seed = 0;
    st.first_time_voiceddec = 1;
    st.prev_gain_pit_dec = 0;
    st.prev_tilt_code_dec = 0;
    st.vbr_hw_bwe_disable_dec = 0;
    st.last_vbr_hw_bwe_disable_dec = 0;
    set16(&mut st.old_hb_synth, 0, L_FRAME48K);

    // DTFS variables
    set16(&mut st.dtfs_dec_a, 0, MAXLAG_WI);
    set16(&mut st.dtfs_dec_b, 0, MAXLAG_WI);
    st.dtfs_dec_lag = 0;
    st.dtfs_dec_n_h = 0;
    st.dtfs_dec_n_h_4k_hz = 0;
    st.dtfs_dec_upper_cut_off_freq_of_interest = 0;
    st.dtfs_dec_upper_cut_off_freq = 0;
    st.ph_offset_d = 0;
    st.last_lgain_d = 0;
    st.last_hgain_d = 0;
    set16(&mut st.lasterb_d, 0, NUM_ERB_WB);
    st.dtfs_dec_q = 0;

    // NELP decoder variables
    set32(&mut st.bp1_filt_mem_nb_dec, 0, 14);
    set16(&mut st.bp1_filt_mem_wb_dec, 0, 8);
    set16(&mut st.shape1_filt_mem_dec, 0, 10);
    set16(&mut st.shape2_filt_mem_dec, 0, 10);
    set16(&mut st.shape3_filt_mem_dec, 0, 10);

    // IGF
    st.igf = 0;
    // set16_fx((Word16*)&st_fx->hIGFDec, 0, ...): the whole instance, its ROM pointers included
    st.h_igf_dec = IgfdecInstance::zeroed();
    st.h_igf_dec.igf_data.igf_info.nf_seed = 9733;

    st.enable_plc_waveadjust = 0;

    // Init Decoder
    open_decoder_lpd(st, st.total_brate, st.bwidth);

    st.m_decode_mode = DEC_NO_FRAM_LOSS;
    st.m_frame_type = ACTIVE_FRAME;
    st.m_old_frame_type = ACTIVE_FRAME;

    let new_cldfb_bands = cldfb_get_num_channels(l_mult0(st.l_frame, 50));
    if let Some(hs) = st.cldfb_ana.as_deref_mut() {
        resample_cldfb(hs, new_cldfb_bands, st.l_frame, 1);
    }
    if let Some(hs) = st.cldfb_bpf.as_deref_mut() {
        resample_cldfb(hs, new_cldfb_bands, st.l_frame, 1);
    }

    // Create FD_CNG instance
    create_fd_cng_dec(&mut st.h_fd_cng_dec);

    // Init FD-CNG (both handles were opened just above)
    if let (Some(hs), Some(syn)) = (st.h_fd_cng_dec.as_deref_mut(), st.cldfb_syn.as_deref()) {
        init_fd_cng_dec(hs, syn.scale);
    }

    st.lp_noise = -167_772_160; // -20.f Q23
    st.force_lpd_reset = 0;

    // initialzie Q values
    st.mem_exp1 = 0;
    st.q_syn2 = 0;
    st.q_exc = 8;
    st.prev_q_exc = 0;
    st.q_syn = 0;
    st.prev_q_syn = 0;
    st.q_subfr[..L_Q_MEM as usize].fill(8);

    // Previous frame LPC initialization for PPP
    st.prev_q_synth = 0;
    st.prev_q_exc_fr = 0;
    st.prev_q_syn_fr = 0;
}

/// `reset_preecho_dec_fx`: initialise the pre-echo reduction memories.
pub fn reset_preecho_dec(st: &mut DecoderState) {
    st.memfilt_lb = 0;
    st.mean_prev_hb = 0;
    st.smoothmem = 32767;
    st.mean_prev = 0;
    st.mean_prev_nc = 0;
    st.wmold_hb = 32767;
    st.prevflag = 0;
    st.pastpre = 0;
}

/// `destroy_decoder`: release what `init_decoder_fx` allocated (the CLDFB banks and FD-CNG).
pub fn destroy_decoder(st: &mut DecoderState) {
    // CLDFB BPF & resampling tools
    delete_cldfb(&mut st.cldfb_ana); // delete analysis for max. SR 16kHz
    delete_cldfb(&mut st.cldfb_bpf); // delete analysis BPF for max. SR 16kHz
    delete_cldfb(&mut st.cldfb_syn); // delete synthesis for output SR
    delete_fd_cng_dec(&mut st.h_fd_cng_dec);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destroy_decoder_releases_every_handle() {
        let mut st = DecoderState::zeroed();
        st.output_fs = 16000;
        st.output_frame = 320;
        init_decoder(&mut st);
        assert!(st.cldfb_ana.is_some() && st.cldfb_bpf.is_some() && st.cldfb_syn.is_some());
        assert!(st.h_fd_cng_dec.is_some());
        destroy_decoder(&mut st);
        assert!(st.cldfb_ana.is_none() && st.cldfb_bpf.is_none() && st.cldfb_syn.is_none());
        assert!(st.h_fd_cng_dec.is_none());
    }
}
