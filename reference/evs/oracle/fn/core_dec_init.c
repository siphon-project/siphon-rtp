/* Function-level oracle for lib_dec/core_dec_init.c (open_decoder_LPD).
 *
 * Each case builds a decoder the way init_decoder_fx and mode_switch_decoder_LPD leave it: a first
 * open_decoder_LPD on a fresh state (ini_frame 0), then zero to three later calls at other bit
 * rates and bandwidths, each after the per-frame fields a decoder would have set (last core,
 * codec mode, frame length, concealment flags) and fresh signal memories. Only the last call is
 * printed: every field open_decoder_LPD reads or writes, before and after. Arrays it only writes
 * are filled with a deterministic pattern before the call and compared by hash. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define CLDFB_STATE_BUFFER_SIZE (9 + 16) /* STATE_BUFFER_SIZE, file-local in cldfb.c */

static long long hash16(const Word16 *x, int n)
{
    unsigned int h = 2166136261u;
    for (int i = 0; i < n; i++) { h ^= (unsigned short)x[i]; h *= 16777619u; }
    return h;
}

static long long hash32(const Word32 *x, int n)
{
    unsigned int h = 2166136261u;
    for (int i = 0; i < n; i++) { h ^= (unsigned int)x[i]; h *= 16777619u; }
    return h;
}

static void fill_pattern16(Word16 *x, int n, int salt)
{
    for (int i = 0; i < n; i++) x[i] = (Word16)((i * 31 + salt * 17) % 2001 - 1000);
}

static void fill_pattern32(Word32 *x, int n, int salt)
{
    for (int i = 0; i < n; i++) x[i] = (Word32)((i * 31 + salt * 17) % 2001 - 1000) * 65537;
}

static int tns_table_id(const struct TnsParameters *p)
{
    const struct TnsParameters *tables[] = {tnsParametersIGF32kHz_LowBR, tnsParameters32kHz, tnsParameters32kHz_grouped,
                                            tnsParameters16kHz, tnsParameters16kHz_grouped, tnsParameters48kHz_grouped};
    for (int i = 0; i < 6; i++) if (p == tables[i]) return i;
    return -1;
}

static int cldfb_buffer_length(HANDLE_CLDFB_FILTER_BANK hs)
{
    return (hs->type == CLDFB_ANALYSIS ? 1 : 2) * CLDFB_STATE_BUFFER_SIZE * hs->no_channels;
}

static void put_banks(Decoder_State_fx *st)
{
    HANDLE_CLDFB_FILTER_BANK banks[3] = {st->cldfbAna_fx, st->cldfbBPF_fx, st->cldfbSyn_fx};
    const char *names[3] = {"cldfb_ana", "cldfb_bpf", "cldfb_syn"};
    for (int b = 0; b < 3; b++) {
        char name[64];
        sprintf(name, "%s_states", names[b]); put1(name, hash16(banks[b]->FilterStates, cldfb_buffer_length(banks[b])));
        sprintf(name, "%s_e", names[b]); put16(name, banks[b]->FilterStates_e, CLDFB_NO_COL_MAX + 9);
        sprintf(name, "%s_eg", names[b]); put1(name, banks[b]->FilterStates_eg);
    }
}

static void put_tns(Decoder_State_fx *st)
{
    for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) {
        STnsConfig *c = &st->tcx_cfg.tnsConfig[i][j];
        char name[32];
        sprintf(name, "tns%d%d", i, j);
        Word16 v[6] = {c->maxOrder, c->nMaxFilters, (Word16)tns_table_id(c->pTnsParameters),
                       c->iFilterBorders[0], c->iFilterBorders[1], c->iFilterBorders[2]};
        put16(name, v, 6);
    }
}

static void put_state(Decoder_State_fx *st)
{
    put1("ini_frame", st->ini_frame_fx);
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("rf_flag", st->rf_flag);
    put1("igf", st->igf);
    put1("bwidth", st->bwidth_fx);
    put1("last_bwidth", st->last_bwidth_fx);
    put1("h_igf_dec.info_igf_stop_freq", st->hIGFDec.infoIGFStopFreq);
    put1("last_codec_mode", st->last_codec_mode);
    put1("core", st->core_fx);
    put1("m_frame_type", st->m_frame_type);
    put1("last_con_tcx", st->last_con_tcx);
    put1("last_total_brate", st->last_total_brate_fx);
    put1("q_syn", st->Q_syn);
    put1("pst_lp_ener", st->pst_lp_ener_fx);
    put1("force_lpd_reset", st->force_lpd_reset);
    put16("fer_samples", st->fer_samples_fx, 960);
    put16("previoussynth", st->previoussynth_fx, 960);
    put1("total_brate", st->total_brate_fx);
    put1("fscale_old", st->fscale_old);
    put1("sr_core", st->sr_core);
    put1("fscale", st->fscale);
    put1("l_frame", st->L_frame_fx);
    put1("l_frame_tcx", st->L_frameTCX);
    put1("last_l_frame", st->last_L_frame_fx);
    put1("l_frame_past", st->L_frame_past);
    put1("l_frame_tcx_past", st->L_frameTCX_past);
    put1("tcxonly", st->tcxonly);
    put1("nb_subfr", st->nb_subfr);
    put1("bits_frame", st->bits_frame);
    put1("tcx_bandwidth", st->TcxBandwidth);
    put1("narrow_band", st->narrowBand);
    put1("pit_min", st->pit_min);
    put1("pit_fr1", st->pit_fr1);
    put1("pit_fr1b", st->pit_fr1b);
    put1("pit_fr2", st->pit_fr2);
    put1("pit_max", st->pit_max);
    put1("pit_res_max", st->pit_res_max);
    put1("pit_res_max_past", st->pit_res_max_past);
    put1("pit_max_tcx", st->pit_max_TCX);
    put1("pit_min_tcx", st->pit_min_TCX);
    put1("preemph_fac", st->preemph_fac);
    put1("gamma", st->gamma);
    put1("inv_gamma", st->inv_gamma);
    put1("lpc_quantization", st->lpcQuantization);
    put1("numlpc", st->numlpc);
    put1("prev_coder_type", st->prev_coder_type_fx);
    put16("prev_lsf_diff", st->prev_lsf_diff_fx, 8);
    put1("prev_tilt_para", st->prev_tilt_para_fx);
    put16("cur_sub_aq", st->cur_sub_Aq_fx, 17);
    put1("tcx_cfg.preemph_fac", st->tcx_cfg.preemph_fac);
    put1("tcx_cfg.tcx_mdct_window_length", st->tcx_cfg.tcx_mdct_window_length);
    put1("tcx_cfg.tcx_mdct_window_length_old", st->tcx_cfg.tcx_mdct_window_length_old);
    put1("tcx_cfg.tcx_mdct_window_delay", st->tcx_cfg.tcx_mdct_window_delay);
    put1("tcx_cfg.tcx_mdct_window_length_fb", st->tcx_cfg.tcx_mdct_window_lengthFB);
    put1("tcx_cfg.tcx_mdct_window_delay_fb", st->tcx_cfg.tcx_mdct_window_delayFB);
    put1("tcx_cfg.tcx_last_overlap_mode", st->tcx_cfg.tcx_last_overlap_mode);
    put1("tcx_cfg.tcx_curr_overlap_mode", st->tcx_cfg.tcx_curr_overlap_mode);
    put1("tcx_cfg.tcx_offset", st->tcx_cfg.tcx_offset);
    put1("tcx_cfg.tcx_offset_fb", st->tcx_cfg.tcx_offsetFB);
    put1("tcx_cfg.lfac_next", st->tcx_cfg.lfacNext);
    put1("tcx_cfg.lfac_next_fb", st->tcx_cfg.lfacNextFB);
    put1("tcx_cfg.tcx_coded_lines", st->tcx_cfg.tcx_coded_lines);
    put1("tcx_cfg.f_is_tns_allowed", st->tcx_cfg.fIsTNSAllowed);
    put1("tcx_cfg.last_aldo", st->tcx_cfg.last_aldo);
    put1("tcx_cfg.ctx_hm", st->tcx_cfg.ctx_hm);
    put1("tcx_cfg.resq", st->tcx_cfg.resq);
    put1("tcx_cfg.sq_rounding", st->tcx_cfg.sq_rounding);
    put1("tcx_cfg.na_scale", st->tcx_cfg.na_scale);
    put16("tec_dec.p_gain_temp_m", st->tecDec_fx.pGainTemp_m, 16);
    put16("tec_dec.p_gain_temp_e", st->tecDec_fx.pGainTemp_e, 16);
    put16("tec_dec.lo_buffer", st->tecDec_fx.loBuffer, 22);
    put1("flag_cna", st->flag_cna);
    put1("last_flag_cna", st->last_flag_cna);
    put1("last_is_cng", st->last_is_cng);
    put1("rate_switching_reset", st->rate_switching_reset);
    put1("old_syn_overl", hash16(st->old_syn_Overl, 320));
    put1("syn_overl_tdac", hash16(st->syn_Overl_TDAC, 320));
    put1("syn_overl_fb", hash16(st->syn_OverlFB, 480));
    put1("syn_overl_tdacfb", hash16(st->syn_Overl_TDACFB, 480));
    put1("syn_overl", hash16(st->syn_Overl, 320));
    put1("old_synth", hash16(st->old_synth, 1280));
    put1("synth_history", hash16(st->synth_history_fx, 2496));
    put16("syn", st->syn, 17);
    put16("mem_syn_r", st->mem_syn_r, 60);
    put1("con_tcx", st->con_tcx);
    put16("mem_ma", st->mem_MA_fx, 16);
    put16("mem_ar", st->mem_AR_fx, 16);
    put16("lspold_uw", st->lspold_uw, 16);
    put16("lsfold_uw", st->lsfold_uw, 16);
    put1("last_core", st->last_core_fx);
    put1("last_core_bfi", st->last_core_bfi);
    put1("q_old_wtda", st->Q_old_wtda);
    put16("old_out", st->old_out_fx, 960);
    put16("old_out_lb", st->old_out_LB_fx, 640);
    put1("q_old_wtda_lb", st->Q_old_wtda_LB);
    put1("tilt_code", st->tilt_code_fx);
    put16("old_exc", st->old_exc_fx, 480);
    put16("mem_syn2", st->mem_syn2_fx, 16);
    put1("pfstat.on", st->pfstat.on);
    put1("pfstat.reset", st->pfstat.reset);
    put16("pfstat.mem_pf_in", st->pfstat.mem_pf_in, 64);
    put16("pfstat.mem_stp", st->pfstat.mem_stp, 64);
    put16("pfstat.mem_res2", st->pfstat.mem_res2, 299);
    put1("pfstat.gain_prec", st->pfstat.gain_prec);
    put16("lsp_old", st->lsp_old_fx, 16);
    put16("lsf_old", st->lsf_old_fx, 16);
    put16("old_aq_12_8", st->old_Aq_12_8_fx, 17);
    put1("old_synth_len", st->old_synth_len);
    put1("old_synth_len_fb", st->old_synth_lenFB);
    put1("bpf_gain_param", st->bpf_gain_param);
    put16("pst_old_syn", st->pst_old_syn_fx, 290);
    put16("lsf_cng", st->lsf_cng, 16);
    put1("seed_tcx_plc", st->seed_tcx_plc);
    put1("past_gpit", st->past_gpit);
    put1("past_gcode", st->past_gcode);
    put1("gc_threshold", st->gc_threshold_fx);
    put16("lspold_cng", st->lspold_cng, 16);
    put1("aq_cng", hash16(st->Aq_cng, 102));
    put1("plc_background_noise_updated", st->plcBackgroundNoiseUpdated);
    put16("lsf_q_cng", st->lsf_q_cng, 16);
    put16("old_lsf_q_cng", st->old_lsf_q_cng, 16);
    put16("lsp_q_cng", st->lsp_q_cng, 16);
    put16("old_lsp_q_cng", st->old_lsp_q_cng, 16);
    put16("mem_syn_unv_back", st->mem_syn_unv_back, 16);
    put1("last_gain_syn_deemph", st->last_gain_syn_deemph);
    put1("last_gain_syn_deemph_e", st->last_gain_syn_deemph_e);
    put1("last_concealed_gain_syn_deemph", st->last_concealed_gain_syn_deemph);
    put1("last_concealed_gain_syn_deemph_e", st->last_concealed_gain_syn_deemph_e);
    put1("conceal_eof_gain", st->conceal_eof_gain);
    put1("mem_aq", hash16(st->mem_Aq, 85));
    put1("lp_ener_fer", st->lp_ener_FER_fx);
    put1("prev_bfi", st->prev_bfi_fx);
    put1("prev_old_bfi", st->prev_old_bfi_fx);
    put16("lsf_adaptive_mean", st->lsf_adaptive_mean_fx, 16);
    put16("lsfoldbfi0", st->lsfoldbfi0_fx, 16);
    put16("lsfoldbfi1", st->lsfoldbfi1_fx, 16);
    put1("clas_dec", st->clas_dec);
    put1("old_enr_lp", st->old_enr_LP);
    put1("enr_old", st->enr_old_fx);
    put1("last_good", st->last_good_fx);
    put1("mode2_lp_gainc", st->Mode2_lp_gainc);
    put1("mode2_lp_gainp", st->Mode2_lp_gainp);
    put1("prev_widow_left_rect", st->prev_widow_left_rect);
    put1("con_cng_level_background_trace", st->conCngLevelBackgroundTrace);
    put1("con_cng_level_background_trace_e", st->conCngLevelBackgroundTrace_e);
    put1("con_noise_level_index", st->conNoiseLevelIndex);
    put1("con_curr_level_index", st->conCurrLevelIndex);
    put1("con_last_frame_level", st->conLastFrameLevel);
    put1("con_last_frame_level_e", st->conLastFrameLevel_e);
    put16("con_noise_level_memory", st->conNoiseLevelMemory, 50);
    put16("con_noise_level_memory_e", st->conNoiseLevelMemory_e, 50);
    put1("cummulative_damping_tcx", st->cummulative_damping_tcx);
    put1("cummulative_damping", st->cummulative_damping);
    put32("old_pitch_buf", st->old_pitch_buf_fx, 12);
    put16("mem_pitch_gain", st->mem_pitch_gain, 12);
    put1("old_fpitch", st->old_fpitch);
    put1("old_fpitch_fb", st->old_fpitchFB);
    put1("rate_switching_init", st->rate_switching_init);
    put1("reset_mem_ar", st->reset_mem_AR);
    put1("dm.prev_gain_code", st->dm_fx.prev_gain_code);
    put16("dm.prev_gain_pit", st->dm_fx.prev_gain_pit, 6);
    put1("dm.prev_state", st->dm_fx.prev_state);
    put1("voice_fac", st->voice_fac);
    put1("tcxltp", st->tcxltp);
    put1("tcxltp_pitch_int", st->tcxltp_pitch_int);
    put1("tcxltp_pitch_fr", st->tcxltp_pitch_fr);
    put1("tcxltp_last_gain_unmodified", st->tcxltp_last_gain_unmodified);
    put16("tcxltp_mem_in", st->tcxltp_mem_in, 12);
    put1("tcxltp_mem_out", hash16(st->tcxltp_mem_out, 960));
    put1("tcxltp_pitch_int_post_prev", st->tcxltp_pitch_int_post_prev);
    put1("tcxltp_pitch_fr_post_prev", st->tcxltp_pitch_fr_post_prev);
    put1("tcxltp_gain_post_prev", st->tcxltp_gain_post_prev);
    put1("tcxltp_filt_idx_prev", st->tcxltp_filt_idx_prev);
    put1("lp_error_ener", st->lp_error_ener);
    put1("mem_error", st->mem_error);
    put1("last_ctx_hm_enabled", st->last_ctx_hm_enabled);
    put1("tcx_lpc_shaped_ari", st->tcx_lpc_shaped_ari);
    put1("env_weighted", st->envWeighted);
    put1("tec_tfa", st->tec_tfa);
    put1("tec_flag", st->tec_flag);
    put1("tfa_flag", st->tfa_flag);
    put1("enable_gplc", st->enableGplc);
    put1("flag_guided_acelp", st->flagGuidedAcelp);
    put1("t0_4th", st->T0_4th);
    put1("guided_t0", st->guidedT0);
    put1("enable_plc_waveadjust", st->enablePlcWaveadjust);
    put1("plc_info.frame_size", st->plcInfo.FrameSize);
    put1("plc_info.pitch", st->plcInfo.Pitch_fx);
    put1("plc_info.t_bfi", st->plcInfo.T_bfi_fx);
    put16("plc_info.transient", st->plcInfo.Transient, 3);
    put16("plc_info.tcx_tonality", st->plcInfo.TCX_Tonality, 10);
    put1("plc_info.outx_new_n1", st->plcInfo.outx_new_n1_fx);
    put1("plc_info.nsapp_gain", st->plcInfo.nsapp_gain_fx);
    put1("plc_info.nsapp_gain_n", st->plcInfo.nsapp_gain_n_fx);
    put1("plc_info.data_reci2", hash32(st->plcInfo.data_reci2_fx, 960));
    put1("plc_info.ener_mean", st->plcInfo.ener_mean_fx);
    put1("plc_info.ener", st->plcInfo.ener_fx);
    put1("plc_info.zp", st->plcInfo.zp_fx);
    put1("plc_info.recovery_gain", st->plcInfo.recovery_gain);
    put1("plc_info.step_concealgain", st->plcInfo.step_concealgain_fx);
    put1("plc_info.concealment_method", st->plcInfo.concealment_method);
    put1("plc_info.subframe", st->plcInfo.subframe_fx);
    put1("plc_info.nb_lost_cmpt", st->plcInfo.nbLostCmpt);
    put1("plc_info.seed", st->plcInfo.seed);
    put1("tonal_mdc_tconceal.n_scale_factors", st->tonalMDCTconceal.nScaleFactors);
    put1("tonal_mdc_tconceal.n_samples", st->tonalMDCTconceal.nSamples);
    put1("tonal_mdc_tconceal.n_samples_core", st->tonalMDCTconceal.nSamplesCore);
    put1("tonal_mdc_tconceal.last_block_data.tonal_concealment_active", st->tonalMDCTconceal.lastBlockData.tonalConcealmentActive);
    put1("tonal_mdc_tconceal.last_block_data.n_samples", st->tonalMDCTconceal.lastBlockData.nSamples);
    put1("tonal_mdc_tconceal.last_block_data.block_is_valid", st->tonalMDCTconceal.lastBlockData.blockIsValid);
    put1("tonal_mdc_tconceal.second_last_block_data.block_is_valid", st->tonalMDCTconceal.secondLastBlockData.blockIsValid);
    put1("last_tns_active", st->last_tns_active);
    put1("second_last_tns_active", st->second_last_tns_active);
    put1("second_last_core", st->second_last_core);
    put1("tcxltp_second_last_pitch", st->tcxltp_second_last_pitch);
    put1("tcxltp_third_last_pitch", st->tcxltp_third_last_pitch);
    put1("dec_glr", st->dec_glr);
    put1("dec_glr_idx", st->dec_glr_idx);
    put1("enable_tcx_lpc", st->enableTcxLpc);
    put1("vad", st->VAD);
    put1("old_gaintcx_bfi", st->old_gaintcx_bfi);
    put1("old_gaintcx_bfi_e", st->old_gaintcx_bfi_e);
    put1("tcx_hm_ltp_pitch_lag", st->tcx_hm_LtpPitchLag);
    put1("tcxltp_gain", st->tcxltp_gain);
    put1("p_bpf_noise_buf", st->p_bpf_noise_buf == NULL ? -1 : (long long)(st->p_bpf_noise_buf - st->bpf_noise_buf));
    put1("tonal_mdc_tconceal.last_pcm_out", st->tonalMDCTconceal.lastPcmOut == NULL ? -1 : (long long)(st->tonalMDCTconceal.lastPcmOut - st->tonalMDCTconceal.timeDataBuffer));
    put1("tonal_mdc_tconceal.second_last_pcm_out", st->tonalMDCTconceal.secondLastPcmOut == NULL ? -1 : (long long)(st->tonalMDCTconceal.secondLastPcmOut - st->tonalMDCTconceal.timeDataBuffer));
    put1("tcx_cfg.p_current_tns_config", st->tcx_cfg.pCurrentTnsConfig == NULL ? -1 : (long long)(st->tcx_cfg.pCurrentTnsConfig - &st->tcx_cfg.tnsConfig[0][0]));
    put_tns(st);
}

static void fill_patterns(Decoder_State_fx *st)
{
    fill_pattern16(st->old_syn_Overl, 320, 1);
    fill_pattern16(st->syn_Overl_TDAC, 320, 2);
    fill_pattern16(st->syn_OverlFB, 480, 3);
    fill_pattern16(st->syn_Overl_TDACFB, 480, 4);
    fill_pattern16(st->syn_Overl, 320, 5);
    fill_pattern16(st->old_synth, 1280, 6);
    fill_pattern16(st->synth_history_fx, 2496, 7);
    fill_pattern16(st->Aq_cng, 102, 8);
    fill_pattern16(st->mem_Aq, 85, 9);
    fill_pattern16(st->tcxltp_mem_out, 960, 10);
    fill_pattern32(st->plcInfo.data_reci2_fx, 960, 11);
    HANDLE_CLDFB_FILTER_BANK banks[3] = {st->cldfbAna_fx, st->cldfbBPF_fx, st->cldfbSyn_fx};
    for (int b = 0; b < 3; b++) {
        fill_pattern16(banks[b]->FilterStates, cldfb_buffer_length(banks[b]), 100 + b);
        for (int i = 0; i < CLDFB_NO_COL_MAX + 9; i++) banks[b]->FilterStates_e[i] = (Word16)(i % 5 + b);
        banks[b]->FilterStates_eg = (Word16)(3 + b);
    }
}

/* An ordered LSF vector at the core rate (Q(x2.56) of 6400 Hz), at least 128 apart, and its LSPs. */
static void random_lsf_lsp(Word16 *lsf, Word16 *lsp)
{
    int pos = random_range(100, 600);
    for (int i = 0; i < M; i++) {
        if (i > 0) pos += random_range(128, 1400);
        if (pos > 16000 - (M - 1 - i) * 200) pos = 16000 - (M - 1 - i) * 200;
        lsf[i] = (Word16)pos;
    }
    E_LPC_lsf_lsp_conversion(lsf, lsp, M);
}

/* A bit rate / bandwidth pair: for the first call (init_decoder_fx) any EVS rate; for a later one
 * (mode_switch_decoder_LPD) a rate the LPD core runs at, channel-aware mode at 13.2 kbit/s
 * included. */
static void random_mode(int first, Word32 *bitrate, Word16 *bandwidth, Word16 *rf_flag)
{
    static const Word32 rates[] = {9600, 13200, 16400, 24400, 32000, 48000, 96000, 128000, 7200, 8000, 64000};
    for (;;) {
        *bitrate = rates[next_random() % (first ? 11 : 8)];
        *bandwidth = (Word16)random_range(NB, FB);
        *rf_flag = 0;
        if (*bandwidth == NB && *bitrate > 24400) continue;
        if (*bandwidth == WB && *bitrate > 64000 && first) continue;
        if (*bandwidth == SWB && *bitrate < 13200) continue;
        if (*bandwidth == FB && *bitrate < 16400) continue;
        if (*bitrate == 13200 && *bandwidth != NB && *bandwidth != FB && (next_random() & 1)) *rf_flag = 1;
        return;
    }
}

/* The bandwidth, RF flag and IGF configuration: init_decoder_fx leaves IGF off and its handle
 * zeroed; mode_switch_decoder_LPD configures it for the new mode. */
static void set_mode(Decoder_State_fx *st, int first, Word32 bitrate, Word16 bandwidth, Word16 rf_flag)
{
    st->rf_flag = rf_flag;
    st->bwidth_fx = bandwidth;
    if (first) return;
    st->igf = getIgfPresent(bitrate, bandwidth, rf_flag);
    st->hIGFDec.infoIGFStopFreq = -1;
    if (st->igf) IGFDecSetMode(&st->hIGFDec, bitrate, bandwidth, -1, -1, rf_flag);
}

/* The per-frame state a decoder leaves between two open_decoder_LPD calls. */
static void next_frame(Decoder_State_fx *st, Word32 last_bitrate)
{
    static const Word16 mode1_cores[] = {ACELP_CORE, ACELP_CORE, HQ_CORE, AMR_WB_CORE};
    static const Word16 mode2_cores[] = {ACELP_CORE, TCX_20_CORE, TCX_10_CORE};
    st->ini_frame_fx = (Word16)(st->ini_frame_fx + 1);
    st->last_bwidth_fx = st->bwidth_fx;
    st->last_total_brate_fx = (next_random() % 8) ? last_bitrate : (Word32)random_range(5900, 128000);
    st->last_L_frame_fx = st->L_frame_fx;
    if (next_random() % 3 == 0) {
        st->last_codec_mode = MODE1;
        st->last_core_fx = mode1_cores[next_random() % 4];
        st->last_L_frame_fx = (st->last_core_fx != AMR_WB_CORE && (next_random() & 1)) ? L_FRAME16k : L_FRAME;
    } else {
        st->last_codec_mode = MODE2;
        st->last_core_fx = mode2_cores[next_random() % 3];
    }
    st->core_fx = (Word16)((next_random() % 3) == 0 ? HQ_CORE : random_range(ACELP_CORE, TCX_20_CORE));
    st->prev_bfi_fx = (Word16)((next_random() % 3) == 0);
    st->m_frame_type = (Word16)((next_random() % 4) == 0 ? SID_FRAME : 0);
    st->last_con_tcx = (Word16)(next_random() & 1);
    st->Q_old_wtda = (Word16)random_range(-2, 4);
    st->Q_syn = (Word16)random_range(-1, 4);
    st->pfstat.on = (Word16)(next_random() & 1);
    st->pst_lp_ener_fx = (Word16)random_range(0, 80 * 256);
    st->force_lpd_reset = (Word16)((next_random() % 4) == 0);
    random_lsf_lsp(st->lsf_old_fx, st->lsp_old_fx);
    Word16 lsp[M];
    random_lsf_lsp(st->lsf_cng, lsp);
    int magnitude = random_range(100, 16000);
    random_signal(st->fer_samples_fx, L_FRAME48k, magnitude);
    /* quieter, and often silent in its first half, so the energy at the end of the frame
     * (frame_ener_fx after a lost HQ frame) depends on which half it measures */
    random_signal(st->previoussynth_fx, L_FRAME48k, random_range(1, 2000));
    if (next_random() & 1) memset(st->previoussynth_fx, 0, sizeof(Word16) * random_range(0, L_FRAME48k / 2));
    if (st->last_core_fx == HQ_CORE && (next_random() & 1)) { st->prev_bfi_fx = 1; st->core_fx = ACELP_CORE; }
    random_signal(st->old_out_fx, L_FRAME48k, magnitude);
    random_signal(st->old_out_LB_fx, L_FRAME32k, magnitude);
    random_signal(st->old_exc_fx, L_EXC_MEM_DEC, magnitude / 2);
    random_signal(st->mem_syn_r, L_SYN_MEM, magnitude);
    random_signal(st->mem_syn2_fx, M, magnitude);
    random_signal(st->pfstat.mem_pf_in, L_SUBFR, magnitude);
    random_signal(st->pfstat.mem_stp, L_SUBFR, magnitude);
    random_signal(st->pfstat.mem_res2, DECMEM_RES2, magnitude);
    random_signal(st->syn, M + 1, magnitude);
    random_signal(st->pst_old_syn_fx, NBPSF_PIT_MAX, magnitude);
}

static void case_open_decoder_lpd(void)
{
    static const Word32 output_rates[] = {8000, 16000, 32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = output_rates[next_random() % 4];
    st->output_frame_fx = (Word16)(st->output_Fs_fx / 50);
    openCldfb(&st->cldfbAna_fx, CLDFB_ANALYSIS, CLDFB_getNumChannels(48000), 320);
    openCldfb(&st->cldfbBPF_fx, CLDFB_ANALYSIS, CLDFB_getNumChannels(16000), 320);
    openCldfb(&st->cldfbSyn_fx, CLDFB_SYNTHESIS, CLDFB_getNumChannels(st->output_Fs_fx), st->output_frame_fx);
    st->hIGFDec.igfData.igfInfo.nfSeed = 9733;
    random_lsf_lsp(st->lsf_old_fx, st->lsp_old_fx);

    Word32 bitrate, last_bitrate = 0;
    Word16 bandwidth, rf_flag;
    int calls = random_range(1, 4);
    for (int call = 0; call < calls; call++) {
        if (call > 0) next_frame(st, last_bitrate);
        random_mode(call == 0, &bitrate, &bandwidth, &rf_flag);
        /* the 12.8 <-> 16 kHz ACELP switch most of the time on a later call */
        if (call > 0 && (next_random() & 1)) {
            static const Word32 acelp_rates[] = {9600, 13200, 16400, 24400, 32000};
            bitrate = acelp_rates[next_random() % 5];
            bandwidth = (Word16)(bitrate <= 9600 ? random_range(NB, WB) : random_range(WB, SWB));
            rf_flag = 0;
        }
        set_mode(st, call == 0, bitrate, bandwidth, rf_flag);
        if (call == calls - 1) {
            fill_patterns(st);
            put1("bitrate", bitrate); put1("bandwidth", bandwidth); put_state(st);
        }
        open_decoder_LPD(st, bitrate, bandwidth);
        last_bitrate = bitrate;
    }
    arrow(); put_state(st); put_banks(st); end_line();
    deleteCldfb(&st->cldfbAna_fx); deleteCldfb(&st->cldfbBPF_fx); deleteCldfb(&st->cldfbSyn_fx);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "open_decoder_lpd")) case_open_decoder_lpd();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
