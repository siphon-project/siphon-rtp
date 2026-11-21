/* Function-level oracle for lib_dec/core_switching_dec_fx.c: bandwidth_switching_detect_fx,
 * bw_switching_pre_proc_fx, core_switching_pre_dec_fx and core_switching_post_dec_fx
 * (core_switching_hq_prepare_dec_fx is covered by its own oracle).
 *
 * Two modes:
 *   corpus FUNCTION COUNT SEED   synthetic cases: init_decoder_fx, then the per-frame state the
 *                                function reads randomised (every switch direction: ACELP <-> HQ
 *                                <-> AMR-WB IO, MODE1 <-> MODE2 with a TCX last frame and a lost
 *                                frame, bandwidth up / down, FD-CNG reconfiguration). The WHOLE state
 *                                is printed before the call ("in.") and, after it, the fields that
 *                                changed ("st."), so every field the function writes is compared and
 *                                every field it must leave alone.
 *   stream FILE FS EVERY         the whole reference decoder over a G.192 conformance bitstream; the
 *                                four functions are wrapped and every EVERY-th call (and every call
 *                                that switches core, bandwidth or codec mode) is recorded the same way.
 */
/* the acelp_core_switch_dec oracle's randomisation of the switching-frame state (and, through it,
 * init_dec.c, harness.h, state_capture.h and conceal_state.h) */
#include <sys/resource.h>
#define main acelp_oracle_main
#include "acelp_core_switch_dec.c"
#undef main

/* The reference functions are renamed so the wrappers below can take their place in the decoder. */
#define bandwidth_switching_detect_fx bandwidth_switching_detect_fx_reference
#define bw_switching_pre_proc_fx bw_switching_pre_proc_fx_reference
#define core_switching_pre_dec_fx core_switching_pre_dec_fx_reference
#define core_switching_post_dec_fx core_switching_post_dec_fx_reference
#include "../../c-code/lib_dec/core_switching_dec_fx.c"
#undef bandwidth_switching_detect_fx
#undef bw_switching_pre_proc_fx
#undef core_switching_pre_dec_fx
#undef core_switching_post_dec_fx

#define SYNTH_LEN (L_FRAME48k + HQ_DELTA_MAX * HQ_DELAY_COMP)

#define RS(array, magnitude) random_signal((array), (int)(sizeof(array) / sizeof((array)[0])), (magnitude))

static void random_signal32(Word32 *x, int n)
{
    for (int i = 0; i < n; i++) x[i] = (Word32)((next_random() & 0x7fffffff) >> random_range(0, 28)) * ((next_random() & 3) ? 1 : -1);
}
#define RS32(array) random_signal32((array), (int)(sizeof(array) / sizeof((array)[0])))

static const Word32 any_rates[] = {0, 2400, 2800, 5900, 7200, 8000, 9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000,
                                   6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};
#define N_ANY_RATES ((int)(sizeof(any_rates) / sizeof(any_rates[0])))
static const Word16 extl_values[] = {-1, WB_TBE, WB_BWE, SWB_CNG, SWB_TBE, SWB_BWE, FB_TBE, FB_BWE};

static Decoder_State_fx *new_decoder(Word32 fs)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = fs;
    st->output_frame_fx = extract_l(Mult_32_16(fs, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    return st;
}

static Word32 any_rate(void) { return any_rates[next_random() % N_ANY_RATES]; }
static Word16 any_extl(void) { return extl_values[next_random() % 8]; }
static Word16 flip(int one_in) { return (Word16)(next_random() % one_in == 0); }

/* The state the switching reads, beyond what the acelp oracle's randomise sets. */
static void switching_randomise(Decoder_State_fx *st, int touch_rates)
{
    int r;
    /* codec mode and cores */
    st->last_codec_mode = (Word16)(next_random() % 4 ? MODE1 : MODE2);
    r = next_random() % 20;
    st->core_fx = r < 9 ? ACELP_CORE : r < 17 ? HQ_CORE : AMR_WB_CORE;
    r = next_random() % 20;
    st->last_core_fx = r < 8 ? ACELP_CORE : r < 14 ? HQ_CORE : r < 16 ? AMR_WB_CORE : r < 18 ? TCX_20_CORE : TCX_10_CORE;
    if (st->last_codec_mode == MODE1 && st->last_core_fx >= TCX_20_CORE && st->last_core_fx <= TCX_10_CORE && next_random() % 8) st->last_core_fx = ACELP_CORE;
    st->prev_bfi_fx = flip(3);
    st->last_core_bfi = (Word16)(next_random() % 3 ? ACELP_CORE : (next_random() & 1) ? HQ_CORE : TCX_20_CORE);
    st->last_con_tcx = flip(3);

    if (touch_rates) {
        st->L_frame_fx = (Word16)((next_random() & 1) ? L_FRAME : L_FRAME16k);
        st->last_L_frame_fx = (Word16)(next_random() % 16 ? ((next_random() & 1) ? L_FRAME : L_FRAME16k) : L_FRAME32k);
        st->last_L_frame_ori_fx = st->last_L_frame_fx;
        st->core_brate_fx = any_rate();
        st->total_brate_fx = (next_random() % 6) ? st->core_brate_fx : any_rate();
        st->bwidth_fx = (Word16)random_range(NB, FB);
        st->last_bwidth_fx = (Word16)((next_random() % 3) ? st->bwidth_fx : random_range(NB, FB));
    }
    st->last_total_brate_fx = any_rate();
    st->last_core_brate_fx = any_rate();
    st->extl_fx = any_extl();
    st->last_extl_fx = (Word16)((next_random() % 3) ? st->extl_fx : any_extl());
    st->rf_flag = flip(6);
    st->rf_flag_last = (Word16)((next_random() % 3) ? st->rf_flag : flip(2));
    st->ini_frame_fx = (Word16)((next_random() % 5) ? random_range(1, MAX_FRAME_COUNTER) : 0);
    st->cng_type_fx = flip(2);
    st->sr_core = (next_random() & 1) ? 12800 : 16000;
    st->pastpre_fx = (Word16)random_range(-3, 5);
    st->bws_cnt_fx = (Word16)((next_random() % 3) ? 0 : random_range(1, N_WS2N_FRAMES + 1));
    st->bws_cnt1_fx = (Word16)((next_random() % 3) ? 0 : random_range(1, N_NS2W_FRAMES + 1));
    st->prev_bws_cnt_fx = (Word16)((next_random() % 3) ? N_WS2N_FRAMES : random_range(0, N_WS2N_FRAMES));
    st->prev_coder_type_fx = (Word16)random_range(INACTIVE, AUDIO);
    st->old_ppp_mode_fx = flip(6);
    st->last_ppp_mode_dec_fx = flip(2);
    st->last_nelp_mode_dec_fx = flip(2);
    st->act_count_fx = (Word16)random_range(0, 8);
    st->uv_count_fx = (Word16)random_range(0, 8);
    st->HqVoicing_fx = flip(2);
    st->oldHqVoicing_fx = flip(2);
    if (touch_rates) st->flag_cna = flip(2);
    st->VAD = flip(2);
    st->m_frame_type = (Word16)random_range(0, 2);
    st->attenu_fx = (Word16)random_range(0, 32767);
    st->prev_fractive_fx = (Word16)random_range(0, 32767);
    st->prev_ener_shb_fx = (Word16)random_range(0, 3000);
    st->tilt_wb_fx = (Word16)random_range(-3000, 3000);
    st->igf = flip(2);
    st->upd_cnt_fx = (Word16)random_range(0, 20);
    st->use_acelp_preq = flip(2);
    st->reset_mem_AR = flip(2);
    st->bpf_off_fx = flip(2);

    /* pre-echo memories (reset_preecho_dec_fx) */
    st->memfilt_lb_fx = (Word16)random_range(-3000, 3000);
    st->mean_prev_hb_fx = (Word32)random_range(0, 1 << 20);
    st->smoothmem_fx = (Word16)random_range(0, 32767);
    st->mean_prev_fx = (Word32)random_range(0, 1 << 20);
    st->mean_prev_nc_fx = (Word32)random_range(0, 1 << 20);
    st->wmold_hb_fx = (Word16)random_range(0, 32767);
    st->prevflag_fx = flip(2);

    /* scaling */
    st->Q_syn = (Word16)random_range(-1, 4);
    st->Q_syn2 = (Word16)random_range(-1, 8);
    st->Q_old_postdec = (Word16)random_range(-2, 6);
    st->Q_old_wtda = (Word16)random_range(-2, 6);
    st->Q_old_wtda_LB = (Word16)random_range(-2, 6);
    st->classifier_Q_mem_syn = (Word16)random_range(-2, 4);

    /* LP and post-filter memories */
    RS(st->syn, 3000);
    RS(st->mem_syn1_fx, 3000);
    RS(st->mem_syn2_fx, 3000);
    RS(st->mem_syn_r, 3000);
    RS(st->mem_syn_clas_estim_fx, 3000);
    RS(st->agc_mem_fx, 3000);
    RS(st->pst_old_syn_fx, 3000);
    RS(st->pfstat.mem_pf_in, 20000);
    RS(st->pfstat.mem_res2, 20000);
    RS(st->pfstat.mem_stp, 20000);
    st->pfstat.on = flip(2);
    st->mem_deemph_fx = (Word16)random_range(-8000, 8000);
    st->pst_lp_ener_fx = (Word16)random_range(0, 8000);
    st->pst_mem_deemp_err_fx = (Word16)random_range(-3000, 3000);
    st->psf_lp_noise_fx = (Word16)random_range(0, 10000);
    st->lp_error_ener = (Word32)random_range(0, 1 << 24) << random_range(0, 6);
    st->lp_noise = (Word32)random_range(0, 1 << 24) << random_range(0, 6);
    st->lp_ener_fx = (next_random() % 6) ? (Word32)random_range(1, 1 << 20) << random_range(0, 8) : 0;
    st->lp_gainc_fx = (Word16)random_range(0, 20000);
    st->lp_gainp_fx = (Word16)random_range(0, 19661);
    st->mem_deemph_old_syn_fx = (Word16)random_range(-3000, 3000);
    RS(st->lsf_old_fx, 16000);
    RS(st->lsfoldbfi0_fx, 16000);
    RS(st->lsfoldbfi1_fx, 16000);
    RS(st->lsf_adaptive_mean_fx, 16000);
    RS(st->mem_MA_fx, 1500);
    RS(st->mem_AR_fx, 9000);
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    st->gc_threshold_fx = (Word32)random_range(0, 1 << 20);
    st->dm_fx.prev_gain_code = (Word32)random_range(0, 1 << 20);
    RS(st->dm_fx.prev_gain_pit, 10000);
    st->dm_fx.prev_state = (Word16)random_range(0, 5);
    st->last_coder_type_fx = (Word16)random_range(INACTIVE, AUDIO);
    st->enr_old_fx = (Word32)random_range(0, 1 << 24);
    st->last_voice_factor_fx = (Word16)random_range(0, 32767);
    st->Last_GSC_noisy_speech_flag_fx = flip(2);
    st->Last_frame_ener_fx = (Word32)random_range(0, 1 << 24);
    RS(st->previoussynth_fx, (next_random() & 1) ? 20000 : 2000);
    RS(st->old_exc_fx, 8000);
    RS(st->old_bwe_exc_fx, 8000);
    RS(st->old_syn_12k8_16k_fx, 8000);
    RS(st->syn_Overl, 8000);
    RS(st->fer_samples_fx, (next_random() & 1) ? 20000 : 2000);
    RS(st->FBTCXdelayBuf, 8000);
    RS(st->prev_synth_buffer_fx, 8000);
    RS(st->hb_prev_synth_buffer_fx, 8000);
    st->old_bwe_delay_fx = (Word16)random_range(0, 200);
    st->prev_hb_synth_fx_exp = (Word16)random_range(0, 31);
    st->bwe_non_lin_prev_scale_fx = (Word32)random_range(0, 1 << 20);
    RS(st->mem_hp400_fx, 3000);
    RS(st->mem_hf_fx, 3000);
    RS(st->mem_syn_hf_fx, 3000);
    RS(st->delay_syn_hf_fx, 3000);
    RS(st->mem_hp_interp_fx, 3000);
    st->seed2_fx = random16();

    /* HQ memories */
    RS32(st->prev_env_fx);
    RS32(st->prev_normq_fx);
    RS32(st->last_ni_gain_fx);
    RS(st->last_env_fx, 20000);
    st->last_max_pos_pulse_fx = (Word16)random_range(0, 300);
    RS(st->prev_SWB_peak_pos_fx, 300);
    st->prev_frm_hfe2_fx = (Word16)random_range(0, 80);
    st->prev_stab_hfe2_fx = (Word16)random_range(0, 3);
    RS32(st->prev_coeff_out_fx);
    RS(st->old_out_fx, (next_random() & 1) ? 20000 : 2000);
    RS(st->delay_buf_out_fx, 8000);
    RS(st->t_audio_q_fx, (next_random() & 1) ? 20000 : 600);
    for (int i = 0; i < 3; i++) st->old_is_transient_fx[i] = flip(2);

    /* BWE / TBE memories */
    RS(st->prev_SWB_fenv_fx, 3000);
    RS(st->L_old_wtda_swb_fx, 3000);
    st->old_wtda_swb_fx_exp = (Word16)random_range(-3, 3);
    st->prev_mode_fx = (Word16)random_range(0, 4);
    st->prev_Energy_fx = (Word16)random_range(0, 3000);
    st->prev_Energy_wb_fx = (Word32)random_range(0, 3000);
    st->prev_L_swb_norm_fx = (Word16)random_range(0, 20);
    st->prev_frica_flag_fx = flip(2);
    RS(st->mem_imdct_fx, 3000);
    st->prev_td_energy_fx = (Word16)random_range(0, 3000);
    st->prev_weight_fx = (Word16)random_range(0, 20000);
    st->prev_fb_ener_adjust_fx = (Word16)random_range(0, 3000);
    st->prev_flag_fx = flip(2);
    RS32(st->mem_csfilt_fx);
    RS(st->mem_genSHBexc_filt_down_shb_fx, 3000);
    RS(st->mem_genSHBexc_filt_down_wb2_fx, 3000);
    RS(st->mem_genSHBexc_filt_down_wb3_fx, 3000);
    RS(st->state_lpc_syn_fx, 3000);
    RS(st->syn_overlap_fx, 3000);
    RS(st->state_syn_shbexc_fx, 3000);
    st->tbe_demph_fx = (Word16)random_range(-3000, 3000);
    st->tbe_premph_fx = (Word16)random_range(-3000, 3000);
    RS(st->mem_stp_swb_fx, 3000);
    RS(st->mem_zero_swb_fx, 3000);
    st->gain_prec_swb_fx = (Word16)random_range(0, 20000);
    RS(st->GainShape_Delay, 3000);
    RS32(st->genSHBsynth_Hilbert_Mem_fx);
    RS(st->genSHBsynth_state_lsyn_filt_shb_local_fx, 3000);
    RS(st->mem_resamp_HB_32k_fx, 3000);
    RS(st->int_3_over_2_tbemem_dec_fx, 3000);
    RS(st->interpol_3_2_cng_dec_fx, 3000);
    RS(st->fb_state_lpc_syn_fx, 3000);
    st->fb_tbe_demph_fx = (Word16)random_range(-3000, 3000);
    for (int i = 0; i < 4; i++) {
        RS32(st->fbbwe_hpf_mem_fx[i]);
        st->fbbwe_hpf_mem_fx_Q[i] = (Word16)random_range(0, 20);
    }
    st->prev_fbbwe_ratio_fx = (Word16)random_range(0, 32767);
    RS(st->state_lsyn_filt_shb_fx, 3000);
    RS(st->state_lsyn_filt_dwn_shb_fx, 3000);
    RS(st->state_32and48k_WB_upsample_fx, 3000);
    RS(st->mem_resamp_HB_fx, 3000);

    /* CLDFB filter states */
    {
        HANDLE_CLDFB_FILTER_BANK banks[3] = {st->cldfbAna_fx, st->cldfbBPF_fx, st->cldfbSyn_fx};
        for (int b = 0; b < 3; b++) {
            if (next_random() & 1) random_signal(banks[b]->FilterStates, rd_cldfb_states_length(banks[b]), 2000);
            for (int i = 0; i < CLDFB_NO_COL_MAX + 9; i++) banks[b]->FilterStates_e[i] = (Word16)random_range(0, 3);
            banks[b]->FilterStates_eg = (Word16)random_range(0, 3);
        }
    }
}

/* The FD-CNG as the decoder left it: configured for a bandwidth, rate and frame length, with
 * overlap buffers in use. The Rust side repeats the configuration (the ROM pointers it sets are
 * not in the loadable dump). */
static Word16 fd_cng_bandwidth, fd_cng_l_frame;
static Word32 fd_cng_brate;
static void fd_cng_randomise(Decoder_State_fx *st)
{
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    HANDLE_FD_CNG_COM com = hs->hFdCngCom;
    fd_cng_bandwidth = (Word16)((next_random() & 1) ? NB : WB);
    fd_cng_brate = any_rate();
    fd_cng_l_frame = (Word16)((next_random() & 1) ? L_FRAME : L_FRAME16k);
    configureFdCngDec(hs, fd_cng_bandwidth, fd_cng_brate, fd_cng_l_frame);
    com->CngBitrate = any_rate();
    random_signal(hs->olapBufferSynth2, FFTLEN, 2000);
    random_signal(com->olapBufferSynth, FFTLEN, (next_random() & 1) ? 20000 : 2000);
}

static void put_fd_cng(void)
{
    put1("fd_cng_bandwidth", fd_cng_bandwidth);
    put1("fd_cng_brate", fd_cng_brate);
    put1("fd_cng_l_frame", fd_cng_l_frame);
}

static void case_bandwidth_switching_detect(void)
{
    Decoder_State_fx *st = new_decoder(16000);
    st->bws_cnt_fx = (Word16)((next_random() % 3) ? random_range(0, N_WS2N_FRAMES + 1) : 0);
    st->bws_cnt1_fx = (Word16)((next_random() % 3) ? random_range(0, N_NS2W_FRAMES + 1) : 0);
    st->bwidth_fx = (Word16)random_range(NB, FB);
    st->last_bwidth_fx = (Word16)((next_random() % 3) ? random_range(NB, FB) : st->bwidth_fx);
    if (next_random() % 3 == 0) { st->last_bwidth_fx = WB; st->bwidth_fx = SWB; }
    if (next_random() % 3 == 0) { st->last_bwidth_fx = SWB; st->bwidth_fx = WB; }
    st->total_brate_fx = any_rate();
    st->last_core_brate_fx = any_rate();
    if (next_random() % 2) {
        /* around the 9.6 kbit/s threshold, equality included */
        static const Word32 near_threshold[] = {8850, 9600, 12650};
        st->total_brate_fx = near_threshold[next_random() % 3];
        st->last_core_brate_fx = near_threshold[next_random() % 3];
    }
    if (next_random() % 3 == 0) st->bws_cnt_fx = 0;
    if (next_random() % 3 == 0) st->bws_cnt1_fx = 0;
    char *before = capture_state(st);
    put_state_in(before);
    bandwidth_switching_detect_fx_reference(st);
    arrow();
    char *after = capture_state(st);
    put_changed(before, after);
    free(before); free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void case_bw_switching_pre_proc(void)
{
    static const Word32 out_rates[4] = {8000, 16000, 32000, 48000};
    Decoder_State_fx *st = new_decoder(out_rates[next_random() % 4]);
    Word16 old_syn[L_FRAME16k];
    switching_randomise(st, 1);
    st->L_frame_fx = (Word16)((next_random() & 1) ? L_FRAME : L_FRAME16k);
    st->core_fx = (Word16)(next_random() % 3 ? ACELP_CORE : HQ_CORE);
    st->last_bwidth_fx = (Word16)((next_random() % 4) ? random_range(NB, FB) : 0);
    random_signal(old_syn, L_FRAME16k, (next_random() & 1) ? 20000 : (next_random() & 1) ? 2000 : 80);
    /* silence now and then: a band energy of zero (Calc_freq_ener's early exit), whole or one band */
    if (next_random() % 6 == 0) memset(old_syn, 0, sizeof old_syn);
    if (next_random() % 6 == 0) memset(st->t_audio_q_fx, 0, sizeof st->t_audio_q_fx);
    if (next_random() % 6 == 0) memset(st->t_audio_q_fx, 0, sizeof(Word16) * (L_FRAME / 2));
    if (next_random() % 6 == 0) memset(st->t_audio_q_fx, 0, sizeof(Word16) * 32);
    put16("old_syn", old_syn, L_FRAME16k);
    char *before = capture_state(st);
    put_state_in(before);
    bw_switching_pre_proc_fx_reference(old_syn, st);
    arrow();
    char *after = capture_state(st);
    put_changed(before, after);
    free(before); free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void case_core_switching_pre_dec(void)
{
    static const Word32 out_rates[4] = {8000, 16000, 32000, 48000};
    Decoder_State_fx *st = new_decoder(out_rates[next_random() % 4]);
    switching_randomise(st, 1);
    if (st->core_fx == AMR_WB_CORE) { st->bwidth_fx = WB; st->L_frame_fx = L_FRAME; }
    if (next_random() % 3 == 0) st->last_L_frame_fx = st->L_frame_fx;
    if (next_random() % 4 == 0) st->last_bwidth_fx = st->bwidth_fx;
    if (next_random() % 4 == 0) {
        /* SID / no-data frames on both sides (the FD-CNG overlap buffers are resampled) */
        st->total_brate_fx = (next_random() & 1) ? 0 : 2400;
        st->last_total_brate_fx = (next_random() & 1) ? 0 : 2400;
    }
    fd_cng_randomise(st);
    /* the FD-CNG configured for the frame the call arrives in, now and then (the no-op path) */
    if (next_random() % 4 == 0) {
        fd_cng_l_frame = st->L_frame_fx;
        configureFdCngDec(st->hFdCngDec_fx, fd_cng_bandwidth, fd_cng_brate, fd_cng_l_frame);
        if (next_random() & 1) st->last_L_frame_fx = st->L_frame_fx;
        if (st->ini_frame_fx == 0) st->ini_frame_fx = 3;
        st->last_bwidth_fx = st->bwidth_fx;
    }
    put_fd_cng();
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    char *before = capture_state(st);
    put_state_in(before);
    core_switching_pre_dec_fx_reference(st, st->output_frame_fx);
    arrow();
    char *after = capture_state(st);
    put_changed(before, after);
    free(before); free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void case_core_switching_post_dec(void)
{
    static Word16 synth[SYNTH_LEN];
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 core_switching_flag, qsynth = (Word16)random_range(-3, 3);
    st->output_Fs_fx = out_rates[next_random() % 4];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    randomise(st, &core_switching_flag);
    Word16 cna_bandwidth = (Word16)(st->bwidth_fx == NB ? NB : WB);
    int lost = next_random() % 4 == 0;
    switching_randomise(st, 0);
    st->L_frame_fx = (Word16)((next_random() & 1) ? L_FRAME : L_FRAME16k);
    if (next_random() % 3 == 0) st->L_frame_fx = st->last_L_frame_fx;
    if (next_random() % 3 == 0) {
        /* a steady stream: only the codec mode can tell the TBE memories to reset */
        st->last_total_brate_fx = st->total_brate_fx;
        st->last_bwidth_fx = st->bwidth_fx;
        st->rf_flag_last = st->rf_flag;
        st->last_extl_fx = st->extl_fx;
        st->last_core_fx = ACELP_CORE;
    }
    st->core_fx = (Word16)(lost ? ACELP_CORE : (next_random() % 5 < 3) ? HQ_CORE : (next_random() % 4) ? ACELP_CORE : AMR_WB_CORE);
    if (lost) {
        conceal_randomise(st, 1);
        st->last_nelp_mode_dec_fx = 0;
        st->nelp_mode_dec_fx = 0;
        st->last_bwidth_fx = (next_random() % 4) ? st->bwidth_fx : (Word16)random_range(NB, SWB);
        RS(st->dct_post_old_exc_fx, 2000);
    }
    if (st->core_fx != HQ_CORE) core_switching_flag = 0;
    else core_switching_flag = (Word16)((st->last_core_fx == ACELP_CORE || st->last_core_fx == AMR_WB_CORE || st->last_core_fx == HQ_CORE) && next_random() % 4);
    /* a SID or no-data frame after an active one (Interp_3_2 CNG memory reset) */
    if (!lost && !core_switching_flag && next_random() % 4 == 0) {
        st->core_brate_fx = (next_random() & 1) ? 0 : 2400;
        if (next_random() & 1) st->last_core_brate_fx = 13200;
    }
    Word16 coder_type = (Word16)random_range(INACTIVE, AUDIO);
    for (int i = 0; i < SYNTH_LEN; i++) synth[i] = -3;
    random_signal(synth, st->output_frame_fx, (next_random() & 1) ? 20000 : (next_random() & 1) ? 2000 : 0);
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("cna_bandwidth", cna_bandwidth);
    put1("cna_brate", cna_brate);
    put1("cna_l_frame", cna_l_frame);
    put1("core_switching_flag", core_switching_flag);
    put1("coder_type", coder_type);
    put1("qsynth", qsynth);
    put16("synth", synth, SYNTH_LEN);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);
    core_switching_post_dec_fx_reference(st, synth, st->output_frame_fx, core_switching_flag, coder_type, &qsynth);
    arrow();
    put16("synth", synth, SYNTH_LEN);
    put1("qsynth", qsynth);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before); free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

/* -------- stream mode -------- */

static int stream_mode;
static long stream_every, stream_calls[4];

/* A call is recorded when it is the n-th of its function, or when the frame switches the core, the
 * bandwidth, the frame length, the codec mode or the extension layer from the last one and fewer than
 * three such calls with the same (function, switch) signature were recorded (the rare switching frames
 * are what the sequences are for; the repeats add volume only). */
static int stream_wanted(int which, const Decoder_State_fx *st)
{
    static long signatures[4][512];
    static int counts[4][512], used[4];
    int switching = st->core_fx != st->last_core_fx || st->bwidth_fx != st->last_bwidth_fx || st->L_frame_fx != st->last_L_frame_fx ||
                    st->codec_mode != st->last_codec_mode || st->extl_fx != st->last_extl_fx;
    int every = (stream_calls[which]++ % stream_every == 0);
    if (!switching) return every;
    long signature = ((((((long)st->core_fx * 8 + st->last_core_fx) * 8 + st->bwidth_fx) * 8 + st->last_bwidth_fx) * 4 + st->codec_mode) * 4 +
                      st->last_codec_mode) * 2 + (st->L_frame_fx != st->last_L_frame_fx);
    signature = signature * 16 + (st->extl_fx + 1) * 1 + 16 * 0;
    signature = signature * 16 + (st->last_extl_fx + 1);
    for (int i = 0; i < used[which]; i++)
        if (signatures[which][i] == signature) return every || counts[which][i]++ < 3;
    if (used[which] < 512) { signatures[which][used[which]] = signature; counts[which][used[which]++] = 1; }
    return 1;
}

void bandwidth_switching_detect_fx(Decoder_State_fx *st)
{
    if (!stream_mode) { bandwidth_switching_detect_fx_reference(st); return; }
    char *before = capture_state(st);
    int wanted = stream_wanted(0, st);
    bandwidth_switching_detect_fx_reference(st);
    if (wanted) {
        printf("which=0 output_fs=%d output_frame=%d", (int)st->output_Fs_fx, st->output_frame_fx);
        for (const char *p = before; *p;) {
            const char *e = strchr(p + 1, ' ');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            printf(" in.%.*s", (int)len - 1, p + 1);
            p += len;
        }
        arrow();
        char *after = capture_state(st);
        put_changed(before, after);
        free(after);
        end_line();
    }
    free(before);
}

void bw_switching_pre_proc_fx(const Word16 *old_syn_12k8_16k_fx, Decoder_State_fx *st)
{
    if (!stream_mode) { bw_switching_pre_proc_fx_reference(old_syn_12k8_16k_fx, st); return; }
    char *before = capture_state(st);
    int wanted = stream_wanted(1, st);
    bw_switching_pre_proc_fx_reference(old_syn_12k8_16k_fx, st);
    if (wanted) {
        printf("which=1 output_fs=%d output_frame=%d", (int)st->output_Fs_fx, st->output_frame_fx);
        put16("old_syn", old_syn_12k8_16k_fx, L_FRAME16k);
        for (const char *p = before; *p;) {
            const char *e = strchr(p + 1, ' ');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            printf(" in.%.*s", (int)len - 1, p + 1);
            p += len;
        }
        arrow();
        char *after = capture_state(st);
        put_changed(before, after);
        free(after);
        end_line();
    }
    free(before);
}

void core_switching_pre_dec_fx(Decoder_State_fx *st, const Word16 output_frame)
{
    if (!stream_mode) { core_switching_pre_dec_fx_reference(st, output_frame); return; }
    char *before = capture_state(st);
    int wanted = stream_wanted(2, st);
    core_switching_pre_dec_fx_reference(st, output_frame);
    if (wanted) {
        printf("which=2 output_fs=%d output_frame=%d", (int)st->output_Fs_fx, output_frame);
        for (const char *p = before; *p;) {
            const char *e = strchr(p + 1, ' ');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            printf(" in.%.*s", (int)len - 1, p + 1);
            p += len;
        }
        arrow();
        char *after = capture_state(st);
        put_changed(before, after);
        free(after);
        end_line();
    }
    free(before);
}

void core_switching_post_dec_fx(Decoder_State_fx *st, Word16 *synth, const Word16 output_frame, const Word16 core_switching_flag, const Word16 coder_type,
                                Word16 *Qsynth)
{
    if (!stream_mode) { core_switching_post_dec_fx_reference(st, synth, output_frame, core_switching_flag, coder_type, Qsynth); return; }
    static Word16 synth_in[SYNTH_LEN];
    memcpy(synth_in, synth, sizeof synth_in);
    Word16 qsynth_in = *Qsynth;
    char *before = capture_state(st);
    int wanted = stream_wanted(3, st) || core_switching_flag || (st->core_fx == ACELP_CORE && st->bfi_fx);
    core_switching_post_dec_fx_reference(st, synth, output_frame, core_switching_flag, coder_type, Qsynth);
    if (wanted) {
        printf("which=3 output_fs=%d output_frame=%d core_switching_flag=%d coder_type=%d qsynth=%d", (int)st->output_Fs_fx, output_frame,
               core_switching_flag, coder_type, qsynth_in);
        put16("synth", synth_in, SYNTH_LEN);
        put_u16("bits", st->bit_stream_fx, st->total_num_bits + 16);
        for (const char *p = before; *p;) {
            const char *e = strchr(p + 1, ' ');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            printf(" in.%.*s", (int)len - 1, p + 1);
            p += len;
        }
        arrow();
        put16("synth", synth, SYNTH_LEN);
        put1("qsynth", *Qsynth);
        char *after = capture_state(st);
        put_changed(before, after);
        free(after);
        end_line();
    }
    free(before);
}

/* The reference decoder's main loop (lib_dec/decoder.c) for a G.192 bitstream, MODE1 and MODE2. */
static void stream(const char *file, Word32 fs, long every)
{
    static UWord16 stream_bits[MAX_BITS_PER_FRAME + 16];
    static Word16 output[L_FRAME48k];
    FILE *f = fopen(file, "rb");
    if (f == NULL) { fprintf(stderr, "cannot open %s\n", file); exit(1); }
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->bit_stream_fx = stream_bits;
    st->Opt_AMR_WB_fx = 0;
    st->Opt_VOIP_fx = 0;
    st->bitstreamformat = G192;
    st->amrwb_rfc4867_flag = -1;
    st->output_Fs_fx = fs;
    read_indices_fx(st, f, 1);
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    reset_indices_dec_fx(st);
    init_decoder_fx(st);
    rd_record_cldfb(st);
    stream_mode = 1;
    stream_every = every;
    while (read_indices_fx(st, f, 0)) {
        if (st->codec_mode == MODE1) {
            if (st->Opt_AMR_WB_fx) amr_wb_dec_fx(output, st);
            else evs_dec_fx(st, output, FRAMEMODE_NORMAL);
        } else if (st->bfi_fx == 0) evs_dec_fx(st, output, FRAMEMODE_NORMAL);
        else evs_dec_fx(st, output, FRAMEMODE_MISSING);
        if (st->ini_frame_fx < MAX_FRAME_COUNTER) st->ini_frame_fx = add(st->ini_frame_fx, 1);
    }
    fprintf(stderr, "calls: detect %ld pre_proc %ld pre_dec %ld post_dec %ld\n", stream_calls[0], stream_calls[1], stream_calls[2], stream_calls[3]);
    fclose(f);
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    /* no core dumps: a crash must fail the Rust test (non-zero exit), not pop up a crash reporter */
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
    if (argc == 5 && !strcmp(argv[1], "stream")) { stream(argv[2], atol(argv[3]), atol(argv[4])); return 0; }
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED | stream FILE FS EVERY\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "bandwidth_switching_detect")) case_bandwidth_switching_detect();
        else if (!strcmp(argv[2], "bw_switching_pre_proc")) case_bw_switching_pre_proc();
        else if (!strcmp(argv[2], "core_switching_pre_dec")) case_core_switching_pre_dec();
        else if (!strcmp(argv[2], "core_switching_post_dec")) case_core_switching_post_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
