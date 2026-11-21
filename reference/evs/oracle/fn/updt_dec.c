/* Function-level oracle for lib_dec/updt_dec_fx.c (updt_dec_fx, updt_bw_switching_fx,
 * updt_dec_common_fx). Each case fills the state fields the function reads with random values in
 * their ranges and prints every field it writes. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static int pick(const int *values, int n) { return values[next_random() % n]; }

static void case_updt_dec(void)
{
    static const int coder_types[] = {INACTIVE, UNVOICED, VOICED, GENERIC, TRANSITION, AUDIO};
    static const int brates[] = {ACELP_7k20, ACELP_8k00, ACELP_13k20, ACELP_24k40, ACELP_32k, SID_1k75,
                                 FRAME_NO_DATA, ACELP_12k65};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 L_frame = next_random() & 1 ? L_FRAME : L_FRAME16k;
    Word16 coder_type = (Word16)pick(coder_types, 6);
    Word16 old_exc[L_FRAME16k + L_EXC_MEM_DEC], pitch_buf[NB_SUBFR16k], Aq[NB_SUBFR16k * (M + 1)];
    Word16 lsf_new[M], lsp_new[M], voice_factors[NB_SUBFR16k], old_bwe_exc[L_FRAME32k + PIT16k_MAX * 2];
    Word16 gain_buf[NB_SUBFR16k], Es_pred = random16();
    random_signal(old_exc, L_frame + L_EXC_MEM_DEC, 20000);
    for (int i = 0; i < NB_SUBFR16k; i++) {
        pitch_buf[i] = (Word16)random_range(34 * 64, 289 * 64);
        voice_factors[i] = random16();
        gain_buf[i] = (Word16)random_range(0, 19661);
    }
    random_signal(Aq, NB_SUBFR16k * (M + 1), 8000);
    random_signal(lsf_new, M, 16000);
    random_signal(lsp_new, M, 32767);
    random_signal(old_bwe_exc, L_FRAME32k + PIT16k_MAX * 2, 20000);

    st->Opt_AMR_WB_fx = (Word16)(next_random() % 4 == 0);
    st->L_frame_fx = next_random() % 8 ? L_frame : (L_frame == L_FRAME ? L_FRAME16k : L_FRAME);
    st->bpf_off_fx = (Word16)random_range(0, 1);
    st->Last_GSC_noisy_speech_flag_fx = (Word16)random_range(0, 1);
    st->Last_GSC_pit_band_idx_fx = (Word16)random_range(0, 3);
    st->total_brate_fx = pick(brates, 8);
    st->core_brate_fx = pick(brates, 8);
    st->seed_tcx_fx = random16();
    st->GSC_noisy_speech_fx = (Word16)random_range(0, 1);
    st->upd_cnt_fx = (Word16)random_range(0, MAX_UPD_CNT);
    for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++) st->old_pitch_buf_fx[i] = random32();
    for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++) st->mem_pitch_gain[i] = random16();
    random_signal(st->lsfoldbfi0_fx, M, 16000);
    random_signal(st->lsfoldbfi1_fx, M, 16000);
    st->last_core_fx = (Word16)random_range(ACELP_CORE, HQ_CORE);
    st->HqVoicing_fx = (Word16)random_range(0, 1);
    st->last_ppp_mode_dec_fx = (Word16)random_range(0, 1);
    st->ppp_mode_dec_fx = (Word16)random_range(0, 1);
    st->nelp_mode_dec_fx = (Word16)random_range(0, 1);
    st->vbr_hw_BWE_disable_dec_fx = (Word16)random_range(0, 1);
    st->last_voice_factor_fx = random16();
    st->noise_lev_fx = random16();
    for (int i = 0; i < MBANDS_GN; i++) st->old_y_gain_fx[i] = random16();
    for (int i = 0; i < L_FRAME; i++) st->Last_GSC_spectrum_fx[i] = random16();
    st->last_coder_type_fx = random16();

    put1("L_frame", L_frame); put1("coder_type", coder_type); put16("old_exc", old_exc, L_frame + L_EXC_MEM_DEC);
    put16("pitch_buf", pitch_buf, NB_SUBFR16k); put1("Es_pred", Es_pred); put16("Aq", Aq, NB_SUBFR16k * (M + 1));
    put16("lsf_new", lsf_new, M); put16("lsp_new", lsp_new, M); put16("voice_factors", voice_factors, NB_SUBFR16k);
    put16("old_bwe_exc", old_bwe_exc, L_FRAME32k + PIT16k_MAX * 2); put16("gain_buf", gain_buf, NB_SUBFR16k);
    put1("opt_amr_wb", st->Opt_AMR_WB_fx); put1("st_l_frame", st->L_frame_fx); put1("bpf_off", st->bpf_off_fx);
    put1("last_gsc_noisy", st->Last_GSC_noisy_speech_flag_fx); put1("last_gsc_pit", st->Last_GSC_pit_band_idx_fx);
    put1("total_brate", st->total_brate_fx); put1("core_brate", st->core_brate_fx); put1("seed_tcx", st->seed_tcx_fx);
    put1("gsc_noisy", st->GSC_noisy_speech_fx); put1("upd_cnt", st->upd_cnt_fx);
    put32("old_pitch_buf", st->old_pitch_buf_fx, 2 * NB_SUBFR16k + 2);
    put16("mem_pitch_gain", st->mem_pitch_gain, 2 * NB_SUBFR16k + 2); put16("lsfoldbfi0", st->lsfoldbfi0_fx, M);
    put16("lsfoldbfi1", st->lsfoldbfi1_fx, M); put1("last_core", st->last_core_fx); put1("hq_voicing", st->HqVoicing_fx);
    put1("last_ppp", st->last_ppp_mode_dec_fx); put1("ppp", st->ppp_mode_dec_fx); put1("nelp", st->nelp_mode_dec_fx);
    put1("vbr_hw", st->vbr_hw_BWE_disable_dec_fx); put1("last_voice_factor", st->last_voice_factor_fx);
    put1("noise_lev", st->noise_lev_fx); put16("old_y_gain", st->old_y_gain_fx, MBANDS_GN);
    put16("last_gsc_spectrum", st->Last_GSC_spectrum_fx, L_FRAME); put1("last_coder_type", st->last_coder_type_fx);

    updt_dec_fx(st, L_frame, coder_type, old_exc, pitch_buf, Es_pred, Aq, lsf_new, lsp_new, voice_factors, old_bwe_exc,
                gain_buf);

    arrow();
    put16("old_exc", st->old_exc_fx, L_EXC_MEM_DEC); put16("old_bwe_exc", st->old_bwe_exc_fx, PIT16k_MAX * 2);
    put16("lsf_old", st->lsf_old_fx, M); put16("lsp_old", st->lsp_old_fx, M);
    put1("last_coder_type", st->last_coder_type_fx); put1("last_gsc_pit", st->Last_GSC_pit_band_idx_fx);
    put1("last_voice_factor", st->last_voice_factor_fx); put1("noise_lev", st->noise_lev_fx);
    put16("old_y_gain", st->old_y_gain_fx, MBANDS_GN); put16("last_gsc_spectrum", st->Last_GSC_spectrum_fx, L_FRAME);
    put1("last_gsc_noisy", st->Last_GSC_noisy_speech_flag_fx); put1("upd_cnt", st->upd_cnt_fx);
    put32("old_pitch_buf", st->old_pitch_buf_fx, 2 * NB_SUBFR16k + 2);
    put16("mem_pitch_gain", st->mem_pitch_gain, 2 * NB_SUBFR16k + 2); put16("lsfoldbfi0", st->lsfoldbfi0_fx, M);
    put16("lsfoldbfi1", st->lsfoldbfi1_fx, M); put1("hq_voicing", st->HqVoicing_fx);
    put1("old_ppp", st->old_ppp_mode_fx); put1("last_ppp", st->last_ppp_mode_dec_fx);
    put1("last_nelp", st->last_nelp_mode_dec_fx); put1("last_vbr_hw", st->last_vbr_hw_BWE_disable_dec_fx);
    put16("old_aq", st->old_Aq_12_8_fx, M + 1); put1("old_es_pred", st->old_Es_pred_fx);
    end_line();
    free(st);
}

static void case_updt_bw_switching(void)
{
    static const int rates[] = {8000, 16000, 32000, 32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 synth[L_FRAME48k], qpost = (Word16)random_range(-2, 4);
    random_signal(synth, L_FRAME48k, next_random() & 1 ? 32767 : random_range(1, 4000));
    st->output_Fs_fx = pick(rates, 5);
    st->bwidth_fx = (Word16)random_range(NB, FB);
    st->enerLH_fx = random32(); st->enerLL_fx = random32();
    st->core_fx = (Word16)(next_random() & 1 ? ACELP_CORE : HQ_CORE);
    st->bws_cnt_fx = (Word16)(next_random() & 1 ? 0 : random_range(0, 50));
    st->prev_mode_fx = (Word16)random_range(0, 4);
    st->last_inner_frame_fx = (Word16)(next_random() & 1 ? L_FRAME16k : random_range(L_FRAME8k, L_FRAME48k));
    st->core_brate_fx = next_random() & 1 ? HQ_16k40 : random_range(5000, 64000);
    st->prev_hqswb_clas_fx = (Word16)random_range(0, 4);
    st->prev_weight1_fx = random16();
    st->tilt_swb_fx = random16();
    put16("synth", synth, L_FRAME32k); put1("qpost", qpost); put1("output_fs", st->output_Fs_fx);
    put1("bwidth", st->bwidth_fx); put1("ener_lh", st->enerLH_fx); put1("ener_ll", st->enerLL_fx);
    put1("core", st->core_fx); put1("bws_cnt", st->bws_cnt_fx); put1("prev_mode", st->prev_mode_fx);
    put1("last_inner_frame", st->last_inner_frame_fx); put1("core_brate", st->core_brate_fx);
    put1("prev_hqswb_clas", st->prev_hqswb_clas_fx); put1("prev_weight1", st->prev_weight1_fx);
    put1("tilt_swb", st->tilt_swb_fx);
    updt_bw_switching_fx(st, synth, qpost);
    arrow(); put1("tilt_swb", st->tilt_swb_fx); put1("prev_ener_lh", st->prev_enerLH_fx);
    put1("prev_ener_ll", st->prev_enerLL_fx); put1("last_bwidth", st->last_bwidth_fx);
    put1("last_inner_frame", st->last_inner_frame_fx); put1("prev_weight1", st->prev_weight1_fx); end_line();
    free(st);
}

static void case_updt_dec_common(void)
{
    static const int rates[] = {8000, 16000, 32000, 48000};
    static const int brates[] = {FRAME_NO_DATA, SID_2k40, SID_1k75, ACELP_7k20, ACELP_8k00, ACELP_13k20, ACELP_32k};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 synth[L_FRAME48k], hq_core_type = (Word16)random_range(0, 1);
    random_signal(synth, L_FRAME48k, 32767);
    st->codec_mode = (Word16)random_range(MODE1, MODE2);
    st->extl_fx = (Word16)random_range(-1, 10);
    st->L_frame_fx = next_random() & 1 ? L_FRAME : L_FRAME16k;
    st->prev_bfi_fx = (Word16)random_range(0, 1);
    st->bfi_fx = (Word16)random_range(0, 1);
    st->nbLostCmpt = (Word16)random_range(0, 5);
    st->con_tcx = (Word16)random_range(0, 1);
    st->last_core_fx = (Word16)random_range(0, 3);
    st->rf_frame_type = (Word16)random_range(0, 7);
    st->use_partial_copy = (Word16)random_range(0, 1);
    st->last_good_fx = (Word16)random_range(0, 6);
    st->clas_dec = (Word16)random_range(0, 6);
    st->m_frame_type = next_random() % 3 ? ACTIVE_FRAME : (next_random() & 1 ? SID_FRAME : ZERO_FRAME);
    st->rf_flag = (Word16)random_range(0, 1);
    st->rf_flag_last = (Word16)random_range(0, 1);
    st->core_brate_fx = pick(brates, 7);
    st->total_brate_fx = pick(brates, 7);
    st->last_is_cng = (Word8)random_range(0, 1);
    st->core_fx = (Word16)random_range(0, 3);
    st->output_Fs_fx = pick(rates, 4);
    st->Q_old_postdec = (Word16)random_range(-3, 3);
    st->cng_type_fx = (Word16)random_range(LP_CNG, FD_CNG);
    st->tcxonly = (Word8)random_range(0, 1);
    st->sr_core = next_random() & 1 ? 12800 : 16000;
    st->last_active_brate_fx = random32();
    st->last_core_bfi = random16();
    random_signal(st->mem_MA_fx, M, 2000);
    random_signal(st->mem_AR_fx, M, 2000);
    put16("synth", synth, L_FRAME48k); put1("hq_core_type", hq_core_type); put1("codec_mode", st->codec_mode);
    put1("extl", st->extl_fx); put1("l_frame", st->L_frame_fx); put1("prev_bfi", st->prev_bfi_fx); put1("bfi", st->bfi_fx);
    put1("nb_lost_cmpt", st->nbLostCmpt); put1("con_tcx", st->con_tcx); put1("last_core", st->last_core_fx);
    put1("rf_frame_type", st->rf_frame_type); put1("use_partial_copy", st->use_partial_copy);
    put1("last_good", st->last_good_fx); put1("clas_dec", st->clas_dec); put1("m_frame_type", st->m_frame_type);
    put1("rf_flag", st->rf_flag); put1("rf_flag_last", st->rf_flag_last); put1("core_brate", st->core_brate_fx);
    put1("total_brate", st->total_brate_fx); put1("last_is_cng", st->last_is_cng); put1("core", st->core_fx);
    put1("output_fs", st->output_Fs_fx); put1("q_old_postdec", st->Q_old_postdec); put1("cng_type", st->cng_type_fx);
    put1("tcxonly", st->tcxonly); put1("sr_core", st->sr_core); put1("last_active_brate", st->last_active_brate_fx);
    put1("last_core_bfi", st->last_core_bfi); put16("mem_ma", st->mem_MA_fx, M); put16("mem_ar", st->mem_AR_fx, M);
    updt_dec_common_fx(st, hq_core_type, synth);
    arrow(); put1("last_codec_mode", st->last_codec_mode); put1("last_extl", st->last_extl_fx);
    put1("last_l_frame", st->last_L_frame_fx); put1("prev_old_bfi", st->prev_old_bfi_fx); put1("prev_bfi", st->prev_bfi_fx);
    put1("old_bfi_cnt", st->old_bfi_cnt_fx); put1("last_con_tcx", st->last_con_tcx); put1("con_tcx", st->con_tcx);
    put1("prev_last_core", st->prev_last_core_fx); put1("tcx_conceal_recalc_exc", st->tcxConceal_recalc_exc);
    put1("last_good", st->last_good_fx); put1("prev_rf_frame_type", st->prev_rf_frame_type);
    put1("rf_flag_last", st->rf_flag_last); put1("last_active_brate", st->last_active_brate_fx);
    put1("last_core", st->last_core_fx); put1("last_hq_core_type", st->last_hq_core_type_fx);
    put1("last_is_cng", st->last_is_cng); put1("last_core_bfi", st->last_core_bfi);
    put1("last_core_brate", st->last_core_brate_fx); put16("old_synth_sw", st->old_synth_sw_fx, NS2SA(48000, FRAME_SIZE_NS - ACELP_LOOK_NS - DELAY_BWE_TOTAL_NS));
    put16("mem_ma", st->mem_MA_fx, M); put16("mem_ar", st->mem_AR_fx, M); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "updt_dec")) case_updt_dec();
        else if (!strcmp(argv[2], "updt_bw_switching")) case_updt_bw_switching();
        else if (!strcmp(argv[2], "updt_dec_common")) case_updt_dec_common();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
