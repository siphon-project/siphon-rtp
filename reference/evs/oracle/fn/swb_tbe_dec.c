/* Function-level oracle for lib_dec/swb_tbe_dec_fx.c (buffer initialisation and reset). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 extls[] = {0, WB_TBE, SWB_TBE, FB_TBE, WB_BWE, SWB_BWE};

static void randomise(Decoder_State_fx *st)
{
    { Word32 *p = (Word32 *)st->mem_csfilt_fx; for (int i = 0; i < 2; i++) p[i] = random32(); }
    { Word16 *p = (Word16 *)st->state_syn_shbexc_fx; for (int i = 0; i < 20; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->state_lpc_syn_fx; for (int i = 0; i < 10; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->fb_state_lpc_syn_fx; for (int i = 0; i < 10; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->fb_tbe_demph_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word32 *p = (Word32 *)&st->fbbwe_hpf_mem_fx[0][0]; for (int i = 0; i < 16; i++) p[i] = random32(); }
    { Word16 *p = (Word16 *)st->fbbwe_hpf_mem_fx_Q; for (int i = 0; i < 4; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->prev_fbbwe_ratio_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->mem_genSHBexc_filt_down_shb_fx; for (int i = 0; i < 7; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->mem_genSHBexc_filt_down_wb2_fx; for (int i = 0; i < 7; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->mem_genSHBexc_filt_down_wb3_fx; for (int i = 0; i < 7; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->state_lsyn_filt_shb_fx; for (int i = 0; i < 6; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->state_lsyn_filt_dwn_shb_fx; for (int i = 0; i < 6; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->state_32and48k_WB_upsample_fx; for (int i = 0; i < 6; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->syn_overlap_fx; for (int i = 0; i < 20; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->lsp_prevfrm_fx; for (int i = 0; i < 10; i++) p[i] = random16(); }
    { Word32 *p = (Word32 *)&st->GainFrame_prevfrm_fx; for (int i = 0; i < 1; i++) p[i] = random32(); }
    { Word16 *p = (Word16 *)&st->GainAttn_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->tbe_demph_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->tbe_premph_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->mem_stp_swb_fx; for (int i = 0; i < 10; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->gain_prec_swb_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->GainShape_Delay; for (int i = 0; i < 8; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->old_core_synth_fx; for (int i = 0; i < 320; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->old_tbe_synth_fx; for (int i = 0; i < 222; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->tilt_swb_fec_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->old_bwe_exc_fx; for (int i = 0; i < 578; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->bwe_seed_fx; for (int i = 0; i < 2; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->old_bwe_exc_extended_fx; for (int i = 0; i < 12; i++) p[i] = random16(); }
    { Word32 *p = (Word32 *)&st->bwe_non_lin_prev_scale_fx; for (int i = 0; i < 1; i++) p[i] = random32(); }
    { Word16 *p = (Word16 *)&st->last_voice_factor_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word32 *p = (Word32 *)st->genSHBsynth_Hilbert_Mem_fx; for (int i = 0; i < 21; i++) p[i] = random32(); }
    { Word16 *p = (Word16 *)st->genSHBsynth_state_lsyn_filt_shb_local_fx; for (int i = 0; i < 6; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->syn_dm_phase_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word32 *p = (Word32 *)&st->prev_wb_bwe_frame_pow_fx; for (int i = 0; i < 1; i++) p[i] = random32(); }
    { Word32 *p = (Word32 *)&st->prev_swb_bwe_frame_pow_fx; for (int i = 0; i < 1; i++) p[i] = random32(); }
    { Word16 *p = (Word16 *)&st->prev_fb_ener_adjust_fx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)st->prev_lpc_wb_fx; for (int i = 0; i < 6; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->prev_Q_bwe_exc; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->prev_ener_fx_Q; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->prev_Qx; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->prev_frame_pow_exp; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->prev_Q_bwe_syn; for (int i = 0; i < 1; i++) p[i] = random16(); }
    { Word16 *p = (Word16 *)&st->prev_Q_bwe_syn2; for (int i = 0; i < 1; i++) p[i] = random16(); }
}

static void print(Decoder_State_fx *st)
{
    put32("mem_csfilt", (Word32 *)st->mem_csfilt_fx, 2);
    put16("state_syn_shbexc", (Word16 *)st->state_syn_shbexc_fx, 20);
    put16("state_lpc_syn", (Word16 *)st->state_lpc_syn_fx, 10);
    put16("fb_state_lpc_syn", (Word16 *)st->fb_state_lpc_syn_fx, 10);
    put16("fb_tbe_demph", (Word16 *)&st->fb_tbe_demph_fx, 1);
    put32("fbbwe_hpf_mem", (Word32 *)&st->fbbwe_hpf_mem_fx[0][0], 16);
    put16("fbbwe_hpf_mem_fx_q", (Word16 *)st->fbbwe_hpf_mem_fx_Q, 4);
    put16("prev_fbbwe_ratio", (Word16 *)&st->prev_fbbwe_ratio_fx, 1);
    put16("mem_gen_sh_bexc_filt_down_shb", (Word16 *)st->mem_genSHBexc_filt_down_shb_fx, 7);
    put16("mem_gen_sh_bexc_filt_down_wb2", (Word16 *)st->mem_genSHBexc_filt_down_wb2_fx, 7);
    put16("mem_gen_sh_bexc_filt_down_wb3", (Word16 *)st->mem_genSHBexc_filt_down_wb3_fx, 7);
    put16("state_lsyn_filt_shb", (Word16 *)st->state_lsyn_filt_shb_fx, 6);
    put16("state_lsyn_filt_dwn_shb", (Word16 *)st->state_lsyn_filt_dwn_shb_fx, 6);
    put16("state_32and48k_wb_upsample", (Word16 *)st->state_32and48k_WB_upsample_fx, 6);
    put16("syn_overlap", (Word16 *)st->syn_overlap_fx, 20);
    put16("lsp_prevfrm", (Word16 *)st->lsp_prevfrm_fx, 10);
    put32("gain_frame_prevfrm", (Word32 *)&st->GainFrame_prevfrm_fx, 1);
    put16("gain_attn", (Word16 *)&st->GainAttn_fx, 1);
    put16("tbe_demph", (Word16 *)&st->tbe_demph_fx, 1);
    put16("tbe_premph", (Word16 *)&st->tbe_premph_fx, 1);
    put16("mem_stp_swb", (Word16 *)st->mem_stp_swb_fx, 10);
    put16("gain_prec_swb", (Word16 *)&st->gain_prec_swb_fx, 1);
    put16("gain_shape_delay", (Word16 *)st->GainShape_Delay, 8);
    put16("old_core_synth", (Word16 *)st->old_core_synth_fx, 320);
    put16("old_tbe_synth", (Word16 *)st->old_tbe_synth_fx, 222);
    put16("tilt_swb_fec", (Word16 *)&st->tilt_swb_fec_fx, 1);
    put16("old_bwe_exc", (Word16 *)st->old_bwe_exc_fx, 578);
    put16("bwe_seed", (Word16 *)st->bwe_seed_fx, 2);
    put16("old_bwe_exc_extended", (Word16 *)st->old_bwe_exc_extended_fx, 12);
    put32("bwe_non_lin_prev_scale", (Word32 *)&st->bwe_non_lin_prev_scale_fx, 1);
    put16("last_voice_factor", (Word16 *)&st->last_voice_factor_fx, 1);
    put32("gen_sh_bsynth_hilbert_mem", (Word32 *)st->genSHBsynth_Hilbert_Mem_fx, 21);
    put16("gen_sh_bsynth_state_lsyn_filt_shb_local", (Word16 *)st->genSHBsynth_state_lsyn_filt_shb_local_fx, 6);
    put16("syn_dm_phase", (Word16 *)&st->syn_dm_phase_fx, 1);
    put32("prev_wb_bwe_frame_pow", (Word32 *)&st->prev_wb_bwe_frame_pow_fx, 1);
    put32("prev_swb_bwe_frame_pow", (Word32 *)&st->prev_swb_bwe_frame_pow_fx, 1);
    put16("prev_fb_ener_adjust", (Word16 *)&st->prev_fb_ener_adjust_fx, 1);
    put16("prev_lpc_wb", (Word16 *)st->prev_lpc_wb_fx, 6);
    put16("prev_q_bwe_exc", (Word16 *)&st->prev_Q_bwe_exc, 1);
    put16("prev_ener_fx_q", (Word16 *)&st->prev_ener_fx_Q, 1);
    put16("prev_qx", (Word16 *)&st->prev_Qx, 1);
    put16("prev_frame_pow_exp", (Word16 *)&st->prev_frame_pow_exp, 1);
    put16("prev_q_bwe_syn", (Word16 *)&st->prev_Q_bwe_syn, 1);
    put16("prev_q_bwe_syn2", (Word16 *)&st->prev_Q_bwe_syn2, 1);
}

static void run(int reset)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    randomise(st);
    st->extl_fx = extls[next_random() % 6];
    put1("extl", st->extl_fx);
    print(st);
    if (reset) ResetSHBbuffer_Dec_fx(st); else InitSWBdecBuffer_fx(st);
    arrow(); print(st); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "init")) run(0);
        else if (!strcmp(argv[2], "reset")) run(1);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
