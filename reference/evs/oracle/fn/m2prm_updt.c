/* Oracle for lib_dec/updt_dec_fx.c: update_decoder_LPD_cng (which also runs FEC_clas_estim_fx and post_decoder),
 * on the whole decoder state. Domain: the CNG frame is synthesised at L_frame 256 (12.8 kHz) or 320 (16 kHz)
 * with old_synth_len = 2 * L_frame, an LP filter in the Q12 form a[0] = 4096, a valid (descending) LSP history,
 * synthesis scaling exponents -2..12. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "m2prm_common.h"

static void case_update_cng(void)
{
    static Word16 buffer[L_FRAME_MAX], noise[L_FRAME_MAX];
    Word16 a[M + 1];
    Decoder_State_fx *st = new_state();
    int l_frame = next_random() & 1 ? 256 : 320;
    Word16 coder_type = (Word16)random_range(0, 6);
    static const Word32 rates[] = {9600, 16400, 24400, 32000, 48000};
    st->L_frame_fx = (Word16)l_frame;
    st->nb_subfr = (Word16)(l_frame == 320 ? 5 : 4);
    st->old_synth_len = (Word16)(2 * l_frame);
    st->tcxonly = 0;
    st->bwidth_fx = (Word16)random_range(NB, FB);
    st->last_bwidth_fx = (Word16)(next_random() % 4 ? st->bwidth_fx : random_range(NB, FB));
    st->pfstat.on = (Word16)(next_random() & 1);
    st->narrowBand = (Word8)(next_random() % 4 == 0);
    st->BER_detect = 0;
    st->core_brate_fx = SID_2k40;
    st->total_brate_fx = rates[next_random() % 5];
    st->last_active_brate_fx = rates[next_random() % 5];
    st->last_core_brate_fx = next_random() % 3 ? SID_2k40 : rates[next_random() % 5];
    st->lp_noise = (Word32)random_range(0, 300) << 16;
    st->preemph_fac = (Word16)random_range(20000, 30000);
    st->Q_exc = (Word16)random_range(-2, 12);
    st->Q_syn = (Word16)random_range(-2, 12);
    st->prev_Q_syn = (Word16)random_range(-2, 12);
    random_lsp(st->lsp_old_fx);
    for (int i = 0; i < M; i++) {
        st->lsf_old_fx[i] = (Word16)random_range(0, 6400);
        st->lsfoldbfi0_fx[i] = (Word16)random_range(0, 6400);
        st->lsfoldbfi1_fx[i] = (Word16)random_range(0, 6400);
    }
    random_synthesis(st->old_synth, 2 * l_frame);
    random_synthesis(st->syn, M + 1);
    random_signal(st->old_exc_fx, L_EXC_MEM_DEC, random_range(100, 20000));
    random_synthesis(st->mem_syn_clas_estim_fx, L_SYN_MEM_CLAS_ESTIM);
    st->old_Es_pred_fx = (Word16)random_range(-300, 300);
    st->classifier_Q_mem_syn = (Word16)random_range(-2, 12);
    st->lp_ener_FER_fx = (Word16)random_range(0, 20000);
    random_lpc(st->old_Aq_12_8_fx);
    for (int i = 0; i < 5; i++) random_lpc(st->mem_Aq + i * (M + 1));
    random_synthesis(st->pst_old_syn_fx, NBPSF_PIT_MAX);
    random_signal(st->pfstat.mem_pf_in, 64, 12000);
    random_signal(st->pfstat.mem_stp, 64, 12000);
    random_signal(st->pfstat.mem_res2, 299, 12000);
    st->pfstat.gain_prec = (Word16)random_range(2000, 30000);
    st->lp_error_ener = (Word32)random_range(-(1 << 22), 1 << 22) * 16;
    st->mem_error = (Word32)random_range(-(1 << 24), 1 << 24);
    st->core_fx = (Word16)(next_random() & 1 ? ACELP_CORE : TCX_20_CORE);
    random_lpc(a);
    random_synthesis(buffer, l_frame);
    for (int i = 0; i < L_FRAME_MAX; i++) noise[i] = 0x5a5a;
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("coder_type", coder_type); put1("l_frame", l_frame);
    put16("a", a, M + 1); put16("buffer", buffer, l_frame);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    update_decoder_LPD_cng(st, coder_type, buffer, a, noise);
    put16("buffer", buffer, l_frame); put16("noise", noise, l_frame);
    finish(st, before);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "update_decoder_LPD_cng")) case_update_cng();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
