/* Function-level oracle for lib_dec/FEC_fx.c: FEC_exc_estim_fx, gain_dec_bfi_fx and the
 * file-local pulseRes_preCalc (the source is included to reach it).
 *
 * FEC_exc_estim_fx runs on a decoder built by init_decoder_fx with a randomised concealment state
 * (conceal_state.h), over one to three consecutive lost frames (the excitation shifted and the
 * loss counter advanced between them, as the decoder does); every frame's outputs are printed
 * (prefix "f<k>.") and the whole state after the sequence is compared (state_capture.h). */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "conceal_state.h"
#include "../../c-code/lib_dec/FEC_fx.c"

#define FEC_BWE_LEN (L_FRAME32k + 8)

static const Word32 fec_out_rates[4] = {8000, 16000, 32000, 48000};

static void case_fec_exc_estim(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 old_exc[L_EXC_DEC], lsf_new[M];
    char key[32];
    st->output_Fs_fx = fec_out_rates[next_random() % 4];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    conceal_randomise(st, 1);
    int frames = (next_random() % 3) ? 1 : random_range(2, 3);
    for (int i = 0; i < L_EXC_DEC; i++) old_exc[i] = i < L_EXC_MEM_DEC ? st->old_exc_fx[i] : -7;
    conceal_lsf(lsf_new, st->L_frame_fx == L_FRAME ? 16000 : 20000);

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("frames", frames);
    put16("lsf_new", lsf_new, M);
    put16("old_exc", old_exc, L_EXC_DEC);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    for (int f = 0; f < frames; f++) {
        Word16 exc2[L_FRAME16k], exc_dct_in[L_FRAME16k], pitch_buf[NB_SUBFR16k], voice_factors[NB_SUBFR16k];
        Word16 bwe_exc[FEC_BWE_LEN], tmp_tc = -1, tmp_noise = -1;
        for (int i = 0; i < L_FRAME16k; i++) { exc2[i] = -1; exc_dct_in[i] = -1; }
        for (int i = 0; i < NB_SUBFR16k; i++) { pitch_buf[i] = -1; voice_factors[i] = -1; }
        for (int i = 0; i < FEC_BWE_LEN; i++) bwe_exc[i] = -1;
        FEC_exc_estim_fx(st, st->L_frame_fx, old_exc + L_EXC_MEM_DEC, exc2, exc_dct_in, pitch_buf, voice_factors, &tmp_tc,
                         bwe_exc, lsf_new, &st->Q_exc, &tmp_noise);
        sprintf(key, "f%d.old_exc", f); put16(key, old_exc, L_EXC_DEC);
        sprintf(key, "f%d.exc2", f); put16(key, exc2, L_FRAME16k);
        sprintf(key, "f%d.exc_dct_in", f); put16(key, exc_dct_in, L_FRAME16k);
        sprintf(key, "f%d.pitch_buf", f); put16(key, pitch_buf, NB_SUBFR16k);
        sprintf(key, "f%d.voice_factors", f); put16(key, voice_factors, NB_SUBFR16k);
        sprintf(key, "f%d.tmp_tc", f); put1(key, tmp_tc);
        sprintf(key, "f%d.bwe_exc", f); put16(key, bwe_exc, FEC_BWE_LEN);
        sprintf(key, "f%d.tmp_noise", f); put1(key, tmp_noise);
        if (f + 1 < frames) {
            memmove(old_exc, old_exc + st->L_frame_fx, L_EXC_MEM_DEC * sizeof(Word16));
            st->nbLostCmpt++;
        }
    }
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void case_pulse_res_pre_calc(void)
{
    Word16 cond1 = -1, cond2 = -1;
    Word32 cond3 = -1;
    Word16 l_frame = (Word16)((next_random() & 1) ? L_FRAME : L_FRAME16k);
    Word16 tc = (Word16)random_range(17, l_frame == L_FRAME ? PIT_MAX + 1 : PIT16k_MAX + 1);
    int mode = next_random() % 4;
    /* the extrapolated pitch: failed (0), near tc (the resynchronised case), anywhere, or edge */
    Word16 new_pit = mode == 0 ? 0 : mode == 1 ? (Word16)(tc + random_range(-tc / 5, tc / 5))
                   : mode == 2 ? (Word16)random_range(17, 300) : random16();
    if (next_random() % 16 == 0) tc = (Word16)random_range(1, 32767);
    put1("new_pit", new_pit); put1("tc", tc); put1("l_frame", l_frame);
    pulseRes_preCalc(&cond1, &cond2, &cond3, new_pit, tc, l_frame);
    arrow(); put1("cond1", cond1); put1("cond2", cond2); put1("cond3", cond3); end_line();
}

static void case_gain_dec_bfi(void)
{
    Word16 past_qua_en[GAIN_PRED_ORDER];
    int mode = next_random() % 3;
    for (int i = 0; i < GAIN_PRED_ORDER; i++)
        past_qua_en[i] = mode == 0 ? (Word16)random_range(-14 * 1024, 4 * 1024) : mode == 1 ? (Word16)random_range(-14336, -10000) : random16();
    put16("past_qua_en", past_qua_en, GAIN_PRED_ORDER);
    gain_dec_bfi_fx(past_qua_en);
    arrow(); put16("past_qua_en", past_qua_en, GAIN_PRED_ORDER); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "pulse_res_pre_calc")) case_pulse_res_pre_calc();
        else if (!strcmp(argv[2], "fec_exc_estim")) case_fec_exc_estim();
        else if (!strcmp(argv[2], "gain_dec_bfi")) case_gain_dec_bfi();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
