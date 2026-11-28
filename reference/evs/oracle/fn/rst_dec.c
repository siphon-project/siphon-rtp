/* Function-level oracle for lib_dec/rst_dec_fx.c: CNG_reset_dec_fx at both internal rates. */
#include "harness.h"
#include "prot_fx.h"

static void case_cng_reset_dec(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->L_frame_fx = (Word16)(next_random() % 2 ? L_FRAME : L_FRAME16k);
    st->lp_ener_fx = next_random() % 5 ? (Word32)(next_random() >> random_range(1, 31)) : 0;
    for (int i = 0; i < M; i++) st->mem_MA_fx[i] = 5;
    put1("l_frame", st->L_frame_fx); put1("lp_ener", st->lp_ener_fx);
    Word16 pitch_buf[NB_SUBFR16k], voice_factors[NB_SUBFR16k];
    for (int i = 0; i < NB_SUBFR16k; i++) { pitch_buf[i] = -7; voice_factors[i] = -7; }
    st->clas_dec = 3; st->last_good_fx = 3; st->bpf_off_fx = 0; st->act_cnt2_fx = 4; st->tilt_code_fx = 9; st->lp_gainp_fx = 9;
    CNG_reset_dec_fx(st, pitch_buf, voice_factors);
    Word16 s[] = {st->lp_gainc_fx, st->lp_gainp_fx, st->tilt_code_fx, st->clas_dec, st->last_good_fx, st->bpf_off_fx, st->act_cnt2_fx};
    arrow(); put16("pitch_buf", pitch_buf, NB_SUBFR16k); put16("voice_factors", voice_factors, NB_SUBFR16k); put16("st", s, 7);
    put16("mem_ar", st->mem_AR_fx, M); put16("mem_ma", st->mem_MA_fx, M);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "cng_reset_dec")) case_cng_reset_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
