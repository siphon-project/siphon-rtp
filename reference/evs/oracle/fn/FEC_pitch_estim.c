/* Function-level oracle for lib_dec/FEC_pitch_estim_fx.c. */
#include "harness.h"
#include "prot_fx.h"

static void case_fec_pitch_estim(void)
{
    Word16 pitch_buf[NB_SUBFR16k];
    Word32 old_pitch_buf[2 * NB_SUBFR16k + 2];
    Word16 opt_amr_wb = (Word16)(next_random() % 4 == 0), last_core = (Word16)random_range(0, 3);
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 clas = (Word16)random_range(0, 6), last_good = (Word16)random_range(0, 6), coder_type = (Word16)random_range(0, 5);
    Word16 bfi_pitch = (Word16)random_range(0, 18000), bfi_pitch_frame = (Word16)random_range(0, 320), upd_cnt = (Word16)random_range(0, 10);
    /* A stable pitch half the time, so the update branch is reached. */
    Word16 base = (Word16)random_range(34 * 64, 231 * 64);
    for (int i = 0; i < NB_SUBFR16k; i++) pitch_buf[i] = (Word16)(next_random() & 1 ? base + random_range(-300, 300) : random_range(17 * 64, 289 * 64));
    for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++) old_pitch_buf[i] = next_random() & 1 ? ((Word32)base << 10) + random_range(-200000, 200000) : (Word32)random_range(17, 289) << 16;
    put1("opt_amr_wb", opt_amr_wb); put1("last_core", last_core); put1("l_frame", l_frame); put1("clas", clas);
    put1("last_good", last_good); put16("pitch_buf", pitch_buf, NB_SUBFR16k); put32("old_pitch_buf", old_pitch_buf, 2 * NB_SUBFR16k + 2);
    put1("bfi_pitch", bfi_pitch); put1("bfi_pitch_frame", bfi_pitch_frame); put1("upd_cnt", upd_cnt); put1("coder_type", coder_type);
    FEC_pitch_estim_fx(opt_amr_wb, last_core, l_frame, clas, last_good, pitch_buf, old_pitch_buf, &bfi_pitch, &bfi_pitch_frame, &upd_cnt, coder_type);
    arrow(); put1("bfi_pitch", bfi_pitch); put1("bfi_pitch_frame", bfi_pitch_frame); put1("upd_cnt", upd_cnt); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "fec_pitch_estim")) case_fec_pitch_estim();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
