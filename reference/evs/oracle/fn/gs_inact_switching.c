/* Function-level oracle for lib_com/gs_inact_switching_fx.c (Inac_swtch_ematch_fx). */
#include "harness.h"
#include "prot_fx.h"

static void case_inac_swtch_ematch(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000};
    Word16 exc2[L_FRAME16k], dct[L_FRAME16k], lt[MBANDS_GN];
    /* Mostly INACTIVE after an ACELP MODE1 frame (the smoothing branch), every other branch too. */
    Word16 coder_type = (Word16)(next_random() % 2 ? INACTIVE : random_range(0, 5));
    Word16 l_frame = (Word16)(next_random() % 4 ? L_FRAME : L_FRAME16k);
    Word32 core_brate = rates[next_random() % 7];
    Word16 q_exc = (Word16)random_range(-1, 12);
    Word16 bfi = (Word16)(next_random() % 5 == 0);
    Word16 last_core = (Word16)(next_random() % 6 ? ACELP_CORE : random_range(0, 2));
    Word16 last_codec_mode = (Word16)(next_random() % 6 ? MODE1 : MODE2);
    int mag = 1 << random_range(4, 15);
    if (mag > 32767) mag = 32767;
    random_signal(exc2, L_FRAME16k, mag);
    random_signal(dct, L_FRAME16k, mag);
    if (next_random() % 10 == 0) for (int i = 0; i < L_FRAME16k; i++) exc2[i] = random16();
    if (next_random() % 20 == 0) for (int i = 0; i < L_FRAME16k; i++) exc2[i] = 0;
    for (int i = 0; i < MBANDS_GN; i++) lt[i] = (Word16)random_range(-8000, 20000);
    put1("coder_type", coder_type); put1("l_frame", l_frame); put1("core_brate", core_brate); put1("q_exc", q_exc);
    put1("bfi", bfi); put1("last_core", last_core); put1("last_codec_mode", last_codec_mode);
    put16("exc2", exc2, L_FRAME16k); put16("dct", dct, L_FRAME16k); put16("lt", lt, MBANDS_GN);
    Inac_swtch_ematch_fx(exc2, dct, lt, coder_type, l_frame, core_brate, q_exc, bfi, last_core, last_codec_mode);
    arrow(); put16("exc2", exc2, L_FRAME16k); put16("dct", dct, L_FRAME16k); put16("lt", lt, MBANDS_GN); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "inac_swtch_ematch")) case_inac_swtch_ematch();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
