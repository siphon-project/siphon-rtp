/* Function-level oracle for lib_com/env_stab_trans_fx.c (env_stab_transient_detect_fx), as
 * fill_spectrum_fx calls it for 640 coefficient frames: HVQ frames with the Q12 decoded spectrum below
 * the cross-over bin, transient frames from the norms of the sub-frame groups, others from the first
 * SFM_N_ENV_STAB norms. */
#include "hq_bit_allocation_inputs.h"

static void case_env_stab_transient_detect(void)
{
    static Word32 coeff[L_FRAME48k];
    Word16 norm[NB_SFM], mode = (Word16)random_range(0, 4);
    Word32 energy_lt = next_random() % 4 ? (Word32)random_range(0, 1 << 20) : next_random() % 2 ? 0 : random32() & 0x7fffffff;
    Word16 hangover = (Word16)(next_random() % 2 ? 0 : random_range(0, ATT_LIM_HANGOVER));
    Word16 is_transient = (Word16)(mode == HQ_TRANSIENT || next_random() % 5 == 0);
    Word16 bin_th = 0;
    int level = random_range(0, 3), spread = random_range(2, 20);
    for (int i = 0; i < NB_SFM; i++) norm[i] = (Word16)(level == 0 ? random_range(0, 39) : level == 1 ? random_range(20, 39) : random_range(0, 20));
    if (next_random() % 4 == 0) for (int i = 0; i < NB_SFM; i++) norm[i] = next_random() % 2 ? 39 : 0;
    /* a transient frame whose sub-frame energies rise */
    if (next_random() % 3 == 0) for (int i = 0; i < NB_SFM; i++) norm[i] = (Word16)(5 + (i * 34 / NB_SFM));
    for (int i = 0; i < L_FRAME48k; i++) coeff[i] = next_random() % 5 == 0 ? 0 : (Word32)((next_random() << 16) ^ next_random()) >> (32 - spread - 1);
    if (mode == HQ_HVQ) bin_th = next_random() & 1 ? band_end_harm[HVQ_THRES_SFM_24k - 1] : band_end_harm[HVQ_THRES_SFM_32k - 1];
    if (next_random() % 8 == 0) for (int i = 0; i < L_FRAME48k; i++) coeff[i] = 0;
    put1("is_transient", is_transient); put16("norm", norm, NB_SFM); put1("hangover", hangover); put1("energy_lt", energy_lt);
    put1("mode", mode); put1("bin_th", bin_th); put32("coeff", coeff, L_FRAME48k);
    env_stab_transient_detect_fx(is_transient, L_FRAME32k, norm, &hangover, &energy_lt, mode, bin_th, coeff, 12);
    arrow(); put1("hangover", hangover); put1("energy_lt", energy_lt); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "env_stab_transient_detect")) case_env_stab_transient_detect();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
