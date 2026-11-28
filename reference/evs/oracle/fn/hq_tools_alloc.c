/* Function-level oracle for limit_band_noise_level_calc_fx and find_last_band_fx of lib_com/hq_tools_fx.c, on the
 * inputs hq_bit_allocation_fx gives them: the weighted norms of the harmonic mode (limit = nb_sfm - 2) and the
 * integer allocation of any class. */
#include "hq_bit_allocation_inputs.h"

static void case_limit_band_noise_level_calc(void)
{
    HqAllocInput c;
    Word16 wnorm[NB_SFM], limit, noise_level = -7;
    RANDOM_INPUT_WHERE(&c, c.hqswb_clas == HQ_HARMONIC);
    random_norms(wnorm, NB_SFM);
    if (next_random() % 3 == 0) for (int i = 0; i < NB_SFM; i++) wnorm[i] = c.normqlg2[i];
    limit = (Word16)(c.nb_sfm - 2);
    put16("wnorm", wnorm, NB_SFM); put1("limit", limit); put1("core_brate", c.core_brate);
    int ok = GUARDED(limit_band_noise_level_calc_fx(wnorm, &limit, c.core_brate, &noise_level));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("limit", limit); put1("noise_level", noise_level); end_line();
}

static void case_find_last_band(void)
{
    HqAllocInput c;
    Word16 bitalloc[NB_SFM];
    random_hq_alloc_input(&c);
    int last = random_range(-1, c.nb_sfm - 1);
    for (int i = 0; i < NB_SFM; i++) bitalloc[i] = (Word16)(i <= last && next_random() % 2 ? random_range(1, 9) : 0);
    if (last >= 0) bitalloc[last] = (Word16)random_range(1, 9);
    put16("bitalloc", bitalloc, NB_SFM); put1("nb_sfm", c.nb_sfm);
    Word16 core_sfm = find_last_band_fx(bitalloc, c.nb_sfm);
    arrow(); put1("core_sfm", core_sfm); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "limit_band_noise_level_calc")) case_limit_band_noise_level_calc();
        else if (!strcmp(argv[2], "find_last_band")) case_find_last_band();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
