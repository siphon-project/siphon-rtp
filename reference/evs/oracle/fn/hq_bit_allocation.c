/* Function-level oracle for lib_com/hq_bit_allocation_fx.c on the inputs hq_hr_dec_fx feeds it
 * (hq_bit_allocation_inputs.h). */
#include "hq_bit_allocation_inputs.h"

static void case_hq_bit_allocation(void)
{
    HqAllocInput c;
    random_hq_alloc_input(&c);
    Word16 num_bits = c.num_bits, noise_level[HVQ_BWE_NOISE_BANDS] = {-7, -7}, R[NB_SFM], Rsubband[NB_SFM];
    Word16 sum = -7, core_sfm = -7;
    for (int i = 0; i < NB_SFM; i++) { R[i] = -7; Rsubband[i] = -7; }
    put1("core_brate", c.core_brate); put1("length", c.length); put1("hqswb_clas", c.hqswb_clas);
    put1("num_bits", num_bits); put16("normqlg2", c.normqlg2, NB_SFM); put1("nb_sfm", c.nb_sfm);
    put16("sfmsize", c.sfmsize, c.nb_sfm); put1("num_env_bands", c.num_env_bands);
    int ok = GUARDED(hq_bit_allocation_fx(c.core_brate, c.length, c.hqswb_clas, &num_bits, c.normqlg2, c.nb_sfm,
                                          c.sfmsize, noise_level, R, Rsubband, &sum, &core_sfm, c.num_env_bands));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("num_bits", num_bits); put16("noise_level", noise_level, 1); put16("r", R, NB_SFM);
    put16("rsubband", Rsubband, c.nb_sfm); put1("sum", sum); put1("core_sfm", core_sfm); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq_bit_allocation")) case_hq_bit_allocation();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
