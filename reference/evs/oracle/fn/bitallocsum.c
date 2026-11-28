/* Function-level oracle for lib_com/bitallocsum_fx.c on integer allocations like bitalloc_fx's: bits per
 * coefficient 0..QBIT_MAX2 on the HQ band layouts, the budget a little above or below what the allocation takes. */
#include "hq_bit_allocation_inputs.h"

static void case_bitallocsum(void)
{
    HqAllocInput c;
    Word16 r[NB_SFM], rsubband[NB_SFM], sum = -7;
    random_hq_alloc_input(&c);
    int mode = next_random() % 4;
    for (int i = 0; i < NB_SFM; i++) {
        r[i] = (Word16)(mode == 0 ? random_range(0, QBIT_MAX2) : mode == 1 ? (i < c.nb_sfm / 2 ? random_range(1, 5) : 0)
                                                                 : (next_random() % 3 ? 0 : random_range(1, 7)));
        rsubband[i] = -7;
    }
    if (next_random() % 10 == 0) for (int i = 0; i < c.nb_sfm; i++) r[i] = 0;
    int total = 0;
    for (int i = 0; i < c.nb_sfm; i++) total += r[i] * c.sfmsize[i];
    Word16 v = (Word16)(total + random_range(-30, 60));
    if (next_random() % 8 == 0) v = c.num_bits;
    /* the leftover loop spins when no band has bits, which bitalloc_fx never returns */
    if (total == 0 && v > 0) v = 0;
    put16("r", r, c.nb_sfm); put1("nb_sfm", c.nb_sfm); put1("v", v); put1("length", c.length);
    put16("sfmsize", c.sfmsize, c.nb_sfm);
    bitallocsum_fx(r, c.nb_sfm, &sum, rsubband, v, c.length, c.sfmsize);
    arrow(); put1("sum", sum); put16("rsubband", rsubband, c.nb_sfm); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "bitallocsum")) case_bitallocsum();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
