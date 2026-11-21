/* Function-level oracle for lib_com/reordvct_fx.c (reordvct_fx): vectors of the lengths the HQ bit
 * allocation sorts (up to 14 bands), with ties and edge values. */
#include "harness.h"
#include "prot_fx.h"

static void case_reordvct(void)
{
    Word16 y[16], idx[16], n = (Word16)random_range(0, 16);
    int range = next_random() % 3 == 0 ? 4 : 1 << random_range(2, 15);
    for (int i = 0; i < 16; i++) {
        y[i] = next_random() % 6 == 0 ? random16() : (Word16)random_range(-range, range - 1);
        idx[i] = (Word16)(i + random_range(0, 3) * 16);
    }
    put16("y", y, 16); put16("idx", idx, 16); put1("n", n);
    reordvct_fx(y, n, idx);
    arrow(); put16("y", y, 16); put16("idx", idx, 16); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "reordvct")) case_reordvct();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
