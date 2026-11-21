/* Function-level oracle for lib_com/weight_a_fx.c. The template every fn/ harness follows. */
#include "harness.h"
#include "prot_fx.h"

static void case_weight_a(void)
{
    Word16 a[M + 1], ap[M + 1];
    Word16 m = (Word16)(next_random() & 1 ? M : 10); /* the orders the decoder uses */
    Word16 gamma = (Word16)(next_random() % 3 == 0 ? random16() : random_range(20000, 32767));
    a[0] = 4096;
    for (int i = 1; i <= m; i++) a[i] = (next_random() & 3) ? (Word16)random_range(-12000, 12000) : random16();
    put16("a", a, m + 1); put1("gamma", gamma); put1("m", m);
    weight_a_fx(a, ap, gamma, m);
    arrow(); put16("ap", ap, m + 1); end_line();
}

static void case_weight_a_lc(void)
{
    Word16 a[M + 1], ap[M + 1], table[M];
    Word16 m = M;
    Word16 gamma = (Word16)random_range(20000, 32767), fac = gamma;
    for (int i = 0; i < m; i++) { table[i] = fac; fac = mult_r(fac, gamma); }
    a[0] = 4096;
    for (int i = 1; i <= m; i++) a[i] = (next_random() & 3) ? (Word16)random_range(-12000, 12000) : random16();
    put16("a", a, m + 1); put16("gammatbl", table, m); put1("m", m);
    weight_a_lc_fx(a, ap, table, m);
    arrow(); put16("ap", ap, m + 1); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "weight_a")) case_weight_a();
        else if (!strcmp(argv[2], "weight_a_lc")) case_weight_a_lc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
