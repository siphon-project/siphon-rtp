/* Function-level oracle for the helpers of the PPP coder: lib_com/ppp_fx.c (Interpol_delay_fx,
 * deemph_lpc_fx), log10_fx (basic_math/log2.c) and find_remd (lib_com/tools_fx.c). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_interpol_delay(void)
{
    Word16 out[3] = {-7, -7, -7}, last = (Word16)random_range(19, 201), cur = (Word16)random_range(19, 201), sub_num = (Word16)random_range(0, 3);
    put1("last", last); put1("cur", cur); put1("sub", sub_num);
    Interpol_delay_fx(out, last, cur, sub_num, frac_4sf_fx);
    arrow(); put16("out", out, 3); end_line();
}

static void case_deemph_lpc(void)
{
    Word16 curr[M], old[M + 1], de_curr[M + 1], de_old[M + 1], flag = (Word16)(next_random() & 1);
    for (int i = 0; i < M; i++) curr[i] = random16();
    old[0] = 4096;
    for (int i = 1; i <= M; i++) old[i] = random16();
    for (int i = 0; i <= M; i++) de_curr[i] = de_old[i] = -7;
    put16("curr", curr, M); put16("old", old, M + 1); put1("flag", flag);
    deemph_lpc_fx(curr, old, de_curr, de_old, flag);
    arrow(); put16("de_curr", de_curr, M + 1); put16("de_old", de_old, M + 1); end_line();
}

static void case_log10(void)
{
    Word32 x = next_random() % 6 == 0 ? random32() : (Word32)(next_random() & 0x7fffffff) >> random_range(0, 30);
    put1("x", x);
    Word32 r = log10_fx(x);
    arrow(); put1("r", r); end_line();
}

static void case_find_remd(void)
{
    Word32 n = (Word32)(next_random() & 0x7fffffff) >> random_range(0, 30), m = (Word32)(next_random() & 0x7fffffff) >> random_range(0, 30);
    if (next_random() % 5 == 0) m = 20971;
    if (m == 0) m = 1;
    Word32 rem = -7;
    put1("n", n); put1("m", m);
    Word32 q = find_remd(n, m, &rem);
    arrow(); put1("q", q); put1("rem", rem); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "interpol_delay")) case_interpol_delay();
        else if (!strcmp(argv[2], "deemph_lpc")) case_deemph_lpc();
        else if (!strcmp(argv[2], "log10")) case_log10();
        else if (!strcmp(argv[2], "find_remd")) case_find_remd();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
