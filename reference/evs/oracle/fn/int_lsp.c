/* Function-level oracle for lib_com/int_lsp_fx.c (int_lsp4_fx: three-point LSP interpolation;
 * int_lsp_fx: two-point LSP/ISP interpolation, both the LSP and the AMR-WB ISP conversion). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

/* A plausible LSP vector: decreasing cosines in Q15, or (rarely) arbitrary values. */
static void random_lsp(Word16 *lsp, int m)
{
    if (next_random() % 8 == 0) {
        for (int i = 0; i < m; i++) lsp[i] = random16();
        return;
    }
    int value = 32767 - random_range(50, 2500);
    for (int i = 0; i < m; i++) {
        lsp[i] = (Word16)value;
        value -= random_range(300, 65000 / m);
        if (value < -32767) value = -32767 + random_range(0, 10);
    }
}

static void case_int_lsp4(void)
{
    static const Word16 relax[] = {0, 1, 2, -1, 3};
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 r = relax[next_random() % 5];
    Word16 m = M;
    Word16 old[M16k], mid[M16k], new[M16k], aq[NB_SUBFR16k * (M + 1)];
    random_lsp(old, m); random_lsp(mid, m); random_lsp(new, m);
    for (int i = 0; i < NB_SUBFR16k * (M + 1); i++) aq[i] = -5;
    put1("l_frame", l_frame); put1("relax", r); put16("old", old, m); put16("mid", mid, m); put16("new", new, m);
    int_lsp4_fx(l_frame, old, mid, new, aq, m, r);
    arrow(); put16("aq", aq, NB_SUBFR16k * (M + 1)); end_line();
}

static void case_int_lsp(void)
{
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 amr = (Word16)(next_random() & 1);
    Word16 m = M;
    Word16 coeffs[NB_SUBFR];
    Word16 old[M16k], new[M16k], aq[NB_SUBFR16k * (M + 1)];
    switch (next_random() % 3) {
    case 0: memcpy(coeffs, interpol_frac_fx, sizeof(coeffs)); break;
    case 1: memcpy(coeffs, interpol_isp_amr_wb_fx, sizeof(coeffs)); break;
    default: for (int i = 0; i < NB_SUBFR; i++) coeffs[i] = (Word16)(next_random() % 3 ? random_range(0, 32767) : 32767); break;
    }
    random_lsp(old, m); random_lsp(new, m);
    for (int i = 0; i < NB_SUBFR16k * (M + 1); i++) aq[i] = -5;
    put1("l_frame", l_frame); put1("amr", amr); put16("coeffs", coeffs, NB_SUBFR); put16("old", old, m); put16("new", new, m);
    int_lsp_fx(l_frame, old, new, aq, m, coeffs, amr);
    arrow(); put16("aq", aq, NB_SUBFR16k * (M + 1)); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "int_lsp4")) case_int_lsp4();
        else if (!strcmp(argv[2], "int_lsp")) case_int_lsp();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
