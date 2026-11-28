/* Function-level oracle for lib_com/tcx_mdct_window.c: mdct_window_aldo at every frame length
 * tcx_utils.c configures (L_frame and L_frameTCX of each core and output rate). The windows are
 * prefilled with a sentinel so a missed write shows. mdct_window_sine is a table lookup, proven by
 * rom_basop_util's getSineWindowTable oracle. */
#include "harness.h"
#include "prot_fx.h"

static void case_mdct_window_aldo(void)
{
    static const Word16 lengths[] = {160, 256, 320, 512, 640, 960};
    static Word16 window1[271], re1[211], im1[211], re2[211], im2[211];
    static PWord16 trunc[211], window2[211];
    Word16 n = lengths[random_range(0, 5)];
    int n0 = n * 9 / 32, n7 = n * 7 / 32;
    for (int i = 0; i < 271; i++) window1[i] = -12345;
    for (int i = 0; i < 211; i++) trunc[i].v.re = trunc[i].v.im = window2[i].v.re = window2[i].v.im = -12345;
    put1("n", n);
    mdct_window_aldo(window1, trunc, window2, n);
    for (int i = 0; i <= n7; i++) { re1[i] = trunc[i].v.re; im1[i] = trunc[i].v.im; re2[i] = window2[i].v.re; im2[i] = window2[i].v.im; }
    arrow(); put16("window1", window1, n0 + 1); put16("trunc_re", re1, n7 + 1); put16("trunc_im", im1, n7 + 1);
    put16("window2_re", re2, n7 + 1); put16("window2_im", im2, n7 + 1); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "mdct_window_aldo")) case_mdct_window_aldo();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
