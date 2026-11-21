/* Function-level oracle for lib_com/lsp_conv_poly_fx.c (lsp_convert_poly_fx and its statics). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "../../c-code/lib_com/lsp_conv_poly_fx.c"

/* An ordered LSF vector (Q(x2.56) of 6400 Hz) as the decoder keeps it (reorder_lsf: at least
 * LSF_GAP apart and off both band edges): spread out, clustered at the minimum spacing (sharp
 * resonances), or close to the decoder's flat initial vector. */
static void random_lsf(Word16 *lsf, int m)
{
    const int gap = 128, top = 16384 - gap;
    int shape = next_random() % 3, pos = gap;
    if (shape == 0) {
        int width = random_range(m * gap, top - gap), low = random_range(gap, top - width);
        for (int i = 0; i < m; i++) lsf[i] = (Word16)(low + width * i / (m - 1));
        return;
    }
    if (shape == 2) {
        for (int i = 0; i < m; i++) lsf[i] = (Word16)((i + 1) * 16384 / (m + 1) + random_range(-40, 40));
        return;
    }
    for (int i = 0; i < m; i++) {
        if (i > 0) pos += random_range(gap, 2 * 16384 / m);
        if (pos > top - (m - 1 - i) * gap) pos = top - (m - 1 - i) * gap;
        lsf[i] = (Word16)pos;
    }
}

/* lsp_convert_poly_fx in both directions (L_frame 256: 16 kHz -> 12.8 kHz; 320: the reverse), on
 * LSPs and, as the AMR-WB IO switching calls it (always to L_FRAME), ISPs. */
static void case_lsp_convert_poly(void)
{
    Word16 lsf[M], w[M];
    Word16 l_frame = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    Word16 opt_amrwb = (next_random() % 4) == 0;
    if (opt_amrwb) l_frame = L_FRAME; /* amr_wb_dec only converts ISPs down to 12.8 kHz */
    for (;;) {
        random_lsf(lsf, M);
        E_LPC_lsf_lsp_conversion(lsf, w, M);
        if (opt_amrwb && (next_random() & 1)) w[M - 1] = (Word16)random_range(-20000, 20000);
        if (opt_amrwb || l_frame == L_FRAME) break;
        /* The upward conversion evaluates the difference polynomial at the Nyquist frequency and
         * inverts its square (b_inv_sq): with the last LSPs crowded against -1.0 it rounds to zero
         * and the reference aborts in div_s. Such a vector never reaches it; draw another. */
        Word32 R[M / 2 + 1], S[M / 2 + 1], g;
        zeros2poly_fx(w, R, S);
        g = S[0];
        for (int j = 1; j <= M / 2; j++) g = L_sub(S[j], g);
        if (g != 0) break;
    }
    put16("w", w, M); put1("l_frame", l_frame); put1("opt_amrwb", opt_amrwb);
    Word16 flag = lsp_convert_poly_fx(w, l_frame, opt_amrwb);
    arrow(); put16("w", w, M); put1("flag", flag); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lsp_convert_poly")) case_lsp_convert_poly();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
