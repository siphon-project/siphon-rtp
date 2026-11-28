/* Function-level oracle for lib_com/lsf_tools_fx.c (the functions the 7.2 / 8 kbit/s decoder runs). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

/* Not in prot_fx.h; defined (non-static) in lsf_tools_fx.c. */
Word16 E_LPC_f_lsp_pol_get(const Word16 lsp[], Word32 f[], const Word16 n, const Word16 past_Ovf, const Word16 isMODE1);

static Word32 offset_scale1[MAX_NO_MODES + 1][MAX_NO_SCALES + 1], offset_scale2[MAX_NO_MODES + 1][MAX_NO_SCALES + 1];
static Word32 offset_scale1_p[MAX_NO_MODES_p + 1][MAX_NO_SCALES + 1], offset_scale2_p[MAX_NO_MODES_p + 1][MAX_NO_SCALES + 1];
static Word16 no_scales[MAX_NO_MODES][2], no_scales_p[MAX_NO_MODES_p][2];

/* An ordered LSF vector (Q(x2.56)) over [0, fs/2): uniform, clustered in a narrow band (the NB
 * resonances that overflow the polynomial), or pushed to the edges. */
static void random_lsf(Word16 *lsf, int m, int top)
{
    int shape = next_random() % 4, pos = 0;
    if (shape == 0) {
        int low = random_range(0, top - m * 20), width = random_range(m * 4, m * 40);
        for (int i = 0; i < m; i++) { pos = low + width * (i + 1) / (m + 1) + random_range(0, 3); lsf[i] = (Word16)(pos < top ? pos : top - 1); }
        return;
    }
    for (int i = 0; i < m; i++) {
        pos += shape == 1 ? random_range(1, 2 * top / m) : random_range(20, 2 * top / m);
        if (pos >= top) pos = top - 1;
        lsf[i] = (Word16)pos;
    }
    if (shape == 3) lsf[m - 1] = (Word16)(top - random_range(1, 40));
}

static void case_lsp_pol_get(void)
{
    Word16 m = (Word16)(next_random() & 1 ? 16 : 10), lsf[16], lsp[16], past = (Word16)(next_random() % 4 ? 0 : random_range(1, 3));
    Word16 is_mode1 = (Word16)(next_random() % 4 != 0), first = (Word16)(next_random() & 1), ovf;
    Word32 f[9];
    random_lsf(lsf, m, 16384);
    lsf2lsp_fx(lsf, lsp, m, INT_FS_FX);
    if (next_random() % 8 == 0) for (int i = 0; i < m; i++) lsp[i] = random16();
    put16("lsp", lsp, m); put1("first", first); put1("n", m / 2); put1("past_ovf", past); put1("is_mode1", is_mode1);
    ovf = E_LPC_f_lsp_pol_get(lsp + first, f, (Word16)(m / 2), past, is_mode1);
    arrow(); put1("ovf", ovf); put32("f", f, m / 2 + 1); end_line();
}

static void case_lsp_a_conversion(void)
{
    Word16 m = (Word16)(next_random() & 1 ? 16 : 10), lsf[16], lsp[16], a[17];
    random_lsf(lsf, m, 16384);
    lsf2lsp_fx(lsf, lsp, m, INT_FS_FX);
    put16("lsp", lsp, m); put1("m", m);
    E_LPC_f_lsp_a_conversion(lsp, a, m);
    arrow(); put16("a", a, m + 1); end_line();
}

static void case_reorder_lsf(void)
{
    Word16 n = (Word16)(next_random() & 1 ? M : 10), lsf[M];
    Word32 fs = next_random() & 1 ? INT_FS_FX : INT_FS_16k_FX;
    Word16 min_dist = (Word16)(next_random() % 3 ? 128 : random_range(0, 400)), top = (Word16)(fs == INT_FS_FX ? 16384 : 20480);
    for (int i = 0; i < n; i++) lsf[i] = (Word16)(next_random() % 4 ? random_range(-200, top + 200) : random16());
    if (next_random() & 1) random_lsf(lsf, n, top);
    put16("lsf", lsf, n); put1("min_dist", min_dist); put1("n", n); put1("fs", fs);
    reorder_lsf_fx(lsf, min_dist, n, fs);
    arrow(); put16("lsf", lsf, n); end_line();
}

static void case_lsf_stab(void)
{
    Word16 lsf[M], lsfold[M], opt = (Word16)(next_random() % 4 == 0), l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    random_lsf(lsf, M, 16384);
    if (next_random() % 3) { for (int i = 0; i < M; i++) lsfold[i] = (Word16)(lsf[i] + random_range(-300, 300)); }
    else random_lsf(lsfold, M, 16384);
    if (next_random() % 10 == 0) for (int i = 0; i < M; i++) lsfold[i] = lsf[i];
    put16("lsf", lsf, M); put16("lsfold", lsfold, M); put1("opt_amr_wb", opt); put1("l_frame", l_frame);
    arrow(); put1("stab", lsf_stab_fx(lsf, lsfold, opt, l_frame)); end_line();
}

static void case_lsp_lsf(void)
{
    Word16 m = (Word16)(next_random() & 1 ? M : 10), lsf[M], lsp[M], lsf2[M], lsp2[M];
    Word32 fs = next_random() & 1 ? INT_FS_FX : INT_FS_16k_FX;
    random_lsf(lsf, m, fs == INT_FS_FX ? 16384 : 20480);
    for (int i = 0; i < m; i++) lsp[i] = (Word16)(next_random() % 3 ? random_range(-32768, 32767) : random16());
    put16("lsf", lsf, m); put16("lsp", lsp, m); put1("m", m); put1("int_fs", fs);
    lsf2lsp_fx(lsf, lsp2, m, fs);
    lsp2lsf_fx(lsp, lsf2, m, fs);
    arrow(); put16("lsf2lsp", lsp2, m); put16("lsp2lsf", lsf2, m); end_line();
}

static void case_sub_lsp2lsf(void)
{
    Word16 lsp = (Word16)(next_random() & 1 ? random_range(-32768, 32767) : random16());
    put1("lsp", lsp); arrow(); put1("lsf", sub_lsp2lsf_fx(lsp)); end_line();
}

static void case_lsf_lsp_conversion(void)
{
    Word16 m = (Word16)(next_random() & 1 ? M : 10), lsf[M], lsp[M];
    random_lsf(lsf, m, 16384);
    if (next_random() % 5 == 0) for (int i = 0; i < m; i++) lsf[i] = random16();
    put16("lsf", lsf, m); put1("m", m);
    E_LPC_lsf_lsp_conversion(lsf, lsp, m);
    arrow(); put16("lsp", lsp, m); end_line();
}

/* E_LPC_lsp_lsf_conversion (and xsp_to_xsf through it): LSPs from real LSFs, or edge values. */
static void case_lsp_lsf_conversion(void)
{
    Word16 m = (Word16)(next_random() & 1 ? M : 10), lsf[M], lsp[M];
    random_lsf(lsf, m, 16384);
    E_LPC_lsf_lsp_conversion(lsf, lsp, m);
    if (next_random() % 5 == 0) for (int i = 0; i < m; i++) lsp[i] = (Word16)(next_random() & 1 ? random_range(-32768, 32767) : random16());
    put16("lsp", lsp, m); put1("m", m);
    E_LPC_lsp_lsf_conversion(lsp, lsf, m);
    arrow(); put16("lsf", lsf, m); end_line();
}

/* E_LPC_a_lsp_conversion (and the static chebyshev): A(z) of a real LSP vector, sometimes at a
 * reduced scale (as Levinson-Durbin leaves it) or perturbed, and now and then a random filter whose
 * roots are not all found (the old-LSP fallback). */
static void case_a_lsp_conversion(void)
{
    Word16 m = (Word16)(next_random() % 4 ? M : 10), lsf[M], lsp[M], old_lsp[M], a[M + 1], out[M];
    random_lsf(lsf, m, m == M ? 16384 : 16384);
    E_LPC_lsf_lsp_conversion(lsf, lsp, m);
    E_LPC_f_lsp_a_conversion(lsp, a, m);
    int kind = next_random() % 8;
    if (kind == 0) { int sh = random_range(1, 3); for (int i = 0; i <= m; i++) a[i] = shr(a[i], sh); }
    else if (kind == 1) { for (int i = 1; i <= m; i++) a[i] = add(a[i], (Word16)random_range(-64, 64)); }
    else if (kind == 2) { a[0] = 4096; for (int i = 1; i <= m; i++) a[i] = (Word16)random_range(-8000, 8000); }
    else if (kind == 3) { a[0] = 4096; for (int i = 1; i <= m; i++) a[i] = random16(); } /* saturating evaluations */
    for (int i = 0; i < m; i++) old_lsp[i] = random16();
    put16("a", a, m + 1); put16("old_lsp", old_lsp, m); put1("m", m);
    E_LPC_a_lsp_conversion(a, out, old_lsp, m);
    arrow(); put16("lsp", out, m); end_line();
}

/* E_LPC_f_isp_a_conversion over real ISP vectors (the last ISP is the reflection-like term). */
static void case_isp_a_conversion(void)
{
    Word16 m = (Word16)(next_random() % 4 ? M : 10), isf[M], isp[M], a[M + 1];
    random_lsf(isf, m, 16384);
    E_LPC_lsf_lsp_conversion(isf, isp, m);
    if (next_random() % 4 == 0) isp[m - 1] = (Word16)random_range(-32768, 32767);
    if (next_random() % 16 == 0) for (int i = 0; i < m; i++) isp[i] = random16();
    put16("isp", isp, m); put1("m", m);
    E_LPC_f_isp_a_conversion(isp, a, m);
    arrow(); put16("a", a, m + 1); end_line();
}

static void case_pred_mode_and_allocate(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000};
    Word16 coder_type = (Word16)random_range(0, 5), bwidth = (Word16)random_range(0, 3);
    Word32 int_fs = next_random() & 1 ? INT_FS_FX : INT_FS_16k_FX, core_brate = rates[next_random() % 7];
    Word16 mode_lvq = -99, mode_lvq_p = -99, predmode, nbits = (Word16)random_range(19, 46);
    Word16 stages0 = -7, stages1 = -7, levels0[6], levels1[6], bits0[6], bits1[6];
    for (int i = 0; i < 6; i++) { levels0[i] = levels1[i] = bits0[i] = bits1[i] = -7; }
    put1("coder_type", coder_type); put1("bwidth", bwidth); put1("int_fs", int_fs); put1("core_brate", core_brate); put1("n_bits", nbits);
    predmode = find_pred_mode(coder_type, bwidth, int_fs, &mode_lvq, &mode_lvq_p, core_brate);
    lsf_allocate_fx(sub(nbits, shr(predmode, 1)), mode_lvq, mode_lvq_p, &stages0, &stages1, levels0, levels1, bits0, bits1);
    arrow(); put1("predmode", predmode); put1("mode_lvq", mode_lvq); put1("mode_lvq_p", mode_lvq_p);
    put1("stages0", stages0); put1("stages1", stages1); put16("levels0", levels0, 6); put16("levels1", levels1, 6);
    put16("bits0", bits0, 6); put16("bits1", bits1, 6); end_line();
}

static void case_vq_dec_lvq(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200};
    Word16 coder_type, bwidth, mode_lvq, mode_lvq_p, predmode, nbits, sf_flag, mode, stages, no_bits;
    Word16 stages0, stages1, levels0[6], levels1[6], bits0[6], bits1[6], *levels, *bits;
    Word16 indices[8], x[M], ber;
    Word32 core_brate;
    int n_words = 0;
    init_lvq_fx(offset_scale1, offset_scale2, offset_scale1_p, offset_scale2_p, no_scales, no_scales_p);
    for (;;) {
        coder_type = (Word16)random_range(1, 5);
        bwidth = (Word16)random_range(0, 1);
        core_brate = rates[next_random() % 4];
        nbits = (Word16)random_range(22, 42);
        stages0 = stages1 = 0;
        predmode = find_pred_mode(coder_type, bwidth, INT_FS_FX, &mode_lvq, &mode_lvq_p, core_brate);
        lsf_allocate_fx(sub(nbits, shr(predmode, 1)), mode_lvq, mode_lvq_p, &stages0, &stages1, levels0, levels1, bits0, bits1);
        sf_flag = (Word16)(predmode == 0 || (predmode == 2 && (next_random() & 1)) ? 1 : 0);
        mode = sf_flag ? mode_lvq : mode_lvq_p;
        stages = sf_flag ? stages0 : stages1;
        levels = sf_flag ? levels0 : levels1;
        bits = sf_flag ? bits0 : bits1;
        if (stages < 1 || mode < 0) continue;
        no_bits = levels[stages - 1];
        if (no_bits < (sf_flag ? min_lat_bits_SN_fx[mode] : min_lat_bits_pred_fx[mode])) continue;
        break;
    }
    for (int i = 0; i < stages - 1; i++) indices[n_words++] = (Word16)random_range(0, (1 << bits[i]) - 1);
    for (int left = no_bits; left > 0; left -= LEN_INDICE) {
        int b = left > LEN_INDICE ? LEN_INDICE : left;
        indices[n_words++] = (Word16)(next_random() % 4 ? (Word16)(next_random() & ((1u << b) - 1)) : random_range(0, 40));
    }
    for (int i = n_words; i < 8; i++) indices[i] = 0;
    for (int i = 0; i < M; i++) x[i] = random16();
    put1("sf_flag", sf_flag); put16("indices", indices, 8); put1("stages", stages); put1("mode", mode); put1("no_bits", no_bits);
    ber = vq_dec_lvq_fx(sf_flag, x, indices, stages, M, mode, no_bits, &offset_scale1[0][0], &offset_scale2[0][0],
                        &offset_scale1_p[0][0], &offset_scale2_p[0][0], &no_scales[0][0], &no_scales_p[0][0]);
    arrow(); put1("ber", ber); put16("x", x, M); put16("indices", indices, 8); end_line();
}

static void case_reorder_isf(void)
{
    Word16 n = (Word16)(next_random() & 1 ? M : 10), isf[M];
    Word16 fs = Fs_2;
    Word16 min_dist = (Word16)(next_random() % 3 ? ISF_GAP_FX : random_range(0, 400)), top = 16384;
    if (next_random() % 4 == 0) fs = (Word16)random_range(2000, 20000);
    for (int i = 0; i < n; i++) isf[i] = (Word16)(next_random() % 4 ? random_range(-200, top + 200) : random16());
    if (next_random() & 1) random_lsf(isf, n, top);
    put16("isf", isf, n); put1("min_dist", min_dist); put1("n", n); put1("fs", fs);
    reorder_isf_fx(isf, min_dist, n, fs);
    arrow(); put16("isf", isf, n); end_line();
}

static void case_isf_isp_conversion(void)
{
    Word16 m = (Word16)(next_random() & 1 ? M : 10), isf[M], isp[M];
    random_lsf(isf, m, 16384);
    if (next_random() % 4 == 0) for (int i = 0; i < m; i++) isf[i] = (Word16)random_range(0, 16383);
    isf[m - 1] = (Word16)(isf[m - 1] >> (next_random() & 1));
    put16("isf", isf, m); put1("m", m);
    E_LPC_isf_isp_conversion(isf, isp, m);
    arrow(); put16("isp", isp, m); end_line();
}

/* qlsf_ARSN_tcvq_Dec_16k_fx (and tcvq_Dec_fx under it) as lsf_end_dec_fx calls it for a 16 kHz
 * VOICED frame: the safety-net flag, then the eleven BC-TCVQ / SVQ indices at their bit widths. */
static void case_tcvq_dec(void)
{
    static const Word16 nbits_set[] = {29, 30, 31, 32, 39, 40, 41};
    Word16 indice[M / 2 + 4], y[M];
    Word16 nbits = nbits_set[next_random() % 7];
    indice[0] = (Word16)(next_random() & 1);
    for (int i = 0; i < M / 2 + 3; i++) indice[i + 1] = (Word16)(next_random() & ((1u << BC_TCVQ_BIT_ALLOC_40B[i + 1]) - 1));
    for (int i = 0; i < M; i++) y[i] = random16();
    put16("indice", indice, M / 2 + 4); put1("nbits", nbits);
    Word16 sn = qlsf_ARSN_tcvq_Dec_16k_fx(y, indice, nbits);
    arrow(); put1("sn", sn); put16("y", y, M); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lsp_pol_get")) case_lsp_pol_get();
        else if (!strcmp(argv[2], "lsp_a_conversion")) case_lsp_a_conversion();
        else if (!strcmp(argv[2], "reorder_lsf")) case_reorder_lsf();
        else if (!strcmp(argv[2], "lsf_stab")) case_lsf_stab();
        else if (!strcmp(argv[2], "lsp_lsf")) case_lsp_lsf();
        else if (!strcmp(argv[2], "sub_lsp2lsf")) case_sub_lsp2lsf();
        else if (!strcmp(argv[2], "lsf_lsp_conversion")) case_lsf_lsp_conversion();
        else if (!strcmp(argv[2], "lsp_lsf_conversion")) case_lsp_lsf_conversion();
        else if (!strcmp(argv[2], "a_lsp_conversion")) case_a_lsp_conversion();
        else if (!strcmp(argv[2], "isp_a_conversion")) case_isp_a_conversion();
        else if (!strcmp(argv[2], "pred_mode_and_allocate")) case_pred_mode_and_allocate();
        else if (!strcmp(argv[2], "vq_dec_lvq")) case_vq_dec_lvq();
        else if (!strcmp(argv[2], "reorder_isf")) case_reorder_isf();
        else if (!strcmp(argv[2], "isf_isp_conversion")) case_isf_isp_conversion();
        else if (!strcmp(argv[2], "tcvq_dec")) case_tcvq_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
