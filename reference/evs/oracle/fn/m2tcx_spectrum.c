/* Function-level oracle for the spectral half of lib_com/tcx_utils.c: lpc2mdct, mdct_shaping,
 * mdct_shaping_16, mdct_noiseShaping_interp, PsychAdaptLowFreqDeemph, AdaptLowFreqDeemph and
 * tcx_noise_filling, with BASOP_Util_Sqrt_InvSqrt_MantExp, compMantExp16Unorm and Norm32Norm proven
 * through them (Norm32Norm through the ITF oracle). Inputs are in the ranges dec_tcx.c and
 * arith_coder.c feed them: spectrum lengths of the TCX frames, normalised LPC gain mantissas,
 * quantised spectra at the Q of the decoder. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static const Word16 frame_lengths[] = {64, 128, 256, 320, 512, 640, 960};

static void random_lpc(Word16 *a, int n)
{
    int style = random_range(0, 3);
    a[0] = (Word16)(style == 3 ? random_range(-32768, 32767) : (4096 << random_range(0, 2)));
    if (style == 2) a[0] = 0;
    for (int k = 1; k < n; k++) a[k] = (Word16)(style == 3 ? random16() : random_range(-12000 / k - 2000, 12000 / k + 2000));
}

static void case_lpc2mdct(void)
{
    Word16 a[M + 2], g[FDNS_NPTS], ge[FDNS_NPTS], ig[FDNS_NPTS], ige[FDNS_NPTS];
    Word16 order = (Word16)(next_random() & 1 ? M : M + 1);
    int mask = random_range(1, 15);
    random_lpc(a, M + 2);
    for (int i = 0; i < FDNS_NPTS; i++) g[i] = ge[i] = ig[i] = ige[i] = 0x5555;
    put16("a", a, M + 2); put1("order", order); put1("mask", mask);
    lpc2mdct(a, order, (mask & 1) ? g : NULL, (mask & 2) ? ge : NULL, (mask & 4) ? ig : NULL, (mask & 8) ? ige : NULL);
    arrow(); put16("g", g, FDNS_NPTS); put16("ge", ge, FDNS_NPTS); put16("ig", ig, FDNS_NPTS); put16("ige", ige, FDNS_NPTS); end_line();
}

static void random_gains(Word16 *g, Word16 *e)
{
    for (int i = 0; i < FDNS_NPTS; i++) {
        g[i] = (Word16)random_range(16384, 32767);
        e[i] = (Word16)random_range(-6, 10);
    }
}

static void random_spectrum(Word32 *x, int n)
{
    int shift = random_range(0, 24);
    for (int i = 0; i < n; i++) x[i] = (next_random() % 4 == 0) ? 0 : (Word32)(random32() >> shift);
}

static void case_mdct_shaping(void)
{
    static const Word16 lengths[] = {64, 80, 128, 160, 240, 256, 320, 480, 512, 640, 960};
    static Word32 x[1200];
    Word16 g[FDNS_NPTS], ge[FDNS_NPTS];
    Word16 lg = lengths[random_range(0, 10)];
    random_gains(g, ge);
    random_spectrum(x, lg);
    put1("lg", lg); put32("x", x, lg); put16("g", g, FDNS_NPTS); put16("ge", ge, FDNS_NPTS);
    mdct_shaping(x, lg, g, ge);
    arrow(); put32("x", x, lg); end_line();
}

static void case_mdct_shaping_16(void)
{
    static Word16 x[1400];
    static Word32 y[1400];
    Word16 g[FDNS_NPTS], ge[FDNS_NPTS];
    Word16 lg = frame_lengths[random_range(0, 6)];
    Word16 lg_total = (Word16)(lg + random_range(0, 3) * 40);
    Word16 max_exp = (Word16)random_range(0, 12);
    random_gains(g, ge);
    for (int i = 0; i < lg_total; i++) x[i] = random16();
    memset(y, 0x55, sizeof(y));
    put1("lg", lg); put1("lg_total", lg_total); put1("max_exp", max_exp); put16("x", x, lg_total); put16("g", g, FDNS_NPTS); put16("ge", ge, FDNS_NPTS);
    mdct_shaping_16(x, lg, lg_total, g, ge, max_exp, y);
    arrow(); put32("y", y, lg_total); end_line();
}

static void case_interp(void)
{
    static Word32 x[1200];
    Word16 g[FDNS_NPTS], ge[FDNS_NPTS];
    Word16 lg = frame_lengths[random_range(0, 6)];
    int null_gains = next_random() % 16 == 0;
    random_gains(g, ge);
    random_spectrum(x, lg);
    put1("lg", lg); put1("null_gains", null_gains); put32("x", x, lg); put16("g", g, FDNS_NPTS); put16("ge", ge, FDNS_NPTS);
    mdct_noiseShaping_interp(x, lg, null_gains ? NULL : g, ge);
    arrow(); put32("x", x, lg); end_line();
}

/* LPC gains as lpc2mdct returns them: normalised mantissas with a smooth exponent; sometimes a
 * low band whose gains are within a factor 32, so the de-emphasis engages. */
static void random_lpc_gains(Word16 *g, Word16 *e)
{
    int flat = next_random() % 2;
    Word16 base_e = (Word16)random_range(-2, 4);
    for (int i = 0; i < FDNS_NPTS; i++) {
        g[i] = (Word16)random_range(16384, 32767);
        e[i] = (Word16)(flat ? base_e + random_range(0, 2) : random_range(-6, 8));
    }
}

static void case_psych(void)
{
    Word32 x[64];
    Word16 g[FDNS_NPTS], ge[FDNS_NPTS], lf[64];
    int with_lf = next_random() & 1;
    random_lpc_gains(g, ge);
    random_spectrum(x, 64);
    for (int i = 0; i < 64; i++) lf[i] = (Word16)random_range(0x2000, 0x4000);
    put1("with_lf", with_lf); put32("x", x, 64); put16("g", g, FDNS_NPTS); put16("ge", ge, FDNS_NPTS); put16("lf", lf, 64);
    PsychAdaptLowFreqDeemph(x, g, ge, with_lf ? lf : NULL);
    arrow(); put32("x", x, 64); put16("lf", lf, 64); end_line();
}

static void case_adapt(void)
{
    static Word32 x[1200];
    Word16 g[FDNS_NPTS], ge[FDNS_NPTS], lf[1200];
    Word16 lg = frame_lengths[random_range(1, 6)];
    Word16 x_e = (Word16)random_range(3, 20);
    Word16 shaped = (Word16)(next_random() & 1);
    int with_lf = !shaped || (next_random() & 1);
    Word32 unit = (Word32)1 << (31 - x_e);
    random_lpc_gains(g, ge);
    /* spectrum lines at integer multiples of the quantiser step, large ones in the low quarter */
    for (int i = 0; i < lg; i++) {
        int r = next_random() % 16;
        Word32 k = r < 9 ? 0 : (r < 13 ? random_range(-2, 2) : random_range(-9, 9));
        if (next_random() % 8 == 0) k = (k < 0 ? -1 : 1) * 4;
        x[i] = k * unit;
    }
    if (next_random() % 6 == 0) for (int i = 0; i < 4; i++) x[i] = 0;
    for (int i = 0; i < lg; i++) lf[i] = 0x4000;
    put1("lg", lg); put1("x_e", x_e); put1("shaped", shaped); put1("with_lf", with_lf);
    put32("x", x, lg); put16("g", g, FDNS_NPTS); put16("ge", ge, FDNS_NPTS);
    AdaptLowFreqDeemph(x, x_e, shaped, g, ge, lg, with_lf ? lf : NULL);
    arrow(); put32("x", x, lg); put16("lf", lf, lg); end_line();
}

static void case_noise_filling(void)
{
    static Word32 q[1200];
    static Word16 info[1200];
    Word16 l_frame = frame_lengths[random_range(2, 6)];
    Word16 q_e = (Word16)random_range(0, 14);
    Word16 seed = random16();
    Word16 first = (Word16)(next_random() & 1 ? l_frame / 8 : idiv1616U(l_frame, 6));
    Word16 lowpass = (Word16)random_range(first + 8, l_frame);
    Word16 trans_width = (Word16)random_range(3, 20);
    Word16 tilt = (Word16)random_range(3072, 32767);
    Word16 fac_ns = (Word16)random_range(1, 32767);
    int with_info = next_random() & 1;
    int density = random_range(1, 12);
    for (int i = 0; i < l_frame; i++) q[i] = (next_random() % 16 < density) ? (Word32)(random32() >> random_range(0, 20)) | 1 : 0;
    memset(info, 0, sizeof(info));
    put1("q_e", q_e); put1("seed", seed); put1("first", first); put1("lowpass", lowpass); put1("trans_width", trans_width);
    put1("l_frame", l_frame); put1("tilt", tilt); put1("fac_ns", fac_ns); put1("with_info", with_info); put32("q", q, l_frame);
    tcx_noise_filling(q, q_e, seed, first, lowpass, trans_width, l_frame, tilt, fac_ns, with_info ? info : NULL);
    arrow(); put32("q", q, l_frame); put16("info", info, with_info ? l_frame : 0); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lpc2mdct")) case_lpc2mdct();
        else if (!strcmp(argv[2], "mdct_shaping")) case_mdct_shaping();
        else if (!strcmp(argv[2], "mdct_shaping_16")) case_mdct_shaping_16();
        else if (!strcmp(argv[2], "mdct_noiseShaping_interp")) case_interp();
        else if (!strcmp(argv[2], "PsychAdaptLowFreqDeemph")) case_psych();
        else if (!strcmp(argv[2], "AdaptLowFreqDeemph")) case_adapt();
        else if (!strcmp(argv[2], "tcx_noise_filling")) case_noise_filling();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
