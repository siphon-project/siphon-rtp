/* Function-level oracle for the 16-bit FFTs of lib_com/fft_fx.c. The source is included so its static
 * helpers (cdftForw_16fx, fft64_16fx, fft5_shift4_16fx, ...) are reachable. bitrv2_SR_16fx,
 * cftfsub_16fx, cft1st_16fx and cftmdl_16fx are proven through cdftForw_16fx. */
#include "harness.h"
#include "../../c-code/lib_com/fft_fx.c"

/* Real-looking data at a random magnitude, or full-scale noise to drive the saturating adds. */
static void fill(Word16 *x, int n)
{
    int mode = random_range(0, 3);
    if (mode == 0) random_signal(x, n, random_range(1, 32767));
    else if (mode == 1) for (int i = 0; i < n; i++) x[i] = random16();
    else if (mode == 2) for (int i = 0; i < n; i++) x[i] = (Word16)random_range(-2000, 2000);
    else { int s = random_range(0, 15); for (int i = 0; i < n; i++) x[i] = (Word16)((Word16)next_random() >> s); }
}

static void case_do_rtft128(void)
{
    Word16 x[128], y[128];
    fill(x, 128); fill(y, 128);
    put16("x", x, 128); put16("y", y, 128);
    DoRTFT128_16fx(x, y);
    arrow(); put16("x", x, 128); put16("y", y, 128); end_line();
}

static void case_do_rtft320(void)
{
    Word16 x[320], y[320];
    fill(x, 320); fill(y, 320);
    put16("x", x, 320); put16("y", y, 320);
    DoRTFT320_16fx(x, y);
    arrow(); put16("x", x, 320); put16("y", y, 320); end_line();
}

static void case_do_rtft160(void)
{
    Word16 x[160], y[160];
    fill(x, 160); fill(y, 160);
    put16("x", x, 160); put16("y", y, 160);
    DoRTFT160_16fx(x, y);
    arrow(); put16("x", x, 160); put16("y", y, 160); end_line();
}

static void case_cdft_forw(void)
{
    Word16 a[256];
    static const Word16 lengths[] = {256, 128, 64};
    Word16 n = lengths[random_range(0, 2)];
    fill(a, n);
    put1("n", n); put16("a", a, n);
    if (n == 256) cdftForw_16fx(n, a, Ip_fft128_16fx, w_fft128_16fx);
    else if (n == 128) cdftForw_16fx(n, a, Ip_fft64_16fx, w_fft64_16fx);
    else cdftForw_16fx(n, a, Ip_fft32_16fx, w_fft32_16fx);
    arrow(); put16("a", a, n); end_line();
}

static void case_fft64(void)
{
    Word16 x[320], y[320];
    Word16 j = (Word16)random_range(0, 4);
    fill(x, 320); fill(y, 320);
    put1("j", j); put16("x", x, 320); put16("y", y, 320);
    fft64_16fx(x, y, Idx_dortft320_16fx + 64 * j);
    arrow(); put16("x", x, 320); put16("y", y, 320); end_line();
}

static void case_fft5_shift4(void)
{
    Word16 x[320], y[320];
    Word16 j = (Word16)random_range(0, 63);
    fill(x, 320); fill(y, 320);
    put1("j", j); put16("x", x, 320); put16("y", y, 320);
    fft5_shift4_16fx(64, x, y, Idx_dortft320_16fx + j);
    arrow(); put16("x", x, 320); put16("y", y, 320); end_line();
}

static void case_fft32_5(void)
{
    Word16 x[160], y[160];
    Word16 j = (Word16)random_range(0, 4);
    fill(x, 160); fill(y, 160);
    put1("j", j); put16("x", x, 160); put16("y", y, 160);
    fft32_5_16fx(x, y, Idx_dortft160 + 32 * j);
    arrow(); put16("x", x, 160); put16("y", y, 160); end_line();
}

static void case_fft5_32(void)
{
    Word16 x[160], y[160];
    Word16 j = (Word16)random_range(0, 31);
    fill(x, 160); fill(y, 160);
    put1("j", j); put16("x", x, 160); put16("y", y, 160);
    fft5_32_16fx(x, y, Idx_dortft160 + j);
    arrow(); put16("x", x, 160); put16("y", y, 160); end_line();
}

/* edct2_fx at the decoder's one length (64, the AVQ pre-quantiser's DCT), both directions. This
 * proves the 32-bit kernels bitrv2_SR_fx, cftfsub_fx, cftbsub_fx, cft1st_fx, cftmdl_fx, rftfsub_fx,
 * rftbsub_fx and dctsub_fx. */
static void case_edct2(void)
{
    Word16 in[64];
    Word32 a[64];
    Word16 q = 0;
    Word16 isgn = (next_random() & 1) ? 1 : -1;
    fill(in, 64);
    if (next_random() % 4 == 0) for (int i = 0; i < 64; i++) in[i] = (Word16)((Word16)random_range(-40, 40) << 10);
    put1("isgn", isgn); put16("in", in, 64);
    edct2_fx(64, isgn, in, a, &q, ip_edct2_64_fx, w_edct2_64_fx);
    arrow(); put32("a", a, 64); put1("q", q); end_line();
}

/* fft3_fx / ifft3_fx in place at the two lengths the phase ECU uses. */
static void case_fft3(int inverse)
{
    static Word16 x[1536];
    Word16 n = next_random() & 1 ? 384 : 1536;
    fill(x, n);
    put1("n", n); put16("x", x, n);
    if (inverse) ifft3_fx(x, x, n); else fft3_fx(x, x, n);
    arrow(); put16("x", x, n); end_line();
}
static void case_fft3_fwd(void) { case_fft3(0); }
static void case_ifft3(void) { case_fft3(1); }

/* DoRTFTn_fx at every length, the input scaled as fec_ecu_dft_fx does (a 16-bit signal shifted to
 * leave the FFT its headroom, zero imaginary part), or arbitrary 32-bit data now and then. */
static void case_do_rtftn(void)
{
    static Word32 x[512], y[512];
    static Word16 s16[512];
    Word16 n = (Word16)(16 << random_range(0, 5));
    int mode = random_range(0, 3);
    fill(s16, n);
    Word16 e = add(Exp16Array(n, s16), add(2, norm_s(n)));
    for (int i = 0; i < n; i++) {
        if (mode == 0) { x[i] = random32(); y[i] = random32(); }
        else if (mode == 1) { x[i] = (Word32)s16[i] << (e > 16 ? 16 : e); y[i] = 0; }
        else { x[i] = L_shl(s16[i], e); y[i] = 0; }
    }
    put1("n", n); put32("x", x, n); put32("y", y, n);
    DoRTFTn_fx(x, y, n);
    arrow(); put32("x", x, n); put32("y", y, n); end_line();
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*fn)(void); } table[] = {
        {"fft3", case_fft3_fwd}, {"ifft3", case_ifft3}, {"do_rtftn", case_do_rtftn},
        {"do_rtft128", case_do_rtft128}, {"do_rtft320", case_do_rtft320}, {"cdft_forw", case_cdft_forw},
        {"fft64", case_fft64}, {"fft5_shift4", case_fft5_shift4}, {"do_rtft160", case_do_rtft160},
        {"fft32_5", case_fft32_5}, {"fft5_32", case_fft5_32}, {"edct2", case_edct2},
    };
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (size_t t = 0; t < sizeof(table) / sizeof(table[0]); t++) {
        if (strcmp(argv[2], table[t].name)) continue;
        for (long i = 0, n = atol(argv[3]); i < n; i++) table[t].fn();
        return 0;
    }
    fprintf(stderr, "unknown function %s\n", argv[2]);
    return 2;
}
