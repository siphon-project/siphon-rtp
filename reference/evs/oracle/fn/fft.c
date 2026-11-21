/* Function-level oracle for lib_com/fft.c. The static kernels (fft5 .. fft32) and fftN2 are proven
 * through BASOP_cfft, which reaches every one of them: the prime-ish lengths call a kernel directly,
 * the composite ones go through fftN2 and its four second passes. */
#include "harness.h"
#include "prot_fx.h"

void fft16(Word32 *re, Word32 *im, Word16 s, Word16 bScale);

static const Word16 cfft_sizes[] = {5, 8, 10, 16, 20, 30, 32, 40, 64, 80, 100, 120, 128, 160, 200, 240, 256, 320, 400, 480, 600};

/* A Word32 vector at a random headroom: real callers hand the FFT data normalised to a few bits
 * below full scale; a quarter of the cases push to the edges to exercise the saturating adds. */
static void random_data(Word32 *x, int n)
{
    int style = random_range(0, 3);
    int shift = random_range(0, 16);
    for (int i = 0; i < n; i++) {
        if (style == 0) x[i] = random32();
        else if (style == 1) x[i] = (Word32)((next_random() << 1) ^ next_random()) >> shift;
        else x[i] = (Word32)random_range(-32768, 32767) << (16 - shift / 2);
    }
    if (style == 3) {
        Word16 sig[1200];
        random_signal(sig, n, 32767);
        for (int i = 0; i < n; i++) x[i] = (Word32)sig[i] << random_range(8, 15);
    }
}

static void case_basop_cfft(void)
{
    static Word32 re[600], im[600], inter[1200], work[2 * BASOP_CFFT_MAX_LENGTH];
    int n = cfft_sizes[random_range(0, sizeof(cfft_sizes) / sizeof(cfft_sizes[0]) - 1)];
    int stride = (next_random() & 1) ? 2 : 1;
    Word16 scale = (Word16)random_range(-20, 20);
    random_data(re, n);
    random_data(im, n);
    put1("size", n); put1("stride", stride); put1("scale", scale); put32("re", re, n); put32("im", im, n);
    if (stride == 1) {
        BASOP_cfft(re, im, (Word16)n, 1, &scale, work);
    } else {
        for (int i = 0; i < n; i++) { inter[2 * i] = re[i]; inter[2 * i + 1] = im[i]; }
        BASOP_cfft(&inter[0], &inter[1], (Word16)n, 2, &scale, work);
        for (int i = 0; i < n; i++) { re[i] = inter[2 * i]; im[i] = inter[2 * i + 1]; }
    }
    arrow(); put32("re", re, n); put32("im", im, n); put1("scale", scale); end_line();
}

static void case_fft16(void)
{
    Word32 re[16], im[16];
    Word16 bscale = (Word16)(next_random() & 1);
    random_data(re, 16);
    random_data(im, 16);
    put1("bscale", bscale); put32("re", re, 16); put32("im", im, 16);
    fft16(re, im, 1, bscale);
    arrow(); put32("re", re, 16); put32("im", im, 16); end_line();
}

static void case_basop_rfft(void)
{
    static const Word16 forward_sizes[] = {40, 64, 80, 128, 256, 320, 512, 640};
    static const Word16 inverse_sizes[] = {64, 512, 640};
    static Word32 x[640];
    Word16 isign = (next_random() & 1) ? 1 : -1;
    Word16 n = isign < 0 ? forward_sizes[random_range(0, 7)] : inverse_sizes[random_range(0, 2)];
    Word16 scale = (Word16)random_range(-20, 20);
    random_data(x, n);
    put1("size", n); put1("isign", isign); put1("scale", scale); put32("x", x, n);
    BASOP_rfft(x, n, &scale, isign);
    arrow(); put32("x", x, n); put1("scale", scale); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "basop_cfft")) case_basop_cfft();
        else if (!strcmp(argv[2], "fft16")) case_fft16();
        else if (!strcmp(argv[2], "basop_rfft")) case_basop_rfft();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
