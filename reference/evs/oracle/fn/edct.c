/* Function-level oracle for lib_com/edct_fx.c. get_edct_table is static and proven through edct_fx,
 * which reaches every length it has a table for. edct_16fx runs at every length it has a table for,
 * 256 (L_FRAME), 320 (L_FRAME16k) and 640 (DCT_L_POST, L_FRAME32k); both edct_fx and edct_16fx are
 * also called in place by the decoder, so a share of the cases alias input and output. */
#include "harness.h"
#include "prot_fx.h"

static const Word16 edct_lengths[] = {1200, 960, 640, 320, 256, 240, 200, 160, 40, 800, 512, 480, 400, 128, 80};

/* Word32 data at a random headroom, as the TCX/HQ spectra reach the transform. */
static void random_data(Word32 *x, int n)
{
    int style = random_range(0, 4);
    int shift = random_range(0, 20);
    for (int i = 0; i < n; i++) {
        if (style == 0) x[i] = random32();
        else if (style == 4) x[i] = 0;
        else x[i] = (Word32)((next_random() << 1) ^ next_random()) >> shift;
    }
    if (style == 3) {
        static Word16 sig[1200];
        random_signal(sig, n, 32767);
        for (int i = 0; i < n; i++) x[i] = (Word32)sig[i] << random_range(0, 15);
    }
}

static void case_edct(void)
{
    static Word32 x[1200], y[1200];
    Word16 length = edct_lengths[random_range(0, 14)];
    Word16 q = (Word16)random_range(-5, 25);
    Word16 in_place = (Word16)(next_random() & 1);
    random_data(x, length);
    put1("length", length); put1("q", q); put1("in_place", in_place); put32("x", x, length);
    if (in_place) {
        edct_fx(x, x, length, &q);
        memcpy(y, x, length * sizeof(Word32));
    } else {
        edct_fx(x, y, length, &q);
    }
    arrow(); put32("y", y, length); put1("q", q); end_line();
}

static void case_edct_16fx(void)
{
    static Word16 x[640], y[640];
    static const Word16 lengths[] = {256, 320, 640};
    Word16 length = lengths[random_range(0, 2)];
    Word16 bh = (Word16)random_range(4, 8);
    Word16 in_place = (Word16)(next_random() & 1);
    int style = random_range(0, 4);
    if (style == 0) for (int i = 0; i < length; i++) x[i] = random16();
    else if (style == 1) memset(x, 0, sizeof(x));
    else random_signal(x, length, random_range(1, 32767));
    put1("length", length); put1("bh", bh); put1("in_place", in_place); put16("x", x, length);
    if (in_place) {
        edct_16fx(x, x, length, bh);
        memcpy(y, x, length * sizeof(Word16));
    } else {
        edct_16fx(x, y, length, bh);
    }
    arrow(); put16("y", y, length); end_line();
}

static void case_iedct_short(void)
{
    static const Word16 segments[] = {80, 160, 320, 480, 640, 960};
    static Word32 in[480], out[960];
    Word16 segment_length = segments[random_range(0, 5)];
    Word16 q = (Word16)random_range(-5, 25);
    random_data(in, segment_length / 2);
    memset(out, 0, sizeof(out));
    put1("segment_length", segment_length); put1("q", q); put32("in", in, segment_length / 2);
    iedct_short_fx(in, &q, out, segment_length);
    arrow(); put32("out", out, segment_length); put1("q", q); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "edct")) case_edct();
        else if (!strcmp(argv[2], "edct_16fx")) case_edct_16fx();
        else if (!strcmp(argv[2], "iedct_short")) case_iedct_short();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
