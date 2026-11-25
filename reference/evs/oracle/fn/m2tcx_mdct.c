/* Function-level oracle for lib_com/tcx_mdct.c (TCX_MDCT, TCX_MDST, TCX_MDCT_Inverse; the two static
 * scale-factor helpers are proven through them) and the DST-IV edst_fx of lib_com/edct_fx.c (alone and
 * in place, as TCX_MDST calls it). The transform length l/2+m+r/2 is one the edct tables cover; l and r
 * are even and at most L_MDCT_OVLP_MAX, m is even, as the decoder's window lengths are. */
#include "harness.h"
#include "prot_fx.h"

static const Word16 lengths[] = {1200, 960, 640, 320, 256, 240, 200, 160, 40, 800, 512, 480, 400, 128, 80};

static void random_data32(Word32 *x, int n)
{
    int style = random_range(0, 4);
    int shift = random_range(0, 20);
    for (int i = 0; i < n; i++) {
        if (style == 0) x[i] = random32();
        else if (style == 4) x[i] = 0;
        else x[i] = (Word32)((next_random() << 1) ^ next_random()) >> shift;
    }
}

static void random_data16(Word16 *x, int n)
{
    int style = random_range(0, 3);
    if (style == 0) for (int i = 0; i < n; i++) x[i] = random16();
    else if (style == 1) memset(x, 0, n * sizeof(Word16));
    else random_signal(x, n, random_range(1, 32767));
}

/* l, m, r with l/2 + m + r/2 = length, l and r even, m even and non-negative. */
static void random_lmr(Word16 length, Word16 *l, Word16 *m, Word16 *r)
{
    for (;;) {
        int cap = length / 2 < 210 ? length / 2 : 210; /* L_MDCT_OVLP_MAX/2: the overlaps of the decoder, which size tmp_buf */
        int a = random_range(0, cap), b = random_range(0, cap);
        if (next_random() % 4 == 0) a = 0;
        if (next_random() % 4 == 0) b = 0;
        int mid = length - a - b;
        if (mid < 0 || (mid & 1)) continue;
        *l = (Word16)(2 * a); *r = (Word16)(2 * b); *m = (Word16)mid;
        return;
    }
}

static void case_edst(void)
{
    static Word32 x[1200], y[1200];
    Word16 length = lengths[random_range(0, 14)];
    Word16 q = (Word16)random_range(-5, 25);
    Word16 in_place = (Word16)(next_random() & 1);
    random_data32(x, length);
    put1("length", length); put1("q", q); put1("in_place", in_place); put32("x", x, length);
    if (in_place) {
        edst_fx(x, x, length, &q);
        memcpy(y, x, length * sizeof(Word32));
    } else {
        edst_fx(x, y, length, &q);
    }
    arrow(); put32("y", y, length); put1("q", q); end_line();
}

static void case_forward(int sine)
{
    static Word16 x[3000];
    static Word32 y[1200];
    Word16 length = lengths[random_range(0, 14)], l, m, r;
    random_lmr(length, &l, &m, &r);
    Word16 y_e = (Word16)random_range(-5, 15);
    random_data16(x, l + m + r);
    memset(y, 0, sizeof(y));
    put1("l", l); put1("m", m); put1("r", r); put1("y_e", y_e); put16("x", x, l + m + r);
    if (sine) TCX_MDST(x, y, &y_e, l, m, r); else TCX_MDCT(x, y, &y_e, l, m, r);
    arrow(); put32("y", y, length); put1("y_e", y_e); end_line();
}

static void case_inverse(void)
{
    static Word32 x[1200];
    static Word16 y[3000];
    Word16 length = lengths[random_range(0, 14)], l, m, r;
    random_lmr(length, &l, &m, &r);
    Word16 x_e = (Word16)random_range(-5, 25);
    random_data32(x, length);
    memset(y, 0, sizeof(y));
    put1("l", l); put1("m", m); put1("r", r); put1("x_e", x_e); put32("x", x, length);
    TCX_MDCT_Inverse(x, x_e, y, l, m, r);
    arrow(); put16("y", y, l + m + r); put32("x", x, length); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "edst")) case_edst();
        else if (!strcmp(argv[2], "TCX_MDCT")) case_forward(0);
        else if (!strcmp(argv[2], "TCX_MDST")) case_forward(1);
        else if (!strcmp(argv[2], "TCX_MDCT_Inverse")) case_inverse();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
