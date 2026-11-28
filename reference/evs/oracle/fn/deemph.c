/* Function-level oracle for lib_com/deemph_fx.c (deemph_fx, E_UTIL_deemph2). */
/* LP filter / signal input generators, shared in spirit by the filter oracles (kept inline: the
 * reference/evs .gitignore admits only *.c and harness.h here). */
#include "harness.h"

/* LP coefficients a[0..m] in Q12: mostly a[0] = 1.0 and taps of the size real filters have,
 * sometimes a differently normalised a[0], sometimes edge values that saturate the filter. */
static void random_lpc(Word16 *a, int m)
{
    int kind = next_random() % 8;
    a[0] = 4096;
    if (kind == 6) a[0] = (Word16)(next_random() & 1 ? 8192 : 2048);
    if (kind == 7) a[0] = random16();
    for (int k = 1; k <= m; k++) {
        if (kind == 5 || kind == 7) a[k] = random16();
        else a[k] = (Word16)random_range(-12000 / k - 2000, 12000 / k + 2000);
    }
}

/* A signal of a random magnitude, from quiet to full scale, sometimes with edge values mixed in. */
static void random_input(Word16 *x, int n)
{
    static const int magnitudes[] = {50, 600, 4000, 16000, 32767};
    random_signal(x, n, magnitudes[next_random() % 5]);
    if (next_random() % 6 == 0)
        for (int i = 0; i < n; i++)
            if (next_random() % 4 == 0) x[i] = random16();
}
#include "prot_fx.h"

static Word16 random_mu(void)
{
    static const Word16 mus[] = {22282, 23593, 21299, 31130};
    return next_random() % 4 ? mus[next_random() % 4] : random16();
}

static void case_deemph(void)
{
    Word16 signal[640];
    static const Word16 lengths[] = {256, 320, 64, 128, 640};
    Word16 l = lengths[next_random() % 5];
    if (next_random() % 4 == 0) l = (Word16)random_range(1, 640);
    Word16 mu = random_mu(), mem = random16();
    random_input(signal, l);
    put16("signal", signal, l); put1("mu", mu); put1("l", l); put1("mem", mem);
    deemph_fx(signal, mu, l, &mem);
    arrow(); put16("signal", signal, l); put1("mem", mem); end_line();
}

/* E_UTIL_deemph2 as the FD-CNG transition uses it (shift NOISE_HEADROOM) and at other shifts,
 * negative ones included. */
static void case_deemph2(void)
{
    Word16 signal[640];
    static const Word16 lengths[] = {256, 320, 128, 640};
    Word16 l = lengths[next_random() % 4];
    if (next_random() % 4 == 0) l = (Word16)random_range(1, 640);
    Word16 shift = (Word16)(next_random() % 2 ? 5 : random_range(-4, 15));
    Word16 mu = random_mu(), mem = random16();
    random_input(signal, l);
    put16("signal", signal, l); put1("shift", shift); put1("mu", mu); put1("l", l); put1("mem", mem);
    E_UTIL_deemph2(shift, signal, mu, l, &mem);
    arrow(); put16("signal", signal, l); put1("mem", mem); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "deemph")) case_deemph();
        else if (!strcmp(argv[2], "deemph2")) case_deemph2();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
