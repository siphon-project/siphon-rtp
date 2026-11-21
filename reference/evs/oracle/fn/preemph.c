/* Function-level oracle for lib_com/preemph_fx.c (preemph_copy_fx). */
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

static void case_preemph_copy(int in_place)
{
    Word16 x[640], y[640];
    static const Word16 mus[] = {22282, 23593, 21299};
    static const Word16 lengths[] = {256, 320, 400, 64};
    Word16 lg = lengths[next_random() % 4];
    if (next_random() % 4 == 0) lg = (Word16)random_range(1, 640);
    Word16 mu = next_random() % 4 ? mus[next_random() % 3] : random16(), mem = random16();
    random_input(x, lg);
    put16("x", x, lg); put1("mu", mu); put1("lg", lg); put1("mem", mem);
    if (in_place) {
        preemph_copy_fx(x, x, mu, lg, &mem);
        memcpy(y, x, sizeof(Word16) * lg);
    } else {
        preemph_copy_fx(x, y, mu, lg, &mem);
    }
    arrow(); put16("y", y, lg); put1("mem", mem); end_line();
}

/* E_UTIL_f_preemph2 / 3 as SynthesisSTFT calls them: mu 0.68, M + frameSize samples. */
static void case_preemph23(int three)
{
    Word16 x[640];
    static const Word16 lengths[] = {16 + 256, 16 + 320};
    Word16 lg = next_random() % 4 ? lengths[next_random() % 2] : (Word16)random_range(1, 640);
    Word16 mu = next_random() % 4 ? 22282 : random16(), mem = random16();
    Word16 shift = (Word16)random_range(-4, 12), bits = (Word16)random_range(0, 3), q = -99;
    random_input(x, lg);
    if (next_random() % 4 == 0) { /* near-silence: preemph3 then scales by the full Q_MAX */
        random_signal(x, lg, random_range(1, 12));
        mem = (Word16)random_range(-4, 4);
    }
    put16("x", x, lg); put1("mu", mu); put1("lg", lg); put1("mem", mem); put1("shift", shift); put1("bits", bits);
    if (three) q = E_UTIL_f_preemph3(x, mu, lg, &mem, bits);
    else E_UTIL_f_preemph2(shift, x, mu, lg, &mem);
    arrow(); put16("y", x, lg); put1("mem", mem); put1("q", q); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "preemph_copy")) case_preemph_copy(0);
        else if (!strcmp(argv[2], "preemph_copy_in_place")) case_preemph_copy(1);
        else if (!strcmp(argv[2], "preemph2")) case_preemph23(0);
        else if (!strcmp(argv[2], "preemph3")) case_preemph23(1);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
