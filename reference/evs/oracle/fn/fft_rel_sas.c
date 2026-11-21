/* Function-level oracle for lib_com/fft_rel_sas_fx.c. */
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

static void case_fft(int inverse)
{
    Word16 x[256];
    Word16 m = (Word16)random_range(2, 8);
    if (next_random() % 3 == 0) m = 8;
    Word16 n = (Word16)(1 << m);
    random_input(x, n);
    put16("x", x, n); put1("n", n); put1("m", m);
    if (inverse) ifft_rel_fx(x, n, m); else fft_rel_fx(x, n, m);
    arrow(); put16("x", x, n); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "fft_rel")) case_fft(0);
        else if (!strcmp(argv[2], "ifft_rel")) case_fft(1);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
