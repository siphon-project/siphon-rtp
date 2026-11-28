/* Function-level oracle for lib_com/residu_fx.c. */
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

static void case_residu3(void)
{
    Word16 a[17], buffer[16 + 128], y[128];
    Word16 lg = (next_random() & 1) ? 64 : (Word16)random_range(1, 128);
    Word16 shift = (Word16)(next_random() % 3 == 0 ? 0 : 1);
    if (next_random() % 8 == 0) shift = (Word16)random_range(-2, 3);
    random_lpc(a, 16);
    random_input(buffer, 16 + lg);
    put16("a", a, 17); put16("x", buffer, 16 + lg); put1("lg", lg); put1("shift", shift);
    Residu3_fx(a, buffer + 16, y, lg, shift);
    arrow(); put16("y", y, lg); end_line();
}

static void case_residu3_lc(void)
{
    Word16 a[17], x[128], y[128];
    Word16 m = (Word16)(next_random() & 1 ? 16 : 10);
    Word16 lg = (next_random() & 1) ? 64 : (Word16)random_range(1, 128);
    Word16 shift = (Word16)random_range(-2, 3);
    random_lpc(a, m);
    random_input(x, lg);
    put16("a", a, m + 1); put1("m", m); put16("x", x, lg); put1("lg", lg); put1("shift", shift);
    Residu3_lc_fx(a, m, x, y, lg, shift);
    arrow(); put16("y", y, lg); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "residu3")) case_residu3();
        else if (!strcmp(argv[2], "residu3_lc")) case_residu3_lc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
