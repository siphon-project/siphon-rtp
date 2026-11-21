/* Function-level oracle for lib_com/est_tilt_fx.c (est_tilt_fx). */
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

static void random_code(Word16 *code)
{
    memset(code, 0, 64 * sizeof(Word16));
    if (next_random() % 4 == 0) { random_input(code, 64); return; }
    int pulses = random_range(1, 24);
    for (int p = 0; p < pulses; p++) code[next_random() % 64] += (Word16)((next_random() & 1 ? 512 : -512) * random_range(1, 3));
}

static void case_est_tilt(void)
{
    Word16 exc[64], code[64], voice_fac = -99;
    random_input(exc, 64);
    random_code(code);
    Word16 gain_pit = (Word16)(next_random() % 6 ? random_range(0, 19661) : random16());
    Word32 gain_code = next_random() % 6 ? L_shr((Word32)random_range(0, 0x7fffffff), (Word16)random_range(0, 30)) : random32();
    Word16 q_exc = (Word16)random_range(-1, 12);
    put16("exc", exc, 64); put1("gain_pit", gain_pit); put16("code", code, 64);
    put1("gain_code", gain_code); put1("q_exc", q_exc);
    Word16 tilt = est_tilt_fx(exc, gain_pit, code, gain_code, &voice_fac, q_exc);
    arrow(); put1("tilt", tilt); put1("voice_fac", voice_fac); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "est_tilt")) case_est_tilt();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
