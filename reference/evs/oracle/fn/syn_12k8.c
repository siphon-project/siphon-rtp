/* Function-level oracle for lib_com/syn_12k8_fx.c. */
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

static void case_syn_12k8(void)
{
    Word16 aq[5 * 17], exc[320], synth[320], mem[16];
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320);
    Word16 update_m = (Word16)(next_random() & 1);
    Word16 q_exc = (Word16)random_range(-1, 12), q_syn = (Word16)random_range(-1, 3);
    for (int s = 0; s < l_frame / 64; s++) random_lpc(aq + 17 * s, 16);
    random_input(exc, l_frame);
    random_input(mem, 16);
    put1("l_frame", l_frame); put16("aq", aq, 17 * (l_frame / 64)); put16("exc", exc, l_frame);
    put16("mem", mem, 16); put1("update_m", update_m); put1("q_exc", q_exc); put1("q_syn", q_syn);
    syn_12k8_fx(l_frame, aq, exc, synth, mem, update_m, q_exc, q_syn);
    arrow(); put16("synth", synth, l_frame); put16("mem", mem, 16); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "syn_12k8")) case_syn_12k8();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
