/* Function-level oracle for lib_com/lpc_tools_fx.c (E_LPC_lev_dur, E_LPC_lev_dur_stab, autocorr_fx). */
#include <math.h>
#include "harness.h"
#include "prot_fx.h"
#include "basop_util.h"

/* Autocorrelations of a real-looking signal in DPF, normalised as the callers do (r[0] scaled to
 * the top bit), or now and then arbitrary DPF values. */
static void random_autocorrelation(Word16 *rh, Word16 *rl, int order)
{
    Word16 x[640];
    int n = random_range(64, 640);
    if (next_random() % 8 == 0) {
        for (int i = 0; i <= order; i++) { rh[i] = random16(); rl[i] = (Word16)random_range(0, 32767); }
        rh[0] = (Word16)random_range(16384, 32767); /* Div_32_opt needs a normalised r[0] */
        return;
    }
    random_signal(x, n, next_random() & 1 ? 8000 : 300);
    double r[25];
    for (int k = 0; k <= order; k++) { r[k] = 0; for (int j = 0; j + k < n; j++) r[k] += (double)x[j] * x[j + k]; }
    if (r[0] <= 0) r[0] = 1;
    r[0] *= 1.0001;
    for (int k = 0; k <= order; k++) {
        double v = r[k] / r[0] * 2147483647.0 * 0.99;
        Word32 l = (Word32)v;
        L_Extract(l, &rh[k], &rl[k]);
    }
}

static void case_lev_dur(void)
{
    Word16 rh[25], rl[25], A[25], mem[25];
    Word32 eps[25];
    int order = next_random() & 1 ? 24 : 16;
    int with_mem = next_random() & 1, with_eps = next_random() & 1;
    Word16 k_max = (Word16)(next_random() & 1 ? 32750 : random_range(20000, 32767));
    random_autocorrelation(rh, rl, order);
    for (int i = 0; i <= order; i++) mem[i] = (Word16)random_range(-8000, 8000);
    put16("rh", rh, order + 1); put16("rl", rl, order + 1); put1("order", order); put1("with_mem", with_mem);
    put1("with_eps", with_eps); put1("k_max", k_max); put16("mem", mem, order + 1);
    Word16 flag = E_LPC_lev_dur_stab(rh, rl, A, with_eps ? eps : NULL, (Word16)order, with_mem ? mem : NULL, k_max);
    arrow(); put16("A", A, order + 1); put1("flag", flag); put16("mem", mem, order + 1);
    if (with_eps) put32("eps", eps, order + 1);
    end_line();
}

/* autocorr_fx over the three windowing modes (reversed, symmetric, asymmetric), signal levels from
 * silent to full scale, and orders 1 to 16. */
static void case_autocorr(void)
{
    Word16 x[960], wind[960], r_h[M + 1], r_l[M + 1], q_r = -99;
    Word16 len = (Word16)(2 * random_range(8, 480)), m = (Word16)(next_random() % 3 ? 16 : random_range(1, 16));
    Word16 rev_flag = (Word16)(next_random() % 3 == 0), sym_flag = (Word16)(next_random() & 1);
    int mag = next_random() % 4 == 0 ? 32767 : 1 << random_range(0, 14);
    random_signal(x, len, mag);
    if (next_random() % 8 == 0) for (int i = 0; i < len; i++) x[i] = random16();
    if (next_random() % 16 == 0) for (int i = 0; i < len; i++) x[i] = 0;
    for (int i = 0; i < len; i++) wind[i] = (Word16)random_range(0, 32767);
    put16("x", x, len); put16("wind", wind, len); put1("m", m); put1("len", len); put1("rev_flag", rev_flag); put1("sym_flag", sym_flag);
    autocorr_fx(x, m, r_h, r_l, &q_r, len, wind, rev_flag, sym_flag);
    arrow(); put16("r_h", r_h, m + 1); put16("r_l", r_l, m + 1); put1("q_r", q_r); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lev_dur")) case_lev_dur();
        else if (!strcmp(argv[2], "autocorr")) case_autocorr();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
