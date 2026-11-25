/* Function-level oracle for the TCX-side LPC helpers of lib_com/lpc_tools_fx.c: E_LPC_schur,
 * E_LPC_lsp_unweight (lsp_reorder is static, proven through it), E_LPC_a_add_tilt and
 * E_LPC_int_lpc_tcx. LSPs are drawn as cosines of ascending LSFs, as the decoder's LSP vectors
 * are; autocorrelations come from real signals, so the Schur recursion's divisions stay in range. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void random_lsp(Word16 *lsp)
{
    Word16 lsf[M];
    int step = 16000 / (M + 1);
    int value = random_range(40, step);
    for (int i = 0; i < M; i++) {
        lsf[i] = (Word16)(value > 16100 ? 16100 : value);
        value += random_range(40, 2 * step - 40);
    }
    for (int i = 0; i < M; i++) lsp[i] = xsf_to_xsp(lsf[i]);
}

static void case_schur(void)
{
    static Word16 x[400];
    Word32 r[M + 1], eps_p[M + 1];
    Word16 refl[M];
    Word16 m = (Word16)(next_random() % 3 ? 8 : random_range(2, M));
    int n = random_range(40, 400);
    random_signal(x, n, random_range(10, 32000));
    if (next_random() % 4 == 0) for (int i = 0; i < n; i++) x[i] = (Word16)(x[i] + random_range(-50, 50));
    /* normalise every lag by the same shift as r[0] */
    {
        long long sum0 = 0;
        for (int i = 0; i < n; i++) sum0 += (long long)x[i] * x[i];
        int shift = 0;
        while ((sum0 >> shift) > 0x3fffffffLL) shift++;
        int scale = random_range(0, 3);
        for (int k = 0; k <= m; k++) {
            long long sum = 0;
            for (int i = 0; i + k < n; i++) sum += (long long)x[i] * x[i + k];
            r[k] = (Word32)((sum >> shift) >> scale);
        }
    }
    if (r[0] <= 0) r[0] = 1;
    memset(eps_p, 0x55, sizeof(eps_p));
    for (int i = 0; i < M; i++) refl[i] = 0x5555;
    put32("r", r, m + 1); put1("m", m);
    Word32 g = E_LPC_schur(r, refl, eps_p, m);
    arrow(); put1("g", g); put32("r", r, m + 1); put16("refl", refl, m); put32("eps_p", eps_p, m + 1); end_line();
}

static void case_unweight(void)
{
    Word16 lsp_w[M], lsp_uw[M], lsf_uw[M];
    Word16 inv_gamma = (Word16)(next_random() & 1 ? GAMMA1_INV : GAMMA16k_INV);
    random_lsp(lsp_w);
    if (next_random() % 6 == 0) for (int i = 0; i < M; i++) lsp_w[i] = (Word16)(lsp_w[i] + random_range(-1500, 1500)); /* near-crossing LSPs: the reorder engages */
    for (int i = 0; i < M; i++) lsp_uw[i] = lsf_uw[i] = 0x5555;
    put16("lsp_w", lsp_w, M); put1("inv_gamma", inv_gamma);
    Word16 r = E_LPC_lsp_unweight(lsp_w, lsp_uw, lsf_uw, inv_gamma, M);
    arrow(); put1("r", r); put16("lsp_uw", lsp_uw, M); put16("lsf_uw", lsf_uw, M); end_line();
}

static void case_add_tilt(void)
{
    Word16 a[M + 1], ap[M + 2];
    int style = random_range(0, 2);
    a[0] = (Word16)(style == 2 ? random16() : (4096 << random_range(0, 2)));
    for (int k = 1; k <= M; k++) a[k] = (Word16)(style == 2 ? random16() : random_range(-12000 / k - 2000, 12000 / k + 2000));
    Word16 gamma = (Word16)(next_random() & 1 ? 22282 : random_range(0, 32767));
    for (int i = 0; i < M + 2; i++) ap[i] = 0x5555;
    put16("a", a, M + 1); put1("gamma", gamma);
    E_LPC_a_add_tilt(a, ap, gamma, M);
    arrow(); put16("ap", ap, M + 2); end_line();
}

static void case_int_lpc(void)
{
    Word16 lsp_old[M], lsp_new[M], a[M + 1];
    random_lsp(lsp_old);
    random_lsp(lsp_new);
    for (int i = 0; i < M + 1; i++) a[i] = 0x5555;
    put16("lsp_old", lsp_old, M); put16("lsp_new", lsp_new, M);
    E_LPC_int_lpc_tcx(lsp_old, lsp_new, a);
    arrow(); put16("a", a, M + 1); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "E_LPC_schur")) case_schur();
        else if (!strcmp(argv[2], "E_LPC_lsp_unweight")) case_unweight();
        else if (!strcmp(argv[2], "E_LPC_a_add_tilt")) case_add_tilt();
        else if (!strcmp(argv[2], "E_LPC_int_lpc_tcx")) case_int_lpc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
