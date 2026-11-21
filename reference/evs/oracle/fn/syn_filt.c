/* Function-level oracle for lib_com/syn_filt_fx.c. The static syn_kern_2/4/6/8/10/24 are proven
 * through E_UTIL_synthesis at the orders that select them (6, 10, 16, 24); syn_kern_16 is public
 * and also checked directly. */
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

static const Word16 orders[] = {6, 10, 16, 24};

static Word16 random_shift(void)
{
    int r = next_random() % 6;
    return (Word16)(r < 2 ? r : (r < 4 ? 1 : random_range(-2, 4)));
}

static Word16 random_lg(Word16 m)
{
    static const Word16 lengths[] = {64, 64, 80, 20, 40, 128};
    Word16 lg = lengths[next_random() % 6];
    if (next_random() % 4 == 0) lg = (Word16)random_range(m, 128);
    return lg < m ? m : lg;
}

/* in_place: 0 separate buffers, 1 x == y; api: 0 E_UTIL_synthesis, 1 Syn_filt_s. */
static void case_synthesis(int in_place, int api)
{
    Word16 a[25], x[128], y[128], mem[24];
    Word16 m = orders[next_random() % 4];
    Word16 shift = random_shift(), lg = random_lg(m), update = (Word16)(next_random() & 1);
    random_lpc(a, m);
    random_input(x, lg);
    random_input(mem, m);
    put1("shift", shift); put16("a", a, m + 1); put16("x", x, lg); put1("lg", lg);
    put16("mem", mem, m); put1("update", update); put1("m", m);
    if (in_place) {
        E_UTIL_synthesis(shift, a, x, x, lg, mem, update, m);
        memcpy(y, x, sizeof(Word16) * lg);
    } else if (api) {
        Syn_filt_s(shift, a, m, x, y, lg, mem, update);
    } else {
        E_UTIL_synthesis(shift, a, x, y, lg, mem, update, m);
    }
    arrow(); put16("y", y, lg); put16("mem", mem, m); end_line();
}

static void case_syn_filt_s_lc(int in_place)
{
    Word16 a[17], x[128], y[128];
    Word16 shift = random_shift();
    Word16 lg = (next_random() & 1) ? 64 : (Word16)random_range(1, 128);
    random_lpc(a, 16);
    random_input(x, lg);
    put1("shift", shift); put16("a", a, 17); put16("x", x, lg); put1("lg", lg);
    if (in_place) {
        syn_filt_s_lc_fx(shift, a, x, x, lg);
        memcpy(y, x, sizeof(Word16) * lg);
    } else {
        syn_filt_s_lc_fx(shift, a, x, y, lg);
    }
    arrow(); put16("y", y, lg); end_line();
}

static void case_syn_kern_16(void)
{
    Word16 a[17], y[17];
    Word32 l_tmp = random32();
    random_lpc(a, 16);
    random_input(y, 17);
    put1("l_tmp", l_tmp); put16("a", a, 17); put16("y", y, 17);
    arrow(); put1("out", syn_kern_16(l_tmp, a, y + 16)); end_line();
}

/* synth_mem_updt2 between the two ACELP core frame lengths (and equal ones), for the decoder's
 * and the encoder's excitation buffer, with and without mem_syn. */
static void case_synth_mem_updt2(void)
{
    Word16 old_exc[L_EXC_MEM_DEC], mem_syn_r[L_SYN_MEM], mem_syn2[M], mem_syn[M];
    Word16 l_frame = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    Word16 last_l_frame = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    Word16 dec = (next_random() % 4) ? DEC : ENC;
    int with_mem_syn = next_random() & 1;
    int n_exc = dec == DEC ? L_EXC_MEM_DEC : L_EXC_MEM;
    random_input(old_exc, n_exc);
    random_input(mem_syn_r, L_SYN_MEM);
    for (int i = 0; i < M; i++) { mem_syn2[i] = random16(); mem_syn[i] = random16(); }
    put1("l_frame", l_frame); put1("last_l_frame", last_l_frame); put1("dec", dec); put1("with_mem_syn", with_mem_syn);
    put16("old_exc", old_exc, n_exc); put16("mem_syn_r", mem_syn_r, L_SYN_MEM); put16("mem_syn", mem_syn, M);
    synth_mem_updt2(l_frame, last_l_frame, old_exc, mem_syn_r, mem_syn2, with_mem_syn ? mem_syn : NULL, dec);
    arrow(); put16("old_exc", old_exc, n_exc); put16("mem_syn_r", mem_syn_r, L_SYN_MEM); put16("mem_syn2", mem_syn2, M);
    put16("mem_syn", mem_syn, M); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "e_util_synthesis")) case_synthesis(0, 0);
        else if (!strcmp(argv[2], "e_util_synthesis_in_place")) case_synthesis(1, 0);
        else if (!strcmp(argv[2], "syn_filt_s")) case_synthesis(0, 1);
        else if (!strcmp(argv[2], "syn_filt_s_lc")) case_syn_filt_s_lc(0);
        else if (!strcmp(argv[2], "syn_filt_s_lc_in_place")) case_syn_filt_s_lc(1);
        else if (!strcmp(argv[2], "syn_kern_16")) case_syn_kern_16();
        else if (!strcmp(argv[2], "synth_mem_updt2")) case_synth_mem_updt2();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
