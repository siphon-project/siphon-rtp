/* Function-level oracle for lib_com/stat_noise_uv_mod_fx.c: stat_noise_uv_mod_fx over runs of
 * consecutive frames (its smoothed gain, LSP average, counters, seed and pre-emphasis memory carry
 * across frames), and calc_tilt_fx / L_Sqrt_Q0 alone. */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_com/stat_noise_uv_mod_fx.c"

#define MAX_FRAMES 8

static void random_lsp(Word16 *lsp)
{
    int value = 32767 - random_range(50, 2500);
    for (int i = 0; i < M; i++) {
        lsp[i] = (Word16)value;
        value -= random_range(300, 65000 / M);
        if (value < -32767) value = -32767 + random_range(0, 10);
    }
}

static void case_stat_noise_uv_mod(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 9600, 8000};
    Word32 ge_sm = next_random() % 4 ? 640 : random_range(0, 1 << 20);
    Word16 uv_count = (Word16)random_range(0, 10), act_count = (Word16)random_range(0, 3);
    Word16 lspold_s[M], seed = (Word16)random16(), min_alpha = (Word16)(next_random() % 3 ? 32767 : random_range(16384, 32767));
    Word16 exc_pe = (Word16)(next_random() % 2 ? 0 : random_range(-3000, 3000));
    Word16 q_stat_noise = (Word16)random_range(-1, 11), q_stat_noise_ge = GE_SHIFT;
    int frames = random_range(1, MAX_FRAMES);
    random_lsp(lspold_s);
    put1("frames", frames); put1("ge_sm", ge_sm); put1("uv_count", uv_count); put1("act_count", act_count);
    put16("lspold_s", lspold_s, M); put1("seed", seed); put1("min_alpha", min_alpha); put1("exc_pe", exc_pe);
    put1("q_stat_noise", q_stat_noise);
    Word16 out_aq[MAX_FRAMES][NB_SUBFR * (M + 1)], out_exc[MAX_FRAMES][L_FRAME];
    Word16 out_state[MAX_FRAMES][12];
    Word32 out_ge[MAX_FRAMES];
    Word16 out_lsp[MAX_FRAMES][M];
    for (int f = 0; f < frames; f++) {
        char name[32];
        Word16 coder_type = (Word16)(next_random() % 4 ? INACTIVE : (next_random() % 2 ? UNVOICED : GENERIC));
        Word16 noisiness = (Word16)random_range(0, 31);
        Word16 bfi = (Word16)(next_random() % 6 == 0);
        Word32 rate = rates[next_random() % 6];
        Word16 bwidth = (Word16)(next_random() % 4 ? WB : NB);
        Word16 q_exc = (Word16)random_range(-3, 13);
        Word16 lsp_old[M], lsp_new[M], lsp_mid[M], exc2[L_FRAME];
        random_lsp(lsp_old); random_lsp(lsp_new); random_lsp(lsp_mid);
        if (next_random() % 8 == 0) for (int i = 0; i < L_FRAME; i++) exc2[i] = random16();
        else if (next_random() % 10 == 0) memset(exc2, 0, sizeof(exc2));
        else random_signal(exc2, L_FRAME, 1 << random_range(2, 15));
        sprintf(name, "f%d", f);
        Word16 params[7] = {coder_type, noisiness, bfi, bwidth, q_exc, (Word16)(rate / 100), 0};
        put16(name, params, 6);
        sprintf(name, "old%d", f); put16(name, lsp_old, M);
        sprintf(name, "new%d", f); put16(name, lsp_new, M);
        sprintf(name, "mid%d", f); put16(name, lsp_mid, M);
        sprintf(name, "exc%d", f); put16(name, exc2, L_FRAME);
        for (int i = 0; i < NB_SUBFR * (M + 1); i++) out_aq[f][i] = -5;
        stat_noise_uv_mod_fx(coder_type, noisiness, lsp_old, lsp_new, lsp_mid, out_aq[f], exc2, q_exc, bfi, &ge_sm, &uv_count,
                             &act_count, lspold_s, &seed, &min_alpha, &exc_pe, rate, bwidth, &q_stat_noise, &q_stat_noise_ge);
        memcpy(out_exc[f], exc2, sizeof(exc2));
        memcpy(out_lsp[f], lspold_s, sizeof(lspold_s));
        out_ge[f] = ge_sm;
        Word16 state[] = {uv_count, act_count, seed, min_alpha, exc_pe, q_stat_noise, q_stat_noise_ge};
        memcpy(out_state[f], state, sizeof(state));
    }
    arrow();
    for (int f = 0; f < frames; f++) {
        char name[32];
        sprintf(name, "aq%d", f); put16(name, out_aq[f], NB_SUBFR * (M + 1));
        sprintf(name, "exc%d", f); put16(name, out_exc[f], L_FRAME);
        sprintf(name, "lspold_s%d", f); put16(name, out_lsp[f], M);
        sprintf(name, "ge_sm%d", f); put1(name, out_ge[f]);
        sprintf(name, "state%d", f); put16(name, out_state[f], 7);
    }
    end_line();
}

static void case_calc_tilt(void)
{
    Word16 x[L_SUBFR];
    Word16 q_shift = (Word16)random_range(0, 8);
    if (next_random() % 4 == 0) for (int i = 0; i < L_SUBFR; i++) x[i] = random16();
    else if (next_random() % 10 == 0) memset(x, 0, sizeof(x));
    else random_signal(x, L_SUBFR, 1 << random_range(0, 15));
    put16("x", x, L_SUBFR); put1("q_shift", q_shift);
    Word16 tilt = calc_tilt_fx(x, q_shift, L_SUBFR);
    arrow(); put1("tilt", tilt); end_line();
}

static void case_l_sqrt_q0(void)
{
    Word32 x = next_random() % 3 ? (Word32)(next_random() >> random_range(0, 30)) : random32();
    put1("x", x);
    Word32 r = L_Sqrt_Q0(x);
    arrow(); put1("r", r); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "stat_noise_uv_mod")) case_stat_noise_uv_mod();
        else if (!strcmp(argv[2], "calc_tilt")) case_calc_tilt();
        else if (!strcmp(argv[2], "l_sqrt_q0")) case_l_sqrt_q0();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
