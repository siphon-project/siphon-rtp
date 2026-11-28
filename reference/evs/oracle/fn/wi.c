/* Function-level oracle for lib_com/wi_fx.c (the waveform interpolation the MODE1 decoder's FEC fast
 * recovery reaches). WIsyn_fx is run in both alignment modes, which proves DTFS_copy_fx,
 * DTFS_alignment_weight_fx, DTFS_alignment_full_fx (FR), DTFS_adjustLag_fx, DTFS_getEngy_fx,
 * DTFS_setEngy_fx, DTFS_zeroPadd_fx, poleFilter_setup_fx, DTFS_poleFilter_fx_9, DTFS_zeroFilter_fx,
 * DTFS_phaseShift_fx, cubicPhase_fx, DTFS_transform_fx, DTFS_fast_fs_inv_fx and the inverse
 * r_fft_4_fx / c_fft_wi_fx through it; the forward FFT and the non-FR alignment are cased directly,
 * and so are the pieces whose faults WIsyn_fx's output can hide (cubicPhase_fx, DTFS_transform_fx,
 * DTFS_adjustLag_fx, the pole / zero filters, DTFS_alignment_weight_fx). */
#include "harness.h"
#include "../../c-code/lib_com/wi_fx.c" /* cubicPhase_fx is static */

#define TAB (PIT_MAX * 4 + 1)

static void put_dtfs(const char *prefix, const DTFS_STRUCTURE_FX *x)
{
    char name[64];
    snprintf(name, sizeof name, "%s_a", prefix); put16(name, x->a_fx, MAXLAG_WI);
    snprintf(name, sizeof name, "%s_b", prefix); put16(name, x->b_fx, MAXLAG_WI);
    Word16 s[7] = {x->lag_fx, x->nH_fx, x->nH_4kHz_fx, x->upper_cut_off_freq_of_interest_fx,
                   x->upper_cut_off_freq_fx, x->Fs_fx, x->Q};
    snprintf(name, sizeof name, "%s_s", prefix); put16(name, s, 7);
}

/* One pitch cycle of excitation-like signal: a pulse plus decaying noise at a random level. */
static void cycle(Word16 *x, int n)
{
    int mode = random_range(0, 3);
    int level = 1 << random_range(4, 14);
    if (mode == 0) random_signal(x, n, level);
    else if (mode == 1) for (int i = 0; i < n; i++) x[i] = random16();
    else {
        for (int i = 0; i < n; i++) x[i] = (Word16)random_range(-level / 16, level / 16);
        int p = random_range(0, n - 1);
        x[p] = (Word16)(next_random() & 1 ? level : -level);
        if (p + 1 < n) x[p + 1] = (Word16)(-level / 2);
    }
    if (mode == 3) for (int i = 0; i < n; i++) x[i] = 0;
}

/* A prototype as the decoder builds one: DTFS_to_fs_fx of a pitch cycle, with its Q offset. */
static void prototype(DTFS_STRUCTURE_FX *x, Word16 lag, Word16 *S, Word16 *C)
{
    Word16 sig[2 * MAXLAG_WI];
    cycle(sig, lag);
    GetSinCosTab_fx(lag, S, C);
    DTFS_to_fs_fx(sig, lag, x, 16000, 1, S, C);
    x->Q = add(x->Q, (Word16)random_range(-1, 12));
}

static Word16 random_lag(void) { return (Word16)(next_random() % 4 ? random_range(34, 149) : random_range(17, 160)); }

static void case_get_sin_cos_tab(void)
{
    Word16 S[TAB], C[TAB];
    Word16 l = (Word16)random_range(1, PIT_MAX);
    put1("l", l);
    GetSinCosTab_fx(l, S, C);
    arrow(); put16("s", S, 4 * l); put16("c", C, 4 * l); end_line();
}

static void case_dtfs_to_fs(void)
{
    Word16 S[TAB], C[TAB], x[2 * MAXLAG_WI];
    DTFS_STRUCTURE_FX *X = DTFS_new_fx();
    Word16 n = random_lag();
    static const Word16 rates[] = {8000, 16000, 32000, (Word16)48000};
    Word16 fs = rates[next_random() % 4];
    Word16 fr_flag = (Word16)(next_random() % 3 ? 1 : 0);
    cycle(x, n);
    GetSinCosTab_fx(n, S, C);
    put16("x", x, n); put1("fs", fs); put1("fr_flag", fr_flag);
    DTFS_to_fs_fx(x, n, X, fs, fr_flag, S, C);
    arrow(); put_dtfs("x", X); end_line();
    free(X);
}

/* WIsyn_fx over two prototypes of independent lags, both alignment modes, every frame length. */
static void case_wi_syn(void)
{
    Word16 S[TAB], C[TAB], out[L_FRAME16k], lpc[M + 1];
    Word16 pf_temp1[MAXLAG_WI], pf_temp2[MAXLAG_WI], pf_temp[MAXLAG_WI], pf_n2[MAXLAG_WI];
    DTFS_STRUCTURE_FX *prev = DTFS_new_fx(), *curr = DTFS_new_fx();
    Word16 prev_lag = random_lag(), curr_lag = random_lag();
    if (next_random() % 6 == 0) curr_lag = prev_lag;
    prototype(prev, prev_lag, S, C);
    prototype(curr, curr_lag, S, C);
    GetSinCosTab_fx(curr_lag, S, C);
    Word16 fr_flag = (Word16)(next_random() & 1);
    Word16 n = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 ph_offset = (Word16)(next_random() % 3 ? 0 : random_range(0, 32767));
    lpc[0] = 4096;
    for (int i = 1; i <= M; i++) lpc[i] = (Word16)random_range(-6000 * (M + 1 - i) / M, 6000 * (M + 1 - i) / M);
    put_dtfs("prev", prev); put_dtfs("curr", curr); put1("fr_flag", fr_flag); put1("n", n);
    put1("ph_offset", ph_offset); put16("lpc", lpc, M + 1);
    WIsyn_fx(*prev, curr, lpc, &ph_offset, out, n, fr_flag, S, C, pf_temp1, pf_temp2, pf_temp, pf_n2);
    arrow(); put16("out", out, n); put1("ph_offset", ph_offset); put_dtfs("curr", curr); end_line();
    free(prev);
    free(curr);
}

/* DTFS_alignment_full_fx in both modes (WIsyn_fx only ever passes the FR one). */
static void case_dtfs_alignment_full(void)
{
    Word16 S[TAB], C[TAB];
    DTFS_STRUCTURE_FX *x1 = DTFS_new_fx(), *x2 = DTFS_new_fx();
    Word16 lag1 = random_lag(), lag2 = random_lag();
    prototype(x1, lag1, S, C);
    prototype(x2, lag2, S, C);
    GetSinCosTab_fx(lag2, S, C);
    Word16 ph_offset = (Word16)random_range(0, 32767);
    Word16 fr_flag = (Word16)(next_random() & 1);
    put_dtfs("x1", x1); put_dtfs("x2", x2); put1("ph_offset", ph_offset); put1("fr_flag", fr_flag);
    Word16 shift = DTFS_alignment_full_fx(*x1, *x2, ph_offset, S, C, fr_flag);
    arrow(); put1("shift", shift); end_line();
    free(x1);
    free(x2);
}

/* r_fft_4_fx in both directions at the 256 points DTFS_fast_fs_inv_fx uses. */
static void case_r_fft_4(void)
{
    Word16 x[257];
    Word16 isign = (Word16)(next_random() & 1 ? 1 : -1);
    int level = 1 << random_range(2, 15);
    for (int i = 0; i < 256; i++) x[i] = (Word16)random_range(-level, level - 1);
    if (next_random() % 4 == 0) for (int i = 0; i < 256; i++) x[i] = random16();
    put1("isign", isign); put16("x", x, 256);
    r_fft_4_fx(x, 256, 7, isign);
    arrow(); put16("x", x, 256); end_line();
}

/* The pieces under WIsyn_fx, directly: their outputs are normalised or only steer an arg-max
 * there, so a fault in them can hide in WIsyn_fx's output. */
static void random_lpc(Word16 *lpc)
{
    lpc[0] = 4096;
    for (int i = 1; i <= M; i++) lpc[i] = (Word16)random_range(-6000 * (M + 1 - i) / M, 6000 * (M + 1 - i) / M);
}

static void case_cubic_phase(void)
{
    Word32 ph[WI_FX_phase_fx];
    Word16 ph1 = (Word16)random_range(0, 32767), ph2 = (Word16)random_range(-32768, 32767);
    Word16 l1 = random_lag(), l2 = random_lag();
    Word16 n = (Word16)(next_random() % 3 ? (next_random() & 1 ? L_FRAME : L_FRAME16k) : random_range(l2 + 2, 2 * L_FRAME));
    /* a period shorter than the second lag: N = n - l2 is negative, the sign branches of the cubic's coefficients */
    if (next_random() % 6 == 0) n = (Word16)random_range(1, l2 - 1);
    put1("ph1", ph1); put1("ph2", ph2); put1("l1", l1); put1("l2", l2); put1("n", n);
    for (int i = 0; i < WI_FX_phase_fx; i++) ph[i] = 0x5a5a5a5a;
    cubicPhase_fx(ph1, ph2, l1, l2, n, ph);
    arrow(); put32("ph", ph, n); end_line();
}

static void case_dtfs_transform(void)
{
    Word16 S[TAB], C[TAB], out[2 * L_FRAME];
    Word32 phase[WI_FX_phase_fx];
    DTFS_STRUCTURE_FX *x = DTFS_new_fx(), *x2 = DTFS_new_fx();
    Word16 lag1 = random_lag(), lag2 = random_lag();
    prototype(x, lag1, S, C);
    prototype(x2, lag2, S, C);
    x->Q = x2->Q;
    /* N above both lags always (the reference divides by lag - N, and cubicPhase_fx by N - L2); within
     * 20 samples of X.lag the weight is linear rather than exponential. */
    Word16 top = lag1 > lag2 ? lag1 : lag2;
    Word16 n = (Word16)(next_random() & 1 ? random_range(top + 1, top + 40) : random_range(top + 1, 2 * L_FRAME));
    Word16 fr_flag = (Word16)(next_random() & 1);
    cubicPhase_fx((Word16)random_range(0, 32767), (Word16)random_range(0, 32767), lag1, lag2, n, phase);
    put_dtfs("x", x); put_dtfs("x2", x2); put32("phase", phase, n); put1("n", n); put1("fr_flag", fr_flag);
    DTFS_transform_fx(*x, *x2, phase, out, n, fr_flag);
    arrow(); put16("out", out, n); end_line();
    free(x);
    free(x2);
}

static void case_dtfs_adjust_lag(void)
{
    Word16 S[TAB], C[TAB];
    DTFS_STRUCTURE_FX *x = DTFS_new_fx();
    Word16 lag = random_lag();
    prototype(x, lag, S, C);
    if (next_random() & 1) { x->upper_cut_off_freq_fx = 4000; x->upper_cut_off_freq_of_interest_fx = 3300; }
    Word16 n = next_random() % 4 ? random_lag() : lag;
    if (next_random() % 3 == 0) {
        /* a prototype with harmonics above lag / 2 (the band-limited ones of a frame-recovery prototype hold up to
         * 0.625 lag of them) */
        int harmonics = lag / 2 + random_range(1, 24);
        if (harmonics > MAXLAG_WI - 1) harmonics = MAXLAG_WI - 1;
        x->nH_fx = (Word16)harmonics;
        for (int i = lag / 2 + 1; i <= harmonics; i++) { x->a_fx[i] = random16(); x->b_fx[i] = random16(); }
    }
    put_dtfs("x", x); put1("n", n);
    DTFS_adjustLag_fx(x, n);
    arrow(); put_dtfs("x", x); end_line();
    free(x);
}

static void case_pole_zero_filter(void)
{
    Word16 S[TAB], C[TAB], lpc[M + 1];
    Word16 pf_temp1[MAXLAG_WI], pf_temp2[MAXLAG_WI], pf_temp[MAXLAG_WI], pf_n2[MAXLAG_WI];
    DTFS_STRUCTURE_FX *x = DTFS_new_fx(), *y = DTFS_new_fx();
    Word16 lag = random_lag();
    prototype(x, lag, S, C);
    GetSinCosTab_fx(lag, S, C);
    random_lpc(lpc);
    DTFS_copy_fx(y, *x);
    put_dtfs("x", x); put16("lpc", lpc, M + 1);
    poleFilter_setup_fx(lpc, M + 1, *x, S, C, pf_temp1, pf_temp2, pf_temp, pf_n2);
    DTFS_poleFilter_fx_9(x, pf_temp1, pf_temp2, pf_temp, pf_n2);
    DTFS_zeroFilter_fx(y, lpc, M + 1, S, C);
    int h = s_min(shr(lag, 1), x->nH_fx) + 1;
    if (h < 0) h = 0;
    arrow(); put16("pf_temp1", pf_temp1, h); put16("pf_temp2", pf_temp2, h); put16("pf_temp", pf_temp, h);
    put16("pf_n2", pf_n2, h); put_dtfs("pole", x); put_dtfs("zero", y); end_line();
    free(x);
    free(y);
}

static void case_dtfs_alignment_weight(void)
{
    Word16 S[TAB], C[TAB], lpc1[M + 1], lpc2[M + 1];
    Word16 pf_temp1[MAXLAG_WI], pf_temp2[MAXLAG_WI], pf_temp[MAXLAG_WI], pf_n2[MAXLAG_WI];
    DTFS_STRUCTURE_FX *x1 = DTFS_new_fx(), *x2 = DTFS_new_fx();
    Word16 lag1 = random_lag(), lag2 = random_lag();
    prototype(x1, lag1, S, C);
    prototype(x2, lag2, S, C);
    GetSinCosTab_fx(lag2, S, C);
    random_lpc(lpc1);
    random_lpc(lpc2);
    Word16 eshift = (Word16)random_range(0, lag2 * 128 - 1);
    put_dtfs("x1", x1); put_dtfs("x2", x2); put1("eshift", eshift); put16("lpc1", lpc1, M + 1); put16("lpc2", lpc2, M + 1);
    Word16 shift = DTFS_alignment_weight_fx(x1, *x2, eshift, lpc1, lpc2, S, C, pf_temp1, pf_temp2, pf_temp, pf_n2);
    arrow(); put1("shift", shift); put_dtfs("x1", x1); end_line();
    free(x1);
    free(x2);
}

/* ---- the QPPP prototype dequantiser (SC-VBR PPP frames) and its spectral helpers ---- */

/* A prototype in the polar domain with the cut-off frequencies and harmonic counts a PPP frame of
 * the given bandwidth class has. */
static void ppp_prototype(DTFS_STRUCTURE_FX *x, Word16 lag, Word16 *S, Word16 *C)
{
    prototype(x, lag, S, C);
    int wide = (int)(next_random() % 2);
    x->upper_cut_off_freq_of_interest_fx = (Word16)(wide ? 4000 : 3300);
    x->upper_cut_off_freq_fx = (Word16)(wide ? 6400 : 4000);
    x->nH_fx = (Word16)((x->upper_cut_off_freq_fx * lag) / 12800);
    x->nH_4kHz_fx = (Word16)((4000 * lag) / 12800);
    if (x->nH_fx > lag / 2) x->nH_fx = (Word16)(lag / 2);
}

static Word16 ppp_lag(void) { return (Word16)(next_random() % 4 ? random_range(34, 150) : random_range(20, 201)); }

static void case_ppp_car2pol(void)
{
    Word16 S[TAB], C[TAB];
    DTFS_STRUCTURE_FX *x = DTFS_new_fx();
    ppp_prototype(x, ppp_lag(), S, C);
    put_dtfs("x", x);
    DTFS_car2pol_fx(x);
    arrow(); put_dtfs("x", x); end_line();
    free(x);
}

static void case_ppp_set_engy_harm(void)
{
    Word16 S[TAB], C[TAB], qa = -99;
    DTFS_STRUCTURE_FX *x = DTFS_new_fx();
    ppp_prototype(x, ppp_lag(), S, C);
    if (next_random() % 4 == 0) {
        /* a loud prototype: the sum of squares of the harmonics saturates the 32-bit accumulator */
        for (int i = 1; i <= x->nH_fx && i < MAXLAG_WI; i++) {
            x->a_fx[i] = (Word16)random_range(16000, 32767);
            x->b_fx[i] = (Word16)random_range(-32768, 32767);
        }
    }
    if (next_random() & 1) DTFS_car2pol_fx(x);
    int band = (int)(next_random() % 3);
    Word16 f1 = band == 0 ? 236 : 2828, f2 = band == 0 ? 2828 : 0x2800, g1 = band == 0 ? 0 : 2828, g2 = band == 0 ? 2828 : 0x4000;
    if (band == 2) { f1 = 2828; f2 = 0x2100; g2 = 0x2800; }
    Word32 en2 = next_random() % 4 == 0 ? (Word32)random_range(1, 1000) : (Word32)(next_random() & 0x7fffffff) >> random_range(0, 20);
    Word16 qen2 = (Word16)random_range(0, 40);
    put_dtfs("x", x); put1("f1", f1); put1("f2", f2); put1("g1", g1); put1("g2", g2); put1("en2", en2); put1("qen2", qen2);
    Word32 r = DTFS_setEngyHarm_fx(f1, f2, g1, g2, en2, qen2, &qa, x);
    arrow(); put1("r", r); put1("qa", qa); put_dtfs("x", x); end_line();
    free(x);
}

static void case_ppp_rshift_harm_band(void)
{
    Word16 S[TAB], C[TAB];
    DTFS_STRUCTURE_FX *x = DTFS_new_fx();
    ppp_prototype(x, ppp_lag(), S, C);
    Word16 lband = (Word16)(next_random() & 1 ? 0 : 2828), hband = (Word16)(lband == 0 ? 2828 : (next_random() & 1 ? 0x4000 : 0x2800));
    Word16 shift = (Word16)random_range(-6, 6);
    put_dtfs("x", x); put1("lband", lband); put1("hband", hband); put1("shift", shift);
    rshiftHarmBand_fx(x, lband, hband, shift);
    arrow(); put_dtfs("x", x); end_line();
    free(x);
}

static void case_ppp_to_erb(void)
{
    Word16 S[TAB], C[TAB], out[24];
    DTFS_STRUCTURE_FX *x = DTFS_new_fx();
    ppp_prototype(x, ppp_lag(), S, C);
    DTFS_car2pol_fx(x);
    for (int i = 0; i < 24; i++) out[i] = -777;
    put_dtfs("x", x);
    DTFS_to_erb_fx(*x, out);
    arrow(); put16("out", out, 24); end_line();
    free(x);
}

static void case_ppp_q2phase_shift(void)
{
    Word16 S[TAB], C[TAB];
    DTFS_STRUCTURE_FX *x = DTFS_new_fx();
    Word16 lag = ppp_lag();
    ppp_prototype(x, lag, S, C);
    Word16 ph = (Word16)(4 * random_range(-60, 60) + (next_random() % 4 ? 0 : random_range(0, 3)));
    put_dtfs("x", x); put1("ph", ph);
    Q2phaseShift_fx(x, ph, lag, S, C);
    arrow(); put_dtfs("x", x); end_line();
    free(x);
}

static void case_ppp_copy_phase(void)
{
    Word16 S[TAB], C[TAB];
    DTFS_STRUCTURE_FX *x1 = DTFS_new_fx(), *x2 = DTFS_new_fx(), *ret = DTFS_new_fx();
    Word16 lag = ppp_lag();
    ppp_prototype(x1, lag, S, C);
    ppp_prototype(x2, lag, S, C);
    DTFS_car2pol_fx(x2);
    put_dtfs("x1", x1); put_dtfs("x2", x2);
    copy_phase_fx(x1, *x2, ret);
    arrow(); put_dtfs("ret", ret); end_line();
    free(x1); free(x2); free(ret);
}

static void case_ppp_dequant_cw(void)
{
    Word16 amp_idx[2], lasterb[24], pl = ppp_lag(), lag = ppp_lag();
    DTFS_STRUCTURE_FX *x = DTFS_new_fx();
    int wide = (int)(next_random() % 2);
    Word16 num_erb = (Word16)(wide ? 24 : 22);
    Word16 power_idx = (Word16)random_range(0, 63);
    amp_idx[0] = (Word16)random_range(0, 63); amp_idx[1] = (Word16)random_range(0, 63);
    Word16 last_l = (Word16)random_range(-3000, 8000), last_h = (Word16)random_range(-3000, 8000);
    /* loud previous gains: the target energy 10^(gain/20 - log10(lag)) then exceeds 2^16 and saturates */
    if (next_random() % 4 == 0) { last_l = (Word16)random_range(12000, 20000); last_h = (Word16)random_range(12000, 20000); }
    for (int i = 0; i < 24; i++) lasterb[i] = (Word16)random_range(0, 20000);
    /* as ppp_quarter_decoder_fx hands them over: cut-off frequencies normalised to 12800 in Q15 */
    Word16 of_interest = (Word16)(wide ? 4000 : 3300), upper = (Word16)(wide ? 6400 : 4000);
    x->lag_fx = lag;
    x->upper_cut_off_freq_of_interest_fx = (Word16)L_shr(L_mult(of_interest, 10486), 13);
    x->upper_cut_off_freq_fx = (Word16)L_shr(L_mult(upper, 10486), 13);
    x->nH_fx = (Word16)((upper * lag) / 12800);
    if (x->nH_fx > lag / 2) x->nH_fx = (Word16)(lag / 2);
    x->nH_4kHz_fx = (Word16)((4000 * lag) / 12800);
    put_dtfs("x", x); put1("pl", pl); put1("power_idx", power_idx); put16("amp_idx", amp_idx, 2);
    put1("last_l", last_l); put1("last_h", last_h); put16("lasterb", lasterb, 24); put1("num_erb", num_erb);
    DTFS_dequant_cw_fx(pl, power_idx, amp_idx, &last_l, &last_h, lasterb, x, num_erb);
    arrow(); put_dtfs("x", x); put1("last_l", last_l); put1("last_h", last_h); put16("lasterb", lasterb, 24); end_line();
    free(x);
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*fn)(void); } table[] = {
        {"get_sin_cos_tab", case_get_sin_cos_tab}, {"dtfs_to_fs", case_dtfs_to_fs}, {"wi_syn", case_wi_syn},
        {"dtfs_alignment_full", case_dtfs_alignment_full}, {"r_fft_4", case_r_fft_4},
        {"cubic_phase", case_cubic_phase}, {"dtfs_transform", case_dtfs_transform},
        {"dtfs_adjust_lag", case_dtfs_adjust_lag}, {"pole_zero_filter", case_pole_zero_filter},
        {"dtfs_alignment_weight", case_dtfs_alignment_weight},
        {"ppp_car2pol", case_ppp_car2pol}, {"ppp_set_engy_harm", case_ppp_set_engy_harm},
        {"ppp_rshift_harm_band", case_ppp_rshift_harm_band}, {"ppp_to_erb", case_ppp_to_erb},
        {"ppp_q2phase_shift", case_ppp_q2phase_shift}, {"ppp_copy_phase", case_ppp_copy_phase},
        {"ppp_dequant_cw", case_ppp_dequant_cw},
    };
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (size_t t = 0; t < sizeof(table) / sizeof(table[0]); t++) {
        if (strcmp(argv[2], table[t].name)) continue;
        for (long i = 0, n = atol(argv[3]); i < n; i++) table[t].fn();
        return 0;
    }
    fprintf(stderr, "unknown function %s\n", argv[2]);
    return 2;
}
