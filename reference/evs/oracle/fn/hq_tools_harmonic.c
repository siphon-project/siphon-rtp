/* Function-level oracle for the harmonic and HVQ bandwidth extensions of lib_com/hq_tools_fx.c
 * (hq_swb_harmonic_calc_norm_envelop_fx, harm_bwe_fine_fx, hvq_bwe_fine_fx, harm_bwe_fx, hvq_bwe_fx,
 * noise_mix_fx). The file is included so a coverage build of this harness measures it. Inputs follow
 * fill_spectrum_fx: the harmonic band layout (31 SWB / 33 FB bands), last_sfm from the HQ bit
 * allocation, Q12 spectra, norms 0..39, the fine structure from the *_fine functions or random. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "../../c-code/lib_com/hq_tools_fx.c"

static Word16 random_norm(void) { return (Word16)(next_random() % 6 == 0 ? 39 : random_range(0, 39)); }

/* A Q12 spectrum of a random magnitude, with silent stretches and occasional edges. */
static void random_spectrum32(Word32 *x, int n)
{
    int kind = next_random() % 8, shift = random_range(4, 30);
    for (int i = 0; i < n; i++) {
        if (kind == 0) x[i] = 0;
        else if (kind == 1) x[i] = random32();
        else if (kind == 2) x[i] = next_random() % 6 ? 0 : (Word32)((next_random() << 16) ^ next_random()) >> random_range(4, 20);
        else x[i] = (Word32)((next_random() << 16) ^ next_random()) >> shift;
    }
}

static void random_spectrum16(Word16 *x, int n)
{
    int kind = next_random() % 7;
    /* full scale, so the widest bands of the harmonic layout reach the top normalisation of the noise level */
    if (kind == 6) { for (int i = 0; i < n; i++) x[i] = (Word16)(next_random() & 1 ? 32767 : -32768); return; }
    if (kind == 0) { for (int i = 0; i < n; i++) x[i] = 0; return; }
    if (kind == 1) { for (int i = 0; i < n; i++) x[i] = random16(); return; }
    random_signal(x, n, 1 << random_range(2, 15));
    for (int i = 0; i < n; i++) if (next_random() & 1) x[i] = (Word16)-x[i];
}

/* Band allocation as the HQ bit allocation leaves it: some coded bands, many zero. */
static void random_alloc(Word16 *r, int n)
{
    int density = random_range(0, 4);
    for (int i = 0; i < n; i++) r[i] = (Word16)(random_range(0, 4) < density ? random_range(1, 60) : 0);
}

typedef struct {
    Word16 num_sfm, last_sfm, high_sfm;
    Word32 core_brate;
} Layout;

static void harmonic_layout(Layout *l)
{
    l->num_sfm = next_random() & 1 ? SFM_N_HARM : SFM_N_HARM_FB;
    l->core_brate = next_random() & 1 ? HQ_24k40 : HQ_32k;
    l->high_sfm = l->core_brate == HQ_24k40 ? HVQ_THRES_SFM_24k - 1 : HVQ_THRES_SFM_32k - 1;
    l->last_sfm = (Word16)random_range(l->high_sfm, l->num_sfm - 1);
    if (next_random() % 3 == 0) l->last_sfm = l->high_sfm;
}

static void case_calc_norm_envelop(void)
{
    static Word32 sig[L_FRAME48k], env[L_FRAME48k];
    Word16 norm = (Word16)random_range(1, 100), len = L_HARMONIC_EXC;
    if (next_random() % 4 == 0) len = (Word16)random_range(norm, 400);
    random_spectrum32(sig, len);
    for (int i = 0; i < L_FRAME48k; i++) env[i] = -7;
    put32("sig", sig, len); put1("norm", norm); put1("len", len);
    hq_swb_harmonic_calc_norm_envelop_fx(sig, env, norm, len);
    arrow(); put32("env", env, len); end_line();
}

static void case_harm_bwe_fine(void)
{
    Layout l;
    harmonic_layout(&l);
    Word16 r[NB_SFM], norm[NB_SFM], coeff[L_FRAME48k], fine[L_FRAME48k];
    Word32 out[L_FRAME48k];
    Word16 prev = (Word16)random_range(0, 80);
    random_alloc(r, l.num_sfm);
    for (int i = 0; i < l.num_sfm; i++) norm[i] = random_norm();
    random_spectrum16(coeff, L_FRAME48k);
    random_spectrum32(out, L_FRAME48k);
    for (int i = 0; i < L_FRAME48k; i++) fine[i] = -7;
    put16("r", r, l.num_sfm); put1("last_sfm", l.last_sfm); put1("high_sfm", l.high_sfm); put1("num_sfm", l.num_sfm);
    put16("norm", norm, l.num_sfm); put1("prev", prev); put16("coeff", coeff, L_FRAME48k); put32("out", out, L_FRAME48k);
    harm_bwe_fine_fx(r, l.last_sfm, l.high_sfm, l.num_sfm, norm, band_start_harm, band_end_harm, &prev, coeff, out, fine);
    arrow(); put1("prev", prev); put32("out", out, L_FRAME48k); put16("fine", fine, L_FRAME48k); end_line();
}

/* HVQ: last_sfm = nb_sfm - 1, peaks inside the coded region. */
static void hvq_layout(Layout *l)
{
    l->num_sfm = next_random() & 1 ? SFM_N_HARM : SFM_N_HARM_FB;
    l->core_brate = next_random() & 1 ? HQ_24k40 : HQ_32k;
    l->last_sfm = l->core_brate == HQ_24k40 ? HVQ_THRES_SFM_24k - 1 : HVQ_THRES_SFM_32k - 1;
    l->high_sfm = l->last_sfm;
}

static void random_hvq_spectrum(Word32 *x, Word16 *peak_idx, Word16 *npeaks, int coded)
{
    random_spectrum32(x, L_FRAME48k);
    int kind = next_random() % 3;
    if (kind == 0) for (int i = 0; i < L_FRAME48k; i++) x[i] = next_random() % 3 ? 0 : x[i] >> random_range(0, 16);
    *npeaks = (Word16)(next_random() % 8 == 0 ? 0 : random_range(1, HVQ_MAX_PEAKS_32k));
    for (int i = 0; i < *npeaks; i++) {
        peak_idx[i] = (Word16)(next_random() % 5 == 0 ? random_range(0, coded) : random_range(0, L_HARMONIC_EXC + 20));
        if (kind != 1) x[peak_idx[i]] = (next_random() & 1 ? 1 : -1) * (Word32)random_range(1 << 12, 1 << 22);
    }
}

static void case_hvq_bwe_fine(void)
{
    Layout l;
    hvq_layout(&l);
    static Word32 x[L_FRAME48k];
    Word16 peak_idx[HVQ_MAX_PEAKS_32k], npeaks, peak_pos[L_HARMONIC_EXC], bwe_peaks[L_FRAME48k], fine[L_FRAME48k];
    Word16 prev = (Word16)random_range(0, 80);
    random_hvq_spectrum(x, peak_idx, &npeaks, band_end_harm[l.last_sfm]);
    for (int i = 0; i < L_HARMONIC_EXC; i++) peak_pos[i] = 0;
    for (int i = 0; i < L_FRAME48k; i++) { bwe_peaks[i] = 0; fine[i] = -7; }
    put1("last_sfm", l.last_sfm); put1("num_sfm", l.num_sfm); put16("peak_idx", peak_idx, npeaks);
    put1("npeaks", npeaks); put1("prev", prev); put32("x", x, L_FRAME48k);
    hvq_bwe_fine_fx(l.last_sfm, l.num_sfm, band_end_harm, peak_idx, npeaks, peak_pos, &prev, x, bwe_peaks, fine);
    arrow(); put1("prev", prev); put16("peak_pos", peak_pos, L_HARMONIC_EXC); put16("bwe_peaks", bwe_peaks, L_FRAME48k);
    put16("fine", fine, L_FRAME48k); end_line();
}

/* limit_band_noise_level_calc_fx and hvq_dec_fx produce 0..8192 (0.25); the smoothed previous level
 * stays below 32767 (at most 4 x 8191 after the boost), which keeps the div_l of harm_bwe_fx off a
 * zero denominator (the STL exits on one). */
static void random_noise_levels(Word16 *nl, Word16 *prev)
{
    for (int k = 0; k < 2; k++) {
        nl[k] = (Word16)(next_random() % 5 == 0 ? (next_random() & 1 ? 0 : 8192) : random_range(0, 8192));
        prev[k] = (Word16)(next_random() % 5 == 0 ? random_range(0, 32764) : random_range(0, 9000));
    }
    /* the boundary values of the smoothing: a level that lands on exactly 0.25 (8192), and a silent history */
    if (next_random() % 8 == 0) { nl[0] = nl[1] = 8192; prev[0] = prev[1] = 8192; }
    if (next_random() % 8 == 0) { prev[0] = 0; prev[1] = 0; if (next_random() & 1) { nl[0] = 0; nl[1] = 0; } }
}

static void case_harm_bwe(void)
{
    Layout l;
    harmonic_layout(&l);
    Word16 r[NB_SFM], norm[NB_SFM], coeff[L_FRAME48k], fine[L_FRAME48k], nl[2], pnl[2];
    static Word32 out[L_FRAME48k];
    Word16 prev_mode = (Word16)random_range(0, 5), seed = random16();
    random_alloc(r, l.num_sfm);
    for (int i = 0; i < l.num_sfm; i++) norm[i] = random_norm();
    random_spectrum16(coeff, L_FRAME48k);
    random_spectrum32(out, L_FRAME48k);
    if (next_random() % 3) {
        Word16 prev_len = (Word16)random_range(0, 80);
        harm_bwe_fine_fx(r, l.last_sfm, l.high_sfm, l.num_sfm, norm, band_start_harm, band_end_harm, &prev_len, coeff, out, fine);
    } else random_spectrum16(fine, L_FRAME48k);
    random_noise_levels(nl, pnl);
    put16("fine", fine, L_FRAME48k); put16("coeff", coeff, L_FRAME48k); put1("num_sfm", l.num_sfm);
    put1("last_sfm", l.last_sfm); put16("r", r, l.num_sfm); put1("prev_mode", prev_mode); put16("norm", norm, l.num_sfm);
    put16("nl", nl, 2); put16("pnl", pnl, 2); put1("seed", seed); put32("out", out, L_FRAME48k);
    harm_bwe_fx(fine, coeff, l.num_sfm, band_start_harm, band_end_harm, l.last_sfm, r, prev_mode, norm, nl, pnl, &seed, out);
    arrow(); put16("nl", nl, 2); put16("pnl", pnl, 2); put1("seed", seed); put32("out", out, L_FRAME48k); end_line();
}

static void case_hvq_bwe(void)
{
    Layout l;
    hvq_layout(&l);
    static Word32 x[L_FRAME48k];
    Word16 peak_idx[HVQ_MAX_PEAKS_32k], npeaks, peak_pos[L_HARMONIC_EXC], bwe_peaks[L_FRAME48k], fine[L_FRAME48k];
    Word16 r[NB_SFM], norm[NB_SFM], nl[2], pnl[2];
    Word16 prev_mode = (Word16)random_range(0, 5), seed = random16(), prev_len = (Word16)random_range(0, 80);
    random_hvq_spectrum(x, peak_idx, &npeaks, band_end_harm[l.last_sfm]);
    for (int i = 0; i < L_HARMONIC_EXC; i++) peak_pos[i] = 0;
    for (int i = 0; i < L_FRAME48k; i++) { bwe_peaks[i] = 0; fine[i] = 0; }
    if (next_random() % 4) hvq_bwe_fine_fx(l.last_sfm, l.num_sfm, band_end_harm, peak_idx, npeaks, peak_pos, &prev_len, x, bwe_peaks, fine);
    else { random_spectrum16(fine, L_FRAME48k); for (int i = 0; i < L_FRAME48k; i++) bwe_peaks[i] = next_random() % 20 == 0; }
    /* the HVQ allocation: the core bands coded, the BWE bands mostly not */
    for (int i = 0; i < l.num_sfm; i++) r[i] = i <= l.last_sfm ? (Word16)random_range(0, 40) : (next_random() % 6 == 0 ? (Word16)random_range(1, 40) : 0);
    for (int i = 0; i < l.num_sfm; i++) norm[i] = random_norm();
    random_noise_levels(nl, pnl);
    if (next_random() % 10 == 0) for (int i = 0; i < L_FRAME48k; i++) fine[i] = 0;
    Word16 bin_th = band_end_harm[l.last_sfm];
    put16("fine", fine, L_FRAME48k); put1("last_sfm", l.last_sfm); put1("prev_mode", prev_mode); put16("bwe_peaks", bwe_peaks, L_FRAME48k);
    put1("bin_th", bin_th); put1("num_sfm", l.num_sfm); put1("core_brate", l.core_brate); put16("r", r, l.num_sfm);
    put16("norm", norm, l.num_sfm); put16("nl", nl, 2); put16("pnl", pnl, 2); put1("seed", seed); put32("out", x, L_FRAME48k);
    /* fill_spectrum_fx passes L_coeff_out as both L_coeff and L_coeff_out */
    hvq_bwe_fx(x, fine, band_start_harm, band_end_harm, band_len_harm, l.last_sfm, prev_mode, bwe_peaks, bin_th, l.num_sfm,
               l.core_brate, r, norm, nl, pnl, &seed, x, 15, 12);
    arrow(); put16("norm", norm, l.num_sfm); put16("nl", nl, 2); put16("pnl", pnl, 2); put1("seed", seed);
    put32("out", x, L_FRAME48k); end_line();
}

static void case_noise_mix(void)
{
    static Word16 fine[L_FRAME48k];
    static Word32 out[L_FRAME48k];
    Word16 offset = (Word16)(next_random() & 1 ? 0 : random_range(0, 320));
    Word16 istart = (Word16)random_range(offset, L_FRAME48k - 1), iend = (Word16)random_range(istart, L_FRAME48k);
    Word32 l_e = next_random() % 4 ? (Word32)random_range(1, 0x7fffffff) >> random_range(0, 30) : random32() & 0x7fffffff;
    Word32 normq = dicn_fx[random_norm()];
    Word16 seed = random16(), nl = (Word16)(next_random() % 4 ? random_range(0, 32767) : random16() & 0x7fff);
    random_spectrum16(fine, L_FRAME48k);
    random_spectrum32(out, L_FRAME48k);
    put16("fine", fine, L_FRAME48k); put1("offset", offset); put1("l_e", l_e); put1("normq", normq); put1("seed", seed);
    put1("istart", istart); put1("iend", iend); put1("nl", nl); put32("out", out, L_FRAME48k);
    noise_mix_fx(&fine[-offset], l_e, normq, &seed, istart, iend, nl, out, 15, 12);
    arrow(); put1("seed", seed); put32("out", out, L_FRAME48k); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq_swb_harmonic_calc_norm_envelop")) case_calc_norm_envelop();
        else if (!strcmp(argv[2], "harm_bwe_fine")) case_harm_bwe_fine();
        else if (!strcmp(argv[2], "hvq_bwe_fine")) case_hvq_bwe_fine();
        else if (!strcmp(argv[2], "harm_bwe")) case_harm_bwe();
        else if (!strcmp(argv[2], "hvq_bwe")) case_hvq_bwe();
        else if (!strcmp(argv[2], "noise_mix")) case_noise_mix();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
