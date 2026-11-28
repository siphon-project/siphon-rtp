/* Function-level oracle for lib_com/gs_noisefill_fx.c: the GSC noise fill (gs_noisf_fx,
 * EstimateNoiseLevel_fx / _inner_fx, Apply_NoiseFill_fx), the high-band reshaping
 * (Decreas_freqPeak_fx, envelop_modify_fx), freq_dnw_scaling_fx and the whole
 * highband_exc_dct_in_fx. The static functions are reached by including the source. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "../../c-code/lib_com/gs_noisefill_fx.c"

static const Word32 rates[] = {7200, 8000, 8000, 8000, 9600, 13200, 16400, 22600, 24400, 32000};

/* A quantized GSC spectrum: sparse pulses of a few levels, zero bands, in Q`q`. */
static void random_spectrum(Word16 *x, int n, int q)
{
    int sparse = random_range(1, 6);
    for (int i = 0; i < n; i++) x[i] = 0;
    for (int i = 0; i < n; i++) {
        if (random_range(0, 9) < sparse) {
            int amp = random_range(1, 6) << q;
            if (next_random() % 12 == 0) amp = random_range(1, 32767);
            x[i] = (Word16)(next_random() & 1 ? amp : -amp);
        }
    }
    if (next_random() % 6 == 0) for (int i = random_range(0, n); i < n; i++) x[i] = 0;
}

/* Ascending LSFs in Hz·2.56 (12.8 kHz core: 0..16384). */
static void random_lsf(Word16 *lsf)
{
    int value = random_range(100, 900);
    for (int i = 0; i < M; i++) {
        lsf[i] = (Word16)value;
        value += random_range(150, 1600);
        if (value > 16300) value = 16300;
    }
    /* The first LSF above 4 kHz would make Decreas_freqPeak_fx read lsf_new_diff[-1] and write the 16
     * samples before the spectrum (undefined); a decoded LSF vector never starts that high. The
     * last band boundary is reached when no LSF passes 4 kHz. */
    if (next_random() % 10 == 0) for (int i = 0; i < M; i++) lsf[i] = (Word16)(200 + 600 * i);
    /* exact boundaries: an LSF at 4 kHz (10240), and a run whose spacing halves exactly, so the
     * ratio test meets equality */
    if (next_random() % 8 == 0) lsf[random_range(6, 12)] = 10240;
    if (next_random() % 8 == 0) {
        int d = random_range(400, 1200) * 4, v = random_range(6000, 8000), from = random_range(8, 11);
        for (int i = from; i < M && v < 16000; i++) { lsf[i] = (Word16)v; v += d; d /= 2; if (d < 16) d = 16; }
        for (int i = 1; i < M; i++) if (lsf[i] <= lsf[i - 1]) lsf[i] = (Word16)(lsf[i - 1] + 1);
    }
}

static void case_gs_noisf(void)
{
    static const Word16 widths[] = {8, 16, 32, 2, 4};
    Word16 x[L_FRAME + 32], seed = random16();
    Word16 nb_qbins = widths[next_random() % 5];
    Word16 start = (Word16)random_range(0, L_FRAME - nb_qbins);
    Word16 noise_fac = (Word16)random_range(0, 32767);
    Word16 coder_type = (Word16)(next_random() % 3 ? random_range(0, 5) : INACTIVE);
    Word16 q = (Word16)random_range(0, 14);
    random_spectrum(x, L_FRAME + 32, q > 12 ? 10 : q);
    put1("start", start); put1("nb_qbins", nb_qbins); put1("noise_fac", noise_fac); put16("x", x, L_FRAME + 32);
    put1("seed", seed); put1("coder_type", coder_type); put1("q", q);
    gs_noisf_fx(start, nb_qbins, noise_fac, x, x, &seed, coder_type, q);
    arrow(); put16("x", x, L_FRAME + 32); put1("seed", seed); end_line();
}

static void case_estimate_noise_level(void)
{
    Word16 noisepb[MBANDS_GN];
    Word32 bitrate = rates[next_random() % 10];
    Word16 diff_len = (Word16)(next_random() % 4 ? random_range(0, 255) : random_range(256, 320));
    Word16 mbands = (Word16)random_range(9, MBANDS_GN);
    Word16 coder_type = (Word16)random_range(0, 5);
    Word16 noise_lev = (Word16)random_range(NOISE_LEVEL_SP0 - 1, NOISE_LEVEL_SP3 + 1);
    Word16 pit_band_idx = (Word16)random_range(0, 16);
    Word16 last_bin = (Word16)random_range(0, 16);
    Word16 bwidth = (Word16)random_range(0, 1);
    for (int i = 0; i < MBANDS_GN; i++) noisepb[i] = (Word16)random_range(0, 20000);
    put1("bitrate", bitrate); put1("diff_len", diff_len); put1("mbands", mbands); put1("coder_type", coder_type);
    put1("noise_lev", noise_lev); put1("pit_band_idx", pit_band_idx); put1("last_bin", last_bin); put1("bwidth", bwidth);
    put16("noisepb", noisepb, MBANDS_GN);
    EstimateNoiseLevel_fx(noisepb, bitrate, diff_len, mbands, coder_type, noise_lev, pit_band_idx, last_bin, bwidth);
    arrow(); put16("noisepb", noisepb, MBANDS_GN); end_line();
}

static void case_decreas_freq_peak(void)
{
    static const Word16 rats[] = {9830, 16384};
    Word16 lsf[M], x[L_FRAME];
    Word16 rat = rats[next_random() & 1];
    random_lsf(lsf);
    random_signal(x, L_FRAME, 1 << random_range(4, 14));
    if (next_random() & 1) { int p = random_range(160, L_FRAME - 1); x[p] = (Word16)(next_random() & 1 ? 32000 : -32000); }
    put16("lsf", lsf, M); put16("x", x, L_FRAME); put1("rat", rat);
    Decreas_freqPeak_fx(lsf, x, rat);
    arrow(); put16("x", x, L_FRAME); end_line();
}

static void case_envelop_modify(void)
{
    Word16 x[L_FRAME16k], ener[MBANDS_GN + 8], seed = random16(), q_hb = 77;
    Word16 last_bin = (Word16)(next_random() % 3 ? 10 : 11);
    Word16 q_exc = (Word16)random_range(-1, 12);
    random_signal(x, L_FRAME16k, 1 << random_range(2, 14));
    for (int i = 0; i < MBANDS_GN + 8; i++) ener[i] = (Word16)random_range(-4000, next_random() % 3 ? 14000 : 18000);
    put16("x", x, L_FRAME16k); put1("seed", seed); put1("last_bin", last_bin); put16("ener", ener, MBANDS_GN);
    put1("q_exc", q_exc);
    envelop_modify_fx(x, &seed, last_bin, ener, q_exc, &q_hb);
    arrow(); put16("x", x, L_FRAME16k); put1("seed", seed); put1("q_hb", q_hb); end_line();
}

static void case_freq_dnw_scaling(void)
{
    Word16 x[L_FRAME];
    Word16 cor = (Word16)random_range(0, 1), coder_type = (Word16)random_range(0, 5);
    Word16 noise_lev = (Word16)random_range(NOISE_LEVEL_SP0, NOISE_LEVEL_SP3);
    Word32 core_brate = rates[next_random() % 10];
    Word16 qx = (Word16)random_range(0, 12);
    random_spectrum(x, L_FRAME, qx > 10 ? 10 : qx);
    if (next_random() % 4 == 0) for (int i = 0; i < L_FRAME; i++) x[i] = random16();
    put1("cor", cor); put1("coder_type", coder_type); put1("noise_lev", noise_lev); put1("core_brate", core_brate);
    put1("qx", qx); put16("x", x, L_FRAME);
    freq_dnw_scaling_fx(cor, coder_type, noise_lev, core_brate, x, qx);
    arrow(); put16("x", x, L_FRAME); end_line();
}

static void case_highband(void)
{
    Word16 exc_diffq[L_FRAME16k], exc_dct_in[L_FRAME], ener_iq[MBANDS_GN], band[MBANDS_GN], lsf[M];
    Word16 last_dct[L_FRAME], last_band[6], exc_alloc[2], wo_nf[L_FRAME], lt[MBANDS_GN];
    /* 8 kbit/s wideband (the high-band reshaping) most of the time */
    Word32 core_brate = next_random() % 3 ? ACELP_8k00 : rates[next_random() % 10];
    Word16 bwidth = (Word16)(next_random() % 5 ? WB : NB);
    Word16 last_bin = (Word16)(next_random() % 2 ? random_range(9, 11) : random_range(0, 15));
    Word16 pit_band_idx = (Word16)random_range(0, 15);
    Word16 diff_len = (Word16)(next_random() % 3 ? 0 : mfreq_loc_div_25[pit_band_idx] + (next_random() & 1));
    Word16 noise_lev = (Word16)random_range(NOISE_LEVEL_SP0, NOISE_LEVEL_SP3);
    Word16 seed = random16(), nb_subfr = (Word16)(next_random() % 3 ? 4 : random_range(1, 2));
    Word16 last_coder_type = (Word16)(next_random() & 1 ? AUDIO : random_range(0, 5));
    Word16 coder_type = (Word16)(next_random() % 3 ? AUDIO : random_range(0, 5));
    Word16 last_ener = (Word16)random_range(0, 3000);
    Word16 bfi = (Word16)(next_random() % 6 == 0);
    Word16 with_wo_nf = (Word16)(next_random() & 1);
    Word16 q_diff = Q_PVQ_OUT, q_exc = (Word16)random_range(-1, 10);
    Word16 noisy = (Word16)(next_random() % 5 == 0);
    random_spectrum(exc_diffq, L_FRAME16k, q_diff);
    for (int i = L_FRAME; i < L_FRAME16k; i++) exc_diffq[i] = 0;
    random_signal(exc_dct_in, L_FRAME, 1 << random_range(next_random() % 4 ? 4 : 1, 13));
    random_signal(last_dct, L_FRAME, 1 << random_range(next_random() % 4 ? 4 : 1, 13));
    for (int i = 0; i < MBANDS_GN; i++) {
        ener_iq[i] = (Word16)random_range(-6000, 12000);
        band[i] = (Word16)(next_random() % 3 == 0);
        lt[i] = (Word16)random_range(-6000, 12000);
    }
    /* keep the high band near the previous energy so the smoothing branch runs */
    if (next_random() & 1) { int e = random_range(-1000, 3000); for (int i = 10; i < MBANDS_GN; i++) ener_iq[i] = (Word16)(e + random_range(-300, 300)); }
    /* now and then the previous frame's energy exactly twice this frame's high-band energy (the
     * smoothing test's tie), computed as highband_exc_dct_in_fx computes it */
    if (next_random() % 8 == 0) {
        Word16 ener = 0, exp, frac;
        for (int j = 10; j < MBANDS_GN; j++) {
            Word32 t = L_shr(L_mult(ener_iq[j], 27213), 10);
            frac = L_Extract_lc(t, &exp);
            ener = add(shl(extract_l(Pow2(14, frac)), sub(exp, 14)), ener);
        }
        last_ener = shl(ener, 1);
        last_coder_type = AUDIO;
    }
    for (int i = 0; i < 6; i++) last_band[i] = (Word16)(next_random() % 3 == 0);
    exc_alloc[0] = (Word16)(next_random() % 3 == 0); exc_alloc[1] = (Word16)(next_random() % 3 == 0);
    for (int i = 0; i < L_FRAME; i++) wo_nf[i] = -11;
    random_lsf(lsf);
    /* envelop_modify_fx reads and writes past its arrays for last_bin above 11 (undefined in the
     * reference); keep the 8 kbit/s wideband high-band path inside what it defines */
    if (core_brate == ACELP_8k00 && bwidth != NB && last_coder_type == AUDIO && last_bin > 11) last_bin = (Word16)random_range(9, 11);
    put1("core_brate", core_brate); put1("last_bin", last_bin); put1("diff_len", diff_len); put1("noise_lev", noise_lev);
    put1("pit_band_idx", pit_band_idx); put16("exc_diffq", exc_diffq, L_FRAME16k); put1("seed", seed);
    put16("ener_iq", ener_iq, MBANDS_GN); put1("nb_subfr", nb_subfr); put16("exc_dct_in", exc_dct_in, L_FRAME);
    put1("last_coder_type", last_coder_type); put16("band", band, MBANDS_GN); put16("lsf", lsf, M);
    put16("last_dct", last_dct, L_FRAME); put1("last_ener", last_ener); put16("last_band", last_band, 6);
    put16("exc_alloc", exc_alloc, 2); put1("bfi", bfi); put1("coder_type", coder_type); put1("bwidth", bwidth);
    put1("with_wo_nf", with_wo_nf); put1("q_diff", q_diff); put1("q_exc", q_exc); put1("noisy", noisy); put16("lt", lt, MBANDS_GN);
    highband_exc_dct_in_fx(core_brate, mfreq_bindiv_loc, last_bin, diff_len, noise_lev, pit_band_idx, exc_diffq, &seed,
                           ener_iq, nb_subfr, exc_dct_in, last_coder_type, band, lsf, last_dct, &last_ener, last_band,
                           exc_alloc, bfi, coder_type, bwidth, with_wo_nf ? wo_nf : NULL, q_diff, q_exc, noisy, lt);
    arrow(); put16("exc_diffq", exc_diffq, L_FRAME); put1("seed", seed); put16("ener_iq", ener_iq, MBANDS_GN);
    put16("exc_dct_in", exc_dct_in, L_FRAME); put16("last_dct", last_dct, L_FRAME); put1("last_ener", last_ener);
    put16("last_band", last_band, 6); put16("wo_nf", wo_nf, L_FRAME); put16("lt", lt, MBANDS_GN); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "gs_noisf")) case_gs_noisf();
        else if (!strcmp(argv[2], "estimate_noise_level")) case_estimate_noise_level();
        else if (!strcmp(argv[2], "decreas_freq_peak")) case_decreas_freq_peak();
        else if (!strcmp(argv[2], "envelop_modify")) case_envelop_modify();
        else if (!strcmp(argv[2], "freq_dnw_scaling")) case_freq_dnw_scaling();
        else if (!strcmp(argv[2], "highband")) case_highband();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
