/* Function-level oracle for the harmonic analysis, envelope smoothing and HF synthesis helpers of
 * lib_com/swb_bwe_com_lr_fx.c (div_s_ss, har_est_fx, est_freq_har_decis_fx, genhf_noise_fx,
 * SpectrumSmoothing_fx, spectrumsmooth_noiseton_fx, convert_lagIndices_pls2smp_fx, GetlagGains_fx,
 * GetPredictedSignal_fx, GetSynthesizedSpecThinOut_fx, get_sigma_fx_har,
 * FindNBiggest2_simple_fx_har, preset_hq2_swb_fx, post_hq2_swb_fx).
 *
 * Band layouts come from hq2_core_configure_fx and hf_parinitiz_fx at the two SWB low-rate HQ
 * bit rates, the only ones swb_bwe_dec_lr_fx runs at; spectra look like what hq_lr_dec_fx hands it
 * (Q12, sparse decoded pulses, harmonic trains for the harmonic class, noise-filled gaps). */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_com/swb_bwe_com_lr_fx.c"

/* Larger than the decoder's N_NBIGGEST_SEARCH_LRG_B (32), so a placement the decoder never makes
 * stays inside the array here and both sides can be compared on it. */
#define PK_SLOTS 64

typedef struct {
    Word32 bwe_br;
    Word16 bands, length, band_width[BANDS_MAX], band_start[BANDS_MAX], band_end[BANDS_MAX];
    Word16 p2a_bands;
} Config;

static void random_config(Config *c)
{
    Word32 qint;
    Word16 eref, baw, gqlevs, ngq, p2a_th, pd, ld, ni;
    c->bwe_br = next_random() & 1 ? HQ_13k20 : HQ_16k40;
    hq2_core_configure_fx(L_FRAME32k, (Word16)random_range(200, 340), 0, &c->bands, &c->length, c->band_width,
                          c->band_start, c->band_end, &qint, &eref, &baw, &gqlevs, &ngq, &c->p2a_bands, &p2a_th,
                          &pd, &ld, &ni, c->bwe_br);
}

typedef struct {
    Word16 low, high, har_bands, wbands[NB_SWB_SUBBANDS], nbands, nbands_search, swb_low, swb_high;
    const Word16 *search_offset, *offsets;
} Layout;

static void layout_for(const Config *c, Word16 clas, Layout *l)
{
    Word32 m[L_FRAME32k];
    l->har_bands = 0;
    preset_hq2_swb_fx(clas, c->band_end, &l->har_bands, c->p2a_bands, c->length, c->bands, &l->low, &l->high, m);
    l->search_offset = subband_search_offsets_fx;
    hf_parinitiz_fx(c->bwe_br, clas, l->low, l->high, l->wbands, &l->search_offset, &l->offsets, &l->nbands,
                    &l->nbands_search, &l->swb_low, &l->swb_high);
}

/* A decoded low band in Q12: sparse pulses of decoded-looking magnitude, a harmonic train for
 * the harmonic class, sometimes nothing at all, sometimes edge values. */
static void random_spectrum(Word32 *x, int n, int harmonic)
{
    int kind = next_random() % 8;
    memset(x, 0, n * sizeof(Word32));
    if (kind == 0) return;
    if (kind == 1) {
        for (int i = 0; i < n; i++) x[i] = (next_random() % 3 == 0) ? random32() : 0;
        return;
    }
    if (harmonic || kind < 4) {
        int spacing = random_range(8, 90), at = random_range(0, spacing + 80), jitter = random_range(0, 3);
        while (at < n) {
            int pos = at + random_range(-jitter, jitter);
            if (pos >= 0 && pos < n) {
                Word32 mag = (Word32)random_range(1 << 10, 1 << random_range(12, 24));
                x[pos] = next_random() & 1 ? mag : -mag;
                if (next_random() % 4 == 0 && pos + 1 < n) x[pos + 1] = x[pos] / random_range(2, 8);
            }
            at += spacing;
        }
    }
    int extra = random_range(0, kind == 7 ? n / 2 : n / 16);
    for (int e = 0; e < extra; e++) {
        int pos = random_range(0, n - 1);
        Word32 mag = (Word32)random_range(1, 1 << random_range(4, 22));
        x[pos] = next_random() & 1 ? mag : -mag;
    }
}

/* The spectrum after noise filling: every gap gets low-level noise. */
static void noise_filled(const Word32 *x, Word32 *ni, int n)
{
    int level = 1 << random_range(6, 14);
    for (int i = 0; i < n; i++)
        ni[i] = x[i] != 0 ? x[i] : (next_random() % 4 ? (Word32)random_range(-level, level) : 0);
}

static void put_items(const char *name, const GainItem_fx *items, int n)
{
    printf(" %s=", name);
    for (int i = 0; i < n; i++) printf(i ? ",%d,%d" : "%d,%d", items[i].nmrValue_fx, items[i].gainIndex_fx);
}

static void random_items(GainItem_fx *items, int n)
{
    for (int i = 0; i < n; i++) { items[i].nmrValue_fx = random16(); items[i].gainIndex_fx = random16(); }
}

static void case_div_s_ss(void)
{
    static const Word16 edges[] = {0, 1, 2, 3, 7, 10, 16, 80, 255, 256, 16383, 16384, 32766, 32767};
    Word16 n = next_random() & 1 ? edges[next_random() % 14] : (Word16)(next_random() & 0x7fff);
    Word16 d = next_random() & 1 ? edges[next_random() % 14] : (Word16)random_range(0, next_random() & 1 ? 100 : 32767);
    if (next_random() % 4 == 0) n = (Word16)random_range(0, 1000);
    put1("n", n); put1("d", d);
    arrow(); put1("r", div_s_ss(n, d)); end_line();
}

static void case_get_predicted_signal(void)
{
    Word16 pred[L_FRAME32k];
    Word32 out[L_FRAME32k];
    random_signal(pred, L_FRAME32k, 12000);
    for (int i = 0; i < L_FRAME32k; i += random_range(1, 40)) pred[i] = random16();
    for (int i = 0; i < L_FRAME32k; i++) out[i] = random32();
    Word16 len = (Word16)random_range(0, 320), lag = (Word16)random_range(0, L_FRAME32k - len);
    Word16 gain = next_random() & 1 ? 0x7fff : random16(), qgain = (Word16)random_range(0, 31);
    put16("pred", pred, L_FRAME32k); put32("out", out, L_FRAME32k); put1("lag", lag); put1("len", len);
    put1("gain", gain); put1("qgain", qgain);
    GetPredictedSignal_fx(pred, out, lag, len, gain, qgain);
    arrow(); put32("out", out, L_FRAME32k); end_line();
}

static void case_est_freq_har_decis(void)
{
    Word16 k = (Word16)random_range(0, 12), k1 = (Word16)random_range(0, 5), k2 = (Word16)random_range(0, 5);
    Word16 sharp = (Word16)(k * random_range(5, 90)), sharp1 = (Word16)(k1 * random_range(10, 110));
    Word16 c1 = (Word16)random_range(0, 4), c2 = (Word16)random_range(0, 4);
    Word16 est1 = (Word16)random_range(0, 100), est2 = (Word16)random_range(0, 200);
    Word16 prev = next_random() % 3 == 0 ? 0 : (Word16)random_range(1, 120);
    if (next_random() % 8 == 0) { sharp = random16(); if (sharp < 0) sharp = (Word16)-sharp; if (sharp < 0) sharp = 32767; }
    put1("est1", est1); put1("est2", est2); put1("sharp", sharp); put1("sharp1", sharp1); put1("c1", c1);
    put1("c2", c2); put1("k", k); put1("k1", k1); put1("k2", k2); put1("prev", prev);
    est_freq_har_decis_fx(&est1, &est2, sharp, sharp1, c1, c2, k, k1, k2, &prev);
    arrow(); put1("est1", est1); put1("est2", est2); put1("prev", prev); end_line();
}

static void case_har_est(void)
{
    Word32 spectra[L_FRAME32k];
    Word16 n = (Word16)(next_random() & 1 ? 256 : 300);
    if (next_random() % 6 == 0) n = (Word16)random_range(80, 480);
    random_spectrum(spectra, n, 1);
    Word16 offs[2] = {120, 210};
    Word16 widths[2];
    if (next_random() & 1) { widths[0] = SWB_SB_BW_LEN0_12KBPS_HAR; widths[1] = SWB_SB_BW_LEN1_12KBPS_HAR; }
    else { widths[0] = SWB_SB_BW_LEN0_16KBPS_HAR; widths[1] = SWB_SB_BW_LEN1_16KBPS_HAR; }
    Word16 est1 = next_random() % 4 ? 0 : (Word16)random_range(0, 90), est2 = random16();
    Word16 flag = next_random() % 8 ? 1 : (Word16)random_range(0, 2);
    Word16 prev = next_random() % 3 == 0 ? 0 : (Word16)random_range(1, 100);
    Word16 stab = next_random() % 3 == 0 ? 0 : (Word16)random_range(-5, n + 20);
    int shape = next_random() % 10;
    if (shape == 0) {
        /* a few peaks at least SWB_HAR_RAN1 apart: the smallest distance decides alone */
        n = (Word16)random_range(300, 480);
        memset(spectra, 0, sizeof spectra);
        for (int at = random_range(80, 130); at < n; at += random_range(80, 140))
            spectra[at] = (Word32)random_range(1 << 12, 1 << 22);
    } else if (shape == 1) {
        /* a fine harmonic train on the previous frame's spacing, the stable peak far away */
        prev = (Word16)random_range(8, 24);
        int spacing = next_random() & 1 ? prev : 2 * prev;
        memset(spectra, 0, sizeof spectra);
        for (int at = random_range(80, 80 + spacing); at < n; at += spacing)
            spectra[at] = (Word32)random_range(1 << 12, 1 << 22) * (next_random() & 1 ? 1 : -1);
        stab = next_random() & 1 ? (Word16)random_range(1, 20) : (Word16)random_range(n - 20, n - 1);
    } else if (shape == 2 || shape == 3) {
        /* the stable peak a few bins from where this frame's lands, around the 9-bin tolerance */
        Word16 e1 = est1, e2 = est2, f = flag, p = prev, s = 0;
        Word16 at = har_est_fx(spectra, n, &e1, &e2, &f, &p, offs, widths, &s);
        Word16 moved = (Word16)(at + random_range(-10, 10));
        if (moved > 0 && moved < n) stab = moved;
        if (shape == 3 && e2 > 0) prev = e2;
    }
    put32("spectra", spectra, n); put1("n", n); put1("est1", est1); put1("est2", est2); put1("flag", flag);
    put1("prev", prev); put16("offs", offs, 2); put16("widths", widths, 2); put1("stab", stab);
    Word16 r = har_est_fx(spectra, n, &est1, &est2, &flag, &prev, offs, widths, &stab);
    arrow(); put1("r", r); put1("est1", est1); put1("est2", est2); put1("flag", flag); put1("prev", prev);
    put1("stab", stab); end_line();
}

static void case_genhf_noise(void)
{
    Config c;
    Layout l;
    Word32 spectra[L_FRAME32k], spectra_ni[L_FRAME32k], xsynth[L_FRAME32k];
    Word16 sspectra[L_FRAME32k], sdiff[L_FRAME32k], sni[L_FRAME32k], qss = 0;
    Word16 pul_res[NB_SWB_SUBBANDS] = {0, 0, 0, 0}, lag[2];
    GainItem_fx pk[PK_SLOTS];
    Word16 est2, pos_max;
    random_config(&c);
    layout_for(&c, HQ_HARMONIC, &l);
    lag[0] = (Word16)(next_random() & 1); lag[1] = (Word16)(next_random() & 1);
    random_spectrum(spectra, l.low, 1);
    noise_filled(spectra, spectra_ni, l.low);
    for (;;) {
        Word16 est1 = 0, flag = 1, prev = next_random() % 2 ? 0 : (Word16)random_range(8, 90);
        Word16 stab = next_random() % 2 ? 0 : (Word16)random_range(0, l.low - 1), prev_in = prev;
        est2 = 0;
        Word32 copy[L_FRAME32k], copy_ni[L_FRAME32k];
        memcpy(copy, spectra, sizeof copy); memcpy(copy_ni, spectra_ni, sizeof copy_ni);
        pos_max = har_est_fx(copy, l.low, &est1, &est2, &flag, &prev, l.search_offset, l.wbands, &stab);
        Word16 prev_ratio = random16() & 0x7fff;
        noise_extr_corcod_fx(copy, copy_ni, sspectra, sdiff, sni, l.low, (Word16)random_range(0, 3), &prev_ratio, &qss);
        if (flag == 0 && (est2 != SWB_HAR_RAN1 || est2 != prev_in)) est2 = add(est2, lag[0]);
        if (next_random() % 4 == 0) { est2 = (Word16)random_range(5, 100); pos_max = (Word16)random_range(0, l.low - 1); }
        if (est2 >= 4 && pos_max >= 0 && pos_max < l.low) break;
        random_spectrum(spectra, l.low, 1);
        noise_filled(spectra, spectra_ni, l.low);
    }
    if (next_random() % 4 == 0) {
        /* raw smoothed buffers, more peaks than the smoother would leave */
        for (int i = 0; i < l.low; i++) {
            sdiff[i] = (Word16)random_range(-10240, 10240);
            sspectra[i] = next_random() % 4 == 0 ? (Word16)random_range(-10240, 10240) : 0;
        }
    }
    for (int i = 0; i < L_FRAME32k; i++) xsynth[i] = random32();
    random_items(pk, PK_SLOTS);
    Word16 qsl = SWB_BWE_LR_Qs;
    put16("noise_flr", sdiff, l.low); put1("qss", qss); put32("xsynth", xsynth, L_FRAME32k); put1("qsl", qsl);
    put16("pred", sspectra, l.low); put1("bands", c.bands); put1("har_bands", l.har_bands); put1("est2", est2);
    put1("pos_max", pos_max); put16("pul_res", pul_res, NB_SWB_SUBBANDS); put_items("pk", pk, PK_SLOTS);
    put1("low", l.low); put1("high", l.high); put16("widths", l.wbands, NB_SWB_SUBBANDS); put16("lag", lag, 2);
    put16("offsets", l.offsets, NB_SWB_SUBBANDS); put16("search", l.search_offset, 2);
    genhf_noise_fx(sdiff, qss, xsynth, qsl, sspectra, c.bands, l.har_bands, est2, pos_max, pul_res, pk, l.low, l.high,
                   l.wbands, lag, l.offsets, l.search_offset);
    arrow(); put32("xsynth", xsynth, L_FRAME32k); put16("pul_res", pul_res, NB_SWB_SUBBANDS); put_items("pk", pk, PK_SLOTS);
    end_line();
}

/* fLen up to 396: past 33 subbands the reference's n_list[BANDS_MAX] can overflow. */
static Word16 smoothing_length(void)
{
    int pick = next_random() % 4;
    if (pick == 0) return 256;
    if (pick == 1) return 300;
    return (Word16)random_range(12, 396);
}

static void case_spectrum_smoothing(void)
{
    Word32 in[L_FRAME32k];
    Word16 out[L_FRAME32k], qss = random16();
    Word16 len = smoothing_length();
    random_spectrum(in, len, next_random() & 1);
    if (next_random() % 4 == 0)
        for (int i = 0; i < len; i++) if (in[i] != 0 && L_abs(in[i]) < 410) in[i] = 0; /* as the callers cut */
    for (int i = 0; i < L_FRAME32k; i++) out[i] = random16();
    Word16 th = next_random() % 3 == 0 ? 0 : (Word16)random_range(0, 3000);
    put32("in", in, len); put16("out", out, L_FRAME32k); put1("len", len); put1("th", th);
    SpectrumSmoothing_fx(in, out, &qss, len, th);
    arrow(); put16("out", out, L_FRAME32k); put1("qss", qss); end_line();
}

static void case_spectrumsmooth_noiseton(void)
{
    Word32 spectra[L_FRAME32k], ni[L_FRAME32k];
    Word16 ss[L_FRAME32k], sdiff[L_FRAME32k], sni[L_FRAME32k], qss = random16(), seed = random16();
    Word16 len = smoothing_length();
    random_spectrum(spectra, len, 0);
    noise_filled(spectra, ni, len);
    for (int i = 0; i < L_FRAME32k; i++) { ss[i] = random16(); sdiff[i] = random16(); sni[i] = random16(); }
    put32("spectra", spectra, len); put32("ni", ni, len); put1("len", len); put1("seed", seed);
    Word16 r = spectrumsmooth_noiseton_fx(spectra, ni, ss, sdiff, sni, &qss, len, &seed);
    arrow(); put1("r", r); put16("ss", ss, L_FRAME32k); put16("sdiff", sdiff, L_FRAME32k);
    put16("sni", sni, L_FRAME32k); put1("qss", qss); put1("seed", seed); end_line();
}

/* A smoothed low band as spectrumsmooth_noiseton_fx leaves it: mostly sparse, Q10 around +-10. */
static void random_smoothed(Word16 *x, int n)
{
    int density = random_range(1, 10);
    for (int i = 0; i < n; i++)
        x[i] = (Word16)(random_range(0, 9) < density ? random_range(-10240, 10240) : 0);
    if (next_random() % 8 == 0) for (int i = 0; i < n; i++) x[i] = 0;
}

static void case_convert_lag_indices(void)
{
    Config c;
    Layout l;
    Word16 ss[L_FRAME32k], in[NB_SWB_SUBBANDS], out[NB_SWB_SUBBANDS];
    random_config(&c);
    layout_for(&c, HQ_NORMAL, &l);
    random_smoothed(ss, l.low);
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) {
        in[k] = (Word16)random_range(0, (1 << bits_lagIndices_modeNormal_fx[k]) - 1);
        if (next_random() % 6 == 0) in[k] = (Word16)random_range(0, 300);
        out[k] = random16();
    }
    put16("ss", ss, l.low); put16("in", in, NB_SWB_SUBBANDS); put1("nbands", l.nbands);
    put16("out", out, NB_SWB_SUBBANDS); put16("widths", l.wbands, NB_SWB_SUBBANDS); put1("low", l.low);
    convert_lagIndices_pls2smp_fx(in, l.nbands, out, ss, l.wbands, l.low);
    arrow(); put16("out", out, NB_SWB_SUBBANDS); end_line();
}

static void lags_for(const Layout *l, Word16 *lags)
{
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) {
        lags[k] = (Word16)random_range(0, l->low - l->wbands[k]);
        if (next_random() % 6 == 0) lags[k] = (Word16)random_range(0, l->low); /* the clamp */
        if (next_random() % 6 == 0) lags[k] = 0;
    }
}

static void case_getlag_gains(void)
{
    Config c;
    Layout l;
    Word16 pred[L_FRAME32k], lags[NB_SWB_SUBBANDS], gains[NB_SWB_SUBBANDS], qgains[NB_SWB_SUBBANDS];
    Word32 energy[NB_SWB_SUBBANDS];
    random_config(&c);
    layout_for(&c, HQ_NORMAL, &l);
    random_smoothed(pred, l.low);
    if (next_random() % 4 == 0) for (int i = 0; i < l.low; i++) pred[i] = random16();
    lags_for(&l, lags);
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) {
        /* band energies, log2 in Q14 */
        energy[k] = (Word32)random_range(-6 << 14, 40 << 14);
        gains[k] = random16(); qgains[k] = random16();
    }
    Word16 qss = next_random() % 4 ? 10 : (Word16)random_range(4, 14);
    put16("pred", pred, l.low); put1("qss", qss); put32("energy", energy, NB_SWB_SUBBANDS);
    put1("nbands", l.nbands); put16("widths", l.wbands, NB_SWB_SUBBANDS); put16("lags", lags, NB_SWB_SUBBANDS);
    put1("low", l.low); put16("gains", gains, NB_SWB_SUBBANDS); put16("qgains", qgains, NB_SWB_SUBBANDS);
    GetlagGains_fx(pred, qss, energy, SWB_BWE_LR_Qbe, l.nbands, l.wbands, lags, l.low, gains, qgains);
    arrow(); put16("gains", gains, NB_SWB_SUBBANDS); put16("qgains", qgains, NB_SWB_SUBBANDS); end_line();
}

static void case_get_synthesized_spec_thin_out(void)
{
    Config c;
    Layout l;
    Word16 pred[L_FRAME32k], lags[NB_SWB_SUBBANDS], gains[NB_SWB_SUBBANDS], qgains[NB_SWB_SUBBANDS];
    Word32 energy[NB_SWB_SUBBANDS], out[L_FRAME32k];
    random_config(&c);
    layout_for(&c, HQ_NORMAL, &l);
    random_smoothed(pred, l.low);
    for (int i = 0; i < l.low; i += random_range(1, 30)) pred[i] = random16();
    lags_for(&l, lags);
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) energy[k] = (Word32)random_range(-6 << 14, 40 << 14);
    GetlagGains_fx(pred, 10, energy, SWB_BWE_LR_Qbe, l.nbands, l.wbands, lags, l.low, gains, qgains);
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) {
        if (next_random() % 3 == 0) gains[k] = mult_r(gains[k], 29491);
        if (next_random() % 5 == 0) { gains[k] = 0; qgains[k] = 15; }
        if (next_random() % 6 == 0) { gains[k] = random16(); qgains[k] = (Word16)random_range(-4, 40); }
    }
    for (int i = 0; i < L_FRAME32k; i++) out[i] = random32();
    Word16 qsl = next_random() % 4 ? SWB_BWE_LR_Qs : (Word16)random_range(0, 20);
    put16("pred", pred, l.low); put32("out", out, L_FRAME32k); put1("qsl", qsl); put1("nbands", l.nbands);
    put16("widths", l.wbands, NB_SWB_SUBBANDS); put16("lags", lags, NB_SWB_SUBBANDS);
    put16("gains", gains, NB_SWB_SUBBANDS); put16("qgains", qgains, NB_SWB_SUBBANDS); put1("low", l.low);
    GetSynthesizedSpecThinOut_fx(pred, 10, out, qsl, l.nbands, l.wbands, lags, gains, qgains, l.low);
    arrow(); put32("out", out, L_FRAME32k); end_line();
}

/* A search buffer as the encoder hands FindNBiggest2_simple_fx_har: an HF stretch of the spectrum. */
static void random_search_buffer(Word32 *x, int n)
{
    int kind = next_random() % 6;
    random_spectrum(x, n, kind == 0);
    if (kind == 1) for (int i = 0; i < n; i++) x[i] = (Word32)random_range(-(1 << 20), 1 << 20);
    if (kind == 2) for (int i = 0; i < n; i++) x[i] = (Word32)random_range(-200, 200);
    if (kind == 3) for (int i = 0; i < n; i++) x[i] = (Word32)random_range(-1, 1);
}

static Word16 search_length(void)
{
    static const Word16 lengths[] = {55, 56, 59, 60, 68, 74, 84, 92, 100, 105, 110, 115, 312, 340};
    return next_random() % 4 ? lengths[next_random() % 14] : (Word16)random_range(2, 400);
}

static void case_get_sigma(void)
{
    Word32 x[L_FRAME32k];
    Word16 len = search_length();
    random_search_buffer(x, len);
    for (int i = 0; i < len; i++) x[i] = L_abs(x[i]);
    Word16 qi = (Word16)random_range(0, 20), avg, qavg;
    /* the average as FindNBiggest2_simple_fx_har forms it, or a random one */
    Word32 sum = 0;
    for (int i = 0; i < len; i++) sum = L_add(sum, L_shr(x[i], 8));
    avg = 0; qavg = 15;
    if (sum != 0) {
        Word16 en = sub(norm_l(sum), 1), ed = norm_s(len);
        avg = div_l(L_shl(sum, en), shl(len, ed));
        qavg = sub(add(sub(qi, 8), en), add(ed, 1));
    }
    if (next_random() % 5 == 0) { avg = (Word16)random_range(0, 32767); qavg = (Word16)random_range(-4, 30); }
    Word16 sigma = random16(), qsigma = random16();
    put32("x", x, len); put1("qi", qi); put1("avg", avg); put1("qavg", qavg); put1("len", len);
    get_sigma_fx_har(x, qi, avg, qavg, len, &sigma, &qsigma);
    arrow(); put1("sigma", sigma); put1("qsigma", qsigma); end_line();
}

/* The threshold FindNBiggest2_simple_fx_har compares against in pass `pass` (1..3), restated from
 * the reference's own operator sequence, so a component can be planted exactly on it. */
static Word32 find_n_biggest2_threshold(const Word32 *in, Word16 q, Word16 len, Word16 nsearch, int pass)
{
    Word32 abs_in[400], max_in = 0, avg = 0, thr;
    Word16 avg_in = 0, qavg = 15, sigma, qsigma, cnt = 0, t;
    for (int j = 0; j < len; j++) {
        abs_in[j] = L_abs(in[j]);
        Word32 s = L_shr(abs_in[j], 8);
        if (L_sub(max_in, s) < 0) max_in = s;
        avg = L_add(avg, s);
    }
    if (avg != 0) {
        Word16 en = sub(norm_l(avg), 1), ed = norm_s(len);
        avg_in = div_l(L_shl(avg, en), shl(len, ed));
        qavg = sub(add(sub(q, 8), en), add(ed, 1));
    }
    if (L_sub(max_in, 1) <= 0) cnt = nsearch;
    get_sigma_fx_har(abs_in, q, avg_in, qavg, len, &sigma, &qsigma);
    t = mult_r(sigma, 18841);
    thr = L_add(extract_l(avg_in), L_shr(extract_l(t), sub(sub(qsigma, 1), qavg)));
    thr = L_shr(thr, sub(qavg, q));
    for (int p = 1; p <= pass; p++) {
        if (p == 2) thr = Mult_32_16(thr, add(round_fx(L_shl(L_mult(div_s_ss(19661, nsearch), cnt), 14)), 22938));
        if (p == 3) thr = Mult_32_16(thr, add(round_fx(L_shl(L_mult(div_s_ss(19661, nsearch), cnt), 15)), 9830));
        if (p == pass) break;
        for (int j = 0; j < len && cnt < nsearch; j++)
            if (L_sub(abs_in[j], thr) > 0) { abs_in[j] = 0; cnt++; }
    }
    return thr;
}

static void case_find_n_biggest2(void)
{
    Word32 x[400];
    GainItem_fx pk[PK_SLOTS];
    Word16 len = search_length();
    random_search_buffer(x, len);
    Word16 q = (Word16)random_range(0, 16), n = random16();
    Word16 nsearch = next_random() % 3 == 0 ? N_NBIGGEST_SEARCH_LRG_B
                   : next_random() & 1 ? N_NBIGGEST_PULSEARCH : (Word16)random_range(1, 40);
    if (next_random() % 3 == 0) {
        /* a component sitting exactly on the second or third pass threshold, which the 0.7 / 0.3
         * offsets decide by one LSB; found as the fixed point of planting it there */
        int pass = random_range(2, 3), at = random_range(0, len - 1);
        for (int it = 0; it < 40; it++) {
            Word32 thr = find_n_biggest2_threshold(x, q, len, nsearch, pass);
            if (thr == L_abs(x[at])) break;
            x[at] = next_random() & 1 ? thr : L_negate(thr);
        }
    }
    random_items(pk, PK_SLOTS);
    put32("x", x, len); put1("q", q); put_items("pk", pk, PK_SLOTS); put1("len", len); put1("nsearch", nsearch);
    FindNBiggest2_simple_fx_har(x, q, pk, len, &n, nsearch);
    arrow(); put_items("pk", pk, PK_SLOTS); put1("n", n); end_line();
}

static void case_preset_post(void)
{
    Config c;
    Word32 m[L_FRAME32k], y2[L_FRAME32k];
    Word16 p2a[BANDS_MAX], npulses[BANDS_MAX], har_bands = random16(), low = random16(), high = random16();
    random_config(&c);
    Word16 clas = next_random() & 1 ? HQ_HARMONIC : HQ_NORMAL;
    for (int i = 0; i < L_FRAME32k; i++) { m[i] = random32(); y2[i] = next_random() % 3 ? 0 : random32(); }
    for (int k = 0; k < BANDS_MAX; k++) { p2a[k] = (Word16)(next_random() & 1); npulses[k] = next_random() % 2 ? 0 : (Word16)random_range(0, 20); }
    put1("clas", clas); put16("band_start", c.band_start, c.bands); put16("band_end", c.band_end, c.bands);
    put1("har_bands", har_bands); put1("p2a_bands", c.p2a_bands); put1("length", c.length); put1("bands", c.bands);
    put32("m", m, L_FRAME32k); put32("y2", y2, L_FRAME32k); put16("p2a", p2a, c.bands); put16("npulses", npulses, c.bands);
    preset_hq2_swb_fx(clas, c.band_end, &har_bands, c.p2a_bands, c.length, c.bands, &low, &high, m);
    arrow(); put1("har_bands", har_bands); put1("low", low); put1("high", high); put32("m", m, L_FRAME32k);
    /* the BWE fills the high band in between */
    for (int i = low; i < low + high; i++) m[i] = next_random() % 3 ? 0 : random32();
    put32("m2", m, L_FRAME32k);
    post_hq2_swb_fx(m, low, high, clas, har_bands, c.bands, p2a, c.band_start, c.band_end, y2, npulses);
    put32("y2", y2, L_FRAME32k); put16("npulses", npulses, c.bands); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "div_s_ss")) case_div_s_ss();
        else if (!strcmp(argv[2], "get_predicted_signal")) case_get_predicted_signal();
        else if (!strcmp(argv[2], "est_freq_har_decis")) case_est_freq_har_decis();
        else if (!strcmp(argv[2], "har_est")) case_har_est();
        else if (!strcmp(argv[2], "genhf_noise")) case_genhf_noise();
        else if (!strcmp(argv[2], "spectrum_smoothing")) case_spectrum_smoothing();
        else if (!strcmp(argv[2], "spectrumsmooth_noiseton")) case_spectrumsmooth_noiseton();
        else if (!strcmp(argv[2], "convert_lag_indices")) case_convert_lag_indices();
        else if (!strcmp(argv[2], "getlag_gains")) case_getlag_gains();
        else if (!strcmp(argv[2], "get_synthesized_spec_thin_out")) case_get_synthesized_spec_thin_out();
        else if (!strcmp(argv[2], "get_sigma")) case_get_sigma();
        else if (!strcmp(argv[2], "find_n_biggest2")) case_find_n_biggest2();
        else if (!strcmp(argv[2], "preset_post")) case_preset_post();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
