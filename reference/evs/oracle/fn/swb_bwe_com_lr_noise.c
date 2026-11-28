/* Function-level oracle for the noise extraction / injection half of lib_com/swb_bwe_com_lr_fx.c
 * (SpectrumSmoothing_nss_fx, Get20Log10Spec_fx, SmoothSpec_fx, noise_extr_corcod_fx,
 * noiseinj_hf_fx, ton_ene_est_fx, norm_vec_32_16_scale_fx, sqrt_32n_16_fx, hf_parinitiz_fx,
 * get_usebit_npswb_fx, return_bits_normal2_fx).
 *
 * The SWB BWE cases replay the decoder's own chain (lib_dec/swb_bwe_dec_lr_fx.c,
 * DecodeSWBSubbands_fx): an SWB 13.2 / 16.4 kbit/s band layout from hq2_core_configure_fx, a
 * spectrum from mdct_spectrum_denorm_fx and its noise-filled copy from hq2_noise_inject_fx, then
 * har_est_fx / genhf_noise_fx (harmonic mode) or spectrumsmooth_noiseton_fx / GetlagGains_fx /
 * GetSynthesizedSpecThinOut_fx (normal mode) up to the function under test, whose inputs are printed
 * as the decoder would hand them over. A quarter of the cases are synthetic, for the edges. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "../../c-code/lib_com/swb_bwe_com_lr_fx.c"

typedef struct {
    Word16 num_bits;
    Word32 bwe_br;
    Word16 bands, length, band_width[BANDS_MAX], band_start[BANDS_MAX], band_end[BANDS_MAX];
    Word32 qint;
    Word16 eref, bit_alloc_weight, gqlevs, ngq, p2a_bands, p2a_th, pd_thresh, ld_slope, ni_coef;
} Config;

/* SWB, long window, at the two rates the low-rate SWB BWE runs at. */
static void random_config(Config *c)
{
    c->bwe_br = (next_random() & 1) ? HQ_13k20 : HQ_16k40;
    c->num_bits = (Word16)random_range(200, 330);
    hq2_core_configure_fx(L_FRAME32k, c->num_bits, 0, &c->bands, &c->length, c->band_width, c->band_start,
                          c->band_end, &c->qint, &c->eref, &c->bit_alloc_weight, &c->gqlevs, &c->ngq,
                          &c->p2a_bands, &c->p2a_th, &c->pd_thresh, &c->ld_slope, &c->ni_coef, c->bwe_br);
}

static void put_layout(const Config *c)
{
    put1("bands", c->bands); put1("length", c->length);
    put16("band_start", c->band_start, c->bands); put16("band_end", c->band_end, c->bands);
    put16("band_width", c->band_width, c->bands);
}

/* A decoded frame: band energies (Qbe = 14), pulses (harmonic: a pulse train in the low band),
 * the denormalised spectrum y2 (Qs = 12) and its noise-filled copy y2_ni. */
static void random_frame(const Config *c, int harmonic, Word32 *energy, Word32 *y2, Word32 *y2_ni, Word16 *npulses)
{
    Word16 inp[L_FRAME32k];
    int spacing = random_range(8, 40), phase = random_range(0, spacing - 1), top = c->band_end[c->bands - 1] + 1;
    int low_top = harmonic ? c->band_end[c->bands - c->p2a_bands] + 1 : top;
    for (int i = 0; i < L_FRAME32k; i++) { inp[i] = 0; y2[i] = 0; y2_ni[i] = 0; }
    for (int k = 0; k < c->bands; k++) {
        int density = random_range(1, 10), total = 0;
        energy[k] = random_range(-1 << 14, 26 << 14);
        if (next_random() % 16 == 0) energy[k] = random_range(26 << 14, 737279);
        /* down to the decoder's floor (-6.7 in Qbe, hq_lr_dec_fx's bit-error check) */
        if (next_random() % 16 == 0) energy[k] = random_range(-109772, -1 << 14);
        for (int i = c->band_start[k]; i <= c->band_end[k]; i++) {
            Word16 v = 0;
            if (harmonic && i < low_top) {
                if ((i - phase) % spacing == 0) v = (Word16)random_range(1, 6) * ((next_random() & 1) ? 1 : -1);
                else if (next_random() % 24 == 0) v = (Word16)random_range(-1, 1);
            } else if (next_random() % density == 0) v = (Word16)random_range(-4, 4);
            if (next_random() % 128 == 0) v = (Word16)random_range(-200, 200);
            inp[i] = v;
            total += abs(v);
        }
        npulses[k] = (Word16)total;
    }
    mdct_spectrum_denorm_fx(inp, y2, c->band_start, c->band_end, c->band_width, energy, npulses, c->bands,
                            c->ld_slope, c->pd_thresh);

    /* The noise-filled copy, exactly as hq_lr_dec_fx derives it. */
    Word32 ep[BANDS_MAX], rk[BANDS_MAX], last_ni_gain[BANDS_MAX], ener_l = 0, ener_h = 0;
    Word16 last_env[BANDS_MAX], last_max_pos_pulse = (Word16)random_range(0, c->bands), p2a[BANDS_MAX];
    for (int k = 0; k < c->bands; k++) {
        Word16 exp;
        Word16 frac1 = L_Extract_lc(L_shl(energy[k], 16 - SWB_BWE_LR_Qbe), &exp);
        ep[k] = L_shl(Pow2(30, frac1), s_max(sub(sub(exp, 30), 6), -31));
        rk[k] = (next_random() % 5) ? random_range(0, c->band_width[k] * 3) << 16 | random_range(0, 65535) : 0;
        p2a[k] = (Word16)random_range(0, 1);
        last_ni_gain[k] = random_range(0, 1 << 20);
        last_env[k] = (Word16)random_range(0, 3000);
        if (k >= c->bands / 2) ener_h = L_add(ener_h, L_shl(ep[k], 2));
        else ener_l = L_add(ener_l, L_shl(ep[k], 2));
    }
    for (int i = 0; i < top; i++) y2_ni[i] = y2[i];
    Word16 seed = add(add(add(npulses[0], npulses[1]), npulses[2]), npulses[3]);
    hq2_noise_inject_fx(y2_ni, c->band_start, c->band_end, c->band_width, ep, rk, npulses, seed, c->bands, 0,
                        (Word16)random_range(1, 320), (Word16)random_range(1, 320), ener_l, ener_h, last_ni_gain,
                        last_env, &last_max_pos_pulse, p2a, c->p2a_bands, harmonic ? HQ_HARMONIC : HQ_NORMAL, SWB,
                        c->bwe_br);
}

/* A Word32 spectrum for the smoothing: sparse pulses, a random walk, or edge values. */
static void random_spectrum32(Word32 *x, int n)
{
    int kind = next_random() % 6;
    Word16 w[L_FRAME32k];
    random_signal(w, n, random_range(1, 32767));
    int shift = random_range(0, 16), period = random_range(2, 5);
    for (int i = 0; i < n; i++) {
        if (kind == 0) x[i] = (next_random() % 6) ? 0 : (Word32)random_range(-200000, 200000);
        else if (kind == 1) x[i] = L_shl((Word32)w[i], shift);
        else if (kind == 2) x[i] = (next_random() % 3) ? 0 : random32();
        else if (kind == 3) x[i] = (next_random() % 4) ? (Word32)random_range(-64, 64) : 0;
        /* silent 8-bin subbands beside loud ones: the all-zero band normalisation */
        else if (kind == 4) x[i] = ((i / 8) % period) ? 0 : L_shl((Word32)w[i], shift);
        /* nothing coded at all */
        else x[i] = 0;
    }
}

/*---------------------------------------------------------------- leaf helpers */

static void case_sqrt_32n_16(void)
{
    Word32 l_in = (next_random() % 4) ? (Word32)(next_random() >> random_range(0, 30)) : random32();
    if (next_random() % 8 == 0) l_in = 0;
    Word16 qin = (Word16)random_range(-20, 62), out, qout;
    put1("l_in", l_in); put1("qin", qin);
    sqrt_32n_16_fx(l_in, qin, &out, &qout);
    arrow(); put1("out", out); put1("qout", qout); end_line();
}

static void case_norm_vec_32_16_scale(void)
{
    Word32 x[L_FRAME32k];
    Word16 out[L_FRAME32k], qout;
    int n = random_range(1, L_FRAME32k);
    random_spectrum32(x, n);
    Word16 qin = (Word16)random_range(-4, 20), exp_safe = (Word16)random_range(0, 6);
    put32("x", x, n); put1("qin", qin); put1("exp_safe", exp_safe);
    norm_vec_32_16_scale_fx(x, qin, (Word16)n, out, &qout, exp_safe);
    arrow(); put16("out", out, n); put1("qout", qout); end_line();
}

static void case_get20_log10_spec(void)
{
    Word32 x[NUM_SUBBAND_SMOOTH_MAX];
    Word16 out[NUM_SUBBAND_SMOOTH_MAX];
    int n = random_range(1, NUM_SUBBAND_SMOOTH_MAX);
    for (int i = 0; i < n; i++) {
        x[i] = (Word32)(next_random() >> random_range(0, 31));
        if (next_random() % 8 == 0) x[i] = (next_random() & 1) ? 0 : 0x7fffffff;
    }
    Word16 q = (Word16)random_range(-10, 56);
    put32("x", x, n); put1("q", q);
    Get20Log10Spec_fx(x, out, (Word16)n, q);
    arrow(); put16("out", out, n); end_line();
}

static void case_smooth_spec(void)
{
    Word16 x[NUM_SUBBAND_SMOOTH_MAX], out[NUM_SUBBAND_SMOOTH_MAX];
    int n = random_range(8, NUM_SUBBAND_SMOOTH_MAX);
    if (next_random() % 4) random_signal(x, n, random_range(1, 32767));
    else for (int i = 0; i < n; i++) x[i] = random16();
    put16("x", x, n);
    SmoothSpec_fx(x, out, (Word16)n);
    arrow(); put16("out", out, n); end_line();
}

static void case_spectrum_smoothing_nss(void)
{
    Word32 x[L_FRAME32k];
    Word16 out[L_FRAME32k], qss;
    int n;
    if (next_random() % 4) {
        Config c;
        Word32 energy[BANDS_MAX], y2[L_FRAME32k], y2_ni[L_FRAME32k];
        Word16 npulses[BANDS_MAX];
        random_config(&c);
        int harmonic = next_random() & 1;
        random_frame(&c, harmonic, energy, y2, y2_ni, npulses);
        n = harmonic ? c.band_end[c.bands - c.p2a_bands] + 1 : c.band_end[c.bands - NB_SWB_SUBBANDS - 1] + 1;
        for (int i = 0; i < n; i++) x[i] = (next_random() & 1) ? y2[i] : L_sub(y2_ni[i], y2[i]);
    } else {
        n = random_range(64, L_FRAME32k);
        random_spectrum32(x, n);
    }
    put32("x", x, n);
    SpectrumSmoothing_nss_fx(x, out, &qss, (Word16)n);
    arrow(); put16("out", out, n); put1("qss", qss); end_line();
}

static void case_hf_parinitiz(void)
{
    static const Word32 rates[] = {HQ_13k20, HQ_16k40, 9600, 24400};
    static const Word16 *const tables[] = {
        subband_offsets_sub5_13p2kbps_Har_fx, subband_search_offsets_13p2kbps_Har_fx,
        subband_offsets_sub5_16p4kbps_Har_fx, subband_search_offsets_16p4kbps_Har_fx,
        subband_offsets_12KBPS, subband_offsets_16KBPS, subband_search_offsets_fx};
    Word32 rate = rates[next_random() % 4];
    Word16 clas = (Word16)random_range(0, 4), low = (Word16)random_range(0, 640), high = (Word16)random_range(0, 640);
    Word16 wbands[NB_SWB_SUBBANDS], nb = -7, nbs = -7, swb_low = -7, swb_high = -7;
    for (int i = 0; i < NB_SWB_SUBBANDS; i++) wbands[i] = random16();
    /* the decoder's initial pointers (swb_bwe_dec_lr_fx) */
    const Word16 *search = subband_search_offsets_13p2kbps_Har_fx, *offsets = subband_offsets_sub5_13p2kbps_Har_fx;
    put1("rate", rate); put1("clas", clas); put1("low", low); put1("high", high); put16("wbands", wbands, 4);
    hf_parinitiz_fx(rate, clas, low, high, wbands, &search, &offsets, &nb, &nbs, &swb_low, &swb_high);
    int search_id = -1, offsets_id = -1;
    for (int i = 0; i < 7; i++) {
        if (tables[i] == search) search_id = i;
        if (tables[i] == offsets) offsets_id = i;
    }
    arrow(); put16("wbands", wbands, 4); put1("search", search_id); put1("offsets", offsets_id);
    put1("n_bands", nb); put1("n_bands_search", nbs); put1("swb_low", swb_low); put1("swb_high", swb_high);
    end_line();
}

static void case_get_usebit_npswb(void)
{
    Word16 clas = (Word16)random_range(-1, 5);
    put1("clas", clas);
    arrow(); put1("bits", get_usebit_npswb_fx(clas)); end_line();
}

static void case_return_bits_normal2(void)
{
    Word16 bands = (Word16)random_range(NB_SWB_SUBBANDS, BANDS_MAX), flags[BANDS_MAX];
    Word16 budget = (Word16)random_range(-50, 400);
    if (next_random() % 16 == 0) budget = 32767;
    for (int k = 0; k < bands; k++) flags[k] = (Word16)random_range(0, 2);
    put1("bands", bands); put16("flags", flags, bands); put1("budget", budget);
    return_bits_normal2_fx(&budget, flags, bands, bits_lagIndices_modeNormal_fx);
    arrow(); put1("budget", budget); end_line();
}

/*---------------------------------------------------------------- noise extraction */

/* Two consecutive frames through one prev_ni_ratio. */
static void case_noise_extr_corcod(void)
{
    Config c;
    random_config(&c);
    Word16 prev_ni_ratio = (next_random() % 4) ? 16384 : (Word16)random_range(0, 32767);
    Word32 spectra[2][L_FRAME32k], spectra_ni[2][L_FRAME32k];
    Word16 n[2], clas[2];
    for (int f = 0; f < 2; f++) {
        Word32 energy[BANDS_MAX];
        Word16 npulses[BANDS_MAX];
        int harmonic = next_random() & 1;
        random_frame(&c, harmonic, energy, spectra[f], spectra_ni[f], npulses);
        n[f] = harmonic ? c.band_end[c.bands - c.p2a_bands] + 1 : c.band_end[c.bands - NB_SWB_SUBBANDS - 1] + 1;
        clas[f] = (Word16)random_range(0, 3);
        if (next_random() % 6 == 0) {
            n[f] = (Word16)random_range(64, L_FRAME32k);
            random_spectrum32(spectra[f], n[f]);
            random_spectrum32(spectra_ni[f], n[f]);
        }
    }
    put1("prev_ni_ratio", prev_ni_ratio);
    for (int f = 0; f < 2; f++) {
        char name[24];
        sprintf(name, "spectra%d", f); put32(name, spectra[f], n[f]);
        sprintf(name, "spectra_ni%d", f); put32(name, spectra_ni[f], n[f]);
        sprintf(name, "clas%d", f); put1(name, clas[f]);
    }
    arrow();
    for (int f = 0; f < 2; f++) {
        Word16 ss[L_FRAME32k], ss_diff[L_FRAME32k], ss_ni[L_FRAME32k], qss;
        noise_extr_corcod_fx(spectra[f], spectra_ni[f], ss, ss_diff, ss_ni, n[f], clas[f], &prev_ni_ratio, &qss);
        char name[24];
        sprintf(name, "ss%d", f); put16(name, ss, n[f]);
        sprintf(name, "ss_diff%d", f); put16(name, ss_diff, n[f]);
        sprintf(name, "ss_ni%d", f); put16(name, ss_ni, n[f]);
        sprintf(name, "qss%d", f); put1(name, qss);
        sprintf(name, "prev_ni_ratio%d", f); put1(name, prev_ni_ratio);
    }
    end_line();
}

/*---------------------------------------------------------------- harmonic mode: ton_ene_est */

typedef struct {
    Word32 xsynth[L_FRAME32k], band_energy[BANDS_MAX], codbuf[L_FRAME32k];
    Word16 low, high, har_bands, g, qss, pul_res[NB_SWB_SUBBANDS], nmr[N_NBIGGEST_SEARCH_LRG_B],
        gidx[N_NBIGGEST_SEARCH_LRG_B];
} TonInputs;

/* The harmonic branch of DecodeSWBSubbands_fx up to ton_ene_est_fx. */
static void harmonic_chain(const Config *c, TonInputs *t, Word16 *prev_frm_hfe2, Word16 *prev_stab_hfe2,
                           Word16 *prev_ni_ratio, Word16 prev_clas)
{
    Word32 y2[L_FRAME32k], y2_ni[L_FRAME32k];
    Word16 npulses[BANDS_MAX], wbands[NB_SWB_SUBBANDS], nb, nbs, low, high;
    const Word16 *search = subband_search_offsets_13p2kbps_Har_fx, *offsets = subband_offsets_sub5_13p2kbps_Har_fx;
    random_frame(c, 1, t->band_energy, y2, y2_ni, npulses);
    memcpy(t->codbuf, y2_ni, sizeof t->codbuf); /* consumes no randomness: ton_ene_est's corpus is unchanged */
    t->har_bands = (Word16)(c->bands - c->p2a_bands + 1);
    Word16 lowlength = (Word16)(c->band_end[t->har_bands - 1] + 1), highlength = (Word16)(c->length - lowlength);
    hf_parinitiz_fx(c->bwe_br, HQ_HARMONIC, lowlength, highlength, wbands, &search, &offsets, &nb, &nbs, &low, &high);

    Word16 est1 = 0, est2 = 0, flag_dis = 1, lag[NB_SWB_SUBBANDS], ss[L_FRAME32k], ss_diff[L_FRAME32k],
           ss_ni[L_FRAME32k], qss;
    GainItem_fx pk_sf[N_NBIGGEST_SEARCH_LRG_B];
    Word16 pos_max = har_est_fx(y2, low, &est1, &est2, &flag_dis, prev_frm_hfe2, search, wbands, prev_stab_hfe2);
    noise_extr_corcod_fx(y2, y2_ni, ss, ss_diff, ss_ni, low, prev_clas, prev_ni_ratio, &qss);
    for (int i = 0; i < NB_SWB_SUBBANDS; i++) lag[i] = (Word16)random_range(0, 1);
    if (flag_dis == 0 && (est2 != SWB_HAR_RAN1 || est2 != *prev_frm_hfe2)) est2 = add(est2, lag[0]);
    for (int i = 0; i < L_FRAME32k; i++) t->xsynth[i] = 0;
    set16_fx(t->pul_res, 0, NB_SWB_SUBBANDS);
    for (int i = 0; i < N_NBIGGEST_SEARCH_LRG_B; i++) { pk_sf[i].nmrValue_fx = 0; pk_sf[i].gainIndex_fx = 0; }
    genhf_noise_fx(ss_diff, qss, t->xsynth, SWB_BWE_LR_Qs, ss, c->bands, t->har_bands, est2, pos_max, t->pul_res,
                   pk_sf, low, high, wbands, lag, offsets, search);
    Word16 imin = (Word16)random_range(0, 3), hi, lo;
    Word32 l_temp = L_shr(L_mult(gain_table_SWB_BWE_fx[imin], 27213), 12);
    lo = L_Extract_lc(l_temp, &hi);
    t->g = shl(extract_l(Pow2(14, lo)), sub(11, sub(14, hi)));
    *prev_frm_hfe2 = flag_dis == 0 ? 0 : est2;
    for (int i = 0; i < N_NBIGGEST_SEARCH_LRG_B; i++) { t->nmr[i] = pk_sf[i].nmrValue_fx; t->gidx[i] = pk_sf[i].gainIndex_fx; }
    t->low = low;
    t->high = high;
    t->qss = qss;
}

/* Synthetic inputs: arbitrary noise, energies and an ordered set of peaks. */
static void synthetic_ton(const Config *c, TonInputs *t)
{
    t->har_bands = (Word16)(c->bands - c->p2a_bands + 1);
    t->low = (Word16)(c->band_end[t->har_bands - 1] + 1);
    t->high = (Word16)(c->length - t->low);
    for (int i = 0; i < L_FRAME32k; i++) t->xsynth[i] = 0;
    Word16 w[L_FRAME32k];
    random_signal(w, t->high, random_range(1, 32767));
    int shift = random_range(0, 6);
    for (int i = 0; i < t->high; i++) t->xsynth[i] = (next_random() % 16) ? L_shl(w[i], shift) : random32() >> 4;
    for (int k = 0; k < c->bands; k++) t->band_energy[k] = random_range(-109772, 30 << 14);
    t->g = (Word16)random_range(1, 32767);
    t->qss = (Word16)random_range(-4, 14);
    for (int i = 0; i < N_NBIGGEST_SEARCH_LRG_B; i++) { t->nmr[i] = 0; t->gidx[i] = 0; }
    int position = 0;
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) {
        int end = c->band_end[t->har_bands + k] - t->low, n = random_range(0, 8);
        t->pul_res[k] = 0;
        for (int j = 0; j < n && position < end; j++) {
            position += random_range(1, 30);
            if (position > end && next_random() % 2) break;
            Word16 v = (Word16)random_range(1, 32767);
            t->nmr[k * 8 + j] = (next_random() & 1) ? v : (Word16)-v;
            t->gidx[k * 8 + j] = (Word16)position;
            t->pul_res[k]++;
        }
    }
}

/* Two frames of the harmonic chain (har_est and noise_extr_corcod state carried by the reference). */
static void case_ton_ene_est(void)
{
    Config c;
    random_config(&c);
    TonInputs t[2];
    Word16 prev_frm_hfe2 = 0, prev_stab_hfe2 = 0, prev_ni_ratio = 16384, prev_clas = (Word16)random_range(0, 3);
    for (int f = 0; f < 2; f++) {
        if (next_random() % 4) harmonic_chain(&c, &t[f], &prev_frm_hfe2, &prev_stab_hfe2, &prev_ni_ratio, prev_clas);
        else synthetic_ton(&c, &t[f]);
        prev_clas = HQ_HARMONIC;
    }
    put_layout(&c);
    for (int f = 0; f < 2; f++) {
        char name[24];
        sprintf(name, "xsynth%d", f); put32(name, t[f].xsynth, t[f].high);
        sprintf(name, "band_energy%d", f); put32(name, t[f].band_energy, c.bands);
        sprintf(name, "low%d", f); put1(name, t[f].low);
        sprintf(name, "high%d", f); put1(name, t[f].high);
        sprintf(name, "har_bands%d", f); put1(name, t[f].har_bands);
        sprintf(name, "g%d", f); put1(name, t[f].g);
        sprintf(name, "qss%d", f); put1(name, t[f].qss);
        sprintf(name, "pul_res%d", f); put16(name, t[f].pul_res, NB_SWB_SUBBANDS);
        sprintf(name, "nmr%d", f); put16(name, t[f].nmr, N_NBIGGEST_SEARCH_LRG_B);
        sprintf(name, "gidx%d", f); put16(name, t[f].gidx, N_NBIGGEST_SEARCH_LRG_B);
    }
    arrow();
    for (int f = 0; f < 2; f++) {
        GainItem_fx pk_sf[N_NBIGGEST_SEARCH_LRG_B];
        Word32 be_tonal[SWB_HAR_RAN1];
        Word16 qbel = -99;
        for (int i = 0; i < SWB_HAR_RAN1; i++) be_tonal[i] = 0;
        for (int i = 0; i < N_NBIGGEST_SEARCH_LRG_B; i++) { pk_sf[i].nmrValue_fx = t[f].nmr[i]; pk_sf[i].gainIndex_fx = t[f].gidx[i]; }
        ton_ene_est_fx(t[f].xsynth, SWB_BWE_LR_Qs, be_tonal, &qbel, t[f].band_energy, SWB_BWE_LR_Qbe, c.band_start,
                       c.band_end, c.band_width, t[f].low, t[f].high, c.bands, t[f].har_bands, t[f].g, pk_sf,
                       t[f].qss, t[f].pul_res);
        char name[24];
        sprintf(name, "xsynth%d", f); put32(name, t[f].xsynth, t[f].high);
        sprintf(name, "be_tonal%d", f); put32(name, be_tonal, c.bands);
        sprintf(name, "qbel%d", f); put1(name, qbel);
    }
    end_line();
}


/*---------------------------------------------------------------- harmonic mode: Gettonl_scalfact */

/* ton_ene_est_fx then Gettonl_scalfact_fx, as DecodeSWBSubbands_fx runs them, over two frames of the
 * harmonic chain; a quarter synthetic (arbitrary peaks and core lines). The p2a flags of the high
 * bands are what hq2_bit_alloc_har_fx left: some cleared. */
static void case_gettonl_scalfact(void)
{
    Config c;
    random_config(&c);
    TonInputs t;
    Word16 prev_frm_hfe2 = 0, prev_stab_hfe2 = 0, prev_ni_ratio = 16384, prev_clas = (Word16)random_range(0, 3);
    for (int f = 0; f < 2; f++) {
        if (next_random() % 4) harmonic_chain(&c, &t, &prev_frm_hfe2, &prev_stab_hfe2, &prev_ni_ratio, prev_clas);
        else {
            synthetic_ton(&c, &t);
            for (int i = 0; i < L_FRAME32k; i++) t.codbuf[i] = next_random() % 3 ? 0 : random_range(-(1 << 20), 1 << 20);
        }
        prev_clas = HQ_HARMONIC;
    }
    GainItem_fx pk_sf[N_NBIGGEST_SEARCH_LRG_B];
    Word32 be_tonal[SWB_HAR_RAN1];
    Word16 qbel = -99, flags[BANDS_MAX];
    for (int i = 0; i < SWB_HAR_RAN1; i++) be_tonal[i] = 0;
    for (int i = 0; i < N_NBIGGEST_SEARCH_LRG_B; i++) { pk_sf[i].nmrValue_fx = t.nmr[i]; pk_sf[i].gainIndex_fx = t.gidx[i]; }
    ton_ene_est_fx(t.xsynth, SWB_BWE_LR_Qs, be_tonal, &qbel, t.band_energy, SWB_BWE_LR_Qbe, c.band_start,
                   c.band_end, c.band_width, t.low, t.high, c.bands, t.har_bands, t.g, pk_sf, t.qss, t.pul_res);
    for (int k = 0; k < c.bands; k++) flags[k] = (Word16)(k < t.har_bands || next_random() % 3 != 0 ? 1 : 0);
    put_layout(&c);
    put32("xsynth", t.xsynth, L_FRAME32k); put32("codbuf", t.codbuf, L_FRAME32k); put1("low", t.low); put1("high", t.high);
    put1("har_bands", t.har_bands); put32("band_energy", t.band_energy, c.bands); put16("flags", flags, c.bands);
    put32("be_tonal", be_tonal, SWB_HAR_RAN1); put1("qbel", qbel); put16("nmr", t.nmr, N_NBIGGEST_SEARCH_LRG_B);
    put16("gidx", t.gidx, N_NBIGGEST_SEARCH_LRG_B); put1("qss", t.qss); put16("pul_res", t.pul_res, NB_SWB_SUBBANDS);
    Gettonl_scalfact_fx(t.xsynth, SWB_BWE_LR_Qs, t.codbuf, t.low, t.high, t.har_bands, c.bands, t.band_energy,
                        SWB_BWE_LR_Qbe, c.band_start, c.band_end, flags, be_tonal, qbel, pk_sf, t.qss, t.pul_res);
    arrow(); put32("xsynth", t.xsynth, L_FRAME32k); end_line();
}

/*---------------------------------------------------------------- normal mode: noiseinj_hf */

typedef struct {
    Word32 xsynth[L_FRAME32k], band_energy[BANDS_MAX], th_g[NB_SWB_SUBBANDS];
    Word16 low, high, flags[BANDS_MAX];
} InjInputs;

/* The normal branch of DecodeSWBSubbands_fx up to noiseinj_hf_fx. */
static void normal_chain(const Config *c, InjInputs *t)
{
    Word32 y2[L_FRAME32k], y2_ni[L_FRAME32k];
    Word16 npulses[BANDS_MAX], wbands[NB_SWB_SUBBANDS], nb, nbs, low, high;
    const Word16 *search = subband_search_offsets_13p2kbps_Har_fx, *offsets = subband_offsets_sub5_13p2kbps_Har_fx;
    random_frame(c, 0, t->band_energy, y2, y2_ni, npulses);
    Word16 lowlength = (Word16)(c->band_end[c->bands - NB_SWB_SUBBANDS - 1] + 1), highlength = (Word16)(c->length - lowlength);
    hf_parinitiz_fx(c->bwe_br, HQ_NORMAL, lowlength, highlength, wbands, &search, &offsets, &nb, &nbs, &low, &high);
    for (int k = 0; k < c->bands; k++) t->flags[k] = (Word16)random_range(0, 1);
    if (next_random() % 8 == 0) for (int k = c->bands - NB_SWB_SUBBANDS; k < c->bands; k++) t->flags[k] = 0;

    Word16 lag[NB_SWB_SUBBANDS], lag_real[NB_SWB_SUBBANDS], gains[NB_SWB_SUBBANDS], qgains[NB_SWB_SUBBANDS];
    Word16 ss[L_FRAME32k], ss_diff[L_FRAME32k], ss_ni[L_FRAME32k], qss, seed = random16();
    for (int sb = 0; sb < nbs; sb++)
        lag[sb] = t->flags[c->bands - NB_SWB_SUBBANDS + sb] == 0
                      ? (Word16)random_range(0, (1 << bits_lagIndices_modeNormal_fx[sb]) - 1) : 0;
    Word16 ss_min = spectrumsmooth_noiseton_fx(y2, y2_ni, ss, ss_diff, ss_ni, &qss, low, &seed);
    convert_lagIndices_pls2smp_fx(lag, nb, lag_real, ss, wbands, low);
    for (int k = 0; k < nb; k++) if (t->flags[c->bands - NB_SWB_SUBBANDS + k] == 1) lag_real[k] = 0;
    GetlagGains_fx(ss_ni, qss, &t->band_energy[c->bands - NB_SWB_SUBBANDS], SWB_BWE_LR_Qbe, nb, wbands, lag_real, low,
                   gains, qgains);
    for (int k = 0; k < nb; k++) {
        if (t->flags[c->bands - NB_SWB_SUBBANDS + k] == 1) { gains[k] = 0; qgains[k] = 15; }
        else gains[k] = mult_r(gains[k], 29491);
    }
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) {
        t->th_g[k] = 0;
        if (t->flags[c->bands - NB_SWB_SUBBANDS + k] == 0)
            t->th_g[k] = L_shl(L_mult(gains[k], ss_min), sub(SWB_BWE_LR_Qs, add(add(qgains[k], qss), 1)));
    }
    for (int i = 0; i < L_FRAME32k; i++) t->xsynth[i] = 0;
    GetSynthesizedSpecThinOut_fx(ss_ni, qss, t->xsynth, SWB_BWE_LR_Qs, nb, wbands, lag_real, gains, qgains, low);
    t->low = low;
    t->high = high;
}

static void synthetic_inj(const Config *c, InjInputs *t)
{
    t->low = (Word16)(c->band_end[c->bands - NB_SWB_SUBBANDS - 1] + 1);
    t->high = (Word16)(c->length - t->low);
    for (int i = 0; i < L_FRAME32k; i++) t->xsynth[i] = 0;
    Word16 w[L_FRAME32k];
    random_signal(w, t->high, random_range(1, 32767));
    int shift = random_range(0, 8);
    for (int i = 0; i < t->high; i++) t->xsynth[i] = (next_random() % 16) ? L_shl(w[i], shift) : random32() >> 2;
    for (int k = 0; k < c->bands; k++) {
        t->band_energy[k] = random_range(-109772, 30 << 14);
        t->flags[k] = (Word16)random_range(0, 1);
    }
    for (int k = 0; k < NB_SWB_SUBBANDS; k++)
        t->th_g[k] = (next_random() % 4) ? (Word32)random_range(0, 1 << random_range(4, 26)) : random32();
}

/* Two frames through one prev_En_sb memory. */
static void case_noiseinj_hf(void)
{
    Config c;
    random_config(&c);
    InjInputs t[2];
    Word16 prev_en_sb[NB_SWB_SUBBANDS];
    for (int k = 0; k < NB_SWB_SUBBANDS; k++) prev_en_sb[k] = (next_random() % 3) ? (Word16)random_range(0, 20000) : 0;
    for (int f = 0; f < 2; f++) {
        if (next_random() % 4) normal_chain(&c, &t[f]);
        else synthetic_inj(&c, &t[f]);
    }
    put_layout(&c);
    put16("prev_en_sb", prev_en_sb, NB_SWB_SUBBANDS);
    for (int f = 0; f < 2; f++) {
        char name[24];
        sprintf(name, "xsynth%d", f); put32(name, t[f].xsynth, t[f].high);
        sprintf(name, "band_energy%d", f); put32(name, t[f].band_energy, c.bands);
        sprintf(name, "th_g%d", f); put32(name, t[f].th_g, NB_SWB_SUBBANDS);
        sprintf(name, "flags%d", f); put16(name, t[f].flags, c.bands);
        sprintf(name, "low%d", f); put1(name, t[f].low);
        sprintf(name, "high%d", f); put1(name, t[f].high);
    }
    arrow();
    for (int f = 0; f < 2; f++) {
        noiseinj_hf_fx(t[f].xsynth, SWB_BWE_LR_Qs, t[f].th_g, t[f].band_energy, SWB_BWE_LR_Qbe, prev_en_sb, t[f].flags,
                       c.bands, c.band_start, c.band_end, t[f].low, t[f].high);
        char name[24];
        sprintf(name, "xsynth%d", f); put32(name, t[f].xsynth, t[f].high);
        sprintf(name, "prev_en_sb%d", f); put16(name, prev_en_sb, NB_SWB_SUBBANDS);
    }
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "sqrt_32n_16")) case_sqrt_32n_16();
        else if (!strcmp(argv[2], "norm_vec_32_16_scale")) case_norm_vec_32_16_scale();
        else if (!strcmp(argv[2], "get20_log10_spec")) case_get20_log10_spec();
        else if (!strcmp(argv[2], "smooth_spec")) case_smooth_spec();
        else if (!strcmp(argv[2], "spectrum_smoothing_nss")) case_spectrum_smoothing_nss();
        else if (!strcmp(argv[2], "hf_parinitiz")) case_hf_parinitiz();
        else if (!strcmp(argv[2], "get_usebit_npswb")) case_get_usebit_npswb();
        else if (!strcmp(argv[2], "return_bits_normal2")) case_return_bits_normal2();
        else if (!strcmp(argv[2], "noise_extr_corcod")) case_noise_extr_corcod();
        else if (!strcmp(argv[2], "ton_ene_est")) case_ton_ene_est();
        else if (!strcmp(argv[2], "gettonl_scalfact")) case_gettonl_scalfact();
        else if (!strcmp(argv[2], "noiseinj_hf")) case_noiseinj_hf();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
