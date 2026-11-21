/* Function-level oracle for lib_com/hq2_noise_inject_fx.c. Band layouts come from
 * hq2_core_configure_fx and the spectrum from mdct_spectrum_denorm_fx (both proven by
 * fn_hq2_core_com), so every case is a configuration and spectrum the decoder can produce. */
#include "harness.h"
#include "prot_fx.h"

typedef struct {
    Word16 frame_length, num_bits, is_transient;
    Word32 bwe_br;
    Word16 bands, length, band_width[BANDS_MAX], band_start[BANDS_MAX], band_end[BANDS_MAX];
    Word32 qint;
    Word16 eref, bit_alloc_weight, gqlevs, ngq, p2a_bands, p2a_th, pd_thresh, ld_slope, ni_coef;
} Config;

static void random_config(Config *c)
{
    /* The combinations the decoder reaches: NB up to 16.4 kbit/s, WB at 13.2 / 16.4, SWB at 13.2 /
     * 16.4 (by bwe_br). A WB frame over the 16.4 budget falls back to the default (SWB 13.2 long)
     * configuration; only its long-window form is drawn, since four short windows of it would be 88
     * bands and overflow the reference's BANDS_MAX arrays. */
    static const Word16 frames[] = {L_FRAME8k, L_FRAME8k, L_FRAME16k, L_FRAME32k};
    static const Word32 brates[] = {HQ_13k20, HQ_16k40};
    c->frame_length = frames[next_random() % 4];
    c->is_transient = (Word16)(next_random() % 3 == 0);
    c->bwe_br = brates[next_random() % 2];
    if (c->frame_length == L_FRAME8k) c->num_bits = (Word16)random_range(100, 330);
    else if (c->frame_length == L_FRAME16k) c->num_bits = (Word16)random_range(200, 328);
    else c->num_bits = (Word16)random_range(200, 330);
    if (c->frame_length == L_FRAME16k && !c->is_transient && next_random() % 8 == 0)
        c->num_bits = (Word16)random_range(329, 400);
    hq2_core_configure_fx(c->frame_length, c->num_bits, c->is_transient, &c->bands, &c->length, c->band_width,
                          c->band_start, c->band_end, &c->qint, &c->eref, &c->bit_alloc_weight, &c->gqlevs,
                          &c->ngq, &c->p2a_bands, &c->p2a_th, &c->pd_thresh, &c->ld_slope, &c->ni_coef, c->bwe_br);
}

static void put_config_inputs(const Config *c)
{
    put1("frame_length", c->frame_length); put1("num_bits", c->num_bits); put1("is_transient", c->is_transient);
    put1("bwe_br", c->bwe_br);
}

/* Decoded pulses: per band mostly zero, a few small magnitudes, occasionally a large one. */
static void random_pulses(const Config *c, Word16 *inp, Word16 *npulses)
{
    for (int k = 0; k < c->bands; k++) {
        int density = random_range(1, 8), total = 0;
        for (int i = c->band_start[k]; i <= c->band_end[k]; i++) {
            Word16 v = 0;
            if (next_random() % density == 0) v = (Word16)random_range(-4, 4);
            if (next_random() % 64 == 0) v = (Word16)random_range(-200, 200);
            inp[i] = v;
            total += abs(v);
        }
        npulses[k] = (Word16)total;
    }
}

/* Two consecutive frames through one noise-filling memory (last_ni_gain, last_env,
 * last_max_pos_pulse). The spectrum is the decoder's: mdct_spectrum_denorm_fx of random pulses. */
static void case_hq2_noise_inject(void)
{
    Config c;
    random_config(&c);
    Word32 last_ni_gain[BANDS_MAX];
    Word16 last_env[BANDS_MAX], last_max_pos_pulse = (Word16)random_range(0, c.bands);
    for (int k = 0; k < BANDS_MAX; k++) last_ni_gain[k] = random_range(0, 1 << 20);
    for (int k = 0; k < BANDS_MAX; k++) last_env[k] = (Word16)random_range(0, 3000);
    static const Word16 classes[] = {HQ_NORMAL, HQ_TRANSIENT, HQ_HARMONIC, HQ_HVQ};
    Word16 hqswb_clas = classes[next_random() % 4];
    /* inner_frame follows the coded bandwidth: 160 NB, 320 WB, 640 SWB. */
    Word16 bwidth = (Word16)(c.frame_length == L_FRAME8k ? NB : c.frame_length == L_FRAME16k ? WB : SWB);
    int n = c.band_end[c.bands - 1] + 1;
    put_config_inputs(&c);
    put32("last_ni_gain", last_ni_gain, BANDS_MAX); put16("last_env", last_env, BANDS_MAX);
    put1("last_max_pos_pulse", last_max_pos_pulse); put1("hqswb_clas", hqswb_clas); put1("bwidth", bwidth);

    Word32 y2[2][L_FRAME48k], ep[2][BANDS_MAX], rk[2][BANDS_MAX], ener_l[2], ener_h[2];
    Word16 npulses[2][BANDS_MAX], seed[2], bw_low[2], bw_high[2], p2a_flags[2][BANDS_MAX];
    for (int f = 0; f < 2; f++) {
        Word16 inp[L_FRAME48k];
        Word32 energy[BANDS_MAX];
        random_pulses(&c, inp, npulses[f]);
        for (int k = 0; k < c.bands; k++) energy[k] = random_range(0, 24 << 14);
        for (int i = 0; i < n; i++) y2[f][i] = 0;
        mdct_spectrum_denorm_fx(inp, y2[f], c.band_start, c.band_end, c.band_width, energy, npulses[f], c.bands,
                                c.ld_slope, c.pd_thresh);
        for (int k = 0; k < c.bands; k++) {
            /* Ep is the band energy in Q-6, derived from the same quantised log2 energy the pulses
             * were scaled to, exactly as hq_lr_dec_fx derives it. */
            Word16 exp;
            Word16 frac1 = L_Extract_lc(L_shl(energy[k], 16 - SWB_BWE_LR_Qbe), &exp);
            ep[f][k] = L_shl(Pow2(30, frac1), s_max(sub(sub(exp, 30), 6), -31));
            rk[f][k] = (next_random() % 5) ? random_range(0, c.band_width[k] * 3) << 16 | random_range(0, 65535) : 0;
            p2a_flags[f][k] = (Word16)random_range(0, 1);
        }
        seed[f] = random16();
        bw_low[f] = (Word16)random_range(1, 320);
        bw_high[f] = (Word16)random_range(1, 320);
        ener_l[f] = 0;
        ener_h[f] = 0;
        for (int k = 0; k < c.bands; k++) {
            if (k >= c.bands / 2) ener_h[f] = L_add(ener_h[f], L_shl(ep[f][k], 2));
            else ener_l[f] = L_add(ener_l[f], L_shl(ep[f][k], 2));
        }
        char name[24];
        sprintf(name, "y2_%d", f); put32(name, y2[f], n);
        sprintf(name, "ep%d", f); put32(name, ep[f], c.bands);
        sprintf(name, "rk%d", f); put32(name, rk[f], c.bands);
        sprintf(name, "npulses%d", f); put16(name, npulses[f], c.bands);
        sprintf(name, "p2a_flags%d", f); put16(name, p2a_flags[f], c.bands);
        sprintf(name, "seed%d", f); put1(name, seed[f]);
        sprintf(name, "bw_low%d", f); put1(name, bw_low[f]);
        sprintf(name, "bw_high%d", f); put1(name, bw_high[f]);
        sprintf(name, "ener_l%d", f); put1(name, ener_l[f]);
        sprintf(name, "ener_h%d", f); put1(name, ener_h[f]);
    }
    arrow();
    for (int f = 0; f < 2; f++) {
        hq2_noise_inject_fx(y2[f], c.band_start, c.band_end, c.band_width, ep[f], rk[f], npulses[f], seed[f], c.bands,
                            0, bw_low[f], bw_high[f], ener_l[f], ener_h[f], last_ni_gain, last_env,
                            &last_max_pos_pulse, p2a_flags[f], c.p2a_bands, hqswb_clas, bwidth, c.bwe_br);
        char name[24];
        sprintf(name, "y2_%d", f); put32(name, y2[f], n);
        sprintf(name, "ep%d", f); put32(name, ep[f], c.bands);
        sprintf(name, "last_ni_gain%d", f); put32(name, last_ni_gain, BANDS_MAX);
        sprintf(name, "last_env%d", f); put16(name, last_env, BANDS_MAX);
        sprintf(name, "last_max_pos_pulse%d", f); put1(name, last_max_pos_pulse);
    }
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq2_noise_inject")) case_hq2_noise_inject();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
