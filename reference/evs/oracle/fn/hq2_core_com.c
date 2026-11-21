/* Function-level oracle for lib_com/hq2_core_com_fx.c (the low-rate HQ core helpers). Band layouts
 * come from hq2_core_configure_fx itself, so every case runs on a configuration the decoder can
 * select. */
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

static void case_hq2_core_configure(void)
{
    Config c;
    random_config(&c);
    put_config_inputs(&c);
    arrow();
    put1("bands", c.bands); put1("length", c.length); put16("band_width", c.band_width, c.bands);
    put16("band_start", c.band_start, c.bands); put16("band_end", c.band_end, c.bands); put1("qint", c.qint);
    put1("eref", c.eref); put1("bit_alloc_weight", c.bit_alloc_weight); put1("gqlevs", c.gqlevs);
    put1("ngq", c.ngq); put1("p2a_bands", c.p2a_bands); put1("p2a_th", c.p2a_th);
    put1("pd_thresh", c.pd_thresh); put1("ld_slope", c.ld_slope); put1("ni_coef", c.ni_coef);
    end_line();
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

static void case_mdct_spectrum_denorm(void)
{
    Config c;
    Word16 inp[L_FRAME48k], npulses[BANDS_MAX];
    Word32 y2[L_FRAME48k], energy[BANDS_MAX];
    random_config(&c);
    random_pulses(&c, inp, npulses);
    for (int k = 0; k < c.bands; k++) energy[k] = random_range(0, 30 << 14);
    int n = c.band_end[c.bands - 1] + 1;
    for (int i = 0; i < n; i++) y2[i] = random_range(-1000, 1000);
    put_config_inputs(&c);
    put16("inp", inp, n); put32("energy", energy, c.bands); put16("npulses", npulses, c.bands); put32("y2", y2, n);
    mdct_spectrum_denorm_fx(inp, y2, c.band_start, c.band_end, c.band_width, energy, npulses, c.bands, c.ld_slope,
                            c.pd_thresh);
    arrow(); put32("y2", y2, n); end_line();
}

static void case_reverse_transient_frame_energies(void)
{
    Word32 energy[BANDS_MAX];
    Word16 bands = (Word16)(4 * random_range(4, 8));
    for (int k = 0; k < bands; k++) energy[k] = random32();
    put32("energy", energy, bands);
    reverse_transient_frame_energies_fx(energy, bands);
    arrow(); put32("energy", energy, bands); end_line();
}

static void case_bit_allocation_second(void)
{
    Config c;
    Word32 rk[BANDS_MAX], rk_sort[BANDS_MAX];
    Word16 k_sort[BANDS_MAX], k_num[2] = {-5, -5}, p2a_flags[BANDS_MAX], last_bitalloc[2];
    random_config(&c);
    for (int k = 0; k < c.bands; k++)
        rk[k] = (next_random() % 5) ? random_range(0, c.band_width[k] * 6) << 16 | random_range(0, 65535) : 0;
    for (int k = 0; k < c.bands; k++) p2a_flags[k] = (Word16)random_range(0, 1);
    last_bitalloc[0] = (Word16)random_range(0, 1);
    last_bitalloc[1] = (Word16)random_range(0, 1);
    srt_vec_ind_fx(rk, rk_sort, k_sort, c.bands);
    static const Word16 frames[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k};
    Word16 input_frame = frames[next_random() % 3];
    put_config_inputs(&c);
    put32("rk", rk, c.bands); put32("rk_sort", rk_sort, c.bands); put16("k_sort", k_sort, c.bands);
    put16("p2a_flags", p2a_flags, c.bands); put16("last_bitalloc", last_bitalloc, 2); put1("input_frame", input_frame);
    bit_allocation_second_fx(rk, rk_sort, c.bands, c.band_width, k_sort, k_num, p2a_flags, c.p2a_bands, last_bitalloc,
                             input_frame);
    arrow(); put16("k_num", k_num, 2); end_line();
}

/* The SWB 13.2 / 16.4 kbit/s long-window layout the shortened-band (SPT) path runs on. */
static void swb_config(Config *c)
{
    c->frame_length = L_FRAME32k;
    c->is_transient = 0;
    c->bwe_br = next_random() & 1 ? HQ_13k20 : HQ_16k40;
    c->num_bits = (Word16)random_range(200, 328);
    hq2_core_configure_fx(c->frame_length, c->num_bits, c->is_transient, &c->bands, &c->length, c->band_width,
                          c->band_start, c->band_end, &c->qint, &c->eref, &c->bit_alloc_weight, &c->gqlevs,
                          &c->ngq, &c->p2a_bands, &c->p2a_th, &c->pd_thresh, &c->ld_slope, &c->ni_coef, c->bwe_br);
}

/* spt_shorten_domain_band_save_fx, spt_shorten_domain_pre_fx and spt_shorten_domain_band_restore_fx
 * in hq_lr_dec_fx's order: previous peaks inside, near the edges of, or absent from each high band. */
static void case_spt_shorten_domain(void)
{
    Config c;
    swb_config(&c);
    Word16 peaks[SPT_SHORTEN_SBNUM], ns[SPT_SHORTEN_SBNUM], ne[SPT_SHORTEN_SBNUM], nw[SPT_SHORTEN_SBNUM];
    Word16 os[SPT_SHORTEN_SBNUM], oe[SPT_SHORTEN_SBNUM], ow[SPT_SHORTEN_SBNUM];
    for (int j = 0; j < SPT_SHORTEN_SBNUM; j++) {
        int k = c.bands - SPT_SHORTEN_SBNUM + j, pick = next_random() % 4;
        peaks[j] = pick == 0 ? 0 : pick == 1 ? c.band_start[k] + random_range(0, 3) : pick == 2 ? c.band_end[k] - random_range(0, 3)
                                                                                               : (Word16)random_range(c.band_start[k], c.band_end[k]);
        ns[j] = ne[j] = nw[j] = os[j] = oe[j] = ow[j] = -7;
    }
    put1("bands", c.bands); put1("bwe_br", c.bwe_br); put16("peaks", peaks, SPT_SHORTEN_SBNUM);
    put16("band_start", c.band_start, c.bands); put16("band_end", c.band_end, c.bands); put16("band_width", c.band_width, c.bands);
    spt_shorten_domain_band_save_fx(c.bands, c.band_start, c.band_end, c.band_width, os, oe, ow);
    spt_shorten_domain_pre_fx(c.band_start, c.band_end, peaks, c.bands, c.bwe_br, ns, ne, nw);
    arrow(); put16("os", os, SPT_SHORTEN_SBNUM); put16("oe", oe, SPT_SHORTEN_SBNUM); put16("ow", ow, SPT_SHORTEN_SBNUM);
    put16("ns", ns, SPT_SHORTEN_SBNUM); put16("ne", ne, SPT_SHORTEN_SBNUM); put16("nw", nw, SPT_SHORTEN_SBNUM);
    /* the decoder moves some of the last bands to their shortened layout, then restores them */
    for (int j = 0; j < SPT_SHORTEN_SBNUM; j++)
        if (next_random() & 1) {
            int k = c.bands - SPT_SHORTEN_SBNUM + j;
            c.band_start[k] = ns[j]; c.band_end[k] = ne[j]; c.band_width[k] = nw[j];
        }
    put16("moved_start", c.band_start, c.bands); put16("moved_end", c.band_end, c.bands); put16("moved_width", c.band_width, c.bands);
    spt_shorten_domain_band_restore_fx(c.bands, c.band_start, c.band_end, c.band_width, os, oe, ow);
    put16("band_start", c.band_start, c.bands); put16("band_end", c.band_end, c.bands); put16("band_width", c.band_width, c.bands);
    end_line();
}

static void case_spt_swb_peakpos_tmp_save(void)
{
    Config c;
    swb_config(&c);
    static Word32 y2[L_FRAME32k];
    Word16 pos[SPT_SHORTEN_SBNUM] = {-7, -7, -7, -7};
    for (int i = 0; i < L_FRAME32k; i++)
        y2[i] = next_random() % 4 ? 0 : next_random() % 8 ? random_range(-(1 << 20), 1 << 20) : random32();
    if (next_random() % 4 == 0) { int at = random_range(0, L_FRAME32k - 2); y2[at + 1] = -y2[at]; }
    put32("y2", y2, L_FRAME32k); put1("bands", c.bands); put16("band_start", c.band_start, c.bands); put16("band_end", c.band_end, c.bands);
    spt_swb_peakpos_tmp_save_fx(y2, c.bands, c.band_start, c.band_end, pos);
    arrow(); put16("pos", pos, SPT_SHORTEN_SBNUM); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq2_core_configure")) case_hq2_core_configure();
        else if (!strcmp(argv[2], "mdct_spectrum_denorm")) case_mdct_spectrum_denorm();
        else if (!strcmp(argv[2], "reverse_transient_frame_energies")) case_reverse_transient_frame_energies();
        else if (!strcmp(argv[2], "bit_allocation_second")) case_bit_allocation_second();
        else if (!strcmp(argv[2], "spt_shorten_domain")) case_spt_shorten_domain();
        else if (!strcmp(argv[2], "spt_swb_peakpos_tmp_save")) case_spt_swb_peakpos_tmp_save();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
