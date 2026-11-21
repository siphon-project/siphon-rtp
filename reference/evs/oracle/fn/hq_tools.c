/* Function-level oracle for the small helpers of lib_com/hq_tools_fx.c: hvq_concat_bands_fx,
 * hq_fold_bwe_fx, enforce_zero_for_min_envelope_fx, map_hq_generic_fenv_norm_fx and
 * get_nor_delta_hf_fx. Layouts and class/rate pairs come from hq_bit_allocation_inputs.h (what
 * hq_hr_dec_fx feeds the HQ tools). */
#include "hq_bit_allocation_inputs.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void case_hvq_concat_bands(void)
{
    /* hvq_pvq_bitalloc_fx returns at least one fixed band, then up to a few selected harmonic bands */
    Word16 fixed = (Word16)random_range(1, 8), n_sel = (Word16)random_range(0, 6);
    Word16 pvq_bands = (Word16)(fixed + n_sel), sel[8], start[16], width[16], end[16];
    for (int i = 0; i < 8; i++) sel[i] = (Word16)random_range(0, SFM_N_HARM_FB - 1);
    for (int i = 0; i < 16; i++) { start[i] = -7; width[i] = -7; end[i] = -7; }
    put1("pvq_bands", pvq_bands); put16("sel", sel, 8); put1("n_sel", n_sel);
    hvq_concat_bands_fx(pvq_bands, sel, n_sel, start, width, end);
    arrow(); put16("start", start, 16); put16("width", width, 16); put16("end", end, 16); end_line();
}

static void case_hq_fold_bwe(void)
{
    /* HQ_NORMAL frames: the SWB/FB/WB band layouts, last_sfm anywhere from the first band to the last */
    HqAllocInput c;
    do random_hq_alloc_input(&c); while (c.hqswb_clas != HQ_NORMAL);
    Word16 coeff[L_FRAME48k], last_sfm = (Word16)random_range(0, c.num_sfm - 1);
    if (next_random() % 4 == 0) last_sfm = (Word16)(c.num_sfm - 1);
    random_signal(coeff, L_FRAME48k, 1 << random_range(2, 15));
    put1("last_sfm", last_sfm); put1("num_sfm", c.num_sfm); put16("sfm_end", c.sfm_end, c.num_sfm);
    put16("coeff", coeff, L_FRAME48k);
    hq_fold_bwe_fx(last_sfm, c.sfm_end, c.num_sfm, coeff);
    arrow(); put16("coeff", coeff, L_FRAME48k); end_line();
}

static void case_enforce_zero_for_min_envelope(void)
{
    HqAllocInput c;
    static Word32 coefsq[L_FRAME48k];
    random_hq_alloc_input(&c);
    for (int i = 0; i < L_FRAME48k; i++) coefsq[i] = random32();
    if (next_random() % 3 == 0) for (int i = 0; i < NB_SFM; i++) c.ynrm[i] = (Word16)(next_random() % 2 ? 39 : 31);
    if (next_random() % 2) c.ynrm[0] = 31;
    put1("hqswb_clas", c.hqswb_clas); put16("ynrm", c.ynrm, NB_SFM); put32("coefsq", coefsq, L_FRAME48k);
    put1("nb_sfm", c.nb_sfm); put16("sfm_start", c.sfm_start, c.nb_sfm); put16("sfm_end", c.sfm_end, c.nb_sfm);
    enforce_zero_for_min_envelope_fx(c.hqswb_clas, c.ynrm, coefsq, c.nb_sfm, c.sfm_start, c.sfm_end);
    arrow(); put32("coefsq", coefsq, L_FRAME48k); end_line();
}

static void case_map_hq_generic_fenv_norm(void)
{
    HqAllocInput c;
    do random_hq_alloc_input(&c); while (c.hqswb_clas != HQ_GEN_SWB && c.hqswb_clas != HQ_GEN_FB);
    Word16 fenv[SWB_FENV + DIM_FB + 4], normqlg2[NB_SFM];
    int kind = (int)(next_random() % 4);
    for (int i = 0; i < SWB_FENV + DIM_FB + 4; i++)
        fenv[i] = (Word16)(kind == 0 ? random_range(0, 32767) : kind == 1 ? 0 : random_range(0, 2500));
    for (int i = 0; i < NB_SFM; i++) normqlg2[i] = -4;
    put1("hqswb_clas", c.hqswb_clas); put16("fenv", fenv, SWB_FENV + DIM_FB + 4); put16("ynrm", c.ynrm, NB_SFM);
    put16("normqlg2", normqlg2, NB_SFM); put1("num_env_bands", c.num_env_bands); put1("nb_sfm", c.nb_sfm);
    put1("hq_generic_offset", c.hq_generic_offset);
    map_hq_generic_fenv_norm_fx(c.hqswb_clas, fenv, c.ynrm, normqlg2, c.num_env_bands, c.nb_sfm, c.hq_generic_offset);
    arrow(); put16("ynrm", c.ynrm, NB_SFM); put16("normqlg2", normqlg2, NB_SFM); end_line();
}

static void case_get_nor_delta_hf(void)
{
    HqAllocInput c;
    do random_hq_alloc_input(&c); while (c.hqswb_clas != HQ_GEN_SWB && c.hqswb_clas != HQ_GEN_FB);
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 rsubband[NB_SFM], core_sfm = (Word16)random_range(c.num_env_bands - 2, c.nb_sfm - 1), bits = -7;
    int n = 600, density = (int)(next_random() % 3);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(density == 0 ? (next_random() % 6 == 0) : (next_random() & 1));
    for (int i = 0; i < NB_SFM; i++)
        rsubband[i] = (Word16)(next_random() % 3 == 0 ? 0 : next_random() % 3 ? random_range(25, 400) : random_range(1, 24));
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(next_random() % 12 ? random_range(0, 100) : random_range(n - 30, n));
    st->codec_mode = MODE1;
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put16("ynrm", c.ynrm, NB_SFM);
    put16("rsubband", rsubband, NB_SFM); put1("num_env_bands", c.num_env_bands); put1("nb_sfm", c.nb_sfm);
    put1("core_sfm", core_sfm);
    /* update_rsubband_fx loops for ever when no band above 24 is left to take bits from; the decoder's
     * allocation always leaves enough, so such a case is printed as skip */
    int ok = GUARDED(bits = get_nor_delta_hf_fx(st, c.ynrm, rsubband, c.num_env_bands, c.nb_sfm, core_sfm));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); free(st); return; }
    put1("bits", bits); put16("ynrm", c.ynrm, NB_SFM); put16("rsubband", rsubband, NB_SFM);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hvq_concat_bands")) case_hvq_concat_bands();
        else if (!strcmp(argv[2], "hq_fold_bwe")) case_hq_fold_bwe();
        else if (!strcmp(argv[2], "enforce_zero_for_min_envelope")) case_enforce_zero_for_min_envelope();
        else if (!strcmp(argv[2], "map_hq_generic_fenv_norm")) case_map_hq_generic_fenv_norm();
        else if (!strcmp(argv[2], "get_nor_delta_hf")) case_get_nor_delta_hf();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
