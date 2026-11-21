/* Function-level oracle for the noise-fill and envelope part of lib_com/hq_tools_fx.c
 * (build_nf_codebook_fx, apply_noisefill_HQ_fx, apply_nf_gain_fx, hq_generic_fine_fx, hq_bwe_fx,
 * apply_envelope_fx). Every case is a scenario as fill_spectrum_fx sees it: the layout, class and rate
 * of hq_hr_dec_fx, a bit allocation with coded low bands, the PVQ spectrum nonzero where bits were
 * spent, last_sfm by fill_spectrum_fx's rule. The later stages run the earlier reference functions
 * to make their inputs (codebook, fine structure, enveloped spectrum). */
#include "hq_scenario.h"

static Word16 flag_for(const Scenario *s) { return (Word16)(s->c.length == L_FRAME32k && next_random() % 2); }

static void case_build_nf_codebook(void)
{
    Scenario s; random_scenario(&s);
    Word16 cb[FREQ_LENGTH], cbm[FREQ_LENGTH], flag = flag_for(&s);
    for (int i = 0; i < FREQ_LENGTH; i++) { cb[i] = -7; cbm[i] = -7; }
    put_layout(&s); put1("flag", flag); put16("coeff", s.coeff, L_FRAME48k);
    Word16 size = build_nf_codebook_fx(flag, s.coeff, s.c.sfm_start, s.c.sfmsize, s.c.sfm_end, s.last_sfm, s.R, cb, cbm);
    arrow(); put1("size", size); put16("cb", cb, FREQ_LENGTH); put16("cbm", cbm, FREQ_LENGTH); end_line();
}

static void case_apply_noisefill_hq(void)
{
    Scenario s; random_scenario(&s);
    Word16 cb[FREQ_LENGTH], cbm[FREQ_LENGTH], flag = flag_for(&s);
    for (int i = 0; i < FREQ_LENGTH; i++) { cb[i] = -7; cbm[i] = -7; }
    Word16 size = build_nf_codebook_fx(flag, s.coeff, s.c.sfm_start, s.c.sfmsize, s.c.sfm_end, s.last_sfm, s.R, cb, cbm);
    if (size <= 0) { size = 1; cb[0] = 4096; cbm[0] = 4096; }
    put_layout(&s); put1("flag", flag); put16("cb", cb, FREQ_LENGTH); put16("cbm", cbm, FREQ_LENGTH); put1("size", size);
    put16("coeff", s.coeff, L_FRAME48k);
    apply_noisefill_HQ_fx(s.R, s.c.length, flag, s.c.core_brate, s.last_sfm, cb, cbm, size, s.c.sfm_start, s.c.sfm_end,
                          s.c.sfmsize, s.coeff);
    arrow(); put16("coeff", s.coeff, L_FRAME48k); end_line();
}

static void case_apply_nf_gain(void)
{
    Scenario s; random_scenario(&s);
    Word16 nf_idx = (Word16)random_range(0, 3);
    put_layout(&s); put1("nf_idx", nf_idx); put16("coeff", s.coeff, L_FRAME48k);
    apply_nf_gain_fx(nf_idx, s.last_sfm, s.R, s.c.sfm_start, s.c.sfm_end, s.coeff);
    arrow(); put16("coeff", s.coeff, L_FRAME48k); end_line();
}

static void case_hq_generic_fine(void)
{
    Scenario s; random_scenario(&s);
    Word16 seed = random16(), out[L_FRAME48k];
    for (int i = 0; i < L_FRAME48k; i++) out[i] = -7;
    put_layout(&s); put1("seed", seed); put16("coeff", s.coeff, L_FRAME48k);
    hq_generic_fine_fx(s.coeff, s.last_sfm, s.c.sfm_start, s.c.sfm_end, &seed, out);
    arrow(); put1("seed", seed); put16("out", out, L_FRAME48k); end_line();
}

/* Norms for apply_envelope_fx / hq_bwe_fx: the indices hq_hr_dec_fx has (ynrm), within 0..39. */
static void case_apply_envelope(void)
{
    Scenario s; random_scenario(&s);
    static Word32 normq_v[NB_SFM], out[L_FRAME48k], out1[L_FRAME48k];
    Word16 fine[L_FRAME48k];
    for (int i = 0; i < NB_SFM; i++) normq_v[i] = -7;
    for (int i = 0; i < L_FRAME48k; i++) { out[i] = -7; out1[i] = -7; fine[i] = (Word16)(next_random() % 3 ? random_range(-4096, 4096) : random16()); }
    put_layout(&s); put16("norm", s.c.ynrm, NB_SFM); put16("norm_adj", s.norm_adj, NB_SFM);
    put16("coeff", s.coeff, L_FRAME48k); put16("fine", fine, L_FRAME48k);
    apply_envelope_fx(s.coeff, s.c.ynrm, s.norm_adj, s.c.num_sfm, s.last_sfm, s.c.hqswb_clas, s.c.length, s.c.sfm_start,
                      s.c.sfm_end, normq_v, out, fine, out1);
    arrow(); put32("normq_v", normq_v, NB_SFM); put32("out", out, L_FRAME48k); put32("out1", out1, L_FRAME48k); end_line();
}

/* HQ GENERIC: the BWE input is hq_generic_fine's excitation scaled by the envelope, the core spectrum
 * the enveloped coefficients, exactly the chain fill_spectrum_fx runs. */
static void case_hq_bwe(void)
{
    Scenario s;
    do random_scenario(&s); while (s.c.hqswb_clas != HQ_GEN_SWB && s.c.hqswb_clas != HQ_GEN_FB);
    static Word32 normq_v[NB_SFM], out[L_FRAME48k], out1[L_FRAME48k];
    Word16 fine[L_FRAME48k], seed = random16(), prev = (Word16)random_range(0, 60);
    Word16 fenv[SWB_FENV + DIM_FB + 4], exc = (Word16)random_range(0, 2);
    for (int i = 0; i < L_FRAME48k; i++) { out[i] = 0; out1[i] = 0; fine[i] = 0; }
    int kind = (int)(next_random() % 4);
    for (int i = 0; i < SWB_FENV + DIM_FB + 4; i++) fenv[i] = (Word16)(kind == 0 ? random_range(0, 32767) : kind == 1 ? random_range(0, 40) : random_range(0, 3000));
    hq_generic_fine_fx(s.coeff, s.last_sfm, s.c.sfm_start, s.c.sfm_end, &seed, fine);
    apply_envelope_fx(s.coeff, s.c.ynrm, s.norm_adj, s.c.num_sfm, s.last_sfm, s.c.hqswb_clas, s.c.length, s.c.sfm_start,
                      s.c.sfm_end, normq_v, out, fine, out1);
    put_layout(&s); put1("offset", s.c.hq_generic_offset); put16("fenv", fenv, SWB_FENV + DIM_FB + 4);
    put1("prev", prev); put1("exc", exc); put32("out", out, L_FRAME48k); put32("out1", out1, L_FRAME48k);
    int ok = GUARDED(hq_bwe_fx(s.c.hqswb_clas, out1, fenv, out, s.c.hq_generic_offset, &prev, exc, s.c.sfm_end, s.c.num_sfm,
                               s.c.num_env_bands, s.R));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("prev", prev); put32("out", out, L_FRAME48k); put32("out1", out1, L_FRAME48k); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "build_nf_codebook")) case_build_nf_codebook();
        else if (!strcmp(argv[2], "apply_noisefill_hq")) case_apply_noisefill_hq();
        else if (!strcmp(argv[2], "apply_nf_gain")) case_apply_nf_gain();
        else if (!strcmp(argv[2], "hq_generic_fine")) case_hq_generic_fine();
        else if (!strcmp(argv[2], "apply_envelope")) case_apply_envelope();
        else if (!strcmp(argv[2], "hq_bwe")) case_hq_bwe();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
