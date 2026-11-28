/* Function-level oracle for the HQ-core parts of lib_com/swb_bwe_com_fx.c: calc_normal_length_fx_32 and
 * hq_generic_decoding_fx (the other functions of that file are covered by swb_bwe_com.c). Inputs are the
 * fill_spectrum_fx scenario (hq_scenario.h) run through hq_generic_fine_fx and apply_envelope_fx. */
#include "hq_scenario.h"

static void random_hq_spectrum32(Word32 *x)
{
    int kind = (int)(next_random() % 5), shift = random_range(8, 30);
    if (kind == 4) kind = 3;
    for (int i = 0; i < 256; i++) {
        if (kind == 0) x[i] = 0;
        else if (kind == 1) x[i] = (i % 16 == 5) ? (Word32)random_range(50000, 1 << 24) : (Word32)random_range(-3000, 3000);
        else if (kind == 2) x[i] = (Word32)((next_random() << 16) ^ next_random()) >> shift;
        else x[i] = 0;
    }
    /* blocks of 16 with a peak of a chosen ratio over a flat floor, around the detector's thresholds,
     * sometimes the peak exactly 40960 */
    if (kind == 3) {
        for (int b = 0; b < 16; b++) {
            Word32 floor_level = next_random() & 1 ? random_range(1, 6000) : random_range(2000, 40000), ratio = random_range(1, 24);
            Word32 peak = next_random() % 8 == 0 ? 40960 + (Word32)(next_random() & 1) : floor_level * ratio;
            for (int i = 0; i < 16; i++) x[b * 16 + i] = (next_random() & 1 ? 1 : -1) * floor_level;
            x[b * 16 + random_range(0, 15)] = next_random() & 1 ? peak : -peak;
        }
    }
}

static void case_calc_normal_length_32(void)
{
    Word32 sp[256];
    random_hq_spectrum32(sp);
    static const Word16 modes[] = {HQ_NORMAL, HQ_TRANSIENT, HQ_HARMONIC, HQ_HVQ, HQ_GEN_SWB, HQ_GEN_FB};
    Word16 core = (Word16)(next_random() % 4 ? HQ_CORE : ACELP_CORE), mode = modes[next_random() % 6];
    if (core == ACELP_CORE) mode = (Word16)random_range(0, 3);
    static const Word16 extls[] = {WB_BWE, SWB_BWE, FB_BWE, -1, SWB_TBE};
    Word16 extl = extls[next_random() % 5], prev = (Word16)random_range(0, 64), norm = -1;
    put32("sp", sp, 256); put1("core", core); put1("mode", mode); put1("extl", extl); put1("prev", prev);
    calc_normal_length_fx_32(core, sp, mode, extl, &norm, &prev);
    arrow(); put1("norm", norm); put1("prev", prev); end_line();
}

static void case_hq_generic_decoding(void)
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
    put1("hqswb_clas", s.c.hqswb_clas); put1("offset", s.c.hq_generic_offset); put16("fenv", fenv, SWB_FENV + DIM_FB + 4);
    put1("prev", prev); put1("exc", exc); put16("r", s.R, NB_SFM); put32("out", out, L_FRAME48k); put32("out1", out1, L_FRAME48k);
    int ok = GUARDED(hq_generic_decoding_fx(s.c.hqswb_clas, out1, fenv, out, s.c.hq_generic_offset, &prev, exc, s.R));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("prev", prev); put32("out", out, L_FRAME48k); put32("out1", out1, L_FRAME48k); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "calc_normal_length_32")) case_calc_normal_length_32();
        else if (!strcmp(argv[2], "hq_generic_decoding")) case_hq_generic_decoding();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
