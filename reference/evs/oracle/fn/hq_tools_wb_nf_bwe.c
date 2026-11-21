/* Function-level oracle for hq_wb_nf_bwe_fx (lib_com/hq_tools_fx.c): the WB noise filling and BWE
 * refinement fill_spectrum_fx runs for 320 coefficient frames at 32 kbit/s. The bit allocation comes
 * from hq_bit_allocation_fx, the norms and the enveloped spectrum from apply_envelope_fx, so the
 * inputs are what the decoder has at that point; the previous-frame memories are random but
 * correlated with the current norms so every smoothing branch is taken. */
#include "hq_bit_allocation_inputs.h"

static void case_hq_wb_nf_bwe(void)
{
    HqAllocInput c;
    do { random_hq_alloc_input(&c); } while (c.length != L_FRAME16k || c.core_brate != HQ_32k);
    Word16 R[NB_SFM], Rsubband[NB_SFM], noise_level[HVQ_BWE_NOISE_BANDS], sum, core_sfm, num_bits = c.num_bits;
    for (int i = 0; i < NB_SFM; i++) { R[i] = 0; Rsubband[i] = 0; }
    sum = 0; core_sfm = 0;
    if (!GUARDED(hq_bit_allocation_fx(c.core_brate, c.length, c.hqswb_clas, &num_bits, c.normqlg2, c.nb_sfm, c.sfmsize,
                                      noise_level, R, Rsubband, &sum, &core_sfm, c.num_env_bands))) {
        printf(" bit_allocation_failed=1 -> skip=1\n");
        return;
    }
    Word16 is_transient = (Word16)(c.hqswb_clas == HQ_TRANSIENT);
    Word16 last_sfm = is_transient ? (Word16)(c.num_sfm - 1) : core_sfm;
    Word16 coeff[L_FRAME48k], norm_adj[NB_SFM], fine[L_FRAME48k];
    static Word32 normq_v[NB_SFM], out[L_FRAME48k], out1[L_FRAME48k];
    int all = next_random() % 6 == 0, sparse = random_range(1, 4), spread = random_range(4, 14);
    for (int i = 0; i < L_FRAME48k; i++) { coeff[i] = 0; fine[i] = 0; out[i] = 0; out1[i] = 0; }
    for (int b = 0; b < c.num_sfm; b++)
        for (int i = c.sfm_start[b]; i < c.sfm_end[b]; i++)
            if ((R[b] != 0 || all) && next_random() % 5 < (unsigned)sparse) coeff[i] = (Word16)random_range(-(1 << spread), 1 << spread);
    for (int i = 0; i < NB_SFM; i++) norm_adj[i] = 32767;
    apply_envelope_fx(coeff, c.ynrm, norm_adj, c.num_sfm, last_sfm, c.hqswb_clas, c.length, c.sfm_start, c.sfm_end, normq_v, out,
                      fine, out1);
    Word32 prev_normq[SFM_N_WB], prev_env[SFM_N_WB], prev_coeff_out[L_HQ_WB_BWE];
    Word16 prev_env_Q[SFM_N_WB], prev_R = (Word16)(next_random() % 3 ? random_range(0, 6) : 0), seed = random16();
    Word16 prev_bfi = (Word16)(next_random() % 4 == 0), prev_is_transient = (Word16)(next_random() % 4 == 0);
    for (int i = 0; i < SFM_N_WB; i++) {
        int kind = (int)(next_random() % 4);
        prev_normq[i] = kind == 0 ? normq_v[i] : kind == 1 ? normq_v[i] >> random_range(0, 2) : kind == 2 ? normq_v[i] << random_range(0, 1) : random32() & 0x7fffffff;
        prev_env[i] = (Word32)(next_random() & 0x3fffffff) >> random_range(0, 20);
        prev_env_Q[i] = (Word16)random_range(0, 30);
    }
    for (int i = 0; i < L_HQ_WB_BWE; i++) prev_coeff_out[i] = out[L_FRAME16k - L_HQ_WB_BWE + i] >> random_range(-1, 3);
    Word32 p_normq[SFM_N_WB], p_env[SFM_N_WB], p_pco[L_HQ_WB_BWE];
    Word16 p_envq[SFM_N_WB], p_R = prev_R, p_seed = seed;
    memcpy(p_normq, prev_normq, sizeof p_normq); memcpy(p_env, prev_env, sizeof p_env);
    memcpy(p_pco, prev_coeff_out, sizeof p_pco); memcpy(p_envq, prev_env_Q, sizeof p_envq);
    put1("is_transient", is_transient); put1("prev_bfi", prev_bfi); put32("normq", normq_v, SFM_N_WB);
    put1("num_sfm", c.num_sfm); put16("sfm_start", c.sfm_start, c.num_sfm); put16("sfm_end", c.sfm_end, c.num_sfm);
    put16("sfmsize", c.sfmsize, c.num_sfm); put1("last_sfm", last_sfm); put16("r", R, NB_SFM);
    put1("prev_is_transient", prev_is_transient); put32("prev_normq", p_normq, SFM_N_WB); put32("prev_env", p_env, SFM_N_WB);
    put1("seed", seed); put32("prev_coeff_out", p_pco, L_HQ_WB_BWE); put1("prev_r", p_R);
    put16("prev_env_q", p_envq, SFM_N_WB); put16("coeff", coeff, L_FRAME16k); put32("out", out, L_FRAME16k);
    int ok = GUARDED(hq_wb_nf_bwe_fx(coeff, is_transient, prev_bfi, normq_v, c.num_sfm, c.sfm_start, c.sfm_end, c.sfmsize,
                                     last_sfm, R, prev_is_transient, prev_normq, prev_env, &seed, prev_coeff_out, &prev_R, out,
                                     prev_env_Q));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put32("prev_normq", prev_normq, SFM_N_WB); put32("prev_env", prev_env, SFM_N_WB); put1("seed", seed);
    put32("prev_coeff_out", prev_coeff_out, L_HQ_WB_BWE); put1("prev_r", prev_R); put16("prev_env_q", prev_env_Q, SFM_N_WB);
    put32("out", out, L_FRAME16k); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq_wb_nf_bwe")) case_hq_wb_nf_bwe();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
