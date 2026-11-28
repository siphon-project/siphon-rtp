/* Function-level oracle for lib_com/env_adj_fx.c, on the layouts hq_hr_dec_fx runs fill_spectrum_fx with
 * (the adjustment only runs for 640 and 320 coefficient frames, never HVQ / harmonic at 640). The pulse
 * counts are what pvq_core_dec_fx leaves: zero for noise-filled bands and beyond the coded ones. */
#include "hq_bit_allocation_inputs.h"

static void case_env_adj(void)
{
    HqAllocInput c;
    do random_hq_alloc_input(&c); while (c.length == L_FRAME48k || c.hqswb_clas == HQ_HVQ || (c.length == L_FRAME32k && c.hqswb_clas == HQ_HARMONIC));
    Word16 pulses[NB_SFM], adj[NB_SFM], env_stab = (Word16)(next_random() % 4 ? random_range(0, 32767) : random16() & 0x7fff);
    Word16 last_sfm = (Word16)random_range(0, c.num_sfm - 1);
    int density = random_range(0, 6);
    for (int i = 0; i < NB_SFM; i++) {
        pulses[i] = (Word16)(i > last_sfm + 1 ? 0 : random_range(0, 6) < density ? random_range(1, 50) : 0);
        if (next_random() % 4 == 0 && pulses[i]) pulses[i] = (Word16)random_range(1, 12);
        adj[i] = -7;
    }
    put1("length", c.length); put1("last_sfm", last_sfm); put1("env_stab", env_stab); put16("pulses", pulses, NB_SFM);
    put16("sfmsize", c.sfmsize, c.num_sfm);
    env_adj_fx(pulses, c.length, last_sfm, adj, env_stab, c.sfmsize);
    arrow(); put16("adj", adj, NB_SFM); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "env_adj")) case_env_adj();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
