/* A fill_spectrum_fx scenario shared by the HQ tool oracles: the layout, class and rate of hq_hr_dec_fx, a
 * bit allocation with coded low bands, the PVQ spectrum nonzero where bits were spent, last_sfm by
 * fill_spectrum_fx's rule. */
#ifndef HQ_SCENARIO_H
#define HQ_SCENARIO_H
#include "hq_bit_allocation_inputs.h"

typedef struct {
    HqAllocInput c;
    Word16 last_sfm, core_sfm, R[NB_SFM], coeff[L_FRAME48k], norm_adj[NB_SFM];
    Word16 sfmsize_copy[NB_SFM];
} Scenario;

static void random_scenario(Scenario *s)
{
    do random_hq_alloc_input(&s->c); while (s->c.hqswb_clas == HQ_HVQ);
    HqAllocInput *c = &s->c;
    int dense = random_range(1, 5);
    s->core_sfm = (Word16)random_range(0, c->nb_sfm - 1);
    for (int i = 0; i < NB_SFM; i++) s->R[i] = 0;
    for (int i = 0; i <= s->core_sfm; i++) s->R[i] = (Word16)(random_range(0, 5) < dense ? random_range(1, 40) : 0);
    s->R[s->core_sfm] = 1;
    if (c->hqswb_clas == HQ_TRANSIENT) s->last_sfm = (Word16)(c->num_sfm - 1);
    else if (c->hqswb_clas == HQ_GEN_SWB || c->hqswb_clas == HQ_GEN_FB) s->last_sfm = s_max(s->core_sfm, sub(c->num_env_bands, 1));
    else s->last_sfm = s->core_sfm;
    if (c->hqswb_clas == HQ_HARMONIC) {
        Word16 high = c->core_brate == HQ_24k40 ? HVQ_THRES_SFM_24k - 1 : HVQ_THRES_SFM_32k - 1;
        if (s->last_sfm < high) s->last_sfm = high;
    }
    if (s->last_sfm > c->num_sfm - 1) s->last_sfm = (Word16)(c->num_sfm - 1);
    int spread = random_range(3, 14), all = next_random() % 6 == 0;
    for (int i = 0; i < L_FRAME48k; i++) s->coeff[i] = 0;
    for (int b = 0; b < c->num_sfm; b++)
        for (int i = c->sfm_start[b]; i < c->sfm_end[b]; i++)
            if (all || s->R[b] != 0) s->coeff[i] = (Word16)(next_random() % 4 ? random_range(-(1 << spread), 1 << spread) : 0);
    for (int i = 0; i < NB_SFM; i++)
        s->norm_adj[i] = (Word16)(next_random() % 3 ? 32767 : next_random() % 2 ? random_range(0, 32767) : random16() & 0x7fff);
}

static void put_layout(const Scenario *s)
{
    const HqAllocInput *c = &s->c;
    put1("length", c->length); put1("hqswb_clas", c->hqswb_clas); put1("core_brate", c->core_brate);
    put1("num_sfm", c->num_sfm); put1("num_env_bands", c->num_env_bands); put1("last_sfm", s->last_sfm);
    put16("sfm_start", c->sfm_start, c->num_sfm); put16("sfm_end", c->sfm_end, c->num_sfm);
    put16("sfmsize", c->sfmsize, c->num_sfm); put16("r", s->R, NB_SFM);
}


#endif
