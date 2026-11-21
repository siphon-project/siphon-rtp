/*
 * Inputs of the HQ high-rate bit allocation as hq_hr_dec_fx feeds it, shared by the oracles of
 * hq_bit_allocation_fx and its callees (bitalloc, bitallocsum, weight, hq_tools_alloc).
 *
 * HQ high rate runs at total rates above LRMDCT_CROSSOVER_POINT (16.4 kbit/s) for WB, SWB and FB
 * (decision_matrix_dec_fx): core rates 24.4 .. 128 kbit/s, frame lengths 320 / 640 / 960. The class
 * follows hq_classifier_dec_fx: SWB/FB at 32 kbit/s and below choose among generic (normal),
 * transient, harmonic and HVQ; otherwise normal or transient. Layouts come from hq_configure_fx;
 * norms are quantised indices (a random walk, sometimes flat or silent) mapped through dicnlg2,
 * the high bands of the generic modes through dicnlg2[min(idx + 10, 39)] as
 * map_hq_generic_fenv_norm_fx does.
 *
 * A reference function that would abort (div_s precondition) or not return prints `skip=1 ->`
 * instead of a case, so a test can tell; none of the generated cases does so far.
 */
#ifndef HQ_BIT_ALLOCATION_INPUTS_H
#define HQ_BIT_ALLOCATION_INPUTS_H

#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

typedef struct {
    Word32 core_brate;
    Word16 length, hqswb_clas, num_bits;
    Word16 num_sfm, nb_sfm, start_norm, num_env_bands, numnrmibits, hq_generic_offset;
    const Word16 *sfmsize, *sfm_start, *sfm_end;
    Word16 ynrm[NB_SFM], normqlg2[NB_SFM];
} HqAllocInput;

static void random_hq_alloc_input(HqAllocInput *c)
{
    static const Word32 rates[] = {HQ_24k40, HQ_32k, HQ_48k, HQ_64k, HQ_96k, HQ_128k};
    static const Word16 lengths[] = {L_FRAME16k, L_FRAME32k, L_FRAME48k};
    c->core_brate = rates[next_random() % 6];
    if (next_random() % 3 == 0) c->core_brate = next_random() & 1 ? HQ_24k40 : HQ_32k;
    c->length = lengths[next_random() % 3];
    if (c->length >= L_FRAME32k && c->core_brate <= HQ_32k) {
        c->hqswb_clas = (Word16)(next_random() % 4);
        if (c->hqswb_clas == HQ_NORMAL) c->hqswb_clas = c->length == L_FRAME48k ? HQ_GEN_FB : HQ_GEN_SWB;
    } else {
        c->hqswb_clas = (Word16)(next_random() % 2);
    }
    c->hq_generic_offset = 0;
    c->num_env_bands = 0;
    hq_configure_fx(c->length, c->hqswb_clas, c->core_brate, &c->num_sfm, &c->nb_sfm, &c->start_norm,
                    &c->num_env_bands, &c->numnrmibits, &c->hq_generic_offset, &c->sfmsize, &c->sfm_start,
                    &c->sfm_end);
    /* the bits hq_hr_dec_fx has left: the frame less signalling, voicing, class and envelope bits
     * (sometimes the 48 kbit/s core-switching cap) */
    int frame = (int)(c->core_brate / 50);
    if (next_random() % 6 == 0 && frame > 960) frame = 960;
    c->num_bits = (Word16)(frame - random_range(3, 12) - random_range(c->nb_sfm, 5 * c->nb_sfm));
    if (next_random() % 10 == 0) c->num_bits = (Word16)random_range(0, frame);

    int mode = next_random() % 8, idx = random_range(0, 39);
    for (int i = 0; i < NB_SFM; i++) {
        if (mode == 0) idx = 39;
        else if (mode == 1) idx = 0;
        else if (mode == 2) idx = random_range(0, 39);
        else {
            idx += random_range(-3, 4);
            if (idx < 0) idx = 0;
            if (idx > 39) idx = 39;
        }
        c->ynrm[i] = (Word16)idx;
        c->normqlg2[i] = dicnlg2[idx];
    }
    if (c->hqswb_clas == HQ_GEN_SWB || c->hqswb_clas == HQ_GEN_FB)
        for (int i = c->num_env_bands; i < c->nb_sfm; i++) c->normqlg2[i] = dicnlg2[s_min(add(c->ynrm[i], 10), 39)];
}


/* Norms for the direct oracles of the allocation callees: log2 norms in the dicnlg2 range (-5 .. 34),
 * as a random walk, flat, silent, uniform, or one band standing out; now and then an out-of-range value. */
static void random_norms(Word16 *w, int n)
{
    int mode = next_random() % 8, v = random_range(-5, 34), spread = random_range(1, 6);
    for (int i = 0; i < n; i++) {
        if (mode == 0) v = random_range(-5, 34);
        else if (mode == 1) v = random_range(-5, 0);
        else if (mode == 2) v = random_range(14, 34);
        else if (mode == 3) v = 0;
        else {
            v += random_range(-spread, spread);
            if (v < -5) v = -5;
            if (v > 34) v = 34;
        }
        w[i] = (Word16)v;
    }
    if (next_random() % 5 == 0) w[random_range(0, n - 1)] = (Word16)random_range(-5, 34);
    if (next_random() % 40 == 0) w[random_range(0, n - 1)] = random16();
}

/* random_hq_alloc_input until `accept` holds, so a direct oracle sees only the cases its function runs on. */
#define RANDOM_INPUT_WHERE(c, accept) do { random_hq_alloc_input(c); } while (!(accept))

static sigjmp_buf guard_jump;
static void guard_signal(int signal) { (void)signal; siglongjmp(guard_jump, 1); }

/* Run `call` with abort and a 2 s hang caught; returns 0 when the reference did not return. */
#define GUARDED(call)                                                                        \
    ({                                                                                       \
        int returned_ = 0;                                                                   \
        signal(SIGABRT, guard_signal);                                                       \
        signal(SIGALRM, guard_signal);                                                       \
        if (sigsetjmp(guard_jump, 1) == 0) {                                                 \
            alarm(2);                                                                        \
            call;                                                                            \
            returned_ = 1;                                                                   \
        }                                                                                    \
        alarm(0);                                                                            \
        returned_;                                                                           \
    })

#endif
