/* Function-level oracle for improv_amr_wb_gs_fx (lib_dec/gs_dec_amr_wb_fx.c), which reaches the statics
 * gs_dec_amr_wb_fx, Ener_per_band_fx, Apply_gain_fx, normalize_spec_fx and NoiseFill_fx. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static const Word32 amr_rates[] = {6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};

/* LP filters of a stable synthesis, a[0] = 4096 */
static void random_lpc(Word16 *a)
{
    a[0] = 4096;
    for (int k = 1; k <= M; k++) {
        int span = 9000 / (k + 2);
        a[k] = (Word16)random_range(-span, span);
    }
}

static void case_improv(void)
{
    Word16 aq[NB_SUBFR * (M + 1)], old_aq[NB_SUBFR * (M + 1)], mem_syn2[M], mem_tmp[M], exc2[L_FRAME], syn[L_FRAME];
    Word16 pitch_buf[NB_SUBFR], seed_tcx = random16();
    Word32 core_brate = amr_rates[next_random() % 9];
    /* the modification is entered mostly: no attack, rate up to 12.65, inactive or unvoiced at low rate */
    Word16 coder_type = (Word16)(next_random() % 4 ? INACTIVE : GENERIC);
    Word16 clas = (Word16)(next_random() % 3 ? (next_random() & 1 ? UNVOICED_CLAS : VOICED_TRANSITION) : random_range(0, 7));
    Word16 locattack = (Word16)(next_random() % 8 == 0);
    Word16 lt_voice_fac = (Word16)random_range(0, 16384), q_exc2 = (Word16)random_range(-1, 8), q_syn = (Word16)random_range(-1, 6);
    Word16 last_ener = (Word16)(next_random() & 1 ? random_range(-768 + 1, 3000) : random_range(-5000, -768));
    Word16 rate_switching_reset = (Word16)(next_random() % 8 == 0);
    Word16 last_coder_type = (Word16)(next_random() % 4 ? UNVOICED : GENERIC);
    int magnitude = random_range(100, 3000);
    for (int k = 0; k < NB_SUBFR; k++) {
        random_lpc(aq + k * (M + 1));
        if (next_random() % 5 == 0) {
            /* a filter whose neighbours differ a lot (a resonance), to reach the stability check */
            for (int j = 1; j <= M; j++) aq[k * (M + 1) + j] = (Word16)random_range(-6000, 6000);
        }
        /* the filters of the previous frame: near these, sometimes not at all alike */
        for (int j = 0; j <= M; j++) {
            int value = aq[k * (M + 1) + j] + (next_random() % 3 ? random_range(-400, 400) : random_range(-5000, 5000));
            old_aq[k * (M + 1) + j] = (Word16)(j == 0 ? 4096 : value);
        }
        pitch_buf[k] = (Word16)random_range(34 * 64, 231 * 64);
    }
    for (int i = 0; i < M; i++) { mem_syn2[i] = (Word16)random_range(-2000, 2000); mem_tmp[i] = (Word16)random_range(-2000, 2000); }
    random_signal(exc2, L_FRAME, magnitude);
    if (next_random() % 8 == 0) for (int i = 0; i < L_FRAME; i++) exc2[i] = (Word16)random_range(-magnitude, magnitude);
    random_signal(syn, L_FRAME, 1000);
    put1("clas", clas); put1("coder_type", coder_type); put1("core_brate", core_brate); put1("seed_tcx", seed_tcx);
    put16("old_aq", old_aq, NB_SUBFR * (M + 1)); put16("mem_syn2", mem_syn2, M); put1("lt_voice_fac", lt_voice_fac);
    put1("locattack", locattack); put16("aq", aq, NB_SUBFR * (M + 1)); put16("exc2", exc2, L_FRAME); put1("q_exc2", q_exc2);
    put16("mem_tmp", mem_tmp, M); put16("syn", syn, L_FRAME); put1("q_syn", q_syn); put16("pitch_buf", pitch_buf, NB_SUBFR);
    put1("last_ener", last_ener); put1("rate_switching_reset", rate_switching_reset); put1("last_coder_type", last_coder_type);
    improv_amr_wb_gs_fx(clas, coder_type, core_brate, &seed_tcx, old_aq, mem_syn2, lt_voice_fac, locattack, aq, exc2, q_exc2,
                        mem_tmp, syn, q_syn, pitch_buf, last_ener, rate_switching_reset, last_coder_type);
    arrow(); put1("seed_tcx", seed_tcx); put16("old_aq", old_aq, NB_SUBFR * (M + 1)); put16("mem_syn2", mem_syn2, M);
    put16("aq", aq, NB_SUBFR * (M + 1)); put16("exc2", exc2, L_FRAME); put16("syn", syn, L_FRAME); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "improv_amr_wb_gs")) case_improv();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
