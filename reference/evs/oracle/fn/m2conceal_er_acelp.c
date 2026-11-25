/* Function-level oracle for lib_dec/er_dec_acelp.c (con_acelp, and through it memsynPrecission).
 *
 * Each case builds an LPD-core decoder (m2conceal_state.h), randomises the concealment state of
 * the ACELP core (last good class and coder type, one to twelve lost frames, the pitch memories, the
 * excitation and synthesis memories at their Qs, the comfort noise filters, gains and seeds; a
 * guided ACELP lag at 24.4 kbit/s) and conceals one frame. Every output of the call is printed and the
 * whole decoder state before and after (state_capture.h), so every memory the function updates is
 * compared. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "m2conceal_state.h"

static void randomise_acelp(Decoder_State_fx *st, Word16 *a, Word16 *coder_type)
{
    int frame = st->L_frame_fx;
    /* core_dec_switch: the guided ACELP side information exists at 24.4 kbit/s from wideband up */
    st->enableGplc = (Word8)(st->total_brate_fx == 24400 && st->bwidth_fx >= WB);
    st->last_core_fx = ACELP_CORE;
    st->core_fx = ACELP_CORE;
    st->bfi_fx = 1;
    st->nbLostCmpt = (Word16)((next_random() % 3) ? random_range(1, 3) : random_range(1, 12));
    st->last_good_fx = (Word16)((next_random() % 3) ? random_range(UNVOICED_TRANSITION, ONSET) : random_range(UNVOICED_CLAS, INACTIVE_CLAS));
    *coder_type = (Word16)((next_random() % 3) ? random_range(UNVOICED, GENERIC) : random_range(0, 9));
    st->core_ext_mode = *coder_type;
    m2c_random_pitch(st);
    m2c_random_gains(st);
    st->Q_exc = (Word16)random_range(0, 8);
    st->Q_syn = (Word16)random_range(-1, 4);
    if (st->nbLostCmpt > 5 && (next_random() & 1)) st->Q_syn = (Word16)random_range(-1, 1);
    st->prev_Q_syn = st->Q_syn;
    for (int k = 0; k < 6; k++) m2c_random_lpc(st->Aq_cng + k * (M + 1), M);
    for (int k = 0; k < 5; k++) m2c_random_lpc(a + k * (M + 1), M);
    {
        /* the excitation history: the last pitch cycle repeated, or noise */
        int tc = (int)((st->old_fpitch + 32768) >> 16), amp = random_range(300, 12000);
        Word16 cycle[400];
        if (tc < 17) tc = 17;
        if (tc > 380) tc = 380;
        random_signal(cycle, tc, amp / 6);
        cycle[random_range(1, tc - 1)] = (Word16)((next_random() & 1) ? amp : -amp);
        for (int i = 0; i < L_EXC_MEM_DEC; i++) st->old_exc_fx[i] = cycle[(i + tc * 4) % tc];
        if (next_random() % 8 == 0) random_signal(st->old_exc_fx, L_EXC_MEM_DEC, amp);
        int magnitude = random_range(50, 12000) >> (st->nbLostCmpt > 5 ? random_range(2, 6) : 0);
        random_signal(st->mem_syn2_fx, M, magnitude);
        if (st->nbLostCmpt > 5 && next_random() % 4 == 0) memset(st->mem_syn2_fx, 0, sizeof st->mem_syn2_fx);
        random_signal(st->mem_syn_unv_back, M, magnitude);
        random_signal(st->mem_syn_clas_estim_fx, L_SYN_MEM_CLAS_ESTIM, magnitude);
        random_signal(st->syn, M + 1, magnitude);
        random_signal(st->syn_Overl_TDAC, frame / 2, magnitude);
        random_signal(st->syn_Overl, frame / 2, magnitude);
        random_signal(st->old_out_LB_fx, 640, magnitude);
    }
    if (st->enableGplc && next_random() % 2 == 0) {
        st->flagGuidedAcelp = 1;
        st->guidedT0 = (Word16)random_range(PIT16k_MIN, PIT16k_MAX);
    } else {
        st->flagGuidedAcelp = 0;
        st->guidedT0 = (Word16)random_range(PIT16k_MIN, PIT16k_MAX);
    }
}

static void case_con_acelp(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 a[5 * (M + 1)], coder_type, synth[L_FRAME16k + 16], p_t[NB_SUBFR16k], pgain_t[NB_SUBFR16k];
    Word16 pitch_buffer[NB_SUBFR16k], voice_factors[NB_SUBFR16k], bwe_exc[648];
    m2c_configure(st, next_random() % 4, L_FRAME16k);
    randomise_acelp(st, a, &coder_type);
    for (int i = 0; i < L_FRAME16k + 16; i++) synth[i] = -1;
    for (int i = 0; i < NB_SUBFR16k; i++) { p_t[i] = -1; pgain_t[i] = -1; pitch_buffer[i] = -1; voice_factors[i] = -1; }
    for (int i = 0; i < 648; i++) bwe_exc[i] = -1;
    Word16 stab_fac = st->stab_fac_fx;

    put16("a", a, 5 * (M + 1)); put1("coder_type", coder_type); put1("stab_fac", stab_fac);
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("bitrate", st->total_brate_fx); put1("bandwidth", st->bwidth_fx);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    con_acelp(a, coder_type, synth, p_t, pgain_t, stab_fac, st, &st->Q_exc, &st->Q_syn, pitch_buffer, voice_factors, bwe_exc);
    put16("synth", synth, L_FRAME16k + 16); put16("p_t", p_t, NB_SUBFR16k); put16("pgain_t", pgain_t, NB_SUBFR16k);
    put16("pitch_buffer", pitch_buffer, NB_SUBFR16k); put16("voice_factors", voice_factors, NB_SUBFR16k);
    put16("bwe_exc", bwe_exc, 648);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "con_acelp")) case_con_acelp();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
