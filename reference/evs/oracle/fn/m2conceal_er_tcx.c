/* Function-level oracle for lib_dec/er_dec_tcx.c (con_tcx, and through it calcGainc, calcGainc2).
 *
 * Each case builds an LPD-core decoder (m2conceal_state.h) at any rate and bandwidth, a past output
 * of 2 * L_frameTCX samples (a few harmonics at the pitch of the last good frame, so the pitch
 * extrapolation and the energy of the harmonic part are exercised, or noise) followed by the frame
 * to conceal, and randomises the concealment state of the TCX core (the class and coder type, one to
 * ten lost frames with and without the recalculation flag, the pitch memories at the FB scale, the
 * LTP lag of a partial copy at 13.2 kbit/s, the excitation memory, gains, noise levels, seeds). The
 * whole synthesis buffer after the call and the whole decoder state before and after are printed
 * (state_capture.h). */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "m2conceal_state.h"

#define MAX_HISTORY (2 * L_FRAME48k)

static void randomise_tcx(Decoder_State_fx *st)
{
    st->last_core_fx = TCX_20_CORE;
    st->core_fx = TCX_20_CORE;
    st->bfi_fx = 1;
    st->nbLostCmpt = (Word16)((next_random() % 2) ? 1 : (next_random() % 3) ? random_range(2, 3) : random_range(2, 10));
    st->tcxConceal_recalc_exc = (Word16)(st->nbLostCmpt > 1 && next_random() % 5 == 0);
    st->last_good_fx = (Word16)((next_random() % 3) ? random_range(UNVOICED_TRANSITION, ONSET) : random_range(UNVOICED_CLAS, INACTIVE_CLAS));
    st->core_ext_mode = (Word16)((next_random() % 3) ? random_range(UNVOICED, GENERIC) : random_range(0, 9));
    st->tcxonly = (Word8)(next_random() & 1);
    m2c_random_pitch(st);
    m2c_random_gains(st);
    /* the pitch at the full band scale */
    {
        double scale = (double)st->L_frameTCX / (double)st->L_frame_fx;
        st->old_fpitchFB = (Word32)((double)st->old_fpitch * scale);
        if (next_random() % 6 == 0) st->old_fpitchFB += (Word32)(random_range(-5, 5) * 65536.0 * scale);
        if (st->old_fpitchFB < 17 * 65536) st->old_fpitchFB = 17 * 65536;
        if (st->old_fpitchFB > st->pit_max_TCX * 65536.0) st->old_fpitchFB = (Word32)(st->pit_max_TCX * 65536.0);
    }
    /* TCX-LTP: the lag of the last frame, and a partial copy at 13.2 kbit/s */
    st->tcxltp_pitch_int = (Word16)random_range(st->pit_min, st->pit_max); /* at the core rate */
    st->tcxltp_pitch_fr = (Word16)random_range(0, st->pit_res_max - 1);
    st->use_partial_copy = 0;
    st->rf_frame_type = 0;
    if (next_random() % 5 == 0) {
        st->use_partial_copy = 1;
        st->rf_frame_type = (Word16)random_range(RF_NO_DATA, RF_TCXTD2);
    }
    st->Q_exc = (Word16)random_range(0, 8);
    st->Q_syn = (Word16)random_range(-1, 4);
    st->prev_Q_syn = (Word16)random_range(-1, 4);
    m2c_random_lpc(st->old_Aq_12_8_fx, M);
    {
        int magnitude = random_range(100, 12000);
        int tc = (int)((st->old_fpitchFB + 32768) >> 16);
        if (tc < 17) tc = 17;
        m2c_voiced_signal(st->old_excFB_fx, L_FRAME48k, tc, magnitude);
        if (next_random() % 8 == 0) random_signal(st->old_excFB_fx, L_FRAME48k, magnitude);
        random_signal(st->old_exc_fx, L_EXC_MEM_DEC, magnitude);
        random_signal(st->mem_syn_r, L_SYN_MEM, magnitude);
        random_signal(st->mem_syn2_fx, M, magnitude);
        random_signal(st->syn, M + 1, magnitude);
        random_signal(st->old_out_fx, L_FRAME48k, magnitude);
        random_signal(st->old_out_LB_fx, 640, magnitude);
        random_signal(st->syn_Overl_TDACFB, st->L_frameTCX / 2, magnitude);
        random_signal(st->syn_OverlFB, st->L_frameTCX / 2, magnitude);
        random_signal(st->old_syn_Overl, st->L_frame_fx / 2, magnitude);
    }
}

static void case_con_tcx(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    static Word16 synth_buffer[MAX_HISTORY + L_FRAME48k + 64];
    m2c_configure(st, next_random() % 4, 100000);
    randomise_tcx(st);
    int history = 2 * st->L_frameTCX, frame = st->L_frameTCX;
    st->old_synth_lenFB = (Word16)history;
    memset(synth_buffer, 0, sizeof synth_buffer);
    {
        int magnitude = random_range(200, 14000);
        double period = (double)st->old_fpitchFB / 65536.0;
        if (next_random() % 6 == 0) random_signal(synth_buffer, history, magnitude);
        else m2c_voiced_signal(synth_buffer, history, period, magnitude);
        for (int i = 0; i < frame; i++) synth_buffer[history + i] = -1;
    }
    put16("synth", synth_buffer, history + frame);
    put1("history", history);
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("bitrate", st->total_brate_fx); put1("bandwidth", st->bwidth_fx);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    con_tcx(st, synth_buffer + history);
    put16("synth", synth_buffer, history + frame);
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
        if (!strcmp(argv[2], "con_tcx")) case_con_tcx();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
