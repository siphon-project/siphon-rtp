/* Function-level oracle for GetPLCModeDecision (lib_dec/er_util.c).
 *
 * Each case builds an LPD-core decoder (m2conceal_state.h), randomises the state the decision
 * reads (the last two cores and the core of the last lost frame, the TCX-LTP gain and the pitch
 * history, the TNS flags, the channel-aware fields, the guided ACELP side information and the loss
 * counter) and, for most cases, feeds the tonal MDCT concealment two good TCX frames (a peaky
 * spectrum and a pitched output) so that its detection of tonal components runs. The decision and
 * the whole decoder state after it are printed (state_capture.h). */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "m2conceal_state.h"

static void feed_tonal_frame(Decoder_State_fx *st, int period)
{
    Word32 spectrum[L_FRAME_MAX];
    Word16 scale_factors[FDNS_NPTS], scale_factors_exp[FDNS_NPTS], pcm[L_FRAME_MAX];
    int n = st->L_frameTCX;
    for (int i = 0; i < n; i++) spectrum[i] = (Word32)random_range(-(1 << 20), 1 << 20);
    for (int k = 1; k < 9; k++) {
        int bin = 2 * k * n / period;
        if (bin + 1 < n) { spectrum[bin] = (Word32)random_range(1 << 24, 1 << 29); spectrum[bin + 1] = (Word32)random_range(-(1 << 29), -(1 << 24)); }
    }
    for (int i = 0; i < FDNS_NPTS; i++) { scale_factors[i] = (Word16)random_range(2000, 20000); scale_factors_exp[i] = (Word16)random_range(0, 3); }
    m2c_voiced_signal(pcm, n, (double)period * n / st->L_frame_fx, random_range(1000, 12000));
    TonalMDCTConceal_SaveFreqSignal(&st->tonalMDCTconceal, spectrum, (Word16)random_range(0, 4), (Word16)n, st->L_frame_fx,
                                    scale_factors, scale_factors_exp, (Word16)random_range(-2, 2));
    TonalMDCTConceal_UpdateState(&st->tonalMDCTconceal, (Word16)n, st->old_fpitch, 0, 0);
    TonalMDCTConceal_SaveTimeSignal(&st->tonalMDCTconceal, pcm, (Word16)n);
}

static void case_plc_mode(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    static const Word16 cores[] = {ACELP_CORE, TCX_20_CORE, TCX_20_CORE, TCX_20_CORE, TCX_10_CORE};
    m2c_configure(st, next_random() % 4, 100000);
    m2c_random_pitch(st);
    int period = (int)((st->old_fpitch + 32768) >> 16);
    if (period < 17) period = 17;
    st->nbLostCmpt = (Word16)((next_random() % 3) ? 1 : random_range(2, 4));
    st->last_core_fx = (Word16)((next_random() % 10) ? cores[next_random() % 5] : -1);
    st->second_last_core = (Word16)((next_random() % 8) ? cores[next_random() % 5] : -1);
    if (next_random() % 3) { st->last_core_fx = TCX_20_CORE; st->second_last_core = TCX_20_CORE; }
    st->last_core_bfi = cores[next_random() % 5];
    st->Opt_AMR_WB_fx = (Word16)(next_random() % 6 == 0);
    st->rf_flag = (Word16)(next_random() % 4 == 0);
    st->use_partial_copy = (Word16)(next_random() % 3 == 0);
    st->rf_frame_type = (Word16)random_range(RF_NO_DATA, RF_TCXTD2);
    st->tcxltp_last_gain_unmodified = (Word16)((next_random() % 4) ? random_range(0, 32767) : 0);
    /* the 0.4 threshold of the TCX-LTP gain, at it and one either side */
    if (next_random() % 3 == 0) st->tcxltp_last_gain_unmodified = (Word16)random_range(13106, 13108);
    st->tcxltp_second_last_pitch = (next_random() % 5) ? st->old_fpitch : st->old_fpitch + (Word32)random_range(-100000, 100000);
    st->tcxltp_third_last_pitch = st->tcxltp_second_last_pitch + (Word32)random_range(-60000, 60000);
    /* the half-sample threshold on the change of the TCX-LTP pitch, at it and one either side */
    if (next_random() % 3 == 0) st->tcxltp_third_last_pitch = st->tcxltp_second_last_pitch + (Word32)random_range(32767, 32769) * ((next_random() & 1) ? 1 : -1);
    /* the lag against half the frame, at it and one either side */
    if (next_random() % 4 == 0) { st->old_fpitch = ((Word32)(st->L_frame_fx >> 1) << 16) + random_range(-1, 1); st->tcxltp_second_last_pitch = st->old_fpitch; }
    st->last_tns_active = (Word8)(next_random() % 6 == 0);
    st->second_last_tns_active = (Word8)(next_random() % 6 == 0);
    st->last_good_fx = (Word16)((next_random() & 1) ? random_range(UNVOICED_CLAS, UNVOICED_TRANSITION) : random_range(UNVOICED_CLAS, INACTIVE_CLAS));
    st->enableGplc = 1;
    st->flagGuidedAcelp = (Word16)(next_random() % 5 == 0);
    st->guidedT0 = (Word16)random_range(PIT16k_MIN, PIT16k_MAX);
    st->tonal_mdct_plc_active = (Word8)(next_random() & 1);
    st->plc_use_future_lag = (Word8)(next_random() & 1);
    if (next_random() % 5) { feed_tonal_frame(st, period); feed_tonal_frame(st, period); }

    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("bitrate", st->total_brate_fx); put1("bandwidth", st->bwidth_fx);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    Word16 core = GetPLCModeDecision(st);
    put1("core", core);
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
        if (!strcmp(argv[2], "plc_mode")) case_plc_mode();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
