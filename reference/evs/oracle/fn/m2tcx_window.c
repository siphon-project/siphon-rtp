/* Function-level oracle for WindowSignal (lib_com/tcx_utils.c); tcx_get_windows and
 * tcx_windowing_analysis are static and proven through it. The TCX configuration comes from
 * init_TCX_config at a core / output rate pair the decoder runs, with tcx_offset as core_dec_init
 * sets it. Every overlap mode the decoder passes is drawn: the left one of TRANSITION (after
 * ACELP), MIN, HALF, FULL and, fullband only, RECTANGULAR; the right one of MIN, HALF, FULL and,
 * fullband only, RECTANGULAR. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define HISTORY 500
#define SIGNAL_LENGTH 2300

static void case_window_signal(void)
{
    static const Word32 core_rates[] = {12800, 16000, 25600, 32000};
    static const Word32 output_rates[] = {8000, 16000, 32000, 48000};
    static Word16 signal[SIGNAL_LENGTH], out[SIGNAL_LENGTH];
    Word32 sr = core_rates[next_random() % 4], fs = output_rates[next_random() % 4];
    Word16 l_frame_core = (Word16)(sr / 50), l_frame_tcx = (Word16)(fs / 50);
    TCX_config *cfg = calloc(1, sizeof(TCX_config));
    init_TCX_config(cfg, l_frame_core, sr2fscale(sr), l_frame_tcx, sr2fscale(fs));
    cfg->tcx_offset = shr(cfg->tcx_mdct_window_delay, 1);
    cfg->tcx_offsetFB = shr(cfg->tcx_mdct_window_delayFB, 1);

    Word8 fullband = (Word8)(next_random() & 1);
    static const Word16 left_modes[] = {TRANSITION_OVERLAP, MIN_OVERLAP, HALF_OVERLAP, FULL_OVERLAP, RECTANGULAR_OVERLAP};
    static const Word16 right_modes[] = {MIN_OVERLAP, HALF_OVERLAP, FULL_OVERLAP, RECTANGULAR_OVERLAP};
    Word16 left_mode = left_modes[random_range(0, fullband ? 4 : 3)];
    Word16 right_mode = right_modes[random_range(0, fullband ? 3 : 2)];
    Word16 offset = fullband ? cfg->tcx_offsetFB : cfg->tcx_offset;
    if (next_random() % 4 == 0) offset = 0;
    Word16 l_frame = fullband ? l_frame_tcx : l_frame_core;
    int divide = random_range(0, 2);
    l_frame = (Word16)(l_frame >> divide);

    for (int i = 0; i < SIGNAL_LENGTH; i++) signal[i] = random16();
    if (next_random() % 2) random_signal(signal, SIGNAL_LENGTH, 20000);
    memset(out, 0x5a, sizeof(out));
    Word16 left_overlap = 0x1111, right_overlap = 0x2222, l_frame_io = l_frame;
    put1("sr", sr); put1("fs", fs); put1("fullband", fullband); put1("left_mode", left_mode); put1("right_mode", right_mode);
    put1("offset", offset); put1("l_frame", l_frame); put16("signal", signal, SIGNAL_LENGTH);
    WindowSignal(cfg, offset, left_mode, right_mode, &left_overlap, &right_overlap, signal + HISTORY, &l_frame_io, out, fullband);
    arrow(); put1("left_overlap", left_overlap); put1("right_overlap", right_overlap); put1("l_frame_io", l_frame_io);
    put16("out", out, (l_frame_io + (left_overlap + right_overlap) / 2 > SIGNAL_LENGTH) ? SIGNAL_LENGTH : l_frame_io + (left_overlap + right_overlap) / 2);
    end_line();
    free(cfg);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "WindowSignal")) case_window_signal();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
