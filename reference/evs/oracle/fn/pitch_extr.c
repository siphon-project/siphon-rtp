/* Function-level oracle for lib_dec/pitch_extr.c: pitch_pred_linear_fit.
 *
 * Inputs as the concealment feeds them: a past lag trajectory (Q16) that is smooth (so the fit
 * runs: a steady, rising, falling or slightly jittered pitch), now and then with one jump or out
 * of range, the past pitch gains (Q14), the first or a later lost frame after every class, both
 * subframe counts with FEC_exc_estim's limits, and the MODE2 options (limitation, future lag). */
#include "harness.h"
#include "prot_fx.h"

static void case_pitch_pred_linear_fit(void)
{
    Word32 old_pitch_buf[2 * NB_SUBFR16k + 2], t0_out = -12345;
    Word16 mem_pitch_gain[2 * NB_SUBFR16k + 2], extrapolation_failed = -1;
    Word16 nb_subfr = (Word16)((next_random() & 1) ? 4 : 5);
    Word16 pit_min = nb_subfr == 4 ? PIT_MIN_DOUBLEEXTEND : PIT16k_MIN_EXTEND;
    Word16 pit_max = nb_subfr == 4 ? PIT_MAX : PIT16k_MAX;
    int lags = 2 * nb_subfr + 2;
    Word16 bfi_cnt = (Word16)((next_random() % 4) ? 1 : random_range(0, 4));
    Word16 last_good = (Word16)((next_random() % 3) ? random_range(UNVOICED_TRANSITION, VOICED_TRANSITION + 1) : random_range(0, 7));
    Word16 limitation = (Word16)((next_random() % 4) ? 0 : 1);
    Word8 future = (Word8)((next_random() % 4) ? 0 : 1);
    if (next_random() % 8 == 0) { pit_min = (Word16)random_range(17, 40); pit_max = (Word16)random_range(150, 300); }

    /* lag trajectory */
    {
        int shape = next_random() % 6;
        double lag = random_range(pit_min, pit_max) + random_range(0, 99) / 100.0;
        double slope = shape == 1 ? random_range(1, 300) / 100.0 : shape == 2 ? -random_range(1, 300) / 100.0 : 0;
        for (int i = 0; i < lags; i++) {
            double v = lag + slope * i;
            if (shape == 3) v += random_range(-150, 150) / 100.0;
            if (shape == 4) v = random_range(pit_min, pit_max + 40);
            old_pitch_buf[i] = (Word32)(v * 65536.0);
        }
        if (shape == 5) old_pitch_buf[random_range(0, lags - 1)] += (Word32)random_range(-30, 30) << 16;
        for (int i = lags; i < 2 * NB_SUBFR16k + 2; i++) old_pitch_buf[i] = 0;
    }
    /* pitch gains, newest first */
    {
        int mode = next_random() % 4;
        for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++)
            mem_pitch_gain[i] = mode == 0 ? (Word16)random_range(8000, 19661) : mode == 1 ? (Word16)random_range(0, 19661)
                              : mode == 2 ? 0 : (Word16)random_range(0, 32767);
        if (mode == 2 && (next_random() & 1)) mem_pitch_gain[random_range(0, 4)] = (Word16)random_range(1, 16384);
    }
    Word32 old_fpitch = old_pitch_buf[2 * nb_subfr - 1];
    if (next_random() % 8 == 0) old_fpitch = (Word32)random_range(pit_min, pit_max + 60) << 16;

    put1("bfi_cnt", bfi_cnt); put1("last_good", last_good); put32("old_pitch_buf", old_pitch_buf, 2 * NB_SUBFR16k + 2);
    put1("old_fpitch", old_fpitch); put1("pit_min", pit_min); put1("pit_max", pit_max);
    put16("mem_pitch_gain", mem_pitch_gain, 2 * NB_SUBFR16k + 2); put1("limitation", limitation);
    put1("future", future); put1("nb_subfr", nb_subfr);
    pitch_pred_linear_fit(bfi_cnt, last_good, old_pitch_buf, &old_fpitch, &t0_out, pit_min, pit_max, mem_pitch_gain,
                          limitation, future, &extrapolation_failed, nb_subfr);
    arrow(); put1("t0", t0_out); put1("failed", extrapolation_failed); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    if (strcmp(argv[2], "pitch_pred_linear_fit")) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) case_pitch_pred_linear_fit();
    return 0;
}
