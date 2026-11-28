/* Function-level oracle for lib_dec/er_sync_exc.c: PulseResynchronization (and through it the
 * file-local GetMinimumPosition, FindMaxPeak, AddSamples and RemoveSamples).
 *
 * The excitation is laid out as FEC_exc_estim_fx lays it out: one buffer holding the source (the
 * last pitch cycle of length Tc repeated over L_frame + L_SUBFR samples, a glottal pulse plus
 * noise) immediately followed by the destination; the pitch moves from Tc to an extrapolated
 * pitch near it (integer as MODE1 passes it, fractional as MODE2 does), sometimes far from it or
 * out of range (the error recovery), and the whole buffer is compared. The largest sample is never
 * the first: with a single pulse in the frame (k = 0) the reference then divides by zero and
 * aborts (div_s), an input FEC_exc_estim_fx's pitch checks keep from it. */
#include "harness.h"
#include "prot_fx.h"

#define BUF (2 * (L_FRAME16k + L_SUBFR) + L_SUBFR)

static void case_pulse_resynchronization(void)
{
    Word16 buf[BUF];
    Word16 nb_subfr = (Word16)((next_random() & 1) ? 4 : 5);
    Word16 l_frame = (Word16)(nb_subfr * L_SUBFR);
    Word16 src_at = 0, dst_at = (Word16)(l_frame + L_SUBFR);
    int tc = random_range(nb_subfr == 4 ? 34 : 42, nb_subfr == 4 ? 231 : 289);
    Word32 pitch_start = (Word32)tc << 16, pitch_end;
    int mode = next_random() % 8;

    /* the past excitation: a pulse train of period tc */
    {
        Word16 cycle[300];
        int amp = random_range(500, 20000), pos = random_range(1, tc - 1);
        random_signal(cycle, tc, amp / 8);
        cycle[pos] = (Word16)((next_random() & 1) ? amp : -amp);
        if (pos + 1 < tc) cycle[pos + 1] = (Word16)(cycle[pos] / 2);
        if (mode == 7) { for (int i = 0; i < tc; i++) cycle[i] = random16(); cycle[0] = 0; }
        for (int i = 0; i < l_frame + L_SUBFR; i++) buf[i] = cycle[i % tc];
        random_signal(buf + dst_at, BUF - dst_at, 3000);
    }
    /* the extrapolated pitch */
    {
        int pct = mode < 5 ? random_range(-15, 15) : random_range(-60, 60);
        double end = tc * (1.0 + pct / 100.0);
        if (end < 17) end = 17;
        pitch_end = (next_random() & 1) ? ((Word32)(end + 0.5)) << 16 : (Word32)(end * 65536.0);
        if (mode == 6) pitch_end = random32() >> random_range(0, 16);
        if (next_random() % 32 == 0) {
            pitch_start = random32() >> random_range(0, 16);
            /* a positive pitch below 0.5 rounds to 0, whose inverse the reference asserts away */
            if (pitch_start > 0 && pitch_start < 0x8000) pitch_start = -pitch_start;
        }
    }
    if (next_random() % 32 == 0) nb_subfr = (Word16)random_range(0, 6);
    if (next_random() % 32 == 0) src_at = dst_at;

    put16("buf", buf, BUF); put1("src_at", src_at); put1("dst_at", dst_at); put1("l_frame", l_frame);
    put1("nb_subfr", nb_subfr); put1("pitch_start", pitch_start); put1("pitch_end", pitch_end);
    PulseResynchronization(buf + src_at, buf + dst_at, l_frame, nb_subfr, pitch_start, pitch_end);
    arrow(); put16("buf", buf, BUF); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    if (strcmp(argv[2], "pulse_resynchronization")) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) case_pulse_resynchronization();
    return 0;
}
