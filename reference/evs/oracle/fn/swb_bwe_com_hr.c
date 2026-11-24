/* Function-level oracle for lib_com/swb_bwe_com_hr_fx.c. swb_hr_noise_fill_fx calls the static
 * swb_hr_nonzero_subband_noise_fill_fx, so that one is proven through it. */
#include "harness.h"
#include "prot_fx.h"

/* The decoded spectrum the noise fill sees: AVQ output scaled by 2^Q_audio, coded sub-vectors
 * non-zero (some zero bins), empty ones zero, a few bands flat so the min == max branch occurs. */
static void random_avq_spectrum(Word16 *t_audio, Word16 *nq, int nsv, int q_audio)
{
    for (int i = 0; i < nsv; i++) {
        int coded = next_random() % 3 != 0;
        nq[i] = (Word16)(coded ? random_range(1, 8) : 0);
        int flat = coded && next_random() % 6 == 0;
        int level = random_range(1, 6);
        for (int j = 0; j < WIDTH_BAND; j++) {
            Word16 value = 0;
            if (coded) {
                value = (Word16)(random_range(0, next_random() % 5 == 0 ? 0 : level) << q_audio);
                if (flat) value = (Word16)(level << q_audio);
                if (next_random() & 1) value = (Word16)-value;
            }
            t_audio[i * WIDTH_BAND + j] = value;
        }
    }
}

static void case_swb_hr_noise_fill(void)
{
    Word16 t_audio[NSV_MAX * WIDTH_BAND], nq[NSV_MAX];
    int transient = next_random() % 3 == 0;
    Word16 spect_start = (Word16)(transient ? NUM_TRANS_START_FREQ_COEF : NUM_NONTRANS_START_FREQ_COEF);
    Word16 spect_end = (Word16)(transient ? NUM_TRANS_END_FREQ_COEF : NUM_NONTRANS_END_FREQ_COEF);
    Word16 nsv = (Word16)(transient ? 8 : random_range(25, 34));
    Word16 q_audio = (Word16)(transient ? 8 : 10);
    Word16 tilt = (Word16)(next_random() % 2 ? random_range(0, 10240) : random_range(10240, 32767));
    Word16 pitch = (Word16)(next_random() % 8 == 0 ? random_range(6400, 12000) : random_range(34 * 16, 231 * 16));
    Word16 seed = random16();
    memset(t_audio, 0, sizeof(t_audio));
    random_avq_spectrum(t_audio, nq, transient ? nsv : 34, q_audio);
    for (int i = (transient ? nsv : 34); i < NSV_MAX; i++) nq[i] = 0;
    /* the non-transient caller hands nq in the layout of its AVQ decode: empty runs at the start and
     * between coded ones, occasionally everything empty or everything coded */
    int shape = next_random() % 8;
    if (!transient && shape == 0) for (int i = 0; i < 34; i++) { nq[i] = 0; memset(t_audio + i * 8, 0, 16); }
    if (!transient && shape == 1) for (int i = 0; i < 34; i++) if (nq[i] == 0) { nq[i] = 1; t_audio[i * 8] = (Word16)(1 << q_audio); }
    put1("transient", transient); put1("start", spect_start); put1("end", spect_end); put1("tilt", tilt);
    put1("pitch", pitch); put16("nq", nq, NSV_MAX); put1("nsv", nsv); put1("seed", seed);
    put16("t_audio", t_audio, NSV_MAX * WIDTH_BAND); put1("q_audio", q_audio);
    swb_hr_noise_fill_fx(transient, spect_start, spect_end, tilt, pitch, nq, nsv, &seed, t_audio, q_audio);
    arrow(); put16("t_audio", t_audio, NSV_MAX * WIDTH_BAND); put1("seed", seed); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "swb_hr_noise_fill")) case_swb_hr_noise_fill();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
