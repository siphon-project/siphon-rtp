/* Boundary-focused oracle for Is_Periodic_x (lib_dec/waveadjust_fec_dec.c): every threshold of the
 * decision (zero crossings 100, correlation 19661 / 26214 / 29491, energy against 50 and against
 * the mean +1, -6 and -8 in Q8) is probed at the value, one below and one above it, with the
 * remaining inputs on both sides of their own thresholds. */
#include <math.h>
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/waveadjust_fec_dec.c"

static Word32 around(Word32 threshold)
{
    static const int deltas[] = {-1, 0, 1, 0, -2, 2};
    return threshold + deltas[next_random() % 6];
}

static void case_is_periodic(void)
{
    Word32 mdct[L_FRAME_MAX];
    static const Word16 sizes[] = {160, 320, 512, 640, 960};
    Word16 frame_size = sizes[next_random() % 5];
    Word16 pitch = (Word16)random_range(frame_size / 8, 3 * frame_size / 4);
    Word32 ener_mean = (Word32)random_range(40 * 256, 70 * 256);
    Word32 ener, cov;
    Word16 zp;
    switch (next_random() % 5) {
    case 0: ener = around(50 * 256); break;
    case 1: ener = around(ener_mean - 8 * 256); break;
    case 2: ener = around(ener_mean - 6 * 256); break;
    case 3: ener = around(ener_mean + 1 * 256); break;
    default: ener = ener_mean + random_range(-3 * 256, 3 * 256); break;
    }
    switch (next_random() % 4) {
    case 0: cov = around(29491); break;
    case 1: cov = around(26214); break;
    case 2: cov = around(19661); break;
    default: cov = random_range(0, 32767); break;
    }
    zp = (Word16)((next_random() % 2) ? around(100) : random_range(0, 140));
    /* a spectrum whose harmonic share moves across the 22938 threshold */
    int amplitude = 1 << random_range(8, 20), peaks = (next_random() % 3) ? 8 : random_range(1, 8);
    for (int i = 0; i < frame_size; i++) mdct[i] = (Word32)random_range(-amplitude, amplitude);
    for (int k = 1; k <= peaks; k++) {
        int h = (2 * k * frame_size) / pitch - 1;
        if (h >= 0 && h + 1 < frame_size) { mdct[h] = (Word32)amplitude * random_range(1, 30); mdct[h + 1] = (Word32)amplitude * random_range(1, 30); }
    }
    put32("mdct", mdct, frame_size); put1("frame_size", frame_size); put1("pitch", pitch); put1("cov", cov);
    put1("zp", zp); put1("ener", ener); put1("ener_mean", ener_mean);
    Word16 periodic = Is_Periodic_x(mdct, (Word16)cov, zp, ener, ener_mean, pitch, frame_size);
    Word16 harm = harmo_x(mdct, frame_size, pitch);
    arrow(); put1("periodic", periodic); put1("harm", harm); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "is_periodic")) case_is_periodic();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
