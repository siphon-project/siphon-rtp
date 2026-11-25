/* Function-level oracle for lib_dec/arith_coder_dec.c (tcx_arith_decode, reached as a static). */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/arith_coder_dec.c"

#define BITS 300

static void case_tcx_arith_decode(void)
{
    static const int sizes[] = {64, 80, 128, 160, 256, 320, 512, 640, 960};
    Word16 l_frame = (Word16)sizes[random_range(0, 8)];
    Word16 envelope[960], prm[BITS], envelope_e = (Word16)random_range(3, 12);
    Word32 q_spectrum[960];
    int low_x = (1 << (16 - envelope_e)) / 10 + 2; /* exp(-x * 2^(e-16)) <= ~0.9: the encoder never gives base near 1 */
    Word16 target_bits = (Word16)random_range(40, 264);
    int zeros = random_range(1, 8);
    for (int i = 0; i < BITS; i++) prm[i] = (Word16)((next_random() % (unsigned)(zeros + 1)) != 0);
    for (int i = 0; i < 960; i++) {
        /* exp(-x * 2^(e-16)) with the argument between 0.1 and 3: bases from 0.05 to 0.9 */
        long x = ((long)random_range(100, 3000) << (16 - envelope_e)) / 1000;
        if (x > 32767) x = 32767;
        if (x < low_x) x = low_x;
        envelope[i] = (Word16)x; q_spectrum[i] = random32();
    }
    if (next_random() % 25 == 0) envelope[random_range(0, l_frame - 1)] = 0; /* bit-error safety check */
    Word16 q_spectrum_e = 77, nf_seed = 77;
    Carry = (Flag)(next_random() & 1);
    int carry_in = Carry;
    put1("l_frame", l_frame); put1("envelope_e", envelope_e); put1("target_bits", target_bits); put1("carry", carry_in);
    put16("envelope", envelope, l_frame); put16("prm", prm, BITS); put32("q_in", q_spectrum, l_frame);
    Word16 bits = tcx_arith_decode(l_frame, envelope, envelope_e, target_bits, prm, q_spectrum, &q_spectrum_e, &nf_seed);
    arrow(); put1("bits", bits); put32("q", q_spectrum, l_frame); put1("q_e", q_spectrum_e); put1("seed", nf_seed);
    put1("carry", Carry); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "tcx_arith_decode")) case_tcx_arith_decode();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
