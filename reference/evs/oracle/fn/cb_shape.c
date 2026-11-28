/* Function-level oracle for lib_com/cb_shape_fx.c (cb_shape_fx, E_GAIN_f_pitch_sharpening). */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_com/cb_shape_fx.c"

/* An order-16 LP filter in Q12 whose coefficients decay with the order, like a real A(z). */
static void random_lpc(Word16 *a)
{
    a[0] = 4096;
    for (int i = 1; i <= M; i++) {
        int span = 6000 * (M + 1 - i) / M;
        a[i] = (next_random() % 16) ? (Word16)random_range(-span, span) : random16();
    }
}

/* An algebraic code vector: a few signed pulses in Q9 (as the ACELP decoders write it), or a
 * gaussian-like random vector (gaus_dec), or edge values. */
static void random_code(Word16 *code)
{
    int kind = next_random() % 4;
    memset(code, 0, L_SUBFR * sizeof(Word16));
    if (kind < 2) {
        int pulses = random_range(1, 24);
        for (int p = 0; p < pulses; p++) {
            int at = random_range(0, L_SUBFR - 1);
            code[at] = add(code[at], (Word16)((next_random() & 1 ? 512 : -512) * random_range(1, 3)));
        }
    } else if (kind == 2) {
        random_signal(code, L_SUBFR, 8000);
    } else {
        for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    }
}

static void case_cb_shape(void)
{
    Word16 a[M + 1], code[L_SUBFR];
    random_lpc(a);
    random_code(code);
    Word16 preemph = next_random() & 1, pitch = next_random() & 1, scrambling = (next_random() % 4) == 0;
    Word16 sharp = next_random() & 1, tilt = (Word16)((next_random() % 3) == 0);
    Word16 g1 = (Word16)random_range(16384, 32767), g2 = (Word16)random_range(16384, 32767);
    Word16 tilt_code = (Word16)(next_random() % 8 ? random_range(0, 16384) : random16());
    Word16 pt_pitch = (Word16)(next_random() % 8 ? random_range(17, 289) : random_range(0, 70));
    Word16 shift = (Word16)random_range(0, 1);
    put1("preemph", preemph); put1("pitch", pitch); put1("scrambling", scrambling); put1("sharp", sharp);
    put1("g1", g1); put1("g2", g2); put16("a", a, M + 1); put16("code", code, L_SUBFR);
    put1("tilt_code", tilt_code); put1("pt_pitch", pt_pitch); put1("shift", shift); put1("tilt", tilt);
    Carry = (Flag)(next_random() & 1);
    put1("carry", Carry);
    cb_shape_fx(preemph, pitch, scrambling, sharp, tilt, g1, g2, a, code, tilt_code, pt_pitch, shift);
    arrow(); put16("code", code, L_SUBFR); put1("carry", Carry); end_line();
}

static void case_pitch_sharpening(void)
{
    Word16 x[L_SUBFR];
    random_code(x);
    Word16 lag = (Word16)random_range(0, 80);
    put16("x", x, L_SUBFR); put1("lag", lag);
    E_GAIN_f_pitch_sharpening(x, lag, L_SUBFR);
    arrow(); put16("x", x, L_SUBFR); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "cb_shape")) case_cb_shape();
        else if (!strcmp(argv[2], "pitch_sharpening")) case_pitch_sharpening();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
