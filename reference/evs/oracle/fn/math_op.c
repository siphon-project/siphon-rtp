/* Function-level oracle for basic_math/math_op.c. */
#include "harness.h"
#include "prot_fx.h"
#include "math_op.h"

/* A positive normalised Q31 mantissa. */
static Word32 normalised(void)
{
    if (next_random() % 4 == 0) {
        static const Word32 e[] = {0x40000000, 0x40000001, 0x7fffffff, 0x7fff0000, 0x5a827999, 0x40007fff};
        return e[next_random() % 6];
    }
    return (Word32)random_range(0x40000000, 0x7fffffff);
}

/* Any 32-bit value, positive values spread over every magnitude. */
static Word32 any32(void)
{
    if (next_random() & 1) return random32();
    return L_shr((Word32)random_range(1, 0x7fffffff), (Word16)random_range(0, 30));
}

static void case_isqrt(void)
{
    Word32 x = any32();
    put1("x", x);
    arrow(); put1("y", Isqrt(x)); end_line();
}

static void case_isqrt_lc(void)
{
    /* The callers pass a normalised mantissa; a non-positive one takes the early return. */
    Word32 frac = (next_random() % 8 == 0) ? -(Word32)random_range(0, 5) : normalised();
    Word16 exp = (next_random() & 1) ? (Word16)random_range(-40, 40) : random16();
    put1("frac", frac); put1("exp", exp);
    Word32 y = Isqrt_lc(frac, &exp);
    arrow(); put1("y", y); put1("exp", exp); end_line();
}

static void case_pow2(void)
{
    Word16 exponant = (Word16)random_range(-2, 31);
    Word16 fraction = (next_random() & 1) ? (Word16)random_range(0, 32767) : (Word16)(random16() & 0x7fff);
    put1("exponant", exponant); put1("fraction", fraction);
    arrow(); put1("y", Pow2(exponant, fraction)); end_line();
}

static void case_dot_product12(void)
{
    Word16 x[64], y[64], exp;
    Word16 lg = (next_random() & 1) ? 64 : (Word16)random_range(1, 64);
    int mode = next_random() % 3;
    for (int i = 0; i < lg; i++) {
        x[i] = mode == 0 ? random16() : (Word16)random_range(-(1 << (mode * 7)), 1 << (mode * 7));
        y[i] = mode == 0 ? random16() : (Word16)random_range(-(1 << (mode * 7)), 1 << (mode * 7));
    }
    if (next_random() % 4 == 0) for (int i = 0; i < lg; i++) y[i] = x[i];
    if (next_random() % 8 == 0) for (int i = 0; i < lg; i++) x[i] = 0;
    put16("x", x, lg); put16("y", y, lg); put1("lg", lg);
    Word32 s = Dot_product12(x, y, lg, &exp);
    arrow(); put1("sum", s); put1("exp", exp); end_line();
}

static void case_sqrt_l(void)
{
    Word32 x = any32();
    Word16 exp = 7;
    put1("x", x);
    Word32 y = Sqrt_l(x, &exp);
    arrow(); put1("y", y); put1("exp", exp); end_line();
}

static void case_l_frac_sqrt_q31(void)
{
    Word32 x = any32();
    put1("x", x);
    arrow(); put1("y", L_Frac_sqrtQ31(x)); end_line();
}

static void case_frac_sqrt(void)
{
    Word16 x = random16();
    put1("x", x);
    arrow(); put1("y", Frac_sqrt(x)); end_line();
}

static void case_i_mult2(void)
{
    Word16 a = random16(), b = random16();
    put1("a", a); put1("b", b);
    arrow(); put1("y", i_mult2(a, b)); end_line();
}

static void case_energy_scale(void)
{
    Word16 x[L_FRAME16k], exp;
    Word16 lg = (Word16)((next_random() & 1) ? L_FRAME / 2 : random_range(1, L_FRAME16k));
    Word16 expi = (Word16)random_range(-6, 4);
    random_signal(x, lg, (next_random() & 1) ? 32767 : random_range(1, 3000));
    if ((next_random() & 7) == 0) for (int i = 0; i < lg; i++) x[i] = random16();
    put16("x", x, lg); put1("expi", expi);
    Word32 r = Energy_scale(x, lg, expi, &exp);
    arrow(); put1("r", r); put1("exp", exp); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "isqrt")) case_isqrt();
        else if (!strcmp(argv[2], "isqrt_lc")) case_isqrt_lc();
        else if (!strcmp(argv[2], "pow2")) case_pow2();
        else if (!strcmp(argv[2], "dot_product12")) case_dot_product12();
        else if (!strcmp(argv[2], "sqrt_l")) case_sqrt_l();
        else if (!strcmp(argv[2], "l_frac_sqrt_q31")) case_l_frac_sqrt_q31();
        else if (!strcmp(argv[2], "frac_sqrt")) case_frac_sqrt();
        else if (!strcmp(argv[2], "i_mult2")) case_i_mult2();
        else if (!strcmp(argv[2], "energy_scale")) case_energy_scale();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
