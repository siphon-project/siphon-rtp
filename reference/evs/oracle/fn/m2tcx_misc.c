/* Function-level oracle for the small helpers of the MODE2 TCX bundle: ISqrt16 and getCosWord16
 * (lib_com/basop_util.c), ham_cos_window (window.c), get_gain2 (get_gain.c) and E_LPC_a_weight_inv
 * (weight_a_fx.c). Inputs are in the ranges the decoder feeds them: ham_cos_window at L_frame
 * 256..960 (n1 = 3/4 L_frame, n2 = L_frame/4), E_LPC_a_weight_inv at order 16 with the weightings
 * of arith_coder.c. */
#include "harness.h"
#include "prot_fx.h"

static void case_isqrt16(void)
{
    Word16 mantissa = (Word16)(next_random() % 4 ? random_range(1, 32767) : random_range(1, 200));
    Word16 exponent = (Word16)random_range(-20, 20);
    put1("mantissa", mantissa); put1("exponent", exponent);
    Word16 r = ISqrt16(mantissa, &exponent);
    arrow(); put1("r", r); put1("exponent", exponent); end_line();
}

static void case_cos(void)
{
    Word16 theta = (next_random() & 1) ? random16() : (Word16)random_range(-32768, 32767);
    put1("theta", theta);
    arrow(); put1("r", getCosWord16(theta)); end_line();
}

static void case_ham_cos_window(void)
{
    static const Word16 frames[] = {256, 320, 512, 640, 960};
    static Word16 fh[1200];
    Word16 l_frame = frames[random_range(0, 4)];
    Word16 n1 = mult(l_frame, 24576), n2 = shr(l_frame, 2);
    memset(fh, 0, sizeof(fh));
    put1("n1", n1); put1("n2", n2);
    ham_cos_window(fh, n1, n2);
    arrow(); put16("fh", fh, n1 + n2); end_line();
}

static void case_get_gain2(void)
{
    Word16 x[L_FRAME16k], y[L_FRAME16k];
    Word16 n = (Word16)(next_random() & 1 ? L_SUBFR - 1 : random_range(1, L_FRAME16k));
    int kind = next_random() % 4;
    random_signal(y, n, kind == 0 ? 32767 : 4000);
    if (kind == 1) for (int i = 0; i < n; i++) x[i] = add(y[i], (Word16)random_range(-500, 500));
    else if (kind == 3) for (int i = 0; i < n; i++) x[i] = negate(y[i]);
    else random_signal(x, n, kind == 2 ? 100 : 20000);
    if (next_random() % 8 == 0) for (int i = 0; i < n; i++) y[i] = random16();
    if (next_random() % 16 == 0) memset(y, 0, sizeof(y));
    put16("x", x, n); put16("y", y, n); put1("n", n);
    Carry = (Flag)(next_random() & 1);
    Word32 g = get_gain2(x, y, n);
    arrow(); put1("gain", g); put1("carry", Carry); end_line();
}

static void case_a_weight_inv(void)
{
    static const Word16 gammas[] = {16384, GAMMA1_INV, GAMMA16k_INV};
    Word16 a[M + 1], ap[M + 1];
    Word16 inv_gamma = gammas[random_range(0, 2)];
    int magnitude = random_range(1, 3) == 1 ? 32767 : 12000;
    a[0] = 4096;
    for (int i = 1; i <= M; i++) a[i] = (Word16)random_range(-magnitude, magnitude);
    if (next_random() % 8 == 0) for (int i = 1; i <= M; i++) a[i] = 0;
    memset(ap, 0x55, sizeof(ap));
    put16("a", a, M + 1); put1("inv_gamma", inv_gamma);
    E_LPC_a_weight_inv(a, ap, inv_gamma, M);
    arrow(); put16("ap", ap, M + 1); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "ISqrt16")) case_isqrt16();
        else if (!strcmp(argv[2], "getCosWord16")) case_cos();
        else if (!strcmp(argv[2], "ham_cos_window")) case_ham_cos_window();
        else if (!strcmp(argv[2], "get_gain2")) case_get_gain2();
        else if (!strcmp(argv[2], "E_LPC_a_weight_inv")) case_a_weight_inv();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
