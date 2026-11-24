/* Function-level oracle for lib_com/basop_util.c (the functions the decoder executes). The source is
 * included so its static helpers (Sqrt32_common, fixp_sin_cos_residual_16) are reachable; its
 * definitions then take the place of the archive's basop_util.o. */
#include "harness.h"
#include "../../c-code/lib_com/basop_util.c"

#define MAXN 640

static void fill16(Word16 *x, int n)
{
    int mode = random_range(0, 3);
    if (mode == 0) random_signal(x, n, random_range(1, 32767));
    else if (mode == 1) for (int i = 0; i < n; i++) x[i] = random16();
    else if (mode == 2) for (int i = 0; i < n; i++) x[i] = (Word16)random_range(-300, 300);
    else for (int i = 0; i < n; i++) x[i] = (next_random() & 1) ? 32767 : -32768;
}

static void fill32(Word32 *x, int n)
{
    int mode = random_range(0, 3);
    for (int i = 0; i < n; i++) {
        if (mode == 0) x[i] = random32();
        else if (mode == 1) x[i] = (Word32)random_range(-1000000, 1000000) << random_range(0, 11);
        else if (mode == 2) x[i] = (Word32)random_range(-40000, 40000);
        else x[i] = 0;
    }
}

/* A non-zero Word32 at a random magnitude. */
static Word32 random32_scaled(void)
{
    Word32 v = random32() >> random_range(0, 31);
    return v ? v : 1;
}

static void case_log2(void)
{
    Word32 x = random32_scaled();
    if (x < 0) x = (x == MIN_32) ? MAX_32 : -x;
    if (next_random() % 16 == 0) x = 0;
    put1("x", x);
    Word32 r = BASOP_Util_Log2(x);
    arrow(); put1("r", r); end_line();
}

static void case_inv_log2(void)
{
    Word32 x = (next_random() & 3) ? (Word32)random_range(-1040187392, 1040187391) : random32_scaled();
    put1("x", x);
    Word32 r = BASOP_Util_InvLog2(x);
    arrow(); put1("r", r); end_line();
}

static void case_divide_mant_exp(void)
{
    Word16 a_m = random16(), b_m = random16(), m, e;
    Word16 a_e = (Word16)random_range(-40, 40), b_e = (Word16)random_range(-40, 40);
    if (next_random() & 1) b_m = (Word16)(b_m >> random_range(0, 14));
    if (b_m == 0) b_m = 1;
    put1("a_m", a_m); put1("a_e", a_e); put1("b_m", b_m); put1("b_e", b_e);
    BASOP_Util_Divide_MantExp(a_m, a_e, b_m, b_e, &m, &e);
    arrow(); put1("m", m); put1("e", e); end_line();
}

static void case_sqrt32(void)
{
    Word32 m = random32_scaled();
    Word16 e = (Word16)random_range(-40, 40);
    if (m < 0) m = (m == MIN_32) ? MAX_32 : -m;
    if (next_random() % 16 == 0) m = 0;
    put1("mantissa", m); put1("exponent", e);
    Word32 r = Sqrt32(m, &e);
    arrow(); put1("mantissa", r); put1("exponent", e); end_line();
}

static void case_sqrt16(void)
{
    Word16 m = random16(), e = (Word16)random_range(-40, 40);
    if (m < 0) m = (m == (Word16)0x8000) ? 32767 : (Word16)-m;
    if (next_random() & 1) m = (Word16)(m >> random_range(0, 14));
    if (next_random() % 16 == 0) m = 0;
    put1("mantissa", m); put1("exponent", e);
    Word16 r = Sqrt16(m, &e);
    arrow(); put1("mantissa", r); put1("exponent", e); end_line();
}

static void case_get_scale_factor(void)
{
    Word16 x[MAXN]; Word32 y[MAXN];
    Word16 len = (Word16)random_range(0, 80);
    fill16(x, len); fill32(y, len);
    if (next_random() % 8 == 0) for (int i = 0; i < len; i++) x[i] = 0;
    if (next_random() & 1) for (int i = 0; i < len; i++) x[i] = (Word16)(x[i] >> random_range(0, 15));
    put16("x16", x, len); put32("x32", y, len); put1("len", len);
    Word16 s16 = getScaleFactor16(x, len), s32 = getScaleFactor32(y, len);
    arrow(); put1("s16", s16); put1("s32", s32); end_line();
}

static void case_divide3232_uu_1616(void)
{
    Word32 x = random32_scaled(), y = random32_scaled();
    Word16 s;
    if (x < 0) x = (x == MIN_32) ? MAX_32 : -x;
    if (y < 0) y = (y == MIN_32) ? MAX_32 : -y;
    if (next_random() % 16 == 0) x = 0;
    put1("x", x); put1("y", y);
    Word16 z = BASOP_Util_Divide3232_uu_1616_Scale(x, y, &s);
    arrow(); put1("z", z); put1("s", s); end_line();
}

static void case_divide3232(void)
{
    Word32 x = random32_scaled(), y = random32_scaled();
    Word16 s;
    if (next_random() % 16 == 0) x = 0;
    put1("x", x); put1("y", y);
    Word16 z = BASOP_Util_Divide3232_Scale(x, y, &s);
    arrow(); put1("z", z); put1("s", s); end_line();
}

/* divide3232 (the plain one): |num| well under |denom|, as its callers guarantee (div_l exits
 * the process otherwise). */
static void case_divide3232_plain(void)
{
    Word32 d = random32();
    if (d > -0x20000 && d < 0x20000) d = 0x40000000 - d; /* round_fx(denom) must stay non-zero */
    if (d == (Word32)0x80000000) d = 0x40000000;
    long long mag = d < 0 ? -(long long)d : d;
    Word32 n = (Word32)((long long)(next_random() % (unsigned)(mag / 2 + 1)) * ((next_random() & 1) ? 1 : -1));
    if (next_random() % 8 == 0) n = (Word32)((n >> random_range(0, 30)));
    put1("num", n); put1("denom", d);
    Word16 z = divide3232(n, d);
    arrow(); put1("z", z); end_line();
}

static void case_divide3216(void)
{
    Word32 x = random32_scaled();
    Word16 y = random16(), s;
    if (next_random() & 1) y = (Word16)(y >> random_range(0, 14));
    if (y == 0) y = -1;
    if (next_random() % 16 == 0) x = 0;
    put1("x", x); put1("y", y);
    Word16 z = BASOP_Util_Divide3216_Scale(x, y, &s);
    arrow(); put1("z", z); put1("s", s); end_line();
}

static void case_sin_cos(void)
{
    Word16 x = random16(), scale = (Word16)random_range(1, 2), sine, cosine;
    Word8 flag = (Word8)(next_random() & 1);
    put1("x", x); put1("scale", scale); put1("flag", flag);
    Word16 residual = fixp_sin_cos_residual_16(x, scale, &sine, &cosine, flag);
    Word16 c = getCosWord16R2(x);
    arrow(); put1("residual", residual); put1("sine", sine); put1("cosine", cosine); put1("cos_r2", c); end_line();
}

static void case_integer(void)
{
    Word16 x = random16(), y = random16();
    if (next_random() & 1) y = (Word16)(y >> random_range(0, 15));
    if (y == 0) y = 1;
    Word16 a = (Word16)random_range(-181, 181), b = (Word16)random_range(-181, 181);
    if (next_random() & 1) { a = random16(); b = (Word16)(a ? random_range(-32767 / (a < 0 ? -a : a), 32767 / (a < 0 ? -a : a)) : random16()); }
    put1("x", x); put1("y", y); put1("a", a); put1("b", b);
    Word16 q = idiv1616(x, y), p = imult1616(a, b);
    arrow(); put1("quotient", q); put1("product", p); end_line();
}

static void case_idiv1616u(void)
{
    /* the operands tcx_ltp_post divides: a rescaled lag (Q of pitres) by pitres, plus the range */
    Word16 x = (Word16)(next_random() & 1 ? random_range(0, 32767) : random_range(29 * 4, 1200 * 6));
    Word16 y = (Word16)(next_random() & 1 ? random_range(1, 32767) : random_range(1, 6));
    put1("x", x); put1("y", y);
    Word16 q = idiv1616U(x, y);
    arrow(); put1("quotient", q); end_line();
}

static void case_dot_product16_hq(void)
{
    Word16 x[MAXN], y[MAXN], e;
    Word16 lg = (Word16)random_range(0, 320);
    Word32 off = (next_random() & 1) ? 0 : random32();
    fill16(x, lg); fill16(y, lg);
    put1("l_off", off); put16("x", x, lg); put16("y", y, lg); put1("lg", lg);
    Carry = (Flag)(next_random() & 1);
    Word32 r = Dot_product16HQ(off, x, y, lg, &e);
    arrow(); put1("r", r); put1("exp", e); put1("carry", Carry); end_line();
}

static void case_norm_llq31(void)
{
    Word32 c = (next_random() & 1) ? random32() : (Word32)random_range(-3, 3), sum = random32();
    Word16 e;
    put1("l_c", c); put1("l_sum", sum);
    Word32 r = norm_llQ31(c, sum, &e);
    arrow(); put1("r", r); put1("exp", e); put1("carry", Carry); end_line();
}

static void case_dot_product_sq16_hq(void)
{
    Word16 x[MAXN], e;
    Word16 lg = (Word16)random_range(0, 320);
    Word32 off = (next_random() & 1) ? 0 : random32();
    fill16(x, lg);
    put1("l_off", off); put16("x", x, lg); put1("lg", lg);
    Carry = (Flag)(next_random() & 1);
    Word32 r = Dot_productSq16HQ(off, x, lg, &e);
    arrow(); put1("r", r); put1("exp", e); put1("carry", Carry); end_line();
}

static void case_dotp_s(void)
{
    Word16 x[MAXN], y[MAXN];
    Word16 n = (Word16)random_range(0, 320), s = (Word16)random_range(-1, 16);
    fill16(x, n); fill16(y, n);
    put16("x", x, n); put16("y", y, n); put1("n", n); put1("s", s);
    Word32 r = dotp_s_fx(x, y, n, s);
    arrow(); put1("r", r); end_line();
}

static void case_norm_reciprocal(void)
{
    Word16 x = (Word16)random_range(0, 160);
    put1("x", x);
    Word16 r = getNormReciprocalWord16(x);
    arrow(); put1("r", r); end_line();
}

static void case_add_mant32_exp(void)
{
    Word32 a = random32_scaled(), b = random32_scaled();
    Word16 a_e = (Word16)random_range(-50, 50), b_e = (Word16)random_range(-50, 50), e;
    if (next_random() % 8 == 0) a = 0;
    if (next_random() % 8 == 0) b = 0;
    if (next_random() % 8 == 0) b = -a;
    put1("a_m", a); put1("a_e", a_e); put1("b_m", b); put1("b_e", b_e);
    Word32 r = BASOP_Util_Add_Mant32Exp(a, a_e, b, b_e, &e);
    arrow(); put1("r", r); put1("exp", e); end_line();
}

static void case_dot_word32_16(void)
{
    Word32 x[MAXN]; Word16 y[MAXN], e;
    Word16 len = (Word16)random_range(1, 320);
    Word16 xe = (Word16)random_range(-20, 31), ye = (Word16)random_range(-20, 15);
    fill32(x, len); fill16(y, len);
    if (next_random() & 1) for (int i = 0; i < len; i++) y[i] = (Word16)(y[i] >> random_range(1, 9));
    put32("x", x, len); put1("x_exp", xe); put16("y", y, len); put1("y_exp", ye); put1("len", len);
    Word32 r = dotWord32_16_Mant32Exp(x, xe, y, ye, len, &e);
    arrow(); put1("r", r); put1("exp", e); end_line();
}

static void case_isqrt32(void)
{
    Word32 m = random32_scaled();
    Word16 e = (Word16)random_range(-40, 40);
    if (m < 0) m = (m == MIN_32) ? MAX_32 : -m;
    if (m == 0) m = 1;
    put1("mantissa", m); put1("exponent", e);
    Word32 r = ISqrt32(m, &e);
    arrow(); put1("mantissa", r); put1("exponent", e); end_line();
}

/* BASOP_util_Pow2: the FD-CNG energy update passes a Q25 log2 (exponent 6); other exponents and
 * full-range mantissas besides. */
static void case_pow2(void)
{
    Word32 m = next_random() % 4 ? (Word32)random_range(-20 << 25, 30 << 25) >> random_range(0, 6) : random32();
    Word16 e = (Word16)(next_random() % 2 ? 6 : random_range(-8, 12)), re = -99;
    put1("exp_m", m); put1("exp_e", e);
    Word32 r = BASOP_util_Pow2(m, e, &re);
    arrow(); put1("r", r); put1("result_e", re); end_line();
}

static void case_norm_s_bands2shift(void)
{
    Word16 x = (Word16)(next_random() % 4 ? random_range(1, 160) : random16());
    put1("x", x);
    Word16 r = BASOP_util_norm_s_bands2shift(x);
    arrow(); put1("r", r); end_line();
}

static void case_divide1616(void)
{
    Word16 x = random16(), y = random16(), s;
    if (next_random() & 1) x = (Word16)(x >> random_range(0, 14));
    if (next_random() & 1) y = (Word16)(y >> random_range(0, 14));
    if (y == 0) y = 1;
    if (next_random() % 16 == 0) x = 0;
    put1("x", x); put1("y", y);
    Word16 z = BASOP_Util_Divide1616_Scale(x, y, &s);
    arrow(); put1("z", z); put1("s", s); end_line();
}

static void case_add_mant_exp(void)
{
    Word16 a_m = random16(), b_m = random16(), sum;
    Word16 a_e = (Word16)random_range(-40, 40), b_e = (Word16)random_range(-40, 40);
    if (next_random() & 1) a_m = (Word16)(a_m >> random_range(0, 15));
    if (next_random() & 1) b_m = (Word16)(b_m >> random_range(0, 15));
    if (next_random() % 4 == 0) b_e = (Word16)(a_e + random_range(-2, 2));
    put1("a_m", a_m); put1("a_e", a_e); put1("b_m", b_m); put1("b_e", b_e);
    Word16 e = BASOP_Util_Add_MantExp(a_m, a_e, b_m, b_e, &sum);
    arrow(); put1("m", sum); put1("e", e); end_line();
}

static void case_inv16(void)
{
    Word16 m = random16(), e = (Word16)random_range(-20, 20);
    if (next_random() & 1) m = (Word16)(m >> random_range(0, 14));
    if (m == 0) m = (Word16)random_range(1, 300);
    put1("m", m); put1("e", e);
    Word16 r = Inv16(m, &e);
    arrow(); put1("r", r); put1("e", e); end_line();
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*fn)(void); } table[] = {
        {"log2", case_log2}, {"inv_log2", case_inv_log2}, {"divide_mant_exp", case_divide_mant_exp},
        {"sqrt32", case_sqrt32}, {"sqrt16", case_sqrt16}, {"get_scale_factor", case_get_scale_factor},
        {"divide3232_uu_1616", case_divide3232_uu_1616}, {"divide3232", case_divide3232},
        {"divide3232_plain", case_divide3232_plain},
        {"divide3216", case_divide3216}, {"sin_cos", case_sin_cos}, {"integer", case_integer},
        {"norm_llq31", case_norm_llq31}, {"dot_product_sq16_hq", case_dot_product_sq16_hq},
        {"dotp_s", case_dotp_s}, {"norm_reciprocal", case_norm_reciprocal},
        {"add_mant32_exp", case_add_mant32_exp}, {"idiv1616u", case_idiv1616u},
        {"dot_product16_hq", case_dot_product16_hq}, {"dot_word32_16", case_dot_word32_16},
        {"isqrt32", case_isqrt32}, {"pow2", case_pow2}, {"norm_s_bands2shift", case_norm_s_bands2shift},
        {"divide1616", case_divide1616}, {"add_mant_exp", case_add_mant_exp}, {"inv16", case_inv16},
    };
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (size_t t = 0; t < sizeof(table) / sizeof(table[0]); t++) {
        if (strcmp(argv[2], table[t].name)) continue;
        for (long i = 0, n = atol(argv[3]); i < n; i++) table[t].fn();
        return 0;
    }
    fprintf(stderr, "unknown function %s\n", argv[2]);
    return 2;
}
