/* Function-level oracle for the MODE2 leftovers of lib_com/basop_util.c and lib_com/tools_fx.c:
 * Sqrt16norm, ISqrt16, Sqrt32norm, ISqrt32norm, BASOP_Util_Sqrt_InvSqrt_MantExp, getCosWord16, imult3216,
 * Norm32Norm, getNormReciprocalWord16Scale, BASOP_Util_fPow, Dot_product12_offs, Dot_product15_offs,
 * bufferCopyFx, BASOP_util_atan, BASOP_util_atan2, compMantExp16Unorm, Exp32Array, Invert16 and
 * dot_prod_satcontr. Linked against the archive (every function is public). */
#include "harness.h"
#include "basop_util.h"
#include "cnst_fx.h"
#include "prot_fx.h"
#include "rom_basop_util.h"

#define MAXN 320

static Word32 random32_scaled(void)
{
    Word32 v = random32() >> random_range(0, 31);
    return v ? v : 1;
}

static Word16 random_norm16(void)
{
    Word16 m = (Word16)random_range(0x4000, 0x7fff);
    return (next_random() % 8 == 0) ? (Word16)0x7fff : m;
}

static Word32 random_norm32(void)
{
    Word32 m = (Word32)random_range(0x40000000, 0x7fffffff);
    return (next_random() % 8 == 0) ? 0x40000000 : m;
}

static void case_sqrt16norm(void)
{
    Word16 m = (next_random() % 16 == 0) ? 0 : random_norm16();
    Word16 e = (Word16)random_range(-30, 30), e_in = e;
    put1("m", m); put1("e", e_in);
    Word16 r = Sqrt16norm(m, &e);
    arrow(); put1("r", r); put1("e", e); end_line();
}

static void case_isqrt16(void)
{
    Word16 m = (Word16)random_range(1, 0x7fff);
    if (next_random() % 4 == 0) m = (Word16)random_range(1, 40);
    Word16 e = (Word16)random_range(-30, 30), e_in = e;
    put1("m", m); put1("e", e_in);
    Word16 r = ISqrt16(m, &e);
    arrow(); put1("r", r); put1("e", e); end_line();
}

static void case_sqrt32norm(void)
{
    Word32 m = (next_random() % 16 == 0) ? 0 : random_norm32();
    Word16 e = (Word16)random_range(-30, 30), e_in = e;
    put1("m", m); put1("e", e_in);
    Word32 r = Sqrt32norm(m, &e);
    arrow(); put1("r", r); put1("e", e); end_line();
}

static void case_isqrt32norm(void)
{
    Word32 m = random_norm32();
    Word16 e = (Word16)random_range(-30, 30), e_in = e;
    put1("m", m); put1("e", e_in);
    Word32 r = ISqrt32norm(m, &e);
    arrow(); put1("r", r); put1("e", e); end_line();
}

static void case_sqrt_invsqrt(void)
{
    Word16 m = (Word16)random_range(1, 0x7fff);
    if (next_random() % 3 == 0) m = (Word16)random_range(1, 100);
    Word16 e = (Word16)random_range(-30, 30);
    Word16 sm, se, im, ie;
    put1("m", m); put1("e", e);
    BASOP_Util_Sqrt_InvSqrt_MantExp(m, e, &sm, &se, &im, &ie);
    arrow(); put1("sm", sm); put1("se", se); put1("im", im); put1("ie", ie); end_line();
}

static void case_get_cos(void)
{
    Word16 t = random16();
    put1("t", t);
    Word16 r = getCosWord16(t);
    arrow(); put1("r", r); end_line();
}

static void case_imult3216(void)
{
    Word32 x = random32();
    Word16 y = random16();
    put1("x", x); put1("y", y);
    Word32 r = imult3216(x, y);
    arrow(); put1("r", r); end_line();
}

static void case_norm32norm(void)
{
    Word32 x[MAXN];
    int n = random_range(1, 64);
    int mode = random_range(0, 2);
    for (int i = 0; i < n; i++) {
        if (mode == 0) x[i] = random32();
        else if (mode == 1) x[i] = (Word32)random_range(-100000, 100000) << random_range(0, 14);
        else x[i] = random_range(-30, 30);
    }
    Word16 headroom = (Word16)getScaleFactor32(x, (Word16)n);
    if (next_random() % 2) headroom = (Word16)(headroom - random_range(0, 3));
    if (next_random() % 8 == 0) headroom = (Word16)random_range(-2, 20);
    Word16 e;
    put32("x", x, n); put1("headroom", headroom); put1("length", n);
    Word32 r = Norm32Norm(x, headroom, (Word16)n, &e);
    arrow(); put1("r", r); put1("e", e); end_line();
}

static void case_norm_reciprocal_scale(void)
{
    Word16 x = (Word16)random_range(0, CHEAP_NORM_SIZE - 1);
    Word16 s = (Word16)random_range(-4, 4);
    put1("x", x); put1("s", s);
    Word16 r = getNormReciprocalWord16Scale(x, s);
    arrow(); put1("r", r); end_line();
}

static void case_fpow(void)
{
    Word32 base_m = (next_random() % 12 == 0) ? 0 : random32_scaled();
    if (base_m < 0) base_m = (base_m == MIN_32) ? MAX_32 : -base_m;
    Word16 base_e = (Word16)random_range(-20, 20);
    Word32 exp_m = (next_random() % 12 == 0) ? 0 : random32();
    Word16 exp_e = (Word16)random_range(-5, 5);
    if (next_random() % 3 == 0) exp_m = (Word32)(0x40000000 + random_range(0, 0x3fffffff));
    Word16 re = 0;
    put1("base_m", base_m); put1("base_e", base_e); put1("exp_m", exp_m); put1("exp_e", exp_e);
    Word32 r = BASOP_Util_fPow(base_m, base_e, exp_m, exp_e, &re);
    arrow(); put1("r", r); put1("e", re); end_line();
}

static void case_dot12(void)
{
    Word16 x[MAXN], y[MAXN];
    int lg = random_range(1, 256);
    int bound = (next_random() % 3 == 0) ? 32767 : 2047;
    for (int i = 0; i < lg; i++) { x[i] = (Word16)random_range(-bound, bound); y[i] = (Word16)random_range(-bound, bound); }
    if (next_random() % 4 == 0) for (int i = 0; i < lg; i++) y[i] = x[i];
    Word32 off = (next_random() % 3 == 0) ? 0 : (Word32)random_range(0, 100000);
    int with_exp = next_random() % 4 != 0;
    Word16 e = -99;
    put16("x", x, lg); put16("y", y, lg); put1("lg", lg); put1("off", off); put1("with_exp", with_exp);
    Word32 r = Dot_product12_offs(x, y, (Word16)lg, with_exp ? &e : NULL, off);
    arrow(); put1("r", r); put1("e", e); end_line();
}

static void case_dot15(void)
{
    Word16 x[MAXN], y[MAXN];
    int lg = random_range(1, 256);
    for (int i = 0; i < lg; i++) { x[i] = random16(); y[i] = random16(); }
    if (next_random() % 4 == 0) for (int i = 0; i < lg; i++) y[i] = (Word16)random_range(-300, 300);
    Word32 off = (next_random() % 3 == 0) ? 0 : (Word32)random_range(-100000, 100000);
    Word16 e;
    put16("x", x, lg); put16("y", y, lg); put1("lg", lg); put1("off", off);
    Word32 r = Dot_product15_offs(x, y, (Word16)lg, &e, off);
    arrow(); put1("r", r); put1("e", e); end_line();
}

static void case_buffer_copy(void)
{
    Word16 src[MAXN], dest[MAXN];
    int length = random_range(0, 80);
    random_signal(src, length ? length : 1, random_range(1, 32767));
    Word16 qf_src = (Word16)random_range(0, 15), qf_dest = (Word16)random_range(0, 15);
    Word16 q_src = (Word16)random_range(-6, 6), q_dest = (Word16)random_range(-6, 6);
    if (next_random() % 4 == 0) qf_dest = qf_src;
    if (next_random() % 4 == 0) q_dest = q_src;
    for (int i = 0; i < MAXN; i++) dest[i] = 77;
    put16("src", src, length ? length : 1); put1("length", length);
    put1("qf_src", qf_src); put1("qf_dest", qf_dest); put1("q_src", q_src); put1("q_dest", q_dest);
    bufferCopyFx(src, dest, (Word16)length, qf_src, qf_dest, q_src, q_dest);
    arrow(); put16("dest", dest, length + 1); end_line();
}

static void case_atan(void)
{
    Word32 x;
    switch (random_range(0, 5)) {
    case 0: x = random32(); break;
    case 1: x = (Word32)random_range(-3000000, 3000000); break;
    case 2: x = (Word32)random_range(-40000000, 40000000); break;
    case 3: x = (Word32)random_range(-70000000, 70000000); break;
    default: x = (Word32)random_range(-2147483647, 2147483647); break;
    }
    put1("x", x);
    Word16 r = BASOP_util_atan(x);
    arrow(); put1("r", r); end_line();
}

static void case_atan2(void)
{
    Word32 y = random32(), x = random32();
    if (next_random() % 6 == 0) y = 0;
    if (next_random() % 8 == 0) x = 0;
    if (next_random() % 3 == 0) { y = random32() >> random_range(0, 20); x = random32() >> random_range(0, 20); }
    Word16 e = (Word16)random_range(-20, 20);
    put1("y", y); put1("x", x); put1("e", e);
    Word16 r = BASOP_util_atan2(y, x, e);
    arrow(); put1("r", r); end_line();
}

static void case_comp_mant_exp(void)
{
    Word16 m1 = random_norm16(), m2 = random_norm16();
    Word16 e1 = (Word16)random_range(-3, 3), e2 = (Word16)random_range(-3, 3);
    if (next_random() & 1) m2 = m1;
    put1("m1", m1); put1("e1", e1); put1("m2", m2); put1("e2", e2);
    Word16 r = compMantExp16Unorm(m1, e1, m2, e2);
    arrow(); put1("r", r); end_line();
}

static void case_exp32array(void)
{
    Word32 x[MAXN];
    int n = random_range(1, 100);
    int mode = random_range(0, 3);
    for (int i = 0; i < n; i++) {
        if (mode == 0) x[i] = random32();
        else if (mode == 1) x[i] = (Word32)random_range(-1000, 1000) << random_range(0, 20);
        else if (mode == 2) x[i] = 0;
        else x[i] = random_range(-3, 3);
    }
    put32("sx", x, n); put1("n", n);
    Word16 r = Exp32Array((Word16)n, x);
    arrow(); put1("r", r); end_line();
}

static void case_invert16(void)
{
    Word16 val = random16();
    if (next_random() & 1) val = (Word16)random_range(1, 5000);
    Word16 e = (Word16)random_range(-10, 10), e_in = e;
    put1("val", val); put1("exp", e_in);
    Word16 r = Invert16(val, &e);
    arrow(); put1("r", r); put1("exp", e); end_line();
}

static void case_dot_prod_satcontr(void)
{
    Word16 x[MAXN], y[MAXN];
    int len = random_range(1, MAXN);
    int magnitude = (Word16)random_range(1, 32767);
    random_signal(x, len, magnitude);
    random_signal(y, len, (next_random() & 1) ? magnitude : random_range(1, 32767));
    if (next_random() % 5 == 0) for (int i = 0; i < len; i++) { x[i] = (next_random() & 1) ? 32767 : -32768; y[i] = x[i]; }
    Word16 qx = (Word16)random_range(0, 15), qy = (Word16)random_range(0, 15), qo = -99;
    put16("x", x, len); put16("y", y, len); put1("qx", qx); put1("qy", qy); put1("len", len);
    Word16 r = dot_prod_satcontr(x, y, qx, qy, &qo, (Word16)len);
    arrow(); put1("r", r); put1("qo", qo); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    struct { const char *name; void (*run)(void); } table[] = {
        {"sqrt16norm", case_sqrt16norm}, {"isqrt16", case_isqrt16}, {"sqrt32norm", case_sqrt32norm},
        {"isqrt32norm", case_isqrt32norm}, {"sqrt_invsqrt", case_sqrt_invsqrt}, {"get_cos", case_get_cos},
        {"imult3216", case_imult3216}, {"norm32norm", case_norm32norm},
        {"norm_reciprocal_scale", case_norm_reciprocal_scale}, {"fpow", case_fpow}, {"dot12", case_dot12},
        {"dot15", case_dot15}, {"buffer_copy", case_buffer_copy}, {"atan", case_atan}, {"atan2", case_atan2},
        {"comp_mant_exp", case_comp_mant_exp}, {"exp32array", case_exp32array}, {"invert16", case_invert16},
        {"dot_prod_satcontr", case_dot_prod_satcontr},
    };
    void (*run)(void) = NULL;
    for (unsigned k = 0; k < sizeof(table) / sizeof(table[0]); k++) if (!strcmp(argv[2], table[k].name)) run = table[k].run;
    if (!run) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) run();
    return 0;
}
