/* Function-level oracle for lib_com/tools_fx.c (the functions the decoder executes). */
#include "harness.h"
#include "prot_fx.h"
#include "basop_util.h"

#define MAXN 640

static Word16 maybe_edge16(int magnitude)
{
    if ((next_random() & 3) == 0) return random16();
    return (Word16)random_range(-magnitude, magnitude);
}

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
    int mode = random_range(0, 2);
    for (int i = 0; i < n; i++) {
        if (mode == 0) x[i] = random32();
        else if (mode == 1) x[i] = (Word32)random_range(-1000000, 1000000) << random_range(0, 11);
        else x[i] = (Word32)random_range(-40000, 40000);
    }
}

static void case_usdequant(void)
{
    Word16 idx = (Word16)random_range(0, 63), qlow = random16(), delta = maybe_edge16(8000);
    put1("idx", idx); put1("qlow", qlow); put1("delta", delta);
    Word16 g = usdequant_fx(idx, qlow, delta);
    arrow(); put1("g", g); end_line();
}

static void case_dot_product(void)
{
    Word16 x[MAXN], y[MAXN];
    Word16 lg = (Word16)random_range(1, 320);
    fill16(x, lg); fill16(y, lg);
    put16("x", x, lg); put16("y", y, lg); put1("lg", lg);
    Word32 s = Dot_product(x, y, lg);
    arrow(); put1("sum", s); end_line();
}

static void case_sum2(void)
{
    Word16 x[MAXN];
    Word16 lvec = (Word16)random_range(0, 320);
    fill16(x, lvec);
    put16("vec", x, lvec); put1("lvec", lvec);
    Word32 s = sum2_fx(x, lvec);
    arrow(); put1("sum", s); end_line();
}

static void case_copy_scale_sig(void)
{
    Word16 x[MAXN], y[MAXN];
    Word16 lg = (Word16)random_range(0, 80), exp0 = (Word16)random_range(-17, 17);
    fill16(x, lg);
    put16("x", x, lg); put1("lg", lg); put1("exp0", exp0);
    Copy_Scale_sig(x, y, lg, exp0);
    arrow(); put16("y", y, lg); end_line();
}

static void case_copy_scale_sig_16_32(void)
{
    Word16 x[MAXN]; Word32 y[MAXN];
    Word16 lg = (Word16)random_range(0, 80), exp0 = (Word16)random_range(-17, 17);
    fill16(x, lg);
    put16("x", x, lg); put1("lg", lg); put1("exp0", exp0);
    Copy_Scale_sig_16_32(x, y, lg, exp0);
    arrow(); put32("y", y, lg); end_line();
}

static void case_own_random2(void)
{
    Word16 seed = random16();
    put1("seed", seed);
    Word16 r = own_random2_fx(seed);
    arrow(); put1("r", r); end_line();
}

static void case_copy_scale_sig_32_16(void)
{
    Word32 x[MAXN]; Word16 y[MAXN];
    Word16 lg = (Word16)random_range(0, 80), exp0 = (Word16)random_range(-33, 17);
    fill32(x, lg);
    put32("x", x, lg); put1("lg", lg); put1("exp0", exp0);
    Copy_Scale_sig_32_16(x, y, lg, exp0);
    arrow(); put16("y", y, lg); end_line();
}

static void case_copy_scale_sig32_16(void)
{
    Word32 x[MAXN]; Word16 y[MAXN];
    Word16 lg = (Word16)random_range(0, 80), exp0 = (Word16)random_range(-33, 33);
    fill32(x, lg);
    put32("x", x, lg); put1("lg", lg); put1("exp0", exp0);
    Copy_Scale_sig32_16(x, y, lg, exp0);
    arrow(); put16("y", y, lg); end_line();
}

static void case_scale_sig32(void)
{
    Word32 x[MAXN];
    Word16 lg = (Word16)random_range(0, 80), exp0 = (Word16)random_range(-33, 33);
    fill32(x, lg);
    put32("x", x, lg); put1("lg", lg); put1("exp0", exp0);
    Scale_sig32(x, lg, exp0);
    arrow(); put32("x", x, lg); end_line();
}

static void case_scale_sig(void)
{
    Word16 x[MAXN];
    Word16 lg = (Word16)random_range(0, 80), exp0 = (Word16)random_range(-17, 17);
    fill16(x, lg);
    put16("x", x, lg); put1("lg", lg); put1("exp0", exp0);
    Scale_sig(x, lg, exp0);
    arrow(); put16("x", x, lg); end_line();
}

static void case_random_fill(void)
{
    Word16 y[MAXN];
    Word16 seed = random16(), n = (Word16)random_range(0, 320), scaling = (Word16)random_range(0, 16);
    put1("seed", seed); put1("n", n); put1("scaling", scaling);
    Random_Fill(&seed, n, y, scaling);
    arrow(); put1("seed", seed); put16("y", y, n); end_line();
}

static void case_random(void)
{
    Word16 seed = random16();
    put1("seed", seed);
    Word16 r = Random(&seed);
    arrow(); put1("seed", seed); put1("r", r); end_line();
}

static void case_mean(void)
{
    Word16 x[MAXN];
    Word16 lvec = (Word16)random_range(1, 40);
    fill16(x, lvec);
    put16("vec", x, lvec); put1("lvec", lvec);
    Word16 m = mean_fx(x, lvec);
    arrow(); put1("mean", m); end_line();
}

static void case_vr_add(void)
{
    Word16 a[MAXN], b[MAXN], c[MAXN];
    Word16 n = (Word16)random_range(0, 80);
    fill16(a, n); fill16(b, n);
    put16("in1", a, n); put16("in2", b, n); put1("n", n);
    Vr_add(a, b, c, n);
    arrow(); put16("out", c, n); end_line();
}

static void case_vr_subt(void)
{
    Word16 a[MAXN], b[MAXN], c[MAXN];
    Word16 n = (Word16)random_range(0, 80);
    fill16(a, n); fill16(b, n);
    put16("x1", a, n); put16("x2", b, n); put1("n", n);
    Vr_subt(a, b, c, n);
    arrow(); put16("y", c, n); end_line();
}

static void case_sort(void)
{
    Word16 r[40];
    int n = random_range(1, 40);
    Word16 lo = (Word16)random_range(0, n - 1), up = (Word16)random_range(lo, n - 1);
    if (next_random() & 1) fill16(r, n); else for (int i = 0; i < n; i++) r[i] = (Word16)random_range(-5, 5);
    put16("r", r, n); put1("lo", lo); put1("up", up);
    sort_fx(r, lo, up);
    arrow(); put16("r", r, n); end_line();
}

static void case_minmax(void)
{
    Word16 x[MAXN];
    Word16 lvec = (Word16)random_range(1, 80), mn, mx;
    if (next_random() & 1) fill16(x, lvec); else for (int i = 0; i < lvec; i++) x[i] = (Word16)random_range(-3, 3);
    put16("vec", x, lvec); put1("lvec", lvec);
    Word16 imn = minimum_fx(x, lvec, &mn);
    Word16 imx = maximum_fx(x, lvec, &mx);
    arrow(); put1("imin", imn); put1("min", mn); put1("imax", imx); put1("max", mx); end_line();
}

static void case_emaximum(void)
{
    Word16 x[MAXN];
    Word16 lvec = (Word16)random_range(1, 80), q = (Word16)random_range(0, 15);
    Word32 e;
    if (next_random() & 1) fill16(x, lvec); else for (int i = 0; i < lvec; i++) x[i] = (Word16)random_range(-3, 3);
    put1("qvec", q); put16("vec", x, lvec); put1("lvec", lvec);
    Word16 ind = emaximum_fx(q, x, lvec, &e);
    arrow(); put1("ind", ind); put1("ener", e); end_line();
}

static void case_sums(void)
{
    Word16 x[MAXN];
    Word16 lvec = (Word16)random_range(0, 320);
    fill16(x, lvec);
    put16("vec", x, lvec); put1("lvec", lvec);
    Word32 s32 = sum16_32_fx(x, lvec);
    Word16 s16 = sum16_fx(x, lvec);
    arrow(); put1("sum32", s32); put1("sum16", s16); end_line();
}

static void case_add_vec(void)
{
    Word16 a[MAXN], b[MAXN], c[MAXN];
    Word16 n = (Word16)random_range(0, 80);
    Word16 qx1 = (Word16)random_range(-2, 15), qx2 = (Word16)random_range(-2, 15), qy = (Word16)random_range(-2, 15);
    if (next_random() & 1) qx1 = qy;
    fill16(a, n); fill16(b, n);
    put16("x1", a, n); put1("qx1", qx1); put16("x2", b, n); put1("qx2", qx2); put1("qy", qy); put1("n", n);
    add_vec_fx(a, qx1, b, qx2, c, qy, n);
    arrow(); put16("y", c, n); end_line();
}

static void case_calc_energy_autoscaled(void)
{
    Word16 x[MAXN];
    static const Word16 lens[] = {64, 80, 160, 256, 320, 7, 15, 0, 1, 100};
    Word16 len = (next_random() & 1) ? lens[next_random() % 10] : (Word16)random_range(0, 320);
    Word16 sexp = (Word16)random_range(-8, 15), eexp;
    fill16(x, len);
    /* Blocks of full-scale samples are what saturate the eight-sample accumulator. */
    if (next_random() & 1)
        for (int i = 0; i < len; i++) if (next_random() % 4) x[i] = (next_random() & 1) ? 32767 : -32768;
    put16("signal", x, len); put1("signal_exp", sexp); put1("len", len);
    Word32 e = Calc_Energy_Autoscaled(x, sexp, len, &eexp);
    arrow(); put1("energy", e); put1("energy_exp", eexp); end_line();
}

static void case_find_max_norm(void)
{
    Word16 x[MAXN]; Word32 y[MAXN];
    Word16 len = (Word16)random_range(0, 80);
    fill16(x, len); fill32(y, len);
    if (next_random() % 4 == 0) for (int i = 0; i < len; i++) { x[i] = 0; y[i] = 0; }
    put16("src16", x, len); put32("src32", y, len); put1("len", len);
    Word16 n16 = Find_Max_Norm16(x, len), n32 = Find_Max_Norm32(y, len);
    arrow(); put1("norm16", n16); put1("norm32", n32); end_line();
}

static void case_acelp_dec_total_exc(void)
{
    Word16 exc[L_FRAME], exc2[L_FRAME], code[L_SUBFR];
    Word16 i_subfr = (Word16)(L_SUBFR * random_range(0, 3));
    Word16 gain_pit = (next_random() & 3) ? (Word16)random_range(0, 19661) : random16();
    Word16 gain_code = (next_random() & 3) ? (Word16)random_range(0, 4000) : random16();
    fill16(exc, L_FRAME); fill16(exc2, L_FRAME);
    for (int i = 0; i < L_SUBFR; i++) code[i] = (next_random() & 3) ? 0 : (Word16)random_range(-4096, 4096);
    put16("exc", exc, L_FRAME); put16("exc2", exc2, L_FRAME); put1("gain_code", gain_code);
    put1("gain_pit", gain_pit); put1("i_subfr", i_subfr); put16("code", code, L_SUBFR);
    Acelp_dec_total_exc(exc, exc2, gain_code, gain_pit, i_subfr, code);
    arrow(); put16("exc", exc, L_FRAME); put16("exc2", exc2, L_FRAME); end_line();
}

static void case_ul(void)
{
    UWord32 val = (UWord32)random32(), num = (UWord32)random32(), den = (UWord32)random32();
    Word16 exp = 0;
    if (next_random() & 1) val >>= random_range(0, 31);
    if (next_random() & 1) den |= 0x80000000u; /* the normalised Q32 denominator UL_inverse passes */
    if (next_random() & 1) num &= 0x7fffffffu;
    printf(" val=%u num=%u den=%u", val, num, den);
    UWord32 inv = UL_inverse(val, &exp);
    UWord32 q = UL_div(num, den);
    printf(" -> inverse=%u exp=%d div=%u\n", inv, exp, q);
}

static void case_hp400_12k8(void)
{
    Word16 x[L_FRAME], mem[6];
    Word16 lg = (next_random() & 3) ? L_FRAME : (Word16)random_range(2, L_FRAME);
    fill16(x, lg);
    if (next_random() & 1) for (int i = 0; i < lg; i++) x[i] = (Word16)(x[i] >> 3);
    for (int i = 0; i < 6; i++) mem[i] = maybe_edge16(8000);
    put16("signal", x, lg); put1("lg", lg); put16("mem", mem, 6);
    hp400_12k8_fx(x, lg, mem);
    arrow(); put16("signal", x, lg); put16("mem", mem, 6); end_line();
}

/* Div_32_optmz is static and reached only through iDiv_and_mod_32, so it is proven here. */
static void case_idiv_and_mod_32(void)
{
    static const Word16 denoms[] = {5472, 2, 172, 345, 140, 190, 223, 463, 1732};
    Word32 numer = (next_random() & 1) ? random_range(0, 0x3fffffff) : random_range(0, 3611648 / 4);
    Word16 denom = (next_random() % 4) ? denoms[next_random() % 9] : (Word16)random_range(1, 32767);
    Word16 rshift = (Word16)((next_random() % 4) == 0);
    Word32 q, m;
    if (rshift && denom > 16383) denom = (Word16)(denom >> 1);
    put1("numer", numer); put1("denom", denom); put1("rshift", rshift);
    iDiv_and_mod_32(numer, denom, &q, &m, rshift);
    arrow(); put1("q", q); put1("m", m); end_line();
}

/* Sqrt_Ratio32 on the energies the FEC scaling feeds it: positive, from tiny to saturated. */
static void case_sqrt_ratio32(void)
{
    /* every caller clamps both energies to >= 1 first; div_s aborts on anything else */
    Word32 v1 = (next_random() % 8) ? (Word32)(next_random() >> random_range(0, 30)) : 0x7fffffff;
    Word32 v2 = (next_random() % 8) ? (Word32)(next_random() >> random_range(0, 30)) : 0x7fffffff;
    if (v1 <= 0) v1 = 1;
    if (v2 <= 0) v2 = 1;
    Word16 e1 = (Word16)random_range(-8, 8), e2 = (Word16)random_range(-8, 8), e;
    put1("v1", v1); put1("e1", e1); put1("v2", v2); put1("e2", e2);
    Word32 r = Sqrt_Ratio32(v1, e1, v2, e2, &e);
    arrow(); put1("r", r); put1("exp", e); end_line();
}

static void case_ratio(void)
{
    Word32 numer = (Word32)(next_random() >> random_range(1, 31)), denom = (Word32)(next_random() >> random_range(1, 31));
    if (numer == 0) numer = 1;
    if (denom == 0) denom = 1;
    if (next_random() % 3 == 0) numer = random_range(1, 200);
    Word16 e;
    put1("numer", numer); put1("denom", denom);
    Word16 q = ratio(numer, denom, &e);
    arrow(); put1("q", q); put1("e", e); end_line();
}

/* find_rem over positive and non-positive operands, both orders of magnitude. */
static void case_find_rem(void)
{
    Word16 n = (next_random() % 8) ? (Word16)random_range(-10, 32767) : random16();
    Word16 m = (next_random() % 8) ? (Word16)random_range(-10, 1 + (int)(next_random() % 32767)) : random16();
    if (next_random() % 4 == 0) m = (Word16)random_range(1, 300);
    Word16 r = 0;
    put1("n", n); put1("m", m);
    Word16 q = find_rem(n, m, &r);
    arrow(); put1("q", q); put1("r", r); end_line();
}

/* rint_new_fx on Q16 values, with exact halves (the ties-to-even branch) a quarter of the time. */
static void case_rint_new(void)
{
    Word32 x = random32();
    if (next_random() % 4 == 0) x = (Word32)(((Word32)random16() << 16) | 0x8000);
    put1("x", x);
    Word16 a = rint_new_fx(x);
    arrow(); put1("a", a); end_line();
}

static void case_exp16_array(void)
{
    Word16 x[MAXN];
    int n = random_range(1, 64);
    fill16(x, n);
    if (next_random() % 8 == 0) for (int i = 0; i < n; i++) x[i] = 0;
    put16("x", x, n);
    Word16 e = Exp16Array((Word16)n, x);
    arrow(); put1("e", e); end_line();
}

/* fir_fx as the decoder runs it: the core-switching high-pass filters (K up to 60, shift 0, on up
 * to half a 48 kHz frame) and the TBE whitening filter (K 4, shift 3), plus random taps. */
static void case_fir(void)
{
    static const Word16 *filters[] = {hp16000_48000_fx, hp12800_16000_fx, hp12800_32000_fx, hp16000_32000_fx, hp12800_48000_fx};
    static const Word16 orders[] = {48, 20, 40, 32, 60};
    Word16 x[L_FRAME32k], y[L_FRAME32k], mem[2 * L_FILT_MAX], h[61];
    int kind = next_random() % 3;
    Word16 k, l, shift, upd = (Word16)(next_random() & 1);
    if (kind == 0) {
        int f = next_random() % 5;
        k = orders[f]; for (int i = 0; i <= k; i++) h[i] = filters[f][i];
        l = (Word16)((next_random() & 1) ? (80 << (next_random() % 3)) : random_range(1, 480)); if (l > 480) l = 480;
        shift = 0;
    } else if (kind == 1) {
        k = 4; for (int i = 0; i <= k; i++) h[i] = maybe_edge16(4096);
        l = (Word16)((next_random() & 1) ? 80 : 320); shift = 3;
    } else {
        k = (Word16)random_range(0, 60); for (int i = 0; i <= k; i++) h[i] = random16();
        /* fir_fx buffers l + k samples in L_FRAME32k + L_FILT_MAX */
        l = (Word16)random_range(1, L_FRAME32k + L_FILT_MAX - k); if (l > L_FRAME32k) l = L_FRAME32k;
        shift = (Word16)random_range(-2, 4);
    }
    fill16(x, l);
    for (int i = 0; i < k; i++) mem[i] = maybe_edge16(16000);
    put16("x", x, l); put16("h", h, k + 1); put16("mem", mem, k);
    put1("l", l); put1("k", k); put1("upd", upd); put1("shift", shift);
    fir_fx(x, h, y, mem, l, k, upd, shift);
    arrow(); put16("y", y, l); put16("mem", mem, k); end_line();
}

/* floating_point_add: normalised mantissas (as peak_vq_dec_fx accumulates them) or the zero / exponent 32 start, plus
 * arbitrary pairs */
static void case_floating_point_add(void)
{
    Word32 mx, my; Word16 ex, ey;
    int kind = next_random() % 4;
    if (kind == 0) { mx = 0; ex = 32; }
    else { mx = (Word32)(0x40000000u | (next_random() & 0x3fffffff)); ex = (Word16)random_range(-10, 60); }
    my = (Word32)(0x40000000u | (next_random() & 0x3fffffff)); ey = (Word16)random_range(-10, 60);
    if (kind == 3) { mx = random32(); my = random32(); ex = (Word16)random_range(-40, 40); ey = (Word16)random_range(-40, 40); }
    put1("mx", mx); put1("ex", ex); put1("my", my); put1("ey", ey);
    floating_point_add(&mx, &ex, my, ey);
    arrow(); put1("mx", mx); put1("ex", ex); end_line();
}

/* pz_filter_sp_fx / pz_filter_dp_fx as the NELP decoder runs them (the band-pass and shaping
 * filters on 256 samples), plus random stable-ish taps and edge inputs. */
#include "rom_com_fx.h"
static void pz_filter_taps(Word16 *b, Word16 *a, Word16 *order, Word16 *qa, int dp)
{
    int kind = next_random() % 6;
    if (dp && kind < 3) {
        *order = 7; *qa = 16 - BP1_COEF_NB_QF_ORDER7;
        for (int i = 0; i <= 7; i++) { b[i] = bp1_num_coef_nb_fx_order7[i]; a[i] = bp1_den_coef_nb_fx_order7[i]; }
    } else if (!dp && kind == 0) {
        *order = 4; *qa = 16 - BP1_COEF_WB_QF;
        for (int i = 0; i <= 4; i++) { b[i] = bp1_num_coef_wb_fx[i]; a[i] = bp1_den_coef_wb_fx[i]; }
    } else if (!dp && kind < 4) {
        const Word16 *nums[] = {shape1_num_coef_fx, shape2_num_coef_fx, shape3_num_coef_fx};
        const Word16 *dens[] = {shape1_den_coef_fx, shape2_den_coef_fx, shape3_den_coef_fx};
        int f = kind - 1;
        *order = 10; *qa = 16 - SHAPE1_COEF_QF;
        for (int i = 0; i <= 10; i++) { b[i] = nums[f][i]; a[i] = dens[f][i]; }
    } else {
        *order = (Word16)random_range(1, 10); *qa = (Word16)random_range(0, 3);
        for (int i = 0; i <= *order; i++) { b[i] = maybe_edge16(8000); a[i] = (Word16)random_range(-3000, 3000); }
    }
}

static void case_pz_filter_sp(void)
{
    Word16 b[11], a[11], order, qa, x[256], y[256], buf[10];
    pz_filter_taps(b, a, &order, &qa, 0);
    Word16 pnr = order, pdr = order, n = (Word16)(next_random() & 1 ? 256 : random_range(1, 256));
    if (next_random() % 8 == 0) pnr = (Word16)random_range(0, order);
    if (next_random() % 8 == 0) pdr = (Word16)random_range(0, order);
    fill16(x, n);
    if (next_random() & 1) for (int i = 0; i < n; i++) x[i] = (Word16)(x[i] >> random_range(0, 6));
    for (int i = 0; i < 10; i++) buf[i] = maybe_edge16(4000);
    put16("b", b, order + 1); put16("a", a, order + 1); put16("x", x, n); put16("buf", buf, 10);
    put1("pnr", pnr); put1("pdr", pdr); put1("n", n); put1("qa", qa);
    pz_filter_sp_fx(b, a, x, y, buf, pnr, pdr, n, qa);
    arrow(); put16("y", y, n); put16("buf", buf, 10); end_line();
}

static void case_pz_filter_dp(void)
{
    Word16 b[11], a[11], order, qa, x[256], y[256];
    Word32 buf[14];
    pz_filter_taps(b, a, &order, &qa, 1);
    Word16 pnr = order, pdr = order, n = (Word16)(next_random() & 1 ? 256 : random_range(1, 256));
    if (next_random() % 8 == 0) pnr = (Word16)random_range(0, order);
    if (next_random() % 8 == 0) pdr = (Word16)random_range(0, order);
    fill16(x, n);
    if (next_random() & 1) for (int i = 0; i < n; i++) x[i] = (Word16)(x[i] >> random_range(0, 8));
    for (int i = 0; i < 14; i++) buf[i] = (next_random() & 1) ? (Word32)maybe_edge16(4000) << random_range(0, 16) : 0;
    put16("b", b, order + 1); put16("a", a, order + 1); put16("x", x, n); put32("buf", buf, 14);
    put1("pnr", pnr); put1("pdr", pdr); put1("n", n); put1("qa", qa);
    pz_filter_dp_fx(b, a, x, y, buf, pnr, pdr, n, qa);
    arrow(); put16("y", y, n); put32("buf", buf, 14); end_line();
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*fn)(void); } table[] = {
        {"usdequant", case_usdequant}, {"dot_product", case_dot_product}, {"sum2", case_sum2},
        {"copy_scale_sig", case_copy_scale_sig}, {"copy_scale_sig_32_16", case_copy_scale_sig_32_16},
        {"copy_scale_sig_16_32", case_copy_scale_sig_16_32}, {"own_random2", case_own_random2},
        {"copy_scale_sig32_16", case_copy_scale_sig32_16}, {"scale_sig32", case_scale_sig32},
        {"scale_sig", case_scale_sig}, {"random_fill", case_random_fill}, {"random", case_random},
        {"mean", case_mean}, {"vr_add", case_vr_add}, {"vr_subt", case_vr_subt}, {"sort", case_sort},
        {"minmax", case_minmax}, {"emaximum", case_emaximum}, {"sums", case_sums},
        {"add_vec", case_add_vec}, {"calc_energy_autoscaled", case_calc_energy_autoscaled},
        {"find_max_norm", case_find_max_norm}, {"acelp_dec_total_exc", case_acelp_dec_total_exc},
        {"ul", case_ul}, {"hp400_12k8", case_hp400_12k8},
        {"idiv_and_mod_32", case_idiv_and_mod_32}, {"sqrt_ratio32", case_sqrt_ratio32},
        {"ratio", case_ratio},
        {"find_rem", case_find_rem}, {"rint_new", case_rint_new}, {"exp16_array", case_exp16_array},
        {"fir", case_fir}, {"floating_point_add", case_floating_point_add},
        {"pz_filter_sp", case_pz_filter_sp}, {"pz_filter_dp", case_pz_filter_dp},
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
