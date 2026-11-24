/* Function-level oracle for the leaf functions the TBE decoder calls: lib_com/tools_fx.c (root_a*,
 * *_flt32_*), residu_fx.c (Residu3_10_fx), modif_fs_fx.c (Decimate_allpass_steep_fx,
 * interpolate_3_over_2_allpass_fx) and lsf_tools_fx.c (lsp2lpc_fx, a2rc_fx, space_lsfs_fx,
 * poscos_fx, compute_poly_product_fx, lsp_convolve_fx). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static Word32 positive32(void)
{
    Word32 value = random32();
    if (value == (Word32)0x80000000) return 0x7fffffff;
    return value < 0 ? -value : value;
}

static void case_root_a(void)
{
    Word32 a = next_random() % 6 == 0 ? random32() : positive32();
    Word16 q_a = (Word16)random_range(0, 31), exp_out = 77;
    put32("a", &a, 1); put1("q_a", q_a);
    Word32 r = root_a_fx(a, q_a, &exp_out);
    arrow(); put32("r", &r, 1); put1("exp", exp_out); end_line();
}

static void case_root_a_over_b(void)
{
    Word32 a = next_random() % 8 == 0 ? random32() : positive32();
    Word32 b = next_random() % 8 == 0 ? random32() : positive32();
    Word16 q_a = (Word16)random_range(0, 40), q_b = (Word16)random_range(0, 40), exp_out = 77;
    put32("a", &a, 1); put1("q_a", q_a); put32("b", &b, 1); put1("q_b", q_b);
    Word32 r = root_a_over_b_fx(a, q_a, b, q_b, &exp_out);
    arrow(); put32("r", &r, 1); put1("exp", exp_out); end_line();
}

static void case_add_flt32(void)
{
    Word32 a = random32(), b = random32();
    Word16 exp_a = (Word16)random_range(0, 31), exp_b = (Word16)random_range(0, 31), exp_out = 77;
    put32("a", &a, 1); put1("exp_a", exp_a); put32("b", &b, 1); put1("exp_b", exp_b);
    Word32 r = Add_flt32_flt32(a, exp_a, b, exp_b, &exp_out);
    arrow(); put32("r", &r, 1); put1("exp", exp_out); end_line();
}

static void case_mul_flt32_q15(void)
{
    Word32 value = random32();
    Word16 exp_v = (Word16)random_range(-10, 40), frac = random16();
    put32("value", &value, 1); put1("exp_v", exp_v); put1("frac", frac);
    Word32 r = Mul_flt32_Q15(value, &exp_v, frac);
    arrow(); put32("r", &r, 1); put1("exp", exp_v); end_line();
}

static void case_div_flt32(void)
{
    Word32 a = random32();
    Word32 b = (Word32)0x40000000 + (Word32)(next_random() & 0x3fffffff);
    Word16 exp_a = (Word16)random_range(0, 31), exp_b = (Word16)random_range(0, 31), exp_out = 77;
    put32("a", &a, 1); put1("exp_a", exp_a); put32("b", &b, 1); put1("exp_b", exp_b);
    Word32 r = Div_flt32_flt32(a, exp_a, b, exp_b, &exp_out);
    arrow(); put32("r", &r, 1); put1("exp", exp_out); end_line();
}

static void case_residu3_10(void)
{
    Word16 a[11], x[10 + 80], y[80];
    Word16 lg = (Word16)random_range(1, 80), shift = (Word16)(next_random() & 1);
    a[0] = (Word16)random_range(2048, 8192);
    for (int i = 1; i <= 10; i++) a[i] = (next_random() & 3) ? (Word16)random_range(-6000, 6000) : random16();
    random_signal(x, 10 + lg, next_random() & 1 ? 20000 : 3000);
    memset(y, 0, sizeof(y));
    put16("a", a, 11); put16("x", x, 10 + lg); put1("lg", lg); put1("shift", shift);
    Residu3_10_fx(a, x + 10, y, lg, shift);
    arrow(); put16("y", y, lg); end_line();
}

static void case_decimate(void)
{
    Word16 in[640], state[7], out[320];
    Word16 n = (Word16)(next_random() & 1 ? 320 : 160);
    if (next_random() % 5 == 0) n = 640;
    int magnitude = next_random() & 1 ? 32000 : 6000;
    random_signal(in, n, magnitude);
    if (next_random() % 4 == 0) for (int i = 0; i < n; i += 7) in[i] = random16();
    random_signal(state, 7, magnitude);
    memset(out, 0, sizeof(out));
    put16("in", in, n); put16("state", state, 7); put1("n", n);
    Decimate_allpass_steep_fx(in, state, n, out);
    arrow(); put16("out", out, n / 2); put16("state_out", state, 7); end_line();
}

static void case_interpolate_3_over_2(void)
{
    Word16 in[640], mem[15], out[960];
    Word16 len = (Word16)(next_random() & 1 ? 640 : 320);
    if (next_random() % 5 == 0) len = (Word16)(2 * random_range(1, 100));
    int magnitude = next_random() & 1 ? 32000 : 5000;
    random_signal(in, len, magnitude);
    random_signal(mem, 15, magnitude);
    memset(out, 0, sizeof(out));
    put16("in", in, len); put16("mem", mem, 15); put1("len", len);
    interpolate_3_over_2_allpass_fx(in, len, out, mem, allpass_poles_3_ov_2);
    arrow(); put16("out", out, (len * 3) / 2); put16("mem_out", mem, 15); end_line();
}

static void case_lsp2lpc(void)
{
    Word16 freq[11], prev_a[10], a[10];
    Word16 order = (Word16)(next_random() & 1 ? 4 : 6);
    if (next_random() % 8 == 0) order = 10;
    int unsorted = next_random() % 6 == 0;
    /* descending cosines in Q15, as the LSP set of a stable filter; the occasional unsorted or
     * extreme set drives the overflow fallbacks */
    int value = 32000;
    for (int i = 0; i <= order; i++) {
        value -= random_range(200, 64000 / (order + 1));
        freq[i] = unsorted ? random16() : (Word16)(value < -32768 ? -32768 : value);
    }
    for (int i = 0; i < order; i++) prev_a[i] = (next_random() & 3) ? (Word16)random_range(-8000, 8000) : random16();
    for (int i = 0; i < 10; i++) a[i] = 0x5a5a;
    put16("freq", freq, order + 1); put16("prev_a", prev_a, order); put1("order", order);
    lsp2lpc_fx(a, freq, prev_a, order);
    arrow(); put16("a", a, order); end_line();
}

static void case_a2rc(void)
{
    Word16 buffer[17], refl[16];
    Word16 lpcorder = (Word16)(next_random() & 1 ? 16 : 10);
    static const Word16 leading[] = {4096, 2048, 8192, 16384, 1024, 32767};
    buffer[0] = leading[next_random() % 6];
    Word16 q = add(norm_s(buffer[0]), 1), one = shl(1, sub(15, q));
    for (int i = 1; i <= lpcorder; i++) {
        buffer[i] = (Word16)random_range(-one / 2, one / 2);
        if (next_random() % 12 == 0) buffer[i] = (Word16)random_range(-one - 2, one + 2);
    }
    for (int i = 0; i < 16; i++) refl[i] = 0x5a5a;
    put16("buffer", buffer, lpcorder + 1); put1("lpcorder", lpcorder);
    a2rc_fx(buffer + 1, refl, lpcorder);
    arrow(); put16("refl", refl, lpcorder); end_line();
}

static void case_space_lsfs(void)
{
    Word16 lsfs[10];
    int value = 0;
    for (int i = 0; i < 10; i++) {
        value += random_range(0, next_random() % 3 ? 1500 : 4000);
        lsfs[i] = (Word16)(value > 16383 ? 16383 : value);
    }
    put16("lsfs", lsfs, 10);
    space_lsfs_fx(lsfs, 10);
    arrow(); put16("lsfs_out", lsfs, 10); end_line();
}

static void case_poscos(void)
{
    Word16 w = next_random() % 10 == 0 ? random16() : (Word16)random_range(-32768, 32767);
    put1("w", w);
    Word32 r = poscos_fx(w);
    arrow(); put32("r", &r, 1); end_line();
}

static void case_compute_poly_product(void)
{
    Word16 coef[11];
    Word32 p[10];
    Word16 order = (Word16)(next_random() & 1 ? 4 : 6);
    if (next_random() % 6 == 0) order = 10;
    for (int i = 0; i <= order; i++) coef[i] = random16();
    for (int i = 0; i < 10; i++) p[i] = 0x5a5a5a5a;
    put16("coef", coef, order + 1); put1("order", order);
    compute_poly_product_fx(coef, p, order);
    arrow(); put32("p", p, order / 2 + 1); end_line();
}

static void case_usquant(void)
{
    Word16 x = next_random() % 4 ? (Word16)random_range(3277, 32440) : random16(), xq = 0;
    put1("x", x);
    Word16 idx = usquant_fx(x, &xq, 4096, 2048, shl(1, 3));
    arrow(); put1("idx", idx); put1("xq", xq); end_line();
}

static void case_sum2_mod(void)
{
    Word16 v[320];
    Word16 n = (Word16)random_range(1, 320);
    if (next_random() & 1) random_signal(v, n, 30000); else for (int i = 0; i < n; i++) v[i] = random16();
    put16("v", v, n);
    Word32 r = sum2_fx_mod(v, n);
    arrow(); put32("r", &r, 1); end_line();
}

static void case_syn_filt6(void)
{
    Word16 a[7], x[80], y[80], mem[6];
    Word16 order = (Word16)(next_random() & 1 ? 6 : 10), lg = (Word16)(next_random() & 1 ? 80 : 20);
    int magnitude = next_random() & 1 ? 32000 : 3000;
    a[0] = 4096;
    Word16 a10[11];
    a10[0] = 4096;
    for (int i = 1; i <= 10; i++) a10[i] = (next_random() & 1) ? (Word16)random_range(-9000, 9000) : random16();
    random_signal(x, 80, magnitude); random_signal(mem, 6, magnitude);
    Word16 mem10[10]; random_signal(mem10, 10, magnitude);
    memset(y, 0, sizeof y);
    if (order == 6) {
        put16("a", a10, 7); put16("x", x, lg); put16("mem", mem, 6); put1("m", 6); put1("lg", lg);
        Syn_filt_s(0, a10, 6, x, y, lg, mem, 1);
        arrow(); put16("y", y, lg); put16("mem_out", mem, 6);
    } else {
        put16("a", a10, 11); put16("x", x, lg); put16("mem", mem10, 10); put1("m", 10); put1("lg", lg);
        Syn_filt_s(0, a10, 10, x, y, lg, mem10, 1);
        arrow(); put16("y", y, lg); put16("mem_out", mem10, 10);
    }
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        const char *f = argv[2];
        if (!strcmp(f, "root_a")) case_root_a();
        else if (!strcmp(f, "root_a_over_b")) case_root_a_over_b();
        else if (!strcmp(f, "add_flt32")) case_add_flt32();
        else if (!strcmp(f, "mul_flt32_q15")) case_mul_flt32_q15();
        else if (!strcmp(f, "div_flt32")) case_div_flt32();
        else if (!strcmp(f, "residu3_10")) case_residu3_10();
        else if (!strcmp(f, "decimate")) case_decimate();
        else if (!strcmp(f, "interpolate_3_over_2")) case_interpolate_3_over_2();
        else if (!strcmp(f, "lsp2lpc")) case_lsp2lpc();
        else if (!strcmp(f, "a2rc")) case_a2rc();
        else if (!strcmp(f, "space_lsfs")) case_space_lsfs();
        else if (!strcmp(f, "poscos")) case_poscos();
        else if (!strcmp(f, "syn_filt")) case_syn_filt6();
        else if (!strcmp(f, "usquant")) case_usquant();
        else if (!strcmp(f, "sum2_mod")) case_sum2_mod();
        else if (!strcmp(f, "compute_poly_product")) case_compute_poly_product();
        else { fprintf(stderr, "unknown function %s\n", f); return 2; }
    }
    return 0;
}
