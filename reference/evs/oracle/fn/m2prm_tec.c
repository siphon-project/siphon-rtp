/* Function-level oracle for lib_com/tec_com.c (decoder side): calcLoBufferDec_Fx, calcLoTempEnv_TBE_Fx,
 * calcLoTempEnv_ns_TBE_Fx, calcGainLinear_TBE_Fx, calcGainTemp_TBE_Fx, setSubfrConfig_Fix, calcSum_Fx,
 * calcSubfrNrg_Fx, procTec_Fx, procTfa_Fx and procTecTfa_TBE_Fx. The file is included so its static
 * functions are called directly.
 *
 * Domain (evs_dec_fx.c): CLDFB banks of 16, 32 and 60 channels (lowSubband = no_channels, so the band offset
 * is 10, 26 or 54), 10 or 16 columns, startPos 0 (a nonzero one too), code (tec_flag) 0..2, l_subfr =
 * output_frame >> 4 (20, 40, 60), a synthesis exponent 0..15, gains with a positive mantissa (a zero one
 * exercises the early return). */
#include "harness.h"
#include "prot_fx.h"
#include "cnst_fx.h"
#include "rom_com_fx.h"
#include "basop_util.h"
#include "../../c-code/lib_com/tec_com.c"

#define ROW 60

static Word32 real_rows[16][ROW], imag_rows[16][ROW];

static void random_rows(int rows, int zero_rows)
{
    int magnitude_shift = random_range(0, 26);
    for (int slot = 0; slot < 16; slot++) {
        for (int k = 0; k < ROW; k++) {
            real_rows[slot][k] = 0;
            imag_rows[slot][k] = 0;
        }
    }
    for (int slot = 0; slot < rows; slot++) {
        if (zero_rows && next_random() % 3 == 0) continue;
        for (int k = 0; k < ROW; k++) {
            if (next_random() % 5 == 0) continue;
            real_rows[slot][k] = random32() >> random_range(magnitude_shift, magnitude_shift + 5);
            imag_rows[slot][k] = random32() >> random_range(magnitude_shift, magnitude_shift + 5);
        }
    }
}

static void put_rows(int rows)
{
    Word32 flat[16 * ROW];
    for (int slot = 0; slot < rows; slot++) for (int k = 0; k < ROW; k++) flat[slot * ROW + k] = real_rows[slot][k];
    put32("real", flat, rows * ROW);
    for (int slot = 0; slot < rows; slot++) for (int k = 0; k < ROW; k++) flat[slot * ROW + k] = imag_rows[slot][k];
    put32("imag", flat, rows * ROW);
}

static int pick_columns(void) { return next_random() & 1 ? 16 : 10 + 6 * (int)(next_random() & 1); }

static void case_lo_buffer(void)
{
    static const int subbands[] = {16, 32, 60};
    Word16 lo_buffer[22];
    Word32 *real[16], *imag[16];
    int columns = pick_columns();
    int start = next_random() % 4 == 0 ? random_range(0, columns - 1) : 0;
    int low_subband = subbands[next_random() % 3];
    Word16 offset = (Word16)(low_subband - 6);
    Word16 scale = (Word16)random_range(-6, 14);
    random_rows(columns, 1);
    for (int i = 0; i < 16; i++) { real[i] = real_rows[i]; imag[i] = imag_rows[i]; }
    for (int i = 0; i < 22; i++) lo_buffer[i] = random16();
    put1("columns", columns); put1("start", start); put1("offset", offset); put1("scale", scale);
    put_rows(columns); put16("lo_buffer", lo_buffer, 22);
    calcLoBufferDec_Fx(real, imag, lo_buffer + MAX_TEC_SMOOTHING_DEG, start, columns, offset, scale);
    arrow(); put16("lo_buffer", lo_buffer, 22); end_line();
}

static void case_lo_temp_env(int no_smoothing)
{
    Word16 lo_buffer[22], env[16];
    Word16 columns = (Word16)random_range(1, 16);
    Word16 adj = (Word16)(next_random() % 4 ? 19531 : random16());
    for (int i = 0; i < 22; i++) lo_buffer[i] = next_random() % 4 ? (Word16)random_range(-30720, 8000) : random16();
    for (int i = 0; i < 16; i++) env[i] = 0x5a5a;
    put1("columns", columns); put1("adj", adj); put16("lo_buffer", lo_buffer, 22);
    if (no_smoothing) calcLoTempEnv_ns_TBE_Fx(lo_buffer + MAX_TEC_SMOOTHING_DEG, columns, env);
    else calcLoTempEnv_TBE_Fx(lo_buffer + MAX_TEC_SMOOTHING_DEG, columns, env, adj);
    arrow(); put16("env", env, columns); end_line();
}

static void case_gain_linear(void)
{
    Word16 env[16], gain_m[16], gain_e[16];
    int start = next_random() % 4 == 0 ? random_range(0, 8) : 0;
    int stop = random_range(start + 1, 16);
    for (int i = 0; i < 16; i++) {
        env[i] = next_random() % 3 ? (Word16)random_range(-12000, 12000) : random16();
        gain_m[i] = 0x5a5a;
        gain_e[i] = 0x5a5a;
    }
    put1("start", start); put1("stop", stop); put16("env", env, 16);
    calcGainLinear_TBE_Fx(env, start, stop, gain_m, gain_e);
    arrow(); put16("gain_m", gain_m, 16); put16("gain_e", gain_e, 16); end_line();
}

static void case_gain_temp(void)
{
    static const int subbands[] = {16, 32, 60};
    Word16 lo_buffer[22], gain_m[16], gain_e[16];
    Word32 *real[16], *imag[16];
    int columns = pick_columns();
    int low_subband = subbands[next_random() % 3];
    Word16 cldfb_exp = (Word16)(15 + random_range(-6, 10));
    Word16 code = (Word16)random_range(0, 2);
    random_rows(columns, 1);
    for (int i = 0; i < 16; i++) { real[i] = real_rows[i]; imag[i] = imag_rows[i]; gain_m[i] = 0x5a5a; gain_e[i] = 0x5a5a; }
    for (int i = 0; i < 22; i++) lo_buffer[i] = next_random() % 4 ? (Word16)random_range(-30720, 8000) : random16();
    put1("columns", columns); put1("low_subband", low_subband); put1("cldfb_exp", cldfb_exp); put1("code", code);
    put_rows(columns); put16("lo_buffer", lo_buffer, 22);
    calcGainTemp_TBE_Fx(real, imag, cldfb_exp, lo_buffer, 0, columns, low_subband, gain_m, gain_e, code);
    arrow(); put16("lo_buffer", lo_buffer, 22); put16("gain_m", gain_m, 16); put16("gain_e", gain_e, 16); end_line();
}

static Word16 random_l_subfr(void) { static const Word16 sizes[] = {20, 40, 60}; return sizes[next_random() % 3]; }

static void random_synth(Word16 *synth, int n)
{
    int kind = random_range(0, 3);
    int magnitude = kind == 0 ? 32767 : random_range(1, 3000);
    random_signal(synth, n, magnitude);
    if (kind == 3) for (int i = 0; i < n; i++) synth[i] = random16();
    /* silent subframes */
    for (int block = 0; block < 16; block++) if (next_random() % 8 == 0) for (int i = 0; i < n / 16; i++) synth[block * (n / 16) + i] = 0;
}

static void random_gains(Word16 *m, Word16 *e)
{
    for (int i = 0; i < 16; i++) {
        m[i] = (Word16)random_range(16384, 32767);
        e[i] = (Word16)random_range(-8, 8);
        if (next_random() % 40 == 0) m[i] = 0;
    }
}

static void case_set_subfr(void)
{
    Word16 offset = (Word16)random_range(0, 1), l_subfr = random_l_subfr(), k_offset, n_subfr;
    put1("offset", offset); put1("l_subfr", l_subfr);
    setSubfrConfig_Fix(offset, &k_offset, &n_subfr, l_subfr);
    arrow(); put1("k_offset", k_offset); put1("n_subfr", n_subfr); end_line();
}

static void case_sum(void)
{
    Word16 m[16], e[16], sum_m = 0x5a5a;
    Word16 len = (Word16)random_range(1, 16);
    random_gains(m, e);
    for (int i = 0; i < 16; i++) if (m[i] == 0) m[i] = (Word16)random_range(1, 32767);
    put1("len", len); put16("m", m, 16); put16("e", e, 16);
    Word16 sum_e = calcSum_Fx(m, e, len, &sum_m);
    arrow(); put1("sum_m", sum_m); put1("sum_e", sum_e); end_line();
}

static void case_subfr_nrg(void)
{
    static Word16 synth[960];
    Word16 enr_m[16], enr_e[16], sum_m = 0x5a5a;
    Word16 l_subfr = random_l_subfr(), offset = (Word16)random_range(0, 1), exp_syn = (Word16)random_range(0, 15);
    Word16 k_offset = (Word16)(offset * l_subfr);
    random_synth(synth, 16 * l_subfr);
    for (int i = 0; i < 16; i++) { enr_m[i] = 0x5a5a; enr_e[i] = 0x5a5a; }
    put1("l_subfr", l_subfr); put1("offset", offset); put1("exp_syn", exp_syn); put16("synth", synth, 16 * l_subfr);
    Word16 sum_e = calcSubfrNrg_Fx(synth, exp_syn, offset, enr_m, enr_e, k_offset, &sum_m, l_subfr);
    arrow(); put16("enr_m", enr_m, 16); put16("enr_e", enr_e, 16); put1("sum_m", sum_m); put1("sum_e", sum_e); end_line();
}

static void case_proc_tec(void)
{
    static Word16 synth[960];
    Word16 gain_m[16], gain_e[16];
    Word16 l_subfr = random_l_subfr(), offset = (Word16)random_range(0, 1), exp_syn = (Word16)random_range(0, 15);
    Word16 code = (Word16)random_range(0, 2);
    random_synth(synth, 16 * l_subfr);
    random_gains(gain_m, gain_e);
    put1("l_subfr", l_subfr); put1("offset", offset); put1("exp_syn", exp_syn); put1("code", code);
    put16("synth", synth, 16 * l_subfr); put16("gain_m", gain_m, 16); put16("gain_e", gain_e, 16);
    Word16 r = procTec_Fx(synth, exp_syn, gain_m, gain_e, offset, l_subfr, code);
    arrow(); put1("r", r); put16("synth", synth, 16 * l_subfr); put16("gain_m", gain_m, 16); put16("gain_e", gain_e, 16); end_line();
}

static void case_proc_tfa(void)
{
    static Word16 synth[960];
    Word16 l_subfr = random_l_subfr(), offset = (Word16)random_range(0, 1), exp_syn = (Word16)random_range(0, 15);
    random_synth(synth, 16 * l_subfr);
    put1("l_subfr", l_subfr); put1("offset", offset); put1("exp_syn", exp_syn); put16("synth", synth, 16 * l_subfr);
    Word16 r = procTfa_Fx(synth, exp_syn, offset, l_subfr);
    arrow(); put1("r", r); put16("synth", synth, 16 * l_subfr); end_line();
}

static void case_proc_tec_tfa(void)
{
    static Word16 synth[960];
    Word16 gain_m[16], gain_e[16];
    Word16 l_subfr = random_l_subfr(), exp = (Word16)random_range(0, 15);
    Word16 flat = (Word16)(next_random() % 3 == 0), last_core = (Word16)random_range(0, 1), code = (Word16)random_range(0, 1);
    random_synth(synth, 16 * l_subfr);
    random_gains(gain_m, gain_e);
    put1("l_subfr", l_subfr); put1("exp", exp); put1("flat", flat); put1("last_core", last_core); put1("code", code);
    put16("synth", synth, 16 * l_subfr); put16("gain_m", gain_m, 16); put16("gain_e", gain_e, 16);
    Word16 r = procTecTfa_TBE_Fx(synth, exp, gain_m, gain_e, flat, last_core, l_subfr, code);
    arrow(); put1("r", r); put16("synth", synth, 16 * l_subfr); put16("gain_m", gain_m, 16); put16("gain_e", gain_e, 16); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "calc_lo_buffer_dec")) case_lo_buffer();
        else if (!strcmp(argv[2], "calc_lo_temp_env_tbe")) case_lo_temp_env(0);
        else if (!strcmp(argv[2], "calc_lo_temp_env_ns_tbe")) case_lo_temp_env(1);
        else if (!strcmp(argv[2], "calc_gain_linear_tbe")) case_gain_linear();
        else if (!strcmp(argv[2], "calc_gain_temp_tbe")) case_gain_temp();
        else if (!strcmp(argv[2], "set_subfr_config")) case_set_subfr();
        else if (!strcmp(argv[2], "calc_sum")) case_sum();
        else if (!strcmp(argv[2], "calc_subfr_nrg")) case_subfr_nrg();
        else if (!strcmp(argv[2], "proc_tec")) case_proc_tec();
        else if (!strcmp(argv[2], "proc_tfa")) case_proc_tfa();
        else if (!strcmp(argv[2], "proc_tec_tfa_tbe")) case_proc_tec_tfa();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
