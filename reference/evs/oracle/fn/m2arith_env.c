/* Function-level oracle for tcx_hm_modify_envelope / tcx_hm_decode (ari_hm.c, ari_hm_dec.c) and
 * tcx_arith_scale_envelope (arith_coder.c). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static const int sizes[] = {64, 80, 128, 160, 256, 320, 512, 640, 800};

static void random_periodicity(int bandwidth, Word16 *index, Word16 *lag)
{
    *lag = 0;
    if (next_random() % 3 == 0) {
        int ltp = random_range(0, 16);
        int multiplier = random_range(1, 1 << NumRatioBits[bandwidth][ltp]);
        *index = (Word16)(kLtpHmFlag | multiplier | (ltp << 9));
        *lag = (Word16)((ltp + 2) * 128 + random_range(-63, 63));
    } else {
        *index = (Word16)random_range(0, 255);
        if (next_random() & 1) *lag = (Word16)random_range(1, 2400);
    }
}

static Word32 random_envelope_value(void)
{
    /* Q16 envelope: log-uniform between 2^8 and 2^27 */
    return (Word32)(random_range(1, 1000) << random_range(0, 17)) + random_range(0, 255);
}

static void case_modify(void)
{
    Word16 l_frame = (Word16)sizes[random_range(0, 8)], periodicity, ltp_lag, p[9], fract_res = 0;
    Word32 lag = 0, env[800];
    random_periodicity(l_frame >= 256, &periodicity, &ltp_lag);
    UnmapIndex(periodicity, (Word8)(l_frame >= 256), ltp_lag, (Word8)(next_random() & 1), &fract_res, &lag);
    if (tcx_hm_render(lag, fract_res, p)) { case_modify(); return; }
    Word16 gain = (next_random() % 5 == 0) ? 0 : qGains[next_random() & 1][random_range(0, 3)];
    for (int i = 0; i < l_frame; i++) env[i] = random_envelope_value();
    put1("gain", gain); put1("lag", lag); put1("fract_res", fract_res); put16("p", p, 9);
    put1("l_frame", l_frame); put32("env", env, l_frame);
    tcx_hm_modify_envelope(gain, lag, fract_res, p, env, l_frame);
    arrow(); put32("env", env, l_frame); end_line();
}

static void case_decode(void)
{
    Word16 l_frame = (Word16)sizes[random_range(0, 8)], prm_hm[3], ltp_lag, hm_bits = 55;
    Word32 env[800];
    random_periodicity(l_frame >= 256, &prm_hm[1], &ltp_lag);
    prm_hm[0] = 1;
    prm_hm[2] = (Word16)(next_random() % 6 == 0 ? random_range(-1, 5) : random_range(0, 3));
    Word16 coder_type = (Word16)((next_random() % 8 == 0) ? random_range(0, 4) : (next_random() & 1 ? VOICED : GENERIC));
    Word16 target_bits = (Word16)random_range(20, 264);
    for (int i = 0; i < l_frame; i++) env[i] = random_envelope_value();
    put1("l_frame", l_frame); put1("target_bits", target_bits); put1("coder_type", coder_type);
    put16("prm_hm", prm_hm, 3); put1("ltp_lag", ltp_lag); put32("env", env, l_frame);
    tcx_hm_decode(l_frame, env, target_bits, coder_type, prm_hm, ltp_lag, &hm_bits);
    arrow(); put1("hm_bits", hm_bits); put32("env", env, l_frame); end_line();
}

static void case_scale(void)
{
    Word16 l_spec = (Word16)sizes[random_range(0, 8)], core = l_spec, e = 0;
    if (next_random() & 1) core = (Word16)(l_spec - random_range(0, l_spec / 3)); /* IGF start line */
    Word32 env[800];
    Word16 target_bits = (Word16)random_range(40, 264), low_complexity = (Word16)(next_random() & 1);
    if (next_random() % 6 == 0) target_bits = (Word16)random_range(8, 40);
    int kind = random_range(0, 2);
    for (int i = 0; i < l_spec; i++) {
        env[i] = random_envelope_value();
        if (kind == 1) env[i] = 65536 + random_range(0, 20000);                /* flat */
        if (kind == 2) env[i] = (Word32)(6000 + 600 * i / 8 + random_range(0, 3000)); /* tilted */
    }
    for (int i = core; i < l_spec; i++) env[i] = env[core - 1]; /* tcx_arith_render_envelope repeats the last line */
    put1("l_spec", l_spec); put1("core", core); put1("target_bits", target_bits); put1("low_complexity", low_complexity);
    put32("env", env, l_spec);
    tcx_arith_scale_envelope(l_spec, core, env, target_bits, low_complexity, (Word16 *)env, &e);
    arrow(); put32("env", env, l_spec); put1("e", e); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "modify")) case_modify();
        else if (!strcmp(argv[2], "decode")) case_decode();
        else if (!strcmp(argv[2], "scale")) case_scale();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
