/* Function-level oracle for the TCX decoder helpers: lib_dec/tcx_utils_dec.c
 * (tcx_decoder_memory_update, tcx_ari_res_invQ_spec, tcx_res_invQ_gain, tcx_res_invQ_spec) and
 * lib_com/tcx_ltp.c tcx_ltp_decode_params. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_memory_update(void)
{
    static const Word16 core_frames[] = {256, 320, 512, 640};
    static Word16 xn_buf[1400], synthout[1400];
    Word16 a[M + 1], syn[M + 1];
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 l_frame = core_frames[random_range(0, 3)];
    Word8 tcxonly = (Word8)(l_frame > 320 ? 1 : (next_random() & 1));
    int magnitude = random_range(1, 3) == 1 ? 32767 : random_range(100, 12000);
    a[0] = 4096;
    for (int k = 1; k <= M; k++) a[k] = (Word16)random_range(-12000 / k - 2000, 12000 / k + 2000);
    random_signal(xn_buf, l_frame, magnitude);
    if (next_random() % 8 == 0) for (int i = 0; i < l_frame; i++) xn_buf[i] = random16();
    random_signal(syn, M + 1, magnitude);
    st->preemph_fac = (Word16)random_range(0, 32767);
    st->tcxonly = tcxonly;
    st->Q_exc = (Word16)random_range(-2, 12);
    st->Q_syn = (Word16)random_range(-2, 12);
    for (int i = 0; i < 5; i++) st->Q_subfr[i] = (Word16)random_range(-2, 12);
    random_signal(st->old_exc_fx, L_EXC_MEM_DEC, random_range(100, 20000));
    for (int i = 0; i < M; i++) st->mem_syn2_fx[i] = random16();
    for (int i = 0; i < L_SYN_MEM; i++) st->mem_syn_r[i] = random16();
    for (int i = 0; i < M + 1; i++) st->old_Aq_12_8_fx[i] = random16();
    st->prev_Q_syn = random16();
    Word8 fb = (Word8)(next_random() % 4 == 0);
    put1("l_frame", l_frame); put1("fb", fb); put1("preemph_fac", st->preemph_fac); put1("tcxonly", tcxonly); put1("q_exc", st->Q_exc);
    put1("q_syn", st->Q_syn); put16("q_subfr", st->Q_subfr, 5); put16("old_exc", st->old_exc_fx, L_EXC_MEM_DEC);
    put16("mem_syn2", st->mem_syn2_fx, M); put16("mem_syn_r", st->mem_syn_r, L_SYN_MEM); put16("old_aq", st->old_Aq_12_8_fx, M + 1);
    put1("prev_q_syn", st->prev_Q_syn); put16("a", a, M + 1); put16("syn", syn, M + 1); put16("xn_buf", xn_buf, l_frame);
    tcx_decoder_memory_update(xn_buf, synthout, l_frame, a, st, syn, fb);
    arrow(); put16("synthout", synthout, l_frame); put16("syn", syn, M + 1); put1("q_syn", st->Q_syn); put1("prev_q_syn", st->prev_Q_syn);
    put16("mem_syn2", st->mem_syn2_fx, M); put16("mem_syn_r", st->mem_syn_r, L_SYN_MEM); put1("q_exc", st->Q_exc);
    put16("q_subfr", st->Q_subfr, 5); put16("old_exc", st->old_exc_fx, L_EXC_MEM_DEC); put16("old_aq", st->old_Aq_12_8_fx, M + 1);
    put16("xn_buf", xn_buf, l_frame);
    end_line();
    free(st);
}

static void case_ari_res(void)
{
    static Word32 x[1200];
    static Word16 prm[NPRM_RESQ + 8], x_fac[1200];
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320);
    Word16 x_e = (Word16)random_range(0, 14);
    Word16 target_bits = (Word16)random_range(0, 140);
    Word16 bits = (Word16)random_range(0, 10);
    Word16 deadzone = (Word16)random_range(0, 32767);
    int density = random_range(1, 14);
    for (int i = 0; i < l_frame; i++) {
        x[i] = (next_random() % 16 < density) ? (Word32)(random32() >> random_range(4, 22)) | 1 : 0;
        x_fac[i] = (Word16)random_range(1, 32767);
    }
    for (int i = 0; i < NPRM_RESQ + 8; i++) prm[i] = (Word16)(next_random() & 1);
    put1("l_frame", l_frame); put1("x_e", x_e); put1("target_bits", target_bits); put1("bits", bits); put1("deadzone", deadzone);
    put32("x", x, l_frame); put16("prm", prm, NPRM_RESQ + 8); put16("x_fac", x_fac, l_frame);
    Word16 used = tcx_ari_res_invQ_spec(x, x_e, l_frame, prm, target_bits, bits, deadzone, x_fac);
    arrow(); put1("used", used); put32("x", x, l_frame); end_line();
}

static void case_res_gain(void)
{
    static Word16 prm[8];
    Word16 gain = (Word16)random_range(16384, 32767), gain_e = (Word16)random_range(-4, 8);
    Word16 res_q_bits = (Word16)random_range(0, 8);
    for (int i = 0; i < 8; i++) prm[i] = (Word16)(next_random() & 1);
    put1("gain", gain); put1("gain_e", gain_e); put1("res_q_bits", res_q_bits); put16("prm", prm, 8);
    Word16 used = tcx_res_invQ_gain(&gain, &gain_e, prm, res_q_bits);
    arrow(); put1("used", used); put1("gain", gain); put1("gain_e", gain_e); end_line();
}

static void case_res_spec(void)
{
    static Word32 x[1200];
    static Word16 prm[NPRM_RESQ + 8], lf[1200];
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320);
    Word16 x_e = (Word16)random_range(0, 14);
    Word16 res_q_bits = (Word16)random_range(0, 140);
    Word16 bits = (Word16)random_range(0, 8);
    Word16 sq_round = (Word16)random_range(2, 0x4000);
    int with_lf = next_random() & 1;
    int density = random_range(1, 14);
    for (int i = 0; i < l_frame; i++) {
        x[i] = (next_random() % 16 < density) ? (Word32)(random32() >> random_range(4, 22)) | 1 : 0;
        lf[i] = (Word16)(next_random() % 4 ? random_range(0x2001, 0x4000) : random_range(0x100, 0x2000));
    }
    for (int i = 0; i < NPRM_RESQ + 8; i++) prm[i] = (Word16)(next_random() & 1);
    put1("l_frame", l_frame); put1("x_e", x_e); put1("res_q_bits", res_q_bits); put1("bits", bits); put1("sq_round", sq_round); put1("with_lf", with_lf);
    put32("x", x, l_frame); put16("prm", prm, NPRM_RESQ + 8); put16("lf", lf, l_frame);
    Word16 used = tcx_res_invQ_spec(x, x_e, l_frame, prm, res_q_bits, bits, sq_round, with_lf ? lf : NULL);
    arrow(); put1("used", used); put32("x", x, l_frame); end_line();
}

static void case_ltp_decode(void)
{
    /* pit_min, pit_fr1, pit_fr2, pit_max, pit_res_max of the four core rates (core_com_config_fx.c) */
    static const Word16 cores[4][5] = {{29, 154, 121, 231, 4}, {36, 165, 36, 289, 6}, {58, 164, 58, 463, 4}, {72, 75, 72, 577, 6}};
    const Word16 *core = cores[random_range(0, 3)];
    Word16 param[3] = {(Word16)(next_random() % 4 != 0), (Word16)random_range(0, 511), (Word16)random_range(0, 3)};
    int null_param = next_random() % 16 == 0;
    Word16 pitch_int = 0x1111, pitch_fr = 0x2222, gain = 0x3333;
    put16("param", param, 3); put1("null_param", null_param); put16("core", core, 5);
    Word16 r = tcx_ltp_decode_params(null_param ? NULL : param, &pitch_int, &pitch_fr, &gain, core[0], core[1], core[2], core[3], core[4]);
    arrow(); put1("r", r); put1("pitch_int", pitch_int); put1("pitch_fr", pitch_fr); put1("gain", gain); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "tcx_decoder_memory_update")) case_memory_update();
        else if (!strcmp(argv[2], "tcx_ari_res_invQ_spec")) case_ari_res();
        else if (!strcmp(argv[2], "tcx_res_invQ_gain")) case_res_gain();
        else if (!strcmp(argv[2], "tcx_res_invQ_spec")) case_res_spec();
        else if (!strcmp(argv[2], "tcx_ltp_decode_params")) case_ltp_decode();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
