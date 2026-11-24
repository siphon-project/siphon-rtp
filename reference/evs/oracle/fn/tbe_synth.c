/* Function-level oracle for lib_com/swb_tbe_com_fx.c: the TBE synthesis helpers the SWB / WB / FB
 * decoders run every frame. The file is included, so its static functions (Hilbert_transform_fx,
 * Hilbert_transform_sp_fx, flip_spectrum_fx, Calc_st_filt_tbe, filt_mu_fx, scale_st_swb) are reached
 * through their callers (flip_and_downmix_generic_fx, GenWBSynth_fx, PostShortTerm_fx). Inputs stay
 * in the ranges the decoder feeds them; stateful functions (the FB band-pass) are run twice, the
 * second call on the state the first left, so the state is always one the reference produced. */
#include "harness.h"
#include "../../c-code/lib_com/swb_tbe_com_fx.c"

static const int magnitudes[] = {50, 600, 4000, 16000, 32767};

static void random_input(Word16 *x, int n)
{
    random_signal(x, n, magnitudes[next_random() % 5]);
    if (next_random() % 6 == 0)
        for (int i = 0; i < n; i++)
            if (next_random() % 4 == 0) x[i] = random16();
}

static Word32 positive32(void)
{
    Word32 value = random32();
    if (value == (Word32)0x80000000) return 0x7fffffff;
    return value < 0 ? -value : value;
}

static void case_flip_and_downmix(void)
{
    Word16 input[640], output[640];
    Word32 mem1[5], mem2[8], mem3[8];
    Word16 phase = (Word16)random_range(0, 16);
    random_input(input, 640);
    for (int i = 0; i < 5; i++) mem1[i] = (Word32)random16() << 16;
    int scale = next_random() & 1 ? 20 : 30;
    for (int i = 0; i < 8; i++) { mem2[i] = (Word32)random_range(-(1 << scale), 1 << scale); mem3[i] = (Word32)random_range(-(1 << scale), 1 << scale); }
    memset(output, 0, sizeof(output));
    put16("input", input, 640); put32("mem1", mem1, 5); put32("mem2", mem2, 8); put32("mem3", mem3, 8); put1("phase", phase);
    flip_and_downmix_generic_fx(input, output, 640, mem1, mem2, mem3, &phase);
    arrow(); put16("input_out", input, 640); put16("output", output, 640); put32("mem1_out", mem1, 5);
    put32("mem2_out", mem2, 8); put32("mem3_out", mem3, 8); put1("phase_out", phase); end_line();
}

static void case_flip_spectrum_and_decimby4(void)
{
    Word16 input[320], output[80], mem1[7], mem2[7];
    Word16 ramp = (Word16)(next_random() & 1);
    random_input(input, 320);
    random_signal(mem1, 7, 8000); random_signal(mem2, 7, 8000);
    memset(output, 0, sizeof(output));
    put16("input", input, 320); put16("mem1", mem1, 7); put16("mem2", mem2, 7); put1("ramp", ramp);
    flip_spectrum_and_decimby4_fx(input, output, 320, mem1, mem2, ramp);
    arrow(); put16("output", output, 80); put16("mem1_out", mem1, 7); put16("mem2_out", mem2, 7); end_line();
}

static void case_create_random_vector(void)
{
    Word16 seed[2] = {random16(), random16()}, output[320];
    static const Word16 lengths[] = {80, 256, 64, 320 - 256};
    Word16 length = lengths[next_random() % 4];
    memset(output, 0, sizeof(output));
    put16("seed", seed, 2); put1("length", length);
    create_random_vector_fx(output, length, seed);
    arrow(); put16("output", output, length); put16("seed_out", seed, 2); end_line();
}

static void case_post_short_term(void)
{
    Word16 history[10 + 80 + 8], lpc[11], out[80], mem_stp[10], mem_zero[10], gain = 0;
    Word16 formant_fac = (Word16)(next_random() % 5 ? random_range(0, 32767) : random16() & 0x7fff);
    random_input(history, 90);
    lpc[0] = 4096;
    for (int i = 1; i <= 10; i++) lpc[i] = (next_random() & 3) ? (Word16)random_range(-9000 / i, 9000 / i) : random16();
    random_signal(mem_stp, 10, 8000);
    memset(mem_zero, 0, sizeof(mem_zero));
    gain = (Word16)random_range(0, 32767);
    memset(out, 0, sizeof(out));
    put16("sig", history, 90); put16("lpc", lpc, 11); put16("mem_stp", mem_stp, 10); put1("gain", gain);
    put1("formant_fac", formant_fac);
    PostShortTerm_fx(history + 10, lpc, out, mem_stp, mem_stp + 9, &gain, mem_zero, formant_fac);
    arrow(); put16("out", out, 80); put16("mem_stp_out", mem_stp, 10); put1("gain_out", gain);
    put16("mem_zero_out", mem_zero, 10); end_line();
}

static void case_swb_formant_fac(void)
{
    Word16 lpc2 = random16(), tilt = (Word16)random_range(0, 32767);
    put1("lpc2", lpc2); put1("tilt", tilt);
    Word16 result = swb_formant_fac_fx(lpc2, &tilt);
    arrow(); put1("result", result); put1("tilt_out", tilt); end_line();
}

static void case_gen_wb_synth(void)
{
    Word16 input[80], output[320], state1[6], state2[6];
    int magnitude = magnitudes[next_random() % 5];
    random_signal(input, 80, magnitude);
    if (next_random() % 8 == 0) memset(input, 0, sizeof(input));
    random_signal(state1, 6, magnitude); random_signal(state2, 6, magnitude);
    memset(output, 0, sizeof(output));
    put16("input", input, 80); put16("state1", state1, 6); put16("state2", state2, 6);
    GenWBSynth_fx(input, output, state1, state2);
    arrow(); put16("output", output, 320); put16("state1_out", state1, 6); put16("state2_out", state2, 6); end_line();
}

static void case_gen_shb_synth(void)
{
    Word16 input[320], output[640], allpass[6];
    Word32 hilbert[21];
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320), phase = (Word16)random_range(0, 16);
    int magnitude = magnitudes[next_random() % 5];
    random_signal(input, 320, magnitude);
    if (next_random() % 8 == 0) memset(input, 0, sizeof(input));
    random_signal(allpass, 6, magnitude);
    int scale = next_random() & 1 ? 18 : 28;
    for (int i = 0; i < 21; i++) hilbert[i] = (Word32)random_range(-(1 << scale), 1 << scale);
    if (next_random() % 8 == 0) memset(hilbert, 0, sizeof(hilbert));
    memset(output, 0, sizeof(output));
    put16("input", input, 320); put16("allpass", allpass, 6); put32("hilbert", hilbert, 21);
    put1("l_frame", l_frame); put1("phase", phase);
    GenSHBSynth_fx(input, output, hilbert, allpass, l_frame, &phase);
    arrow(); put16("output", output, 640); put16("allpass_out", allpass, 6); put32("hilbert_out", hilbert, 21);
    put1("phase_out", phase); end_line();
}

static void random_lpc_shb(Word16 *a, int order)
{
    a[0] = 4096;
    for (int i = 1; i <= order; i++) a[i] = (next_random() & 3) ? (Word16)random_range(-7000 / i, 7000 / i) : random16();
}

static void case_gen_shaped_wb_excitation(void)
{
    Word16 exc_shb[80], lpc[7], exc4k[80], down1[7], down2[7], down3[7], state_lpc[6], bwe[640], seed[2];
    Word16 voice[5], coder_type = (Word16)random_range(0, 3), q_bwe_exc = (Word16)random_range(3, 20);
    Word16 uv_flag = (Word16)(next_random() % 4 == 0), igf_flag = (Word16)(next_random() % 3 == 0);
    Word32 mem_csfilt = next_random() & 1 ? 0 : (Word32)(next_random() & 0xfffff);
    random_lpc_shb(lpc, 6);
    random_input(bwe, 640);
    if (next_random() % 10 == 0) memset(bwe, 0, sizeof(bwe));
    random_signal(down1, 7, 8000); random_signal(down2, 7, 8000); random_signal(down3, 7, 8000);
    random_signal(state_lpc, 6, 8000);
    seed[0] = (Word16)random_range(0, 32767); seed[1] = (Word16)random_range(0, 32767);
    for (int i = 0; i < 5; i++) voice[i] = (Word16)(next_random() % 6 ? random_range(0, 32767) : random16() & 0x7fff);
    memset(exc_shb, 0, sizeof(exc_shb)); memset(exc4k, 0, sizeof(exc4k));
    put16("lpc", lpc, 7); put16("bwe", bwe, 640); put16("down1", down1, 7); put16("down2", down2, 7);
    put16("down3", down3, 7); put16("state_lpc", state_lpc, 6); put16("seed", seed, 2); put16("voice", voice, 5);
    put1("coder_type", coder_type); put1("q_bwe_exc", q_bwe_exc); put1("uv_flag", uv_flag); put1("igf_flag", igf_flag);
    put32("mem_csfilt", &mem_csfilt, 1);
    GenShapedWBExcitation_fx(exc_shb, lpc, exc4k, &mem_csfilt, down1, down2, down3, state_lpc, coder_type, bwe,
                             q_bwe_exc, seed, voice, uv_flag, igf_flag);
    arrow(); put16("exc_shb", exc_shb, 80); put16("exc4k", exc4k, 80); put32("mem_csfilt_out", &mem_csfilt, 1);
    put16("down1_out", down1, 7); put16("down2_out", down2, 7); put16("down3_out", down3, 7);
    put16("state_lpc_out", state_lpc, 6); put16("seed_out", seed, 2); end_line();
}

static void random_windows(Word16 *win, Word16 *subwin)
{
    for (int i = 0; i < 20; i++) win[i] = (Word16)random_range(0, 32767);
    for (int i = 0; i < 24; i++) subwin[i] = (Word16)random_range(0, 32767);
}

static void shaped_inputs(Word16 length, Word16 *syn, Word16 *overlap, Word16 *subgain, Word32 *frame_gain, Word16 *win, Word16 *subwin)
{
    int magnitude = magnitudes[next_random() % 5];
    random_signal(syn, 340, magnitude);
    random_signal(overlap, 20, magnitude);
    for (int i = 0; i < 16; i++) subgain[i] = (Word16)(next_random() % 10 ? random_range(0, 32767) : random16());
    *frame_gain = next_random() % 10 == 0 ? 0 : positive32();
    random_windows(win, subwin);
    (void)length;
}

static void case_scale_shaped_shb(void)
{
    Word16 syn[340], overlap[20], subgain[16], win[20], subwin[24];
    Word32 frame_gain;
    Word16 length = (Word16)(next_random() & 1 ? 10 : 20);
    Word16 q_bwe_exc = (Word16)random_range(0, 20), qx = 0, n_mem3 = (Word16)random_range(0, 4), prev = (Word16)random_range(0, 14);
    shaped_inputs(length, syn, overlap, subgain, &frame_gain, win, subwin);
    put1("length", length); put16("syn", syn, 340); put16("overlap", overlap, 20); put16("subgain", subgain, 16);
    put32("frame_gain", &frame_gain, 1); put16("win", win, 20); put16("subwin", subwin, 24);
    put1("q_bwe_exc", q_bwe_exc); put1("n_mem3", n_mem3); put1("prev", prev);
    ScaleShapedSHB_fx(length, syn, overlap, subgain, frame_gain, win, subwin, &q_bwe_exc, &qx, n_mem3, prev);
    arrow(); put16("syn_out", syn, length == 10 ? 80 : 320); put16("overlap_out", overlap, 20);
    put1("q_bwe_exc_out", q_bwe_exc); put1("qx", qx); end_line();
}

static void case_scale_shaped_wb(void)
{
    Word16 syn[340], overlap[20], subgain[16], win[20], subwin[24];
    Word32 frame_gain, hilbert[21];
    Word16 length = (Word16)(next_random() & 1 ? 10 : 20);
    Word16 q_bwe_exc = (Word16)random_range(0, 14), l_frame = (Word16)(next_random() & 1 ? 256 : 320);
    Word16 dynq = (Word16)(next_random() % 4 != 0), qx = 0, prev_qx = (Word16)random_range(0, 10);
    shaped_inputs(length, syn, overlap, subgain, &frame_gain, win, subwin);
    int scale = next_random() & 1 ? 18 : 28;
    for (int i = 0; i < 21; i++) hilbert[i] = (Word32)random_range(-(1 << scale), 1 << scale);
    put1("length", length); put16("syn", syn, 340); put16("overlap", overlap, 20); put16("subgain", subgain, 16);
    put32("frame_gain", &frame_gain, 1); put16("win", win, 20); put16("subwin", subwin, 24);
    put1("q_bwe_exc", q_bwe_exc); put1("l_frame", l_frame); put1("dynq", dynq); put1("prev_qx", prev_qx);
    put32("hilbert", hilbert, 21);
    ScaleShapedWB_fx(length, syn, overlap, subgain, frame_gain, win, subwin, q_bwe_exc, l_frame, dynq, &qx, prev_qx, hilbert);
    arrow(); put16("syn_out", syn, length == 10 ? 80 : 320); put16("overlap_out", overlap, 20); put1("qx", qx); end_line();
}

static void case_estimate_mix_factors(void)
{
    Word16 shb_res[320], exc[320], white[320], vf[5] = {0, 0, 0, 0, 0}, vf_ind = 0;
    Word16 q_shb = (Word16)random_range(2, 14), q_bwe_exc = (Word16)random_range(2, 18), q_frac = (Word16)random_range(2, 18);
    Word16 q_pow1 = (Word16)random_range(10, 40), q_pow22 = (Word16)random_range(10, 40);
    Word32 pow1 = positive32() | 1, pow22 = positive32() | 1;
    random_input(shb_res, 320); random_input(exc, 320); random_input(white, 320);
    put16("shb_res", shb_res, 320); put16("exc", exc, 320); put16("white", white, 320); put1("q_shb", q_shb);
    put1("q_bwe_exc", q_bwe_exc); put1("q_frac", q_frac); put32("pow1", &pow1, 1); put1("q_pow1", q_pow1);
    put32("pow22", &pow22, 1); put1("q_pow22", q_pow22);
    Estimate_mix_factors_fx(shb_res, q_shb, exc, q_bwe_exc, white, q_frac, pow1, q_pow1, pow22, q_pow22, vf, &vf_ind);
    arrow(); put16("vf", vf, 5); put1("vf_ind", vf_ind); end_line();
}

static void case_elliptic_bpf(void)
{
    Word16 in1[960], in2[960], out1[960], out2[960], q_in = (Word16)random_range(0, 10), memory_q[4] = {0, 0, 0, 0};
    Word32 memory[4][4];
    int magnitude = magnitudes[next_random() % 5];
    memset(memory, 0, sizeof(memory));
    random_signal(in1, 960, magnitude); random_signal(in2, 960, magnitude);
    for (int i = 0; i < 960; i += 3) { if (next_random() & 1) in1[i + 1] = in1[i + 2] = 0; }
    const Word16 (*table)[5] = next_random() & 1 ? full_band_bpf_3_fx : full_band_bpf_1_fx;
    Word16 q2 = (Word16)random_range(0, 10);
    put16("in1", in1, 960); put16("in2", in2, 960); put1("q_in", q_in); put1("q2_in", q2);
    put1("table3", table == full_band_bpf_3_fx);
    elliptic_bpf_48k_generic_fx(in1, &q_in, out1, memory, memory_q, table);
    Word16 q_mid = q_in;
    elliptic_bpf_48k_generic_fx(in2, &q2, out2, memory, memory_q, table);
    arrow(); put16("out1", out1, 960); put1("q_mid", q_mid);
    put16("out2", out2, 960); put1("q2", q2);
    put32("mem0", memory[0], 4); put32("mem1", memory[1], 4); put32("mem2", memory[2], 4); put32("mem3", memory[3], 4);
    put16("memory_q", memory_q, 4); end_line();
}

static void case_synthesise_fb(void)
{
    Word16 exc1[320], exc2[320], out1[960], out2[960], memory_q[4] = {0, 0, 0, 0}, prev_ratio = 0;
    Word32 memory[4][4];
    Word16 q_fb = (Word16)random_range(2, 14), l_frame = (Word16)(next_random() & 1 ? 320 : 256);
    Word16 ratio1 = (Word16)random_range(0, 32767), ratio2 = (Word16)random_range(0, 32767);
    Word16 bfi1 = (Word16)(next_random() % 4 == 0), bfi2 = (Word16)(next_random() % 4 == 0);
    Word16 q_out = (Word16)random_range(2, 14);
    Word32 energy1 = next_random() % 10 == 0 ? 0 : positive32(), energy2 = next_random() % 10 == 0 ? 0 : positive32();
    int magnitude = magnitudes[next_random() % 5];
    memset(memory, 0, sizeof(memory));
    random_signal(exc1, 320, magnitude); random_signal(exc2, 320, magnitude);
    put16("exc1", exc1, 320); put16("exc2", exc2, 320); put1("q_fb", q_fb); put1("l_frame", l_frame);
    put1("ratio1", ratio1); put1("ratio2", ratio2); put1("bfi1", bfi1); put1("bfi2", bfi2); put1("q_out", q_out);
    put32("energy1", &energy1, 1); put32("energy2", &energy2, 1);
    synthesise_fb_high_band_fx(exc1, q_fb, out1, energy1, ratio1, l_frame, bfi1, &prev_ratio, memory, memory_q, q_out);
    Word16 prev_mid = prev_ratio;
    synthesise_fb_high_band_fx(exc2, q_fb, out2, energy2, ratio2, l_frame, bfi2, &prev_ratio, memory, memory_q, q_out);
    arrow(); put16("out1", out1, 960); put1("prev_mid", prev_mid); put16("out2", out2, 960); put1("prev_ratio", prev_ratio);
    put32("mem0", memory[0], 4); put32("mem1", memory[1], 4); put32("mem2", memory[2], 4); put32("mem3", memory[3], 4);
    put16("memory_q", memory_q, 4); end_line();
}

static void case_gen_shaped_shb_excitation(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000};
    Word16 exc_shb[340], lpc[11], lpc_sf[44], white_fb[320], down[7], state_lpc[10], bwe[640], seed[2], voice[5];
    Word16 shb_res[320], gshape[5], fb_state[10], coder_type = (Word16)random_range(0, 3), extl = next_random() & 1 ? 8 : 11;
    Word16 vf_ind = (Word16)(next_random() & 1 ? 20 : random_range(0, 7)), formant = (Word16)random_range(0, 32767);
    Word16 demph = random16() / 4, premph = random16() / 4, fb_demph = random16() / 4;
    Word16 q_bwe_exc = (Word16)random_range(4, 24), q_fb = (Word16)random_range(0, 30), q_shb = (Word16)random_range(0, 12);
    Word16 n_mem2 = (Word16)random_range(0, 15), prev_q_syn = (Word16)random_range(0, 15), prev_bfi = (Word16)(next_random() % 4 == 0);
    Word32 mem_csfilt[2] = {next_random() % 3 ? 0 : (Word32)(next_random() & 0xfffff), 0}, bitrate = rates[next_random() % 7];
    Word32 ener = next_random() % 10 == 0 ? 0 : positive32() >> (next_random() % 10);
    int magnitude = magnitudes[next_random() % 5];
    /* LPCs of a stable filter: small taps, which keeps the synthesis out of saturation */
    for (int k = 0; k < 5; k++) {
        Word16 *a = k == 4 ? lpc : lpc_sf + 11 * k;
        a[0] = 4096;
        for (int i = 1; i <= 10; i++) a[i] = (Word16)random_range(-2400 / i, 2400 / i);
    }
    random_input(bwe, 640);
    if (next_random() % 10 == 0) memset(bwe, 0, sizeof bwe);
    random_signal(exc_shb, 340, magnitude); random_signal(down, 7, 8000); random_signal(state_lpc, 10, 8000);
    random_signal(fb_state, 10, 8000); random_input(shb_res, 320);
    seed[0] = (Word16)random_range(0, 32767); seed[1] = (Word16)random_range(0, 32767);
    for (int i = 0; i < 5; i++) { voice[i] = (Word16)(next_random() % 6 ? random_range(0, 32767) : (random16() & 0x7fff)); gshape[i] = (Word16)random_range(500, 9000); }
    memset(white_fb, 0, sizeof white_fb);
    put16("lpc", lpc, 11); put16("lpc_sf", lpc_sf, 44); put16("bwe", bwe, 640); put16("exc_shb", exc_shb, 340);
    put16("down", down, 7); put16("state_lpc", state_lpc, 10); put16("seed", seed, 2); put16("voice", voice, 5);
    put16("shb_res", shb_res, 320); put16("gshape", gshape, 5); put16("fb_state", fb_state, 10);
    put1("coder_type", coder_type); put1("extl", extl); put1("vf_ind", vf_ind); put1("formant", formant);
    put1("demph", demph); put1("premph", premph); put1("fb_demph", fb_demph); put1("q_bwe_exc", q_bwe_exc);
    put1("q_fb", q_fb); put1("q_shb", q_shb); put1("n_mem2", n_mem2); put1("prev_q_syn", prev_q_syn);
    put1("prev_bfi", prev_bfi); put32("mem_csfilt", mem_csfilt, 1); put1("bitrate", bitrate); put32("ener", &ener, 1);
    GenShapedSHBExcitation_fx(exc_shb + 20, lpc, white_fb, mem_csfilt, down, state_lpc, coder_type, bwe, seed, voice,
                              extl, &demph, &premph, lpc_sf, ener, gshape, shb_res, &vf_ind, formant, fb_state,
                              &fb_demph, &q_bwe_exc, &q_fb, q_shb, n_mem2, prev_q_syn, bitrate, prev_bfi);
    arrow(); put16("exc_shb_out", exc_shb, 340); put16("white_fb", white_fb, 320); put32("mem_csfilt_out", mem_csfilt, 1);
    put16("down_out", down, 7); put16("state_lpc_out", state_lpc, 10); put16("seed_out", seed, 2); put16("voice_out", voice, 5);
    put1("demph_out", demph); put1("premph_out", premph); put1("vf_ind_out", vf_ind); put16("fb_state_out", fb_state, 10);
    put1("fb_demph_out", fb_demph); put1("q_bwe_exc_out", q_bwe_exc); put1("q_fb_out", q_fb); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        const char *f = argv[2];
        if (!strcmp(f, "flip_and_downmix")) case_flip_and_downmix();
        else if (!strcmp(f, "flip_spectrum_and_decimby4")) case_flip_spectrum_and_decimby4();
        else if (!strcmp(f, "create_random_vector")) case_create_random_vector();
        else if (!strcmp(f, "post_short_term")) case_post_short_term();
        else if (!strcmp(f, "swb_formant_fac")) case_swb_formant_fac();
        else if (!strcmp(f, "gen_shaped_shb_excitation")) case_gen_shaped_shb_excitation();
        else if (!strcmp(f, "gen_wb_synth")) case_gen_wb_synth();
        else if (!strcmp(f, "gen_shb_synth")) case_gen_shb_synth();
        else if (!strcmp(f, "gen_shaped_wb_excitation")) case_gen_shaped_wb_excitation();
        else if (!strcmp(f, "scale_shaped_shb")) case_scale_shaped_shb();
        else if (!strcmp(f, "scale_shaped_wb")) case_scale_shaped_wb();
        else if (!strcmp(f, "estimate_mix_factors")) case_estimate_mix_factors();
        else if (!strcmp(f, "elliptic_bpf")) case_elliptic_bpf();
        else if (!strcmp(f, "synthesise_fb")) case_synthesise_fb();
        else { fprintf(stderr, "unknown function %s\n", f); return 2; }
    }
    return 0;
}
