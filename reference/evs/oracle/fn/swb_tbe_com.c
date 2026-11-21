/* Function-level oracle for lib_com/swb_tbe_com_fx.c: the TBE excitation helpers the ACELP core
 * runs every subframe. The static non_linearity_scaled_copy is proven through non_linearity_fx
 * (both its en_abs branches); interp_code_4over2_fx through prep_tbe_exc_fx at L_frame 320. */
/* LP filter / signal input generators, shared in spirit by the filter oracles (kept inline: the
 * reference/evs .gitignore admits only *.c and harness.h here). */
#include "harness.h"

/* LP coefficients a[0..m] in Q12: mostly a[0] = 1.0 and taps of the size real filters have,
 * sometimes a differently normalised a[0], sometimes edge values that saturate the filter. */
static void random_lpc(Word16 *a, int m)
{
    int kind = next_random() % 8;
    a[0] = 4096;
    if (kind == 6) a[0] = (Word16)(next_random() & 1 ? 8192 : 2048);
    if (kind == 7) a[0] = random16();
    for (int k = 1; k <= m; k++) {
        if (kind == 5 || kind == 7) a[k] = random16();
        else a[k] = (Word16)random_range(-12000 / k - 2000, 12000 / k + 2000);
    }
}

/* A signal of a random magnitude, from quiet to full scale, sometimes with edge values mixed in. */
static void random_input(Word16 *x, int n)
{
    static const int magnitudes[] = {50, 600, 4000, 16000, 32767};
    random_signal(x, n, magnitudes[next_random() % 5]);
    if (next_random() % 6 == 0)
        for (int i = 0; i < n; i++)
            if (next_random() % 4 == 0) x[i] = random16();
}
#include "prot_fx.h"

#define HISTORY 700

static void random_pitch(Word16 l_frame, Word16 *t0, Word16 *t0_frac)
{
    *t0 = (Word16)random_range(l_frame == 256 ? 34 : 42, l_frame == 256 ? 231 : 289);
    *t0_frac = (Word16)random_range(0, 3);
}

static Word16 random_subframe(Word16 l_frame) { return (Word16)(64 * random_range(0, l_frame / 64 - 1)); }

static void case_tbe_celp_exc_offset(void)
{
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320), t0, t0_frac;
    random_pitch(l_frame, &t0, &t0_frac);
    put1("t0", t0); put1("t0_frac", t0_frac); put1("l_frame", l_frame);
    arrow(); put1("offset", tbe_celp_exc_offset(t0, t0_frac, l_frame)); end_line();
}

static void case_tbe_celp_exc(void)
{
    Word16 buffer[HISTORY + 640], t0, t0_frac;
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320), i_subfr = random_subframe(l_frame);
    random_pitch(l_frame, &t0, &t0_frac);
    Word16 error = (Word16)(next_random() % 8 ? random_range(-200, 200) : random_range(-640, 640));
    int n = l_frame == 256 ? 160 : 128, start = l_frame == 256 ? i_subfr * 5 / 2 : i_subfr * 2;
    int total = HISTORY + start + n;
    random_input(buffer, total);
    put1("l_frame", l_frame); put1("i_subfr", i_subfr); put1("t0", t0); put1("t0_frac", t0_frac);
    put1("error", error); put16("bwe_exc", buffer, total);
    tbe_celp_exc(l_frame, i_subfr, t0, t0_frac, &error, buffer + HISTORY);
    arrow(); put1("error", error); put16("bwe_exc", buffer, total); end_line();
}

static void case_calc_rc0_h(void)
{
    Word16 h[20], rc0 = -99;
    int kind = next_random() % 6;
    if (kind == 0) for (int i = 0; i < 20; i++) h[i] = random16();
    else if (kind == 1) for (int i = 0; i < 20; i++) h[i] = 0;
    else {
        int value = random_range(-32768, 32767), decay = random_range(16000, 32767);
        for (int i = 0; i < 20; i++) {
            h[i] = (Word16)value;
            value = (value * decay) >> 15;
            if (next_random() & 1) value = -value;
            value += random_range(-200, 200);
            if (value > 32767) value = 32767;
            if (value < -32768) value = -32768;
        }
    }
    put16("h", h, 20);
    Calc_rc0_h(h, &rc0);
    arrow(); put1("rc0", rc0); end_line();
}

static void case_interp_code_5over2(void)
{
    Word16 in[64], out[160];
    random_input(in, 64);
    put16("inp", in, 64);
    interp_code_5over2_fx(in, out, 64);
    arrow(); put16("out", out, 160); end_line();
}

static void case_non_linearity(void)
{
    Word16 input[640], voice_factors[5];
    Word32 output[640];
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320);
    Word16 coder_type = (Word16)(next_random() & 1 ? 2 : random_range(0, 7));
    Word16 q_inp = (Word16)random_range(0, 12);
    for (int i = 0; i < 5; i++)
        voice_factors[i] = (Word16)(next_random() & 1 ? random_range(25000, 32767) : random_range(0, 32767));
    random_input(input, 640);
    if (next_random() % 6 == 0) for (int i = 0; i < 640; i++) input[i] = (Word16)(input[i] >> 10);
    if (next_random() % 6 == 0) { /* the peak at the start of a half: the j == 0 branch */
        for (int i = 0; i < 640; i++) input[i] = (Word16)(input[i] >> 2);
        input[0] = 32767;
        input[320] = -32768;
    }
    Word32 prev_scale;
    switch (next_random() % 5) {
    case 0: prev_scale = 0; break;
    case 1: prev_scale = -(Word32)random_range(1, 1000); break;
    case 2: prev_scale = random32(); break;
    default: prev_scale = L_shr((Word32)random_range(1, 0x7fffffff), (Word16)random_range(0, 24));
    }
    put16("input", input, 640); put1("prev_scale", prev_scale); put1("q_inp", q_inp);
    put1("coder_type", coder_type); put16("voice_factors", voice_factors, 5); put1("l_frame", l_frame);
    non_linearity_fx(input, output, 640, &prev_scale, q_inp, coder_type, voice_factors, l_frame);
    arrow(); put32("output", output, 640); put1("prev_scale", prev_scale); end_line();
}

static void case_prep_tbe_exc(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000};
    Word16 code[64], code_pre_q[64], bwe_exc[640], t0, t0_frac, voice_factors = -99;
    Word16 l_frame = (Word16)(next_random() & 1 ? 256 : 320), i_subfr = random_subframe(l_frame);
    random_pitch(l_frame, &t0, &t0_frac);
    Word16 gain_pit = (Word16)(next_random() % 6 ? random_range(0, 19661) : random16());
    Word32 gain_code = next_random() % 6 ? L_shr((Word32)random_range(0, 0x7fffffff), (Word16)random_range(4, 30)) : random32();
    Word16 voice_fac = random16();
    Word16 gain_pre_q = (Word16)(next_random() % 3 ? 0 : random_range(-8000, 8000));
    Word16 q_exc = (Word16)random_range(0, 12), coder_type = (Word16)random_range(0, 7);
    Word32 core_brate = rates[next_random() % 7];
    memset(code, 0, sizeof(code));
    for (int p = random_range(1, 24); p > 0; p--) code[next_random() % 64] += (Word16)(next_random() & 1 ? 512 : -512);
    if (next_random() % 6 == 0) random_input(code, 64);
    random_input(code_pre_q, 64);
    random_input(bwe_exc, 640);
    put1("l_frame", l_frame); put1("i_subfr", i_subfr); put1("gain_pit", gain_pit); put1("gain_code", gain_code);
    put16("code", code, 64); put1("voice_fac", voice_fac); put16("bwe_exc", bwe_exc, 640);
    put1("gain_pre_q", gain_pre_q); put16("code_pre_q", code_pre_q, 64); put1("q_exc", q_exc);
    put1("t0", t0); put1("t0_frac", t0_frac); put1("coder_type", coder_type); put1("core_brate", core_brate);
    prep_tbe_exc_fx(l_frame, i_subfr, gain_pit, gain_code, code, voice_fac, &voice_factors, bwe_exc,
                    gain_pre_q, code_pre_q, q_exc, t0, t0_frac, coder_type, core_brate);
    arrow(); put1("voice_factors", voice_factors); put16("bwe_exc", bwe_exc, 640); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "tbe_celp_exc_offset")) case_tbe_celp_exc_offset();
        else if (!strcmp(argv[2], "tbe_celp_exc")) case_tbe_celp_exc();
        else if (!strcmp(argv[2], "calc_rc0_h")) case_calc_rc0_h();
        else if (!strcmp(argv[2], "interp_code_5over2")) case_interp_code_5over2();
        else if (!strcmp(argv[2], "non_linearity")) case_non_linearity();
        else if (!strcmp(argv[2], "prep_tbe_exc")) case_prep_tbe_exc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
