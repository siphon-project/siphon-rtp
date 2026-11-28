/* Function-level oracle for lib_com/swb_bwe_com_fx.c (the WB BWE decoder helpers). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 coder_types[] = {INACTIVE, UNVOICED, VOICED, GENERIC, TRANSITION, AUDIO, LR_MDCT};

static Word16 random_coder_type(void) { return coder_types[next_random() % 7]; }

/* A spectrum: a random walk of a random magnitude, sometimes plain edge values, sometimes silent. */
static void random_spectrum(Word16 *x, int n)
{
    int kind = next_random() % 8;
    if (kind == 0) { for (int i = 0; i < n; i++) x[i] = 0; return; }
    if (kind == 1) { for (int i = 0; i < n; i++) x[i] = random16(); return; }
    random_signal(x, n, 1 << random_range(4, 15));
    for (int i = 0; i < n; i++) if (next_random() & 1) x[i] = (Word16)-x[i];
}

static void case_wb_bwe_gain_pred(void)
{
    Word16 freq[L_FRAME16k], fenv[2] = {-1, -1}, voice[4], pitch[4];
    random_spectrum(freq, L_FRAME16k);
    /* A falling spectrum (the high band 8x and more below 4-6 kHz) reaches the envelope-variation
     * branch, which flat spectra never do. */
    if (next_random() % 3 == 0) {
        int shift = random_range(3, 8);
        for (int i = 192; i < L_FRAME16k; i++) freq[i] = (Word16)(freq[i] >> shift);
    }
    Word16 coder_type = random_coder_type(), prev_coder_type = random_coder_type();
    Word16 prev_fenv = (Word16)random_range(0, 4000);
    for (int i = 0; i < 4; i++) voice[i] = (Word16)random_range(0, 32767);
    for (int i = 0; i < 4; i++) pitch[i] = (Word16)random_range(34 * 64, 231 * 64);
    static const Word32 brates[] = {ACELP_7k20, ACELP_8k00, ACELP_9k60, ACELP_13k20, 0};
    Word32 last_core_brate = brates[next_random() % 5];
    Word16 last_ener = (Word16)random_range(0, 4000);
    /* The decoder's spectrum sits at Q_syn with a few bits of headroom; mostly pair a loud
     * spectrum with a low Q so the envelope lands in a non-trivial Q3 range. */
    Word16 q_syn = (Word16)(next_random() % 4 ? random_range(-2, 3) : random_range(-2, 10));
    Word16 last_extl = (Word16)(next_random() & 1 ? WB_BWE : -1);
    Word16 tilt = (Word16)(next_random() & 1 ? random_range(0, 127) : random_range(0, 32767));
    put16("freq", freq, L_FRAME16k); put1("coder_type", coder_type); put1("prev_coder_type", prev_coder_type);
    put1("prev_fenv", prev_fenv); put16("voice", voice, 4); put16("pitch", pitch, 4);
    put1("last_core_brate", last_core_brate); put1("last_ener", last_ener); put1("q_syn", q_syn);
    put1("last_extl", last_extl); put1("tilt", tilt);
    Word16 mode = WB_BWE_gain_pred_fx(fenv, freq, coder_type, prev_coder_type, prev_fenv, voice, pitch,
                                      last_core_brate, last_ener, q_syn, last_extl, tilt);
    arrow(); put1("mode", mode); put16("fenv", fenv, 2); end_line();
}

static void case_calc_normal_length(void)
{
    Word16 sp[256];
    random_spectrum(sp, 256);
    Word16 core = (Word16)(next_random() & 1 ? ACELP_CORE : HQ_CORE);
    Word16 mode = (Word16)random_range(0, 4);
    static const Word16 extls[] = {WB_BWE, SWB_BWE, FB_BWE, -1, SWB_TBE};
    Word16 extl = extls[next_random() % 5];
    Word16 prev = (Word16)random_range(0, 64), norm = -1;
    Word16 q_syn = (Word16)random_range(-2, 10);
    put16("sp", sp, 256); put1("core", core); put1("mode", mode); put1("extl", extl);
    put1("prev", prev); put1("q_syn", q_syn);
    calc_normal_length_fx(core, sp, mode, extl, &norm, &prev, q_syn);
    arrow(); put1("norm", norm); put1("prev", prev); end_line();
}

static void case_calc_tilt_bwe(void)
{
    static const Word16 lengths[] = {L_FRAME, L_FRAME16k, L_FRAME32k};
    Word16 sp[L_FRAME32k];
    Word16 n = lengths[next_random() % 3];
    int kind = next_random() % 4;
    if (kind == 0) { /* full-scale blocks: the energy accumulation overflows */
        for (int i = 0; i < n; i++) sp[i] = (Word16)((next_random() & 1) ? 32767 : -32768);
        for (int i = 0; i < n; i++) if (next_random() % 8 == 0) sp[i] = (Word16)random_range(-30000, 30000);
    } else random_spectrum(sp, n);
    Word16 exp_sp = (Word16)random_range(-2, 10);
    put16("sp", sp, n); put1("exp_sp", exp_sp);
    Word32 tilt = calc_tilt_bwe_fx(sp, exp_sp, n);
    arrow(); put1("tilt", tilt); end_line();
}

static void case_calc_norm_envelop(void)
{
    Word16 signal[L_FRAME48k];
    Word32 envelope[L_FRAME48k];
    int swb = next_random() & 1;
    Word16 flength = (Word16)(swb ? L_FRAME32k - 80 : L_FRAME16k);
    Word16 offset = (Word16)(swb && (next_random() & 1) ? 80 : 0);
    Word16 norm = (Word16)random_range(1, 64);
    random_spectrum(signal, flength + offset);
    for (int i = 0; i < flength + offset; i++) envelope[i] = -1;
    put16("signal", signal, flength + offset); put1("norm", norm); put1("flength", flength); put1("offset", offset);
    calc_norm_envelop_fx(signal, envelope, norm, flength, offset);
    arrow(); put32("envelope", envelope, flength + offset); end_line();
}

/* Three consecutive frames through one memory: prev_Energy, prev_WB_fenv, prev_L_wb_norm, Seed and
 * prev_flag carry from frame to frame. */
static void case_wb_bwe_decoding(void)
{
    /* One loudness for all three frames, and a previous energy near the frames' own, so the
     * envelope smoothing's energy-ratio windows are reached. */
    int level = 1 << random_range(4, 15);
    Word32 prev_energy = (next_random() % 4) ? random_range(level, level * 40) : random_range(0, 1 << 20);
    Word16 prev_fenv[2] = {(Word16)random_range(0, 4000), (Word16)random_range(0, 4000)};
    Word16 prev_norm = (Word16)random_range(0, 64), seed = random16(), prev_flag = (Word16)random_range(0, 1);
    Word16 prev_coder_type = random_coder_type();
    Word16 q_syn = (Word16)random_range(-1, 8);
    static const Word32 brates[] = {ACELP_7k20, ACELP_8k00, ACELP_9k60, ACELP_13k20};
    Word32 total_brate = brates[next_random() % 4];
    put1("prev_energy", prev_energy); put16("prev_fenv", prev_fenv, 2); put1("prev_norm", prev_norm);
    put1("seed", seed); put1("prev_flag", prev_flag); put1("total_brate", total_brate);
    Word16 freq[3][L_FRAME16k], fenv[3][2], mode[3], last_extl[3], coder_type[3], prev_ct[3];
    for (int f = 0; f < 3; f++) {
        if (next_random() % 4) {
            random_signal(freq[f], L_FRAME16k, level);
            for (int i = 0; i < L_FRAME16k; i++) if (next_random() & 1) freq[f][i] = (Word16)-freq[f][i];
        } else random_spectrum(freq[f], L_FRAME16k);
        fenv[f][0] = (Word16)random_range(0, 4000);
        fenv[f][1] = (Word16)(next_random() & 1 ? fenv[f][0] : random_range(0, 4000));
        mode[f] = (Word16)(next_random() % 3 ? NORMAL : random_range(0, 4));
        last_extl[f] = (Word16)(next_random() % 4 ? WB_BWE : -1);
        coder_type[f] = random_coder_type();
        prev_ct[f] = f ? coder_type[f - 1] : prev_coder_type;
        char name[16];
        sprintf(name, "freq%d", f); put16(name, freq[f], L_FRAME16k);
        sprintf(name, "fenv%d", f); put16(name, fenv[f], 2);
        sprintf(name, "mode%d", f); put1(name, mode[f]);
        sprintf(name, "last_extl%d", f); put1(name, last_extl[f]);
        sprintf(name, "coder_type%d", f); put1(name, coder_type[f]);
        sprintf(name, "prev_ct%d", f); put1(name, prev_ct[f]);
    }
    put1("q_syn", q_syn);
    arrow();
    for (int f = 0; f < 3; f++) {
        Word32 signal[L_FRAME16k];
        Word16 q_hb = -99;
        for (int i = 0; i < L_FRAME16k; i++) signal[i] = 12345;
        WB_BWE_decoding_fx(freq[f], fenv[f], signal, L_FRAME16k, mode[f], last_extl[f], &prev_energy, prev_fenv,
                           &prev_norm, WB_BWE, coder_type[f], total_brate, &seed, &prev_flag, prev_ct[f], q_syn,
                           &q_hb);
        char name[16];
        sprintf(name, "signal%d", f); put32(name, signal, L_FRAME16k);
        sprintf(name, "fenv%d", f); put16(name, fenv[f], 2);
        sprintf(name, "q_hb%d", f); put1(name, q_hb);
        sprintf(name, "prev_energy%d", f); put1(name, prev_energy);
        sprintf(name, "prev_fenv%d", f); put16(name, prev_fenv, 2);
        sprintf(name, "prev_norm%d", f); put1(name, prev_norm);
        sprintf(name, "seed%d", f); put1(name, seed);
        sprintf(name, "prev_flag%d", f); put1(name, prev_flag);
    }
    end_line();
}

static void case_save_old_syn(void)
{
    Word16 syn[L_FRAME16k], old_syn[L_FRAME16k], mem[34];
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 fac = (Word16)(l_frame == L_FRAME ? PREEMPH_FAC : PREEMPH_FAC_16k);
    Word16 tmps = (Word16)(l_frame == L_FRAME ? 28 : 34);
    random_spectrum(syn, l_frame);
    random_signal(mem, tmps, 1 << random_range(4, 15));
    Word16 mem_deemph = random16();
    put16("syn", syn, l_frame); put16("mem", mem, tmps); put1("fac", fac); put1("mem_deemph", mem_deemph);
    save_old_syn_fx(l_frame, syn, old_syn, mem, fac, &mem_deemph);
    arrow(); put16("old_syn", old_syn, l_frame); put16("mem", mem, tmps); put1("mem_deemph", mem_deemph);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "wb_bwe_gain_pred")) case_wb_bwe_gain_pred();
        else if (!strcmp(argv[2], "calc_normal_length")) case_calc_normal_length();
        else if (!strcmp(argv[2], "calc_tilt_bwe")) case_calc_tilt_bwe();
        else if (!strcmp(argv[2], "calc_norm_envelop")) case_calc_norm_envelop();
        else if (!strcmp(argv[2], "wb_bwe_decoding")) case_wb_bwe_decoding();
        else if (!strcmp(argv[2], "save_old_syn")) case_save_old_syn();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
