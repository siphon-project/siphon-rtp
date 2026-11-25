/* Function-level oracle for the MODE2 ACELP parameter decoders: limit_T0_voiced (lib_com/limit_t0_fx.c),
 * Mode2_pit_decode / Mode2_abs_pit_dec / Mode2_delta_pit_dec (lib_dec/pit_dec.c), calc_gain_inov
 * (lib_com/gain_inov.c), decode_acelp_gains / d_gain_pred (lib_dec/d_gain2p.c, which reaches its static
 * Mode2_gain_dec_mless, gain_dec_uv, gain_dec_gacelp_uv, calc_gcode0, calc_gain_code), gaus_L2_dec
 * (lib_dec/gaus_dec_fx.c), E_UTIL_voice_factor (lib_com/est_tilt_fx.c), E_UTIL_enhancer
 * (lib_com/enhancer_fx.c, through lib_com/phase_dispersion.c). */
#include "harness.h"
#include "cnst_fx.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void random_lpc(Word16 *a, int m)
{
    int kind = next_random() % 8;
    a[0] = 4096;
    for (int k = 1; k <= m; k++) {
        if (kind == 5) a[k] = random16();
        else a[k] = (Word16)random_range(-12000 / k - 2000, 12000 / k + 2000);
    }
}

/* A Q9 algebraic code: a few signed pulses, as the decoder's fixed codebooks make. */
static void random_code(Word16 *code, int lg)
{
    memset(code, 0, lg * sizeof(Word16));
    if (next_random() % 8 == 0) { random_signal(code, lg, 512 * random_range(1, 8)); return; }
    int pulses = random_range(1, 24);
    for (int p = 0; p < pulses; p++) code[next_random() % lg] += (Word16)((next_random() & 1 ? 512 : -512) * random_range(1, 3));
}

static const Word16 ltp_modes[] = {0, 1, 2, 3, 4, 8, 9};

static void case_limit_t0_voiced(void)
{
    static const Word16 res_table[] = {2, 3, 4, 6};
    Word16 res = res_table[next_random() % 4];
    Word16 nbits = (Word16)random_range(4, 6);
    Word16 pit_min = (next_random() & 1) ? PIT_MIN_12k8 : PIT_MIN_16k;
    Word16 pit_max = (pit_min == PIT_MIN_16k) ? PIT_MAX_16k : PIT_MAX_12k8;
    Word16 t0 = (Word16)random_range(pit_min - 4, pit_max + 4);
    Word16 t0_res = (Word16)random_range(1, 6);
    Word16 t0_frac = (Word16)random_range(0, t0_res - 1);
    Word16 t0_min, t0_min_frac, t0_max, t0_max_frac;
    put1("nbits", nbits); put1("res", res); put1("t0", t0); put1("t0_frac", t0_frac); put1("t0_res", t0_res);
    put1("pit_min", pit_min); put1("pit_max", pit_max);
    limit_T0_voiced(nbits, res, t0, t0_frac, t0_res, &t0_min, &t0_min_frac, &t0_max, &t0_max_frac, pit_min, pit_max);
    arrow(); put1("t0_min", t0_min); put1("t0_min_frac", t0_min_frac); put1("t0_max", t0_max); put1("t0_max_frac", t0_max_frac);
    end_line();
}

/* One frame of pitch decoding, subframe after subframe, the T0 window carried between them. */
static void case_pitch_frame(void)
{
    Word16 mode = ltp_modes[next_random() % 7];
    Word32 sr_core = (next_random() & 1) ? 12800 : 16000;
    Word16 pit_min, pit_fr1, pit_fr1b, pit_fr2, pit_max;
    Word16 pit_res_max = initPitchLagParameters(sr_core, &pit_min, &pit_fr1, &pit_fr1b, &pit_fr2, &pit_max);
    int nsub = (sr_core == 16000) ? 5 : 4;
    if (next_random() % 5 == 0) nsub = (nsub == 5) ? 4 : 5;
    Word16 indices[8], bits_of[8], T0 = 0, T0_frac = 0, T0_res = 1, T0_min = 0, T0_min_frac = 0, T0_max = 0, T0_max_frac = 0;
    Word16 pitch_hi[8], pitch_lo[8], t0s[8], fracs[8], ress[8], mins[8], max_[8], minfs[8], maxfs[8];
    int used = 0;
    for (int i = 0; i < nsub; i++) {
        int bits = ACELP_LTP_BITS_SFR[mode][i];
        bits_of[i] = (Word16)bits;
        if (mode == 0) { indices[used++] = 0; continue; } /* coder_type 0 reads no index */
        indices[used++] = (Word16)random_range(0, (1 << bits) - 1);
    }
    put1("mode", mode); put1("sr_core", sr_core); put1("nsub", nsub); put16("indices", indices, used);
    Word16 *prm = indices;
    for (int i = 0; i < nsub; i++) {
        Word32 pitch = Mode2_pit_decode(mode, (Word16)(i * L_SUBFR), L_SUBFR, &prm, &T0, &T0_frac, &T0_res, &T0_min, &T0_min_frac,
                                        &T0_max, &T0_max_frac, pit_min, pit_fr1, pit_fr1b, pit_fr2, pit_max, pit_res_max);
        pitch_hi[i] = (Word16)(pitch >> 16); pitch_lo[i] = (Word16)(pitch & 0xffff);
        t0s[i] = T0; fracs[i] = T0_frac; ress[i] = T0_res; mins[i] = T0_min; minfs[i] = T0_min_frac; max_[i] = T0_max; maxfs[i] = T0_max_frac;
    }
    arrow(); put16("pitch_hi", pitch_hi, nsub); put16("pitch_lo", pitch_lo, nsub); put16("t0", t0s, nsub); put16("frac", fracs, nsub);
    put16("res", ress, nsub); put16("t0_min", mins, nsub); put16("t0_min_frac", minfs, nsub); put16("t0_max", max_, nsub);
    put16("t0_max_frac", maxfs, nsub); put1("consumed", (long long)(prm - indices));
    end_line();
}

static void case_gains(void)
{
    static const Word16 modes[] = {1, 2, 3, 6, 7};
    static const Word16 mode_bits[] = {5, 6, 7, 6, 7};
    int k = next_random() % 5;
    Word16 gains_mode = modes[k];
    Word16 index = (Word16)random_range(0, (1 << mode_bits[k]) - 1);
    static const Word16 lcodes[] = {64, 64, 64, 64, 80, 40, 32};
    Word16 lcode = lcodes[next_random() % 7];
    Word16 code[80], code2[80];
    random_code(code, lcode); random_code(code2, lcode);
    Word16 mean_ener = (Word16)random_range(-6000, 16000);
    Word16 past_gpit = random16(), gain_pit = random16(), gain_inov = random16();
    Word32 past_gcode = random32(), gain_code = random32(), gain_code2 = random32();
    Word16 one[2] = {index, 1234}, *prm = one;
    put16("code", code, lcode); put16("code2", code2, lcode); put1("lcode", lcode); put1("gains_mode", gains_mode);
    put1("mean_ener", mean_ener); put1("index", index); put1("past_gpit", past_gpit); put1("past_gcode", past_gcode);
    put1("gain_pit", gain_pit); put1("gain_code", gain_code); put1("gain_inov", gain_inov); put1("gain_code2", gain_code2);
    decode_acelp_gains(code, gains_mode, mean_ener, &gain_pit, &gain_code, &prm, &past_gpit, &past_gcode, &gain_inov, lcode, code2, &gain_code2);
    arrow(); put1("gain_pit", gain_pit); put1("gain_code", gain_code); put1("past_gpit", past_gpit); put1("past_gcode", past_gcode);
    put1("gain_inov", gain_inov); put1("gain_code2", gain_code2); put1("consumed", (long long)(prm - one));
    end_line();
}

static void case_gain_pred(void)
{
    Word16 nrg_mode = (Word16)random_range(0, 4);
    Word16 bits = (nrg_mode == 1) ? 3 : 4;
    Word16 index = (Word16)random_range(0, (1 << bits) - 1);
    Word16 es_pred = random16();
    Word16 one[2] = {index, 99}, *prm = one;
    put1("nrg_mode", nrg_mode); put1("index", index); put1("es_pred", es_pred);
    d_gain_pred(nrg_mode, &es_pred, &prm);
    arrow(); put1("es_pred", es_pred); put1("consumed", (long long)(prm - one)); end_line();
}

static void case_gain_inov(void)
{
    static const Word16 lcodes[] = {32, 40, 64, 80};
    Word16 lcode = lcodes[next_random() % 4];
    Word16 code[80];
    random_code(code, lcode);
    Word32 dotp = -1; Word16 dotp_e = -1;
    int with_out = next_random() % 4 != 0;
    put16("code", code, lcode); put1("lcode", lcode); put1("with_out", with_out);
    Word32 r = with_out ? calc_gain_inov(code, lcode, &dotp, &dotp_e) : calc_gain_inov(code, lcode, NULL, NULL);
    arrow(); put1("r", r); put1("dotp", dotp); put1("dotp_e", dotp_e); end_line();
}

static void case_gaus_l2(void)
{
    Word16 code[L_SUBFR], a[17];
    random_lpc(a, 16);
    Word16 tilt = (Word16)random_range(0, 16384);
    Word16 formant_enh = (next_random() & 1) ? 24576 : 26214;
    Word16 seed = random16();
    for (int i = 0; i < L_SUBFR; i++) code[i] = 5555;
    put1("tilt", tilt); put16("a", a, 17); put1("formant_enh", formant_enh); put1("seed", seed);
    gaus_L2_dec(code, tilt, a, formant_enh, &seed);
    arrow(); put16("code", code, L_SUBFR); put1("seed", seed); end_line();
}

static void case_voice_factor(void)
{
    static const int magnitudes[] = {50, 600, 4000, 16000, 32767};
    Word16 exc[5 * L_SUBFR], code[L_SUBFR];
    random_signal(exc, 5 * L_SUBFR, magnitudes[next_random() % 5]);
    random_code(code, L_SUBFR);
    Word16 i_subfr = (Word16)(L_SUBFR * random_range(0, 4));
    Word16 gain_pit = (Word16)(next_random() % 6 ? random_range(0, 19661) : random16());
    Word32 gain_code = next_random() % 6 ? L_shr((Word32)random_range(0, 0x7fffffff), (Word16)random_range(0, 30)) : random32();
    Word16 flag_tilt = (Word16)random_range(0, 2), q_new = (Word16)random_range(-1, 12);
    Word16 shift = (next_random() % 4 == 0) ? (Word16)random_range(1, 3) : 0;
    Word16 voice_fac = -99, tilt_code = -99;
    put16("exc", exc, 5 * L_SUBFR); put1("i_subfr", i_subfr); put16("code", code, L_SUBFR); put1("gain_pit", gain_pit);
    put1("gain_code", gain_code); put1("flag_tilt", flag_tilt); put1("q_new", q_new); put1("shift", shift);
    E_UTIL_voice_factor(exc, i_subfr, code, gain_pit, gain_code, &voice_fac, &tilt_code, L_SUBFR, flag_tilt, q_new, shift);
    arrow(); put1("voice_fac", voice_fac); put1("tilt_code", tilt_code); end_line();
}

static void case_enhancer(void)
{
    static const Word16 coder_types[] = {0, 1, 2, 3, 4};
    static const int magnitudes[] = {600, 4000, 16000, 32767};
    Word16 code[L_SUBFR], exc2[L_SUBFR], prev_gain_pit[6], prev_state;
    random_code(code, L_SUBFR);
    random_signal(exc2, L_SUBFR, magnitudes[next_random() % 4]);
    for (int i = 0; i < 6; i++) prev_gain_pit[i] = (Word16)random_range(0, 20000);
    prev_state = (Word16)random_range(0, 2);
    Word16 voice_fac = (Word16)(next_random() % 8 ? random_range(-32768, 32767) : random16());
    Word16 stab_fac = (Word16)random_range(0, 32767);
    Word32 gain_code = random32() >> random_range(0, 20);
    if (gain_code < 0) gain_code = -gain_code - 1;
    Word16 gain_inov = (Word16)random_range(1, 32767);
    Word32 gc_threshold = random32() >> random_range(0, 20);
    if (gc_threshold < 0) gc_threshold = -gc_threshold - 1;
    Word16 gain_pit = (Word16)(next_random() % 6 ? random_range(0, 19661) : random16());
    if (next_random() % 5 == 0) { static const Word16 edges[] = {14745, 14746, 9829, 9830}; gain_pit = edges[next_random() % 4]; }
    Word32 prev_gain_code = random32() >> random_range(0, 20);
    if (prev_gain_code < 0) prev_gain_code = -prev_gain_code - 1;
    Word16 coder_type = coder_types[next_random() % 5], cdk_index = (Word16)random_range(0, 40);
    Word16 l_frame = (next_random() & 1) ? 256 : 320, q_new = (Word16)random_range(-1, 12);
    put1("voice_fac", voice_fac); put1("stab_fac", stab_fac); put1("gain_code", gain_code); put1("gain_inov", gain_inov);
    put1("gc_threshold", gc_threshold); put16("code", code, L_SUBFR); put16("exc2", exc2, L_SUBFR); put1("gain_pit", gain_pit);
    put1("prev_gain_code", prev_gain_code); put16("prev_gain_pit", prev_gain_pit, 6); put1("prev_state", prev_state);
    put1("coder_type", coder_type); put1("cdk_index", cdk_index); put1("l_frame", l_frame); put1("q_new", q_new);
    Word16 r = E_UTIL_enhancer(voice_fac, stab_fac, gain_code, gain_inov, &gc_threshold, code, exc2, gain_pit, &prev_gain_code,
                               prev_gain_pit, &prev_state, coder_type, cdk_index, L_SUBFR, l_frame, q_new);
    arrow(); put1("r", r); put1("gc_threshold", gc_threshold); put16("code", code, L_SUBFR); put16("exc2", exc2, L_SUBFR);
    put1("prev_gain_code", prev_gain_code); put16("prev_gain_pit", prev_gain_pit, 6); put1("prev_state", prev_state);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    struct { const char *name; void (*run)(void); } table[] = {
        {"limit_t0_voiced", case_limit_t0_voiced}, {"pitch_frame", case_pitch_frame}, {"gains", case_gains},
        {"gain_pred", case_gain_pred}, {"gain_inov", case_gain_inov}, {"gaus_l2", case_gaus_l2},
        {"voice_factor", case_voice_factor}, {"enhancer", case_enhancer},
    };
    void (*run)(void) = NULL;
    for (unsigned k = 0; k < sizeof(table) / sizeof(table[0]); k++) if (!strcmp(argv[2], table[k].name)) run = table[k].run;
    if (!run) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) run();
    return 0;
}
