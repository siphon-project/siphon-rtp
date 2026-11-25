/* Function-level oracle for lib_com/codec_tcx_common.c: tcxGetNoiseFillingTilt,
 * tcxFormantEnhancement and tcxInvertWindowGrouping. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_tilt(void)
{
    static const Word16 frames[] = {80, 128, 160, 256, 320, 512, 640, 960};
    Word16 a[M + 1], tilt = 0x1234;
    Word16 l_frame = frames[random_range(0, 7)];
    Word16 mode = (Word16)(next_random() & 1);
    int style = random_range(0, 2);
    a[0] = (Word16)(4096 << random_range(0, 2));
    for (int k = 1; k <= M; k++) a[k] = (Word16)(style == 2 ? random16() : random_range(-12000 / k - 2000, 12000 / k + 2000));
    Carry = (Flag)(next_random() & 1);
    put16("a", a, M + 1); put1("l_frame", l_frame); put1("mode", mode); put1("carry_in", Carry);
    Word16 first = tcxGetNoiseFillingTilt(a, M, l_frame, mode, &tilt);
    arrow(); put1("first", first); put1("tilt", tilt); put1("carry", Carry); end_line();
}

static void case_formant(void)
{
    static const Word16 frames[] = {256, 320, 512, 640, 960};
    static Word32 spectrum[1400];
    Word16 xn_buf[1400], g[FDNS_NPTS], ge[FDNS_NPTS];
    Word16 l_frame = frames[random_range(0, 4)];
    Word16 l_frame_tcx = (Word16)(l_frame + (next_random() & 1 ? 0 : random_range(0, 3) * 80));
    Word16 spectrum_e = (Word16)random_range(0, 12);
    int shape = random_range(0, 3);
    Word16 base_e = (Word16)random_range(-3, 5);
    for (int i = 0; i < FDNS_NPTS; i++) {
        g[i] = (Word16)random_range(16384, 32767);
        /* a smooth envelope with peaks (the case that interpolates), or noise on the exponent */
        ge[i] = (Word16)(shape == 0 ? random_range(-4, 8) : base_e + ((i % 9 == 4) ? 2 : random_range(0, 1)));
    }
    for (int i = 0; i < l_frame_tcx; i++) spectrum[i] = random32() >> random_range(0, 16);
    memset(xn_buf, 0x55, sizeof(xn_buf));
    put1("l_frame", l_frame); put1("l_frame_tcx", l_frame_tcx); put1("spectrum_e", spectrum_e);
    put16("g", g, FDNS_NPTS); put16("ge", ge, FDNS_NPTS); put32("spectrum", spectrum, l_frame_tcx);
    tcxFormantEnhancement(xn_buf, g, ge, spectrum, &spectrum_e, l_frame, l_frame_tcx);
    arrow(); put32("spectrum", spectrum, l_frame_tcx); put1("spectrum_e", spectrum_e); put16("xn_buf", xn_buf, FDNS_NPTS); end_line();
}

static void case_window_grouping(void)
{
    static const Word16 frames[] = {64, 128, 160, 256, 320, 512, 640};
    static const Word16 modes[] = {FULL_OVERLAP, MIN_OVERLAP, HALF_OVERLAP};
    static Word32 spectrum[700], xn_buf[700];
    TCX_config *cfg = calloc(1, sizeof(TCX_config));
    Word16 l_frame = frames[random_range(0, 6)];
    Word16 l_spec = (Word16)(next_random() % 3 ? random_range(16, l_frame / 2 + 8) * 2 : l_frame + 2 * random_range(0, 20));
    if (l_spec > l_frame + 40) l_spec = l_frame;
    Word8 use_tns = (Word8)(next_random() & 1);
    Word16 last_core = (Word16)(next_random() & 1 ? ACELP_CORE : TCX_20_CORE);
    Word16 index = (Word16)random_range(0, 1), frame_cnt = (Word16)random_range(0, 3), bfi = (Word16)(next_random() % 4 == 0);
    cfg->tcx_last_overlap_mode = modes[random_range(0, 2)];
    cfg->tcx_curr_overlap_mode = modes[random_range(0, 2)];
    cfg->fIsTNSAllowed = (Word8)(next_random() % 4 != 0);
    cfg->tnsConfig[0][0].iFilterBorders[0] = l_spec;
    for (int i = 0; i < 700; i++) { spectrum[i] = random32(); xn_buf[i] = 0x55555555; }
    put1("l_frame", l_frame); put1("l_spec", l_spec); put1("use_tns", use_tns); put1("last_core", last_core); put1("index", index);
    put1("frame_cnt", frame_cnt); put1("bfi", bfi); put1("last_mode", cfg->tcx_last_overlap_mode); put1("curr_mode", cfg->tcx_curr_overlap_mode);
    put1("tns_allowed", cfg->fIsTNSAllowed); put32("spectrum", spectrum, l_frame);
    tcxInvertWindowGrouping(cfg, xn_buf, spectrum, l_frame, use_tns, last_core, index, frame_cnt, bfi);
    arrow(); put32("spectrum", spectrum, l_frame); put32("xn_buf", xn_buf, l_frame); put1("last_mode", cfg->tcx_last_overlap_mode); end_line();
    free(cfg);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "tcxGetNoiseFillingTilt")) case_tilt();
        else if (!strcmp(argv[2], "tcxFormantEnhancement")) case_formant();
        else if (!strcmp(argv[2], "tcxInvertWindowGrouping")) case_window_grouping();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
