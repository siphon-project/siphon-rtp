/* Function-level oracle for lib_com/tcx_utils.c (getInvFrameLen, init_TCX_config, InitTnsConfigs, the synthesis
 * windowing). Each sine window
 * the configuration points at is printed by content (length/2 pairs), NULL as an empty list. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_inv_frame_len(void)
{
    static const Word16 bases[] = {64, 75, 80, 90, 96, 100, 120};
    Word16 l = (Word16)(bases[next_random() % 7] << random_range(0, 3));
    put1("l", l);
    Word16 r = getInvFrameLen(l);
    arrow(); put1("r", r); end_line();
}

static void put_window(const char *name, const PWord16 *w, Word16 len)
{
    Word16 v[2 * 420];
    int n = w ? len / 2 : 0;
    for (int i = 0; i < n; i++) { v[2 * i] = w[i].v.re; v[2 * i + 1] = w[i].v.im; }
    put16(name, v, 2 * n);
}

static void case_init_tcx_config(void)
{
    static const Word32 core_rates[] = {12800, 16000, 25600, 32000};
    static const Word32 output_rates[] = {8000, 16000, 32000, 48000};
    Word32 sr = core_rates[next_random() % 4], fs = output_rates[next_random() % 4];
    Word16 l_frame = (Word16)(sr / 50), l_frame_tcx = (Word16)(fs / 50);
    Word16 fscale = sr2fscale(sr), fscale_fb = sr2fscale(fs);
    TCX_config *c = calloc(1, sizeof(TCX_config));
    put1("l_frame", l_frame); put1("fscale", fscale); put1("l_frame_tcx", l_frame_tcx); put1("fscale_fb", fscale_fb);
    init_TCX_config(c, l_frame, fscale, l_frame_tcx, fscale_fb);
    Word16 s[14] = {c->tcx_mdct_window_length, c->tcx_mdct_window_delay, c->tcx_mdct_window_half_length,
                    c->tcx_mdct_window_min_length, c->tcx_mdct_window_trans_length, c->tcx5Size,
                    c->tcx_mdct_window_lengthFB, c->tcx_mdct_window_delayFB, c->tcx_mdct_window_half_lengthFB,
                    c->tcx_mdct_window_min_lengthFB, c->tcx_mdct_window_trans_lengthFB, c->tcx5SizeFB, 0, 0};
    arrow(); put16("lengths", s, 12);
    put_window("w", c->tcx_mdct_window, c->tcx_mdct_window_length);
    put_window("w_half", c->tcx_mdct_window_half, c->tcx_mdct_window_half_length);
    put_window("w_min", c->tcx_mdct_window_minimum, c->tcx_mdct_window_min_length);
    put_window("w_trans", c->tcx_mdct_window_trans, c->tcx_mdct_window_trans_length);
    put_window("w_fb", c->tcx_mdct_windowFB, c->tcx_mdct_window_lengthFB);
    put_window("w_half_fb", c->tcx_mdct_window_halfFB, c->tcx_mdct_window_half_lengthFB);
    put_window("w_min_fb", c->tcx_mdct_window_minimumFB, c->tcx_mdct_window_min_lengthFB);
    put_window("w_trans_fb", c->tcx_mdct_window_transFB, c->tcx_mdct_window_trans_lengthFB);
    put16("aldo1", c->tcx_aldo_window_1, 180);
    put_window("aldo1_trunc", c->tcx_aldo_window_1_trunc, 2 * 140);
    put_window("aldo2", c->tcx_aldo_window_2, 2 * 140);
    put16("aldo1_fb", c->tcx_aldo_window_1_FB, 270);
    put_window("aldo1_fb_trunc", c->tcx_aldo_window_1_FB_trunc, 2 * 210);
    put_window("aldo2_fb", c->tcx_aldo_window_2_FB, 2 * 210);
    end_line();
    free(c);
}

static int tns_table_id(const struct TnsParameters *p)
{
    const struct TnsParameters *tables[] = {tnsParametersIGF32kHz_LowBR, tnsParameters32kHz, tnsParameters32kHz_grouped,
                                            tnsParameters16kHz, tnsParameters16kHz_grouped, tnsParameters48kHz_grouped};
    for (int i = 0; i < 6; i++) if (p == tables[i]) return i;
    return -1;
}

/* InitTnsConfigs as open_decoder_LPD calls it: bwMode2fs[bwidth], getNumTcxCodedLines(bwidth), the
 * IGF stop frequency (0 without IGF) and the bit rate; all four configurations printed, the ones it
 * leaves alone included. */
static void case_init_tns_configs(void)
{
    static const Word32 rates[] = {8000, 16000, 32000, 48000};
    static const Word16 lines[] = {160, 320, 640, 960};
    static const Word32 brates[] = {9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};
    static const Word16 igf_stop[] = {0, 0, 9600, 14400, 16000, 20000};
    int bw = next_random() % 4;
    Word32 brate = brates[next_random() % 9];
    if (bw == 0) brate = brates[next_random() % 5]; /* narrowband exists only up to 24.4 kbit/s (the reference asserts the 16 kHz tables' start lines are under Nyquist) */
    Word16 igf = igf_stop[next_random() % 6];
    STnsConfig c[2][2];
    memset(c, 0, sizeof(c));
    for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) {
        c[i][j].maxOrder = random16(); c[i][j].nMaxFilters = random16(); c[i][j].pTnsParameters = NULL;
        for (int k = 0; k < 3; k++) c[i][j].iFilterBorders[k] = random16();
    }
    put1("sr", rates[bw]); put1("l_frame", lines[bw]); put1("igf_stop_freq", igf); put1("bitrate", brate);
    for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) {
        char name[32];
        sprintf(name, "in%d%d", i, j);
        Word16 v[5] = {c[i][j].maxOrder, c[i][j].nMaxFilters, c[i][j].iFilterBorders[0], c[i][j].iFilterBorders[1], c[i][j].iFilterBorders[2]};
        put16(name, v, 5);
    }
    InitTnsConfigs(rates[bw], lines[bw], c, igf, brate);
    arrow();
    for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) {
        char name[32];
        sprintf(name, "out%d%d", i, j);
        Word16 v[6] = {c[i][j].maxOrder, c[i][j].nMaxFilters, (Word16)tns_table_id(c[i][j].pTnsParameters),
                       c[i][j].iFilterBorders[0], c[i][j].iFilterBorders[1], c[i][j].iFilterBorders[2]};
        put16(name, v, 6);
    }
    end_line();
}

/* The two synthesis-windowing functions. The windows are random PWord16 slopes: the functions only
 * multiply by them. Every branch is drawn: after CNG, the ACELP and TCX rectangular transitions,
 * the normal window after ACELP, and the minimum / half / full overlaps after TCX, each with and
 * without fullband scaling. */
#define SIG_LEN 2048

static void synthesis_random_window(PWord16 *w, int n)
{
    for (int i = 0; i < n; i++) {
        w[i].v.re = (Word16)random_range(0, 32767);
        w[i].v.im = (Word16)random_range(0, 32767);
    }
}

static void synthesis_random_lpc(Word16 *a, int m)
{
    a[0] = 4096;
    for (int k = 1; k <= m; k++) a[k] = (Word16)random_range(-12000 / k - 2000, 12000 / k + 2000);
}

static void synthesis_put_window(const char *name, const PWord16 *w, int n)
{
    Word16 flat[2 * 512];
    for (int i = 0; i < n; i++) { flat[2 * i] = w[i].v.re; flat[2 * i + 1] = w[i].v.im; }
    put16(name, flat, 2 * n);
}

static void case_current_frame(void)
{
    static PWord16 window[512], window_half[512], window_min[512], window_trans[512];
    static Word16 signal[SIG_LEN], acelp_zir[512], old_syn[512], syn_overl[512], a_zir[M + 1];
    Word16 window_length = (Word16)(2 * random_range(16, 160));
    Word16 window_half_length = (Word16)(2 * random_range(1, window_length / 2));
    Word16 window_min_length = (Word16)(2 * random_range(1, window_half_length / 2));
    Word16 overlap = window_length / 2;
    Word16 acelp_mem_len = (Word16)random_range(overlap < 16 ? 16 - overlap : 0, overlap);
    int zir_low = 2 * acelp_mem_len > 64 ? 2 * acelp_mem_len : 64; /* the TDAC reads 2 * mem_len back */
    Word16 acelp_zir_len = (Word16)random_range(zir_low, zir_low > 240 ? zir_low + 40 : 240);
    Word16 left_rect = (Word16)random_range(0, 1);
    Word16 left_mode = (Word16)random_range(2, 4);
    Word16 last_core_bfi = (Word16)(next_random() & 1 ? ACELP_CORE : TCX_20_CORE);
    Word8 last_is_cng = (Word8)(next_random() % 3 == 0);
    static const Word16 scales[] = {640, 1280, 1920};
    Word16 fullband_scale = (Word16)(next_random() & 1 ? 0 : scales[next_random() % 3]);
    if (fullband_scale && last_is_cng == 1 && left_rect == 0) {
        /* The ZIR is upsampled from shl(acelp_zir_len, 9) / scale samples (saturating above 63).
         * Past a ratio of 3.96 lerp works in stages through the caller's tmp_buf and its last
         * stage reads one sample past what the previous one wrote: uninitialised stack, so only
         * the single-stage lengths (the real fullband ratios with an unsaturated length) are
         * compared. */
        acelp_zir_len = (Word16)random_range(M, 63);
    }
    synthesis_random_window(window, window_length / 2);
    synthesis_random_window(window_half, window_half_length / 2);
    synthesis_random_window(window_min, window_min_length / 2);
    synthesis_random_window(window_trans, acelp_mem_len > 0 ? acelp_mem_len : 1);
    int mag = next_random() & 1 ? 32767 : random_range(10, 4000);
    random_signal(signal, SIG_LEN, mag);
    random_signal(acelp_zir, 512, mag);
    random_signal(old_syn, 512, mag);
    random_signal(syn_overl, 512, mag);
    synthesis_random_lpc(a_zir, M);

    synthesis_put_window("window", window, window_length / 2); synthesis_put_window("window_half", window_half, window_half_length / 2);
    synthesis_put_window("window_min", window_min, window_min_length / 2);
    synthesis_put_window("window_trans", window_trans, acelp_mem_len > 0 ? acelp_mem_len : 1);
    put1("window_length", window_length); put1("window_half_length", window_half_length);
    put1("window_min_length", window_min_length); put1("left_rect", left_rect); put1("left_mode", left_mode);
    put16("signal", signal, SIG_LEN); put16("acelp_zir", acelp_zir, 512); put16("old_syn", old_syn, 512);
    put16("syn_overl", syn_overl, 512); put16("a_zir", a_zir, M + 1); put1("acelp_zir_len", acelp_zir_len);
    put1("acelp_mem_len", acelp_mem_len); put1("last_core_bfi", last_core_bfi); put1("last_is_cng", last_is_cng);
    put1("fullband_scale", fullband_scale);
    tcx_windowing_synthesis_current_frame(signal, window, window_half, window_min, window_length, window_half_length,
                                          window_min_length, left_rect, left_mode, acelp_zir, old_syn, syn_overl, a_zir,
                                          window_trans, acelp_zir_len, acelp_mem_len, last_core_bfi, last_is_cng,
                                          fullband_scale);
    arrow(); put16("signal", signal, SIG_LEN); put16("acelp_zir", acelp_zir, 512); end_line();
}

static void case_past_frame(void)
{
    static PWord16 window[512], window_half[512], window_min[512];
    static Word16 signal[SIG_LEN];
    Word16 window_length = (Word16)(2 * random_range(16, 320));
    Word16 window_half_length = (Word16)(2 * random_range(1, window_length / 2));
    Word16 window_min_length = (Word16)(2 * random_range(1, window_half_length / 2));
    Word16 right_mode = (Word16)random_range(2, 4);
    synthesis_random_window(window, window_length / 2);
    synthesis_random_window(window_half, window_half_length / 2);
    synthesis_random_window(window_min, window_min_length / 2);
    random_signal(signal, window_length, next_random() & 1 ? 32767 : random_range(10, 4000));
    synthesis_put_window("window", window, window_length / 2); synthesis_put_window("window_half", window_half, window_half_length / 2);
    synthesis_put_window("window_min", window_min, window_min_length / 2); put1("window_length", window_length);
    put1("window_half_length", window_half_length); put1("window_min_length", window_min_length);
    put1("right_mode", right_mode); put16("signal", signal, window_length);
    tcx_windowing_synthesis_past_frame(signal, window, window_half, window_min, window_length, window_half_length,
                                       window_min_length, right_mode);
    arrow(); put16("signal", signal, window_length); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "inv_frame_len")) case_inv_frame_len();
        else if (!strcmp(argv[2], "init_tcx_config")) case_init_tcx_config();
        else if (!strcmp(argv[2], "init_tns_configs")) case_init_tns_configs();
        else if (!strcmp(argv[2], "current_frame")) case_current_frame();
        else if (!strcmp(argv[2], "past_frame")) case_past_frame();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
