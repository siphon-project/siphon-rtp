/* Function-level oracle for lib_com/tcx_ltp.c (tcx_ltp_post, tcx_ltp_synth_filter, tcx_ltp_get_zir). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "../../c-code/lib_com/tcx_ltp.c"

/* The pitch resolution each tcxLtpFilters entry is tabulated for (12.8, 16, 25.6 kHz cores). */
static Word16 filter_pitres(int idx) { return idx >= 4 && idx < 8 ? 6 : 4; }

static void case_synth_filter(void)
{
    static const Word16 lengths[] = {40, 80, 160, 240};
    Word16 out[2 * 960], in[12 + 960 + 12];
    int filt_idx = random_range(0, 11);
    Word16 pitres = filter_pitres(filt_idx);
    Word16 length = next_random() & 1 ? lengths[next_random() % 4] : (Word16)random_range(1, 700);
    Word16 at = 960, in_at = 12;
    Word16 pitch_int = (Word16)random_range(20, 900);
    Word16 pitch_fr = (Word16)random_range(0, pitres - 1);
    Word16 gain = (Word16)(next_random() % 8 ? random_range(0, 20480) : random16());
    Word16 fade = (Word16)random_range(-1, 1);
    int with_zir = next_random() & 1;
    Word16 zir[960];
    random_signal(out, 2 * 960, next_random() & 1 ? 30000 : 3000);
    random_signal(in, 12 + 960 + 12, next_random() & 1 ? 30000 : 3000);
    random_signal(zir, length, 2000);
    put1("filt_idx", filt_idx); put1("pitres", pitres); put1("length", length); put1("pitch_int", pitch_int);
    put1("pitch_fr", pitch_fr); put1("gain", gain); put1("fade", fade); put1("with_zir", with_zir);
    put16("out", out, at + length); put16("in", in, in_at + length + 12); put16("zir", zir, length);
    tcx_ltp_synth_filter(out + at, in + in_at, length, pitch_int, pitch_fr, gain, pitres, with_zir ? zir : NULL,
                         fade, filt_idx);
    arrow(); put16("out", out, at + length); end_line();
}

static void case_get_zir(void)
{
    static const Word16 lengths[] = {40, 80, 160, 240};
    Word16 out[2 * 960], in[12 + 960 + 12], A[TCXLTP_LTP_ORDER + 1], zir[960 / 4];
    int filt_idx = random_range(0, 11);
    Word16 pitres = filter_pitres(filt_idx);
    Word16 length = lengths[next_random() % 4];
    Word16 at = 960 - TCXLTP_LTP_ORDER, in_at = 12 + 100 - TCXLTP_LTP_ORDER;
    Word16 pitch_int = (Word16)random_range(20, 900);
    Word16 pitch_fr = (Word16)random_range(0, pitres - 1);
    Word16 gain = (Word16)random_range(0, 20480);
    A[0] = 4096;
    for (int i = 1; i <= TCXLTP_LTP_ORDER; i++) {
        int span = 5000 * (TCXLTP_LTP_ORDER + 1 - i) / TCXLTP_LTP_ORDER;
        A[i] = (Word16)random_range(-span, span);
    }
    random_signal(out, 2 * 960, next_random() & 1 ? 30000 : 3000);
    random_signal(in, 12 + 960 + 12, next_random() & 1 ? 30000 : 3000);
    put1("filt_idx", filt_idx); put1("pitres", pitres); put1("length", length); put1("pitch_int", pitch_int);
    put1("pitch_fr", pitch_fr); put1("gain", gain); put16("A", A, TCXLTP_LTP_ORDER + 1);
    put16("out", out, at + TCXLTP_LTP_ORDER + 12); put16("in", in, in_at + TCXLTP_LTP_ORDER + 12);
    tcx_ltp_get_zir(zir, length, out + at, in + in_at, A, TCXLTP_LTP_ORDER, gain, pitch_int, pitch_fr, pitres, filt_idx);
    arrow(); put16("zir", zir, length); end_line();
}

static void case_get_lpc(void)
{
    static const Word16 lengths[] = {160, 256, 320, 512, 640, 960};
    Word16 x[960], A[TCXLTP_LTP_ORDER + 1];
    Word16 L = lengths[next_random() % 6];
    int kind = next_random() % 4;
    random_signal(x, L, kind == 0 ? 32767 : kind == 1 ? 3000 : kind == 2 ? 30 : 16000);
    if (next_random() % 16 == 0) memset(x, 0, sizeof(x));
    if (next_random() % 8 == 0) for (int i = 0; i < L; i++) x[i] = random16();
    put16("x", x, L); put1("L", L);
    tcx_ltp_get_lpc(x, L, A, TCXLTP_LTP_ORDER);
    arrow(); put16("A", A, TCXLTP_LTP_ORDER + 1); end_line();
}

/* Three consecutive frames through one post-filter state: ACELP frames (core 0, as every MODE1
 * frame calls it) and TCX frames at any output and core rate, parameter changes included. */
static void case_post(void)
{
    static const Word16 lengths[] = {160, 320, 640, 960};
    static const Word32 rates[] = {13200, 16400, 24400, 32000, 48000, 64000, 96000};
    static const Word16 cores[] = {256, 320, 512};
    int tcx = next_random() & 1;
    Word16 L_frame = lengths[next_random() % 4];
    Word16 L_frame_core = tcx ? cores[next_random() % 3] : (Word16)(next_random() & 1 ? 256 : 320);
    Word16 tcx_buf_len = (Word16)(L_frame / 80);
    Word16 pitres = L_frame_core == 320 ? 6 : 4;
    /* the largest output-rate lag that keeps the filter inside the L_frame-sample history */
    int pit_max = L_frame - 20;
    Word32 bitrate = tcx ? rates[next_random() % 7] : (next_random() & 1 ? 7200 : 8000);
    Word16 mem_in[12], mem_out[960], sig[960], tcx_buf[12];
    Word16 pitch_int_past = (Word16)random_range(29, pit_max), pitch_fr_past = (Word16)random_range(0, pitres - 1);
    Word16 gain_past = (Word16)(next_random() & 1 ? 0 : random_range(1, 13107));
    Word16 pitres_past = pitres;
    Word16 filt_idx_past = (Word16)((L_frame_core == 256 ? 0 : L_frame_core == 320 ? 4 : 8) + (L_frame == 160 ? 0 : L_frame == 320 ? 1 : L_frame == 640 ? 2 : 3));
    Word8 tcxltp_on = (Word8)(tcx ? (next_random() % 4 != 0) : 0);
    random_signal(mem_in, tcx_buf_len, 20000);
    random_signal(mem_out, L_frame, 20000);
    put1("tcx", tcx); put1("L_frame", L_frame); put1("L_frame_core", L_frame_core); put1("tcx_buf_len", tcx_buf_len);
    put1("pitres", pitres); put1("bitrate", bitrate); put1("tcxltp_on", tcxltp_on);
    put1("pitch_int_past", pitch_int_past); put1("pitch_fr_past", pitch_fr_past); put1("gain_past", gain_past);
    put1("filt_idx_past", filt_idx_past); put16("mem_in", mem_in, tcx_buf_len); put16("mem_out", mem_out, L_frame);
    Word16 sigs[3][960];
    for (int f = 0; f < 3; f++) {
        Word16 core = tcx ? (Word16)(next_random() % 4 != 0) : 0;
        /* MODE2's delay is the ACELP look-ahead at the output rate plus a shift, at least 24 */
        Word16 delay = (Word16)(tcx ? random_range(TCXLTP_LTP_ORDER, L_frame / 2) : 0);
        Word16 bfi = (Word16)((next_random() % 4) == 0);
        Word16 side_info_only = (Word16)((next_random() % 8) == 0);
        /* a core-rate lag that lands inside the history once rescaled to the output rate */
        Word16 pitch_int = (Word16)random_range(29, (pit_max * L_frame_core) / L_frame - 2), pitch_fr = (Word16)random_range(0, pitres - 1);
        Word16 gain = (Word16)(0x1400 * random_range(1, 4));
        Word16 damping = (Word16)(next_random() & 1 ? 16384 : random_range(0, 32767));
        if ((next_random() & 1) && pitch_int_past >= 29 && L_frame == L_frame_core) { /* repeat the previous parameters exactly */
            pitch_int = pitch_int_past; pitch_fr = pitch_fr_past;
        }
        if (bfi && (gain_past & 1) == 0) damping = 16384; /* the concealed gain then equals the past one */
        random_signal(sig, L_frame, next_random() & 1 ? 30000 : 3000);
        random_signal(tcx_buf, tcx_buf_len, 3000);
        char name[32];
#define PUT(n, v) do { sprintf(name, #n "%d", f); put1(name, v); } while (0)
        PUT(core, core); PUT(delay, delay); PUT(bfi, bfi); PUT(side_info_only, side_info_only); PUT(pitch_int, pitch_int);
        PUT(pitch_fr, pitch_fr); PUT(gain, gain); PUT(damping, damping);
        sprintf(name, "sig%d", f); put16(name, sig, L_frame);
        sprintf(name, "tcx_buf%d", f); put16(name, tcx_buf, tcx_buf_len);
        tcx_ltp_post(tcxltp_on, core, L_frame, L_frame_core, delay, sig, tcx_buf, tcx_buf_len, bfi, pitch_int, pitch_fr,
                     gain, &pitch_int_past, &pitch_fr_past, &gain_past, &filt_idx_past, pitres, &pitres_past, damping,
                     side_info_only, mem_in, mem_out, bitrate);
        memcpy(sigs[f], sig, sizeof(sig));
    }
    arrow();
    for (int f = 0; f < 3; f++) { char name[16]; sprintf(name, "sig%d", f); put16(name, sigs[f], L_frame); }
    put1("pitch_int_past", pitch_int_past); put1("pitch_fr_past", pitch_fr_past); put1("gain_past", gain_past);
    put1("filt_idx_past", filt_idx_past); put1("pitres_past", pitres_past);
    put16("mem_in", mem_in, tcx_buf_len); put16("mem_out", mem_out, L_frame);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "synth_filter")) case_synth_filter();
        else if (!strcmp(argv[2], "get_zir")) case_get_zir();
        else if (!strcmp(argv[2], "post")) case_post();
        else if (!strcmp(argv[2], "get_lpc")) case_get_lpc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
