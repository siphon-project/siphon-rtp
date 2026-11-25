/* Function-level oracle for lib_dec/waveadjust_fec_dec.c, the TCX waveform-adjustment concealment.
 *
 * The file is included, so its static functions can be driven. Signals are built the way the
 * decoder meets them: PCM history with a pitch (a pulse train through a smoothing filter plus
 * noise, pitch between 0.13 and 0.75 of the frame, as pitch_search_fx can return), spectra with
 * harmonic peaks, frame sizes of the TCX frames at 12.8 to 48 kHz (160, 320, 512, 640, 960), the
 * PCM history laid out as the tonal concealment lays it out (second last output 1.5 frames, last
 * output 1 frame before the end of the 1440 sample buffer, so the two overlap). */
#include <math.h>
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/waveadjust_fec_dec.c"

static const Word16 frame_sizes[] = {160, 320, 512, 640, 960};

static Word16 random_frame_size(void) { return frame_sizes[next_random() % 5]; }

/* a signal with period `pitch`: pulses through a two-pole smoother, plus noise */
static void random_voiced(Word16 *x, int n, int pitch, int amplitude)
{
    int y1 = 0, y2 = 0, noise = amplitude / (int)(2 + next_random() % 12);
    for (int i = 0; i < n; i++) {
        int pulse = (i % pitch == 0) ? amplitude : 0;
        int v = (pulse * 3 + y1 * 2 - y2 * 1) / 4 + random_range(-noise, noise);
        if (next_random() % 64 == 0) v = random_range(-amplitude, amplitude);
        y2 = y1; y1 = v;
        if (v > 32767) v = 32767;
        if (v < -32768) v = -32768;
        x[i] = (Word16)v;
    }
}

/* a few harmonics of the pitch with a little noise: strongly periodic, few zero crossings */
static void random_harmonic(Word16 *x, int n, int pitch, int amplitude)
{
    double phase = random_range(0, 628) / 100.0;
    int noise = amplitude / (int)(8 + next_random() % 32);
    for (int i = 0; i < n; i++) {
        double v = 0;
        for (int k = 1; k <= 4; k++) v += sin(phase + 6.283185307 * k * i / pitch) / k;
        x[i] = (Word16)(v * amplitude * 0.5 + random_range(-noise, noise));
    }
}

static void random_pcm(Word16 *x, int n, int pitch)
{
    static const int amplitudes[] = {200, 2000, 8000, 20000};
    int amplitude = amplitudes[next_random() % 4];
    int kind = next_random() % 10;
    if (kind == 0) random_signal(x, n, amplitude);
    else if (kind < 4) random_voiced(x, n, pitch, amplitude);
    else random_harmonic(x, n, pitch, amplitude);
}

static Word16 random_pitch(Word16 frame_size)
{
    int low = (0x80 + 34 * frame_size) >> 8, high = (2 + 3 * frame_size) >> 2;
    if (frame_size > 320) low = 2 * ((0x80 + 34 * (frame_size / 2)) >> 8);
    return (Word16)random_range(low, high);
}

/* a spectrum with harmonic peaks (the bins harmo_x reads) over a decaying floor */
static void random_spectrum(Word32 *x, int n, int pitch)
{
    int amplitude = 1 << random_range(8, 24);
    int floor_shift = (next_random() % 3 == 0) ? random_range(3, 10) : 0;
    for (int i = 0; i < n; i++) {
        int decay = 1 + (int)((long long)i * 8 / n);
        x[i] = (Word32)((long long)(random_range(-amplitude, amplitude)) / decay) >> floor_shift;
    }
    if (pitch > 0) {
        for (int k = 1; k < 9; k++) {
            int h = (2 * k * n) / pitch - 1;
            if (h >= 0 && h + 1 < n) { x[h] = (Word32)amplitude * random_range(2, 40); x[h + 1] = (Word32)amplitude * random_range(2, 40); }
        }
    }
    if (next_random() % 8 == 0) for (int i = 0; i < n; i++) x[i] = random32() >> random_range(0, 20);
}

static void random_plc(T_PLCInfo *p, Word16 frame_size)
{
    memset(p, 0, sizeof(*p));
    p->FrameSize = frame_size;
    p->Pitch_fx = (next_random() % 4) ? random_pitch(frame_size) : 0;
    p->T_bfi_fx = (Word8)(next_random() & 1);
    for (int i = 0; i < MAX_POST_LEN; i++) p->Transient[i] = (Word16)random_range(0, 2);
    for (int i = 0; i < DEC_STATE_LEN; i++) p->TCX_Tonality[i] = (Word16)random_range(0, 1);
    p->outx_new_n1_fx = random16();
    p->nsapp_gain_fx = (Word16)random_range(0, 32767);
    p->nsapp_gain_n_fx = (Word16)random_range(0, 32767);
    random_spectrum(p->data_reci2_fx, L_FRAME_MAX, p->Pitch_fx);
    p->data_reci2_scale = (Word16)random_range(-4, 12);
    random_signal(p->data_noise, L_FRAME_MAX, 8000);
    p->ener_mean_fx = (next_random() % 3) ? (Word32)random_range(40 * 256, 70 * 256) : random_range(0, 1 << 15);
    p->ener_fx = (next_random() % 3) ? (Word32)random_range(30 * 256, 80 * 256) : random32() >> random_range(8, 24);
    p->zp_fx = (Word16)random_range(0, frame_size / 2);
    p->recovery_gain = (Word16)random_range(0, 32767);
    p->step_concealgain_fx = (next_random() % 5) ? (Word16)random_range(0, 3000) : 0;
    p->concealment_method = (Word16)((next_random() % 5) ? TCX_NONTONAL : 1);
    p->subframe_fx = (Word16)((next_random() & 1) ? 0 : frame_size / 2);
    p->nbLostCmpt = (Word32)random_range(0, 7);
    p->seed = random16();
}

static void put_plc(const char *prefix, const T_PLCInfo *p)
{
    char name[64];
#define PUT1(field) snprintf(name, sizeof name, "%s" #field, prefix), put1(name, p->field)
#define PUT16(field, n) snprintf(name, sizeof name, "%s" #field, prefix), put16(name, p->field, n)
#define PUT32(field, n) snprintf(name, sizeof name, "%s" #field, prefix), put32(name, p->field, n)
    PUT1(FrameSize); PUT1(Pitch_fx); PUT1(T_bfi_fx); PUT16(Transient, MAX_POST_LEN); PUT16(TCX_Tonality, DEC_STATE_LEN);
    PUT1(outx_new_n1_fx); PUT1(nsapp_gain_fx); PUT1(nsapp_gain_n_fx); PUT32(data_reci2_fx, L_FRAME_MAX);
    PUT1(data_reci2_scale); PUT16(data_noise, L_FRAME_MAX); PUT1(ener_mean_fx); PUT1(ener_fx); PUT1(zp_fx);
    PUT1(recovery_gain); PUT1(step_concealgain_fx); PUT1(concealment_method); PUT1(subframe_fx);
    PUT1(nbLostCmpt); PUT1(seed);
}

static void case_update_x(void)
{
    T_PLCInfo p;
    Word16 frame_size = random_frame_size(), curr_mode = (Word16)((next_random() & 1) ? 1 : 2);
    Word16 bfi = (Word16)(next_random() & 1), tonality = (Word16)random_range(0, 1);
    Word16 scale = (Word16)random_range(-4, 12);
    Word32 invkoef[L_FRAME_MAX];
    random_plc(&p, frame_size);
    random_spectrum(invkoef, L_FRAME_MAX, random_pitch(frame_size));
    put_plc("p.", &p); put1("bfi", bfi); put1("curr_mode", curr_mode); put1("tonality", tonality);
    put32("invkoef", invkoef, L_FRAME_MAX); put1("scale", scale);
    concealment_update_x(bfi, curr_mode, tonality, invkoef, &scale, &p);
    arrow(); put_plc("p.", &p); end_line();
}

static void case_decode_fix(void)
{
    T_PLCInfo p;
    Word16 frame_size = random_frame_size(), curr_mode = (Word16)((next_random() & 1) ? 1 : 2);
    Word16 scale = 77;
    Word32 invkoef[L_FRAME_MAX];
    random_plc(&p, frame_size);
    for (int i = 0; i < L_FRAME_MAX; i++) invkoef[i] = -7;
    put_plc("p.", &p); put1("curr_mode", curr_mode);
    concealment_decode_fix(curr_mode, invkoef, &scale, &p);
    arrow(); put_plc("p.", &p); put32("invkoef", invkoef, L_FRAME_MAX); put1("scale", scale); end_line();
}

static void case_pitch_search(void)
{
    Word16 frame_size = random_frame_size(), curr_mode = (Word16)((next_random() % 4) ? 1 : 2);
    Word16 s[L_FRAME_MAX], outx_new[L_FRAME_MAX], voicing = -1;
    Word32 mdct[L_FRAME_MAX];
    int pitch = random_pitch(frame_size);
    Word16 zp = (Word16)random_range(0, 140);
    if (next_random() % 2) zp = (Word16)random_range(0, 60);
    Word32 ener = (next_random() % 4) ? (Word32)random_range(30 * 256, 80 * 256) : random32() >> random_range(8, 24);
    Word32 ener_mean = (Word32)random_range(40 * 256, 70 * 256);
    random_pcm(s, frame_size, pitch);
    if (next_random() % 4) random_harmonic(outx_new, frame_size, pitch, 6000); else random_signal(outx_new, frame_size, 6000);
    random_spectrum(mdct, L_FRAME_MAX, pitch);
    if (next_random() % 3 == 0) for (int i = 0; i < 40; i++) mdct[i] = mdct[i] * 4;
    put16("s", s, L_FRAME_MAX); put16("outx_new", outx_new, L_FRAME_MAX); put32("mdct", mdct, L_FRAME_MAX);
    put1("frame_size", frame_size); put1("zp", zp); put1("ener", ener); put1("ener_mean", ener_mean); put1("curr_mode", curr_mode);
    Word16 result = pitch_search_fx(s, outx_new, frame_size, &voicing, zp, ener, ener_mean, mdct, curr_mode);
    arrow(); put1("pitch", result); put1("voicing", voicing); end_line();
}

static void case_parts(void)
{
    /* the helpers of the pitch search on their own, on signals of the sizes it feeds them */
    Word16 frame_size = random_frame_size();
    Word16 s[L_FRAME_MAX], lp[L_FRAME_MAX];
    Word32 mdct[L_FRAME_MAX];
    int pitch = random_pitch(frame_size);
    random_pcm(s, frame_size, pitch);
    random_spectrum(mdct, L_FRAME_MAX, pitch);
    LpFilter2_x(s, lp, frame_size);
    Word32 enr1 = 0, enr2 = 0, cov_max = 0;
    Word16 cov_bits = 0, found = 0;
    sig_tilt_x(lp, frame_size, &enr1, &enr2);
    Word16 half = (Word16)(frame_size > 320 ? frame_size / 2 : frame_size);
    Word16 start = (Word16)((0x80 + 34 * half) >> 8), end = (Word16)((2 + 3 * half) >> 2);
    get_maxConv_and_pitch_x(lp, start, end, half, &cov_max, &cov_bits, &found);
    Word16 voicing = get_voicing_x(lp, found, cov_max, cov_bits, half);
    Word16 pitch_in = found, voicing_in = voicing;
    pitch_modify_x(lp, &voicing_in, &pitch_in, half);
    Word16 relation = get_conv_relation_x(lp, found, (Word16)(frame_size - found));
    Word16 flag_pitch = (Word16)random_range(start, end);
    Word16 cov = (Word16)random_range(0, 32767);
    Word16 zp = (Word16)random_range(0, 140);
    Word32 ener = (Word32)random_range(30 * 256, 80 * 256), ener_mean = (Word32)random_range(40 * 256, 70 * 256);
    Word16 periodic = Is_Periodic_x(mdct, cov, zp, ener, ener_mean, flag_pitch, frame_size);
    Word16 harm = harmo_x(mdct, frame_size, flag_pitch);
    Word32 value = (Word32)(random32() & 0x7fffffff) >> random_range(0, 28);
    Word16 root = Sqrt_x_fast(value);
    Word16 a = (Word16)random_range(0, 32767), b = (Word16)((next_random() % 8) ? random_range(0, 3000) : random_range(0, 32767));
    Word16 quotient = int_div_s_x(a, b);
    put16("s", s, L_FRAME_MAX); put32("mdct", mdct, L_FRAME_MAX); put1("frame_size", frame_size);
    put1("flag_pitch", flag_pitch); put1("cov", cov); put1("zp", zp); put1("ener", ener); put1("ener_mean", ener_mean);
    put1("value", value); put1("a", a); put1("b", b);
    arrow(); put16("lp", lp, frame_size); put1("enr1", enr1); put1("enr2", enr2); put1("cov_max", cov_max);
    put1("cov_bits", cov_bits); put1("found", found); put1("voicing", voicing); put1("pitch_mod", pitch_in);
    put1("voicing_mod", voicing_in); put1("relation", relation); put1("periodic", periodic); put1("harm", harm);
    put1("root", root); put1("quotient", quotient); end_line();
}

static void case_log10(void)
{
    Word16 x[L_FRAME_MAX], scale_factor = -1, zp_in = 0;
    Word16 frame_size = random_frame_size();
    static const int amplitudes[] = {0, 1, 40, 2000, 32767};
    int amplitude = amplitudes[next_random() % 5];
    T_PLCInfo p;
    Word32 enerlog = 5, value = (Word32)(next_random() % 4 ? (Word32)random_range(0, 1 << 30) : random32());
    Word16 q = (Word16)random_range(-6, 20), sf_vec;
    random_signal(x, frame_size, amplitude ? amplitude : 1);
    if (!amplitude) memset(x, 0, sizeof x);
    if (next_random() % 3 == 0) {
        /* a slow sine whose level is around 50 (dB, Q8: 12800), where the running mean of the energy starts to follow it */
        double rms = random_range(250, 450);
        for (int i = 0; i < frame_size; i++) x[i] = (Word16)(rms * 1.41421356 * sin(6.283185307 * i / frame_size * random_range(1, 3)));
    }
    random_plc(&p, frame_size);
    p.zp_fx = zp_in;
    Word32 con = con_Log10(value, q);
    Word16 len = (Word16)random_range(1, L_FRAME_MAX);
    Word16 sf = ffr_getSfWord16(x, len);
    Word32 energy = Spl_Energy_x(x, frame_size, &sf_vec);
    Log10OfEnergy_x(x, &enerlog, frame_size);
    put16("x", x, L_FRAME_MAX); put1("frame_size", frame_size); put1("value", value); put1("q", q); put1("len", len);
    put_plc("p.", &p);
    concealment_update2_x(x, &p, frame_size);
    arrow(); put1("con", con); put1("sf", sf); put1("energy", energy); put1("sf_vec", sf_vec); put1("enerlog", enerlog);
    put_plc("p.", &p); end_line();
}

#define TDB_LEN 1440

static void case_waveform_adj(void)
{
    Word16 tdb[TDB_LEN], outx_new[L_FRAME_MAX], data_noise[L_FRAME_MAX];
    Word16 frame_size = random_frame_size(), curr_mode = (Word16)((next_random() & 1) ? 1 : 2), pitch = random_pitch(frame_size);
    Word16 outx_new_n1 = random16(), nsapp_gain = random16(), nsapp_gain_n = random16(), voicing = (Word16)random_range(0, 32767);
    Word8 t_bfi = (Word8)(next_random() & 1);
    /* the pitch refinement runs for a pitch up to half the frame: probe that limit */
    if (next_random() % 5 == 0) pitch = (Word16)(frame_size / 2 + random_range(-1, 1));
    if (next_random() % 3 == 0) { t_bfi = 1; curr_mode = 1; }
    int overlap_at = TDB_LEN - 3 * frame_size / 2, outdata2_at = TDB_LEN - frame_size;
    random_pcm(tdb, TDB_LEN, pitch);
    if (next_random() % 3) random_voiced(outx_new, frame_size, pitch, 6000); else random_signal(outx_new, frame_size, 6000);
    random_signal(data_noise, L_FRAME_MAX, 3000);
    put16("tdb", tdb, TDB_LEN); put16("outx_new", outx_new, L_FRAME_MAX); put16("data_noise", data_noise, L_FRAME_MAX);
    put1("frame_size", frame_size); put1("curr_mode", curr_mode); put1("pitch", pitch); put1("outx_new_n1", outx_new_n1);
    put1("nsapp_gain", nsapp_gain); put1("nsapp_gain_n", nsapp_gain_n); put1("voicing", voicing); put1("t_bfi", t_bfi);
    Word16 result = waveform_adj_fix(tdb + overlap_at, tdb + outdata2_at, outx_new, data_noise, &outx_new_n1,
                                     &nsapp_gain, &nsapp_gain_n, frame_size, t_bfi, voicing, curr_mode, pitch);
    arrow(); put1("pitch", result); put16("tdb", tdb, TDB_LEN); put16("outx_new", outx_new, L_FRAME_MAX);
    put16("data_noise", data_noise, L_FRAME_MAX); put1("outx_new_n1", outx_new_n1); put1("nsapp_gain", nsapp_gain);
    put1("nsapp_gain_n", nsapp_gain_n); end_line();
}

static void case_waveform_adj2(void)
{
    Word16 tdb[TDB_LEN], outx_new[L_FRAME_MAX], data_noise[L_FRAME_MAX];
    Word16 frame_size = random_frame_size(), pitch = (Word16)((next_random() % 8) ? random_pitch(frame_size) : 0);
    Word16 outx_new_n1 = random16(), nsapp_gain = (Word16)random_range(0, 32767), nsapp_gain_n = (Word16)random_range(0, 32767);
    Word16 recovery_gain = (Word16)random_range(0, 32767), step = (Word16)((next_random() % 5) ? random_range(0, 3000) : 0);
    Word16 bfi_cnt = (Word16)random_range(1, 5), bfi = (Word16)(next_random() & 1);
    int overlap_at = TDB_LEN - 3 * frame_size / 2;
    random_pcm(tdb, TDB_LEN, pitch ? pitch : 100);
    random_pcm(outx_new, frame_size, pitch ? pitch : 100);
    random_signal(data_noise, L_FRAME_MAX, 3000);
    put16("tdb", tdb, TDB_LEN); put16("outx_new", outx_new, L_FRAME_MAX); put16("data_noise", data_noise, L_FRAME_MAX);
    put1("frame_size", frame_size); put1("pitch", pitch); put1("outx_new_n1", outx_new_n1); put1("nsapp_gain", nsapp_gain);
    put1("nsapp_gain_n", nsapp_gain_n); put1("recovery_gain", recovery_gain); put1("step", step);
    put1("bfi_cnt", bfi_cnt); put1("bfi", bfi);
    waveform_adj2_fix(tdb + overlap_at, outx_new, data_noise, &outx_new_n1, &nsapp_gain, &nsapp_gain_n, &recovery_gain,
                      step, pitch, frame_size, 0, bfi_cnt, bfi);
    arrow(); put16("tdb", tdb, TDB_LEN); put16("outx_new", outx_new, L_FRAME_MAX); put16("data_noise", data_noise, L_FRAME_MAX);
    put1("outx_new_n1", outx_new_n1); put1("nsapp_gain", nsapp_gain); put1("recovery_gain", recovery_gain); end_line();
}

static void case_signal_tuning(void)
{
    static Decoder_State_fx st;
    Word16 tdb[TDB_LEN], outx_new[L_FRAME_MAX];
    T_PLCInfo p;
    Word16 frame_size = random_frame_size();
    Word16 curr_mode = (Word16)((next_random() & 1) ? 1 : 2), bfi = (Word16)(next_random() & 1);
    Word16 nb_lost = (Word16)random_range(1, 6), pre_bfi = (Word16)(next_random() & 1), past_core_mode = (Word16)(next_random() & 1);
    int overlap_at = TDB_LEN - 3 * frame_size / 2, outdata2_at = TDB_LEN - frame_size;
    random_plc(&p, frame_size);
    p.nbLostCmpt = (Word32)random_range(0, 6);
    st.enablePlcWaveadjust = (Word16)((next_random() % 4) ? 1 : 0);
    st.last_total_brate_fx = (next_random() & 1) ? 48000 : 24400;
    st.last_codec_mode = (Word16)((next_random() & 1) ? MODE2 : MODE1);
    random_pcm(tdb, TDB_LEN, p.Pitch_fx ? p.Pitch_fx : random_pitch(frame_size));
    random_pcm(outx_new, frame_size, random_pitch(frame_size));
    put16("tdb", tdb, TDB_LEN); put16("outx_new", outx_new, L_FRAME_MAX); put_plc("p.", &p);
    put1("bfi", bfi); put1("curr_mode", curr_mode); put1("nb_lost", nb_lost); put1("pre_bfi", pre_bfi);
    put1("past_core_mode", past_core_mode); put1("enable", st.enablePlcWaveadjust); put1("brate", st.last_total_brate_fx);
    put1("codec_mode", st.last_codec_mode);
    concealment_signal_tuning_fx(bfi, curr_mode, outx_new, &p, nb_lost, pre_bfi, tdb + overlap_at, past_core_mode, tdb + outdata2_at, &st);
    arrow(); put16("tdb", tdb, TDB_LEN); put16("outx_new", outx_new, L_FRAME_MAX); put_plc("p.", &p); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "update_x")) case_update_x();
        else if (!strcmp(argv[2], "decode_fix")) case_decode_fix();
        else if (!strcmp(argv[2], "pitch_search")) case_pitch_search();
        else if (!strcmp(argv[2], "parts")) case_parts();
        else if (!strcmp(argv[2], "log10")) case_log10();
        else if (!strcmp(argv[2], "waveform_adj")) case_waveform_adj();
        else if (!strcmp(argv[2], "waveform_adj2")) case_waveform_adj2();
        else if (!strcmp(argv[2], "signal_tuning")) case_signal_tuning();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
