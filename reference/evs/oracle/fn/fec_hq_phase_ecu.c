/* Function-level oracle for lib_dec/FEC_HQ_phase_ecu_fx.c (the HQ phase ECU). The source is included
 * so its static helpers are reachable.
 *
 * Every function is called on random inputs (a plausible previous synthesis: voiced harmonics at a
 * random pitch, noise, or a signal with an onset in the middle; spectra from the preceding stage).
 *
 * hq_phase_ecu_sequence / hq_ecu_sequence: six frames on one decoder at 16, 32 or 48 kHz output, good
 * frames replacing the synthesis history and lost frames calling hq_phase_ecu_fx / hq_ecu_fx; the whole
 * state is printed before the sequence ("in.") and around each call as the fields that differ from
 * it ("fK_pre." / "fK.").
 *
 * stream: hq_ecu_fx exactly as hq_core_dec_fx calls it on a conformance bitstream. */
#include <math.h>
#include <sys/resource.h>
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#define hq_ecu_fx hq_ecu_fx_reference
#include "../../c-code/lib_dec/FEC_HQ_phase_ecu_fx.c"
#undef hq_ecu_fx
#include "stream_mode.h"

#define SEQUENCE_FRAMES 6

void hq_ecu_fx(const Word16 *prevsynth, Word32 *ecu_rec, Word16 *time_offs, Word16 *X_sav, Word16 *Q_spec,
               Word16 *num_p, Word16 *plocs, Word32 *plocsi, const Word16 env_stab, Word16 *last_fec,
               const Word16 ph_ecu_HqVoicing, Word16 *ph_ecu_active, Word16 *gapsynth, const Word16 prev_bfi,
               const Word16 old_is_transient[2], Word16 *mag_chg_1st, Word16 *Xavg, Word16 *beta_mute,
               const Word16 output_frame, Decoder_State_fx *st)
{
    if (!stream_mode) {
        hq_ecu_fx_reference(prevsynth, ecu_rec, time_offs, X_sav, Q_spec, num_p, plocs, plocsi, env_stab, last_fec,
                            ph_ecu_HqVoicing, ph_ecu_active, gapsynth, prev_bfi, old_is_transient, mag_chg_1st, Xavg,
                            beta_mute, output_frame, st);
        return;
    }
    static Word32 ecu_in[L_FRAME48k];
    static Word16 gap_in[L_FRAME48k];
    memcpy(ecu_in, ecu_rec, sizeof ecu_in);
    memcpy(gap_in, gapsynth, sizeof gap_in);
    char *before = capture_state(st);
    hq_ecu_fx_reference(prevsynth, ecu_rec, time_offs, X_sav, Q_spec, num_p, plocs, plocsi, env_stab, last_fec,
                        ph_ecu_HqVoicing, ph_ecu_active, gapsynth, prev_bfi, old_is_transient, mag_chg_1st, Xavg,
                        beta_mute, output_frame, st);
    if (stream_calls++ % stream_every == 0) {
        put1("output_fs", st->output_Fs_fx);
        put1("output_frame", st->output_frame_fx);
        put1("call_output_frame", output_frame);
        put32("ecu_in", ecu_in, L_FRAME48k);
        put16("gap_in", gap_in, L_FRAME48k);
        put_state_in(before);
        arrow();
        put32("ecu_rec", ecu_rec, L_FRAME48k);
        put16("gapsynth", gapsynth, L_FRAME48k);
        char *after = capture_state(st);
        put_changed("st.", before, after);
        free(after);
        end_line();
    }
    free(before);
}

/* -------- random inputs -------- */

static const Word16 frame_sizes[] = {L_FRAME16k, L_FRAME32k, L_FRAME48k};

/* A previous synthesis: voiced harmonics, noise, or an onset in the middle. */
static void synthesis_signal(Word16 *x, int n)
{
    int mode = random_range(0, 5);
    int magnitude = 1 << random_range(6, 14);
    if (mode <= 2) tonal16(x, n, magnitude);
    else if (mode == 3) for (int i = 0; i < n; i++) x[i] = (Word16)random_range(-magnitude, magnitude);
    else if (mode == 4) {
        tonal16(x, n, magnitude);
        for (int i = 0; i < n / 2; i++) x[i] = (Word16)(x[i] >> random_range(2, 8));
    } else {
        tonal16(x, n, magnitude);
        for (int i = n / 2; i < n; i++) x[i] = (Word16)(x[i] >> random_range(2, 8));
    }
}

static void case_rand_phase(void)
{
    Word16 seed = random16(), sin_f = -7, cos_f = -7;
    put1("seed", seed);
    Word16 seed2 = rand_phase_fx(seed, &sin_f, &cos_f);
    arrow(); put1("seed2", seed2); put1("sin", sin_f); put1("cos", cos_f); end_line();
}

static void case_fft_spec2(void)
{
    static const Word16 sizes[] = {128, 256, 384, 512, 1024, 1536};
    static Word16 x[1536];
    static Word32 mag[1536 / 2 + 1];
    Word16 n = sizes[next_random() % 6];
    for (int i = 0; i < n; i++) x[i] = random16();
    for (int i = 0; i < n / 2 + 1; i++) mag[i] = -7;
    put16("x", x, n); put1("n", n);
    fft_spec2_fx(x, mag, n);
    arrow(); put32("mag", mag, n / 2 + 1); end_line();
}

static void case_sqrt2nd_order(void)
{
    Word16 x = (Word16)random_range(0x4000, 0x7fff);
    if (next_random() % 8 == 0) x = (Word16)(next_random() & 1 ? 0x4000 : 0x7fff);
    put1("x", x);
    arrow(); put1("y", sqrt2ndOrder(x)); end_line();
}

static void case_windowing(void)
{
    static Word16 x[1536], y[1536], win[400];
    Word16 half = (Word16)random_range(1, 192), rect = (Word16)(next_random() % 3 ? 0 : random_range(1, 100));
    for (int i = 0; i < 1536; i++) { x[i] = random16(); y[i] = -7; }
    for (int i = 0; i < 400; i++) win[i] = (Word16)random_range(0, 32767);
    put16("x", x, 2 * half + rect); put16("win", win, half); put1("rect", rect); put1("half", half);
    windowing(x, y, win, rect, half);
    arrow(); put16("y", y, 2 * half + rect); end_line();
}

static void case_windowing_rom_optimized(void)
{
    static Word16 x[1536], y[1536];
    static const Word16 downs[] = {4, 8};
    Word16 down = downs[next_random() & 1];
    /* the half lengths and the rectangle the 16 and 32 kHz prototypes use */
    Word16 half = down == 4 ? 192 : 96, rect = (Word16)((down == 4 ? 1024 : 512) - 2 * half);
    for (int i = 0; i < 1536; i++) { x[i] = random16(); y[i] = -7; }
    put16("x", x, 2 * half + rect); put1("down", down); put1("rect", rect); put1("half", half);
    windowing_ROM_optimized(x, y, down, rect, half);
    arrow(); put16("y", y, 2 * half + rect); end_line();
}

static void case_trans_ana(void)
{
    static Word16 xfp[1536];
    Word16 mag_chg[Lgw_max], ph_dith = -7, mag_chg_1st[Lgw_max], alpha[Lgw_max], beta[Lgw_max], beta_mute, xavg[Lgw_max];
    Word16 output_frame = frame_sizes[next_random() % 3];
    Word16 time_offs = (Word16)(output_frame * (next_random() % 8 == 0 ? random_range(30, 34) : random_range(0, 14)));
    Word16 est_mus_content = (Word16)random_range(0, 32767), last_fec = (Word16)(next_random() % 3 == 0);
    synthesis_signal(xfp, 1536);
    if (next_random() % 8 == 0) {
        /* a silent last quarter of the analysis window after a loud left side */
        int window = next_random() % 3 == 0 ? 1536 : 512 << random_range(0, 1);
        for (int i = window * 3 / 4; i < window; i++) xfp[i] = 0;
    }
    for (int k = 0; k < Lgw_max; k++) {
        mag_chg[k] = alpha[k] = beta[k] = xavg[k] = -7;
        mag_chg_1st[k] = (Word16)random_range(0, 32767);
    }
    beta_mute = (Word16)random_range(0, 16384);
    if (next_random() % 4 == 0) {
        /* the mute factor still at its start value, and a small first-burst magnitude change */
        beta_mute = 16384;
        time_offs = (Word16)(output_frame * random_range(2, 9));
        last_fec = 0;
        for (int k = 0; k < Lgw_max; k++) mag_chg_1st[k] = (Word16)random_range(0, 300);
    }
    put16("xfp", xfp, 1536); put1("output_frame", output_frame); put1("time_offs", time_offs);
    put1("est_mus_content", est_mus_content); put1("last_fec", last_fec);
    put16("mag_chg_1st", mag_chg_1st, Lgw_max); put1("beta_mute", beta_mute);
    trans_ana_fx(xfp, mag_chg, &ph_dith, mag_chg_1st, output_frame, time_offs, est_mus_content, last_fec, alpha, beta,
                 &beta_mute, xavg);
    arrow(); put16("mag_chg", mag_chg, Lgw_max); put1("ph_dith", ph_dith); put16("mag_chg_1st", mag_chg_1st, Lgw_max);
    put16("alpha", alpha, Lgw_max); put16("beta", beta, Lgw_max); put1("beta_mute", beta_mute);
    put16("xavg", xavg, Lgw_max); end_line();
}

/* A magnitude spectrum: noise floor with a few peaks, a ramp, a plateau, or a monotone slope. */
static void spectrum_like(Word16 *x, int n)
{
    int mode = random_range(0, 5);
    int top = 1 << random_range(5, 14);
    for (int i = 0; i < n; i++) x[i] = (Word16)random_range(0, top / 8);
    if (mode <= 2) {
        int peaks = random_range(1, 30);
        for (int p = 0; p < peaks; p++) x[random_range(0, n - 1)] = (Word16)random_range(top / 4, top);
        if (next_random() % 4 == 0) x[0] = (Word16)top;
        if (next_random() % 4 == 0) x[n - 1] = (Word16)top;
    } else if (mode == 3) {
        for (int i = 0; i < n; i++) x[i] = (Word16)(top * i / n);
        if (next_random() & 1) for (int i = 0; i < n; i++) x[i] = (Word16)(top - x[i]);
    } else if (mode == 4) {
        for (int i = 0; i < n; i++) x[i] = (Word16)(next_random() % 3 ? top / 2 : top / 2 + random_range(-2, 2));
    }
}

static void case_peakfinder(void)
{
    static Word16 x0[1536], plocs[400];
    Word16 len0 = (Word16)(next_random() % 4 == 0 ? random_range(2, 12) : random_range(3, 769));
    if (next_random() % 4 == 0) len0 = (Word16)(next_random() & 1 ? 257 : 513);
    Word16 c_ind = -7;
    spectrum_like(x0, len0);
    if (next_random() % 8 == 0) {
        /* every bin an extremum: the list of candidate extrema fills the whole spectrum */
        len0 = (Word16)(next_random() & 1 ? 768 : 769);
        for (int i = 0; i < len0; i++) x0[i] = (Word16)((i & 1 ? 9000 : 1000) + random_range(0, 400));
    }
    Word16 xmax = x0[0], xmin = x0[0];
    for (int i = 0; i < len0; i++) { if (x0[i] > xmax) xmax = x0[i]; if (x0[i] < xmin) xmin = x0[i]; }
    Word16 sel = mult_r(sub(xmax, xmin), CMPLMNT_PFIND_SENS_FX);
    if (next_random() % 4 == 0) sel = (Word16)random_range(0, 3000);
    for (int i = 0; i < 400; i++) plocs[i] = -7;
    put16("x0", x0, len0); put1("sel", sel);
    peakfinder_fx(x0, len0, plocs, &c_ind, sel);
    arrow(); put1("c_ind", c_ind); put16("plocs", plocs, c_ind > 0 ? c_ind : 0); end_line();
}

static void case_imax(void)
{
    Word16 y[3], special = (Word16)random_range(-1, 1);
    int mag = 1 << random_range(2, 15);
    for (int i = 0; i < 3; i++) y[i] = (Word16)random_range(0, mag);
    if (next_random() % 5 == 0) y[1] = y[0];
    if (next_random() % 7 == 0) y[2] = y[1];
    put16("y", y, 3); put1("special", special);
    arrow(); put1("posi", imax_fx(y, special)); end_line();
}

static void case_spec_ana(void)
{
    static Word16 prevsynth[1536], plocs[400], x_sav[1536];
    static Word32 plocsi[400];
    Word16 output_frame = frame_sizes[next_random() % 3], num_plocs = -7, q = -7;
    Word16 bwidth = (Word16)random_range(output_frame == L_FRAME16k ? 1 : output_frame == L_FRAME32k ? 1 : 1, output_frame == L_FRAME16k ? 1 : output_frame == L_FRAME32k ? 2 : 3);
    synthesis_signal(prevsynth, 1536);
    for (int i = 0; i < 400; i++) { plocs[i] = -7; plocsi[i] = -7; }
    for (int i = 0; i < 1536; i++) x_sav[i] = -7;
    put16("prevsynth", prevsynth, 1536); put1("output_frame", output_frame); put1("bwidth", bwidth);
    spec_ana_fx(prevsynth, plocs, plocsi, &num_plocs, x_sav, output_frame, bwidth, &q);
    arrow(); put1("num_plocs", num_plocs); put16("plocs", plocs, num_plocs > 0 ? num_plocs : 0);
    put32("plocsi", plocsi, num_plocs > 0 ? num_plocs : 0); put16("x_sav", x_sav, 1536); put1("q", q); end_line();
}

static void case_subst_spec(void)
{
    static Word16 plocs[400], x[1536];
    static Word32 plocsi[400];
    Word16 output_frame = frame_sizes[next_random() % 3];
    Word16 lprot = output_frame == L_FRAME16k ? 512 : output_frame == L_FRAME32k ? 1024 : 1536;
    Word16 num_plocs = (Word16)(next_random() % 6 == 0 ? random_range(0, 3) : random_range(0, 60));
    Word16 mag_chg[Lgw_max], alpha[Lgw_max], beta[Lgw_max], xavg[Lgw_max], is_trans[2];
    Word16 time_offs = (Word16)(output_frame * random_range(0, 12)), ph_dith = 0, seed = random16();
    Word16 beta_mute = (Word16)random_range(0, 16384);
    /* strictly increasing peak positions below Lprot/2 */
    int position = random_range(0, 4);
    for (int p = 0; p < num_plocs; p++) {
        plocs[p] = (Word16)position;
        plocsi[p] = ((Word32)position << 16) + random_range(-32768, 32767);
        position += random_range(1, lprot / 2 / (num_plocs + 1));
        if (position >= lprot / 2) { num_plocs = (Word16)(p + 1); break; }
    }
    plocs[num_plocs] = (Word16)random_range(0, lprot / 2);
    for (int i = 0; i < lprot; i++) x[i] = random16();
    for (int k = 0; k < Lgw_max; k++) {
        mag_chg[k] = (Word16)random_range(0, 32767);
        int fading = next_random() % 3 == 0;
        alpha[k] = (Word16)(fading ? random_range(0, 32765) : 32767);
        beta[k] = (Word16)random_range(0, 32767);
        xavg[k] = (Word16)random_range(0, 5000);
    }
    int dither = next_random() % 3;
    ph_dith = (Word16)(dither == 0 ? 0 : dither == 1 ? 16384 : 32767);
    is_trans[0] = (Word16)(next_random() % 8 == 0);
    is_trans[1] = (Word16)(next_random() % 8 == 0);
    put16("plocs", plocs, num_plocs + 1); put32("plocsi", plocsi, num_plocs + 1); put1("num_plocs", num_plocs);
    put1("time_offs", time_offs); put16("x", x, lprot); put16("mag_chg", mag_chg, Lgw_max); put1("ph_dith", ph_dith);
    put16("is_trans", is_trans, 2); put1("output_frame", output_frame); put1("seed", seed);
    put16("alpha", alpha, Lgw_max); put16("beta", beta, Lgw_max); put1("beta_mute", beta_mute); put16("xavg", xavg, Lgw_max);
    subst_spec_fx(plocs, plocsi, &num_plocs, time_offs, x, mag_chg, ph_dith, is_trans, output_frame, &seed, alpha, beta,
                  beta_mute, xavg);
    arrow(); put1("num_plocs", num_plocs); put16("x", x, lprot); put1("seed", seed); end_line();
}

static void case_rec_wtda(void)
{
    static Word16 x[1536];
    static Word32 ecu_rec[L_FRAME48k];
    Word16 output_frame = frame_sizes[next_random() % 3];
    Word16 lprot = output_frame == L_FRAME16k ? 512 : output_frame == L_FRAME32k ? 1024 : 1536;
    synthesis_signal(x, lprot);
    for (int i = 0; i < L_FRAME48k; i++) ecu_rec[i] = -7;
    put16("x", x, lprot); put1("output_frame", output_frame);
    rec_wtda_fx(x, ecu_rec, output_frame, lprot, output_frame * 50);
    arrow(); put32("ecu_rec", ecu_rec, output_frame); put16("x", x, lprot); end_line();
}

static void case_rec_frame(void)
{
    static Word16 x[1536];
    static Word32 ecu_rec[L_FRAME48k];
    Word16 output_frame = frame_sizes[next_random() % 3];
    Word16 lprot = output_frame == L_FRAME16k ? 512 : output_frame == L_FRAME32k ? 1024 : 1536;
    Word16 q = (Word16)random_range(0, 6);
    int magnitude = 1 << random_range(4, 15);
    for (int i = 0; i < lprot; i++) x[i] = (Word16)random_range(-magnitude, magnitude);
    for (int i = 0; i < L_FRAME48k; i++) ecu_rec[i] = -7;
    put16("x", x, lprot); put1("output_frame", output_frame); put1("q", q);
    rec_frame_fx(x, ecu_rec, output_frame, q);
    arrow(); put32("ecu_rec", ecu_rec, output_frame); put16("x", x, lprot); end_line();
}

static void case_mult_32_32_q(void)
{
    Word32 a = random32(), b = random32();
    Word16 q = (Word16)random_range(0, 30);
    put1("a", a); put1("b", b); put1("q", q);
    arrow(); put1("r", mult_32_32_q(a, b, q)); end_line();
}

static void case_fir_dwn(void)
{
    static Word16 x[2000], y[400];
    static const Word16 lengths[] = {L_FRAME48k, L_FRAME32k, L_FRAME16k, 160};
    int which = (int)(next_random() % 3); /* the default branch (L < 320) would read past the 20 tap table */
    Word16 decim = which == 0 ? 6 : which == 1 ? 4 : 2, k = which == 0 ? 60 : which == 1 ? 40 : which == 2 ? 20 : 40;
    Word16 l = (Word16)(lengths[which] * 2), q = which == 0 ? 17 : 15;
    const Word16 *h = which == 0 ? Asr_LP48_fx : which == 1 ? Asr_LP32_fx : Asr_LP16_fx;
    synthesis_signal(x, l);
    for (int i = 0; i < 400; i++) y[i] = -7;
    put16("x", x, l); put1("which", which);
    fir_dwn_fx(x, h, q, y, l, k, decim);
    arrow(); put16("y", y, 320); end_line();
}

static void case_fec_ecu_pitch(void)
{
    static Word16 prevsynth[2000], lp[320];
    Word16 l = frame_sizes[next_random() % 3], n = -7, corr = -7, decim = -7, voicing = (Word16)(next_random() & 1);
    synthesis_signal(prevsynth, 2000);
    /* digital silence, or a sparse unit-amplitude signal: no delay has a positive correlation with its own energy */
    switch (next_random() % 6) {
    case 0: for (int i = 0; i < 2000; i++) prevsynth[i] = 0; break;
    case 1: for (int i = 0; i < 2000; i++) prevsynth[i] = (Word16)(next_random() % 16 == 0 ? random_range(-1, 1) : 0); break;
    default: break;
    }
    for (int i = 0; i < 320; i++) lp[i] = -7;
    put16("prevsynth", prevsynth, 2000); put1("l", l); put1("voicing", voicing);
    fec_ecu_pitch_fx(prevsynth, lp, l, &n, &corr, &decim, voicing);
    arrow(); put16("lp", lp, 320); put1("n", n); put1("corr", corr); put1("decim", decim); end_line();
}

static void case_sin_cos_est(void)
{
    Word32 phi = random_range(0, 1686629376);
    if (next_random() % 8 == 0) phi = next_random() & 1 ? 0 : 1686629376;
    /* the table step is 4392264 (2*pi/1432 in the reference's Q), where the interpolation index changes */
    if (next_random() % 4 == 0) phi = (Word32)random_range(0, 383) * 4392264 + random_range(0, 2);
    Word16 cosf = -7, sinf = -7;
    put1("phi", phi);
    sin_cos_est_fx(phi, &cosf, &sinf);
    arrow(); put1("cos", cosf); put1("sin", sinf); end_line();
}

static void case_abs_iter(void)
{
    Word16 re = random16(), im = random16(), n = (Word16)random_range(1, 8);
    if (next_random() % 6 == 0) re = 0;
    if (next_random() % 6 == 0) im = 0;
    put1("re", re); put1("im", im); put1("n", n);
    arrow(); put1("a", abs_iter_fx(re, im, n)); end_line();
}

/* the down-sampled signal fec_ecu_pitch_fx hands on */
static void lowpassed_signal(Word16 *lp)
{
    tonal16(lp, 320, 1 << random_range(6, 13));
    if (next_random() % 5 == 0) for (int i = 0; i < 320; i++) lp[i] = (Word16)random_range(-3000, 3000);
}

static void case_fec_ecu_dft(void)
{
    static Word16 lp[320], tfr[512], tfi[512], tf_abs[256];
    Word32 sum = -7;
    Word16 n = (Word16)(next_random() % 4 == 0 ? random_range(8, 296) : random_range(30, 280)), nfft = -7, exp = -7;
    if (next_random() % 6 == 0) n = (Word16)(next_random() & 1 ? 256 : 128);
    lowpassed_signal(lp);
    for (int i = 0; i < 512; i++) tfr[i] = tfi[i] = -7;
    for (int i = 0; i < 256; i++) tf_abs[i] = -7;
    put16("lp", lp, 320); put1("n", n);
    fec_ecu_dft_fx(lp, n, tfr, tfi, &sum, tf_abs, &nfft, &exp);
    arrow(); put1("nfft", nfft); put1("exp", exp); put1("sum", sum); put16("tfr", tfr, nfft / 2); put16("tfi", tfi, nfft / 2);
    put16("tf_abs", tf_abs, nfft / 2); end_line();
}

static void case_singenerator(void)
{
    static Word32 xx[1920];
    Word16 l = (Word16)(2 * frame_sizes[next_random() % 3]);
    Word16 cosf, sinf, a_re = random16(), a_im = random16();
    sin_cos_est_fx(random_range(0, 1686629376), &cosf, &sinf);
    for (int i = 0; i < l; i++) xx[i] = random_range(-(1 << 20), 1 << 20);
    put1("l", l); put1("cos", cosf); put1("sin", sinf); put1("a_re", a_re); put1("a_im", a_im); put32("xx", xx, l);
    singenerator_fx(l, cosf, sinf, a_re, a_im, xx);
    arrow(); put32("xx", xx, l); end_line();
}

/* The inputs sinusoidal_synthesis_fx gets from fec_ecu_dft_fx, for a random pitch period. */
static void case_sinusoidal_synthesis(void)
{
    static Word16 lp[320], tfr[512], tfi[512], tf_abs[256], synthesis[1920];
    Word32 sum = -7;
    Word16 l = frame_sizes[next_random() % 3], nfft = -7, exp = -7;
    Word16 decim = l == L_FRAME48k ? 6 : l == L_FRAME32k ? 4 : 2, voicing = (Word16)(next_random() & 1);
    Word16 n = (Word16)(next_random() % 4 == 0 ? random_range(8, 272) : random_range(40, 272));
    lowpassed_signal(lp);
    fec_ecu_dft_fx(lp, n, tfr, tfi, &sum, tf_abs, &nfft, &exp);
    for (int i = 0; i < 1920; i++) synthesis[i] = -7;
    put16("tfr", tfr, nfft / 2); put16("tfi", tfi, nfft / 2); put16("tf_abs", tf_abs, nfft / 2); put1("n", n); put1("l", l);
    put1("decim", decim); put1("nfft", nfft); put1("sum", sum); put1("voicing", voicing); put1("exp", exp);
    sinusoidal_synthesis_fx(tfr, tfi, tf_abs, n, l, decim, nfft, sum, synthesis, voicing, exp);
    arrow(); put16("synthesis", synthesis, 2 * l); put16("tf_abs", tf_abs, nfft / 2); end_line();
}

static void case_fec_noise_filling(void)
{
    static Word16 prevsynth[2000], synthesis[1920], gapsynth[960];
    Word16 l = frame_sizes[next_random() % 3], seed = random16(), voicing = (Word16)(next_random() & 1);
    Word16 n = (Word16)random_range(l / 10, l * 3 / 2);
    synthesis_signal(prevsynth, 2000);
    synthesis_signal(synthesis, 2 * l);
    for (int i = 0; i < 960; i++) gapsynth[i] = -7;
    put16("prevsynth", prevsynth, 2000); put16("synthesis", synthesis, 2 * l); put1("seed", seed); put1("l", l);
    put1("n", n); put1("voicing", voicing);
    fec_noise_filling_fx(prevsynth, synthesis, &seed, l, n, voicing, gapsynth);
    arrow(); put16("synthesis", synthesis, 2 * l); put1("seed", seed); put16("gapsynth", gapsynth, l); end_line();
}

static void case_fec_alg(void)
{
    static Word16 prevsynth[2000], lp[320], gapsynth[960];
    static Word32 ecu_rec[L_FRAME48k];
    Word16 l = frame_sizes[next_random() % 3], seed = random16(), voicing = (Word16)(next_random() & 1);
    Word16 decim = l == L_FRAME48k ? 6 : l == L_FRAME32k ? 4 : 2, n = (Word16)random_range(20, 272);
    synthesis_signal(prevsynth, 2000);
    lowpassed_signal(lp);
    for (int i = 0; i < 960; i++) { gapsynth[i] = -7; ecu_rec[i] = -7; }
    put16("prevsynth", prevsynth, 2000); put16("lp", lp, 320); put1("seed", seed); put1("l", l); put1("n", n);
    put1("decim", decim); put1("voicing", voicing);
    fec_alg_fx(prevsynth, lp, &seed, ecu_rec, l, n, decim, voicing, gapsynth);
    arrow(); put32("ecu_rec", ecu_rec, l); put1("seed", seed); put16("gapsynth", gapsynth, l); end_line();
}

/* -------- the sequences -------- */

/* hq_ecu_fx / hq_phase_ecu_fx called as hq_core_dec_fx does, on a decoder in the state previous good
 * and lost frames leave. */
static void case_sequence(int whole_ecu)
{
    static Word32 ecu_rec[L_FRAME48k];
    static Word16 gapsynth[L_FRAME48k];
    static const Word32 brates[] = {24400, 32000, 48000, 64000, 96000, 128000};
    Word32 fs = frame_sizes[next_random() % 3] * 50;
    Decoder_State_fx *st = new_decoder(fs);
    Word16 output_frame = (Word16)(fs / 50);
    int max_bwidth = output_frame == L_FRAME16k ? 1 : output_frame == L_FRAME32k ? 2 : 3;
    st->bwidth_fx = (Word16)random_range(1, max_bwidth);
    st->total_brate_fx = brates[next_random() % 6];
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    char *initial = capture_state(st);
    put_state_in(initial);
    int lost = 0;
    for (int f = 0; f < SEQUENCE_FRAMES; f++) {
        char name[48];
        int bfi = f == 0 ? 0 : (lost ? next_random() % 4 != 0 : next_random() % 3 == 0);
        /* the decoder's bookkeeping around a frame */
        st->prev_old_bfi_fx = st->prev_bfi_fx;
        st->prev_bfi_fx = st->bfi_fx;
        st->bfi_fx = (Word16)bfi;
        if (!bfi) {
            /* a good frame: a new synthesis history and the signal analysis it feeds */
            synthesis_signal(st->synth_history_fx, Lprot48k + L_FRAME_MAX);
            st->env_stab_fx = (Word16)random_range(0, 32767);
            st->env_stab_plc_fx = (Word16)(next_random() & 1);
            st->ph_ecu_HqVoicing_fx = (Word16)(next_random() % 3 == 0);
            st->old_is_transient_fx[2] = st->old_is_transient_fx[1];
            st->old_is_transient_fx[1] = st->old_is_transient_fx[0];
            st->old_is_transient_fx[0] = (Word16)(next_random() % 8 == 0);
            if (next_random() % 3 == 0) { st->time_offs_fx = 0; st->last_fec_fx = 0; }
        } else {
            st->old_is_transient_fx[2] = st->old_is_transient_fx[1];
            st->old_is_transient_fx[1] = st->old_is_transient_fx[0];
        }
        lost = bfi;
        sprintf(name, "f%d_bfi", f); put1(name, bfi);
        char *pre = capture_state(st);
        sprintf(name, "f%d_pre.", f); put_changed(name, initial, pre);
        free(pre);
        if (bfi) {
            for (int i = 0; i < L_FRAME48k; i++) { ecu_rec[i] = 0; gapsynth[i] = 0; }
            if (whole_ecu)
                hq_ecu_fx(st->prev_good_synth_fx, ecu_rec, &st->time_offs_fx, st->X_sav_fx, &st->Q_X_sav, &st->num_p_fx,
                          st->plocs_fx, st->plocsi_fx, st->env_stab_fx, &st->last_fec_fx, st->ph_ecu_HqVoicing_fx,
                          &st->ph_ecu_active_fx, gapsynth, st->prev_bfi_fx, st->old_is_transient_fx, st->mag_chg_1st_fx,
                          st->Xavg_fx, &st->beta_mute_fx, output_frame, st);
            else
                hq_phase_ecu_fx(st->prev_good_synth_fx, ecu_rec, &st->time_offs_fx, st->X_sav_fx, &st->Q_X_sav,
                                &st->num_p_fx, st->plocs_fx, st->plocsi_fx, st->env_stab_fx, &st->last_fec_fx,
                                &st->ph_ecu_active_fx, st->prev_bfi_fx, st->old_is_transient_fx, st->mag_chg_1st_fx,
                                st->Xavg_fx, &st->beta_mute_fx, st->bwidth_fx, output_frame);
            sprintf(name, "f%d_ecu_rec", f); put32(name, ecu_rec, output_frame);
            sprintf(name, "f%d_gapsynth", f); put16(name, gapsynth, output_frame);
            char *post = capture_state(st);
            sprintf(name, "f%d.", f); put_changed(name, initial, post);
            free(post);
        }
    }
    free(initial);
    arrow();
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    /* a crash must not pop up a core-dump report: no core files */
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
    if (argc == 5 && !strcmp(argv[1], "stream")) { stream(argv[2], atol(argv[3]), atol(argv[4])); return 0; }
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        const char *f = argv[2];
        if (!strcmp(f, "rand_phase")) case_rand_phase();
        else if (!strcmp(f, "fft_spec2")) case_fft_spec2();
        else if (!strcmp(f, "sqrt2nd_order")) case_sqrt2nd_order();
        else if (!strcmp(f, "windowing")) case_windowing();
        else if (!strcmp(f, "windowing_rom_optimized")) case_windowing_rom_optimized();
        else if (!strcmp(f, "trans_ana")) case_trans_ana();
        else if (!strcmp(f, "peakfinder")) case_peakfinder();
        else if (!strcmp(f, "imax")) case_imax();
        else if (!strcmp(f, "spec_ana")) case_spec_ana();
        else if (!strcmp(f, "subst_spec")) case_subst_spec();
        else if (!strcmp(f, "rec_wtda")) case_rec_wtda();
        else if (!strcmp(f, "rec_frame")) case_rec_frame();
        else if (!strcmp(f, "mult_32_32_q")) case_mult_32_32_q();
        else if (!strcmp(f, "fir_dwn")) case_fir_dwn();
        else if (!strcmp(f, "fec_ecu_pitch")) case_fec_ecu_pitch();
        else if (!strcmp(f, "sin_cos_est")) case_sin_cos_est();
        else if (!strcmp(f, "abs_iter")) case_abs_iter();
        else if (!strcmp(f, "fec_ecu_dft")) case_fec_ecu_dft();
        else if (!strcmp(f, "singenerator")) case_singenerator();
        else if (!strcmp(f, "sinusoidal_synthesis")) case_sinusoidal_synthesis();
        else if (!strcmp(f, "fec_noise_filling")) case_fec_noise_filling();
        else if (!strcmp(f, "fec_alg")) case_fec_alg();
        else if (!strcmp(f, "hq_phase_ecu_sequence")) case_sequence(0);
        else if (!strcmp(f, "hq_ecu_sequence")) case_sequence(1);
        else { fprintf(stderr, "unknown function %s\n", f); return 2; }
    }
    return 0;
}
