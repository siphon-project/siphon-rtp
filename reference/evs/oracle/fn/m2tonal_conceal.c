/* Function-level oracle for lib_dec/tonalMDCTconcealment.c (every function but TonalMDCTConceal_Init,
 * which tonalMDCTconcealment.c covers): a stateful sequence, the way the decoder drives it.
 *
 * `corpus run COUNT SEED` prints one line per call (COUNT lines), the calls of consecutive scenarios:
 * init (as core_dec_init does), then good frames (SaveFreqSignal, SaveTimeSignal, UpdateState) and
 * lost frames (Detect, InsertNoise, Apply, UpdateState) with the tonal concealment on whenever Detect
 * found components (and a coin says so), on a tonal (harmonic comb plus noise) or a noise-only
 * signal. The spectra come from the reference's own TCX MDCT of that signal so the peaks the
 * detection looks for are really there. Every line prints the call's inputs, its outputs and the
 * whole concealment state after it; the Rust test keeps one state across the lines and compares them.
 *
 * Domain: nSamples = TCX lines at the output rate (160/320/640/960, 25 Hz per line), nSamplesCore =
 * the core frame (256 or 320), pitch a Q16 lag at the core rate (or 0), crossOverFreq at or below
 * nSamples, the cross-fade gain and tilt factor Q15 in their usual ranges. */
#include "harness.h"
#include "prot_fx.h"
#include "stat_dec_fx.h"
#include <math.h>

enum { OP_INIT, OP_SAVE_FREQ, OP_SAVE_TIME, OP_UPDATE, OP_DETECT, OP_NOISE, OP_APPLY };

static struct tonalmdctconceal *self;
static TCX_config cfg;
static Word16 n_samples, n_samples_core;

/* The signal. */
static int tonal;
static double f0_hz, amp, noise_amp, phase_of[40], output_rate_hz;
static int harmonics;

static Word16 sample(long position)
{
    double value = 0;
    if (tonal)
        for (int k = 1; k <= harmonics; k++)
            value += amp / k * sin(2 * M_PI * k * f0_hz * (double)position / output_rate_hz + phase_of[k]);
    value += (double)random_range((int)-noise_amp, (int)noise_amp);
    if (value > 30000) value = 30000;
    if (value < -30000) value = -30000;
    return (Word16)value;
}

/* The MDCT of the signal around frame `frame`, as CalcMDXT builds it, for SaveFreqSignal. */
static void analyse(long frame, Word32 *spectrum, Word16 *spectrum_exp)
{
    Word16 *signal = calloc(6 * 960, sizeof(Word16));
    Word16 *windowed = calloc(L_FRAME_PLUS + 2 * L_MDCT_OVLP_MAX, sizeof(Word16));
    Word16 left, right, length = n_samples;
    long start = frame * n_samples - n_samples / 2 - 2 * n_samples;
    for (int i = 0; i < 5 * n_samples; i++) signal[i] = sample(start + i);
    WindowSignal(&cfg, cfg.tcx_offsetFB, FULL_OVERLAP, FULL_OVERLAP, &left, &right, signal + 2 * n_samples, &length, windowed, 1);
    *spectrum_exp = 16;
    TCX_MDCT(windowed, spectrum, spectrum_exp, left, sub(length, shr(add(left, right), 1)), right);
    free(signal); free(windowed);
}

static void put_state(void)
{
    put1("s_n_samples", self->nSamples); put1("s_n_samples_core", self->nSamplesCore);
    put1("s_n_non_zero", self->nNonZeroSamples); put1("s_n_scale_factors", self->nScaleFactors);
    put1("s_last_pitch_lag", self->lastPitchLag); put1("s_n_frames_lost", self->nFramesLost);
    const blockData *blocks[2] = {&self->lastBlockData, &self->secondLastBlockData};
    for (int b = 0; b < 2; b++) {
        char name[64];
        const char *tag = b ? "second_" : "last_";
#define FIELD(field, value) snprintf(name, sizeof name, "%s%s", tag, field); put1(name, value)
        FIELD("n_samples", blocks[b]->nSamples); FIELD("n_samples_core", blocks[b]->nSamplesCore);
        FIELD("spectral", blocks[b]->spectralData == self->spectralDataBuffers[0] ? 0 : 1);
        FIELD("spectral_exp", blocks[b]->spectralData_exp);
        FIELD("sf", blocks[b]->scaleFactors == self->scaleFactorsBuffers[0] ? 0 : 1);
        FIELD("sf_exp_ptr", blocks[b]->scaleFactors_exp == self->scaleFactorsBuffers_exp[0] ? 0 : 1);
        FIELD("sf_max_e", blocks[b]->scaleFactors_max_e); FIELD("gain_tcx_exp", blocks[b]->gain_tcx_exp);
        FIELD("valid", blocks[b]->blockIsValid); FIELD("concealed", blocks[b]->blockIsConcealed);
        FIELD("tonal", blocks[b]->tonalConcealmentActive);
    }
    put1("s_second_power", self->secondLastPowerSpectrum == self->spectralDataBuffers[0] ? 0 : 1);
    put1("s_second_power_exp", self->secondLastPowerSpectrum_exp);
    put1("s_last_pcm_out", self->lastPcmOut - self->timeDataBuffer);
    put1("s_second_last_pcm_out", self->secondLastPcmOut - self->timeDataBuffer);
    put16("s_spectral0", self->spectralDataBuffers[0], L_FRAME_MAX);
    put16("s_spectral1", self->spectralDataBuffers[1], L_FRAME_MAX);
    put16("s_sf0", self->scaleFactorsBuffers[0], FDNS_NPTS); put16("s_sf1", self->scaleFactorsBuffers[1], FDNS_NPTS);
    put16("s_sf_exp0", self->scaleFactorsBuffers_exp[0], FDNS_NPTS); put16("s_sf_exp1", self->scaleFactorsBuffers_exp[1], FDNS_NPTS);
    put16("s_time", self->timeDataBuffer, (3 * L_FRAME_MAX) / 2);
}

static void random_scale_factors(Word16 *mantissa, Word16 *exponent)
{
    for (int i = 0; i < FDNS_NPTS; i++) { mantissa[i] = (Word16)random_range(6000, 32767); exponent[i] = (Word16)random_range(0, 6); }
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus") || strcmp(argv[2], "run")) { fprintf(stderr, "usage: corpus run COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    long lines = atol(argv[3]), printed = 0, frame = 0;
    self = calloc(1, sizeof(struct tonalmdctconceal));
    Word32 *x = calloc(2 * L_FRAME_MAX, sizeof(Word32));
    Word16 sf[FDNS_NPTS], sf_exp[FDNS_NPTS];
    Word32 pitch = 0;

#define LINE_END() do { put_state(); end_line(); if (++printed >= lines) goto done; } while (0)

    for (;;) {
        /* A scenario: configuration, then a run of good frames and a run of lost ones. */
        static const Word32 core_rates[] = {12800, 16000};
        static const Word32 output_rates[] = {8000, 16000, 32000, 48000};
        Word32 sr = core_rates[next_random() & 1], fs = output_rates[next_random() % 4];
        Word16 l_frame = (Word16)(sr / 50), l_frame_tcx = (Word16)(fs / 50);
        n_samples = l_frame_tcx; n_samples_core = l_frame;
        output_rate_hz = (double)fs;
        memset(&cfg, 0, sizeof cfg);
        init_TCX_config(&cfg, l_frame, sr2fscale(sr), l_frame_tcx, sr2fscale(fs));
        cfg.tcx_offsetFB = shr(cfg.tcx_mdct_window_delayFB, 1);

        /* core_dec_init's pre-initialisation, then Init (on a state a previous scenario may have left). */
        self->nScaleFactors = 0; self->nSamples = 0; self->lastPcmOut = 0; self->lastBlockData.tonalConcealmentActive = 0; self->lastBlockData.nSamples = 0;
        TonalMDCTConceal_Init(self, l_frame_tcx, l_frame, FDNS_NPTS, &cfg);
        put1("op", OP_INIT); put1("l_frame", l_frame); put1("fscale", sr2fscale(sr)); put1("l_frame_tcx", l_frame_tcx); put1("fscale_fb", sr2fscale(fs));
        arrow(); LINE_END();

        /* The signal of this scenario. */
        tonal = next_random() % 4 != 0;
        int whole = random_range(34 * l_frame / 256, l_frame / 2);
        int quarter = (int)(next_random() % 4);
        double lag_samples = whole + quarter / 4.0;
        Word32 lag_q16 = ((Word32)whole << 16) + quarter * 16384;
        f0_hz = (double)sr / lag_samples;
        harmonics = (int)(fs / 2 / f0_hz); if (harmonics > 30) harmonics = 30; if (harmonics < 1) harmonics = 1;
        amp = random_range(1500, 4000); noise_amp = tonal ? random_range(20, 300) : random_range(300, 3000);
        for (int k = 0; k < 40; k++) phase_of[k] = (next_random() % 6283) / 1000.0;
        random_scale_factors(sf, sf_exp);
        int tonal_active_before = 0;

        /* Round 0: good frames, then lost ones; round 1: recovery, then another loss,
         * which is when the second last frame was concealed with the tonal concealment (the refinement path). */
        for (int round = 0; round < 2; round++) {
        int good = round ? random_range(1, 2) : random_range(2, 5), lost = random_range(1, 3);

        for (int f = 0; f < good; f++, frame++) {
            Word32 pitch_arg = next_random() % 4 ? lag_q16 + random_range(-3000, 3000) : 0;
            Word16 x_e; Word16 gain_tcx_e = (Word16)random_range(-2, 4);
            analyse(frame, x, &x_e);
            /* Band-limited half of the time: the lines above the cutoff quantise to zero. */
            if (next_random() & 1) for (int i = random_range(n_samples / 4, n_samples); i < n_samples; i++) x[i] = 0;
            for (int i = 0; i < FDNS_NPTS; i++) if (next_random() % 8 == 0) { sf[i] = (Word16)random_range(6000, 32767); }
            /* SaveFreqSignal */
            put1("op", OP_SAVE_FREQ); put32("x", x, n_samples); put1("x_e", x_e); put16("sf", sf, FDNS_NPTS); put16("sf_exp", sf_exp, FDNS_NPTS);
            put1("gain_tcx_e", gain_tcx_e);
            TonalMDCTConceal_SaveFreqSignal(self, x, x_e, l_frame_tcx, l_frame, sf, sf_exp, gain_tcx_e);
            arrow(); LINE_END();
            /* UpdateState */
            put1("op", OP_UPDATE); put1("n_new", l_frame_tcx); put1("pitch", pitch_arg); put1("bfi", 0); put1("tonal", 0);
            TonalMDCTConceal_UpdateState(self, l_frame_tcx, pitch_arg, 0, 0);
            pitch = pitch_arg;
            arrow(); LINE_END();
            /* SaveTimeSignal */
            Word16 synth[L_FRAME_MAX];
            for (int i = 0; i < n_samples; i++) synth[i] = sample((long)frame * n_samples + i);
            put1("op", OP_SAVE_TIME); put16("synth", synth, n_samples); put1("n_new", n_samples);
            TonalMDCTConceal_SaveTimeSignal(self, synth, n_samples);
            arrow(); LINE_END();
            tonal_active_before = 0;
        }

        for (int f = 0; f < lost; f++, frame++) {
            Word16 count = -1;
            /* Detect, as dec_tcx / er_util call it, with the pitch of the last good frame (0 when its LTP gain was 0). */
            put1("op", OP_DETECT); put1("pitch", pitch);
            TonalMDCTConceal_Detect(self, pitch, &count);
            arrow(); put1("count", count); LINE_END();
            int active = count > 0 && (next_random() % 8 != 0 || tonal_active_before);
            /* InsertNoise: garbage in the spectrum, an arbitrary exponent in. */
            for (int i = 0; i < n_samples; i++) x[i] = random32();
            Word16 x_e = (Word16)random_range(8, 24), seed = random16();
            Word16 tilt = next_random() % 4 ? (Word16)random_range(3000, 32767) : 32767;
            Word16 crossfade = next_random() % 6 ? (Word16)random_range(0, 32767) : (Word16)(next_random() % 2 ? 32767 : 0);
            Word16 cross_over = (Word16)random_range(n_samples * 3 / 4, n_samples);
            put1("op", OP_NOISE); put32("x_in", x, n_samples); put1("x_e_in", x_e); put1("active", active); put1("seed_in", seed);
            put1("tilt", tilt); put1("crossfade", crossfade); put1("cross_over", cross_over);
            TonalMDCTConceal_InsertNoise(self, x, &x_e, (Word8)active, &seed, tilt, crossfade, cross_over);
            arrow(); put32("x", x, n_samples); put1("x_e", x_e); put1("seed", seed); LINE_END();
            if (active) {
                put1("op", OP_APPLY); put32("x_in", x, n_samples); put1("x_e_in", x_e);
                TonalMDCTConceal_Apply(self, x, &x_e);
                arrow(); put32("x", x, n_samples); LINE_END();
            }
            Word32 pitch_arg = next_random() % 4 ? pitch : 0;
            put1("op", OP_UPDATE); put1("n_new", l_frame_tcx); put1("pitch", pitch_arg); put1("bfi", 1); put1("tonal", active);
            TonalMDCTConceal_UpdateState(self, l_frame_tcx, pitch_arg, 1, (Word8)active);
            arrow(); LINE_END();
            tonal_active_before = active;
        }
        }
    }
done:
    return 0;
}
