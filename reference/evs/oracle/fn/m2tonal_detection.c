/* Function-level oracle for lib_dec/TonalComponentDetection.c: DetectTonalComponents and
 * RefineTonalComponents, and through them every static function of the file (calcPseudoSpec,
 * getEnvelope, GetF0, findStrongestHarmonics, CorrectF0, modifyThreshold(s), findCandidates,
 * RefineThresholdsUsingPitch, findTonalComponents).
 *
 * Inputs stay in the domain the concealment feeds: nSamples is the TCX length at the output
 * rate (160/320/640/960 lines, 25 Hz per line), nSamplesCore the core frame (256 or 320, a multiple
 * of FDNS_NPTS as mdct_shaping_16 requires), the pitch a Q16 lag at the core rate (or 0), and the
 * spectra harmonic combs over a noise floor so peaks are actually found. */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/TonalComponentDetection.c"

#define MAX_LINES L_FRAME_MAX

typedef struct
{
    Word16 n_samples, n_samples_core, floor_power_spectrum;
    Word16 last_spectrum[MAX_LINES];
    Word16 last_spectrum_exp;
    Word16 scale_factors[FDNS_NPTS], scale_factors_exp[FDNS_NPTS], scale_factors_max_e;
    Word32 power_spectrum[MAX_LINES];
    Word32 last_pitch_lag, current_pitch_lag;
} Scenario;

/* A harmonic comb of spacing `spacing_q10` (bins, Q10) over a noise floor: a magnitude per line. */
static void comb_magnitudes(Word32 *magnitude, int n, int spacing_q10, int level, int floor_level)
{
    for (int i = 0; i < n; i++) magnitude[i] = floor_level + random_range(0, floor_level);
    if (spacing_q10 <= 0) return;
    for (long position = spacing_q10; position / 1024 + 2 < n; position += spacing_q10) {
        int line = (int)(position / 1024);
        if (next_random() % 8 == 0) continue; /* missing harmonic */
        int height = level >> random_range(0, 3);
        magnitude[line] += height;
        magnitude[line - 1] += height >> random_range(1, 3);
        magnitude[line + 1] += height >> random_range(1, 3);
    }
}

static void make_scenario(Scenario *s)
{
    static const Word16 lengths[] = {160, 320, 640, 960};
    static const Word16 cores[] = {256, 320};
    s->n_samples = lengths[next_random() % 4];
    s->n_samples_core = cores[next_random() & 1];
    s->floor_power_spectrum = extract_l(Mpy_32_16_1(L_mult0(s->n_samples, s->n_samples), 82));

    /* The pitch: a lag at the core rate in [34*core/256, core/2], with quarter-sample fractions; 25 percent none. */
    Word32 lag = 0;
    int spacing_q10 = 0;
    if (next_random() % 4) {
        int whole = random_range(34 * s->n_samples_core / 256, s->n_samples_core / 2);
        lag = ((Word32)whole << 16) + (Word32)(next_random() % 4) * 16384;
        spacing_q10 = (int)(2.0 * s->n_samples_core * 1024.0 * 65536.0 / (double)lag);
    }
    s->last_pitch_lag = lag;
    /* Stable pitch 3 of 4 times (|diff| < 0.25 in Q16), a jump otherwise. */
    s->current_pitch_lag = lag ? lag + random_range(-6000, 6000) : (Word32)(next_random() % 3 ? 0 : 40 << 16);
    if (next_random() % 4 == 0 && lag) s->current_pitch_lag = lag + (Word32)random_range(1, 8) * 16384;
    if (s->current_pitch_lag < 0) s->current_pitch_lag = 0;

    /* Last good spectrum: 16 bit lines after mdct_shaping_16 inputs. */
    Word32 magnitude[MAX_LINES];
    comb_magnitudes(magnitude, s->n_samples, spacing_q10, random_range(2000, 30000), random_range(20, 600));
    for (int i = 0; i < MAX_LINES; i++) {
        Word32 m = i < s->n_samples ? magnitude[i] : 0;
        if (m > 32767) m = 32767;
        s->last_spectrum[i] = (next_random() & 1) ? (Word16)m : (Word16)-m;
    }
    s->last_spectrum_exp = (Word16)random_range(0, 12);
    Word16 max_e = -32768;
    for (int i = 0; i < FDNS_NPTS; i++) {
        s->scale_factors[i] = (Word16)random_range(6000, 32767);
        s->scale_factors_exp[i] = (Word16)random_range(0, 6);
        if (s->scale_factors_exp[i] > max_e) max_e = s->scale_factors_exp[i];
    }
    s->scale_factors_max_e = max_e;

    /* Second last power spectrum (32 bit, positive, 3 bits headroom): comb squared. */
    comb_magnitudes(magnitude, s->n_samples, spacing_q10, random_range(1 << 8, 1 << 12), random_range(2, 60));
    int shift = random_range(0, 3);
    for (int i = 0; i < MAX_LINES; i++) {
        Word32 m = i < s->n_samples ? magnitude[i] : 0;
        s->power_spectrum[i] = m * m << shift;
        if (s->power_spectrum[i] < s->floor_power_spectrum && i < s->n_samples) s->power_spectrum[i] = s->floor_power_spectrum;
    }
}

static void put_inputs(const Scenario *s)
{
    put1("n_samples", s->n_samples); put1("n_samples_core", s->n_samples_core);
    put1("floor", s->floor_power_spectrum);
    put1("last_pitch_lag", s->last_pitch_lag); put1("current_pitch_lag", s->current_pitch_lag);
    put16("last_spectrum", s->last_spectrum, MAX_LINES);
    put1("last_spectrum_exp", s->last_spectrum_exp);
    put16("scale_factors", s->scale_factors, FDNS_NPTS);
    put16("scale_factors_exp", s->scale_factors_exp, FDNS_NPTS);
    put1("scale_factors_max_e", s->scale_factors_max_e);
    put32("power_spectrum", s->power_spectrum, s->n_samples);
}

static void case_detect(void)
{
    Scenario *s = calloc(1, sizeof(Scenario));
    make_scenario(s);
    put_inputs(s);
    Word16 index_of_tonal_peak[MAX_NUMBER_OF_IDX], lower[MAX_NUMBER_OF_IDX], upper[MAX_NUMBER_OF_IDX];
    Word16 num_indexes = -1;
    memset(index_of_tonal_peak, 0, sizeof index_of_tonal_peak); memset(lower, 0, sizeof lower); memset(upper, 0, sizeof upper);
    DetectTonalComponents(index_of_tonal_peak, lower, upper, &num_indexes, s->last_pitch_lag, s->current_pitch_lag,
                          s->last_spectrum, s->last_spectrum_exp, s->scale_factors, s->scale_factors_exp,
                          s->scale_factors_max_e, s->power_spectrum, s->n_samples, s->n_samples_core,
                          s->floor_power_spectrum);
    arrow();
    put1("num_indexes", num_indexes);
    put16("index_of_tonal_peak", index_of_tonal_peak, MAX_NUMBER_OF_IDX);
    put16("lower", lower, MAX_NUMBER_OF_IDX);
    put16("upper", upper, MAX_NUMBER_OF_IDX);
    end_line();
    free(s);
}

static void case_refine(void)
{
    Scenario *s = calloc(1, sizeof(Scenario));
    make_scenario(s);
    put_inputs(s);
    Word16 index_of_tonal_peak[MAX_NUMBER_OF_IDX], lower[MAX_NUMBER_OF_IDX], upper[MAX_NUMBER_OF_IDX];
    Word16 phase_diff[MAX_NUMBER_OF_IDX], phases[MAX_NUMBER_OF_IDX * GROUP_LENGTH];
    Word16 num_indexes = 0;
    memset(index_of_tonal_peak, 0, sizeof index_of_tonal_peak); memset(lower, 0, sizeof lower); memset(upper, 0, sizeof upper);
    /* The tonal components of an earlier detection in the same spectrum, then a refinement of them. */
    DetectTonalComponents(index_of_tonal_peak, lower, upper, &num_indexes, s->last_pitch_lag, s->last_pitch_lag,
                          s->last_spectrum, s->last_spectrum_exp, s->scale_factors, s->scale_factors_exp,
                          s->scale_factors_max_e, s->power_spectrum, s->n_samples, s->n_samples_core,
                          s->floor_power_spectrum);
    for (int i = 0; i < MAX_NUMBER_OF_IDX; i++) phase_diff[i] = (Word16)(1000 + i * 37);
    for (int i = 0; i < MAX_NUMBER_OF_IDX * GROUP_LENGTH; i++) phases[i] = (Word16)(2000 + i * 3);
    put1("old_num_indexes", num_indexes);
    put16("old_index_of_tonal_peak", index_of_tonal_peak, MAX_NUMBER_OF_IDX);
    put16("old_lower", lower, MAX_NUMBER_OF_IDX);
    put16("old_upper", upper, MAX_NUMBER_OF_IDX);
    put16("old_phase_diff", phase_diff, MAX_NUMBER_OF_IDX);
    put16("old_phases", phases, MAX_NUMBER_OF_IDX * GROUP_LENGTH);
    /* Refine against a (slightly) different spectrum: new randomness in the power spectrum. */
    for (int i = 0; i < s->n_samples; i++) {
        if (next_random() % 5 == 0) s->power_spectrum[i] = Mpy_32_16_1(s->power_spectrum[i], (Word16)random_range(8000, 32767));
        if (s->power_spectrum[i] < s->floor_power_spectrum) s->power_spectrum[i] = s->floor_power_spectrum;
    }
    put32("new_power_spectrum", s->power_spectrum, s->n_samples);
    RefineTonalComponents(index_of_tonal_peak, lower, upper, phase_diff, phases, &num_indexes, s->last_pitch_lag,
                          s->current_pitch_lag, s->last_spectrum, s->last_spectrum_exp, s->scale_factors,
                          s->scale_factors_exp, s->scale_factors_max_e, s->power_spectrum, s->n_samples,
                          s->n_samples_core, s->floor_power_spectrum);
    arrow();
    put1("num_indexes", num_indexes);
    put16("index_of_tonal_peak", index_of_tonal_peak, MAX_NUMBER_OF_IDX);
    put16("lower", lower, MAX_NUMBER_OF_IDX);
    put16("upper", upper, MAX_NUMBER_OF_IDX);
    put16("phase_diff", phase_diff, MAX_NUMBER_OF_IDX);
    put16("phases", phases, MAX_NUMBER_OF_IDX * GROUP_LENGTH);
    end_line();
    free(s);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "detect")) case_detect();
        else if (!strcmp(argv[2], "refine")) case_refine();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
