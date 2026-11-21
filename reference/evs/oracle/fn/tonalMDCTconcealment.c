/* Function-level oracle for lib_dec/tonalMDCTconcealment.c (TonalMDCTConceal_Init). Pointer
 * fields are printed as the offset / buffer index the Rust state stores. */
#include "harness.h"
#include "prot_fx.h"

static void case_init(void)
{
    struct tonalmdctconceal *self = calloc(1, sizeof(struct tonalmdctconceal));
    TCX_config tcx_cfg;
    static const Word16 lengths[] = {80, 160, 256, 320, 480, 512, 640, 960};
    Word16 n = lengths[next_random() % 8], core = (Word16)random_range(n / 2, n), sf = (Word16)random_range(1, FDNS_NPTS);
    /* Leave state behind a first configuration half the time, as a re-initialisation does. */
    Word16 dirty = (Word16)(next_random() & 1);
    if (dirty) {
        self->lastBlockData.blockIsValid = 1; self->secondLastBlockData.blockIsValid = 1;
        self->lastBlockData.blockIsConcealed = 1; self->secondLastBlockData.blockIsConcealed = 1;
        self->lastPitchLag = random32(); self->nSamples = (Word16)(n == 960 ? 640 : 960); self->nScaleFactors = (Word16)random_range(0, 64);
    }
    put1("n_samples", n); put1("n_samples_core", core); put1("n_scale_factors", sf); put1("dirty", dirty);
    put1("last_pitch_lag", self->lastPitchLag); put1("old_n_samples", self->nSamples); put1("old_n_scale_factors", self->nScaleFactors);
    TONALMDCTCONCEAL_ERROR error = TonalMDCTConceal_Init(self, n, core, sf, &tcx_cfg);
    arrow(); put1("error", error); put1("n_samples", self->nSamples); put1("n_samples_core", self->nSamplesCore);
    put1("n_scale_factors", self->nScaleFactors); put1("last_pitch_lag", self->lastPitchLag);
    put1("last_spectral", self->lastBlockData.spectralData == self->spectralDataBuffers[0] ? 0 : 1);
    put1("second_spectral", self->secondLastBlockData.spectralData == self->spectralDataBuffers[1] ? 1 : 0);
    put1("second_power", self->secondLastPowerSpectrum == self->spectralDataBuffers[1] ? 1 : 0);
    put1("last_sf", self->lastBlockData.scaleFactors == self->scaleFactorsBuffers[0] ? 0 : 1);
    put1("second_sf", self->secondLastBlockData.scaleFactors == self->scaleFactorsBuffers[1] ? 1 : 0);
    put1("last_sf_exp", self->lastBlockData.scaleFactors_exp == self->scaleFactorsBuffers_exp[0] ? 0 : 1);
    put1("second_sf_exp", self->secondLastBlockData.scaleFactors_exp == self->scaleFactorsBuffers_exp[1] ? 1 : 0);
    put1("valid", self->lastBlockData.blockIsValid); put1("second_valid", self->secondLastBlockData.blockIsValid);
    put1("concealed", self->lastBlockData.blockIsConcealed); put1("second_concealed", self->secondLastBlockData.blockIsConcealed);
    put1("last_pcm_out", self->lastPcmOut - self->timeDataBuffer);
    put1("second_last_pcm_out", self->secondLastPcmOut - self->timeDataBuffer);
    put1("tci_at_time_data", (void *)self->pTCI == (void *)self->timeDataBuffer);
    put1("tcx_cfg_is_argument", self->tcx_cfg == &tcx_cfg);
    end_line();
    free(self);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "init")) case_init();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
