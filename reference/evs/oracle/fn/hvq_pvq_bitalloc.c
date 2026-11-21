/* Function-level oracle for lib_com/hvq_pvq_bitalloc_fx.c (hvq_pvq_bitalloc_fx), on the inputs
 * peak_vq_dec_fx gives it: the PVQ bit budget left after the peaks, SWB or FB at 24.4 / 32 kbit/s,
 * a norm envelope and the peak energy as a (mantissa, exponent) pair. */
#include "harness.h"
#include "prot_fx.h"
#include "cnst_fx.h"

/* A norm envelope over the harmonic bands: a random walk, now and then one band far stronger
 * (a small index) so the selected-band path is taken. */
static void random_envelope(Word16 *ynrm, int n)
{
    int v = random_range(5, 35);
    for (int i = 0; i < n; i++) {
        v += random_range(-3, 3);
        if (v < 0) v = 0;
        if (v > 39) v = 39;
        ynrm[i] = (Word16)v;
    }
    if (next_random() % 2) ynrm[random_range(HVQ_THRES_SFM_24k, n - 1)] = (Word16)random_range(0, 10);
    if (next_random() % 8 == 0) for (int i = 0; i < n; i++) ynrm[i] = (Word16)random_range(0, 39);
}

static void case_hvq_pvq_bitalloc(void)
{
    Word16 ynrm[NB_SFM], R[NB_SFM], Rk[MAX_PVQ_BANDS], sel_bands[HVQ_NUM_SFM_24k], n_sel = -7;
    Word32 brate = next_random() & 1 ? HQ_24k40 : HQ_32k;
    Word16 bwidth = next_random() & 1 ? FB : SWB;
    Word16 num_bits = (Word16)(next_random() % 8 == 0 ? random_range(-40, 120) : random_range(100, brate == HQ_24k40 ? 480 : 640));
    Word32 man; Word16 ex;
    random_envelope(ynrm, SFM_N_HARM_FB);
    for (int i = 0; i < NB_SFM; i++) R[i] = (Word16)(next_random() % 4 ? 0 : random_range(0, 300));
    for (int i = 0; i < MAX_PVQ_BANDS; i++) Rk[i] = -7;
    for (int i = 0; i < HVQ_NUM_SFM_24k; i++) sel_bands[i] = -7;
    if (next_random() % 6 == 0) { man = 0; ex = 32; }
    else { man = (Word32)(0x40000000u | (next_random() & 0x3fffffff)); ex = (Word16)random_range(-20, 40); }
    put1("num_bits", num_bits); put1("brate", brate); put1("bwidth", bwidth); put16("ynrm", ynrm, SFM_N_HARM_FB);
    put1("man", man); put1("ex", ex); put16("r", R, NB_SFM);
    Word16 bands = hvq_pvq_bitalloc_fx(num_bits, brate, bwidth, ynrm, man, ex, Rk, R, sel_bands, &n_sel);
    arrow(); put1("bands", bands); put16("rk", Rk, MAX_PVQ_BANDS); put16("r", R, NB_SFM);
    put16("sel_bands", sel_bands, HVQ_NUM_SFM_24k); put1("n_sel", n_sel); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hvq_pvq_bitalloc")) case_hvq_pvq_bitalloc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
