/* Function-level oracle for lib_com/fine_gain_bits_fx.c. */
#include "harness.h"
#include "prot_fx.h"

static void case_assign_gain_bits(void)
{
    Word16 band_width[SFM_N_HARM_FB], rk[SFM_N_HARM_FB], bits[SFM_N_HARM_FB], rcalc;
    Word16 bands = (Word16)random_range(1, SFM_N_HARM_FB), core = (next_random() % 4) ? HQ_CORE : TCX_20_CORE;
    for (int i = 0; i < bands; i++) {
        band_width[i] = (Word16)(8 * random_range(1, 12));
        rk[i] = (next_random() % 4) == 0 ? 0 : (Word16)random_range(0, band_width[i] * 8 * 8);
        if ((next_random() % 8) == 0) rk[i] = (Word16)(band_width[i] * 8 * random_range(1, 8)); /* exact bits per sample */
    }
    if ((next_random() % 8) == 0) for (int i = 0; i < bands; i++) rk[i] = 0;
    put1("core", core); put16("band_width", band_width, bands); put16("rk", rk, bands);
    Word16 r = assign_gain_bits_fx(core, bands, band_width, rk, bits, &rcalc);
    arrow(); put1("r", r); put16("rk", rk, bands); put16("bits", bits, bands); put1("rcalc", rcalc); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "assign_gain_bits")) case_assign_gain_bits();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
