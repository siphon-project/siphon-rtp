/* Function-level oracle for lib_com/gs_bitallocation_fx.c (GSC band selection and bit allocation,
 * decoder side: exc_diff / concat_in are NULL). */
#include "harness.h"
#include "prot_fx.h"

static void case_bands_and_bit_alloc(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200};
    static const Word16 coder_types[] = {AUDIO, INACTIVE, GENERIC};
    Word16 ener[MBANDS_GN], max_ener_band[MBANDS_GN], out_bits[MBANDS_GN];
    Word16 cor_strong_limit = (Word16)random_range(0, 1), noise_lev = (Word16)random_range(0, 16);
    Word32 core_brate = rates[next_random() % 4];
    Word16 diff_len = (Word16)(next_random() & 1 ? 0 : random_range(1, 256));
    Word16 bits_used = (Word16)random_range(20, core_brate / 50 - 30);
    Word16 coder_type = coder_types[next_random() % 3], bwidth = (Word16)random_range(0, 2);
    Word16 noisy = (Word16)(next_random() % 4 == 0);
    Word16 bit = random16(), nb_subbands = random16(), pvq_len = random16();
    for (int b = 0; b < MBANDS_GN; b++) {
        ener[b] = (Word16)(next_random() % 6 ? random_range(-2000, 24000) : random16());
        max_ener_band[b] = -999; out_bits[b] = -999;
    }
    /* Ties between band energies decide the order the maximum search picks them in. */
    if (next_random() % 5 == 0) ener[random_range(4, 15)] = ener[random_range(4, 15)];
    put1("cor_strong_limit", cor_strong_limit); put1("noise_lev", noise_lev); put1("core_brate", core_brate);
    put1("diff_len", diff_len); put1("bits_used", bits_used); put16("ener_per_bd_i_q", ener, MBANDS_GN);
    put1("coder_type", coder_type); put1("bwidth", bwidth); put1("gsc_noisy_speech", noisy);
    bands_and_bit_alloc_fx(cor_strong_limit, noise_lev, core_brate, diff_len, bits_used, &bit, ener, max_ener_band,
                           out_bits, &nb_subbands, NULL, NULL, &pvq_len, coder_type, bwidth, noisy);
    arrow(); put1("bit", bit); put16("max_ener_band", max_ener_band, MBANDS_GN); put16("out_bits_per_bands", out_bits, MBANDS_GN);
    put1("nb_subbands", nb_subbands); put1("pvq_len", pvq_len); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "bands_and_bit_alloc")) case_bands_and_bit_alloc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
