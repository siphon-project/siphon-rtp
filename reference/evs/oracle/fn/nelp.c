/* Function-level oracle for lib_com/nelp_fx.c: dequantize_uvg_fx and generate_nelp_excitation_fx. */
#include "harness.h"
#include "prot_fx.h"

static void case_dequantize_uvg(void)
{
    Word16 iG1 = (Word16)random_range(0, 31), iG2[2], G[10];
    iG2[0] = (Word16)random_range(0, 63);
    iG2[1] = (Word16)random_range(0, 63);
    Word16 bwidth = (Word16)random_range(NB, SWB), do_scale = (Word16)(next_random() & 1);
    for (int i = 0; i < 10; i++) G[i] = -7;
    put1("i_g1", iG1); put16("i_g2", iG2, 2); put1("bwidth", bwidth); put1("do_scale", do_scale);
    Word16 q = dequantize_uvg_fx(iG1, iG2, G, bwidth, do_scale);
    arrow(); put1("q", q); put16("g", G, 10); end_line();
}

static void case_generate_nelp_excitation(void)
{
    Word16 seed = random16(), gains[10], output[L_FRAME];
    static const Word16 facs[] = {22446, 19005};
    Word16 gain_fac = (next_random() % 4) ? facs[next_random() & 1] : random16();
    int mode = next_random() % 3;
    for (int i = 0; i < 10; i++)
        gains[i] = mode == 0 ? (Word16)random_range(0, 3000) : mode == 1 ? (Word16)random_range(0, 32767 >> random_range(0, 14)) : random16();
    for (int i = 0; i < L_FRAME; i++) output[i] = -3;
    put1("seed", seed); put16("gains", gains, 10); put1("gain_fac", gain_fac);
    generate_nelp_excitation_fx(&seed, gains, output, gain_fac);
    arrow(); put1("seed", seed); put16("output", output, L_FRAME); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "dequantize_uvg")) case_dequantize_uvg();
        else if (!strcmp(argv[2], "generate_nelp_excitation")) case_generate_nelp_excitation();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
