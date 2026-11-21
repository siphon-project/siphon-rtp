/* Function-level oracle for lib_com/fft_rel_fx.c. c_fft_fx is static and proven through r_fft_fx_lc. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

/* The (size, stages, table) triples the reference uses: the enhancer's 64-point transform with
 * phs_tbl_dec (enhancer_fx.c), and 128/256/512 with FFT_W64/W128/W256 (fft_fx.c, FEC_HQ_phase_ecu_fx.c). */
static void case_r_fft_fx_lc(void)
{
    static Word16 in[1024], out[1024];
    const Word16 *table;
    int pick = random_range(0, 5), size, stages;
    switch (pick) {
    case 0: case 1: case 2: size = 64; stages = 5; table = phs_tbl_dec; break;
    case 3: size = 128; stages = 6; table = FFT_W64; break;
    case 4: size = 256; stages = 7; table = FFT_W128; break;
    default: size = 512; stages = 8; table = FFT_W256; break;
    }
    Word16 isign = (Word16)(next_random() & 1);
    int style = random_range(0, 3);
    for (int i = 0; i < size; i++) in[i] = 0;
    if (style == 0) {
        for (int i = 0; i < size; i++) in[i] = random16();
    } else if (style == 1) {
        random_signal(in, size, random_range(100, 32767));
    } else if (style == 2) {
        /* a sparse fixed-codebook-like vector, as the enhancer transforms */
        for (int p = random_range(1, 8); p > 0; p--) in[random_range(0, size - 1)] = (Word16)random_range(-16384, 16384);
    } else {
        for (int i = 0; i < size; i++) in[i] = (Word16)random_range(-2000, 2000);
    }
    int inplace = (int)(next_random() & 1);
    put1("size", size); put1("stages", stages); put1("isign", isign); put1("inplace", inplace); put16("in", in, size);
    if (inplace) {
        memcpy(out, in, sizeof(Word16) * size);
        r_fft_fx_lc(table, (Word16)size, (Word16)(size / 2), (Word16)stages, out, out, isign);
    } else {
        r_fft_fx_lc(table, (Word16)size, (Word16)(size / 2), (Word16)stages, in, out, isign);
    }
    arrow(); put16("out", out, size); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "r_fft_fx_lc")) case_r_fft_fx_lc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
