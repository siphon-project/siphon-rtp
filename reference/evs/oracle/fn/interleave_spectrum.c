/* Function-level oracle for lib_com/interleave_spectrum_fx.c: both directions over the 16, 32 and
 * 48 kHz layouts on random spectra (the whole 960-coefficient buffer is compared, so the untouched
 * tail of the 48 kHz interleave is checked too). */
#include "harness.h"
#include "prot_fx.h"

static void case_interleave(int inverse)
{
    static const Word16 lengths[] = {L_FRAME16k, L_FRAME32k, L_FRAME48k};
    Word32 coefs[L_FRAME48k];
    Word16 length = lengths[next_random() % 3];
    int mode = next_random() % 3;
    for (int i = 0; i < L_FRAME48k; i++) coefs[i] = mode == 0 ? random32() : mode == 1 ? (Word32)i : (Word32)random_range(-100000, 100000);
    put32("coefs", coefs, L_FRAME48k); put1("length", length);
    if (inverse) de_interleave_spectrum_fx(coefs, length);
    else interleave_spectrum_fx(coefs, length);
    arrow(); put32("coefs", coefs, L_FRAME48k); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "interleave_spectrum")) case_interleave(0);
        else if (!strcmp(argv[2], "de_interleave_spectrum")) case_interleave(1);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
