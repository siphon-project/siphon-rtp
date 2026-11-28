/* Function-level oracle for lib_dec/re8_dec_fx.c (re8_dec_fx). It also proves
 * re8_decode_base_index_fx (lib_dec/lead_deindexing_fx.c), re8_k2y_fx (lib_com/re8_util_fx.c) and
 * re8_PPV_fx (lib_com/re8_ppv_fx.c), which the decoder reaches only through it. */
#include "harness.h"
#include "prot_fx.h"

/* Every codebook number AVQ_demuxdec_fx can produce (0, 2..33), base indices over the whole 16-bit
 * range each codebook's bit count allows (4n bits below Q5, 12 or 16 above; a wider index is not
 * something the demultiplexer can read, and the reference walks off its tables on one) and Voronoi indices of the extension order the codebook
 * number implies. */
static void case_re8_dec(void)
{
    Word16 n = (next_random() % 6 == 0) ? 0 : (Word16)random_range(2, 33);
    if (next_random() % 3 == 0) n = (Word16)random_range(2, 8);
    UWord16 I;
    int bits = n < 5 ? 4 * n : (n & 1 ? 12 : 16);
    if (bits >= 16) I = (UWord16)next_random();
    else I = (UWord16)(next_random() & ((1u << bits) - 1));
    /* the indices past the Q4 codebook that the reference folds to 0 */
    if (bits == 16 && next_random() % 8 == 0) I = (UWord16)random_range(65510, 65535);
    Word16 k[8], y[8];
    int order = n < 5 ? 0 : (n >> 1) - ((n & 1) ? 1 : 2);
    for (int i = 0; i < 8; i++) k[i] = order > 0 ? (Word16)(next_random() & ((1u << (order > 15 ? 15 : order)) - 1)) : 0;
    put1("n", n); put1("i", I); put16("k", k, 8);
    re8_dec_fx(n, I, k, y);
    arrow(); put16("y", y, 8); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "re8_dec")) case_re8_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
