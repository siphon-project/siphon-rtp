/* Function-level oracle for lib_com/range_com_fx.c (rangeCoderFinalizationFBits_fx). */
#include "harness.h"
#include "prot_fx.h"

static void case_fbits(void)
{
    Word16 brc = (Word16)random_range(0, 1200), fbits;
    UWord32 intrc = (UWord32)random32();
    if (next_random() % 4 == 0) intrc >>= random_range(0, 31);
    put1("brc", brc); put1("int_rc", (long long)intrc);
    rangeCoderFinalizationFBits_fx(brc, intrc, &fbits);
    arrow(); put1("fbits", fbits);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "fbits")) case_fbits();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
