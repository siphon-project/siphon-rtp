/* Function-level oracle for basic_math/log2.c (Log2_norm_lc). */
#include "harness.h"
#include "prot_fx.h"
#include "log2.h"

/* Log2_norm_lc is only ever called on a normalised mantissa (or a non-positive value, which it
 * maps to 0x40000000); anything else would index outside its table. */
static void case_log2_norm_lc(void)
{
    Word32 x;
    switch (next_random() % 4) {
    case 0: x = (Word32)random_range(0x40000000, 0x7fffffff); break;
    case 1: { static const Word32 e[] = {0x40000000, 0x40000001, 0x7fffffff, 0x7fff0000, 0x5a827999, 0, -1, (Word32)0x80000000};
              x = e[next_random() % 8]; break; }
    case 2: x = -(Word32)random_range(1, 0x7fffffff); break;
    default: { Word32 v = random32(); x = v > 0 ? L_shl(v, norm_l(v)) : v; break; }
    }
    put32("x", &x, 1);
    arrow(); put1("y", Log2_norm_lc(x)); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "log2_norm_lc")) case_log2_norm_lc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
