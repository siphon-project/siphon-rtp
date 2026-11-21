/* Function-level oracle for basic_math/math_32.c (Mult_32_16, Mult_32_32). */
#include "harness.h"
#include "prot_fx.h"
#include "math_32.h"

static void case_mult_32_16(void)
{
    Word32 a = random32();
    Word16 b = random16();
    put1("a", a); put1("b", b);
    arrow(); put1("y", Mult_32_16(a, b)); end_line();
}

static void case_mult_32_32(void)
{
    Word32 a = random32(), b = random32();
    put1("a", a); put1("b", b);
    arrow(); put1("y", Mult_32_32(a, b)); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "mult_32_16")) case_mult_32_16();
        else if (!strcmp(argv[2], "mult_32_32")) case_mult_32_32();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
