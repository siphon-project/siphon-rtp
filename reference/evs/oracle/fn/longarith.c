/* Function-level oracle for lib_com/longarith.c (longshr). */
#include "harness.h"
#include "prot_fx.h"

static void case_longshr(void)
{
    UWord32 a[8];
    Word16 bits = (Word16)random_range(1, 31), len = (Word16)random_range(1, 8);
    for (int i = 0; i < len; i++) a[i] = (UWord32)random32();
    printf(" a="); for (int i = 0; i < len; i++) printf(i ? ",%d" : "%d", (Word32)a[i]);
    put1("bits", bits);
    longshr(a, bits, len);
    arrow(); printf(" a="); for (int i = 0; i < len; i++) printf(i ? ",%d" : "%d", (Word32)a[i]);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "longshr")) case_longshr();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
