/* Function-level oracle for lib_com/get_gain.c (get_gain). */
#include "harness.h"
#include "prot_fx.h"

static void case_get_gain(void)
{
    Word16 x[L_FRAME16k], y[L_FRAME16k];
    Word16 n = (Word16)(next_random() & 1 ? L_SUBFR - 1 : random_range(1, L_FRAME16k));
    int kind = next_random() % 4;
    random_signal(y, n, kind == 0 ? 32767 : 4000);
    if (kind == 1) for (int i = 0; i < n; i++) x[i] = add(y[i], (Word16)random_range(-500, 500));
    else random_signal(x, n, kind == 2 ? 100 : 20000);
    if (next_random() % 8 == 0) for (int i = 0; i < n; i++) y[i] = random16();
    if (next_random() % 16 == 0) memset(y, 0, sizeof(y));
    put16("x", x, n); put16("y", y, n); put1("n", n);
    Carry = (Flag)(next_random() & 1);
    Word32 g = get_gain(x, y, n);
    arrow(); put1("gain", g); put1("carry", Carry); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "get_gain")) case_get_gain();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
