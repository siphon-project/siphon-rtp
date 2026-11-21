/* Function-level oracle for lib_com/limit_t0_fx.c (limit_T0_fx). */
#include "harness.h"
#include "prot_fx.h"

static void case_limit_t0(void)
{
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 delta = (Word16)(next_random() & 1 ? 8 : random_range(1, 16));
    Word16 pit_flag = (Word16)(next_random() & 1 ? 0 : L_SUBFR);
    Word16 limit_flag = (Word16)random_range(0, 2);
    Word16 t0 = (Word16)random_range(-5, 300), t0_frac = (Word16)random_range(0, 3), t0_min, t0_max;
    put1("l_frame", l_frame); put1("delta", delta); put1("pit_flag", pit_flag); put1("limit_flag", limit_flag);
    put1("t0", t0); put1("t0_frac", t0_frac);
    limit_T0_fx(l_frame, delta, pit_flag, limit_flag, t0, t0_frac, &t0_min, &t0_max);
    arrow(); put1("t0_min", t0_min); put1("t0_max", t0_max); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "limit_t0")) case_limit_t0();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
