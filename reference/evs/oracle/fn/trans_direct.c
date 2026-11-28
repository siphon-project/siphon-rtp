/* Function-level oracle for lib_com/trans_direct_fx.c (direct_transform_fx). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 frame_lengths[] = {160, 320, 640, 960};

static void fill_signal32(Word32 *x, int n)
{
    int mode = random_range(0, 3), shift = random_range(0, 16);
    Word16 tmp[960];
    if (mode == 3) { for (int i = 0; i < n; i++) x[i] = random32(); return; }
    random_signal(tmp, n, random_range(1, 32767));
    for (int i = 0; i < n; i++) x[i] = ((Word32)tmp[i] << shift) + (mode == 1 ? random_range(-(1 << shift), 1 << shift) : 0);
    if (mode == 2) for (int i = 0; i < n; i++) x[i] = 0;
}

static void case_direct_transform(void)
{
    Word32 in[960], out[960];
    Word16 l = frame_lengths[next_random() % 4], is_transient = (Word16)(next_random() & 1);
    Word16 q = (Word16)random_range(-2, 15);
    fill_signal32(in, l);
    put32("in", in, l); put1("is_transient", is_transient); put1("l", l); put1("q", q);
    direct_transform_fx(in, out, is_transient, l, &q);
    arrow(); put32("out", out, l); put1("q", q); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "direct_transform")) case_direct_transform();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
