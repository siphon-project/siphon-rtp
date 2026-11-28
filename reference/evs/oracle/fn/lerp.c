/* Function-level oracle for lib_com/lerp.c (lerp and its static lerp_proc). Lengths are the frame,
 * overlap, excitation-memory and CLDFB-state sizes the decoder resamples between, plus random ones,
 * at ratios up to 8 so the staged (doubling / halving) path runs too. The three ways the decoder
 * aims the two pointers are all covered: two buffers, the same position (in place), and two offsets
 * of one memory (mem + L - old to mem + L - new, and arbitrary offsets). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 sizes[] = {16, 20, 24, 32, 40, 48, 60, 64, 80, 90, 96, 100, 120, 128, 144, 160, 180, 192,
                               200, 240, 256, 288, 320, 360, 384, 400, 480, 512, 576, 640, 720, 768, 800, 960,
                               1200, 1280, 1440, 1920};
#define NSIZES ((int)(sizeof(sizes) / sizeof(sizes[0])))

static void pick(Word16 *new_size, Word16 *old_size)
{
    for (;;) {
        Word16 a, b;
        if (random_range(0, 3) == 0) { a = (Word16)random_range(3, 960); b = (Word16)random_range(3, 960); }
        else { a = sizes[random_range(0, NSIZES - 1)]; b = sizes[random_range(0, NSIZES - 1)]; }
        if (random_range(0, 9) == 0) b = a;
        if (a > 8 * b || b > 8 * a) continue;
        *new_size = a; *old_size = b;
        return;
    }
}

static void fill(Word16 *x, int n)
{
    if (random_range(0, 5) == 0) { for (int i = 0; i < n; i++) x[i] = random16(); return; }
    random_signal(x, n, random_range(1, 32767));
}

static void case_lerp(void)
{
    static Word16 a[4400], out[2000];
    Word16 new_size, old_size;
    int mode = random_range(0, 3);
    pick(&new_size, &old_size);
    if (mode == 0) {
        fill(a, old_size + 1);
        fill(out, new_size);
        put1("mode", mode); put1("new", new_size); put1("old", old_size);
        put16("f", a, old_size + 1); put16("out", out, new_size);
        lerp(a, out, new_size, old_size);
        arrow(); put16("out", out, new_size); end_line();
        return;
    }
    if (new_size > 1920) new_size = 1920;
    int len = (new_size > old_size ? new_size : old_size) + 2;
    int f_at = 0, out_at = 0;
    if (mode == 2) {
        int mem = (new_size > old_size ? new_size : old_size) + random_range(0, 40);
        f_at = mem - old_size; out_at = mem - new_size; len = mem + 2;
    } else if (mode == 3) {
        /* arbitrary offsets of one memory: partial overlap either way, or none */
        int mem = (new_size > old_size ? new_size : old_size) + random_range(0, 400);
        f_at = random_range(0, mem - old_size); out_at = random_range(0, mem - new_size); len = mem + 2;
    }
    /* a reduction by more than 3.96 halves in stages through the output, writing old / 2 there */
    if (out_at + old_size + 2 > len) len = out_at + old_size + 2;
    fill(a, len);
    put1("mode", mode); put1("new", new_size); put1("old", old_size); put1("f_at", f_at); put1("out_at", out_at);
    put16("x", a, len);
    lerp(a + f_at, a + out_at, new_size, old_size);
    arrow(); put16("x", a, len); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lerp")) case_lerp();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
