/* Function-level oracle for lib_com/hp50.c. */
#include "harness.h"
#include "../../c-code/lib_com/hp50.c"

static void case_mpy(void)
{
    Word32 a = random32(), b = random32();
    Word16 c = random16();
    put1("a", a); put1("b", b); put1("c", c);
    arrow();
    put1("r32", HP50_Mpy_32_32_fix(a, b));
    put1("r16", HP50_Mode2_Mpy_32_16_fix(a, c));
    end_line();
}

static const Word16 frames[] = {160, 320, 640, 960};

static void case_hp20(void)
{
    Word16 lg = frames[next_random() % 4];
    Word32 sfreq = L_mult0(lg, 50);
    Word16 signal[960];
    Word32 mem[5];
    int magnitude = (next_random() & 3) == 0 ? 32767 : random_range(1, 20000);
    random_signal(signal, lg, magnitude);
    if ((next_random() & 7) == 0) for (int i = 0; i < lg; i++) signal[i] = random16();
    if ((next_random() & 15) == 0) for (int i = 0; i < lg; i++) signal[i] = 0;
    mem[4] = random_range(-12, 3);
    for (int i = 0; i < 4; i++) {
        int kind = next_random() % 4;
        mem[i] = kind == 0 ? 0 : kind == 1 ? random32() : (Word32)random_range(-(1 << 24), 1 << 24);
    }
    put16("signal", signal, lg); put32("mem", mem, 5); put1("sfreq", sfreq);
    hp20(signal, 1, lg, mem, sfreq);
    arrow(); put16("signal", signal, lg); put32("mem", mem, 5); end_line();
}

/* filter_2nd_order with a stride, which hp20 never uses, and arbitrary coefficients. */
static void case_filter(void)
{
    Word16 stride = (Word16)random_range(1, 3), lg = (Word16)(2 * random_range(1, 40));
    Word16 prescale = (Word16)random_range(-12, 3);
    Word16 signal[3 * 80];
    Word32 mem[4], a1 = random32(), a2 = random32(), b1 = random32(), b2 = random32();
    random_signal(signal, stride * lg, 32767);
    for (int i = 0; i < 4; i++) mem[i] = random32();
    put16("signal", signal, stride * lg); put1("stride", stride); put1("prescale", prescale);
    put32("mem", mem, 4); put1("a1", a1); put1("a2", a2); put1("b1", b1); put1("b2", b2);
    filter_2nd_order(signal, stride, prescale, lg, mem, a1, a2, b1, b2);
    arrow(); put16("signal", signal, stride * lg); put32("mem", mem, 4); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "mpy")) case_mpy();
        else if (!strcmp(argv[2], "hp20")) case_hp20();
        else if (!strcmp(argv[2], "filter_2nd_order")) case_filter();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
