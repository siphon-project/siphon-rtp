/* Function-level oracle for lib_dec/syn_outp_fx.c. */
#include "harness.h"
#include "prot_fx.h"

static const Word16 frames[] = {160, 320, 640, 960};

static void case_syn_output(void)
{
    Word16 synth[960], out[960];
    Word16 mode = (Word16)random_range(1, 2), frame = frames[next_random() % 4];
    Word16 q = (Word16)random_range(-1, 12);
    random_signal(synth, frame, (next_random() & 3) ? 32767 : random_range(1, 4000));
    put1("mode", mode); put1("frame", frame); put1("q", q); put16("synth", synth, frame);
    syn_output_fx(mode, synth, frame, out, q);
    arrow(); put16("out", out, frame); end_line();
}

static void case_unscale_agc(void)
{
    Word16 x[320], y[320], mem[2];
    Word16 n = (next_random() & 1) ? 256 : 320, qx = (Word16)random_range(-1, 4);
    random_signal(x, n, (next_random() & 1) ? 32767 : random_range(100, 30000));
    if ((next_random() & 7) == 0) for (int i = 0; i < n; i++) x[i] = random16();
    mem[0] = (Word16)random_range(0, 16384); mem[1] = (Word16)random_range(-16384, 16383);
    if (next_random() & 1) mem[0] = 0;
    put16("x", x, n); put1("qx", qx); put16("mem", mem, 2);
    unscale_AGC(x, qx, y, mem, n);
    arrow(); put16("y", y, n); put16("mem", mem, 2); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "syn_output")) case_syn_output();
        else if (!strcmp(argv[2], "unscale_agc")) case_unscale_agc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
