/* Function-level oracle for get_subframe_pitch (lib_dec/pitch_extr.c) and the lower case
 * rescale_mem (lib_com/scale_mem_fx.c), as the MODE2 concealment calls them: lags in the pitch range
 * with a fraction (15Q16), 4 or 5 subframes; excitation Q 0..12, synthesis Qs -1..12, a synthesis
 * memory of any loudness, with or without the synthesis so far. */
#include "harness.h"
#include "prot_fx.h"

static void case_get_subframe_pitch(void)
{
    Word16 n = (Word16)((next_random() & 1) ? 4 : 5);
    Word32 start = (Word32)(random_range(17, 289) * 65536.0 + random_range(0, 65535));
    Word32 end = (Word32)(random_range(17, 289) * 65536.0 + random_range(0, 65535));
    Word32 buf[NB_SUBFR16k] = {-1, -1, -1, -1, -1};
    if (next_random() % 4 == 0) end = start + (Word32)random_range(-200000, 200000);
    if (end < 65536) end = 65536;
    put1("n", n); put1("start", start); put1("end", end);
    get_subframe_pitch(n, start, end, buf);
    arrow(); put32("buf", buf, NB_SUBFR16k); end_line();
}

static void case_rescale_mem(void)
{
    Word16 q_exc = (Word16)random_range(0, 12), prev_q = (Word16)random_range(-1, 12), q_syn = (Word16)random_range(-1, 12);
    Word16 mem[M], syn[L_FRAME16k];
    Word16 mem_len = (Word16)((next_random() % 4) ? M : random_range(1, M));
    Word16 i_subfr = (Word16)((next_random() & 1) ? 0 : random_range(1, L_FRAME16k));
    int with_syn = next_random() & 1;
    static const int magnitudes[] = {0, 3, 100, 2000, 16000, 32767};
    int magnitude = magnitudes[next_random() % 6];
    random_signal(mem, M, magnitude ? magnitude : 1);
    if (!magnitude) memset(mem, 0, sizeof mem);
    random_signal(syn, L_FRAME16k, magnitudes[next_random() % 6] + 1);
    put1("q_exc", q_exc); put1("prev_q", prev_q); put1("q_syn", q_syn); put16("mem", mem, M); put16("syn", syn, L_FRAME16k);
    put1("mem_len", mem_len); put1("i_subfr", i_subfr); put1("with_syn", with_syn);
    Word16 shift = rescale_mem(&q_exc, &prev_q, &q_syn, mem, with_syn ? syn : NULL, mem_len, i_subfr);
    arrow(); put1("shift", shift); put1("prev_q", prev_q); put1("q_syn", q_syn); put16("mem", mem, M);
    put16("syn", syn, L_FRAME16k); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "get_subframe_pitch")) case_get_subframe_pitch();
        else if (!strcmp(argv[2], "rescale_mem")) case_rescale_mem();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
