/* Function-level oracle for lib_dec/dec_acelp.c. */
#include "harness.h"
#include "../../c-code/lib_dec/dec_acelp.c"

static void case_decode_arithtrack(void)
{
    Word16 v[64];
    Word16 p = (Word16)random_range(1, 9), track = (Word16)random_range(0, 3);
    Word32 limit = pulsestostates[16][p - 1];
    Word32 s = (Word32)(((unsigned long long)next_random() << 16 ^ next_random()) % (unsigned long long)limit);
    if ((next_random() & 7) == 0) s = (next_random() & 1) ? 0 : limit - 1;
    for (int i = 0; i < 64; i++) v[i] = random16();
    put1("s", s); put1("p", p); put1("track", track); put16("v", v, 64);
    D_ACELP_decode_arithtrack(v + track, s, p, 4, 16);
    arrow(); put16("v", v, 64); end_line();
}

static void case_indexing(void)
{
    Word16 code[L_SUBFR], index[8], ber = 0;
    int c = random_range(0, ACELP_FIXED_CDK_NB - 1);
    PulseConfig config = PulseConfTable[c];
    Word16 wordcnt = (Word16)((config.bits + 15) >> 4);
    for (int k = 0; k < wordcnt; k++) index[k] = (Word16)next_random();
    {
        /* a bitstream fills exactly config.bits bits (wider words can drive the reference's
         * D_ACELP_decode_arithtrack into its s >= 0 assertion) */
        int top = config.bits - 16 * (wordcnt - 1);
        if (top < 16) index[wordcnt - 1] = (Word16)(index[wordcnt - 1] & ((1 << top) - 1));
    }
    for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    put1("config", c); put16("index", index, wordcnt);
    D_ACELP_indexing(code, config, NB_TRACK_FCB_4T, index, &ber);
    arrow(); put16("code", code, L_SUBFR); put1("ber", ber); end_line();
}

static void case_joint_decode(void)
{
    UWord16 idxs[8];
    UWord32 index_n[4];
    Word16 pulse_num[4], wordcnt = (Word16)random_range(2, 7), sum = 0;
    for (int t = 0; t < 4; t++) { pulse_num[t] = (Word16)random_range(1, 9); sum += pulse_num[t] >> 1; }
    /* as in the codebook configurations: the joint branch has at least 2 pulses per track (1 would
     * divide by indx_fact[1] = 0), the other at most 2 (index_mask_ACELP has 3 entries) */
    if (sum < 4) { for (int t = 0; t < 4; t++) if (pulse_num[t] > 2) pulse_num[t] = 2; }
    else { for (int t = 0; t < 4; t++) if (pulse_num[t] < 2) pulse_num[t] = 2; }
    for (int k = 0; k < 8; k++) idxs[k] = (UWord16)next_random();
    for (int t = 0; t < 4; t++) index_n[t] = (UWord32)random32();
    put_u16("idxs", idxs, 8); put1("wordcnt", wordcnt); put16("pulse_num", pulse_num, 4);
    printf(" index_n="); for (int t = 0; t < 4; t++) printf(t ? ",%d" : "%d", (Word32)index_n[t]);
    fcb_pulse_track_joint_decode(idxs, wordcnt, index_n, pulse_num, 4);
    arrow(); printf(" index_n="); for (int t = 0; t < 4; t++) printf(t ? ",%d" : "%d", (Word32)index_n[t]);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decode_arithtrack")) case_decode_arithtrack();
        else if (!strcmp(argv[2], "indexing")) case_indexing();
        else if (!strcmp(argv[2], "joint_decode")) case_joint_decode();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
