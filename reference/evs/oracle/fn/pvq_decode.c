/* Function-level oracle for lib_dec/pvq_decode_fx.c: a range-coded segment of random bits read by
 * several consecutive pvq_decode_fx calls (the range coder and the BER flags carry over). */
#include "harness.h"
#include "prot_fx.h"

#define N_OPT_FX 5 /* lib_com/index_pvq_opt_fx.c */

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define CALLS 4

static void random_shape(Word16 *dim, Word16 *k)
{
    /* Codebooks a little above 2^8 entries make rc_dec_uniform_fx split off one or two raw bits,
     * the only shape where an index can land exactly on the codebook size. */
    if (next_random() % 3 == 0) { *dim = 2; *k = (Word16)random_range(64, 250); return; }
    *dim = (Word16)(next_random() % 3 == 0 ? random_range(1, 5) : random_range(6, 48));
    if (*dim <= N_OPT_FX) *k = (Word16)(next_random() % 4 ? random_range(1, 40) : random_range(1, 512));
    else *k = (Word16)random_range(1, next_random() % 2 ? 12 : 96);
}

static void case_pvq_decode(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = random_range(400, 2560);
    Word16 tot_bits = (Word16)(next_random() % 8 ? random_range(200, n) : random_range(200, 2560));
    Word16 dim[CALLS], k[CALLS], gain[CALLS];
    Word16 xq[64], y[64];
    Word32 t[CALLS * 8];
    int kk = 0;

    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->codec_mode = MODE1;
    st->ber_occured_in_pvq = (Word16)(next_random() % 10 == 0);
    for (int c = 0; c < CALLS; c++) {
        random_shape(&dim[c], &k[c]);
        gain[c] = (Word16)(next_random() % 8 == 0 ? 0 : (next_random() & 1 ? -32768 : -random_range(1, 32767)));
    }
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("tot_bits", tot_bits);
    put1("ber_pvq", st->ber_occured_in_pvq);
    put16("dim", dim, CALLS); put16("k", k, CALLS); put16("gain", gain, CALLS);
    rc_dec_init_fx(st, tot_bits);
    arrow();
    for (int c = 0; c < CALLS; c++) {
        char name[16];
        for (int i = 0; i < 64; i++) { xq[i] = -7; y[i] = -7; }
        pvq_decode_fx(st, xq, y, k[c], dim[c], gain[c]);
        sprintf(name, "xq%d", c); put16(name, xq, 64);
        sprintf(name, "y%d", c); put16(name, y, 64);
        t[kk++] = (Word32)st->rc_low_fx; t[kk++] = (Word32)st->rc_range_fx; t[kk++] = st->rc_num_bits_fx;
        t[kk++] = st->rc_offset_fx; t[kk++] = st->next_bit_pos_fx; t[kk++] = st->BER_detect;
        t[kk++] = st->ber_occured_in_pvq; t[kk++] = (Word32)st->rc_help_fx;
    }
    put32("trace", t, kk); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "pvq_decode")) case_pvq_decode();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
