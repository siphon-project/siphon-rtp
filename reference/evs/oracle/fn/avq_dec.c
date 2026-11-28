/* Function-level oracle for lib_dec/avq_dec_fx.c (AVQ_demuxdec_fx, the decoder's AVQ path). */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

/* AVQ_demuxdec_fx at the pre-quantiser's 8 sub-vectors with the bit budgets of the 16 kHz core
 * (AVQ_bits_16kHz_tbl plus carried bits), over random bitstreams biased towards long unary codes
 * so the Voronoi extensions and the corrupt-frame branch (codebook > 32) are reached. Also smaller
 * Nsv. xriq starts with stale contents, as the reference's code_preQ does between subframes. */
static void case_avq_demuxdec(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = MAX_BITS_PER_FRAME;
    int ones = random_range(1, 15); /* 1 in `ones` bits is a 0 */
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)((next_random() % (unsigned)(ones + 1)) != 0);
    if (next_random() % 4 == 0) for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)random_range(200, n);
    st->next_bit_pos_fx = (Word16)random_range(0, 150);
    st->codec_mode = MODE1;
    st->BER_detect = 0;
    Word16 nsv = (next_random() % 4) ? 8 : (Word16)random_range(1, 8);
    Word16 nb_bits = (Word16)random_range(0, 200);
    if (next_random() % 4 == 0) nb_bits = (Word16)random_range(0, 20);
    Word16 xriq[64], nq[8];
    for (int i = 0; i < 64; i++) xriq[i] = random16();
    for (int i = 0; i < 8; i++) nq[i] = 7;
    put_u16("bits", bit_buffer, n); put1("total_num_bits", st->total_num_bits);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("nsv", nsv); put1("nb_bits", nb_bits);
    put16("xriq", xriq, 64);
    AVQ_demuxdec_fx(st, xriq, &nb_bits, nsv, nq);
    arrow(); put16("xriq", xriq, 64); put16("nq", nq, 8); put1("nb_bits", nb_bits);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "avq_demuxdec")) case_avq_demuxdec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
