/* Function-level oracle for lib_dec/dec2t32_fx.c (the 12- and 7-bit algebraic codebooks). */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void codebook(int twelve)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 code[L_SUBFR];
    int n = 160;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    /* Now and then a read that runs past the frame, which flags BER_detect and reads index 0. */
    st->next_bit_pos_fx = (Word16)(next_random() % 10 ? random_range(0, n - 12) : random_range(n - 11, n));
    st->codec_mode = MODE1;
    for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
    if (twelve) dec_acelp_2t32_fx(st, code); else dec_acelp_1t64_fx(st, code);
    arrow(); put16("code", code, L_SUBFR); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "acelp_2t32")) codebook(1);
        else if (!strcmp(argv[2], "acelp_1t64")) codebook(0);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
