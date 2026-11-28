/* Function-level oracle for lib_dec/dec4t64_fx.c (dec_acelp_4t64_fx, D_ACELP_decode_43bit). */
#include "harness.h"
#include "prot_fx.h"

static void case_decode_43bit(void)
{
    UWord16 idxs[4];
    Word16 code[L_SUBFR], pulsestrack[4] = {3, 3, 2, 2};
    for (int i = 0; i < 3; i++) idxs[i] = (UWord16)next_random();
    if (next_random() & 1) {
        /* a joint index inside the codebook: below 5472 * PI_offset-limited range */
        Word32 joint = random_range(0, 5472 * 5472 - 1);
        if (next_random() & 1) joint += 3611648;
        Word32 word = (joint << 2) | (idxs[1] & 3);
        idxs[1] = (UWord16)word; idxs[2] = (UWord16)(word >> 16);
    }
    idxs[3] = 0;
    for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    put_u16("idxs", idxs, 3);
    D_ACELP_decode_43bit(idxs, code, pulsestrack);
    arrow(); put16("code", code, L_SUBFR); end_line();
}

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

/* dec_acelp_4t64_fx on a random bitstream, both the EVS codebooks (through D_ACELP_indexing) and the
 * AMR-WB IO ones (dec_1p_N1 ... dec_6p_6N2); occasionally a stream too short for the index. */
static void case_acelp_4t64(void)
{
    static const Word16 evs_bits[] = {20, 28, 36, 43, 50, 62, 87};
    static const Word16 amr_bits[] = {20, 36, 44, 52, 64, 72, 88};
    Word16 opt_amr_wb = (Word16)(next_random() & 1);
    Word16 nbbits = opt_amr_wb ? amr_bits[next_random() % 7] : evs_bits[next_random() % 7];
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = (next_random() % 16) ? 400 : random_range(0, 120);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 200);
    st->BER_detect = 0;
    Word16 code[L_SUBFR];
    for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("nbbits", nbbits); put1("opt_amr_wb", opt_amr_wb); put16("code", code, L_SUBFR);
    dec_acelp_4t64_fx(st, nbbits, code, opt_amr_wb);
    arrow(); put16("code", code, L_SUBFR); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decode_43bit")) case_decode_43bit();
        else if (!strcmp(argv[2], "acelp_4t64")) case_acelp_4t64();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
