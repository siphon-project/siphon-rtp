/* Function-level oracle for lib_dec/range_dec_fx.c: one range-coded segment per case, a random
 * sequence of uniform / raw-bit / table-symbol reads through it, the coder state traced after
 * every operation. */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define OPS 12

static void trace(Decoder_State_fx *st, Word32 *t, int *k)
{
    t[(*k)++] = (Word32)st->rc_low_fx;
    t[(*k)++] = (Word32)st->rc_range_fx;
    t[(*k)++] = (Word32)st->rc_help_fx;
    t[(*k)++] = st->rc_num_bits_fx;
    t[(*k)++] = st->rc_offset_fx;
    t[(*k)++] = st->rc_end_fx;
    t[(*k)++] = st->next_bit_pos_fx;
    t[(*k)++] = st->BER_detect;
}

static void case_range(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = random_range(700, 2560);
    Word16 start = (Word16)random_range(0, n / 4);
    /* Mostly a segment that fits the frame; sometimes one that runs past it, where the reads
     * flag BER_detect. */
    Word16 tot_bits = (Word16)(next_random() % 8 ? random_range(400, n - start) : random_range(400, n));
    Word32 op[OPS], param[OPS], width[OPS], value[OPS];
    Word32 t[(OPS + 2) * 8];
    int k = 0;

    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    /* An all-zero or all-one prefix drives rc_low to its extremes. */
    if (next_random() % 6 == 0) {
        UWord16 b = (UWord16)(next_random() & 1);
        for (int i = start; i < start + 48 && i < n; i++) bit_buffer[i] = b;
    }
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = start;
    st->codec_mode = MODE1;

    for (int i = 0; i < OPS; i++) {
        op[i] = (Word32)random_range(0, 2);
        width[i] = 1;
        if (op[i] == 0) param[i] = next_random() % 3 ? random_range(2, 300) : random_range(2, 1 << 22);
        else if (op[i] == 1) param[i] = random_range(1, 24);
        else { param[i] = next_random() % 2 ? random_range(2, 1 << 15) : (1 << random_range(1, 15)); width[i] = random_range(1, 80); }
    }

    put_u16("bits", bit_buffer, n); put1("next_bit_pos", start); put1("tot_bits", tot_bits);
    put32("op", op, OPS); put32("param", param, OPS); put32("width", width, OPS);

    rc_dec_init_fx(st, tot_bits);
    trace(st, t, &k);
    for (int i = 0; i < OPS; i++) {
        if (op[i] == 0) value[i] = (Word32)rc_dec_uniform_fx(st, (UWord32)param[i]);
        else if (op[i] == 1) value[i] = rc_dec_bits_fx(st, (Word16)param[i]);
        else {
            UWord32 tot = (UWord32)param[i], val = rc_decode_fx(st, tot), cum, sym;
            cum = val - val % (UWord32)width[i];
            sym = tot - cum < (UWord32)width[i] ? tot - cum : (UWord32)width[i];
            if (sym == 0) sym = 1;
            rc_dec_update_fx(st, cum, sym);
            value[i] = (Word32)val;
        }
        trace(st, t, &k);
    }
    rc_dec_finish_fx(st);
    trace(st, t, &k);

    arrow(); put32("value", value, OPS); put32("trace", t, k); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "range")) case_range();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
