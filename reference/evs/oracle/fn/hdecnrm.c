/* Function-level oracle for lib_dec/hdecnrm_fx.c (fixed, transient, context and resized norm decoding). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_dec_fx.h"
#include "rom_com_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static Decoder_State_fx *random_stream(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = random_range(0, 1) ? 640 : random_range(20, 300);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() % 5 ? next_random() & 1 : 0);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->codec_mode = MODE1;
    put_u16("bits", bit_buffer, n);
    return st;
}

static void case_context(void)
{
    Word16 index[NB_SFM], n = (Word16)random_range(2, NB_SFM), n_length = (Word16)random_range(0, 50);
    Decoder_State_fx *st = random_stream();
    memset(index, 0, sizeof(index));
    index[0] = (Word16)random_range(0, 31);
    put1("n", n); put1("index0", index[0]); put1("n_length", n_length);
    hdecnrm_context_fx(st, n, index, &n_length);
    arrow(); put16("index", index, n); put1("n_length", n_length); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

static void case_resize(void)
{
    Word16 index[NB_SFM], n = (Word16)random_range(2, NB_SFM);
    Decoder_State_fx *st = random_stream();
    memset(index, 0, sizeof(index));
    put1("n", n);
    hdecnrm_resize_fx(st, n, index);
    arrow(); put16("index", index, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
    end_line();
    free(st);
}

static void case_huff(void)
{
    Word16 table = (Word16)(next_random() & 1), rbits = (Word16)random_range(0, 100);
    Decoder_State_fx *st = random_stream();
    put1("table", table); put1("rbits", rbits);
    Word16 symbol = decode_huff_context_fx(st, table ? hetable_fx : hntable_fx, &rbits);
    arrow(); put1("symbol", symbol); put1("rbits", rbits); put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

/* hdecnrm_fx (plain == 1) and hdecnrm_tran_fx (plain == 0): n - 1 indices from the stream. */
static void case_fixed(int plain)
{
    Word16 index[NB_SFM], n = (Word16)random_range(2, NB_SFM);
    Decoder_State_fx *st = random_stream();
    for (int i = 0; i < NB_SFM; i++) index[i] = -7;
    put1("n", n);
    if (plain) hdecnrm_fx(st, n, index); else hdecnrm_tran_fx(st, n, index);
    arrow(); put16("index", index, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
    end_line();
    free(st);
}

/* huff_dec_fx with both HVQ tables it is called with (peak gains, code positions). */
static void case_huff_dec(void)
{
    Word16 table = (Word16)(next_random() & 1);
    Word16 n = (Word16)random_range(1, table ? 23 : 40);
    Word16 index[64];
    Decoder_State_fx *st = random_stream();
    st->next_bit_pos_fx = (Word16)(next_random() % 6 ? random_range(0, st->total_num_bits / 2) : random_range(0, st->total_num_bits));
    for (int i = 0; i < 64; i++) index[i] = -9;
    put1("table", table); put1("n", n); put1("next_bit_pos", st->next_bit_pos_fx);
    if (table) huff_dec_fx(st, n, MAX_PG_HUFFLEN, NUM_PG_HUFFLEN, hvq_pg_huff_thres, hvq_pg_huff_offset, hvq_pg_huff_tab, index);
    else huff_dec_fx(st, n, HVQ_CP_HUFF_MAX_CODE, HVQ_CP_HUFF_NUM_LEN, hvq_cp_huff_thres, hvq_cp_huff_offset, hvq_cp_huff_tab, index);
    arrow(); put16("index", index, 64); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "context")) case_context();
        else if (!strcmp(argv[2], "resize")) case_resize();
        else if (!strcmp(argv[2], "huff")) case_huff();
        else if (!strcmp(argv[2], "huff_dec")) case_huff_dec();
        else if (!strcmp(argv[2], "fixed")) case_fixed(1);
        else if (!strcmp(argv[2], "tran")) case_fixed(0);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
