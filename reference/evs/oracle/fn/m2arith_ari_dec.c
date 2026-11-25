/* Function-level oracle for lib_dec/ari_dec.c and lib_com/ari.c (the MODE2 14-bit arithmetic decoder). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define BITS 300
static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void random_model(UWord16 *table, int symbols)
{
    /* strictly decreasing cumulative frequencies 16384 .. 0, as every model of the decoder */
    int chosen[40], count = symbols - 1;
    for (int i = 0; i < count; i++) {
        int again;
        do {
            chosen[i] = random_range(1, 16383);
            if (next_random() % 3 == 0) chosen[i] = random_range(1, 600) * ((next_random() & 1) ? 1 : -1) + (next_random() & 1 ? 0 : 16384);
            if (chosen[i] < 1) chosen[i] = 1;
            if (chosen[i] > 16383) chosen[i] = 16383;
            again = 0;
            for (int j = 0; j < i; j++) if (chosen[j] == chosen[i]) again = 1;
        } while (again);
    }
    for (int i = 0; i < count; i++)
        for (int j = i + 1; j < count; j++)
            if (chosen[j] > chosen[i]) { int t = chosen[i]; chosen[i] = chosen[j]; chosen[j] = t; }
    table[0] = 16384;
    for (int i = 0; i < count; i++) table[i + 1] = (UWord16)chosen[i];
    table[symbols] = 0;
}

/* One start + a run of table-driven decodes on one bitstream. */
static void case_ari_session(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    TastatDec as;
    int n = 520; /* total_num_bits <= 400, MODE2 reads at most 16 past it */
    memset(bit_buffer, 0, sizeof(bit_buffer));
    int zeros = random_range(1, 6);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)((next_random() % (unsigned)(zeros + 1)) != 0);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)random_range(60, 400);
    st->next_bit_pos_fx = (Word16)random_range(0, 20);
    st->codec_mode = MODE2;
    st->BER_detect = 0;
    int steps = random_range(1, 40);
    int kinds[40], pkis[40], symbols[40], overflow[40];
    UWord16 tables[40][28];
    for (int i = 0; i < steps; i++) {
        kinds[i] = random_range(0, 3);
        pkis[i] = random_range(0, 63);
        if (kinds[i] == 0) random_model(tables[i], 17);
        else if (kinds[i] == 1) random_model(tables[i], 27);
        else memset(tables[i], 0, sizeof(tables[i]));
    }
    put_u16("bits", bit_buffer, n); put1("total_num_bits", st->total_num_bits);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("steps", steps);
    put32("kinds", kinds, steps); put32("pkis", pkis, steps);
    for (int i = 0; i < steps; i++) {
        char name[16];
        snprintf(name, sizeof(name), "table%d", i);
        put_u16(name, tables[i], 28);
    }
    ari_start_decoding_14bits(st, &as);
    for (int i = 0; i < steps; i++) {
        if (kinds[i] == 0) symbols[i] = ari_decode_14bits_s17_ext(st, &as, tables[i]);
        else if (kinds[i] == 1) symbols[i] = ari_decode_14bits_s27_ext(st, &as, tables[i]);
        else if (kinds[i] == 2) symbols[i] = ari_decode_14bits_bit_ext(st, &as);
        else symbols[i] = ari_decode_14bits_s17_ext(st, &as, ari_pk_s17_LC_ext[pkis[i]]);
        overflow[i] = ari_decode_overflow(&as);
    }
    arrow(); put32("symbols", symbols, steps); put32("overflow", overflow, steps);
    put1("low", as.low); put1("high", as.high); put1("vobf", as.vobf);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

/* ari_start_decoding_14bits_prm + a run of pow / sign decodes over a parameter array. */
static void case_ari_prm_session(void)
{
    Word16 prm[BITS];
    TastatDec as;
    int zeros = random_range(1, 6);
    for (int i = 0; i < BITS; i++) prm[i] = (Word16)((next_random() % (unsigned)(zeros + 1)) != 0);
    Word16 bits = (Word16)random_range(20, 264);
    if (next_random() % 4 == 0) bits = (Word16)random_range(17, 40);
    Word16 bp = (Word16)random_range(0, 3);
    int steps = random_range(1, 60);
    int kinds[60], bases[60], results[60], positions[60];
    for (int i = 0; i < steps; i++) {
        kinds[i] = (int)(next_random() & 1);
        /* exp_k = round(expfp(envelope)): log-uniform over the Q15 range */
        bases[i] = random_range(1, 30000) >> random_range(0, 13); /* near 1.0 the reference asserts: the encoder never produces it */
        if (bases[i] < 1) bases[i] = 1;
    }
    put16("prm", prm, BITS); put1("bits", bits); put1("bp", bp); put1("steps", steps);
    put32("kinds", kinds, steps); put32("bases", bases, steps);
    Word16 position = ari_start_decoding_14bits_prm(prm, bp, &as);
    int done = 0;
    for (int i = 0; i < steps; i++) {
        Word16 res = 0;
        if (done) { results[i] = 0; positions[i] = 0; continue; }
        if (kinds[i] == 0) position = ari_decode_14bits_pow(prm, position, bits, &res, &as, (Word16)bases[i]);
        else position = ari_decode_14bits_sign(prm, position, bits, &res, &as);
        results[i] = res; positions[i] = position;
        if (position < 0) done = 1;
    }
    arrow(); put32("results", results, steps); put32("positions", positions, steps);
    put1("low", as.low); put1("high", as.high); put1("vobf", as.vobf); end_line();
}


/* One pow / sign decode from a directly set state close to the end of the budget: reaches the
 * bit-error return of ari_decode_14bits_notbl, which a decoder started from a bitstream does not. */
static void case_ari_notbl_direct(void)
{
    Word16 prm[BITS];
    TastatDec as, before;
    for (int i = 0; i < BITS; i++) prm[i] = (Word16)(next_random() & 1);
    Word16 bits = (Word16)random_range(20, 264);
    Word16 bp = (Word16)(bits - random_range(0, 3));
    int sign = (int)(next_random() % 3 == 0);
    int base = random_range(1, 30000) >> random_range(0, 13);
    if (base < 1) base = 1;
    as.low = (next_random() & 1) ? 0 : random_range(0, 65000);
    as.high = as.low + ((next_random() & 1) ? random_range(1, 6) : random_range(1, 65536 - as.low));
    as.vobf = as.low + random_range(0, as.high - as.low - 1);
    before = as;
    put16("prm", prm, BITS); put1("bits", bits); put1("bp", bp); put1("sign", sign); put1("base", base);
    put1("low", as.low); put1("high", as.high); put1("vobf", as.vobf);
    Word16 res = 7, position;
    if (sign) position = ari_decode_14bits_sign(prm, bp, bits, &res, &as);
    else position = ari_decode_14bits_pow(prm, bp, bits, &res, &as, (Word16)base);
    arrow(); put1("res", res); put1("position", position);
    put1("low", as.low); put1("high", as.high); put1("vobf", as.vobf); end_line();
    (void)before;
}

/* One table-driven decode from a directly set state, vobf anywhere (a value below low is a bit-error
 * state the reference answers with cum saturated). */
static void case_ari_ext_direct(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    TastatDec as;
    UWord16 table[28];
    int symbols = (next_random() & 1) ? 17 : 27;
    random_model(table, symbols);
    int n = 100;
    memset(bit_buffer, 0, sizeof(bit_buffer));
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = 80;
    st->next_bit_pos_fx = (Word16)random_range(0, 20);
    st->codec_mode = MODE2;
    as.low = (next_random() & 1) ? 0 : random_range(0, 65000);
    as.high = as.low + ((next_random() & 1) ? random_range(2, 40) : random_range(2, 65536 - as.low));
    as.vobf = (next_random() % 3 == 0) ? random_range(0, 65535) : as.low + random_range(0, as.high - as.low - 1);
    put_u16("bits", bit_buffer, n); put1("symbols", symbols); put_u16("table", table, 28);
    put1("next_bit_pos", st->next_bit_pos_fx);
    put1("low", as.low); put1("high", as.high); put1("vobf", as.vobf);
    Word16 symbol = (symbols == 17) ? ari_decode_14bits_s17_ext(st, &as, table) : ari_decode_14bits_s27_ext(st, &as, table);
    arrow(); put1("symbol", symbol); put1("low", as.low); put1("high", as.high); put1("vobf", as.vobf);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

static void case_mul(void)
{
    Word32 range = random32() & 0x1ffff; Word16 c = (Word16)random_range(0, 16384);
    Word16 xh = (Word16)random_range(0, 3), xl = (Word16)random_range(0, 32767), y = random16();
    put1("range", range); put1("c", c); put1("xh", xh); put1("xl", xl); put1("y", y);
    arrow(); put1("mul", mul_sbc_14bits(range, c)); put1("multi", L_multi31x16_X2(xh, xl, y)); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "ari_session")) case_ari_session();
        else if (!strcmp(argv[2], "ari_prm_session")) case_ari_prm_session();
        else if (!strcmp(argv[2], "ari_notbl_direct")) case_ari_notbl_direct();
        else if (!strcmp(argv[2], "ari_ext_direct")) case_ari_ext_direct();
        else if (!strcmp(argv[2], "mul")) case_mul();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
