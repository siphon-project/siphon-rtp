/* Function-level oracle for gain_dec_amr_wb_fx (lib_dec/gain_dec_fx.c): the AMR-WB IO gain decoder. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];
static const Word32 amr_rates[] = {6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};

/* An algebraic code vector in Q9: a few +-1 pulses (stacked now and then), as the AMR-WB codebooks give. */
static void algebraic_code(Word16 *code)
{
    set16_fx(code, 0, L_SUBFR);
    for (int p = random_range(2, 24); p > 0; p--) code[random_range(0, L_SUBFR - 1)] += (Word16)(next_random() & 1 ? 512 : -512);
}

static void case_gain_dec_amr_wb(void)
{
    int n = 120;
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(next_random() % 10 ? random_range(0, n - 40) : random_range(n - 8, n));
    st->codec_mode = MODE1;
    Word32 core_brate = amr_rates[next_random() % 9];
    Word16 code[L_SUBFR], gain_pit = -1, gain_inov = -1, past_qua_en[GAIN_PRED_ORDER];
    Word32 gain_code = -1, norm_gain_code = -1;
    for (int i = 0; i < GAIN_PRED_ORDER; i++) past_qua_en[i] = (Word16)random_range(-14 * 1024, 4 * 1024);
    for (int i = 0; i < GAIN_PRED_ORDER; i++) st->past_qua_en_fx[i] = past_qua_en[i];
    algebraic_code(code);
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("core_brate", core_brate);
    put16("code", code, L_SUBFR); put16("past_qua_en", past_qua_en, GAIN_PRED_ORDER);
    gain_dec_amr_wb_fx(st, core_brate, &gain_pit, &gain_code, st->past_qua_en_fx, &gain_inov, code, &norm_gain_code);
    arrow(); put1("gain_pit", gain_pit); put1("gain_code", gain_code); put1("gain_inov", gain_inov);
    put1("norm_gain_code", norm_gain_code); put16("past_qua_en", st->past_qua_en_fx, GAIN_PRED_ORDER);
    put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "gain_dec_amr_wb")) case_gain_dec_amr_wb();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
