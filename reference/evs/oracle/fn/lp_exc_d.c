/* Function-level oracle for lib_dec/lp_exc_d_fx.c (low-pass filtering of the adaptive excitation). */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define EXC_AT 8

static void case_lp_filt_exc_dec(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 11600, 13200, 16400, 24400, 32000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 buffer[L_FRAME16k + 2 * EXC_AT];
    Word16 codec_type = (Word16)(next_random() % 4 ? MODE1 : MODE2);
    Word32 core_brate = rates[next_random() % 8];
    Word16 opt_amr_wb = (Word16)(next_random() % 5 == 0);
    Word16 coder_type = (Word16)random_range(0, 5);
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 l_subfr = (Word16)(coder_type == AUDIO && (next_random() & 1) ? 2 * L_SUBFR : L_SUBFR);
    Word16 i_subfr = (Word16)(l_subfr * random_range(0, l_frame / l_subfr - 1));
    Word16 lp_flag = (Word16)random_range(0, 1);
    int n = 200;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, n);
    st->codec_mode = codec_type;
    if (next_random() % 3) random_signal(buffer, L_FRAME16k + 2 * EXC_AT, 30000);
    else for (int i = 0; i < L_FRAME16k + 2 * EXC_AT; i++) buffer[i] = random16();
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("codec_type", codec_type);
    put1("core_brate", core_brate); put1("opt_amr_wb", opt_amr_wb); put1("coder_type", coder_type); put1("i_subfr", i_subfr);
    put1("l_subfr", l_subfr); put1("l_frame", l_frame); put1("lp_flag", lp_flag); put16("exc", buffer, L_FRAME16k + 2 * EXC_AT);
    lp_filt_exc_dec_fx(st, codec_type, core_brate, opt_amr_wb, coder_type, i_subfr, l_subfr, l_frame, lp_flag, buffer + EXC_AT);
    arrow(); put16("exc", buffer, L_FRAME16k + 2 * EXC_AT); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lp_filt_exc_dec")) case_lp_filt_exc_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
