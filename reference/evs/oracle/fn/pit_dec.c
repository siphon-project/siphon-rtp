/* Function-level oracle for lib_dec/pit_dec.c (the MODE1 pitch decoders). */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void case_pit_decode(void)
{
    static const Word32 evs_rates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000, 64000};
    static const Word32 amr_rates[] = {6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 opt_amr_wb = (Word16)(next_random() % 4 == 0);
    Word32 core_brate = opt_amr_wb ? amr_rates[next_random() % 9] : evs_rates[next_random() % 8];
    /* The 12.8 kHz core runs up to 13.2 kbit/s, the 16 kHz core above. */
    Word16 l_frame = (Word16)(!opt_amr_wb && core_brate >= 16400 ? L_FRAME16k : L_FRAME);
    Word16 i_subfr = (Word16)(L_SUBFR * random_range(0, l_frame == L_FRAME ? 3 : 4));
    Word16 coder_type = (Word16)random_range(1, 5);
    Word16 l_subfr = (Word16)(coder_type == AUDIO && (next_random() & 1) ? L_FRAME / 2 : L_SUBFR);
    Word16 limit_flag = (Word16)random_range(0, 2), T0 = (Word16)random_range(17, 289), T0_frac = (Word16)random_range(0, 3);
    Word16 T0_min = (Word16)random_range(17, 280), T0_max = (Word16)random_range(T0_min, 289);
    int n = core_brate / 50;
    Word16 pitch;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, n - 4);
    st->codec_mode = MODE1;
    if (l_subfr == L_FRAME / 2 && (i_subfr % (L_FRAME / 2))) i_subfr = L_FRAME / 2;
    /* A coder type the bit rate never signals indexes past ACB_bits_tbl (400 entries) /
     * ACB_bits_16kHz_tbl (385), which the reference reads out of bounds; the port reads no bits
     * there instead. Keep the corpus to what the tables cover. */
    if (!opt_amr_wb && coder_type != AUDIO &&
        (l_frame == L_FRAME ? BIT_ALLOC_IDX_fx(core_brate, coder_type, i_subfr, 0) >= 400
                            : BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr, 0) >= 385))
        coder_type = AUDIO;
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("core_brate", core_brate); put1("opt_amr_wb", opt_amr_wb); put1("l_frame", l_frame);
    put1("i_subfr", i_subfr); put1("coder_type", coder_type); put1("limit_flag", limit_flag);
    put1("t0", T0); put1("t0_frac", T0_frac); put1("t0_min", T0_min); put1("t0_max", T0_max); put1("l_subfr", l_subfr);
    pitch = pit_decode_fx(st, core_brate, opt_amr_wb, l_frame, i_subfr, coder_type, &limit_flag, &T0, &T0_frac, &T0_min, &T0_max, l_subfr);
    arrow(); put1("pitch", pitch); put1("limit_flag", limit_flag); put1("t0", T0); put1("t0_frac", T0_frac);
    put1("t0_min", T0_min); put1("t0_max", T0_max); put1("ber_detect", st->BER_detect); put1("next_bit_pos", st->next_bit_pos_fx);
    end_line();
    free(st);
}

static void case_pit_q_dec(void)
{
    static const Word16 bits[] = {4, 5, 6, 8, 9, 10};
    Word16 opt_amr_wb = (Word16)(next_random() & 1);
    Word16 nbits = bits[next_random() % 6];
    Word16 pitch_index = (Word16)(next_random() % 8 ? random_range(0, (1 << nbits) - 1) : random_range(0, 1023));
    Word16 delta = (Word16)(next_random() & 1 ? 8 : 4);
    Word16 pit_flag = (Word16)(L_SUBFR * random_range(0, 2));
    Word16 limit_flag = (Word16)random_range(0, 2);
    Word16 T0 = (Word16)random_range(17, 289), T0_frac = (Word16)random_range(0, 3);
    Word16 T0_min = (Word16)random_range(17, 280), T0_max = (Word16)random_range(T0_min, 289), ber = (Word16)(next_random() & 1);
    put1("opt_amr_wb", opt_amr_wb); put1("pitch_index", pitch_index); put1("n_bits", nbits); put1("delta", delta);
    put1("pit_flag", pit_flag); put1("limit_flag", limit_flag); put1("t0", T0); put1("t0_frac", T0_frac);
    put1("t0_min", T0_min); put1("t0_max", T0_max); put1("ber_detect", ber);
    pit_Q_dec_fx(opt_amr_wb, pitch_index, nbits, delta, pit_flag, limit_flag, &T0, &T0_frac, &T0_min, &T0_max, &ber);
    arrow(); put1("t0", T0); put1("t0_frac", T0_frac); put1("t0_min", T0_min); put1("t0_max", T0_max); put1("ber_detect", ber);
    end_line();
}

static void case_pit16k_q_dec(void)
{
    static const Word16 bits[] = {6, 9, 10};
    Word16 nbits = bits[next_random() % 3];
    Word16 pitch_index = (Word16)(next_random() % 8 ? random_range(0, (1 << nbits) - 1) : random_range(0, 1023));
    Word16 limit_flag = (Word16)random_range(0, 2);
    Word16 T0 = (Word16)random_range(21, 289), T0_frac = (Word16)random_range(0, 3);
    Word16 T0_min = (Word16)random_range(21, 280), T0_max = (Word16)random_range(T0_min, 289), ber = 0;
    put1("pitch_index", pitch_index); put1("n_bits", nbits); put1("limit_flag", limit_flag); put1("t0", T0);
    put1("t0_frac", T0_frac); put1("t0_min", T0_min); put1("t0_max", T0_max);
    pit16k_Q_dec_fx(pitch_index, nbits, limit_flag, &T0, &T0_frac, &T0_min, &T0_max, &ber);
    arrow(); put1("t0", T0); put1("t0_frac", T0_frac); put1("t0_min", T0_min); put1("t0_max", T0_max); put1("ber_detect", ber);
    end_line();
}

static void case_abs_delta(void)
{
    Word16 fr_steps = (Word16)(next_random() % 5 == 0 ? random_range(0, 4) : 2 * random_range(1, 2));
    Word16 pitch_index = (Word16)random_range(0, 511), limit_flag = (Word16)random_range(0, 2);
    Word16 T0 = (Word16)random_range(17, 289), T0_frac = (Word16)random_range(0, 3), T0_min = (Word16)random_range(17, 280);
    Word16 aT0 = T0, aT0_frac = T0_frac;
    put1("fr_steps", fr_steps); put1("pitch_index", pitch_index); put1("limit_flag", limit_flag);
    put1("t0", T0); put1("t0_frac", T0_frac); put1("t0_min", T0_min);
    abs_pit_dec_fx(fr_steps, pitch_index, limit_flag, &aT0, &aT0_frac);
    delta_pit_dec_fx(fr_steps, (Word16)(pitch_index & 63), &T0, &T0_frac, T0_min);
    arrow(); put1("abs_t0", aT0); put1("abs_t0_frac", aT0_frac); put1("delta_t0", T0); put1("delta_t0_frac", T0_frac);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "pit_decode")) case_pit_decode();
        else if (!strcmp(argv[2], "pit_q_dec")) case_pit_q_dec();
        else if (!strcmp(argv[2], "pit16k_q_dec")) case_pit16k_q_dec();
        else if (!strcmp(argv[2], "abs_delta")) case_abs_delta();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
