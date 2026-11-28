/* Function-level oracle for lib_dec/gaus_dec_fx.c: a whole unvoiced frame (four gaus_dec_fx calls,
 * as decod_unvoiced_fx makes them) from random bits, and gaus_dec2v_fx (with dec_2pos_fx) alone. */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/gaus_dec_fx.c"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define EXC_LEN L_EXC_DEC
#define EXC_AT L_EXC_MEM_DEC
#define BWE_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)
#define BWE_AT (PIT16k_MAX * 2)
#define DCT_LEN (DCT_L_POST - OFFSET2)

static Decoder_State_fx *random_stream(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = random_range(100, 400);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(next_random() % 10 ? random_range(0, 40) : random_range(n - 30, n));
    st->codec_mode = MODE1;
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
    return st;
}

static void case_gaus_dec(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200};
    static Word16 old_exc[EXC_LEN], old_bwe[BWE_LEN], exc2[L_FRAME16k];
    Word16 code[4][L_SUBFR], out16[4 * 6];
    Word32 out32[4 * 2];
    Decoder_State_fx *st = random_stream();
    Word32 core_brate = rates[next_random() % 4];
    Word16 q = (Word16)random_range(-1, 10);
    int mag = 1 << random_range(3, 14);
    st->core_brate_fx = core_brate;
    st->L_frame_fx = (Word16)(next_random() % 6 ? L_FRAME : L_FRAME16k);
    st->Q_exc = q;
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)(next_random() % 3 ? q : random_range(-1, 12));
    st->lp_gainp_fx = random16(); st->lp_gainc_fx = random16(); st->tilt_code_fx = random16();
    random_signal(old_exc, EXC_LEN, mag); random_signal(old_bwe, BWE_LEN, mag); random_signal(exc2, L_FRAME16k, mag);
    random_signal(st->dct_post_old_exc_fx, DCT_LEN, mag); random_signal(st->last_exc_dct_in_fx, L_FRAME, mag);
    put1("core_brate", core_brate); put1("l_frame", st->L_frame_fx); put1("q_exc", st->Q_exc); put16("q_subfr", st->Q_subfr, L_Q_MEM);
    put1("lp_gainp", st->lp_gainp_fx); put1("lp_gainc", st->lp_gainc_fx); put1("tilt_code", st->tilt_code_fx);
    put16("exc", old_exc, EXC_LEN); put16("bwe", old_bwe, BWE_LEN); put16("exc2", exc2, L_FRAME16k);
    put16("dct_post", st->dct_post_old_exc_fx, DCT_LEN); put16("last_dct", st->last_exc_dct_in_fx, L_FRAME);
    for (int s = 0; s < 4; s++) {
        Word16 i_subfr = (Word16)(s * L_SUBFR);
        Word32 norm_gain = 0x1234, gain_code = 0x4321;
        Word16 inv_gain = 7, voice_fac = 7, gain_pit = 7, pitch = 7;
        gaus_dec_fx(st, core_brate, i_subfr, code[s], &norm_gain, &st->lp_gainp_fx, &st->lp_gainc_fx, &inv_gain,
                    &st->tilt_code_fx, &voice_fac, &gain_pit, &pitch, old_exc + EXC_AT, &gain_code, exc2,
                    old_bwe + BWE_AT, &st->Q_exc, st->Q_subfr);
        out16[6 * s] = inv_gain; out16[6 * s + 1] = voice_fac; out16[6 * s + 2] = gain_pit; out16[6 * s + 3] = pitch;
        out16[6 * s + 4] = st->Q_exc; out16[6 * s + 5] = st->BER_detect;
        out32[2 * s] = norm_gain; out32[2 * s + 1] = gain_code;
    }
    arrow(); put16("code", code[0], 4 * L_SUBFR); put16("scalars", out16, 24); put32("gains", out32, 8);
    put16("exc", old_exc, EXC_LEN); put16("bwe", old_bwe, BWE_LEN); put16("exc2", exc2, L_FRAME16k);
    put16("dct_post", st->dct_post_old_exc_fx, DCT_LEN); put16("last_dct", st->last_exc_dct_in_fx, L_FRAME);
    put16("q_subfr", st->Q_subfr, L_Q_MEM); put1("lp_gainp", st->lp_gainp_fx); put1("lp_gainc", st->lp_gainc_fx);
    put1("tilt_code", st->tilt_code_fx); put1("next_bit_pos", st->next_bit_pos_fx);
    end_line();
    free(st);
}

static void case_gaus_dec2v(void)
{
    Decoder_State_fx *st = random_stream();
    Word16 nb_bits = (Word16)random_range(0, 6), lg = (Word16)(next_random() % 4 ? L_SUBFR : random_range(1, L_SUBFR));
    Word16 code[L_SUBFR];
    for (int i = 0; i < L_SUBFR; i++) code[i] = -3;
    put1("nb_bits", nb_bits); put1("lg", lg);
    gaus_dec2v_fx(st, code, lg, nb_bits);
    arrow(); put16("code", code, L_SUBFR); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "gaus_dec")) case_gaus_dec();
        else if (!strcmp(argv[2], "gaus_dec2v")) case_gaus_dec2v();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
