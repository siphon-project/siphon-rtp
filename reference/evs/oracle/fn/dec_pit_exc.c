/* Function-level oracle for lib_dec/dec_pit_exc_fx.c (dec_pit_exc_fx).
 *
 * One case is one to three consecutive frames on the same decoder state (the GSC coder's subframe
 * counts 1, 2 and 4, GSC noisy speech or not, every 12.8 kHz rate the GSC coder runs at), so the
 * excitation Q, the FEC gains and the tilt carry across calls; between frames the harness shifts the
 * excitation histories by one frame, as acelp_core_dec_fx does, and the Rust replay does the same.
 * The bitstream is random: the function reads from the middle of a frame. BER_detect is set on
 * entry now and then, so the corrupted-frame pitch gain branch is reached. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define NBITS 400
#define EXC_LEN L_EXC_DEC
#define BWE_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)
#define BWE_AT (PIT16k_MAX * 2)

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static Word16 level(void) { return (Word16)(1 << random_range(3, 14)); }

static void random_lpc(Word16 *a, int nsub)
{
    for (int s = 0; s < nsub; s++) {
        a[s * (M + 1)] = 4096;
        for (int i = 1; i <= M; i++) {
            int span = 6000 * (M + 1 - i) / M;
            a[s * (M + 1) + i] = (Word16)random_range(-span, span);
        }
    }
}

static void case_dec_pit_exc(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 11600, 13200};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 old_exc[EXC_LEN], old_bwe[BWE_LEN], code[L_SUBFR];
    Word16 pitch_buf[NB_SUBFR], gain_buf[NB_SUBFR];
    Word16 aq[NB_SUBFR16k * (M + 1)];

    st->codec_mode = MODE1;
    st->core_brate_fx = rates[next_random() % 5];
    st->L_frame_fx = L_FRAME;
    st->GSC_noisy_speech_fx = (Word16)(next_random() % 3 == 0);
    Word16 nb_subfr;
    if (st->GSC_noisy_speech_fx) nb_subfr = NB_SUBFR;
    else nb_subfr = (Word16)((st->core_brate_fx >= ACELP_9k60 && (next_random() & 1)) ? 2 : 1);
    Word16 coder_type = (Word16)(next_random() % 4 ? AUDIO : INACTIVE);
    st->Q_exc = (Word16)random_range(0, 8);
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)random_range(0, 12);
    random_signal(st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2, level());
    random_signal(st->last_exc_dct_in_fx, L_FRAME, level());
    st->lp_gainp_fx = (Word16)random_range(0, 19661);
    st->lp_gainc_fx = (Word16)random_range(0, 32767);
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    Carry = (Flag)(next_random() & 1);
    random_signal(old_exc, EXC_LEN, level());
    random_signal(old_bwe, BWE_LEN, level());
    for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    for (int i = 0; i < NB_SUBFR; i++) { pitch_buf[i] = random16(); gain_buf[i] = random16(); }

    put1("core_brate", st->core_brate_fx); put1("noisy", st->GSC_noisy_speech_fx); put1("nb_subfr", nb_subfr);
    put1("coder_type", coder_type); put1("q_exc", st->Q_exc); put16("q_subfr", st->Q_subfr, L_Q_MEM);
    put16("dct_post_old_exc", st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2);
    put16("last_exc_dct_in", st->last_exc_dct_in_fx, L_FRAME);
    put1("lp_gainp", st->lp_gainp_fx); put1("lp_gainc", st->lp_gainc_fx); put1("tilt_code", st->tilt_code_fx);
    put1("carry", Carry); put16("old_exc", old_exc, EXC_LEN); put16("old_bwe", old_bwe, BWE_LEN);
    put16("code", code, L_SUBFR); put16("pitch_buf", pitch_buf, NB_SUBFR); put16("gain_buf", gain_buf, NB_SUBFR);

    int frames = random_range(1, 3);
    put1("frames", frames);
    static char out_text[1 << 16];
    size_t out_len = 0;
    for (int f = 0; f < frames; f++) {
        char name[32];
        for (int i = 0; i < NBITS; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
        st->bit_stream_fx = bit_buffer;
        st->total_num_bits = NBITS;
        st->next_bit_pos_fx = (Word16)random_range(0, 100);
        st->BER_detect = (Word16)(next_random() % 8 == 0);
        Word16 es_pred = Es_pred_qua_5b_fx[next_random() % 32];
        random_lpc(aq, NB_SUBFR16k);
        snprintf(name, sizeof name, "bits%d", f); put_u16(name, bit_buffer, NBITS);
        snprintf(name, sizeof name, "next_bit_pos%d", f); put1(name, st->next_bit_pos_fx);
        snprintf(name, sizeof name, "ber%d", f); put1(name, st->BER_detect);
        snprintf(name, sizeof name, "es_pred%d", f); put1(name, es_pred);
        snprintf(name, sizeof name, "aq%d", f); put16(name, aq, NB_SUBFR16k * (M + 1));

        dec_pit_exc_fx(st, aq, coder_type, es_pred, pitch_buf, code, old_exc + L_EXC_MEM_DEC, old_bwe + BWE_AT,
                       nb_subfr, gain_buf);

        char *p = out_text + out_len;
        size_t room = sizeof out_text - out_len;
        int w = snprintf(p, room, " pitch_buf%d=", f);
        for (int i = 0; i < NB_SUBFR; i++) w += snprintf(p + w, room - w, i ? ",%d" : "%d", pitch_buf[i]);
        w += snprintf(p + w, room - w, " gain_buf%d=", f);
        for (int i = 0; i < NB_SUBFR; i++) w += snprintf(p + w, room - w, i ? ",%d" : "%d", gain_buf[i]);
        w += snprintf(p + w, room - w, " code%d=", f);
        for (int i = 0; i < L_SUBFR; i++) w += snprintf(p + w, room - w, i ? ",%d" : "%d", code[i]);
        w += snprintf(p + w, room - w, " next_bit_pos%d=%d ber_detect%d=%d q_exc%d=%d lp_gainp%d=%d lp_gainc%d=%d tilt_code%d=%d",
                      f, st->next_bit_pos_fx, f, st->BER_detect, f, st->Q_exc, f, st->lp_gainp_fx, f, st->lp_gainc_fx,
                      f, st->tilt_code_fx);
        out_len += (size_t)w;
        if (f + 1 == frames) break;
        memmove(old_exc, old_exc + L_FRAME, (size_t)(EXC_LEN - L_FRAME) * sizeof(Word16));
        memmove(old_bwe, old_bwe + 2 * L_FRAME, (size_t)(BWE_LEN - 2 * L_FRAME) * sizeof(Word16));
    }
    arrow();
    fputs(out_text, stdout);
    put16("q_subfr", st->Q_subfr, L_Q_MEM);
    put16("dct_post_old_exc", st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2);
    put16("last_exc_dct_in", st->last_exc_dct_in_fx, L_FRAME);
    put1("carry", Carry); put16("old_exc", old_exc, EXC_LEN); put16("old_bwe", old_bwe, BWE_LEN);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "dec_pit_exc")) case_dec_pit_exc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
