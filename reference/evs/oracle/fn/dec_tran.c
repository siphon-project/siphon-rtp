/* Function-level oracle for lib_dec/dec_tran_fx.c: decod_tran_fx over a whole TRANSITION frame from
 * random bits (tc_classif_fx first, as the ACELP core calls it), at both internal rates, below and
 * above 24.4 kbit/s (the transform pre-quantiser) and 32 kbit/s (scalar gains, no enhancer). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define EXC_LEN L_EXC_DEC
#define EXC_AT L_EXC_MEM_DEC
#define BWE_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)
#define BWE_AT (PIT16k_MAX * 2)
#define DCT_LEN (DCT_L_POST - OFFSET2)

static void random_lpc(Word16 *a)
{
    a[0] = 4096;
    for (int i = 1; i <= M; i++) {
        int span = 6000 * (M + 1 - i) / M;
        a[i] = (next_random() % 16) ? (Word16)random_range(-span, span) : random16();
    }
}

static void put_state(Decoder_State_fx *st)
{
    Word16 s[] = {st->tilt_code_fx, st->prev_gain_pit_dec_fx, st->lp_gainp_fx, st->lp_gainc_fx, st->Q_exc, st->next_bit_pos_fx,
                  st->BER_detect, st->dm_fx.prev_state, st->stab_fac_fx, st->mem_preemp_preQ_fx, st->last_nq_preQ_fx,
                  st->use_acelp_preq, (Word16)Carry};
    put16("st", s, 13);
    Word32 l[] = {st->gc_threshold_fx, st->dm_fx.prev_gain_code};
    put32("l", l, 2);
    put16("prev_gain_pit", st->dm_fx.prev_gain_pit, 6);
    put16("tilt_code_dec", st->tilt_code_dec_fx, NB_SUBFR16k);
    put16("q_subfr", st->Q_subfr, L_Q_MEM);
    put16("dct_post", st->dct_post_old_exc_fx, DCT_LEN); put16("last_dct", st->last_exc_dct_in_fx, L_FRAME);
}

static void case_decod_tran(void)
{
    /* Not 16.4 or 24.4 kbit/s at 12.8 kHz: those are MODE2 rates (lib_com/bitstream_fx.c, the
     * total-rate switch that sets codec_mode), so no MODE1 ACELP frame has them,
     * and their FCB_bits_tbl rows give 56- and 92-bit codebooks that dec_acelp_4t64_fx has no case
     * for: config.nb_pulse is read uninitialised, and the result depends on the compiler's stack
     * (a gcc 14 build aborts in div_s on indx_fact[13], a gcc 15 build happens to read 0). */
    static const Word32 rates12k8[] = {7200, 8000, 9600, 11600, 13200};
    /* Not 24.4 kbit/s at 16 kHz: that is no MODE1 configuration, and there tc_dec_fx's 5-bit TC lag
     * leaves T0 unset (decod_tran_fx's uninitialised stack variable reaches prep_tbe_exc_fx). */
    static const Word32 rates16k[] = {32000, 48000, 64000, 32000};
    static Word16 old_exc[EXC_LEN], old_bwe[BWE_LEN], exc2[L_FRAME16k];
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = 1200, ones = next_random() % 5 == 0;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(ones ? next_random() % 10 != 0 : next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 30);
    st->codec_mode = MODE1;
    Word16 l_frame = (Word16)(next_random() % 2 ? L_FRAME : L_FRAME16k);
    st->L_frame_fx = l_frame;
    st->core_brate_fx = l_frame == L_FRAME ? rates12k8[next_random() % 5] : rates16k[next_random() % 4];
    Word16 q = (Word16)random_range(-1, 8);
    int mag = 1 << random_range(3, 14);
    st->Q_exc = q;
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)(next_random() % 3 ? q : random_range(-1, 12));
    st->lp_gainp_fx = (Word16)random_range(0, 16384); st->lp_gainc_fx = (Word16)random_range(0, 32767);
    st->tilt_code_fx = (Word16)random_range(-8000, 8000);
    st->stab_fac_fx = (Word16)random_range(0, 32767);
    st->gc_threshold_fx = random_range(0, 1 << 24);
    st->dm_fx.prev_state = (Word16)random_range(0, 2);
    st->dm_fx.prev_gain_code = random_range(0, 1 << 22);
    for (int i = 0; i < 6; i++) st->dm_fx.prev_gain_pit[i] = (Word16)random_range(0, 16384);
    st->mem_preemp_preQ_fx = (Word16)random_range(-3000, 3000);
    st->last_nq_preQ_fx = (Word16)random_range(0, 20);
    st->prev_gain_pit_dec_fx = -7;
    for (int i = 0; i < NB_SUBFR16k; i++) st->tilt_code_dec_fx[i] = -7;
    Carry = (Flag)(next_random() & 1);
    random_signal(old_exc, EXC_LEN, mag); random_signal(old_bwe, BWE_LEN, mag); random_signal(exc2, L_FRAME16k, mag);
    random_signal(st->dct_post_old_exc_fx, DCT_LEN, mag); random_signal(st->last_exc_dct_in_fx, L_FRAME, mag);
    Word16 aq[NB_SUBFR16k * (M + 1)];
    for (int s = 0; s < NB_SUBFR16k; s++) random_lpc(&aq[s * (M + 1)]);
    Word16 es_pred = next_random() % 2 ? Es_pred_qua_5b_fx[next_random() % 32] : Es_pred_qua_4b_fx[next_random() % 16];
    Word16 sharp = (Word16)(next_random() & 1);
    Word16 unbits = (Word16)random_range(0, 12);
    Word16 pitch_buf[NB_SUBFR16k], voice_factors[NB_SUBFR16k], gain_buf[NB_SUBFR16k];
    for (int i = 0; i < NB_SUBFR16k; i++) { pitch_buf[i] = -7; voice_factors[i] = -7; gain_buf[i] = -7; }
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("l_frame", l_frame);
    put1("core_brate", st->core_brate_fx); put16("aq", aq, NB_SUBFR16k * (M + 1)); put1("es_pred", es_pred); put1("sharp", sharp);
    put1("unbits", unbits);
    put16("exc", old_exc, EXC_LEN); put16("bwe", old_bwe, BWE_LEN); put16("exc2", exc2, L_FRAME16k);
    put_state(st);
    Word16 tc_subfr = tc_classif_fx(st, l_frame);
    decod_tran_fx(st, l_frame, tc_subfr, aq, TRANSITION, es_pred, pitch_buf, voice_factors, old_exc + EXC_AT, exc2, old_bwe + BWE_AT,
                  &unbits, sharp, gain_buf);
    arrow(); put1("tc_subfr", tc_subfr); put16("pitch_buf", pitch_buf, NB_SUBFR16k); put16("voice_factors", voice_factors, NB_SUBFR16k);
    put16("gain_buf", gain_buf, NB_SUBFR16k); put1("unbits", unbits);
    put16("exc", old_exc, EXC_LEN); put16("bwe", old_bwe, BWE_LEN); put16("exc2", exc2, L_FRAME16k);
    put_state(st);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decod_tran")) case_decod_tran();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
