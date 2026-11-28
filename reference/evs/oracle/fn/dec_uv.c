/* Function-level oracle for lib_dec/dec_uv.c: decod_unvoiced_fx over a whole unvoiced frame from
 * random bits (gaus_dec_fx, enhancer_fx and interp_code_5over2_fx per subframe), with the SC-VBR
 * reset (CNG_reset_dec_fx) after a NELP / PPP frame. */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define EXC_LEN L_EXC_DEC
#define EXC_AT L_EXC_MEM_DEC
#define BWE_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)
#define BWE_AT (PIT16k_MAX * 2)
#define DCT_LEN (DCT_L_POST - OFFSET2)

static void put_state(Decoder_State_fx *st)
{
    Word16 s[] = {st->tilt_code_fx, st->prev_gain_pit_dec_fx, st->lp_gainp_fx, st->lp_gainc_fx, st->Q_exc, st->next_bit_pos_fx,
                  st->BER_detect, st->clas_dec, st->last_good_fx, st->bpf_off_fx, st->act_cnt2_fx, st->dm_fx.prev_state};
    put16("st", s, 12);
    Word32 l[] = {st->gc_threshold_fx, st->dm_fx.prev_gain_code, st->lp_ener_fx};
    put32("l", l, 3);
    put16("prev_gain_pit", st->dm_fx.prev_gain_pit, 6);
    put16("tilt_code_dec", st->tilt_code_dec_fx, NB_SUBFR16k);
    put16("q_subfr", st->Q_subfr, L_Q_MEM);
    put16("dct_post", st->dct_post_old_exc_fx, DCT_LEN); put16("last_dct", st->last_exc_dct_in_fx, L_FRAME);
    put16("mem_ar", st->mem_AR_fx, M); put16("mem_ma", st->mem_MA_fx, M);
}

static void case_decod_unvoiced(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200};
    static Word16 old_exc[EXC_LEN], old_bwe[BWE_LEN], exc2[L_FRAME16k];
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = random_range(100, 300);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->codec_mode = MODE1;
    put_u16("bits", bit_buffer, n);
    Word32 core_brate = rates[next_random() % 4];
    Word16 q = (Word16)random_range(-1, 10);
    int mag = 1 << random_range(3, 14);
    st->core_brate_fx = core_brate;
    st->L_frame_fx = L_FRAME;
    st->Q_exc = q;
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)(next_random() % 3 ? q : random_range(-1, 12));
    st->lp_gainp_fx = (Word16)random_range(0, 16384); st->lp_gainc_fx = (Word16)random_range(0, 32767);
    st->tilt_code_fx = (Word16)random_range(-8000, 8000);
    st->last_ppp_mode_dec_fx = (Word16)(next_random() % 6 == 0);
    st->last_nelp_mode_dec_fx = (Word16)(next_random() % 6 == 0);
    st->lp_ener_fx = next_random() % 5 ? random_range(1, 1 << 28) : 0;
    st->stab_fac_fx = (Word16)random_range(0, 32767);
    st->gc_threshold_fx = random_range(0, 1 << 24);
    st->dm_fx.prev_state = (Word16)random_range(0, 2);
    st->dm_fx.prev_gain_code = random_range(0, 1 << 22);
    for (int i = 0; i < 6; i++) st->dm_fx.prev_gain_pit[i] = (Word16)random_range(0, 16384);
    for (int i = 0; i < M; i++) { st->mem_AR_fx[i] = (Word16)random_range(0, 20000); st->mem_MA_fx[i] = (Word16)random_range(-500, 500); }
    st->clas_dec = (Word16)random_range(0, 6); st->last_good_fx = (Word16)random_range(0, 6);
    st->bpf_off_fx = (Word16)random_range(0, 1); st->act_cnt2_fx = (Word16)random_range(0, 10);
    for (int i = 0; i < NB_SUBFR16k; i++) st->tilt_code_dec_fx[i] = -7;
    st->prev_gain_pit_dec_fx = -7;
    Word16 coder_type = (Word16)(next_random() % 4 ? UNVOICED : INACTIVE);
    random_signal(old_exc, EXC_LEN, mag); random_signal(old_bwe, BWE_LEN, mag); random_signal(exc2, L_FRAME16k, mag);
    random_signal(st->dct_post_old_exc_fx, DCT_LEN, mag); random_signal(st->last_exc_dct_in_fx, L_FRAME, mag);
    Word16 pitch_buf[NB_SUBFR16k], voice_factors[NB_SUBFR16k], gain_buf[NB_SUBFR16k], tmp_noise = -7;
    for (int i = 0; i < NB_SUBFR16k; i++) { pitch_buf[i] = -7; voice_factors[i] = -7; gain_buf[i] = -7; }
    Word16 aq[NB_SUBFR16k * (M + 1)] = {0};
    put1("core_brate", core_brate); put1("coder_type", coder_type); put1("last_ppp", st->last_ppp_mode_dec_fx);
    put1("last_nelp", st->last_nelp_mode_dec_fx); put1("next_bit_pos", st->next_bit_pos_fx); put1("stab_fac", st->stab_fac_fx);
    put16("exc", old_exc, EXC_LEN); put16("bwe", old_bwe, BWE_LEN); put16("exc2", exc2, L_FRAME16k);
    put_state(st);
    decod_unvoiced_fx(st, aq, coder_type, &tmp_noise, pitch_buf, voice_factors, old_exc + EXC_AT, exc2, old_bwe + BWE_AT, gain_buf);
    arrow(); put1("tmp_noise", tmp_noise); put16("pitch_buf", pitch_buf, NB_SUBFR16k); put16("voice_factors", voice_factors, NB_SUBFR16k);
    put16("gain_buf", gain_buf, NB_SUBFR16k);
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
        if (!strcmp(argv[2], "decod_unvoiced")) case_decod_unvoiced();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
