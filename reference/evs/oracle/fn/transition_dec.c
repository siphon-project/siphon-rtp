/* Function-level oracle for lib_dec/transition_dec_fx.c: a whole TRANSITION frame (tc_classif_fx,
 * then transition_dec_fx for every subframe as decod_tran_fx calls it, which reaches tc_dec_fx in
 * the TC subframe) from random bits, and tc_classif_fx alone. */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define EXC_LEN L_EXC_DEC
#define EXC_AT L_EXC_MEM_DEC
#define BWE_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)
#define BWE_AT (PIT16k_MAX * 2)

static Decoder_State_fx *random_stream(int n)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    /* A quarter of the streams are mostly ones: the top pitch indices (the 16 kHz 8-bit lag at
     * 2*L_SUBFR and its bit-error clamp, the extended 10-bit TC lags) need runs of ones. */
    int ones = next_random() % 4 == 0;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(ones ? next_random() % 10 != 0 : next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(next_random() % 12 ? random_range(0, 30) : random_range(n - 40, n));
    st->codec_mode = MODE1;
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
    return st;
}

static void case_tc_classif(void)
{
    Decoder_State_fx *st = random_stream(random_range(10, 60));
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    put1("l_frame", l_frame);
    Word16 tc = tc_classif_fx(st, l_frame);
    arrow(); put1("tc", tc); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

static void case_transition_dec(void)
{
    static const Word32 rates12k8[] = {7200, 8000, 9600, 11600, 13200, 16400, 24400};
    static const Word32 rates16k[] = {24400, 32000, 48000, 64000};
    static Word16 old_exc[EXC_LEN], old_bwe[BWE_LEN];
    Word16 pitch_buf[NB_SUBFR16k], trace[NB_SUBFR16k * 8];
    Decoder_State_fx *st = random_stream(random_range(150, 400));
    Word16 l_frame = (Word16)(next_random() % 2 ? L_FRAME : L_FRAME16k);
    Word32 core_brate = l_frame == L_FRAME ? rates12k8[next_random() % 7] : rates16k[next_random() % 4];
    Word16 coder_type = (Word16)(next_random() % 6 ? TRANSITION : GENERIC);
    Word16 classify = (Word16)(next_random() % 5 != 0);
    Word16 tc_subfr;
    Word16 jopt = (Word16)random_range(0, 1), t0 = (Word16)random_range(34, 231), t0_frac = (Word16)random_range(0, 3);
    Word16 t0_min = (Word16)random_range(34, 200), t0_max, position = (Word16)random_range(0, 255);
    Word16 q_exc = (Word16)random_range(-1, 8);
    int k = 0;
    t0_max = (Word16)(t0_min + random_range(10, 30));
    random_signal(old_exc, EXC_LEN, 1 << random_range(4, 14));
    random_signal(old_bwe, BWE_LEN, 1 << random_range(4, 14));
    for (int i = 0; i < NB_SUBFR16k; i++) pitch_buf[i] = -1;
    st->Q_exc = q_exc;
    put1("l_frame", l_frame); put1("core_brate", core_brate); put1("coder_type", coder_type); put1("classify", classify);
    if (classify) tc_subfr = tc_classif_fx(st, l_frame);
    else {
        static const Word16 all[] = {0, 1, 2, 3, 4, 64, 128, 192, 256};
        tc_subfr = all[next_random() % 9];
    }
    put1("tc_subfr", tc_subfr); put1("jopt", jopt); put1("t0", t0); put1("t0_frac", t0_frac); put1("t0_min", t0_min);
    put1("t0_max", t0_max); put1("position", position); put1("q_exc", q_exc);
    put16("exc", old_exc, EXC_LEN); put16("bwe", old_bwe, BWE_LEN);
    Word16 *pt_pitch = pitch_buf;
    for (Word16 i_subfr = 0; i_subfr < l_frame; i_subfr += L_SUBFR) {
        transition_dec_fx(st, core_brate, 0, l_frame, i_subfr, coder_type, tc_subfr, &jopt, old_exc + EXC_AT, &t0, &t0_frac,
                          &t0_min, &t0_max, &pt_pitch, &position, old_bwe + BWE_AT, &st->Q_exc);
        trace[k++] = jopt; trace[k++] = t0; trace[k++] = t0_frac; trace[k++] = t0_min; trace[k++] = t0_max;
        trace[k++] = position; trace[k++] = (Word16)(pt_pitch - pitch_buf); trace[k++] = st->next_bit_pos_fx;
        pt_pitch++;
    }
    arrow(); put16("trace", trace, k); put16("pitch", pitch_buf, NB_SUBFR16k); put16("exc", old_exc, EXC_LEN);
    put16("bwe", old_bwe, BWE_LEN); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "tc_classif")) case_tc_classif();
        else if (!strcmp(argv[2], "transition_dec")) case_transition_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
