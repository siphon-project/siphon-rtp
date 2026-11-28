/* Function-level oracle for lib_com/gs_gains_fx.c (GSC band gains; the static Comp_band_log_ener,
 * GSC_gain_adj and VDQ_vec are proven through their callers). */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void case_comp_and_apply_gain(void)
{
    Word16 exc[L_FRAME], ener_i[MBANDS_GN], ener_y[MBANDS_GN];
    Word16 mbands = (Word16)random_range(1, MBANDS_GN), reuse = (Word16)random_range(0, 1);
    Word16 qexc_diff = (Word16)random_range(0, 15), q_exc = (Word16)random_range(-1, 12);
    if (next_random() % 3) random_signal(exc, L_FRAME, 8000); else for (int i = 0; i < L_FRAME; i++) exc[i] = random16();
    for (int b = 0; b < MBANDS_GN; b++) {
        ener_i[b] = (Word16)random_range(-4000, 20000);
        ener_y[b] = (Word16)(reuse ? random_range(0, 32767) : random_range(-4000, 20000));
    }
    put16("exc_diff_q", exc, L_FRAME); put16("ener_i", ener_i, MBANDS_GN); put16("ener_y", ener_y, MBANDS_GN);
    put1("mbands_gn", mbands); put1("re_use_gain", reuse); put1("qexc_diff", qexc_diff); put1("q_exc", q_exc);
    Comp_and_apply_gain_fx(exc, ener_i, ener_y, mbands, reuse, qexc_diff, q_exc);
    arrow(); put16("exc_diff_q", exc, L_FRAME); put16("ener_y", ener_y, MBANDS_GN); end_line();
}

static void case_ener_per_band_comp(void)
{
    Word16 exc[L_FRAME], y_gain4[MBANDS_GN + 2];
    Word16 eflag = (Word16)random_range(0, 1);
    Word16 mband = (Word16)(eflag ? MBANDS_GN : random_range(1, MBANDS_GN + 1));
    Word16 q_exc = (Word16)random_range(-2, 14);
    int shape = next_random() % 4;
    if (shape == 0) for (int i = 0; i < L_FRAME; i++) exc[i] = random16();
    else if (shape == 1) set16_fx(exc, 0, L_FRAME);
    else random_signal(exc, L_FRAME, shape == 2 ? 30000 : 300);
    for (int b = 0; b < MBANDS_GN + 2; b++) y_gain4[b] = -12345;
    put16("exc_diff", exc, L_FRAME); put1("q_exc", q_exc); put1("mband", mband); put1("eflag", eflag);
    Ener_per_band_comp_fx(exc, y_gain4, q_exc, mband, eflag);
    arrow(); put16("y_gain4", y_gain4, MBANDS_GN + 2); end_line();
}

static void case_gsc_gaindec(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 11600, 13200, 16400, 24400};
    static const Word16 coder_types[] = {INACTIVE, AUDIO, GENERIC, UNVOICED};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 y_gain_q[MBANDS_GN], old_y_gain[MBANDS_GN], mean;
    Word32 core_brate = rates[next_random() % 7];
    Word16 coder_type = coder_types[next_random() % 4], bwidth = (Word16)(next_random() % 3 ? NB : WB);
    int n = 120;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 80);
    st->codec_mode = MODE1;
    for (int b = 0; b < MBANDS_GN; b++) { y_gain_q[b] = random16(); old_y_gain[b] = random16(); }
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("core_brate", core_brate);
    put1("coder_type", coder_type); put1("bwidth", bwidth); put16("y_gain_q", y_gain_q, MBANDS_GN); put16("old_y_gain", old_y_gain, MBANDS_GN);
    mean = gsc_gaindec_fx(st, y_gain_q, core_brate, old_y_gain, coder_type, bwidth);
    arrow(); put1("mean", mean); put16("y_gain_q", y_gain_q, MBANDS_GN); put16("old_y_gain", old_y_gain, MBANDS_GN);
    put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "comp_and_apply_gain")) case_comp_and_apply_gain();
        else if (!strcmp(argv[2], "ener_per_band_comp")) case_ener_per_band_comp();
        else if (!strcmp(argv[2], "gsc_gaindec")) case_gsc_gaindec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
