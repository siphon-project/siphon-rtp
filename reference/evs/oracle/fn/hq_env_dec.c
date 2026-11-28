/* Function-level oracle for lib_dec/hq_env_dec_fx.c (envelope index decoding). */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void case_decode_envelope_indices(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 difidx[NB_SFM], hcode_l;
    Word16 num_sfm = (Word16)random_range(2, NB_SFM), start_norm = (Word16)random_range(0, NB_SFM - num_sfm);
    Word16 flag_hq2 = (Word16)random_range(0, 2), is_transient = (Word16)random_range(0, 1);
    Word16 numnrmibits = (Word16)random_range(0, 250);
    int n = 900;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() % 5 ? next_random() & 1 : 0);
    /* Force each mode now and then: the first two/three bits select it. */
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(next_random() % 10 ? random_range(0, 200) : random_range(n - 60, n));
    st->codec_mode = MODE1;
    for (int i = 0; i < NB_SFM; i++) difidx[i] = -7;
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("start_norm", start_norm);
    put1("num_sfm", num_sfm); put1("numnrmibits", numnrmibits); put1("flag_hq2", flag_hq2); put1("is_transient", is_transient);
    hcode_l = decode_envelope_indices_fx(st, start_norm, num_sfm, numnrmibits, difidx, flag_hq2, is_transient);
    arrow(); put1("hcode_l", hcode_l); put16("difidx", difidx, NB_SFM); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

/* dequantize_norms_fx: differential indices around 15 (no change), sometimes wild enough to leave
 * 0..39 and raise BER_detect; transient frames go through recovernorm_fx. */
static void case_dequantize_norms(void)
{
    static const Word16 counts[] = {NB_SFM, SFM_N_SWB, SFM_N_WB, 20};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 ynrm[NB_SFM], normqlg2[NB_SFM];
    Word16 is_transient = (Word16)(next_random() % 3 == 0);
    Word16 num_sfm = counts[next_random() % 4];
    Word16 start_norm = (Word16)(is_transient || next_random() % 2 ? 0 : random_range(0, NB_SFM - num_sfm));
    int spread = next_random() % 4 ? 3 : 15;
    for (int i = 0; i < NB_SFM; i++) ynrm[i] = (Word16)random_range(15 - spread, 15 + spread);
    ynrm[start_norm] = (Word16)random_range(0, 31);
    if (is_transient) ynrm[0] = (Word16)random_range(0, 31);
    for (int i = 0; i < NB_SFM; i++) normqlg2[i] = -4;
    put1("start_norm", start_norm); put1("num_sfm", num_sfm); put1("is_transient", is_transient); put16("ynrm", ynrm, NB_SFM);
    dequantize_norms_fx(st, start_norm, num_sfm, is_transient, ynrm, normqlg2);
    arrow(); put16("ynrm", ynrm, NB_SFM); put16("normqlg2", normqlg2, NB_SFM); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decode_envelope_indices")) case_decode_envelope_indices();
        else if (!strcmp(argv[2], "dequantize_norms")) case_dequantize_norms();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
