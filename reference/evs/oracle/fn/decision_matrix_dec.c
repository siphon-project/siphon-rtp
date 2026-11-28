/* Function-level oracle for lib_dec/decision_matrix_dec_fx.c. */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

/* Every Decoder_State_fx field the function reads or writes: C member, oracle name. */
#define FIELDS(X) \
    X(core_fx, core) X(core_brate_fx, core_brate) X(extl_fx, extl) X(extl_brate_fx, extl_brate) \
    X(ppp_mode_dec_fx, ppp_mode_dec) X(nelp_mode_dec_fx, nelp_mode_dec) X(igf, igf) \
    X(vbr_hw_BWE_disable_dec_fx, vbr_hw_bwe_disable_dec) X(mdct_sw, mdct_sw) X(total_brate_fx, total_brate) \
    X(cng_type_fx, cng_type) X(L_frame_fx, l_frame) X(bwidth_fx, bwidth) X(output_Fs_fx, output_fs) \
    X(prev_bfi_fx, prev_bfi) X(bfi_fx, bfi) X(last_CNG_L_frame_fx, last_cng_l_frame) X(fscale, fscale) \
    X(ini_frame_fx, ini_frame) X(last_L_frame_fx, last_l_frame) X(last_core_fx, last_core) \
    X(last_core_brate_fx, last_core_brate) X(last_extl_fx, last_extl) X(BER_detect, ber_detect) \
    X(last_total_brate_fx, last_total_brate) X(last_coder_type_fx, last_coder_type) X(last_bwidth_fx, last_bwidth) \
    X(last_total_brate_ber_fx, last_total_brate_ber) X(last_core_bfi, last_core_bfi) X(codec_mode, codec_mode) \
    X(last_L_frame_ori_fx, last_l_frame_ori) X(first_CNG_fx, first_cng) X(act_cnt2_fx, act_cnt2) \
    X(nb_subfr, nb_subfr) X(next_bit_pos_fx, next_bit_pos)

#define PUT(member, name) put1(#name, st->member);

static void case_decision_matrix(void)
{
    static const Word32 rates[] = {0, 2400, 2800, 7200, 8000, 9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};
    static const Word32 fs[] = {8000, 16000, 32000, 48000};
    static const Word32 last_rates[] = {-1, 7200, 8000, 13200, 24400, 32000, 64000};
    static const Word16 lengths[] = {256, 320, 640};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word32 rate = rates[next_random() % 14];
    int n = rate / 50;
    Word16 coder_type = (Word16)random_range(0, 7), sharp = (Word16)random_range(0, 1);
    Word16 hq_core_type = (Word16)random_range(0, 1), core_switching_flag = (Word16)random_range(0, 1);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->codec_mode = MODE1;
    st->total_brate_fx = rate;
    st->mdct_sw = (Word16)(next_random() % 6 == 0 ? MODE2 : 0);
    st->core_fx = (Word16)random_range(-1, 4); st->core_brate_fx = random_range(0, 64000);
    st->extl_fx = (Word16)random_range(-1, 13); st->extl_brate_fx = random_range(0, 3000);
    st->vbr_hw_BWE_disable_dec_fx = (Word16)random_range(0, 1);
    st->cng_type_fx = (Word16)random_range(0, 1); st->L_frame_fx = lengths[next_random() % 3];
    st->bwidth_fx = (Word16)random_range(0, 3); st->output_Fs_fx = fs[next_random() % 4];
    st->prev_bfi_fx = (Word16)random_range(0, 1); st->bfi_fx = (Word16)(next_random() % 4 == 0);
    st->last_CNG_L_frame_fx = lengths[next_random() % 2]; st->fscale = (Word16)random_range(0, 1000);
    st->ini_frame_fx = (Word16)random_range(0, 2); st->last_L_frame_fx = lengths[next_random() % 2];
    st->last_core_fx = (Word16)random_range(0, 4); st->last_core_brate_fx = random_range(0, 64000);
    st->last_extl_fx = (Word16)random_range(-1, 13);
    st->last_total_brate_fx = last_rates[next_random() % 7]; st->last_coder_type_fx = (Word16)random_range(0, 5);
    st->last_bwidth_fx = (Word16)random_range(0, 3); st->last_total_brate_ber_fx = last_rates[1 + next_random() % 6];
    st->last_core_bfi = (Word16)random_range(0, 4); st->last_L_frame_ori_fx = lengths[next_random() % 2];
    st->first_CNG_fx = (Word16)random_range(0, 1); st->act_cnt2_fx = (Word16)random_range(0, 30);
    st->nb_subfr = (Word16)random_range(4, 5); st->next_bit_pos_fx = 0;
    put_u16("bits", bit_buffer, n);
    put1("coder_type", coder_type); put1("sharp_flag", sharp); put1("hq_core_type", hq_core_type);
    put1("core_switching_flag", core_switching_flag);
    FIELDS(PUT)
    decision_matrix_dec_fx(st, &coder_type, &sharp, &hq_core_type, &core_switching_flag);
    arrow();
    put1("coder_type", coder_type); put1("sharp_flag", sharp); put1("hq_core_type", hq_core_type);
    put1("core_switching_flag", core_switching_flag);
    FIELDS(PUT)
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decision_matrix")) case_decision_matrix();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
