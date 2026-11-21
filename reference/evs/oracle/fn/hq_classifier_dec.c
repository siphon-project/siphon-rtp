/* Function-level oracle for lib_dec/hq_classifier_dec_fx.c: the class bits are read from a random
 * bitstream (sometimes too short, so the bit-error path is taken); the whole decoder state after the
 * call is compared, and the outputs. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "../../c-code/lib_dec/hq_classifier_dec_fx.c"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void case_hq_classifier_dec(void)
{
    static const Word32 out_rates[] = {16000, 32000, 48000};
    static const Word32 rates[] = {HQ_16k40, HQ_24k40, HQ_32k, HQ_48k, HQ_64k, HQ_96k, HQ_128k, ACELP_13k20};
    static const Word16 lengths[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k, L_FRAME48k};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = out_rates[next_random() % 3];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);

    int n = next_random() % 6 ? 64 : random_range(0, 3);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(n > 4 ? random_range(0, 8) : 0);
    st->codec_mode = MODE1;
    Word32 core_brate = rates[next_random() % 8];
    Word16 length = lengths[next_random() % 4];
    Word16 is_transient = -7, hqswb_clas = -7;

    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    char *before = capture_state(st);
    put_state_in(before);
    put_u16("bits", bit_buffer, n); put1("core_brate", core_brate); put1("length", length);
    put1("total_num_bits", n); put1("start", st->next_bit_pos_fx);
    Word16 bits = hq_classifier_dec_fx(st, core_brate, length, &is_transient, &hqswb_clas);
    arrow();
    put1("bits", bits); put1("is_transient", is_transient); put1("hqswb_clas", hqswb_clas);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before); free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq_classifier_dec")) case_hq_classifier_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
