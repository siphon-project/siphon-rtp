/* Function-level oracle for core_switching_hq_prepare_dec_fx (lib_dec/core_switching_dec_fx.c).
 *
 * corpus: a decoder with random switching-frame state (last core, previous frame loss, last frame
 * length, core bit rate, bandwidth, the concealed previous output); the whole state is printed
 * before ("in.") and, after the arrow, the fields the call changed ("st.").
 *
 * stream: the call exactly as hq_core_dec_fx makes it on a conformance bitstream (every
 * ACELP->HQ switching frame is recorded). */
#include <math.h>
#include <sys/resource.h>
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#define core_switching_hq_prepare_dec_fx core_switching_hq_prepare_dec_fx_reference
#include "../../c-code/lib_dec/core_switching_dec_fx.c"
#undef core_switching_hq_prepare_dec_fx
#include "stream_mode.h"

void core_switching_hq_prepare_dec_fx(Decoder_State_fx *st, Word16 *num_bits, const Word16 output_frame)
{
    if (!stream_mode) {
        core_switching_hq_prepare_dec_fx_reference(st, num_bits, output_frame);
        return;
    }
    Word16 bits_in = *num_bits;
    char *before = capture_state(st);
    core_switching_hq_prepare_dec_fx_reference(st, num_bits, output_frame);
    if (stream_calls++ % stream_every == 0) {
        put1("output_fs", st->output_Fs_fx);
        put1("output_frame", st->output_frame_fx);
        put1("num_bits_in", bits_in);
        put1("call_output_frame", output_frame);
        put_state_in(before);
        arrow();
        put1("num_bits", *num_bits);
        char *after = capture_state(st);
        put_changed("st.", before, after);
        free(after);
        end_line();
    }
    free(before);
}

static void case_core_switching_hq_prepare(void)
{
    static const Word32 rates[] = {ACELP_7k20, ACELP_8k00, ACELP_9k60, ACELP_11k60, ACELP_12k85, ACELP_13k20,
                                   ACELP_14k80, ACELP_16k40, ACELP_22k60, ACELP_23k05, ACELP_23k85, ACELP_24k40,
                                   ACELP_32k, ACELP_48k, ACELP_64k, HQ_96k, HQ_128k};
    static const Word16 frames[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k, L_FRAME48k};
    Word32 fs = frames[next_random() % 4] * 50;
    Decoder_State_fx *st = new_decoder(fs);
    st->last_core_fx = (Word16)(next_random() % 4 ? HQ_CORE : ACELP_CORE);
    st->prev_bfi_fx = (Word16)(next_random() & 1);
    st->last_L_frame_fx = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    st->core_brate_fx = rates[next_random() % (sizeof rates / sizeof rates[0])];
    st->bwidth_fx = (Word16)random_range(0, 3);
    st->Q_old_wtda = (Word16)random_range(0, 4);
    for (int i = 0; i < L_FRAME48k; i++) {
        st->old_out_fx[i] = random16();
        st->fer_samples_fx[i] = (Word16)random_range(-9, 9);
    }
    Word16 output_frame = (Word16)(fs / 50);
    Word16 num_bits = (Word16)random_range(100, 1300);
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("num_bits_in", num_bits);
    put1("call_output_frame", output_frame);
    char *before = capture_state(st);
    put_state_in(before);
    core_switching_hq_prepare_dec_fx(st, &num_bits, output_frame);
    arrow();
    put1("num_bits", num_bits);
    char *after = capture_state(st);
    put_changed("st.", before, after);
    free(after);
    free(before);
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    /* a crash must not pop up a core-dump report: no core files */
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
    if (argc == 5 && !strcmp(argv[1], "stream")) { stream(argv[2], atol(argv[3]), atol(argv[4])); return 0; }
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "core_switching_hq_prepare_dec")) case_core_switching_hq_prepare();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
