/* Oracle for lib_dec/acelp_core_dec_fx.c, the ACELP core decoder.
 *
 * `stream FILE OUTPUT_FS EVERY` runs the whole reference decoder (lib_dec/decoder.c's main loop,
 * MODE1) over a TS 26.444 conformance bitstream and records the calls of acelp_core_dec_fx: the
 * first few calls of every distinct frame situation (bad frame, comfort noise, NELP, PPP, each
 * coder type, each frame length and bandwidth, the frame after a SID or a loss, ...) and then every
 * EVERY-th call. Each recorded call prints the WHOLE decoder state before it (prefix "in."), the
 * bits and the caller's buffers, and after it the outputs and the state fields that changed
 * (prefix "st."); tests/evs_fn_oracle/acelp_core_dec.rs replays every line on a Rust decoder
 * loaded with the "before" state and compares the outputs and the whole state.
 *
 * The reference's acelp_core_dec_fx is renamed so a wrapper can take its place in the decoder; the
 * wrapper forwards unchanged outside stream mode. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#define acelp_core_dec_fx acelp_core_dec_fx_reference
#include "../../c-code/lib_dec/acelp_core_dec_fx.c"
#undef acelp_core_dec_fx

static int stream_mode;
static long stream_every, stream_calls, stream_recorded;

#define SIGNATURES 4096
static unsigned long long signature_keys[SIGNATURES];
static int signature_counts[SIGNATURES], signature_used;
#define FIRST_PER_SIGNATURE 3

/* How many times this frame situation was seen (including this call). */
static int situation_count(Decoder_State_fx *st, Word16 coder_type)
{
    unsigned long long key = 0;
    key = key * 4 + (st->bfi_fx != 0);
    key = key * 4 + (st->nelp_mode_dec_fx == 1);
    key = key * 4 + (st->ppp_mode_dec_fx == 1);
    key = key * 8 + (unsigned)coder_type;
    key = key * 4 + (st->core_brate_fx == FRAME_NO_DATA ? 0 : st->core_brate_fx == SID_2k40 ? 1 : st->core_brate_fx == SID_1k75 ? 2 : 3);
    key = key * 4 + (st->L_frame_fx == L_FRAME);
    key = key * 4 + (unsigned)st->bwidth_fx;
    key = key * 4 + (unsigned)st->last_bwidth_fx;
    key = key * 4 + (st->last_core_brate_fx == FRAME_NO_DATA ? 0 : st->last_core_brate_fx <= SID_2k40 ? 1 : 2);
    key = key * 4 + (st->prev_bfi_fx != 0);
    key = key * 4 + (st->last_core_fx == ACELP_CORE ? 0 : st->last_core_fx == HQ_CORE ? 1 : 2);
    key = key * 4 + (st->cng_type_fx == FD_CNG);
    key = key * 4 + (st->flag_cna != 0);
    key = key * 4 + (st->L_frame_fx != st->last_L_frame_fx);
    key = key * 4 + (st->last_good_fx == INACTIVE_CLAS ? 0 : st->last_good_fx >= VOICED_CLAS ? 1 : 2);
    key = key * 4 + (st->last_ppp_mode_dec_fx == 1);
    key = key * 4 + (st->last_nelp_mode_dec_fx == 1);
    key = key * 4 + (st->extl_fx == -1 ? 0 : st->extl_fx == WB_BWE ? 1 : 2);
    key = key * 16 + (unsigned)(st->core_brate_fx / 1600);
    for (int i = 0; i < signature_used; i++)
        if (signature_keys[i] == key) return ++signature_counts[i];
    if (signature_used < SIGNATURES) {
        signature_keys[signature_used] = key;
        signature_counts[signature_used++] = 1;
    }
    return 1;
}

void acelp_core_dec_fx(Decoder_State_fx *st, Word16 synth_out[], Word32 bwe_exc_extended[], Word16 *voice_factors,
                       Word16 old_syn_12k8_16k[], Word16 coder_type, Word16 sharpFlag, Word16 pitch_buf_fx[NB_SUBFR16k],
                       Word16 *unbits, Word16 *sid_bw)
{
    if (!stream_mode) {
        acelp_core_dec_fx_reference(st, synth_out, bwe_exc_extended, voice_factors, old_syn_12k8_16k, coder_type, sharpFlag,
                                    pitch_buf_fx, unbits, sid_bw);
        return;
    }
    static UWord16 bits_in[MAX_BITS_PER_FRAME + 16];
    static Word32 bwe_in[L_FRAME32k + NL_BUFF_OFFSET];
    Word16 voice_in[NB_SUBFR16k], syn_in[L_FRAME16k], pitch_in[NB_SUBFR16k], unbits_in = *unbits, sid_in = *sid_bw;
    int nbits = st->total_num_bits + 16;
    int sampled = situation_count(st, coder_type) <= FIRST_PER_SIGNATURE || stream_calls % stream_every == 0;
    stream_calls++;
    if (!sampled) {
        acelp_core_dec_fx_reference(st, synth_out, bwe_exc_extended, voice_factors, old_syn_12k8_16k, coder_type, sharpFlag,
                                    pitch_buf_fx, unbits, sid_bw);
        return;
    }
    memcpy(bits_in, st->bit_stream_fx, nbits * sizeof(UWord16));
    memcpy(bwe_in, bwe_exc_extended, sizeof bwe_in);
    memcpy(voice_in, voice_factors, sizeof voice_in);
    memcpy(syn_in, old_syn_12k8_16k, sizeof syn_in);
    memcpy(pitch_in, pitch_buf_fx, sizeof pitch_in);
    char *before = capture_state(st);
    acelp_core_dec_fx_reference(st, synth_out, bwe_exc_extended, voice_factors, old_syn_12k8_16k, coder_type, sharpFlag,
                                pitch_buf_fx, unbits, sid_bw);
    stream_recorded++;
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("coder_type", coder_type);
    put1("sharp_flag", sharpFlag);
    put_u16("bits", bits_in, nbits);
    put32("bwe_in", bwe_in, L_FRAME32k + NL_BUFF_OFFSET);
    put16("voice_in", voice_in, NB_SUBFR16k);
    put16("syn_in", syn_in, L_FRAME16k);
    put16("pitch_in", pitch_in, NB_SUBFR16k);
    put1("unbits_in", unbits_in);
    put1("sid_in", sid_in);
    put_state_in(before);
    arrow();
    put16("synth_out", synth_out, st->output_frame_fx);
    put32("bwe_out", bwe_exc_extended, L_FRAME32k + NL_BUFF_OFFSET);
    put16("voice_out", voice_factors, NB_SUBFR16k);
    put16("syn_out", old_syn_12k8_16k, L_FRAME16k);
    put16("pitch_out", pitch_buf_fx, NB_SUBFR16k);
    put1("unbits_out", *unbits);
    put1("sid_out", *sid_bw);
    char *after = capture_state(st);
    put_changed(before, after);
    free(after);
    free(before);
    end_line();
}

/* The reference decoder's main loop (lib_dec/decoder.c) for a G.192 bitstream, MODE1 and MODE2. */
static void stream(const char *file, Word32 fs, long every)
{
    static UWord16 stream_bits[MAX_BITS_PER_FRAME + 16];
    static Word16 output[L_FRAME48k];
    FILE *f = fopen(file, "rb");
    if (f == NULL) { fprintf(stderr, "cannot open %s\n", file); exit(1); }
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->bit_stream_fx = stream_bits;
    st->Opt_AMR_WB_fx = 0;
    st->Opt_VOIP_fx = 0;
    st->bitstreamformat = G192;
    st->amrwb_rfc4867_flag = -1;
    st->output_Fs_fx = fs;
    read_indices_fx(st, f, 1);
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    reset_indices_dec_fx(st);
    init_decoder_fx(st);
    rd_record_cldfb(st);
    stream_mode = 1;
    stream_every = every;
    while (read_indices_fx(st, f, 0)) {
        if (st->codec_mode == MODE1) {
            if (st->Opt_AMR_WB_fx) amr_wb_dec_fx(output, st);
            else evs_dec_fx(st, output, FRAMEMODE_NORMAL);
        } else if (st->bfi_fx == 0) evs_dec_fx(st, output, FRAMEMODE_NORMAL);
        else evs_dec_fx(st, output, FRAMEMODE_MISSING);
        if (st->ini_frame_fx < MAX_FRAME_COUNTER) st->ini_frame_fx = add(st->ini_frame_fx, 1);
    }
    fprintf(stderr, "acelp_core_dec_fx calls: %ld recorded: %ld\n", stream_calls, stream_recorded);
    fclose(f);
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    no_core_dumps();
    if (argc == 5 && !strcmp(argv[1], "stream")) { stream(argv[2], atol(argv[3]), atol(argv[4])); return 0; }
    fprintf(stderr, "usage: stream FILE OUTPUT_FS EVERY\n");
    return 2;
}
