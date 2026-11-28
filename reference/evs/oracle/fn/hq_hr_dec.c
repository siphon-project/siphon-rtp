/* Function-level oracle for hq_hr_dec_fx (lib_dec/hq_hr_dec_fx.c): the whole decoder state before and
 * after, over consecutive frames on one decoder (`corpus hq_hr_dec_frames`, random bits at 24.4 to
 * 128 kbit/s, frame lengths 320 / 640 / 960) and exactly where the reference decoder calls it on a
 * conformance bitstream (`stream FILE RATE EVERY`). The reference's hq_hr_dec_fx is renamed so the
 * wrapper below can take its place in the decoder. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#define hq_hr_dec_fx hq_hr_dec_fx_reference
#include "../../c-code/lib_dec/hq_hr_dec_fx.c"
#undef hq_hr_dec_fx

#define FRAMES 4

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static int stream_mode;
static long stream_every, stream_calls, stream_classes[8];

void hq_hr_dec_fx(Decoder_State_fx *st, Word32 *t_audio_q, const Word16 length, Word16 num_bits, Word16 *ynrm,
                  Word16 *is_transient, Word16 *hqswb_clas, Word16 *SWB_fenv)
{
    if (!stream_mode) {
        hq_hr_dec_fx_reference(st, t_audio_q, length, num_bits, ynrm, is_transient, hqswb_clas, SWB_fenv);
        return;
    }
    static UWord16 bits_in[MAX_BITS_PER_FRAME + 16];
    static Word32 audio_in[L_FRAME48k];
    Word16 ynrm_in[NB_SFM], fenv_in[SWB_FENV + DIM_FB];
    int nbits = st->total_num_bits + 16;
    memcpy(bits_in, st->bit_stream_fx, nbits * sizeof(UWord16));
    memcpy(audio_in, t_audio_q, sizeof audio_in);
    memcpy(ynrm_in, ynrm, sizeof ynrm_in);
    memcpy(fenv_in, SWB_fenv, sizeof fenv_in);
    char *before = capture_state(st);
    hq_hr_dec_fx_reference(st, t_audio_q, length, num_bits, ynrm, is_transient, hqswb_clas, SWB_fenv);
    stream_classes[*hqswb_clas & 7]++;
    if (stream_calls++ % stream_every == 0) {
        put1("output_fs", st->output_Fs_fx);
        put1("output_frame", st->output_frame_fx);
        put1("length", length);
        put1("num_bits", num_bits);
        put_u16("bits", bits_in, nbits);
        put32("audio_in", audio_in, L_FRAME48k);
        put16("ynrm_in", ynrm_in, NB_SFM);
        put16("fenv_in", fenv_in, SWB_FENV + DIM_FB);
        put_state_in(before);
        arrow();
        put32("audio", t_audio_q, L_FRAME48k);
        put16("ynrm", ynrm, NB_SFM);
        put1("is_transient", *is_transient);
        put1("hqswb_clas", *hqswb_clas);
        put16("fenv", SWB_fenv, SWB_FENV + DIM_FB);
        char *after = capture_state(st);
        put_changed(before, after);
        free(after);
        end_line();
    }
    free(before);
}

/* The reference decoder's main loop (lib_dec/decoder.c) for a G.192 bitstream. */
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
    fprintf(stderr, "hq_hr_dec_fx calls: %ld classes normal %ld transient %ld harmonic %ld hvq %ld gen_swb %ld gen_fb %ld\n",
            stream_calls, stream_classes[0], stream_classes[1], stream_classes[2], stream_classes[3], stream_classes[4],
            stream_classes[5]);
    fclose(f);
    destroy_decoder(st);
    free(st);
}

static void random_frame_bits(int n)
{
    int density = (int)(next_random() % 4);
    for (int i = 0; i < n; i++)
        bit_buffer[i] = (UWord16)(density == 0 ? (next_random() % 5 == 0) : density == 1 ? (next_random() % 5 != 0) : (next_random() & 1));
}

static void random_mode(Word32 *brate, Word16 *length)
{
    static const Word32 rates[] = {HQ_24k40, HQ_32k, HQ_48k, HQ_64k, HQ_96k, HQ_128k, HQ_24k40, HQ_32k, HQ_32k};
    static const Word16 lengths[] = {L_FRAME16k, L_FRAME32k, L_FRAME48k, L_FRAME32k, L_FRAME48k, L_FRAME32k};
    *brate = rates[next_random() % 9];
    *length = lengths[next_random() % 6];
}

static void random_memories(Decoder_State_fx *st)
{
    for (int i = 0; i < 27; i++) st->mem_norm_fx[i] = st->mem_norm_hqfec_fx[i] = (Word16)random_range(0, 39);
    st->mem_env_delta_fx = (Word16)random_range(0, 20000);
    st->mem_env_delta_hqfec_fx = (Word16)random_range(0, 20000);
    int p = random_range(1, 32766);
    st->env_stab_state_p_fx[0] = (Word16)p;
    st->env_stab_state_p_fx[1] = (Word16)(32767 - p);
    st->envstabplc_hocnt_fx = (Word16)random_range(0, 10);
    st->prev_ener_shb_fx = (Word16)random_range(0, 3000);
    for (int i = 0; i < SWB_FENV; i++) st->prev_SWB_fenv_fx[i] = (Word16)random_range(0, 3000);
    st->bws_cnt1_fx = (Word16)(next_random() % 2 ? 0 : random_range(1, 10));
    st->L_frame_fx = next_random() % 2 ? L_FRAME16k : L_FRAME;
    st->last_inner_frame_fx = (Word16)(next_random() % 3 == 0 ? L_FRAME16k : next_random() % 2 ? L_FRAME32k : L_FRAME48k);
    st->prev_frm_hfe2_fx = (Word16)(next_random() % 2 ? 0 : random_range(1, 80));
    st->prev_stab_hfe2_fx = (Word16)random_range(0, 3);
    st->no_att_hangover_fx = (Word16)(next_random() % 2 ? 0 : random_range(1, 10));
    st->energy_lt_fx = (Word32)((next_random() & 0x7fffffff) >> random_range(0, 20));
    st->hq_generic_seed_fx = (Word16)random_range(-32768, 32767);
    st->prev_noise_level_fx[0] = (Word16)random_range(0, 20000);
    st->prev_noise_level_fx[1] = (Word16)random_range(0, 20000);
    st->prev_R_fx = (Word16)random_range(0, 8);
    for (int i = 0; i < 20; i++) st->prev_coeff_out_fx[i] = random_range(-(1 << 20), 1 << 20);
    for (int i = 0; i < 3; i++) st->old_is_transient_fx[i] = (Word16)(next_random() & 1);
    for (int i = 0; i < 26; i++) {
        st->prev_normq_fx[i] = (Word32)((next_random() & 0x3fffffff) >> random_range(0, 20));
        st->prev_env_fx[i] = (Word32)((next_random() & 0x3fffffff) >> random_range(0, 20));
        st->prev_env_Q[i] = (Word16)random_range(0, 20);
    }
    st->prev_bfi_fx = (Word16)(next_random() % 4 == 0);
    st->prev_L_swb_norm_fx = (Word16)random_range(0, 64);
    st->prev_hqswb_clas_fx = (Word16)random_range(0, 5);
    st->core_fx = HQ_CORE;
}

static void case_hq_hr_dec_frames(void)
{
    static const Word32 out_rates[] = {16000, 32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = out_rates[next_random() % 3];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    random_memories(st);
    Word32 brate;
    Word16 length;
    random_mode(&brate, &length);
    if (next_random() % 4 == 0) {
        /* the 24.4 kbit/s SWB frame whose HQ generic envelope the bandwidth-switching counter scales on its
         * last step (bws_cnt1 == 1), with a nonzero previous envelope */
        brate = HQ_24k40;
        length = L_FRAME32k;
        st->bws_cnt1_fx = 1;
        for (int i = 0; i < SWB_FENV; i++) st->prev_SWB_fenv_fx[i] = (Word16)random_range(1, 3000);
    }

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    char *before = capture_state(st);
    put_state_in(before);
    char *previous = before;
    int completed = 0;
    for (int f = 0; f < FRAMES; f++) {
        char name[32];
        static Word32 audio[L_FRAME48k];
        Word16 ynrm[NB_SFM], fenv[SWB_FENV + DIM_FB], is_transient = -7, hqswb_clas = -7;
        if (f > 0 && next_random() % 3 == 0) random_mode(&brate, &length);
        st->core_brate_fx = brate;
        int frame_bits = (int)(brate / 50), lead = next_random() % 8 ? random_range(0, 12) : random_range(40, 200);
        Word16 num_bits = (Word16)s_min(frame_bits, HQ_48k / 50);
        num_bits = sub(num_bits, (Word16)lead);
        random_frame_bits(frame_bits);
        st->bit_stream_fx = bit_buffer;
        st->total_num_bits = (Word16)frame_bits;
        st->next_bit_pos_fx = (Word16)lead;
        st->BER_detect = 0;
        for (int i = 0; i < L_FRAME48k; i++) audio[i] = 0;
        for (int i = 0; i < NB_SFM; i++) ynrm[i] = 39;
        for (int i = 0; i < SWB_FENV + DIM_FB; i++) fenv[i] = 0;
        Word32 mode[] = {brate, length, num_bits, lead};
        sprintf(name, "f%d_mode", f); put32(name, mode, 4);
        sprintf(name, "f%d_bits", f); put_u16(name, bit_buffer, frame_bits);
        int ok = GUARDED(hq_hr_dec_fx(st, audio, length, num_bits, ynrm, &is_transient, &hqswb_clas, fenv));
        if (!ok) { sprintf(name, "f%d_skip", f); put1(name, 1); break; }
        sprintf(name, "f%d_audio", f); put32(name, audio, L_FRAME48k);
        sprintf(name, "f%d_ynrm", f); put16(name, ynrm, NB_SFM);
        sprintf(name, "f%d_is_transient", f); put1(name, is_transient);
        sprintf(name, "f%d_hqswb_clas", f); put1(name, hqswb_clas);
        sprintf(name, "f%d_fenv", f); put16(name, fenv, SWB_FENV + DIM_FB);
        char *after = capture_state(st);
        sprintf(name, "f%d.", f);
        /* fields that differ from the state before the first frame (the test overlays on in.) */
        {
            /* put_changed prints "st."; emulate the frame prefix by printing the diff manually */
            const char *a = after, *b = before;
            while (*a) {
                const char *a_end = strchr(a + 1, ' '), *b_end = strchr(b + 1, ' ');
                size_t a_len = a_end ? (size_t)(a_end - a) : strlen(a);
                size_t b_len = b_end ? (size_t)(b_end - b) : strlen(b);
                if (a_len != b_len || memcmp(a, b, a_len)) printf(" %s%.*s", name, (int)a_len - 1, a + 1);
                a += a_len;
                b += b_len;
            }
        }
        free(after);
        completed++;
    }
    (void)previous; (void)completed;
    free(before);
    arrow();
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "stream")) { stream(argv[2], atol(argv[3]), atol(argv[4])); return 0; }
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq_hr_dec_frames")) case_hq_hr_dec_frames();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
