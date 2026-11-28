/* Conformance-bitstream support shared by the oracles that wrap a function the reference decoder
 * calls (the pattern of hq_lr_dec.c): the whole-state capture as a string, the "only the fields that
 * changed" printer, and the decoder's main loop (lib_dec/decoder.c) over a G.192 bitstream.
 * Include after init_dec.c (STATE_DUMP_LIBRARY). The wrapper in the including oracle checks
 * `stream_mode`, and records the call when `stream_sample()` says so. */
#ifndef EVS_ORACLE_STREAM_MODE_H
#define EVS_ORACLE_STREAM_MODE_H

static int stream_mode;
static long stream_every, stream_calls;

/* The state dump as a string (keys without prefix). */
static char *capture_state(Decoder_State_fx *st)
{
    char *buffer = NULL;
    size_t length = 0;
    FILE *saved = stdout;
    fflush(stdout);
    stdout = open_memstream(&buffer, &length);
    rd_dump_DecoderState("", st);
    fclose(stdout);
    stdout = saved;
    return buffer;
}

/* Print `after` as only the fields that differ from `before`, with prefix `pre`. */
static void put_changed(const char *pre, const char *before, const char *after)
{
    while (*after) {
        const char *a_end = strchr(after + 1, ' '), *b_end = strchr(before + 1, ' ');
        size_t a_len = a_end ? (size_t)(a_end - after) : strlen(after);
        size_t b_len = b_end ? (size_t)(b_end - before) : strlen(before);
        if (a_len != b_len || memcmp(after, before, a_len)) printf(" %s%.*s", pre, (int)a_len - 1, after + 1);
        after += a_len;
        before += b_len;
    }
}

/* The whole state `before`, every key with prefix "in.". */
static void put_state_in(const char *before)
{
    for (const char *p = before; *p;) {
        const char *e = strchr(p + 1, ' ');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        printf(" in.%.*s", (int)len - 1, p + 1);
        p += len;
    }
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
    fprintf(stderr, "wrapped calls: %ld\n", stream_calls);
    fclose(f);
    destroy_decoder(st);
    free(st);
}

/* A new decoder at the given output rate, as the oracles start one. */
static Decoder_State_fx *new_decoder(Word32 output_fs)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = output_fs;
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    return st;
}

/* Plausible 16-bit audio: a few sinusoids at a random level plus noise. */
static void tonal16(Word16 *x, int n, int magnitude)
{
    int harmonics = random_range(1, 4);
    double period = random_range(30, 110) + (next_random() % 100) / 100.0;
    double phase = (next_random() % 628) / 100.0;
    for (int i = 0; i < n; i++) {
        double v = 0;
        for (int h = 1; h <= harmonics; h++) v += sin(6.283185307 * h * (i / period) + phase * h) / h;
        v = v * magnitude / 2.0 + random_range(-magnitude / 16, magnitude / 16);
        if (v > 32767) v = 32767;
        if (v < -32768) v = -32768;
        x[i] = (Word16)v;
    }
}

static void tonal32(Word32 *x, int n, int magnitude)
{
    int harmonics = random_range(1, 4);
    double period = random_range(30, 110) + (next_random() % 100) / 100.0;
    double phase = (next_random() % 628) / 100.0;
    for (int i = 0; i < n; i++) {
        double v = 0;
        for (int h = 1; h <= harmonics; h++) v += sin(6.283185307 * h * (i / period) + phase * h) / h;
        x[i] = (Word32)(v * magnitude / 2.0) + random_range(-magnitude / 16, magnitude / 16);
    }
}

#endif
