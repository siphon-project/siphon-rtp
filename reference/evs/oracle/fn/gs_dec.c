/* Function-level oracle for lib_dec/gs_dec_fx.c (decod_audio_fx and gsc_dec_fx).
 *
 * decod_audio: each case builds a decoder with init_decoder_fx, randomises the per-frame state the
 * GSC decoder reads (the GSC memories, the FEC gains, the excitation Q values, the previous frame's
 * coder type and class), then decodes one to four consecutive AUDIO / INACTIVE frames on it at a
 * rate / bandwidth combination the MODE1 decision matrix produces (7.2 and 8.0 kbit/s NB and WB,
 * 13.2 kbit/s NB, WB under WB BWE or TBE, SWB and FB under SWB BWE / TBE). Between frames the
 * excitation histories shift by one frame, as acelp_core_dec_fx does, and the frame's coder type
 * becomes last_coder_type as update_dec does (INACTIVE as UNVOICED). The per-frame inputs (bits,
 * bit position, coder type, bfi / BER flags, LP filters, LSFs) are all printed before the arrow;
 * after it, each frame's outputs and every state field that changed since the start (prefix
 * "s<f>."), so the Rust replay compares the whole state after every frame.
 *
 * gsc_dec: the FEC caller's form (bfi set, no bits, exc_wo_nf NULL, nb_subfr 4), on the same kind
 * of randomised state, comparing the spectrum and the whole state after. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"

#define NBITS 300
#define MAX_FRAMES 4
#define EXC_LEN L_EXC_DEC
#define BWE_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)
#define BWE_AT (PIT16k_MAX * 2)
#define AQ_LEN (NB_SUBFR16k * (M + 1))

static UWord16 bits[MAX_FRAMES][NBITS + 16];

/* total bit rate, bandwidth, extension-layer bit rate */
static const int combos[][3] = {
    {7200, NB, 0},     {7200, WB, 0},     {8000, NB, 0},     {8000, WB, 0},
    {13200, NB, 0},    {13200, WB, 350},  {13200, WB, 1050}, {13200, SWB, 1600},
    {13200, FB, 1600}, {8000, SWB, 0},
    /* 8 kbit/s WB has its own high-band path (bitallocation_exc, the band 9 edge bins): weighted */
    {8000, WB, 0},     {8000, WB, 0},     {8000, WB, 0},
};
static const Word16 last_types[] = {UNVOICED, AUDIO, GENERIC, VOICED, TRANSITION, AUDIO, UNVOICED};

static Word16 level(void) { return (Word16)(1 << random_range(3, 14)); }

static void random_lpc(Word16 *a, int nsub)
{
    for (int s = 0; s < nsub; s++) {
        a[s * (M + 1)] = 4096;
        for (int i = 1; i <= M; i++) {
            int span = 6000 * (M + 1 - i) / M;
            a[s * (M + 1) + i] = (Word16)random_range(-span, span);
        }
    }
}

/* Ascending LSFs in Hz·2.56 whose first one is below 4 kHz, as a decoded vector is. */
static void random_lsf(Word16 *lsf)
{
    int value = random_range(100, 900);
    for (int i = 0; i < M; i++) {
        lsf[i] = (Word16)value;
        value += random_range(150, 1600);
        if (value > 16300) value = 16300;
    }
    for (int i = 1; i < M; i++) if (lsf[i] <= lsf[i - 1]) lsf[i] = (Word16)(lsf[i - 1] + 1);
}

/* decod_audio_band9: only 8 kbit/s WB, and only cases where a good frame codes the last two bins of
 * band 9 (exc_diffQ[158] / [159], which set bitallocation_exc); about one frame in a few hundred
 * does, so the generator draws cases until one does and prints only that one. */
static int force_8k_wb;
static int band9_hit;
static int quiet; /* a trial draw: no state dumps */

static void randomise(Decoder_State_fx *st)
{
    static const int wb_8k[3] = {8000, WB, 0};
    const int *combo = combos[next_random() % (sizeof combos / sizeof combos[0])];
    if (force_8k_wb) combo = wb_8k;
    st->codec_mode = MODE1;
    st->L_frame_fx = L_FRAME;
    st->total_brate_fx = combo[0];
    st->bwidth_fx = (Word16)combo[1];
    st->extl_brate_fx = combo[2];
    st->core_brate_fx = combo[0] - combo[2];

    st->Q_exc = (Word16)random_range(0, 8);
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)random_range(0, 12);
    random_signal(st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2, level());
    random_signal(st->last_exc_dct_in_fx, L_FRAME, level());
    st->lp_gainp_fx = (Word16)random_range(0, 19661);
    /* lp_gainc is 10·mean_gain in Q3, a few hundred in practice (the lost-frame gain adds
     * shl(mult_r(lp_gainc, 0.1), 9) to each band: anything above ~640 saturates it); odd multiples
     * of 5 sit where the rounding of that 0.1 changes */
    {
        int r = next_random() % 8;
        st->lp_gainc_fx = (Word16)(r < 4 ? random_range(0, 400) : r < 6 ? 10 * random_range(0, 40) + 5 : random_range(0, 32767));
    }
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    for (int i = 0; i < NB_SUBFR16k; i++) st->tilt_code_dec_fx[i] = (Word16)random_range(0, 16384);
    st->seed_tcx_fx = random16();
    for (int i = 0; i < MBANDS_GN; i++) {
        st->old_y_gain_fx[i] = (Word16)random_range(-2000, 16000);
        st->lt_ener_per_band_fx[i] = (Word16)random_range(-2000, 16000);
    }
    random_signal(st->Last_GSC_spectrum_fx, L_FRAME, level());
    st->last_ener_fx = (Word16)random_range(0, 32767);
    for (int i = 0; i < 6; i++) st->last_bitallocation_band_fx[i] = (Word16)(next_random() & 1);
    st->Last_frame_ener_fx = (Word32)((next_random() & 0x7fffffff) >> random_range(0, 24));
    st->last_coder_type_fx = last_types[next_random() % (sizeof last_types / sizeof last_types[0])];
    st->last_good_fx = (Word16)random_range(0, 6);
    st->Last_GSC_noisy_speech_flag_fx = (Word16)(next_random() % 3 == 0);
    st->GSC_noisy_speech_fx = (Word16)(next_random() % 3 == 0);
    st->Last_GSC_pit_band_idx_fx = (Word16)random_range(0, 13);
    st->bpf_off_fx = (Word16)(next_random() & 1);
    st->noise_lev_fx = (Word16)random_range(NOISE_LEVEL_SP0, NOISE_LEVEL_SP3);
    st->cor_strong_limit_fx = (Word16)(next_random() & 1);
    for (int i = 0; i < GAIN_PRED_ORDER; i++) st->past_qua_en_fx[i] = (Word16)random_range(-14336, 3000);
    Carry = (Flag)(next_random() & 1);
}

static char *capture_state(Decoder_State_fx *st)
{
    if (quiet) return calloc(1, 1);
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

static void put_in_state(const char *before)
{
    for (const char *p = before; *p;) {
        const char *end = strchr(p + 1, ' ');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        printf(" in.%.*s", (int)len - 1, p + 1);
        p += len;
    }
}

/* The fields of `after` that differ from `before`, with prefix `pre`. */
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

static Decoder_State_fx *new_decoder(void)
{
    static const Word32 out_rates[3] = {16000, 32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = out_rates[next_random() % 3];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    randomise(st);
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    return st;
}

static void case_decod_audio(void)
{
    Decoder_State_fx *st = new_decoder();
    Word16 old_exc[EXC_LEN], old_bwe[BWE_LEN], exc2[L_FRAME], dct_epit[L_FRAME];
    Word16 pitch_buf[NB_SUBFR16k], voice_factors[NB_SUBFR16k], gain_buf[NB_SUBFR16k];
    Word16 aq[MAX_FRAMES][AQ_LEN], lsf_new[MAX_FRAMES][M];
    Word16 coder_type[MAX_FRAMES], next_bit_pos[MAX_FRAMES], total_num_bits[MAX_FRAMES];
    Word16 bfi[MAX_FRAMES], ber[MAX_FRAMES], last_good[MAX_FRAMES];
    int frames = random_range(1, MAX_FRAMES);
    char name[32];

    random_signal(old_exc, EXC_LEN, level());
    random_signal(old_bwe, BWE_LEN, level());
    for (int i = 0; i < L_FRAME; i++) { exc2[i] = random16(); dct_epit[i] = random16(); }
    for (int i = 0; i < NB_SUBFR16k; i++) { pitch_buf[i] = random16(); voice_factors[i] = random16(); gain_buf[i] = random16(); }
    put16("old_exc", old_exc, EXC_LEN);
    put16("old_bwe", old_bwe, BWE_LEN);
    put16("exc2", exc2, L_FRAME);
    put16("dct_epit", dct_epit, L_FRAME);
    put16("pitch_buf", pitch_buf, NB_SUBFR16k);
    put16("voice_factors", voice_factors, NB_SUBFR16k);
    put16("gain_buf", gain_buf, NB_SUBFR16k);
    put1("frames", frames);
    for (int f = 0; f < frames; f++) {
        for (int i = 0; i < NBITS; i++) bits[f][i] = (UWord16)(next_random() & 1);
        coder_type[f] = (Word16)(next_random() % 3 ? AUDIO : INACTIVE);
        next_bit_pos[f] = (Word16)random_range(20, 60);
        /* the frame's bit count; now and then too few, so the reads run out (BER_detect) */
        total_num_bits[f] = (Word16)(next_random() % 16 ? st->total_brate_fx / 50 : random_range(30, 120));
        bfi[f] = (Word16)(next_random() % 12 == 0);
        ber[f] = (Word16)(next_random() % 10 == 0);
        last_good[f] = (Word16)random_range(0, 6);
        random_lpc(aq[f], NB_SUBFR16k);
        random_lsf(lsf_new[f]);
        snprintf(name, sizeof name, "bits%d", f); put_u16(name, bits[f], NBITS);
        snprintf(name, sizeof name, "coder_type%d", f); put1(name, coder_type[f]);
        snprintf(name, sizeof name, "next_bit_pos%d", f); put1(name, next_bit_pos[f]);
        snprintf(name, sizeof name, "total_num_bits%d", f); put1(name, total_num_bits[f]);
        snprintf(name, sizeof name, "bfi%d", f); put1(name, bfi[f]);
        snprintf(name, sizeof name, "ber%d", f); put1(name, ber[f]);
        snprintf(name, sizeof name, "last_good%d", f); put1(name, last_good[f]);
        snprintf(name, sizeof name, "aq%d", f); put16(name, aq[f], AQ_LEN);
        snprintf(name, sizeof name, "lsf_new%d", f); put16(name, lsf_new[f], M);
    }
    char *before = capture_state(st);
    put_in_state(before);
    put1("carry", Carry);

    /* the frames' outputs go to a buffer: the arrow comes after every input */
    char *out = NULL;
    size_t out_length = 0;
    FILE *saved = stdout;
    fflush(stdout);
    stdout = open_memstream(&out, &out_length);
    for (int f = 0; f < frames; f++) {
        if (f > 0) {
            memmove(old_exc, old_exc + L_FRAME, (size_t)(EXC_LEN - L_FRAME) * sizeof(Word16));
            memmove(old_bwe, old_bwe + 2 * L_FRAME, (size_t)(BWE_LEN - 2 * L_FRAME) * sizeof(Word16));
            st->last_coder_type_fx = coder_type[f - 1] == INACTIVE ? UNVOICED : coder_type[f - 1];
            st->Last_GSC_noisy_speech_flag_fx = st->GSC_noisy_speech_fx;
        }
        st->bit_stream_fx = bits[f];
        st->next_bit_pos_fx = next_bit_pos[f];
        st->total_num_bits = total_num_bits[f];
        st->bfi_fx = bfi[f];
        st->BER_detect = ber[f];
        st->last_good_fx = last_good[f];

        decod_audio_fx(st, dct_epit, aq[f], coder_type[f], pitch_buf, voice_factors, old_exc + L_EXC_MEM_DEC, exc2,
                       old_bwe + BWE_AT, lsf_new[f], gain_buf);
        if (!bfi[f] && !st->BER_detect && st->core_brate_fx == ACELP_8k00 && st->bwidth_fx != NB &&
            (st->Last_GSC_spectrum_fx[L_FRAME8k - 2] != 0 || st->Last_GSC_spectrum_fx[L_FRAME8k - 1] != 0))
            band9_hit = 1;

        snprintf(name, sizeof name, "old_exc%d", f); put16(name, old_exc, EXC_LEN);
        snprintf(name, sizeof name, "old_bwe%d", f); put16(name, old_bwe, BWE_LEN);
        snprintf(name, sizeof name, "exc2%d", f); put16(name, exc2, L_FRAME);
        snprintf(name, sizeof name, "dct_epit%d", f); put16(name, dct_epit, L_FRAME);
        snprintf(name, sizeof name, "pitch_buf%d", f); put16(name, pitch_buf, NB_SUBFR16k);
        snprintf(name, sizeof name, "voice_factors%d", f); put16(name, voice_factors, NB_SUBFR16k);
        snprintf(name, sizeof name, "gain_buf%d", f); put16(name, gain_buf, NB_SUBFR16k);
        snprintf(name, sizeof name, "carry%d", f); put1(name, Carry);
        char *after = capture_state(st);
        snprintf(name, sizeof name, "s%d.", f);
        put_changed(name, before, after);
        free(after);
    }
    fclose(stdout);
    stdout = saved;
    arrow();
    fputs(out, stdout);
    free(out);
    free(before);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void case_decod_audio_band9(void)
{
    force_8k_wb = 1;
    for (;;) {
        unsigned long long start = harness_state;
        char *line = NULL;
        size_t length = 0;
        FILE *saved = stdout;
        fflush(stdout);
        stdout = open_memstream(&line, &length);
        band9_hit = 0;
        quiet = 1;
        case_decod_audio();
        quiet = 0;
        fclose(stdout);
        stdout = saved;
        free(line);
        if (band9_hit) {
            /* replay the same draw, printed */
            harness_state = start;
            case_decod_audio();
            break;
        }
    }
    force_8k_wb = 0;
}

static void case_gsc_dec(void)
{
    Decoder_State_fx *st = new_decoder();
    Word16 exc_dct_in[L_FRAME], lsf_new[M], last_bin = random16();

    st->bfi_fx = 1;
    st->BER_detect = (Word16)(next_random() % 4 == 0);
    st->next_bit_pos_fx = 0;
    st->total_num_bits = 0;
    random_signal(exc_dct_in, L_FRAME, level());
    random_lsf(lsf_new);
    Word16 pit_band_idx = st->Last_GSC_pit_band_idx_fx;
    Word16 diff_len = pit_band_idx == 0 ? 0 : (Word16)(mfreq_loc_div_25[pit_band_idx] + 1);
    put16("exc_dct_in", exc_dct_in, L_FRAME);
    put16("lsf_new", lsf_new, M);
    put1("diff_len", diff_len);
    put1("last_bin", last_bin);
    char *before = capture_state(st);
    put_in_state(before);

    gsc_dec_fx(st, exc_dct_in, pit_band_idx, diff_len, 0, st->L_frame_fx / L_SUBFR, st->last_coder_type_fx, &last_bin,
               lsf_new, NULL, st->Q_exc);

    arrow();
    put16("exc_dct_in", exc_dct_in, L_FRAME);
    put1("last_bin", last_bin);
    char *after = capture_state(st);
    put_changed("st.", before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decod_audio")) case_decod_audio();
        else if (!strcmp(argv[2], "decod_audio_band9")) case_decod_audio_band9();
        else if (!strcmp(argv[2], "gsc_dec")) case_gsc_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
