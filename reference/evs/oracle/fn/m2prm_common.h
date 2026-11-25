/* Shared by the m2prm_* oracles: a decoder built by init_decoder_fx, the whole-state print helpers and
 * generators of in-domain signals. Include after init_dec.c (STATE_DUMP_LIBRARY) and state_capture.h. */
#ifndef M2PRM_COMMON_H
#define M2PRM_COMMON_H

static Decoder_State_fx *new_state_at(Word32 output_fs)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = output_fs;
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    st->codec_mode = MODE2;
    return st;
}

static Decoder_State_fx *new_state(void)
{
    static const Word32 out_rates[3] = {16000, 32000, 48000};
    return new_state_at(out_rates[next_random() % 3]);
}

static void finish(Decoder_State_fx *st, char *before)
{
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void random_lpc(Word16 *a)
{
    a[0] = 4096;
    for (int k = 1; k <= M; k++) a[k] = (Word16)random_range(-12000 / k - 2000, 12000 / k + 2000);
}

/* a LSP vector: M cosines in descending order */
static void random_lsp(Word16 *lsp)
{
    int upper = 32000;
    for (int i = 0; i < M; i++) {
        int step = random_range(200, 4000);
        upper -= step;
        if (upper < -32000 + (M - 1 - i) * 100) upper = -32000 + (M - 1 - i) * 100;
        lsp[i] = (Word16)upper;
    }
}

static void random_synthesis(Word16 *x, int n)
{
    int magnitude = next_random() % 4 == 0 ? 32767 : random_range(50, 12000);
    random_signal(x, n, magnitude);
    if (next_random() % 6 == 0) for (int i = 0; i < n; i++) x[i] = (Word16)(x[i] + random_range(-300, 300));
    if (next_random() % 12 == 0) for (int i = 0; i < n; i++) x[i] = 0;
}

#endif

/* ---- MODE2 (rate, bandwidth, RF) combinations the decoder runs the LPD core at ---- */
typedef struct { Word32 rate; Word16 bw, rf; } Mode2Combo;

static const Mode2Combo mode2_combos[] = {
    {9600, NB, 0}, {9600, WB, 0}, {9600, SWB, 0},
    {13200, NB, 0}, {13200, WB, 0}, {13200, SWB, 0}, {13200, WB, 1}, {13200, SWB, 1},
    {16400, NB, 0}, {16400, WB, 0}, {16400, SWB, 0}, {16400, FB, 0},
    {24400, NB, 0}, {24400, WB, 0}, {24400, SWB, 0}, {24400, FB, 0},
    {32000, WB, 0}, {32000, SWB, 0}, {32000, FB, 0},
    {48000, WB, 0}, {48000, SWB, 0}, {48000, FB, 0},
    {96000, WB, 0}, {96000, SWB, 0}, {96000, FB, 0},
    {128000, WB, 0}, {128000, SWB, 0}, {128000, FB, 0},
};
#define N_MODE2_COMBOS (int)(sizeof(mode2_combos) / sizeof(mode2_combos[0]))

static const Mode2Combo *random_combo(void) { return &mode2_combos[next_random() % N_MODE2_COMBOS]; }

/* FrameSizeConfig index of a bit rate */
static Word16 frame_size_index_of(Word32 rate)
{
    for (int n = 0; n < FRAME_SIZE_NB; n++) if (FrameSizeConfig[n].frame_bits == rate / 50) return (Word16)n;
    return 0;
}

/* Fill the LPD memories the switching code moves with random in-range data. */
static void randomise_lpd_memories(Decoder_State_fx *st)
{
    random_signal(st->old_syn_Overl, 320, random_range(100, 12000));
    random_signal(st->syn_Overl, 320, random_range(100, 12000));
    random_signal(st->syn_Overl_TDAC, 320, random_range(100, 12000));
    random_signal(st->mem_syn_clas_estim_fx, L_SYN_MEM_CLAS_ESTIM, random_range(100, 12000));
    st->classifier_Q_mem_syn = (Word16)random_range(-2, 12);
    random_lsp(st->lsp_old_fx);
    random_lsp(st->lspold_uw);
    for (int i = 0; i < M; i++) {
        st->lsf_old_fx[i] = (Word16)random_range(0, 6400);
        st->lsfold_uw[i] = (Word16)random_range(0, 6400);
        st->lsfoldbfi0_fx[i] = (Word16)random_range(0, 6400);
        st->lsfoldbfi1_fx[i] = (Word16)random_range(0, 6400);
        st->lsf_adaptive_mean_fx[i] = (Word16)random_range(0, 6400);
    }
    random_signal(st->tecDec_fx.loBuffer, 22, 6000);
}
