/* Function-level oracle for the local functions of lib_dec/hq_lr_dec_fx.c (all static, so the file is
 * included). Band layouts, qint, eref and the fine-gain parameters come from hq2_core_configure_fx as in
 * hq_lr_dec_fx; the coded bits are random, biased now and then towards zeros so the Huffman codes take
 * their short paths and the frame end is reached. */
/* the whole-state dump of init_dec.c (also brings harness.h and prot_fx.h) */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
/* The reference's hq_lr_dec_fx is renamed so the wrapper below can take its place in the decoder
 * (`stream` mode runs the whole reference decoder over a conformance bitstream and records every
 * call); every corpus case below calls the wrapper, which forwards unchanged outside stream mode. */
#define hq_lr_dec_fx hq_lr_dec_fx_reference
#include "../../c-code/lib_dec/hq_lr_dec_fx.c"
#undef hq_lr_dec_fx

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

typedef struct {
    Word16 inner_frame, num_bits, is_transient, bands, length, band_width[BANDS_MAX], band_start[BANDS_MAX];
    Word16 band_end[BANDS_MAX], eref, bit_alloc_weight, gqlevs, ngq, p2a_bands, p2a_th, pd_thresh, ld_slope, ni_coef;
    Word32 qint, bwe_br;
} Config;

static void random_config(Config *c)
{
    static const Word16 frames[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k, L_FRAME8k};
    static const Word32 brates[] = {HQ_13k20, HQ_16k40, ACELP_7k20, ACELP_8k00};
    c->inner_frame = frames[next_random() % 4];
    c->is_transient = (Word16)(next_random() % 3 == 0);
    c->bwe_br = brates[next_random() % 4];
    /* at 16/32 kHz the decoder never asks for more than 16.4 kbit/s (328 bits); above that the reference
     * keeps its default 32 kHz layout, which a transient frame expands past BANDS_MAX */
    c->num_bits = (Word16)(c->inner_frame == L_FRAME8k ? random_range(100, 330) : random_range(140, 328));
    hq2_core_configure_fx(c->inner_frame, c->num_bits, c->is_transient, &c->bands, &c->length, c->band_width,
                          c->band_start, c->band_end, &c->qint, &c->eref, &c->bit_alloc_weight, &c->gqlevs, &c->ngq,
                          &c->p2a_bands, &c->p2a_th, &c->pd_thresh, &c->ld_slope, &c->ni_coef, c->bwe_br);
}

/* Random bits, sometimes sparse (long zero runs), sometimes a frame shorter than the read. */
static Decoder_State_fx *random_stream(int *n)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int density = (int)(next_random() % 4);
    *n = next_random() % 8 ? 400 : random_range(0, 60);
    for (int i = 0; i < *n; i++)
        bit_buffer[i] = (UWord16)(density == 0 ? (next_random() % 6 == 0) : (next_random() & 1));
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)*n;
    st->next_bit_pos_fx = 0;
    st->codec_mode = MODE1;
    return st;
}

static void put_stream_after(Decoder_State_fx *st)
{
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
}

static void case_calc_inv(void)
{
    /* every caller passes a non-negative energy; a negative one would divide by a negative mantissa */
    static const Word32 edges[] = {0, 1, 0xffff, 0x10000, 0x7fffffff, 0x40000000, 0x3fffffff};
    Word32 x = (Word32)(next_random() & 0x7fffffff) >> (next_random() % 31);
    if (next_random() % 5 == 0) x = edges[next_random() % 7];
    Word16 exp = -99, r;
    put1("x", x);
    r = Calc_inv(x, &exp);
    arrow(); put1("r", r); put1("exp", exp); end_line();
}

static void case_spt_shorten_domain_set_dec(void)
{
    Config c; int n;
    random_config(&c);
    Decoder_State_fx *st = random_stream(&n);
    Word16 p2a_flags[BANDS_MAX], nbs[4], nbe[4], nbw[4], bit_budget = (Word16)random_range(-5, 300);
    for (int k = 0; k < c.bands; k++) p2a_flags[k] = (Word16)(next_random() & 1);
    for (int j = 0; j < 4; j++) { nbs[j] = (Word16)random_range(0, 600); nbe[j] = (Word16)(nbs[j] + random_range(0, 40)); nbw[j] = (Word16)random_range(1, 40); }
    put_u16("bits", bit_buffer, n); put1("bands", c.bands); put16("p2a_flags", p2a_flags, c.bands);
    put16("nbs", nbs, 4); put16("nbe", nbe, 4); put16("nbw", nbw, 4); put16("band_start", c.band_start, c.bands);
    put16("band_end", c.band_end, c.bands); put16("band_width", c.band_width, c.bands); put1("bit_budget", bit_budget);
    spt_shorten_domain_set_dec_fx(st, p2a_flags, nbs, nbe, nbw, c.bands, c.band_start, c.band_end, c.band_width, &bit_budget);
    arrow(); put16("band_start", c.band_start, c.bands); put16("band_end", c.band_end, c.bands);
    put16("band_width", c.band_width, c.bands); put1("bit_budget", bit_budget); put_stream_after(st); end_line();
    free(st);
}

/* small_symbol_dec_tran_fx / small_symbol_dec_fx / large_symbol_dec_fx: one decoder each, same shape. */
static void case_symbol(int which)
{
    Config c; int n;
    random_config(&c);
    Decoder_State_fx *st = random_stream(&n);
    Word16 qbidx[BANDS_MAX], bits;
    for (int k = 0; k < BANDS_MAX; k++) qbidx[k] = -7;
    put_u16("bits", bit_buffer, n); put1("bands", c.bands); put1("is_transient", c.is_transient);
    if (which == 0) bits = small_symbol_dec_tran_fx(st, qbidx, c.bands, c.is_transient);
    else if (which == 1) bits = small_symbol_dec_fx(st, qbidx, c.bands, c.is_transient);
    else bits = large_symbol_dec_fx(st, qbidx, c.bands);
    arrow(); put1("cnt", bits); put16("qbidx", qbidx, BANDS_MAX); put_stream_after(st); end_line();
    free(st);
}

static void case_decode_huff_8s(void)
{
    int n;
    Decoder_State_fx *st = random_stream(&n);
    Word16 rbits = (Word16)random_range(0, 20), sym;
    put_u16("bits", bit_buffer, n); put1("rbits", rbits);
    sym = decode_huff_8s_fx(st, hestable_fx, &rbits);
    arrow(); put1("sym", sym); put1("rbits", rbits); put_stream_after(st); end_line();
    free(st);
}

static void case_band_energy_dequant(void)
{
    Config c; int n;
    random_config(&c);
    Decoder_State_fx *st = random_stream(&n);
    Word32 energy[BANDS_MAX];
    Word16 bits;
    for (int k = 0; k < BANDS_MAX; k++) energy[k] = -7;
    put_u16("bits", bit_buffer, n); put1("bands", c.bands); put1("qint", c.qint); put1("eref", c.eref);
    put1("is_transient", c.is_transient);
    bits = band_energy_dequant_fx(st, energy, c.bands, c.qint, c.eref, c.is_transient);
    arrow(); put1("cnt", bits); put32("energy", energy, BANDS_MAX); put_stream_after(st); end_line();
    free(st);
}

static void case_p2a_threshold_dequant(void)
{
    Config c; int n;
    random_config(&c);
    Decoder_State_fx *st = random_stream(&n);
    Word16 flags[BANDS_MAX], bits;
    for (int k = 0; k < BANDS_MAX; k++) flags[k] = -7;
    put_u16("bits", bit_buffer, n); put1("bands", c.bands); put1("p2a_bands", c.p2a_bands);
    bits = p2a_threshold_dequant_fx(st, flags, c.bands, c.p2a_bands);
    arrow(); put1("cnt", bits); put16("flags", flags, BANDS_MAX); put_stream_after(st); end_line();
    free(st);
}

static void case_mdct_spectrum_fine_gain_dec(void)
{
    Config c; int n;
    random_config(&c);
    Decoder_State_fx *st = random_stream(&n);
    static Word32 y2[L_FRAME48k];
    Word16 k_sort[BANDS_MAX], gqbits = sub(14, norm_s(c.gqlevs));
    for (int i = 0; i < L_FRAME48k; i++)
        y2[i] = next_random() % 4 ? random_range(-(1 << 24), 1 << 24) : (next_random() % 3 ? 0 : random32());
    /* a permutation of the bands, as tcq_core_LR_dec_fx sorts them */
    for (int k = 0; k < c.bands; k++) k_sort[k] = (Word16)k;
    for (int k = c.bands - 1; k > 0; k--) { int j = random_range(0, k); Word16 t = k_sort[k]; k_sort[k] = k_sort[j]; k_sort[j] = t; }
    put_u16("bits", bit_buffer, n); put32("y2", y2, L_FRAME48k); put16("band_start", c.band_start, c.bands);
    put16("band_end", c.band_end, c.bands); put16("k_sort", k_sort, c.bands); put1("bands", c.bands);
    put1("qint", c.qint); put1("ngq", c.ngq); put1("gqlevs", c.gqlevs); put1("gqbits", gqbits);
    mdct_spectrum_fine_gain_dec_fx(st, y2, c.band_start, c.band_end, k_sort, c.bands, c.qint, c.ngq, c.gqlevs, gqbits);
    arrow(); put32("y2", y2, L_FRAME48k); put_stream_after(st); end_line();
    free(st);
}


/* -------- hq_lr_dec_fx over whole frames on one decoder -------- */

#define FRAMES 4

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


/* -------- stream mode: hq_lr_dec_fx as the reference decoder calls it on real bitstreams -------- */

static int stream_mode;
static long stream_every, stream_calls;

void hq_lr_dec_fx(Decoder_State_fx *st, Word32 L_yout[], const Word16 inner_frame, Word16 num_bits, Word16 *is_transient)
{
    if (!stream_mode) {
        hq_lr_dec_fx_reference(st, L_yout, inner_frame, num_bits, is_transient);
        return;
    }
    /* every n-th call, and every SWB harmonic frame (rare on the sequences, and the only way into
     * hq2_bit_alloc_har_fx and the harmonic BWE) */
    static UWord16 bits_in[MAX_BITS_PER_FRAME + 16];
    static Word32 yout_in[L_FRAME48k];
    int nbits = st->total_num_bits + 16;
    memcpy(bits_in, st->bit_stream_fx, nbits * sizeof(UWord16));
    memcpy(yout_in, L_yout, sizeof yout_in);
    char *before = capture_state(st);
    hq_lr_dec_fx_reference(st, L_yout, inner_frame, num_bits, is_transient);
    int sampled = stream_calls++ % stream_every == 0;
    int harmonic = st->bwidth_fx == SWB && st->prev_hqswb_clas_fx == HQ_HARMONIC;
    if (sampled || harmonic) {
        put1("output_fs", st->output_Fs_fx);
        put1("output_frame", st->output_frame_fx);
        put1("inner_frame", inner_frame);
        put1("num_bits", num_bits);
        put_u16("bits", bits_in, nbits);
        put32("yout_in", yout_in, L_FRAME48k);
        for (const char *p = before; *p;) {
            const char *e = strchr(p + 1, ' ');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            printf(" in.%.*s", (int)len - 1, p + 1);
            p += len;
        }
        arrow();
        put32("yout", L_yout, L_FRAME48k);
        put1("is_transient", *is_transient);
        char *after = capture_state(st);
        put_changed("st.", before, after);
        free(after);
        end_line();
    }
    free(before);
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
    fprintf(stderr, "hq_lr_dec_fx calls: %ld\n", stream_calls);
    fclose(f);
    destroy_decoder(st);
    free(st);
}

/* One frame's bits: random, with the band-energy code steered towards plausible envelopes now and
 * then (a frame of all-random bits mostly decodes an energy outside the reference's sanity window
 * and stops there, which is covered too). */
static void random_frame_bits(int n)
{
    int density = (int)(next_random() % 4);
    for (int i = 0; i < n; i++)
        bit_buffer[i] = (UWord16)(density == 0 ? (next_random() % 5 == 0) : density == 1 ? (next_random() % 5 != 0) : (next_random() & 1));
}

/* Bandwidth, inner frame and bit rate of an LR-HQ frame, as hq_core_dec_fx sets them. */
static void random_mode(Decoder_State_fx *st, Word16 *inner_frame)
{
    static const Word32 nbwb_rates[] = {ACELP_7k20, ACELP_8k00, ACELP_13k20, ACELP_16k40};
    int r = next_random() % 10;
    if (r < 2) { st->bwidth_fx = NB; *inner_frame = L_FRAME8k; st->core_brate_fx = nbwb_rates[next_random() % 3]; }
    else if (r < 5) { st->bwidth_fx = WB; *inner_frame = L_FRAME16k; st->core_brate_fx = nbwb_rates[next_random() % 4]; }
    else { st->bwidth_fx = SWB; *inner_frame = L_FRAME32k; st->core_brate_fx = next_random() & 1 ? ACELP_13k20 : ACELP_16k40; }
}

static void case_hq_lr_dec_frames(void)
{
    static const Word32 out_rates[] = {16000, 32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = out_rates[next_random() % 3];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);

    /* the memories the previous frames leave */
    Word16 inner_frame;
    random_mode(st, &inner_frame);
    st->prev_hqswb_clas_fx = (Word16)random_range(0, 3);
    for (int i = 0; i < SPT_SHORTEN_SBNUM; i++) st->prev_SWB_peak_pos_fx[i] = next_random() % 2 ? 0 : (Word16)random_range(200, 300);
    if (next_random() % 2) {
        for (int i = 0; i < BANDS_MAX; i++) {
            st->last_ni_gain_fx[i] = (Word32)((next_random() & 0x7fffffff) >> random_range(8, 24));
            st->last_env_fx[i] = (Word16)random_range(0, 20000);
        }
        st->last_max_pos_pulse_fx = (Word16)random_range(0, 300);
    }
    st->last_inner_frame_fx = (Word16)(next_random() % 3 == 0 ? L_FRAME8k : next_random() % 2 ? L_FRAME16k : L_FRAME32k);
    st->bws_cnt_fx = (Word16)(next_random() % 2 ? 0 : random_range(1, N_WS2N_FRAMES));
    st->prev_frm_hfe2_fx = (Word16)(next_random() % 2 ? 0 : random_range(1, 80));
    st->prev_stab_hfe2_fx = (Word16)random_range(0, 3);
    st->prev_ni_ratio_fx = (Word16)random_range(0, 32767);
    for (int i = 0; i < NB_SWB_SUBBANDS; i++) st->prev_En_sb_fx[i] = (Word16)random_range(0, 3000);
    st->prev_ener_shb_fx = (Word16)random_range(0, 3000);

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    char *before = capture_state(st);
    for (const char *p = before; *p;) {
        const char *end = strchr(p + 1, ' ');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        printf(" in.%.*s", (int)len - 1, p + 1);
        p += len;
    }

    for (int f = 0; f < FRAMES; f++) {
        char name[32];
        static Word32 yout[L_FRAME48k];
        Word16 is_transient = -7;
        if (f > 0 && next_random() % 4 == 0) random_mode(st, &inner_frame);
        int frame_bits = (int)(st->core_brate_fx / 50), lead = next_random() % 8 ? random_range(0, 12) : random_range(40, frame_bits - 40);
        Word16 num_bits = (Word16)(frame_bits - lead);
        random_frame_bits(frame_bits);
        st->bit_stream_fx = bit_buffer;
        st->total_num_bits = (Word16)frame_bits;
        st->next_bit_pos_fx = (Word16)lead;
        st->BER_detect = 0;
        for (int i = 0; i < L_FRAME48k; i++) yout[i] = -7;
        Word32 mode[] = {st->bwidth_fx, inner_frame, st->core_brate_fx, num_bits, lead};
        sprintf(name, "f%d_mode", f); put32(name, mode, 5);
        sprintf(name, "f%d_bits", f); put_u16(name, bit_buffer, frame_bits);
        /* the frame starts from the state the previous one left: print what the test cannot know */
        hq_lr_dec_fx(st, yout, inner_frame, num_bits, &is_transient);
        sprintf(name, "f%d_yout", f); put32(name, yout, L_FRAME48k);
        sprintf(name, "f%d_is_transient", f); put1(name, is_transient);
        char *after = capture_state(st);
        sprintf(name, "f%d.", f);
        put_changed(name, before, after);
        free(after);
    }
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
        if (!strcmp(argv[2], "calc_inv")) case_calc_inv();
        else if (!strcmp(argv[2], "spt_shorten_domain_set_dec")) case_spt_shorten_domain_set_dec();
        else if (!strcmp(argv[2], "small_symbol_dec_tran")) case_symbol(0);
        else if (!strcmp(argv[2], "small_symbol_dec")) case_symbol(1);
        else if (!strcmp(argv[2], "large_symbol_dec")) case_symbol(2);
        else if (!strcmp(argv[2], "decode_huff_8s")) case_decode_huff_8s();
        else if (!strcmp(argv[2], "band_energy_dequant")) case_band_energy_dequant();
        else if (!strcmp(argv[2], "p2a_threshold_dequant")) case_p2a_threshold_dequant();
        else if (!strcmp(argv[2], "mdct_spectrum_fine_gain_dec")) case_mdct_spectrum_fine_gain_dec();
        else if (!strcmp(argv[2], "hq_lr_dec_frames")) case_hq_lr_dec_frames();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
