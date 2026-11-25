/* Function-level oracle for TNS: lib_com/tns_base.c (ApplyTnsFilter, ITF_Detect_fx, ITF_Apply_fx;
 * Index2Parcor, the lattice filters, ITF_TnsFilter_fx, ITF_GetFilterParameters_fx, ResetTnsData,
 * DecodeUsingTable and the Decode* / Set* callbacks are proven through them) and
 * lib_dec/tns_base_dec.c (ReadTnsData, DecodeTnsData over the three parameter maps). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define STREAM_LENGTH 40

static UWord16 bit_buffer[2576];

static void put_tns_data(const STnsData *d)
{
    put1("n_filters", d->nFilters);
    for (int f = 0; f < TNS_MAX_NUM_OF_FILTERS; f++) {
        char name[32];
        Word16 v[2 + TNS_MAX_FILTER_ORDER] = {d->filter[f].order, d->filter[f].predictionGain};
        for (int i = 0; i < TNS_MAX_FILTER_ORDER; i++) v[2 + i] = d->filter[f].coefIndex[i];
        sprintf(name, "filter%d", f);
        put16(name, v, 2 + TNS_MAX_FILTER_ORDER);
    }
}

/* One of the three parameter maps, as InitTnsConfiguration builds the configuration that selects it. */
static void tns_config_for_map(STnsConfig *c, int map)
{
    memset(c, 0, sizeof(*c));
    c->maxOrder = TNS_MAX_FILTER_ORDER;
    c->nMaxFilters = (Word16)(map == 2 ? 1 : 2);
    c->iFilterBorders[0] = (Word16)(map == 0 ? 640 : map == 1 ? 320 : 320);
}

static void case_read_decode(void)
{
    static Word16 stream[STREAM_LENGTH];
    STnsConfig config;
    STnsData data;
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int map = random_range(0, 2);
    int mode = next_random() % 8;
    Word16 total_bits = (Word16)random_range(4, 120);
    Word16 start = (Word16)random_range(0, 20);
    Word16 n_bits = 0x1111, n_size = 0, n_size_decode = 0;
    tns_config_for_map(&config, map);
    for (int i = 0; i < 2576; i++) bit_buffer[i] = (UWord16)(mode == 0 ? 0 : mode == 1 ? 1 : (next_random() & 1));
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = total_bits;
    st->next_bit_pos_fx = start;
    for (int i = 0; i < STREAM_LENGTH; i++) stream[i] = 0x5555;
    memset(&data, 0x55, sizeof(data));
    put1("map", map); put1("total_bits", total_bits); put1("start", start); put_u16("bits", bit_buffer, 160);
    Word16 r = ReadTnsData(&config, st, &n_bits, stream, &n_size);
    arrow();
    put1("read_result", r); put1("n_bits", n_bits); put1("n_size", n_size); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect); put16("stream", stream, STREAM_LENGTH);
    Word16 used = DecodeTnsData(&config, stream, &n_size_decode, &data);
    put1("decode_result", used); put1("n_size_decode", n_size_decode); put_tns_data(&data);
    end_line();
    free(st);
}

/* A TNS configuration as open_decoder_LPD builds it (a bandwidth, a bit rate, IGF stop frequency). */
static void random_config(Word32 *sr, Word16 *frame_length, Word16 *igf, Word32 *brate, STnsConfig *c)
{
    static const Word32 rates[] = {8000, 16000, 32000, 48000};
    static const Word16 lines[] = {160, 320, 640, 960};
    static const Word32 brates[] = {9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};
    static const Word16 igf_stop[] = {0, 0, 9600, 14400, 16000, 20000};
    int bw = next_random() % 4;
    *brate = brates[next_random() % 9];
    if (bw == 0) *brate = brates[next_random() % 5];
    *igf = igf_stop[next_random() % 6];
    *sr = rates[bw];
    if (*igf > *sr / 2) *igf = 0; /* the IGF stop frequency lies inside the band */
    int which = random_range(0, 2);
    *frame_length = which == 0 ? shr(lines[bw], 1) : which == 1 ? lines[bw] : add(lines[bw], shr(lines[bw], 2));
    if (which == 0 && *brate <= 32000) *frame_length = lines[bw];
    memset(c, 0, sizeof(*c));
    InitTnsConfiguration(*sr, *frame_length, c, *igf, *brate);
}

static void case_apply(void)
{
    static Word32 spectrum[1400];
    STnsConfig config;
    STnsData data;
    Word32 sr, brate;
    Word16 frame_length, igf;
    for (;;) {
        /* the reference asserts every filter's line count is non-negative, and zero only for order 0 */
        random_config(&sr, &frame_length, &igf, &brate, &config);
        int ok = 1;
        for (int f = 0; f < config.nMaxFilters; f++) if (config.iFilterBorders[f] - config.iFilterBorders[f + 1] < 0) ok = 0;
        if (ok) break;
    }
    Word8 analysis = (Word8)(next_random() & 1);
    int style = random_range(0, 3);
    memset(&data, 0, sizeof(data));
    ResetTnsData(&data);
    data.nFilters = (Word16)random_range(0, config.nMaxFilters);
    for (int f = 0; f < TNS_MAX_NUM_OF_FILTERS; f++) {
        data.filter[f].order = (Word16)(style == 0 ? 0 : random_range(0, TNS_MAX_FILTER_ORDER));
        for (int i = 0; i < data.filter[f].order; i++) data.filter[f].coefIndex[i] = (Word16)random_range(-INDEX_SHIFT, INDEX_SHIFT - 1);
    }
    for (int f = 0; f < config.nMaxFilters; f++) {
        if (config.iFilterBorders[f] - config.iFilterBorders[f + 1] == 0) {
            data.filter[f].order = 0;
            for (int i = 0; i < TNS_MAX_FILTER_ORDER; i++) data.filter[f].coefIndex[i] = 0;
        }
    }
    if (next_random() % 16 == 0) data.nFilters = -1;
    for (int i = 0; i < frame_length; i++) spectrum[i] = random32() >> random_range(0, 20);
    put1("sr", sr); put1("frame_length", frame_length); put1("igf", igf); put1("brate", brate); put1("analysis", analysis);
    put1("n_max_filters", config.nMaxFilters); put16("borders", config.iFilterBorders, 3);
    put_tns_data(&data); put32("spectrum", spectrum, frame_length);
    Word16 r = ApplyTnsFilter(&config, &data, spectrum, analysis);
    arrow(); put1("result", r); put32("spectrum", spectrum, frame_length); end_line();
}

static void case_itf(void)
{
    static Word32 x[1400], x_apply[1400];
    Word16 a[ITF_MAX_FILTER_ORDER + 1], q_a = 0x5555, prediction_gain = 0, curr_order = 0;
    Word16 start_line = (Word16)random_range(IGF_START_MN, 400);
    Word16 stop_line = (Word16)(start_line + random_range(12, 600));
    Word16 max_order = (Word16)random_range(1, 8);
    Word16 q = (Word16)(2 * random_range(0, 12));
    int style = random_range(0, 3);
    int base_shift = random_range(0, 22);
    for (int i = 0; i < ITF_MAX_FILTER_ORDER + 1; i++) a[i] = 0x5555;
    for (int i = 0; i < 1400; i++) {
        int shift = base_shift;
        if (style == 1 && i > start_line + (stop_line - start_line) / 2) shift += 14; /* a quiet upper part: a low-energy subdivision */
        if (style == 2 && i < start_line + (stop_line - start_line) / 3) shift += 16;
        x[i] = random32() >> shift;
        /* correlated lines, so the filter has something to predict */
        if (style == 3 && i > 0) x[i] = (x[i] / 2) + (x[i - 1] / 2);
    }
    memcpy(x_apply, x, sizeof(x));
    put1("start_line", start_line); put1("stop_line", stop_line); put1("max_order", max_order); put1("q", q);
    put32("x", x, 1400);
    Word16 r = ITF_Detect_fx(x + IGF_START_MN, start_line, stop_line, max_order, a, &q_a, &prediction_gain, &curr_order, q);
    ITF_Apply_fx(x_apply, start_line, stop_line, a, q_a, curr_order);
    arrow(); put1("result", r); put16("a", a, ITF_MAX_FILTER_ORDER + 1); put1("q_a", q_a); put1("prediction_gain", prediction_gain);
    put1("curr_order", curr_order); put32("x_apply", x_apply, 1400); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "read_decode")) case_read_decode();
        else if (!strcmp(argv[2], "ApplyTnsFilter")) case_apply();
        else if (!strcmp(argv[2], "ITF")) case_itf();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
