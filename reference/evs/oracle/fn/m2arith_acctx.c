/* Function-level oracle for lib_com/ari_hm.c, lib_com/ACcontextMapping.c, lib_dec/ACcontextMapping_dec.c,
 * lib_dec/ari_hm_dec.c (DecodeIndex, tcx_hm_dequantize_gain) and lib_com/arith_coder.c (expfp). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "../../c-code/lib_dec/ari_hm_dec.c"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

/* a periodicity index the encoder can produce for `bandwidth`, with its LTP lag when it is an LTP index */
static void random_periodicity(int bandwidth, Word16 *index, Word16 *lag)
{
    *lag = 0;
    if (next_random() % 3 == 0) {
        int ltp = random_range(0, 16);
        int multiplier = random_range(1, 1 << NumRatioBits[bandwidth][ltp]);
        *index = (Word16)(kLtpHmFlag | multiplier | (ltp << 9));
        *lag = (Word16)((ltp + 2) * 128 + random_range(-63, 63));
    } else {
        *index = (Word16)random_range(0, 255);
        if (next_random() & 1) *lag = (Word16)random_range(1, 2400);
    }
}

static void case_acctx(void)
{
    static const int sizes[] = {64, 80, 128, 160, 256, 320, 512, 640, 960};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 x[1300], buffer_index[4000], nt = (Word16)sizes[random_range(0, 8)];
    CONTEXT_HM_CONFIG cfg, *hm_cfg = NULL;
    Word16 resq = (Word16)random_range(0, 40), periodicity = 0, ltp_lag = 0;
    int mapped = (int)(next_random() & 1);
    Word16 start = (Word16)random_range(0, 60);
    Word16 nbbits = (Word16)random_range(20, nt * ((next_random() & 1) ? 3 : 7));
    if (nbbits > 2300) nbbits = 2300;
    Word16 target_bits = nbbits;
    memset(bit_buffer, 0, sizeof(bit_buffer));
    int zeros = random_range(1, 8);
    for (int i = 0; i < start + nbbits + 24; i++) bit_buffer[i] = (UWord16)((next_random() % (unsigned)(zeros + 1)) != 0);
    int bits = start + nbbits + 24;
    for (int i = 0; i < 1300; i++) x[i] = random16();
    memset(buffer_index, 0, sizeof(buffer_index));
    if (mapped) {
        random_periodicity(nt >= 256, &periodicity, &ltp_lag);
        cfg.indexBuffer = buffer_index;
        ConfigureContextHm(nt, target_bits, periodicity, ltp_lag, &cfg);
        if (cfg.numPeakIndices + cfg.numHoleIndices + 1 > N_MAX + 1) { free(st); case_acctx(); return; }
        hm_cfg = &cfg;
    }
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)(start + nbbits + random_range(0, 30));
    st->next_bit_pos_fx = start;
    st->codec_mode = MODE2;
    st->BER_detect = 0;
    put_u16("bits", bit_buffer, bits); put1("total_num_bits", st->total_num_bits); put1("start", start);
    put1("nt", nt); put1("nbbits", nbbits); put1("resq", resq); put1("mapped", mapped);
    put1("periodicity", periodicity); put1("ltp_lag", ltp_lag); put1("target_bits", target_bits);
    put16("x_in", x, nt + resq);
    Word16 result = ACcontextMapping_decode2_no_mem_s17_LC(st, x, nt, nbbits, resq, hm_cfg);
    arrow(); put16("x", x, nt + resq); put1("result", result); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect);
    if (hm_cfg) {
        put1("num_peak", cfg.numPeakIndices); put1("num_hole", cfg.numHoleIndices);
        put16("index_buffer", buffer_index, cfg.numPeakIndices + cfg.numHoleIndices + 1);
        put1("hole_at", (long long)(cfg.holeIndices - cfg.indexBuffer));
    }
    end_line();
    free(st);
}

/* UnmapIndex, ConfigureContextHm, CountIndexBits and tcx_hm_render for one periodicity index */
static void case_hm(void)
{
    Word16 buffer_index[4000], periodicity, ltp_lag, num_coeffs;
    static const int sizes[] = {64, 80, 128, 160, 256, 320, 512, 640, 960};
    num_coeffs = (Word16)sizes[random_range(0, 8)];
    int bandwidth = num_coeffs >= 256;
    random_periodicity(bandwidth, &periodicity, &ltp_lag);
    Word16 target_bits = (Word16)random_range(20, 400);
    memset(buffer_index, 0, sizeof(buffer_index));
    CONTEXT_HM_CONFIG cfg;
    cfg.indexBuffer = buffer_index;
    Word16 fract_res = 0; Word32 lag = 0;
    UnmapIndex(periodicity, (Word8)bandwidth, ltp_lag, (Word8)(next_random() & 1), &fract_res, &lag);
    ConfigureContextHm(num_coeffs, target_bits, periodicity, ltp_lag, &cfg);
    Word16 p[9];
    for (int i = 0; i < 9; i++) p[i] = 12345;
    int render = tcx_hm_render(lag, fract_res, p);
    put1("periodicity", periodicity); put1("ltp_lag", ltp_lag); put1("num_coeffs", num_coeffs); put1("target_bits", target_bits);
    put1("bandwidth", bandwidth);
    arrow(); put1("fract_res", fract_res); put1("lag", lag);
    put1("bits", CountIndexBits(bandwidth, periodicity));
    put1("num_peak", cfg.numPeakIndices); put1("num_hole", cfg.numHoleIndices);
    put16("index_buffer", buffer_index, cfg.numPeakIndices + cfg.numHoleIndices + 1);
    put1("render", render); put16("p", p, 9); end_line();
}

static void case_render(void)
{
    Word32 lag = (next_random() & 1) ? random_range(40, 400) << 3 : random_range(1, 60000);
    Word16 fract_res = (Word16)random_range(0, 7), p[9];
    if (next_random() % 4 == 0) lag = random_range(1, 40);
    for (int i = 0; i < 9; i++) p[i] = 12345;
    put1("lag", lag); put1("fract_res", fract_res);
    int render = tcx_hm_render(lag, fract_res, p);
    arrow(); put1("render", render); put16("p", p, 9); end_line();
}

static void case_decode_index(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    memset(bit_buffer, 0, sizeof(bit_buffer));
    for (int i = 0; i < 64; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer; st->total_num_bits = 64; st->codec_mode = MODE2;
    st->next_bit_pos_fx = (Word16)random_range(0, 8);
    st->tcx_hm_LtpPitchLag = (next_random() & 1) ? (Word16)random_range(256, 2300) : (Word16)random_range(-1, 0);
    st->tcxltp_gain = (Word16)(next_random() & 1 ? random_range(0, 32767) : random_range(14000, 16500));
    if (next_random() % 8 == 0) st->tcxltp_gain = (Word16)random_range(kLtpHmGainThr - 1, kLtpHmGainThr + 1);
    Word16 bandwidth = (Word16)(next_random() & 1), index = 5;
    put_u16("bits", bit_buffer, 64); put1("lag", st->tcx_hm_LtpPitchLag); put1("gain", st->tcxltp_gain);
    put1("bandwidth", bandwidth); put1("next_bit_pos", st->next_bit_pos_fx);
    Word16 bits = DecodeIndex(st, bandwidth, &index);
    arrow(); put1("bits", bits); put1("index", index); put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

static void case_gain(void)
{
    Word16 coder = (Word16)(next_random() & 1), idx = (Word16)random_range(-2, 6), gain = 77;
    put1("coder", coder); put1("idx", idx);
    Word16 err = tcx_hm_dequantize_gain(coder, idx, &gain);
    arrow(); put1("err", err); put1("gain", gain); end_line();
}

static void case_mixed(void)
{
    Word16 ctx = (Word16)random_range(0, 1023), a = (Word16)random_range(0, 4000);
    if (next_random() & 1) a = (Word16)random_range(0, 20);
    put1("ctx", ctx); put1("a", a);
    arrow(); put1("out", update_mixed_context(ctx, a)); end_line();
}

static void case_expfp(void)
{
    /* x = envelope[k] > 0, e = envelope_e - 16 as tcx_arith_decode passes it */
    Word16 x = (Word16)random_range(1, 32767), e = (Word16)random_range(-20, 4);
    if (next_random() & 1) x = (Word16)(x >> random_range(0, 12)) + 1;
    put1("x", x); put1("e", e);
    arrow(); put1("y", expfp(x, e)); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "acctx")) case_acctx();
        else if (!strcmp(argv[2], "hm")) case_hm();
        else if (!strcmp(argv[2], "render")) case_render();
        else if (!strcmp(argv[2], "decode_index")) case_decode_index();
        else if (!strcmp(argv[2], "gain")) case_gain();
        else if (!strcmp(argv[2], "mixed")) case_mixed();
        else if (!strcmp(argv[2], "expfp")) case_expfp();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
