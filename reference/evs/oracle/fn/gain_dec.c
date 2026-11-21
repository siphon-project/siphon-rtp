/* Function-level oracle for lib_dec/gain_dec_fx.c (the MODE1 gain decoders). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static const Word32 rates_12k8[] = {7200, 8000, 9600, 13200};
static const Word32 rates_16k[] = {16400, 24400, 32000, 64000};

static Decoder_State_fx *new_state(int n)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(next_random() % 10 ? random_range(0, n - 40) : random_range(n - 8, n));
    st->codec_mode = MODE1;
    return st;
}

static void put_state(Decoder_State_fx *st, int n)
{
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
}

/* An algebraic code vector in Q9: a few ±1 pulses (stacked now and then), or a low-level noise
 * vector like the Gaussian codebook's. */
static void algebraic_code(Word16 *code)
{
    set16_fx(code, 0, L_SUBFR);
    if (next_random() % 6 == 0) { random_signal(code, L_SUBFR, 3000); return; }
    for (int p = random_range(1, 24); p > 0; p--) code[random_range(0, L_SUBFR - 1)] += (Word16)(next_random() & 1 ? 512 : -512);
}

static int fits(Word32 core_brate, Word16 l_frame, Word16 coder_type, Word16 i_subfr, Word16 tc_subfr)
{
    if (l_frame == L_FRAME) return BIT_ALLOC_IDX_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_fx(tc_subfr)) < 400;
    return BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_16KHZ_fx(tc_subfr)) < 385;
}

static void case_es_pred_dec(void)
{
    int n = 200;
    Decoder_State_fx *st = new_state(n);
    Word32 core_brate = next_random() & 1 ? rates_12k8[next_random() % 4] : rates_16k[next_random() % 4];
    Word16 coder_type = (Word16)random_range(0, 5), es_pred = -1;
    while (BIT_ALLOC_IDX_fx(core_brate, coder_type, -1, -1) >= 68) coder_type = (Word16)random_range(0, 3);
    put_state(st, n); put1("coder_type", coder_type); put1("core_brate", core_brate);
    Es_pred_dec_fx(st, &es_pred, coder_type, core_brate);
    arrow(); put1("es_pred", es_pred); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

static void put_gains(Word16 gain_pit, Word32 gain_code, Word16 gain_inov, Word32 norm_gain_code)
{
    put1("gain_pit", gain_pit); put1("gain_code", gain_code); put1("gain_inov", gain_inov); put1("norm_gain_code", norm_gain_code);
}

static void case_gain_dec_tc(void)
{
    int n = 300;
    Decoder_State_fx *st = new_state(n);
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k), code[L_SUBFR];
    Word32 core_brate = l_frame == L_FRAME ? rates_12k8[next_random() % 4] : rates_16k[next_random() % 4];
    /* transition_dec_fx leaves Jopt_flag 0 (and dec_tran_fx so decodes the gain here) in the
     * subframes before the glottal-impulse subframe, and in two TC_0_x cases of the 12.8 kHz core. */
    Word16 last = (Word16)(l_frame == L_FRAME ? 3 : 4);
    Word16 tc_subfr = (Word16)(L_SUBFR * random_range(1, last));
    Word16 i_subfr = (Word16)(L_SUBFR * random_range(0, tc_subfr / L_SUBFR - 1));
    Word16 es_pred = Es_pred_qua_5b_fx[next_random() % 32];
    Word16 gain_pit = -1, gain_inov = -1;
    Word32 gain_code = -1, norm_gain_code = -1;
    if (l_frame == L_FRAME && next_random() % 6 == 0) {
        if (next_random() & 1) { i_subfr = L_SUBFR; tc_subfr = (Word16)(next_random() & 1 ? TC_0_128 : TC_0_192); }
        else { i_subfr = 2 * L_SUBFR; tc_subfr = TC_0_192; }
    }
    algebraic_code(code);
    put_state(st, n); put1("core_brate", core_brate); put16("code", code, L_SUBFR); put1("l_frame", l_frame);
    put1("i_subfr", i_subfr); put1("tc_subfr", tc_subfr); put1("es_pred", es_pred);
    gain_dec_tc_fx(st, core_brate, code, l_frame, i_subfr, tc_subfr, es_pred, &gain_pit, &gain_code, &gain_inov, &norm_gain_code);
    arrow(); put_gains(gain_pit, gain_code, gain_inov, norm_gain_code); put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

static void case_gain_dec_mless(void)
{
    int n = 300;
    Decoder_State_fx *st = new_state(n);
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k), code[L_SUBFR];
    Word32 core_brate = l_frame == L_FRAME ? rates_12k8[next_random() % 4] : rates_16k[next_random() % 3]; /* above 32 kbit/s the decoder uses gain_dec_SQ */
    Word16 coder_type = (Word16)random_range(0, 4);
    Word16 i_subfr = (Word16)(L_SUBFR * random_range(0, l_frame == L_FRAME ? 3 : 4)), tc_subfr = -1;
    Word16 es_pred = Es_pred_qua_5b_fx[next_random() % 32];
    Word16 gain_pit = -1, gain_inov = -1;
    Word32 gain_code = -1, norm_gain_code = -1;
    if (coder_type == TRANSITION) {
        /* The TC subframe the decoder signals; the last subframe of a TC192 / TC256 frame takes the
         * scalar-quantiser branch. */
        Word16 last = (Word16)(l_frame == L_FRAME ? 3 : 4);
        if (next_random() % 4 == 0) {
            /* first glottal impulse in the first subframe: TC_0_0 .. TC_0_192 */
            tc_subfr = (Word16)random_range(TC_0_0, TC_0_192);
            i_subfr = (Word16)(L_SUBFR * random_range(0, last));
        } else {
            tc_subfr = (Word16)(next_random() % 3 ? last * L_SUBFR : L_SUBFR * random_range(0, last));
            i_subfr = (Word16)(L_SUBFR * random_range(tc_subfr / L_SUBFR, last));
        }
    }
    /* A combination whose table entry is 0 or 1 bits is one the bitstream never signals (the
     * reference divides by zero on it); so is one of more than 7 bits outside the TC192 branch (the
     * reference reads past its largest codebook, as at 7.2 / 8 kbit/s GENERIC, which takes
     * gain_dec_lbr instead). */
    while (!fits(core_brate, l_frame, coder_type, i_subfr, tc_subfr) ||
           (tc_subfr == -1 || coder_type != TRANSITION) &&
           (l_frame == L_FRAME ? gain_bits_tbl[BIT_ALLOC_IDX_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_fx(tc_subfr))]
                               : gain_bits_16kHz_tbl[BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_16KHZ_fx(tc_subfr))]) > 7 ||
           (l_frame == L_FRAME ? gain_bits_tbl[BIT_ALLOC_IDX_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_fx(tc_subfr))]
                               : gain_bits_16kHz_tbl[BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_16KHZ_fx(tc_subfr))]) < 2)
    { coder_type = GENERIC; tc_subfr = -1; core_brate = l_frame == L_FRAME ? 13200 : 24400; }
    algebraic_code(code);
    put_state(st, n); put1("core_brate", core_brate); put1("l_frame", l_frame); put1("coder_type", coder_type);
    put1("i_subfr", i_subfr); put1("tc_subfr", tc_subfr); put16("code", code, L_SUBFR); put1("es_pred", es_pred);
    gain_dec_mless_fx(st, core_brate, l_frame, coder_type, i_subfr, tc_subfr, code, es_pred, &gain_pit, &gain_code, &gain_inov, &norm_gain_code);
    arrow(); put_gains(gain_pit, gain_code, gain_inov, norm_gain_code); put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

/* One frame of the low-rate decoder: four subframes in order, carrying gc_mem / gp_mem. */
static void case_gain_dec_lbr(void)
{
    static const Word32 rates[] = {7200, 8000}; /* dec_gen_voic uses it at <= ACELP_8k00 */
    int n = 300;
    Decoder_State_fx *st = new_state(n);
    Word32 core_brate = rates[next_random() % 2];
    /* VOICED or GENERIC: unvoiced frames at these rates take the Gaussian codebook (gaus_dec). */
    Word16 coder_type = (Word16)random_range(VOICED, GENERIC), code[4 * L_SUBFR];
    Word16 gp_mem[4], gain_pit[4], gain_inov[4];
    Word32 gc_mem[4], gain_code[4], norm_gain_code[4];
    for (int s = 0; s < 4; s++) { gp_mem[s] = random16(); gc_mem[s] = random32(); algebraic_code(code + s * L_SUBFR); }
    st->next_bit_pos_fx = (Word16)random_range(0, n - 40);
    put_state(st, n); put1("core_brate", core_brate); put1("coder_type", coder_type); put16("code", code, 4 * L_SUBFR);
    put16("gp_mem", gp_mem, 4); put32("gc_mem", gc_mem, 4);
    for (int s = 0; s < 4; s++) {
        gain_pit[s] = -1; gain_inov[s] = -1; gain_code[s] = -1; norm_gain_code[s] = -1;
        gain_dec_lbr_fx(st, core_brate, coder_type, (Word16)(s * L_SUBFR), code + s * L_SUBFR, &gain_pit[s], &gain_code[s],
                        &gain_inov[s], &norm_gain_code[s], gc_mem, gp_mem);
    }
    arrow(); put16("gain_pit", gain_pit, 4); put32("gain_code", gain_code, 4); put16("gain_inov", gain_inov, 4);
    put32("norm_gain_code", norm_gain_code, 4); put16("gp_mem", gp_mem, 4); put32("gc_mem", gc_mem, 4);
    put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

/* A frame's worth of updates, in subframe order. */
static void case_lp_gain_updt(void)
{
    Word16 l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k), nsub = (Word16)(l_frame == L_FRAME ? 4 : 5);
    Word16 gain_pit[5], lp_gainp = random16(), lp_gainc = random16(), out_p[5], out_c[5];
    Word32 norm_gain_code[5];
    for (int s = 0; s < nsub; s++) {
        gain_pit[s] = (Word16)(next_random() % 4 ? random_range(0, 19661) : random16());
        norm_gain_code[s] = next_random() % 4 ? random_range(0, 1 << 26) : random32();
    }
    put1("l_frame", l_frame); put16("gain_pit", gain_pit, nsub); put32("norm_gain_code", norm_gain_code, nsub);
    put1("lp_gainp", lp_gainp); put1("lp_gainc", lp_gainc);
    for (int s = 0; s < nsub; s++) {
        lp_gain_updt_fx((Word16)(s * L_SUBFR), gain_pit[s], norm_gain_code[s], &lp_gainp, &lp_gainc, l_frame);
        out_p[s] = lp_gainp; out_c[s] = lp_gainc;
    }
    arrow(); put16("lp_gainp", out_p, nsub); put16("lp_gainc", out_c, nsub); end_line();
}

static void case_gain_dec_gaus(void)
{
    Word16 bits = (Word16)random_range(4, 8), index = (Word16)random_range(0, (1 << bits) - 1);
    Word16 inv_gain_inov = (Word16)(next_random() % 5 ? random_range(256, 32767) : random_range(1, 255));
    Word16 low = -30, top = 190;
    Word32 norm = -1, gain;
    if (next_random() % 6 == 0) { low = (Word16)random_range(-40, 0); top = (Word16)random_range(100, 200); }
    put1("index", index); put1("bits", bits); put1("low_bound", low); put1("top_bound", top); put1("inv_gain_inov", inv_gain_inov);
    gain = gain_dec_gaus_fx(index, bits, low, top, inv_gain_inov, &norm);
    arrow(); put1("gain", gain); put1("norm_gain_code", norm); end_line();
}

/* gain_dec_SQ_fx: the 16 kHz core above 32 kbit/s (decod_gen_voic_fx's branch), every coder type
 * and subframe whose bit-allocation row exists and carries at least 2 gain bits. */
static void case_gain_dec_sq(void)
{
    int n = 300;
    Decoder_State_fx *st = new_state(n);
    static const Word32 rates[] = {48000, 64000, 32000, 24400};
    Word32 core_brate;
    Word16 coder_type, i_subfr, code[L_SUBFR];
    for (;;) {
        core_brate = rates[next_random() % 4];
        coder_type = (Word16)random_range(0, 4);
        i_subfr = (Word16)(L_SUBFR * random_range(0, 4));
        if (fits(core_brate, L_FRAME16k, coder_type, i_subfr, -1) &&
            gain_bits_16kHz_tbl[BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_16KHZ_fx(-1))] >= 2)
            break;
    }
    Word16 es_pred = Es_pred_qua_5b_fx[next_random() % 32];
    Word16 gain_pit = -1, gain_inov = -1;
    Word32 gain_code = -1, norm_gain_code = -1;
    algebraic_code(code);
    put_state(st, n); put1("core_brate", core_brate); put1("coder_type", coder_type);
    put1("i_subfr", i_subfr); put16("code", code, L_SUBFR); put1("es_pred", es_pred);
    gain_dec_SQ_fx(st, core_brate, coder_type, i_subfr, -1, code, es_pred, &gain_pit, &gain_code, &gain_inov, &norm_gain_code);
    arrow(); put_gains(gain_pit, gain_code, gain_inov, norm_gain_code); put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "es_pred_dec")) case_es_pred_dec();
        else if (!strcmp(argv[2], "gain_dec_tc")) case_gain_dec_tc();
        else if (!strcmp(argv[2], "gain_dec_mless")) case_gain_dec_mless();
        else if (!strcmp(argv[2], "gain_dec_lbr")) case_gain_dec_lbr();
        else if (!strcmp(argv[2], "lp_gain_updt")) case_lp_gain_updt();
        else if (!strcmp(argv[2], "gain_dec_gaus")) case_gain_dec_gaus();
        else if (!strcmp(argv[2], "gain_dec_sq")) case_gain_dec_sq();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
