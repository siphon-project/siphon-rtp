/* Function-level oracle for lib_dec/dec_higher_acelp_fx.c (gain_dequant_fx, transf_cdbk_dec_fx). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void case_gain_dequant(void)
{
    /* The (min Q15, max Q0) pairs the decoder passes, and arbitrary positive ones. */
    static const Word16 limits[][2] = {{655, 5}, {19661, 41}, {2621, 96}, {26214, 96}};
    int kind = next_random() % 5;
    Word16 min, max;
    if (kind < 4) { min = limits[kind][0]; max = limits[kind][1]; }
    else { min = (Word16)random_range(1, 32767); max = (Word16)random_range(1, 32767); }
    Word16 bits = (Word16)(kind == 2 || kind == 3 ? 6 : random_range(1, 7));
    Word16 index = (Word16)random_range(0, (1 << bits) - 1);
    Word16 expg = -99;
    put1("index", index); put1("min", min); put1("max", max); put1("bits", bits);
    Word16 gain = gain_dequant_fx(index, min, max, bits, &expg);
    arrow(); put1("gain", gain); put1("expg", expg); end_line();
}

/* transf_cdbk_dec_fx at the rates above 24.4 kbit/s, the coder types and TC positions whose AVQ
 * row exists, over bitstreams biased towards long unary codes (so the larger codebooks, Voronoi
 * extensions and the sparse-frame preemphasis reset are reached), every harmonic flag. */
static void case_transf_cdbk_dec(void)
{
    static const Word32 rates[] = {32000, 48000, 64000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = MAX_BITS_PER_FRAME;
    int ones = random_range(1, 12);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)((next_random() % (unsigned)(ones + 1)) != 0);
    if (next_random() % 3 == 0) for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 600);
    st->codec_mode = MODE1;
    Word32 core_brate;
    Word16 coder_type, i_subfr, tc_subfr;
    for (;;) {
        core_brate = rates[next_random() % 3];
        coder_type = (Word16)random_range(0, 4);
        i_subfr = (Word16)(L_SUBFR * random_range(0, 4));
        tc_subfr = -1;
        if (coder_type == TRANSITION) tc_subfr = (Word16)(L_SUBFR * random_range(0, 4));
        if (BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_16KHZ_fx(tc_subfr)) < 385) break;
    }
    Word16 harm_flag = (Word16)(next_random() & 1);
    Word16 es_pred = (Word16)random_range(-2048, 14000);
    Word32 gain_code = (Word32)random_range(0, 1 << 24) >> random_range(0, 8);
    Word16 mem_preemp = (Word16)random_range(-20000, 20000);
    Word16 unbits = (Word16)random_range(0, 24);
    st->last_nq_preQ_fx = (Word16)random_range(0, 33);
    st->use_acelp_preq = 0;
    if (next_random() % 8 == 0) {
        /* every codebook empty and no preemphasis memory: the zero-energy branch */
        for (int i = 0; i < n; i++) bit_buffer[i] = 0;
        mem_preemp = 0;
    }
    Word16 gain_preQ = -1, code_preQ[L_SUBFR];
    Word32 norm_gain_preQ = -1;
    for (int i = 0; i < L_SUBFR; i++) code_preQ[i] = random16();
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("core_brate", core_brate); put1("coder_type", coder_type); put1("harm_flag", harm_flag);
    put1("i_subfr", i_subfr); put1("tc_subfr", tc_subfr); put1("es_pred", es_pred); put1("gain_code", gain_code);
    put1("mem_preemp", mem_preemp); put1("unbits", unbits); put1("last_nq_preq", st->last_nq_preQ_fx);
    put16("code_preq", code_preQ, L_SUBFR);
    transf_cdbk_dec_fx(st, core_brate, coder_type, harm_flag, i_subfr, tc_subfr, es_pred, gain_code, &mem_preemp,
                       &gain_preQ, &norm_gain_preQ, code_preQ, &unbits);
    arrow(); put1("gain_preq", gain_preQ); put1("norm_gain_preq", norm_gain_preQ); put16("code_preq", code_preQ, L_SUBFR);
    put1("mem_preemp", mem_preemp); put1("unbits", unbits); put1("last_nq_preq", st->last_nq_preQ_fx);
    put1("use_acelp_preq", st->use_acelp_preq); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "gain_dequant")) case_gain_dequant();
        else if (!strcmp(argv[2], "transf_cdbk_dec")) case_transf_cdbk_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
