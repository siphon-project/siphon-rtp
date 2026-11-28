/* Function-level oracle for lib_dec/inov_dec_fx.c (inov_decode_fx). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

/* An order-16 LP filter in Q12 whose coefficients decay with the order, like a real A(z). */
static void random_lpc(Word16 *a)
{
    a[0] = 4096;
    for (int i = 1; i <= M; i++) {
        int span = 6000 * (M + 1 - i) / M;
        a[i] = (next_random() % 16) ? (Word16)random_range(-span, span) : random16();
    }
}

/* inov_decode_fx over the EVS bit-allocation rows of both ACELP cores (every coder type, subframe and
 * TC position whose FCB_bits row lies inside the table) and every AMR-WB IO rate. */
static void case_inov_decode(void)
{
    static const Word32 brates_12k8[] = {7200, 8000, 9600, 11600, 13200, 16400, 24400, 32000, 64000};
    static const Word32 brates_16k[] = {9600, 13200, 16400, 24400, 32000, 48000, 64000};
    static const Word32 brates_amr[] = {6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};
    Word16 opt_amr_wb = (next_random() % 4) == 0;
    Word16 l_frame = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    Word32 core_brate;
    Word16 coder_type, tc_subfr, i_subfr;
    for (;;) {
        coder_type = (Word16)random_range(INACTIVE, AUDIO);
        i_subfr = (Word16)(L_SUBFR * random_range(0, (opt_amr_wb || l_frame == L_FRAME) ? 3 : 4));
        tc_subfr = -1;
        if (coder_type == TRANSITION) tc_subfr = (Word16)(L_SUBFR * random_range(0, l_frame == L_FRAME ? 3 : 4));
        if (opt_amr_wb) {
            l_frame = L_FRAME;
            core_brate = brates_amr[next_random() % 9];
            break;
        }
        if (l_frame == L_FRAME) {
            core_brate = brates_12k8[next_random() % 9];
            Word32 idx = BIT_ALLOC_IDX_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_fx(tc_subfr));
            if (idx >= 0 && idx < 400 /* FCB_bits_tbl */) break;
        } else {
            core_brate = brates_16k[next_random() % 7];
            Word32 idx = BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr, TC_SUBFR2IDX_16KHZ_fx(tc_subfr));
            if (idx >= 0 && idx < 385 /* FCB_bits_16kHz_tbl */) break;
        }
    }
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = 400;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 200);
    st->BER_detect = 0;
    Word16 a[M + 1], code[L_SUBFR];
    random_lpc(a);
    for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    Word16 sharp = next_random() & 1;
    Word16 tilt_code = (Word16)(next_random() % 8 ? random_range(0, 16384) : random16());
    Word16 pt_pitch = (Word16)(next_random() % 8 ? random_range(34 * 64, 231 * 64) : random_range(0, 289 * 64));
    Carry = (Flag)(next_random() & 1);
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("core_brate", core_brate); put1("opt_amr_wb", opt_amr_wb); put1("l_frame", l_frame);
    put1("coder_type", coder_type); put1("sharp", sharp); put1("i_subfr", i_subfr); put1("tc_subfr", tc_subfr);
    put16("a", a, M + 1); put1("tilt_code", tilt_code); put1("pt_pitch", pt_pitch); put16("code", code, L_SUBFR);
    put1("carry", Carry);
    inov_decode_fx(st, core_brate, opt_amr_wb, l_frame, coder_type, sharp, i_subfr, tc_subfr, a, tilt_code,
                   pt_pitch, code);
    arrow(); put16("code", code, L_SUBFR); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect); put1("carry", Carry); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "inov_decode")) case_inov_decode();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
