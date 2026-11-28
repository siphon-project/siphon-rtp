/* Function-level oracle for lib_dec/tcq_core_dec_fx.c. Band layouts come from hq2_core_configure_fx
 * and most allocations from hq2_bit_alloc_fx, as in hq_lr_dec_fx; the coded bits are random, which
 * the arithmetic decoder turns into an arbitrary but valid pulse sequence. */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void case_tcq_core_lr_dec(void)
{
    static const Word16 frames[] = {L_FRAME8k, L_FRAME8k, L_FRAME16k, L_FRAME32k};
    static const Word32 brates[] = {HQ_13k20, HQ_16k40};
    Word16 frame_length = frames[next_random() % 4], is_transient = (Word16)(next_random() % 3 == 0);
    Word32 bwe_br = brates[next_random() % 2], qint;
    Word16 num_bits, bands, length, band_width[BANDS_MAX], band_start[BANDS_MAX], band_end[BANDS_MAX];
    Word16 eref, bit_alloc_weight, gqlevs, ngq, p2a_bands, p2a_th, pd_thresh, ld_slope, ni_coef;
    if (frame_length == L_FRAME8k) num_bits = (Word16)random_range(100, 330);
    else num_bits = (Word16)random_range(200, 328);
    hq2_core_configure_fx(frame_length, num_bits, is_transient, &bands, &length, band_width, band_start, band_end,
                          &qint, &eref, &bit_alloc_weight, &gqlevs, &ngq, &p2a_bands, &p2a_th, &pd_thresh, &ld_slope,
                          &ni_coef, bwe_br);

    Word32 rk[BANDS_MAX], energy[BANDS_MAX];
    Word16 p2a_flags[BANDS_MAX], last_bitalloc[2], bit_budget = (Word16)random_range(num_bits / 2, num_bits);
    for (int k = 0; k < bands; k++) p2a_flags[k] = (Word16)(next_random() % 3 == 0);
    int kind = next_random() % 8;
    if (kind == 7) {
        /* a starved allocation: a few bands of a fraction of a bit up to 1.5 bits, so the TCQ surplus goes
         * negative and the shortfall is spread over the remaining bands */
        int nonzero = random_range(2, 6);
        for (int k = 0; k < bands; k++) rk[k] = 0;
        for (int j = 0; j < nonzero; j++) rk[random_range(0, bands - 1)] = random_range(1 << 12, 3 << 15);
    } else if (kind < 5) {
        for (int k = 0; k < bands; k++) energy[k] = random_range(0, 20 << 14);
        hq2_bit_alloc_fx(energy, bands, rk, &bit_budget, p2a_flags, bit_alloc_weight, band_width, num_bits,
                         (Word16)(next_random() & 1 ? HQ_NORMAL : HQ_HARMONIC), (Word16)random_range(NB, SWB),
                         is_transient);
        if (bit_budget < 0) bit_budget = 0;
    } else {
        for (int k = 0; k < bands; k++)
            rk[k] = (next_random() % 5) ? random_range(0, band_width[k] * 6) << 16 | random_range(0, 65535) : 0;
    }
    last_bitalloc[0] = (Word16)random_range(0, 1);
    last_bitalloc[1] = (Word16)random_range(0, 1);
    Word16 adjust_flag = (Word16)(next_random() % 4 == 0);
    Word16 input_frame = frame_length;

    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int nbits = bit_budget + 8;
    for (int i = 0; i < nbits; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)nbits;
    st->codec_mode = MODE1;

    Word16 inp[L_FRAME48k], npulses[BANDS_MAX], k_sort[BANDS_MAX];
    for (int i = 0; i < L_FRAME48k; i++) inp[i] = -7;
    for (int k = 0; k < BANDS_MAX; k++) npulses[k] = -7;

    put_u16("bits", bit_buffer, nbits); put1("bit_budget", bit_budget); put1("bands", bands);
    put16("band_start", band_start, bands); put16("band_width", band_width, bands); put32("rk", rk, bands);
    put16("p2a_flags", p2a_flags, bands); put1("p2a_bands", p2a_bands); put16("last_bitalloc", last_bitalloc, 2);
    put1("input_frame", input_frame); put1("adjust_flag", adjust_flag); put1("is_transient", is_transient);
    tcq_core_LR_dec_fx(st, inp, bit_budget, bands, band_start, band_width, rk, npulses, k_sort, p2a_flags, p2a_bands,
                       last_bitalloc, input_frame, adjust_flag, &is_transient);
    arrow(); put16("inp", inp, band_end[bands - 1] + 1); put16("npulses", npulses, bands); put16("k_sort", k_sort, bands);
    put32("rk", rk, bands); put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "tcq_core_lr_dec")) case_tcq_core_lr_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
