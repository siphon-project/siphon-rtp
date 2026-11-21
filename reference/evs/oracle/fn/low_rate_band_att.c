/* Function-level oracle for lib_com/low_rate_band_att_fx.c (PVQ fine gains). */
#include "harness.h"
#include "prot_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

#define BANDS 20

/* A PVQ band layout: widths the PVQ coder uses (band_len_idx has a row for each). */
static int layout(Word16 *start, Word16 *end, Word16 *size, Word16 n)
{
    static const Word16 widths[] = {8, 16, 24, 32, 48, 64, 80, 96};
    int pos = 0;
    for (int b = 0; b < n; b++) {
        start[b] = (Word16)pos;
        size[b] = widths[next_random() % 8];
        pos += size[b];
        end[b] = (Word16)pos;
    }
    return pos;
}

static void permutation(Word16 *p, Word16 n)
{
    for (int b = 0; b < n; b++) p[b] = (Word16)b;
    for (int b = n - 1; b > 0; b--) { int j = random_range(0, b); Word16 t = p[b]; p[b] = p[j]; p[j] = t; }
}

static void case_fine_gain_pred(void)
{
    Word16 n = (Word16)random_range(1, BANDS), start[BANDS], end[BANDS], size[BANDS], sort[BANDS];
    Word16 k[BANDS], maxpulse[BANDS], r[BANDS], fg_pred[BANDS], xq[BANDS * 96], y[BANDS * 96];
    Word16 core = (Word16)(next_random() % 3 ? HQ_CORE : ACELP_CORE), use_r = (Word16)(next_random() % 4 != 0);
    int len = layout(start, end, size, n);
    permutation(sort, n);
    for (int b = 0; b < n; b++) {
        k[b] = (Word16)(next_random() % 5 ? random_range(1, 120) : 0);
        maxpulse[b] = (Word16)(k[b] ? random_range(1, k[b]) : 0);
        r[b] = (Word16)random_range(0, 600);
        fg_pred[b] = random16();
    }
    for (int i = 0; i < len; i++) {
        y[i] = (Word16)random_range(-6, 6);
        /* A unit-norm shape in Q15 mostly; sometimes an all-zero band, sometimes full-scale. */
        xq[i] = (Word16)(next_random() % 10 ? random_range(-12000, 12000) : (next_random() & 1 ? 0 : random16()));
    }
    if (next_random() % 5 == 0) for (int i = start[0]; i < end[0]; i++) xq[i] = 0;
    put16("sfm_start", start, n); put16("sfm_end", end, n); put16("sfm_size", size, n); put16("i_sort", sort, n);
    put16("k", k, n); put16("maxpulse", maxpulse, n); put16("r", r, n); put1("use_r", use_r); put1("core", core);
    put16("xq", xq, len); put16("y", y, len); put16("fg_pred", fg_pred, n);
    fine_gain_pred_fx(start, end, size, sort, k, maxpulse, use_r ? r : NULL, n, xq, y, fg_pred, core);
    arrow(); put16("xq", xq, len); put16("y", y, len); put16("fg_pred", fg_pred, n); end_line();
}

static void case_get_max_pulses(void)
{
    Word16 n = (Word16)random_range(1, BANDS), start[BANDS], end[BANDS], size[BANDS], sort[BANDS], npulses[BANDS], maxpulse[BANDS];
    Word16 inp[BANDS * 96];
    int len = layout(start, end, size, n);
    permutation(sort, n);
    for (int b = 0; b < n; b++) { npulses[b] = (Word16)(next_random() % 4 ? random_range(1, 100) : 0); maxpulse[b] = random16(); }
    for (int i = 0; i < len; i++) inp[i] = (Word16)(next_random() % 8 ? random_range(-20, 20) : random16());
    put16("band_start", start, n); put16("band_end", end, n); put16("k_sort", sort, n); put16("npulses", npulses, n);
    put16("inp_vector", inp, len); put16("maxpulse", maxpulse, n);
    get_max_pulses_fx(start, end, sort, npulses, n, inp, maxpulse);
    arrow(); put16("maxpulse", maxpulse, n); end_line();
}

static void case_fine_gain_dec(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 n = (Word16)random_range(1, BANDS), ord[BANDS], gain_bits[BANDS], fg_pred[BANDS];
    int nbits = 400;
    for (int i = 0; i < nbits; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)nbits;
    st->next_bit_pos_fx = (Word16)(next_random() % 8 ? random_range(0, nbits - 100) : random_range(nbits - 40, nbits));
    st->codec_mode = MODE1;
    permutation(ord, n);
    for (int b = 0; b < n; b++) {
        gain_bits[b] = (Word16)random_range(0, 5);
        fg_pred[b] = (Word16)(next_random() % 6 ? random_range(1, 32767) : (next_random() & 1 ? 0 : random16()));
    }
    put_u16("bits", bit_buffer, nbits); put1("next_bit_pos", st->next_bit_pos_fx);
    put16("ord", ord, n); put16("gain_bits", gain_bits, n); put16("fg_pred", fg_pred, n);
    fine_gain_dec_fx(st, ord, n, gain_bits, fg_pred);
    arrow(); put16("fg_pred", fg_pred, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "fine_gain_pred")) case_fine_gain_pred();
        else if (!strcmp(argv[2], "get_max_pulses")) case_get_max_pulses();
        else if (!strcmp(argv[2], "fine_gain_dec")) case_fine_gain_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
