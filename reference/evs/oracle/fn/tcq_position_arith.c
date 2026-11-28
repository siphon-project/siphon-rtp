/* Function-level oracle for lib_com/tcq_position_arith_fx.c (the decoder half). The file is included
 * so its static functions (ar_decode_fx, GetBitsFromPulses_fx, quantize_fx, ...) are reachable. */
#include "harness.h"
#include "../../c-code/lib_com/tcq_position_arith_fx.c"

/* The band widths the low-rate HQ configurations use (rom_com_fx.c band_width_*), plus a few
 * narrower ones as edges. */
static Word16 random_band_width(void)
{
    if (next_random() % 8 == 0) return (Word16)random_range(2, 5);
    return (Word16)random_range(6, 115);
}

static void case_ar_div(void)
{
    Word32 num, denum;
    switch (next_random() % 4) {
    case 0: num = random32(); denum = random32(); break;
    case 1: num = random_range(0, 1 << 24); denum = random_range(0, 120); break; /* Rk / band_width */
    case 2: num = (Word32)((unsigned)random_range(0, 1 << 20) * 16383u); denum = random_range(1, 1 << 22); break;
    default: num = random_range(-(1 << 24), 1 << 24); denum = random_range(-(1 << 16), 1 << 16); break;
    }
    put1("num", num); put1("denum", denum);
    Word32 r = ar_div(num, denum);
    arrow(); put1("r", r); end_line();
}

static void case_get_bits_from_pulses(void)
{
    Word16 n = random_band_width();
    Word16 m = (Word16)(next_random() % 3 == 0 ? random_range(0, MAX_PULSES) : random_range(0, 2 * n));
    put1("m", m); put1("n", n);
    Word32 r = GetBitsFromPulses_fx(m, n);
    arrow(); put1("r", r); end_line();
}

static void case_get_scale(void)
{
    Word16 blen = random_band_width();
    Word32 bits = (Word32)random_range(0, blen * 8) << 16 | random_range(0, 65535);
    if (next_random() % 8 == 0) bits = random_range(1, 1 << 16);
    Word32 surplus = random_range(-(1 << 20), 1 << 20);
    put1("blen", blen); put1("bits", bits); put1("surplus", surplus);
    Word16 pulses = GetScale_fx(blen, bits, &surplus);
    arrow(); put1("pulses", pulses); put1("surplus", surplus); end_line();
}

static void case_quantize(void)
{
    Word16 val = (next_random() & 1) ? random16() : (Word16)(random_range(1, 30) << 10);
    Word16 d = (Word16)random_range(0, 3);
    put1("val", val); put1("d", d);
    Word16 r = quantize_fx(val, d);
    arrow(); put1("r", r); end_line();
}

static void case_ar_make_model(void)
{
    Word16 freq[TCQ_MAX_BAND_SIZE], model[TCQ_MAX_BAND_SIZE + 1];
    Word16 len = (Word16)random_range(1, TCQ_MAX_BAND_SIZE - 1);
    int kind = next_random() % 4;
    for (int i = 0; i < len; i++) {
        if (kind == 0) freq[i] = (Word16)random_range(1, 32767);
        else if (kind == 1) freq[i] = (Word16)random_range(0, 20);
        else if (kind == 2) freq[i] = (next_random() % 4) ? 1 : (Word16)random_range(1, 32767);
        else freq[i] = 0;
    }
    for (int i = 0; i <= len; i++) model[i] = (Word16)random_range(-5, 5);
    put16("freq", freq, len); put16("model", model, len + 1);
    Word32 r = ar_make_model_fx(freq, model, len);
    arrow(); put1("r", r); put16("model", model, len + 1); end_line();
}

static void case_srt_vec_ind(void)
{
    Word32 linear[BANDS_MAX], srt[BANDS_MAX];
    Word16 idx[BANDS_MAX];
    Word16 length = (Word16)random_range(1, BANDS_MAX);
    for (int i = 0; i < length; i++)
        linear[i] = (next_random() % 3) ? random_range(0, 8) << 16 : random32();
    put32("linear", linear, length);
    srt_vec_ind_fx(linear, srt, idx, length);
    arrow(); put32("srt", srt, length); put16("i", idx, length); end_line();
}

static void case_tcq_lsb_dec(void)
{
    Word16 dpath[280], mbuffer[560];
    Word16 bcount = (Word16)(next_random() % 4 ? 2 * TCQ_AMP : 2 * random_range(0, 140));
    for (int i = 0; i < bcount / 2; i++) dpath[i] = (Word16)random_range(0, 1);
    for (int i = 0; i < bcount; i++) mbuffer[i] = 7;
    put16("dpath", dpath, bcount / 2); put1("bcount", bcount);
    TCQLSBdec_fx(dpath, mbuffer, bcount);
    arrow(); put16("mbuffer", mbuffer, bcount); end_line();
}

static void case_restore_tcq_dec(void)
{
    Word16 magn[TCQ_MAX_BAND_SIZE], mbuffer[2 * TCQ_AMP + 4];
    Word16 size = random_band_width();
    int density = random_range(1, 6);
    for (int i = 0; i < size; i++)
        magn[i] = (next_random() % density) ? 0 : (Word16)random_range(-6, 6);
    for (int i = 0; i < 2 * TCQ_AMP + 4; i++) mbuffer[i] = (Word16)(next_random() & 1 ? 1 : -1);
    Word16 bcount = (Word16)random_range(0, 2 * TCQ_AMP + 2);
    put16("magn", magn, size); put1("size", size); put1("bcount", bcount);
    put16("mbuffer", mbuffer, 2 * TCQ_AMP + 4);
    RestoreTCQdec_fx(magn, size, &bcount, mbuffer);
    arrow(); put16("magn", magn, size); put1("bcount", bcount); put16("mbuffer", mbuffer, 2 * TCQ_AMP + 4);
    end_line();
}

/* A whole low-rate HQ decode over random bits, the way tcq_core_dec_fx drives these functions: start
 * the decoder, per band the pulse count, positions, magnitudes (TCQ or USQ) and signs, then the LSB
 * trellis path and the rollback. Any bit string is a valid arithmetic-coded stream. */
static void case_decode_bands(void)
{
    static BITSTREAM_FX bs;
    static ARCODEC_FX ar;
    Word16 nbytes = (Word16)random_range(2, 160);
    Word16 bands = (Word16)random_range(1, 8);
    Word16 size[8], npulses[8], usq[8], out_init[8][TCQ_MAX_BAND_SIZE];
    Word16 lsb = (Word16)(next_random() & 1 ? TCQ_AMP : 0);
    UWord8 bytes[MAX_SIZEBUF_PBITSTREAM];

    memset(&bs, 0, sizeof(bs));
    memset(&ar, 0, sizeof(ar));
    for (int i = 0; i < nbytes; i++) bytes[i] = (UWord8)next_random();
    for (int b = 0; b < bands; b++) {
        size[b] = random_band_width();
        int kind = next_random() % 4;
        if (kind == 0) npulses[b] = (Word16)random_range(-1, 1);
        else if (kind == 1) npulses[b] = GetScale_fx(size[b], (Word32)random_range(0, size[b] * 4) << 16, NULL);
        else npulses[b] = (Word16)random_range(2, 3 * size[b]);
        if (npulses[b] > MAX_PULSES) npulses[b] = MAX_PULSES;
        usq[b] = (Word16)(next_random() & 1);
        for (int i = 0; i < size[b]; i++) out_init[b][i] = (Word16)random_range(-3, 3);
    }

    printf(" bytes=");
    for (int i = 0; i < nbytes; i++) printf(i ? ",%d" : "%d", bytes[i]);
    put16("size", size, bands); put16("npulses", npulses, bands); put16("usq", usq, bands);
    for (int b = 0; b < bands; b++) {
        char name[16];
        sprintf(name, "init%d", b);
        put16(name, out_init[b], size[b]);
    }
    put1("lsb", lsb);
    arrow();

    for (int i = 0; i < nbytes; i++) bs.buf[i] = bytes[i];
    bs.curPos = 7;
    bs.numbits = 0;
    bs.numByte = 0;
    bs.maxBytes = nbytes + 2; /* tcq_core_dec_fx's two zero flush bytes */
    ar_decoder_start_fx(&ar, &bs);

    Word32 surplus = 0;
    for (int b = 0; b < bands; b++) {
        Word16 positions[L_FRAME48k], out[L_FRAME48k], nz = -7;
        for (int i = 0; i < size[b]; i++) { positions[i] = 9; out[i] = out_init[b][i]; }
        decode_position_ari_fx(&ar, size[b], npulses[b], &nz, positions);
        if (usq[b]) decode_magnitude_usq_fx(&ar, size[b], npulses[b], nz, positions, out);
        else decode_mangitude_tcq_fx(&ar, size[b], npulses[b], nz, positions, out, &surplus);
        decode_signs_fx(&ar, size[b], out);
        char name[16];
        sprintf(name, "nz%d", b); put1(name, nz);
        sprintf(name, "pos%d", b); put16(name, positions, size[b]);
        sprintf(name, "out%d", b); put16(name, out, size[b]);
    }
    Word16 dpath[280], mbuffer[560];
    LoadTCQdata_fx(&ar, dpath, lsb);
    TCQLSBdec_fx(dpath, mbuffer, 2 * lsb);
    ar_decoder_done_fx(&ar);
    put1("surplus", surplus);
    put16("dpath", dpath, lsb); put16("mbuffer", mbuffer, 2 * lsb);
    put1("low", ar.low); put1("high", ar.high); put1("value", ar.value);
    put1("cur_pos", bs.curPos); put1("num_byte", bs.numByte); put1("numbits", bs.numbits);
    end_line();
    return;
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "ar_div")) case_ar_div();
        else if (!strcmp(argv[2], "get_bits_from_pulses")) case_get_bits_from_pulses();
        else if (!strcmp(argv[2], "get_scale")) case_get_scale();
        else if (!strcmp(argv[2], "quantize")) case_quantize();
        else if (!strcmp(argv[2], "ar_make_model")) case_ar_make_model();
        else if (!strcmp(argv[2], "srt_vec_ind")) case_srt_vec_ind();
        else if (!strcmp(argv[2], "tcq_lsb_dec")) case_tcq_lsb_dec();
        else if (!strcmp(argv[2], "restore_tcq_dec")) case_restore_tcq_dec();
        else if (!strcmp(argv[2], "decode_bands")) case_decode_bands();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
