/* Function-level oracle for the IGF decoder: lib_com/igf_base.c, lib_dec/igf_scf_dec.c and
 * lib_dec/igf_dec.c. The three files are included, so their static functions (IGF_gridSetUp,
 * IGF_MapBitRateToIndex, IGF_prep, IGF_calc, IGF_appl, ...) are reached through the public ones.
 *
 * Functions on the decoder state (set_mode, update_info, copy_flat, store_restore, read_data,
 * read_level, apply_mono) build a decoder with init_decoder_fx, configure IGF with IGFDecSetMode for
 * one of the bit-rate / bandwidth combinations the decoder runs it at (getIgfPresent), randomise
 * what the function reads inside its documented domain, and print the WHOLE state before the call
 * (prefix "in.") and after it only the fields that changed (prefix "st."), as peak_vq_dec.c does.
 * Direct ones (config_tables, square_spec, sfb_energy) print their buffers.
 *
 * Domain notes: the spectrum is a core-coded MDCT spectrum (random walk of random magnitude, zero
 * runs, a few lines above the IGF start), exponents and levels are in the ranges dec_tcx gives
 * them; the whitening level is 0..2 per tile, igf_curr is 0..91. The SCF bitstream is random bits:
 * any bit pattern is a valid input of the arithmetic decoder (it flags BER_detect when it decodes
 * a value out of range). */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "../../c-code/lib_com/igf_base.c"
#include "../../c-code/lib_dec/igf_scf_dec.c"
#include "../../c-code/lib_dec/igf_dec.c"

#define NBITS 480
#define SPECTRUM_LEN 1000

typedef struct { Word32 rate; Word16 mode, rf; } Combo;

/* what getIgfPresent allows in MODE2, per bandwidth mode (WB 1, SWB 2, FB 3) */
static const Combo combos[] = {
    {9600, 1, 0}, {13200, 1, 1},
    {9600, 2, 0}, {13200, 2, 0}, {13200, 2, 1}, {16400, 2, 0}, {24400, 2, 0}, {32000, 2, 0}, {48000, 2, 0},
    {16400, 3, 0}, {24400, 3, 0}, {32000, 3, 0}, {48000, 3, 0}, {96000, 3, 0}, {128000, 3, 0},
};
#define NCOMBOS (int)(sizeof(combos) / sizeof(combos[0]))

static UWord16 bits[NBITS + 64];

static Decoder_State_fx *new_state(void)
{
    static const Word32 out_rates[2] = {32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = out_rates[next_random() % 2];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    st->codec_mode = MODE2;
    st->bit_stream_fx = bits;
    return st;
}

static const Combo *configure(Decoder_State_fx *st)
{
    const Combo *combo = &combos[next_random() % NCOMBOS];
    st->igf = 1;
    st->total_brate_fx = combo->rate;
    IGFDecSetMode(&st->hIGFDec, combo->rate, combo->mode, -1, -1, combo->rf);
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("rate", combo->rate);
    put1("mode", combo->mode);
    put1("rf", combo->rf);
    return combo;
}

static void random_bits(int n)
{
    int density = (int)(next_random() % 4);
    for (int i = 0; i < n; i++)
        bits[i] = (UWord16)(density == 0 ? (next_random() % 5 == 0) : density == 1 ? (next_random() % 5 != 0) : (next_random() & 1));
    for (int i = n; i < NBITS + 64; i++) bits[i] = 0;
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

/* a random walk of the given magnitude with zero runs */
static void random_lines(Word32 *x, int from, int to, int magnitude_bits)
{
    Word32 magnitude = (Word32)1 << magnitude_bits;
    Word32 value = 0;
    for (int i = from; i < to; i++) {
        if (next_random() % 6 == 0) { x[i] = 0; continue; }
        value += (Word32)((int)(next_random() % (unsigned)(magnitude / 2 + 1)) - (int)(magnitude / 4));
        if (value > magnitude) value = magnitude;
        if (value < -magnitude) value = -magnitude;
        x[i] = value;
    }
}

static void case_set_mode(void)
{
    Decoder_State_fx *st = new_state();
    /* every valid combination and, now and then, a rate IGF does not run at (13.2 kbit/s WB, no RF) */
    Word32 rate;
    Word16 mode, rf, default_start = (Word16)random_range(-3, 400), default_stop = (Word16)random_range(-3, 900);
    if (next_random() % 8 == 0) { rate = 13200; mode = 1; rf = 0; }
    else { const Combo *c = &combos[next_random() % NCOMBOS]; rate = c->rate; mode = c->mode; rf = c->rf; }
    st->igf = 1;
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("rate", rate); put1("mode", mode); put1("rf", rf);
    put1("default_start", default_start); put1("default_stop", default_stop);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    IGFDecSetMode(&st->hIGFDec, rate, mode, default_start, default_stop, rf);
    finish(st, before);
}

static void case_update_info(void)
{
    Decoder_State_fx *st = new_state();
    configure(st);
    IGF_DEC_INSTANCE_HANDLE h = &st->hIGFDec;
    Word16 idx = (Word16)random_range(0, 2);
    h->infoIGFStartFreq = random16(); h->infoIGFStopFreq = random16();
    h->infoIGFStartLine = random16(); h->infoIGFStopLine = random16();
    if (next_random() % 5 == 0) h->isIGFActive = 0;
    put1("idx", idx);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    IGFDecUpdateInfo(h, idx);
    finish(st, before);
}

static void case_copy_flat(void)
{
    Decoder_State_fx *st = new_state();
    configure(st);
    IGF_DEC_INSTANCE_HANDLE h = &st->hIGFDec;
    Word16 idx = (Word16)random_range(0, 2);
    Word32 flat[800];
    for (int i = 0; i < 800; i++) flat[i] = random32();
    Word16 flat_exp = (Word16)random_range(-10, 30);
    put1("idx", idx); put32("flat", flat, 800); put1("flat_exp", flat_exp);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    IGFDecCopyLPCFlatSpectrum(h, flat, flat_exp, idx);
    finish(st, before);
}

static void case_store_restore(void)
{
    Decoder_State_fx *st = new_state();
    configure(st);
    IGF_DEC_INSTANCE_HANDLE h = &st->hIGFDec;
    IGF_DEC_PRIVATE_DATA_HANDLE p = &h->igfData;
    Word16 sub_frame = (Word16)random_range(0, 1), restore = (Word16)random_range(0, 1);
    for (int i = 0; i < 23; i++) { p->igf_curr[i] = (Word16)random_range(0, 91); p->igf_prev[i] = (Word16)random_range(0, 91); }
    for (int i = 0; i < 5; i++) { p->currWhiteningLevel[i] = (Word16)random_range(0, 2); p->prevWhiteningLevel[i] = (Word16)random_range(0, 2); }
    h->flatteningTrigger = (Word16)random_range(0, 1);
    for (int s = 0; s < 2; s++) {
        for (int i = 0; i < 23; i++) { p->igf_curr_subframe[s][0][i] = (Word16)random_range(0, 91); p->igf_prev_subframe[s][i] = (Word16)random_range(0, 91); }
        for (int i = 0; i < 5; i++) { p->currWhiteningLevel_subframe[s][i] = (Word16)random_range(0, 2); p->prevWhiteningLevel_subframe[s][i] = (Word16)random_range(0, 2); }
        p->igf_flatteningTrigger_subframe[s] = (Word16)random_range(0, 1);
    }
    put1("sub_frame", sub_frame); put1("restore", restore);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    if (restore) IGFDecRestoreTCX10SubFrameData(h, sub_frame);
    else IGFDecStoreTCX10SubFrameData(h, sub_frame);
    finish(st, before);
}

static void case_read_data(void)
{
    Decoder_State_fx *st = new_state();
    configure(st);
    IGF_DEC_PRIVATE_DATA_HANDLE p = &st->hIGFDec.igfData;
    Word16 idx = (Word16)random_range(0, 2), indep = (Word16)random_range(0, 1);
    for (int i = 0; i < 5; i++) { p->prevWhiteningLevel[i] = (Word16)random_range(0, 2); p->currWhiteningLevel[i] = (Word16)random_range(0, 2); }
    random_bits(NBITS);
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(next_random() % 8 == 0 ? random_range(0, 60) : random_range(60, NBITS - 16));
    put1("idx", idx); put1("indep", indep);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    IGFDecReadData(&st->hIGFDec, st, idx, indep);
    finish(st, before);
}

static void case_read_level(void)
{
    Decoder_State_fx *st = new_state();
    configure(st);
    IGF_DEC_PRIVATE_DATA_HANDLE p = &st->hIGFDec.igfData;
    Word16 idx = (Word16)random_range(0, 2), indep = (Word16)random_range(0, 1);
    for (int i = 0; i < 23; i++) { p->igf_curr[i] = (Word16)random_range(0, 91); p->igf_prev[i] = (Word16)random_range(0, 91); }
    for (int i = 0; i < 64; i++) p->hArithSCFdec.prev[i] = (Word16)random_range(0, 91);
    p->hArithSCFdec.t = (Word16)random_range(0, 2);
    random_bits(NBITS);
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(next_random() % 8 == 0 ? random_range(0, 60) : random_range(60, NBITS - 16));
    put1("idx", idx); put1("indep", indep);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);
    int ok = GUARDED({ IGFDecReadLevel(&st->hIGFDec, st, idx, indep); });
    arrow();
    if (!ok) { put1("skip", 1); end_line(); free(before); destroy_decoder(st); free(st); return; }
    finish(st, before);
}

static void case_apply_mono(void)
{
    Decoder_State_fx *st = new_state();
    configure(st);
    IGF_DEC_INSTANCE_HANDLE h = &st->hIGFDec;
    IGF_DEC_PRIVATE_DATA_HANDLE p = &h->igfData;
    Word16 idx = (Word16)random_range(0, 2), bfi = (Word16)(next_random() % 5 < 2);
    H_IGF_GRID grid = &p->igfInfo.grid[idx];
    Word32 spectrum[SPECTRUM_LEN + 16];
    Word16 spectrum_e = (Word16)random_range(0, 12);
    memset(spectrum, 0, sizeof spectrum);
    random_lines(spectrum, 0, grid->startLine, random_range(8, 28));
    if (next_random() % 3 == 0) random_lines(spectrum, grid->startLine, grid->stopLine, random_range(6, 20));
    else for (int i = grid->startLine; i < grid->stopLine; i++) if (next_random() % 12 == 0) spectrum[i] = random_range(-4000, 4000);
    if (next_random() % 10 == 0) for (int i = 0; i < grid->startLine; i++) spectrum[i] = 0;
    random_lines(p->pSpecFlat, 0, grid->startLine, random_range(8, 28));
    p->pSpecFlat_exp = (Word16)random_range(8, 30);
    for (int i = 0; i < IGF_START_MX; i++) h->infoTCXNoise[i] = (Word16)(next_random() % 3 == 0);
    if (next_random() % 6 == 0) for (int i = 0; i < IGF_START_MX; i++) h->infoTCXNoise[i] = 0;
    for (int i = 0; i < 23; i++) p->igf_curr[i] = (Word16)random_range(0, 91);
    int levels = (int)(next_random() % 5);
    for (int i = 0; i < 5; i++) p->currWhiteningLevel[i] = (Word16)(levels < 3 ? levels : random_range(0, 2));
    p->igfInfo.nfSeed = random16();
    p->frameLossCounter = (Word16)(next_random() % 2 == 0 ? random_range(0, 7) : 0);
    h->infoIGFAllZero = (Word16)(next_random() % 10 == 0);
    if (next_random() % 3 == 0) {
        /* few TCX noise lines, so the noise-replacement corner cases occur: no energy at all, a
         * generated energy of zero (a seed whose first value is small) and a measured energy far above
         * the generated one */
        int whitening = (int)(next_random() % 3), kind = (int)(next_random() % 4), n = kind == 2 ? 1 : random_range(1, 3);
        memset(h->infoTCXNoise, 0, sizeof h->infoTCXNoise);
        for (int i = 0; i < 5; i++) p->currWhiteningLevel[i] = (Word16)whitening;
        for (int k = 0; k < n; k++) {
            int line = random_range(grid->minSrcSubband, grid->startLine - 1);
            h->infoTCXNoise[line] = 1;
            if (kind == 0) p->pSpecFlat[line] = 0;
            if (kind == 1) p->pSpecFlat[line] = (Word32)1 << random_range(24, 30);
        }
        if (kind == 0) for (int i = 0; i < grid->startLine; i++) if (next_random() % 2) p->pSpecFlat[i] = 0;
        if (kind == 3 || (whitening == 2 && kind == 0)) {
            /* silence just below the IGF start (the whitening average runs down to nothing), or in the
             * whole source range (strong whitening of a silent source) */
            int from = kind == 3 ? grid->startLine - 20 : grid->sbWrap[0];
            for (int i = from < 0 ? 0 : from; i < grid->startLine; i++) p->pSpecFlat[i] = 0;
        }
        if (kind == 2) {
            for (int tries = 0; tries < 100000; tries++) {
                Word16 seed = random16(), value = seed;
                value = Random(&value);
                if (value >= 0 && value < 32) { p->igfInfo.nfSeed = seed; break; }
            }
        }
    }
    put1("idx", idx); put1("bfi", bfi); put32("spectrum", spectrum, SPECTRUM_LEN); put1("spectrum_e", spectrum_e);
    char *before = capture_state(st);
    put_state_in(before);
    int ok = GUARDED({ IGFDecApplyMono(h, spectrum, &spectrum_e, idx, bfi); });
    arrow();
    if (!ok) { put1("skip", 1); end_line(); free(before); destroy_decoder(st); free(st); return; }
    put32("spectrum", spectrum, SPECTRUM_LEN); put1("spectrum_e", spectrum_e);
    finish(st, before);
}

/* the cumulative-frequency tables of every bit rate and mode, in full */
static void case_config_tables(void)
{
    Word32 rate;
    Word16 mode, rf;
    if (next_random() % 6 == 0) { rate = 13200; mode = 1; rf = 0; }
    else { const Combo *c = &combos[next_random() % NCOMBOS]; rate = c->rate; mode = c->mode; rf = c->rf; }
    const Word16 *cf_se00 = NULL, *cf_se01 = NULL, *cf_se02 = NULL, *cf_off_se02 = NULL, *cf_se10 = NULL, *cf_se11 = NULL, *cf_off_se11 = NULL;
    Word16 cf_off_se01 = -99, cf_off_se10 = -99;
    put1("rate", rate); put1("mode", mode); put1("rf", rf);
    Word16 ret = IGFCommonFuncsIGFGetCFTables(rate, mode, rf, &cf_se00, &cf_se01, &cf_off_se01, &cf_se02, &cf_off_se02, &cf_se10, &cf_off_se10, &cf_se11, &cf_off_se11);
    arrow();
    put1("ret", ret);
    if (ret) {
        put16("cf_se00", cf_se00, 28); put16("cf_se01", cf_se01, 28); put1("cf_off_se01", cf_off_se01);
        put16("cf_se02", cf_se02, 7 * 28); put16("cf_off_se02", cf_off_se02, 7);
        put16("cf_se10", cf_se10, 28); put1("cf_off_se10", cf_off_se10);
        put16("cf_se11", cf_se11, 49 * 28); put16("cf_off_se11", cf_off_se11, 49);
    }
    end_line();
}

static void case_square_spec(void)
{
    Word32 spec[300], out[300];
    Word16 begin = (Word16)random_range(24, 120), count = (Word16)random_range(0, 120);
    Word16 spec_e = (Word16)random_range(-10, 30);
    Word16 offset = (Word16)random_range(-begin, 20);
    for (int i = 0; i < 300; i++) { spec[i] = next_random() % 5 == 0 ? 0 : random32() >> random_range(0, 24); out[i] = random32(); }
    Word16 out_e = (Word16)random_range(-5, 5);
    put1("begin", begin); put1("count", count); put32("spec", spec, 300); put1("spec_e", spec_e); put1("offset", offset); put32("out", out, 300); put1("out_e", out_e);
    if (count == 0) { /* getScaleFactor32 of an empty range: keep the reference in its domain */ }
    IGFCommonFuncsMDCTSquareSpec(begin, begin + count, spec, spec_e, out, &out_e, offset);
    arrow();
    put32("out", out, 300); put1("out_e", out_e);
    end_line();
}

static void case_sfb_energy(void)
{
    Word16 offsets[24];
    Word32 power[400], energy[24];
    Word16 energy_e[24];
    Word16 nsfb = (Word16)random_range(1, 22), start = (Word16)random_range(0, nsfb - 1), stop = (Word16)random_range(start, nsfb);
    offsets[0] = (Word16)random_range(0, 20);
    for (int i = 1; i <= nsfb; i++) offsets[i] = (Word16)(offsets[i - 1] + random_range(1, 16));
    for (int i = 0; i < 400; i++) {
        int kind = (int)(next_random() % 6);
        power[i] = kind == 0 ? 0 : kind == 1 ? 0x3fffffff : (Word32)(next_random() >> random_range(1, 24)) & 0x3fffffff;
    }
    for (int i = 0; i < 24; i++) { energy[i] = random32(); energy_e[i] = random16(); }
    Word16 power_e = (Word16)random_range(-20, 20);
    int null_spectrum = next_random() % 10 == 0;
    put1("start", start); put1("stop", stop); put16("offsets", offsets, nsfb + 1); put32("power", power, 400);
    put1("power_e", power_e); put32("energy", energy, 24); put16("energy_e", energy_e, 24); put1("null_spectrum", null_spectrum);
    IGFCommonFuncsCalcSfbEnergyPowerSpec(start, stop, offsets, null_spectrum ? NULL : power, &power_e, energy, energy_e);
    arrow();
    put32("energy", energy, 24); put16("energy_e", energy_e, 24);
    end_line();
}

/* getIgfPresent / getCnaPresent (lib_com/core_com_config_fx.c) over every rate and bandwidth */
static void case_present(void)
{
    static const Word32 rates[] = {5900, 7200, 8000, 9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000, 13201, 63999};
    Word32 rate = rates[next_random() % 14];
    Word16 bandwidth = (Word16)random_range(0, 3), rf = (Word16)random_range(0, 1);
    put1("rate", rate); put1("bandwidth", bandwidth); put1("rf", rf);
    arrow();
    put1("igf", getIgfPresent(rate, bandwidth, rf)); put1("cna", getCnaPresent(rate, bandwidth));
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "set_mode")) case_set_mode();
        else if (!strcmp(argv[2], "update_info")) case_update_info();
        else if (!strcmp(argv[2], "copy_flat")) case_copy_flat();
        else if (!strcmp(argv[2], "store_restore")) case_store_restore();
        else if (!strcmp(argv[2], "read_data")) case_read_data();
        else if (!strcmp(argv[2], "read_level")) case_read_level();
        else if (!strcmp(argv[2], "apply_mono")) case_apply_mono();
        else if (!strcmp(argv[2], "config_tables")) case_config_tables();
        else if (!strcmp(argv[2], "square_spec")) case_square_spec();
        else if (!strcmp(argv[2], "sfb_energy")) case_sfb_energy();
        else if (!strcmp(argv[2], "present")) case_present();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
