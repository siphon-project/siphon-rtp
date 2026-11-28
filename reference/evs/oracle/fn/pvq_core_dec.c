/* Function-level oracle for lib_dec/pvq_core_dec_fx.c: pvq_core_dec_fx over random bits with the
 * GSC band layout (ACELP core) and random HQ layouts (HQ core), which reaches pvq_decode_frame_fx,
 * pvq_decode_band_fx, get_pvq_splits_fx, decode_energies_fx and densitySymbolIndexDecode_fx; and
 * decode_energies_fx alone on a freshly initialised range decoder. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "../../c-code/lib_dec/pvq_core_dec_fx.c"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 64];

static Decoder_State_fx *new_state(int n_bits)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int style = next_random() % 5;
    for (int i = 0; i < n_bits; i++)
        bit_buffer[i] = (UWord16)(style == 0 ? next_random() % 8 == 0 : style == 1 ? next_random() % 8 != 0 : next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n_bits;
    st->next_bit_pos_fx = 0;
    put_u16("bits", bit_buffer, n_bits);
    return st;
}

static void put_rc(Decoder_State_fx *st)
{
    Word32 rc[] = {(Word32)st->rc_low_fx, (Word32)st->rc_range_fx, (Word32)st->rc_help_fx};
    Word16 s[] = {st->rc_num_bits_fx, st->rc_offset_fx, st->rc_end_fx, st->next_bit_pos_fx, st->BER_detect, st->ber_occured_in_pvq};
    put32("rc", rc, 3); put16("st", s, 6);
}

static void case_pvq_core_dec(void)
{
    static const Word16 widths[] = {8, 8, 16, 16, 24, 32, 48, 64, 96, 4, 12, 20};
    Word16 sfm_start[NB_SFM], sfm_end[NB_SFM], sfmsize[NB_SFM], r[NB_SFM], rs[NB_SFM];
    Word16 npulses[NB_SFM], maxpulse[NB_SFM], coefs[L_FRAME48k];
    Word16 core = (Word16)(next_random() % 2 ? ACELP_CORE : HQ_CORE);
    Word16 nb_sfm;
    int total = 0, sum_r = 0;
    if (core == ACELP_CORE && next_random() % 3) {
        nb_sfm = (Word16)random_range(1, 16);
        for (int i = 0; i < nb_sfm; i++) { sfm_start[i] = gsc_sfm_start[i]; sfm_end[i] = gsc_sfm_end[i]; sfmsize[i] = gsc_sfm_size[i]; }
    } else {
        nb_sfm = (Word16)random_range(1, NB_SFM);
        int n = 0;
        for (; n < nb_sfm; n++) {
            Word16 w = widths[next_random() % 12];
            if (total + w > L_FRAME48k) break;
            sfm_start[n] = (Word16)total; sfmsize[n] = w; total += w; sfm_end[n] = (Word16)total;
        }
        nb_sfm = (Word16)(n ? n : 1);
        if (!n) { sfm_start[0] = 0; sfmsize[0] = 8; sfm_end[0] = 8; }
    }
    total = sfm_end[nb_sfm - 1];
    int budget = random_range(20, 1600);
    for (int i = 0; i < nb_sfm; i++) {
        int bits = next_random() % 4 == 0 ? 0 : random_range(1, sfmsize[i] * (next_random() % 3 ? 3 : 6));
        if (sum_r + bits > budget) bits = 0;
        r[i] = (Word16)(bits * 8 - (bits ? random_range(0, 7) : 0));
        if (r[i] < 0) r[i] = 0;
        sum_r += bits;
        rs[i] = (Word16)random_range(0, 40);
    }
    Word16 bits_tot = (Word16)(sum_r + random_range(0, 12));
    Decoder_State_fx *st = new_state(bits_tot + 48);
    Word16 use_rs = (Word16)(core == HQ_CORE);
    for (int i = 0; i < L_FRAME48k; i++) coefs[i] = -9;
    for (int i = 0; i < NB_SFM; i++) { npulses[i] = 0; maxpulse[i] = -9; }
    put1("core", core); put1("nb_sfm", nb_sfm); put1("bits_tot", bits_tot); put1("use_rs", use_rs);
    put16("sfm_start", sfm_start, nb_sfm); put16("sfm_end", sfm_end, nb_sfm); put16("sfmsize", sfmsize, nb_sfm);
    put16("r", r, nb_sfm); put16("rs", rs, nb_sfm);
    Word16 q = -1;
    Word16 ret = pvq_core_dec_fx(st, sfm_start, sfm_end, sfmsize, coefs, &q, bits_tot, nb_sfm, r, use_rs ? rs : NULL, npulses,
                                 maxpulse, core);
    arrow(); put1("ret", ret); put1("q", q); put16("coefs", coefs, total); put16("r", r, nb_sfm); put16("rs", rs, nb_sfm);
    put16("npulses", npulses, nb_sfm); put16("maxpulse", maxpulse, nb_sfm); put_rc(st); end_line();
    free(st);
}

static void case_decode_energies(void)
{
    Word16 dim = (Word16)random_range(2, 96);
    Word16 np = (Word16)random_range(2, dim < MAX_SPLITS ? dim : MAX_SPLITS);
    Word16 dim_part[MAX_SPLITS + 1], bits_part[MAX_SPLITS + 1], g_part[MAX_SPLITS];
    Word16 parts = (Word16)(dim / np);
    for (int i = 0; i < np - 1; i++) dim_part[i] = parts;
    dim_part[np - 1] = (Word16)(dim - parts * (np - 1));
    for (int i = 0; i <= MAX_SPLITS; i++) bits_part[i] = -9;
    for (int i = 0; i < MAX_SPLITS; i++) g_part[i] = -32768;
    Word16 qband = (Word16)random_range(0, dim * 40), bits_left = (Word16)random_range(qband, qband + 2000);
    Word16 strict = (Word16)random_range(0, 1);
    Decoder_State_fx *st = new_state(400);
    Word16 pvq_bits = (Word16)random_range(20, 380);
    put1("dim", dim); put1("np", np); put1("qband", qband); put1("bits_left", bits_left); put1("strict", strict);
    put1("pvq_bits", pvq_bits);
    rc_dec_init_fx(st, pvq_bits);
    decode_energies_fx(st, np, dim_part, bits_part, g_part, qband, &bits_left, dim, strict);
    arrow(); put16("bits_part", bits_part, MAX_SPLITS + 1); put16("g_part", g_part, MAX_SPLITS); put1("bits_left", bits_left);
    put_rc(st); end_line();
    free(st);
}

/* densitySymbolIndexDecode_fx alone, over every split shape: an opposite part much smaller than the
 * near one (c == 0), much larger (c == density), and balanced ones (both halves of the general case). */
static void case_density_symbol(void)
{
    Decoder_State_fx *st = new_state(200);
    Word16 density = (Word16)((random_range(1, 64) << 1) | 1);
    if (next_random() % 8 == 0) density = (Word16)random_range(0, 3);
    Word16 opp = (Word16)random_range(1, 64), near = (Word16)random_range(1, 64);
    int shape = next_random() % 3;
    if (shape == 0) { opp = (Word16)random_range(1, 3); near = (Word16)random_range(40, 64); }
    else if (shape == 1) { opp = (Word16)random_range(40, 64); near = (Word16)random_range(1, 3); }
    Word16 pvq_bits = (Word16)random_range(20, 180), index_phi = -7;
    put1("density", density); put1("opp", opp); put1("near", near); put1("pvq_bits", pvq_bits);
    rc_dec_init_fx(st, pvq_bits);
    densitySymbolIndexDecode_fx(st, density, opp, near, &index_phi);
    arrow(); put1("index_phi", index_phi); put_rc(st); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "pvq_core_dec")) case_pvq_core_dec();
        else if (!strcmp(argv[2], "decode_energies")) case_decode_energies();
        else if (!strcmp(argv[2], "density_symbol")) case_density_symbol();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
