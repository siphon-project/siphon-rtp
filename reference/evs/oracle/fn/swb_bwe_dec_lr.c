/* Function-level oracle for lib_dec/swb_bwe_dec_lr_fx.c (swb_bwe_dec_lr_fx and, through it, the
 * file-local DecodeSWBGenericParameters_fx and DecodeSWBSubbands_fx).
 *
 * Each case is a decoder from init_decoder_fx whose SWB BWE memories are randomised, run for three
 * consecutive frames on SWB 13.2 / 16.4 kbit/s long-window layouts (hq2_core_configure_fx), each
 * frame HQ_NORMAL or HQ_HARMONIC with the lengths preset_hq2_swb_fx gives, a spectrum from
 * mdct_spectrum_denorm_fx and its noise-filled copy, as hq_lr_dec_fx hands them over. The whole
 * state is printed before the first frame ("in.") and, after each, the fields that changed ("fN."). */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"

#define FRAMES 3

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static char *capture_state(Decoder_State_fx *st)
{
    char *buffer = NULL;
    size_t length = 0;
    FILE *saved = stdout;
    fflush(stdout);
    stdout = open_memstream(&buffer, &length);
    rd_dump_DecoderState("", st);
    fclose(stdout);
    stdout = saved;
    return buffer;
}

static void put_changed(const char *pre, const char *before, const char *after)
{
    while (*after) {
        const char *a_end = strchr(after + 1, ' '), *b_end = strchr(before + 1, ' ');
        size_t a_len = a_end ? (size_t)(a_end - after) : strlen(after);
        size_t b_len = b_end ? (size_t)(b_end - before) : strlen(before);
        if (a_len != b_len || memcmp(after, before, a_len)) printf(" %s%.*s", pre, (int)a_len - 1, after + 1);
        after += a_len;
        before += b_len;
    }
}

/* One frame's input: band energies (Q14), the denormalised spectrum (Q12) of random pulses (a pulse
 * train in the low band for the harmonic class) and its noise-filled copy. */
static void random_frame(Word16 clas, Word16 bands, const Word16 *start, const Word16 *end, const Word16 *width,
                         Word16 pd, Word16 ld, Word32 *energy, Word32 *y2, Word32 *y2_ni, Word16 *flags)
{
    Word16 inp[L_FRAME32k], npulses[BANDS_MAX];
    int spacing = random_range(8, 40), phase = random_range(0, spacing - 1), level = 1 << random_range(6, 14);
    for (int i = 0; i < L_FRAME32k; i++) { inp[i] = 0; y2[i] = 0; y2_ni[i] = 0; }
    for (int k = 0; k < bands; k++) {
        int density = random_range(1, 10), total = 0;
        energy[k] = next_random() % 16 ? random_range(-(1 << 14), 24 << 14) : random_range(-109772, 737279);
        for (int i = start[k]; i <= end[k]; i++) {
            Word16 v = 0;
            if (clas == HQ_HARMONIC && k < bands - 4) {
                if ((i - phase) % spacing == 0) v = (Word16)(random_range(1, 6) * ((next_random() & 1) ? 1 : -1));
            } else if (next_random() % density == 0) v = (Word16)random_range(-4, 4);
            inp[i] = v;
            total += abs(v);
        }
        npulses[k] = (Word16)total;
        flags[k] = (Word16)(k < bands - 4 ? 1 : next_random() % 3 != 0);
    }
    mdct_spectrum_denorm_fx(inp, y2, start, end, width, energy, npulses, bands, ld, pd);
    if (clas == HQ_HARMONIC && next_random() % 2) {
        /* a few low-band peaks at least SWB_HAR_RAN1 apart (or none past the first), so har_est_fx
         * gives up on a harmonic grid (flag_dis == 0) and falls back to the lag-indexed estimate */
        int top = end[bands - 5] + 1;
        for (int i = 0; i < top; i++) y2[i] = 0;
        for (int at = random_range(10, 130); at < top; at += random_range(80, 160))
            y2[at] = (Word32)random_range(1 << 12, 1 << 22) * (next_random() & 1 ? 1 : -1);
    }
    for (int i = 0; i <= end[bands - 1]; i++)
        y2_ni[i] = y2[i] != 0 ? y2[i] : (next_random() % 4 ? (Word32)random_range(-level, level) : 0);
}

static void case_swb_bwe_dec_lr(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = next_random() & 1 ? 32000 : 48000;
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    st->prev_hqswb_clas_fx = (Word16)random_range(0, 3);
    st->prev_frm_hfe2_fx = (Word16)(next_random() % 2 ? 0 : random_range(1, 80));
    st->prev_stab_hfe2_fx = (Word16)random_range(0, 3);
    st->prev_ni_ratio_fx = (Word16)random_range(0, 32767);
    for (int i = 0; i < NB_SWB_SUBBANDS; i++) st->prev_En_sb_fx[i] = (Word16)random_range(0, 3000);
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    char *before = capture_state(st);
    for (const char *p = before; *p;) {
        const char *e = strchr(p + 1, ' ');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        printf(" in.%.*s", (int)len - 1, p + 1);
        p += len;
    }
    for (int f = 0; f < FRAMES; f++) {
        char name[32];
        Word32 qint, brate = next_random() & 1 ? HQ_13k20 : HQ_16k40;
        Word16 bands, length, width[BANDS_MAX], start[BANDS_MAX], end[BANDS_MAX];
        Word16 eref, baw, gqlevs, ngq, p2a_bands, p2a_th, pd, ld, ni;
        hq2_core_configure_fx(L_FRAME32k, (Word16)random_range(200, 328), 0, &bands, &length, width, start, end, &qint,
                              &eref, &baw, &gqlevs, &ngq, &p2a_bands, &p2a_th, &pd, &ld, &ni, brate);
        Word16 clas = next_random() & 1 ? HQ_HARMONIC : HQ_NORMAL, har_bands = bands, low, high;
        static Word32 m[L_FRAME32k], energy[BANDS_MAX], y2[L_FRAME32k], y2_ni[L_FRAME32k];
        Word16 flags[BANDS_MAX];
        high = end[bands - 1];
        preset_hq2_swb_fx(clas, end, &har_bands, p2a_bands, length, bands, &low, &high, m);
        random_frame(clas, bands, start, end, width, pd, ld, energy, y2, y2_ni, flags);
        Word16 ni_seed = random16();
        int nbits = 40;
        for (int i = 0; i < nbits; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
        st->bit_stream_fx = bit_buffer;
        st->total_num_bits = (Word16)(next_random() % 8 ? nbits : random_range(0, 3));
        st->next_bit_pos_fx = 0;
        for (int i = 0; i < L_FRAME32k; i++) m[i] = -7;
        Word32 mode[] = {brate, clas, bands, low, high, har_bands, ni_seed, st->total_num_bits};
        sprintf(name, "f%d_mode", f); put32(name, mode, 8);
        sprintf(name, "f%d_bits", f); put_u16(name, bit_buffer, nbits);
        sprintf(name, "f%d_start", f); put16(name, start, bands);
        sprintf(name, "f%d_end", f); put16(name, end, bands);
        sprintf(name, "f%d_width", f); put16(name, width, bands);
        sprintf(name, "f%d_energy", f); put32(name, energy, bands);
        sprintf(name, "f%d_flags", f); put16(name, flags, bands);
        sprintf(name, "f%d_y2", f); put32(name, y2, L_FRAME32k);
        sprintf(name, "f%d_y2_ni", f); put32(name, y2_ni, L_FRAME32k);
        swb_bwe_dec_lr_fx(st, y2, SWB_BWE_LR_Qs, m, brate, bands, start, end, energy, SWB_BWE_LR_Qbe, flags, clas, low, high,
                          har_bands, &st->prev_frm_hfe2_fx, &st->prev_stab_hfe2_fx, width, y2_ni, &ni_seed);
        sprintf(name, "f%d_m", f); put32(name, m, L_FRAME32k);
        sprintf(name, "f%d_ni_seed", f); put1(name, ni_seed);
        char *after = capture_state(st);
        sprintf(name, "f%d.", f);
        put_changed(name, before, after);
        free(after);
        st->prev_hqswb_clas_fx = clas;
    }
    free(before);
    arrow();
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    if (strcmp(argv[2], "swb_bwe_dec_lr")) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) case_swb_bwe_dec_lr();
    return 0;
}
