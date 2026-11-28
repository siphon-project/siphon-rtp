/* Function-level oracle for lib_dec/peak_vq_dec_fx.c: hvq_dec_fx and peak_vq_dec_fx (dequant_peaks_fx,
 * hvq_dec_pos_fx and sparse_dec_pos_fx are static and reached through them), on the inputs
 * hq_hr_dec_fx gives them: a harmonic-band norm envelope, the global allocation R, a zeroed spectrum and the
 * bits after the envelope, SWB or FB at 24.4 and 32 kbit/s.
 *
 * Each case builds a decoder with init_decoder_fx and prints the WHOLE state before the call (prefix "in.")
 * and after it only the fields that changed (prefix "st."), as acelp_core_switch_dec.c does. The bits are
 * random, in four densities, so the Huffman and the sparse position codes, the Huffman and the fixed-length
 * gain codes, the bit-error guards and frames shorter than the read all occur. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "../../c-code/lib_dec/peak_vq_dec_fx.c"

#define NBITS 800

static UWord16 bits[NBITS + 16];
static Word32 coefs_buffer[L_FRAME48k + 16];

/* A norm envelope over the harmonic bands: a random walk, now and then one band far stronger. */
static void random_envelope(Word16 *ynrm, int n)
{
    int v = random_range(5, 35);
    for (int i = 0; i < n; i++) {
        v += random_range(-3, 3);
        if (v < 0) v = 0;
        if (v > 39) v = 39;
        ynrm[i] = (Word16)v;
    }
    if (next_random() % 2) ynrm[random_range(HVQ_THRES_SFM_24k, n - 1)] = (Word16)random_range(0, 10);
    if (next_random() % 8 == 0) for (int i = 0; i < n; i++) ynrm[i] = (Word16)random_range(0, 39);
}

static void random_bits(int n)
{
    int density = (int)(next_random() % 4);
    for (int i = 0; i < n; i++)
        bits[i] = (UWord16)(density == 0 ? (next_random() % 6 == 0) : density == 1 ? (next_random() % 6 != 0) : (next_random() & 1));
}

/* Does the stream decode without a bit-error flag? Probed on a bare decoder (the function reads only the bit
 * fields, the bandwidth and the core). */
static int decodes_cleanly(Word16 bwidth, Word32 brate, Word16 total_num_bits, Word16 next_bit_pos, const Word16 *ynrm,
                           const Word16 *R_in, Word16 num_bits, int through_hvq_dec)
{
    static Word32 probe_coefs[L_FRAME48k + 16];
    Decoder_State_fx *probe = calloc(1, sizeof(Decoder_State_fx));
    Word16 R[NB_SFM], peak_idx[HVQ_MAX_PEAKS_32k], npeaks = 0;
    memcpy(R, R_in, sizeof R);
    memset(probe_coefs, 0, sizeof probe_coefs);
    probe->bwidth_fx = bwidth;
    probe->bit_stream_fx = bits;
    probe->total_num_bits = total_num_bits;
    probe->next_bit_pos_fx = next_bit_pos;
    probe->codec_mode = MODE1;
    memset(peak_idx, 0, sizeof peak_idx);
    Word16 noise_level[HVQ_BWE_NOISE_BANDS];
    int ok = GUARDED({
        if (through_hvq_dec) hvq_dec_fx(probe, num_bits, brate, ynrm, R, noise_level, peak_idx, &npeaks, probe_coefs + 8, HQ_CORE);
        else peak_vq_dec_fx(probe, probe_coefs + 8, (Word16)brate, num_bits, ynrm, R, peak_idx, &npeaks, HQ_CORE);
    });
    int clean = ok && probe->BER_detect == 0;
    free(probe);
    return clean;
}

static void case_hvq(int through_hvq_dec)
{
    static const Word32 out_rates[2] = {32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word32 brate = next_random() & 1 ? HQ_24k40 : HQ_32k;
    Word16 ynrm[NB_SFM], R[NB_SFM], peak_idx[HVQ_MAX_PEAKS_32k], noise_level[HVQ_BWE_NOISE_BANDS], npeaks = -7;
    Word32 *coefs = coefs_buffer + 8;
    int frame_bits = (int)(brate / 50);

    st->output_Fs_fx = out_rates[next_random() % 2];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    st->bwidth_fx = next_random() & 1 ? FB : SWB;
    st->core_brate_fx = brate;
    st->total_brate_fx = brate;
    st->codec_mode = MODE1;
    st->core_fx = HQ_CORE;
    int want_clean = next_random() % 10 < 7;
    st->BER_detect = (Word16)(!want_clean && next_random() % 16 == 0);
    st->bit_stream_fx = bits;
    random_envelope(ynrm, SFM_N_HARM_FB);
    for (int i = 0; i < NB_SFM; i++) R[i] = (Word16)(next_random() % 4 ? 0 : random_range(0, 300));
    Word16 num_bits = (Word16)(next_random() % 8 == 0 ? random_range(-40, 120) : random_range(100, brate == HQ_24k40 ? 480 : 640));
    if (want_clean) num_bits = (Word16)random_range(150, brate == HQ_24k40 ? 480 : 640);
    /* most cases decode a real frame: draw streams until one decodes without a bit-error flag */
    for (int attempt = 0; attempt < 3000; attempt++) {
        random_bits(NBITS);
        st->total_num_bits = (Word16)(!want_clean && next_random() % 6 == 0 ? random_range(0, frame_bits) : frame_bits);
        st->next_bit_pos_fx = (Word16)(next_random() % 10 ? random_range(0, 30) : random_range(0, st->total_num_bits));
        if (!want_clean) break;
        if (decodes_cleanly(st->bwidth_fx, brate, st->total_num_bits, st->next_bit_pos_fx, ynrm, R, num_bits, through_hvq_dec)) break;
    }
    for (int i = 0; i < HVQ_MAX_PEAKS_32k; i++) peak_idx[i] = 0;
    for (int i = 0; i < HVQ_BWE_NOISE_BANDS; i++) noise_level[i] = -7;
    for (int i = 0; i < L_FRAME48k + 16; i++) coefs_buffer[i] = 0;

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("num_bits", num_bits); put1("brate", brate); put16("ynrm", ynrm, SFM_N_HARM_FB); put16("r", R, NB_SFM);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);

    int ok = GUARDED({
        if (through_hvq_dec) hvq_dec_fx(st, num_bits, brate, ynrm, R, noise_level, peak_idx, &npeaks, coefs, HQ_CORE);
        else peak_vq_dec_fx(st, coefs, (Word16)brate, num_bits, ynrm, R, peak_idx, &npeaks, HQ_CORE);
    });
    arrow();
    if (!ok) { put1("skip", 1); end_line(); free(before); destroy_decoder(st); free(st); return; }
    put32("coefs", coefs, L_FRAME48k); put16("r", R, NB_SFM); put16("peak_idx", peak_idx, HVQ_MAX_PEAKS_32k);
    put1("npeaks", npeaks); put16("noise_level", noise_level, HVQ_BWE_NOISE_BANDS);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hvq_dec")) case_hvq(1);
        else if (!strcmp(argv[2], "peak_vq_dec")) case_hvq(0);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
