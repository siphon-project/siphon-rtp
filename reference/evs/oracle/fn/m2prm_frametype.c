/* Oracle for the static decode_frame_type of lib_dec/dec_acelp_tcx_main.c (the frame type / bandwidth header read,
 * and the rate-change reconfiguration of the core, the CLDFB banks and FD-CNG), on the whole decoder state.
 *
 * The decoder is first brought to a running configuration by decode_frame_type itself (the first frame of a stream
 * at a MODE2 rate / bandwidth), its memories are randomised, and the case then decodes the header of the next frame:
 * an active frame (bandwidth bits, reserved bit, sometimes a corrupt one: a bandwidth past the rate's range, a
 * reserved bit set), a SID frame (FD-CNG type, bandwidth, frame-length bit), a zero frame, a MODE1-rate frame whose
 * core switched to MODE2 (13.2 / 32 kbit/s, no header), with or without channel-aware RF at 13.2 kbit/s. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "m2prm_common.h"
#include "../../c-code/lib_dec/dec_acelp_tcx_main.c"

#define NBITS 64
static UWord16 bits[NBITS];

static void put_bits(int value, int count, int *position)
{
    for (int i = count - 1; i >= 0; i--) bits[(*position)++] = (UWord16)((value >> i) & 1);
}

/* The header an active frame of `combo` carries; `corrupt` = 1 pushes the bandwidth field past the rate's range
 * and 2 sets the reserved bit. */
static void active_header(const Mode2Combo *combo, int corrupt)
{
    Word16 index = frame_size_index_of(combo->rate);
    const FrameSizeParams *config = &FrameSizeConfig[index];
    int position = 0, field = combo->bw - config->bandwidth_min;
    memset(bits, 0, sizeof bits);
    if (!combo->rf) {
        if (corrupt == 1) field = (1 << config->bandwidth_bits) - 1;
        put_bits(field, config->bandwidth_bits, &position);
        if (config->reserved_bits) put_bits(corrupt == 2, 1, &position);
    }
}

static void sid_header(int bandwidth, int indicator, int cng_type)
{
    int position = 0;
    memset(bits, 0, sizeof bits);
    put_bits(cng_type, 1, &position);
    put_bits(bandwidth, 2, &position);
    put_bits(indicator, 1, &position);
}

static void load_header(Decoder_State_fx *st, Word32 rate)
{
    st->bit_stream_fx = bits;
    st->next_bit_pos_fx = 0;
    st->total_num_bits = NBITS;
    st->total_brate_fx = rate;
    (void)rate;
}

static UWord16 first_bits[NBITS];

static Decoder_State_fx *running_state(const Mode2Combo *first)
{
    Decoder_State_fx *st = new_state();
    st->last_codec_mode = MODE1;
    st->mdct_sw = MODE2;
    st->rf_flag = first->rf;
    st->bwidth_fx = first->rf ? first->bw - FrameSizeConfig[frame_size_index_of(first->rate)].bandwidth_min : first->bw;
    st->last_bwidth_fx = first->bw;
    st->rf_flag_last = first->rf;
    st->nb_subfr = 4;
    st->ini_frame_fx = 0;
    st->last_total_brate_fx = 0;
    active_header(first, 0);
    memcpy(first_bits, bits, sizeof bits);
    load_header(st, first->rate);
    decode_frame_type(st);
    /* a few frames later */
    st->ini_frame_fx = (Word16)random_range(1, 60);
    st->last_codec_mode = (Word16)(next_random() % 8 == 0 ? MODE1 : MODE2);
    st->force_lpd_reset = 0;
    st->last_core_fx = (Word16)(next_random() % 3 == 0 ? ACELP_CORE : TCX_20_CORE);
    st->last_L_frame_fx = st->L_frame_fx;
    st->last_total_brate_fx = first->rate;
    st->last_bwidth_fx = st->bwidth_fx;
    st->prev_bfi_fx = (Word16)(next_random() % 5 == 0);
    st->last_core_bfi = (Word16)(next_random() % 3 == 0 ? ACELP_CORE : TCX_20_CORE);
    st->last_extl_fx = (Word16)(next_random() & 1 ? SWB_TBE : -1);
    st->BER_detect = (Word16)(next_random() % 20 == 0);
    st->m_frame_type = (Word16)(next_random() % 5 == 0 ? SID_FRAME : ACTIVE_FRAME);
    st->rf_flag_last = st->rf_flag;
    randomise_lpd_memories(st);
    if (st->hFdCngDec_fx) {
        random_signal(st->hFdCngDec_fx->olapBufferSynth2, 640, 8000);
        random_signal(st->hFdCngDec_fx->hFdCngCom->olapBufferSynth, 640, 8000);
        st->hFdCngDec_fx->hFdCngCom->frame_type_previous = (Word16)(next_random() & 1 ? ACTIVE_FRAME : SID_FRAME);
        st->hFdCngDec_fx->hFdCngCom->msFrCnt_init_counter = (Word16)random_range(0, 100);
    }
    return st;
}

static void case_decode_frame_type(void)
{
    const Mode2Combo *first = random_combo();
    Decoder_State_fx *st = running_state(first);
    int kind = random_range(0, 19);
    const Mode2Combo *second = next_random() % 3 == 0 ? first : random_combo();
    if (kind < 12) {
        /* active */
        int corrupt = next_random() % 8 == 0 ? random_range(1, 2) : 0;
        active_header(second, corrupt);
        st->rf_flag = second->rf;
        st->bwidth_fx = second->rf ? second->bw - FrameSizeConfig[frame_size_index_of(second->rate)].bandwidth_min : st->bwidth_fx;
        load_header(st, second->rate);
        st->mdct_sw = MODE2;
    } else if (kind < 16) {
        /* SID: the bandwidth fits the frame-length bit (no FB at 12.8 kHz); a corrupt header is a wrong
         * FD-CNG type or a narrowband frame that claims 16 kHz (both flag BER_detect and leave a valid frame) */
        int indicator = (int)(next_random() & 1);
        int bandwidth = indicator ? random_range(NB, FB) : random_range(NB, SWB);
        int cng_type = next_random() % 12 == 0 ? 0 : 1;
        if (next_random() % 12 == 0) { bandwidth = NB; indicator = 1; }
        sid_header(bandwidth, indicator, cng_type);
        st->rf_flag = 0;
        st->mdct_sw = MODE2;
        load_header(st, SID_2k40);
        if (next_random() & 1) st->last_total_brate_fx = (next_random() & 1) ? 16400 : 24400;
    } else if (kind < 18) {
        /* zero frame */
        memset(bits, 0, sizeof bits);
        st->rf_flag = 0;
        st->mdct_sw = MODE2;
        load_header(st, 0);
    } else {
        /* MODE1 rate that switched to the MODE2 core: no header is read */
        static const Mode2Combo mode1_rates[] = {{13200, NB, 0}, {13200, WB, 0}, {13200, SWB, 0}, {32000, WB, 0}, {32000, SWB, 0}, {32000, FB, 0}};
        const Mode2Combo *combo = &mode1_rates[next_random() % 6];
        memset(bits, 0, sizeof bits);
        st->rf_flag = 0;
        st->mdct_sw = MODE1;
        st->bwidth_fx = combo->bw;
        load_header(st, combo->rate);
    }
    st->force_lpd_reset = (Word16)(next_random() % 12 == 0);
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("first_rate", first->rate); put1("first_bw", first->bw); put1("first_rf", first->rf);
    put_u16("first_bits", first_bits, NBITS);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    decode_frame_type(st);
    finish(st, before);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decode_frame_type")) case_decode_frame_type();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
