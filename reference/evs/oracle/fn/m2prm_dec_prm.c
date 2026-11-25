/* Oracle for lib_dec/dec_prm.c: dec_prm (with its static dec_prm_hm), on the whole decoder state, and for
 * get_tbe_bits_fx (lib_com/swb_tbe_com_fx.c), which dec_prm uses for the ACELP bit budget.
 *
 * A case brings the decoder to a running LPD configuration for a MODE2 rate / bandwidth (mode_switch_decoder_LPD, as
 * the first frame of a stream does), randomises what dec_prm reads from the history (previous core, class, overlap
 * modes, IGF levels), sets the fields the frame header read before dec_prm would have set (the rate's reading mode:
 * MODE1-rate TCX at 13.2 / 32 kbit/s, the 1-bit ACELP / TCX decision at 16.4 / 24.4, the 3-bit coder type elsewhere,
 * TCX-only above 32 kbit/s; the RF fields of 13.2 kbit/s channel-aware frames, primary or partial copy), and decodes
 * a random bit stream of the frame's size: ACELP and TCX20 / TCX10 frames, IGF, LTP and TNS on and off (as the rate
 * enables them), the arithmetic and the raw-bit spectrum paths, and the corrupt streams a random one makes (BER_detect
 * set, frames shorter than the read). Streams carry the 16 zero bits the arithmetic coder may read past the frame. */
#define STATE_DUMP_LIBRARY
#include <unistd.h>
#include <fcntl.h>
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "m2prm_common.h"
#include "../../c-code/lib_dec/dec_prm.c"

#define NBITS (2560 + 64)
static UWord16 bits[NBITS];
static Word16 param[DEC_NPRM_DIV * NB_DIV + NPRM_LPC_NEW];

static void random_bits(int n, int bias)
{
    for (int i = 0; i < NBITS; i++) bits[i] = 0;
    for (int i = 0; i < n; i++)
        bits[i] = (UWord16)(bias == 0 ? (next_random() % 5 == 0) : bias == 1 ? (next_random() % 5 != 0) : (next_random() & 1));
}

static Decoder_State_fx *running_state(const Mode2Combo *combo)
{
    Decoder_State_fx *st = new_state();
    st->total_brate_fx = combo->rate;
    st->bwidth_fx = combo->bw;
    st->last_bwidth_fx = combo->bw;
    st->rf_flag = combo->rf;
    st->ini_frame_fx = 0;
    st->last_codec_mode = MODE1;
    st->nb_subfr = 4;
    mode_switch_decoder_LPD(st, combo->bw, combo->rate, frame_size_index_of(combo->rate));
    st->ini_frame_fx = (Word16)random_range(1, 60);
    st->last_codec_mode = MODE2;
    return st;
}

static void randomise_igf(Decoder_State_fx *st)
{
    IGF_DEC_PRIVATE_DATA_HANDLE p = &st->hIGFDec.igfData;
    for (int i = 0; i < 23; i++) { p->igf_curr[i] = (Word16)random_range(0, 91); p->igf_prev[i] = (Word16)random_range(0, 91); }
    for (int i = 0; i < 5; i++) { p->prevWhiteningLevel[i] = (Word16)random_range(0, 2); p->currWhiteningLevel[i] = (Word16)random_range(0, 2); }
    st->hIGFDec.flatteningTrigger = (Word16)random_range(0, 1);
}

static void case_dec_prm(void)
{
    /* a quarter of the cases are channel-aware 13.2 kbit/s frames, which the 28 combinations hold two of */
    const Mode2Combo *combo = next_random() % 4 == 0 ? &mode2_combos[6 + next_random() % 2] : random_combo();
    Decoder_State_fx *st = running_state(combo);
    Word16 index = frame_size_index_of(combo->rate);
    const FrameSizeParams *config = &FrameSizeConfig[index];
    Word32 rate = combo->rate;
    int num_bits = (int)(rate / 50);
    int partial = combo->rf && next_random() % 2;
    Word16 coder_type = (Word16)random_range(0, 3), total_nbbits, bits_read = 0; /* the ACELP coder types; 4 and above mean TCX in the 3-bit coder type field */

    st->mdct_sw = (Word16)((rate == 13200 && !combo->rf) || rate == 32000 ? MODE1 : 0);
    st->mdct_sw_enable = (Word16)(rate == 13200 || rate == 32000 ? MODE1 : (rate == 16400 || rate == 24400) ? MODE2 : 0);
    st->nb_subfr = (Word16)(st->L_frame_fx == 320 ? 5 : 4);
    st->last_core_fx = (Word16)(next_random() % 3 ? TCX_20_CORE : ACELP_CORE);
    st->last_core_bs_fx = st->last_core_fx;
    st->last_total_brate_fx = (Word32)(next_random() % 6 == 0 ? 0 : rate);
    st->clas_dec = (Word16)random_range(0, 5);
    st->last_good_fx = (Word16)random_range(0, 5);
    st->prev_bfi_fx = (Word16)(next_random() % 4 == 0);
    st->tcx_cfg.tcx_curr_overlap_mode = (Word16)(next_random() % 4 == 0 ? ALDO_WINDOW : random_range(0, 3));
    st->tcx_cfg.tcx_last_overlap_mode = (Word16)random_range(0, 4);
    st->enablePlcWaveadjust = (Word16)(next_random() & 1);
    st->tcxltp_gain = (Word16)random_range(0, 8000);
    st->BER_detect = 0;
    st->use_partial_copy = 0;
    st->rf_frame_type = 0;
    st->rf_target_bits = 0;
    st->core_fx = (Word16)(next_random() & 1 ? ACELP_CORE : TCX_20_CORE);
    randomise_igf(st);
    if (combo->rf) {
        static const Word16 rf_bits[8] = {5, 27, 16, 16, 63, 66, 70, 45};
        st->rf_frame_type = (Word16)(partial ? random_range(1, 7) : random_range(0, 7));
        st->rf_target_bits = rf_bits[st->rf_frame_type];
        if (partial) {
            st->use_partial_copy = 1;
            st->core_fx = (Word16)(st->rf_frame_type >= RF_TCXFD && st->rf_frame_type <= RF_TCXTD2 ? TCX_20_CORE : ACELP_CORE);
            st->bfi_fx = (Word16)(st->core_fx == TCX_20_CORE);
        }
    }
    /* the header decode_frame_type read: bandwidth bits and the reserved bit; an RF frame's two flag bits */
    if (combo->rf) st->next_bit_pos_fx = 2;
    else if (st->mdct_sw == MODE1) st->next_bit_pos_fx = (Word16)random_range(1, 3);
    else st->next_bit_pos_fx = (Word16)(config->bandwidth_bits + config->reserved_bits);
    st->total_num_bits = (Word16)num_bits;
    st->bit_stream_fx = bits;
    random_bits(num_bits, random_range(0, 3));
    /* 16.4 / 24.4 kbit/s: a TCX frame whose coder type has bit 2 set is the HQ core, which switches the decoder to MODE1
     * before dec_prm (dec_prm_core), so dec_prm never sees it */
    if (st->mdct_sw_enable == MODE2 && st->mdct_sw != MODE1 && !st->tcxonly && !combo->rf && bits[st->next_bit_pos_fx] == 1)
        bits[st->next_bit_pos_fx + 1] = 0;
    st->bits_frame_core = st->bits_frame;
    /* dec_acelp_tcx_frame: num_bits - (next_bit_pos - start_bit_pos) with its start_bit_pos taken before the header */
    total_nbbits = (Word16)(combo->rf ? num_bits - (st->next_bit_pos_fx + 2) : num_bits - st->next_bit_pos_fx);
    for (int i = 0; i < DEC_NPRM_DIV * NB_DIV + NPRM_LPC_NEW; i++) param[i] = 0x5a5a;
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("rate", rate); put1("bw", combo->bw); put1("rf", combo->rf);
    put1("coder_type", coder_type); put1("total_nbbits", total_nbbits); put1("l_frame", st->L_frame_fx);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    /* BITS_ALLOC_config_acelp prints a warning for a budget that is too small */
    fflush(stdout);
    int saved = dup(1), null = open("/dev/null", O_WRONLY);
    dup2(null, 1);
    dec_prm(&coder_type, param, param + DEC_NPRM_DIV * NB_DIV, &total_nbbits, st, st->L_frame_fx, &bits_read);
    fflush(stdout);
    dup2(saved, 1); close(saved); close(null);
    put16("param", param, DEC_NPRM_DIV * NB_DIV + NPRM_LPC_NEW);
    put1("coder_type_out", coder_type); put1("bits_read", bits_read);
    finish(st, before);
}

static void case_tbe_bits(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};
    Word32 rate = rates[next_random() % 11];
    Word16 bandwidth = (Word16)random_range(NB, FB), rf = (Word16)(next_random() % 4 == 0);
    put1("rate", rate); put1("bandwidth", bandwidth); put1("rf", rf);
    Word16 r = get_tbe_bits_fx(rate, bandwidth, rf);
    arrow(); put1("r", r); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "dec_prm")) case_dec_prm();
        else if (!strcmp(argv[2], "get_tbe_bits")) case_tbe_bits();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
