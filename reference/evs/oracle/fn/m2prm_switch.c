/* Oracle for lib_dec/core_dec_switch.c (mode_switch_decoder_LPD) and lib_dec/core_dec_reconf.c
 * (reconfig_decoder_LPD), on the whole decoder state. The decoder is first brought to a running LPD
 * configuration (a first mode_switch_decoder_LPD at a MODE2 rate / bandwidth, as the first frame of a stream),
 * its memories are randomised, and the case then switches to a second rate / bandwidth (or reconfigures for it).
 * Rates and bandwidths are the MODE2 ones (getIgfPresent / FrameSizeConfig): 9.6 .. 128 kbit/s, 13.2 kbit/s
 * also with channel-aware RF; the previous frame's core (ACELP / TCX / AMR-WB IO), codec mode, bad-frame
 * flags and TBE extension are drawn from what the decoder leaves behind. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "m2prm_common.h"

static Decoder_State_fx *running_state(const Mode2Combo *first)
{
    Decoder_State_fx *st = new_state();
    st->total_brate_fx = first->rate;
    st->bwidth_fx = first->bw;
    st->last_bwidth_fx = first->bw;
    st->rf_flag = first->rf;
    st->ini_frame_fx = 0;
    st->last_codec_mode = MODE1;
    st->nb_subfr = 4;
    mode_switch_decoder_LPD(st, first->bw, first->rate, frame_size_index_of(first->rate));
    /* a few frames later */
    st->ini_frame_fx = (Word16)random_range(1, 60);
    st->last_codec_mode = (Word16)(next_random() % 8 == 0 ? MODE1 : MODE2);
    st->force_lpd_reset = (Word16)(next_random() % 10 == 0);
    st->last_core_fx = (Word16)(next_random() % 12 == 0 ? AMR_WB_CORE : (next_random() % 3 == 0 ? ACELP_CORE : TCX_20_CORE));
    st->last_L_frame_fx = st->L_frame_fx;
    st->prev_bfi_fx = (Word16)(next_random() % 5 == 0);
    st->last_core_bfi = (Word16)(next_random() % 3 == 0 ? ACELP_CORE : TCX_20_CORE);
    st->last_extl_fx = (Word16)(next_random() % 3 == 0 ? random_range(0, 11) : (next_random() & 1 ? SWB_TBE : -1));
    st->tec_tfa = (Word16)(next_random() & 1);
    st->envWeighted = (Word8)(next_random() % 3 == 0);
    st->rf_flag_last = st->rf_flag;
    randomise_lpd_memories(st);
    return st;
}

static void case_mode_switch(void)
{
    const Mode2Combo *first = random_combo();
    const Mode2Combo *second = next_random() % 4 == 0 ? first : random_combo();
    Decoder_State_fx *st = running_state(first);
    st->total_brate_fx = second->rate;
    st->bwidth_fx = second->bw;
    st->rf_flag = second->rf;
    st->nb_subfr = (Word16)(next_random() & 1 ? 4 : 5);
    Word16 index = frame_size_index_of(second->rate);
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("rate", second->rate); put1("bw", second->bw); put1("index", index);
    put1("first_rate", first->rate); put1("first_bw", first->bw); put1("first_rf", first->rf);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    mode_switch_decoder_LPD(st, second->bw, second->rate, index);
    finish(st, before);
}

static void case_reconfig(void)
{
    const Mode2Combo *first = random_combo();
    const Mode2Combo *second = random_combo();
    Decoder_State_fx *st = running_state(first);
    Word16 l_frame_old = st->L_frame_fx;
    /* move to the second configuration the way the switch does it, but stop short of reconfig_decoder_LPD */
    st->total_brate_fx = second->rate;
    st->bwidth_fx = second->bw;
    st->rf_flag = second->rf;
    st->nb_subfr = (Word16)(next_random() & 1 ? 4 : 5);
    st->fscale_old = st->fscale;
    if (next_random() & 1) { st->fscale_old = (Word16)(st->fscale == 512 ? 640 : 512); }
    if (next_random() & 1) st->L_frame_fx = (Word16)(next_random() & 1 ? 256 : 320);
    st->numlpc = (Word16)(next_random() % 3 ? 1 : 2);
    st->lpcQuantization = (Word16)(next_random() % 3 ? 1 : 0);
    Word16 bits_frame = (Word16)FrameSizeConfig[frame_size_index_of(second->rate)].frame_net_bits;
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("bits_frame", bits_frame); put1("bw", second->bw); put1("rate", second->rate); put1("l_frame_old", l_frame_old);
    put1("first_rate", first->rate); put1("first_bw", first->bw); put1("first_rf", first->rf);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    reconfig_decoder_LPD(st, bits_frame, second->bw, second->rate, l_frame_old);
    finish(st, before);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "mode_switch_decoder_LPD")) case_mode_switch();
        else if (!strcmp(argv[2], "reconfig_decoder_LPD")) case_reconfig();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
