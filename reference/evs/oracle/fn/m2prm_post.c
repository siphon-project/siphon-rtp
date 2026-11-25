/* Oracle for lib_dec/post_dec.c: post_decoder (whole decoder state), the static bass_pf_1sf_delay (direct)
 * and cldfb_synth_set_bandsToZero (whole decoder state). post_dec.c is included, so the static function is
 * reached directly.
 *
 * Domain. post_decoder runs after the MODE2 ACELP / TCX frame (update_decoder_LPD_cng, dec_acelp_tcx_frame):
 * L_frame 256 or 320 with 4 or 5 subframes for the ACELP-capable cores, 512 / 640 / 960 for TCX-only; old_synth_len
 * is 2 * L_frame; pitch lags are 12.8 / 16 kHz lags (34..289) and the bass post-filter gains Q14; the bandwidth
 * last_bwidth / bwidth is NB..FB; LP filters are the Q12 form a[0] = 4096. cldfb_synth_set_bandsToZero is the
 * AMR-WB IO bandwidth detector: 16 slots, the synthesis bank of 16, 32 or 60 channels. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "../../c-code/lib_dec/post_dec.c"

#include "m2prm_common.h"

static void random_pitches(Word16 *pitch, int n, int maximum)
{
    int base = random_range(34, maximum);
    for (int i = 0; i < n; i++) {
        int lag = next_random() % 4 == 0 ? random_range(34, maximum) : base + random_range(-3, 3);
        if (lag < 34) lag = 34;
        if (lag > maximum) lag = maximum;
        pitch[i] = (Word16)lag;
    }
}

static void case_bass_pf(void)
{
    static Word16 syn_buf[400 + 320 + 8], noise[320], t_sf[5], gain[5], factor[5];
    int l_frame = next_random() & 1 ? 256 : 320;
    int history = NBPSF_PIT_MAX;
    Word16 *syn = syn_buf + history;
    Word8 disable_bpf = (Word8)(next_random() % 5 == 0);
    Word32 lp_error_ener = (Word32)random_range(-(1 << 22), 1 << 22) * 16, mem_error = (Word32)random_range(-(1 << 24), 1 << 24);
    if (next_random() % 6 == 0) mem_error = 0;
    random_synthesis(syn_buf, history + l_frame);
    random_pitches(t_sf, 5, l_frame == 256 ? 231 : 289);
    for (int i = 0; i < 5; i++) {
        gain[i] = (Word16)(next_random() % 5 == 0 ? random_range(-2000, 0) : random_range(0, 16384));
        factor[i] = (Word16)random_range(0, 6);
    }
    for (int i = 0; i < 320; i++) noise[i] = 0x5a5a;
    put1("l_frame", l_frame); put1("disable_bpf", disable_bpf); put1("lp_error_ener", lp_error_ener); put1("mem_error", mem_error);
    put16("syn", syn_buf, history + l_frame); put16("t_sf", t_sf, 5); put16("gain", gain, 5); put16("factor", factor, 5);
    bass_pf_1sf_delay(syn, t_sf, gain, (Word16)l_frame, L_SUBFR, noise, factor, disable_bpf, &lp_error_ener, &mem_error);
    arrow(); put16("noise", noise, l_frame); put1("lp_error_ener", lp_error_ener); put1("mem_error", mem_error); end_line();
}

static void case_post_decoder(void)
{
    static Word16 synth_buf[OLD_SYNTH_SIZE_DEC + L_FRAME_MAX + M], out[L_FRAME_MAX], noise[L_FRAME_MAX], pit_gain[5], pitch[5];
    Decoder_State_fx *st = new_state();
    int kind = random_range(0, 3); /* 0: TCX-only, 1..3: ACELP-capable cores */
    static const int tcxonly_frames[] = {512, 640, 960};
    int l_frame = kind == 0 ? tcxonly_frames[next_random() % 3] : (next_random() & 1 ? 256 : 320);
    Word16 coder_type = (Word16)random_range(0, 6);
    st->tcxonly = (Word8)(kind == 0);
    st->L_frame_fx = (Word16)l_frame;
    st->nb_subfr = (Word16)(l_frame == 320 ? 5 : 4);
    st->old_synth_len = (Word16)(2 * l_frame);
    st->bwidth_fx = (Word16)random_range(NB, FB);
    st->last_bwidth_fx = (Word16)(next_random() % 4 ? st->bwidth_fx : random_range(NB, FB));
    st->pfstat.on = (Word16)(next_random() & 1);
    st->pfstat.reset = (Word16)(next_random() % 5 == 0);
    st->core_fx = (Word16)(next_random() % 3 ? ACELP_CORE : TCX_20_CORE);
    st->lp_noise = (Word32)random_range(0, 300) << 16;
    if (next_random() % 3 == 0) st->lp_noise = (Word32)random_range(160, 260) << 20;
    {
        static const Word32 rates[] = {9600, 16400, 24400, 32000, 48000, 96000, 128000};
        st->total_brate_fx = rates[next_random() % 7];
        st->last_active_brate_fx = rates[next_random() % 7];
        st->core_brate_fx = next_random() % 4 == 0 ? SID_2k40 : st->total_brate_fx;
    }
    st->preemph_fac = (Word16)random_range(20000, 30000);
    st->bpf_gain_param = (Word16)random_range(0, 6);
    st->narrowBand = (Word8)(next_random() % 4 == 0);
    st->BER_detect = (Word16)(next_random() % 8 == 0);
    random_lpc(st->old_Aq_12_8_fx);
    for (int i = 0; i < 5; i++) random_lpc(st->mem_Aq + i * (M + 1));
    random_synthesis(st->pst_old_syn_fx, NBPSF_PIT_MAX);
    random_signal(st->pfstat.mem_pf_in, 64, 12000);
    random_signal(st->pfstat.mem_stp, 64, 12000);
    random_signal(st->pfstat.mem_res2, 299, 12000);
    st->pfstat.gain_prec = (Word16)random_range(2000, 30000);
    st->lp_error_ener = (Word32)random_range(-(1 << 22), 1 << 22) * 16;
    st->mem_error = (Word32)random_range(-(1 << 24), 1 << 24);
    random_synthesis(synth_buf, st->old_synth_len + l_frame);
    random_pitches(pitch, 5, l_frame == 320 ? 289 : 231);
    for (int i = 0; i < 5; i++) pit_gain[i] = (Word16)(next_random() % 5 == 0 ? random_range(-2000, 0) : random_range(0, 16384));
    for (int i = 0; i < L_FRAME_MAX; i++) { noise[i] = 0x5a5a; out[i] = 0x4b4b; }
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("coder_type", coder_type); put1("l_frame", l_frame);
    put16("synth_buf", synth_buf, st->old_synth_len + l_frame); put16("pit_gain", pit_gain, 5); put16("pitch", pitch, 5);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    post_decoder(st, coder_type, synth_buf, pit_gain, pitch, out, noise);
    put16("synth_buf", synth_buf, st->old_synth_len + l_frame); put16("out", out, l_frame);
    put16("noise", noise, st->tcxonly ? 0 : l_frame);
    finish(st, before);
}

static void case_bands_to_zero(void)
{
    static Word32 real[16][60], imag[16][60];
    Word32 *r_rows[16], *i_rows[16];
    Decoder_State_fx *st = new_state();
    CLDFB_SCALE_FACTOR scale;
    memset(&scale, 0, sizeof scale);
    scale.lb_scale = (Word16)random_range(0, 8);
    st->VAD = (Word16)(next_random() % 5 != 0);
    st->ini_frame_fx = (Word16)random_range(0, 60);
    st->active_frame_cnt_bwddec = (Word16)random_range(0, 100);
    st->total_frame_cnt_bwddec = (Word16)random_range(0, 500);
    if (next_random() % 3 == 0) { st->active_frame_cnt_bwddec = (Word16)random_range(60, 100); st->total_frame_cnt_bwddec = (Word16)random_range(260, 500); }
    st->perc_bwddec = (Word16)(next_random() % 3 ? random_range(10000, 16384) : random_range(0, 16384));
    for (int i = 0; i < 20; i++) st->flag_buffer[i] = (Word16)(next_random() % 4 != 0);
    if (next_random() % 8 == 0) for (int i = 0; i < 20; i++) st->flag_buffer[i] = 0;
    st->last_flag_filter_NB = (Word16)(next_random() & 1);
    st->avg_nrg_LT = (Word32)(next_random() % 4 ? random_range(0, 1 << 24) : 0);
    st->last_active_bandsToZero_bwdec = (Word16)random_range(0, 12);
    st->cldfbSyn_fx->bandsToZero = (Word16)(next_random() % 3 ? 0 : random_range(0, 10));
    if (next_random() % 6 == 0) {
        /* on the detection thresholds, with the other hysteresis conditions open */
        st->perc_bwddec = (Word16)(next_random() & 1 ? 14746 : 13107);
        st->active_frame_cnt_bwddec = (Word16)random_range(60, 98);
        st->total_frame_cnt_bwddec = (Word16)random_range(260, 498);
        st->last_flag_filter_NB = (Word16)(st->perc_bwddec == 13107);
        for (int i = 0; i < 20; i++) st->flag_buffer[i] = 1;
        st->VAD = 1;
    }
    int strong = next_random() & 1;
    for (int k = 0; k < 16; k++) {
        for (int i = 0; i < 60; i++) {
            int band_shift = (i > 12 && strong) ? 14 : 4;
            real[k][i] = random32() >> random_range(band_shift, 24);
            imag[k][i] = random32() >> random_range(band_shift, 24);
        }
        r_rows[k] = real[k];
        i_rows[k] = imag[k];
    }
    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    put1("lb_scale", scale.lb_scale);
    Word32 flat[16 * 60];
    for (int k = 0; k < 16; k++) for (int i = 0; i < 60; i++) flat[k * 60 + i] = real[k][i];
    put32("real", flat, 16 * 60);
    for (int k = 0; k < 16; k++) for (int i = 0; i < 60; i++) flat[k * 60 + i] = imag[k][i];
    put32("imag", flat, 16 * 60);
    char *before = capture_state(st);
    put_state_in(before);
    arrow();
    cldfb_synth_set_bandsToZero(st, r_rows, i_rows, 16, scale);
    finish(st, before);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "bass_pf_1sf_delay")) case_bass_pf();
        else if (!strcmp(argv[2], "post_decoder")) case_post_decoder();
        else if (!strcmp(argv[2], "bands_to_zero")) case_bands_to_zero();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
