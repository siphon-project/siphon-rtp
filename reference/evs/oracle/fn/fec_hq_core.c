/* Function-level oracle for lib_dec/FEC_HQ_core_fx.c. The source is included so its static helpers
 * are reachable.
 *
 * hq_fec_mem_update: three consecutive good frames through one calloc'ed decoder state; every state
 * field the function reads is randomised and every field it writes is printed after each frame.
 *
 * nb_sequence: the 8 kHz-output frame loop of hq_core_dec_fx (good frames through HQ_FEC_Mem_update_fx,
 * lost frames through HQ_FEC_processing_fx, then time_domain_FEC_HQ_fx or window_ola_fx), eight frames
 * on one decoder, with the whole state printed before the sequence ("in.") and, around each call, as
 * the fields that differ from it ("fKa_pre." / "fKa." for the first call of frame K, "fKb_pre." /
 * "fKb." for the second).
 *
 * The array helpers (common_overlapping, the windowing and smoothing helpers, the phase matching and
 * repetition smoothing functions, Next_good_after_burst_erasures_fx) are called on random vectors.
 *
 * stream: HQ_FEC_processing_fx and time_domain_FEC_HQ_fx exactly as the reference decoder calls them
 * on a conformance bitstream (every call is recorded, with the whole state before it). */
#include <math.h>
#include <sys/resource.h>
/* the whole-state dump of init_dec.c (also brings harness.h and prot_fx.h) */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "stat_dec_fx.h"
#define HQ_FEC_processing_fx HQ_FEC_processing_fx_reference
#define time_domain_FEC_HQ_fx time_domain_FEC_HQ_fx_reference
#include "../../c-code/lib_dec/FEC_HQ_core_fx.c"
#undef HQ_FEC_processing_fx
#undef time_domain_FEC_HQ_fx
#include "stream_mode.h"

static void put_state(int f, const Decoder_State_fx *st)
{
    char name[32];
#define PUT16(field, n) sprintf(name, #field "%d", f); put16(name, st->field, n)
#define PUT1(field) sprintf(name, #field "%d", f); put1(name, st->field)
    PUT16(prev_sign_switch_fx, HQ_FEC_SIGN_SFM);
    PUT16(prev_sign_switch_2_fx, HQ_FEC_SIGN_SFM);
    sprintf(name, "old_coeffs_fx%d", f); put32(name, st->old_coeffs_fx, L_FRAME8k);
    sprintf(name, "ynrm_values_fx%d", f); put32(name, &st->ynrm_values_fx[0][0], MAX_SB_NB * MAX_PGF);
    PUT16(Norm_gain_fx, SFM_N_NB);
    PUT16(energy_MA_Curr_fx, 2);
    PUT1(diff_energy_fx);
    PUT1(stat_mode_old_fx);
    PUT1(stat_mode_out_fx);
    PUT1(old_Min_ind_fx);
    PUT1(phase_mat_flag_fx);
    PUT16(old_is_transient_fx, 3);
#undef PUT16
#undef PUT1
}

static void case_hq_fec_mem_update(void)
{
    static Decoder_State_fx *st;
    if (!st) st = calloc(1, sizeof(*st));
    memset(st, 0, sizeof(*st));
    for (int j = 0; j < HQ_FEC_SIGN_SFM; j++) {
        st->prev_sign_switch_fx[j] = (Word16)random_range(0, 4);
        st->prev_sign_switch_2_fx[j] = (Word16)random_range(0, 4);
    }
    for (int i = 0; i < L_FRAME8k; i++) st->old_coeffs_fx[i] = random_range(-(1 << 20), 1 << 20);
    for (int i = 0; i < MAX_SB_NB; i++)
        for (int j = 0; j < MAX_PGF; j++) st->ynrm_values_fx[i][j] = random_range(1, 1 << random_range(4, 24));
    for (int i = 0; i < SFM_N_NB; i++) st->Norm_gain_fx[i] = (Word16)random_range(0, 32767);
    st->energy_MA_Curr_fx[0] = (Word16)random_range(1, 3000);
    st->energy_MA_Curr_fx[1] = (Word16)random_range(1, 3000);
    st->diff_energy_fx = (Word16)random_range(0, 3000);
    st->stat_mode_old_fx = (Word16)random_range(0, 1);
    st->stat_mode_out_fx = (Word16)random_range(0, 1);
    st->old_Min_ind_fx = (Word16)random_range(0, 3);
    st->phase_mat_flag_fx = (Word16)random_range(0, 1);
    for (int i = 0; i < 3; i++) st->old_is_transient_fx[i] = (Word16)(next_random() % 4 == 0);
    put16("prev_sign_switch", st->prev_sign_switch_fx, HQ_FEC_SIGN_SFM);
    put16("prev_sign_switch_2", st->prev_sign_switch_2_fx, HQ_FEC_SIGN_SFM);
    put32("old_coeffs", st->old_coeffs_fx, L_FRAME8k);
    put32("ynrm_values", &st->ynrm_values_fx[0][0], MAX_SB_NB * MAX_PGF);
    put16("norm_gain", st->Norm_gain_fx, SFM_N_NB);
    put16("energy_ma_curr", st->energy_MA_Curr_fx, 2);
    put1("diff_energy", st->diff_energy_fx); put1("stat_mode_old", st->stat_mode_old_fx);
    put1("stat_mode_out", st->stat_mode_out_fx); put1("old_min_ind", st->old_Min_ind_fx);
    put1("phase_mat_flag", st->phase_mat_flag_fx); put16("old_is_transient", st->old_is_transient_fx, 3);

    Word32 t_audio[3][L_FRAME8k];
    Word16 ynrm_in[3][NB_SFM], is_transient[3], hqswb_clas[3], c_switching[3], hq_core_type[3], output_frame[3];
    Word16 bfi[3], prev_bfi[3], prev_old_bfi[3], last_core[3], core[3], prev_last_core[3];
    static const Word16 classes[] = {HQ_NORMAL, HQ_TRANSIENT, HQ_HARMONIC, HQ_HVQ};
    static const Word16 frames[] = {L_FRAME8k, L_FRAME8k, L_FRAME8k, L_FRAME16k, L_FRAME32k};
    for (int f = 0; f < 3; f++) {
        int magnitude = 1 << random_range(4, 24);
        for (int i = 0; i < L_FRAME8k; i++)
            t_audio[f][i] = (next_random() % 4) ? random_range(-magnitude, magnitude) : 0;
        for (int i = 0; i < NB_SFM; i++) ynrm_in[f][i] = (Word16)random_range(0, 39);
        is_transient[f] = (Word16)(next_random() % 4 == 0);
        hqswb_clas[f] = classes[next_random() % 4];
        c_switching[f] = (Word16)(next_random() % 6 == 0);
        hq_core_type[f] = (Word16)random_range(0, 1);
        output_frame[f] = frames[next_random() % 5];
        bfi[f] = (Word16)(next_random() % 6 == 0);
        prev_bfi[f] = (Word16)(next_random() % 6 == 0);
        prev_old_bfi[f] = (Word16)(next_random() % 6 == 0);
        last_core[f] = (Word16)(next_random() % 4 ? HQ_CORE : ACELP_CORE);
        core[f] = (Word16)(next_random() % 4 ? HQ_CORE : ACELP_CORE);
        prev_last_core[f] = (Word16)(next_random() % 4 ? HQ_CORE : ACELP_CORE);
        char name[32];
        sprintf(name, "t_audio%d", f); put32(name, t_audio[f], L_FRAME8k);
        sprintf(name, "ynrm%d", f); put16(name, ynrm_in[f], NB_SFM);
        sprintf(name, "is_transient%d", f); put1(name, is_transient[f]);
        sprintf(name, "hqswb_clas%d", f); put1(name, hqswb_clas[f]);
        sprintf(name, "c_switching%d", f); put1(name, c_switching[f]);
        sprintf(name, "hq_core_type%d", f); put1(name, hq_core_type[f]);
        sprintf(name, "output_frame%d", f); put1(name, output_frame[f]);
        sprintf(name, "bfi%d", f); put1(name, bfi[f]);
        sprintf(name, "prev_bfi%d", f); put1(name, prev_bfi[f]);
        sprintf(name, "prev_old_bfi%d", f); put1(name, prev_old_bfi[f]);
        sprintf(name, "last_core%d", f); put1(name, last_core[f]);
        sprintf(name, "core%d", f); put1(name, core[f]);
        sprintf(name, "prev_last_core%d", f); put1(name, prev_last_core[f]);
    }
    arrow();
    for (int f = 0; f < 3; f++) {
        Word32 normq[NB_SFM];
        Word16 num_bands_p[MAX_SB_NB] = {8, 8, 2}, mean_en_high = -77;
        for (int i = 0; i < NB_SFM; i++) normq[i] = -1;
        st->bfi_fx = bfi[f];
        st->prev_bfi_fx = prev_bfi[f];
        st->prev_old_bfi_fx = prev_old_bfi[f];
        st->last_core_fx = last_core[f];
        st->core_fx = core[f];
        st->prev_last_core_fx = prev_last_core[f];
        HQ_FEC_Mem_update_fx(st, t_audio[f], normq, ynrm_in[f], num_bands_p, is_transient[f], hqswb_clas[f],
                             c_switching[f], SFM_N_NB, MAX_SB_NB, &mean_en_high, hq_core_type[f], output_frame[f]);
        char name[32];
        sprintf(name, "normq%d", f); put32(name, normq, SFM_N_NB);
        sprintf(name, "ynrm%d", f); put16(name, ynrm_in[f], SFM_N_NB);
        sprintf(name, "mean_en_high%d", f); put1(name, mean_en_high);
        put_state(f, st);
    }
    end_line();
}


/* -------- HQ_FEC_processing_fx / time_domain_FEC_HQ_fx as the decoder calls them (stream mode) -------- */

void HQ_FEC_processing_fx(Decoder_State_fx *st, Word32 *t_audio_q, Word16 is_transient, Word32 ynrm_values[][MAX_PGF],
                          Word32 r_p_values[][MAX_ROW], Word16 num_Sb, Word16 nb_sfm, Word16 *num_bands_p,
                          Word16 output_frame, const Word16 *sfm_start, const Word16 *sfm_end)
{
    if (!stream_mode) {
        HQ_FEC_processing_fx_reference(st, t_audio_q, is_transient, ynrm_values, r_p_values, num_Sb, nb_sfm, num_bands_p,
                                       output_frame, sfm_start, sfm_end);
        return;
    }
    static Word32 audio_in[L_FRAME8k];
    memcpy(audio_in, t_audio_q, sizeof audio_in);
    char *before = capture_state(st);
    HQ_FEC_processing_fx_reference(st, t_audio_q, is_transient, ynrm_values, r_p_values, num_Sb, nb_sfm, num_bands_p,
                                   output_frame, sfm_start, sfm_end);
    if (stream_calls++ % stream_every == 0) {
        put1("output_fs", st->output_Fs_fx);
        put1("output_frame", st->output_frame_fx);
        put1("is_transient", is_transient);
        put1("num_sb", num_Sb);
        put1("nb_sfm", nb_sfm);
        put16("num_bands_p", num_bands_p, MAX_SB_NB);
        put16("sfm_start", sfm_start, nb_sfm);
        put16("sfm_end", sfm_end, nb_sfm);
        put1("call_output_frame", output_frame);
        put32("t_audio_in", audio_in, L_FRAME8k);
        put_state_in(before);
        arrow();
        put32("t_audio", t_audio_q, L_FRAME8k);
        char *after = capture_state(st);
        put_changed("st.", before, after);
        free(after);
        end_line();
    }
    free(before);
}

void time_domain_FEC_HQ_fx(Decoder_State_fx *st, Word32 *wtda_audio, Word16 *out, Word16 mean_en_high,
                           const Word16 output_frame, Word16 *Q_synth)
{
    if (!stream_mode) {
        time_domain_FEC_HQ_fx_reference(st, wtda_audio, out, mean_en_high, output_frame, Q_synth);
        return;
    }
    static Word32 wtda_in[2 * L_FRAME8k];
    static Word16 out_in[L_FRAME8k];
    memcpy(wtda_in, wtda_audio, sizeof wtda_in);
    memcpy(out_in, out, sizeof out_in);
    Word16 q_synth_in = *Q_synth;
    char *before = capture_state(st);
    time_domain_FEC_HQ_fx_reference(st, wtda_audio, out, mean_en_high, output_frame, Q_synth);
    if (stream_calls++ % stream_every == 0) {
        put1("output_fs", st->output_Fs_fx);
        put1("output_frame", st->output_frame_fx);
        put1("mean_en_high", mean_en_high);
        put1("call_output_frame", output_frame);
        put1("q_synth_in", q_synth_in);
        put32("wtda_in", wtda_in, 2 * L_FRAME8k);
        put16("out_in", out_in, L_FRAME8k);
        put_state_in(before);
        arrow();
        put16("out", out, L_FRAME8k);
        put1("q_synth", *Q_synth);
        char *after = capture_state(st);
        put_changed("st.", before, after);
        free(after);
        end_line();
    }
    free(before);
}

/* -------- nb_sequence -------- */

#define SEQUENCE_FRAMES 8

/* The memories a few good frames leave behind at 8 kHz output, as plausible signal. */
static void randomize_nb_memories(Decoder_State_fx *st)
{
    tonal16(st->old_out_fx, 480, 1 << random_range(8, 14));
    st->Q_old_wtda = (Word16)(next_random() % 3 == 0 ? random_range(1, 3) : 0);
    tonal16(&st->old_out_pha_fx[0][0], 2 * N_LEAD_NB, 1 << random_range(8, 13));
    tonal32(st->oldIMDCTout_fx, L_FRAME8k / 2, 1 << random_range(12, 22));
    tonal16(st->prev_oldauOut_fx, L_FRAME8k, 1 << random_range(8, 13));
    if (next_random() % 3) tonal16(st->old_auOut_2fr_fx, 2 * L_FRAME8k, 1 << random_range(8, 14));
    else for (int i = 0; i < 2 * L_FRAME8k; i++) st->old_auOut_2fr_fx[i] = (Word16)random_range(-3000, 3000);
    for (int i = 0; i < L_FRAME8k; i++) st->old_coeffs_fx[i] = random_range(-(1 << 20), 1 << 20);
    for (int i = 0; i < MAX_SB_NB; i++)
        for (int j = 0; j < MAX_PGF; j++) st->ynrm_values_fx[i][j] = random_range(1, 1 << random_range(4, 24));
    for (int i = 0; i < MAX_SB_NB; i++)
        for (int j = 0; j < MAX_ROW; j++) st->r_p_values_fx[i][j] = random_range(-(1 << 12), 1 << 12);
    for (int i = 0; i < SFM_N_NB; i++) st->Norm_gain_fx[i] = (Word16)random_range(0, 32767);
    st->energy_MA_Curr_fx[0] = (Word16)random_range(1, 3000);
    st->energy_MA_Curr_fx[1] = (Word16)random_range(1, 3000);
    st->diff_energy_fx = (Word16)random_range(0, 1500);
    st->stat_mode_old_fx = (Word16)(next_random() & 1);
    st->stat_mode_out_fx = (Word16)(next_random() % 3 == 0);
    st->old_Min_ind_fx = (Word16)random_range(0, 3);
    st->phase_mat_flag_fx = (Word16)(next_random() & 1);
    st->phase_mat_next_fx = (Word16)(next_random() % 5 == 0);
    for (int i = 0; i < 3; i++) st->old_is_transient_fx[i] = (Word16)(next_random() % 5 == 0);
    for (int j = 0; j < HQ_FEC_SIGN_SFM; j++) {
        st->prev_sign_switch_fx[j] = (Word16)random_range(0, 4);
        st->prev_sign_switch_2_fx[j] = (Word16)random_range(0, 4);
    }
    st->HQ_FEC_seed_fx = (Word16)random_range(-32768, 32767);
        st->last_core_fx = (Word16)(next_random() % 10 ? HQ_CORE : ACELP_CORE);
    st->prev_last_core_fx = (Word16)(next_random() % 10 ? HQ_CORE : ACELP_CORE);
    st->core_fx = HQ_CORE;
    st->last_codec_mode = (Word16)(next_random() % 10 ? MODE1 : MODE2);
    st->tcx_cfg.tcx_last_overlap_mode = ALDO_WINDOW;
    st->tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;
    st->oldHqVoicing_fx = (Word16)(next_random() & 1);
    tonal16(st->oldgapsynth_fx, L_FRAME48k, 1 << random_range(8, 13));
    st->bfi_fx = 0;
    st->prev_bfi_fx = (Word16)(next_random() % 4 == 0);
    st->prev_old_bfi_fx = (Word16)(next_random() % 4 == 0);
    st->nbLostCmpt = st->prev_bfi_fx;
}

/* A good frame's spectrum: decaying with frequency, sometimes sparse. */
static void random_spectrum(Word32 *t_audio)
{
    int magnitude = 1 << random_range(8, 22);
    for (int i = 0; i < L_FRAME8k; i++) {
        int envelope = magnitude / (1 + i / 8);
        t_audio[i] = next_random() % 5 ? random_range(-envelope, envelope) : 0;
    }
}

static void case_nb_sequence(void)
{
    static Word32 wtda_audio[2 * L_FRAME48k], t_audio_q[L_FRAME48k], normq[NB_SFM];
    static Word16 synth[L_FRAME48k];
    Decoder_State_fx *st = new_decoder(8000);
    randomize_nb_memories(st);
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    char *initial = capture_state(st);
    put_state_in(initial);

    Word16 num_bands_p[MAX_SB_NB], nb_sfm, num_Sb;
    const Word16 *sfmsize, *sfm_start, *sfm_end;
    hq_configure_bfi_fx(&nb_sfm, &num_Sb, num_bands_p, &sfmsize, &sfm_start, &sfm_end);
    int burst = 0;
    for (int f = 0; f < SEQUENCE_FRAMES; f++) {
        char name[48];
        Word16 bfi = (Word16)(burst ? next_random() % 3 != 0 : next_random() % 4 == 0);
        burst = bfi;
        /* the decoder's bookkeeping before the frame (evs_dec_fx / updt) */
        st->prev_old_bfi_fx = st->prev_bfi_fx;
        st->prev_bfi_fx = st->bfi_fx;
        st->bfi_fx = bfi;
        st->old_bfi_cnt_fx = st->nbLostCmpt; /* updt_dec_fx, at the end of the previous frame */
        st->nbLostCmpt = bfi ? add(st->nbLostCmpt, 1) : 0;
        Word16 is_transient = 0, mean_en_high = 0;
        Word16 ynrm[NB_SFM];
        for (int i = 0; i < NB_SFM; i++) ynrm[i] = 39;
        for (int i = 0; i < L_FRAME48k; i++) t_audio_q[i] = 0;

        sprintf(name, "f%d_bfi", f); put1(name, bfi);
        char *pre = capture_state(st);
        sprintf(name, "f%da_pre.", f); put_changed(name, initial, pre);
        free(pre);
        if (!bfi) {
            is_transient = (Word16)(next_random() % 5 == 0);
            random_spectrum(t_audio_q);
            for (int i = 0; i < NB_SFM; i++) ynrm[i] = (Word16)random_range(0, 39);
            sprintf(name, "f%d_t_audio", f); put32(name, t_audio_q, L_FRAME8k);
            sprintf(name, "f%d_ynrm", f); put16(name, ynrm, NB_SFM);
            sprintf(name, "f%d_is_transient", f); put1(name, is_transient);
            for (int i = 0; i < NB_SFM; i++) normq[i] = -1;
            HQ_FEC_Mem_update_fx(st, t_audio_q, normq, ynrm, num_bands_p, is_transient, is_transient, 0, nb_sfm, num_Sb,
                                 &mean_en_high, 0, L_FRAME8k);
            sprintf(name, "f%d_normq", f); put32(name, normq, SFM_N_NB);
            sprintf(name, "f%d_ynrm_out", f); put16(name, ynrm, SFM_N_NB);
            sprintf(name, "f%d_mean_en_high", f); put1(name, mean_en_high);
        } else {
            is_transient = st->old_is_transient_fx[0];
            HQ_FEC_processing_fx(st, t_audio_q, is_transient, st->ynrm_values_fx, st->r_p_values_fx, num_Sb, nb_sfm,
                                 num_bands_p, L_FRAME8k, sfm_start, sfm_end);
            st->old_is_transient_fx[2] = st->old_is_transient_fx[1];
            st->old_is_transient_fx[1] = st->old_is_transient_fx[0];
            sprintf(name, "f%d_is_transient", f); put1(name, is_transient);
            sprintf(name, "f%d_t_audio_out", f); put32(name, t_audio_q, L_FRAME8k);
        }
        char *post = capture_state(st);
        sprintf(name, "f%da.", f); put_changed(name, initial, post);
        free(post);

        /* the IMDCT output of the frame (the synthesis filterbank is not under test) */
        tonal32(wtda_audio, 2 * L_FRAME8k, 1 << random_range(14, 24));
        if (next_random() % 6 == 0) for (int i = 0; i < 2 * L_FRAME8k; i++) wtda_audio[i] = random32() >> random_range(0, 16);
        sprintf(name, "f%d_wtda", f); put32(name, wtda_audio, 2 * L_FRAME8k);
        /* hq_core_dec_fx before the time-domain stage */
        if (st->bfi_fx == 0 && st->prev_bfi_fx == 0)
            Copy_Scale_sig(st->old_out_fx + N_ZERO_NB, st->prev_oldauOut_fx, L_FRAME8k - N_ZERO_NB, negate(st->Q_old_wtda));
        else if (st->prev_bfi_fx == 1) set16_fx(st->prev_oldauOut_fx, 0, L_FRAME8k);
        Word16 q_synth = (Word16)random_range(0, 12);
        int time_domain = (st->prev_bfi_fx == 1 || st->bfi_fx == 1) && st->old_is_transient_fx[2] == 0 &&
                          st->last_core_fx == HQ_CORE && st->last_codec_mode == MODE1;
        for (int i = 0; i < L_FRAME48k; i++) synth[i] = -7;
        sprintf(name, "f%d_time_domain", f); put1(name, time_domain);
        sprintf(name, "f%d_mean_en_high_for_time_domain", f); put1(name, mean_en_high);
        sprintf(name, "f%d_q_synth_in", f); put1(name, q_synth);
        pre = capture_state(st);
        sprintf(name, "f%db_pre.", f); put_changed(name, initial, pre);
        free(pre);
        if (time_domain) {
            time_domain_FEC_HQ_fx(st, wtda_audio, synth, mean_en_high, L_FRAME8k, &q_synth);
        } else {
            window_ola_fx(wtda_audio, synth, &q_synth, st->old_out_fx, &st->Q_old_wtda, L_FRAME8k,
                          st->tcx_cfg.tcx_last_overlap_mode, st->tcx_cfg.tcx_curr_overlap_mode, st->prev_bfi_fx,
                          st->oldHqVoicing_fx, st->oldgapsynth_fx);
            st->phase_mat_next_fx = 0;
        }
        sprintf(name, "f%d_synth", f); put16(name, synth, L_FRAME8k);
        sprintf(name, "f%d_q_synth", f); put1(name, q_synth);
        post = capture_state(st);
        sprintf(name, "f%db.", f); put_changed(name, initial, post);
        free(post);
    }
    free(initial);
    arrow();
    end_line();
    destroy_decoder(st);
    free(st);
}

/* -------- the array helpers -------- */

static void fill_audio16(Word16 *x, int n)
{
    int mode = random_range(0, 3);
    if (mode == 0) tonal16(x, n, 1 << random_range(6, 14));
    else if (mode == 1) for (int i = 0; i < n; i++) x[i] = random16();
    else if (mode == 2) for (int i = 0; i < n; i++) x[i] = (Word16)random_range(-3000, 3000);
    else random_signal(x, n, random_range(1, 32767));
}

static void fill_imdct(Word32 *x, int n)
{
    int mode = random_range(0, 3);
    if (mode == 0) tonal32(x, n, 1 << random_range(10, 26));
    else if (mode == 1) for (int i = 0; i < n; i++) x[i] = random32();
    else if (mode == 2) for (int i = 0; i < n; i++) x[i] = random_range(-(1 << 22), 1 << 22);
    else for (int i = 0; i < n; i++) x[i] = random32() >> random_range(0, 24);
}

static void case_common_overlapping(void)
{
    static Word16 au_out[2 * L_FRAME8k], win[2 * L_FRAME8k + 50], old[2 * L_FRAME8k];
    Word16 end1 = (Word16)random_range(0, 80), offset1 = (Word16)random_range(0, 60), start2 = (Word16)random_range(0, 20);
    Word16 end2 = (Word16)random_range(0, 80), offset_i2 = (Word16)random_range(0, 100), offset2 = (Word16)random_range(0, 100);
    fill_audio16(win, 2 * L_FRAME8k + 50); fill_audio16(old, 2 * L_FRAME8k);
    for (int i = 0; i < 2 * L_FRAME8k; i++) au_out[i] = -7;
    put16("win", win, 2 * L_FRAME8k + 50); put16("old", old, 2 * L_FRAME8k);
    put1("end1", end1); put1("offset1", offset1); put1("start2", start2); put1("end2", end2);
    put1("offset_i2", offset_i2); put1("offset2", offset2);
    common_overlapping_fx(au_out, win, old, end1, offset1, start2, end2, offset_i2, offset2);
    arrow(); put16("au_out", au_out, 2 * L_FRAME8k); end_line();
}

static void case_smoothing_vector_nb(int scaledown)
{
    static Word16 old[L_FRAME8k + 40], win[L_FRAME8k + 40], smoothing[48], au_out[L_FRAME8k + 40];
    Word16 ol_size = (Word16)random_range(0, 24);
    fill_audio16(old, L_FRAME8k + 40); fill_audio16(win, L_FRAME8k + 40);
    for (int i = 0; i < 48; i++) smoothing[i] = (Word16)random_range(0, 32767);
    for (int i = 0; i < L_FRAME8k + 40; i++) au_out[i] = -7;
    put16("old", old, L_FRAME8k + 40); put16("win", win, L_FRAME8k + 40); put16("smoothing", smoothing, 48);
    put1("ol_size", ol_size);
    if (scaledown) Smoothing_vector_scaledown_NB_fx(old, win, smoothing, au_out, ol_size);
    else Smoothing_vector_NB_fx(old, win, smoothing, au_out, ol_size);
    arrow(); put16("au_out", au_out, L_FRAME8k + 40); end_line();
}

static void case_windowing_1st_nb(void)
{
    static Word16 out[2 * L_FRAME8k], win[L_FRAME8k + 25], smoothing[80];
    static Word32 imdct[2 * L_FRAME8k];
    int with_smoothing = (int)(next_random() & 1);
    fill_imdct(imdct, 2 * L_FRAME8k); fill_audio16(win, L_FRAME8k + 25);
    for (int i = 0; i < 80; i++) smoothing[i] = (Word16)random_range(0, 32767);
    for (int i = 0; i < 2 * L_FRAME8k; i++) out[i] = -7;
    put32("imdct", imdct, 2 * L_FRAME8k); put16("win", win, L_FRAME8k + 25); put16("smoothing", smoothing, 80);
    put1("with_smoothing", with_smoothing);
    Windowing_1st_NB_fx(out, imdct, win, with_smoothing ? smoothing : NULL, (Word16)with_smoothing);
    arrow(); put16("out", out, 2 * L_FRAME8k); end_line();
}

static void case_windowing_2nd_nb(void)
{
    static Word16 out[2 * L_FRAME8k], win[L_FRAME8k + 25];
    static Word32 imdct[2 * L_FRAME8k];
    fill_imdct(imdct, 2 * L_FRAME8k); fill_audio16(win, L_FRAME8k + 25);
    for (int i = 0; i < 2 * L_FRAME8k; i++) out[i] = (Word16)random_range(-9, 9);
    put32("imdct", imdct, 2 * L_FRAME8k); put16("win", win, L_FRAME8k + 25); put16("out_in", out, 2 * L_FRAME8k);
    Windowing_2nd_NB_fx(out, imdct, win);
    arrow(); put16("out", out, 2 * L_FRAME8k); end_line();
}

static void case_scaledown(void)
{
    static Word16 x[L_FRAME8k], y[L_FRAME8k];
    Word16 scale = random16(), n = (Word16)random_range(0, L_FRAME8k);
    fill_audio16(x, L_FRAME8k);
    for (int i = 0; i < L_FRAME8k; i++) y[i] = -7;
    put16("x", x, L_FRAME8k); put1("scale", scale); put1("n", n);
    Scaledown_fx(x, y, scale, n);
    arrow(); put16("y", y, L_FRAME8k); end_line();
}

static void case_next_good_after_burst(void)
{
    static Word16 au_out[L_FRAME8k], old[L_FRAME8k];
    static Word32 imdct[2 * L_FRAME8k];
    Word16 ol_size = N_LEAD_NB;
    fill_imdct(imdct, 2 * L_FRAME8k); fill_audio16(old, L_FRAME8k);
    for (int i = 0; i < L_FRAME8k; i++) au_out[i] = -7;
    put32("imdct", imdct, 2 * L_FRAME8k); put16("old", old, L_FRAME8k); put1("ol_size", ol_size);
    Next_good_after_burst_erasures_fx(imdct, au_out, old, ol_size);
    arrow(); put16("au_out", au_out, L_FRAME8k); put16("old", old, L_FRAME8k); end_line();
}

static void case_phase_matching_nextgood(int burst)
{
    static Word16 au_out[L_FRAME8k], old[L_FRAME8k], prev_old[L_FRAME8k], pha[2][N_LEAD_NB];
    static Word32 imdct[2 * L_FRAME8k];
    Word16 mean_en_high = (Word16)random_range(0, 30);
    fill_imdct(imdct, 2 * L_FRAME8k); fill_audio16(old, L_FRAME8k); fill_audio16(prev_old, L_FRAME8k);
    tonal16(&pha[0][0], 2 * N_LEAD_NB, 1 << random_range(6, 13));
    for (int i = 0; i < L_FRAME8k; i++) au_out[i] = -7;
    put32("imdct", imdct, 2 * L_FRAME8k); put16("old", old, L_FRAME8k); put16("prev_old", prev_old, L_FRAME8k);
    put16("pha", &pha[0][0], 2 * N_LEAD_NB); put1("mean_en_high", mean_en_high);
    if (burst) FEC_phase_matching_burst_fx(imdct, au_out, old, pha, prev_old);
    else FEC_phase_matching_nextgood_fx(imdct, au_out, old, pha, mean_en_high);
    arrow(); put16("au_out", au_out, L_FRAME8k); put16("old", old, L_FRAME8k); put16("prev_old", prev_old, L_FRAME8k);
    put16("pha", &pha[0][0], 2 * N_LEAD_NB); end_line();
}

static void case_repetition_smoothing(int nextgood)
{
    static Word16 au_out[L_FRAME8k], old[L_FRAME8k], prev_old[L_FRAME8k];
    static Word32 imdct[2 * L_FRAME8k], old_imdct[L_FRAME8k / 2];
    Word16 flag = (Word16)(next_random() & 1), overlap_time = N_LEAD_NB, ret = -7;
    fill_imdct(imdct, 2 * L_FRAME8k); fill_imdct(old_imdct, L_FRAME8k / 2);
    fill_audio16(old, L_FRAME8k); fill_audio16(prev_old, L_FRAME8k);
    for (int i = 0; i < L_FRAME8k; i++) au_out[i] = -7;
    put32("imdct", imdct, 2 * L_FRAME8k); put32("old_imdct", old_imdct, L_FRAME8k / 2);
    put16("old", old, L_FRAME8k); put16("prev_old", prev_old, L_FRAME8k); put1("flag", flag);
    if (nextgood) Repetition_smoothing_nextgood_fx(imdct, au_out, old_imdct, old, flag, overlap_time);
    else ret = Repetition_smoothing_fx(imdct, au_out, old_imdct, old, L_FRAME8k, prev_old, overlap_time);
    arrow(); put1("ret", ret); put16("au_out", au_out, L_FRAME8k); put16("old", old, L_FRAME8k);
    put16("prev_old", prev_old, L_FRAME8k); end_line();
}

static void case_regression_anal(void)
{
    Word32 values[MAX_PGF], r_p[2] = {-7, -7};
    Word16 num_pgf = (Word16)(next_random() & 1 ? 4 : 2);
    for (int i = 0; i < MAX_PGF; i++) values[i] = random_range(1, 1 << random_range(4, 24));
    put32("values", values, MAX_PGF); put1("num_pgf", num_pgf);
    Regression_Anal_fx(values, r_p, num_pgf);
    arrow(); put32("r_p", r_p, 2); end_line();
}

static void case_fec_scaling(void)
{
    static Word32 old_coeffs[L_FRAME8k], t_audio[L_FRAME8k];
    Word16 norm_gain[SFM_N_NB], seed = random16(), num_bands_p[MAX_SB_NB], nb_sfm, num_Sb;
    const Word16 *sfmsize, *sfm_start, *sfm_end;
    hq_configure_bfi_fx(&nb_sfm, &num_Sb, num_bands_p, &sfmsize, &sfm_start, &sfm_end);
    for (int i = 0; i < L_FRAME8k; i++) { old_coeffs[i] = random_range(-(1 << 22), 1 << 22); t_audio[i] = -7; }
    for (int i = 0; i < SFM_N_NB; i++) norm_gain[i] = (Word16)random_range(0, 32767);
    put32("old_coeffs", old_coeffs, L_FRAME8k); put16("norm_gain", norm_gain, SFM_N_NB); put1("seed", seed);
    put1("nb_sfm", nb_sfm); put16("start", sfm_start, nb_sfm); put16("end", sfm_end, nb_sfm);
    FEC_scaling_fx(old_coeffs, t_audio, norm_gain, &seed, nb_sfm, sfm_start, sfm_end);
    arrow(); put32("t_audio", t_audio, L_FRAME8k); put1("seed", seed); end_line();
}

static void case_find_best_delay(void)
{
    static Word16 mu_o[2 * L_FRAME8k + MAXDELAY_FEC];
    Word16 delta = (Word16)random_range(1, 4), mind1 = (Word16)random_range(0, 20), lin = (Word16)random_range(8, 80);
    Word16 maxd1 = (Word16)(mind1 + random_range(1, 40) * delta), false_flag = -7;
    Word16 in_at = (Word16)random_range(0, L_FRAME8k + 60);
    fill_audio16(mu_o, 2 * L_FRAME8k + MAXDELAY_FEC);
    /* quiet and silent signals: the correlations the search compares are then tiny or exactly zero */
    switch (next_random() % 5) {
    case 0: for (int i = 0; i < 2 * L_FRAME8k + MAXDELAY_FEC; i++) mu_o[i] = (Word16)random_range(-3, 3); break;
    case 1: for (int i = 0; i < lin && in_at + i < 2 * L_FRAME8k + MAXDELAY_FEC; i++) mu_o[in_at + i] = 0; break;
    case 2: for (int i = 0; i < lin && in_at + i < 2 * L_FRAME8k + MAXDELAY_FEC; i++) mu_o[in_at + i] = (Word16)random_range(-1, 1); break;
    default: break;
    }
    put16("mu_o", mu_o, 2 * L_FRAME8k + MAXDELAY_FEC); put1("in_at", in_at);
    put1("mind1", mind1); put1("maxd1", maxd1); put1("lin", lin); put1("delta", delta);
    Word16 d1m = find_best_delay_fx(mu_o, mu_o + in_at, mind1, maxd1, lin, delta, &false_flag);
    arrow(); put1("d1m", d1m); put1("false_flag", false_flag); end_line();
}

static void case_search_max_corr(void)
{
    static Word16 mu_o[2 * L_FRAME8k];
    Word16 old_min_ind = (Word16)random_range(0, 3);
    fill_audio16(mu_o, 2 * L_FRAME8k);
    put16("mu_o", mu_o, 2 * L_FRAME8k); put1("old_min_ind", old_min_ind);
    Word16 pos = Search_Max_Corr_fx(mu_o, old_min_ind, L_FRAME8k);
    arrow(); put1("pos", pos); end_line();
}

int main(int argc, char **argv)
{
    /* a crash must not pop up a core-dump report: no core files */
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
    if (argc == 5 && !strcmp(argv[1], "stream")) { stream(argv[2], atol(argv[3]), atol(argv[4])); return 0; }
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        const char *f = argv[2];
        if (!strcmp(f, "hq_fec_mem_update")) case_hq_fec_mem_update();
        else if (!strcmp(f, "nb_sequence")) case_nb_sequence();
        else if (!strcmp(f, "common_overlapping")) case_common_overlapping();
        else if (!strcmp(f, "smoothing_vector_nb")) case_smoothing_vector_nb(0);
        else if (!strcmp(f, "smoothing_vector_scaledown_nb")) case_smoothing_vector_nb(1);
        else if (!strcmp(f, "windowing_1st_nb")) case_windowing_1st_nb();
        else if (!strcmp(f, "windowing_2nd_nb")) case_windowing_2nd_nb();
        else if (!strcmp(f, "scaledown")) case_scaledown();
        else if (!strcmp(f, "next_good_after_burst_erasures")) case_next_good_after_burst();
        else if (!strcmp(f, "fec_phase_matching_nextgood")) case_phase_matching_nextgood(0);
        else if (!strcmp(f, "fec_phase_matching_burst")) case_phase_matching_nextgood(1);
        else if (!strcmp(f, "repetition_smoothing_nextgood")) case_repetition_smoothing(1);
        else if (!strcmp(f, "repetition_smoothing")) case_repetition_smoothing(0);
        else if (!strcmp(f, "regression_anal")) case_regression_anal();
        else if (!strcmp(f, "fec_scaling")) case_fec_scaling();
        else if (!strcmp(f, "find_best_delay")) case_find_best_delay();
        else if (!strcmp(f, "search_max_corr")) case_search_max_corr();
        else { fprintf(stderr, "unknown function %s\n", f); return 2; }
    }
    return 0;
}
