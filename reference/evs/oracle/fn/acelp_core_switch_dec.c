/* Function-level oracle for lib_dec/acelp_core_switch_dec_fx.c (acelp_core_switch_dec_fx and,
 * through it, the file-local decod_gen_voic_core_switch_fx; acelp_core_switch_dec_bfi_fx).
 *
 * Each case builds a decoder with init_decoder_fx at a random output rate, then randomises the
 * per-frame state the switching frame reads (the previous frame's core, frame length and rate,
 * the excitation and LP memories, the synthesis Q values, the post-filter, bass post-filter and
 * FD-CNG noise state, the CLDFB filter states, the bit-stream position and the bits). It prints
 * the WHOLE state before the call (prefix "in."), the bits and the caller's buffers, and after the
 * call the outputs and every state field that changed (prefix "st."), with the generated dump of
 * init_dec.c; the test overlays the changes on the "before" state and compares the whole state,
 * so every field the function writes is compared, and every field it should not.
 *
 * acelp_core_switch_dec_bfi_fx (the switching frame lost) gets the same randomised synthesis
 * state plus the concealment state of conceal_state.h (every class and coder type of the last
 * good frame, GSC and AMR-WB IO included) and, now and then, a NELP last frame. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "conceal_state.h"

#define NBITS 1400

static UWord16 bits[2 * MAX_BITS_PER_FRAME + 16];

static const Word32 out_rates[4] = {8000, 16000, 32000, 48000};
static const Word32 brates_12k8[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000, 64000};
static const Word32 brates_16k[] = {8000, 14800, 16400, 22600, 24400, 32000, 48000, 64000};

/* A stable order-16 A(z) in Q12 from random reflection coefficients (step-up recursion). */
static void random_lpc(Word16 *a)
{
    double k[M], c[M + 1], t[M + 1];
    for (int i = 0; i < M; i++) k[i] = ((int)(next_random() % 1801) - 900) / 1000.0 * (i < 2 ? 1.0 : 0.6);
    c[0] = 1.0;
    for (int m = 1; m <= M; m++) {
        for (int i = 1; i < m; i++) t[i] = c[i] + k[m - 1] * c[m - i];
        for (int i = 1; i < m; i++) c[i] = t[i];
        c[m] = k[m - 1];
    }
    a[0] = 4096;
    for (int i = 1; i <= M; i++) {
        double v = c[i] * 4096.0;
        a[i] = (Word16)(v > 32767 ? 32767 : v < -32768 ? -32768 : (v < 0 ? v - 0.5 : v + 0.5));
    }
}

/* the arguments the FD-CNG configuration was last given (the Rust side repeats it, as the ROM
 * pointers it sets are not in the loadable dump) */
static Word32 cna_brate;
static Word16 cna_l_frame;

static void randomise(Decoder_State_fx *st, Word16 *core_switching_flag)
{
    int mag;

    *core_switching_flag = (Word16)(next_random() % 8 != 0);
    st->last_L_frame_fx = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    st->last_L_frame_ori_fx = (next_random() % 8 == 0) ? (Word16)(L_FRAME + L_FRAME16k - st->last_L_frame_fx) : st->last_L_frame_fx;
    st->L_frame_fx = st->last_L_frame_fx;
    {
        int r = next_random() % 10;
        st->last_core_fx = r < 7 ? ACELP_CORE : r < 9 ? AMR_WB_CORE : HQ_CORE;
    }
    st->core_brate_fx = st->last_L_frame_fx == L_FRAME ? brates_12k8[next_random() % 8] : brates_16k[next_random() % 8];
    st->total_brate_fx = st->core_brate_fx;
    st->bwidth_fx = (Word16)(next_random() % 4);
    st->last_bwidth_fx = (Word16)(next_random() % 4);
    st->Opt_AMR_WB_fx = (Word16)(next_random() % 8 == 0);
    st->BER_detect = (Word16)(next_random() % 8 == 0);

    /* excitation and LP memories */
    mag = (next_random() & 1) ? 16000 : 1500;
    random_signal(st->old_exc_fx, L_EXC_MEM_DEC, mag);
    random_lpc(st->old_Aq_12_8_fx);
    st->Q_exc = (Word16)random_range(0, 8);
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)random_range(0, 8);
    st->prev_Q_syn = (Word16)random_range(0, 4);
    st->Q_syn = (Word16)random_range(-1, 4);
    random_signal(st->mem_syn2_fx, M, 3000);
    random_signal(st->mem_syn_clas_estim_fx, L_SYN_MEM_CLAS_ESTIM, 3000);
    st->mem_deemph_fx = (Word16)random_range(-8000, 8000);
    st->agc_mem_fx[0] = (Word16)random_range(-4000, 4000);
    st->agc_mem_fx[1] = (Word16)random_range(-4000, 4000);
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    st->prev_bfi_fx = (Word16)(next_random() % 4 == 0);
    st->lp_gainc_fx = (Word16)random_range(0, 20000);
    st->old_Es_pred_fx = (Word16)random_range(-2000, 15000);
    random_signal(st->last_exc_dct_in_fx, L_FRAME, 3000);
    for (int i = 0; i < GAIN_PRED_ORDER; i++) st->past_qua_en_fx[i] = (Word16)random_range(-14336, 3000);

    /* post-filter */
    st->pfstat.on = (Word16)(next_random() & 1);
    st->pfstat.reset = (Word16)(next_random() % 8 == 0);
    mag = (next_random() & 1) ? 20000 : 2000;
    random_signal(st->pfstat.mem_pf_in, L_SUBFR, mag);
    random_signal(st->pfstat.mem_stp, L_SUBFR, mag);
    random_signal(st->pfstat.mem_res2, DECMEM_RES2, mag);
    st->pfstat.gain_prec = (Word16)random_range(0, 20000);
    st->psf_lp_noise_fx = (Word16)random_range(0, 10000);

    /* bass post-filter */
    st->bpf_off_fx = (Word16)(next_random() % 4 == 0);
    st->stab_fac_fx = (Word16)random_range(0, 32767);
    st->stab_fac_smooth_fx = (Word16)random_range(0, 32767);
    random_signal(st->pst_old_syn_fx, NBPSF_PIT_MAX, 3000);
    st->pst_mem_deemp_err_fx = (Word16)random_range(-3000, 3000);
    st->pst_lp_ener_fx = (Word16)random_range(0, 8000);
    for (int i = 0; i < L_TRACK_HIST; i++) {
        st->mem_mean_pit_fx[i] = (Word16)random_range(34 * 64 / 64, 231);
        st->Track_on_hist_fx[i] = (Word16)(next_random() & 1);
        st->vibrato_hist_fx[i] = (Word16)(next_random() & 1);
    }
    st->psf_att_fx = (Word16)random_range(0, 32767);

    /* CLDFB filter states (history of the earlier frames) */
    {
        HANDLE_CLDFB_FILTER_BANK banks[3] = {st->cldfbAna_fx, st->cldfbBPF_fx, st->cldfbSyn_fx};
        for (int b = 0; b < 3; b++) {
            if (next_random() & 1) random_signal(banks[b]->FilterStates, rd_cldfb_states_length(banks[b]), 2000);
            for (int i = 0; i < CLDFB_NO_COL_MAX + 9; i++) banks[b]->FilterStates_e[i] = (Word16)random_range(0, 3);
            banks[b]->FilterStates_eg = (Word16)random_range(0, 3);
        }
    }

    /* the high band of the previous frame */
    random_signal(st->old_synth_sw_fx, NS2SA(48000, FRAME_SIZE_NS - ACELP_LOOK_NS - DELAY_BWE_TOTAL_NS), (next_random() & 1) ? 20000 : 1000);

    /* FD-CNG masking noise */
    st->flag_cna = (Word16)(next_random() % 3 == 0);
    if (st->flag_cna) {
        HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
        HANDLE_FD_CNG_COM com = hs->hFdCngCom;
        configureFdCngDec(hs, st->bwidth_fx == NB ? NB : WB, st->core_brate_fx, st->last_L_frame_fx);
        cna_brate = st->core_brate_fx;
        cna_l_frame = st->last_L_frame_fx;
        for (int i = 0; i < FFTCLDFBLEN; i++) com->cngNoiseLevel[i] = (Word32)((next_random() & 0x7fffffff) >> random_range(4, 31));
        com->cngNoiseLevelExp = (Word16)random_range(-4, 8);
        com->seed = random16();
        com->likelihood_noisy_speech = (Word16)random_range(0, 32767);
        random_signal(hs->olapBufferSynth2, FFTLEN, 2000);
    }

    /* the bit stream */
    for (int i = 0; i < NBITS; i++) bits[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bits;
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    /* the frame's bit count; now and then too few, so the reads run out (BER_detect) */
    st->total_num_bits = (Word16)(next_random() % 16 ? st->total_brate_fx / 50 : random_range(0, 120));
}

static void case_acelp_core_switch_dec(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 core_switching_flag, q_syn = (Word16)random_range(-3, 3);
    Word16 synth_subfr_out[SWITCH_MAX_GAP], tmp_synth_bwe[SWITCH_MAX_GAP], mem_synth[NS2SA(16000, DELAY_CLDFB_NS) + 2];

    st->output_Fs_fx = out_rates[next_random() % 4];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    randomise(st, &core_switching_flag);
    random_signal(synth_subfr_out, SWITCH_MAX_GAP, 1000);
    random_signal(tmp_synth_bwe, SWITCH_MAX_GAP, 1000);
    random_signal(mem_synth, NS2SA(16000, DELAY_CLDFB_NS) + 2, 1000);

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("core_switching_flag", core_switching_flag);
    put1("cna_bandwidth", st->bwidth_fx == NB ? NB : WB);
    put1("q_syn", q_syn);
    put16("synth_subfr_out", synth_subfr_out, SWITCH_MAX_GAP);
    put16("tmp_synth_bwe", tmp_synth_bwe, SWITCH_MAX_GAP);
    put16("mem_synth", mem_synth, NS2SA(16000, DELAY_CLDFB_NS) + 2);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);

    acelp_core_switch_dec_fx(st, synth_subfr_out, tmp_synth_bwe, st->output_frame_fx, core_switching_flag, mem_synth, &q_syn);

    arrow();
    put16("synth_subfr_out", synth_subfr_out, SWITCH_MAX_GAP);
    put16("tmp_synth_bwe", tmp_synth_bwe, SWITCH_MAX_GAP);
    put16("mem_synth", mem_synth, NS2SA(16000, DELAY_CLDFB_NS) + 2);
    put1("q_syn", q_syn);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void case_acelp_core_switch_dec_bfi(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 core_switching_flag, synth_out[L_FRAME48k];

    st->output_Fs_fx = out_rates[next_random() % 4];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    randomise(st, &core_switching_flag);
    Word16 cna_bandwidth = (Word16)(st->bwidth_fx == NB ? NB : WB);
    conceal_randomise(st, 1);

    /* SC-VBR: a NELP last frame now and then (NB / WB only), with its filter memories */
    st->last_nelp_mode_dec_fx = (Word16)(st->L_frame_fx == L_FRAME && !st->Opt_AMR_WB_fx && st->bwidth_fx != FB && next_random() % 4 == 0);
    st->nelp_mode_dec_fx = (Word16)(st->last_nelp_mode_dec_fx && next_random() % 2);
    st->last_bwidth_fx = (next_random() % 4) ? st->bwidth_fx : (Word16)random_range(NB, SWB);
    for (int i = 0; i < 14; i++) st->bp1_filt_mem_nb_dec_fx[i] = (next_random() & 1) ? (Word32)random_range(-200000, 200000) << random_range(0, 10) : 0;
    random_signal(st->bp1_filt_mem_wb_dec_fx, 8, 2000);
    random_signal(st->shape1_filt_mem_dec_fx, 10, 2000);
    random_signal(st->shape2_filt_mem_dec_fx, 10, 2000);
    random_signal(st->shape3_filt_mem_dec_fx, 10, 2000);
    st->nelp_dec_seed_fx = random16();
    random_signal(st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2, 2000);

    Word16 coder_type = (Word16)((next_random() % 3) ? (st->last_nelp_mode_dec_fx ? UNVOICED : GENERIC) : random_range(INACTIVE, AUDIO));
    for (int i = 0; i < L_FRAME48k; i++) synth_out[i] = -3;

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("cna_bandwidth", cna_bandwidth);
    put1("cna_brate", cna_brate);
    put1("cna_l_frame", cna_l_frame);
    put1("coder_type", coder_type);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);

    acelp_core_switch_dec_bfi_fx(st, synth_out, coder_type);

    arrow();
    put16("synth_out", synth_out, L_FRAME48k);
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
        if (!strcmp(argv[2], "acelp_core_switch_dec")) case_acelp_core_switch_dec();
        else if (!strcmp(argv[2], "acelp_core_switch_dec_bfi")) case_acelp_core_switch_dec_bfi();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
