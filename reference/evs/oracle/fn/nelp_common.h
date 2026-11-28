/* Shared driver of the NELP oracles (nelp_dec.c, dec_nelp.c): a decoder built by init_decoder_fx
 * whose NELP state is randomised, run over a short sequence of good frames followed by lost ones
 * (bfi = 1), the way the decoder meets them: the excitation history carries from frame to frame,
 * and between frames last_nelp_mode_dec = 1 and last_bwidth = bwidth (updt_dec); the state after
 * the last frame is left as the function wrote it. Include after init_dec.c and state_capture.h. */
#ifndef EVS_ORACLE_NELP_COMMON_H
#define EVS_ORACLE_NELP_COMMON_H

#define NELP_NBITS 400
#define NELP_MAX_FRAMES 6

static UWord16 nelp_bits[2 * MAX_BITS_PER_FRAME + 16];

static const Word32 nelp_out_rates[4] = {8000, 16000, 32000, 48000};

typedef struct {
    Word16 frames;
    Word16 bfi[NELP_MAX_FRAMES];
    Word16 coder_type;
    Word16 q_exc;
    Word16 exc_history[L_SUBFR];
} NelpSequence;

/* Build and randomise the decoder; print the inputs (whole state with prefix "in."). */
static Decoder_State_fx *nelp_setup(NelpSequence *seq, char **before)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = nelp_out_rates[next_random() % 4];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);

    /* NELP runs at NB and WB (SWB uses the WB tables); FB has no NELP codebook */
    st->bwidth_fx = (Word16)random_range(NB, SWB);
    st->last_bwidth_fx = (next_random() % 4) ? st->bwidth_fx : (Word16)random_range(NB, FB);
    st->last_nelp_mode_dec_fx = (Word16)(next_random() & 1);
    seq->coder_type = (next_random() % 5) ? UNVOICED : (Word16)random_range(0, 7);

    for (int i = 0; i < 14; i++) st->bp1_filt_mem_nb_dec_fx[i] = (next_random() & 1) ? (Word32)random_range(-200000, 200000) << random_range(0, 10) : 0;
    random_signal(st->bp1_filt_mem_wb_dec_fx, 8, (next_random() & 1) ? 3000 : 200);
    random_signal(st->shape1_filt_mem_dec_fx, 10, (next_random() & 1) ? 3000 : 200);
    random_signal(st->shape2_filt_mem_dec_fx, 10, (next_random() & 1) ? 3000 : 200);
    random_signal(st->shape3_filt_mem_dec_fx, 10, (next_random() & 1) ? 3000 : 200);
    st->nelp_dec_seed_fx = random16();
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    for (int i = 0; i < NB_SUBFR16k; i++) st->tilt_code_dec_fx[i] = (Word16)random_range(0, 16384);
    st->dm_fx.prev_state = (Word16)random_range(0, 2);
    for (int i = 0; i < 6; i++) st->dm_fx.prev_gain_pit[i] = (Word16)random_range(0, 16384);
    st->prev_gain_pit_dec_fx = (Word16)random_range(0, 16384);

    /* channel-aware partial copy now and then */
    st->use_partial_copy = (Word16)(next_random() % 4 == 0);
    st->rf_frame_type = (next_random() & 1) ? RF_NELP : (Word16)random_range(0, 7);
    st->rf_indx_nelp_iG1 = (Word16)random_range(0, 31);
    st->rf_indx_nelp_iG2[0] = (Word16)random_range(0, 63);
    st->rf_indx_nelp_iG2[1] = (Word16)random_range(0, 63);
    st->rf_indx_nelp_fid = (Word16)random_range(0, 3);

    /* the frame sequence: some good frames, then some lost ones */
    {
        int good = random_range(0, 3), bad = random_range(0, 3);
        if (good + bad == 0) bad = 1;
        seq->frames = (Word16)(good + bad);
        for (int f = 0; f < seq->frames; f++) seq->bfi[f] = (Word16)(f >= good);
    }

    /* the excitation of the last subframe before the sequence, and its Q */
    {
        int mag = (next_random() % 3) ? random_range(200, 16000) : random_range(0, 40);
        random_signal(seq->exc_history, L_SUBFR, mag);
        if (next_random() % 16 == 0) memset(seq->exc_history, 0, sizeof(seq->exc_history));
        seq->q_exc = (Word16)random_range(0, 8);
    }

    for (int i = 0; i < NELP_NBITS; i++) nelp_bits[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = nelp_bits;
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)((next_random() % 16) ? NELP_NBITS : random_range(0, 60));

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("frames", seq->frames);
    put16("bfi", seq->bfi, seq->frames);
    put1("coder_type", seq->coder_type);
    put1("q_exc", seq->q_exc);
    put16("exc_history", seq->exc_history, L_SUBFR);
    put_u16("bits", nelp_bits, NELP_NBITS);
    *before = capture_state(st);
    put_state_in(*before);
    return st;
}

/* After a frame: the decoder's own updates the next frame reads. */
static void nelp_next_frame(Decoder_State_fx *st, Word16 *exc_buf)
{
    memmove(exc_buf, exc_buf + L_FRAME, L_SUBFR * sizeof(Word16));
    st->last_nelp_mode_dec_fx = 1;
    st->last_bwidth_fx = st->bwidth_fx;
}

static void nelp_finish(Decoder_State_fx *st, char *before)
{
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

#endif
