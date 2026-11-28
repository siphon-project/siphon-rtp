/* The ACELP concealment state of a decoder after some good frames, for the oracles of the frame
 * loss concealment (FEC.c, acelp_core_switch_dec.c): the class and coder type of the last good
 * frame, the LSF and pitch memories, the concealment gains and seeds, the GSC memories and an
 * excitation history that repeats the last pitch, at the MODE1 rates of both internal sampling
 * rates and in AMR-WB IO mode. Values follow what the decoder writes there, so the concealment
 * meets the cases it meets on a real loss (pulse resynchronisation, GSC replication, fading).
 * Include after harness.h / init_dec.c. */
#ifndef EVS_ORACLE_CONCEAL_STATE_H
#define EVS_ORACLE_CONCEAL_STATE_H

/* An ordered LSF vector (Q(x2.56)) below top. */
static void conceal_lsf(Word16 *lsf, int top)
{
    int pos = 0;
    for (int i = 0; i < M; i++) {
        pos += random_range(top / (3 * M), 2 * top / M);
        if (pos > top - (M - i) * 60) pos = top - (M - i) * 60;
        lsf[i] = (Word16)pos;
    }
}

/* Randomise the concealment state of st (already initialised). With allow_amr, AMR-WB IO frames
 * are drawn now and then. */
static void conceal_randomise(Decoder_State_fx *st, int allow_amr)
{
    static const Word32 rates_12k8[] = {7200, 8000, 13200, 9600, 16400, 24400};
    static const Word32 rates_16k[] = {16400, 24400, 32000, 64000};
    static const Word32 rates_amr[] = {6600, 8850, 12650, 15850, 23850};

    st->bfi_fx = 1;
    st->Opt_AMR_WB_fx = (Word16)(allow_amr && next_random() % 6 == 0);
    st->L_frame_fx = (Word16)((st->Opt_AMR_WB_fx || next_random() % 3) ? L_FRAME : L_FRAME16k);
    if (st->Opt_AMR_WB_fx) st->core_brate_fx = rates_amr[next_random() % 5];
    else if (st->L_frame_fx == L_FRAME) st->core_brate_fx = rates_12k8[(next_random() % 4) ? random_range(0, 2) : random_range(3, 5)];
    else st->core_brate_fx = rates_16k[next_random() % 4];
    st->total_brate_fx = st->core_brate_fx;
    st->bwidth_fx = (Word16)(st->L_frame_fx == L_FRAME ? random_range(NB, SWB) : random_range(WB, FB));
    if (st->Opt_AMR_WB_fx) st->bwidth_fx = WB;

    /* the last good frame */
    st->last_good_fx = (Word16)random_range(UNVOICED_CLAS, INACTIVE_CLAS);
    st->clas_dec = st->last_good_fx;
    st->last_coder_type_fx = (Word16)random_range(INACTIVE, AUDIO);
    /* a GSC frame only below 24.4 kbit/s and not in AMR-WB IO: otherwise FEC_exc_estim_fx would
     * build its total excitation from an uninitialised buffer */
    if (st->last_coder_type_fx == AUDIO && (st->total_brate_fx > ACELP_24k40 || st->Opt_AMR_WB_fx)) st->last_coder_type_fx = GENERIC;
    st->Last_GSC_pit_band_idx_fx = (Word16)((next_random() % 3) ? 0 : random_range(BAND1k2 + 1, 13));
    st->Last_GSC_noisy_speech_flag_fx = (Word16)(next_random() % 5 == 0);
    st->nbLostCmpt = (Word16)((next_random() % 3) ? 1 : random_range(2, 8));

    /* LSF memories */
    {
        int top = st->L_frame_fx == L_FRAME ? 16384 - 400 : 20480 - 400;
        conceal_lsf(st->lsf_old_fx, top);
        conceal_lsf(st->lsf_adaptive_mean_fx, top);
        conceal_lsf(st->mem_AR_fx, top);
        for (int i = 0; i < M; i++) st->mem_MA_fx[i] = (Word16)random_range(-1500, 1500);
        if (st->Opt_AMR_WB_fx) E_LPC_isf_isp_conversion(st->lsf_old_fx, st->lsp_old_fx, M);
        else lsf2lsp_fx(st->lsf_old_fx, st->lsp_old_fx, M, st->L_frame_fx == L_FRAME ? INT_FS_FX : INT_FS_16k_FX);
    }
    st->stab_fac_fx = (Word16)((next_random() % 4) ? random_range(0, 32767) : 32767);

    /* pitch memories: a steady, rising or falling trajectory near the last pitch */
    {
        int pmin = st->L_frame_fx == L_FRAME ? PIT_MIN : PIT16k_MIN, pmax = st->L_frame_fx == L_FRAME ? PIT_MAX : PIT16k_MAX;
        double lag = random_range(pmin, pmax - 20) + random_range(0, 99) / 100.0;
        double slope = (next_random() % 3) ? random_range(-150, 150) / 100.0 : 0;
        for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++) {
            double v = lag + slope * (i - 2 * NB_SUBFR16k);
            if (next_random() % 16 == 0) v += random_range(-20, 20);
            if (v < pmin) v = pmin;
            if (v > pmax) v = pmax;
            st->old_pitch_buf_fx[i] = (Word32)(v * 65536.0);
        }
        Word16 last = (Word16)round_fx(L_shl(st->old_pitch_buf_fx[st->L_frame_fx == L_FRAME ? 2 * NB_SUBFR - 1 : 2 * NB_SUBFR16k - 1], 6));
        st->bfi_pitch_fx = (next_random() % 3) ? last : (Word16)(random_range(pmin, pmax) << 6);
        st->bfi_pitch_frame_fx = st->L_frame_fx;
        for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++) st->mem_pitch_gain[i] = (Word16)random_range(4000, 19661);
        st->upd_cnt_fx = (Word16)random_range(0, 2 * MAX_UPD_CNT);
    }

    /* concealment gains and seeds */
    st->lp_ener_fx = (next_random() % 8) ? (Word32)random_range(1, 1 << 20) << random_range(0, 8) : 0;
    st->lp_gainc_fx = (Word16)random_range(0, 1 << random_range(4, 14));
    st->lp_gainp_fx = (Word16)random_range(0, 19661);
    st->seed_fx = random16();
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    st->last_voice_factor_fx = (Word16)random_range(0, 32767);
    for (int i = 0; i < GAIN_PRED_ORDER; i++) st->past_qua_en_fx[i] = (Word16)random_range(-14336, 3000);
    st->enr_old_fx = (Word32)random_range(0, 1 << 24);

    /* GSC memories */
    st->noise_lev_fx = (Word16)random_range(NOISE_LEVEL_SP0, NOISE_LEVEL_SP3);
    st->cor_strong_limit_fx = (Word16)(next_random() & 1);
    st->seed_tcx_fx = random16();
    for (int i = 0; i < MBANDS_GN; i++) {
        st->old_y_gain_fx[i] = (Word16)random_range(-2000, 14000);
        st->lt_ener_per_band_fx[i] = (Word16)random_range(-2000, 14000);
    }
    random_signal(st->Last_GSC_spectrum_fx, L_FRAME, (next_random() & 1) ? 8000 : 500);
    random_signal(st->last_exc_dct_in_fx, L_FRAME, (next_random() & 1) ? 8000 : 500);
    st->last_ener_fx = (Word16)random_range(0, 32767 >> random_range(0, 14));
    for (int i = 0; i < 6; i++) st->last_bitallocation_band_fx[i] = (Word16)(next_random() & 1);

    /* the excitation history: the last pitch cycle (a pulse plus noise) repeated, Q_exc */
    {
        Word16 cycle[PIT16k_MAX + 1];
        int tc = shr_r(st->bfi_pitch_fx, 6), amp = random_range(300, 12000);
        if (tc < 17) tc = 17;
        random_signal(cycle, tc, amp / 6);
        cycle[random_range(1, tc - 1)] = (Word16)((next_random() & 1) ? amp : -amp);
        for (int i = 0; i < L_EXC_MEM_DEC; i++) st->old_exc_fx[i] = cycle[(i + tc * 4) % tc];
        if (next_random() % 8 == 0) random_signal(st->old_exc_fx, L_EXC_MEM_DEC, amp);
        random_signal(st->old_exc2_fx, L_EXC_MEM, amp);
        random_signal(st->old_bwe_exc_fx, PIT16k_MAX * 2, amp);
        st->Q_exc = (Word16)random_range(0, 8);
    }
}

#endif
