/* Function-level oracle for lib_dec/dec_ace.c (decoder_acelp, the MODE2 ACELP frame decoder) and
 * lib_com/scale_mem_fx.c (the lower-case rescale_mem).
 *
 * Each decoder_acelp case builds a decoder with init_decoder_fx, then configures it the way
 * open_decoder_LPD and dec_prm leave it for an ACELP frame: the core rate and frame length, the
 * pitch limits, the IGF flag, the ACELP configuration of BITS_ALLOC_init_config_acelp /
 * BITS_ALLOC_config_acelp for the frame's bit budget and coder type, and a parameter stream laid out
 * the way dec_prm writes it (so every pitch / gain index is in its bit width and the algebraic
 * codebook words are valid indices most of the time). The per-frame memories (excitation, synthesis,
 * classifier, enhancer, concealment state) are randomised in the ranges the decoder keeps them in.
 * The WHOLE state is printed before the call ("in.") and after it only the changed fields ("st."),
 * with the buffers the function writes.
 *
 * Domains: 9.6 / 13.2 / 16.4 / 24.4 / 32 kbit/s at 12.8 and 16 kHz cores (NB to FB as the bandwidth
 * rules allow, so the TBE excitation path of IGF runs at SWB / FB), coder types INACTIVE .. GENERIC,
 * previous frame good, lost, or concealed TCX, a bit-error flag now and then, and the channel-aware
 * partial copies (13.2 kbit/s: ALLPRED, NOPRED, GENPRED, NELP) which decoder_LPD runs with the
 * decoder's own bfi_fx set. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"

#define MAX_PRM 80
#define BWE_EXC_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)

static const Word32 out_rates[4] = {8000, 16000, 32000, 48000};

/* A stable order-16 A(z) in Q12 from random reflection coefficients (step-up recursion). */
static void random_lpc(Word16 *a)
{
    double k[M], c[M + 1], t[M + 1];
    double scale = (next_random() % 4 == 0) ? 0.95 : 0.6;
    for (int i = 0; i < M; i++) k[i] = ((int)(next_random() % 1801) - 900) / 1000.0 * (i < 2 ? 1.0 : scale);
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

/* A sorted LSP vector (Q15, cosine domain: descending). */
static void random_lsp(Word16 *lsp)
{
    int previous = 32000;
    for (int i = 0; i < M; i++) {
        int remaining = M - i;
        int step = (previous - 400) / (remaining + 1);
        int value = previous - random_range(step / 3 + 1, step * 5 / 3 + 1);
        if (value < 400 * (remaining)) value = 400 * remaining;
        if (value >= previous) value = previous - 1;
        lsp[i] = (Word16)value;
        previous = value;
    }
}

static void random_nonnegative32(Word32 *x, int shift_low, int shift_high)
{
    Word32 v = random32() >> random_range(shift_low, shift_high);
    *x = v < 0 ? -(v + 1) : v;
}

/* printf to nowhere (BITS_ALLOC_config_acelp warns on stdout when the budget is too small). */
static Word16 config_acelp_quiet(Word16 bits, Word16 coder_type, ACELP_config *cfg, Word16 narrow_band, Word16 nb_subfr)
{
    FILE *saved = stdout;
    stdout = fopen("/dev/null", "w");
    Word16 r = BITS_ALLOC_config_acelp(bits, coder_type, cfg, narrow_band, nb_subfr);
    fclose(stdout);
    stdout = saved;
    return r;
}

/* The parameters of one frame as dec_prm lays them out. */
static int build_prm(Decoder_State_fx *st, Word16 *prm, int partial_copy, int rf_type, int valid_codebooks)
{
    int j = 0;
    ACELP_config *cfg = &st->acelp_cfg;
    int nb_subfr = st->nb_subfr;
    if (partial_copy) {
        if (rf_type == RF_NELP) return 0;
        prm[j++] = (Word16)random_range(0, 7); /* energy */
        for (int sfr = 0; sfr < nb_subfr; sfr++) {
            int n = ACELP_LTP_BITS_SFR[cfg->ltp_mode][sfr];
            if (n != 0) prm[j++] = (Word16)random_range(0, (1 << n) - 1);
            if (rf_type == RF_NOPRED || (rf_type == RF_GENPRED && (sfr == 0 || sfr == 2))) {
                prm[j] = (Word16)random_range(0, 127);
                j += 8;
            }
            if (sfr == 0 || sfr == 2) {
            int n = ACELP_GAINS_BITS[cfg->gains_mode[sfr]];
            prm[j++] = (Word16)(next_random() % 3 == 0 ? ((next_random() & 1) ? random_range(0, 3) : random_range((1 << n) - 4, (1 << n) - 1)) : random_range(0, (1 << n) - 1));
        }
        }
        return j;
    }
    {
        int n = ACELP_NRG_BITS[cfg->nrg_mode];
        if (n != 0) prm[j++] = (Word16)random_range(0, (1 << n) - 1);
    }
    for (int sfr = 0; sfr < nb_subfr; sfr++) {
        int n = ACELP_LTP_BITS_SFR[cfg->ltp_mode][sfr];
        if (n != 0) prm[j++] = (Word16)random_range(0, (1 << n) - 1);
        if (cfg->ltf_mode == 2) prm[j++] = (Word16)(next_random() & 1);
        {
            int index = cfg->fixed_cdk_index[sfr];
            int wordcnt = ACELP_FIXED_CDK_BITS(index) >> 4, bitcnt = ACELP_FIXED_CDK_BITS(index) & 15;
            Word16 code[L_SUBFR];
            for (int attempt = 0; attempt < 60; attempt++) {
                for (int ix = 0; ix < wordcnt; ix++) prm[j + ix] = (Word16)(next_random() & 0xffff);
                if (bitcnt) prm[j + wordcnt] = (Word16)random_range(0, (1 << bitcnt) - 1);
                if (!valid_codebooks) break;
                Word16 ber = 0;
                D_ACELP_indexing(code, PulseConfTable[index], NB_TRACK_FCB_4T, prm + j, &ber);
                if (!ber) break;
            }
            j += 8;
        }
        n = ACELP_GAINS_BITS[cfg->gains_mode[sfr]];
        /* now and then an index at either end of the quantiser (the largest pitch gains) */
        prm[j++] = (Word16)(n ? (next_random() % 3 == 0 ? ((next_random() & 1) ? random_range(0, 3) : random_range((1 << n) - 4, (1 << n) - 1)) : random_range(0, (1 << n) - 1)) : 0);
    }
    return j;
}

static void randomise_memories(Decoder_State_fx *st)
{
    int mag = (next_random() % 3 == 0) ? 16000 : (next_random() & 1) ? 3000 : 300;
    random_signal(st->old_exc_fx, L_EXC_MEM_DEC, mag);
    st->Q_exc = (Word16)random_range(0, 8);
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)random_range(0, 8);
    st->Q_syn = (Word16)random_range(-1, 4);
    st->prev_Q_syn = (Word16)random_range(-1, 4);
    mag = (next_random() & 1) ? 6000 : 800;
    random_signal(st->mem_syn2_fx, M, mag);
    random_signal(st->mem_syn_r, L_SYN_MEM, mag);
    random_signal(st->syn, M + 1, mag);
    random_signal(st->mem_syn_clas_estim_fx, L_SYN_MEM_CLAS_ESTIM, mag);
    st->classifier_Q_mem_syn = (Word16)random_range(-1, 4);
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    st->voice_fac = (Word16)random_range(-30000, 30000);
    st->past_gpit = (Word16)random_range(0, 20000);
    random_nonnegative32(&st->past_gcode, 6, 22);
    random_nonnegative32(&st->gc_threshold_fx, 6, 22);
    random_nonnegative32(&st->dm_fx.prev_gain_code, 6, 22);
    for (int i = 0; i < 6; i++) st->dm_fx.prev_gain_pit[i] = (Word16)random_range(0, 20000);
    st->dm_fx.prev_state = (Word16)random_range(0, 2);
    st->seed_acelp = random16();
    st->bpf_gain_param = (Word16)random_range(0, 3);
    for (int i = 0; i < NB_SUBFR16k; i++) st->tilt_code_dec_fx[i] = (Word16)random_range(0, 16384);
    st->prev_tilt_code_dec_fx = (Word16)random_range(0, 16384);
    st->next_coder_type = (Word16)random_range(0, 3);
    st->last_coder_type_fx = (Word16)random_range(0, 3);
    for (int i = 0; i < 2 * NB_SUBFR16k; i++) st->old_pitch_buf_fx[i] = L_deposit_h((Word16)random_range(st->pit_min, st->pit_max));
    st->old_fpitch = L_deposit_h((Word16)random_range(st->pit_min, st->pit_max));
    st->tcxltp_second_last_pitch = L_deposit_h((Word16)random_range(st->pit_min, st->pit_max));
    st->tcxltp_third_last_pitch = L_deposit_h((Word16)random_range(st->pit_min, st->pit_max));
    st->last_good_fx = (Word16)random_range(0, 7);
    st->clas_dec = (Word16)random_range(0, 7);
    st->lp_ener_FER_fx = (Word16)random_range(0, 8000);
    random_nonnegative32(&st->enr_old_fx, 4, 24);
    st->scaling_flag = (Word16)random_range(0, 2);
    random_nonnegative32(&st->lp_ener_FEC_av, 4, 24);
    random_nonnegative32(&st->lp_ener_FEC_max, 4, 24);
    st->old_enr_LP = (Word16)(next_random() % 3 ? random_range(1, 30000) : 0);
    st->mid_lsf_int_fx = 0;
    random_lsp(st->lsp_q_cng);
    random_lsp(st->old_lsp_q_cng);
    st->T0_4th = (Word16)random_range(st->pit_min, st->pit_max);
}

static void case_decoder_acelp(void)
{
    static const Word32 rates[] = {9600, 13200, 16400, 24400, 32000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 a[NB_SUBFR16k * (M + 1)], prm[MAX_PRM], synth[L_FRAME16k], p_t[NB_SUBFR16k], pgain_t[NB_SUBFR16k];
    Word16 pitch_buffer[NB_SUBFR16k], voice_factors[NB_SUBFR16k], bwe_exc_buffer[BWE_EXC_LEN];
    Word16 *bwe_exc = bwe_exc_buffer + PIT16k_MAX * 2;

    st->output_Fs_fx = out_rates[next_random() % 4];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);

    /* the channel-aware partial copy runs at 13.2 kbit/s only, WB or SWB */
    int partial_copy = next_random() % 5 == 0;
    Word32 bitrate;
    Word16 bandwidth, rf_flag = 0;
    for (;;) {
        bitrate = partial_copy ? 13200 : rates[next_random() % 5];
        bandwidth = (Word16)(partial_copy ? random_range(WB, SWB) : random_range(NB, FB));
        if (bandwidth == NB && bitrate > 24400) continue;
        if (bandwidth == SWB && bitrate < 13200) continue;
        if (bandwidth == FB && bitrate < 16400) continue;
        break;
    }
    if (partial_copy) rf_flag = 1;
    st->rf_flag = rf_flag;
    st->bwidth_fx = bandwidth;
    st->last_bwidth_fx = bandwidth;
    st->total_brate_fx = bitrate;
    st->core_brate_fx = bitrate;
    st->codec_mode = MODE2;
    st->last_codec_mode = MODE2;
    st->ini_frame_fx = 3;

    /* open_decoder_LPD's per-rate configuration (only the integer fields decoder_acelp reads) */
    st->sr_core = getCoreSamplerateMode2(bitrate, bandwidth, rf_flag);
    st->fscale = sr2fscale(st->sr_core);
    st->L_frame_fx = extract_l(Mult_32_16(st->sr_core, 0x0290));
    st->L_frameTCX = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    st->last_L_frame_fx = st->L_frame_past = st->L_frame_fx;
    {
        static const Word16 past_lengths[] = {160, 320, 640, 960};
        st->L_frameTCX_past = (next_random() % 3) ? st->L_frameTCX : past_lengths[next_random() % 4];
    }
    st->tcxonly = getTcxonly(bitrate);
    st->nb_subfr = NB_SUBFR;
    if (st->L_frame_fx == L_FRAME16k && bitrate <= 32000) st->nb_subfr = NB_SUBFR16k;
    st->narrowBand = (Word16)(bandwidth == NB);
    st->pit_res_max = initPitchLagParameters(st->sr_core, &st->pit_min, &st->pit_fr1, &st->pit_fr1b, &st->pit_fr2, &st->pit_max);
    st->preemph_fac = st->fscale < (16000 * FSCALE_DENOM) / 12800 ? PREEMPH_FAC : PREEMPH_FAC_16k;
    st->igf = getIgfPresent(bitrate, bandwidth, rf_flag);
    st->enableGplc = (Word16)(bitrate == 24400 && bandwidth >= WB);

    /* the ACELP configuration of the frame's coder type and bit budget */
    Word16 coder_type = (Word16)random_range(INACTIVE, GENERIC);
    int rf_type = 0;
    BITS_ALLOC_init_config_acelp(bitrate, (Word8)st->narrowBand, st->nb_subfr, &st->acelp_cfg);
    if (partial_copy) {
        st->use_partial_copy = 1;
        st->rf_frame_type = rf_type = random_range(RF_ALLPRED, RF_NELP);
        st->prev_rf_frame_type = (Word16)random_range(0, 7);
        st->rf_target_bits = (Word16)random_range(56, 72);
        Word16 r = config_acelp_quiet(st->rf_target_bits, st->rf_frame_type, &st->acelp_cfg, 0, st->nb_subfr);
        st->BER_detect = (Word16)(r < 0);
        st->rf_indx_nelp_iG1 = (Word16)random_range(0, 31);
        st->rf_indx_nelp_iG2[0] = (Word16)random_range(0, 63);
        st->rf_indx_nelp_iG2[1] = (Word16)random_range(0, 63);
        st->rf_indx_nelp_fid = (Word16)random_range(0, 3);
        st->rf_indx_tbeGainFr = (Word16)random_range(0, 31);
        st->bfi_fx = 1;
        st->bwidth_fx = bandwidth;
        /* NELP runs at WB (SWB uses the WB tables) */
    } else {
        int bits_frame = (int)(bitrate / 50);
        int budget = bits_frame - random_range(30, 90);
        Word16 r;
        for (;;) {
            r = config_acelp_quiet((Word16)budget, coder_type, &st->acelp_cfg, st->narrowBand, st->nb_subfr);
            if (r >= 0) break;
            budget += 12;
        }
        st->BER_detect = (Word16)(next_random() % 16 == 0);
        st->bfi_fx = 0;
    }
    st->use_partial_copy = (Word16)partial_copy;
    st->prev_use_partial_copy = (Word16)(bitrate == 13200 ? next_random() % 3 == 0 : 0);
    st->core_fx = ACELP_CORE;
    st->core_ext_mode = coder_type == INACTIVE ? UNVOICED : coder_type;
    {
        int r = next_random() % 10;
        st->last_core_fx = r < 7 ? ACELP_CORE : r < 9 ? TCX_20_CORE : TCX_10_CORE;
        st->last_core_bfi = (Word16)((next_random() % 3 == 0) ? random_range(ACELP_CORE, TCX_10_CORE) : st->last_core_fx);
    }
    st->prev_bfi_fx = (Word16)(next_random() % 4 == 0 || partial_copy && next_random() % 2);
    st->last_con_tcx = (Word16)(next_random() % 5 == 0);
    {
        static const Word32 last_rates[] = {0, 2400, 7200, 8000, 9600, 13200, 16400, 24400, 32000, 48000, 96000, 128000};
        st->last_core_brate_fx = last_rates[next_random() % 12];
    }
    randomise_memories(st);
    if (st->use_partial_copy || st->prev_use_partial_copy) {
        /* the channel-aware gain adjustments of the total excitation need these */
        if (next_random() % 5 < 3) st->next_coder_type = VOICED;
        if (next_random() % 5 < 3) st->prev_tilt_code_dec_fx = (Word16)random_range(6600, 16384);
        if (next_random() % 2) st->last_coder_type_fx = UNVOICED;
        if (next_random() % 5 < 4) st->last_core_fx = ACELP_CORE;
    }

    /* the frame's input */
    int prm_words = build_prm(st, prm, partial_copy, rf_type, next_random() % 4 != 0);
    for (int i = prm_words; i < MAX_PRM; i++) prm[i] = (Word16)random_range(0, 3);
    for (int sfr = 0; sfr < NB_SUBFR16k; sfr++) {
        if (sfr == 0 || next_random() % 3 == 0) random_lpc(a + sfr * (M + 1));
        else memcpy(a + sfr * (M + 1), a + (sfr - 1) * (M + 1), (M + 1) * sizeof(Word16));
    }
    random_signal(bwe_exc_buffer, PIT16k_MAX * 2, 2000);
    memset(bwe_exc, 0, (BWE_EXC_LEN - PIT16k_MAX * 2) * sizeof(Word16));
    for (int i = 0; i < L_FRAME16k; i++) synth[i] = -3;
    for (int i = 0; i < NB_SUBFR16k; i++) { p_t[i] = -4; pgain_t[i] = -5; pitch_buffer[i] = -6; voice_factors[i] = -7; }
    if (st->last_con_tcx && st->old_enr_LP) {
        /* the LP energy of the concealed frame close to this frame's, so the rescaling ratio varies */
        Word32 e = Enr_1_Az_fx(a, L_SUBFR);
        st->old_enr_LP = (Word16)((e * random_range(300, 1100)) / 1000);
        if (st->old_enr_LP < 1) st->old_enr_LP = 1;
    }
    Word16 stab_fac = (Word16)random_range(0, 32767);
    Word16 lsf_q_prediction = (Word16)random_range(-1, 3);

    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("coder_type", coder_type);
    put1("stab_fac", stab_fac);
    put1("lsf_q_prediction", lsf_q_prediction);
    put16("prm", prm, MAX_PRM);
    put16("a", a, NB_SUBFR16k * (M + 1));
    put16("bwe_exc", bwe_exc_buffer, BWE_EXC_LEN);
    char *before = capture_state(st);
    put_state_in(before);

    int returned = GUARDED(decoder_acelp(st, coder_type, prm, a, st->acelp_cfg, synth, p_t, pgain_t, stab_fac, pitch_buffer, voice_factors,
                                         lsf_q_prediction, bwe_exc));
    arrow();
    if (!returned) {
        put1("skip", 1);
        end_line();
        free(before);
        destroy_decoder(st);
        free(st);
        return;
    }
    put16("synth", synth, L_FRAME16k);
    put16("p_t", p_t, NB_SUBFR16k);
    put16("pgain_t", pgain_t, NB_SUBFR16k);
    put16("pitch_buffer", pitch_buffer, NB_SUBFR16k);
    put16("voice_factors", voice_factors, NB_SUBFR16k);
    put16("bwe_exc", bwe_exc_buffer, BWE_EXC_LEN);
    put1("prm_words", prm_words);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

static void case_rescale_mem(void)
{
    Word16 mem[M], syn[320];
    Word16 q_exc = (Word16)random_range(-1, 12), prev_q_syn = (Word16)random_range(-1, 8), q_syn = (Word16)random_range(-1, 8);
    Word16 i_subfr = (Word16)(L_SUBFR * random_range(0, 5));
    Word16 mem_len = (Word16)(next_random() % 6 ? M : random_range(1, M));
    int magnitude = (next_random() % 4) ? random_range(1, 20000) : 32767;
    int with_syn = next_random() % 4 != 0;
    random_signal(mem, M, magnitude);
    random_signal(syn, 320, (next_random() & 1) ? magnitude : random_range(1, 4000));
    if (next_random() % 8 == 0) memset(mem, 0, sizeof mem);
    if (next_random() % 12 == 0) memset(syn, 0, sizeof syn);
    put1("q_exc", q_exc); put1("prev_q_syn", prev_q_syn); put1("q_syn", q_syn); put16("mem", mem, M); put16("syn", syn, 320);
    put1("mem_len", mem_len); put1("i_subfr", i_subfr); put1("with_syn", with_syn);
    Word16 r = rescale_mem(&q_exc, &prev_q_syn, &q_syn, mem, with_syn ? syn : NULL, mem_len, i_subfr);
    arrow();
    put1("r", r); put1("prev_q_syn", prev_q_syn); put1("q_syn", q_syn); put16("mem", mem, M); put16("syn", syn, 320);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decoder_acelp")) case_decoder_acelp();
        else if (!strcmp(argv[2], "rescale_mem")) case_rescale_mem();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
