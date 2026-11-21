/* Function-level oracle for lib_dec/fd_cng_dec.c. Every case builds the decoder-side FD-CNG state
 * the way the decoder does (createFdCngDec, initFdCngDec, configureFdCngDec for a bandwidth / bit
 * rate / frame length the decoder runs) and fills the decoder-state fields the functions read with
 * random values in their ranges. The memoryful functions run over many consecutive frames: the
 * "pipeline" case drives the MODE1 / MODE2 FD-CNG sequence of acelp_core_dec_fx (SID decoding,
 * comfort noise, noisy-speech detection, ApplyFdCng, masking noise) over a random pattern of
 * active, SID and no-data frames. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "rom_basop_util.h"
#include "stat_dec_fx.h"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

/* A stable LP filter (Q12) through the LSF domain. */
static void random_stable_lpc(Word16 *a)
{
    Word16 lsf[M], lsp[M];
    int at = 0;
    for (int i = 0; i < M; i++) {
        at += random_range(300, 1400);
        if (at > 12700) at = 12700 - (M - i) * 10;
        lsf[i] = (Word16)at;
    }
    lsf2lsp_fx(lsf, lsp, M, INT_FS_FX);
    E_LPC_f_lsp_a_conversion(lsp, a, M);
}

static void random_lsp(Word16 *lsp)
{
    Word16 lsf[M];
    int at = 0;
    for (int i = 0; i < M; i++) {
        at += random_range(300, 1400);
        if (at > 12700) at = 12700 - (M - i) * 10;
        lsf[i] = (Word16)at;
    }
    lsf2lsp_fx(lsf, lsp, M, INT_FS_FX);
}

typedef struct {
    Word16 scale, bandwidth, L_frame;
    Word32 bitrate;
} Config;

/* A configuration the decoder sets up: MODE1 FD-CNG at 7.2 - 13.2 kbit/s (NB / WB / SWB, 12.8 kHz
 * core), the 16 kHz core rates, and a SID / no-data reconfiguration. */
static void random_config(Config *c)
{
    static const Word32 rates[] = {ACELP_7k20, ACELP_8k00, ACELP_9k60, ACELP_13k20, ACELP_16k40, ACELP_24k40,
                                   ACELP_32k, SID_2k40, FRAME_NO_DATA};
    c->scale = (Word16)random_range(16384, 32767); /* div_s needs invScalingFactor >= 0.5 */
    c->bandwidth = (Word16)random_range(NB, FB);
    c->bitrate = rates[next_random() % 9];
    c->L_frame = next_random() % 3 ? L_FRAME : L_FRAME16k;
}

static Decoder_State_fx *make_state(const Config *c)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    createFdCngDec(&st->hFdCngDec_fx);
    initFdCngDec(st->hFdCngDec_fx, c->scale);
    configureFdCngDec(st->hFdCngDec_fx, c->bandwidth, c->bitrate, c->L_frame);
    return st;
}

static void put_config(const Config *c)
{
    put1("scale", c->scale); put1("bandwidth", c->bandwidth); put1("bitrate", c->bitrate); put1("L_frame", c->L_frame);
}

static void free_state(Decoder_State_fx *st)
{
    deleteFdCngDec(&st->hFdCngDec_fx);
    free(st);
}

/* The decoder-state fields the comfort noise and ApplyFdCng read, random in their ranges. */
static void random_decoder(Decoder_State_fx *st, const Config *c)
{
    /* overlap lengths with a sine window table (getSineWindowTable(n) holds n / 2 slopes) */
    static const Word16 lengths[] = {96, 112, 120, 140, 180, 224, 280};
    static const Word16 half_lengths[] = {16, 20, 30, 32, 40, 48, 60, 70, 96};
    static const Word16 min_lengths[] = {10, 16, 20};
    static const Word16 overlap_modes[] = {ALDO_WINDOW, FULL_OVERLAP, MIN_OVERLAP, HALF_OVERLAP};
    st->L_frame_fx = c->L_frame;
    st->sr_core = c->L_frame == L_FRAME ? 12800 : 16000;
    st->bwidth_fx = (Word16)random_range(NB, SWB);
    st->CNG_mode_fx = (Word16)random_range(-1, 4);
    st->lp_ener_fx = random_range(0, 1 << 24);
    st->Q_exc = (Word16)random_range(0, 8);
    st->Q_syn = (Word16)random_range(-1, 3);
    st->codec_mode = (Word16)(next_random() % 3 ? MODE1 : MODE2);
    st->last_core_bfi = (Word16)(next_random() & 1 ? ACELP_CORE : TCX_20_CORE);
    st->preemph_fac = c->L_frame == L_FRAME ? PREEMPH_FAC : PREEMPH_FAC_16k;
    random_signal(st->old_exc_fx, L_EXC_MEM_DEC, random_range(100, 20000));
    random_signal(st->mem_syn2_fx, M, 8000);
    random_signal(st->syn, M + 1, 8000);
    random_stable_lpc(st->old_Aq_12_8_fx);
    int h = lengths[next_random() % 7], hh = half_lengths[next_random() % 9], mh = min_lengths[next_random() % 3];
    if (hh > h) hh = 96;
    if (mh > hh) mh = 10;
    st->tcx_cfg.tcx_mdct_window = getSineWindowTable((Word16)h);
    st->tcx_cfg.tcx_mdct_window_half = getSineWindowTable((Word16)hh);
    st->tcx_cfg.tcx_mdct_window_minimum = getSineWindowTable((Word16)mh);
    st->tcx_cfg.tcx_mdct_window_length = (Word16)h;
    st->tcx_cfg.tcx_mdct_window_half_length = (Word16)hh;
    st->tcx_cfg.tcx_mdct_window_min_length = (Word16)mh;
    st->tcx_cfg.tcx_offset = (Word16)random_range(-60, 60);
    st->tcx_cfg.last_aldo = (Word16)random_range(0, 1);
    st->tcx_cfg.tcx_last_overlap_mode = overlap_modes[next_random() % 4];
    random_signal(st->old_out_LB_fx, L_FRAME32k, 20000);
    st->Q_old_wtda_LB = (Word16)random_range(-2, 4);
    random_signal(st->syn_Overl, L_FRAME32k / 2, 8000);
    st->cng_type_fx = (Word16)(next_random() % 4 ? FD_CNG : LP_CNG);
    st->BER_detect = (Word16)(next_random() % 16 == 0);
    random_lsp(st->lspold_cng);
    random_signal(st->lsf_cng, M, 12000);
}

static void put_decoder(Decoder_State_fx *st)
{
    put1("st_bwidth", st->bwidth_fx); put1("st_cng_mode", st->CNG_mode_fx); put1("st_lp_ener", st->lp_ener_fx);
    put1("st_q_exc", st->Q_exc); put1("st_q_syn", st->Q_syn); put1("st_codec_mode", st->codec_mode);
    put1("st_last_core_bfi", st->last_core_bfi); put1("st_preemph_fac", st->preemph_fac);
    put16("st_old_exc", st->old_exc_fx, L_EXC_MEM_DEC); put16("st_mem_syn2", st->mem_syn2_fx, M);
    put16("st_syn", st->syn, M + 1); put16("st_old_aq", st->old_Aq_12_8_fx, M + 1);
    put1("st_win_length", st->tcx_cfg.tcx_mdct_window_length);
    put1("st_win_half_length", st->tcx_cfg.tcx_mdct_window_half_length);
    put1("st_win_min_length", st->tcx_cfg.tcx_mdct_window_min_length); put1("st_tcx_offset", st->tcx_cfg.tcx_offset);
    put1("st_last_aldo", st->tcx_cfg.last_aldo); put1("st_last_overlap_mode", st->tcx_cfg.tcx_last_overlap_mode);
    put16("st_old_out_lb", st->old_out_LB_fx, L_FRAME32k); put1("st_q_old_wtda_lb", st->Q_old_wtda_LB);
    put16("st_syn_overl", st->syn_Overl, L_FRAME32k / 2); put1("st_cng_type", st->cng_type_fx);
    put1("st_ber_detect", st->BER_detect); put16("st_lspold_cng", st->lspold_cng, M); put16("st_lsf_cng", st->lsf_cng, M);
}

/* The FD-CNG state after a call: the common and the decoder part. */
static void put_fd_cng(const char *prefix, Decoder_State_fx *st)
{
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    HANDLE_FD_CNG_COM c = hs->hFdCngCom;
    char name[64];
#define P16(field, n) do { sprintf(name, "%s_%s", prefix, #field); put16(name, field, n); } while (0)
#define P32(field, n) do { sprintf(name, "%s_%s", prefix, #field); put32(name, field, n); } while (0)
#define P1(field) do { sprintf(name, "%s_%s", prefix, #field); put1(name, field); } while (0)
    P32(c->cngNoiseLevel, FFTCLDFBLEN); P1(c->cngNoiseLevelExp); P1(c->seed); P16(c->A_cng, M + 1);
    P16(c->exc_cng, L_FRAME16k); P16(c->timeDomainBuffer, L_FRAME16k); P32(c->fftBuffer, FFTLEN);
    P16(c->olapBufferSynth, FFTLEN); P32(c->sidNoiseEst, NPART); P1(c->sidNoiseEstExp);
    P1(c->inactive_frame_counter); P1(c->sid_frame_counter); P1(c->flag_noisy_speech);
    P1(c->likelihood_noisy_speech); P32(c->periodog, PERIODOGLEN); P1(c->periodog_exp);
    P1(c->msFrCnt_init_counter); P1(c->msFrCnt); P1(c->init_old); P1(c->offsetflag);
    P32(hs->msNoiseEst, NPART_SHAPING); P1(hs->msNoiseEst_exp); P16(hs->msLogNoiseEst, NPART_SHAPING);
    P32(hs->msPeriodog, NPART_SHAPING); P1(hs->msPeriodog_exp); P1(hs->msPeriodog_exp_fft);
    P1(hs->msPeriodog_exp_cldfb); P32(hs->bandNoiseShape, FFTLEN2); P1(hs->bandNoiseShape_exp);
    P32(hs->partNoiseShape, NPART); P1(hs->partNoiseShape_exp); P1(hs->flag_dtx_mode); P1(hs->lp_noise);
    P1(hs->lp_speech); P16(hs->olapBufferAna, 320); P16(hs->olapBufferSynth2, FFTLEN);
#undef P16
#undef P32
#undef P1
}

static void case_configure(void)
{
    Config c;
    random_config(&c);
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    HANDLE_FD_CNG_COM com = hs->hFdCngCom;
    /* a second configuration over the first, as a bandwidth or rate switch does */
    Config c2;
    random_config(&c2);
    int twice = next_random() & 1;
    put1("twice", twice); put1("bandwidth2", c2.bandwidth); put1("bitrate2", c2.bitrate); put1("L_frame2", c2.L_frame);
    if (twice) configureFdCngDec(hs, c2.bandwidth, c2.bitrate, c2.L_frame);
    arrow();
    put1("cng_bandwidth", com->CngBandwidth); put1("cng_bitrate", com->CngBitrate); put1("num_slots", com->numSlots);
    put1("setup_fftlen", com->FdCngSetup.fftlen); put1("setup_stop", com->FdCngSetup.stopFFTbin);
    put1("setup_num_partitions", com->FdCngSetup.numPartitions);
    put1("setup_num_shaping", com->FdCngSetup.numShapingPartitions);
    put1("num_core_bands", com->numCoreBands); put1("regular_stop_band", com->regularStopBand);
    put1("fftlen", com->fftlen); put1("stop_fft_bin", com->stopFFTbin); put1("start_band", com->startBand);
    put1("stop_band", com->stopBand); put1("npart", com->npart); put16("part", com->part, com->npart);
    put16("midband", com->midband, com->npart); put16("psize", com->psize, com->npart);
    put16("psize_norm", com->psize_norm, com->npart); put1("psize_norm_exp", com->psize_norm_exp);
    put16("psize_inv", com->psize_inv, com->npart); put1("n_fft_part", com->nFFTpart);
    put1("n_cldfb_part", com->nCLDFBpart); put16("cldfb_part", com->CLDFBpart, com->nCLDFBpart);
    put16("cldfb_psize_inv", com->CLDFBpsize_inv, com->nCLDFBpart); put1("npart_shaping", hs->npart_shaping);
    put1("n_fft_part_shaping", hs->nFFTpart_shaping); put16("part_shaping", hs->part_shaping, hs->npart_shaping);
    put16("midband_shaping", hs->midband_shaping, hs->npart_shaping);
    put16("psize_shaping", hs->psize_shaping, hs->npart_shaping);
    put16("psize_shaping_norm", hs->psize_shaping_norm, hs->npart_shaping);
    put1("psize_shaping_norm_exp", hs->psize_shaping_norm_exp);
    put16("psize_inv_shaping", hs->psize_inv_shaping, hs->npart_shaping); put1("fftlen_shift", com->fftlenShift);
    put1("fftlen_fac", com->fftlenFac); put1("frame_size", com->frameSize);
    put16("win_ana", (const Word16 *)com->olapWinAna, com->fftlen / 2);
    put16("win_syn", (const Word16 *)com->olapWinSyn, com->fftlen / 4);
    put1("inv_scaling_factor", com->invScalingFactor); put1("lp_noise", hs->lp_noise); put1("lp_speech", hs->lp_speech);
    put32("ms_min_buf", hs->msMinBuf, MSNUMSUBFR * NPART_SHAPING);
    end_line();
    free_state(st);
}

/* A frame of noisy input: a noise floor with occasional speech-like bursts, sometimes silent,
 * sometimes clipped at the frame edges (which suspends the estimation). */
static void random_frame(Word16 *x, int n, int level)
{
    int burst = next_random() % 5 == 0 ? random_range(2000, 20000) : 0;
    for (int i = 0; i < n; i++) {
        int v = random_range(-level, level) + (burst ? (int)((i % 40) < 20 ? burst : -burst) * random_range(0, 100) / 100 : 0);
        x[i] = (Word16)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
    }
    if (next_random() % 30 == 0) for (int i = 0; i < n; i++) x[i] = 0;
    if (next_random() % 30 == 0) x[0] = 32767;
}

#define EST_FRAMES 48
static void case_noise_estimation(void)
{
    Config c;
    random_config(&c);
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    int n = hs->hFdCngCom->frameSize;
    static Word16 frames[EST_FRAMES][L_FRAME16k];
    Word16 q[EST_FRAMES];
    int level = random_range(10, 3000);
    for (int f = 0; f < EST_FRAMES; f++) {
        if (next_random() % 12 == 0) level = random_range(10, 3000);
        random_frame(frames[f], n, level);
        q[f] = (Word16)random_range(-1, 2);
        char name[24]; sprintf(name, "x%d", f); put16(name, frames[f], n);
    }
    put16("q", q, EST_FRAMES);
    arrow();
    for (int f = 0; f < EST_FRAMES; f++) {
        perform_noise_estimation_dec(frames[f], q[f], hs);
        char name[24];
        sprintf(name, "est%d", f); put32(name, hs->msNoiseEst, hs->npart_shaping);
        sprintf(name, "est_exp%d", f); put1(name, hs->msNoiseEst_exp);
    }
    put_fd_cng("end", st);
    end_line();
    free_state(st);
}

static void case_decode_sid(void)
{
    Config c;
    random_config(&c);
    if (c.bitrate == SID_2k40 || c.bitrate == FRAME_NO_DATA) c.bitrate = ACELP_8k00;
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    st->preemph_fac = (Word16)(next_random() % 4 ? (c.L_frame == L_FRAME ? PREEMPH_FAC : PREEMPH_FAC_16k) : 0);
    int nbits = 44 + random_range(0, 8);
    for (int i = 0; i < nbits; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)nbits;
    st->codec_mode = MODE1;
    put_u16("bits", bit_buffer, nbits); put1("preemph_fac", st->preemph_fac);
    FdCng_decodeSID(st->hFdCngDec_fx->hFdCngCom, st);
    arrow(); put1("next_bit_pos", st->next_bit_pos_fx); put_fd_cng("end", st); end_line();
    free_state(st);
}

static void case_noisy_speech_detection(void)
{
    Config c;
    random_config(&c);
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    Word16 x[L_FRAME16k], vad = (Word16)random_range(0, 1), q = (Word16)random_range(-1, 3);
    Word16 frame = c.L_frame;
    int level = next_random() % 4 ? random_range(0, 8000) : 32767;
    random_signal(x, frame, level ? level : 1);
    if (level == 0) for (int i = 0; i < frame; i++) x[i] = 0;
    Word32 est[NPART_SHAPING];
    for (int i = 0; i < hs->nFFTpart_shaping; i++)
        est[i] = next_random() % 10 ? (Word32)((next_random() & 0x7fffffff) >> random_range(1, 31)) : 0;
    if (next_random() % 10 == 0) for (int i = 0; i < hs->nFFTpart_shaping; i++) est[i] = 0;
    Word16 est_exp = (Word16)random_range(-10, 30);
    Word32 lp_noise = random_range(-200000000, 300000000), lp_speech = random_range(-200000000, 400000000);
    Word16 flag = -5;
    put16("x", x, frame); put1("vad", vad); put1("q", q); put32("est", est, hs->nFFTpart_shaping);
    put1("est_exp", est_exp); put1("lp_noise", lp_noise); put1("lp_speech", lp_speech);
    noisy_speech_detection(vad, x, frame, q, est, est_exp, hs->psize_shaping_norm, hs->psize_shaping_norm_exp,
                           hs->nFFTpart_shaping, &lp_noise, &lp_speech, &flag);
    arrow(); put1("lp_noise", lp_noise); put1("lp_speech", lp_speech); put1("flag", flag); end_line();
    free_state(st);
}

/* A plausible CNG level: the decoder-side estimate after a few frames, or a decoded SID. */
static void prime_levels(Decoder_State_fx *st)
{
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    HANDLE_FD_CNG_COM com = hs->hFdCngCom;
    Word16 x[L_FRAME16k];
    int frames = random_range(1, 12), level = random_range(10, 3000);
    for (int f = 0; f < frames; f++) {
        random_frame(x, com->frameSize, level);
        perform_noise_estimation_dec(x, 0, hs);
    }
    scalebands(hs->msNoiseEst, hs->part_shaping, hs->nFFTpart_shaping, hs->midband_shaping, hs->nFFTpart_shaping,
               com->stopFFTbin - com->startBand, hs->bandNoiseShape, 1);
    hs->bandNoiseShape_exp = hs->msNoiseEst_exp;
    Copy32(hs->bandNoiseShape, com->cngNoiseLevel, com->stopFFTbin - com->startBand);
    com->cngNoiseLevelExp = hs->bandNoiseShape_exp;
    for (int i = com->stopFFTbin - com->startBand; i < FFTCLDFBLEN; i++)
        com->cngNoiseLevel[i] = (Word32)((next_random() & 0x7fffffff) >> random_range(4, 31));
    if (next_random() & 1) com->cngNoiseLevelExp = (Word16)(com->cngNoiseLevelExp + 1);
    com->seed = random16();
    com->likelihood_noisy_speech = (Word16)random_range(0, 32767);
    random_stable_lpc(com->A_cng);
    com->frame_type_previous = next_random() & 1 ? ACTIVE_FRAME : SID_FRAME;
    random_signal(com->olapBufferSynth, FFTLEN, 2000);
    random_signal(hs->olapBufferSynth2, FFTLEN, 2000);
}

static void put_primed(Decoder_State_fx *st)
{
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    HANDLE_FD_CNG_COM com = hs->hFdCngCom;
    put32("p_cng_level", com->cngNoiseLevel, FFTCLDFBLEN); put1("p_cng_exp", com->cngNoiseLevelExp);
    put1("p_seed", com->seed); put1("p_likelihood", com->likelihood_noisy_speech); put16("p_a_cng", com->A_cng, M + 1);
    put1("p_frame_type_previous", com->frame_type_previous); put16("p_olap_synth", com->olapBufferSynth, FFTLEN);
    put16("p_olap_synth2", hs->olapBufferSynth2, FFTLEN);
}

static void case_comfort_noise(void)
{
    static Word32 real_rows[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX], imag_rows[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX];
    Word32 *real[CLDFB_NO_COL_MAX], *imag[CLDFB_NO_COL_MAX];
    Config c;
    random_config(&c);
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    random_decoder(st, &c);
    prime_levels(st);
    put_decoder(st); put_primed(st);
    int with_cldfb = next_random() & 1;
    Word16 scale = -99;
    for (int i = 0; i < CLDFB_NO_COL_MAX; i++) {
        real[i] = real_rows[i]; imag[i] = imag_rows[i];
        for (int j = 0; j < CLDFB_NO_CHANNELS_MAX; j++) real_rows[i][j] = imag_rows[i][j] = 7;
    }
    put1("with_cldfb", with_cldfb);
    generate_comfort_noise_dec(with_cldfb ? real : NULL, with_cldfb ? imag : NULL, with_cldfb ? &scale : NULL, st,
                               &st->Q_exc, 2);
    arrow();
    put_fd_cng("end", st); put1("q_exc", st->Q_exc); put1("lp_ener", st->lp_ener_fx); put1("scale", scale);
    put16("syn_overl", st->syn_Overl, L_FRAME32k / 2);
    for (int i = 0; i < CLDFB_NO_COL_MAX; i++) {
        char name[24];
        sprintf(name, "real%d", i); put32(name, real_rows[i], CLDFB_NO_CHANNELS_MAX);
        sprintf(name, "imag%d", i); put32(name, imag_rows[i], CLDFB_NO_CHANNELS_MAX);
    }
    end_line();
    free_state(st);
}

static void case_comfort_noise_hf(void)
{
    static Word32 real_rows[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX], imag_rows[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX];
    Word32 *real[CLDFB_NO_COL_MAX], *imag[CLDFB_NO_COL_MAX];
    Config c;
    random_config(&c);
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    prime_levels(st);
    put_primed(st);
    Word16 scale = -99;
    for (int i = 0; i < CLDFB_NO_COL_MAX; i++) {
        real[i] = real_rows[i]; imag[i] = imag_rows[i];
        for (int j = 0; j < CLDFB_NO_CHANNELS_MAX; j++) real_rows[i][j] = imag_rows[i][j] = 7;
    }
    generate_comfort_noise_dec_hf(real, imag, &scale, st);
    arrow(); put1("seed", st->hFdCngDec_fx->hFdCngCom->seed); put1("scale", scale);
    for (int i = 0; i < CLDFB_NO_COL_MAX; i++) {
        char name[24];
        sprintf(name, "real%d", i); put32(name, real_rows[i], CLDFB_NO_CHANNELS_MAX);
        sprintf(name, "imag%d", i); put32(name, imag_rows[i], CLDFB_NO_CHANNELS_MAX);
    }
    end_line();
    free_state(st);
}

static void case_masking_noise(void)
{
    Config c;
    random_config(&c);
    if (c.bitrate == SID_2k40 || c.bitrate == FRAME_NO_DATA) c.bitrate = ACELP_13k20;
    Word16 core = (Word16)(next_random() % 4 ? ACELP_CORE : AMR_WB_CORE);
    if (core == AMR_WB_CORE) { static const Word32 amr[] = {6600, 8850, 12650, 23850}; c.bitrate = amr[next_random() % 4]; }
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    HANDLE_FD_CNG_COM com = st->hFdCngDec_fx->hFdCngCom;
    if (core == AMR_WB_CORE) com->CngBitrate = c.bitrate;
    prime_levels(st);
    put_primed(st);
    Word16 x[L_FRAME16k], q = (Word16)random_range(-1, 3);
    Word16 length = (Word16)(next_random() & 1 ? com->frameSize : random_range(1, 2 * L_SUBFR * 2));
    random_signal(x, L_FRAME16k, random_range(10, 20000));
    put1("core", core); put1("q", q); put1("length", length); put16("x", x, L_FRAME16k);
    put1("cng_bitrate", com->CngBitrate);
    generate_masking_noise(x, q, com, length, core);
    arrow(); put16("x", x, L_FRAME16k); put_fd_cng("end", st); end_line();
    free_state(st);
}

static void case_masking_noise_mdct(void)
{
    Config c;
    random_config(&c);
    if (c.bitrate == SID_2k40 || c.bitrate == FRAME_NO_DATA) c.bitrate = ACELP_13k20;
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    HANDLE_FD_CNG_COM com = st->hFdCngDec_fx->hFdCngCom;
    prime_levels(st);
    put_primed(st);
    Word32 mdct[2 * L_FRAME16k];
    Word16 l_frame = c.L_frame, e = (Word16)random_range(-5, 25);
    int shift = random_range(1, 31);
    for (int i = 0; i < 2 * L_FRAME16k; i++) mdct[i] = (Word32)random32() >> shift;
    put32("mdct", mdct, 2 * L_FRAME16k); put1("e", e);
    generate_masking_noise_mdct(mdct, &e, com, l_frame);
    arrow(); put32("mdct", mdct, 2 * L_FRAME16k); put1("e", e); put1("seed", com->seed); end_line();
    free_state(st);
}

static void case_update_seed(void)
{
    Config c;
    random_config(&c);
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    HANDLE_FD_CNG_COM com = st->hFdCngDec_fx->hFdCngCom;
    com->seed = random16();
    if (next_random() % 4 == 0) com->startBand = 0;
    put1("seed", com->seed); put1("start_band", com->startBand);
    generate_masking_noise_update_seed(com);
    arrow(); put1("seed", com->seed); end_line();
    free_state(st);
}

/* The FD-CNG sequence of acelp_core_dec_fx over PIPE_FRAMES frames. */
#define PIPE_FRAMES 24
static void case_pipeline(void)
{
    static Word32 real_rows[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX], imag_rows[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX];
    Word32 *real[CLDFB_NO_COL_MAX], *imag[CLDFB_NO_COL_MAX];
    static Word16 syn[PIPE_FRAMES][L_FRAME16k];
    Word16 types[PIPE_FRAMES], vad[PIPE_FRAMES], conceal[PIPE_FRAMES], music[PIPE_FRAMES], cna[PIPE_FRAMES];
    Word16 lost[PIPE_FRAMES];
    static UWord16 sid_bits[PIPE_FRAMES][48];
    Config c;
    random_config(&c);
    if (c.bitrate == SID_2k40 || c.bitrate == FRAME_NO_DATA) c.bitrate = ACELP_7k20;
    put_config(&c);
    Decoder_State_fx *st = make_state(&c);
    random_decoder(st, &c);
    put_decoder(st);
    HANDLE_FD_CNG_DEC hs = st->hFdCngDec_fx;
    HANDLE_FD_CNG_COM com = hs->hFdCngCom;
    for (int i = 0; i < CLDFB_NO_COL_MAX; i++) { real[i] = real_rows[i]; imag[i] = imag_rows[i]; }

    /* talk spurts and DTX: a run of active frames, then a SID, no-data frames, a SID ... */
    int active_run = random_range(2, 14), level = random_range(10, 3000);
    int silent = next_random() % 8 == 0; /* digital silence: the estimated shape is all zero */
    for (int f = 0; f < PIPE_FRAMES; f++) {
        if (f < active_run || next_random() % (silent ? 2 : 10) == 0) types[f] = ACTIVE_FRAME;
        else types[f] = (f == active_run || next_random() % 6 == 0) ? SID_FRAME : ZERO_FRAME;
        vad[f] = (Word16)(types[f] == ACTIVE_FRAME && next_random() % 3 != 0);
        conceal[f] = (Word16)(next_random() % 16 == 0);
        lost[f] = (Word16)(conceal[f] ? random_range(1, 2) : 0);
        music[f] = (Word16)(next_random() % 20 == 0);
        cna[f] = (Word16)(next_random() % 3);
        random_frame(syn[f], c.L_frame, level);
        if (silent) for (int i = 0; i < c.L_frame; i++) syn[f][i] = 0;
        for (int i = 0; i < 48; i++) sid_bits[f][i] = (UWord16)(next_random() & 1);
        char name[24];
        sprintf(name, "syn%d", f); put16(name, syn[f], c.L_frame);
        sprintf(name, "sid_bits%d", f); put_u16(name, sid_bits[f], 48);
    }
    put16("types", types, PIPE_FRAMES); put16("vad", vad, PIPE_FRAMES); put16("conceal", conceal, PIPE_FRAMES);
    put16("lost", lost, PIPE_FRAMES); put16("music", music, PIPE_FRAMES); put16("cna", cna, PIPE_FRAMES);
    arrow();
    for (int f = 0; f < PIPE_FRAMES; f++) {
        char name[32];
        st->m_frame_type = types[f];
        st->VAD = vad[f];
        st->nbLostCmpt = lost[f];
        if (types[f] != ACTIVE_FRAME && st->cng_type_fx == FD_CNG) {
            if (types[f] == SID_FRAME) {
                st->bit_stream_fx = sid_bits[f];
                st->total_num_bits = 48;
                st->next_bit_pos_fx = 0;
                FdCng_decodeSID(com, st);
            }
            generate_comfort_noise_dec(NULL, NULL, NULL, st, &st->Q_exc, 2);
        }
        noisy_speech_detection(st->VAD, syn[f], c.L_frame, st->Q_syn, hs->msNoiseEst, hs->msNoiseEst_exp,
                               hs->psize_shaping_norm, hs->psize_shaping_norm_exp, hs->nFFTpart_shaping,
                               &hs->lp_noise, &hs->lp_speech, &com->flag_noisy_speech);
        com->likelihood_noisy_speech = mult_r(com->likelihood_noisy_speech, 32440);
        if (com->flag_noisy_speech != 0) com->likelihood_noisy_speech = add(com->likelihood_noisy_speech, 328);
        for (int i = 0; i < CLDFB_NO_COL_MAX; i++)
            for (int j = 0; j < CLDFB_NO_CHANNELS_MAX; j++) real_rows[i][j] = imag_rows[i][j] = 7;
        Word16 scale = -99;
        Word16 r = ApplyFdCng(syn[f], st->Q_syn, real, imag, &scale, hs, types[f], st, conceal[f], music[f]);
        if (cna[f] == 1) generate_masking_noise(syn[f], st->Q_syn, com, com->frameSize, 0);
        else if (cna[f] == 2) generate_masking_noise_update_seed(com);
        com->frame_type_previous = types[f];
        sprintf(name, "r%d", f); put1(name, r);
        sprintf(name, "out%d", f); put16(name, syn[f], c.L_frame);
        sprintf(name, "level%d", f); put32(name, com->cngNoiseLevel, FFTCLDFBLEN);
        sprintf(name, "level_exp%d", f); put1(name, com->cngNoiseLevelExp);
        sprintf(name, "td%d", f); put1(name, st->cngTDLevel);
        sprintf(name, "td_e%d", f); put1(name, st->cngTDLevel_e);
        sprintf(name, "lp_ener%d", f); put1(name, st->lp_ener_fx);
        sprintf(name, "q_exc%d", f); put1(name, st->Q_exc);
        sprintf(name, "tdb%d", f); put16(name, com->timeDomainBuffer, com->frameSize);
        sprintf(name, "exc%d", f); put16(name, com->exc_cng, c.L_frame);
        sprintf(name, "seed%d", f); put1(name, com->seed);
        sprintf(name, "lsf_cng%d", f); put16(name, st->lsf_cng, M);
        sprintf(name, "plc%d", f); put1(name, st->plcBackgroundNoiseUpdated);
        sprintf(name, "scale%d", f); put1(name, scale);
        sprintf(name, "real%d", f); put32(name, real_rows[3], CLDFB_NO_CHANNELS_MAX);
        sprintf(name, "imag%d", f); put32(name, imag_rows[15], CLDFB_NO_CHANNELS_MAX);
    }
    put_fd_cng("end", st);
    put16("lspold_cng", st->lspold_cng, M);
    end_line();
    free_state(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "configure")) case_configure();
        else if (!strcmp(argv[2], "noise_estimation")) case_noise_estimation();
        else if (!strcmp(argv[2], "decode_sid")) case_decode_sid();
        else if (!strcmp(argv[2], "noisy_speech_detection")) case_noisy_speech_detection();
        else if (!strcmp(argv[2], "comfort_noise")) case_comfort_noise();
        else if (!strcmp(argv[2], "comfort_noise_hf")) case_comfort_noise_hf();
        else if (!strcmp(argv[2], "masking_noise")) case_masking_noise();
        else if (!strcmp(argv[2], "masking_noise_mdct")) case_masking_noise_mdct();
        else if (!strcmp(argv[2], "update_seed")) case_update_seed();
        else if (!strcmp(argv[2], "pipeline")) case_pipeline();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
