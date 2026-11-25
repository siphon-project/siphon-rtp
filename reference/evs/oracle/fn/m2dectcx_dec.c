/* Function-level oracle for lib_dec/dec_tcx.c: decoder_tcx (and through it IMDCT, CalculateAbsEnergy and
 * the rest of the file's statics) and decoder_tcx_post.
 *
 * Each case builds a decoder with init_decoder_fx, configures the MODE2 core for one of the bit-rate /
 * bandwidth combinations of the frame size table exactly as mode_switch_decoder_LPD does (getIgfPresent,
 * IGFDecSetMode, open_decoder_LPD, reconfig_decoder_LPD), then runs a short sequence of TCX frames
 * through the reference: the parameters of every good frame are read by the reference's own dec_prm
 * from a bit stream whose header (core, class / coder type, last core, overlap mode) is written here
 * and whose body is random, so the layout of prm, the IGF / TNS / HM / LTP side information and the
 * state dec_prm leaves behind (overlap modes, last_core_bs, tcxltp_*, igf, clas_dec, ...) are the
 * decoder's own; a stream that dec_prm flags (BER_detect) is drawn again. Concealed frames follow
 * a good one with GetPLCModeDecision and the frame counters decoder_LPD keeps. The last frame's
 * decoder_tcx (or decoder_tcx_post) call is the measured one: the WHOLE state before it is printed
 * (prefix "in.") and after it only the fields that changed (prefix "st."), as m2igf_igf.c does.
 *
 * Domain notes: the LPC filters are stable (random reflection coefficients); TCX-10 only at the
 * rates that are TCX-only (above 32 kbit/s) and then never after ACELP (dec_prm forces last core
 * TCX); an ACELP last core is the first frame after a core switch, with random ACELP overlap /
 * ZIR memories; output rates 16, 32 and 48 kHz (and 8 kHz now and then). */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"
#include "../../c-code/lib_dec/dec_prm.c"
#include <math.h>

#define NBITS 2800
#define PARAM_LEN (DEC_NPRM_DIV * NB_DIV + NPRM_LPC_NEW)

typedef struct { Word32 rate; Word16 bw_min, bw_max; } RateRange;

static const RateRange ranges[] = {
    {9600, 0, 2}, {13200, 0, 2}, {16400, 0, 3}, {24400, 0, 3},
    {32000, 1, 3}, {48000, 1, 3}, {96000, 1, 3}, {128000, 1, 3},
};
#define NRANGES (int)(sizeof(ranges) / sizeof(ranges[0]))

static UWord16 bits[NBITS + 64];
static Word16 param[PARAM_LEN];
static Word16 synth_buf[2 * L_FRAME_MAX + 64], synthFB_buf[2 * L_FRAME_MAX + 64];

typedef struct {
    Decoder_State_fx *st;
    Word32 rate;
    Word16 bw;
    Word16 output_fs;
} Run;

/* ---------------------------------------------------------------- random helpers */

/* A stable LPC filter A(z) = 1 + a1 z^-1 + ... in Q12 (a[0] = 4096), by the step-up recursion on random
 * reflection coefficients. */
static void random_lpc(Word16 *a)
{
    for (int attempt = 0;; attempt++) {
        double poly[M + 1] = {1.0}, next[M + 1];
        double u = 0.2 + 0.75 * (double)(next_random() % 1000) / 1000.0 / (1.0 + attempt * 0.4);
        double decay = 0.80 + 0.17 * (double)(next_random() % 1000) / 1000.0;
        int ok = 1;
        for (int m = 1; m <= M; m++) {
            double k = u * pow(decay, m - 1) * ((next_random() & 1) ? 1.0 : -1.0) * (0.3 + 0.7 * (double)(next_random() % 1000) / 1000.0);
            for (int j = 1; j < m; j++) next[j] = poly[j] + k * poly[m - j];
            for (int j = 1; j < m; j++) poly[j] = next[j];
            poly[m] = k;
        }
        a[0] = 4096;
        for (int j = 1; j <= M; j++) {
            double v = poly[j] * 4096.0;
            if (v > 30000 || v < -30000) ok = 0;
            a[j] = (Word16)lrint(v);
        }
        if (ok) return;
    }
}

static void put_bits(int *pos, int value, int n)
{
    for (int i = n - 1; i >= 0; i--) bits[(*pos)++] = (UWord16)((value >> i) & 1);
}

static void random_bits(int from, int to)
{
    int density = (int)(next_random() % 4);
    for (int i = from; i < to; i++)
        bits[i] = (UWord16)(density == 0 ? (next_random() % 5 == 0) : density == 1 ? (next_random() % 5 != 0) : (next_random() & 1));
}

/* ---------------------------------------------------------------- decoder set-up */

static Decoder_State_fx *new_decoder(Run *run)
{
    static const Word32 out_rates[] = {16000, 32000, 48000, 32000, 48000, 8000};
    const RateRange *range = &ranges[next_random() % NRANGES];
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    run->st = st;
    run->rate = range->rate;
    run->bw = (Word16)random_range(range->bw_min, range->bw_max);
    run->output_fs = (Word16)0;
    st->output_Fs_fx = out_rates[next_random() % 6];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);

    st->codec_mode = MODE2;
    st->last_codec_mode = MODE2;
    st->bwidth_fx = run->bw;
    st->total_brate_fx = run->rate;
    st->core_brate_fx = run->rate;
    st->last_total_brate_fx = run->rate;
    st->rf_flag = 0;
    st->use_partial_copy = 0;

    st->igf = getIgfPresent(run->rate, run->bw, st->rf_flag);
    st->hIGFDec.infoIGFStopFreq = -1;
    if (st->igf) IGFDecSetMode(&st->hIGFDec, run->rate, run->bw, -1, -1, st->rf_flag);
    open_decoder_LPD(st, run->rate, run->bw);

    Word16 frame_size = 0;
    for (int n = 0; n < FRAME_SIZE_NB; n++)
        if (FrameSizeConfig[n].frame_bits == (Word16)(run->rate / 50)) frame_size = FrameSizeConfig[n].frame_net_bits;
    reconfig_decoder_LPD(st, frame_size, run->bw, run->rate, st->L_frame_fx);
    st->ini_frame_fx = 1;

    st->bit_stream_fx = bits;
    st->total_num_bits = (Word16)(run->rate / 50);
    st->bits_frame_core = st->bits_frame;
    st->nbLostCmpt = 0;
    st->prev_bfi_fx = 0;
    st->bfi_fx = 0;

    /* the memories an ACELP frame leaves behind, and the history a TCX frame starts from */
    random_signal(st->old_syn_Overl, L_FRAME32k / 2, random_range(100, 8000));
    random_signal(st->syn_Overl_TDAC, L_FRAME32k / 2, random_range(100, 8000));
    random_signal(st->syn_Overl, L_FRAME32k / 2, random_range(100, 8000));
    random_signal(st->syn_OverlFB, L_FRAME_MAX / 2, random_range(100, 8000));
    random_signal(st->syn_Overl_TDACFB, L_FRAME_MAX / 2, random_range(100, 8000));
    random_signal(st->old_out_fx, L_FRAME_MAX, random_range(100, 8000));
    random_signal(st->old_out_LB_fx, L_FRAME32k, random_range(100, 8000));
    st->Q_old_wtda = (Word16)random_range(-2, 0);
    st->Q_old_wtda_LB = (Word16)random_range(-2, 0);
    st->tcx_cfg.last_aldo = (Word16)(next_random() & 1);
    random_lpc(st->old_Aq_12_8_fx);
    st->last_core_fx = TCX_20_CORE;
    st->last_core_bfi = TCX_20_CORE;
    st->last_core_bs_fx = TCX_20_CORE;
    st->tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;
    st->tcx_cfg.tcx_last_overlap_mode = ALDO_WINDOW;
    st->last_good_fx = (Word16)random_range(0, 7);
    st->cngTDLevel = (Word16)random_range(200, 32767);
    st->cngTDLevel_e = (Word16)random_range(-2, 8);
    st->Mode2_lp_gainp = (Word32)random_range(1 << 20, 1 << 29);
    st->old_fpitch = (Word32)random_range(40, 400) << 16;
    st->tcxltp_second_last_pitch = st->old_fpitch;
    st->tcxltp_third_last_pitch = st->old_fpitch;
    st->clas_dec = (Word16)random_range(0, 5);
    return st;
}

/* ---------------------------------------------------------------- one TCX frame */

typedef struct {
    int bfi;
    int core;            /* TCX_20_CORE or TCX_10_CORE */
    int last_core_bs;    /* 0 ACELP, 1 TCX */
    int overlap_bits;    /* 0, 2 or 3: the coded overlap mode of the frame */
    int coder_type;      /* INACTIVE..GENERIC */
    int clas_bits;       /* the class bits of a TCX-only frame */
} Spec;

static Spec random_spec(Run *run, int allow_acelp_last, int bfi)
{
    Spec s;
    s.bfi = bfi;
    s.core = (run->rate > 32000 && next_random() % 2 == 0) ? TCX_10_CORE : TCX_20_CORE;
    s.last_core_bs = (allow_acelp_last && s.core == TCX_20_CORE && next_random() % 4 == 0) ? 0 : 1;
    int pick = (int)(next_random() % 4);
    s.overlap_bits = pick == 0 ? 0 : pick == 1 ? 2 : 3;
    if (s.core == TCX_20_CORE && next_random() % 2) s.overlap_bits = 0;
    s.coder_type = random_range(0, 3);
    s.clas_bits = random_range(0, 3);
    return s;
}

/* Run dec_prm on a stream with the header of `spec` and a random body; returns 1 when the reference
 * accepts it (no BER_detect). */
static int read_parameters(Run *run, const Spec *spec, Word16 *coder_type)
{
    Decoder_State_fx *st = run->st;
    int pos = 0;
    if (st->tcxonly) {
        put_bits(&pos, spec->core - 1, 1);
        put_bits(&pos, spec->clas_bits, 2);
    } else {
        put_bits(&pos, ACELP_MODE_MAX + spec->coder_type, 3);
    }
    /* last core of the bit stream: read when the core is TCX */
    put_bits(&pos, spec->last_core_bs, 1);
    /* the overlap mode */
    if (spec->overlap_bits == 0) put_bits(&pos, 0, 1);
    else { put_bits(&pos, 1, 1); put_bits(&pos, spec->overlap_bits - 2, 1); }
    random_bits(pos, NBITS);
    for (int i = NBITS; i < NBITS + 64; i++) bits[i] = 0;

    st->next_bit_pos_fx = 0;
    st->BER_detect = 0;
    st->bits_frame_core = st->bits_frame;
    Word16 total_nbbits = (Word16)(run->rate / 50), bits_read = 0;
    memset(param, 0, sizeof param);
    st->core_fx = TCX_20_CORE;
    *coder_type = (Word16)spec->coder_type;
    dec_prm(coder_type, param, param + DEC_NPRM_DIV * NB_DIV, &total_nbbits, st, st->L_frame_fx, &bits_read);
    return !st->BER_detect && st->core_fx == spec->core;
}

/* decoder_LPD's bookkeeping before decoder_tcx of a good frame */
static void before_good_frame(Decoder_State_fx *st)
{
    st->bfi_fx = 0;
    st->prev_nbLostCmpt = st->prev_bfi_fx ? st->nbLostCmpt : 0;
    st->nbLostCmpt = 0;
}

/* decoder_LPD's bookkeeping after a frame (updt_dec_fx and the end of decoder_LPD) */
static void after_frame(Decoder_State_fx *st, int bfi)
{
    st->last_core_bfi = st->core_fx;
    st->last_core_fx = st->core_fx;
    st->prev_bfi_fx = (Word16)bfi;
    st->last_is_cng = 0;
    if (!bfi) st->last_good_fx = st->clas_dec;
}

typedef struct {
    Word16 a[M + 1], a_ind[M + 1];
    Word16 coder_type, stab_fac, l_frame_glob, l_frame_tcx_glob, l_spec, frame_cnt;
} Frame;

static void frame_arguments(Decoder_State_fx *st, Frame *f, int k)
{
    random_lpc(f->a);
    random_lpc(f->a_ind);
    f->stab_fac = (Word16)random_range(0, 16384);
    if (st->core_fx == TCX_10_CORE) {
        f->l_frame_glob = shr(st->L_frame_fx, 1);
        f->l_frame_tcx_glob = shr(st->L_frameTCX, 1);
        f->l_spec = shr(st->tcx_cfg.tcx_coded_lines, 1);
    } else {
        f->l_frame_glob = st->L_frame_fx;
        f->l_frame_tcx_glob = st->L_frameTCX;
        f->l_spec = st->tcx_cfg.tcx_coded_lines;
    }
    f->frame_cnt = (Word16)k;
}

/* decoder_tcx leaves part of the full-band overlap of a TCX-10 frame in the special overlap case
 * (frame_cnt 0, full overlap on both sides) unwritten: IMDCT never fills xn_bufFB beyond
 * overlap/2 + min_overlap/2 past the frame, and the reference copies that uninitialised stack into
 * syn_OverlFB. The next sub-frame windows only the minimum overlap of it, so it never reaches the
 * output, but the state would otherwise hold stack residue. The port keeps zeros there; scrub the
 * reference the same way so the whole state can be compared. */
static void call_tcx(Decoder_State_fx *st, Frame *f, Word16 *prm, int k, Word16 bfi)
{
    int offset = k * f->l_frame_glob, offset_fb = k * f->l_frame_tcx_glob;
    int special = bfi == 0 && f->frame_cnt == 0 && st->tcxonly && st->core_fx == TCX_10_CORE &&
                  st->tcx_cfg.tcx_last_overlap_mode == FULL_OVERLAP && st->tcx_cfg.tcx_curr_overlap_mode == FULL_OVERLAP;
    decoder_tcx(&st->tcx_cfg, prm, f->a, f->a_ind, f->l_frame_glob, f->l_frame_tcx_glob, f->l_spec,
                synth_buf + offset, synthFB_buf + offset_fb, st, f->coder_type, bfi, f->frame_cnt, f->stab_fac);
    if (special) {
        int from = st->tcx_cfg.tcx_mdct_window_lengthFB / 2 + st->tcx_cfg.tcx_mdct_window_min_lengthFB / 2;
        for (int i = from; i < st->tcx_cfg.tcx_mdct_window_lengthFB; i++) st->syn_OverlFB[i] = 0;
    }
}

/* Run the frames of a TCX frame; `measure_k` selects the call whose state is captured (-1: none).
 * Returns 1 when the calls returned. */
typedef struct {
    int measure_k;
    char *before;
    Word16 prm_copy[DEC_NPRM_DIV * NB_DIV];
    Frame frame_copy;
    Word16 carry, overflow;
    Word16 bfi;
} Capture;

static void print_inputs(Capture *c, Run *run, Decoder_State_fx *st, Frame *f, Word16 *prm, int prm_len, Word16 bfi, int core)
{
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("rate", run->rate);
    put1("bw", run->bw);
    put1("core", core);
    put1("bfi", bfi);
    put1("carry", Carry);
    put1("overflow", Overflow);
    put16("prm", prm, prm_len);
    put16("a", f->a, M + 1);
    put16("a_ind", f->a_ind, M + 1);
    put1("coder_type", f->coder_type);
    put1("stab_fac", f->stab_fac);
    put1("l_frame_glob", f->l_frame_glob);
    put1("l_frame_tcx_glob", f->l_frame_tcx_glob);
    put1("l_spec", f->l_spec);
    put1("frame_cnt", f->frame_cnt);
    (void)c;
}

/* A good frame; `measure` -1 for none, otherwise 0 / 1 = the call (decoder_tcx k) to capture, or 100 for
 * the decoder_tcx_post of the frame. Returns 0 when dec_prm rejected the stream. */
static int run_good_frame(Run *run, const Spec *spec, int measure, Capture *capture, int with_post)
{
    Decoder_State_fx *st = run->st;
    Frame f;
    Word16 coder_type;
    /* after an ACELP frame that was concealed the first TCX frame follows a lost one (prev_bfi) */
    if (spec->last_core_bs == 0 && next_random() % 3 == 0) {
        st->prev_bfi_fx = 1;
        st->nbLostCmpt = (Word16)random_range(1, 5);
    }
    /* a TCX-20 frame after a CNG frame (CNG frames exist at the low rates only, where there is no TCX-10: a grouped
     * TCX-10 transform would take the ZIR memory from before its buffer, which the reference does not define) */
    st->last_is_cng = (Word8)(spec->last_core_bs != 0 && spec->core == TCX_20_CORE && next_random() % 6 == 0);
    if (!read_parameters(run, spec, &coder_type)) return 0;
    /* updt_dec keeps the core of the last frame, lost or not, in last_core_bfi, as dec_prm leaves last_core */
    st->last_core_bfi = st->last_core_fx;
    before_good_frame(st);
    memset(synth_buf, 0, sizeof synth_buf);
    memset(synthFB_buf, 0, sizeof synthFB_buf);
    int calls = st->core_fx == TCX_10_CORE ? 2 : 1;
    f.coder_type = coder_type;
    for (int k = 0; k < calls; k++) {
        Word16 *prm = param + k * DEC_NPRM_DIV;
        frame_arguments(st, &f, k);
        f.coder_type = coder_type;
        if (st->core_fx == TCX_10_CORE) IGFDecRestoreTCX10SubFrameData(&st->hIGFDec, (Word16)k);
        if (measure == k) {
            capture->before = capture_state(st);
            capture->carry = Carry;
            capture->overflow = Overflow;
            put_state_in(capture->before);
            print_inputs(capture, run, st, &f, prm, calls == 2 ? DEC_NPRM_DIV : DEC_NPRM_DIV * NB_DIV, 0, st->core_fx);
            call_tcx(st, &f, prm, k, 0);
            arrow();
            put1("carry_out", Carry);
            put16("synth", synth_buf + k * f.l_frame_glob, f.l_frame_glob);
            put16("synth_fb", synthFB_buf + k * f.l_frame_tcx_glob, f.l_frame_tcx_glob);
            return 2;
        }
        call_tcx(st, &f, prm, k, 0);
    }
    TonalMDCTConceal_SaveTimeSignal(&st->tonalMDCTconceal, synthFB_buf, st->L_frameTCX);
    if (with_post) {
        if (measure == 100) {
            Word16 aq[M + 1];
            random_lpc(aq);
            capture->before = capture_state(st);
            put_state_in(capture->before);
            put1("output_fs", st->output_Fs_fx);
            put1("output_frame", st->output_frame_fx);
            put1("rate", run->rate);
            put1("bw", run->bw);
            put1("bfi", 0);
            put1("carry", Carry);
            put1("overflow", Overflow);
            put16("synth", synth_buf, st->L_frame_fx);
            put16("synth_fb", synthFB_buf, st->L_frameTCX);
            put16("a", aq, M + 1);
            decoder_tcx_post(st, synth_buf, synthFB_buf, aq, 0);
            arrow();
            put1("carry_out", Carry);
            put16("synth", synth_buf, st->L_frame_fx);
            put16("synth_fb", synthFB_buf, st->L_frameTCX);
            return 2;
        }
        Word16 aq[M + 1];
        random_lpc(aq);
        decoder_tcx_post(st, synth_buf, synthFB_buf, aq, 0);
    }
    after_frame(st, 0);
    return 1;
}

/* A last good frame whose spectrum is tonal: harmonic peaks over a low floor, in the buffers the tonal concealment
 * reads (and in the pitch / activity state that makes GetPLCModeDecision run its detection), so that
 * the detection finds tonal components and the tonal concealment is used. */
static void make_last_frame_tonal(Decoder_State_fx *st)
{
    TonalMDCTConcealPtr t = &st->tonalMDCTconceal;
    blockData *blocks[2] = {&t->lastBlockData, &t->secondLastBlockData};
    int period = random_range(5, 14);
    for (int b = 0; b < 2; b++) {
        Word16 *d = blocks[b]->spectralData;
        int n = blocks[b]->nSamples;
        if (d == NULL || n <= 0 || n > 2 * L_FRAME_MAX) continue;
        for (int i = 0; i < n; i++) d[i] = (Word16)random_range(-300, 300);
        for (int k = random_range(2, period); k + 1 < n / 2; k += period) {
            d[k] = (Word16)(random_range(12000, 30000) * ((next_random() & 1) ? 1 : -1));
            d[k + 1] = (Word16)(d[k] / random_range(2, 6));
        }
    }
    /* the detection analyses the saved time signal: a harmonic one */
    {
        double f0 = (double)period / (2.0 * t->nSamples), phase[16];
        int harmonics = (int)(0.42 / f0);
        if (harmonics > 16) harmonics = 16;
        for (int h = 0; h < harmonics; h++) phase[h] = 6.283185307 * (double)(next_random() % 1000) / 1000.0;
        for (int i = 0; i < 1440; i++) {
            double v = 0;
            for (int h = 0; h < harmonics; h++) v += 2500.0 / (1 + h) * sin(6.283185307 * f0 * (h + 1) * i + phase[h]);
            t->timeDataBuffer[i] = (Word16)lrint(v);
        }
    }
    st->second_last_core = TCX_20_CORE;
    st->old_fpitch = (Word32)random_range(30, st->L_frame_fx / 2) << 16;
    st->tcxltp_second_last_pitch = st->old_fpitch;
    st->tcxltp_third_last_pitch = st->old_fpitch;
    st->last_tns_active = 0;
    st->second_last_tns_active = 0;
}

/* A concealed frame after at least one good one; the same measurement convention. Returns 0 when the
 * concealment mode decision is not TCX. */
static int run_lost_frame(Run *run, int measure, Capture *capture, int with_post)
{
    Decoder_State_fx *st = run->st;
    Frame f;
    st->bfi_fx = 1;
    st->use_partial_copy = 0;
    /* the frame class and the LTP gain of the last good frame decide whether the concealment is TCX
     * (GetPLCModeDecision); a low class and gain are the common case for it */
    if (st->nbLostCmpt == 0 && next_random() % 4 != 0) {
        st->last_good_fx = (Word16)random_range(0, 1);
        st->tcxltp_last_gain_unmodified = (Word16)random_range(0, 13107);
    }
    int tonal = st->nbLostCmpt == 0 && st->last_core_fx == TCX_20_CORE && next_random() % 2 == 0;
    if (tonal) make_last_frame_tonal(st);
    st->nbLostCmpt = (Word16)(st->nbLostCmpt + 1);
    if (st->enablePlcWaveadjust) st->plcInfo.nbLostCmpt++;
    st->core_fx = GetPLCModeDecision(st);
    if (tonal && st->core_fx == TCX_20_CORE && !st->tonal_mdct_plc_active) {
        /* the detection of GetPLCModeDecision found too little: run it on the tonal frame regardless, the state
         * it leaves is the one a successful detection leaves */
        Word16 num_indices = 0;
        Word32 pitch = st->tcxltp_last_gain_unmodified > 0 ? st->old_fpitch : 0;
        TonalMDCTConceal_Detect(&st->tonalMDCTconceal, pitch, &num_indices);
        if (num_indices > 0) st->tonal_mdct_plc_active = 1;
    }
    if (st->core_fx != TCX_20_CORE && st->core_fx != TCX_10_CORE) return 0;
    if (st->core_fx == TCX_10_CORE && !st->tcxonly) return 0;
    memset(synth_buf, 0, sizeof synth_buf);
    memset(synthFB_buf, 0, sizeof synthFB_buf);
    int calls = st->core_fx == TCX_10_CORE ? 2 : 1;
    Word16 coder_type = (Word16)random_range(0, 3);
    for (int k = 0; k < calls; k++) {
        Word16 *prm = param + k * DEC_NPRM_DIV;
        frame_arguments(st, &f, k);
        f.coder_type = coder_type;
        if (st->core_fx == TCX_10_CORE) IGFDecRestoreTCX10SubFrameData(&st->hIGFDec, (Word16)k);
        if (measure == k) {
            capture->before = capture_state(st);
            put_state_in(capture->before);
            print_inputs(capture, run, st, &f, prm, calls == 2 ? DEC_NPRM_DIV : DEC_NPRM_DIV * NB_DIV, 1, st->core_fx);
            call_tcx(st, &f, prm, k, 1);
            arrow();
            put1("carry_out", Carry);
            put16("synth", synth_buf + k * f.l_frame_glob, f.l_frame_glob);
            put16("synth_fb", synthFB_buf + k * f.l_frame_tcx_glob, f.l_frame_tcx_glob);
            return 2;
        }
        call_tcx(st, &f, prm, k, 1);
    }
    if (with_post) {
        Word16 aq[M + 1];
        random_lpc(aq);
        if (measure == 100) {
            capture->before = capture_state(st);
            put_state_in(capture->before);
            put1("output_fs", st->output_Fs_fx);
            put1("output_frame", st->output_frame_fx);
            put1("rate", run->rate);
            put1("bw", run->bw);
            put1("bfi", 1);
            put1("carry", Carry);
            put1("overflow", Overflow);
            put16("synth", synth_buf, st->L_frame_fx);
            put16("synth_fb", synthFB_buf, st->L_frameTCX);
            put16("a", aq, M + 1);
            decoder_tcx_post(st, synth_buf, synthFB_buf, aq, 1);
            arrow();
            put1("carry_out", Carry);
            put16("synth", synth_buf, st->L_frame_fx);
            put16("synth_fb", synthFB_buf, st->L_frameTCX);
            return 2;
        }
        decoder_tcx_post(st, synth_buf, synthFB_buf, aq, 1);
    }
    after_frame(st, 1);
    return 1;
}

/* ---------------------------------------------------------------- cases */

/* one case of `function`: 0 decoder_tcx, 1 decoder_tcx_post; `lost` 1 measures a concealed frame */
static void case_tcx(int post)
{
    for (;;) {
        Run run;
        Capture capture;
        memset(&capture, 0, sizeof capture);
        Decoder_State_fx *st = new_decoder(&run);
        int lost = next_random() % 3 == 0;
        int warm = lost ? random_range(2, 3) : random_range(0, 2);
        int ok = 1;
        /* the very first good frame may follow ACELP */
        for (int i = 0; i < warm && ok; i++) {
            Spec spec = random_spec(&run, i == 0, 0);
            if (lost && i >= warm - 2 && next_random() % 4 != 0) { spec.core = TCX_20_CORE; spec.last_core_bs = 1; }
            if (lost && i == warm - 1 && run.rate > 32000 && next_random() % 3 == 0) {
                spec.core = TCX_10_CORE; spec.last_core_bs = 1;
                if (next_random() % 4 != 0) spec.overlap_bits = 2 + (int)(next_random() % 2);
            }
            if (!run_good_frame(&run, &spec, -1, &capture, 1)) ok = 0;
        }
        if (ok && lost && next_random() % 3 == 0) ok = run_lost_frame(&run, -1, &capture, 1) != 0;
        int result = 0;
        if (ok) {
            if (lost) {
                int calls_k = 0;
                (void)calls_k;
                result = run_lost_frame(&run, post ? 100 : (next_random() % 4 == 0 ? 1 : 0), &capture, 1);
                if (result == 1 && !post) result = 0; /* the chosen k does not exist (TCX-20 frame) */
            } else {
                Spec spec = random_spec(&run, warm == 0, 0);
                int k = post ? 100 : (spec.core == TCX_10_CORE ? (int)(next_random() % 2) : 0);
                result = run_good_frame(&run, &spec, k, &capture, 1);
                /* a TCX-10 frame measured at k = 1 first runs k = 0 inside run_good_frame */
            }
        }
        if (result == 2) {
            char *after = capture_state(st);
            put_changed(capture.before, after);
            free(after);
            free(capture.before);
            end_line();
            destroy_decoder(st);
            free(st);
            return;
        }
        if (capture.before) free(capture.before);
        /* the case did not pan out (stream rejected, no TCX concealment): output nothing for it, draw again;
         * output printed so far for this attempt is impossible because every print happens at the measured call */
        destroy_decoder(st);
        free(st);
    }
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decoder_tcx")) case_tcx(0);
        else if (!strcmp(argv[2], "decoder_tcx_post")) case_tcx(1);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
