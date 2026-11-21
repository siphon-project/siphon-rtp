/* Function-level oracle for lib_com/fd_cng_com.c. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_basop_util.h"
#include "stat_dec_fx.h"

/* From rom_com_fx.h. getmidbands reads psize[0] (its own output) before writing it, as the
 * starting maximum it asserts on (norm_s(-max) >= 9 also rejects 0), so every psize array here
 * starts as {1, 0, ...}. */
extern const Word16 maxN_37bits;
extern const Word16 stages_37bits;
extern const Word16 bits_37bits[6];
extern Word16 const * const cdk_37bits[];

static void case_rand_gauss(void)
{
    Word16 seed = random16();
    put1("seed", seed);
    Word32 r = rand_gauss(&seed);
    arrow(); put1("r", r); put1("seed", seed); end_line();
}

static void case_mhvals(void)
{
    Word16 d = next_random() & 1 ? 12 : 72, m = -1;
    put1("d", d);
    mhvals(d, &m);
    arrow(); put1("m", m); end_line();
}

static void case_init(void)
{
    HANDLE_FD_CNG_COM hs = NULL;
    Word16 scale = (Word16)random_range(16384, 32767); /* div_s needs invScalingFactor >= 0.5 */
    createFdCngCom(&hs);
    put1("scale", scale);
    initFdCngCom(hs, scale);
    arrow();
    put1("inv_scaling_factor", hs->invScalingFactor); put1("scaling_factor", hs->scalingFactor);
    put1("ms_m_win", hs->msM_win); put1("ms_m_subwin", hs->msM_subwin); put16("a_cng", hs->A_cng, M + 1);
    put1("frame_type_previous", hs->frame_type_previous); put32("ms_alpha_cor", hs->msAlphaCor, 2);
    put1("ms_fr_cnt", hs->msFrCnt); put1("ms_fr_cnt_init_thresh", hs->msFrCnt_init_thresh);
    end_line();
    deleteFdCngCom(&hs);
}

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
        a[i] = (Word16)(v > 32767 ? 32767 : v < -32768 ? -32768 : (int)(v < 0 ? v - 0.5 : v + 0.5));
    }
}

/* FdCng_exc on both frame lengths, with and without a CNG history (first_CNG). */
static void case_fd_cng_exc(void)
{
    HANDLE_FD_CNG_COM hs = NULL;
    Word16 mode = 7, L_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k), first_CNG = (Word16)(next_random() & 1);
    Word16 lsp_old[M], lsp_cng[M], Aq[NB_SUBFR16k * (M + 1)], lsp_new[M], lsf_new[M];
    Word16 exc[L_FRAME16k], exc2[L_FRAME16k], bwe_exc[2 * L_FRAME16k];
    createFdCngCom(&hs);
    random_lpc(hs->A_cng);
    random_signal(hs->exc_cng, L_FRAME16k, next_random() & 1 ? 20000 : 500);
    for (int i = 0; i < M; i++) lsp_old[i] = (Word16)(32000 - i * 3500 + random_range(-1000, 1000));
    for (int i = 0; i < M; i++) lsp_cng[i] = (Word16)(32000 - i * 3500 + random_range(-1000, 1000));
    for (int i = 0; i < NB_SUBFR16k * (M + 1); i++) Aq[i] = -12345;
    for (int i = 0; i < 2 * L_FRAME16k; i++) bwe_exc[i] = -12345;
    for (int i = 0; i < L_FRAME16k; i++) exc[i] = exc2[i] = -12345;
    put1("L_frame", L_frame); put1("first_CNG", first_CNG); put16("a_cng", hs->A_cng, M + 1);
    put16("exc_cng", hs->exc_cng, L_FRAME16k); put16("lsp_old", lsp_old, M); put16("lsp_cng", lsp_cng, M);
    FdCng_exc(hs, &mode, L_frame, lsp_old, first_CNG, lsp_cng, Aq, lsp_new, lsf_new, exc, exc2, bwe_exc);
    arrow(); put1("mode", mode); put16("Aq", Aq, NB_SUBFR16k * (M + 1)); put16("lsp_new", lsp_new, M);
    put16("lsf_new", lsf_new, M); put16("lsp_cng", lsp_cng, M); put16("exc", exc, L_FRAME16k);
    put16("exc2", exc2, L_FRAME16k); put16("bwe_exc", bwe_exc, 2 * L_FRAME16k); end_line();
    deleteFdCngCom(&hs);
}

static void case_compress_range(void)
{
    Word32 in[NPART_SHAPING];
    Word16 out[NPART_SHAPING];
    Word16 len = (Word16)random_range(1, NPART_SHAPING), in_exp = (Word16)random_range(-20, 30);
    for (int i = 0; i < len; i++) {
        int k = next_random() % 8;
        /* energies: non-negative (BASOP_Util_Log2 asserts on a negative argument) */
        in[i] = k == 0 ? 0 : k == 1 ? (Word32)(random32() & 0x7fffffff) : (Word32)(next_random() >> random_range(1, 31));
    }
    put32("in", in, len); put1("in_exp", in_exp); put1("len", len);
    compress_range(in, in_exp, out, len);
    arrow(); put16("out", out, len); end_line();
}

static void case_expand_range(void)
{
    Word16 in[NPART_SHAPING];
    Word32 out[NPART_SHAPING];
    Word16 len = (Word16)random_range(1, NPART_SHAPING), out_exp = -99;
    int top = next_random() & 1 ? 20000 : 32767;
    int quiet = next_random() % 4 == 0; /* a near-silent band set: 2^in - 1 rounds to 0 */
    for (int i = 0; i < len; i++) in[i] = (Word16)(next_random() % 8 ? random_range(0, top) : random16());
    if (quiet) for (int i = 0; i < len; i++) in[i] = (Word16)(next_random() % 3 ? 0 : random_range(0, 1100));
    put16("in", in, len); put1("len", len);
    expand_range(in, out, &out_exp, len);
    arrow(); put32("out", out, len); put1("out_exp", out_exp); end_line();
}

/* Increasing partition bounds part[0..npart) with sizes 1..max_size, the last one nband - 1. */
static Word16 random_parts(Word16 *part, int npart_max, int max_size)
{
    int npart = random_range(1, npart_max), at = -1;
    for (int p = 0; p < npart; p++) { at += random_range(1, max_size); part[p] = (Word16)at; }
    return (Word16)npart;
}

static void case_init_partitions(void)
{
    Word16 part_in[40], part_out[NPART_SHAPING], midband[NPART_SHAPING], psize[NPART_SHAPING] = {1};
    Word16 psize_norm[NPART_SHAPING], psize_inv[NPART_SHAPING], npart_out = -1, psize_norm_exp = -1;
    int with_table = next_random() % 4 != 0;
    Word16 npart_in = random_parts(part_in, 30, 12);
    Word16 start_band = (Word16)random_range(0, 8);
    Word16 stop_band_fr = (Word16)random_range(0, start_band + 30);
    Word16 stop_band = with_table ? (Word16)random_range(start_band + 1, part_in[npart_in - 1] + 10)
                                  : (Word16)random_range(start_band + 1, start_band + NPART_SHAPING);
    put1("with_table", with_table); put16("part_in", part_in, npart_in); put1("npart_in", npart_in);
    put1("start_band", start_band); put1("stop_band", stop_band); put1("stop_band_fr", stop_band_fr);
    initPartitions(with_table ? part_in : NULL, npart_in, start_band, stop_band, part_out, &npart_out, midband, psize,
                   psize_norm, &psize_norm_exp, psize_inv, stop_band_fr);
    arrow(); put1("npart", npart_out);
    put16("part", part_out, npart_out); put16("midband", midband, npart_out); put16("psize", psize, npart_out);
    put16("psize_norm", psize_norm, npart_out); put1("psize_norm_exp", psize_norm_exp);
    put16("psize_inv", psize_inv, npart_out); end_line();
}

static void case_bandcombinepow(void)
{
    Word16 part[NPART_SHAPING], midband[NPART_SHAPING], psize[NPART_SHAPING] = {1}, psize_norm[NPART_SHAPING];
    Word16 psize_inv[NPART_SHAPING], psize_norm_exp, exp_partpow = -99;
    Word32 bandpow[320], partpow[NPART_SHAPING];
    Word16 npart = random_parts(part, NPART_SHAPING, next_random() & 1 ? 1 : 10);
    Word16 nband = (Word16)(part[npart - 1] + 1);
    if (nband > 318) { npart = 1; part[0] = 9; nband = 10; }
    getmidbands(part, npart, midband, psize, psize_norm, &psize_norm_exp, psize_inv);
    Word16 exp_bandpow = (Word16)random_range(-10, 30);
    for (int i = 0; i < nband; i++) {
        int k = next_random() % 8;
        bandpow[i] = k == 0 ? 0 : k == 1 ? (Word32)(next_random() & 0x7fffffff) : (Word32)(next_random() >> random_range(1, 31));
    }
    put16("part", part, npart); put1("npart", npart); put1("nband", nband); put16("psize_inv", psize_inv, npart);
    put32("bandpow", bandpow, nband); put1("exp_bandpow", exp_bandpow);
    bandcombinepow(bandpow, exp_bandpow, nband, part, npart, psize_inv, partpow, &exp_partpow);
    arrow(); put32("partpow", partpow, npart); put1("exp_partpow", exp_partpow); end_line();
}

static void case_scalebands(void)
{
    Word16 part[NPART_SHAPING], midband[NPART_SHAPING], psize[NPART_SHAPING] = {1}, psize_norm[NPART_SHAPING];
    Word16 psize_inv[NPART_SHAPING], psize_norm_exp;
    Word32 bandpow[320], partpow[NPART_SHAPING];
    Word16 npart = random_parts(part, NPART_SHAPING, next_random() & 1 ? 3 : 10);
    if (part[npart - 1] >= 318) { npart = 2; part[0] = 4; part[1] = 9; }
    Word16 nband = (Word16)(part[npart - 1] + 1);
    Word16 nfftpart = (Word16)(next_random() & 1 ? npart : random_range(1, npart));
    Word16 flag = (Word16)(next_random() % 4 != 0);
    if (!flag && nfftpart == npart) flag = 1; /* nothing would be written */
    getmidbands(part, npart, midband, psize, psize_norm, &psize_norm_exp, psize_inv);
    for (int p = 0; p < npart; p++) {
        int k = next_random() % 8;
        partpow[p] = k == 0 ? 0 : k == 1 ? (Word32)(next_random() & 0x7fffffff) : (Word32)(next_random() >> random_range(1, 31));
    }
    for (int i = 0; i < 320; i++) bandpow[i] = 12345;
    put32("partpow", partpow, npart); put16("part", part, npart); put1("npart", npart);
    put16("midband", midband, npart); put1("nfftpart", nfftpart); put1("nband", nband); put1("flag", flag);
    scalebands(partpow, part, npart, midband, nfftpart, nband, bandpow, flag);
    arrow(); put32("bandpow", bandpow, nband); end_line();
}

static void case_getmidbands(void)
{
    Word16 part[NPART_SHAPING], midband[NPART_SHAPING], psize[NPART_SHAPING] = {1}, psize_norm[NPART_SHAPING];
    Word16 psize_inv[NPART_SHAPING], psize_norm_exp = -1;
    Word16 npart = random_parts(part, NPART_SHAPING, 20);
    put16("part", part, npart); put1("npart", npart);
    getmidbands(part, npart, midband, psize, psize_norm, &psize_norm_exp, psize_inv);
    arrow(); put16("midband", midband, npart); put16("psize", psize, npart); put16("psize_norm", psize_norm, npart);
    put1("psize_norm_exp", psize_norm_exp); put16("psize_inv", psize_inv, npart); end_line();
}

/* minimum_statistics over FRAMES consecutive frames of a noise-like log periodogram with bursts. */
#define FRAMES 40
static void case_minimum_statistics(void)
{
    HANDLE_FD_CNG_DEC hs = calloc(1, sizeof(FD_CNG_DEC));
    createFdCngCom(&hs->hFdCngCom);
    HANDLE_FD_CNG_COM st = hs->hFdCngCom;
    initFdCngCom(st, (Word16)random_range(16384, 32767));
    Word16 part[NPART_SHAPING], midband[NPART_SHAPING], psize[NPART_SHAPING] = {1}, psize_norm[NPART_SHAPING];
    Word16 psize_inv[NPART_SHAPING], psize_norm_exp;
    Word16 len = random_parts(part, NPART_SHAPING, 8);
    if (len < 2) { len = 2; part[0] = 3; part[1] = 7; }
    Word16 len_fft = (Word16)(next_random() % 4 ? len : random_range(1, len - 1));
    getmidbands(part, len, midband, psize, psize_norm, &psize_norm_exp, psize_inv);
    st->startBand = (Word16)random_range(0, 2);
    st->stopFFTbin = (Word16)(st->startBand + part[len_fft - 1] + 1);
    st->stopBand = (Word16)(st->startBand + part[len - 1] + 1);
    if (next_random() & 1) st->init_old = 32767;
    put1("len", len); put1("len_fft", len_fft); put16("psize", psize_norm, len); put1("start_band", st->startBand);
    put1("stop_fft_bin", st->stopFFTbin); put1("stop_band", st->stopBand); put1("init_old", st->init_old);
    put1("ms_m_win", st->msM_win); put1("ms_m_subwin", st->msM_subwin);
    int level = random_range(2000, 16000), spread = random_range(10, 2000);
    Word16 est[FRAMES][NPART_SHAPING];
    int silence = 0; /* frames left in a near-silent stretch (the offset reset) */
    for (int f = 0; f < FRAMES; f++) {
        Word16 periodog[NPART_SHAPING];
        int burst = (next_random() % 6 == 0) ? random_range(500, 6000) : 0;
        if (silence == 0 && next_random() % 10 == 0) silence = random_range(1, 4);
        if (next_random() % 30 == 0) level = random_range(2000, 16000); /* a sudden level change */
        for (int i = 0; i < len; i++) {
            int v = silence ? random_range(1, 60) : level + burst + random_range(-spread, spread);
            periodog[i] = (Word16)(v < 1 ? 1 : v > 32767 ? 32767 : v);
        }
        if (next_random() % 20 == 0) periodog[0] = 1;
        if (silence) silence--;
        char name[24]; sprintf(name, "periodog%d", f); put16(name, periodog, len);
        minimum_statistics(len, len_fft, psize_norm, periodog, hs->msNoiseFloor, hs->msLogNoiseEst, hs->msAlpha,
                           hs->msPsd, hs->msPsdFirstMoment, hs->msPsdSecondMoment, hs->msMinBuf, hs->msBminWin,
                           hs->msBminSubWin, hs->msCurrentMin, hs->msCurrentMinOut, hs->msCurrentMinSubWindow,
                           hs->msLocalMinFlag, hs->msNewMinFlag, hs->msPeriodogBuf, &hs->msPeriodogBufPtr, st);
        memcpy(est[f], hs->msLogNoiseEst, sizeof(est[f]));
    }
    arrow();
    for (int f = 0; f < FRAMES; f++) { char name[16]; sprintf(name, "est%d", f); put16(name, est[f], len); }
    put16("noise_floor", hs->msNoiseFloor, len); put32("alpha", hs->msAlpha, len); put16("psd", hs->msPsd, len);
    put16("first_moment", hs->msPsdFirstMoment, len); put32("second_moment", hs->msPsdSecondMoment, len);
    put32("min_buf", hs->msMinBuf, 6 * len); put32("bmin_win", hs->msBminWin, len);
    put32("bmin_sub_win", hs->msBminSubWin, len); put32("current_min", hs->msCurrentMin, len);
    put32("current_min_out", hs->msCurrentMinOut, len); put32("current_min_sub_window", hs->msCurrentMinSubWindow, len);
    put16("local_min_flag", hs->msLocalMinFlag, len); put16("new_min_flag", hs->msNewMinFlag, len);
    put16("periodog_buf", hs->msPeriodogBuf, 5 * len); put1("periodog_buf_ptr", hs->msPeriodogBufPtr);
    put32("periodog_sum", st->msPeriodogSum, 2); put32("psd_sum", st->msPsdSum, 2); put32("alpha_cor", st->msAlphaCor, 2);
    put16("slope", st->msSlope, 2); put32("qeq_inv_av", st->msQeqInvAv, 2); put1("fr_cnt", st->msFrCnt);
    put1("min_buffer_ptr", st->msMinBufferPtr); put1("offsetflag", st->offsetflag); put1("init_old", st->init_old);
    put1("init_counter", st->msFrCnt_init_counter);
    end_line();
    deleteFdCngCom(&hs->hFdCngCom);
    free(hs);
}

static void case_analysis_stft(void)
{
    HANDLE_FD_CNG_COM st = NULL;
    Word16 olap[320], input[320];
    Word32 fft[640];
    createFdCngCom(&st);
    initFdCngCom(st, 16384);
    st->fftlen = next_random() & 1 ? 512 : 640;
    st->frameSize = st->fftlen / 2;
    st->olapBufferAna = olap;
    BASOP_getTables(&st->olapWinAna, NULL, NULL, shr(st->fftlen, 1));
    random_signal(olap, 320, 20000);
    Word16 Q = (Word16)random_range(0, 4);
    put1("fftlen", st->fftlen); put1("Q", Q); put16("olap", olap, st->fftlen - st->frameSize);
    Word32 outs[2][640]; Word16 exps[2];
    for (int f = 0; f < 2; f++) {
        random_signal(input, st->frameSize, next_random() & 1 ? 32767 : 2000);
        char name[16]; sprintf(name, "input%d", f); put16(name, input, st->frameSize);
        AnalysisSTFT(input, Q, fft, &exps[f], st);
        memcpy(outs[f], fft, sizeof(fft));
    }
    arrow();
    for (int f = 0; f < 2; f++) { char name[16]; sprintf(name, "fft%d", f); put32(name, outs[f], st->fftlen);
        sprintf(name, "exp%d", f); put1(name, exps[f]); }
    put16("olap", olap, st->fftlen - st->frameSize);
    end_line();
    deleteFdCngCom(&st);
}

static void case_synthesis_stft(void)
{
    HANDLE_FD_CNG_COM st = NULL;
    Word16 output[320];
    createFdCngCom(&st);
    initFdCngCom(st, 16384);
    st->fftlen = next_random() & 1 ? 512 : 640;
    st->frameSize = st->fftlen / 2;
    st->fftlenShift = st->fftlen == 512 ? 8 : 9;
    st->fftlenFac = st->fftlen == 512 ? 32767 : 20480;
    BASOP_getTables(&st->olapWinSyn, NULL, NULL, shr(st->fftlen, 2));
    random_signal(st->olapBufferSynth, st->fftlen, 20000);
    Word16 gen_exc = (Word16)random_range(0, 2), Q_new = (Word16)random_range(0, 12);
    st->A_cng[0] = 4096;
    for (int i = 1; i <= M; i++) st->A_cng[i] = (Word16)random_range(-6000 * (M + 1 - i) / M, 6000 * (M + 1 - i) / M);
    put1("fftlen", st->fftlen); put16("olap", st->olapBufferSynth, st->fftlen);
    put1("gen_exc", gen_exc); put1("Q_new", Q_new); put16("A_cng", st->A_cng, M + 1);
    Word16 outs[2][320], excs[2][320], qs[2];
    for (int f = 0; f < 2; f++) {
        Word16 tcx_transition = (Word16)(next_random() % 4 == 0);
        Word16 exp = (Word16)random_range(-10, 20);
        int shift = random_range(4, 31);
        for (int i = 0; i < st->fftlen; i++) st->fftBuffer[i] = (Word32)((Word32)(next_random() << 1) >> shift);
        char name[24];
        sprintf(name, "fft%d", f); put32(name, st->fftBuffer, st->fftlen);
        sprintf(name, "exp%d", f); put1(name, exp);
        sprintf(name, "tcx_transition%d", f); put1(name, tcx_transition);
        SynthesisSTFT(st->fftBuffer, exp, output, st->olapBufferSynth, st->olapWinSyn, tcx_transition, st, gen_exc, &Q_new);
        memcpy(outs[f], output, sizeof(output));
        memcpy(excs[f], st->exc_cng, sizeof(excs[f]));
        qs[f] = Q_new;
    }
    arrow();
    for (int f = 0; f < 2; f++) {
        char name[16]; sprintf(name, "out%d", f); put16(name, outs[f], st->frameSize);
        sprintf(name, "exc%d", f); put16(name, excs[f], st->frameSize);
        sprintf(name, "q%d", f); put1(name, qs[f]);
    }
    put16("olap", st->olapBufferSynth, st->fftlen);
    end_line();
    deleteFdCngCom(&st);
}

/* lpc_from_spectrum as FdCng_decodeSID (preemphasis) and the concealment update (none) call it:
 * a non-negative noise level over bins startBand..stopFFTbin of a 512 or 640 FFT. */
static void case_lpc_from_spectrum(void)
{
    static const Word16 stops[] = {160, 256, 256, 320};
    static const Word16 preemph[] = {0, 22282, 23593, 0};
    Word32 powspec[FFTLEN2];
    Word16 a[M + 1];
    Word16 fftlen = next_random() & 1 ? 512 : 640, start = 2;
    Word16 stop = stops[next_random() % 4];
    if (stop > fftlen / 2) stop = fftlen / 2;
    Word16 exp = (Word16)random_range(-10, 40);
    Word16 pre = next_random() % 4 ? preemph[next_random() % 4] : random16() & 0x7fff;
    int shift = random_range(1, 31), quiet = next_random() % 8 == 0;
    for (int i = 0; i < stop - start; i++) {
        powspec[i] = (Word32)((next_random() & 0x7fffffff) >> shift);
        if (quiet) powspec[i] = random_range(0, 3);
    }
    put32("powspec", powspec, stop - start); put1("exp", exp); put1("start", start); put1("stop", stop);
    put1("fftlen", fftlen); put1("preemph", pre);
    lpc_from_spectrum(powspec, exp, start, stop, fftlen, a, M, pre);
    arrow(); put16("a", a, M + 1); end_line();
}

static void case_msvq_decoder(void)
{
    Word16 idx[6], uq[32];
    Word16 n = (Word16)random_range(17, 24);
    for (int s = 0; s < stages_37bits; s++) idx[s] = (Word16)random_range(0, (1 << bits_37bits[s]) - 1);
    put16("idx", idx, stages_37bits); put1("n", n);
    msvq_decoder(cdk_37bits, stages_37bits, n, maxN_37bits, idx, uq);
    arrow(); put16("uq", uq, n); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "rand_gauss")) case_rand_gauss();
        else if (!strcmp(argv[2], "fd_cng_exc")) case_fd_cng_exc();
        else if (!strcmp(argv[2], "mhvals")) case_mhvals();
        else if (!strcmp(argv[2], "init")) case_init();
        else if (!strcmp(argv[2], "compress_range")) case_compress_range();
        else if (!strcmp(argv[2], "expand_range")) case_expand_range();
        else if (!strcmp(argv[2], "init_partitions")) case_init_partitions();
        else if (!strcmp(argv[2], "getmidbands")) case_getmidbands();
        else if (!strcmp(argv[2], "bandcombinepow")) case_bandcombinepow();
        else if (!strcmp(argv[2], "scalebands")) case_scalebands();
        else if (!strcmp(argv[2], "minimum_statistics")) case_minimum_statistics();
        else if (!strcmp(argv[2], "analysis_stft")) case_analysis_stft();
        else if (!strcmp(argv[2], "synthesis_stft")) case_synthesis_stft();
        else if (!strcmp(argv[2], "lpc_from_spectrum")) case_lpc_from_spectrum();
        else if (!strcmp(argv[2], "msvq_decoder")) case_msvq_decoder();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
