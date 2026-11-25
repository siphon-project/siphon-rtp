/* The MODE2 concealment state of a decoder after some good frames, for the oracles of con_acelp and
 * con_tcx: a decoder configured by init_decoder_fx and open_decoder_LPD at an LPD core rate and
 * bandwidth, then loaded with the memories the concealment reads (LPC filters from reflection
 * coefficients so the synthesis stays stable, a pitch trajectory, an excitation history that
 * repeats the last pitch cycle, gains, noise levels and seeds), in the ranges the decoder leaves
 * them in. Include after init_dec.c (STATE_DUMP_LIBRARY) and state_capture.h. */
#ifndef EVS_ORACLE_M2CONCEAL_STATE_H
#define EVS_ORACLE_M2CONCEAL_STATE_H

#include <math.h>

/* a stable LPC filter a[0..order] (Q12) from random reflection coefficients */
static void m2c_random_lpc(Word16 *a, int order)
{
    double work[40] = {1.0}, next[40];
    double bound = (next_random() % 4 == 0) ? 0.97 : 0.8;
    for (int i = 1; i <= order; i++) {
        double k = (random_range(-1000, 1000) / 1000.0) * bound / (1.0 + 0.05 * i);
        for (int j = 1; j < i; j++) next[j] = work[j] + k * work[i - j];
        for (int j = 1; j < i; j++) work[j] = next[j];
        work[i] = k;
    }
    a[0] = 4096;
    for (int i = 1; i <= order; i++) {
        double v = work[i] * 4096.0;
        a[i] = (Word16)(v > 32767 ? 32767 : v < -32768 ? -32768 : (int)floor(v + 0.5));
    }
}

/* the LPD core configuration an ACELP (core 0) or TCX concealment runs at: any rate and bandwidth
 * the LPD core supports; the first of the pair is the core rate in kbit/s */
static void m2c_configure(Decoder_State_fx *st, int output_index, int max_l_frame)
{
    static const Word32 output_rates[] = {8000, 16000, 32000, 48000};
    for (;;) {
        static const Word32 rates[] = {9600, 13200, 16400, 24400, 32000, 48000, 96000, 128000};
        Word32 bitrate = rates[next_random() % 8];
        Word16 bandwidth = (Word16)random_range(NB, FB);
        if (bandwidth == NB && bitrate > 24400) continue;
        if (bandwidth == SWB && bitrate < 13200) continue;
        if (bandwidth == FB && bitrate < 16400) continue;
        st->output_Fs_fx = output_rates[output_index];
        if (bandwidth >= SWB && st->output_Fs_fx < 32000) continue;
        if (bandwidth == WB && st->output_Fs_fx < 16000) continue;
        st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
        init_decoder_fx(st);
        rd_record_cldfb(st);
        st->codec_mode = MODE2;
        st->bwidth_fx = bandwidth;
        st->total_brate_fx = bitrate;
        st->core_brate_fx = bitrate;
        open_decoder_LPD(st, bitrate, bandwidth);
        if (st->L_frame_fx > max_l_frame) { destroy_decoder(st); memset(st, 0, sizeof *st); continue; }
        return;
    }
}

/* the pitch memories: a steady, rising or falling trajectory near the last pitch */
static void m2c_random_pitch(Decoder_State_fx *st)
{
    int pmin = st->pit_min, pmax = st->pit_max;
    if (pmax - pmin < 40) pmax = pmin + 40;
    double lag = random_range(pmin + 5, pmax - 25) + random_range(0, 99) / 100.0;
    double slope = (next_random() % 3) ? random_range(-150, 150) / 100.0 : 0;
    for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++) {
        double v = lag + slope * (i - 2 * NB_SUBFR16k);
        if (next_random() % 16 == 0) v += random_range(-20, 20);
        if (v < pmin) v = pmin;
        if (v > pmax) v = pmax;
        st->old_pitch_buf_fx[i] = (Word32)(v * 65536.0);
    }
    st->old_fpitch = st->old_pitch_buf_fx[2 * st->nb_subfr - 1];
    if (next_random() % 8 == 0) st->old_fpitch = (Word32)((pmin + random_range(0, pmax - pmin)) * 65536.0 + random_range(0, 65535));
    for (int i = 0; i < 2 * NB_SUBFR16k + 2; i++) st->mem_pitch_gain[i] = (Word16)random_range(4000, 19661);
    st->plc_use_future_lag = (Word8)((next_random() % 4) == 0);
}

/* the gains, levels and seeds both concealments carry */
static void m2c_random_gains(Decoder_State_fx *st)
{
    st->Mode2_lp_gainp = (Word32)random_range(0, 1 << 29);
    if (next_random() % 8 == 0) st->Mode2_lp_gainp = (next_random() & 1) ? 0 : (Word32)1 << 29;
    st->Mode2_lp_gainc = (Word32)random_range(0, 1 << random_range(8, 22));
    /* now and then a start-of-frame gain below the background level, which the concealment then raises */
    if (next_random() % 4 == 0) st->Mode2_lp_gainc = (Word32)random_range(0, 300);
    st->cummulative_damping = (Word16)random_range(2000, 32767);
    st->seed_acelp = random16();
    st->cngTDLevel = (Word16)random_range(328, 32767);
    st->cngTDLevel_e = (Word16)random_range(-4, 3);
    st->conCngLevelBackgroundTrace = (Word16)random_range(328, 32767);
    st->conCngLevelBackgroundTrace_e = (Word16)random_range(-4, 3);
    st->voice_fac = (Word16)random_range(-32768, 32767);
    st->last_voice_factor_fx = (Word16)random_range(0, 32767);
    st->last_gain_syn_deemph = (Word16)random_range(4000, 32767);
    st->last_gain_syn_deemph_e = (Word16)random_range(-3, 3);
    st->stab_fac_fx = (Word16)((next_random() % 4) ? random_range(0, 32767) : 32767);
    st->enr_old_fx = (Word32)random_range(0, 1 << 24);
    st->lp_ener_FER_fx = (Word16)random_range(0, 80 * 256);
    st->clas_dec = (Word16)random_range(UNVOICED_CLAS, INACTIVE_CLAS);
    st->classifier_Q_mem_syn = (Word16)random_range(-1, 4);
    st->last_core_brate_fx = (next_random() % 4) ? st->core_brate_fx : (Word32)(next_random() & 1 ? 6600 : 23850);
}

/* a pitched signal at the output rate: a few harmonics of `period` samples, with noise */
static void m2c_voiced_signal(Word16 *x, int n, double period, int amplitude)
{
    double phase = random_range(0, 628) / 100.0;
    int noise = amplitude / (int)(8 + next_random() % 40);
    for (int i = 0; i < n; i++) {
        double v = 0;
        for (int k = 1; k <= 4; k++) v += sin(phase + 6.283185307 * k * i / period) / k;
        x[i] = (Word16)(v * amplitude * 0.5 + random_range(-noise, noise));
    }
}

#endif
