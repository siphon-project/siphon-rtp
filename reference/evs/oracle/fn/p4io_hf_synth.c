/* Function-level oracle for the AMR-WB IO high band of lib_dec/hf_synth_fx.c: AdaptiveStartBand_fx,
 * envelope_fx (with EnhanceClass_fx), hf_synth_amr_wb_reset_fx and hf_synth_amr_wb_fx (which reaches
 * hf_synthesis_amr_wb_fx). The statics are reached by including the source. Inputs follow what
 * amr_wb_dec_fx feeds them: the nine AMR-WB bit rates, ISFs in Q2 on a 6.4 kHz scale (x2.56) with a
 * minimum gap, LP filters of a stable synthesis, Q_out = 0 (the CLDFB output is brought to Q0 before). */
#include "harness.h"
#include "../../c-code/lib_dec/hf_synth_fx.c"

static const Word32 amr_rates[] = {6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};
static const Word16 out_frames[] = {L_FRAME16k, L_FRAME32k, L_FRAME48k};

/* A stable LP filter of the interpolated ISPs of a speech frame: a[0] = 4096 or a power of two off it
 * (the dynamic scaling envelope_fx undoes), small taps. */
static void random_lpc(Word16 *a, int scale_shift)
{
    int base = 4096;
    a[0] = (Word16)(scale_shift >= 0 ? base << scale_shift : base >> -scale_shift);
    for (int k = 1; k <= M; k++) {
        int span = 9000 / (k + 2);
        int value = random_range(-span, span);
        a[k] = (Word16)(scale_shift >= 0 ? value << scale_shift : value >> -scale_shift);
    }
}

/* Sorted ISFs, at least 150 apart (Q2 of the x2.56 scale: 0 .. 16384): a spread of gaps summing to the range */
static void random_isf(Word16 *isf)
{
    int gap[M + 1], total = 0, position = 0;
    for (int i = 0; i <= M; i++) { gap[i] = random_range(1, 100); total += gap[i]; }
    int room = 16000 - 150 * M;
    for (int i = 0; i < M; i++) {
        position += gap[i];
        isf[i] = (Word16)(150 * (i + 1) + (long)room * position / total);
    }
}

static void case_adaptive_start_band(void)
{
    Word16 lsf[M], start_band = -1, voicing_flag = (Word16)(next_random() & 1), start_band_old = (Word16)random_range(40, 160);
    Word16 voicing_fac = (Word16)random_range(0, 16384), clas = (Word16)random_range(0, 7);
    Word32 rate = amr_rates[next_random() % 9];
    Word32 opt_crit_old = next_random() % 4 ? (Word32)random_range(0, 3000000) : 32768;
    random_isf(lsf);
    put1("rate", rate); put16("lsf", lsf, M); put1("voicing_fac", voicing_fac); put1("clas", clas);
    put1("voicing_flag", voicing_flag); put1("start_band_old", start_band_old); put1("opt_crit_old", opt_crit_old);
    AdaptiveStartBand_fx(&start_band, rate, lsf, voicing_fac, clas, &voicing_flag, &start_band_old, &opt_crit_old);
    arrow(); put1("start_band", start_band); put1("voicing_flag", voicing_flag); put1("start_band_old", start_band_old);
    put1("opt_crit_old", opt_crit_old); end_line();
}

static void case_envelope(void)
{
    Word16 aq[M + 1], ap[M + 1], sub_gain = -1;
    Word32 rate = amr_rates[next_random() % 9];
    Word16 tilt0 = (Word16)random_range(-4000, 16384), tilt = (Word16)random_range(-4000, 12000);
    Word16 voice_factor = (Word16)random_range(0, 32767), prev_r = (Word16)random_range(0, 12000);
    Word16 voice_fac = (Word16)random_range(0, 32767), unvoicing = (Word16)random_range(0, 32767);
    Word16 unvoicing_sm = (Word16)random_range(0, 32767), unvoicing_flag = (Word16)(next_random() & 1);
    random_lpc(aq, random_range(-1, 1));
    memset(ap, 0, sizeof(ap));
    put1("rate", rate); put16("aq", aq, M + 1); put1("tilt0", tilt0); put1("tilt", tilt); put1("voice_factor", voice_factor);
    put1("prev_r", prev_r); put1("voice_fac", voice_fac); put1("unvoicing", unvoicing); put1("unvoicing_sm", unvoicing_sm);
    put1("unvoicing_flag", unvoicing_flag);
    envelope_fx(rate, aq, ap, &sub_gain, tilt0, tilt, voice_factor, &prev_r, &voice_fac, &unvoicing, &unvoicing_sm, &unvoicing_flag);
    arrow(); put16("ap", ap, M + 1); put1("sub_gain", sub_gain); put1("prev_r", prev_r); put1("voice_fac", voice_fac);
    put1("unvoicing", unvoicing); put1("unvoicing_sm", unvoicing_sm); put1("unvoicing_flag", unvoicing_flag); end_line();
}

static void case_reset(void)
{
    Word16 seed2 = random16(), mem_syn_hf[M], mem_hp_interp[INTERP_3_1_MEM_LEN], delay_syn_hf[20];
    Word16 prev_r = random16(), fmerit_w_sm = random16(), frame_count = random16(), ne_min = random16(), fmerit_m_sm = random16();
    Word16 voice_fac = random16(), unvoicing = random16(), unvoicing_sm = random16(), unvoicing_flag = random16(), voicing_flag = random16();
    Word16 start_band_old = random16();
    Word32 opt_crit_old = random32();
    for (int i = 0; i < M; i++) mem_syn_hf[i] = random16();
    for (int i = 0; i < INTERP_3_1_MEM_LEN; i++) mem_hp_interp[i] = random16();
    for (int i = 0; i < 20; i++) delay_syn_hf[i] = random16();
    put1("seed2", seed2); put16("mem_syn_hf", mem_syn_hf, M); put16("mem_hp_interp", mem_hp_interp, INTERP_3_1_MEM_LEN);
    put16("delay_syn_hf", delay_syn_hf, 20);
    hf_synth_amr_wb_reset_fx(&seed2, mem_syn_hf, mem_hp_interp, &prev_r, &fmerit_w_sm, delay_syn_hf, &frame_count, &ne_min,
                             &fmerit_m_sm, &voice_fac, &unvoicing, &unvoicing_sm, &unvoicing_flag, &voicing_flag, &start_band_old, &opt_crit_old);
    arrow(); put1("seed2", seed2); put16("mem_syn_hf", mem_syn_hf, M); put16("mem_hp_interp", mem_hp_interp, INTERP_3_1_MEM_LEN);
    put16("delay_syn_hf", delay_syn_hf, 20); put1("prev_r", prev_r); put1("fmerit_w_sm", fmerit_w_sm); put1("frame_count", frame_count);
    put1("ne_min", ne_min); put1("fmerit_m_sm", fmerit_m_sm); put1("voice_fac", voice_fac); put1("unvoicing", unvoicing);
    put1("unvoicing_sm", unvoicing_sm); put1("unvoicing_flag", unvoicing_flag); put1("voicing_flag", voicing_flag);
    put1("start_band_old", start_band_old); put1("opt_crit_old", opt_crit_old); end_line();
}

static void case_hf_synth_amr_wb(void)
{
    Word16 aq[NB_SUBFR * (M + 1)], exc[L_FRAME], synth[L_FRAME], mem_syn_hf[M], delay_syn_hf[20], mem_hp_interp[INTERP_3_1_MEM_LEN];
    Word16 synth_out[L_FRAME48k], hf_gain[NB_SUBFR], voice_factors[NB_SUBFR], pitch_buf[NB_SUBFR], lsf_new[M];
    Word32 rate = amr_rates[next_random() % 9];
    Word16 output_frame = out_frames[next_random() % 3];
    Word16 prev_r = (Word16)random_range(0, 12000), fmerit_w_sm = (Word16)random_range(0, 8000), amr_io_class = (Word16)random_range(0, 7);
    Word16 fmerit = (Word16)random_range(0, 16384), ng_ener_st = (Word16)random_range(-13000, 1500);
    Word16 frame_count = (Word16)random_range(0, 220), ne_min = (Word16)random_range(-7680, 1500), fmerit_m_sm = (Word16)random_range(0, 16384);
    Word16 voice_fac_sm = (Word16)random_range(0, 32767), unvoicing = (Word16)random_range(0, 32767), unvoicing_sm = (Word16)random_range(0, 32767);
    Word16 unvoicing_flag = (Word16)(next_random() & 1), voicing_flag = (Word16)(next_random() & 1), start_band_old = (Word16)random_range(40, 160);
    Word32 opt_crit_old = next_random() % 4 ? (Word32)random_range(0, 3000000) : 32768;
    Word16 q_exc = (Word16)random_range(0, 6), q_out = 0;
    int magnitude = random_range(300, 6000);
    for (int k = 0; k < NB_SUBFR; k++) {
        random_lpc(aq + k * (M + 1), 0);
        hf_gain[k] = (Word16)random_range(0, 15);
        voice_factors[k] = (Word16)random_range(0, 32767);
        pitch_buf[k] = (Word16)random_range(34 * 32, 231 * 32);
    }
    random_isf(lsf_new);
    random_signal(exc, L_FRAME, magnitude);
    random_signal(synth, L_FRAME, random_range(300, 9000));
    random_signal(synth_out, output_frame, random_range(100, 12000));
    for (int i = 0; i < M; i++) mem_syn_hf[i] = (Word16)random_range(-300, 300);
    for (int i = 0; i < 20; i++) delay_syn_hf[i] = (Word16)random_range(-300, 300);
    for (int i = 0; i < INTERP_3_1_MEM_LEN; i++) mem_hp_interp[i] = (Word16)random_range(-300, 300);
    put1("rate", rate); put1("output_frame", output_frame); put16("aq", aq, NB_SUBFR * (M + 1)); put16("exc", exc, L_FRAME);
    put16("synth", synth, L_FRAME); put16("mem_syn_hf", mem_syn_hf, M); put16("delay_syn_hf", delay_syn_hf, 20);
    put16("mem_hp_interp", mem_hp_interp, INTERP_3_1_MEM_LEN); put16("synth_out", synth_out, output_frame);
    put1("prev_r", prev_r); put1("fmerit_w_sm", fmerit_w_sm); put1("amr_io_class", amr_io_class); put1("fmerit", fmerit);
    put16("hf_gain", hf_gain, NB_SUBFR); put16("voice_factors", voice_factors, NB_SUBFR); put16("pitch_buf", pitch_buf, NB_SUBFR);
    put1("ng_ener_st", ng_ener_st); put16("lsf_new", lsf_new, M); put1("frame_count", frame_count); put1("ne_min", ne_min);
    put1("fmerit_m_sm", fmerit_m_sm); put1("voice_fac", voice_fac_sm); put1("unvoicing", unvoicing); put1("unvoicing_sm", unvoicing_sm);
    put1("unvoicing_flag", unvoicing_flag); put1("voicing_flag", voicing_flag); put1("start_band_old", start_band_old);
    put1("opt_crit_old", opt_crit_old); put1("q_exc", q_exc);
    hf_synth_amr_wb_fx(rate, output_frame, aq, exc, synth, mem_syn_hf, delay_syn_hf, &prev_r, &fmerit_w_sm, &amr_io_class,
                       mem_hp_interp, synth_out, fmerit, hf_gain, voice_factors, pitch_buf, ng_ener_st, lsf_new, &frame_count,
                       &ne_min, &fmerit_m_sm, &voice_fac_sm, &unvoicing, &unvoicing_sm, &unvoicing_flag, &voicing_flag,
                       &start_band_old, &opt_crit_old, q_exc, q_out);
    arrow(); put16("synth", synth, L_FRAME); put16("mem_syn_hf", mem_syn_hf, M); put16("delay_syn_hf", delay_syn_hf, 20);
    put16("mem_hp_interp", mem_hp_interp, INTERP_3_1_MEM_LEN); put16("synth_out", synth_out, output_frame);
    put1("prev_r", prev_r); put1("fmerit_w_sm", fmerit_w_sm); put1("frame_count", frame_count); put1("ne_min", ne_min);
    put1("fmerit_m_sm", fmerit_m_sm); put1("voice_fac", voice_fac_sm); put1("unvoicing", unvoicing); put1("unvoicing_sm", unvoicing_sm);
    put1("unvoicing_flag", unvoicing_flag); put1("voicing_flag", voicing_flag); put1("start_band_old", start_band_old);
    put1("opt_crit_old", opt_crit_old); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "adaptive_start_band")) case_adaptive_start_band();
        else if (!strcmp(argv[2], "envelope")) case_envelope();
        else if (!strcmp(argv[2], "reset")) case_reset();
        else if (!strcmp(argv[2], "hf_synth_amr_wb")) case_hf_synth_amr_wb();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
