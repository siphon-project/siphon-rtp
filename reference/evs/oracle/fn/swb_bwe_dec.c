/* Function-level oracle for lib_dec/swb_bwe_dec_fx.c (para_pred_bws_fx is static, so the file is
 * included). The decoder-state functions run three consecutive frames on one state, so what one frame
 * leaves in the BWE memories (prev_SWB_fenv, attenu, the MDCT/IMDCT overlap, the energy and norm
 * trackers, the noise seed) is what the next one reads. */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/swb_bwe_dec_fx.c"

#define FRAMES 3

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void random_bits(Decoder_State_fx *st, int n)
{
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)(next_random() % 8 ? random_range(0, n - 30) : random_range(n - 8, n));
    st->codec_mode = MODE1;
}

/* A plausible MDCT spectrum: band-limited random walk with a random overall scale, sometimes silent. */
static void random_spectrum(Word16 *x, int n)
{
    int magnitude = 1 << random_range(0, 14);
    random_signal(x, n, magnitude);
    for (int i = 0; i < n; i++)
        if (next_random() % 3 == 0) x[i] = (Word16)random_range(-magnitude, magnitude);
    if (next_random() % 4 == 0) {
        /* tonal: a low floor with a few strong lines, so bands read as peaky (HARMONIC) */
        for (int i = 0; i < n; i++) x[i] = (Word16)random_range(-(magnitude >> 6), magnitude >> 6);
        for (int i = 0; i < n / 8; i++) x[random_range(0, n - 1)] = (Word16)random_range(-magnitude, magnitude);
    }
    if (next_random() % 16 == 0) memset(x, 0, n * sizeof(Word16));
}

static Word32 random_energy(void) { return (Word32)(next_random() & 0x7fffffff) >> random_range(0, 30); }

static void case_para_pred_bws(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->tilt_wb_fx = (Word16)(next_random() % 3 ? random_range(0, 32767) : random_range(16000, 32767));
    st->attenu_fx = (Word16)random_range(3277, 31129);
    st->bws_cnt_fx = (Word16)random_range(0, N_WS2N_FRAMES);
    st->L_frame_fx = (Word16)(next_random() & 1 ? L_FRAME16k : L_FRAME);
    for (int i = 0; i < SWB_FENV; i++) st->prev_SWB_fenv_fx[i] = (Word16)random_range(0, 1 << random_range(4, 15));
    put1("tilt_wb", st->tilt_wb_fx); put1("attenu", st->attenu_fx); put1("bws_cnt", st->bws_cnt_fx);
    put1("l_frame", st->L_frame_fx); put16("prev_swb_fenv", st->prev_SWB_fenv_fx, SWB_FENV);
    for (int f = 0; f < FRAMES; f++) {
        Word16 signal[L_FRAME16k], fenv[SWB_FENV], q_syn = (Word16)random_range(-4, 12), coder_type = (Word16)random_range(0, 5), mode;
        char name[32];
        random_spectrum(signal, L_FRAME16k);
        st->last_core_fx = (Word16)(next_random() % 3 ? ACELP_CORE : HQ_CORE);
        st->last_codec_mode = (Word16)(next_random() % 4 ? MODE1 : MODE2);
        st->prev_coder_type_fx = (Word16)random_range(0, 5);
        st->core_brate_fx = next_random() % 2 ? ACELP_13k20 : ACELP_9k60;
        st->last_core_brate_fx = next_random() % 3 ? st->core_brate_fx : ACELP_16k40;
        st->prev_enerLH_fx = random_energy();
        st->enerLH_fx = next_random() % 2 ? st->prev_enerLH_fx + (Word32)random_range(-(st->prev_enerLH_fx / 3), st->prev_enerLH_fx / 3) : random_energy();
        st->prev_enerLL_fx = random_energy();
        st->enerLL_fx = next_random() % 2 ? st->prev_enerLL_fx + (Word32)random_range(-(st->prev_enerLL_fx / 3), st->prev_enerLL_fx / 3) : random_energy();
        for (int i = 0; i < SWB_FENV; i++) fenv[i] = -7;
        sprintf(name, "f%d_signal", f); put16(name, signal, L_FRAME16k);
        sprintf(name, "f%d_frame", f);
        Word16 frame[] = {q_syn, coder_type, st->last_core_fx, st->last_codec_mode, st->prev_coder_type_fx};
        put16(name, frame, 5);
        Word32 frame32[] = {st->core_brate_fx, st->last_core_brate_fx, st->enerLH_fx, st->prev_enerLH_fx, st->enerLL_fx, st->prev_enerLL_fx};
        sprintf(name, "f%d_frame32", f); put32(name, frame32, 6);
        mode = para_pred_bws_fx(st, signal, fenv, q_syn, coder_type);
        Word16 out[SWB_FENV + 2];
        out[0] = mode; out[1] = st->attenu_fx;
        memcpy(out + 2, fenv, sizeof(fenv));
        sprintf(name, "f%d_out", f); put16(name, out, SWB_FENV + 2);
    }
    printf(" ->"); end_line();
    free(st);
}

static void case_wb_bwe_gain_deq(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 fenv[2] = {-7, -7}, mode;
    random_bits(st, 64);
    put_u16("bits", bit_buffer, 64); put1("next_bit_pos", st->next_bit_pos_fx);
    mode = WB_BWE_gain_deq_fx(st, fenv);
    arrow(); put1("mode", mode); put16("fenv", fenv, 2); put1("next_bit_pos", st->next_bit_pos_fx);
    put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

static void case_swb_bwe_gain_deq(void)
{
    static const Word16 clas[] = {-1, -1, 0, 1, 2, 3, HQ_GEN_SWB, HQ_GEN_FB, HQ_GEN_FB};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 tenv[SWB_TENV], fenv[SWB_FENV + DIM_FB], mode;
    Word16 core = (Word16)(next_random() % 2 ? ACELP_CORE : HQ_CORE), hr_flag = (Word16)(next_random() % 3 == 0);
    Word16 hqswb_clas = clas[next_random() % 9];
    random_bits(st, 80);
    st->bws_cnt1_fx = (Word16)(next_random() % 2 ? 0 : random_range(1, N_NS2W_FRAMES));
    for (int i = 0; i < SWB_TENV; i++) tenv[i] = -7;
    for (int i = 0; i < SWB_FENV + DIM_FB; i++) fenv[i] = -7;
    put_u16("bits", bit_buffer, 80); put1("next_bit_pos", st->next_bit_pos_fx); put1("core", core);
    put1("hr_flag", hr_flag); put1("hqswb_clas", hqswb_clas); put1("bws_cnt1", st->bws_cnt1_fx);
    mode = swb_bwe_gain_deq_fx(st, core, tenv, fenv, hr_flag, hqswb_clas);
    arrow(); put1("mode", mode); put16("tenv", tenv, SWB_TENV); put16("fenv", fenv, SWB_FENV + DIM_FB);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

static void put_wb_state(const char *prefix, Decoder_State_fx *st)
{
    char name[48];
    Word16 s[] = {st->old_wtda_swb_fx_exp, st->mem_imdct_exp_fx, st->prev_Q_synth, st->prev_L_swb_norm_fx,
                  st->Seed_fx, st->prev_flag_fx, st->last_wb_bwe_ener_fx, st->prev_mode_fx};
    sprintf(name, "%s_state", prefix); put16(name, s, 8);
    sprintf(name, "%s_energy", prefix); put1(name, st->prev_Energy_wb_fx);
    sprintf(name, "%s_fenv", prefix); put16(name, st->prev_SWB_fenv_fx, SWB_FENV);
    sprintf(name, "%s_wtda", prefix); put16(name, st->L_old_wtda_swb_fx, L_FRAME48k);
    sprintf(name, "%s_imdct", prefix); put16(name, st->mem_imdct_fx, L_FRAME48k);
}

static void case_wb_bwe_dec(void)
{
    static const Word16 frames[] = {L_FRAME16k, L_FRAME16k, L_FRAME32k, L_FRAME48k};
    static const Word32 rates[] = {16000, 16000, 32000, 48000};
    static const Word16 extls[] = {WB_BWE, WB_BWE, WB_BWE, -1, SWB_BWE, WB_TBE};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int which = next_random() % 4;
    Word16 output_frame = frames[which];
    st->output_Fs_fx = rates[which];
    st->old_wtda_swb_fx_exp = (Word16)random_range(0, 4);
    st->mem_imdct_exp_fx = (Word16)random_range(0, 4);
    st->prev_Q_synth = (Word16)random_range(-2, 8);
    st->prev_L_swb_norm_fx = (Word16)random_range(1, 10);
    st->Seed_fx = random16();
    st->prev_flag_fx = (Word16)random_range(0, 1);
    st->last_wb_bwe_ener_fx = (Word16)random_range(0, 2000);
    st->prev_mode_fx = (Word16)random_range(NORMAL, HARMONIC);
    /* half the time a loud previous frame at a low Q, so the energy is renormalised upwards */
    /* mostly an energy of the size the core spectrum gives (a sum of 80-160 magnitudes), sometimes at a
     * much lower Q, so the energy is renormalised upwards and the frame's own Q follows it */
    st->prev_Energy_wb_fx = next_random() % 4 ? random_range(1 << 16, 1 << 23) : random_energy();
    if (next_random() % 2) st->prev_Q_synth = (Word16)random_range(-12, 1);
    int magnitude = random_range(6, 14);
    for (int i = 0; i < SWB_FENV; i++) st->prev_SWB_fenv_fx[i] = (Word16)random_range(0, 1 << random_range(4, 12));
    random_signal(st->L_old_wtda_swb_fx, L_FRAME48k, 1 << random_range(4, 13));
    random_signal(st->mem_imdct_fx, L_FRAME48k, 1 << random_range(4, 13));
    put1("output_frame", output_frame); put1("output_fs", st->output_Fs_fx);
    put_wb_state("init", st);
    for (int f = 0; f < FRAMES; f++) {
        Word16 synth[L_FRAME48k], hb[L_FRAME48k], voice[NB_SUBFR16k], pitch[NB_SUBFR16k], qpost = (Word16)random_range(-1, 3), q_hb;
        Word16 coder_type = (Word16)random_range(0, 5);
        char name[32];
        random_signal(synth, L_FRAME48k, 1 << (next_random() % 4 ? magnitude : random_range(6, 14)));
        for (int i = 0; i < L_FRAME48k; i++) hb[i] = -7;
        for (int i = 0; i < NB_SUBFR16k; i++) { voice[i] = (Word16)random_range(0, 32767); pitch[i] = (Word16)random_range(34 * 64, 231 * 64); }
        random_bits(st, 64);
        st->bfi_fx = (Word16)(next_random() % 6 == 0);
        st->total_brate_fx = next_random() % 2 ? ACELP_13k20 : (next_random() % 2 ? ACELP_8k00 : ACELP_9k60);
        st->last_extl_fx = f > 0 && next_random() % 2 ? WB_BWE : extls[next_random() % 6];
        st->extl_fx = WB_BWE;
        st->prev_coder_type_fx = (Word16)random_range(0, 5);
        st->last_core_brate_fx = next_random() % 2 ? st->total_brate_fx : ACELP_16k40;
        st->tilt_wb_fx = (Word16)random_range(0, 32767);
        Word16 in16[] = {qpost, coder_type, st->bfi_fx, st->last_extl_fx, st->prev_coder_type_fx, st->tilt_wb_fx, st->next_bit_pos_fx};
        Word32 in32[] = {st->total_brate_fx, st->last_core_brate_fx};
        sprintf(name, "f%d_in16", f); put16(name, in16, 7);
        sprintf(name, "f%d_in32", f); put32(name, in32, 2);
        sprintf(name, "f%d_bits", f); put_u16(name, bit_buffer, 64);
        sprintf(name, "f%d_voice", f); put16(name, voice, NB_SUBFR16k);
        sprintf(name, "f%d_pitch", f); put16(name, pitch, NB_SUBFR16k);
        sprintf(name, "f%d_synth", f); put16(name, synth, L_FRAME48k);
        q_hb = wb_bwe_dec_fx(synth, hb, output_frame, coder_type, voice, pitch, st, &qpost);
        Word16 q[] = {q_hb, qpost, st->next_bit_pos_fx};
        sprintf(name, "f%d_q", f); put16(name, q, 3);
        sprintf(name, "f%d_osynth", f); put16(name, synth, L_FRAME48k);
        sprintf(name, "f%d_hb", f); put16(name, hb, output_frame);
        sprintf(name, "f%d", f); put_wb_state(name, st);
    }
    printf(" ->"); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "para_pred_bws")) case_para_pred_bws();
        else if (!strcmp(argv[2], "wb_bwe_gain_deq")) case_wb_bwe_gain_deq();
        else if (!strcmp(argv[2], "swb_bwe_gain_deq")) case_swb_bwe_gain_deq();
        else if (!strcmp(argv[2], "wb_bwe_dec")) case_wb_bwe_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
