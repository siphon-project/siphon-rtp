/* Function-level oracle for lib_dec/swb_bwe_dec_hr_fx.c (Gain_Dequant_HR and TD_Postprocess are
 * static, proven through swb_bwe_dec_hr_fx). Three frames run on one decoder state, so what a frame
 * leaves (the saved coefficients, the long-term energy, the overlap memory) is what the next one,
 * or a lost one, reads. The bitstream is random: the decoder must accept any bits. */
#include "harness.h"
#include "prot_fx.h"

#define FRAMES 3
#define BITS 1280

static UWord16 bit_buffer[BITS];

/* Half of the frames carry fair random bits; the rest are sparse (few ones), which the AVQ codes as many
 * empty sub-vectors and small indices, leaving bits for the second stage and the noise fill. */
static void random_bits(Decoder_State_fx *st)
{
    static const int densities[] = {50, 50, 20, 8, 3};
    int density = densities[next_random() % 5];
    for (int i = 0; i < BITS; i++) bit_buffer[i] = (UWord16)(i < 8 ? (next_random() & 1) : (int)(next_random() % 100) < density);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = BITS;
    st->next_bit_pos_fx = 0;
    st->codec_mode = MODE1;
}

static Word32 random_energy(void) { return (Word32)(next_random() & 0x7fffffff) >> random_range(0, 20); }

/* A 16 kHz core synthesis of random tilt: white noise through a one-pole filter. */
static void random_core_synthesis(Word16 *x, int n)
{
    int level = 1 << random_range(4, 13);
    int pole = random_range(-28000, 28000), state = 0;
    for (int i = 0; i < n; i++) {
        state = (state * pole) / 32768 + random_range(-level, level);
        if (state > 32767) state = 32767;
        if (state < -32768) state = -32768;
        x[i] = (Word16)state;
    }
    if (next_random() % 16 == 0) memset(x, 0, n * sizeof(Word16));
}

/* A time signal with a loud stretch, so the onset decision of the final adjustments is reached. */
static void put_hr_state(const char *prefix, Decoder_State_fx *st)
{
    char name[48];
    Word16 s[] = {st->prev_ener_shb_fx, st->prev_SWB_fenv_fx[0], st->prev_SWB_fenv_fx[SWB_FENV - 1], st->Q_old_wtda,
                  st->old_is_transient_hr_bwe_fx, st->mem_EnergyLT_fx_exp, st->bwe_highrate_seed_fx,
                  st->next_bit_pos_fx, st->BER_detect, st->t_audio_prev_fx_exp[0], st->t_audio_prev_fx_exp[1],
                  st->t_audio_prev_fx_exp[2], st->t_audio_prev_fx_exp[3]};
    sprintf(name, "%s_state", prefix); put16(name, s, 13);
    sprintf(name, "%s_energy_lt", prefix); put1(name, st->L_mem_EnergyLT_fx);
    sprintf(name, "%s_wtda", prefix); put16(name, st->L_old_wtda_swb_fx, L_FRAME48k);
    sprintf(name, "%s_prev", prefix); put16(name, st->t_audio_prev_fx, 496);
}

static void case_swb_bwe_dec_hr(void)
{
    static const Word16 last_extls[] = {-1, WB_BWE, SWB_BWE, FB_BWE, SWB_BWE_HIGHRATE, SWB_BWE_HIGHRATE, FB_BWE_HIGHRATE, FB_BWE_HIGHRATE};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int which = next_random() % 3;
    Word16 output_frame = (Word16)(which == 0 ? L_FRAME32k : L_FRAME48k);
    st->extl_fx = (Word16)(which == 2 ? FB_BWE_HIGHRATE : SWB_BWE_HIGHRATE);
    st->Q_old_wtda = (Word16)random_range(10, 16);
    st->old_is_transient_hr_bwe_fx = (Word16)random_range(0, 1);
    /* always normalised and non-zero (init_dec sets 0x40000000, every update renormalises); a zero or
     * unnormalised value aborts the reference in div_s */
    st->L_mem_EnergyLT_fx = (Word32)(0x40000000 + (next_random() & 0x3fffffff));
    st->mem_EnergyLT_fx_exp = (Word16)random_range(10, 50);
    for (int k = 0; k < 4; k++) st->t_audio_prev_fx_exp[k] = (Word16)random_range(14, 30);
    random_signal(st->t_audio_prev_fx, 496, 1 << random_range(6, 15));
    random_signal(st->L_old_wtda_swb_fx, L_FRAME48k, 1 << random_range(4, 13));
    st->bws_cnt1_fx = (Word16)(next_random() % 4 ? 0 : random_range(1, N_NS2W_FRAMES));
    put1("output_frame", output_frame);
    Word16 cfg[] = {st->extl_fx, st->Q_old_wtda, st->old_is_transient_hr_bwe_fx, st->mem_EnergyLT_fx_exp, st->bws_cnt1_fx};
    put16("cfg", cfg, 5); put1("init_energy_lt", st->L_mem_EnergyLT_fx);
    put16("init_exps", st->t_audio_prev_fx_exp, 4); put16("init_prev", st->t_audio_prev_fx, 496);
    put16("init_wtda", st->L_old_wtda_swb_fx, L_FRAME48k);
    static UWord16 bits[FRAMES][BITS];
    Word16 syn[FRAMES][L_FRAME16k], pitch_buf[FRAMES][NB_SUBFR16k], in16[FRAMES][8];
    for (int f = 0; f < FRAMES; f++) {
        char name[32];
        Word16 exp = (Word16)random_range(-2, 4), unbits = (Word16)(next_random() % 2 ? random_range(0, 80) : random_range(81, 250));
        random_core_synthesis(syn[f], L_FRAME16k);
        for (int i = 0; i < NB_SUBFR16k; i++) pitch_buf[f][i] = (Word16)random_range(34 * 64, 231 * 64);
        random_bits(st);
        memcpy(bits[f], bit_buffer, sizeof(bit_buffer));
        in16[f][0] = exp; in16[f][1] = unbits;
        in16[f][2] = (Word16)(next_random() % 5 == 0);
        in16[f][3] = (Word16)(next_random() % 3 ? ACELP_CORE : HQ_CORE);
        in16[f][4] = (f > 0 && next_random() % 3) ? st->extl_fx : last_extls[next_random() % 8];
        in16[f][5] = (Word16)(next_random() % 2 ? random_range(0, 6) : (next_random() % 2 ? VOICED_CLAS : INACTIVE_CLAS));
        in16[f][6] = (Word16)random_range(0, 6);
        in16[f][7] = (Word16)(next_random() % 4 ? 0 : random_range(1, N_NS2W_FRAMES));
        sprintf(name, "f%d_in16", f); put16(name, in16[f], 8);
        sprintf(name, "f%d_syn", f); put16(name, syn[f], L_FRAME16k);
        sprintf(name, "f%d_pitch", f); put16(name, pitch_buf[f], NB_SUBFR16k);
        sprintf(name, "f%d_bits", f); put_u16(name, bits[f], BITS);
    }
    printf(" ->");
    for (int f = 0; f < FRAMES; f++) {
        Word16 hb[L_FRAME48k];
        char name[32];
        for (int i = 0; i < L_FRAME48k; i++) hb[i] = -7;
        memcpy(bit_buffer, bits[f], sizeof(bit_buffer));
        st->bit_stream_fx = bit_buffer;
        st->total_num_bits = BITS;
        st->next_bit_pos_fx = 0;
        st->codec_mode = MODE1;
        st->bfi_fx = in16[f][2];
        st->last_core_fx = in16[f][3];
        st->last_extl_fx = in16[f][4];
        st->clas_dec = in16[f][5];
        st->nbLostCmpt = in16[f][6];
        st->bws_cnt1_fx = in16[f][7];
        Word16 hb_exp = swb_bwe_dec_hr_fx(st, syn[f], in16[f][0], hb, output_frame, in16[f][1], pitch_buf[f]);
        sprintf(name, "f%d_exp", f); put1(name, hb_exp);
        sprintf(name, "f%d_hb", f); put16(name, hb, output_frame);
        sprintf(name, "f%d", f); put_hr_state(name, st);
    }
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "swb_bwe_dec_hr")) case_swb_bwe_dec_hr();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
