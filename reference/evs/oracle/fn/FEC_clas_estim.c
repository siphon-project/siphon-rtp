/* Function-level oracle for lib_dec/FEC_clas_estim_fx.c (FEC_clas_estim_fx, FEC_pos_dec_fx,
 * FEC_dec_class_fx, Corre). */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/FEC_clas_estim_fx.c"

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

/* A decoded synthesis: a voiced-like periodic signal at the given pitch with noise, a random walk,
 * silence, or edge values, scaled to roughly `magnitude`. */
static void random_synthesis(Word16 *x, int n, int pitch, int magnitude)
{
    int kind = next_random() % 8;
    if (kind < 4) {
        Word16 pulse[300];
        if (pitch < 1) pitch = 1;
        random_signal(pulse, pitch, magnitude);
        int noise = magnitude / random_range(4, 64);
        for (int i = 0; i < n; i++) {
            int v = pulse[i % pitch] + random_range(-noise, noise);
            x[i] = (Word16)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
        }
    } else if (kind < 6) {
        random_signal(x, n, magnitude);
    } else if (kind == 6) {
        for (int i = 0; i < n; i++) x[i] = (Word16)random_range(-2, 2);
    } else {
        for (int i = 0; i < n; i++) x[i] = random16();
    }
}

/* Four subframe pitches in Q6 around one lag (or jumping), inside the decoder's range. */
static void random_pitch(Word16 *pitch, int n, int l_frame)
{
    int max_lag = l_frame == L_FRAME ? PIT_MAX : PIT16k_MAX;
    int min_lag = PIT_MIN;
    /* Now and then a lag under PIT_MIN (never decoded, but the classifier's third and fourth
     * correlation windows are reachable only there). */
    if (next_random() % 16 == 0) { min_lag = 10; max_lag = 40; }
    int lag = random_range(min_lag * 64, max_lag * 64);
    for (int i = 0; i < n; i++) {
        if (next_random() % 4 == 0) lag = random_range(min_lag * 64, max_lag * 64);
        else lag += random_range(-256, 256);
        if (lag < min_lag * 64) lag = min_lag * 64;
        if (lag > max_lag * 64) lag = max_lag * 64;
        pitch[i] = (Word16)lag;
    }
}

static void put_state(Decoder_State_fx *st)
{
    put1("clas", st->clas_dec); put1("lp_ener_fer", st->lp_ener_FER_fx); put1("decision_hyst", st->decision_hyst_fx);
    put1("uv_cnt", st->UV_cnt_fx); put1("lt_uv_cnt", st->LT_UV_cnt_fx); put1("last_ener", st->Last_ener_fx);
    put16("lt_diff_etot", st->lt_diff_etot_fx, MAX_LT);
    put16("mem", st->mem_syn_clas_estim_fx, L_SYN_MEM_CLAS_ESTIM);
    put1("q_mem_syn", st->classifier_Q_mem_syn); put1("carry", Carry);
}

/* The four caller configurations: MODE1 ACELP (acelp_core_dec), MODE1 AMR-WB IO (amr_wb_dec),
 * MODE2 ACELP classifier (dec_ace, er_dec_acelp, updt_dec) and MODE2 TCX classifier (dec_LPD).
 * A few warm-up calls first, so the memories hold what the function itself leaves there. */
static void case_clas_estim(void)
{
    static const Word32 mode1_rates[] = {7200, 8000, 9600, 11600, 13200, 16400, 24400, 32000};
    static const Word32 amr_rates[] = {6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};
    static const Word32 last_rates[] = {0, 1750, 6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850,
                                        7200, 9600, 13200, 16400, 24400, 32000};
    int config = next_random() % 4;
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 opt_amr_wb = config == 1, l_frame, mode = 0, ltp_gain = -32768, bfi = 0;
    Word32 bitrate = 0;
    st->codec_mode = config < 2 ? MODE1 : MODE2;
    l_frame = (config >= 2 && (next_random() & 1)) ? L_FRAME16k : L_FRAME;
    st->L_frame_fx = l_frame;
    st->last_L_frame_fx = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    if (config == 0) bitrate = mode1_rates[next_random() % 8];
    if (config == 1) bitrate = amr_rates[next_random() % 9];
    if (config >= 2) {
        st->tcxonly = (next_random() % 4) == 0;
        st->narrowBand = next_random() & 1;
        static const Word16 preemph[] = {PREEMPH_FAC, PREEMPH_FAC_16k, PREEMPH_FAC_SWB};
        st->preemph_fac = preemph[next_random() % 3];
        bfi = (next_random() % 4) == 0;
    }
    if (config == 3) {
        mode = CLASSIFIER_TCX;
        ltp_gain = (next_random() % 3) ? (Word16)random_range(0, 19661) : -32768;
    }
    Word32 last_core_brate = last_rates[next_random() % 17];
    st->clas_dec = (Word16)random_range(UNVOICED_CLAS, AUDIO_CLAS);
    st->lp_ener_FER_fx = (Word16)random_range(0, 80 * 256);
    st->decision_hyst_fx = (Word16)random_range(0, 200);
    st->UV_cnt_fx = (Word16)random_range(0, 300);
    st->LT_UV_cnt_fx = (Word16)random_range(0, 300 * 64);
    st->Last_ener_fx = (Word16)random_range(-20 * 256, 80 * 256);
    for (int i = 0; i < MAX_LT; i++) st->lt_diff_etot_fx[i] = (Word16)random_range(-15 * 256, 15 * 256);
    Word16 q_syn = (Word16)(config >= 2 ? random_range(-1, 4) : random_range(-1, 8));
    st->classifier_Q_mem_syn = (Word16)(q_syn + random_range(-3, 1));
    int magnitude = (next_random() % 8) ? random_range(100, 20000) : random_range(1, 100);
    random_synthesis(st->mem_syn_clas_estim_fx, L_SYN_MEM_CLAS_ESTIM, random_range(PIT_MIN, PIT_MAX), magnitude);
    int warmups = random_range(0, 3);
    for (int call = 0; call <= warmups; call++) {
        Word16 syn[1 + L_FRAME16k], pitch[NB_SUBFR16k];
        Word16 coder_type = (Word16)random_range(INACTIVE, AUDIO);
        Word16 locattack = (Word16)random_range(0, 1), amr_io_class = (Word16)random_range(0, 7);
        Word16 class_para = random16();
        random_pitch(pitch, NB_SUBFR16k, l_frame);
        random_synthesis(syn, 1 + l_frame, pitch[3] >> 6, magnitude);
        Carry = (Flag)(next_random() & 1);
        if (call == warmups) {
            put1("codec_mode", st->codec_mode); put1("tcxonly", st->tcxonly); put1("narrow_band", st->narrowBand);
            put1("preemph_fac", st->preemph_fac); put1("last_l_frame", st->last_L_frame_fx);
            put1("l_frame", l_frame); put1("opt_amr_wb", opt_amr_wb); put1("coder_type", coder_type);
            put16("pitch", pitch, NB_SUBFR16k); put16("syn", syn, 1 + l_frame); put1("bitrate", bitrate);
            put1("q_syn", q_syn); put1("ltp_gain", ltp_gain); put1("mode", mode); put1("bfi", bfi);
            put1("last_core_brate", last_core_brate); put1("locattack", locattack);
            put1("amr_io_class", amr_io_class); put1("class_para", class_para);
            put_state(st);
        }
        if (config == 0)
            FEC_clas_estim_fx(st, 0, l_frame, &st->clas_dec, coder_type, pitch, syn + 1, &st->lp_ener_FER_fx,
                              &st->decision_hyst_fx, NULL, NULL, NULL, NULL, 0, NULL, bitrate, q_syn, &class_para,
                              st->mem_syn_clas_estim_fx, &st->classifier_Q_mem_syn, 0, 0, 0, last_core_brate);
        else if (config == 1)
            FEC_clas_estim_fx(st, 1, l_frame, &st->clas_dec, coder_type, pitch, syn + 1, &st->lp_ener_FER_fx,
                              &st->decision_hyst_fx, &st->UV_cnt_fx, &st->LT_UV_cnt_fx, &st->Last_ener_fx,
                              &locattack, st->lt_diff_etot_fx, &amr_io_class, bitrate, q_syn, &class_para,
                              st->mem_syn_clas_estim_fx, &st->classifier_Q_mem_syn, 0, 0, 0, last_core_brate);
        else
            FEC_clas_estim_fx(st, 0, l_frame, &st->clas_dec, coder_type, pitch, syn + 1, &st->lp_ener_FER_fx,
                              NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, q_syn, NULL,
                              st->mem_syn_clas_estim_fx, &st->classifier_Q_mem_syn, ltp_gain, mode, bfi,
                              last_core_brate);
        if (call == warmups) {
            arrow(); put1("locattack", locattack); put1("amr_io_class", amr_io_class);
            put1("class_para", class_para); put_state(st); end_line();
        }
        last_core_brate = bitrate;
    }
    free(st);
}

static void case_corre(void)
{
    Word16 x[300], y[300];
    Word16 l = (Word16)random_range(1, 289);
    int magnitude = (next_random() % 4) ? random_range(1, 32767) : random_range(1, 8);
    if (next_random() & 1) {
        random_synthesis(y, l, random_range(1, l), magnitude);
        for (int i = 0; i < l; i++) x[i] = (next_random() % 8) ? y[i] : random16();
    } else {
        random_synthesis(x, l, random_range(1, l), magnitude);
        random_synthesis(y, l, random_range(1, l), magnitude);
    }
    Word16 gain;
    put16("x", x, l); put16("y", y, l);
    Corre(x, y, l, &gain);
    arrow(); put1("gain", gain); end_line();
}

static void case_pos_dec(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 11600, 13200, 14800, 16400, 22600, 24400, 32000, 48000, 64000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = 400;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = (Word16)random_range(0, 200);
    st->BER_detect = (next_random() % 8) == 0;
    st->bwidth_fx = (Word16)random_range(NB, FB);
    Word16 coder_type = (Word16)random_range(INACTIVE, AUDIO);
    Word16 last_good = (Word16)random_range(UNVOICED_CLAS, AUDIO_CLAS);
    Word32 core_brate = rates[next_random() % 12];
    Word16 last_pulse_pos = random16(), clas = (Word16)random_range(0, 7);
    Word32 enr_q = random32();
    put_u16("bits", bit_buffer, n); put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect);
    put1("bwidth", st->bwidth_fx); put1("coder_type", coder_type); put1("last_good", last_good);
    put1("core_brate", core_brate); put1("last_pulse_pos", last_pulse_pos); put1("clas", clas); put1("enr_q", enr_q);
    Word16 t0 = FEC_pos_dec_fx(st, coder_type, last_good, &last_pulse_pos, &clas, &enr_q, core_brate);
    arrow(); put1("t0", t0); put1("last_pulse_pos", last_pulse_pos); put1("clas", clas); put1("enr_q", enr_q);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "clas_estim")) case_clas_estim();
        else if (!strcmp(argv[2], "corre")) case_corre();
        else if (!strcmp(argv[2], "pos_dec")) case_pos_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
