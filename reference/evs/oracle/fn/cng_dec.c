/* Function-level oracle for lib_dec/cng_dec_fx.c (CNG_dec_fx) and, through its AMR-WB IO branch,
 * lib_com/isf_dec_amr_wb_fx.c (isf_dec_amr_wb_fx and its split-multistage dequantisers).
 *
 * Each case builds a decoder with init_decoder_fx at a random output rate, randomises what CNG_dec_fx
 * reads (the previous frames' rates and frame length, the LSF memories, the CNG and hangover
 * histories and circular buffers, the bit stream) and prints the WHOLE state before the call
 * (prefix "in."), the bits and the caller's buffers, and after it the outputs and the state fields
 * that changed (prefix "st."), with the generated dump of init_dec.c; the test overlays the changes
 * on the "before" state and compares the whole state. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "conceal_state.h"

#include <setjmp.h>
#include <signal.h>
#include <sys/resource.h>

#define NBITS 400

/* lsp_convert_poly_fx asserts (div_s by 0) on an LSP set whose polynomial vanishes on its grid,
 * which a real LSP set never does; the random sets are probed first and redrawn if they would. */
static sigjmp_buf probe_jump;
static void probe_abort(int signal_number) { (void)signal_number; siglongjmp(probe_jump, 1); }
static int convertible(Word16 *lsp, Word16 l_frame)
{
    Word16 copy[M];
    memcpy(copy, lsp, sizeof copy);
    void (*saved)(int) = signal(SIGABRT, probe_abort);
    int ok = 0;
    if (sigsetjmp(probe_jump, 1) == 0) { lsp_convert_poly_fx(copy, l_frame, 0); ok = 1; }
    signal(SIGABRT, saved);
    return ok;
}

static UWord16 bits[NBITS + 16];

static const Word32 out_rates[4] = {8000, 16000, 32000, 48000};

/* An LSP vector (Q15 cosines, descending) from a random ordered LSF vector. */
static void random_lsp(Word16 *lsp, Word16 *lsf, int l_frame, int amr)
{
    conceal_lsf(lsf, l_frame == L_FRAME ? 16384 - 400 : 20480 - 400);
    if (amr) E_LPC_isf_isp_conversion(lsf, lsp, M);
    else lsf2lsp_fx(lsf, lsp, M, l_frame == L_FRAME ? INT_FS_FX : INT_FS_16k_FX);
}

static void randomise_cng(Decoder_State_fx *st, int amr)
{
    static const Word32 active_rates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000};
    static const Word32 last_rates[] = {FRAME_NO_DATA, SID_2k40, SID_1k75, 13200, 7200, 24400, 9600, 16400, 32000};
    st->Opt_AMR_WB_fx = (Word16)amr;
    st->L_frame_fx = (Word16)((amr || next_random() % 2) ? L_FRAME : L_FRAME16k);
    st->last_L_frame_fx = (Word16)(next_random() % 4 ? st->L_frame_fx : (st->L_frame_fx == L_FRAME ? L_FRAME16k : L_FRAME));
    st->bwidth_fx = (Word16)(amr ? WB : (st->L_frame_fx == L_FRAME ? random_range(NB, SWB) : random_range(WB, FB)));
    st->core_brate_fx = amr ? (next_random() % 5 ? SID_1k75 : FRAME_NO_DATA) : (next_random() % 5 ? SID_2k40 : FRAME_NO_DATA);
    st->last_core_brate_fx = amr ? (next_random() % 3 ? SID_1k75 : active_rates[next_random() % 7]) : last_rates[next_random() % 9];
    if (amr && next_random() % 3 == 0) st->last_core_brate_fx = (Word32[]){6600, 8850, 12650, 15850, 23850}[next_random() % 5];
    st->total_brate_fx = st->core_brate_fx;
    st->prev_bfi_fx = (Word16)(next_random() % 6 == 0);
    st->old_enr_index_fx = (Word16)(next_random() % 5 ? random_range(0, 127) : -1);
    st->first_CNG_fx = (Word16)(next_random() % 3 != 0);
    st->last_active_brate_fx = amr ? (Word32[]){6600, 8850, 12650, 15850, 19850, 23850}[next_random() % 6] : active_rates[next_random() % 7];
    st->act_cnt2_fx = (Word16)random_range(0, 2 * MIN_ACT_CNG_UPD);
    st->act_cnt_fx = (Word16)random_range(0, 30);
    st->CNG_mode_fx = (Word16)random_range(-1, 4);
    st->num_ho_fx = (Word16)random_range(0, 8);
    st->lp_ener_fx = (Word32)random_range(1, 1 << 18) << random_range(0, 6);
    st->Enew_fx = (Word32)random_range(1, 1 << 18) << random_range(0, 6);
    st->last_CNG_L_frame_fx = (Word16)(next_random() % 3 ? st->L_frame_fx : (st->L_frame_fx == L_FRAME ? L_FRAME16k : L_FRAME));
    st->cng_type_fx = LP_CNG;

    random_lsp(st->lsp_old_fx, st->lsf_old_fx, st->L_frame_fx, amr);
    random_lsp(st->lspCNG_fx, st->lsf_adaptive_mean_fx, st->L_frame_fx, amr);
    conceal_lsf(st->lsfoldbfi0_fx, st->L_frame_fx == L_FRAME ? 16384 - 400 : 20480 - 400);
    conceal_lsf(st->lsfoldbfi1_fx, st->L_frame_fx == L_FRAME ? 16384 - 400 : 20480 - 400);
    conceal_lsf(st->mem_AR_fx, st->L_frame_fx == L_FRAME ? 16384 - 400 : 20480 - 400);
    for (int i = 0; i < M; i++) st->mem_MA_fx[i] = (Word16)random_range(-1500, 1500);
    st->stab_fac_fx = (Word16)random_range(0, 32767);
    st->sr_core = st->L_frame_fx == L_FRAME ? 12800 : 16000;
    st->ho_hist_size_fx = (Word16)(next_random() % 6 == 0 ? random_range(-1, 0) : random_range(1, HO_HIST_SIZE));
    st->ho_hist_ptr_fx = (Word16)random_range(0, HO_HIST_SIZE - 1);
    st->ho_circ_size_fx = (Word16)random_range(0, HO_HIST_SIZE);
    st->ho_circ_ptr_fx = (Word16)(st->ho_circ_size_fx ? random_range(0, st->ho_circ_size_fx - 1) : 0);
    st->ho_sid_bw_fx = (Word32)(next_random() & 0xff);
    for (int i = 0; i < HO_HIST_SIZE; i++) {
        Word16 lsf[M];
        /* the history is in the current rate; the circular buffer keeps the rate of its frame (the
         * flag), which the conversion to the current rate needs to be the true one */
        random_lsp(&st->ho_lsp_hist_fx[i * M], lsf, st->L_frame_fx, 0);
        st->ho_16k_lsp_fx[i] = (Word16)(next_random() & 1);
        do random_lsp(&st->ho_lsp_circ_fx[i * M], lsf, st->ho_16k_lsp_fx[i] ? L_FRAME16k : L_FRAME, 0);
        while (!convertible(&st->ho_lsp_circ_fx[i * M], st->L_frame_fx));
        /* energies near the current one so the averaging accepts some of them */
        st->ho_ener_hist_fx[i] = (Word32)(st->lp_ener_fx * (0.6 + (next_random() % 1000) / 1250.0));
        st->ho_ener_circ_fx[i] = (Word32)(st->lp_ener_fx * (0.5 + (next_random() % 1000) / 800.0));
        for (int j = 0; j < NUM_ENV_CNG; j++) {
            st->ho_env_hist_fx[i * NUM_ENV_CNG + j] = random_range(0, 1 << 14) << random_range(0, 4);
            st->ho_env_circ_fx[i * NUM_ENV_CNG + j] = random_range(0, 1 << 14) << random_range(0, 4);
        }
    }
    for (int j = 0; j < NUM_ENV_CNG; j++) st->lp_env_fx[j] = random_range(0, 1 << 14) << random_range(0, 4);
    for (int i = 0; i < NBITS; i++) bits[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bits;
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(next_random() % 16 ? 100 : random_range(0, 20));
}

static void case_cng_dec(int amr)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 Aq[NB_SUBFR16k * (M + 1)], lsp_new[M], lsf_new[M], allow_cn_step = -7, sid_bw = (Word16)random_range(-1, 1);
    Word32 q_env[NUM_ENV_CNG];
    st->output_Fs_fx = amr ? 16000 : out_rates[next_random() % 4];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    randomise_cng(st, amr);
    for (int i = 0; i < NB_SUBFR16k * (M + 1); i++) Aq[i] = -12345;
    for (int i = 0; i < M; i++) lsp_new[i] = lsf_new[i] = -12345;
    for (int i = 0; i < NUM_ENV_CNG; i++) q_env[i] = -777;
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put1("sid_bw", sid_bw);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);
    CNG_dec_fx(st, st->L_frame_fx, Aq, st->core_brate_fx, lsp_new, lsf_new, &allow_cn_step, &sid_bw, q_env);
    arrow();
    put16("Aq", Aq, NB_SUBFR16k * (M + 1));
    put16("lsp_new", lsp_new, M);
    put16("lsf_new", lsf_new, M);
    put1("allow_cn_step", allow_cn_step);
    put1("sid_bw_out", sid_bw);
    put32("q_env", q_env, NUM_ENV_CNG);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

/* isf_dec_amr_wb_fx on every AMR-WB IO rate and the SID. */
static void case_isf_dec_amr_wb(void)
{
    static const Word32 rates[] = {SID_1k75, 6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 Aq[NB_SUBFR * (M + 1)], isf_new[M], isp_new[M];
    st->output_Fs_fx = 16000;
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);
    randomise_cng(st, 1);
    st->core_brate_fx = rates[next_random() % 10];
    st->total_brate_fx = st->core_brate_fx;
    for (int i = 0; i < NB_SUBFR * (M + 1); i++) Aq[i] = -12345;
    for (int i = 0; i < M; i++) isf_new[i] = isp_new[i] = -12345;
    put1("output_fs", st->output_Fs_fx);
    put1("output_frame", st->output_frame_fx);
    put_u16("bits", bits, NBITS);
    char *before = capture_state(st);
    put_state_in(before);
    isf_dec_amr_wb_fx(st, Aq, isf_new, isp_new);
    arrow();
    put16("Aq", Aq, NB_SUBFR * (M + 1));
    put16("isf_new", isf_new, M);
    put16("isp_new", isp_new, M);
    char *after = capture_state(st);
    put_changed(before, after);
    free(before);
    free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core); /* a crash must not reach the desktop crash reporter */
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "cng_dec")) case_cng_dec(0);
        else if (!strcmp(argv[2], "cng_dec_amr_wb")) case_cng_dec(1);
        else if (!strcmp(argv[2], "isf_dec_amr_wb")) case_isf_dec_amr_wb();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
