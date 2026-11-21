/* Function-level oracle for lib_dec/lsf_dec_fx.c: lsf_dec_fx over runs of consecutive MODE1 frames
 * on one decoder state (the AR / MA predictor memories, the old LSFs / LSPs, mid_lsf_int and the FEC
 * adaptive mean carry across frames), SID frames included (dqlsf_CNG_fx), reading random bits; and
 * lsf_end_dec_fx's MODE2 path, which takes its indices from param_lpc. lsf_mid_dec_fx is proven
 * through lsf_dec_fx. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define MAX_FRAMES 6

static UWord16 bit_buffer[MAX_FRAMES * 64 + 16];

static void random_lsf(Word16 *lsf, int int_fs)
{
    /* An ordered LSF vector in Q(x2.56): 0 .. int_fs/2 maps to 0 .. 1.28·int_fs. */
    int top = int_fs == 16000 ? 20480 : 16384;
    int value = random_range(100, 900);
    for (int i = 0; i < M; i++) {
        lsf[i] = (Word16)value;
        value += random_range(200, (top - value) / (M - i) * 2 > 300 ? (top - value) / (M - i) * 2 : 300);
        if (value > top - 50) value = top - 50;
    }
}

static int frame_is_valid(Word16 l_frame, Word32 core_brate, Word16 coder_type, Word16 nelp, Word16 ppp, Word16 bwidth)
{
    Word16 idx = (Word16)LSF_BIT_ALLOC_IDX_fx(core_brate, coder_type);
    if (core_brate == SID_2k40) return coder_type == INACTIVE;
    if (nelp) return coder_type == UNVOICED && l_frame == L_FRAME;
    if (ppp) return coder_type == VOICED && l_frame == L_FRAME;
    if (LSF_bits_tbl[idx] == 0) return 0;
    if (l_frame == L_FRAME16k && coder_type == UNVOICED) return 0;
    if (l_frame == L_FRAME16k && bwidth == NB) return 0;
    Word16 mid = mid_LSF_bits_tbl[idx];
    if (coder_type == VOICED) return mid == 4 || mid == 5;
    if (coder_type == UNVOICED) return 1;
    return mid == 2 || mid == 5;
}

static void put_state(Decoder_State_fx *st, const char *suffix)
{
    char name[32];
    Word16 s[] = {st->BER_detect, st->next_bit_pos_fx, st->safety_net_fx, st->mid_lsf_int_fx, st->relax_prev_lsf_interp_fx,
                  st->stab_fac_fx, st->mode_lvq, st->reset_mem_AR};
    sprintf(name, "st%s", suffix); put16(name, s, 8);
    sprintf(name, "mem_ar%s", suffix); put16(name, st->mem_AR_fx, M);
    sprintf(name, "mem_ma%s", suffix); put16(name, st->mem_MA_fx, M);
    sprintf(name, "lsf_old%s", suffix); put16(name, st->lsf_old_fx, M);
    sprintf(name, "lsp_old%s", suffix); put16(name, st->lsp_old_fx, M);
    sprintf(name, "mean%s", suffix); put16(name, st->lsf_adaptive_mean_fx, M);
}

static Decoder_State_fx *new_state(int n_bits)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int style = next_random() % 6;
    for (int i = 0; i < n_bits; i++)
        bit_buffer[i] = (UWord16)(style == 0 ? next_random() % 8 == 0 : style == 1 ? next_random() % 8 != 0 : next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n_bits;
    st->next_bit_pos_fx = 0;
    init_lvq_fx(st->offset_scale1_fx, st->offset_scale2_fx, st->offset_scale1_p_fx, st->offset_scale2_p_fx, st->no_scales_fx,
                st->no_scales_p_fx);
    put_u16("bits", bit_buffer, n_bits);
    return st;
}

static void case_lsf_dec(void)
{
    static const Word32 rates12k8[] = {7200, 8000, 11600, 12150, 12850, 13200, 14800, 16400, 22600, 24400, SID_2k40};
    static const Word32 rates16k[] = {24400, 29000, 32000, 48000, 64000, SID_2k40};
    static const Word16 classes[] = {UNVOICED_CLAS, UNVOICED_TRANSITION, VOICED_TRANSITION, VOICED_CLAS, ONSET, SIN_ONSET, INACTIVE_CLAS};
    Decoder_State_fx *st = new_state(MAX_FRAMES * 64);
    Word16 l_frame = (Word16)(next_random() % 3 ? L_FRAME : L_FRAME16k);
    int int_fs = l_frame == L_FRAME ? INT_FS_FX : INT_FS_16k_FX;
    int frames = random_range(1, MAX_FRAMES);
    st->L_frame_fx = l_frame;
    random_lsf(st->lsf_old_fx, int_fs);
    lsf2lsp_fx(st->lsf_old_fx, st->lsp_old_fx, M, int_fs);
    random_lsf(st->mem_AR_fx, int_fs);
    for (int i = 0; i < M; i++) st->mem_MA_fx[i] = (Word16)random_range(-400, 400);
    random_lsf(st->lsfoldbfi0_fx, int_fs);
    random_lsf(st->lsfoldbfi1_fx, int_fs);
    st->mid_lsf_int_fx = (Word16)(next_random() & 1);
    st->safety_net_fx = (Word16)(next_random() & 1);
    st->relax_prev_lsf_interp_fx = (Word16)random_range(-1, 1);
    st->reset_mem_AR = (Word16)(next_random() % 6 == 0);
    st->BER_detect = 0;
    put1("frames", frames); put1("l_frame", l_frame);
    put16("lsfoldbfi0", st->lsfoldbfi0_fx, M); put16("lsfoldbfi1", st->lsfoldbfi1_fx, M);
    put_state(st, "");
    Word16 params[MAX_FRAMES][12];
    Word32 total[MAX_FRAMES];
    for (int f = 0; f < frames; f++) {
        char name[32];
        Word16 coder_type, nelp, ppp, bwidth, tc_subfr;
        Word32 core_brate;
        do {
            core_brate = l_frame == L_FRAME ? rates12k8[next_random() % 11] : rates16k[next_random() % 6];
            coder_type = (Word16)random_range(0, 5);
            nelp = (Word16)(l_frame == L_FRAME && next_random() % 8 == 0);
            ppp = (Word16)(!nelp && l_frame == L_FRAME && next_random() % 16 == 0);
            bwidth = (Word16)(l_frame == L_FRAME ? random_range(0, 2) : random_range(1, 3));
        } while (!frame_is_valid(l_frame, core_brate, coder_type, nelp, ppp, bwidth));
        {
            static const Word16 tcs[] = {0, 64, 128, 192, 256};
            tc_subfr = tcs[next_random() % 5];
            if (l_frame == L_FRAME16k && next_random() % 3 == 0) tc_subfr = L_FRAME16k - L_SUBFR;
        }
        total[f] = core_brate == SID_2k40 ? core_brate : core_brate + random_range(0, 1) * 400;
        Word16 nb_param = (Word16)(next_random() % 4 == 0 ? NB : bwidth);
        Word16 p[] = {coder_type, (Word16)(core_brate / 50), (Word16)((total[f] - core_brate) / 400), nelp, ppp,
                      bwidth, nb_param, tc_subfr, (Word16)(next_random() % 4 == 0), (Word16)(next_random() % 8 == 0),
                      classes[next_random() % 7], (Word16)(next_random() % 6 == 0 ? HQ_CORE : ACELP_CORE)};
        memcpy(params[f], p, sizeof(p));
        sprintf(name, "f%d", f); put16(name, p, 12);
    }
    arrow();
    for (int f = 0; f < frames; f++) {
        char name[32];
        Word16 *p = params[f];
        st->core_brate_fx = (Word32)p[1] * 50;
        st->total_brate_fx = total[f];
        st->nelp_mode_dec_fx = p[3];
        st->ppp_mode_dec_fx = p[4];
        st->bwidth_fx = p[5];
        st->prev_bfi_fx = p[8];
        st->rate_switching_reset = p[9];
        st->clas_dec = p[10];
        st->last_core_fx = p[11];
        st->core_fx = ACELP_CORE;
        Word16 aq[NB_SUBFR16k * (M + 1)], lsf_new[M], lsp_new[M], lsp_mid[M], pred = -7;
        for (int i = 0; i < NB_SUBFR16k * (M + 1); i++) aq[i] = -5;
        for (int i = 0; i < M; i++) { lsf_new[i] = -3; lsp_new[i] = -3; lsp_mid[i] = -3; }
        lsf_dec_fx(st, p[7], l_frame, p[0], p[6], aq, &pred, lsf_new, lsp_new, lsp_mid);
        sprintf(name, "aq%d", f); put16(name, aq, NB_SUBFR16k * (M + 1));
        sprintf(name, "lsf%d", f); put16(name, lsf_new, M);
        sprintf(name, "lsp%d", f); put16(name, lsp_new, M);
        sprintf(name, "mid%d", f); put16(name, lsp_mid, M);
        sprintf(name, "pred%d", f); put1(name, pred);
        sprintf(name, "%d", f); put_state(st, name);
        /* The frame-end update the decoder makes (updt_dec_fx). */
        Copy(lsf_new, st->lsf_old_fx, M);
        Copy(lsp_new, st->lsp_old_fx, M);
    }
    end_line();
    free(st);
}

/* lsf_end_dec_fx's MODE2 path: the indices come from param_lpc, laid out as the MODE2 bitstream
 * reader would (the predictor selector, then the stage indices at their bit widths, then the
 * lattice index in 15-bit words); the 16 kHz VOICED case takes the ten TCVQ indices. */
static void case_lsf_end_dec_mode2(void)
{
    static const Word16 types[] = {GENERIC, AUDIO, VOICED, UNVOICED, INACTIVE, TRANSITION};
    Decoder_State_fx *st = new_state(8);
    Word32 sr_core = next_random() % 2 ? INT_FS_FX : INT_FS_16k_FX;
    Word16 coder_type, narrow_band, mode_lvq, mode_lvq_p, predmode;
    Word16 stages0, stages1, levels0[MAX_VQ_STAGES], levels1[MAX_VQ_STAGES], bits0[MAX_VQ_STAGES], bits1[MAX_VQ_STAGES];
    Word16 param[16], n = 0;
    Word32 core_brate = sr_core == INT_FS_FX ? 9600 + 400 * random_range(0, 12) : 16400 + 800 * random_range(0, 10);
    do {
        coder_type = types[next_random() % 6];
        narrow_band = (Word16)(sr_core == INT_FS_FX && next_random() % 4 == 0);
        predmode = find_pred_mode(coder_type, sub(1, narrow_band), sr_core, &mode_lvq, &mode_lvq_p, core_brate);
    } while (predmode < 0 || (sr_core == INT_FS_16k_FX && coder_type == UNVOICED));
    stages0 = stages1 = 0;
    lsf_allocate_fx(sub(31, shr(predmode, 1)), mode_lvq, mode_lvq_p, &stages0, &stages1, levels0, levels1, bits0, bits1);
    Word16 safety_net = predmode == 0 ? 1 : predmode == 1 ? 0 : (Word16)(next_random() & 1);
    if (sr_core == INT_FS_16k_FX && coder_type == VOICED) {
        param[n++] = safety_net;
        for (int i = 0; i < 9; i++) param[n++] = (Word16)(next_random() & ((1u << BC_TCVQ_BIT_ALLOC_40B[i + 1]) - 1));
    } else {
        if (predmode == 2) param[n++] = safety_net;
        Word16 stages = safety_net ? stages0 : stages1, *bits = safety_net ? bits0 : bits1, *levels = safety_net ? levels0 : levels1;
        for (int i = 0; i < stages - 1; i++) param[n++] = (Word16)(next_random() & ((1u << bits[i]) - 1));
        for (int left = levels[stages - 1]; left > 0; left -= LEN_INDICE) {
            int b = left > LEN_INDICE ? LEN_INDICE : left;
            param[n++] = (Word16)(next_random() % 4 ? (next_random() & ((1u << b) - 1)) : random_range(0, 40));
        }
    }
    while (n < 16) param[n++] = 0;
    random_lsf(st->mem_AR_fx, sr_core);
    for (int i = 0; i < M; i++) st->mem_MA_fx[i] = (Word16)random_range(-400, 400);
    st->reset_mem_AR = (Word16)(next_random() % 6 == 0);
    st->total_brate_fx = core_brate;
    st->core_brate_fx = core_brate;
    put1("sr_core", sr_core); put1("coder_type", coder_type); put1("narrow_band", narrow_band); put1("core_brate", core_brate);
    put16("param", param, 16);
    put_state(st, "");
    Word16 lsf[M], pred = -7, nb_indices = -9;
    for (int i = 0; i < M; i++) lsf[i] = -3;
    lsf_end_dec_fx(st, 1, coder_type, sub(1, narrow_band), 31, lsf, st->mem_AR_fx, st->mem_MA_fx, sr_core, st->core_brate_fx,
                   &st->offset_scale1_fx[0][0], &st->offset_scale2_fx[0][0], &st->offset_scale1_p_fx[0][0], &st->offset_scale2_p_fx[0][0],
                   &st->no_scales_fx[0][0], &st->no_scales_p_fx[0][0], &st->safety_net_fx, param, &pred, &nb_indices);
    arrow(); put16("lsf", lsf, M); put1("pred", pred); put1("nb_indices", nb_indices); put_state(st, ""); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lsf_dec")) case_lsf_dec();
        else if (!strcmp(argv[2], "lsf_end_dec_mode2")) case_lsf_end_dec_mode2();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
