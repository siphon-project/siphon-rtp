/* Function-level oracle for the MODE2 LPC dequantisation front end: AVQ_dec_lpc (lib_dec/avq_dec_fx.c),
 * vlpc_1st_dec, vlpc_2st_dec, lsf_weight_2st, dlpc_avq, decode_lpc_avq (with unary_decode, pack4bits),
 * lpc_unquantize (lib_dec/dlpc_stoch.c), dlpc_bfi (lib_com/dlpc_bfi.c) and the guided-PLC helpers
 * modify_lsf, reorder_lsfs, RecLpcSpecPowDiffuseLc (lib_com/guided_plc_util.c, included for its static). */
#include "harness.h"
#include "../../c-code/lib_com/guided_plc_util.c"

#define BUFFER_BITS (MAX_BITS_PER_FRAME + 16)
#define NPRM_LPC 136
static UWord16 bit_buffer[BUFFER_BITS];

static void random_lsf(Word16 *lsf, int top)
{
    int pos = 0;
    for (int i = 0; i < M; i++) {
        pos += random_range(100, 2 * top / M - 100);
        if (pos >= top - 120) pos = top - 120;
        lsf[i] = (Word16)pos;
    }
}

static Decoder_State_fx *new_state(int total_bits)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int style = next_random() % 5;
    for (int i = 0; i < BUFFER_BITS; i++)
        bit_buffer[i] = (UWord16)(style == 0 ? next_random() % 8 == 0 : style == 1 ? next_random() % 8 != 0 : next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)total_bits;
    st->next_bit_pos_fx = (Word16)random_range(0, 12);
    st->codec_mode = MODE2;
    init_lvq_fx(st->offset_scale1_fx, st->offset_scale2_fx, st->offset_scale1_p_fx, st->offset_scale2_p_fx, st->no_scales_fx,
                st->no_scales_p_fx);
    return st;
}

static void case_avq_dec_lpc(void)
{
    Word16 indx[2 + 64], nvecq[16];
    static const Word16 nqs[] = {0, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13};
    Word16 nq0 = nqs[next_random() % 11], nq1 = nqs[next_random() % 11];
    indx[0] = nq0; indx[1] = nq1;
    int words = nq0 + nq1;
    for (int i = 0; i < words; i++) indx[2 + i] = (Word16)(next_random() & 0xF);
    for (int i = 0; i < 16; i++) nvecq[i] = 4321;
    put16("indx", indx, 2 + words);
    AVQ_dec_lpc(indx, nvecq, 2);
    arrow(); put16("nvecq", nvecq, 16); end_line();
}

static void case_vlpc_1st(void)
{
    Word16 lsfq[M];
    Word16 index = (Word16)random_range(0, 255);
    for (int i = 0; i < M; i++) lsfq[i] = (Word16)random_range(-2000, 2000);
    put1("index", index); put16("lsfq", lsfq, M);
    vlpc_1st_dec(index, lsfq);
    arrow(); put16("lsfq", lsfq, M); end_line();
}

static void case_weight(void)
{
    Word16 lsfq[M], w[M];
    random_lsf(lsfq, 16384);
    if (next_random() % 4 == 0) for (int i = 0; i < M; i++) lsfq[i] = (Word16)(lsfq[i] + random_range(-60, 60));
    Word16 mode = (Word16)(next_random() % 3 == 0 ? 3 : random_range(0, 1));
    put16("lsfq", lsfq, M); put1("mode", mode);
    for (int i = 0; i < M; i++) w[i] = 4321;
    lsf_weight_2st(lsfq, w, mode);
    arrow(); put16("w", w, M); end_line();
}

static Word32 random_core_rate(void)
{
    static const Word32 rates[] = {12800, 16000, 25600, 32000};
    return rates[next_random() % 4];
}

static void case_vlpc_2st(void)
{
    Word16 lsfq[M], indx[2 + 48];
    static const Word16 nqs[] = {0, 2, 3, 4, 5, 6, 7, 8, 9, 11};
    Word16 nq0 = nqs[next_random() % 10], nq1 = nqs[next_random() % 10];
    random_lsf(lsfq, 16384);
    indx[0] = nq0; indx[1] = nq1;
    int words = nq0 + nq1;
    for (int i = 0; i < words; i++) indx[2 + i] = (Word16)(next_random() & 0xF);
    Word16 mode = (Word16)(next_random() & 1 ? 0 : 3);
    Word32 sr_core = random_core_rate();
    put16("lsfq", lsfq, M); put16("indx", indx, 2 + words); put1("mode", mode); put1("sr_core", sr_core);
    vlpc_2st_dec(lsfq, indx, mode, sr_core);
    arrow(); put16("lsfq", lsfq, M); end_line();
}

static void case_decode_lpc_avq(void)
{
    Word16 param[NPRM_LPC];
    Decoder_State_fx *st = new_state(640);
    Word16 numlpc = (Word16)random_range(1, 2);
    for (int i = 0; i < NPRM_LPC; i++) param[i] = 77;
    put1("numlpc", numlpc); put1("start", st->next_bit_pos_fx); put_u16("bits", bit_buffer, 640);
    Word16 r = decode_lpc_avq(st, numlpc, param);
    arrow(); put1("r", r); put16("param", param, NPRM_LPC); put1("pos", st->next_bit_pos_fx); put1("ber", st->BER_detect); end_line();
    free(st);
}

static void case_dlpc_avq(void)
{
    Word16 param[NPRM_LPC], lsf_q[2 * M];
    Decoder_State_fx *st = new_state(640);
    Word16 numlpc = (Word16)random_range(1, 2);
    Word32 sr_core = random_core_rate();
    for (int i = 0; i < NPRM_LPC; i++) param[i] = 0;
    decode_lpc_avq(st, numlpc, param);
    for (int i = 0; i < 2 * M; i++) lsf_q[i] = 4321;
    put1("numlpc", numlpc); put1("sr_core", sr_core); put16("param", param, NPRM_LPC);
    Word16 r = dlpc_avq(param, lsf_q, numlpc, sr_core);
    arrow(); put1("r", r); put16("lsf_q", lsf_q, numlpc * M); end_line();
    free(st);
}

static void case_lpc_unquantize(void)
{
    static const Word16 types[] = {GENERIC, AUDIO, VOICED, UNVOICED, INACTIVE};
    Decoder_State_fx *st = new_state(640);
    Word32 sr_core = next_random() % 2 ? INT_FS_FX : INT_FS_16k_FX;
    Word16 lpcq = (Word16)(next_random() % 3 != 0);
    Word16 core = (Word16)(next_random() % 4 == 0 ? TCX_20_CORE : ACELP_CORE);
    Word16 coder_type, narrow_band, mode_lvq, mode_lvq_p, predmode, numlpc = (Word16)(lpcq ? 1 : random_range(1, 2));
    Word16 stages0, stages1, levels0[MAX_VQ_STAGES], levels1[MAX_VQ_STAGES], bits0[MAX_VQ_STAGES], bits1[MAX_VQ_STAGES];
    Word16 param[NPRM_LPC], n = 0;
    Word32 core_brate = sr_core == INT_FS_FX ? 9600 + 400 * random_range(0, 12) : 16400 + 800 * random_range(0, 10);
    Word16 eff;
    for (int i = 0; i < NPRM_LPC; i++) param[i] = 0;
    st->core_fx = core;
    do {
        coder_type = types[next_random() % 5];
        narrow_band = (Word16)(sr_core == INT_FS_FX && next_random() % 4 == 0);
        eff = (sr_core == INT_FS_16k_FX && coder_type == UNVOICED) ? GENERIC : (core == TCX_20_CORE) ? AUDIO : coder_type;
        predmode = find_pred_mode(eff, sub(1, narrow_band), sr_core, &mode_lvq, &mode_lvq_p, core_brate);
    } while (lpcq && predmode < 0);
    if (lpcq) {
        stages0 = stages1 = 0;
        lsf_allocate_fx(sub(31, shr(predmode, 1)), mode_lvq, mode_lvq_p, &stages0, &stages1, levels0, levels1, bits0, bits1);
        Word16 safety_net = predmode == 0 ? 1 : predmode == 1 ? 0 : (Word16)(next_random() & 1);
        if (sr_core == INT_FS_16k_FX && eff == VOICED) {
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
        param[n] = (Word16)random_range(0, 31); /* the mid-frame index follows the others */
    } else {
        decode_lpc_avq(st, numlpc, param);
    }
    int top = sr_core == INT_FS_FX ? 16384 : 20480;
    random_lsf(st->lsf_old_fx, top);
    lsf2lsp_fx(st->lsf_old_fx, st->lsp_old_fx, M, sr_core);
    random_lsf(st->mem_AR_fx, top);
    for (int i = 0; i < M; i++) st->mem_MA_fx[i] = (Word16)random_range(-400, 400);
    st->reset_mem_AR = (Word16)(next_random() % 6 == 0);
    st->sr_core = sr_core;
    st->core_brate_fx = core_brate;
    st->total_brate_fx = core_brate;
    st->mid_lsf_int_fx = (Word16)(next_random() & 1);
    st->safety_net_fx = (Word16)(next_random() & 1);
    st->rate_switching_reset = (Word16)(next_random() % 8 == 0);
    st->seed_acelp = random16();
    st->numlpc = numlpc;
    st->lpcQuantization = lpcq;
    st->narrowBand = (Word8)narrow_band;
    Word16 mid_lpc = (Word16)(next_random() % 3 != 0), prev_bfi = (Word16)(next_random() % 4 == 0);
    Word16 lsf[(NB_DIV + 1) * M], lsp[(NB_DIV + 1) * M], lspmid[M], lsfmid[M], pred = -7;
    for (int i = 0; i < (NB_DIV + 1) * M; i++) { lsf[i] = -3; lsp[i] = -3; }
    for (int i = 0; i < M; i++) { lspmid[i] = -4; lsfmid[i] = -4; }
    put1("sr_core", sr_core); put1("core", core); put1("lpcq", lpcq); put1("numlpc", numlpc); put1("coder_type", coder_type);
    put1("narrow_band", narrow_band); put1("core_brate", core_brate); put16("param", param, NPRM_LPC);
    put16("lsf_old", st->lsf_old_fx, M); put16("lsp_old", st->lsp_old_fx, M); put16("mem_ar", st->mem_AR_fx, M);
    put16("mem_ma", st->mem_MA_fx, M); put1("reset_mem_ar", st->reset_mem_AR); put1("mid_lsf_int", st->mid_lsf_int_fx);
    put1("safety_net", st->safety_net_fx); put1("rate_switching_reset", st->rate_switching_reset); put1("seed", st->seed_acelp);
    put1("mid_lpc", mid_lpc); put1("prev_bfi", prev_bfi);
    lpc_unquantize(st, st->lsf_old_fx, st->lsp_old_fx, lsf, lsp, M, st->lpcQuantization, param, st->numlpc, st->core_fx,
                   st->mem_MA_fx, st->mem_AR_fx, lspmid, lsfmid, coder_type, mid_lpc, st->narrowBand, &(st->seed_acelp),
                   st->sr_core, &st->mid_lsf_int_fx, prev_bfi, &pred, &st->safety_net_fx);
    arrow(); put16("lsf", lsf, (NB_DIV + 1) * M); put16("lsp", lsp, (NB_DIV + 1) * M); put16("lspmid", lspmid, M);
    put16("lsfmid", lsfmid, M); put1("pred", pred); put1("seed", st->seed_acelp); put1("mid_lsf_int", st->mid_lsf_int_fx);
    put1("safety_net", st->safety_net_fx); put16("mem_ar", st->mem_AR_fx, M); put16("mem_ma", st->mem_MA_fx, M);
    put1("reset_mem_ar", st->reset_mem_AR);
    end_line();
    free(st);
}

static void case_dlpc_bfi(void)
{
    static const Word16 l_frames[] = {L_FRAME, L_FRAME16k, 320, 512, 640, 200};
    Word16 l_frame = l_frames[next_random() % 6], tcxonly = (Word16)(next_random() & 1);
    Word16 plc_updated = (Word16)(next_random() & 1), have_q_cng = (Word16)(next_random() & 1), have_cng = (Word16)(next_random() & 1);
    Word16 numlpc = (Word16)random_range(1, 2);
    Word32 sr = l_frame == L_FRAME ? 12800 : (next_random() & 1) ? 16000 : 25600;
    const Word16 *base = PlcGetLsfBase((Word16)(next_random() & 1), (Word16)(next_random() & 1), sr);
    int top = l_frame == L_FRAME ? 16384 : 20480;
    Word16 lsf_q[2 * M], lsfold[M], mean[M], mem_ma[M], mem_ar[M], lsf_q_cng[M], lsf_cng[M], old_q_cng[M];
    random_lsf(lsfold, top); random_lsf(mean, top); random_lsf(lsf_cng, top); random_lsf(old_q_cng, top);
    for (int i = 0; i < M; i++) { mem_ma[i] = (Word16)random_range(-2000, 2000); mem_ar[i] = (Word16)random_range(0, top); lsf_q_cng[i] = -1; }
    for (int i = 0; i < 2 * M; i++) lsf_q[i] = -1;
    Word16 stab_fac = (Word16)random_range(0, 32767), last_good = (Word16)random_range(0, 7), lost = (Word16)random_range(1, 9);
    put1("l_frame", l_frame); put16("lsfold", lsfold, M); put16("mean", mean, M); put16("base", base, M);
    put16("mem_ma", mem_ma, M); put16("mem_ar", mem_ar, M); put1("stab_fac", stab_fac); put1("last_good", last_good);
    put1("lost", lost); put1("numlpc", numlpc); put1("plc_updated", plc_updated); put1("have_q_cng", have_q_cng);
    put1("have_cng", have_cng); put16("lsf_cng", lsf_cng, M); put16("old_q_cng", old_q_cng, M); put1("tcxonly", tcxonly);
    dlpc_bfi(l_frame, lsf_q, lsfold, last_good, lost, mem_ma, mem_ar, &stab_fac, mean, numlpc, have_cng ? lsf_cng : NULL,
             (Word8)plc_updated, have_q_cng ? lsf_q_cng : NULL, have_q_cng ? old_q_cng : NULL, base, (Word8)tcxonly);
    arrow(); put16("lsf_q", lsf_q, 2 * M); put16("mem_ma", mem_ma, M); put16("mem_ar", mem_ar, M); put16("lsf_q_cng", lsf_q_cng, M);
    end_line();
}

static void case_modify_lsf(void)
{
    Word16 lsf[M];
    Word32 sr_core = (next_random() & 1) ? 12800 : 16000;
    Word16 reset_q = (Word16)(next_random() & 1);
    random_lsf(lsf, sr_core == 12800 ? 16384 : 20480);
    if (next_random() % 6 == 0) for (int i = 0; i < M; i++) lsf[i] = (Word16)(200 + i * 50);
    if (next_random() % 8 == 0) for (int i = 0; i < M; i++) lsf[i] = (Word16)(1000 + i * 100);
    if (next_random() % 3 == 0) { /* an LSF right at one of the thresholds */
        static const Word16 thresholds[] = {4864, 6080, 2048, 2560};
        int at = random_range(3, 12);
        for (int i = 0; i < M; i++) lsf[i] = (Word16)(300 + i * 200);
        lsf[at] = (Word16)(thresholds[next_random() % 4] - random_range(0, 1));
    }
    put16("lsf", lsf, M); put1("sr_core", sr_core); put1("reset_q", reset_q);
    modify_lsf(lsf, M, sr_core, reset_q);
    arrow(); put16("lsf", lsf, M); end_line();
}

static void case_reorder_lsfs(void)
{
    Word16 lsf[M];
    Word32 sr_core = (next_random() & 1) ? 12800 : 16000;
    Word16 min_dist = (Word16)(next_random() & 1 ? LSF_GAP_FX : random_range(50, 300));
    random_lsf(lsf, sr_core == 12800 ? 16384 : 20480);
    int mode = next_random() % 4;
    if (mode == 0) for (int i = 0; i < M; i++) lsf[i] = (Word16)random_range(0, sr_core == 12800 ? 16400 : 20500);
    if (mode == 1) for (int i = 0; i < M; i++) lsf[i] = (Word16)(sr_core == 12800 ? 16100 + i : 20200 + i);
    if (mode == 2) for (int i = 0; i < M; i++) lsf[i] = (Word16)(300 + 3 * i);
    put16("lsf", lsf, M); put1("sr_core", sr_core); put1("min_dist", min_dist);
    reorder_lsfs(lsf, min_dist, M, sr_core);
    arrow(); put16("lsf", lsf, M); end_line();
}

static void case_rec_lpc(void)
{
    Decoder_State_fx *st = new_state(8);
    Word32 sr_core = (next_random() & 1) ? 12800 : 16000;
    int top = sr_core == 12800 ? 16384 : 20480;
    Word16 reset_q = (Word16)(next_random() & 1), lspq[M], lsp_old[M], lsfq[M];
    st->sr_core = sr_core;
    st->lpcQuantization = (Word16)(next_random() & 1);
    st->narrowBand = (Word8)(next_random() & 1);
    random_lsf(st->lsf_old_fx, top);
    for (int i = 0; i < M; i++) { st->mem_MA_fx[i] = (Word16)random_range(-400, 400); lspq[i] = -1; lsp_old[i] = -1; }
    random_lsf(lsfq, top);
    put1("sr_core", sr_core); put1("lpcq", st->lpcQuantization); put1("narrow_band", st->narrowBand); put16("lsf_old", st->lsf_old_fx, M);
    put16("mem_ma", st->mem_MA_fx, M); put16("lsfq", lsfq, M); put1("reset_q", reset_q);
    RecLpcSpecPowDiffuseLc(lspq, lsp_old, lsfq, st, reset_q);
    arrow(); put16("lspq", lspq, M); put16("lsp_old", lsp_old, M); put16("lsfq", lsfq, M); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    struct { const char *name; void (*run)(void); } table[] = {
        {"avq_dec_lpc", case_avq_dec_lpc}, {"vlpc_1st", case_vlpc_1st}, {"weight", case_weight}, {"vlpc_2st", case_vlpc_2st},
        {"decode_lpc_avq", case_decode_lpc_avq}, {"dlpc_avq", case_dlpc_avq}, {"lpc_unquantize", case_lpc_unquantize},
        {"dlpc_bfi", case_dlpc_bfi}, {"modify_lsf", case_modify_lsf}, {"reorder_lsfs", case_reorder_lsfs},
        {"rec_lpc", case_rec_lpc},
    };
    void (*run)(void) = NULL;
    for (unsigned k = 0; k < sizeof(table) / sizeof(table[0]); k++) if (!strcmp(argv[2], table[k].name)) run = table[k].run;
    if (!run) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) run();
    return 0;
}
