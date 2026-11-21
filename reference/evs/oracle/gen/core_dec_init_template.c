/* Function-level oracle for lib_dec/core_dec_init.c (open_decoder_LPD).
 *
 * Each case builds a decoder the way init_decoder_fx and mode_switch_decoder_LPD leave it: a first
 * open_decoder_LPD on a fresh state (ini_frame 0), then zero to three later calls at other bit
 * rates and bandwidths, each after the per-frame fields a decoder would have set (last core,
 * codec mode, frame length, concealment flags) and fresh signal memories. Only the last call is
 * printed: every field open_decoder_LPD reads or writes, before and after. Arrays it only writes
 * are filled with a deterministic pattern before the call and compared by hash. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define CLDFB_STATE_BUFFER_SIZE (9 + 16) /* STATE_BUFFER_SIZE, file-local in cldfb.c */

static long long hash16(const Word16 *x, int n)
{
    unsigned int h = 2166136261u;
    for (int i = 0; i < n; i++) { h ^= (unsigned short)x[i]; h *= 16777619u; }
    return h;
}

static long long hash32(const Word32 *x, int n)
{
    unsigned int h = 2166136261u;
    for (int i = 0; i < n; i++) { h ^= (unsigned int)x[i]; h *= 16777619u; }
    return h;
}

static void fill_pattern16(Word16 *x, int n, int salt)
{
    for (int i = 0; i < n; i++) x[i] = (Word16)((i * 31 + salt * 17) % 2001 - 1000);
}

static void fill_pattern32(Word32 *x, int n, int salt)
{
    for (int i = 0; i < n; i++) x[i] = (Word32)((i * 31 + salt * 17) % 2001 - 1000) * 65537;
}

static int tns_table_id(const struct TnsParameters *p)
{
    const struct TnsParameters *tables[] = {tnsParametersIGF32kHz_LowBR, tnsParameters32kHz, tnsParameters32kHz_grouped,
                                            tnsParameters16kHz, tnsParameters16kHz_grouped, tnsParameters48kHz_grouped};
    for (int i = 0; i < 6; i++) if (p == tables[i]) return i;
    return -1;
}

static int cldfb_buffer_length(HANDLE_CLDFB_FILTER_BANK hs)
{
    return (hs->type == CLDFB_ANALYSIS ? 1 : 2) * CLDFB_STATE_BUFFER_SIZE * hs->no_channels;
}

static void put_banks(Decoder_State_fx *st)
{
    HANDLE_CLDFB_FILTER_BANK banks[3] = {st->cldfbAna_fx, st->cldfbBPF_fx, st->cldfbSyn_fx};
    const char *names[3] = {"cldfb_ana", "cldfb_bpf", "cldfb_syn"};
    for (int b = 0; b < 3; b++) {
        char name[64];
        sprintf(name, "%s_states", names[b]); put1(name, hash16(banks[b]->FilterStates, cldfb_buffer_length(banks[b])));
        sprintf(name, "%s_e", names[b]); put16(name, banks[b]->FilterStates_e, CLDFB_NO_COL_MAX + 9);
        sprintf(name, "%s_eg", names[b]); put1(name, banks[b]->FilterStates_eg);
    }
}

static void put_tns(Decoder_State_fx *st)
{
    for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) {
        STnsConfig *c = &st->tcx_cfg.tnsConfig[i][j];
        char name[32];
        sprintf(name, "tns%d%d", i, j);
        Word16 v[6] = {c->maxOrder, c->nMaxFilters, (Word16)tns_table_id(c->pTnsParameters),
                       c->iFilterBorders[0], c->iFilterBorders[1], c->iFilterBorders[2]};
        put16(name, v, 6);
    }
}

static void put_state(Decoder_State_fx *st)
{
@@DUMP@@
    put_tns(st);
}

static void fill_patterns(Decoder_State_fx *st)
{
@@FILL@@
    HANDLE_CLDFB_FILTER_BANK banks[3] = {st->cldfbAna_fx, st->cldfbBPF_fx, st->cldfbSyn_fx};
    for (int b = 0; b < 3; b++) {
        fill_pattern16(banks[b]->FilterStates, cldfb_buffer_length(banks[b]), 100 + b);
        for (int i = 0; i < CLDFB_NO_COL_MAX + 9; i++) banks[b]->FilterStates_e[i] = (Word16)(i % 5 + b);
        banks[b]->FilterStates_eg = (Word16)(3 + b);
    }
}

/* An ordered LSF vector at the core rate (Q(x2.56) of 6400 Hz), at least 128 apart, and its LSPs. */
static void random_lsf_lsp(Word16 *lsf, Word16 *lsp)
{
    int pos = random_range(100, 600);
    for (int i = 0; i < M; i++) {
        if (i > 0) pos += random_range(128, 1400);
        if (pos > 16000 - (M - 1 - i) * 200) pos = 16000 - (M - 1 - i) * 200;
        lsf[i] = (Word16)pos;
    }
    E_LPC_lsf_lsp_conversion(lsf, lsp, M);
}

/* A bit rate / bandwidth pair: for the first call (init_decoder_fx) any EVS rate; for a later one
 * (mode_switch_decoder_LPD) a rate the LPD core runs at, channel-aware mode at 13.2 kbit/s
 * included. */
static void random_mode(int first, Word32 *bitrate, Word16 *bandwidth, Word16 *rf_flag)
{
    static const Word32 rates[] = {9600, 13200, 16400, 24400, 32000, 48000, 96000, 128000, 7200, 8000, 64000};
    for (;;) {
        *bitrate = rates[next_random() % (first ? 11 : 8)];
        *bandwidth = (Word16)random_range(NB, FB);
        *rf_flag = 0;
        if (*bandwidth == NB && *bitrate > 24400) continue;
        if (*bandwidth == WB && *bitrate > 64000 && first) continue;
        if (*bandwidth == SWB && *bitrate < 13200) continue;
        if (*bandwidth == FB && *bitrate < 16400) continue;
        if (*bitrate == 13200 && *bandwidth != NB && *bandwidth != FB && (next_random() & 1)) *rf_flag = 1;
        return;
    }
}

/* The bandwidth, RF flag and IGF configuration: init_decoder_fx leaves IGF off and its handle
 * zeroed; mode_switch_decoder_LPD configures it for the new mode. */
static void set_mode(Decoder_State_fx *st, int first, Word32 bitrate, Word16 bandwidth, Word16 rf_flag)
{
    st->rf_flag = rf_flag;
    st->bwidth_fx = bandwidth;
    if (first) return;
    st->igf = getIgfPresent(bitrate, bandwidth, rf_flag);
    st->hIGFDec.infoIGFStopFreq = -1;
    if (st->igf) IGFDecSetMode(&st->hIGFDec, bitrate, bandwidth, -1, -1, rf_flag);
}

/* The per-frame state a decoder leaves between two open_decoder_LPD calls. */
static void next_frame(Decoder_State_fx *st, Word32 last_bitrate)
{
    static const Word16 mode1_cores[] = {ACELP_CORE, ACELP_CORE, HQ_CORE, AMR_WB_CORE};
    static const Word16 mode2_cores[] = {ACELP_CORE, TCX_20_CORE, TCX_10_CORE};
    st->ini_frame_fx = (Word16)(st->ini_frame_fx + 1);
    st->last_bwidth_fx = st->bwidth_fx;
    st->last_total_brate_fx = (next_random() % 8) ? last_bitrate : (Word32)random_range(5900, 128000);
    st->last_L_frame_fx = st->L_frame_fx;
    if (next_random() % 3 == 0) {
        st->last_codec_mode = MODE1;
        st->last_core_fx = mode1_cores[next_random() % 4];
        st->last_L_frame_fx = (st->last_core_fx != AMR_WB_CORE && (next_random() & 1)) ? L_FRAME16k : L_FRAME;
    } else {
        st->last_codec_mode = MODE2;
        st->last_core_fx = mode2_cores[next_random() % 3];
    }
    st->core_fx = (Word16)((next_random() % 3) == 0 ? HQ_CORE : random_range(ACELP_CORE, TCX_20_CORE));
    st->prev_bfi_fx = (Word16)((next_random() % 3) == 0);
    st->m_frame_type = (Word16)((next_random() % 4) == 0 ? SID_FRAME : 0);
    st->last_con_tcx = (Word16)(next_random() & 1);
    st->Q_old_wtda = (Word16)random_range(-2, 4);
    st->Q_syn = (Word16)random_range(-1, 4);
    st->pfstat.on = (Word16)(next_random() & 1);
    st->pst_lp_ener_fx = (Word16)random_range(0, 80 * 256);
    st->force_lpd_reset = (Word16)((next_random() % 4) == 0);
    random_lsf_lsp(st->lsf_old_fx, st->lsp_old_fx);
    Word16 lsp[M];
    random_lsf_lsp(st->lsf_cng, lsp);
    int magnitude = random_range(100, 16000);
    random_signal(st->fer_samples_fx, L_FRAME48k, magnitude);
    /* quieter, and often silent in its first half, so the energy at the end of the frame
     * (frame_ener_fx after a lost HQ frame) depends on which half it measures */
    random_signal(st->previoussynth_fx, L_FRAME48k, random_range(1, 2000));
    if (next_random() & 1) memset(st->previoussynth_fx, 0, sizeof(Word16) * random_range(0, L_FRAME48k / 2));
    if (st->last_core_fx == HQ_CORE && (next_random() & 1)) { st->prev_bfi_fx = 1; st->core_fx = ACELP_CORE; }
    random_signal(st->old_out_fx, L_FRAME48k, magnitude);
    random_signal(st->old_out_LB_fx, L_FRAME32k, magnitude);
    random_signal(st->old_exc_fx, L_EXC_MEM_DEC, magnitude / 2);
    random_signal(st->mem_syn_r, L_SYN_MEM, magnitude);
    random_signal(st->mem_syn2_fx, M, magnitude);
    random_signal(st->pfstat.mem_pf_in, L_SUBFR, magnitude);
    random_signal(st->pfstat.mem_stp, L_SUBFR, magnitude);
    random_signal(st->pfstat.mem_res2, DECMEM_RES2, magnitude);
    random_signal(st->syn, M + 1, magnitude);
    random_signal(st->pst_old_syn_fx, NBPSF_PIT_MAX, magnitude);
}

static void case_open_decoder_lpd(void)
{
    static const Word32 output_rates[] = {8000, 16000, 32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = output_rates[next_random() % 4];
    st->output_frame_fx = (Word16)(st->output_Fs_fx / 50);
    openCldfb(&st->cldfbAna_fx, CLDFB_ANALYSIS, CLDFB_getNumChannels(48000), 320);
    openCldfb(&st->cldfbBPF_fx, CLDFB_ANALYSIS, CLDFB_getNumChannels(16000), 320);
    openCldfb(&st->cldfbSyn_fx, CLDFB_SYNTHESIS, CLDFB_getNumChannels(st->output_Fs_fx), st->output_frame_fx);
    st->hIGFDec.igfData.igfInfo.nfSeed = 9733;
    random_lsf_lsp(st->lsf_old_fx, st->lsp_old_fx);

    Word32 bitrate, last_bitrate = 0;
    Word16 bandwidth, rf_flag;
    int calls = random_range(1, 4);
    for (int call = 0; call < calls; call++) {
        if (call > 0) next_frame(st, last_bitrate);
        random_mode(call == 0, &bitrate, &bandwidth, &rf_flag);
        /* the 12.8 <-> 16 kHz ACELP switch most of the time on a later call */
        if (call > 0 && (next_random() & 1)) {
            static const Word32 acelp_rates[] = {9600, 13200, 16400, 24400, 32000};
            bitrate = acelp_rates[next_random() % 5];
            bandwidth = (Word16)(bitrate <= 9600 ? random_range(NB, WB) : random_range(WB, SWB));
            rf_flag = 0;
        }
        set_mode(st, call == 0, bitrate, bandwidth, rf_flag);
        if (call == calls - 1) {
            fill_patterns(st);
            put1("bitrate", bitrate); put1("bandwidth", bandwidth); put_state(st);
        }
        open_decoder_LPD(st, bitrate, bandwidth);
        last_bitrate = bitrate;
    }
    arrow(); put_state(st); put_banks(st); end_line();
    deleteCldfb(&st->cldfbAna_fx); deleteCldfb(&st->cldfbBPF_fx); deleteCldfb(&st->cldfbSyn_fx);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "open_decoder_lpd")) case_open_decoder_lpd();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
