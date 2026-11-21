/* Function-level oracle for lib_dec/stat_noise_uv_dec_fx.c: stat_noise_uv_dec_fx over runs of
 * consecutive frames on one decoder state (the unvoiced counter, the CNG LSP / energy averages and
 * the stat_noise_uv_mod_fx state all carry across frames), reading its noisiness parameter from a
 * random bit stream. */
#include "harness.h"
#include "prot_fx.h"

#define MAX_FRAMES 8

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static void random_lsp(Word16 *lsp)
{
    int value = 32767 - random_range(50, 2500);
    for (int i = 0; i < M; i++) {
        lsp[i] = (Word16)value;
        value -= random_range(300, 65000 / M);
        if (value < -32767) value = -32767 + random_range(0, 10);
    }
}

static void put_state(Decoder_State_fx *st, const char *suffix)
{
    char name[32];
    Word16 s[] = {st->unv_cnt_fx, st->lp_gainc_fx, st->uv_count_fx, st->act_count_fx, st->noimix_seed_fx, st->min_alpha_fx,
                  st->exc_pe_fx, st->Q_stat_noise, st->Q_stat_noise_ge, st->next_bit_pos_fx};
    sprintf(name, "st%s", suffix); put16(name, s, 10);
    Word32 l[] = {st->lp_ener_fx, st->ge_sm_fx};
    sprintf(name, "l%s", suffix); put32(name, l, 2);
    sprintf(name, "lspcng%s", suffix); put16(name, st->lspCNG_fx, M);
    sprintf(name, "lspold_s%s", suffix); put16(name, st->lspold_s_fx, M);
}

static void case_stat_noise_uv_dec(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 16400, 8000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    int n = MAX_FRAMES * 5 + 8;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)n;
    st->next_bit_pos_fx = 0;
    st->unv_cnt_fx = (Word16)(next_random() % 2 ? random_range(0, 25) : random_range(15, 22));
    st->lp_gainc_fx = (Word16)random_range(0, 32767);
    st->lp_ener_fx = next_random() % 4 ? random_range(0, 1 << 24) : random32() & 0x7fffffff;
    random_lsp(st->lspCNG_fx);
    random_lsp(st->lsp_old_fx);
    random_lsp(st->lspold_s_fx);
    st->Opt_AMR_WB_fx = (Word16)(next_random() % 8 == 0);
    st->ge_sm_fx = next_random() % 4 ? 640 : random_range(0, 1 << 20);
    st->uv_count_fx = (Word16)random_range(0, 10);
    st->act_count_fx = (Word16)random_range(0, 3);
    st->noimix_seed_fx = random16();
    st->min_alpha_fx = (Word16)(next_random() % 3 ? 32767 : random_range(16384, 32767));
    st->exc_pe_fx = (Word16)(next_random() % 2 ? 0 : random_range(-3000, 3000));
    st->Q_stat_noise = (Word16)random_range(-1, 11);
    st->Q_stat_noise_ge = GE_SHIFT;
    st->bwidth_fx = (Word16)(next_random() % 4 ? WB : NB);
    int frames = random_range(1, MAX_FRAMES);
    put1("frames", frames); put_u16("bits", bit_buffer, n); put16("lsp_old", st->lsp_old_fx, M); put1("amr", st->Opt_AMR_WB_fx);
    put1("bwidth", st->bwidth_fx);
    put_state(st, "");
    Word16 out_aq[MAX_FRAMES][NB_SUBFR * (M + 1)], out_exc[MAX_FRAMES][L_FRAME];
    for (int f = 0; f < frames; f++) {
        char name[32];
        Word16 coder_type = (Word16)(next_random() % 4 ? INACTIVE : (next_random() % 2 ? UNVOICED : GENERIC));
        st->core_brate_fx = rates[next_random() % 6];
        st->Q_exc = (Word16)random_range(-3, 13);
        Word16 lsp_new[M], lsp_mid[M];
        random_lsp(lsp_new); random_lsp(lsp_mid);
        Word16 *exc2 = out_exc[f];
        if (next_random() % 10 == 0) memset(exc2, 0, L_FRAME * sizeof(Word16));
        else random_signal(exc2, L_FRAME, 1 << random_range(2, 15));
        Word16 params[3] = {coder_type, (Word16)(st->core_brate_fx / 100), st->Q_exc};
        sprintf(name, "f%d", f); put16(name, params, 3);
        sprintf(name, "new%d", f); put16(name, lsp_new, M);
        sprintf(name, "mid%d", f); put16(name, lsp_mid, M);
        sprintf(name, "exc%d", f); put16(name, exc2, L_FRAME);
        for (int i = 0; i < NB_SUBFR * (M + 1); i++) out_aq[f][i] = -5;
        stat_noise_uv_dec_fx(st, coder_type, lsp_new, lsp_mid, out_aq[f], exc2);
    }
    arrow();
    for (int f = 0; f < frames; f++) {
        char name[32];
        sprintf(name, "aq%d", f); put16(name, out_aq[f], NB_SUBFR * (M + 1));
        sprintf(name, "exc%d", f); put16(name, out_exc[f], L_FRAME);
    }
    put_state(st, "");
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "stat_noise_uv_dec")) case_stat_noise_uv_dec();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
