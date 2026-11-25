/* Function-level oracle for the MODE2 LSF quantisation helpers: E_LPC_a_isp_conversion,
 * E_LPC_isp_isf_conversion, lsp2isp_fx, isp2lsp_fx, lsf2isf_fx, isf2lsf_fx, lsf_update_memory,
 * tcxlpc_get_cdk, msvq_dec (lib_com/lsf_tools_fx.c); midlsf_dec, lsf_ind_is_active (lib_com/lsf_msvq_ma.c);
 * lsf_msvq_ma_decprm, lsf_bctcvq_decprm, D_lsf_tcxlpc, dec_lsf_tcxlpc (lib_dec/lsf_msvq_ma_dec.c). */
#include "harness.h"
#include "cnst_fx.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define BUFFER_BITS (MAX_BITS_PER_FRAME + 16)
static UWord16 bit_buffer[BUFFER_BITS];

/* Ascending LSFs in Q(x2.56) (0..16384) with a minimum gap, as a quantiser yields them. */
static void random_lsf(Word16 *lsf, int m)
{
    int spread = random_range(100, 600);
    for (int k = 0; k < m; k++) lsf[k] = (Word16)((k + 1) * 16384 / (m + 1) + random_range(-spread, spread));
    for (int k = 0; k < m; k++) {
        int low = (k ? lsf[k - 1] + 120 : 120);
        if (lsf[k] < low) lsf[k] = (Word16)low;
    }
    if (lsf[m - 1] > 16384 - 120) lsf[m - 1] = 16384 - 120;
}

static void random_stable(Word16 *x, int m)
{
    if (next_random() % 3 == 0) { for (int i = 0; i < m; i++) x[i] = random16(); return; }
    for (int i = 0; i < m; i++) x[i] = (Word16)(stable_ISP_fx[i] + random_range(-300, 300));
}

static Decoder_State_fx *new_state(int total_bits, Word32 brate)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    for (int i = 0; i < BUFFER_BITS; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    if (next_random() % 6 == 0) memset(bit_buffer, 0, sizeof(bit_buffer));
    st->bit_stream_fx = bit_buffer;
    st->total_num_bits = (Word16)total_bits;
    st->next_bit_pos_fx = (Word16)random_range(0, 20);
    st->codec_mode = MODE2;
    st->total_brate_fx = brate;
    return st;
}

static const Word32 mode2_rates[] = {9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};

static void case_a_isp(void)
{
    Word16 lsf[M], lsp[M], a[M + 1], isp[M], old_isp[M];
    random_lsf(lsf, M);
    E_LPC_lsf_lsp_conversion(lsf, lsp, M);
    E_LPC_f_lsp_a_conversion(lsp, a, M);
    int kind = next_random() % 8;
    if (kind == 0) for (int i = 0; i <= M; i++) a[i] = random16();
    if (kind == 1) for (int i = 0; i <= M; i++) a[i] = (Word16)(a[i] + random_range(-2000, 2000));
    if (kind == 2) a[M] = (Word16)random_range(-9000, 9000);
    random_stable(old_isp, M);
    for (int i = 0; i < M; i++) isp[i] = 4321;
    put16("a", a, M + 1); put16("old_isp", old_isp, M);
    E_LPC_a_isp_conversion(a, isp, old_isp, M);
    arrow(); put16("isp", isp, M); end_line();
}

static void case_isp_isf(void)
{
    Word16 isp[M], isf[M];
    Word16 m = (next_random() % 4) ? M : 10;
    for (int i = 0; i < M; i++) isp[i] = (Word16)(next_random() % 5 ? 32767 - (i * 4000 + random_range(0, 2000)) : random16());
    for (int i = 0; i < M; i++) isf[i] = 777;
    put16("isp", isp, M); put1("m", m);
    E_LPC_isp_isf_conversion(isp, isf, m);
    arrow(); put16("isf", isf, M); end_line();
}

static void case_lsp2isp(void)
{
    Word16 lsf[M], lsp[M], isp[M], stable[M];
    random_lsf(lsf, M);
    E_LPC_lsf_lsp_conversion(lsf, lsp, M);
    if (next_random() % 6 == 0) for (int i = 0; i < M; i++) lsp[i] = (Word16)(lsp[i] + random_range(-3000, 3000));
    random_stable(stable, M);
    for (int i = 0; i < M; i++) isp[i] = 4321;
    put16("lsp", lsp, M); put16("stable", stable, M);
    lsp2isp_fx(lsp, isp, stable, M);
    arrow(); put16("isp", isp, M); put16("stable", stable, M); end_line();
}

static void case_isp2lsp(void)
{
    Word16 lsf[M], lsp[M], isp[M], stable[M];
    random_lsf(lsf, M);
    E_LPC_lsf_lsp_conversion(lsf, isp, M);
    isp[M - 1] = (Word16)random_range(-20000, 20000);
    if (next_random() % 6 == 0) for (int i = 0; i < M; i++) isp[i] = (Word16)(isp[i] + random_range(-3000, 3000));
    random_stable(stable, M);
    for (int i = 0; i < M; i++) lsp[i] = 4321;
    put16("isp", isp, M); put16("stable", stable, M);
    isp2lsp_fx(isp, lsp, stable, M);
    arrow(); put16("lsp", lsp, M); put16("stable", stable, M); end_line();
}

static void case_lsf2isf(void)
{
    Word16 lsf[M], isf[M], stable[M];
    random_lsf(lsf, M);
    random_stable(stable, M);
    for (int i = 0; i < M; i++) isf[i] = 4321;
    put16("lsf", lsf, M); put16("stable", stable, M);
    lsf2isf_fx(lsf, isf, stable, M);
    arrow(); put16("isf", isf, M); put16("stable", stable, M); end_line();
}

static void case_isf2lsf(void)
{
    Word16 isf[M], lsf[M], stable[M];
    random_lsf(isf, M);
    isf[M - 1] = (Word16)random_range(3000, 8000);
    random_stable(stable, M);
    for (int i = 0; i < M; i++) lsf[i] = 4321;
    put16("isf", isf, M); put16("stable", stable, M);
    isf2lsf_fx(isf, lsf, stable);
    arrow(); put16("lsf", lsf, M); put16("stable", stable, M); end_line();
}

static void case_update_memory(void)
{
    Word16 qlsf[M], old_mem[M], mem[M];
    Word16 narrowband = (Word16)(next_random() & 1), order = (Word16)random_range(1, M);
    random_lsf(qlsf, M);
    for (int i = 0; i < M; i++) { old_mem[i] = (Word16)(next_random() & 1 ? random_range(-4000, 4000) : random_range(-32768, 32767)); mem[i] = 5555; }
    put1("narrowband", narrowband); put16("qlsf", qlsf, M); put16("old_mem", old_mem, M); put1("order", order);
    lsf_update_memory(narrowband, qlsf, old_mem, mem, order);
    arrow(); put16("mem", mem, M); end_line();
}

static void case_get_cdk(void)
{
    Word16 mode = (Word16)random_range(0, 5);
    put1("mode", mode);
    Word16 r = tcxlpc_get_cdk(mode);
    arrow(); put1("r", r); end_line();
}

/* Variants: 0 = TCX stages with dims/offs, 1 = the independent refinement stage, 2 = one full-size stage
 * without dims/offs, 3 = dims without offs. */
static void case_msvq(void)
{
    int variant = next_random() % 4;
    Word16 nb = (Word16)(next_random() & 1), cdk = (Word16)(next_random() & 1);
    Word16 idx[4] = {0, 0, 0, 0}, uq[M], stages;
    const Word16 *const *cb = lsf_codebook[nb][cdk];
    const Word16 *dims = lsf_dims, *offs = lsf_offs;
    for (int i = 0; i < M; i++) uq[i] = 999;
    if (variant == 0) { stages = TCXLPC_NUMSTAGES; for (int i = 0; i < 3; i++) idx[i] = (Word16)random_range(0, (1 << lsf_numbits[i]) - 1); }
    else if (variant == 1) { cb = lsf_ind_codebook[nb][cdk]; dims = lsf_ind_dims; offs = lsf_ind_offs; stages = TCXLPC_IND_NUMSTAGES; idx[0] = (Word16)random_range(0, 3); }
    else if (variant == 2) { stages = 1; dims = NULL; offs = NULL; idx[0] = (Word16)random_range(0, 31); }
    else { stages = 1; offs = NULL; idx[0] = (Word16)random_range(0, 31); }
    put1("variant", variant); put1("nb", nb); put1("cdk", cdk); put16("idx", idx, 4);
    msvq_dec(cb, dims, offs, stages, M, M, idx, uq);
    arrow(); put16("uq", uq, M); end_line();
}

static void case_midlsf(void)
{
    Word16 q0[M], q1[M], q[M];
    random_lsf(q0, M); random_lsf(q1, M);
    if (next_random() % 5 == 0) for (int i = 0; i < M; i++) q1[i] = (Word16)(q1[i] + random_range(-1500, 1500));
    Word16 idx = (Word16)random_range(0, 31), coder_type = (Word16)random_range(0, 3);
    Word16 mid = (Word16)(next_random() & 1), prev_bfi = (Word16)(next_random() % 3 == 0), safety_net = (Word16)(next_random() & 1);
    int decoder = next_random() % 4 != 0;
    for (int i = 0; i < M; i++) q[i] = 4321;
    put16("q0", q0, M); put16("q1", q1, M); put1("idx", idx); put1("coder_type", coder_type); put1("mid", mid);
    put1("prev_bfi", prev_bfi); put1("safety_net", safety_net); put1("decoder", decoder);
    midlsf_dec(q0, q1, idx, q, coder_type, decoder ? &mid : NULL, prev_bfi, safety_net);
    arrow(); put16("q", q, M); put1("mid", mid); end_line();
}

static void case_ind_active(void)
{
    Word16 q[M], nb = (Word16)(next_random() & 1), cdk = (Word16)(next_random() & 1);
    for (int i = 0; i < M; i++) q[i] = (Word16)random_range(-3000, 3000);
    put16("q", q, M); put1("nb", nb); put1("cdk", cdk);
    Word16 r = lsf_ind_is_active(q, lsf_means[nb], nb, cdk);
    arrow(); put1("r", r); end_line();
}

static void case_decprm(void)
{
    Word16 param[10];
    Word16 core = (Word16)(next_random() & 1), acelp_mode = (Word16)random_range(0, 3), mid_lpc = (Word16)(next_random() & 1);
    Word16 narrow = (Word16)(next_random() % 4 == 0);
    Word32 sr_core = (next_random() & 1) ? 12800 : 16000;
    if (sr_core == 16000 && acelp_mode == VOICED && core == 0) acelp_mode = GENERIC; /* BC-TCVQ territory */
    Decoder_State_fx *st = new_state(300, mode2_rates[next_random() % 9]);
    for (int i = 0; i < 10; i++) param[i] = 77;
    put1("core", core); put1("acelp_mode", acelp_mode); put1("mid_lpc", mid_lpc); put1("narrow", narrow);
    put1("sr_core", sr_core); put1("total_brate", st->total_brate_fx); put1("start", st->next_bit_pos_fx);
    put_u16("bits", bit_buffer, 96);
    Word16 r = lsf_msvq_ma_decprm(st, param, core, acelp_mode, mid_lpc, narrow, sr_core);
    arrow(); put1("r", r); put16("param", param, 10); put1("pos", st->next_bit_pos_fx); put1("ber", st->BER_detect); end_line();
    free(st);
}

static void case_bctcvq(void)
{
    Word16 param[12];
    Decoder_State_fx *st = new_state(300, 24400);
    if (next_random() % 5 == 0) st->total_num_bits = (Word16)random_range(30, 60);
    for (int i = 0; i < 12; i++) param[i] = 77;
    put1("start", st->next_bit_pos_fx); put1("total", st->total_num_bits); put_u16("bits", bit_buffer, 96);
    Word16 r = lsf_bctcvq_decprm(st, param);
    arrow(); put1("r", r); put16("param", param, 12); put1("pos", st->next_bit_pos_fx); put1("ber", st->BER_detect); end_line();
    free(st);
}

static void case_d_lsf_tcxlpc(void)
{
    Word16 indices[6], lsf_q[M], lsp[M], mem[M], nb = (Word16)(next_random() & 1), cdk = (Word16)(next_random() & 1);
    int with_lsp = next_random() % 4 != 0;
    indices[0] = (Word16)(next_random() & 1);
    for (int i = 0; i < 3; i++) indices[1 + i] = (Word16)random_range(0, (1 << lsf_numbits[i]) - 1);
    indices[4] = (Word16)random_range(0, 3); indices[5] = 0;
    for (int i = 0; i < M; i++) { mem[i] = (Word16)random_range(-3000, 3000); lsf_q[i] = 111; lsp[i] = 222; }
    put16("indices", indices, 5); put1("nb", nb); put1("cdk", cdk); put16("mem", mem, M); put1("with_lsp", with_lsp);
    Word16 r = D_lsf_tcxlpc(indices, lsf_q, with_lsp ? lsp : NULL, nb, cdk, mem);
    arrow(); put1("r", r); put16("lsf_q", lsf_q, M); put16("lsp", lsp, M); end_line();
}

static void case_dec_lsf_tcxlpc(void)
{
    Word16 storage[8], *indices = storage;
    Word16 nb = (Word16)(next_random() & 1), cdk = (Word16)(next_random() & 1);
    Decoder_State_fx *st = new_state(300, 9600);
    for (int i = 0; i < 8; i++) storage[i] = 77;
    put1("nb", nb); put1("cdk", cdk); put1("start", st->next_bit_pos_fx); put_u16("bits", bit_buffer, 96);
    Word16 r = dec_lsf_tcxlpc(st, &indices, nb, cdk);
    arrow(); put1("r", r); put16("storage", storage, 8); put1("advance", (long long)(indices - storage));
    put1("pos", st->next_bit_pos_fx); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    struct { const char *name; void (*run)(void); } table[] = {
        {"a_isp", case_a_isp}, {"isp_isf", case_isp_isf}, {"lsp2isp", case_lsp2isp}, {"isp2lsp", case_isp2lsp},
        {"lsf2isf", case_lsf2isf}, {"isf2lsf", case_isf2lsf}, {"update_memory", case_update_memory},
        {"get_cdk", case_get_cdk}, {"msvq", case_msvq}, {"midlsf", case_midlsf}, {"ind_active", case_ind_active},
        {"decprm", case_decprm}, {"bctcvq", case_bctcvq}, {"d_lsf_tcxlpc", case_d_lsf_tcxlpc},
        {"dec_lsf_tcxlpc", case_dec_lsf_tcxlpc},
    };
    void (*run)(void) = NULL;
    for (unsigned k = 0; k < sizeof(table) / sizeof(table[0]); k++) if (!strcmp(argv[2], table[k].name)) run = table[k].run;
    if (!run) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) run();
    return 0;
}
