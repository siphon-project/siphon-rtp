/* Function-level oracle for lib_dec/FEC_lsf_estim_fx.c: FEC_lsf2lsp_interp, on the concealed LSFs
 * lsf_dec_bfi produces (ordered, at 12.8 and 16 kHz, LSF and AMR-WB IO ISF) and an arbitrary past
 * LSP vector. It reads Opt_AMR_WB_fx and lsp_old_fx from the state and writes nothing there. */
#include "harness.h"
#include "prot_fx.h"

static void random_lsf(Word16 *lsf, int top)
{
    int pos = 0;
    for (int i = 0; i < M; i++) {
        pos += random_range(20, 2 * top / M);
        if (pos >= top) pos = top - 1;
        lsf[i] = (Word16)pos;
    }
}

static void random_lsp(Word16 *lsp)
{
    int value = 32767 - random_range(50, 2500);
    for (int i = 0; i < M; i++) {
        lsp[i] = (Word16)value;
        value -= random_range(300, 65000 / M);
        if (value < -32767) value = -32767 + random_range(0, 10);
    }
    if (next_random() % 8 == 0) for (int i = 0; i < M; i++) lsp[i] = random16();
}

static void case_fec_lsf2lsp_interp(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 lsf[M], lsp[M], aq[NB_SUBFR16k * (M + 1)];
    st->Opt_AMR_WB_fx = (Word16)(next_random() % 3 == 0);
    Word16 l_frame = (Word16)(st->Opt_AMR_WB_fx || (next_random() & 1) ? L_FRAME : L_FRAME16k);
    if (next_random() % 8 == 0) l_frame = (Word16)(L_FRAME + L_FRAME16k - l_frame);
    random_lsf(lsf, l_frame == L_FRAME ? 16384 : 20480);
    random_lsp(st->lsp_old_fx);
    for (int i = 0; i < NB_SUBFR16k * (M + 1); i++) aq[i] = -5;
    put1("opt_amr_wb", st->Opt_AMR_WB_fx); put1("l_frame", l_frame); put16("lsf", lsf, M);
    put16("lsp_old", st->lsp_old_fx, M);
    FEC_lsf2lsp_interp(st, l_frame, aq, lsf, lsp);
    arrow(); put16("aq", aq, NB_SUBFR16k * (M + 1)); put16("lsp", lsp, M); end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    if (strcmp(argv[2], "fec_lsf2lsp_interp")) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) case_fec_lsf2lsp_interp();
    return 0;
}
