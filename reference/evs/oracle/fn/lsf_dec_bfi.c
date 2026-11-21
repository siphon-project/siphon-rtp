/* Function-level oracle for lib_com/lsf_dec_bfi_fx.c: lsf_dec_bfi and PlcGetLsfBase.
 *
 * lsf_dec_bfi is driven over the decoder's concealment states: MODE1 (ACELP, AMR-WB IO) and
 * MODE2 (with and without the background-noise LSFs), every class of the last good frame and
 * coder type, the first to the tenth lost frame, both ACELP rates and the TCX-only frame lengths. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

/* An ordered LSF vector (Q(x2.56)) below top, now and then disordered or at the edges. */
static void random_lsf(Word16 *lsf, int top)
{
    int pos = 0;
    for (int i = 0; i < M; i++) {
        pos += random_range(20, 2 * top / M);
        if (pos >= top) pos = top - 1;
        lsf[i] = (Word16)pos;
    }
    if (next_random() % 8 == 0) for (int i = 0; i < M; i++) lsf[i] = (Word16)random_range(-100, top + 100);
    if (next_random() % 16 == 0) for (int i = 0; i < M; i++) lsf[i] = random16();
}

static void case_lsf_dec_bfi(void)
{
    static const Word16 l_frames_mode2[] = {L_FRAME, L_FRAME16k, 320, 512, 640, 200};
    Word16 codec_mode = (Word16)(next_random() % 3 ? MODE1 : MODE2);
    Word16 opt_amr_wb = 0, l_frame, tcxonly = 0, bwidth = (Word16)random_range(NB, FB);
    Word16 lsf[M], lsfold[M], mean[M], mem_ma[M], mem_ar[M], lsf_q_cng[M], lsf_cng[M], old_q_cng[M];
    Word16 have_q_cng = 0, have_cng = 0, plc_updated = 0;
    const Word16 *base = NULL;

    if (codec_mode == MODE1) {
        opt_amr_wb = (Word16)(next_random() % 4 == 0);
        l_frame = opt_amr_wb || (next_random() & 1) ? L_FRAME : L_FRAME16k;
    } else {
        l_frame = l_frames_mode2[next_random() % 6];
        tcxonly = (Word16)(next_random() & 1);
        plc_updated = (Word16)(next_random() & 1);
        have_q_cng = (Word16)(next_random() & 1);
        have_cng = (Word16)(next_random() & 1);
        base = PlcGetLsfBase((Word16)(next_random() & 1), (Word16)(next_random() & 1),
                             (Word32)(l_frame == L_FRAME ? 12800 : (next_random() & 1) ? 16000 : 25600));
    }
    int top = l_frame == L_FRAME ? 16384 : 20480;
    random_lsf(lsfold, top);
    random_lsf(mean, top);
    random_lsf(lsf_cng, top);
    random_lsf(old_q_cng, top);
    for (int i = 0; i < M; i++) {
        mem_ma[i] = (Word16)random_range(-2000, 2000);
        mem_ar[i] = (Word16)random_range(0, top);
        lsf[i] = -1;
        lsf_q_cng[i] = -1;
    }
    Word16 stab_fac = (Word16)(next_random() % 4 ? random_range(0, 32767) : random16());
    Word16 last_coder_type = (Word16)random_range(0, 7);
    Word16 last_good = (Word16)random_range(0, 7);
    Word16 nb_lost = (Word16)(next_random() % 4 ? random_range(1, 4) : random_range(1, 30));
    Word16 gsc_idx = (Word16)(next_random() & 1 ? 0 : random_range(1, 17));

    put1("codec_mode", codec_mode); put16("lsfold", lsfold, M); put16("lsf_adaptive_mean", mean, M);
    put1("have_base", base != NULL); if (base) put16("lsf_base", base, M);
    put16("mem_ma", mem_ma, M); put16("mem_ar", mem_ar, M); put1("stab_fac", stab_fac);
    put1("last_coder_type", last_coder_type); put1("l_frame", l_frame); put1("last_good", last_good);
    put1("nb_lost_cmpt", nb_lost); put1("plc_updated", plc_updated);
    put1("have_q_cng", have_q_cng); put1("have_cng", have_cng);
    put16("lsf_cng", lsf_cng, M); put16("old_lsf_q_cng", old_q_cng, M);
    put1("gsc_idx", gsc_idx); put1("opt_amr_wb", opt_amr_wb); put1("tcxonly", tcxonly); put1("bwidth", bwidth);
    lsf_dec_bfi(codec_mode, lsf, lsfold, mean, base, mem_ma, mem_ar, stab_fac, last_coder_type, l_frame,
                last_good, nb_lost, (Word8)plc_updated, have_q_cng ? lsf_q_cng : NULL, have_cng ? lsf_cng : NULL,
                have_q_cng ? old_q_cng : NULL, gsc_idx, opt_amr_wb, (Word8)tcxonly, bwidth);
    arrow(); put16("lsf", lsf, M); put16("mem_ma", mem_ma, M); put16("mem_ar", mem_ar, M);
    put16("lsf_q_cng", lsf_q_cng, M); end_line();
}

static void case_plc_get_lsf_base(void)
{
    static const Word32 rates[] = {12800, 16000, 25600, 32000, 8000};
    Word16 q = (Word16)(next_random() & 1), nb = (Word16)(next_random() & 1);
    Word32 sr = rates[next_random() % 5];
    put1("lpc_quantization", q); put1("narrow_band", nb); put1("sr_core", sr);
    const Word16 *base = PlcGetLsfBase(q, nb, sr);
    arrow(); put16("base", base, M); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lsf_dec_bfi")) case_lsf_dec_bfi();
        else if (!strcmp(argv[2], "plc_get_lsf_base")) case_plc_get_lsf_base();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
