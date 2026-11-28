/* Function-level oracle for lib_com/swb_bwe_com_lr_fx.c (updat_prev_frm_fx). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 lengths[] = {160, 320, 480, 640, 960};
static const Word32 rates[] = {9600, 13200, 16400, 24400, 32000};

static void case_updat_prev_frm(void)
{
    Word32 y2[L_FRAME48k], t_audio[L_FRAME48k];
    Word16 peak[SPT_SHORTEN_SBNUM], peak_tmp[SPT_SHORTEN_SBNUM];
    Word16 a = (Word16)(next_random() % 5), b = (Word16)(next_random() % 5);
    Word16 length = lengths[a < b ? a : b], inner = lengths[a < b ? b : a];
    Word32 rate = rates[next_random() % 5];
    Word16 bands = (Word16)random_range(14, 32), bwidth = (Word16)random_range(0, 3), transient = (Word16)(next_random() & 1);
    Word16 clas = (Word16)random_range(0, 3), prev_clas = random16(), hfe2 = random16(), stab = random16();
    Word16 bws = (Word16)((next_random() % 4) == 0);
    for (int i = 0; i < L_FRAME48k; i++) { y2[i] = random32(); t_audio[i] = random32(); }
    for (int i = 0; i < SPT_SHORTEN_SBNUM; i++) { peak[i] = random16(); peak_tmp[i] = random16(); }
    put32("y2", y2, L_FRAME48k); put32("t_audio", t_audio, L_FRAME48k); put16("peak", peak, SPT_SHORTEN_SBNUM);
    put16("peak_tmp", peak_tmp, SPT_SHORTEN_SBNUM); put1("rate", rate); put1("length", length); put1("inner", inner);
    put1("bands", bands); put1("bwidth", bwidth); put1("transient", transient); put1("clas", clas);
    put1("prev_clas", prev_clas); put1("hfe2", hfe2); put1("stab", stab); put1("bws", bws);
    updat_prev_frm_fx(y2, t_audio, rate, length, inner, bands, bwidth, transient, clas, &prev_clas, peak, peak_tmp,
                      &hfe2, &stab, bws);
    arrow(); put32("t_audio", t_audio, L_FRAME48k); put16("peak", peak, SPT_SHORTEN_SBNUM); put1("prev_clas", prev_clas);
    put1("hfe2", hfe2); put1("stab", stab); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "updat_prev_frm")) case_updat_prev_frm();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
