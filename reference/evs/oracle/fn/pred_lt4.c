/* Function-level oracle for lib_com/pred_lt4_fx.c. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define HIST 320 /* > the longest lag plus the window half-length */
#define LEN (HIST + 2 * L_SUBFR + 40)

/* The decoder always calls pred_lt4 in place (excI == excO); so does this oracle. */
static void case_pred_lt4(void)
{
    Word16 exc[LEN];
    Word16 six = (Word16)(next_random() & 1);
    Word16 up = six ? PIT_UP_SAMP6 : PIT_UP_SAMP, nb = six ? PIT_L_INTERPOL6_2 : L_INTERPOL2;
    const Word16 *win = six ? pitch_inter6_2 : pitch_inter4_2;
    Word16 lsub = (next_random() % 4 == 0) ? L_SUBFR : L_SUBFR + 1;
    Word16 t0 = (Word16)((next_random() & 3) == 0 ? random_range(nb + 1, 70) : random_range(34, 289));
    Word16 frac = (Word16)random_range(0, up - 1);
    random_signal(exc, LEN, (next_random() & 3) ? 32767 : random_range(1, 3000));
    if ((next_random() & 7) == 0) for (int i = 0; i < LEN; i++) exc[i] = random16();
    put16("exc", exc, LEN); put1("t0", t0); put1("frac", frac); put1("lsub", lsub); put1("six", six);
    pred_lt4(&exc[HIST], &exc[HIST], t0, frac, lsub, win, nb, up);
    arrow(); put16("exc", exc, LEN); end_line();
}

#define TC_LEN (L_SUBFR + L_FRAME + L_SUBFR)
static void case_pred_lt4_tc(void)
{
    Word16 exc[TC_LEN];
    Word16 t0 = (Word16)random_range(17, 100), frac = (Word16)random_range(0, 3);
    Word16 imp_pos = (Word16)random_range(0, 63), i_subfr = (Word16)(L_SUBFR * random_range(0, 3));
    random_signal(exc, TC_LEN, (next_random() & 3) ? 32767 : random_range(1, 3000));
    put16("exc", exc, TC_LEN); put1("t0", t0); put1("frac", frac); put1("imp_pos", imp_pos); put1("i_subfr", i_subfr);
    pred_lt4_tc_fx(&exc[L_SUBFR], t0, frac, inter4_2_fx, imp_pos, i_subfr);
    arrow(); put16("exc", exc, TC_LEN); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "pred_lt4")) case_pred_lt4();
        else if (!strcmp(argv[2], "pred_lt4_tc")) case_pred_lt4_tc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
