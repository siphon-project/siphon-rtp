/* Function-level oracle for lib_com/lag_wind.c (lag_wind) and lib_com/interpol_fx.c (Interpol_lc_fx). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_lag_wind(void)
{
    static const struct { Word32 sr; int strengths; } rates[] = {
        {8000, 1}, {12800, 3}, {16000, 3}, {24000, 3}, {25600, 3}, {32000, 3}, {48000, 1}};
    int pick = random_range(0, 6);
    Word32 sr = rates[pick].sr;
    Word16 strength = (Word16)(rates[pick].strengths == 1 ? LAGW_STRONG : random_range(0, 2));
    Word16 m = (Word16)(next_random() % 3 ? 16 : random_range(1, 16));
    Word16 r_h[M + 1], r_l[M + 1];
    for (int i = 0; i <= M; i++) { r_h[i] = random16(); r_l[i] = (Word16)random_range(0, 32767); }
    put1("sr", sr); put1("strength", strength); put1("m", m); put16("r_h", r_h, M + 1); put16("r_l", r_l, M + 1);
    lag_wind(r_h, r_l, m, sr, strength);
    arrow(); put16("r_h", r_h, M + 1); put16("r_l", r_l, M + 1); end_line();
}

/* Interpol_lc_fx with the polyphase filters of the resampling table (up-sampling factor fac_num,
 * filt_len coefficients), at every fraction. */
static void case_interpol_lc(void)
{
    int count = 0;
    for (const Resampling_cfg_fx *c = &resampling_cfg_tbl_fx[0]; c->fin_fx != 0; c++) count++;
    int k = random_range(0, count - 1);
    const Resampling_cfg_fx *c = &resampling_cfg_tbl_fx[k];
    Word16 x[2 * 64 + 2], frac = (Word16)random_range(0, c->fac_num_fx - 1);
    /* the three trailing rows are the 4 kHz low-pass variants: their filter has only half the taps
     * (modify_Fs_fx halves the tap count there), so a full-length read runs past the table */
    Word16 nb_coef = (Word16)(k < count - 3 && next_random() % 4 ? c->filt_len_fx : (c->filt_len_fx + 1) / 2);
    int at = 64;
    int mag = next_random() % 3 == 0 ? 32767 : random_range(1, 8000);
    random_signal(x, 2 * 64 + 2, mag);
    put1("k", k); put1("frac", frac); put1("nb_coef", nb_coef); put16("x", x, 2 * 64 + 2);
    Word32 r = Interpol_lc_fx(x + at, c->filter_fx, frac, c->fac_num_fx, nb_coef);
    arrow(); put1("r", r); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "lag_wind")) case_lag_wind();
        else if (!strcmp(argv[2], "interpol_lc")) case_interpol_lc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
