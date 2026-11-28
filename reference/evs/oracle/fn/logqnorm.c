/* Function-level oracle for lib_com/logqnorm_fx.c (logqnorm_fx). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_logqnorm(void)
{
    Word32 x[96];
    static const Word16 widths[] = {1, 8, 16, 24, 32, 48, 64, 96};
    Word16 n = widths[next_random() % 8];
    if (next_random() % 4 == 0) n = (Word16)random_range(1, 96);
    Word16 l = (Word16)(next_random() & 1 ? 40 : 32);
    Word16 qx = (Word16)(next_random() % 3 == 0 ? 12 : random_range(-4, 20));
    Word16 hvq = (Word16)(next_random() & 1);
    int mode = next_random() % 4, magnitude = random_range(0, 30);
    for (int i = 0; i < n; i++) {
        if (mode == 0) x[i] = random32();
        else if (mode == 1) x[i] = 0;
        else x[i] = L_shr((Word32)((next_random() << 16) ^ next_random()), (Word16)magnitude);
    }
    put32("x", x, n); put1("qx", qx); put1("l", l); put1("n", n); put1("hvq", hvq);
    Word16 k = -99;
    logqnorm_fx(x, qx, &k, l, n, hvq);
    arrow(); put1("k", k); end_line();
}

/* logqnorm_2_fx: thresholds are thren_fx (39 entries, L = 40) or a random descending table (L = 8..39) */
static void case_logqnorm_2(void)
{
    Word32 env[44], thren[39];
    Word16 ynrm[44], normqlg2[44];
    Word16 l = 40;
    Word16 n_env = (Word16)random_range(0, 30), nb = (Word16)(n_env + random_range(0, 14));
    if (next_random() % 3 == 0) {
        l = (Word16)random_range(8, 40);
        Word32 v = (Word32)(next_random() & 0x3fffffff);
        for (int i = 0; i < 39; i++) { thren[i] = v; v -= (Word32)(next_random() % 2000000); }
    } else memcpy(thren, thren_fx, sizeof thren);
    int n = nb - n_env;
    for (int i = 0; i < n; i++) {
        int mode = next_random() % 4;
        if (mode == 0) env[i] = thren[next_random() % (l - 1)] + random_range(-1, 1);
        else if (mode == 1) env[i] = random32();
        else env[i] = (Word32)(next_random() & 0x3fffffff) >> random_range(0, 24);
    }
    for (int i = 0; i < 44; i++) { ynrm[i] = -7; normqlg2[i] = -7; }
    put32("env", env, n); put1("l", l); put1("n_env", n_env); put1("nb", nb); put32("thren", thren, 39);
    logqnorm_2_fx(env, l, n_env, nb, ynrm, normqlg2, thren);
    arrow(); put16("ynrm", ynrm, n); put16("normqlg2", normqlg2, n); end_line();
}

static void case_calc_norm(void)
{
    Word32 x[960];
    Word16 norm[44], normlg[44];
    Word16 start = (Word16)random_range(0, 20), num = (Word16)random_range(1, 44 - start);
    Word16 qx = (Word16)(next_random() % 3 == 0 ? 12 : random_range(-2, 18));
    int mode = next_random() % 3, magnitude = random_range(0, 30);
    for (int i = 0; i < 960; i++) x[i] = mode == 0 ? random32() : L_shr((Word32)((next_random() << 16) ^ next_random()), (Word16)magnitude);
    for (int i = 0; i < 44; i++) { norm[i] = -7; normlg[i] = -7; }
    put32("x", x, 960); put1("qx", qx); put1("start", start); put1("num", num);
    calc_norm_fx(x, qx, norm, normlg, start, num, band_len_HQ, band_start_HQ);
    arrow(); put16("norm", norm, start + num); put16("normlg", normlg + start, num); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "logqnorm")) case_logqnorm();
        else if (!strcmp(argv[2], "logqnorm_2")) case_logqnorm_2();
        else if (!strcmp(argv[2], "calc_norm")) case_calc_norm();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
