/* Function-level oracle for lib_com/stab_est_fx.c (stab_est_fx). */
#include "harness.h"
#include "prot_fx.h"

static void case_stab_est(void)
{
    Word16 lt[40], thresh[4];
    int spread = (int[]){50, 400, 2000, 8000, 32767}[next_random() % 5];
    for (int i = 0; i < 40; i++) lt[i] = (Word16)random_range(-spread, spread);
    if (next_random() % 8 == 0) for (int i = 0; i < 40; i++) lt[i] = random16();
    Word16 etot = (Word16)(next_random() % 6 ? random_range(-2000, 25000) : random16());
    Word16 mem_etot = (Word16)(next_random() % 6 ? random_range(-2000, 25000) : random16());
    Word16 nb_thr_3 = (Word16)random_range(0, 40), nb_thr_1 = (Word16)random_range(0, 40);
    if (next_random() % 16 == 0) nb_thr_3 = 32767;
    thresh[0] = (Word16)random_range(3000, 10000);
    thresh[1] = (Word16)random_range(2000, 9000);
    thresh[2] = (Word16)random_range(1500, 7000);
    thresh[3] = (Word16)random_range(1000, 6000);
    Word16 last = (Word16)random_range(0, 4), vad = (Word16)(next_random() % 4 != 0);
    put1("etot", etot); put16("lt_diff_etot", lt, 40); put1("mem_etot", mem_etot);
    put1("nb_thr_3", nb_thr_3); put1("nb_thr_1", nb_thr_1); put16("thresh", thresh, 4);
    put1("last_music_flag", last); put1("vad_flag", vad);
    Word16 flag = stab_est_fx(etot, lt, &mem_etot, &nb_thr_3, &nb_thr_1, thresh, &last, vad);
    arrow(); put1("flag", flag); put16("lt_diff_etot", lt, 40); put1("mem_etot", mem_etot);
    put1("nb_thr_3", nb_thr_3); put1("nb_thr_1", nb_thr_1); put16("thresh", thresh, 4);
    put1("last_music_flag", last); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "stab_est")) case_stab_est();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
