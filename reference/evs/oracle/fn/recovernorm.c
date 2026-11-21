/* Function-level oracle for lib_com/recovernorm_fx.c. */
#include "harness.h"
#include "prot_fx.h"

static void case_recovernorm(void)
{
    static const Word16 counts[] = {NB_SFM, SFM_N_SWB, SFM_N_WB, 20};
    Word16 nb_sfm = counts[next_random() % 4];
    Word16 idxbuf[NB_SFM], ynrm[NB_SFM], normqlg2[NB_SFM];
    for (int i = 0; i < NB_SFM; i++) { idxbuf[i] = (Word16)random_range(0, 39); ynrm[i] = -3; normqlg2[i] = -4; }
    put1("nb_sfm", nb_sfm); put16("idxbuf", idxbuf, NB_SFM);
    recovernorm_fx(idxbuf, ynrm, normqlg2, nb_sfm);
    arrow(); put16("ynrm", ynrm, NB_SFM); put16("normqlg2", normqlg2, NB_SFM); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "recovernorm")) case_recovernorm();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
