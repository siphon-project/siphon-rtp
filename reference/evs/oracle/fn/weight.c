/* Function-level oracle for lib_com/weight_fx.c: map_quant_weight_fx (sfm2mqb_fx and mqb2sfm_fx are static and
 * reached through it) on the 44-band norms of a 48 kHz frame, transient or not. */
#include "hq_bit_allocation_inputs.h"

static void case_map_quant_weight(void)
{
    Word16 normqlg2[NB_SFM], wnorm[NB_SFM];
    Word16 is_transient = (Word16)(next_random() % 3 == 0);
    random_norms(normqlg2, NB_SFM);
    for (int i = 0; i < NB_SFM; i++) wnorm[i] = -7;
    put16("normqlg2", normqlg2, NB_SFM); put1("is_transient", is_transient);
    map_quant_weight_fx(normqlg2, wnorm, is_transient);
    arrow(); put16("wnorm", wnorm, NB_SFM); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "map_quant_weight")) case_map_quant_weight();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
