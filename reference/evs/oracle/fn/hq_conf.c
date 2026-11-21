/* Function-level oracle for lib_com/hq_conf_fx.c (hq_configure_fx): every frame length (including the
 * WB fall-through), HQ class 0..5 and the rates the decoder uses (and some it does not), with the
 * outputs preset to a sentinel so the cases where the reference leaves one unset are visible. The
 * band tables are reported as an id: 0 = untouched, 1 = HQ, 2 = harmonic, 3 = WB. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static int table_id(const Word16 *sfmsize)
{
    if (sfmsize == band_len_HQ) return 1;
    if (sfmsize == band_len_harm) return 2;
    if (sfmsize == band_len_wb) return 3;
    return -1;
}

static void case_hq_configure(void)
{
    static const Word32 rates[] = {HQ_13k20, HQ_16k40, HQ_24k40, HQ_32k, HQ_48k, HQ_64k, HQ_96k, HQ_128k};
    static const Word16 lengths[] = {L_FRAME16k, L_FRAME32k, L_FRAME48k, L_FRAME8k};
    Word16 length = lengths[next_random() % 4], clas = (Word16)(next_random() % 6);
    Word32 brate = rates[next_random() % 8];
    Word16 num_sfm = -7, nb_sfm = -7, start_norm = -7, num_env_bands = -7, numnrmibits = -7, offset = -7;
    const Word16 *sfmsize = NULL, *sfm_start = NULL, *sfm_end = NULL;
    put1("length", length); put1("clas", clas); put1("brate", brate);
    hq_configure_fx(length, clas, brate, &num_sfm, &nb_sfm, &start_norm, &num_env_bands, &numnrmibits, &offset,
                    &sfmsize, &sfm_start, &sfm_end);
    arrow();
    put1("num_sfm", num_sfm); put1("nb_sfm", nb_sfm); put1("start_norm", start_norm);
    put1("num_env_bands", num_env_bands); put1("numnrmibits", numnrmibits); put1("offset", offset);
    put1("sfmsize", table_id(sfmsize));
    put1("sfm_start", sfm_start == band_start_HQ ? 1 : sfm_start == band_start_harm ? 2 : sfm_start == band_start_wb ? 3 : -1);
    put1("sfm_end", sfm_end == band_end_HQ ? 1 : sfm_end == band_end_harm ? 2 : sfm_end == band_end_wb ? 3 : -1);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq_configure")) case_hq_configure();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
