/* Function-level oracle for lib_com/mslvq_com_fx.c (MSLVQ table init and LSF index decoding). */
#include "harness.h"
#include "../../c-code/lib_com/mslvq_com_fx.c"

static Word32 offset_scale1[MAX_NO_MODES + 1][MAX_NO_SCALES + 1], offset_scale2[MAX_NO_MODES + 1][MAX_NO_SCALES + 1];
static Word32 offset_scale1_p[MAX_NO_MODES_p + 1][MAX_NO_SCALES + 1], offset_scale2_p[MAX_NO_MODES_p + 1][MAX_NO_SCALES + 1];
static Word16 no_scales[MAX_NO_MODES][2], no_scales_p[MAX_NO_MODES_p][2];

static void case_init_lvq(void)
{
    init_lvq_fx(offset_scale1, offset_scale2, offset_scale1_p, offset_scale2_p, no_scales, no_scales_p);
    put1("call", 1); arrow();
    put32("offset_scale1", &offset_scale1[0][0], (MAX_NO_MODES + 1) * (MAX_NO_SCALES + 1));
    put32("offset_scale2", &offset_scale2[0][0], (MAX_NO_MODES + 1) * (MAX_NO_SCALES + 1));
    put32("offset_scale1_p", &offset_scale1_p[0][0], (MAX_NO_MODES_p + 1) * (MAX_NO_SCALES + 1));
    put32("offset_scale2_p", &offset_scale2_p[0][0], (MAX_NO_MODES_p + 1) * (MAX_NO_SCALES + 1));
    put16("no_scales", &no_scales[0][0], MAX_NO_MODES * 2);
    put16("no_scales_p", &no_scales_p[0][0], MAX_NO_MODES_p * 2);
    end_line();
}

static void case_deindex_lvq(void)
{
    Word16 index[3], x_lvq[2 * LATTICE_DIM], sf_flag, mode, no_bits, ber;
    init_lvq_fx(offset_scale1, offset_scale2, offset_scale1_p, offset_scale2_p, no_scales, no_scales_p);
    do {
        sf_flag = (Word16)(next_random() & 1);
        mode = (Word16)(sf_flag ? random_range(0, 17) : random_range(0, 18));
    } while ((sf_flag ? min_lat_bits_SN_fx[mode] : min_lat_bits_pred_fx[mode]) < 0);
    no_bits = (Word16)((sf_flag ? min_lat_bits_SN_fx[mode] : min_lat_bits_pred_fx[mode]) + random_range(0, sf_flag ? 20 : 31));
    /* A random no_bits-bit index, split into 15-bit words; a quarter of them small, where the
     * zero-index and low-truncation branches live. */
    for (int i = 0; i < 3; i++) {
        int bits = no_bits - 15 * i;
        bits = bits > 15 ? 15 : bits < 0 ? 0 : bits;
        index[i] = (Word16)(bits ? next_random() & ((1u << bits) - 1) : 0);
    }
    if (next_random() % 4 == 0) { index[1] = 0; index[2] = 0; index[0] = (Word16)random_range(0, 300); }
    if (next_random() % 50 == 0) index[random_range(0, 2)] = -1;
    for (int i = 0; i < 2 * LATTICE_DIM; i++) x_lvq[i] = random16();
    put16("index", index, 3); put1("mode", mode); put1("sf_flag", sf_flag); put1("no_bits", no_bits);
    if (sf_flag) ber = deindex_lvq_fx(index, x_lvq, mode, sf_flag, no_bits, &offset_scale1[0][0], &offset_scale2[0][0], &no_scales[0][0]);
    else ber = deindex_lvq_fx(index, x_lvq, mode, sf_flag, no_bits, &offset_scale1_p[0][0], &offset_scale2_p[0][0], &no_scales_p[0][0]);
    arrow(); put1("ber", ber); put16("x_lvq", x_lvq, 2 * LATTICE_DIM); put16("index", index, 3); end_line();
}

/* deindex_lvq_cng_fx as dqlsf_CNG_fx calls it: a 4-bit first-stage index and a 25-bit lattice
 * index read as 15 + 10 bits (index[2] unused), sometimes small or corrupt (-1). */
static void case_deindex_lvq_cng(void)
{
    Word16 index[3], x_lvq[2 * LATTICE_DIM], idx_cv = (Word16)random_range(0, 15), ber;
    init_lvq_fx(offset_scale1, offset_scale2, offset_scale1_p, offset_scale2_p, no_scales, no_scales_p);
    index[0] = (Word16)(next_random() & 0x7fff);
    index[1] = (Word16)(next_random() & 0x3ff);
    index[2] = (Word16)random16();
    if (next_random() % 4 == 0) { index[1] = 0; index[0] = (Word16)random_range(0, 300); }
    if (next_random() % 8 == 0) { index[0] = 0; }
    if (next_random() % 50 == 0) index[random_range(0, 1)] = -1;
    for (int i = 0; i < 2 * LATTICE_DIM; i++) x_lvq[i] = random16();
    put16("index", index, 3); put1("idx_cv", idx_cv);
    ber = deindex_lvq_cng_fx(index, x_lvq, idx_cv, LSF_BITS_CNG - 4, &offset_scale1[0][0], &offset_scale2[0][0], &no_scales[0][0]);
    arrow(); put1("ber", ber); put16("x_lvq", x_lvq, 2 * LATTICE_DIM); put16("index", index, 3); end_line();
}

static void case_divide(void)
{
    Word32 y = random32() & 0x7fffffff, x = (Word32)random_range(1, 0x7fffffff), rem, q, rem64, q64;
    Word16 y16 = (Word16)random_range(0, 32767), x16 = (Word16)random_range(1, 32767), rem16, q16;
    Word16 xs[3] = {(Word16)random_range(0, 32767), (Word16)random_range(0, 32767), (Word16)random_range(0, 32767)};
    Word32 x64 = (Word32)random_range(1 << 15, 0x7fffffff);
    if (next_random() & 1) x = (Word32)random_range(1, 5000);
    if (next_random() & 1) x16 = (Word16)random_range(1, 100);
    put1("y", y); put1("x", x); put1("y16", y16); put1("x16", x16); put16("xs", xs, 3); put1("x64", x64);
    q = divide_32_32_fx(y, x, &rem);
    q16 = divide_16_16_fx(y16, x16, &rem16);
    divide_64_32_fx(xs, x64, &q64, &rem64);
    arrow(); put1("q", q); put1("rem", rem); put1("q16", q16); put1("rem16", rem16); put1("q64", q64); put1("rem64", rem64);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "init_lvq")) case_init_lvq();
        else if (!strcmp(argv[2], "deindex_lvq")) case_deindex_lvq();
        else if (!strcmp(argv[2], "divide")) case_divide();
        else if (!strcmp(argv[2], "deindex_lvq_cng")) case_deindex_lvq_cng();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
