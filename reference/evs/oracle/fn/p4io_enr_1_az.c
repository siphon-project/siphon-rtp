/* Oracle for Enr_1_Az_fx (lib_com/enr_1_az_fx.c) including the STL Overflow flag it leaves behind, which
 * improv_amr_wb_gs_fx reads. */
#include "harness.h"
#include "prot_fx.h"

static void random_lpc(Word16 *a, int m)
{
    int kind = next_random() % 8;
    a[0] = 4096;
    if (kind == 6) a[0] = (Word16)(next_random() & 1 ? 8192 : 2048);
    if (kind == 7) a[0] = random16();
    for (int k = 1; k <= m; k++) {
        if (kind == 5 || kind == 7) a[k] = random16();
        else if (kind == 4) a[k] = (Word16)(next_random() & 1 ? 32767 : -32768);
        else {
            /* taps of a log-uniform size: from a filter that rings little to one that saturates its energy sum */
            int size = 1 << ((kind * 7 + 3) % 8 + 7);
            if (k == 1) size = 1 << random_range(8, 13);
            a[k] = (Word16)random_range(-size / k - 40, size / k + 40);
        }
    }
}

static void case_enr_1_az(void)
{
    Word16 a[17];
    static const Word16 lengths[] = {64, 128, 64, 128, 2, 17};
    Word16 len = lengths[next_random() % 6];
    random_lpc(a, 16);
    put16("aq", a, 17); put1("len", len);
    Overflow = 0;
    Word16 enr = Enr_1_Az_fx(a, len);
    arrow(); put1("enr", enr); put1("overflow", Overflow); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "enr_1_az")) case_enr_1_az();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
