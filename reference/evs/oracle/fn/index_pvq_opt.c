/* Function-level oracle for lib_com/index_pvq_opt_fx.c (MPVQ sizes, offsets and index decoding). */
#include "harness.h"
#include "../../c-code/lib_com/index_pvq_opt_fx.c"

#define H_LEN (1 + 512 + 1)

/* dim and pulses as pvq_decode_fx sees them: dimensions above five keep to KMAX_NON_DIRECT_FX
 * pulses (its h_mem holds 98 entries) and at least one (k = 0 reads h[-1]); a few cases take
 * the k > TABLE_LIM_OPT_FX branch, which only the size and offset path can reach. */
static void random_shape(Word16 *dim, Word16 *k)
{
    *dim = (Word16)(next_random() % 3 == 0 ? random_range(1, 5) : random_range(6, 48));
    if (*dim <= N_OPT_FX) *k = (Word16)(next_random() & 1 ? random_range(0, 40) : random_range(0, 512));
    else *k = (Word16)(next_random() % 20 == 0 ? random_range(97, 200) : random_range(1, 96));
}

static void case_size(void)
{
    static UWord32 h[H_LEN];
    Word16 dim, k;
    random_shape(&dim, &k);
    memset(h, 0, sizeof(h));
    PvqEntry_fx entry = get_size_mpvq_calc_offset_fx(dim, k, h);
    put1("dim", dim); put1("k", k);
    arrow(); put1("size", (long long)entry.size); put1("e_dim", entry.dim); put1("e_k", entry.k_val);
    printf(" h="); for (int i = 0; i < (dim > N_OPT_FX ? k + 2 : 1); i++) printf(i ? ",%u" : "%u", h[i]);
    end_line();
}

static void case_decode(void)
{
    static UWord32 h[H_LEN];
    Word16 dim, k, vec[64];
    do random_shape(&dim, &k); while (dim > N_OPT_FX && k > KMAX_NON_DIRECT_FX);
    memset(h, 0, sizeof(h));
    PvqEntry_fx entry = get_size_mpvq_calc_offset_fx(dim, k, h);
    UWord32 r = ((UWord32)next_random() << 16) ^ next_random();
    entry.index = entry.size ? (next_random() % 8 == 0 ? entry.size - 1 - (r % 3 < entry.size ? r % 3 : 0) : r % entry.size) : 0;
    if (next_random() % 8 == 0) entry.index = 0;
    entry.lead_sign_ind = (Word16)(next_random() & 1);
    for (int i = 0; i < 64; i++) vec[i] = 7;
    put1("dim", dim); put1("k", k); put1("index", (long long)entry.index); put1("lead_sign_ind", entry.lead_sign_ind);
    mpvq_decode_vec_fx(&entry, h, vec);
    arrow(); put16("vec", vec, dim);
    printf(" h="); for (int i = 0; i < (dim > N_OPT_FX ? k + 2 : 1); i++) printf(i ? ",%u" : "%u", h[i]);
    end_line();
}

static void case_sqrt(void)
{
    Word32 val = next_random() & 1 ? random_range(1, 4 * 512 * 512) : random_range(1, 1 << 30);
    put1("val", val); arrow(); put1("root", getSqrtWord32(val)); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "size")) case_size();
        else if (!strcmp(argv[2], "decode")) case_decode();
        else if (!strcmp(argv[2], "sqrt")) case_sqrt();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
