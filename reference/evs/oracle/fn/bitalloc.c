/* Function-level oracle for lib_com/bitalloc_fx.c: bitalloc_fx, BitAllocF_fx and BitAllocWB_fx (Bit_group_fx is
 * static and reached through BitAllocWB_fx), on the inputs hq_bit_allocation_fx gives them. The file is included so
 * a coverage build measures it. */
#include "hq_bit_allocation_inputs.h"
#include "../../c-code/lib_com/bitalloc_fx.c"

static void case_bitalloc(void)
{
    HqAllocInput c;
    Word16 y[NB_SFM], idx[NB_SFM], r[NB_SFM];
    RANDOM_INPUT_WHERE(&c, c.hqswb_clas != HQ_HVQ);
    random_norms(y, c.nb_sfm);
    if (next_random() % 4 == 0) for (int i = 0; i < c.nb_sfm; i++) y[i] = c.normqlg2[i];
    for (int i = 0; i < c.nb_sfm; i++) idx[i] = (Word16)i;
    reordvct_fx(y, c.nb_sfm, idx);
    for (int i = 0; i < NB_SFM; i++) r[i] = 0;
    Word16 k = next_random() % 6 ? QBIT_MAX2 : (Word16)random_range(3, 12);
    put16("y", y, c.nb_sfm); put16("idx", idx, c.nb_sfm); put1("sum", c.num_bits); put1("n", c.nb_sfm); put1("k", k);
    put16("sfmsize", c.sfmsize, c.nb_sfm); put1("hqswb_clas", c.hqswb_clas);
    int ok = GUARDED(bitalloc_fx(y, idx, c.num_bits, c.nb_sfm, k, r, c.sfmsize, c.hqswb_clas));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put16("y", y, c.nb_sfm); put16("r", r, NB_SFM); end_line();
}

static void case_bit_alloc_f(void)
{
    HqAllocInput c;
    Word16 y[NB_SFM], r[NB_SFM], rsubband[NB_SFM];
    RANDOM_INPUT_WHERE(&c, c.length >= L_FRAME32k && (c.hqswb_clas == HQ_GEN_SWB || c.hqswb_clas == HQ_GEN_FB ||
                                                      c.hqswb_clas == HQ_TRANSIENT));
    random_norms(y, c.nb_sfm);
    if (next_random() % 3 == 0) for (int i = 0; i < c.nb_sfm; i++) y[i] = c.normqlg2[i];
    for (int i = 0; i < NB_SFM; i++) { r[i] = -7; rsubband[i] = -7; }
    Word32 rate = next_random() % 3 ? c.core_brate : (next_random() & 1 ? HQ_24k40 : HQ_32k);
    put16("y", y, c.nb_sfm); put1("bit_rate", rate); put1("b", c.num_bits); put1("n", c.nb_sfm);
    put1("hqswb_clas", c.hqswb_clas); put1("num_env_bands", c.num_env_bands);
    Word16 used = -7;
    int ok = GUARDED(used = BitAllocF_fx(y, rate, c.num_bits, c.nb_sfm, r, rsubband, c.hqswb_clas, c.num_env_bands));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("used", used); put16("r", r, c.nb_sfm); put16("rsubband", rsubband, c.nb_sfm); end_line();
}

/* Norms flat per group (bands 0..15, 16..23, 24..N-1), with the group means a few steps apart so that the group
 * averages sit on the thresholds BitAllocWB_fx tests (6, 3.75 and 12 in Q16 steps); one band may differ by one. */
static void flat_group_norms(Word16 *y, int n)
{
    int a = random_range(0, 34), b, c;
    static const int d01[] = {5, 6, 7, 11, 12, 13}, d12[] = {3, 4, 0, 5};
    b = a - d01[next_random() % 6];
    c = b - d12[next_random() % 4];
    if (next_random() % 3 == 0) c = random_range(10, 14);
    if (next_random() % 5 == 0) { a = random_range(-5, 34); b = random_range(-5, 34); c = random_range(-5, 34); }
    int v[3] = {a, b, c};
    for (int k = 0; k < 3; k++) { if (v[k] > 34) v[k] = 34; if (v[k] < -5) v[k] = -5; }
    for (int i = 0; i < n; i++) y[i] = (Word16)v[i < SFM_G1 ? 0 : i < SFM_G1G2 ? 1 : 2];
    if (next_random() % 2) y[random_range(0, n - 1)] += (Word16)random_range(-1, 1);
}

/* Does BitAllocWB_fx round the second group's share up on the large-difference path (the +1 after
 * "L_add(L_tmp1, 2)")? The same arithmetic as the reference, for group sums r0, r1, r2 (26 bands). */
static int rounds_second_share_up(Word16 r0, Word16 r1, Word16 r2, Word16 B)
{
    Word16 rsum = add(add(r0, r1), r2), exp = norm_s(rsum), tmp = div_s(16384, shl(rsum, exp));
    Word32 l1 = Mult_32_16(1975684956, shl(B, 5));
    l1 = Mult_32_16(l1, shl(r1, 7));
    Word16 b2 = extract_h(L_shl(Mult_32_16(l1, tmp), sub(exp, 11)));
    return L_sub(l1, L_shl(L_mult(b2, rsum), 12)) > 0 && L_sub(L_add(l1, 2), L_shl(L_mult(add(b2, 1), rsum), 12)) >= 0;
}

static void case_bit_alloc_wb(void)
{
    HqAllocInput c;
    Word16 y[NB_SFM], r[NB_SFM], rsubband[NB_SFM];
    RANDOM_INPUT_WHERE(&c, c.length == L_FRAME16k);
    int flat = next_random() % 2;
    if (flat) flat_group_norms(y, c.nb_sfm); else random_norms(y, c.nb_sfm);
    if (next_random() % 3 == 0) {
        /* the decoder lifts the four lowest bands to the average of bands 10..17 first */
        Word16 avrg = y[10];
        for (int i = 11; i < 18; i++) avrg = add(avrg, y[i]);
        avrg = shr(avrg, 3);
        for (int i = 0; i < 4; i++) if (y[i] < avrg) y[i] = avrg;
    }
    for (int i = 0; i < NB_SFM; i++) { r[i] = -7; rsubband[i] = -7; }
    Word16 b = (Word16)(next_random() % 8 ? random_range(100, 640) : random_range(0, 900));
    if (next_random() % 4 == 0) b = (Word16)random_range(0, 70); /* a small last group */
    if (flat && next_random() % 2) {
        /* land a group's share exactly on its cap (288, 256, 96) */
        Word16 g0 = 0, g1 = 0, g2 = 0;
        for (int i = 0; i < SFM_G1; i++) if (y[i] > 0) g0 += y[i];
        for (int i = SFM_G1; i < SFM_G1G2; i++) if (y[i] > 0) g1 += y[i];
        for (int i = SFM_G1G2; i < c.nb_sfm; i++) if (y[i] > 0) g2 += y[i];
        int total = g0 + g1 + g2, pick = next_random() % 3;
        int cap = pick == 0 ? 288 : pick == 1 ? 256 : 96, g = pick == 0 ? g0 : pick == 1 ? g1 : g2;
        /* only a budget the decoder can pass (0..900, as above): a small group under a large total
         * would otherwise wrap Word16 negative, where the reference faults on one build and returns
         * on another */
        int landed = g > 0 ? (cap * total + g - 1) / g + random_range(-1, 1) : -1;
        if (landed >= 0 && landed <= 900) b = (Word16)landed;
    }
    if (flat && c.nb_sfm == 26 && next_random() % 2) {
        /* a budget on which that rounding fires, on the large-difference path (flat groups: sums 16a, 8b, 2c) */
        Word16 r0 = 0, r1 = 0, r2 = 0;
        for (int i = 0; i < SFM_G1; i++) if (y[i] > 0) r0 += y[i];
        for (int i = SFM_G1; i < SFM_G1G2; i++) if (y[i] > 0) r1 += y[i];
        for (int i = SFM_G1G2; i < 26; i++) if (y[i] > 0) r2 += y[i];
        if (r0 + r1 + r2 > 0) {
            int start = random_range(0, 900);
            for (int t = 0; t < 901; t++) {
                Word16 cand = (Word16)((start + t) % 901);
                if (rounds_second_share_up(r0, r1, r2, cand)) { b = cand; break; }
            }
        }
    }
    put16("y", y, c.nb_sfm); put1("b", b); put1("n", c.nb_sfm);
    Word16 used = -7;
    int ok = GUARDED(used = BitAllocWB_fx(y, b, c.nb_sfm, r, rsubband));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("used", used); put16("r", r, c.nb_sfm); put16("rsubband", rsubband, c.nb_sfm); end_line();
}


/* Wide-input stress modes: the same call as the corpus modes above, on bit budgets from nothing to the whole
 * frame (the corpus mostly gives the allocation a full budget), a shorter band count, and, for BitAllocF_fx,
 * a budget solved so that one band's initial share is exactly zero. */
static Word16 wide_budget(const HqAllocInput *c, int limit)
{
    switch (next_random() % 4) {
    case 0: return (Word16)random_range(0, 64);
    case 1: return (Word16)random_range(0, 300);
    case 2: return (Word16)random_range(0, limit);
    default: return c->num_bits;
    }
}

static void case_bitalloc_wide(void)
{
    HqAllocInput c;
    Word16 y[NB_SFM], idx[NB_SFM], r[NB_SFM];
    RANDOM_INPUT_WHERE(&c, c.hqswb_clas != HQ_HVQ);
    random_norms(y, c.nb_sfm);
    if (next_random() % 4 == 0) for (int i = 0; i < c.nb_sfm; i++) y[i] = c.normqlg2[i];
    Word16 n = next_random() % 4 ? c.nb_sfm : (Word16)random_range(2, c.nb_sfm);
    for (int i = 0; i < n; i++) idx[i] = (Word16)i;
    /* the decoder sorts the norms first; one case in four skips that, so the band-window logic sees any order */
    if (next_random() % 4 != 0) reordvct_fx(y, n, idx);
    for (int i = 0; i < NB_SFM; i++) r[i] = 0;
    Word16 k = next_random() % 2 ? QBIT_MAX2 : (Word16)random_range(3, 12);
    Word16 sum = wide_budget(&c, 1000);
    put16("y", y, n); put16("idx", idx, n); put1("sum", sum); put1("n", n); put1("k", k);
    put16("sfmsize", c.sfmsize, c.nb_sfm); put1("hqswb_clas", c.hqswb_clas);
    int ok = GUARDED(bitalloc_fx(y, idx, sum, n, k, r, c.sfmsize, c.hqswb_clas));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put16("y", y, n); put16("r", r, NB_SFM); end_line();
}

static void case_bit_alloc_f_wide(void)
{
    HqAllocInput c;
    Word16 y[NB_SFM], r[NB_SFM], rsubband[NB_SFM];
    RANDOM_INPUT_WHERE(&c, c.length >= L_FRAME32k && (c.hqswb_clas == HQ_GEN_SWB || c.hqswb_clas == HQ_GEN_FB ||
                                                      c.hqswb_clas == HQ_TRANSIENT || c.hqswb_clas == HQ_NORMAL));
    random_norms(y, c.nb_sfm);
    if (next_random() % 3 == 0) for (int i = 0; i < c.nb_sfm; i++) y[i] = c.normqlg2[i];
    for (int i = 0; i < NB_SFM; i++) { r[i] = -7; rsubband[i] = -7; }
    Word32 rate = next_random() % 3 ? c.core_brate : (next_random() & 1 ? HQ_24k40 : HQ_32k);
    Word16 b = wide_budget(&c, 1000);
    if (next_random() % 3 == 0) {
        /* BitAllocF_fx's initial share of band i is extract_l(y[i] * band_end - (sum Nb*y - 3B)) * Nb: solve B so
         * that it is exactly zero for one band */
        int weighted = (c.hqswb_clas == HQ_GEN_SWB || c.hqswb_clas == HQ_GEN_FB) ? c.num_env_bands : c.nb_sfm;
        int total = 0, i = random_range(0, c.nb_sfm - 1);
        for (int j = 0; j < weighted; j++) total += Nb[j] * y[j];
        int num = total - y[i] * band_end_HQ[weighted - 1];
        if (num >= 0 && num % 3 == 0 && num / 3 <= 1000) b = (Word16)(num / 3);
    }
    put16("y", y, c.nb_sfm); put1("bit_rate", rate); put1("b", b); put1("n", c.nb_sfm);
    put1("hqswb_clas", c.hqswb_clas); put1("num_env_bands", c.num_env_bands);
    Word16 used = -7;
    int ok = GUARDED(used = BitAllocF_fx(y, rate, b, c.nb_sfm, r, rsubband, c.hqswb_clas, c.num_env_bands));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("used", used); put16("r", r, c.nb_sfm); put16("rsubband", rsubband, c.nb_sfm); end_line();
}


/* The second group's share on BitAllocWB_fx's large-difference path rounds up when "L_add(L_tmp1, 2)" reaches
 * the next multiple; the comparisons behind that rounding are exact, so the budgets that put L_tmp1 two or three
 * below that multiple are searched for, over the second group's norm sum r1, the total rsum and the budget; the
 * cases are built on them (26 bands, a first group of 16 bands, a second of 8, a third of 2), with the first and
 * third group sums chosen so that the large-difference path is the one taken. */
typedef struct { Word16 r0, r1, r2, budget; } WbBoundary;
#define WB_HITS 20000
static WbBoundary wb_hits[WB_HITS];
static int wb_hit_count = -1;

static void find_wb_boundaries(void)
{
    wb_hit_count = 0;
    for (Word16 r1 = 0; r1 <= 272; r1++)
        for (Word16 rsum = (Word16)(r1 > 0 ? r1 : 1); rsum <= 884; rsum++) {
            Word16 r0 = 0, r2 = 0;
            int found = 0;
            for (Word16 candidate = 0; candidate <= 68 && !found; candidate++) {
                Word16 other = (Word16)(rsum - r1 - candidate);
                if (other < 0 || other > 544) continue;
                if (L_sub(L_mult((Word16)other, 2048), L_mult(r1, 4096)) >= 393216 ||
                    L_sub(L_mult(r1, 4096), L_mult(candidate, div_s(1, 2))) >= 245760) {
                    r0 = other; r2 = candidate; found = 1;
                }
            }
            if (!found) continue;
            Word16 exp = norm_s(rsum), tmp = div_s(16384, shl(rsum, exp));
            for (Word16 budget = 0; budget <= 900; budget++) {
                Word32 l1 = Mult_32_16(1975684956, shl(budget, 5));
                l1 = Mult_32_16(l1, shl(r1, 7));
                Word16 b2 = extract_h(L_shl(Mult_32_16(l1, tmp), sub(exp, 11)));
                Word32 gap = L_sub(L_shl(L_mult(add(b2, 1), rsum), 12), l1);
                if ((gap == 2 || gap == 3) && L_sub(l1, L_shl(L_mult(b2, rsum), 12)) > 0 && wb_hit_count < WB_HITS) {
                    WbBoundary hit = {r0, r1, r2, budget};
                    wb_hits[wb_hit_count++] = hit;
                }
            }
        }
}

/* y[from .. from + count) positive values summing to total */
static void spread_norms(Word16 *y, int from, int count, int total)
{
    for (int i = 0; i < count; i++) y[from + i] = (Word16)(total / count + (i < total % count));
}

static void case_bit_alloc_wb_boundary(void)
{
    Word16 y[NB_SFM], r[NB_SFM], rsubband[NB_SFM];
    if (wb_hit_count < 0) find_wb_boundaries();
    int n = 26;
    Word16 budget;
    if (wb_hit_count > 0) {
        WbBoundary hit = wb_hits[next_random() % (unsigned int)wb_hit_count];
        spread_norms(y, 0, SFM_G1, hit.r0);
        spread_norms(y, SFM_G1, SFM_G1G2 - SFM_G1, hit.r1);
        spread_norms(y, SFM_G1G2, n - SFM_G1G2, hit.r2);
        budget = hit.budget;
    } else {
        for (int i = 0; i < n; i++) y[i] = 5;
        budget = 100;
    }
    for (int i = 0; i < NB_SFM; i++) { r[i] = -7; rsubband[i] = -7; }
    put16("y", y, n); put1("b", budget); put1("n", n); put1("hits", wb_hit_count);
    Word16 used = -7;
    int ok = GUARDED(used = BitAllocWB_fx(y, budget, n, r, rsubband));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("used", used); put16("r", r, n); put16("rsubband", rsubband, n); end_line();
}

/* A budget too small for the bands that ask for bits: low budgets (below the frame's 8-bit-per-band share) with
 * the norms falling away towards the high bands, so some bands are dropped above others that are pinned at one
 * bit per coefficient. */
static void case_bit_alloc_f_scarce(void)
{
    HqAllocInput c;
    Word16 y[NB_SFM], r[NB_SFM], rsubband[NB_SFM];
    RANDOM_INPUT_WHERE(&c, c.length >= L_FRAME32k && (c.hqswb_clas == HQ_GEN_SWB || c.hqswb_clas == HQ_GEN_FB ||
                                                      c.hqswb_clas == HQ_TRANSIENT || c.hqswb_clas == HQ_NORMAL));
    int level = random_range(5, 34), slope = random_range(0, 3);
    for (int i = 0; i < c.nb_sfm; i++) {
        y[i] = (Word16)level;
        level += random_range(-slope - 1, 1);
        if (level < -5) level = -5;
        if (level > 34) level = 34;
    }
    for (int i = 0; i < NB_SFM; i++) { r[i] = -7; rsubband[i] = -7; }
    Word32 rate = next_random() & 1 ? HQ_24k40 : HQ_32k;
    Word16 b = (Word16)random_range(0, 200);
    put16("y", y, c.nb_sfm); put1("bit_rate", rate); put1("b", b); put1("n", c.nb_sfm);
    put1("hqswb_clas", c.hqswb_clas); put1("num_env_bands", c.num_env_bands);
    Word16 used = -7;
    int ok = GUARDED(used = BitAllocF_fx(y, rate, b, c.nb_sfm, r, rsubband, c.hqswb_clas, c.num_env_bands));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("used", used); put16("r", r, c.nb_sfm); put16("rsubband", rsubband, c.nb_sfm); end_line();
}

/* The bits BitAllocWB_fx reports come from extract_h(L_shr(total, 5)) of a Q21 total that is always a multiple of
 * 8; this norm vector and budget leave the total 8 short of the next unit, so one stray Q21 step per unallocated
 * band (as a mutated copy of Bit_group_fx would leave) shows in the result. Found by differencing the reference
 * against such a copy over 20 million random cases. */
static void case_bit_alloc_wb_carry(void)
{
    static const Word16 y[26] = {28, 21, 23, 11, 21, 28, 24, 21, -5, 31, 9, 23, 28, 28, 0, 12, 0, 8, -1, 7, 4, 14, 14, 4, 5, 5};
    Word16 r[NB_SFM], rsubband[NB_SFM], b = 39;
    for (int i = 0; i < NB_SFM; i++) { r[i] = -7; rsubband[i] = -7; }
    put16("y", y, 26); put1("b", b); put1("n", 26);
    Word16 used = -7;
    int ok = GUARDED(used = BitAllocWB_fx((Word16 *)y, b, 26, r, rsubband));
    arrow();
    if (!ok) { put1("skip", 1); end_line(); return; }
    put1("used", used); put16("r", r, 26); put16("rsubband", rsubband, 26); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    /* an input outside what the reference tolerates may fault rather than abort: that is a skipped case too */
    signal(SIGSEGV, guard_signal);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "bitalloc")) case_bitalloc();
        else if (!strcmp(argv[2], "bit_alloc_f")) case_bit_alloc_f();
        else if (!strcmp(argv[2], "bit_alloc_wb")) case_bit_alloc_wb();
        else if (!strcmp(argv[2], "bit_alloc_wb_boundary")) case_bit_alloc_wb_boundary();
        else if (!strcmp(argv[2], "bit_alloc_f_scarce")) case_bit_alloc_f_scarce();
        else if (!strcmp(argv[2], "bit_alloc_wb_carry")) case_bit_alloc_wb_carry();
        else if (!strcmp(argv[2], "bitalloc_wide")) case_bitalloc_wide();
        else if (!strcmp(argv[2], "bit_alloc_f_wide")) case_bit_alloc_f_wide();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
