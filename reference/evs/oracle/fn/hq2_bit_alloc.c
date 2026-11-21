/* Function-level oracle for lib_com/hq2_bit_alloc_fx.c (hq2_bit_alloc_fx, hq2_bit_alloc_har_fx,
 * Bits2indvsb_fx). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 band_counts[] = {14, 16, 20, 23, 24, 26, 30, BANDS_MAX};
static const Word16 num_bits_list[] = {144, 160, 200, 264, 328, 400, 650};
static const Word32 rates[] = {7200, 8000, 13200, 16400, 32000};

static void case_hq2_bit_alloc(void)
{
    Word32 energy[BANDS_MAX], rk[BANDS_MAX];
    Word16 p2a[BANDS_MAX], width[BANDS_MAX];
    Word16 bands = band_counts[next_random() % 8], num_bits = num_bits_list[next_random() % 7];
    Word16 budget = (Word16)random_range(20, num_bits), weight = (Word16)random_range(1638, 8192);
    Word16 clas = (Word16)random_range(0, 3), bwidth = (Word16)random_range(0, 3), transient = (Word16)(next_random() & 1);
    if (next_random() & 1) bwidth = SWB;
    if (next_random() & 1) clas = HQ_NORMAL;
    if ((next_random() & 7) == 0) budget = (Word16)random_range(-20, 20);
    for (int i = 0; i < bands; i++) {
        energy[i] = (next_random() % 8) ? random_range(0, 20 << 14) : random_range(-(4 << 14), 30 << 14);
        p2a[i] = (Word16)((next_random() % 3) == 0);
        width[i] = (Word16)(next_random() % 3 ? random_range(8, 32) : random_range(4, 64));
        rk[i] = random32();
    }
    put32("energy", energy, bands); put16("p2a", p2a, bands); put16("width", width, bands);
    put1("budget", budget); put1("weight", weight); put1("num_bits", num_bits); put1("clas", clas);
    put1("bwidth", bwidth); put1("transient", transient);
    Word32 r = hq2_bit_alloc_fx(energy, bands, rk, &budget, p2a, weight, width, num_bits, clas, bwidth, transient);
    arrow(); put1("r", r); put32("rk", rk, bands); put1("budget", budget); put16("p2a", p2a, bands); end_line();
}

/* A band energy (Qbe = 14) as band_energy_dequant_fx decodes it: inside hq_lr_dec_fx's sanity window,
 * mostly a smooth envelope with peaks. */
static Word32 random_energy(void)
{
    if (next_random() % 8 == 0) return random_range(-109772, 737279);
    return random_range(-(1 << 14), 22 << 14);
}

/* hq2_bit_alloc_har_fx where hq_lr_dec_fx calls it: an SWB 13.2 / 16.4 kbit/s long-window layout
 * from hq2_core_configure_fx, every p2a flag set (set16_fx over har_bands = bands), the budget
 * left after the energies and fine gains. */
static void case_hq2_bit_alloc_har(void)
{
    Word32 energy[BANDS_MAX], rk[BANDS_MAX], qint, brate = next_random() & 1 ? HQ_13k20 : HQ_16k40;
    Word16 p2a[BANDS_MAX], bands, length, width[BANDS_MAX], start[BANDS_MAX], end[BANDS_MAX];
    Word16 eref, baw, gqlevs, ngq, p2a_bands, p2a_th, pd, ld, ni;
    hq2_core_configure_fx(L_FRAME32k, (Word16)random_range(200, 328), 0, &bands, &length, width, start, end, &qint,
                          &eref, &baw, &gqlevs, &ngq, &p2a_bands, &p2a_th, &pd, &ld, &ni, brate);
    int shape = next_random() % 6, level = random_range(4, 18);
    for (int i = 0; i < bands; i++) {
        if (shape == 0) energy[i] = random_energy();
        else if (shape == 1)
            /* a falling envelope, mostly monotone, on the dequantiser's grid (multiples of a step, so
             * neighbours tie): the group ends run past G1_RANGE / G1G2_RANGE */
            energy[i] = (Word32)((level * 4 - i * random_range(0, 2) + (next_random() % 6 ? 0 : random_range(-2, 2))) * 4096);
        else energy[i] = (level << 14) - i * random_range(0, 1 << 13) + random_range(-(3 << 14), 3 << 14);
        p2a[i] = 1;
        rk[i] = random32();
    }
    if (shape == 5 && bands == 22) {
        /* the high-band reservation's corner (13.2 kbit/s layout only): one loud high band of about
         * five times the low-band level, the rest of the high band silent */
        int low = random_range(2 << 14, 6 << 14);
        for (int i = 0; i < 18; i++) energy[i] = low + random_range(-(1 << 11), 1 << 11);
        for (int i = 18; i < bands; i++) energy[i] = random_range(-(1 << 12), 0);
        energy[random_range(18, bands - 1)] = (Word32)((long long)low * random_range(4800, 5300) / 1000);
    }
    Word16 budget = (Word16)(next_random() % 8 ? random_range(60, 260) : random_range(0, 60));
    put32("energy", energy, bands); put16("width", width, bands); put1("budget", budget); put1("p2a_bands", p2a_bands);
    put1("brate", brate);
    hq2_bit_alloc_har_fx(energy, budget, bands, rk, p2a_bands, brate, p2a, width);
    arrow(); put32("rk", rk, bands); put16("p2a", p2a, bands); end_line();
}

/* Bits2indvsb_fx on one group as hq2_bit_alloc_har_fx forms it: up to 14 bands, a budget, the
 * group's threshold (THR1..THR3 or an estimated HF bit count, in QRk). */
static void case_bits2indvsb(void)
{
    Word32 energy[BANDS_MAX], rk[BANDS_MAX];
    Word16 p2a[BANDS_MAX];
    Word16 start = (Word16)random_range(0, 18), n = (Word16)random_range(1, 14), end = (Word16)(start + n);
    for (int i = 0; i < BANDS_MAX; i++) {
        energy[i] = random_energy();
        p2a[i] = (Word16)(next_random() % 5 != 0);
        rk[i] = random32();
    }
    Word16 bits = (Word16)(next_random() % 8 ? random_range(1, 120) : random_range(0, 400));
    Word32 needed = L_shl((Word32)random_range(THR1, 10), SWB_BWE_LR_QRk);
    put32("energy", energy, BANDS_MAX); put1("start", start); put1("end", end); put1("bits", bits); put1("needed", needed);
    put16("p2a", p2a, BANDS_MAX); put32("rk", rk, BANDS_MAX);
    Bits2indvsb_fx(energy, start, end, bits, needed, rk, p2a);
    arrow(); put32("rk", rk, BANDS_MAX); put16("p2a", p2a, BANDS_MAX); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq2_bit_alloc")) case_hq2_bit_alloc();
        else if (!strcmp(argv[2], "hq2_bit_alloc_har")) case_hq2_bit_alloc_har();
        else if (!strcmp(argv[2], "bits2indvsb")) case_bits2indvsb();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
