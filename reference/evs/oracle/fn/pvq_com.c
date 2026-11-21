/* Function-level oracle for lib_com/pvq_com_fx.c (the PVQ helpers the decoder runs). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_int_lim_c_div(void)
{
    Word32 num = next_random() % 3 ? random_range(-(1 << 20), 1 << 20) : random32();
    Word16 den = (Word16)random_range(1, 67);
    if (num == (Word32)0x80000000) num = 0; /* L_abs saturates; not a value the decoder divides */
    put1("num", num); put1("den", den);
    arrow(); put1("pos", (Word32)intLimCDivPos_fx((UWord32)(num < 0 ? -num : num), den));
    put1("signed", intLimCDivSigned_fx(num, den)); end_line();
}

static void case_shrt_c_div(void)
{
    Word16 num = (Word16)(next_random() % 3 ? random_range(-4000, 4000) : random16());
    Word16 den = (Word16)random_range(1, 10);
    put1("num", num); put1("den", den);
    arrow(); put1("quotient", shrtCDivSignedApprox(num, den)); end_line();
}

static void case_ds_dirac_per_quanta(void)
{
    Word16 td = (Word16)random_range(1, 64), dsm = (Word16)random_range(0, 1);
    Word16 nsv = hBitsN[td][0];
    Word16 t_quanta = (Word16)(next_random() % 4 ? random_range(0, hBitsN[td][nsv] + 20) : random_range(-20, 2400));
    Word16 idx;
    put1("td", td); put1("t_quanta", t_quanta); put1("dsm", dsm);
    dsDiracPerQuanta_fx(td, t_quanta, dsm, hBitsN, &idx);
    arrow(); put1("ds_idx", idx); end_line();
}

static void case_conservative_l1_norm(void)
{
    Word16 l = (Word16)random_range(1, 64), qvec = (Word16)random_range(0, 1600), fcons = (Word16)random_range(0, 1);
    Word16 qavail = (Word16)random_range(-40, 2000), qreserv = (Word16)random_range(-100, 400), dspec = (Word16)random_range(0, 200);
    Word16 dvec, qspare, qreservplus, dspecplus;
    put1("l", l); put1("qvec", qvec); put1("fcons", fcons); put1("qavail", qavail); put1("qreserv", qreserv); put1("dspec", dspec);
    conservativeL1Norm_fx(l, qvec, fcons, qavail, qreserv, dspec, &dvec, &qspare, &qreservplus, &dspecplus);
    arrow(); put1("dvec", dvec); put1("qspare", qspare); put1("qreservplus", qreservplus); put1("dspecplus", dspecplus); end_line();
}

static void case_band_bits_adjustment(void)
{
    Word16 brc = (Word16)random_range(0, 700);
    UWord32 int_rc = (UWord32)random_range(1 << 24, 0x7fffffff) * (UWord32)random_range(1, 2) - (UWord32)random_range(0, 1);
    Word16 bavail = (Word16)random_range(0, 1300), nbands = (Word16)random_range(1, 20), d = (Word16)random_range(1, nbands);
    Word16 l = (Word16)random_range(1, 64), bband = (Word16)random_range(0, 900), breserv = (Word16)random_range(-60, 300);
    Word16 bband_adj, brem, breservplus;
    put1("brc", brc); put1("int_rc", (Word32)int_rc); put1("bavail", bavail); put1("nbands", nbands); put1("d", d);
    put1("l", l); put1("bband", bband); put1("breserv", breserv);
    bandBitsAdjustment_fx(brc, int_rc, bavail, nbands, d, l, bband, breserv, &bband_adj, &brem, &breservplus);
    arrow(); put1("bband_adj", bband_adj); put1("brem", brem); put1("breservplus", breservplus); end_line();
}

static void case_apply_gain(void)
{
    Word16 num_sfm = (Word16)random_range(1, 20), ord[20], start[20], end[20], gains[20], xq[20 * 32];
    int pos = 0;
    for (int b = 0; b < num_sfm; b++) {
        start[b] = (Word16)pos;
        pos += 8 * random_range(1, 4);
        end[b] = (Word16)pos;
        ord[b] = (Word16)b;
        gains[b] = (Word16)(next_random() % 4 ? random_range(0, 32767) : random16());
    }
    for (int b = num_sfm - 1; b > 0; b--) { int j = random_range(0, b); Word16 t = ord[b]; ord[b] = ord[j]; ord[j] = t; }
    for (int i = 0; i < pos; i++) xq[i] = random16();
    put16("ord", ord, num_sfm); put16("band_start", start, num_sfm); put16("band_end", end, num_sfm);
    put16("gains", gains, num_sfm); put16("xq", xq, pos);
    apply_gain_fx(ord, start, end, num_sfm, gains, xq);
    arrow(); put16("xq", xq, pos); end_line();
}

static void case_srt_vec_ind16(void)
{
    Word16 length = (Word16)random_range(1, 44), linear[44], srt[44], idx[44];
    int narrow = next_random() & 1; /* repeated keys exercise the stability of the exchange sort */
    for (int i = 0; i < length; i++) linear[i] = narrow ? (Word16)random_range(-3, 3) : random16();
    put16("linear", linear, length);
    srt_vec_ind16_fx(linear, srt, idx, length);
    arrow(); put16("srt", srt, length); put16("index", idx, length); end_line();
}

/* The split-energy helpers decode_energies_fx runs: inputs in the ranges the band splits give. */
static void case_near_proj(void)
{
    Word16 x = (Word16)(next_random() % 4 ? random_range(0, 32767) : random16());
    put1("x", x);
    Word16 r;
    nearProjQ15_fx(x, &r);
    arrow(); put1("r", r); end_line();
}

static void case_energy_density(void)
{
    /* div_s takes no negative numerator, so the long-band branch only sees r >= 0 (as in the decoder) */
    Word16 l = (Word16)random_range(1, 96), r = (Word16)(next_random() % 4 ? random_range(0, 2400) : random_range(-100, 8000));
    if (2 * l - 1 > 67 && r < 0) r = (Word16)-r;
    Word16 d;
    put1("l", l); put1("r", r);
    obtainEnergyQuantizerDensity_fx(l, r, &d);
    arrow(); put1("d", d); end_line();
}

static void case_quanta_per_ds_dirac(void)
{
    Word16 td = (Word16)random_range(1, 64);
    Word16 idx = (Word16)random_range(0, hBitsN[td][0]);
    Word16 q;
    put1("td", td); put1("idx", idx);
    QuantaPerDsDirac_fx(td, idx, hBitsN, &q);
    arrow(); put1("q", q); end_line();
}

static void case_ratio_rq3(void)
{
    Word16 opp = (Word16)random_range(1, 32767), near = (Word16)random_range(1, 32767);
    if (next_random() % 3 == 0) opp = (Word16)random_range(1, 300);
    if (next_random() % 3 == 0) near = (Word16)random_range(1, 300);
    Word16 r;
    put1("opp", opp); put1("near", near);
    Ratio_rQ3_fx(opp, near, &r);
    arrow(); put1("r", r); end_line();
}

static void case_density_angle(void)
{
    Word16 d = (Word16)random_range(1, 128), idx = (Word16)(next_random() % 8 ? random_range(0, d) : -1);
    Word16 opp, near, ratio_q3;
    put1("d", d); put1("idx", idx);
    densityAngle2RmsProjDec_fx(d, idx, &opp, &near, &ratio_q3);
    arrow(); put1("opp", opp); put1("near", near); put1("ratio", ratio_q3); end_line();
}

static void case_near_opp_split(void)
{
    /* The band split as pvq_decode_band_fx / decode_energies_fx form it: np parts of floor(dim/np)
     * coefficients, the remainder in the last; near = the first np/2 parts, opp = the rest. */
    Word16 dim, np, part, nhead, ntail, nnear, nopp;
    Word16 qband = (Word16)random_range(-50, 3000), qzero = (Word16)random_range(0, 800);
    Word16 qac = (Word16)random_range(0, 900);
    UWord32 intac = (UWord32)next_random() | 0x80000000u;
    if (next_random() % 4 == 0) intac = (UWord32)next_random() >> random_range(0, 8);
    Word16 qglobal = (Word16)random_range(-100, 4000), cons = (Word16)random_range(0, 1);
    Word16 oppr = (Word16)random_range(-40, 40);
    dim = (Word16)random_range(2, 96);
    np = (Word16)random_range(2, dim < 10 ? dim : 10);
    part = (Word16)(dim / np);
    nhead = part;
    ntail = (Word16)(dim - part * (np - 1));
    nnear = (Word16)(part * (np / 2));
    nopp = (Word16)(dim - nnear);
    Word16 qnear, qopp, qupd;
    put1("qband", qband); put1("qzero", qzero); put1("qac", qac); put1("intac", intac); put1("qglobal", qglobal);
    put1("cons", cons); put1("np", np); put1("nhead", nhead); put1("ntail", ntail); put1("nnear", nnear); put1("nopp", nopp);
    put1("oppr", oppr);
    NearOppSplitAdjustment_fx(qband, qzero, qac, intac, qglobal, cons, np, nhead, ntail, nnear, nopp, oppr, &qnear, &qopp, &qupd);
    arrow(); put1("qnear", qnear); put1("qopp", qopp); put1("qupd", qupd); end_line();
}

static void case_atan2(void)
{
    Word32 y, x;
    if (next_random() % 2) { y = SQRT_DIM_fx[random_range(0, 64)]; x = SQRT_DIM_fx[random_range(0, 64)]; }
    else { y = (Word32)(next_random() >> random_range(1, 31)); x = (Word32)(next_random() >> random_range(1, 31)); }
    if (next_random() % 50 == 0) x = 0;
    if (y == 0) y = 1;
    put1("y", y); put1("x", x);
    arrow(); put1("angle", atan2_fx(y, x)); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "int_lim_c_div")) case_int_lim_c_div();
        else if (!strcmp(argv[2], "shrt_c_div")) case_shrt_c_div();
        else if (!strcmp(argv[2], "ds_dirac_per_quanta")) case_ds_dirac_per_quanta();
        else if (!strcmp(argv[2], "conservative_l1_norm")) case_conservative_l1_norm();
        else if (!strcmp(argv[2], "band_bits_adjustment")) case_band_bits_adjustment();
        else if (!strcmp(argv[2], "apply_gain")) case_apply_gain();
        else if (!strcmp(argv[2], "srt_vec_ind16")) case_srt_vec_ind16();
        else if (!strcmp(argv[2], "near_proj")) case_near_proj();
        else if (!strcmp(argv[2], "energy_density")) case_energy_density();
        else if (!strcmp(argv[2], "quanta_per_ds_dirac")) case_quanta_per_ds_dirac();
        else if (!strcmp(argv[2], "ratio_rq3")) case_ratio_rq3();
        else if (!strcmp(argv[2], "density_angle")) case_density_angle();
        else if (!strcmp(argv[2], "near_opp_split")) case_near_opp_split();
        else if (!strcmp(argv[2], "atan2")) case_atan2();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
