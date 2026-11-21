/* Function-level oracle for lib_dec/FEC_adapt_codebook_fx.c (FEC_SinOnset_fx, FEC_enhACB_fx,
 * FEC_synchro_exc_fx) and for findpulse_fx of lib_com/findpulse_fx.c, which it calls. */
#include <math.h>
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/FEC_adapt_codebook_fx.c"

/* A stable order-16 A(z) in Q12 from random reflection coefficients (step-up recursion). */
static void random_lpc(Word16 *a)
{
    double k[M], c[M + 1], t[M + 1];
    for (int i = 0; i < M; i++) k[i] = ((int)(next_random() % 1801) - 900) / 1000.0 * (i < 2 ? 1.0 : 0.6);
    c[0] = 1.0;
    for (int m = 1; m <= M; m++) {
        for (int i = 1; i < m; i++) t[i] = c[i] + k[m - 1] * c[m - i];
        for (int i = 1; i < m; i++) c[i] = t[i];
        c[m] = k[m - 1];
    }
    a[0] = 4096;
    for (int i = 1; i <= M; i++) {
        double v = c[i] * 4096.0;
        a[i] = (Word16)(v > 32767 ? 32767 : v < -32768 ? -32768 : lrint(v));
    }
}

/* A pulse train of the given period with noise, so the pulse searches find something. */
static void pulse_train(Word16 *x, int n, int period, int amplitude)
{
    int phase = random_range(0, period - 1), negative = (int)(next_random() % 3 == 0);
    for (int i = 0; i < n; i++) {
        x[i] = (Word16)random_range(-amplitude / 8, amplitude / 8);
        if ((i + phase) % period == 0) x[i] = (Word16)(negative ? -amplitude : amplitude);
    }
}

static void case_findpulse(void)
{
    Word16 res[L_FRAME16k], sign = (Word16)(next_random() & 1);
    Word16 L_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 enc = (Word16)(next_random() % 3 ? DEC : ENC);
    Word16 T0 = (Word16)random_range(2, L_frame);
    int amplitude = next_random() % 3 == 0 ? 32767 : random_range(1, 12000);
    if (next_random() % 4 == 0) pulse_train(res, L_frame, random_range(17, 200), amplitude);
    else random_signal(res, L_frame, amplitude);
    if (next_random() % 8 == 0) for (int i = 0; i < L_frame; i++) res[i] = random16();
    put1("L_frame", L_frame); put16("res", res, L_frame); put1("T0", T0); put1("enc", enc); put1("sign", sign);
    Word16 r = findpulse_fx(L_frame, res, T0, enc, &sign);
    arrow(); put1("r", r); put1("sign", sign); end_line();
}

static void case_sin_onset(void)
{
    Word16 exc[L_EXC_MEM], Aq[M + 1], L_frame = (Word16)(next_random() % 3 ? L_FRAME : L_FRAME16k);
    Word16 pitch_max = L_frame == L_FRAME ? PIT_MAX : PIT16k_MAX;
    Word16 puls_pos = (Word16)random_range(1, next_random() % 8 ? pitch_max : 400);
    if (next_random() % 2) puls_pos = negate(puls_pos);
    Word16 T0 = (Word16)random_range(17, pitch_max), Qold = (Word16)random_range(0, 10);
    Word32 enr_q = next_random() % 6 == 0 ? random32() : (Word32)random_range(0, 1 << 24) << random_range(0, 6);
    random_lpc(Aq);
    for (int i = 0; i < L_EXC_MEM; i++) exc[i] = -12345;
    put1("L_frame", L_frame); put1("puls_pos", puls_pos); put1("T0", T0); put1("enr_q", enr_q); put16("Aq", Aq, M + 1); put1("Qold", Qold);
    Word16 q = FEC_SinOnset_fx(exc, puls_pos, T0, enr_q, Aq, L_frame, Qold);
    arrow(); put1("q", q); put16("exc", exc, L_EXC_MEM); end_line();
}

static void case_enh_acb(void)
{
    Word16 L_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 last_L_frame = (Word16)(next_random() % 4 ? L_FRAME16k : L_FRAME);
    Word16 pitch_max = L_frame == L_FRAME ? PIT_MAX : PIT16k_MAX, pitch_min = L_frame == L_FRAME ? PIT_MIN : PIT16k_MIN;
    Word16 tc = (Word16)random_range(pitch_min, pitch_max - 1);
    Word16 bfi_pitch = (Word16)((tc << 6) + random_range(0, 63));
    Word16 new_pit = (Word16)(tc + random_range(-3, 3));
    Word16 puls_pos = (Word16)random_range(1, next_random() % 8 ? tc : pitch_max + 50);
    if (next_random() % 3 == 0) puls_pos = negate(puls_pos);
    Word16 exc_io[L_EXC_MEM];
    if (next_random() % 6) pulse_train(exc_io, L_EXC_MEM, tc, random_range(2000, 12000));
    else random_signal(exc_io, L_EXC_MEM, 12000);
    put1("L_frame", L_frame); put1("last_L_frame", last_L_frame); put16("exc_io", exc_io, L_EXC_MEM);
    put1("new_pit", new_pit); put1("puls_pos", puls_pos); put1("bfi_pitch", bfi_pitch);
    Word16 r = FEC_enhACB_fx(L_frame, last_L_frame, exc_io, new_pit, puls_pos, bfi_pitch);
    arrow(); put1("r", r); put16("exc_io", exc_io, L_EXC_MEM); end_line();
}

static void case_synchro_exc(void)
{
    Word16 L_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 exc[L_FRAME16k + L_SUBFR];
    Word16 old_pitch = (Word16)random_range(next_random() % 4 ? 34 : 17, next_random() % 4 ? 160 : 289);
    /* dist_Plast = Tc - Tlist: between -64 and Tc, and the position must stay inside the frame (div_s needs it) */
    Word16 true_pos = (Word16)random_range(-64, next_random() % 4 ? 120 : (L_frame == L_FRAME ? PIT_MAX : PIT16k_MAX));
    Word16 desire = (Word16)(true_pos + random_range(-40, 40));
    if (next_random() % 4 == 0) desire = (Word16)(true_pos + (next_random() & 1 ? 1 : -1));
    pulse_train(exc, L_FRAME16k + L_SUBFR, old_pitch, random_range(500, 12000));
    if (next_random() % 8 == 0) random_signal(exc, L_FRAME16k + L_SUBFR, 9000);
    put1("L_frame", L_frame); put16("exc", exc, L_FRAME16k + L_SUBFR); put1("desire", desire); put1("true_pos", true_pos); put1("old_pitch", old_pitch);
    Word16 r = FEC_synchro_exc_fx(L_frame, exc, desire, true_pos, old_pitch);
    arrow(); put1("r", r); put16("exc", exc, L_FRAME16k + L_SUBFR); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "findpulse")) case_findpulse();
        else if (!strcmp(argv[2], "sin_onset")) case_sin_onset();
        else if (!strcmp(argv[2], "enh_acb")) case_enh_acb();
        else if (!strcmp(argv[2], "synchro_exc")) case_synchro_exc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
