/* Function-level oracle for lib_com/window_ola_fx.c. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static void case_sinq(void)
{
    Word16 x[L_FRAME48k];
    Word16 n = (Word16)random_range(3, L_FRAME48k - 270);
    /* window_ola_fx passes tmp2 / 2 and tmp2 / 4 with tmp2 ~ 2 pi / (L - n) in Q15 */
    Word16 tmp = (Word16)(next_random() % 4 ? random_range(0, 800) : random16());
    Word16 phi = (Word16)(next_random() % 4 ? random_range(0, 400) : random16());
    put1("tmp", tmp); put1("phi", phi); put1("n", n);
    sinq_fx(tmp, phi, n, x);
    arrow(); put16("x", x, n); end_line();
}

/* window_ola_fx over two consecutive frames through one overlap memory, at the HQ output lengths
 * (and the 25.6 kHz TCX ones), the overlap modes the MODE1 decoder sets (MIN 2, HALF 3, ALDO 4),
 * and the concealment window (with and without the voiced gap synthesis) on the second frame. */
static void case_window_ola(void)
{
    static const Word16 lengths[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k, L_FRAME48k, 256, 512};
    Word16 L = lengths[random_range(0, 5)];
    Word16 old_out[L_FRAME48k], gap[2][L_FRAME48k], out[L_FRAME48k];
    Word32 wtda[2][2 * L_FRAME48k];
    Word16 left[2], right[2], use_bfi[2], voicing[2], q_sig[2];
    Word16 q_old = (Word16)random_range(-4, 8);
    random_signal(old_out, L, next_random() & 1 ? 32767 : random_range(10, 4000));
    put1("L", L); put16("old_out", old_out, L); put1("q_old", q_old);
    for (int f = 0; f < 2; f++) {
        char name[32];
        int bfi_ok = f == 1 && L != 256 && L != 512;
        use_bfi[f] = (Word16)(bfi_ok && next_random() % 2);
        left[f] = use_bfi[f] ? ALDO_WINDOW : (Word16)random_range(2, 4);
        right[f] = use_bfi[f] ? ALDO_WINDOW : (Word16)random_range(2, 4);
        voicing[f] = (Word16)(use_bfi[f] && next_random() % 2);
        q_sig[f] = (Word16)random_range(-2, 12);
        int shift = random_range(0, 20);
        for (int i = 0; i < L; i++) wtda[f][i] = (Word32)(random32() >> shift);
        if (next_random() % 8 == 0) for (int i = 0; i < L; i++) wtda[f][i] = (Word32)random_range(-3, 3);
        random_signal(gap[f], L, random_range(10, 20000));
        sprintf(name, "wtda%d", f); put32(name, wtda[f], L);
        sprintf(name, "left%d", f); put1(name, left[f]);
        sprintf(name, "right%d", f); put1(name, right[f]);
        sprintf(name, "bfi%d", f); put1(name, use_bfi[f]);
        sprintf(name, "voicing%d", f); put1(name, voicing[f]);
        sprintf(name, "q_sig%d", f); put1(name, q_sig[f]);
        sprintf(name, "gap%d", f); put16(name, gap[f], L);
    }
    arrow();
    for (int f = 0; f < 2; f++) {
        char name[32];
        for (int i = 0; i < L; i++) out[i] = -12345;
        window_ola_fx(wtda[f], out, &q_sig[f], old_out, &q_old, L, right[f], left[f], use_bfi[f], voicing[f], gap[f]);
        sprintf(name, "out%d", f); put16(name, out, L);
        sprintf(name, "old_out%d", f); put16(name, old_out, L);
        sprintf(name, "gap%d", f); put16(name, gap[f], L);
        sprintf(name, "q_sig%d", f); put1(name, q_sig[f]);
        sprintf(name, "q_old%d", f); put1(name, q_old);
    }
    end_line();
}

/* core_switching_OLA_fx at every output rate, after a 12.8 or a 16 kHz ACELP frame. */
static void case_core_switching_ola(void)
{
    static const Word16 frames[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k, L_FRAME48k};
    static const Word32 rates[] = {8000, 16000, 32000, 48000};
    int r = random_range(0, 3);
    Word16 output_frame = frames[r];
    Word32 output_fs = rates[r];
    Word16 last_L_frame = next_random() & 1 ? L_FRAME : L_FRAME16k;
    Word16 bwidth = (Word16)random_range(NB, r == 0 ? NB : r == 1 ? WB : r == 2 ? SWB : FB);
    Word16 mem[22], synth[L_FRAME48k], subfr[SWITCH_MAX_GAP], bwe[SWITCH_MAX_GAP];
    Word16 qsynth = (Word16)random_range(-2, 4), qsubfr = (Word16)random_range(-2, 4);
    int mag = next_random() & 1 ? 32767 : random_range(10, 8000);
    random_signal(mem, 22, mag);
    random_signal(synth, output_frame, mag);
    random_signal(subfr, SWITCH_MAX_GAP, mag);
    random_signal(bwe, SWITCH_MAX_GAP, mag);
    put1("output_frame", output_frame); put1("output_fs", output_fs); put1("last_L_frame", last_L_frame);
    put1("bwidth", bwidth); put16("mem", mem, 22); put16("synth", synth, output_frame);
    put16("subfr", subfr, SWITCH_MAX_GAP); put16("bwe", bwe, SWITCH_MAX_GAP); put1("qsynth", qsynth);
    put1("qsubfr", qsubfr);
    core_switching_OLA_fx(mem, last_L_frame, output_fs, synth, subfr, bwe, output_frame, bwidth, &qsynth, &qsubfr);
    arrow(); put16("mem", mem, 22); put16("synth", synth, output_frame); put16("subfr", subfr, SWITCH_MAX_GAP);
    put16("bwe", bwe, SWITCH_MAX_GAP); put1("qsynth", qsynth); put1("qsubfr", qsubfr); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "sinq")) case_sinq();
        else if (!strcmp(argv[2], "window_ola")) case_window_ola();
        else if (!strcmp(argv[2], "core_switching_ola")) case_core_switching_ola();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
