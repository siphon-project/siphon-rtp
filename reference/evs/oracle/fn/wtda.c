/* Function-level oracle for lib_com/wtda_fx.c (tcx_get_windows_mode1, wtda_fx). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 lengths[] = {160, 320, 640, 960};

static void case_windows(void)
{
    static const Word16 modes[] = {0, 1, 2, 3, 4, -2};
    static const Word16 all_lengths[] = {256, 512, 160, 320, 640, 960};
    Word16 left_mode = modes[next_random() % 6], right_mode = modes[next_random() % 6];
    Word16 L = all_lengths[next_random() % 6];
    Word16 lw[690], rw[420], lwi[230], rwi[140];
    for (int i = 0; i < 690; i++) lw[i] = 1234;
    for (int i = 0; i < 420; i++) rw[i] = 1234;
    for (int i = 0; i < 230; i++) lwi[i] = 1234;
    for (int i = 0; i < 140; i++) rwi[i] = 1234;
    put1("left_mode", left_mode); put1("right_mode", right_mode); put1("L", L);
    tcx_get_windows_mode1(left_mode, right_mode, lw, rw, lwi, rwi, L);
    arrow(); put16("left_win", lw, 690); put16("right_win", rw, 420); put16("left_win_int", lwi, 230);
    put16("right_win_int", rwi, 140); end_line();
}

/* wtda_fx without (old_wtda NULL, the ECU's call) or with an old-frame buffer (the BWE's call);
 * with one, two consecutive frames run through it. */
static void case_wtda(void)
{
    static const Word16 modes[] = {2, 3, 4, -2};
    Word16 L = lengths[next_random() % 4];
    Word16 left_mode = modes[next_random() % 3], right_mode = modes[next_random() % 4];
    int with_old = next_random() & 1;
    Word16 buffer[2 * 960];
    Word32 out[960];
    Word16 old[960];
    Word16 Q = (Word16)random_range(-2, 4), Qold = (Word16)random_range(-2, 4);
    int frames = with_old ? 2 : 1;
    put1("L", L); put1("left_mode", left_mode); put1("right_mode", right_mode); put1("with_old", with_old);
    put1("Q", Q); put1("Qold", Qold);
    if (with_old) { random_signal(old, L, 20000); put16("old", old, L); }
    Word32 outs[2][960];
    Word16 Qs[2];
    for (int f = 0; f < frames; f++) {
        random_signal(buffer, 2 * L, next_random() & 1 ? 30000 : 4000);
        if (next_random() % 8 == 0) for (int i = 0; i < 2 * L; i++) buffer[i] = random16();
        char name[16];
        sprintf(name, "buffer%d", f); put16(name, buffer, 2 * L);
        /* without old_wtda the frame starts L samples into the buffer and reads back to L - n */
        wtda_fx(buffer + L, &Q, out, with_old ? old : NULL, &Qold, left_mode, right_mode, L);
        memcpy(outs[f], out, sizeof(out));
        Qs[f] = Q;
        if (f == 0 && frames == 2) { sprintf(name, "after%d", f); }
    }
    arrow();
    for (int f = 0; f < frames; f++) { char name[16]; sprintf(name, "out%d", f); put32(name, outs[f], L); }
    put1("Q", Q); put1("Qold", Qold);
    if (with_old) put16("old", old, L);
    put16("buffer_last", buffer, 2 * L);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "windows")) case_windows();
        else if (!strcmp(argv[2], "wtda")) case_wtda();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
