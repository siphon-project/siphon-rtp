/* Function-level oracle for lib_com/trans_inv_fx.c (Inverse_Transform, preecho_sb_fx). */
#include "harness.h"
#include "prot_fx.h"

static const Word16 frame_lengths[] = {160, 320, 640, 960};

static void fill_signal32(Word32 *x, int n, int shift)
{
    int mode = random_range(0, 4);
    Word16 tmp[960];
    if (mode == 3) { for (int i = 0; i < n; i++) x[i] = random32(); return; }
    random_signal(tmp, n, random_range(1, 32767));
    for (int i = 0; i < n; i++) x[i] = ((Word32)tmp[i] << shift) + (mode == 1 ? random_range(-(1 << shift), 1 << shift) : 0);
    if (mode == 2) for (int i = 0; i < n; i++) x[i] = 0;
    if (mode == 4) for (int i = 0; i < n; i++) x[i] = (i % 37 == 0) ? random32() : x[i] >> 8;  /* sparse spectrum */
}

static void case_inverse_transform(void)
{
    Word32 in[960], out[960];
    Word16 l = frame_lengths[next_random() % 4], l_inner = l, is_transient = (Word16)(next_random() & 1);
    if (next_random() & 1) l_inner = frame_lengths[next_random() % 4];
    Word16 q = (Word16)random_range(-2, 15);
    fill_signal32(in, l_inner > l ? l_inner : l, random_range(0, 16));
    put32("in", in, l_inner > l ? l_inner : l); put1("is_transient", is_transient); put1("l", l);
    put1("l_inner", l_inner); put1("q", q);
    Inverse_Transform(in, &q, out, is_transient, l, l_inner);
    arrow(); put32("out", out, l); put1("q", q); end_line();
}

/* A frame of synthesis with an optional attack: quiet noise, then a burst from a random sub-frame. */
static void attack_signal(Word16 *x, int n)
{
    int onset = random_range(0, n), quiet = random_range(1, 2000), loud = random_range(quiet, 32767);
    int mode = random_range(0, 4);
    if (mode == 0) { random_signal(x, n, random_range(1, 32767)); return; }
    if (mode == 1) { for (int i = 0; i < n; i++) x[i] = random16(); return; }
    for (int i = 0; i < n; i++) {
        int mag = i < onset ? quiet : loud;
        x[i] = (Word16)random_range(-mag, mag);
        if (mode == 3 && i < onset) x[i] = (Word16)(((i / 3) & 1) ? mag / 2 : -mag / 2); /* tonal, few crossings */
    }
}

static void case_preecho_sb(void)
{
    enum { FRAMES = 3 };
    Word16 l = frame_lengths[next_random() % 4];
    Word16 bwidth = (Word16)random_range(0, 3);
    Word16 memfilt = random16(), smoothmem = (Word16)((next_random() & 1) ? 32767 : random_range(0, 32767));
    Word16 wmold_hb = (Word16)((next_random() & 1) ? 32767 : random_range(0, 32767));
    Word16 prevflag = (Word16)(next_random() & 1), pastpre = (Word16)random_range(0, 2);
    Word32 mean_prev_hb = random_range(0, 1 << random_range(0, 30)), mean_prev = random_range(0, 1 << random_range(0, 30));
    Word32 mean_prev_nc = random_range(0, 1 << random_range(0, 30));
    Word32 brate[FRAMES], wtda[FRAMES][960];
    Word16 q32[FRAMES], q16[FRAMES], rec[FRAMES][960];
    static const Word32 brates[] = {7200, 8000, 13200, 16400, 24400, 32000, 48000};
    put1("l", l); put1("bwidth", bwidth); put1("memfilt", memfilt); put1("smoothmem", smoothmem);
    put1("wmold_hb", wmold_hb); put1("prevflag", prevflag); put1("pastpre", pastpre);
    put1("mean_prev_hb", mean_prev_hb); put1("mean_prev", mean_prev); put1("mean_prev_nc", mean_prev_nc);
    char name[32];
    for (int k = 0; k < FRAMES; k++) {
        brate[k] = brates[next_random() % 7];
        q32[k] = (Word16)random_range(0, 15);
        q16[k] = (Word16)random_range(-1, 3);
        fill_signal32(wtda[k], l, random_range(0, q32[k]));
        attack_signal(rec[k], l);
        snprintf(name, sizeof name, "brate%d", k); put1(name, brate[k]);
        snprintf(name, sizeof name, "q32_%d", k); put1(name, q32[k]);
        snprintf(name, sizeof name, "q16_%d", k); put1(name, q16[k]);
        snprintf(name, sizeof name, "wtda%d", k); put32(name, wtda[k], l);
        snprintf(name, sizeof name, "rec%d", k); put16(name, rec[k], l);
    }
    arrow();
    for (int k = 0; k < FRAMES; k++) {
        preecho_sb_fx(brate[k], wtda[k], q32[k], rec[k], q16[k], l, &memfilt, &mean_prev_hb, &smoothmem, &mean_prev,
                      &mean_prev_nc, &wmold_hb, &prevflag, &pastpre, bwidth);
        snprintf(name, sizeof name, "rec%d", k); put16(name, rec[k], l);
        snprintf(name, sizeof name, "state%d", k);
        Word32 st[8] = {memfilt, mean_prev_hb, smoothmem, mean_prev, mean_prev_nc, wmold_hb, prevflag, pastpre};
        put32(name, st, 8);
    }
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "inverse_transform")) case_inverse_transform();
        else if (!strcmp(argv[2], "preecho_sb")) case_preecho_sb();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
