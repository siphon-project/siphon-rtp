/* Function-level oracle for lib_dec/dec_nelp_fx.c: decod_nelp_fx, over a sequence of good and
 * lost frames (nelp_common.h); each frame's outputs are printed (prefix "f<k>.") and the whole
 * state after the sequence is compared. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "nelp_common.h"

static void case_decod_nelp(void)
{
    NelpSequence seq;
    char *before;
    Decoder_State_fx *st = nelp_setup(&seq, &before);
    Word16 exc_buf[L_SUBFR + L_FRAME], exc2[L_FRAME], pitch_buf[NB_SUBFR16k], voice_factors[NB_SUBFR16k];
    Word16 bwe_exc[L_FRAME * 5 / 2 + 8], gain_buf[NB_SUBFR16k], tmp_noise;
    Word16 q_exc = seq.q_exc;
    char key[32];

    memcpy(exc_buf, seq.exc_history, sizeof(seq.exc_history));
    arrow();
    for (int f = 0; f < seq.frames; f++) {
        for (int i = 0; i < NB_SUBFR16k; i++) { gain_buf[i] = -1; pitch_buf[i] = -1; voice_factors[i] = -1; }
        for (int i = 0; i < L_FRAME * 5 / 2 + 8; i++) bwe_exc[i] = -1;
        tmp_noise = -1;
        decod_nelp_fx(st, seq.coder_type, &tmp_noise, pitch_buf, exc_buf + L_SUBFR, exc2, voice_factors, bwe_exc, &q_exc,
                      seq.bfi[f], gain_buf);
        sprintf(key, "f%d.exc", f); put16(key, exc_buf + L_SUBFR, L_FRAME);
        sprintf(key, "f%d.exc2", f); put16(key, exc2, L_FRAME);
        sprintf(key, "f%d.q_exc", f); put1(key, q_exc);
        sprintf(key, "f%d.tmp_noise", f); put1(key, tmp_noise);
        sprintf(key, "f%d.pitch_buf", f); put16(key, pitch_buf, NB_SUBFR16k);
        sprintf(key, "f%d.voice_factors", f); put16(key, voice_factors, NB_SUBFR16k);
        sprintf(key, "f%d.bwe_exc", f); put16(key, bwe_exc, L_FRAME * 5 / 2 + 8);
        sprintf(key, "f%d.gain_buf", f); put16(key, gain_buf, NB_SUBFR16k);
        if (f + 1 < seq.frames) nelp_next_frame(st, exc_buf);
    }
    nelp_finish(st, before);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    if (strcmp(argv[2], "decod_nelp")) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) case_decod_nelp();
    return 0;
}
