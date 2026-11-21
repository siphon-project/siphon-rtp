/* Function-level oracle for lib_dec/nelp_dec_fx.c: nelp_decoder_fx and the file-local
 * normalize_arr.
 *
 * nelp_decoder_fx runs over a sequence of good and lost frames (nelp_common.h), every NELP
 * bandwidth and coder type, the bit-stream and the RF partial-copy gain indices; each frame's
 * outputs are printed (prefix "f<k>.") and the whole state after the sequence is compared. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#include "nelp_common.h"
#include "../../c-code/lib_dec/nelp_dec_fx.c"

static void case_normalize_arr(void)
{
    Word16 arr[10], qf = 0, size = (Word16)random_range(1, 10), hdr = (Word16)random_range(0, 6);
    int mode = next_random() % 4;
    for (int i = 0; i < size; i++)
        arr[i] = mode == 0 ? random16() : mode == 1 ? (Word16)random_range(-300, 300) : mode == 2 ? 0 : (Word16)random_range(0, 32767 >> random_range(0, 14));
    put16("arr", arr, size); put1("size", size); put1("hdr", hdr);
    normalize_arr(arr, &qf, size, hdr);
    arrow(); put16("arr", arr, size); put1("qf", qf); end_line();
}

static void case_nelp_decoder(void)
{
    NelpSequence seq;
    char *before;
    Decoder_State_fx *st = nelp_setup(&seq, &before);
    Word16 exc_buf[L_SUBFR + L_FRAME], exc_nelp[L_FRAME], gain_buf[NB_SUBFR16k];
    Word16 q_exc = seq.q_exc;
    char key[32];

    memcpy(exc_buf, seq.exc_history, sizeof(seq.exc_history));
    arrow();
    for (int f = 0; f < seq.frames; f++) {
        for (int i = 0; i < NB_SUBFR16k; i++) gain_buf[i] = -1;
        nelp_decoder_fx(st, exc_nelp, exc_buf + L_SUBFR, &q_exc, seq.bfi[f], seq.coder_type, gain_buf);
        sprintf(key, "f%d.exc_nelp", f); put16(key, exc_nelp, L_FRAME);
        sprintf(key, "f%d.q_exc", f); put1(key, q_exc);
        sprintf(key, "f%d.gain_buf", f); put16(key, gain_buf, NB_SUBFR16k);
        memcpy(exc_buf + L_SUBFR, exc_nelp, sizeof(exc_nelp));
        if (f + 1 < seq.frames) nelp_next_frame(st, exc_buf);
    }
    nelp_finish(st, before);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "normalize_arr")) case_normalize_arr();
        else if (!strcmp(argv[2], "nelp_decoder")) case_nelp_decoder();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
