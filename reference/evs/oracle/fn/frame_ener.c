/* Function-level oracle for lib_com/frame_ener_fx.c. */
#include "harness.h"
#include "prot_fx.h"

static void case_frame_energy(void)
{
    Word16 speech[L_FRAME16k], pitch[4], frame_ener;
    Word16 l_frame = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    Word16 max_pitch = l_frame == L_FRAME ? PIT_MAX : PIT16k_MAX, min_pitch = l_frame == L_FRAME ? PIT_MIN : PIT16k_MIN;
    Word16 q_syn = (Word16)random_range(-1, 8), lp_speech = (Word16)random_range(0, 20000);
    for (int i = 0; i < 4; i++) pitch[i] = (Word16)random_range(min_pitch * 64, max_pitch * 64);
    random_signal(speech, l_frame, (next_random() & 3) ? 32767 : random_range(1, 300));
    if ((next_random() & 15) == 0) for (int i = 0; i < l_frame; i++) speech[i] = 0;
    put1("l_frame", l_frame); put16("pitch", pitch, 4); put16("speech", speech, l_frame);
    put1("lp_speech", lp_speech); put1("q_syn", q_syn);
    Word16 r = frame_energy_fx(l_frame, pitch, speech, lp_speech, &frame_ener, q_syn);
    arrow(); put1("r", r); put1("frame_ener", frame_ener); end_line();
}

static const Word16 frames_all[] = {L_FRAME, L_FRAME16k, L_FRAME32k, L_FRAME48k};

static void case_frame_ener(void)
{
    Word16 synth[L_FRAME48k];
    Word32 enr_q;
    Word16 enc = (Word16)((next_random() % 4) == 0);
    Word16 l_frame = enc ? frames_all[next_random() % 2] : frames_all[next_random() % 4];
    Word16 clas = (Word16)random_range(0, 6), pitch = (Word16)random_range(17, l_frame == L_FRAME ? PIT_MAX : PIT16k_MAX);
    Word16 offset = (Word16)(next_random() % 3 == 0 ? 0 : (next_random() & 1) ? 1 : l_frame);
    Word16 q_new = (Word16)random_range(-1, 8), shift = (Word16)((next_random() & 1) ? 3 : 0);
    if (!enc && (next_random() & 3) == 0) { q_new = 0; shift = 0; }
    random_signal(synth, l_frame, (next_random() & 1) ? 32767 : random_range(1, 4000));
    if ((next_random() & 3) == 0) for (int i = 0; i < l_frame; i++) synth[i] = (Word16)((next_random() & 1) ? 32767 : -32768);
    if ((next_random() & 15) == 0) for (int i = 0; i < l_frame; i++) synth[i] = 0;
    put1("l_frame", l_frame); put1("clas", clas); put16("synth", synth, l_frame); put1("pitch", pitch);
    put1("offset", offset); put1("q_new", q_new); put1("shift", shift); put1("enc", enc);
    Word16 r = frame_ener_fx(l_frame, clas, synth, pitch, &enr_q, offset, q_new, shift, enc);
    arrow(); put1("r", r); put1("enr_q", enr_q); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "frame_energy")) case_frame_energy();
        else if (!strcmp(argv[2], "frame_ener")) case_frame_ener();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
