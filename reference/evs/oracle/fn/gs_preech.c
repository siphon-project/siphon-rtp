/* Function-level oracle for lib_com/gs_preech_fx.c (pre_echo_att_fx). */
#include "harness.h"
#include "prot_fx.h"

static void case_pre_echo_att(void)
{
    Word16 exc[L_FRAME];
    /* A quiet start and an onset at a random section, the shape the attack path is for; or plain
     * excitation. */
    int onset = random_range(0, L_FRAME - 1);
    int quiet = 1 << random_range(0, 10), loud = 1 << random_range(6, 15);
    if (next_random() % 4) {
        random_signal(exc, onset, quiet);
        random_signal(exc + onset, L_FRAME - onset, loud);
    } else if (next_random() & 1) {
        for (int i = 0; i < L_FRAME; i++) exc[i] = random16();
    } else random_signal(exc, L_FRAME, loud);
    Word16 attack = (Word16)(next_random() % 4 ? 1 : 0);
    Word16 last_coder_type = (Word16)(next_random() % 4 ? AUDIO : GENERIC);
    Word16 q_new = (Word16)random_range(0, 10);
    Word32 last_ener = (next_random() & 1) ? random_range(0, 1 << random_range(0, 30)) : random_range(0, 64);
    put16("exc", exc, L_FRAME); put1("attack", attack); put1("last_coder_type", last_coder_type);
    put1("q_new", q_new); put1("last_ener", last_ener);
    pre_echo_att_fx(&last_ener, exc, attack, q_new, last_coder_type);
    arrow(); put16("exc", exc, L_FRAME); put1("last_ener", last_ener); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "pre_echo_att")) case_pre_echo_att();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
