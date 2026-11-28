/* Function-level oracle for lib_com/enhancer_fx.c (enhancer_fx with phase_dispersion_fx, agc2_fx). */
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_com/enhancer_fx.c"

static void random_code(Word16 *code)
{
    int kind = next_random() % 4;
    memset(code, 0, L_SUBFR * sizeof(Word16));
    if (kind < 2) {
        int pulses = random_range(1, 24);
        for (int p = 0; p < pulses; p++) {
            int at = random_range(0, L_SUBFR - 1);
            code[at] = add(code[at], (Word16)((next_random() & 1 ? 4096 : -4096) * random_range(1, 3)));
        }
    } else if (kind == 2) {
        random_signal(code, L_SUBFR, 12000);
    } else {
        for (int i = 0; i < L_SUBFR; i++) code[i] = random16();
    }
}

/* Four consecutive subframes through one dispersion memory and gain threshold. */
static void case_enhancer(void)
{
    static const Word32 rates[] = {6600, 7200, 8000, 8850, 9600, 13200, 12650, 23850};
    struct dispMem_fx dm;
    Word32 gc_threshold = next_random() & 1 ? 0 : (Word32)random_range(0, 1 << 24);
    Word16 opt_amr_wb = (next_random() % 4) == 0;
    Word32 core_brate = rates[next_random() % 8];
    Word16 L_frame = opt_amr_wb ? 256 : (next_random() & 1 ? 256 : 320);
    Word16 Q_exc = (Word16)random_range(0, 12);
    dm.prev_state = (Word16)random_range(0, 2);
    dm.prev_gain_code = (Word32)random_range(0, 1 << 22);
    for (int i = 0; i < 6; i++) dm.prev_gain_pit[i] = (Word16)random_range(0, 19661);
    printf(" calls=4"); put1("core_brate", core_brate); put1("opt_amr_wb", opt_amr_wb);
    put1("L_frame", L_frame); put1("Q_exc", Q_exc); put1("gc_threshold", gc_threshold);
    put1("prev_state", dm.prev_state); put1("prev_gain_code", dm.prev_gain_code);
    put16("prev_gain_pit", dm.prev_gain_pit, 6);
    Word16 exc2[L_FRAME16k];
    Word16 code_out[4][L_SUBFR];
    for (int c = 0; c < 4; c++) {
        Word16 code[L_SUBFR];
        Word16 coder_type = opt_amr_wb ? -1 : (Word16)random_range(0, 5);
        Word16 i_subfr = (Word16)(c * L_SUBFR);
        Word16 voice_fac = (Word16)(next_random() % 8 ? random_range(-32768, 32767) : random16());
        Word16 stab_fac = (Word16)random_range(0, 32767);
        Word32 norm_gain_code = next_random() % 8 ? (Word32)random_range(0, 1 << 24) : (Word32)(next_random() & 0x7fffffff);
        Word16 gain_inov = (Word16)random_range(0, 32767);
        Word16 gain_pit = (Word16)(next_random() % 8 ? random_range(0, 19661) : random_range(0, 32767));
        random_code(code);
        if (c == 0) { random_signal(exc2, L_FRAME16k, 16000); put16("exc2", exc2, L_FRAME16k); }
        char name[32];
        sprintf(name, "coder_type%d", c); put1(name, coder_type);
        sprintf(name, "voice_fac%d", c); put1(name, voice_fac);
        sprintf(name, "stab_fac%d", c); put1(name, stab_fac);
        sprintf(name, "norm_gain_code%d", c); put1(name, norm_gain_code);
        sprintf(name, "gain_inov%d", c); put1(name, gain_inov);
        sprintf(name, "gain_pit%d", c); put1(name, gain_pit);
        sprintf(name, "code%d", c); put16(name, code, L_SUBFR);
        enhancer_fx(core_brate, opt_amr_wb, coder_type, i_subfr, L_frame, voice_fac, stab_fac, norm_gain_code,
                    gain_inov, &gc_threshold, code, exc2, gain_pit, &dm, Q_exc);
        memcpy(code_out[c], code, sizeof(code));
    }
    arrow();
    for (int c = 0; c < 4; c++) { char name[32]; sprintf(name, "code%d", c); put16(name, code_out[c], L_SUBFR); }
    put16("exc2", exc2, L_FRAME16k); put1("gc_threshold", gc_threshold);
    put1("prev_state", dm.prev_state); put1("prev_gain_code", dm.prev_gain_code);
    put16("prev_gain_pit", dm.prev_gain_pit, 6);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "enhancer")) case_enhancer();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
