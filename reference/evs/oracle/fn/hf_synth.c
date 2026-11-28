/* Function-level oracle for lib_dec/hf_synth_fx.c (the 12.8 kHz core's HF synthesis). */
#include "harness.h"
#include "../../c-code/lib_dec/hf_synth_fx.c"

static void case_filt_6k_7k_scale(void)
{
    Word16 signal[L_SUBFR16k], mem[2 * L_FILT16k];
    Word16 fact = (Word16)((next_random() & 3) ? random_range(3277, 32767) : random16());
    Word16 exp = (Word16)random_range(-8, 8);
    random_signal(signal, L_SUBFR16k, (next_random() & 1) ? 32767 : random_range(1, 3000));
    if ((next_random() & 7) == 0) for (int i = 0; i < L_SUBFR16k; i++) signal[i] = random16();
    random_signal(mem, 2 * L_FILT16k, (next_random() & 1) ? 32767 : random_range(1, 3000));
    put16("signal", signal, L_SUBFR16k); put16("mem", mem, 2 * L_FILT16k); put1("fact", fact); put1("exp", exp);
    filt_6k_7k_scale_fx(signal, L_SUBFR16k, mem, fact, exp);
    arrow(); put16("signal", signal, L_SUBFR16k); put16("mem", mem, 2 * L_FILT16k); end_line();
}

static void case_hf_synth_reset(void)
{
    Word16 seed = random16(), mem_hf[2 * L_FILT16k], syn[M], hp400[6], interp[INTERP_3_1_MEM_LEN], delay[20];
    for (int i = 0; i < 2 * L_FILT16k; i++) mem_hf[i] = random16();
    for (int i = 0; i < M; i++) syn[i] = random16();
    for (int i = 0; i < 6; i++) hp400[i] = random16();
    for (int i = 0; i < INTERP_3_1_MEM_LEN; i++) interp[i] = random16();
    for (int i = 0; i < 20; i++) delay[i] = random16();
    put1("seed", seed); put16("mem_hf", mem_hf, 2 * L_FILT16k); put16("syn", syn, M); put16("hp400", hp400, 6);
    put16("interp", interp, INTERP_3_1_MEM_LEN); put16("delay", delay, 20);
    hf_synth_reset_fx(&seed, mem_hf, syn, hp400, interp, delay);
    arrow(); put1("seed", seed); put16("mem_hf", mem_hf, 2 * L_FILT16k); put16("syn", syn, M); put16("hp400", hp400, 6);
    put16("interp", interp, INTERP_3_1_MEM_LEN); put16("delay", delay, 20); end_line();
}

static const Word32 brates[] = {ACELP_7k20, ACELP_8k00, FRAME_NO_DATA, SID_2k40, ACELP_13k20};
static const Word16 out_frames[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k, L_FRAME48k};

/* hf_synthesis_fx is static and reached only through hf_synth_fx, so it is proven here. */
static void case_hf_synth(void)
{
    Word16 aq[NB_SUBFR * (M + 1)], exc[L_FRAME], synth[L_FRAME], synth16k[L_FRAME48k];
    Word16 hp400[6], syn_hf[M], mem_hf[2 * L_FILT16k], delay[20], interp[INTERP_3_1_MEM_LEN];
    Word32 brate = brates[next_random() % 5];
    Word16 out_frame = out_frames[next_random() % 4], q_exc = (Word16)random_range(-1, 8);
    Word16 q_syn2 = (Word16)random_range(-1, 4), seed = random16(), mem_exp1 = (Word16)random_range(-10, 10);
    Word16 extl = (Word16)random_range(0, 5), cng_mode = (Word16)random_range(-1, 3);
    int mag = (next_random() & 1) ? 32767 : random_range(1, 4000);
    for (int k = 0; k < NB_SUBFR; k++) {
        aq[k * (M + 1)] = 4096;
        for (int i = 1; i <= M; i++) aq[k * (M + 1) + i] = (Word16)random_range(-4096 / i, 4096 / i);
    }
    random_signal(exc, L_FRAME, mag);
    if ((next_random() & 15) == 0) for (int i = 0; i < L_FRAME; i++) exc[i] = 0;
    random_signal(synth, L_FRAME, mag);
    random_signal(synth16k, out_frame, mag);
    random_signal(hp400, 6, 8000); random_signal(syn_hf, M, 2000); random_signal(mem_hf, 2 * L_FILT16k, 2000);
    random_signal(delay, 20, 2000); random_signal(interp, INTERP_3_1_MEM_LEN, (next_random() & 1) ? 2000 : 32767);
    put1("brate", brate); put1("out_frame", out_frame); put16("aq", aq, NB_SUBFR * (M + 1)); put16("exc", exc, L_FRAME);
    put16("synth", synth, L_FRAME); put16("synth16k", synth16k, out_frame); put1("seed", seed);
    put16("hp400", hp400, 6); put16("syn_hf", syn_hf, M); put16("mem_hf", mem_hf, 2 * L_FILT16k);
    put1("q_exc", q_exc); put1("q_syn2", q_syn2); put16("delay", delay, 20); put1("mem_exp1", mem_exp1);
    put16("interp", interp, INTERP_3_1_MEM_LEN); put1("extl", extl); put1("cng_mode", cng_mode);
    hf_synth_fx(brate, out_frame, aq, exc, synth, synth16k, &seed, hp400, syn_hf, mem_hf, q_exc, q_syn2, delay,
                &mem_exp1, interp, extl, cng_mode);
    arrow(); put16("synth", synth, L_FRAME); put16("synth16k", synth16k, out_frame); put1("seed", seed);
    put16("hp400", hp400, 6); put16("syn_hf", syn_hf, M); put16("mem_hf", mem_hf, 2 * L_FILT16k);
    put16("delay", delay, 20); put1("mem_exp1", mem_exp1); put16("interp", interp, INTERP_3_1_MEM_LEN); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "filt_6k_7k_scale")) case_filt_6k_7k_scale();
        else if (!strcmp(argv[2], "hf_synth_reset")) case_hf_synth_reset();
        else if (!strcmp(argv[2], "hf_synth")) case_hf_synth();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
