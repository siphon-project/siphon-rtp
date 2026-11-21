/* Function-level oracle for lib_dec/FEC_scale_syn_fx.c (FEC_scale_syn_fx). Each case runs FRAMES
 * consecutive calls carrying the state the function keeps between frames (scaling_flag,
 * lp_ener_FEC_av/max, old_enr_LP, mem_syn), with fresh per-frame inputs. */
#include "harness.h"
#include "prot_fx.h"

#define FRAMES 3
#define LMAX L_FRAME16k
#define NAQ (NB_SUBFR16k * (M + 1))

typedef struct {
    Word16 L_frame, clas, last_good, coder_type, LSF_Q_prediction, bfi, prev_bfi, Q_exc, Q_syn, avoid, force;
    Word32 enr_old, enr_q, total_brate, last_core_brate;
    Word16 synth[LMAX], pitch[NB_SUBFR16k], exc[LMAX], exc2[LMAX], Aq[NAQ], mem_tmp[M];
} Frame;

static Word32 random_energy(void)
{
    switch (next_random() % 6) {
    case 0: return 0;
    case 1: return random_range(1, 3);
    case 2: return random32() & 0x7fffffff;
    default: return (Word32)(next_random() >> random_range(1, 30));
    }
}

static void random_aq(Word16 *aq)
{
    for (int s = 0; s < NB_SUBFR16k; s++) {
        Word16 *a = aq + s * (M + 1);
        a[0] = 4096;
        int mode = random_range(0, 2);
        for (int i = 1; i <= M; i++) a[i] = 0;
        if (mode == 0) { a[1] = (Word16)-random_range(3000, 4090); }           /* resonant low-pass: high tilt */
        else if (mode == 1) { for (int i = 1; i <= M; i++) a[i] = (Word16)random_range(-1500 >> (i / 4), 1500 >> (i / 4)); }
        else { for (int i = 1; i <= M; i++) a[i] = random16(); }               /* hostile */
    }
}

static void random_frame(Frame *f)
{
    static const Word32 brates[] = {7200, 8000, 9600, 11600, 12150, 12850, 13200, 16400, 24400, 32000};
    static const Word32 core_brates[] = {0, 1750, 2400, 7200, 8000, 13200};
    f->L_frame = (next_random() & 1) ? L_FRAME : L_FRAME16k;
    f->clas = (Word16)random_range(0, 6);
    f->last_good = (Word16)random_range(0, 6);
    f->coder_type = (Word16)random_range(0, 5);
    f->LSF_Q_prediction = (Word16)random_range(0, 2);
    f->bfi = (Word16)((next_random() % 4) == 0);
    f->prev_bfi = (Word16)((next_random() % 3) == 0);
    f->Q_exc = (Word16)random_range(-1, 10);
    f->Q_syn = (Word16)random_range(-1, f->Q_exc);
    f->avoid = (Word16)(next_random() & 1);
    f->force = (Word16)((next_random() % 4) == 0);
    f->enr_old = random_energy();
    f->enr_q = (next_random() & 1) ? 0 : random_energy();
    f->total_brate = brates[next_random() % 10];
    f->last_core_brate = core_brates[next_random() % 6];
    int mag = random_range(1, 32767);
    random_signal(f->synth, f->L_frame, mag);
    if ((next_random() % 8) == 0) for (int i = 0; i < f->L_frame; i++) f->synth[i] = 0;
    for (int i = 0; i < NB_SUBFR16k; i++) f->pitch[i] = (Word16)random_range(PIT_MIN, f->L_frame == L_FRAME ? PIT_MAX : PIT16k_MAX); /* Q0 */
    random_signal(f->exc, f->L_frame, random_range(1, 32767));
    random_signal(f->exc2, f->L_frame, random_range(1, 32767));
    if ((next_random() % 8) == 0) for (int i = 0; i < f->L_frame; i++) { f->exc[i] = random16(); f->exc2[i] = random16(); }
    random_aq(f->Aq);
    random_signal(f->mem_tmp, M, random_range(1, 32767));
}

static void put_frame(int k, const Frame *f)
{
    char name[32];
#define P1(field) snprintf(name, sizeof name, #field "%d", k); put1(name, f->field)
#define PV(field, n) snprintf(name, sizeof name, #field "%d", k); put16(name, f->field, n)
    P1(L_frame); P1(clas); P1(last_good); P1(coder_type); P1(LSF_Q_prediction); P1(bfi); P1(prev_bfi);
    P1(Q_exc); P1(Q_syn); P1(avoid); P1(force); P1(enr_old); P1(enr_q); P1(total_brate); P1(last_core_brate);
    PV(synth, f->L_frame); PV(pitch, NB_SUBFR16k); PV(exc, f->L_frame); PV(exc2, f->L_frame); PV(Aq, NAQ);
    PV(mem_tmp, M);
#undef P1
#undef PV
}

static void case_fec_scale_syn(void)
{
    Frame f[FRAMES];
    Word16 scaling_flag = (Word16)random_range(0, 2), old_enr_LP = (Word16)random_range(0, 2000), mem_syn[M];
    Word32 lp_av = random_energy(), lp_max = random_energy();
    random_signal(mem_syn, M, 1000);
    for (int k = 0; k < FRAMES; k++) random_frame(&f[k]);
    put1("scaling_flag", scaling_flag); put1("old_enr_LP", old_enr_LP); put1("lp_av", lp_av); put1("lp_max", lp_max);
    put16("mem_syn", mem_syn, M);
    for (int k = 0; k < FRAMES; k++) put_frame(k, &f[k]);
    Word16 update[FRAMES], sf[FRAMES], oe[FRAMES], ms[FRAMES][M];
    Word32 av[FRAMES], mx[FRAMES];
    Flag carry[FRAMES];
    for (int k = 0; k < FRAMES; k++) {
        Carry = 0;
        FEC_scale_syn_fx(f[k].L_frame, &update[k], f[k].clas, f[k].last_good, f[k].synth, f[k].pitch, f[k].enr_old,
                         f[k].enr_q, f[k].coder_type, f[k].LSF_Q_prediction, &scaling_flag, &lp_av, &lp_max, f[k].bfi,
                         f[k].total_brate, f[k].prev_bfi, f[k].last_core_brate, f[k].exc, f[k].exc2, f[k].Aq, &old_enr_LP,
                         f[k].mem_tmp, mem_syn, f[k].Q_exc, f[k].Q_syn, f[k].avoid, f[k].force);
        update[k] = update[k]; sf[k] = scaling_flag; oe[k] = old_enr_LP; av[k] = lp_av; mx[k] = lp_max; carry[k] = Carry;
        memcpy(ms[k], mem_syn, sizeof mem_syn);
    }
    arrow();
    char name[32];
    for (int k = 0; k < FRAMES; k++) {
        snprintf(name, sizeof name, "update%d", k); put1(name, update[k]);
        snprintf(name, sizeof name, "scaling_flag%d", k); put1(name, sf[k]);
        snprintf(name, sizeof name, "old_enr_LP%d", k); put1(name, oe[k]);
        snprintf(name, sizeof name, "lp_av%d", k); put1(name, av[k]);
        snprintf(name, sizeof name, "lp_max%d", k); put1(name, mx[k]);
        snprintf(name, sizeof name, "carry%d", k); put1(name, carry[k]);
        snprintf(name, sizeof name, "mem_syn%d", k); put16(name, ms[k], M);
        snprintf(name, sizeof name, "synth%d", k); put16(name, f[k].synth, f[k].L_frame);
        snprintf(name, sizeof name, "exc%d", k); put16(name, f[k].exc, f[k].L_frame);
        snprintf(name, sizeof name, "exc2%d", k); put16(name, f[k].exc2, f[k].L_frame);
    }
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "fec_scale_syn")) case_fec_scale_syn();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
