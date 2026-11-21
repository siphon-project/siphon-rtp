/* Function-level oracle for lib_com/env_stab_fx.c: env_stability_fx (norm vectors with large steps and
 * a large smoothing memory reach the saturated Overflow branch; both nb_sfm values the decoder uses
 * plus others) and env_stab_smo_fx (state probabilities and stability values the decoder produces,
 * and arbitrary ones). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

/* env_delta (Q13) and the pre-shift accumulator exactly as env_stability_fx forms them for a
 * norm step of `step` in every band (nb_sfm = 26, mem_env_delta = m). */
static Word32 accumulator(Word16 step, Word16 m, Word16 *env_delta_q13)
{
    Word32 l_env_delta = L_deposit_l(0), l_tmp;
    Word16 exp, exp2, env_delta;
    for (int i = 0; i < 26; i++) l_env_delta = L_mac0(l_env_delta, step, step);
    exp = norm_l(l_env_delta);
    l_env_delta = Mult_32_16(L_shl(l_env_delta, exp), 20165);
    l_tmp = Sqrt_l(l_env_delta, &exp2);
    exp = add(35, add(exp, exp2));
    if (sub(s_and(exp, 1), 1) == 0) l_tmp = Mult_32_16(l_tmp, 23170);
    exp = shr(exp, 1);
    env_delta = round_fx(L_shl(l_tmp, sub(26, exp)));
    l_tmp = L_mult0(26214, env_delta);
    l_tmp = L_mac(l_tmp, 29491, m);
    Overflow = 0;
    *env_delta_q13 = round_fx(L_shl(l_tmp, 1));
    return l_tmp;
}

/* Inputs steered to a boundary of env_stability_fx: either the L_shl(L_tmp, 1) + 0x8000 window just
 * below saturation (Overflow set by the rounding only), or an env_delta (Q13) landing exactly on a
 * lookup threshold M +- (D/2 + k*D) or on M itself. Falls back to a plain case if nothing is found. */
static int steered(Word16 *ynrm, Word16 *mem_norm, Word16 *mem_env_delta)
{
    int kind = next_random() % 2;
    Word16 step = (Word16)random_range(1, 39), target_k = (Word16)random_range(-1, 9), sign = (Word16)(next_random() & 1 ? 1 : -1);
    for (int tries = 0; tries < 40; tries++, step = (Word16)random_range(1, 39)) {
        Word16 first = -1, found[40], count = 0;
        for (int m = 0; m < 32768 && count < 40; m++) {
            Word16 env_delta;
            Word32 l_tmp = accumulator(step, (Word16)m, &env_delta);
            Word32 headroom = L_sub(0x7fffffff, l_tmp);
            if (kind == 0) {
                /* window: l_tmp*2 does not saturate (l_tmp <= 0x3fffffff) but l_tmp*2 + 0x8000 does */
                if (l_tmp <= 0x3fffffff && L_shl(l_tmp, 1) > 0x7fff7fff) found[count++] = (Word16)m;
            } else {
                Word16 delta = target_k < 0 ? 0 : (Word16)(HALF_D_STAB_TBL_FX + target_k * D_STAB_TBL_FX);
                Word16 want = target_k < 0 ? M_STAB_TBL_FX : (Word16)(M_STAB_TBL_FX + sign * delta);
                if (env_delta == want && headroom > 0) found[count++] = (Word16)m;
            }
            (void)first;
        }
        if (count) {
            *mem_env_delta = found[next_random() % count];
            for (int i = 0; i < 27; i++) {
                ynrm[i] = (Word16)random_range(step, 39);
                mem_norm[i] = (Word16)(ynrm[i] - step);
            }
            return 1;
        }
    }
    return 0;
}

static void case_env_stability(void)
{
    Word16 ynrm[27], mem_norm[27], mem_env_delta, result;
    static const Word16 sizes[] = {26, 27, 26, 27, 10, 1, 20};
    Word16 nb_sfm = sizes[next_random() % 7];
    int mode = next_random() % 4;
    int steer = next_random() % 3 == 0 && steered(ynrm, mem_norm, &mem_env_delta);
    if (steer) nb_sfm = 26;
    for (int i = 0; i < 27 && !steer; i++) {
        if (mode == 0) { ynrm[i] = (Word16)random_range(0, 39); mem_norm[i] = (Word16)random_range(0, 39); }
        else if (mode == 1) { ynrm[i] = (Word16)random_range(10, 14); mem_norm[i] = (Word16)(ynrm[i] + random_range(-1, 1)); }
        else if (mode == 2) { ynrm[i] = (Word16)(next_random() & 1 ? 0 : 39); mem_norm[i] = (Word16)(next_random() & 1 ? 0 : 39); }
        else { ynrm[i] = (Word16)random_range(0, 39); mem_norm[i] = ynrm[i]; }
    }
    if (!steer) {
        mem_env_delta = (Word16)(next_random() % 3 == 0 ? random_range(28000, 32767) : next_random() % 3 == 0 ? random_range(0, 400) : random_range(0, 32767));
        if (next_random() % 20 == 0) mem_env_delta = random16();
    }
    put16("ynrm", ynrm, 27); put1("nb_sfm", nb_sfm); put16("mem_norm", mem_norm, 27); put1("mem_env_delta", mem_env_delta);
    result = env_stability_fx(ynrm, nb_sfm, mem_norm, &mem_env_delta);
    arrow(); put1("result", result); put16("mem_norm", mem_norm, 27); put1("mem_env_delta", mem_env_delta); end_line();
}

static void case_env_stab_smo(void)
{
    Word16 p[NUM_ENV_STAB_PLC_STATES], env_stab, ho_cnt, pa0, pa1, pp1, sum;
    for (;;) {
        int mode = next_random() % 3;
        if (mode == 0) env_stab = stab_trans_fx[next_random() % L_STAB_TBL];
        else if (mode == 1) env_stab = sub(32767, stab_trans_fx[next_random() % L_STAB_TBL]);
        else env_stab = (Word16)random_range(stab_trans_fx[L_STAB_TBL - 1], 32767);
        if (next_random() % 2) {
            p[0] = (Word16)random_range(0, 32767); p[1] = sub(32767, p[0]);
        } else { p[0] = (Word16)random_range(0, 32767); p[1] = (Word16)random_range(0, 32767); }
        /* the sum the reference renormalises by must be positive (div_s) */
        Word16 tmp = round_fx(L_shl(L_mult(sub(env_stab, stab_trans_fx[L_STAB_TBL - 1]), INV_STAB_TRANS_FX), 1));
        pa0 = round_fx(Dot_product(env_stab_tp_fx[0], p, NUM_ENV_STAB_PLC_STATES));
        pa1 = round_fx(Dot_product(env_stab_tp_fx[1], p, NUM_ENV_STAB_PLC_STATES));
        pp1 = tmp;
        sum = add(mult_r(pa0, sub(32767, tmp)), mult_r(pa1, pp1));
        if (sum > 0) break;
    }
    ho_cnt = (Word16)random_range(0, 10);
    Word16 state;
    put1("env_stab", env_stab); put16("p", p, NUM_ENV_STAB_PLC_STATES); put1("ho_cnt", ho_cnt);
    state = env_stab_smo_fx(env_stab, p, &ho_cnt);
    arrow(); put1("state", state); put16("p", p, NUM_ENV_STAB_PLC_STATES); put1("ho_cnt", ho_cnt); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "env_stability")) case_env_stability();
        else if (!strcmp(argv[2], "env_stab_smo")) case_env_stab_smo();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
