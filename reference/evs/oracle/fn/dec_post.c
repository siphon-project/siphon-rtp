/* Function-level oracle for lib_dec/dec_post.c: nb_post_filt over consecutive frames (Dec_postfilt,
 * pst_ltp, search_del, compute_ltp_l, select_ltp, filt_plt, calc_st_filt, Filt_mu, scale_st), and
 * pst_ltp, modify_pst_param, Filt_mu and scale_st on their own. */
#include <math.h>
#include "harness.h"
#include "prot_fx.h"
#include "../../c-code/lib_dec/dec_post.c"

/* A stable order-16 A(z) in Q12 from random reflection coefficients (step-up recursion), or now
 * and then an arbitrary one, so the filters see both real and saturating coefficient sets. */
static void random_lpc(Word16 *a)
{
    double k[M], c[M + 1], t[M + 1];
    if (next_random() % 8 == 0) {
        a[0] = 4096;
        for (int i = 1; i <= M; i++) a[i] = (Word16)random_range(-12000, 12000);
        return;
    }
    for (int i = 0; i < M; i++) k[i] = ((int)(next_random() % 1801) - 900) / 1000.0 * (i < 2 ? 1.0 : 0.6);
    c[0] = 1.0;
    for (int m = 1; m <= M; m++) {
        for (int i = 1; i < m; i++) t[i] = c[i] + k[m - 1] * c[m - i];
        for (int i = 1; i < m; i++) c[i] = t[i];
        c[m] = k[m - 1];
    }
    a[0] = 4096;
    for (int i = 1; i <= M; i++) {
        double v = c[i] * 4096.0;
        a[i] = (Word16)(v > 32767 ? 32767 : v < -32768 ? -32768 : lrint(v));
    }
}

static void random_pfstat(PFSTAT *pf)
{
    Init_post_filter(pf);
    if (next_random() % 4 == 0) return; /* fresh state */
    int mag = next_random() & 1 ? 20000 : 2000;
    random_signal(pf->mem_pf_in, L_SUBFR, mag);
    random_signal(pf->mem_stp, L_SUBFR, mag);
    random_signal(pf->mem_res2, DECMEM_RES2, mag);
    pf->gain_prec = (Word16)random_range(0, 20000);
    pf->reset = (Word16)(next_random() % 8 == 0);
}

static void put_pfstat(PFSTAT *pf)
{
    put1("reset", pf->reset); put16("mem_pf_in", pf->mem_pf_in, L_SUBFR); put16("mem_stp", pf->mem_stp, L_SUBFR);
    put16("mem_res2", pf->mem_res2, DECMEM_RES2); put1("gain_prec", pf->gain_prec);
}

static void case_nb_post_filt(void)
{
    PFSTAT pf;
    Word16 L_frame = next_random() & 1 ? L_FRAME : L_FRAME16k;
    Word16 nb_subfr = L_frame / L_SUBFR;
    Word16 pit_max = L_frame == L_FRAME ? 231 : 289;
    Word16 psf_lp_noise = (Word16)(next_random() & 1 ? random_range(0, 8000) : random_range(0, 32767));
    Word16 disable_hpf = (Word16)(next_random() % 8 == 0);
    random_pfstat(&pf);
    put1("L_frame", L_frame); put1("psf_lp_noise", psf_lp_noise); put1("disable_hpf", disable_hpf);
    put_pfstat(&pf);
    Word16 synth_out[3][L_FRAME16k];
    for (int f = 0; f < 3; f++) {
        Word16 synth[L_FRAME16k], Aq[NB_SUBFR16k * (M + 1)], pitch[NB_SUBFR16k];
        Word16 tmp_noise = (Word16)random_range(0, 2000);
        Word16 coder_type = (Word16)random_range(0, 5);
        Word16 ber = (Word16)(next_random() % 8 == 0);
        random_signal(synth, L_frame, next_random() & 1 ? 30000 : (next_random() & 1 ? 3000 : 100));
        if (next_random() % 16 == 0) memset(synth, 0, sizeof(synth));
        for (int s = 0; s < nb_subfr; s++) {
            random_lpc(&Aq[s * (M + 1)]);
            pitch[s] = (Word16)random_range(17, pit_max);
        }
        if (f == 1 && next_random() % 8 == 0) pf.reset = 1;
        char name[32];
        sprintf(name, "synth%d", f); put16(name, synth, L_frame);
        sprintf(name, "Aq%d", f); put16(name, Aq, nb_subfr * (M + 1));
        sprintf(name, "pitch%d", f); put16(name, pitch, nb_subfr);
        sprintf(name, "tmp_noise%d", f); put1(name, tmp_noise);
        sprintf(name, "coder_type%d", f); put1(name, coder_type);
        sprintf(name, "ber%d", f); put1(name, ber);
        sprintf(name, "reset%d", f); put1(name, pf.reset);
        nb_post_filt(L_frame, &pf, &psf_lp_noise, tmp_noise, synth, Aq, pitch, coder_type, ber, disable_hpf);
        memcpy(synth_out[f], synth, sizeof(synth));
    }
    arrow();
    for (int f = 0; f < 3; f++) { char name[16]; sprintf(name, "synth%d", f); put16(name, synth_out[f], L_frame); }
    put1("psf_lp_noise", psf_lp_noise); put_pfstat(&pf);
    end_line();
}

/* formant_post_filt over three consecutive frames on one PFSTAT: both frame lengths, the rate and
 * noise-level branches, loud subframes (the half-scale path), the off flag and the reset. */
static void case_formant_post_filt(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 13200, 15850, 16400, 24400, 32000, 64000};
    static const Word32 noises[] = {0, 1000, 167772159, 167772160, 167772161, 2000000000};
    PFSTAT pf;
    Word16 L_frame = next_random() & 1 ? L_FRAME : L_FRAME16k;
    Word16 nb_subfr = L_frame / L_SUBFR;
    random_pfstat(&pf);
    put1("L_frame", L_frame); put_pfstat(&pf);
    Word16 history[3][L_SYN_MEM], out[3][L_FRAME16k];
    for (int f = 0; f < 3; f++) {
        Word16 temp_buf[L_FRAME16k + L_SYN_MEM], Aq[NB_SUBFR16k * (M + 1)];
        Word32 lp_noise = next_random() % 3 ? noises[next_random() % 6] : (Word32)(next_random() & 0x7fffffff);
        Word32 rate = rates[next_random() % 9];
        Word16 off_flag = (Word16)(next_random() % 6 == 0);
        int mag = next_random() % 3 == 0 ? 32767 : next_random() & 1 ? 12000 : 200;
        random_signal(temp_buf, L_FRAME16k + L_SYN_MEM, mag);
        if (f == 1 && next_random() % 6 == 0) pf.reset = 1;
        for (int s = 0; s < nb_subfr; s++) random_lpc(&Aq[s * (M + 1)]);
        char name[32];
        sprintf(name, "synth%d", f); put16(name, temp_buf + L_SYN_MEM, L_frame);
        sprintf(name, "Aq%d", f); put16(name, Aq, nb_subfr * (M + 1));
        sprintf(name, "lp_noise%d", f); put1(name, lp_noise);
        sprintf(name, "rate%d", f); put1(name, rate);
        sprintf(name, "off_flag%d", f); put1(name, off_flag);
        sprintf(name, "reset%d", f); put1(name, pf.reset);
        sprintf(name, "history%d", f); put16(name, temp_buf, L_SYN_MEM);
        formant_post_filt(&pf, temp_buf + L_SYN_MEM, Aq, out[f], L_frame, lp_noise, rate, off_flag);
        memcpy(history[f], temp_buf, sizeof(history[f]));
    }
    arrow();
    for (int f = 0; f < 3; f++) {
        char name[16];
        sprintf(name, "out%d", f); put16(name, out[f], L_frame);
        sprintf(name, "history%d", f); put16(name, history[f], L_SYN_MEM);
    }
    put_pfstat(&pf);
    end_line();
}

static void case_pst_ltp(void)
{
    Word16 res2[DECMEM_RES2 + L_SUBFR], out[L_SUBFR];
    Word16 t0 = (Word16)(next_random() % 8 ? random_range(17, 289) : random_range(9, 290));
    Word16 gain_factor = (Word16)random_range(0, 32767);
    int kind = next_random() % 4;
    if (kind == 0) {
        /* a periodic residual, so the pitch search finds something */
        Word16 period[300];
        random_signal(period, t0, 20000);
        for (int i = 0; i < DECMEM_RES2 + L_SUBFR; i++) res2[i] = add(period[i % t0], (Word16)random_range(-500, 500));
    } else if (kind == 1) {
        for (int i = 0; i < DECMEM_RES2 + L_SUBFR; i++) res2[i] = random16();
    } else {
        random_signal(res2, DECMEM_RES2 + L_SUBFR, next_random() & 1 ? 30000 : 300);
    }
    put1("t0", t0); put1("gain_factor", gain_factor); put16("res2", res2, DECMEM_RES2 + L_SUBFR);
    pst_ltp(t0, res2 + DECMEM_RES2, out, gain_factor);
    arrow(); put16("out", out, L_SUBFR); end_line();
}

static void case_modify_pst_param(void)
{
    Word16 lp_noise = (Word16)(next_random() & 1 ? random_range(0, 8000) : random16());
    Word16 coder_type = (Word16)random_range(0, 5), g1 = -1, g2 = -1, gain_factor = -1;
    put1("lp_noise", lp_noise); put1("coder_type", coder_type);
    modify_pst_param(lp_noise, &g1, &g2, coder_type, &gain_factor);
    arrow(); put1("g1", g1); put1("g2", g2); put1("gain_factor", gain_factor); end_line();
}

static void case_filt_mu(void)
{
    Word16 in[L_SUBFR + 1], out[L_SUBFR];
    Word16 parcor0 = random16();
    random_signal(in, L_SUBFR + 1, next_random() & 1 ? 32767 : 3000);
    put16("in", in, L_SUBFR + 1); put1("parcor0", parcor0);
    Filt_mu(in, out, parcor0, L_SUBFR);
    arrow(); put16("out", out, L_SUBFR); end_line();
}

static void case_scale_st(void)
{
    Word16 in[L_SUBFR], out[L_SUBFR];
    Word16 gain_prec = (Word16)random_range(0, 20000);
    random_signal(in, L_SUBFR, next_random() & 1 ? 32767 : 300);
    random_signal(out, L_SUBFR, next_random() & 1 ? 32767 : 300);
    if (next_random() % 8 == 0) memset(in, 0, sizeof(in));
    if (next_random() % 8 == 0) memset(out, 0, sizeof(out));
    put16("in", in, L_SUBFR); put16("out", out, L_SUBFR); put1("gain_prec", gain_prec);
    scale_st(in, out, &gain_prec, L_SUBFR);
    arrow(); put16("out", out, L_SUBFR); put1("gain_prec", gain_prec); end_line();
}

static void case_select_ltp(void)
{
    Word16 num1 = (Word16)random_range(0, 32767), den1 = (Word16)random_range(0, 32767);
    Word16 sh_num1 = (Word16)random_range(0, 16), sh_den1 = (Word16)random_range(0, 16);
    Word16 num2 = (Word16)random_range(0, 32767), den2 = (Word16)random_range(0, 32767);
    Word16 sh_num2 = (Word16)random_range(0, 16), sh_den2 = (Word16)random_range(0, 16);
    int kind = next_random() % 4;
    if (kind == 0) { num2 = num1; den2 = den1; sh_num2 = sh_num1; sh_den2 = sh_den1; } /* a tie */
    if (kind == 1) den2 = 0;
    put1("num1", num1); put1("den1", den1); put1("sh_num1", sh_num1); put1("sh_den1", sh_den1);
    put1("num2", num2); put1("den2", den2); put1("sh_num2", sh_num2); put1("sh_den2", sh_den2);
    Word16 r = select_ltp(num1, den1, sh_num1, sh_den1, num2, den2, sh_num2, sh_den2);
    arrow(); put1("r", r); end_line();
}

static void case_blend_subfr2(void)
{
    Word16 in1[L_SUBFR / 2], in2[L_SUBFR / 2], out[L_SUBFR / 2];
    random_signal(in1, L_SUBFR / 2, next_random() & 1 ? 32767 : 3000);
    random_signal(in2, L_SUBFR / 2, next_random() & 1 ? 32767 : 3000);
    if (next_random() % 4 == 0) for (int i = 0; i < L_SUBFR / 2; i++) { in1[i] = random16(); in2[i] = random16(); }
    put16("in1", in1, L_SUBFR / 2); put16("in2", in2, L_SUBFR / 2);
    blend_subfr2(in1, in2, out);
    arrow(); put16("out", out, L_SUBFR / 2); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "nb_post_filt")) case_nb_post_filt();
        else if (!strcmp(argv[2], "formant_post_filt")) case_formant_post_filt();
        else if (!strcmp(argv[2], "pst_ltp")) case_pst_ltp();
        else if (!strcmp(argv[2], "modify_pst_param")) case_modify_pst_param();
        else if (!strcmp(argv[2], "filt_mu")) case_filt_mu();
        else if (!strcmp(argv[2], "scale_st")) case_scale_st();
        else if (!strcmp(argv[2], "select_ltp")) case_select_ltp();
        else if (!strcmp(argv[2], "blend_subfr2")) case_blend_subfr2();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
