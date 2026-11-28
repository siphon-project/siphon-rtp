/* Function-level oracle for lib_dec/LD_music_post_filter_fx.c. spectrum_mod_dct_fx, analy_sp_dct_fx,
 * find_enr_dct_fx and norm_lfe are static and proven through LD_music_post_filter_fx, run over
 * consecutive frames carrying every memory (the stability estimate needs a history to reach the
 * music branches). Prep_music_postP_fx and Post_music_postP_fx are run on their own. */
#include "harness.h"
#include "prot_fx.h"

#define FRAMES 4
#define DCT DCT_L_POST

static void put_named16(const char *base, int k, const Word16 *x, int n)
{
    char name[40]; snprintf(name, sizeof name, "%s%d", base, k); put16(name, x, n);
}
static void put_named32(const char *base, int k, const Word32 *x, int n)
{
    char name[40]; snprintf(name, sizeof name, "%s%d", base, k); put32(name, x, n);
}
static void put_named1(const char *base, int k, long long v)
{
    char name[40]; snprintf(name, sizeof name, "%s%d", base, k); put1(name, v);
}

/* A music-like DCT: a few strong partials over a noise floor whose level drifts slowly. */
static void random_dct(Word16 *x, int level)
{
    int mode = random_range(0, 4);
    if (mode == 4) { for (int i = 0; i < DCT; i++) x[i] = random16(); return; }
    if (mode == 3) { for (int i = 0; i < DCT; i++) x[i] = 0; return; }
    for (int i = 0; i < DCT; i++) x[i] = (Word16)random_range(-level / 16 - 1, level / 16 + 1);
    int partials = random_range(0, 30);
    for (int p = 0; p < partials; p++) x[random_range(0, DCT - 1)] = (Word16)random_range(-level, level);
    if (mode == 2) random_signal(x, DCT, level);
}

static void case_ld_music_post_filter(void)
{
    static const Word32 brates[] = {6600, 7200, 8000, 8850, 9600, 12650, 13200, 15850, 16400, 23850};
    Word16 last_music_flag = (Word16)random_range(0, 4), thresh[4], nb_thr_1 = (Word16)random_range(0, 35);
    Word16 nb_thr_3 = (Word16)random_range(0, 35), lt_diff_etot[MAX_LT], mem_etot = (Word16)random_range(-2000, 20000);
    Word32 bckr[MBANDS_GN_LD], lf_EO[DCT];
    Word16 lp_gbin[DCT], filt_lfE[DCT], last_nonfull_music = (Word16)random_range(0, 51), old_ener_q = (Word16)random_range(-1, 8);
    Word16 min_ns_gain = (next_random() & 1) ? 8231 : (Word16)random_range(1000, 32767);
    Word32 core_brate = brates[next_random() % 10];
    Word16 coder_type = (next_random() % 4) ? AUDIO : -1;
    thresh[0] = (Word16)random_range(3840, 9600); thresh[1] = (Word16)random_range(2560, 8640);
    thresh[2] = (Word16)random_range(1920, 6720); thresh[3] = (Word16)random_range(1280, 5760);
    int jitter = random_range(0, 600);
    int stable = (next_random() % 3) == 0; /* a long run of steady music: the strongest shaping */
    if (stable) { jitter = 0; last_music_flag = 4; last_nonfull_music = (Word16)random_range(38, 51); }
    for (int i = 0; i < MAX_LT; i++) lt_diff_etot[i] = (Word16)random_range(-jitter, jitter);
    for (int i = 0; i < MBANDS_GN_LD; i++) bckr[i] = (next_random() % 8) ? random_range(0, 1 << random_range(0, 24)) : 0;
    for (int i = 0; i < DCT; i++) {
        lf_EO[i] = random_range(1, 1 << random_range(1, 24));
        lp_gbin[i] = (Word16)random_range(4000, 16384);
        filt_lfE[i] = (Word16)random_range(0, 20480);
    }
    put1("last_music_flag", last_music_flag); put16("thresh", thresh, 4); put1("nb_thr_1", nb_thr_1);
    put1("nb_thr_3", nb_thr_3); put16("lt_diff_etot", lt_diff_etot, MAX_LT); put1("mem_etot", mem_etot);
    put32("bckr", bckr, MBANDS_GN_LD); put32("lf_eo", lf_EO, DCT); put16("lp_gbin", lp_gbin, DCT);
    put16("filt_lfe", filt_lfE, DCT); put1("last_nonfull_music", last_nonfull_music); put1("old_ener_q", old_ener_q);
    put1("min_ns_gain", min_ns_gain); put1("core_brate", core_brate); put1("coder_type", coder_type);

    Word16 dtc[FRAMES][DCT], last_coder_type[FRAMES], qdct[FRAMES];
    int level = random_range(100, 32767);
    for (int k = 0; k < FRAMES; k++) {
        random_dct(dtc[k], level);
        last_coder_type[k] = (stable || (next_random() % 6)) ? AUDIO : (Word16)random_range(0, 4);
        qdct[k] = (Word16)((next_random() % 3) ? old_ener_q : random_range(-1, 8));
        put_named16("dtc", k, dtc[k], DCT); put_named1("last_coder_type", k, last_coder_type[k]);
        put_named1("qdct", k, qdct[k]);
    }
    arrow();
    for (int k = 0; k < FRAMES; k++) {
        LD_music_post_filter_fx(dtc[k], dtc[k], core_brate, &last_music_flag, thresh, &nb_thr_1, &nb_thr_3,
                                lt_diff_etot, &mem_etot, min_ns_gain, bckr, lf_EO, lp_gbin, filt_lfE,
                                &last_nonfull_music, &old_ener_q, coder_type, last_coder_type[k], qdct[k]);
        put_named16("dtc", k, dtc[k], DCT);
        Word16 sc[7] = {last_music_flag, nb_thr_1, nb_thr_3, mem_etot, last_nonfull_music, old_ener_q, 0};
        put_named16("scalars", k, sc, 6); put_named16("thresh", k, thresh, 4);
        put_named16("lt_diff_etot", k, lt_diff_etot, MAX_LT); put_named32("bckr", k, bckr, MBANDS_GN_LD);
        put_named32("lf_eo", k, lf_EO, DCT); put_named16("lp_gbin", k, lp_gbin, DCT); put_named16("filt_lfe", k, filt_lfE, DCT);
    }
    end_line();
}

static void case_prep(void)
{
    Word16 exc[DCT], dct[DCT], filt[DCT], gbin[DCT], pitch[NB_SUBFR], qdct = 99;
    Word16 last_core = (Word16)((next_random() & 1) ? HQ_CORE : random_range(0, 5));
    Word16 q_exc = (Word16)random_range(-1, 12);
    if (next_random() % 4) random_signal(exc, DCT, random_range(1, 32767));
    else for (int i = 0; i < DCT; i++) exc[i] = random16();
    for (int i = 0; i < DCT; i++) { filt[i] = (Word16)random_range(0, 20480); gbin[i] = (Word16)random_range(0, 16384); }
    for (int i = 0; i < NB_SUBFR; i++) pitch[i] = (Word16)(random_range(PIT_MIN, PIT_MAX) * 64 + random_range(0, 63));
    if (next_random() & 1) pitch[3] = (Word16)(random_range(PIT_MIN, PIT_MAX) * 64 + 16 * random_range(0, 3));
    put16("exc", exc, DCT); put16("filt", filt, DCT); put16("gbin", gbin, DCT); put1("last_core", last_core);
    put16("pitch", pitch, NB_SUBFR); put1("q_exc", q_exc);
    Prep_music_postP_fx(exc, dct, filt, last_core, pitch, gbin, q_exc, &qdct);
    arrow(); put16("exc", exc, DCT); put16("dct", dct, DCT); put16("filt", filt, DCT); put16("gbin", gbin, DCT);
    put1("qdct", qdct); end_line();
}

static void case_post(void)
{
    Word16 dct[DCT], exc2[L_FRAME], mem_tmp[M], mem_syn2[M], aq[NB_SUBFR * (M + 1)], syn[L_FRAME];
    Word16 clas[L_SYN_MEM_CLAS_ESTIM], pst[NBPSF_PIT_MAX], tmpbuf[L_FRAME], mem_tmp2[M];
    Word16 deemph = random16(), err = random16(), agc = random16();
    Word16 q_exc = (Word16)random_range(-1, 12), prev_q_syn = (Word16)random_range(-1, 12), q_syn = (Word16)random_range(-1, 12);
    Word16 is_io = (Word16)(next_random() & 1), alias = (Word16)(next_random() & 1), has_tmp = (Word16)(next_random() & 1);
    PFSTAT pf;
    memset(&pf, 0, sizeof pf);
    int mag = (next_random() & 1) ? 32767 : random_range(1, 4000);
    random_signal(dct, DCT, random_range(1, 32767));
    random_signal(mem_tmp, M, mag); random_signal(mem_syn2, M, mag);
    for (int s = 0; s < NB_SUBFR; s++) {
        aq[s * (M + 1)] = 4096;
        for (int i = 1; i <= M; i++) aq[s * (M + 1) + i] = (Word16)random_range(-1500 >> (i / 4), 1500 >> (i / 4));
    }
    random_signal(clas, L_SYN_MEM_CLAS_ESTIM, mag); random_signal(pst, NBPSF_PIT_MAX, mag); random_signal(tmpbuf, L_FRAME, mag);
    random_signal(pf.mem_pf_in, L_SUBFR, mag); random_signal(pf.mem_res2, DECMEM_RES2, mag); random_signal(pf.mem_stp, L_SUBFR, mag);
    for (int i = 0; i < M; i++) mem_tmp2[i] = 0x1234;
    put16("dct", dct, DCT); put16("mem_tmp", mem_tmp, M); put16("mem_syn2", mem_syn2, M); put16("aq", aq, NB_SUBFR * (M + 1));
    put16("clas", clas, L_SYN_MEM_CLAS_ESTIM); put16("pst", pst, NBPSF_PIT_MAX); put16("tmpbuf", tmpbuf, L_FRAME);
    put16("pf_in", pf.mem_pf_in, L_SUBFR); put16("pf_res2", pf.mem_res2, DECMEM_RES2); put16("pf_stp", pf.mem_stp, L_SUBFR);
    put1("deemph", deemph); put1("err", err); put1("agc", agc); put1("q_exc", q_exc); put1("prev_q_syn", prev_q_syn);
    put1("q_syn", q_syn); put1("is_io", is_io); put1("alias", alias); put1("has_tmp", has_tmp);
    Post_music_postP_fx(dct, exc2, alias ? mem_syn2 : mem_tmp, mem_syn2, aq, syn, &q_exc, &prev_q_syn, &q_syn, clas, is_io,
                        &deemph, pst, &err, &agc, &pf, has_tmp ? tmpbuf : NULL, mem_tmp2);
    arrow(); put16("exc2", exc2, L_FRAME); put16("syn", syn, L_FRAME); put16("mem_syn2", mem_syn2, M);
    put16("mem_tmp2", mem_tmp2, M); put16("clas", clas, L_SYN_MEM_CLAS_ESTIM); put16("pst", pst, NBPSF_PIT_MAX);
    put16("pf_in", pf.mem_pf_in, L_SUBFR); put16("pf_res2", pf.mem_res2, DECMEM_RES2); put16("pf_stp", pf.mem_stp, L_SUBFR);
    put1("deemph", deemph); put1("err", err); put1("agc", agc); put1("q_exc", q_exc); put1("prev_q_syn", prev_q_syn);
    put1("q_syn", q_syn); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "ld_music_post_filter")) case_ld_music_post_filter();
        else if (!strcmp(argv[2], "prep")) case_prep();
        else if (!strcmp(argv[2], "post")) case_post();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
