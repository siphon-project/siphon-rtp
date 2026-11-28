/* Function-level oracle for lib_com/scale_mem_fx.c. */
#include "harness.h"
#include "prot_fx.h"

#define EXC_LEN (L_EXC_MEM_DEC + L_FRAME)
#define BWE_LEN (PIT16k_MAX * 2 + L_FRAME32k)
#define DCT_LEN (DCT_L_POST - OFFSET2)

static const Word16 lgs[] = {L_SUBFR, 2 * L_SUBFR, L_FRAME, L_FRAME16k};
static const Word16 coder_types[] = {INACTIVE, UNVOICED, VOICED, GENERIC, TRANSITION, AUDIO};

static void case_rescale_exc(void)
{
    Word16 exc[L_EXC_MEM_DEC + L_FRAME16k], bwe[BWE_LEN], dct[DCT_LEN], last[L_FRAME], exc2[L_FRAME16k];
    Word16 sq_subfr[L_Q_MEM], sq_exc, lg = lgs[next_random() % 4], lg32 = (Word16)random_range(0, L_FRAME32k);
    Word16 coder_type = coder_types[next_random() % 6], i_subfr = (Word16)random_range(0, lg);
    Word32 gain = (next_random() & 1) ? random32() : random_range(0, 6000000);
    int has_dct = next_random() & 1, has_bwe = next_random() & 1, has_last = next_random() & 1, has_exc2 = next_random() & 1;
    int exc_len = L_EXC_MEM_DEC + lg;
    random_signal(exc, exc_len, (next_random() & 1) ? 32767 : random_range(1, 3000));
    random_signal(bwe, BWE_LEN, 8000); random_signal(dct, DCT_LEN, 8000);
    random_signal(last, L_FRAME, 8000); random_signal(exc2, L_FRAME16k, 8000);
    sq_exc = (Word16)random_range(-1, 12);
    for (int i = 0; i < L_Q_MEM; i++) sq_subfr[i] = (Word16)random_range(-1, 12);
    put16("exc", exc, exc_len); put16("bwe", bwe, BWE_LEN); put16("dct", dct, DCT_LEN); put16("last", last, L_FRAME);
    put16("exc2", exc2, L_FRAME16k); put16("sq_subfr", sq_subfr, L_Q_MEM); put1("sq_exc", sq_exc);
    put1("lg", lg); put1("lg32", lg32); put1("coder_type", coder_type); put1("i_subfr", i_subfr); put1("gain", gain);
    put1("has_dct", has_dct); put1("has_bwe", has_bwe); put1("has_last", has_last); put1("has_exc2", has_exc2);
    Word16 r = Rescale_exc(has_dct ? dct : NULL, exc + L_EXC_MEM_DEC, has_bwe ? bwe + PIT16k_MAX * 2 : NULL,
                           has_last ? last : NULL, lg, lg32, gain, &sq_exc, sq_subfr, has_exc2 ? exc2 : NULL, i_subfr, coder_type);
    arrow(); put1("r", r); put16("exc", exc, exc_len); put16("bwe", bwe, BWE_LEN); put16("dct", dct, DCT_LEN);
    put16("last", last, L_FRAME); put16("exc2", exc2, L_FRAME16k); put16("sq_subfr", sq_subfr, L_Q_MEM); put1("sq_exc", sq_exc);
    end_line();
}

static void case_rescale_mem(void)
{
    Word16 mem_syn2[M], clas[L_SYN_MEM_CLAS_ESTIM], pst[NBPSF_PIT_MAX], tmpbuf[L_FRAME];
    Word16 deemph, err, agc, prev_q_syn, q_syn, q_exc;
    PFSTAT pf;
    int mag = (next_random() & 1) ? 32767 : random_range(1, 4000);
    int has_tmp = next_random() & 1;
    Word16 vad = (Word16)(next_random() & 1), cna = (Word16)(next_random() & 1), max_scaling = (Word16)random_range(3, 5);
    memset(&pf, 0, sizeof(pf));
    random_signal(mem_syn2, M, mag); random_signal(clas, L_SYN_MEM_CLAS_ESTIM, mag);
    random_signal(pst, NBPSF_PIT_MAX, mag); random_signal(tmpbuf, L_FRAME, mag);
    random_signal(pf.mem_pf_in, L_SUBFR, mag); random_signal(pf.mem_res2, DECMEM_RES2, mag); random_signal(pf.mem_stp, L_SUBFR, mag);
    deemph = random16(); err = random16(); agc = random16();
    q_exc = (Word16)random_range(-1, 12); prev_q_syn = (Word16)random_range(-1, 12); q_syn = (Word16)random_range(-1, 12);
    put16("mem_syn2", mem_syn2, M); put16("clas", clas, L_SYN_MEM_CLAS_ESTIM); put16("pst", pst, NBPSF_PIT_MAX);
    put16("tmpbuf", tmpbuf, L_FRAME); put16("pf_in", pf.mem_pf_in, L_SUBFR); put16("pf_res2", pf.mem_res2, DECMEM_RES2);
    put16("pf_stp", pf.mem_stp, L_SUBFR); put1("deemph", deemph); put1("err", err); put1("agc", agc);
    put1("q_exc", q_exc); put1("prev_q_syn", prev_q_syn); put1("q_syn", q_syn); put1("vad", vad); put1("cna", cna);
    put1("max_scaling", max_scaling); put1("has_tmp", has_tmp);
    Rescale_mem(q_exc, &prev_q_syn, &q_syn, mem_syn2, clas, max_scaling, &deemph, pst, &err, &agc, &pf, vad, cna,
                has_tmp ? tmpbuf : NULL);
    arrow(); put16("mem_syn2", mem_syn2, M); put16("clas", clas, L_SYN_MEM_CLAS_ESTIM); put16("pst", pst, NBPSF_PIT_MAX);
    put16("pf_in", pf.mem_pf_in, L_SUBFR); put16("pf_res2", pf.mem_res2, DECMEM_RES2); put16("pf_stp", pf.mem_stp, L_SUBFR);
    put1("deemph", deemph); put1("err", err); put1("agc", agc); put1("prev_q_syn", prev_q_syn); put1("q_syn", q_syn);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "rescale_exc")) case_rescale_exc();
        else if (!strcmp(argv[2], "rescale_mem")) case_rescale_mem();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
