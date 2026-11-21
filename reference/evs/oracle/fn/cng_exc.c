/* Function-level oracle for lib_com/cng_exc_fx.c (CNG_exc_fx, cng_params_upd_fx). Three consecutive calls through
 * one hangover memory, in the decoder's (DEC) form mostly and the encoder's (ENC) now and then. */
#include "harness.h"
#include "prot_fx.h"

static void case_cng_params_upd(void)
{
    Word16 ho_circ_ptr = (Word16)random_range(-1, HO_HIST_SIZE - 1), ho_circ_size = (Word16)random_range(0, HO_HIST_SIZE);
    Word16 cng_buf_cnt = (Word16)random_range(0, HO_HIST_SIZE);
    Word32 ho_ener_circ[HO_HIST_SIZE], ho_env_circ[HO_HIST_SIZE * NUM_ENV_CNG], cng_brate_buf[HO_HIST_SIZE];
    Word16 ho_lsp_circ[HO_HIST_SIZE * M], cng_qexc_buf[HO_HIST_SIZE];
    static Word16 cng_exc2_buf[HO_HIST_SIZE * L_FFT];
    for (int i = 0; i < HO_HIST_SIZE; i++) { ho_ener_circ[i] = random32(); cng_brate_buf[i] = random32(); cng_qexc_buf[i] = random16(); }
    for (int i = 0; i < HO_HIST_SIZE * NUM_ENV_CNG; i++) ho_env_circ[i] = random32();
    for (int i = 0; i < HO_HIST_SIZE * M; i++) ho_lsp_circ[i] = random16();
    for (int i = 0; i < HO_HIST_SIZE * L_FFT; i++) cng_exc2_buf[i] = (Word16)i;
    put1("ho_circ_ptr", ho_circ_ptr); put1("ho_circ_size", ho_circ_size); put1("cng_buf_cnt", cng_buf_cnt);
    put32("ho_ener_circ", ho_ener_circ, HO_HIST_SIZE); put32("ho_env_circ", ho_env_circ, HO_HIST_SIZE * NUM_ENV_CNG);
    put32("cng_brate_buf", cng_brate_buf, HO_HIST_SIZE); put16("cng_qexc_buf", cng_qexc_buf, HO_HIST_SIZE);
    put16("ho_lsp_circ", ho_lsp_circ, HO_HIST_SIZE * M);

    static const Word32 brates[] = {ACELP_7k20, ACELP_8k00, ACELP_9k60, ACELP_13k20, ACELP_16k40, ACELP_24k40, 5900};
    Word16 lsp[3][M], exc[3][L_FRAME16k], l_frame[3], q_exc[3], flag[3];
    Word32 brate[3];
    for (int f = 0; f < 3; f++) {
        l_frame[f] = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
        for (int i = 0; i < M; i++) lsp[f][i] = random16();
        int kind = next_random() % 6;
        if (kind == 0) for (int i = 0; i < l_frame[f]; i++) exc[f][i] = 0;
        else if (kind == 1) for (int i = 0; i < l_frame[f]; i++) exc[f][i] = random16();
        else random_signal(exc[f], l_frame[f], 1 << random_range(2, 15));
        q_exc[f] = (Word16)random_range(-1, 12);
        flag[f] = (Word16)(next_random() % 5 ? DEC : ENC);
        brate[f] = brates[next_random() % 7];
        char name[24];
        sprintf(name, "lsp%d", f); put16(name, lsp[f], M);
        sprintf(name, "exc%d", f); put16(name, exc[f], l_frame[f]);
        sprintf(name, "q_exc%d", f); put1(name, q_exc[f]);
        sprintf(name, "flag%d", f); put1(name, flag[f]);
        sprintf(name, "brate%d", f); put1(name, brate[f]);
    }
    arrow();
    for (int f = 0; f < 3; f++) {
        cng_params_upd_fx(lsp[f], exc[f], l_frame[f], &ho_circ_ptr, ho_ener_circ, &ho_circ_size, ho_lsp_circ, q_exc[f],
                          flag[f], ho_env_circ, &cng_buf_cnt, cng_exc2_buf, cng_qexc_buf, cng_brate_buf, brate[f]);
        char name[24];
        sprintf(name, "ho_circ_ptr%d", f); put1(name, ho_circ_ptr);
        sprintf(name, "ho_circ_size%d", f); put1(name, ho_circ_size);
        sprintf(name, "cng_buf_cnt%d", f); put1(name, cng_buf_cnt);
        sprintf(name, "ho_ener_circ%d", f); put32(name, ho_ener_circ, HO_HIST_SIZE);
        sprintf(name, "ho_env_circ%d", f); put32(name, ho_env_circ, HO_HIST_SIZE * NUM_ENV_CNG);
        sprintf(name, "ho_lsp_circ%d", f); put16(name, ho_lsp_circ, HO_HIST_SIZE * M);
        sprintf(name, "cng_brate_buf%d", f); put32(name, cng_brate_buf, HO_HIST_SIZE);
        sprintf(name, "cng_qexc_buf%d", f); put16(name, cng_qexc_buf, HO_HIST_SIZE);
        /* Only the current slot changes (the buffer starts as 0, 1, 2, ...): print that one. */
        sprintf(name, "cng_exc2_slot%d", f); put16(name, &cng_exc2_buf[ho_circ_ptr * L_FFT], L_FFT);
    }
    end_line();
}

/* CNG_exc_fx over three consecutive frames through one set of CNG memories: both frame lengths, SID
 * (2.4 kbit/s, 1.75 kbit/s) and no-data frames after active or comfort-noise frames, every energy
 * update branch, the AMR-WB IO mode (no spectral shaping) and the envelope-shaped excitation. */
static void case_cng_exc(void)
{
    static const Word32 brates[] = {FRAME_NO_DATA, SID_2k40, SID_1k75, FRAME_NO_DATA, SID_2k40};
    static const Word32 last_brates[] = {FRAME_NO_DATA, SID_2k40, SID_1k75, ACELP_7k20, ACELP_13k20, ACELP_24k40, ACELP_9k60};
    Word16 L_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
    Word16 opt_amr_wb = (Word16)(next_random() % 5 == 0);
    Word16 excbuf[PIT16k_MAX + L_FRAME16k], exc2[L_FRAME16k], exc3[L_FRAME16k], bwe_exc[2 * L_FRAME16k + 8];
    Word16 seed = random16(), cng_ener_seed = random16(), cng_ener_seed1 = random16(), first_CNG = (Word16)(next_random() & 1);
    Word16 last_allow_cn_step = (Word16)(next_random() & 1), exc_mem[24], exc_mem1[30];
    Word32 Enew = (Word32)random_range(1, 1 << 22) << random_range(0, 3), lp_ener = (Word32)random_range(1, 1 << 22) << random_range(0, 3);
    Word32 q_env[NUM_ENV_CNG], lp_env[NUM_ENV_CNG], old_env[NUM_ENV_CNG];
    Word16 sid_bw = (Word16)(next_random() % 4 == 0);
    random_signal(excbuf, PIT16k_MAX + L_FRAME16k, next_random() & 1 ? 3000 : 200);
    random_signal(exc_mem, 24, 2000); random_signal(exc_mem1, 30, 2000);
    for (int i = 0; i < NUM_ENV_CNG; i++) {
        q_env[i] = random_range(-300, 700); lp_env[i] = random_range(0, 1 << 14) << random_range(0, 4); old_env[i] = random_range(0, 1 << 14) << random_range(0, 4);
    }
    put1("L_frame", L_frame); put1("opt_amr_wb", opt_amr_wb); put16("excbuf", excbuf, PIT16k_MAX + L_FRAME16k);
    put1("seed", seed); put1("cng_ener_seed", cng_ener_seed); put1("cng_ener_seed1", cng_ener_seed1); put1("first_CNG", first_CNG);
    put1("last_allow_cn_step", last_allow_cn_step); put16("exc_mem", exc_mem, 24); put16("exc_mem1", exc_mem1, 30);
    put1("Enew", Enew); put1("lp_ener", lp_ener); put32("q_env", q_env, NUM_ENV_CNG); put32("lp_env", lp_env, NUM_ENV_CNG);
    put32("old_env", old_env, NUM_ENV_CNG); put1("sid_bw", sid_bw);
    Word32 core[3], last_core[3];
    Word16 allow[3], old_q[3], q[3], num_ho[3], first[3];
    for (int f = 0; f < 3; f++) {
        core[f] = brates[next_random() % 5]; last_core[f] = last_brates[next_random() % 7];
        allow[f] = (Word16)(next_random() % 3 == 0); old_q[f] = (Word16)random_range(0, 8); q[f] = (Word16)random_range(0, 8);
        num_ho[f] = (Word16)random_range(0, 8);
        first[f] = (Word16)(f == 0 ? first_CNG : (next_random() % 3 ? 1 : 0));
        char name[24];
        sprintf(name, "first%d", f); put1(name, first[f]);
        sprintf(name, "core%d", f); put1(name, core[f]); sprintf(name, "last_core%d", f); put1(name, last_core[f]);
        sprintf(name, "allow%d", f); put1(name, allow[f]); sprintf(name, "old_q%d", f); put1(name, old_q[f]);
        sprintf(name, "q%d", f); put1(name, q[f]); sprintf(name, "num_ho%d", f); put1(name, num_ho[f]);
    }
    arrow();
    for (int f = 0; f < 3; f++) {
        first_CNG = first[f];
        for (int i = 0; i < L_FRAME16k; i++) exc2[i] = exc3[i] = -12345;
        for (int i = 0; i < 2 * L_FRAME16k + 8; i++) bwe_exc[i] = -12345;
        CNG_exc_fx(core[f], L_frame, &Enew, &seed, excbuf + PIT16k_MAX, exc2, &lp_ener, last_core[f], &first_CNG, &cng_ener_seed, bwe_exc,
                   allow[f], &last_allow_cn_step, old_q[f], q[f], num_ho[f], q_env, lp_env, old_env, exc_mem, exc_mem1, &sid_bw,
                   &cng_ener_seed1, exc3, opt_amr_wb);
        char name[24];
        sprintf(name, "Enew%d", f); put1(name, Enew); sprintf(name, "seed%d", f); put1(name, seed);
        sprintf(name, "exc%d", f); put16(name, excbuf + PIT16k_MAX, L_frame); sprintf(name, "exc2_%d", f); put16(name, exc2, L_FRAME16k);
        sprintf(name, "exc3_%d", f); put16(name, exc3, L_FRAME16k); sprintf(name, "lp_ener%d", f); put1(name, lp_ener);
        sprintf(name, "first_CNG%d", f); put1(name, first_CNG); sprintf(name, "cng_ener_seed%d", f); put1(name, cng_ener_seed);
        sprintf(name, "cng_ener_seed1_%d", f); put1(name, cng_ener_seed1); sprintf(name, "bwe_exc%d", f); put16(name, bwe_exc, 2 * L_FRAME16k + 8);
        sprintf(name, "last_allow%d", f); put1(name, last_allow_cn_step); sprintf(name, "lp_env%d", f); put32(name, lp_env, NUM_ENV_CNG);
        sprintf(name, "old_env%d", f); put32(name, old_env, NUM_ENV_CNG); sprintf(name, "exc_mem%d", f); put16(name, exc_mem, 24);
        sprintf(name, "exc_mem1_%d", f); put16(name, exc_mem1, 30); sprintf(name, "sid_bw%d", f); put1(name, sid_bw);
    }
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "cng_params_upd")) case_cng_params_upd();
        else if (!strcmp(argv[2], "cng_exc")) case_cng_exc();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
