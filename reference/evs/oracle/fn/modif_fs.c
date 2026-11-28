/* Function-level oracle for lib_com/modif_fs_fx.c (the 2:1 and 3:1 all-pass interpolators, the cubic
 * interpolator). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"
#include "rom_enc_fx.h"

static void case_interpolate_allpass_steep(void)
{
    Word16 in[L_FRAME32k], out[2 * L_FRAME32k], state[2 * ALLPASSSECTIONS_STEEP + 1];
    Word16 n = (Word16)((next_random() & 1) ? L_SUBFR16k : random_range(1, L_FRAME32k));
    int mag = (next_random() & 1) ? 32767 : random_range(1, 8000);
    random_signal(in, n, mag);
    random_signal(state, 2 * ALLPASSSECTIONS_STEEP + 1, mag);
    put16("in", in, n); put16("state", state, 2 * ALLPASSSECTIONS_STEEP + 1);
    Interpolate_allpass_steep_fx(in, state, n, out);
    arrow(); put16("out", out, 2 * n); put16("state", state, 2 * ALLPASSSECTIONS_STEEP + 1); end_line();
}

static void case_interpolate_3_over_1(void)
{
    Word16 in[L_FRAME16k], out[3 * L_FRAME16k], mem[INTERP_3_1_MEM_LEN];
    Word16 len = (Word16)((next_random() & 1) ? L_SUBFR16k : random_range(1, L_FRAME16k));
    int mag = (next_random() & 1) ? 32767 : random_range(1, 8000);
    random_signal(in, len, mag);
    random_signal(mem, INTERP_3_1_MEM_LEN, mag);
    put16("in", in, len); put16("mem", mem, INTERP_3_1_MEM_LEN);
    interpolate_3_over_1_allpass_fx(in, len, out, mem, allpass_poles_3_ov_2);
    arrow(); put16("out", out, 3 * len); put16("mem", mem, INTERP_3_1_MEM_LEN); end_line();
}

/* modify_Fs_intcub3m_sup_fx on the rate pairs core_switching_OLA_fx uses (and an equal pair, the
 * copy), at the 1.25 ms lengths it passes and at other whole-period lengths. The 12.8 -> 8 kHz and
 * 16 -> 12.8 kHz rows read past the reference's own input buffer at the end of the signal (heap
 * garbage), and no caller uses them, so they are not compared. The output buffer starts as a
 * sentinel and is printed past the returned length, so a stray write shows. */
static void case_intcub3m_sup(void)
{
    static const Word32 pairs[][2] = {{12800, 16000}, {12800, 32000}, {12800, 48000},
                                      {16000, 32000}, {16000, 48000}, {16000, 16000}};
    Word16 in[2 + 200], out[4 * 200 + 16], delay = -99;
    int p = random_range(0, 5);
    Word32 fin = pairs[p][0], fout = pairs[p][1];
    Word16 lg;
    switch (next_random() % 2) {
    case 0: lg = fin == 12800 ? 16 : 20; break;
    /* whole interpolation periods (4 or 5 input samples): on any other length the reference reads
     * past its own buffer */
    default: lg = (Word16)(20 * random_range(1, 10)); break;
    }
    int mag = (next_random() & 1) ? 32767 : random_range(1, 8000);
    random_signal(in, lg + 2, mag);
    for (int i = 0; i < 4 * 200 + 16; i++) out[i] = -12345;
    put1("fin", fin); put1("fout", fout); put16("in", in, lg + 2);
    Word16 lg_out = modify_Fs_intcub3m_sup_fx(in + 2, lg, fin, out, fout, &delay);
    arrow(); put1("lg_out", lg_out); put1("delay", delay); put16("out", out, 4 * lg + 16); end_line();
}

/* retro_interp4_5_fx / retro_interp5_4_fx over the 290-sample post-filter memory */
static void case_retro_interp(int forward)
{
    Word16 memory[NBPSF_PIT_MAX], syn[2];
    int mag = (next_random() & 1) ? 32767 : random_range(1, 8000);
    random_signal(memory, NBPSF_PIT_MAX, mag);
    random_signal(syn, 2, mag);
    put16("memory", memory, NBPSF_PIT_MAX); put16("syn", syn, 2);
    if (forward) retro_interp4_5_fx(syn, memory);
    else retro_interp5_4_fx(memory);
    arrow(); put16("memory", memory, NBPSF_PIT_MAX); end_line();
}

/* modify_Fs_fx on every rate pair of the resampling table, with the frame length of the input rate
 * and now and then a shorter input; the 8 -> 12.8 kHz pair runs the LPC ringing extension. */
static void case_modify_fs(void)
{
    static Word16 in[L_FRAME48k], out[2 * L_FRAME48k], mem[2 * L_FILT_MAX];
    int valid[32][2], count = 0;
    for (const Resampling_cfg_fx *c = &resampling_cfg_tbl_fx[0]; c->fin_fx != 0; c++) {
        valid[count][0] = (int)c->fin_fx;
        valid[count][1] = (int)c->fout_fx;
        count++;
    }
    int pick = random_range(0, count);
    Word32 fin = pick == count ? 16000 : valid[pick][0], fout = pick == count ? 16000 : valid[pick][1];
    Word16 lg = (Word16)(fin / 50);
    /* a shorter input (never at 8 kHz, whose LPC extension looks 120 samples back) only below L_FRAME, where the output length follows the input (above it the
     * reference always produces a frame and reads its own stack past a short input) */
    if (fin != 8000 && next_random() % 4 == 0) lg = (Word16)random_range(20, lg < L_FRAME ? lg : L_FRAME - 1);
    Word16 nblp = (Word16)(fin > 8000 && fout == 12800 && next_random() % 3 == 0);
    int mem_len = 2 * L_FILT_MAX;
    int mag = next_random() % 3 == 0 ? 32767 : random_range(1, 8000);
    random_signal(in, lg, mag);
    random_signal(mem, mem_len, mag);
    for (int i = 0; i < 2 * L_FRAME48k; i++) out[i] = -12345;
    put1("fin", fin); put1("fout", fout); put1("lg", lg); put1("nblp", nblp); put16("in", in, lg); put16("mem", mem, mem_len);
    Word16 lg_out = modify_Fs_fx(in, lg, fin, out, fout, mem, nblp);
    arrow(); put1("lg_out", lg_out); put16("out", out, lg_out + 8); put16("mem", mem, mem_len); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "interpolate_allpass_steep")) case_interpolate_allpass_steep();
        else if (!strcmp(argv[2], "interpolate_3_over_1")) case_interpolate_3_over_1();
        else if (!strcmp(argv[2], "intcub3m_sup")) case_intcub3m_sup();
        else if (!strcmp(argv[2], "modify_fs")) case_modify_fs();
        else if (!strcmp(argv[2], "retro_interp4_5")) case_retro_interp(1);
        else if (!strcmp(argv[2], "retro_interp5_4")) case_retro_interp(0);
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
