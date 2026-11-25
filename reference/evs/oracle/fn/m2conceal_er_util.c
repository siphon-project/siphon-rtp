/* Function-level oracle for lib_dec/er_util.c (minimumStatistics, getLevelSynDeemph,
 * genPlcFiltBWAdap, highPassFiltering) and lib_dec/er_scale_syn.c (Damping_fact).
 *
 * Inputs stay in what the MODE2 concealment feeds them: a class and coder type the classifier can
 * produce, a lost-frame counter that grows from 1, a pitch gain memory in [0, 1] (2Q29), LPC
 * coefficient sets of a stable-looking synthesis filter, noise levels as positive normalised
 * mantissa / exponent pairs. */
#include "harness.h"
#include "prot_fx.h"
#include "basop_util.h"

static void random_lpc(Word16 *a, int m)
{
    int kind = next_random() % 8;
    a[0] = 4096;
    for (int k = 1; k <= m; k++) {
        if (kind == 5) a[k] = random16();
        else a[k] = (Word16)random_range(-12000 / k - 2000, 12000 / k + 2000);
    }
}

static void case_damping_fact(void)
{
    Word16 coder_type = (Word16)((next_random() & 1) ? ((next_random() & 1) ? UNVOICED : GENERIC) : random_range(0, 9));
    Word16 nb_lost = (Word16)((next_random() % 3) ? random_range(1, 4) : random_range(1, 40));
    Word16 last_good = (Word16)((next_random() % 3 == 0) ? ONSET : random_range(0, 6));
    Word16 stab_fac = (Word16)((next_random() % 4) ? random_range(0, 32767) : (next_random() & 1) ? 32767 : 0);
    Word32 lp_gainp = (next_random() % 5) ? (Word32)random_range(0, 1 << 29) : (next_random() & 1) ? 0 : (Word32)(1 << 29);
    Word16 core = (Word16)random_range(0, 3);
    if (next_random() % 8 == 0) lp_gainp = (Word32)random_range(0, 1 << 30);
    put1("coder_type", coder_type); put1("nb_lost", nb_lost); put1("last_good", last_good);
    put1("stab_fac", stab_fac); put1("lp_gainp", lp_gainp); put1("core", core);
    Word16 alpha = Damping_fact(coder_type, nb_lost, last_good, stab_fac, &lp_gainp, core);
    arrow(); put1("alpha", alpha); put1("lp_gainp", lp_gainp); end_line();
}

static void case_gen_plc_filt_bw_adap(void)
{
    static const Word32 rates[] = {12800, 16000, 12800, 16000, 25600, 32000};
    Word32 sr_core = rates[next_random() % 6];
    Word16 type = (Word16)(next_random() & 1);
    Word16 alpha = (Word16)((next_random() % 4) ? random_range(0, 32767) : (next_random() & 1) ? 0 : 32767);
    Word16 taps[3] = {-1, -1, -1};
    put1("sr_core", sr_core); put1("type", type); put1("alpha", alpha);
    genPlcFiltBWAdap(sr_core, taps, type, alpha);
    arrow(); put16("taps", taps, 3); end_line();
}

static void case_high_pass_filtering(void)
{
    Word16 exc2[640 + 16];
    Word16 hp_filt[11];
    int l_fir = (next_random() & 1) ? 3 : 11;
    Word16 last_good = (Word16)random_range(0, 6);
    Word16 length = (Word16)random_range(8, 640);
    static const int magnitudes[] = {50, 600, 4000, 16000, 32767};
    random_signal(exc2, length + l_fir, magnitudes[next_random() % 5]);
    if (next_random() % 6 == 0) for (int i = 0; i < length + l_fir; i++) if (next_random() % 4 == 0) exc2[i] = random16();
    for (int i = 0; i < l_fir; i++) hp_filt[i] = (Word16)random_range(-12000, 24000);
    put16("exc2", exc2, length + l_fir); put16("hp_filt", hp_filt, l_fir);
    put1("last_good", last_good); put1("length", length); put1("l_fir", l_fir);
    highPassFiltering(last_good, length, exc2, hp_filt, (Word16)l_fir);
    arrow(); put16("exc2", exc2, length + l_fir); end_line();
}

static void case_get_level_syn_deemph(void)
{
    static const Word16 lengths[] = {64, 64, 80, 96, 128, 160, 192, 240};
    Word16 a[5 * (M + 1)];
    Word16 h1_init[1];
    Word16 length = lengths[next_random() % 8];
    Word16 loops = (Word16)((next_random() % 3) ? 1 : random_range(2, 5));
    Word16 preemph_fac = (Word16)((next_random() & 1) ? 22282 : random_range(0, 32767));
    Word16 exp = -1;
    for (int k = 0; k < 5; k++) random_lpc(a + k * (M + 1), M);
    h1_init[0] = (Word16)((next_random() % 3) ? 32767 : random_range(1, 32767));
    put16("a", a, 5 * (M + 1)); put16("h1_init", h1_init, 1); put1("length", length);
    put1("loops", loops); put1("preemph_fac", preemph_fac);
    Word16 level = getLevelSynDeemph(h1_init, a, M, length, preemph_fac, loops, &exp);
    arrow(); put1("level", level); put1("exp", exp); put16("h1_init", h1_init, 1); end_line();
}

static Word16 positive_mantissa(void)
{
    return (Word16)((next_random() % 6) ? random_range(8192, 32767) : (next_random() & 1) ? 32767 : random_range(1, 32767));
}

static void case_minimum_statistics(void)
{
    Word16 memory[PLC_MIN_STAT_BUFF_SIZE], memory_e[PLC_MIN_STAT_BUFF_SIZE];
    Word16 noise_index = (Word16)random_range(0, PLC_MIN_STAT_BUFF_SIZE - 1);
    Word16 curr_index = (Word16)random_range(0, PLC_MIN_STAT_BUFF_SIZE - 1);
    Word16 noise_estimate = positive_mantissa(), last_level = positive_mantissa();
    Word16 current_level = positive_mantissa();
    Word16 noise_estimate_e = (Word16)random_range(-3, 6), last_level_e = (Word16)random_range(-3, 6);
    Word16 current_level_e = (Word16)random_range(-3, 6), new_e = 0;
    int base_e = random_range(-2, 5);
    for (int i = 0; i < PLC_MIN_STAT_BUFF_SIZE; i++) {
        memory[i] = positive_mantissa();
        memory_e[i] = (Word16)(base_e + (next_random() % 4 == 0 ? random_range(-2, 2) : 0));
    }
    if (next_random() % 4 == 0) { noise_index = curr_index; }
    if (next_random() % 3 == 0) {
        /* nearly constant levels: the recursion lands on values already in the buffer */
        int level = random_range(8192, 32760);
        for (int i = 0; i < PLC_MIN_STAT_BUFF_SIZE; i++) { memory[i] = (Word16)(level + random_range(0, 3)); memory_e[i] = (Word16)base_e; }
        noise_estimate = (Word16)level; last_level = (Word16)level; current_level = (Word16)(level + random_range(0, 3));
        noise_estimate_e = last_level_e = current_level_e = (Word16)base_e;
    }
    put16("memory", memory, PLC_MIN_STAT_BUFF_SIZE); put16("memory_e", memory_e, PLC_MIN_STAT_BUFF_SIZE);
    put1("noise_index", noise_index); put1("curr_index", curr_index);
    put1("noise_estimate", noise_estimate); put1("last_level", last_level); put1("current_level", current_level);
    put1("noise_estimate_e", noise_estimate_e); put1("last_level_e", last_level_e); put1("current_level_e", current_level_e);
    minimumStatistics(memory, &noise_index, &curr_index, &noise_estimate, &last_level, current_level, memory_e,
                      noise_estimate_e, &new_e, &last_level_e, current_level_e);
    arrow(); put16("memory", memory, PLC_MIN_STAT_BUFF_SIZE); put16("memory_e", memory_e, PLC_MIN_STAT_BUFF_SIZE);
    put1("noise_index", noise_index); put1("curr_index", curr_index); put1("noise_estimate", noise_estimate);
    put1("last_level", last_level); put1("new_e", new_e); put1("last_level_e", last_level_e); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "damping_fact")) case_damping_fact();
        else if (!strcmp(argv[2], "gen_plc_filt_bw_adap")) case_gen_plc_filt_bw_adap();
        else if (!strcmp(argv[2], "high_pass_filtering")) case_high_pass_filtering();
        else if (!strcmp(argv[2], "get_level_syn_deemph")) case_get_level_syn_deemph();
        else if (!strcmp(argv[2], "minimum_statistics")) case_minimum_statistics();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
