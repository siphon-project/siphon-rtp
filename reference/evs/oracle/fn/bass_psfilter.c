/* Function-level oracle for lib_dec/bass_psfilter_fx.c: bass_psfilter_fx (Pit_track_fx is static and
 * reached through it with Opt_AMR_WB set) over consecutive frames carrying the filter memories, and
 * addBassPostFilterFx on a CLDFB analysis bank set up as the decoder does. */
#include "harness.h"
#include "prot_fx.h"

#define FRAMES 3
#define HIST 10

static void case_bass_psfilter(void)
{
    Word16 opt_amr_wb = (Word16)(next_random() & 1);
    Word16 l_frame = (opt_amr_wb || (next_random() & 1)) ? L_FRAME : L_FRAME16k;
    Word16 old_syn[NBPSF_PIT_MAX], mem_deemph_err = random16(), lp_ener = (Word16)random_range(-2000, 20000);
    Word16 v_stab_smooth = (Word16)random_range(0, 32767), mem_mean_pit[HIST], track_on_hist[HIST], vibrato_hist[HIST];
    Word16 psf_att = (Word16)((next_random() & 1) ? 32767 : random_range(3277, 32767));
    random_signal(old_syn, NBPSF_PIT_MAX, random_range(1, 32767));
    /* a strictly periodic signal decoded at twice its period: the tracker halves the lag */
    int period = (opt_amr_wb && (next_random() % 3) == 0) ? random_range(PIT_MIN, 110) : 0;
    Word16 pattern[110];
    if (period) {
        random_signal(pattern, period, random_range(1000, 20000));
        for (int i = 0; i < NBPSF_PIT_MAX; i++) old_syn[i] = pattern[i % period];
    }
    for (int i = 0; i < HIST; i++) {
        mem_mean_pit[i] = (Word16)random_range(PIT_MIN * 16, PIT16k_MAX * 16);
        track_on_hist[i] = (Word16)(next_random() & 1);
        vibrato_hist[i] = (Word16)(next_random() & 1);
    }
    if (next_random() & 1) { /* a vibrato-like history */
        int base = random_range(PIT_MIN * 16, 200 * 16);
        for (int i = 0; i < HIST; i++) mem_mean_pit[i] = (Word16)(base + random_range(0, 9 * 16));
    }
    put1("opt_amr_wb", opt_amr_wb); put1("l_frame", l_frame); put16("old_syn", old_syn, NBPSF_PIT_MAX);
    put1("mem_deemph_err", mem_deemph_err); put1("lp_ener", lp_ener); put1("v_stab_smooth", v_stab_smooth);
    put16("mem_mean_pit", mem_mean_pit, HIST); put16("track_on_hist", track_on_hist, HIST);
    put16("vibrato_hist", vibrato_hist, HIST); put1("psf_att", psf_att);

    Word16 synth[FRAMES][L_FRAME16k], pitch[FRAMES][NB_SUBFR16k], bpf_off[FRAMES], null_pitch[FRAMES];
    Word16 v_stab[FRAMES], coder_type[FRAMES], q_syn[FRAMES];
    char name[32];
    int nb = l_frame / L_SUBFR, pit_max = l_frame == L_FRAME ? PIT_MAX : PIT16k_MAX;
    for (int k = 0; k < FRAMES; k++) {
        int mode = random_range(0, 3);
        if (mode == 3) for (int i = 0; i < l_frame; i++) synth[k][i] = random16();
        else random_signal(synth[k], l_frame, random_range(1, 32767));
        if (mode == 2) { /* periodic, so the gain and the tracker have something to find */
            int period = random_range(PIT_MIN, pit_max / 2);
            for (int i = 0; i < l_frame; i++) synth[k][i] = (Word16)(((i % period) < period / 3 ? 1 : -1) * random_range(1000, 8000));
        }
        if (period) for (int i = 0; i < l_frame; i++) synth[k][i] = pattern[(NBPSF_PIT_MAX + k * l_frame + i) % period];
        int base = period ? 2 * period : random_range(PIT_MIN, pit_max);
        for (int i = 0; i < nb; i++) {
            int lag = (period || (next_random() & 1)) ? base : random_range(PIT_MIN, pit_max);
            pitch[k][i] = (Word16)((lag << 6) + (period ? 0 : random_range(-32, 31)));
        }
        /* no lag below half a sample: on the last subframe it would extend the synthesis with the
         * reference's uninitialised stack (syn_buf_fx past the frame), where the port has zeros */
        bpf_off[k] = (Word16)((next_random() % 6) == 0);
        null_pitch[k] = (Word16)((next_random() % 8) == 0);
        v_stab[k] = (Word16)random_range(0, 32767);
        coder_type[k] = (Word16)random_range(0, 5);
        q_syn[k] = (Word16)random_range(-1, 4);
        snprintf(name, sizeof name, "synth%d", k); put16(name, synth[k], l_frame);
        snprintf(name, sizeof name, "pitch%d", k); put16(name, pitch[k], nb);
        snprintf(name, sizeof name, "bpf_off%d", k); put1(name, bpf_off[k]);
        snprintf(name, sizeof name, "null_pitch%d", k); put1(name, null_pitch[k]);
        snprintf(name, sizeof name, "v_stab%d", k); put1(name, v_stab[k]);
        snprintf(name, sizeof name, "coder_type%d", k); put1(name, coder_type[k]);
        snprintf(name, sizeof name, "q_syn%d", k); put1(name, q_syn[k]);
    }
    arrow();
    for (int k = 0; k < FRAMES; k++) {
        Word16 noise[L_FRAME16k];
        memset(noise, 0x55, sizeof noise);
        bass_psfilter_fx(opt_amr_wb, synth[k], l_frame, null_pitch[k] ? NULL : pitch[k], old_syn, &mem_deemph_err,
                         &lp_ener, bpf_off[k], v_stab[k], &v_stab_smooth, mem_mean_pit, track_on_hist, vibrato_hist,
                         &psf_att, coder_type[k], q_syn[k], noise);
        snprintf(name, sizeof name, "noise%d", k); put16(name, noise, l_frame);
        snprintf(name, sizeof name, "old_syn%d", k); put16(name, old_syn, NBPSF_PIT_MAX);
        Word16 st[5] = {mem_deemph_err, lp_ener, v_stab_smooth, psf_att, 0};
        snprintf(name, sizeof name, "state%d", k); put16(name, st, 4);
        snprintf(name, sizeof name, "mem_mean_pit%d", k); put16(name, mem_mean_pit, HIST);
        snprintf(name, sizeof name, "track_on_hist%d", k); put16(name, track_on_hist, HIST);
        snprintf(name, sizeof name, "vibrato_hist%d", k); put16(name, vibrato_hist, HIST);
    }
    end_line();
}

static void case_init(void)
{
    Word16 old_syn[NBPSF_PIT_MAX], mem = random16(), lp = random16();
    for (int i = 0; i < NBPSF_PIT_MAX; i++) old_syn[i] = random16();
    bass_psfilter_init_fx(old_syn, &mem, &lp);
    arrow(); put16("old_syn", old_syn, NBPSF_PIT_MAX); put1("mem", mem); put1("lp", lp); end_line();
}

static void case_add_bass_post_filter(void)
{
    static const Word16 bands_total[] = {16, 20, 32, 40, 60};
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    Word16 m = (next_random() & 1) ? 16 : 20;
    static Word32 r[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX], im[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX];
    Word32 *rp[CLDFB_NO_COL_MAX], *ip[CLDFB_NO_COL_MAX];
    static Word32 work[128 * 3];
    Word16 time[CLDFB_NO_COL_MAX * 20];
    CLDFB_SCALE_FACTOR sf;
    openCldfb(&h, CLDFB_ANALYSIS, 60, 960);
    configureCldfb(h, m, (Word16)(16 * m));
    if (next_random() & 1) {
        random_signal(h->FilterStates, 25 * m, random_range(1, 32767));
        for (int i = 0; i < 25; i++) h->FilterStates_e[i] = (Word16)random_range(-16, 4);
        h->FilterStates_eg = (Word16)random_range(-16, 4);
    }
    Word16 slots = (Word16)((next_random() % 4) ? CLDFB_NO_COL_MAX : random_range(0, CLDFB_NO_COL_MAX));
    Word16 total = CLDFB_NO_COL_MAX;
    Word16 nbands = bands_total[next_random() % 5];
    Word16 time_e = (Word16)random_range(-4, 16);
    memset(&sf, 0, sizeof sf);
    sf.lb_scale = (Word16)random_range(-20, 20);
    random_signal(time, slots * m, random_range(1, 32767));
    for (int k = 0; k < CLDFB_NO_COL_MAX; k++) {
        rp[k] = r[k]; ip[k] = im[k];
        for (int b = 0; b < CLDFB_NO_CHANNELS_MAX; b++) {
            r[k][b] = b < nbands ? (random32() >> random_range(0, 16)) : 0;
            im[k][b] = b < nbands ? (random32() >> random_range(0, 16)) : 0;
        }
    }
    put1("m", m); put16("states", h->FilterStates, 25 * m); put16("states_e", h->FilterStates_e, 25);
    put1("eg", h->FilterStates_eg); put1("slots", slots); put1("total", total); put1("nbands", nbands);
    put1("time_e", time_e); put1("lb_scale", sf.lb_scale); put16("time", time, slots * m);
    put32("r", &r[0][0], CLDFB_NO_COL_MAX * CLDFB_NO_CHANNELS_MAX);
    put32("i", &im[0][0], CLDFB_NO_COL_MAX * CLDFB_NO_CHANNELS_MAX);
    addBassPostFilterFx(time, rp, ip, h, work, time_e, slots, total, nbands, &sf);
    arrow();
    put32("r", &r[0][0], CLDFB_NO_COL_MAX * CLDFB_NO_CHANNELS_MAX);
    put32("i", &im[0][0], CLDFB_NO_COL_MAX * CLDFB_NO_CHANNELS_MAX);
    put1("lb_scale", sf.lb_scale); put16("states", h->FilterStates, 25 * m); put16("states_e", h->FilterStates_e, 25);
    end_line();
    deleteCldfb(&h);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "bass_psfilter")) case_bass_psfilter();
        else if (!strcmp(argv[2], "init")) case_init();
        else if (!strcmp(argv[2], "add_bass_post_filter")) case_add_bass_post_filter();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
