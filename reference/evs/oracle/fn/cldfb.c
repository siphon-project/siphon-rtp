/* Function-level oracle for lib_com/cldfb.c. The static helpers (cplxMult*, cplxMultAdd*,
 * calcModulation, calcModulationAndFolding, cldfb_init_proto_and_twiddles, cldfb_get_memory_length)
 * are proven through the public functions that reach them: analysis at every band count reaches
 * calcModulation at every m, synthesis at 10/20/40/60 bands reaches every calcModulationAndFolding
 * branch, open/configure reach the table setup, save_memory reaches the memory length. lerp is
 * proven by its own oracle (lerp.c) and again here inside resampleCldfb and cldfb_restore_memory.
 *
 * analysis and synthesis run several consecutive frames on one bank, so the filter-state memory and
 * the exponent bookkeeping carry from frame to frame, as in the decoder. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

static const Word16 analysis_bands[] = {10, 16, 20, 32, 40, 60};
static const Word16 synthesis_bands[] = {10, 20, 40, 60};

static void put_bank(HANDLE_CLDFB_FILTER_BANK h)
{
    put1("no_channels", h->no_channels); put1("no_col", h->no_col); put1("p_filter_length", h->p_filter_length);
    put1("filter_scale", h->filterScale); put1("syn_gain", h->synGain); put1("lsb", h->lsb); put1("usb", h->usb);
    put1("zeros", h->zeros); put1("ana_scalefactor", h->anaScalefactor); put1("syn_scalefactor", h->synScalefactor);
    put1("out_scalefactor", h->outScalefactor); put1("syn_filter_headroom", h->synFilterHeadroom);
    put1("flags", h->flags); put1("bands_to_zero", h->bandsToZero); put1("filtermode", h->filtermode);
    put1("type", h->type); put1("memory_length", h->memory_length); put1("scale", h->scale);
    put1("eg", h->FilterStates_eg); put16("states_e", h->FilterStates_e, 25);
    put16("p_filter", h->p_filter, 10 * h->no_channels);
    put16("r_rot", h->rRotVctr, h->no_channels / 2); put16("i_rot", h->iRotVctr, h->no_channels / 2);
}

/* openCldfb at a decoder setup, then (half the time) configureCldfb to another band count, as
 * resampleCldfb does on the first frame. */
static void case_open(void)
{
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    Word16 type = (Word16)(next_random() & 1);
    Word16 bands = type == CLDFB_ANALYSIS ? analysis_bands[random_range(0, 5)] : synthesis_bands[random_range(0, 3)];
    Word16 frame = (next_random() & 1) ? (Word16)(16 * bands) : 320;
    Word16 reconfigure = (Word16)(next_random() & 1);
    Word16 bands2 = analysis_bands[random_range(0, 5)];
    Word16 frame2 = (Word16)(16 * bands2);
    if (bands2 > bands) bands2 = bands, frame2 = (Word16)(16 * bands);
    put1("type", type); put1("bands", bands); put1("frame", frame);
    put1("reconfigure", reconfigure); put1("bands2", bands2); put1("frame2", frame2);
    openCldfb(&h, type, bands, frame);
    if (reconfigure) configureCldfb(h, bands2, frame2);
    arrow(); put_bank(h); end_line();
    deleteCldfb(&h);
}

static void random_states(Word16 *states, int n)
{
    int style = random_range(0, 2);
    if (style == 0) { memset(states, 0, n * sizeof(Word16)); return; }
    if (style == 1) { random_signal(states, n, random_range(1, 32767)); return; }
    for (int i = 0; i < n; i++) states[i] = random16();
}

/* A frame of time signal: mostly a random walk at a random level, sometimes edge values. */
static void random_time(Word16 *x, int n)
{
    static const int levels[] = {32767, 16000, 3000, 300, 20};
    if (random_range(0, 7) == 0) { for (int i = 0; i < n; i++) x[i] = random16(); return; }
    random_signal(x, n, levels[random_range(0, 4)]);
}

static Word16 random_slots(Word16 no_col)
{
    int pick = random_range(0, 7);
    if (pick < 4) return 16;
    if (pick == 4) return no_col;
    if (pick == 5) return 6; /* CLDFB_NO_COL_MAX_SWITCH */
    return (Word16)random_range(0, 16);
}

static void case_analysis(void)
{
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    Word16 m = analysis_bands[random_range(0, 5)];
    Word16 from_60 = (Word16)(next_random() & 1); /* the decoder opens at 48 kHz, then resamples */
    Word16 max_bands = from_60 ? 60 : m;
    Word16 frames = (Word16)random_range(1, 4);
    static Word32 r[16][CLDFB_NO_CHANNELS_MAX], im[16][CLDFB_NO_CHANNELS_MAX];
    Word32 *rp[16], *ip[16];
    static Word16 time[16 * CLDFB_NO_CHANNELS_MAX];
    static Word32 work[128 * 3];
    CLDFB_SCALE_FACTOR sf;
    char name[32];

    for (int k = 0; k < 16; k++) { rp[k] = r[k]; ip[k] = im[k]; }
    openCldfb(&h, CLDFB_ANALYSIS, max_bands, from_60 ? 320 : (Word16)(16 * m));
    if (from_60) configureCldfb(h, m, (Word16)(16 * m));
    random_states(h->FilterStates, 25 * max_bands);
    for (int i = 0; i < 25; i++) h->FilterStates_e[i] = (Word16)random_range(-16, 4);
    h->FilterStates_eg = (Word16)random_range(-16, 4);
    memset(&sf, 0, sizeof(sf));
    sf.lb_scale = (Word16)random_range(-20, 20);

    put1("m", m); put1("max_bands", max_bands); put1("frames", frames); put1("lb_scale", sf.lb_scale);
    put16("states", h->FilterStates, 25 * max_bands); put16("states_e", h->FilterStates_e, 25);
    put1("eg", h->FilterStates_eg);
    Word16 slots[4], exps[4];
    for (int f = 0; f < frames; f++) {
        slots[f] = random_slots(h->no_col);
        exps[f] = (Word16)random_range(-16, 4);
        random_time(time, slots[f] * m);
        sprintf(name, "slots%d", f); put1(name, slots[f]);
        sprintf(name, "time_e%d", f); put1(name, exps[f]);
        sprintf(name, "time%d", f); put16(name, time, slots[f] * m);
        /* run the frame now; its outputs are printed after the arrow once every input is out */
        static Word32 out_r[4][16 * CLDFB_NO_CHANNELS_MAX], out_i[4][16 * CLDFB_NO_CHANNELS_MAX];
        static Word16 out_lb[4];
        for (int k = 0; k < 16; k++) { memset(r[k], 0, sizeof(r[k])); memset(im[k], 0, sizeof(im[k])); }
        cldfbAnalysisFiltering(h, rp, ip, &sf, time, exps[f], slots[f], work);
        for (int k = 0; k < slots[f]; k++) {
            memcpy(&out_r[f][k * m], r[k], m * sizeof(Word32));
            memcpy(&out_i[f][k * m], im[k], m * sizeof(Word32));
        }
        out_lb[f] = sf.lb_scale;
        if (f == frames - 1) {
            arrow();
            for (int g = 0; g < frames; g++) {
                sprintf(name, "r%d", g); put32(name, out_r[g], slots[g] * m);
                sprintf(name, "i%d", g); put32(name, out_i[g], slots[g] * m);
                sprintf(name, "lb_scale%d", g); put1(name, out_lb[g]);
            }
            put16("states", h->FilterStates, 25 * max_bands); put16("states_e", h->FilterStates_e, 25);
            put1("eg", h->FilterStates_eg);
            end_line();
        }
    }
    deleteCldfb(&h);
}

/* Subband samples at a random headroom, as the analysis and the bandwidth extension leave them. */
static void random_subbands(Word32 *x, int n)
{
    int style = random_range(0, 3);
    int shift = random_range(0, 20);
    for (int i = 0; i < n; i++) {
        if (style == 0) x[i] = random32();
        else if (style == 3) x[i] = 0;
        else x[i] = (Word32)((next_random() << 1) ^ next_random()) >> shift;
    }
}

static void case_synthesis(void)
{
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    Word16 m = synthesis_bands[random_range(0, 3)];
    Word16 frames = (Word16)random_range(1, 4);
    static Word32 r[16][CLDFB_NO_CHANNELS_MAX], im[16][CLDFB_NO_CHANNELS_MAX];
    Word32 *rp[16], *ip[16];
    static Word16 out[4][16 * CLDFB_NO_CHANNELS_MAX];
    static Word32 work[128 * 3];
    CLDFB_SCALE_FACTOR sf;
    char name[32];
    Word16 slots[4];

    for (int k = 0; k < 16; k++) { rp[k] = r[k]; ip[k] = im[k]; }
    openCldfb(&h, CLDFB_SYNTHESIS, m, (Word16)(16 * m));
    random_states(h->FilterStates, 50 * m);
    h->FilterStates_eg = (Word16)random_range(-16, 4);
    put1("m", m); put1("frames", frames);
    put16("states", h->FilterStates, 50 * m); put1("eg", h->FilterStates_eg);
    for (int f = 0; f < frames; f++) {
        static const Word16 lsbs[] = {10, 16, 20, 32, 40, 60};
        Word16 lsb = lsbs[random_range(0, 5)];
        Word16 bz_pick = (Word16)random_range(0, 3);
        Word16 bands_to_zero = bz_pick == 0 ? 0 : bz_pick == 1 ? (Word16)(m - 10) : (Word16)random_range(0, m);
        Word16 time_e = (Word16)random_range(-16, 4);
        memset(&sf, 0, sizeof(sf));
        sf.lb_scale = (Word16)random_range(-5, 30);
        sf.hb_scale = (Word16)random_range(-5, 30);
        h->lsb = lsb < m ? lsb : m;
        h->usb = (next_random() & 3) ? m : (Word16)random_range(0, m);
        h->bandsToZero = bands_to_zero;
        slots[f] = random_slots(h->no_col);
        for (int k = 0; k < 16; k++) { random_subbands(r[k], m); random_subbands(im[k], m); }
        sprintf(name, "lsb%d", f); put1(name, h->lsb);
        sprintf(name, "usb%d", f); put1(name, h->usb);
        sprintf(name, "bz%d", f); put1(name, h->bandsToZero);
        sprintf(name, "lb_scale%d", f); put1(name, sf.lb_scale);
        sprintf(name, "hb_scale%d", f); put1(name, sf.hb_scale);
        sprintf(name, "time_e%d", f); put1(name, time_e);
        sprintf(name, "slots%d", f); put1(name, slots[f]);
        printf(" r%d=", f);
        for (int k = 0; k < slots[f]; k++) for (int j = 0; j < m; j++) printf((k || j) ? ",%d" : "%d", r[k][j]);
        printf(" i%d=", f);
        for (int k = 0; k < slots[f]; k++) for (int j = 0; j < m; j++) printf((k || j) ? ",%d" : "%d", im[k][j]);
        memset(out[f], 0, sizeof(out[f]));
        cldfbSynthesisFiltering(h, rp, ip, &sf, out[f], time_e, slots[f], work);
    }
    arrow();
    for (int f = 0; f < frames; f++) { sprintf(name, "out%d", f); put16(name, out[f], slots[f] * m); }
    put16("states", h->FilterStates, 50 * m); put1("eg", h->FilterStates_eg);
    end_line();
    deleteCldfb(&h);
}

static void case_save_memory(void)
{
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    Word16 type = (Word16)(next_random() & 1);
    Word16 m = type == CLDFB_ANALYSIS ? analysis_bands[random_range(0, 5)] : synthesis_bands[random_range(0, 3)];
    Word16 size = type == CLDFB_ANALYSIS ? (Word16)(25 * m) : (Word16)(50 * m);
    openCldfb(&h, type, m, (Word16)(16 * m));
    random_states(h->FilterStates, size);
    for (int i = 0; i < 25; i++) h->FilterStates_e[i] = random16();
    h->FilterStates_eg = random16();
    put1("type", type); put1("m", m); put16("states", h->FilterStates, size);
    put16("states_e", h->FilterStates_e, 25); put1("eg", h->FilterStates_eg);
    cldfb_save_memory(h);
    arrow(); put1("memory_length", h->memory_length); put16("memory", h->memory, h->memory_length + 26);
    put16("states", h->FilterStates, size);
    end_line();
    free(h->memory);
    h->memory = NULL;
    deleteCldfb(&h);
}

static void case_reset_memory(void)
{
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    Word16 type = (Word16)(next_random() & 1);
    Word16 m = type == CLDFB_ANALYSIS ? analysis_bands[random_range(0, 5)] : synthesis_bands[random_range(0, 3)];
    Word16 size = type == CLDFB_ANALYSIS ? (Word16)(25 * m) : (Word16)(50 * m);
    openCldfb(&h, type, m, (Word16)(16 * m));
    random_states(h->FilterStates, size);
    for (int i = 0; i < 25; i++) h->FilterStates_e[i] = random16();
    h->FilterStates_eg = random16();
    put1("type", type); put1("m", m); put16("states", h->FilterStates, size);
    put16("states_e", h->FilterStates_e, 25); put1("eg", h->FilterStates_eg);
    cldfb_reset_memory(h);
    arrow(); put16("states", h->FilterStates, size); put16("states_e", h->FilterStates_e, 25);
    put1("eg", h->FilterStates_eg);
    end_line();
    deleteCldfb(&h);
}

/* The decoder's resampling sequence: a bank opened at 48 kHz (or the BPF bank at 16 kHz),
 * resampled on the first frame to the core's band count, then switched between core rates with
 * firstFrame = 0 (which runs lerp on the states) with an analysis frame in between each switch. */
static void case_resample(void)
{
    static const Word16 core_bands[] = {16, 20};
    static const Word16 other_bands[] = {10, 16, 20, 32, 40, 60};
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    static Word32 r[16][CLDFB_NO_CHANNELS_MAX], im[16][CLDFB_NO_CHANNELS_MAX];
    Word32 *rp[16], *ip[16];
    static Word16 time[16 * CLDFB_NO_CHANNELS_MAX];
    static Word32 work[128 * 3];
    CLDFB_SCALE_FACTOR sf;
    char name[32];
    Word16 bpf = (Word16)(random_range(0, 3) == 0);
    Word16 max_bands = bpf ? 20 : 60;
    Word16 steps = (Word16)random_range(1, 4);

    for (int k = 0; k < 16; k++) { rp[k] = r[k]; ip[k] = im[k]; }
    memset(&sf, 0, sizeof(sf));
    openCldfb(&h, CLDFB_ANALYSIS, max_bands, 320);
    Word16 bands = core_bands[random_range(0, 1)];
    resampleCldfb(h, bands, (Word16)(16 * bands), 1);
    put1("bpf", bpf); put1("max_bands", max_bands); put1("bands", bands); put1("steps", steps);
    Word16 time_e = (Word16)random_range(-16, 4);
    put1("time_e", time_e);
    for (int s = 0; s < steps; s++) {
        Word16 next = bpf ? core_bands[random_range(0, 1)]
                          : (random_range(0, 3) ? core_bands[random_range(0, 1)] : other_bands[random_range(0, 5)]);
        random_time(time, 16 * h->no_channels);
        sprintf(name, "time%d", s); put16(name, time, 16 * h->no_channels);
        sprintf(name, "next%d", s); put1(name, next);
        cldfbAnalysisFiltering(h, rp, ip, &sf, time, time_e, 16, work);
        resampleCldfb(h, next, (Word16)(16 * next), 0);
    }
    arrow(); put1("no_channels", h->no_channels); put1("no_col", h->no_col); put1("flags", h->flags);
    put16("states", h->FilterStates, 25 * max_bands); put16("states_e", h->FilterStates_e, 25);
    put1("eg", h->FilterStates_eg);
    end_line();
    deleteCldfb(&h);
}

/* save, perturb the states as a filtering call would, restore. Half the cases change the band count
 * in between (set directly: configureCldfb would drop the save) so the lerp branch runs. */
static void case_restore_memory(void)
{
    HANDLE_CLDFB_FILTER_BANK h = NULL;
    Word16 type = (Word16)(next_random() & 1);
    Word16 m = type == CLDFB_ANALYSIS ? analysis_bands[random_range(0, 5)] : synthesis_bands[random_range(0, 3)];
    Word16 m2 = (next_random() & 1) ? m : (type == CLDFB_ANALYSIS ? analysis_bands[random_range(0, 5)] : synthesis_bands[random_range(0, 3)]);
    int size = type == CLDFB_ANALYSIS ? 25 * 60 : 50 * 60;
    openCldfb(&h, type, 60, 960);
    configureCldfb(h, m, (Word16)(16 * m));
    random_states(h->FilterStates, size);
    for (int i = 0; i < 25; i++) h->FilterStates_e[i] = random16();
    h->FilterStates_eg = random16();
    put1("type", type); put1("m", m); put1("m2", m2); put16("states", h->FilterStates, size);
    put16("states_e", h->FilterStates_e, 25); put1("eg", h->FilterStates_eg);
    cldfb_save_memory(h);
    random_states(h->FilterStates, size);
    for (int i = 0; i < 25; i++) h->FilterStates_e[i] = random16();
    h->FilterStates_eg = random16();
    put16("states_between", h->FilterStates, size); put16("states_e_between", h->FilterStates_e, 25);
    put1("eg_between", h->FilterStates_eg);
    h->no_channels = m2;
    cldfb_restore_memory(h);
    arrow(); put16("states", h->FilterStates, size); put16("states_e", h->FilterStates_e, 25);
    put1("eg", h->FilterStates_eg); put1("memory_length", h->memory_length);
    end_line();
    deleteCldfb(&h);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "open")) case_open();
        else if (!strcmp(argv[2], "analysis")) case_analysis();
        else if (!strcmp(argv[2], "synthesis")) case_synthesis();
        else if (!strcmp(argv[2], "save_memory")) case_save_memory();
        else if (!strcmp(argv[2], "reset_memory")) case_reset_memory();
        else if (!strcmp(argv[2], "resample")) case_resample();
        else if (!strcmp(argv[2], "restore_memory")) case_restore_memory();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
