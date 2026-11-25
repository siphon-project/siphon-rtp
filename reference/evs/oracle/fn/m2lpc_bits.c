/* Function-level oracle for lib_com/bits_alloc.c (BITS_ALLOC_init_config_acelp, BITS_ALLOC_config_acelp,
 * BITS_ALLOC_adjust_acelp_fixed_cdk with its static BITS_ALLOC_adjust_generic). */
#include <unistd.h>
#include <fcntl.h>
#include "harness.h"
#include "cnst_fx.h"
#include "prot_fx.h"
#include "rom_com_fx.h"


static void put_config(const ACELP_config *c)
{
    Word16 f[] = {c->mode_index, c->midLpc, c->midLpc_enable, c->pre_emphasis, c->pitch_sharpening, c->phase_scrambling,
                  c->formant_enh, c->formant_tilt, c->voice_tilt, c->formant_enh_num, c->formant_enh_den, c->bpf_mode,
                  c->nrg_mode, c->nrg_bits, c->ltp_mode, c->ltp_bits, c->ltf_mode, c->ltf_bits};
    put16("config", f, sizeof(f) / sizeof(f[0]));
    put16("gains_mode", c->gains_mode, NB_SUBFR16k);
    put16("fixed_cdk_index", c->fixed_cdk_index, NB_SUBFR16k);
}

static const Word32 mode2_rates[] = {9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};

static void case_init_config(void)
{
    ACELP_config config;
    memset(&config, 0x5a, sizeof(config));
    Word32 rate = mode2_rates[next_random() % 9];
    Word8 narrow = (Word8)(next_random() % 3 == 0);
    Word16 nb_subfr = (Word16)(next_random() & 1 ? 4 : 5);
    put1("rate", rate); put1("narrow", narrow); put1("nb_subfr", nb_subfr);
    BITS_ALLOC_init_config_acelp(rate, narrow, nb_subfr, &config);
    arrow(); put_config(&config); end_line();
}

static void case_config_acelp(void)
{
    ACELP_config config;
    memset(&config, 0, sizeof(config));
    Word32 rate = mode2_rates[next_random() % 9];
    Word16 narrow = (Word16)(next_random() % 3 == 0);
    Word16 nb_subfr = (Word16)(next_random() & 1 ? 4 : 5);
    BITS_ALLOC_init_config_acelp(rate, (Word8)narrow, nb_subfr, &config);
    Word16 coder_type = (Word16)random_range(0, 6);
    Word16 bits_frame = (Word16)(next_random() % 4 == 0 ? random_range(0, 60) : random_range(60, 700));
    for (int i = 0; i < NB_SUBFR16k; i++) { config.gains_mode[i] = 55; config.fixed_cdk_index[i] = 66; }
    put1("rate", rate); put1("narrow", narrow); put1("nb_subfr", nb_subfr); put1("coder_type", coder_type);
    put1("bits_frame", bits_frame);
    /* the reference prints a warning for a budget that is too small */
    fflush(stdout);
    int saved = dup(1), null = open("/dev/null", O_WRONLY);
    dup2(null, 1);
    Word16 r = BITS_ALLOC_config_acelp(bits_frame, coder_type, &config, narrow, nb_subfr);
    fflush(stdout);
    dup2(saved, 1); close(saved); close(null);
    arrow(); put1("r", r); put_config(&config); end_line();
}

static void case_adjust(void)
{
    Word16 index[NB_SUBFR16k];
    Word16 nb_subfr = (Word16)(next_random() & 1 ? 4 : 5);
    Word16 bits_frame = (Word16)(next_random() % 5 == 0 ? random_range(0, 40) : random_range(40, 400));
    for (int i = 0; i < NB_SUBFR16k; i++) index[i] = 66;
    put1("nb_subfr", nb_subfr); put1("bits_frame", bits_frame);
    Word16 r = BITS_ALLOC_adjust_acelp_fixed_cdk(bits_frame, index, nb_subfr);
    arrow(); put1("r", r); put16("index", index, NB_SUBFR16k); end_line();
}

/* A three-level map: top (2 bit count, zero allowed) -> mid (a value with an encode / decode function, which takes
 * care of zero itself, and a 3 bit non-zero value) -> leaf (1 bit non-zero). The set function stores the value at p[index] and, for an odd
 * value, hands out p + 8 as the sub-structure. */
int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    struct { const char *name; void (*run)(void); } table[] = {
        {"init_config", case_init_config}, {"config_acelp", case_config_acelp}, {"adjust", case_adjust}
    };
    void (*run)(void) = NULL;
    for (unsigned k = 0; k < sizeof(table) / sizeof(table[0]); k++) if (!strcmp(argv[2], table[k].name)) run = table[k].run;
    if (!run) { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    for (long i = 0, n = atol(argv[3]); i < n; i++) run();
    return 0;
}
