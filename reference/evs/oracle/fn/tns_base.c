/* Function-level oracle for lib_com/tns_base.c (InitTnsConfiguration). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

/* The TNS parameter table a configuration points at, as an index into this list (-1 = other). */
static int table_id(const struct TnsParameters *p)
{
    const struct TnsParameters *tables[] = {tnsParametersIGF32kHz_LowBR, tnsParameters32kHz, tnsParameters32kHz_grouped,
                                            tnsParameters16kHz, tnsParameters16kHz_grouped, tnsParameters48kHz_grouped};
    for (int i = 0; i < 6; i++) if (p == tables[i]) return i;
    return -1;
}

void put_tns_config(const char *prefix, STnsConfig *c)
{
    char name[64];
    sprintf(name, "%s_max_order", prefix); put1(name, c->maxOrder);
    sprintf(name, "%s_n_max_filters", prefix); put1(name, c->nMaxFilters);
    sprintf(name, "%s_table", prefix); put1(name, table_id(c->pTnsParameters));
    sprintf(name, "%s_borders", prefix); put16(name, c->iFilterBorders, 3);
}

/* InitTnsConfiguration at every TCX frame length (TCX10, TCX20, TCX20 after ACELP) of every
 * bandwidth, low and high bit rates, with and without an IGF stop frequency. */
static void case_init_tns_configuration(void)
{
    static const Word32 rates[] = {8000, 16000, 32000, 48000};
    static const Word16 lines[] = {160, 320, 640, 960};
    static const Word32 brates[] = {9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};
    static const Word16 igf_stop[] = {0, 0, 9600, 14400, 16000, 20000};
    int bw = next_random() % 4;
    Word32 sr = rates[bw];
    Word16 l = lines[bw];
    switch (next_random() % 3) { case 0: l = shr(l, 1); break; case 1: break; default: l = add(l, shr(l, 2)); }
    if (next_random() % 8 == 0) l = (Word16)random_range(16, 1200);
    Word32 brate = brates[next_random() % 9];
    if (bw == 0) brate = brates[next_random() % 5]; /* narrowband exists only up to 24.4 kbit/s (the reference asserts the 16 kHz tables' start lines are under Nyquist) */
    Word16 igf = igf_stop[next_random() % 6];
    STnsConfig c;
    memset(&c, 0, sizeof(c));
    for (int i = 0; i < 3; i++) c.iFilterBorders[i] = random16();
    put1("sr", sr); put1("frame_length", l); put1("igf_stop_freq", igf); put1("bitrate", brate);
    put16("borders", c.iFilterBorders, 3);
    Word16 err = InitTnsConfiguration(sr, l, &c, igf, brate);
    arrow(); put1("err", err); put_tns_config("c", &c); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "init_tns_configuration")) case_init_tns_configuration();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
