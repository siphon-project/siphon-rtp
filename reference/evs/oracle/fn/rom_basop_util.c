/* Function-level oracle for lib_com/rom_basop_util.c (BASOP_getTables, getSineWindowTable). */
#include "harness.h"
#include "rom_basop_util.h"

extern const PWord16 SineTable320[];
const PWord16 *getSineWindowTable(Word16 length);
void BASOP_getTables(const PWord16 **ptwiddle, const PWord16 **sin_twiddle, Word16 *psin_step, Word16 length);

/* Lengths whose window slope exists (the C asserts otherwise), lengths where only the sine table and
 * step are asked for (BASOP_rfft's call), and lengths off both rasters. */
static const Word16 slope_lengths[] = {16, 32, 64, 128, 256, 10, 20, 40, 80, 160, 320};
static const Word16 sine_lengths[] = {32, 64, 256, 320, 512, 640, 1024, 20, 40, 160};
static const Word16 other_lengths[] = {0, 3, 6, 12, 24, 48, 96, 120, 240, 480, 600, 1000};
static long case_index;

static void put_pword(const char *name, const PWord16 *p, int n)
{
    printf(" %s=", name);
    for (int i = 0; i < n; i++) printf(i ? ",%d,%d" : "%d,%d", p[i].v.re, p[i].v.im);
}

static int sine_id(const PWord16 *p) { return p == SineTable512 ? 512 : p == SineTable320 ? 320 : p == NULL ? 0 : -1; }

static void case_basop_get_tables(void)
{
    const PWord16 *twiddle = NULL, *sine = NULL;
    Word16 step = -1;
    int group = (int)(case_index % 3);
    long k = case_index / 3;
    case_index++;
    if (group == 0) {
        Word16 length = slope_lengths[k % 11];
        BASOP_getTables(&twiddle, &sine, &step, length);
        put1("length", length); put1("mode", 0); arrow();
        put_pword("twiddle", twiddle, length / 2); put1("sine", sine_id(sine)); put1("step", step);
    } else if (group == 1) {
        Word16 length = sine_lengths[k % 10];
        BASOP_getTables(NULL, &sine, &step, length);
        put1("length", length); put1("mode", 1); arrow();
        put1("sine", sine_id(sine)); put1("step", step);
    } else {
        Word16 length = other_lengths[k % 12];
        sine = SineTable512;
        BASOP_getTables(NULL, &sine, NULL, length);
        put1("length", length); put1("mode", 2); arrow();
        put1("sine", sine_id(sine));
    }
    end_line();
}

static void case_get_sine_window_table(void)
{
    static const Word16 lengths[] = {10, 16, 20, 30, 32, 40, 48, 60, 70, 96, 112, 120, 140, 180, 224, 280, 420};
    Word16 length = lengths[case_index++ % 17];
    /* SineWindow60 is a full 60-entry table, every other one holds length / 2 entries. */
    int entries = length == 60 ? 60 : length / 2;
    put1("length", length); arrow(); put_pword("table", getSineWindowTable(length), entries); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "basop_get_tables")) case_basop_get_tables();
        else if (!strcmp(argv[2], "get_sine_window_table")) case_get_sine_window_table();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
