/* Function-level oracle for lib_dec/init_dec_fx.c (init_decoder_fx, reset_preecho_dec_fx,
 * destroy_decoder).
 *
 * init_decoder_fx turns a calloc'ed Decoder_State_fx into a working decoder, so its oracle prints
 * the WHOLE state after the call: every integer field of every struct reachable from the state
 * (the CLDFB banks and FD-CNG through their handles included), ROM table pointers by their first
 * entries, pointers into the state's own arrays as offsets. The dump below and the Rust walk in
 * crates/siphon-rtp-codec/tests/evs_fn_oracle/state_dump.rs are generated together by one gdb walk
 * over the reference's debug info, so the two sides cannot drift; regenerate both together.
 *
 * Cases: each output rate (8, 16, 32, 48 kHz), on a calloc'ed state and on one whose every integer
 * field was first filled with a deterministic pattern (so a field init does not write, or one it
 * reads before writing, shows up as a difference).
 *
 * acelp_core_switch_dec.c includes this file with STATE_DUMP_LIBRARY defined to reuse the dump. */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

/* -------- runtime of the generated state dump -------- */

static unsigned int rd_pattern_state;

static int rd_pattern_next(void)
{
    rd_pattern_state = rd_pattern_state * 1103515245u + 12345u;
    return (int)((rd_pattern_state >> 16) & 0x7fff) - 16384;
}

static void rd_fill_i8(signed char *x, int n) { for (int i = 0; i < n; i++) x[i] = (signed char)rd_pattern_next(); }
static void rd_fill_u8(unsigned char *x, int n) { for (int i = 0; i < n; i++) x[i] = (unsigned char)rd_pattern_next(); }
static void rd_fill_i16(Word16 *x, int n) { for (int i = 0; i < n; i++) x[i] = (Word16)rd_pattern_next(); }
static void rd_fill_u16(UWord16 *x, int n) { for (int i = 0; i < n; i++) x[i] = (UWord16)rd_pattern_next(); }
static void rd_fill_i32(Word32 *x, int n) { for (int i = 0; i < n; i++) x[i] = (Word32)rd_pattern_next() * 65537; }
static void rd_fill_u32(UWord32 *x, int n) { for (int i = 0; i < n; i++) x[i] = (UWord32)((Word32)rd_pattern_next() * 65537); }

static void rd_key(const char *pre, const char *name) { printf(" %s%s=", pre, name); }
static void rd_put1(const char *pre, const char *name, long long v) { rd_key(pre, name); printf("%lld", v); }
#define RD_PUT(suffix, type)                                                                     \
    static void rd_put_##suffix(const char *pre, const char *name, const type *x, int n)          \
    {                                                                                             \
        rd_key(pre, name);                                                                        \
        for (int i = 0; i < n; i++) printf(i ? ",%lld" : "%lld", (long long)x[i]);                 \
    }
RD_PUT(i8, signed char)
RD_PUT(u8, unsigned char)
RD_PUT(i16, Word16)
RD_PUT(u16, UWord16)
RD_PUT(i32, Word32)
RD_PUT(u32, UWord32)
static void rd_put16(const char *pre, const char *name, const Word16 *x, int n) { rd_put_i16(pre, name, x, n); }

/* A ROM table is identified by its first entries (NULL prints empty). */
static void rd_put_rom16(const char *pre, const char *name, const Word16 *x) { rd_put_i16(pre, name, x, x == NULL ? 0 : 8); }
static void rd_put_romp16(const char *pre, const char *name, const PWord16 *x) { rd_put_i16(pre, name, (const Word16 *)x, x == NULL ? 0 : 16); }

static long long rd_tns_table_id(const struct TnsParameters *p)
{
    const struct TnsParameters *tables[] = {tnsParametersIGF32kHz_LowBR, tnsParameters32kHz, tnsParameters32kHz_grouped,
                                            tnsParameters16kHz, tnsParameters16kHz_grouped, tnsParameters48kHz_grouped};
    for (int i = 0; i < 6; i++) if (p == tables[i]) return i;
    return -1;
}

/* Which of two rows a pointer points at: 0, 1, -1 for NULL, -2 elsewhere. */
static long long rd_row(const Word16 *p, const Word16 *row0, const Word16 *row1)
{
    if (p == NULL) return -1;
    if (p == row0) return 0;
    if (p == row1) return 1;
    return -2;
}

static FD_CNG_DEC *rd_parent_fd_cng_dec;
static struct tonalmdctconceal *rd_parent_tonal;

/* The FilterStates allocation of a CLDFB bank, recorded by the harness when it opens the banks
 * (openCldfb sizes it from the band count at open time, which resampleCldfb later changes). */
static HANDLE_CLDFB_FILTER_BANK rd_cldfb_handles[3];
static int rd_cldfb_lengths[3];

static void rd_record_cldfb(Decoder_State_fx *st)
{
    rd_cldfb_handles[0] = st->cldfbAna_fx; rd_cldfb_lengths[0] = 25 * CLDFB_getNumChannels(48000);
    rd_cldfb_handles[1] = st->cldfbBPF_fx; rd_cldfb_lengths[1] = 25 * CLDFB_getNumChannels(16000);
    rd_cldfb_handles[2] = st->cldfbSyn_fx; rd_cldfb_lengths[2] = 2 * 25 * CLDFB_getNumChannels(st->output_Fs_fx);
}

static int rd_cldfb_states_length(HANDLE_CLDFB_FILTER_BANK p)
{
    for (int i = 0; i < 3; i++) if (p == rd_cldfb_handles[i]) return rd_cldfb_lengths[i];
    fprintf(stderr, "unknown CLDFB bank\n");
    exit(1);
}

/* -------- BEGIN GENERATED STATE DUMP (rd_dump_* / rd_fill_*) -------- */
