/* Whole-decoder-state oracle for the AMR-WB IO decoder (lib_dec/amr_wb_dec_fx.c and what it reaches:
 * decod_amr_wb_fx, gain_dec_amr_wb_fx, improv_amr_wb_gs_fx, hf_synth_amr_wb_fx, updt_IO_switch_dec_fx, and the
 * AMR-WB IO branch of lib_dec/decoder.c).
 *
 * The functions need a decoder that has run: ROM pointers, filter banks, FD-CNG and the concealment memories are
 * configured by earlier frames, and a state dump does not restore the ROM-pointer fields. So the oracle runs the
 * reference decoder loop (lib_dec/decoder.c: io_ini_dec_fx, read_indices_fx, amr_wb_dec_fx / evs_dec_fx, the frame
 * counter) over TS 26.444 decoder sequences that reach AMR-WB IO (all nine bit rates, SID and no-data frames,
 * frame erasures, bit-rate switching between AMR-WB IO and EVS primary modes in both directions), and prints the
 * WHOLE decoder state (prefix "in.") after chosen frames together with that frame's output; the Rust test runs the
 * same bit stream through the port in step and compares every field after each printed frame, so the first wrong
 * field is named.
 *
 * Debugging: with $P4IO_PATH (a path under testvec), $P4IO_KHZ, $P4IO_FROM and $P4IO_TO set, `corpus decode 0 0`
 * prints every frame FROM..TO of that one sequence.
 *
 * Sequences are found under $SIPHON_RTP_EVS_VECTORS or the testvec directory next to the build directory. */
#define STATE_DUMP_LIBRARY
#include <unistd.h>
#include <fcntl.h>
#include "init_dec.c"
#include "state_capture.h"
#include "hq_bit_allocation_inputs.h"

long frame = 0;

typedef struct { const char *path; int khz; } Sequence;

#define SEQ(dir, name, khz) {"testv/bitstreams/" dir "/" name, khz}
static const Sequence sequences[] = {
    SEQ("amrwb", "T01_6600_16kHz.COD", 16),
    SEQ("amrwb", "T02_8850_16kHz.f06.COD", 16),
    SEQ("amrwb", "T03_12650_16kHz.COD", 16),
    SEQ("amrwb", "T05_14250_16kHz.b10.COD", 16),
    SEQ("amrwb", "T07_15850_16kHz.f06.COD", 16),
    SEQ("amrwb", "T09_19850_16kHz.COD", 16),
    SEQ("amrwb", "T11_23050_16kHz.f06.COD", 16),
    SEQ("amrwb", "T13_23850_16kHz.COD", 16),
    SEQ("amrwb", "T15_dtx_6600_16kHz.COD", 16),
    SEQ("amrwb", "T17_dtx_12650_16kHz.f06.COD", 16),
    SEQ("amrwb", "T19_dtx_15850_16kHz.b10.COD", 16),
    SEQ("amrwb", "T21_dtx_23850_16kHz.COD", 16),
    SEQ("amrwb", "T04_sw_amrwb_16kHz.COD", 16),
    SEQ("amrwb", "T06_sw_amrwb_evs_16kHz.COD", 16),
    SEQ("amrwb", "T08_sw_amrwb_evs_16kHz.f06.COD", 16),
    SEQ("amrwb", "T10_dtx_sw_amrwb_16kHz.COD", 16),
    SEQ("amrwb", "T12_dtx_sw_amrwb_evs_16kHz.COD", 16),
    SEQ("amrwb", "T14_dtx_sw_amrwb_evs_16kHz.b10.COD", 16),
    SEQ("amrwb", "Dtx1_dtx_12650_16kHz.COD", 16),
    SEQ("amrwb", "Dtx2_dtx_sw_amrwb_evs_16kHz.COD", 16),
    SEQ("swb", "stv32c_bw_59_1280_evs_amrwb_32kHz.COD", 32),
    SEQ("swb", "stv32n1_dtx_bw_59_1280_evs_amrwb_32kHz.f06.COD", 32),
    SEQ("fb", "stv48c_bw_59_1280_evs_amrwb_48kHz.COD", 48),
    SEQ("fb", "stv48n2_dtx_bw_59_1280_evs_amrwb_48kHz.b10.COD", 48),
};
#define NSEQ (int)(sizeof(sequences) / sizeof(sequences[0]))
#define PER_SEQUENCE 4

/* the directory holding testv/ */
static const char *vectors_root(const char *argv0)
{
    static char root[4096];
    const char *env = getenv("SIPHON_RTP_EVS_VECTORS");
    if (env && *env) return env;
    snprintf(root, sizeof(root), "%s", argv0);
    char *slash = strrchr(root, '/');
    if (slash) *slash = 0; else snprintf(root, sizeof(root), ".");
    strncat(root, "/../testvec", sizeof(root) - strlen(root) - 1);
    return root;
}

/* Decode one sequence. With `from` >= 0 print the whole state after every frame in [from, to]; with `targets` print it
 * after those frames; with neither (`bfi_out` set) only record in bfi_out[n] whether frame n is a lost one. */
static int run_sequence(int index, const char *rel_path, int output_khz, const char *root, const int *targets, int from, int to,
                        int stdout_fd, unsigned char *bfi_out)
{
    char path[4608], khz[8];
    snprintf(path, sizeof(path), "%s/%s", root, rel_path);
    snprintf(khz, sizeof(khz), "%d", output_khz);
    /* io_ini_dec_fx rewrites its arguments in place */
    char name[] = "EVS_dec", quiet[] = "-q", output_path[] = "/dev/null";
    char *argv[] = {name, quiet, khz, path, output_path, NULL};
    int argc = 5;
    UWord16 bit_stream[MAX_BITS_PER_FRAME + 16];
    Word16 output[L_FRAME48k];
    FILE *f_stream, *f_synth;
    Word16 quiet_mode = 0, no_delay_cmp = 0;
    char *jbm_trace = NULL, *jbm_fec = NULL;
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));

    st->bit_stream_fx = bit_stream;
    io_ini_dec_fx(argc, argv, &f_stream, &f_synth, &quiet_mode, &no_delay_cmp, st, &jbm_trace, &jbm_fec);
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    reset_indices_dec_fx(st);
    init_decoder_fx(st);
    rd_record_cldfb(st);

    int next_wanted = 0, frames = 0;
    for (int n = 0; read_indices_fx(st, f_stream, 0); n++) {
        frames = n + 1;
        if (bfi_out) bfi_out[n] = (unsigned char)(st->bfi_fx != 0);
        if (st->codec_mode == MODE1) {
            if (st->Opt_AMR_WB_fx) amr_wb_dec_fx(output, st);
            else evs_dec_fx(st, output, FRAMEMODE_NORMAL);
        } else {
            evs_dec_fx(st, output, st->bfi_fx == 0 ? FRAMEMODE_NORMAL : FRAMEMODE_MISSING);
        }
        if (st->ini_frame_fx < MAX_FRAME_COUNTER) st->ini_frame_fx = add(st->ini_frame_fx, 1);
        int dump = from >= 0 ? (n >= from && n <= to) : (targets && next_wanted < PER_SEQUENCE && n == targets[next_wanted]);
        if (dump) {
            char *state = capture_state(st);
            fflush(stdout);
            int null_fd = dup(1);
            dup2(stdout_fd, 1);
            printf("sequence=%d frame=%d khz=%d output_frame=%d path=", index, n, output_khz, st->output_frame_fx);
            for (const char *c = rel_path; *c; c++) printf(c == rel_path ? "%d" : ",%d", *c);
            put16("output", output, st->output_frame_fx);
            put_state_in(state);
            arrow();
            end_line();
            fflush(stdout);
            dup2(null_fd, 1);
            close(null_fd);
            free(state);
            next_wanted++;
        }
        if (from >= 0 && n >= to) break;
        if (targets && next_wanted >= PER_SEQUENCE) break;
    }
    fclose(f_stream);
    fclose(f_synth);
    free(st);
    return frames;
}

/* Target frames: one in each quarter of the sequence, a lost frame where the quarter has one (so the concealment is
 * dumped), the first of them early in the stream where the start-up paths are. */
static void pick_targets(int *targets, const unsigned char *bfi, int frames, const int *wanted)
{
    for (int k = 0; k < PER_SEQUENCE; k++) {
        int lo = frames * k / PER_SEQUENCE, hi = frames * (k + 1) / PER_SEQUENCE - 1, lost = 0;
        for (int n = lo; n <= hi; n++) lost += bfi[n];
        if (lost > 0) {
            int pick = wanted[k] % lost;
            for (int n = lo; n <= hi; n++) if (bfi[n] && pick-- == 0) { targets[k] = n; break; }
        } else {
            targets[k] = lo + wanted[k] % (hi - lo + 1);
        }
    }
    if (!bfi[wanted[0] % 15] && wanted[0] % 3 == 0) targets[0] = wanted[0] % 15;
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus") || strcmp(argv[2], "decode")) {
        fprintf(stderr, "usage: corpus decode COUNT SEED\n");
        return 2;
    }
    long count = atol(argv[3]);
    seed_random(argv[4]);
    const char *root = vectors_root(argv[0]);
    /* the reference prints progress and warnings: keep stdout for the corpus lines only */
    fflush(stdout);
    int stdout_fd = dup(1), null = open("/dev/null", O_WRONLY);
    dup2(null, 1);
    close(null);
    const char *debug_path = getenv("P4IO_PATH");
    if (debug_path && *debug_path) {
        const char *debug_khz = getenv("P4IO_KHZ");
        run_sequence(0, debug_path, debug_khz ? atoi(debug_khz) : 16, root, NULL, atoi(getenv("P4IO_FROM")), atoi(getenv("P4IO_TO")), stdout_fd, NULL);
        return 0;
    }
    for (int index = 0, done = 0; done < count; index = (index + 1) % NSEQ) {
        int wanted[PER_SEQUENCE];
        for (int k = 0; k < PER_SEQUENCE; k++) wanted[k] = random_range(0, 1000);
        static unsigned char bfi[20000];
        int targets[PER_SEQUENCE];
        int frames = run_sequence(index, sequences[index].path, sequences[index].khz, root, NULL, -1, -1, stdout_fd, bfi);
        pick_targets(targets, bfi, frames, wanted);
        run_sequence(index, sequences[index].path, sequences[index].khz, root, targets, -1, -1, stdout_fd, NULL);
        done += PER_SEQUENCE;
    }
    return 0;
}
