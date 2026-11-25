/* Whole-decoder-state oracle for the MODE2 driver (lib_dec/dec_LPD.c decoder_LPD, lib_dec/dec_acelp_tcx_main.c
 * dec_acelp_tcx_frame, and the MODE2 part of lib_dec/evs_dec_fx.c).
 *
 * The functions need a decoder that has run: ROM pointers, filter banks, FD-CNG, TCX windows and the concealment
 * memories are all configured by earlier frames, and a state dump does not restore the ROM-pointer fields. So the
 * oracle runs the reference decoder loop (lib_dec/decoder.c: io_ini_dec_fx, read_indices_fx, evs_dec_fx, the frame
 * counter) over TS 26.444 decoder sequences that reach MODE2 (ACELP / TCX20 / TCX10 at 9.6 to 128 kbit/s, the
 * 13.2 / 32 kbit/s switching streams, channel-aware, DTX, frame erasures, bit rate and bandwidth switching), and
 * prints the WHOLE decoder state (prefix "in.") after chosen frames together with that frame's output; the Rust test
 * runs the same bit stream through the port in step and compares every field after each printed frame, so the first
 * wrong field of decoder_LPD, dec_acelp_tcx_frame or the MODE2 part of evs_dec is named.
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
    SEQ("wb", "stv16c_9600_16kHz.COD", 16),
    SEQ("wb", "stv16c_9600_16kHz.f06.COD", 16),
    SEQ("wb", "stv16c_16400_16kHz.COD", 16),
    SEQ("wb", "stv16c_16400_16kHz.b10.COD", 16),
    SEQ("wb", "stv16c_24400_16kHz.f06.COD", 16),
    SEQ("wb", "stv16c_13200_16kHz.COD", 16),
    SEQ("wb", "stv16c_32000_16kHz.COD", 16),
    SEQ("wb", "stv16c_48000_16kHz.COD", 16),
    SEQ("wb", "stv16c_96000_16kHz.b10.COD", 16),
    SEQ("wb", "stv16c_128000_16kHz.COD", 16),
    SEQ("wb", "stv16c_dtx_9600_16kHz.COD", 16),
    SEQ("wb", "stv16c_dtx_24400_16kHz.b10.COD", 16),
    SEQ("wb", "stv16c_dtx_48000_16kHz.COD", 16),
    SEQ("wb", "stv16c_rfHI3_13200_16kHz.COD", 16),
    SEQ("wb", "stv16c_rfrf_config.cfg_13200_16kHz.b10.COD", 16),
    SEQ("wb", "stv16c_dtx_rfHI3_13200_16kHz.f06.COD", 16),
    SEQ("wb", "stv16c_dtx_sw_59_1280_16kHz.COD", 16),
    SEQ("nb", "stv8c_9600_8kHz.COD", 8),
    SEQ("nb", "stv8c_16400_8kHz.b10.COD", 8),
    SEQ("nb", "stv8c_24400_8kHz.COD", 8),
    SEQ("nb", "stv8c_dtx_9600_8kHz.f06.COD", 8),
    SEQ("nb", "stv8c_sw_72_244_8kHz.COD", 8),
    SEQ("swb", "stv32c_9600_32kHz.COD", 32),
    SEQ("swb", "stv32c_16400_32kHz.f06.COD", 32),
    SEQ("swb", "stv32c_24400_32kHz.COD", 32),
    SEQ("swb", "stv32c_13200_32kHz.COD", 32),
    SEQ("swb", "stv32c_32000_32kHz.COD", 32),
    SEQ("swb", "stv32c_48000_32kHz.b10.COD", 32),
    SEQ("swb", "stv32c_96000_32kHz.COD", 32),
    SEQ("swb", "stv32c_128000_32kHz.f06.COD", 32),
    SEQ("swb", "stv32c_dtx_16400_32kHz.COD", 32),
    SEQ("swb", "stv32c_dtx_48000_32kHz.b10.COD", 32),
    SEQ("swb", "stv32c_dtx_rfrf_config.cfg_13200_32kHz.COD", 32),
    SEQ("swb", "stv32c_dtx_sw_59_164_32kHz.COD", 32),
    SEQ("swb", "stv32c_dtx_sw_96_1280_32kHz.f06.COD", 32),
    SEQ("swb", "stv32c_bw_59_1280_32kHz.COD", 32),
    SEQ("fb", "stv48c_16400_48kHz.COD", 48),
    SEQ("fb", "stv48c_24400_48kHz.b10.COD", 48),
    SEQ("fb", "stv48c_32000_48kHz.COD", 48),
    SEQ("fb", "stv48c_48000_48kHz.f06.COD", 48),
    SEQ("fb", "stv48c_96000_48kHz.COD", 48),
    SEQ("fb", "stv48c_128000_48kHz.COD", 48),
    SEQ("fb", "stv48c_dtx_16400_48kHz.f06.COD", 48),
    SEQ("fb", "stv48c_dtx_128000_48kHz.COD", 48),
    SEQ("fb", "stv48c_sw_164_1280_48kHz.COD", 48),
    SEQ("fb", "stv48c_sw_72_244_48kHz.b10.COD", 48),
    SEQ("fb", "stv48c_dtx_sw_59_244_48kHz.COD", 48),
    SEQ("fb", "stv48c_bw_59_1280_48kHz.COD", 48),
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

/* Decode one sequence; print the whole state after each target frame in `wanted` (ascending, PER_SEQUENCE long, 100 apart) or
 * after the first concealed frame following it. */
static void run_sequence(int index, const char *root, const int *wanted, int stdout_fd)
{
    char path[4608], khz[8];
    snprintf(path, sizeof(path), "%s/%s", root, sequences[index].path);
    snprintf(khz, sizeof(khz), "%d", sequences[index].khz);
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

    int next_wanted = 0;
    for (int n = 0; read_indices_fx(st, f_stream, 0) && next_wanted < PER_SEQUENCE; n++) {
        if (st->codec_mode == MODE1) {
            if (st->Opt_AMR_WB_fx) amr_wb_dec_fx(output, st);
            else evs_dec_fx(st, output, FRAMEMODE_NORMAL);
        } else {
            evs_dec_fx(st, output, st->bfi_fx == 0 ? FRAMEMODE_NORMAL : FRAMEMODE_MISSING);
        }
        if (st->ini_frame_fx < MAX_FRAME_COUNTER) st->ini_frame_fx = add(st->ini_frame_fx, 1);
        /* at the target frame, or after it at the first concealed one (a frame-erased stream), within 60 frames */
        if (n >= wanted[next_wanted] && (st->bfi_fx || n >= wanted[next_wanted] + 60)) {
            char *state = capture_state(st);
            fflush(stdout);
            int null_fd = dup(1);
            dup2(stdout_fd, 1);
            printf("sequence=%d frame=%d khz=%d output_frame=%d path=", index, n, sequences[index].khz, st->output_frame_fx);
            for (const char *c = sequences[index].path; *c; c++) printf(c == sequences[index].path ? "%d" : ",%d", *c);
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
    }
    fclose(f_stream);
    fclose(f_synth);
    free(st);
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
    for (int index = 0, done = 0; done < count; index = (index + 1) % NSEQ) {
        int wanted[PER_SEQUENCE];
        wanted[0] = random_range(0, 14);
        wanted[1] = random_range(100, 199);
        wanted[2] = random_range(300, 399);
        wanted[3] = random_range(600, 700);
        run_sequence(index, root, wanted, stdout_fd);
        done += PER_SEQUENCE;
    }
    return 0;
}
