/* Function-level oracle for lib_com/bitstream_fx.c (the decoder half).
 *
 * read_indices: a synthetic G.192 frame of every EVS / AMR-WB IO size, good or bad, random or
 * all-zero bits, against a decoder state whose DTX / codec-selection fields are randomised; the
 * frame goes through read_indices_fx exactly as EVS_dec feeds it, from a FILE*.
 * stream: (not a corpus) `fn_bitstream stream FILE.COD` runs every frame of a real bitstream
 * through read_indices_fx on one persistent state and prints the state after each frame.
 */
#include "harness.h"
#include "../../c-code/lib_com/bitstream_fx.c"

#define BUFFER_BITS (MAX_BITS_PER_FRAME + 16)

static UWord16 bit_buffer[BUFFER_BITS];

static Decoder_State_fx *new_state(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    memset(bit_buffer, 0, sizeof(bit_buffer));
    st->bit_stream_fx = bit_buffer;
    return st;
}

static const int sizes[] = {0, 35, 48, 56, 132, 177, 253, 285, 317, 365, 397, 461, 477,
                            144, 160, 192, 264, 328, 488, 640, 960, 1280, 1920, 2560};

static int random_size(void) { return sizes[next_random() % (sizeof(sizes) / sizeof(sizes[0]))]; }

static void random_bits(Word16 *bits, int n)
{
    int mode = next_random() % 8;
    for (int i = 0; i < n; i++) bits[i] = mode == 0 ? 0 : mode == 1 ? 1 : (Word16)(next_random() & 1);
}

static void put_state(const Decoder_State_fx *st, int stream_bits)
{
    put1("bfi", st->bfi_fx); put1("ber_detect", st->BER_detect);
    put1("mdct_sw_enable", st->mdct_sw_enable); put1("mdct_sw", st->mdct_sw);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("total_num_bits", st->total_num_bits);
    put1("total_brate", st->total_brate_fx); put1("codec_mode", st->codec_mode);
    put1("last_codec_mode", st->last_codec_mode); put1("opt_amr_wb", st->Opt_AMR_WB_fx);
    put1("cng", st->CNG_fx); put1("prev_ft_speech", st->prev_ft_speech_fx);
    put1("cng_type", st->cng_type_fx); put1("last_cng_type", st->last_cng_type_fx);
    put1("core", st->core_fx); put1("bwidth", st->bwidth_fx); put1("m_frame_type", st->m_frame_type);
    if (stream_bits >= 0) put_u16("bit_stream", st->bit_stream_fx, stream_bits);
}

/* The fields read_indices_fx and what it calls read, randomised, then printed as inputs. */
static void randomise_reader_state(Decoder_State_fx *st)
{
    static const Word32 last_rates[] = {0, 2400, 7200, 13200, 13200, 16400, 32000, 64000};
    st->ini_frame_fx = (Word16)(next_random() % 3);
    st->last_codec_mode = (Word16)random_range(-1, 2);
    st->codec_mode = (Word16)random_range(0, 2);
    st->core_fx = (Word16)(next_random() % 4 == 0 ? AMR_WB_CORE : random_range(-1, 3));
    st->bwidth_fx = (Word16)random_range(0, 3);
    st->prev_ft_speech_fx = (Word16)(next_random() & 1);
    st->CNG_fx = (Word16)(next_random() & 1);
    st->Opt_AMR_WB_fx = (Word16)(next_random() & 1);
    st->last_total_brate_fx = last_rates[next_random() % 8];
    st->cng_type_fx = (Word16)(next_random() & 1);
    st->last_cng_type_fx = (Word16)(next_random() & 1);
    put1("ini_frame", st->ini_frame_fx); put1("last_codec_mode", st->last_codec_mode);
    put1("codec_mode", st->codec_mode); put1("core", st->core_fx); put1("bwidth", st->bwidth_fx);
    put1("prev_ft_speech", st->prev_ft_speech_fx); put1("cng", st->CNG_fx);
    put1("opt_amr_wb", st->Opt_AMR_WB_fx); put1("last_total_brate", st->last_total_brate_fx);
    put1("cng_type", st->cng_type_fx); put1("last_cng_type", st->last_cng_type_fx);
}

static void case_read_indices(void)
{
    Decoder_State_fx *st = new_state();
    Word16 bits[MAX_BITS_PER_FRAME];
    UWord16 words[2 + MAX_BITS_PER_FRAME];
    int n = random_size();
    int good = next_random() % 4 != 0;
    random_bits(bits, n);
    randomise_reader_state(st);
    put1("good", good); put16("bits", bits, n);

    words[0] = good ? SYNC_GOOD_FRAME : SYNC_BAD_FRAME;
    words[1] = (UWord16)n;
    for (int i = 0; i < n; i++) words[2 + i] = bits[i] ? G192_BIN1 : G192_BIN0;
    FILE *file = fmemopen(words, (size_t)(2 + n) * sizeof(UWord16), "rb");
    Word16 ok = read_indices_fx(st, file, 0);
    fclose(file);

    arrow(); put1("ok", ok); put_state(st, n + 16); end_line();
    free(st);
}

/* A random sequence of bit-reader calls on random bits. */
static void case_readers(void)
{
    Decoder_State_fx *st = new_state();
    int n = random_size();
    Word16 ops[3 * 24], results[24], positions[24], ber[24];
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->total_num_bits = (Word16)n;
    st->codec_mode = (Word16)random_range(1, 2);
    st->next_bit_pos_fx = (Word16)(n ? random_range(0, n) : 0);
    put_u16("bits", bit_buffer, n);
    put1("total_num_bits", n); put1("codec_mode", st->codec_mode); put1("next_bit_pos", st->next_bit_pos_fx);
    for (int k = 0; k < 24; k++) {
        Word16 kind = (Word16)(next_random() % 5);
        Word16 a = (Word16)random_range(0, 16);
        Word16 b = (Word16)(n ? random_range(0, n + 4) : random_range(0, 4));
        ops[3 * k] = kind; ops[3 * k + 1] = a; ops[3 * k + 2] = b;
        switch (kind) {
        case 0: results[k] = (Word16)get_next_indice_fx(st, a); break;
        case 1: results[k] = (Word16)get_next_indice_1_fx(st); break;
        case 2: results[k] = (Word16)get_indice_fx(st, b, a); break;
        case 3: results[k] = (Word16)get_indice_1_fx(st, b); break;
        default: get_next_indice_tmp_fx(st, (Word16)(a % 4)); results[k] = 0; break;
        }
        positions[k] = st->next_bit_pos_fx;
        ber[k] = st->BER_detect;
    }
    put16("ops", ops, 3 * 24);
    arrow(); put16("results", results, 24); put16("positions", positions, 24); put16("ber", ber, 24);
    end_line();
    free(st);
}

/* decision_matrix_core_dec / dec_prm_core called directly, at every rate. */
static void case_core_dec(void)
{
    /* decision_matrix_core_dec runs off acelp_sig_tbl for a rate without an ACELP section (it is
     * only called at 13.2 and 32 kbit/s), dec_prm_core off FrameSizeConfig for 2.8 kbit/s. */
    static const Word32 mode1_rates[] = {2800, 7200, 8000, 13200, 32000, 64000, 96000, 128000};
    static const Word32 mode2_rates[] = {0, 2400, 7200, 8000, 9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000};
    Decoder_State_fx *st = new_state();
    Word16 which = (Word16)(next_random() & 1);
    Word32 rate = which ? mode2_rates[next_random() % 13] : mode1_rates[next_random() % 8];
    int n = rate / 50;
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->total_brate_fx = rate; st->total_num_bits = (Word16)n;
    st->codec_mode = (Word16)(which ? MODE2 : MODE1);
    put1("which", which); put1("total_brate", rate); put_u16("bits", bit_buffer, n);
    if (which) dec_prm_core(st); else decision_matrix_core_dec(st);
    arrow(); put1("core", st->core_fx); put1("bwidth", st->bwidth_fx); put1("m_frame_type", st->m_frame_type);
    put1("next_bit_pos", st->next_bit_pos_fx); put1("ber_detect", st->BER_detect); end_line();
    free(st);
}

static void case_partial_copy(void)
{
    Decoder_State_fx *st = new_state();
    Word32 rate = next_random() % 4 ? 13200 : (next_random() & 1 ? 9600 : 24400);
    int n = rate / 50;
    Word16 coder_type = (Word16)random_range(0, 7), sharp = (Word16)random_range(0, 1);
    for (int i = 0; i < n; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
    st->total_brate_fx = rate; st->total_num_bits = (Word16)n;
    st->bfi_fx = (Word16)random_range(0, 2);
    st->codec_mode = MODE1;
    st->use_partial_copy = (Word16)random_range(0, 1);
    st->last_bwidth_fx = (Word16)random_range(0, 3);
    st->bwidth_fx = (Word16)random_range(0, 3);
    st->core_fx = (Word16)random_range(0, 3);
    st->rf_target_bits = (Word16)random_range(0, 80);
    put1("total_brate", rate); put_u16("bits", bit_buffer, n); put1("bfi", st->bfi_fx);
    put1("use_partial_copy", st->use_partial_copy); put1("last_bwidth", st->last_bwidth_fx);
    put1("bwidth", st->bwidth_fx); put1("core", st->core_fx); put1("rf_target_bits", st->rf_target_bits);
    put1("coder_type", coder_type); put1("sharp_flag", sharp);
    getPartialCopyInfo(st, &coder_type, &sharp);
    arrow(); put1("rf_flag", st->rf_flag); put1("rf_frame_type", st->rf_frame_type);
    put1("rf_fec_offset", st->rf_fec_offset); put1("rf_target_bits", st->rf_target_bits);
    put1("coder_type", coder_type); put1("sharp_flag", sharp); put1("bwidth", st->bwidth_fx);
    put1("codec_mode", st->codec_mode); put1("bfi", st->bfi_fx); put1("core", st->core_fx);
    put1("use_partial_copy", st->use_partial_copy); put1("ber_detect", st->BER_detect);
    put1("next_bit_pos", st->next_bit_pos_fx); end_line();
    free(st);
}

static void case_bit_alloc_idx(void)
{
    static const Word32 rates[] = {7200, 8000, 9600, 11600, 12150, 12850, 13200, 14800, 16400, 22600, 24400,
                                   29000, 29200, 30200, 30400, 32000, 48000, 64000, 96000, 128000};
    Word32 brate = rates[next_random() % 20];
    Word16 ctype = (Word16)random_range(0, 7), sfrm = (Word16)random_range(-1, 320), tc = (Word16)random_range(-1, 4);
    if (next_random() & 1) sfrm = (Word16)(64 * random_range(-1, 4));
    Word32 any_rate = next_random() & 1 ? brate : (Word32)random_size() * 50 + (next_random() % 4 == 0);
    put1("brate", brate); put1("ctype", ctype); put1("sfrm", sfrm); put1("tc", tc); put1("any_rate", any_rate);
    arrow(); put1("idx", BIT_ALLOC_IDX_fx(brate, ctype, sfrm, tc)); put1("idx16k", BIT_ALLOC_IDX_16KHZ_fx(brate, ctype, sfrm, tc));
    put1("brate2idx", BRATE2IDX_fx(brate)); put1("brate2idx16k", BRATE2IDX16k_fx(brate));
    put1("rate2evs_mode", rate2EVSmode(any_rate));
    end_line();
}

static void stream(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file) { perror(path); exit(2); }
    Decoder_State_fx *st = new_state();
    /* What init_decoder_fx sets of the fields the reader uses. */
    st->codec_mode = MODE1; st->last_codec_mode = MODE1;
    st->core_fx = -1; st->CNG_fx = 0; st->prev_ft_speech_fx = 1;
    for (long frame = 0; read_indices_fx(st, file, 0); frame++) {
        put1("frame", frame); arrow(); put_state(st, st->bfi_fx ? -1 : st->total_num_bits + 16); end_line();
        /* What the decoder carries into the next frame of the fields the reader reads. */
        st->ini_frame_fx = 1;
        st->last_codec_mode = st->codec_mode;
        if (!st->bfi_fx) st->last_total_brate_fx = st->total_brate_fx;
    }
    fclose(file);
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "stream")) { stream(argv[2]); return 0; }
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED | stream FILE\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "read_indices")) case_read_indices();
        else if (!strcmp(argv[2], "readers")) case_readers();
        else if (!strcmp(argv[2], "core_dec")) case_core_dec();
        else if (!strcmp(argv[2], "partial_copy")) case_partial_copy();
        else if (!strcmp(argv[2], "bit_alloc_idx")) case_bit_alloc_idx();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
