/* -------- END GENERATED STATE DUMP -------- */

#ifndef STATE_DUMP_LIBRARY

static const Word32 rates[4] = {8000, 16000, 32000, 48000};

/* init_decoder_fx on a fresh state for each output rate; odd blocks of four start from a state
 * whose integer fields all hold a pattern instead of zero. */
static void corpus_init_decoder(int count, unsigned int seed)
{
    for (int k = 0; k < count; k++) {
        Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
        int filled = (k / 4) % 2;
        unsigned int pattern = seed * 7919u + (unsigned int)k;
        if (filled) {
            rd_pattern_state = pattern;
            rd_fill_DecoderState(st);
        }
        st->output_Fs_fx = rates[k % 4];
        st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
        put1("output_fs", st->output_Fs_fx);
        put1("output_frame", st->output_frame_fx);
        put1("filled", filled);
        put1("pattern", pattern);
        init_decoder_fx(st);
        rd_record_cldfb(st);
        arrow();
        rd_dump_DecoderState("st.", st);
        end_line();
        destroy_decoder(st);
        free(st);
    }
}

/* reset_preecho_dec_fx on a pattern-filled state. */
static void corpus_reset_preecho(int count, unsigned int seed)
{
    for (int k = 0; k < count; k++) {
        Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
        unsigned int pattern = seed * 104729u + (unsigned int)k;
        rd_pattern_state = pattern;
        rd_fill_DecoderState(st);
        put1("pattern", pattern);
        reset_preecho_dec_fx(st);
        arrow();
        rd_dump_DecoderState("st.", st);
        end_line();
        free(st);
    }
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    int count = atoi(argv[3]);
    unsigned int seed = (unsigned int)strtoul(argv[4], NULL, 10);
    if (!strcmp(argv[2], "init_decoder")) corpus_init_decoder(count, seed);
    else if (!strcmp(argv[2], "reset_preecho")) corpus_reset_preecho(count, seed);
    else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    return 0;
}

#endif
