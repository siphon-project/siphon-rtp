/* Function-level oracle for hq_pred_hb_bws_fx (lib_dec/hq_hr_dec_fx.c): whole decoder state before and
 * after, over frame lengths 640 / 960 and shorter, every HQ class, rates at / above and below the
 * 32 kbit/s threshold, last_inner_frame on both sides of 640. */
#define STATE_DUMP_LIBRARY
#include "init_dec.c"
#include "state_capture.h"
#define hq_hr_dec_fx hq_hr_dec_fx_unused
#include "../../c-code/lib_dec/hq_hr_dec_fx.c"

static void case_hq_pred_hb_bws(void)
{
    static const Word32 out_rates[] = {16000, 32000, 48000};
    static const Word32 rates[] = {HQ_16k40, HQ_24k40, HQ_32k, HQ_48k, HQ_64k, HQ_96k, HQ_128k};
    static const Word16 lengths[] = {L_FRAME16k, L_FRAME32k, L_FRAME48k, L_FRAME32k, L_FRAME48k};
    static const Word16 frames[] = {L_FRAME8k, L_FRAME16k, L_FRAME32k, L_FRAME48k};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->output_Fs_fx = out_rates[next_random() % 3];
    st->output_frame_fx = extract_l(Mult_32_16(st->output_Fs_fx, 0x0290));
    init_decoder_fx(st);
    rd_record_cldfb(st);

    Word16 ynrm[NB_SFM], swb_fenv[SWB_FENV + DIM_FB];
    Word16 length = lengths[next_random() % 5], hqswb_clas = (Word16)(next_random() % 6);
    st->core_brate_fx = rates[next_random() % 7];
    st->last_inner_frame_fx = frames[next_random() % 4];
    st->prev_ener_shb_fx = random16();
    for (int i = 0; i < SWB_FENV; i++) st->prev_SWB_fenv_fx[i] = random16();
    int mode = next_random() % 4, idx = random_range(0, 39);
    for (int i = 0; i < NB_SFM; i++) {
        if (mode == 0) idx = 39;
        else if (mode == 1) idx = random_range(0, 39);
        else { idx += random_range(-3, 3); if (idx < 0) idx = 0; if (idx > 39) idx = 39; }
        ynrm[i] = (Word16)idx;
    }
    for (int i = 0; i < SWB_FENV + DIM_FB; i++) swb_fenv[i] = next_random() & 1 ? (Word16)random_range(0, 4000) : random16();

    put1("output_fs", st->output_Fs_fx); put1("output_frame", st->output_frame_fx);
    char *before = capture_state(st);
    put_state_in(before);
    put16("ynrm", ynrm, NB_SFM); put1("length", length); put1("hqswb_clas", hqswb_clas);
    put16("swb_fenv", swb_fenv, SWB_FENV + DIM_FB);
    hq_pred_hb_bws_fx(st, ynrm, length, hqswb_clas, swb_fenv);
    arrow();
    char *after = capture_state(st);
    put_changed(before, after);
    free(before); free(after);
    end_line();
    destroy_decoder(st);
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "hq_pred_hb_bws")) case_hq_pred_hb_bws();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
