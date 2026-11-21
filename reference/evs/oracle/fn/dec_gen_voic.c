/* Function-level oracle for lib_dec/dec_gen_voic_fx.c (decod_gen_voic_fx).
 *
 * One case is one to three consecutive frames on the same decoder state, so the memories the
 * function carries (Q_exc / Q_subfr, the FEC gains, the dispersion and pre-quantiser memories, the
 * tilt) and the excitation history are exercised across calls. Between frames the harness shifts
 * the excitation histories forward by one frame, as acelp_core_dec_fx does; the Rust replay does
 * the same. Every frame reads a fresh random bitstream (the function reads from the middle of a
 * frame, after the header and LSF bits, so random bits are as good as real ones and reach every
 * codebook index). */
#include "harness.h"
#include "prot_fx.h"
#include "rom_com_fx.h"

#define NBITS 1400
#define EXC_LEN L_EXC_DEC
#define BWE_LEN ((PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2)
#define BWE_AT (PIT16k_MAX * 2)

static UWord16 bit_buffer[MAX_BITS_PER_FRAME + 16];

static Word16 level(void) { return (Word16)(1 << random_range(3, 14)); }

/* An order-16 LP filter in Q12 per subframe, coefficients decaying with the order. */
static void random_lpc(Word16 *a, int nsub)
{
    for (int s = 0; s < nsub; s++) {
        a[s * (M + 1)] = 4096;
        for (int i = 1; i <= M; i++) {
            int span = 6000 * (M + 1 - i) / M;
            a[s * (M + 1) + i] = (Word16)random_range(-span, span);
        }
    }
}

/* A rate / frame length / coder type combination decod_gen_voic_fx is called with, whose
 * bit-allocation rows exist for every subframe (and whose gain row the memory-less quantiser can
 * read: 2..7 bits). */
static int valid(Word32 brate, Word16 l_frame, Word16 coder_type)
{
    for (Word16 i_subfr = 0; i_subfr < l_frame; i_subfr += L_SUBFR) {
        if (l_frame == L_FRAME) {
            Word32 idx = BIT_ALLOC_IDX_fx(brate, coder_type, i_subfr, TC_SUBFR2IDX_fx(-1));
            if (idx < 0 || idx >= 400) return 0;
            if (brate > ACELP_8k00 && (gain_bits_tbl[idx] < 2 || gain_bits_tbl[idx] > 7)) return 0;
            if (FCB_bits_tbl[idx] <= 0 || ACB_bits_tbl[idx] <= 0) return 0;
        } else {
            Word32 idx = BIT_ALLOC_IDX_16KHZ_fx(brate, coder_type, i_subfr, TC_SUBFR2IDX_16KHZ_fx(-1));
            if (idx < 0 || idx >= 385) return 0;
            if (gain_bits_16kHz_tbl[idx] < 2 || (brate <= ACELP_32k && gain_bits_16kHz_tbl[idx] > 7)) return 0;
            if (FCB_bits_16kHz_tbl[idx] <= 0 || ACB_bits_16kHz_tbl[idx] <= 0) return 0;
        }
    }
    return 1;
}

static void case_decod_gen_voic(void)
{
    static const Word32 rates_12k8[] = {7200, 8000, 9600, 11600, 13200};
    static const Word32 rates_16k[] = {16400, 24400, 32000, 48000, 64000};
    static const Word32 fs[] = {8000, 16000, 32000, 48000};
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    Word16 old_exc[EXC_LEN], old_bwe[BWE_LEN], exc2[L_FRAME16k];
    Word16 pitch_buf[NB_SUBFR16k], voice_factors[NB_SUBFR16k], gain_buf[NB_SUBFR16k];
    Word16 aq[NB_SUBFR16k * (M + 1)];

    Word16 l_frame;
    Word32 core_brate;
    Word16 coder_type;
    do {
        l_frame = (Word16)(next_random() & 1 ? L_FRAME : L_FRAME16k);
        core_brate = l_frame == L_FRAME ? rates_12k8[next_random() % 5] : rates_16k[next_random() % 5];
        coder_type = (Word16)(next_random() & 1 ? GENERIC : VOICED);
        if (core_brate > ACELP_24k40 && next_random() % 3 == 0) coder_type = INACTIVE;
    } while (!valid(core_brate, l_frame, coder_type));

    /* the state decod_gen_voic_fx and its callees read */
    st->codec_mode = MODE1;
    st->core_brate_fx = core_brate;
    st->L_frame_fx = l_frame;
    st->output_Fs_fx = fs[next_random() % 4];
    st->Q_exc = (Word16)random_range(0, 8);
    for (int i = 0; i < L_Q_MEM; i++) st->Q_subfr[i] = (Word16)random_range(0, 12);
    st->Q_syn = (Word16)random_range(-1, 8);
    st->prev_Q_exc_fr = (Word16)(next_random() & 1 ? st->Q_exc : random_range(0, 8));
    st->prev_Q_syn_fr = (Word16)(next_random() & 1 ? st->Q_syn : random_range(-1, 8));
    random_signal(st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2, level());
    random_signal(st->last_exc_dct_in_fx, L_FRAME, level());
    st->lp_gainp_fx = (Word16)random_range(0, 19661);
    st->lp_gainc_fx = (Word16)random_range(0, 32767);
    st->tilt_code_fx = (Word16)random_range(0, 16384);
    st->stab_fac_fx = (Word16)random_range(0, 32767);
    st->gc_threshold_fx = (Word32)random_range(0, 1 << 24);
    st->dm_fx.prev_state = (Word16)random_range(0, 2);
    st->dm_fx.prev_gain_code = (Word32)random_range(0, 1 << 22);
    for (int i = 0; i < 6; i++) st->dm_fx.prev_gain_pit[i] = (Word16)random_range(0, 19661);
    st->mem_preemp_preQ_fx = (Word16)random_range(-20000, 20000);
    st->last_nq_preQ_fx = (Word16)random_range(0, 33);
    st->use_acelp_preq = 0;
    st->bfi_pitch_fx = (Word16)(next_random() % 6 ? random_range(34 * 64, 149 * 64) : random_range(17 * 64, 289 * 64));
    Word16 hist = level();
    random_signal(st->old_exc2_fx, L_EXC_MEM, hist);
    random_signal(st->old_syn2_fx, L_EXC_MEM, hist);
    random_signal(st->mem_syn2_fx, M, 2000);
    Carry = (Flag)(next_random() & 1);

    random_signal(old_exc, EXC_LEN, level());
    random_signal(old_bwe, BWE_LEN, level());
    random_signal(exc2, L_FRAME16k, level());
    for (int i = 0; i < NB_SUBFR16k; i++) {
        pitch_buf[i] = (Word16)(next_random() % 6 ? random_range(34 * 64, 149 * 64) : random_range(17 * 64, 289 * 64));
        voice_factors[i] = random16();
        gain_buf[i] = random16();
    }
    Word16 unbits = (Word16)random_range(0, 12);

    put1("l_frame", l_frame); put1("core_brate", core_brate); put1("coder_type", coder_type);
    put1("output_fs", st->output_Fs_fx); put1("q_exc", st->Q_exc); put16("q_subfr", st->Q_subfr, L_Q_MEM);
    put1("q_syn", st->Q_syn); put1("prev_q_exc_fr", st->prev_Q_exc_fr); put1("prev_q_syn_fr", st->prev_Q_syn_fr);
    put16("dct_post_old_exc", st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2);
    put16("last_exc_dct_in", st->last_exc_dct_in_fx, L_FRAME);
    put1("lp_gainp", st->lp_gainp_fx); put1("lp_gainc", st->lp_gainc_fx); put1("tilt_code", st->tilt_code_fx);
    put1("stab_fac", st->stab_fac_fx); put1("gc_threshold", st->gc_threshold_fx);
    put1("dm_prev_state", st->dm_fx.prev_state); put1("dm_prev_gain_code", st->dm_fx.prev_gain_code);
    put16("dm_prev_gain_pit", st->dm_fx.prev_gain_pit, 6);
    put1("mem_preemp_preq", st->mem_preemp_preQ_fx); put1("last_nq_preq", st->last_nq_preQ_fx);
    put1("bfi_pitch", st->bfi_pitch_fx); put16("old_exc2", st->old_exc2_fx, L_EXC_MEM);
    put16("old_syn2", st->old_syn2_fx, L_EXC_MEM); put16("mem_syn2", st->mem_syn2_fx, M); put1("carry", Carry);
    put16("old_exc", old_exc, EXC_LEN); put16("old_bwe", old_bwe, BWE_LEN); put16("exc2", exc2, L_FRAME16k);
    put16("pitch_buf", pitch_buf, NB_SUBFR16k); put16("voice_factors", voice_factors, NB_SUBFR16k);
    put16("gain_buf", gain_buf, NB_SUBFR16k); put1("unbits", unbits);

    int frames = random_range(1, 3);
    put1("frames", frames);
    for (int f = 0; f < frames; f++) {
        char name[32];
        for (int i = 0; i < NBITS; i++) bit_buffer[i] = (UWord16)(next_random() & 1);
        st->bit_stream_fx = bit_buffer;
        st->total_num_bits = NBITS;
        st->next_bit_pos_fx = (Word16)random_range(0, 100);
        st->BER_detect = 0;
        Word16 sharp = (Word16)(next_random() & 1);
        Word16 es_pred = Es_pred_qua_5b_fx[next_random() % 32];
        Word16 do_wi = (Word16)(next_random() % 3 ? 1 : 0);
        random_lpc(aq, NB_SUBFR16k);
        snprintf(name, sizeof name, "bits%d", f); put_u16(name, bit_buffer, NBITS);
        snprintf(name, sizeof name, "next_bit_pos%d", f); put1(name, st->next_bit_pos_fx);
        snprintf(name, sizeof name, "sharp%d", f); put1(name, sharp);
        snprintf(name, sizeof name, "es_pred%d", f); put1(name, es_pred);
        snprintf(name, sizeof name, "do_wi%d", f); put1(name, do_wi);
        snprintf(name, sizeof name, "aq%d", f); put16(name, aq, NB_SUBFR16k * (M + 1));

        decod_gen_voic_fx(st, l_frame, sharp, aq, coder_type, es_pred, do_wi, pitch_buf, voice_factors,
                          old_exc + L_EXC_MEM_DEC, exc2, old_bwe + BWE_AT, &unbits, gain_buf);

        /* the per-frame outputs are kept in a side buffer and printed after the arrow */
        static char out_text[1 << 20];
        static size_t out_len;
        if (f == 0) out_len = 0;
        {
            char *p = out_text + out_len;
            size_t room = sizeof out_text - out_len;
            int w = snprintf(p, room, " pitch_buf%d=", f);
            for (int i = 0; i < NB_SUBFR16k; i++) w += snprintf(p + w, room - w, i ? ",%d" : "%d", pitch_buf[i]);
            w += snprintf(p + w, room - w, " voice_factors%d=", f);
            for (int i = 0; i < NB_SUBFR16k; i++) w += snprintf(p + w, room - w, i ? ",%d" : "%d", voice_factors[i]);
            w += snprintf(p + w, room - w, " gain_buf%d=", f);
            for (int i = 0; i < NB_SUBFR16k; i++) w += snprintf(p + w, room - w, i ? ",%d" : "%d", gain_buf[i]);
            w += snprintf(p + w, room - w, " exc2_%d=", f);
            for (int i = 0; i < L_FRAME16k; i++) w += snprintf(p + w, room - w, i ? ",%d" : "%d", exc2[i]);
            w += snprintf(p + w, room - w, " unbits%d=%d next_bit_pos%d=%d ber_detect%d=%d q_exc%d=%d", f, unbits, f,
                          st->next_bit_pos_fx, f, st->BER_detect, f, st->Q_exc);
            out_len += (size_t)w;
        }
        if (f + 1 == frames) {
            arrow();
            fputs(out_text, stdout);
            break;
        }
        /* next frame: shift the excitation histories, as acelp_core_dec_fx's updates do */
        memmove(old_exc, old_exc + l_frame, (size_t)(EXC_LEN - l_frame) * sizeof(Word16));
        memmove(old_bwe, old_bwe + 2 * l_frame, (size_t)(BWE_LEN - 2 * l_frame) * sizeof(Word16));
        memmove(st->old_exc2_fx, st->old_exc2_fx + l_frame, (size_t)(L_EXC_MEM - l_frame) * sizeof(Word16));
        memcpy(st->old_exc2_fx + L_EXC_MEM - l_frame, exc2, (size_t)l_frame * sizeof(Word16));
        st->prev_Q_exc_fr = st->Q_exc;
    }

    put1("q_exc", st->Q_exc); put16("q_subfr", st->Q_subfr, L_Q_MEM);
    put16("dct_post_old_exc", st->dct_post_old_exc_fx, DCT_L_POST - OFFSET2);
    put16("last_exc_dct_in", st->last_exc_dct_in_fx, L_FRAME);
    put1("lp_gainp", st->lp_gainp_fx); put1("lp_gainc", st->lp_gainc_fx); put1("tilt_code", st->tilt_code_fx);
    put1("gc_threshold", st->gc_threshold_fx);
    put1("dm_prev_state", st->dm_fx.prev_state); put1("dm_prev_gain_code", st->dm_fx.prev_gain_code);
    put16("dm_prev_gain_pit", st->dm_fx.prev_gain_pit, 6);
    put1("mem_preemp_preq", st->mem_preemp_preQ_fx); put1("last_nq_preq", st->last_nq_preQ_fx);
    put1("use_acelp_preq", st->use_acelp_preq);
    put1("prev_gain_pit_dec", st->prev_gain_pit_dec_fx); put1("prev_tilt_code_dec", st->prev_tilt_code_dec_fx);
    put16("old_exc2", st->old_exc2_fx, L_EXC_MEM); put16("mem_syn2", st->mem_syn2_fx, M); put1("carry", Carry);
    put16("old_exc", old_exc, EXC_LEN); put16("old_bwe", old_bwe, BWE_LEN);
    end_line();
    free(st);
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "decod_gen_voic")) case_decod_gen_voic();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
