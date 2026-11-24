/* Function-level oracle for the TBE decoder of lib_dec/swb_tbe_dec_fx.c: find_max_mem_*, rescale_gen*_mem,
 * TBEreset_dec_fx, tbe_read_bitstream_fx, dequantizeSHBparams_fx_9_1, gradientGainShape, wb_tbe_dec_fx,
 * fb_tbe_dec_fx, GenTransition_fx and GenTransition_WB_fx. The file is included, so its static functions
 * are reached directly.
 *
 * Every case runs on a calloc'ed decoder state of which only the fields the function reads or writes
 * are randomised (the table below, one entry per field, printed before and after the call, so a field
 * the port forgets to write shows up as a difference). Values stay in the ranges the decoder gives
 * them. */
#include "harness.h"
#include "../../c-code/lib_dec/swb_tbe_dec_fx.c"

typedef struct { const char *name; void *pointer; int bits, count; } Field;
static Field fields[192];
static int field_count;
static UWord16 bits[2576];

#define FIELD(rust, cname, width, count_) do { \
    _Static_assert(sizeof(((Decoder_State_fx *)0)->cname) == ((width) / 8) * (count_), "field size " #cname); \
    fields[field_count++] = (Field){rust, (void *)&st->cname, width, count_}; } while (0)

static void describe(Decoder_State_fx *st)
{
    field_count = 0;
    FIELD("old_bwe_exc_extended", old_bwe_exc_extended_fx, 16, 12);
    FIELD("mem_gen_sh_bexc_filt_down_shb", mem_genSHBexc_filt_down_shb_fx, 16, 7);
    FIELD("mem_gen_sh_bexc_filt_down_wb2", mem_genSHBexc_filt_down_wb2_fx, 16, 7);
    FIELD("mem_gen_sh_bexc_filt_down_wb3", mem_genSHBexc_filt_down_wb3_fx, 16, 7);
    FIELD("state_lpc_syn", state_lpc_syn_fx, 16, 10);
    FIELD("state_syn_shbexc", state_syn_shbexc_fx, 16, 20);
    FIELD("mem_stp_swb", mem_stp_swb_fx, 16, 10);
    FIELD("fb_state_lpc_syn", fb_state_lpc_syn_fx, 16, 10);
    FIELD("syn_overlap", syn_overlap_fx, 16, 20);
    FIELD("gen_sh_bsynth_state_lsyn_filt_shb_local", genSHBsynth_state_lsyn_filt_shb_local_fx, 16, 6);
    FIELD("int_3_over_2_tbemem_dec", int_3_over_2_tbemem_dec_fx, 16, 15);
    FIELD("mem_resamp_hb_32k", mem_resamp_HB_32k_fx, 16, 7);
    FIELD("mem_resamp_hb", mem_resamp_HB_fx, 16, 13);
    FIELD("state_lsyn_filt_shb", state_lsyn_filt_shb_fx, 16, 6);
    FIELD("state_lsyn_filt_dwn_shb", state_lsyn_filt_dwn_shb_fx, 16, 6);
    FIELD("state_32and48k_wb_upsample", state_32and48k_WB_upsample_fx, 16, 6);
    FIELD("lsp_prevfrm", lsp_prevfrm_fx, 16, 10);
    FIELD("prev_lpc_wb", prev_lpc_wb_fx, 16, 6);
    FIELD("bwe_seed", bwe_seed_fx, 16, 2);
    FIELD("old_tbe_synth", old_tbe_synth_fx, 16, 222);
    FIELD("gain_shape_delay", GainShape_Delay, 16, 8);
    FIELD("lsf_idx", lsf_idx_fx, 16, 5);
    FIELD("idx_res_gs", idx_res_gs_fx, 16, 5);
    FIELD("mem_csfilt", mem_csfilt_fx, 32, 2);
    FIELD("gen_sh_bsynth_hilbert_mem", genSHBsynth_Hilbert_Mem_fx, 32, 21);
    FIELD("fbbwe_hpf_mem", fbbwe_hpf_mem_fx, 32, 16);
    FIELD("fbbwe_hpf_mem_fx_q", fbbwe_hpf_mem_fx_Q, 16, 4);
    FIELD("tbe_demph", tbe_demph_fx, 16, 1);
    FIELD("tbe_premph", tbe_premph_fx, 16, 1);
    FIELD("fb_tbe_demph", fb_tbe_demph_fx, 16, 1);
    FIELD("extl", extl_fx, 16, 1);
    FIELD("l_frame", L_frame_fx, 16, 1);
    FIELD("bfi", bfi_fx, 16, 1);
    FIELD("prev_bfi", prev_bfi_fx, 16, 1);
    FIELD("bws_cnt", bws_cnt_fx, 16, 1);
    FIELD("use_partial_copy", use_partial_copy, 16, 1);
    FIELD("last_extl", last_extl_fx, 16, 1);
    FIELD("rf_frame_type", rf_frame_type, 16, 1);
    FIELD("rf_indx_tbe_gain_fr", rf_indx_tbeGainFr, 16, 1);
    FIELD("core", core_fx, 16, 1);
    FIELD("last_core", last_core_fx, 16, 1);
    FIELD("prev_use_partial_copy", prev_use_partial_copy, 16, 1);
    FIELD("prev_coder_type", prev_coder_type_fx, 16, 1);
    FIELD("last_coder_type", last_coder_type_fx, 16, 1);
    FIELD("prev_tilt_code_dec", prev_tilt_code_dec_fx, 16, 1);
    FIELD("codec_mode", codec_mode, 16, 1);
    FIELD("prev_q_bwe_exc", prev_Q_bwe_exc, 16, 1);
    FIELD("prev_qx", prev_Qx, 16, 1);
    FIELD("prev_frame_pow_exp", prev_frame_pow_exp, 16, 1);
    FIELD("last_wb_bwe_ener", last_wb_bwe_ener_fx, 16, 1);
    FIELD("igf", igf, 16, 1);
    FIELD("gain_attn", GainAttn_fx, 16, 1);
    FIELD("prev_fbbwe_ratio", prev_fbbwe_ratio_fx, 16, 1);
    FIELD("rf_flag", rf_flag, 16, 1);
    FIELD("rf_flag_last", rf_flag_last, 16, 1);
    FIELD("last_good", last_good_fx, 16, 1);
    FIELD("nb_lost_cmpt", nbLostCmpt, 16, 1);
    FIELD("ber_detect", BER_detect, 16, 1);
    FIELD("bwidth", bwidth_fx, 16, 1);
    FIELD("lsf_wb", lsf_WB_fx, 16, 1);
    FIELD("g_frame_wb", gFrame_WB_fx, 16, 1);
    FIELD("idx_sub_gains", idxSubGains_fx, 16, 1);
    FIELD("idx_frame_gain", idxFrameGain_fx, 16, 1);
    FIELD("idx_shb_fr_gain", idx_shb_fr_gain_fx, 16, 1);
    FIELD("idx_mix_fac", idx_mixFac_fx, 16, 1);
    FIELD("m_idx", m_idx_fx, 16, 1);
    FIELD("grid_idx", grid_idx_fx, 16, 1);
    FIELD("idx_gain", idxGain_fx, 16, 1);
    FIELD("tec_tfa", tec_tfa, 16, 1);
    FIELD("tec_flag", tec_flag, 16, 1);
    FIELD("tfa_flag", tfa_flag, 16, 1);
    FIELD("next_bit_pos", next_bit_pos_fx, 16, 1);
    FIELD("total_num_bits", total_num_bits, 16, 1);
    FIELD("prev_fb_ener_adjust", prev_fb_ener_adjust_fx, 16, 1);
    FIELD("gain_prec_swb", gain_prec_swb_fx, 16, 1);
    FIELD("bwe_non_lin_prev_scale", bwe_non_lin_prev_scale_fx, 32, 1);
    FIELD("total_brate", total_brate_fx, 32, 1);
    FIELD("last_total_brate", last_total_brate_fx, 32, 1);
    FIELD("output_fs", output_Fs_fx, 32, 1);
    FIELD("extl_brate", extl_brate_fx, 32, 1);
    FIELD("gain_frame_prevfrm", GainFrame_prevfrm_fx, 32, 1);
    FIELD("prev_wb_bwe_frame_pow", prev_wb_bwe_frame_pow_fx, 32, 1);
    FIELD("lsp_shb_prev", lsp_shb_prev_fx, 16, 10);
    FIELD("lsp_shb_prev_prev", lsp_shb_prev_prev_fx, 16, 10);
    FIELD("swb_lsp_prev_interp", swb_lsp_prev_interp_fx, 16, 10);
    FIELD("prev_lsf_diff", prev_lsf_diff_fx, 16, 8);
    FIELD("cur_sub_aq", cur_sub_Aq_fx, 16, 17);
    FIELD("prev_swb_fenv", prev_SWB_fenv_fx, 16, 14);
    FIELD("mem_zero_swb", mem_zero_swb_fx, 16, 10);
    FIELD("clas_dec", clas_dec, 16, 1);
    FIELD("tilt_wb", tilt_wb_fx, 16, 1);
    FIELD("tilt_swb", tilt_swb_fx, 16, 1);
    FIELD("prev_fractive", prev_fractive_fx, 16, 1);
    FIELD("prev_gain_shape", prev_GainShape_fx, 16, 1);
    FIELD("prev_tilt_para", prev_tilt_para_fx, 16, 1);
    FIELD("bws_cnt1", bws_cnt1_fx, 16, 1);
    FIELD("prev_res_shb_gshape", prev_res_shb_gshape_fx, 16, 1);
    FIELD("prev_mix_factors", prev_mixFactors_fx, 16, 1);
    FIELD("tilt_mem", tilt_mem_fx, 16, 1);
    FIELD("prev_q_bwe_exc_fb", prev_Q_bwe_exc_fb, 16, 1);
    FIELD("prev_q_bwe_syn", prev_Q_bwe_syn, 16, 1);
    FIELD("prev_q_bwe_syn2", prev_Q_bwe_syn2, 16, 1);
    FIELD("prev_ener_fx_q", prev_ener_fx_Q, 16, 1);
    FIELD("prev_ener_shb", prev_ener_shb_fx, 16, 1);
    FIELD("tilt_swb_fec", tilt_swb_fec_fx, 16, 1);
    FIELD("next_coder_type", next_coder_type, 16, 1);
    FIELD("cummulative_damping", cummulative_damping, 16, 1);
    FIELD("q_syn2", Q_syn2, 16, 1);
    FIELD("shb_dtx_count", shb_dtx_count_fx, 16, 1);
    FIELD("ener_lh", enerLH_fx, 32, 1);
    FIELD("ener_ll", enerLL_fx, 32, 1);
    FIELD("prev_ener_lh", prev_enerLH_fx, 32, 1);
    FIELD("prev_ener_ll", prev_enerLL_fx, 32, 1);
    FIELD("last_core_brate", last_core_brate_fx, 32, 1);
    FIELD("core_brate", core_brate_fx, 32, 1);
    FIELD("prev1_shb_ener_sf", prev1_shb_ener_sf_fx, 32, 1);
    FIELD("prev2_shb_ener_sf", prev2_shb_ener_sf_fx, 32, 1);
    FIELD("prev3_shb_ener_sf", prev3_shb_ener_sf_fx, 32, 1);
    FIELD("prev_ener", prev_ener_fx, 32, 1);
    FIELD("prev_swb_bwe_frame_pow", prev_swb_bwe_frame_pow_fx, 32, 1);
}

static Decoder_State_fx *new_state(void)
{
    Decoder_State_fx *st = calloc(1, sizeof(Decoder_State_fx));
    st->bit_stream_fx = bits;
    describe(st);
    return st;
}

static const int magnitudes[] = {20, 300, 3000, 12000, 32000};

/* Every integer field gets a plausible random value; the cases then set the control fields. */
static void randomise(void)
{
    for (int f = 0; f < field_count; f++) {
        int magnitude = magnitudes[next_random() % 5];
        for (int i = 0; i < fields[f].count; i++) {
            if (fields[f].bits == 16) ((Word16 *)fields[f].pointer)[i] = (Word16)random_range(-magnitude, magnitude);
            else ((Word32 *)fields[f].pointer)[i] = (Word32)random_range(-magnitude * 65536, magnitude * 65536);
        }
        if (next_random() % 12 == 0) memset(fields[f].pointer, 0, (fields[f].bits / 8) * fields[f].count);
    }
}

static void put_fields(void)
{
    for (int f = 0; f < field_count; f++) {
        if (fields[f].bits == 16) put16(fields[f].name, (Word16 *)fields[f].pointer, fields[f].count);
        else put32(fields[f].name, (Word32 *)fields[f].pointer, fields[f].count);
    }
}

static void random_bits(int n)
{
    int density = (int)(next_random() % 3);
    for (int i = 0; i < n; i++)
        bits[i] = (UWord16)(density == 0 ? (next_random() % 5 == 0) : density == 1 ? (next_random() % 5 != 0) : (next_random() & 1));
}

static Word32 positive32(void)
{
    Word32 value = random32();
    if (value == (Word32)0x80000000) return 0x7fffffff;
    return value < 0 ? -value : value;
}

static const Word32 total_brates[] = {7200, 8000, 9600, 13200, 16400, 24400, 32000};
static const Word32 fs_values[] = {16000, 32000, 48000};

static void common_controls(Decoder_State_fx *st)
{
    st->total_brate_fx = total_brates[next_random() % 7];
    st->output_Fs_fx = fs_values[next_random() % 3];
    st->L_frame_fx = next_random() & 1 ? 256 : 320;
    st->codec_mode = 1;
    st->bfi_fx = next_random() % 6 == 0;
    st->prev_bfi_fx = next_random() % 6 == 0;
    st->BER_detect = 0;
}

static void case_find_max_mem_dec(void)
{
    Decoder_State_fx *st = new_state();
    Word16 n_mem = 0, n_mem2 = 0, n_mem3 = 0;
    randomise(); common_controls(st);
    st->extl_fx = next_random() & 1 ? SWB_TBE : FB_TBE;
    put_fields();
    find_max_mem_dec(st, &n_mem, &n_mem2, &n_mem3);
    arrow(); put1("n_mem", n_mem); put1("n_mem2", n_mem2); put1("n_mem3", n_mem3); put_fields(); end_line();
    free(st);
}

static void case_rescale_gen_shb_mem(void)
{
    Decoder_State_fx *st = new_state();
    Word16 sf = (Word16)random_range(-3, 5);
    randomise(); common_controls(st);
    st->extl_fx = next_random() & 1 ? SWB_TBE : FB_TBE;
    put_fields(); put1("sf", sf);
    rescale_genSHB_mem_dec(st, sf);
    arrow(); put_fields(); end_line();
    free(st);
}

static void case_find_max_mem_wb(void)
{
    Decoder_State_fx *st = new_state();
    Word16 n_mem = 0;
    randomise(); common_controls(st);
    put_fields();
    find_max_mem_wb(st, &n_mem);
    arrow(); put1("n_mem", n_mem); put_fields(); end_line();
    free(st);
}

static void case_rescale_gen_wb_mem(void)
{
    Decoder_State_fx *st = new_state();
    Word16 sf = (Word16)random_range(-3, 5);
    randomise(); common_controls(st);
    put_fields(); put1("sf", sf);
    rescale_genWB_mem(st, sf);
    arrow(); put_fields(); end_line();
    free(st);
}

static void case_tbe_reset_dec(void)
{
    Decoder_State_fx *st = new_state();
    Word16 bandwidth = (Word16)random_range(0, 3);
    randomise(); common_controls(st);
    st->last_core_fx = (Word16)(next_random() & 1);
    put_fields(); put1("bandwidth", bandwidth);
    TBEreset_dec_fx(st, bandwidth);
    arrow(); put_fields(); end_line();
    free(st);
}

static void case_tbe_read_bitstream(void)
{
    Decoder_State_fx *st = new_state();
    randomise(); common_controls(st);
    st->bwidth_fx = (Word16)random_range(0, 3);
    st->rf_flag = (Word16)(next_random() % 4 == 0);
    st->tec_tfa = (Word16)(next_random() & 1);
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(st->next_bit_pos_fx + random_range(10, 120));
    random_bits(200);
    put16("bits", (Word16 *)0, 0); { for (int i = 0; i < 200; i++) printf(i ? ",%d" : "%d", bits[i]); }
    put_fields();
    tbe_read_bitstream_fx(st);
    arrow(); put_fields(); end_line();
    free(st);
}

static void case_dequantize(void)
{
    Decoder_State_fx *st = new_state();
    static const Word32 swb_brates[] = {1600, 1800, 2800, 3000};
    Word16 extl, uv_flag = 0;
    Word32 extl_brate;
    Word16 lsf[10], subgain[16], res_gshape[5], mix = 0x5a5a;
    Word32 framegain = 0x5a5a5a5a, shb_ener = 0x5a5a5a5a;
    randomise(); common_controls(st);
    switch (next_random() % 3) {
    case 0: extl = WB_TBE; extl_brate = next_random() & 1 ? 350 : 1050; break;
    case 1: extl = SWB_TBE; extl_brate = swb_brates[next_random() % 4]; break;
    default: extl = FB_TBE; extl_brate = next_random() & 1 ? 1800 : 3000; break;
    }
    st->extl_fx = extl; st->extl_brate_fx = extl_brate;
    st->codec_mode = next_random() % 3 ? 1 : 2;
    st->rf_flag = (Word16)(next_random() % 8 == 0);
    st->total_brate_fx = total_brates[next_random() % 7];
    if (st->total_brate_fx == 7200 || st->total_brate_fx == 8000) st->total_brate_fx = 13200;
    if (next_random() % 8 == 0) { st->total_brate_fx = 0; st->last_total_brate_fx = next_random() & 1 ? 9600 : 13200; st->rf_flag_last = (Word16)(next_random() & 1); }
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(st->next_bit_pos_fx + (next_random() % 6 ? random_range(60, 200) : random_range(0, 60)));
    random_bits(300);
    /* MODE2 and 9.6 kbit/s read their indices from the state, each bounded by its bit count */
    st->lsf_WB_fx = (Word16)random_range(0, 3); st->gFrame_WB_fx = (Word16)random_range(0, 15);
    /* the 8-bit first index is only used by the single-stage branch (9.6 kbit/s, RF), the others by the
     * 5-stage one, whose first codebook has 16 entries */
    int single_stage = !(st->rf_flag == 0 && !(st->total_brate_fx == 9600 || (st->total_brate_fx == 0 && (st->last_total_brate_fx == 9600 || (st->last_total_brate_fx == 13200 && st->rf_flag_last == 1)))));
    st->lsf_idx_fx[0] = (Word16)random_range(0, single_stage ? 255 : 15);
    st->lsf_idx_fx[1] = (Word16)random_range(0, 15);
    for (int i = 2; i < 5; i++) st->lsf_idx_fx[i] = (Word16)random_range(0, 7);
    st->m_idx_fx = (Word16)random_range(0, 3); st->grid_idx_fx = (Word16)random_range(0, 3);
    st->idxSubGains_fx = (Word16)random_range(0, 31); st->idxFrameGain_fx = (Word16)random_range(0, 31);
    st->idx_shb_fr_gain_fx = (Word16)random_range(0, 63); st->idx_mixFac_fx = (Word16)random_range(0, 7);
    for (int i = 0; i < 5; i++) st->idx_res_gs_fx[i] = (Word16)random_range(0, 7);
    for (int i = 0; i < 10; i++) lsf[i] = 0x5a5a;
    for (int i = 0; i < 16; i++) subgain[i] = 0x5a5a;
    for (int i = 0; i < 5; i++) res_gshape[i] = 0x5a5a;
    put16("bits", (Word16 *)0, 0); { for (int i = 0; i < 300; i++) printf(i ? ",%d" : "%d", bits[i]); }
    put_fields(); put1("extl", extl); put1("extl_brate_arg", extl_brate);
    dequantizeSHBparams_fx_9_1(st, extl, extl_brate, lsf, subgain, &framegain, &uv_flag, &shb_ener, res_gshape, &mix);
    arrow(); put16("lsf", lsf, 10); put16("subgain", subgain, 16); put32("framegain", &framegain, 1);
    put1("uv_flag", uv_flag); put32("shb_ener", &shb_ener, 1); put16("res_gshape", res_gshape, 5); put1("mix", mix);
    put_fields(); end_line();
    free(st);
}

static void case_gradient_gain_shape(void)
{
    Decoder_State_fx *st = new_state();
    Word16 gain_shape[16];
    Word32 gain_frame = 0x5a5a5a5a;
    randomise(); common_controls(st);
    for (int i = 0; i < 8; i++) st->GainShape_Delay[i] = (Word16)random_range(0, next_random() & 1 ? 16384 : 3000);
    st->prev_coder_type_fx = (Word16)random_range(0, 3);
    st->last_good_fx = (Word16)random_range(0, 3);
    st->nbLostCmpt = (Word16)random_range(1, 4);
    st->GainAttn_fx = (Word16)random_range(0, 32767);
    st->GainFrame_prevfrm_fx = positive32() >> (next_random() % 8);
    for (int i = 0; i < 16; i++) gain_shape[i] = 0x5a5a;
    put_fields();
    gradientGainShape(st, gain_shape, &gain_frame);
    arrow(); put16("gain_shape", gain_shape, 16); put32("gain_frame", &gain_frame, 1); put_fields(); end_line();
    free(st);
}

static void random_voice_factors(Word16 *vf)
{
    for (int i = 0; i < 5; i++) vf[i] = (Word16)(next_random() % 6 ? random_range(0, 32767) : (random16() & 0x7fff));
}

static void case_wb_tbe_dec(void)
{
    Decoder_State_fx *st = new_state();
    Word32 exc[640];
    Word16 vf[5], synth[960], q_synth = 0x5a5a, q_exc = (Word16)random_range(0, 7);
    Word16 coder_type = (Word16)random_range(0, 3);
    int magnitude = magnitudes[next_random() % 5];
    randomise(); common_controls(st);
    st->extl_fx = WB_TBE; st->extl_brate_fx = next_random() & 1 ? 350 : 1050;
    st->bws_cnt_fx = (Word16)(next_random() % 10 == 0);
    st->use_partial_copy = (Word16)(next_random() % 8 == 0);
    /* the RF partial copy only carries the 0.35 kbit/s WB TBE (4 LSFs); with 6 the reference would read the
     * two LSFs it never set */
    if (st->use_partial_copy) st->extl_brate_fx = 350;
    st->prev_use_partial_copy = (Word16)(next_random() % 4 == 0);
    st->last_extl_fx = (Word16)(next_random() % 3 ? 5 : random_range(0, 11));
    st->rf_frame_type = (Word16)random_range(4 + 1, 4 + 3);
    st->rf_indx_tbeGainFr = (Word16)(st->rf_frame_type == 4 + 3 || next_random() % 8 == 0 ? random_range(0, 20) : random_range(0, 3));
    st->core_fx = (Word16)(next_random() % 4 == 0); st->last_core_fx = (Word16)(next_random() % 4 == 0);
    st->prev_coder_type_fx = (Word16)random_range(0, 3); st->last_coder_type_fx = (Word16)random_range(0, 3);
    st->prev_tilt_code_dec_fx = (Word16)random_range(0, 4000);
    st->codec_mode = next_random() % 4 ? 1 : 2;
    st->prev_Q_bwe_exc = (Word16)random_range(0, 26); st->prev_Qx = (Word16)random_range(0, 10);
    st->prev_frame_pow_exp = (Word16)random_range(0, 40);
    st->prev_wb_bwe_frame_pow_fx = positive32() >> (next_random() % 12);
    st->igf = (Word16)(next_random() & 1);
    st->GainAttn_fx = (Word16)random_range(0, 32767);
    st->GainFrame_prevfrm_fx = positive32() >> (next_random() % 8);
    st->lsf_WB_fx = (Word16)random_range(0, 3); st->gFrame_WB_fx = (Word16)random_range(0, 15);
    /* the previous LSFs of a stable filter: increasing, spread over (0, 0.5) in Q15 */
    { int lsf = 0; for (int i = 0; i < 10; i++) { lsf += random_range(700, 4200); st->lsp_prevfrm_fx[i] = (Word16)(lsf > 32000 ? 32000 : lsf); } }
    for (int i = 0; i < 6; i++) st->prev_lpc_wb_fx[i] = (Word16)random_range(-8000, 8000);
    for (int i = 0; i < 2; i++) st->bwe_seed_fx[i] = (Word16)random_range(0, 32767);
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(st->next_bit_pos_fx + (next_random() % 6 ? random_range(60, 200) : random_range(0, 60)));
    random_bits(300);
    for (int i = 0; i < 640; i++) exc[i] = (Word32)random_range(-magnitude * 64, magnitude * 64) * (next_random() & 1 ? 1 : 1024);
    if (next_random() % 10 == 0) memset(exc, 0, sizeof exc);
    random_voice_factors(vf);
    for (int i = 0; i < 960; i++) synth[i] = (Word16)random_range(-1000, 1000);
    put16("bits", (Word16 *)0, 0); { for (int i = 0; i < 300; i++) printf(i ? ",%d" : "%d", bits[i]); }
    put32("exc", exc, 640); put16("vf", vf, 5); put1("q_exc", q_exc); put1("coder_type", coder_type); put16("synth", synth, 960);
    put_fields();
    wb_tbe_dec_fx(st, coder_type, exc, q_exc, vf, synth, &q_synth);
    arrow(); put16("synth_out", synth, 960); put1("q_synth", q_synth); put_fields(); end_line();
    free(st);
}

static void case_fb_tbe_dec(void)
{
    Decoder_State_fx *st = new_state();
    Word16 fb_exc1[320], fb_exc2[320], hb1[960], hb2[960], q_fb = (Word16)random_range(2, 14), exp1 = (Word16)random_range(2, 14);
    int magnitude = magnitudes[next_random() % 5];
    randomise(); common_controls(st);
    memset(st->fbbwe_hpf_mem_fx, 0, sizeof st->fbbwe_hpf_mem_fx);
    memset(st->fbbwe_hpf_mem_fx_Q, 0, sizeof st->fbbwe_hpf_mem_fx_Q);
    st->extl_fx = FB_TBE;
    st->codec_mode = next_random() % 3 ? 1 : 2;
    st->idxGain_fx = (Word16)random_range(0, 15);
    st->prev_fbbwe_ratio_fx = (Word16)random_range(0, 32767);
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(st->next_bit_pos_fx + (next_random() % 6 ? random_range(60, 200) : random_range(0, 4)));
    random_bits(300);
    random_signal(fb_exc1, 320, magnitude); random_signal(fb_exc2, 320, magnitude);
    random_signal(hb1, 960, 8000); random_signal(hb2, 960, 8000);
    put16("bits", (Word16 *)0, 0); { for (int i = 0; i < 300; i++) printf(i ? ",%d" : "%d", bits[i]); }
    put16("exc1", fb_exc1, 320); put16("exc2", fb_exc2, 320); put16("hb1", hb1, 960); put16("hb2", hb2, 960);
    put1("q_fb", q_fb); put1("exp1", exp1);
    put_fields();
    fb_tbe_dec_fx(st, fb_exc1, q_fb, hb1, exp1);
    Word16 first_bfi = st->bfi_fx;
    (void)first_bfi;
    st->bfi_fx = (Word16)(next_random() % 4 == 0);
    put1("bfi2", st->bfi_fx);
    fb_tbe_dec_fx(st, fb_exc2, q_fb, hb2, exp1);
    arrow(); put16("hb1_out", hb1, 960); put16("hb2_out", hb2, 960); put_fields(); end_line();
    free(st);
}

static void case_swb_tbe_dec(void)
{
    static const Word32 swb_brates[] = {1600, 1800, 2800, 3000};
    Decoder_State_fx *st = new_state();
    Word32 exc[640];
    Word16 vf[5], synth[960], white[320], old_syn[320], pitch[5], q_synth = 0x5a5a, q_white = (Word16)random_range(2, 14);
    Word16 q_exc = (Word16)random_range(0, 7), coder_type = (Word16)random_range(0, 4);
    int magnitude = magnitudes[next_random() % 5];
    randomise(); common_controls(st);
    st->extl_fx = next_random() % 3 ? SWB_TBE : FB_TBE;
    st->extl_brate_fx = swb_brates[next_random() % 4];
    st->codec_mode = next_random() % 4 ? 1 : 2;
    st->bws_cnt_fx = (Word16)(next_random() % 8 == 0 ? random_range(1, 40) : 0);
    st->bws_cnt1_fx = (Word16)(next_random() % 8 == 0 ? random_range(1, 40) : 0);
    st->use_partial_copy = (Word16)(next_random() % 10 == 0);
    st->rf_flag = (Word16)(st->use_partial_copy || next_random() % 12 == 0);
    st->prev_use_partial_copy = (Word16)(next_random() % 4 == 0);
    st->last_extl_fx = (Word16)(next_random() % 3 ? (next_random() & 1 ? 8 : 11) : random_range(0, 11));
    st->rf_frame_type = (Word16)random_range(4 + 1, 4 + 3);
    st->rf_indx_tbeGainFr = (Word16)(st->rf_frame_type == 4 + 3 ? random_range(0, 15) : random_range(0, 3));
    st->core_fx = (Word16)(next_random() % 4 == 0); st->last_core_fx = (Word16)(next_random() % 4 == 0);
    st->prev_coder_type_fx = (Word16)random_range(0, 4); st->last_coder_type_fx = (Word16)random_range(0, 3);
    st->next_coder_type = (Word16)random_range(0, 3);
    st->last_good_fx = (Word16)random_range(0, 3); st->nbLostCmpt = (Word16)random_range(0, 4);
    if (st->use_partial_copy && next_random() % 3) {   /* the conditions of the RF gain smoothing */
        st->core_fx = 0; st->last_core_fx = 0; st->prev_use_partial_copy = 0; st->last_coder_type_fx = 2;
        st->last_extl_fx = 8; st->rf_frame_type = (Word16)(next_random() & 1 ? 4 + 2 : 4 + 3);
        st->rf_indx_tbeGainFr = (Word16)(st->rf_frame_type == 4 + 3 ? random_range(0, 15) : random_range(0, 3));
        st->prev_coder_type_fx = 1; st->next_coder_type = 1;
        st->GainFrame_prevfrm_fx = random_range(1500000, 4200000);
    }
    st->clas_dec = (Word16)random_range(0, 5);
    st->prev_Q_bwe_exc = (Word16)random_range(0, 26); st->prev_Q_bwe_syn = (Word16)random_range(0, 15);
    st->prev_Q_bwe_syn2 = (Word16)random_range(0, 15); st->prev_Qx = (Word16)random_range(0, 15);
    st->prev_Q_bwe_exc_fb = (Word16)(next_random() & 1 ? 51 : random_range(0, 30));
    st->prev_ener_fx_Q = (Word16)random_range(0, 30);
    st->prev_frame_pow_exp = (Word16)random_range(0, 40);
    st->Q_syn2 = (Word16)random_range(4, 15);
    st->prev_swb_bwe_frame_pow_fx = positive32() >> (next_random() % 14);
    st->prev_ener_fx = positive32() >> (next_random() % 14);
    st->prev1_shb_ener_sf_fx = positive32() >> (next_random() % 20);
    st->prev2_shb_ener_sf_fx = positive32() >> (next_random() % 20);
    st->prev3_shb_ener_sf_fx = positive32() >> (next_random() % 20);
    {   /* the lost-frame energy estimate divides by a root of the older energies: div_s needs the
         * numerator not above the denominator, which real energies satisfy; a stand-in that would not
         * is replaced by zero */
        Word16 exp = 0;
        Word32 product = L_mult(extract_l(st->prev2_shb_ener_sf_fx), extract_l(st->prev3_shb_ener_sf_fx));
        Word16 root = round_fx(root_a_fx(product, 1, &exp)), first = extract_l(st->prev1_shb_ener_sf_fx);
        first = shl(first, sub(norm_s(first), 1));
        if (root != 0 && (first < 0 || first > root)) st->prev1_shb_ener_sf_fx = 0;
    }
    st->enerLH_fx = positive32() >> (next_random() % 14); st->enerLL_fx = positive32() >> (next_random() % 14);
    st->prev_enerLH_fx = (next_random() & 1) ? st->enerLH_fx + random_range(-1000, 1000) : positive32() >> (next_random() % 14);
    st->prev_enerLL_fx = (next_random() & 1) ? st->enerLL_fx + random_range(-1000, 1000) : positive32() >> (next_random() % 14);
    if (st->prev_enerLH_fx < 0) st->prev_enerLH_fx = 0;
    if (st->prev_enerLL_fx < 0) st->prev_enerLL_fx = 0;
    st->last_core_brate_fx = total_brates[next_random() % 7]; st->core_brate_fx = total_brates[next_random() % 7];
    st->tilt_wb_fx = (Word16)random_range(0, 30000); st->tilt_swb_fx = (Word16)random_range(0, 30000);
    st->tilt_swb_fec_fx = (Word16)random_range(0, 30000); st->prev_fractive_fx = (Word16)(next_random() & 1);
    st->prev_GainShape_fx = (Word16)random_range(0, 32767); st->prev_ener_shb_fx = (Word16)random_range(0, 32767);
    st->prev_mixFactors_fx = (Word16)random_range(0, 18432); st->prev_res_shb_gshape_fx = (Word16)random_range(1000, 9500);
    st->tilt_mem_fx = (Word16)random_range(0, 32767); st->cummulative_damping = (Word16)random_range(0, 32767);
    st->prev_tilt_para_fx = (Word16)random_range(0, 8000);
    st->GainAttn_fx = (Word16)random_range(0, 32767);
    if (!(st->use_partial_copy && st->core_fx == 0 && st->last_extl_fx == 8 && st->GainFrame_prevfrm_fx > 1000000)) st->GainFrame_prevfrm_fx = positive32() >> (next_random() % 8);
    for (int i = 0; i < 8; i++) st->GainShape_Delay[i] = (Word16)random_range(0, next_random() & 1 ? 16384 : 3000);
    { int lsf = 0; for (int i = 0; i < 10; i++) { lsf += random_range(700, 4200); st->lsp_prevfrm_fx[i] = (Word16)(lsf > 32000 ? 32000 : lsf); } }
    { int cos = 32000; for (int i = 0; i < 10; i++) { cos -= random_range(500, 6000); st->swb_lsp_prev_interp_fx[i] = (Word16)(cos < -32000 ? -32000 : cos); } }
    for (int i = 0; i < 8; i++) st->prev_lsf_diff_fx[i] = (Word16)random_range(-200, 3000);
    st->cur_sub_Aq_fx[0] = next_random() % 3 ? 4096 : (next_random() & 1 ? 2048 : 8192);
    for (int i = 1; i < 17; i++) st->cur_sub_Aq_fx[i] = (Word16)random_range(-2400 / i, 2400 / i);
    for (int i = 0; i < 10; i++) st->lsp_shb_prev_fx[i] = (Word16)random_range(0, 16384);
    memset(st->mem_zero_swb_fx, 0, sizeof st->mem_zero_swb_fx);
    st->ptr_mem_stp_swb_fx = st->mem_stp_swb_fx + 10 - 1;
    for (int i = 0; i < 2; i++) st->bwe_seed_fx[i] = (Word16)random_range(0, 32767);
    for (int i = 0; i < 14; i++) st->prev_SWB_fenv_fx[i] = random16();
    /* indices read from the state (MODE2, 9.6 kbit/s), each bounded by its bit count */
    int single_stage = !(st->rf_flag == 0 && !(st->total_brate_fx == 9600 || (st->total_brate_fx == 0 && (st->last_total_brate_fx == 9600 || (st->last_total_brate_fx == 13200 && st->rf_flag_last == 1)))));
    st->lsf_idx_fx[0] = (Word16)random_range(0, single_stage ? 255 : 15);
    st->lsf_idx_fx[1] = (Word16)random_range(0, 15);
    for (int i = 2; i < 5; i++) st->lsf_idx_fx[i] = (Word16)random_range(0, 7);
    st->m_idx_fx = (Word16)random_range(0, 3); st->grid_idx_fx = (Word16)random_range(0, 3);
    st->idxSubGains_fx = (Word16)random_range(0, 31); st->idxFrameGain_fx = (Word16)random_range(0, 31);
    st->idx_shb_fr_gain_fx = (Word16)random_range(0, 63); st->idx_mixFac_fx = (Word16)random_range(0, 7);
    for (int i = 0; i < 5; i++) st->idx_res_gs_fx[i] = (Word16)random_range(0, 7);
    st->idxGain_fx = (Word16)random_range(0, 15);
    st->next_bit_pos_fx = (Word16)random_range(0, 40);
    st->total_num_bits = (Word16)(st->next_bit_pos_fx + (next_random() % 8 ? random_range(100, 250) : random_range(0, 60)));
    random_bits(300);
    for (int i = 0; i < 640; i++) exc[i] = (Word32)random_range(-magnitude * 64, magnitude * 64) * (next_random() & 1 ? 1 : 1024);
    if (next_random() % 12 == 0) memset(exc, 0, sizeof exc);
    random_voice_factors(vf);
    random_signal(old_syn, 320, magnitudes[next_random() % 5]);
    for (int i = 0; i < 5; i++) pitch[i] = (Word16)random_range(1000, 18560);
    for (int i = 0; i < 320; i++) white[i] = (Word16)random_range(-300, 300);
    for (int i = 0; i < 960; i++) synth[i] = (Word16)random_range(-1000, 1000);
    put16("bits", (Word16 *)0, 0); { for (int i = 0; i < 300; i++) printf(i ? ",%d" : "%d", bits[i]); }
    put32("exc", exc, 640); put16("vf", vf, 5); put16("old_syn", old_syn, 320); put16("pitch", pitch, 5);
    put1("q_exc", q_exc); put1("coder_type", coder_type); put16("white", white, 320); put1("q_white", q_white);
    put16("synth", synth, 960);
    put_fields();
    swb_tbe_dec_fx(st, coder_type, exc, q_exc, vf, old_syn, white, &q_white, synth, &q_synth, pitch);
    arrow(); put16("synth_out", synth, 960); put1("q_synth", q_synth); put16("white_out", white, 320);
    put1("q_white_out", q_white); put_fields(); end_line();
    free(st);
}

static void case_gen_transition(void)
{
    Word16 input[20], old_hb[222], output[640], local[6], resamp[7], up_mem[15], phase = (Word16)random_range(0, 16);
    Word32 hilbert[21];
    static const Word16 lengths[] = {74, 148, 222};
    Word16 length = lengths[next_random() % 3];
    Word32 target_fs = fs_values[next_random() % 3], bitrate = total_brates[next_random() % 7];
    Word16 rf_flag = (Word16)(next_random() % 4 == 0);
    int magnitude = magnitudes[next_random() % 5];
    random_signal(input, 20, magnitude); random_signal(old_hb, 222, magnitude);
    random_signal(output, 640, magnitude); random_signal(local, 6, magnitude); random_signal(resamp, 7, magnitude);
    random_signal(up_mem, 15, magnitude);
    for (int i = 0; i < 21; i++) hilbert[i] = (Word32)random_range(-(1 << (next_random() & 1 ? 18 : 28)), 1 << (next_random() & 1 ? 18 : 28));
    put16("input", input, 20); put16("old_hb", old_hb, 222); put16("output", output, 640); put16("local", local, 6);
    put16("resamp", resamp, 7); put16("up_mem", up_mem, 15); put32("hilbert", hilbert, 21); put1("phase", phase);
    put1("length", length); put1("target_fs", target_fs); put1("bitrate", bitrate); put1("rf_flag", rf_flag);
    GenTransition_fx(input, old_hb, length, output, hilbert, local, resamp, &phase, target_fs, up_mem, rf_flag, bitrate);
    arrow(); put16("output_out", output, 640); put16("local_out", local, 6); put16("resamp_out", resamp, 7);
    put16("up_mem_out", up_mem, 15); put32("hilbert_out", hilbert, 21); put1("phase_out", phase); end_line();
}

static void case_gen_transition_wb(void)
{
    Word16 input[10], old_hb[222], output[960], state1[6], state2[6], up_mem[13], prev_qx = (Word16)random_range(0, 8);
    static const Word16 lengths[] = {74, 148, 222};
    Word16 length = lengths[next_random() % 3];
    Word32 output_fs = fs_values[next_random() % 3];
    int magnitude = magnitudes[next_random() % 5];
    random_signal(input, 10, magnitude); random_signal(old_hb, 222, magnitude);
    random_signal(output, 960, magnitude); random_signal(state1, 6, magnitude); random_signal(state2, 6, magnitude);
    random_signal(up_mem, 13, magnitude);
    put16("input", input, 10); put16("old_hb", old_hb, 222); put16("output", output, 960); put16("state1", state1, 6);
    put16("state2", state2, 6); put16("up_mem", up_mem, 13); put1("prev_qx", prev_qx); put1("length", length);
    put1("output_fs", output_fs);
    GenTransition_WB_fx(input, old_hb, prev_qx, length, output, state1, state2, output_fs, up_mem);
    arrow(); put16("output_out", output, 960); put16("state1_out", state1, 6); put16("state2_out", state2, 6);
    put16("up_mem_out", up_mem, 13); end_line();
}

static void case_decimate_in_place(void)
{
    Word16 buffer[640], state[7];
    int magnitude = magnitudes[next_random() % 5];
    random_signal(buffer, 640, magnitude); random_signal(state, 7, magnitude);
    put16("buffer", buffer, 640); put16("state", state, 7);
    Decimate_allpass_steep_fx(buffer, state, 640, buffer);
    arrow(); put16("buffer_out", buffer, 320); put16("state_out", state, 7); end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        const char *f = argv[2];
        if (!strcmp(f, "find_max_mem_dec")) case_find_max_mem_dec();
        else if (!strcmp(f, "rescale_gen_shb_mem")) case_rescale_gen_shb_mem();
        else if (!strcmp(f, "find_max_mem_wb")) case_find_max_mem_wb();
        else if (!strcmp(f, "rescale_gen_wb_mem")) case_rescale_gen_wb_mem();
        else if (!strcmp(f, "tbe_reset_dec")) case_tbe_reset_dec();
        else if (!strcmp(f, "tbe_read_bitstream")) case_tbe_read_bitstream();
        else if (!strcmp(f, "dequantize")) case_dequantize();
        else if (!strcmp(f, "gradient_gain_shape")) case_gradient_gain_shape();
        else if (!strcmp(f, "wb_tbe_dec")) case_wb_tbe_dec();
        else if (!strcmp(f, "fb_tbe_dec")) case_fb_tbe_dec();
        else if (!strcmp(f, "swb_tbe_dec")) case_swb_tbe_dec();
        else if (!strcmp(f, "gen_transition")) case_gen_transition();
        else if (!strcmp(f, "gen_transition_wb")) case_gen_transition_wb();
        else if (!strcmp(f, "decimate_in_place")) case_decimate_in_place();
        else { fprintf(stderr, "unknown function %s\n", f); return 2; }
    }
    return 0;
}
