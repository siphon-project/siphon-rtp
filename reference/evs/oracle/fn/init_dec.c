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
static void rd_dump_DispMem(const char *pre, struct dispMem_fx *p);
static void rd_fill_DispMem(struct dispMem_fx *p);
static void rd_dump_CldfbFilterBank(const char *pre, struct CLDFB_FILTER_BANK *p);
static void rd_fill_CldfbFilterBank(struct CLDFB_FILTER_BANK *p);
static void rd_dump_FdCngCom(const char *pre, FD_CNG_COM *p);
static void rd_fill_FdCngCom(FD_CNG_COM *p);
static void rd_dump_FdCngDec(const char *pre, FD_CNG_DEC *p);
static void rd_fill_FdCngDec(FD_CNG_DEC *p);
static void rd_dump_AcelpConfig(const char *pre, ACELP_config *p);
static void rd_fill_AcelpConfig(ACELP_config *p);
static void rd_dump_STnsConfig(const char *pre, STnsConfig *p);
static void rd_fill_STnsConfig(STnsConfig *p);
static void rd_dump_TcxConfig(const char *pre, TCX_config *p);
static void rd_fill_TcxConfig(TCX_config *p);
static void rd_dump_Pfstat(const char *pre, PFSTAT *p);
static void rd_fill_Pfstat(PFSTAT *p);
static void rd_dump_BlockData(const char *pre, blockData *p);
static void rd_fill_BlockData(blockData *p);
static void rd_dump_TonalComponentsInfo(const char *pre, TonalComponentsInfo *p);
static void rd_fill_TonalComponentsInfo(TonalComponentsInfo *p);
static void rd_dump_Tonalmdctconceal(const char *pre, struct tonalmdctconceal *p);
static void rd_fill_Tonalmdctconceal(struct tonalmdctconceal *p);
static void rd_dump_TPLCInfo(const char *pre, T_PLCInfo *p);
static void rd_fill_TPLCInfo(T_PLCInfo *p);
static void rd_dump_IgfGrid(const char *pre, IGF_GRID *p);
static void rd_fill_IgfGrid(IGF_GRID *p);
static void rd_dump_IgfInfo(const char *pre, IGF_INFO *p);
static void rd_fill_IgfInfo(IGF_INFO *p);
static void rd_dump_TastatDec(const char *pre, TastatDec *p);
static void rd_fill_TastatDec(TastatDec *p);
static void rd_dump_IgfscfdecInstance(const char *pre, IGFSCFDEC_INSTANCE *p);
static void rd_fill_IgfscfdecInstance(IGFSCFDEC_INSTANCE *p);
static void rd_dump_IgfdecPrivateData(const char *pre, IGFDEC_PRIVATE_DATA *p);
static void rd_fill_IgfdecPrivateData(IGFDEC_PRIVATE_DATA *p);
static void rd_dump_IgfdecInstance(const char *pre, IGFDEC_INSTANCE *p);
static void rd_fill_IgfdecInstance(IGFDEC_INSTANCE *p);
static void rd_dump_CldfbScaleFactor(const char *pre, CLDFB_SCALE_FACTOR *p);
static void rd_fill_CldfbScaleFactor(CLDFB_SCALE_FACTOR *p);
static void rd_dump_TemporalEnvelopeCodingDecoderFx(const char *pre, TEMPORAL_ENVELOPE_CODING_DECODER_FX *p);
static void rd_fill_TemporalEnvelopeCodingDecoderFx(TEMPORAL_ENVELOPE_CODING_DECODER_FX *p);
static void rd_dump_DecoderState(const char *pre, Decoder_State_fx *p);
static void rd_fill_DecoderState(Decoder_State_fx *p);
static void rd_dump_DispMem(const char *pre, struct dispMem_fx *p)
{
    rd_put_i16(pre, "prev_state", (Word16 *)&p->prev_state, 1);
    rd_put_i32(pre, "prev_gain_code", (Word32 *)&p->prev_gain_code, 1);
    rd_put_i16(pre, "prev_gain_pit", (Word16 *)&p->prev_gain_pit, 6);
}
static void rd_fill_DispMem(struct dispMem_fx *p)
{
    rd_fill_i16((Word16 *)&p->prev_state, 1);
    rd_fill_i32((Word32 *)&p->prev_gain_code, 1);
    rd_fill_i16((Word16 *)&p->prev_gain_pit, 6);
}
static void rd_dump_CldfbFilterBank(const char *pre, struct CLDFB_FILTER_BANK *p)
{
    rd_put_rom16(pre, "p_filter", (const Word16 *)p->p_filter);
    if (p->FilterStates == NULL) rd_put16(pre, "FilterStates", NULL, 0); else rd_put16(pre, "FilterStates", p->FilterStates, rd_cldfb_states_length(p));
    rd_put_i16(pre, "FilterStates_e", (Word16 *)&p->FilterStates_e, 25);
    rd_put_i16(pre, "FilterStates_eg", (Word16 *)&p->FilterStates_eg, 1);
    rd_put_i16(pre, "p_filter_length", (Word16 *)&p->p_filter_length, 1);
    rd_put_rom16(pre, "rRotVctr", (const Word16 *)p->rRotVctr);
    rd_put_rom16(pre, "iRotVctr", (const Word16 *)p->iRotVctr);
    rd_put_i16(pre, "filterScale", (Word16 *)&p->filterScale, 1);
    rd_put_i16(pre, "synGain", (Word16 *)&p->synGain, 1);
    rd_put_i16(pre, "no_channels", (Word16 *)&p->no_channels, 1);
    rd_put_i16(pre, "no_col", (Word16 *)&p->no_col, 1);
    rd_put_i16(pre, "lsb", (Word16 *)&p->lsb, 1);
    rd_put_i16(pre, "usb", (Word16 *)&p->usb, 1);
    rd_put_i16(pre, "zeros", (Word16 *)&p->zeros, 1);
    rd_put_i16(pre, "anaScalefactor", (Word16 *)&p->anaScalefactor, 1);
    rd_put_i16(pre, "synScalefactor", (Word16 *)&p->synScalefactor, 1);
    rd_put_i16(pre, "outScalefactor", (Word16 *)&p->outScalefactor, 1);
    rd_put_i16(pre, "synFilterHeadroom", (Word16 *)&p->synFilterHeadroom, 1);
    rd_put_u16(pre, "flags", (UWord16 *)&p->flags, 1);
    rd_put_i16(pre, "bandsToZero", (Word16 *)&p->bandsToZero, 1);
    rd_put_i16(pre, "filtermode", (Word16 *)&p->filtermode, 1);
    rd_put_i16(pre, "type", (Word16 *)&p->type, 1);
    if (p->memory == NULL) rd_put16(pre, "memory", NULL, 0); else rd_put16(pre, "memory", p->memory, p->memory_length + CLDFB_NO_COL_MAX + 9 + 1);
    rd_put_i16(pre, "memory_length", (Word16 *)&p->memory_length, 1);
    rd_put_i16(pre, "scale", (Word16 *)&p->scale, 1);
}
static void rd_fill_CldfbFilterBank(struct CLDFB_FILTER_BANK *p)
{
    rd_fill_i16((Word16 *)&p->FilterStates_e, 25);
    rd_fill_i16((Word16 *)&p->FilterStates_eg, 1);
    rd_fill_i16((Word16 *)&p->p_filter_length, 1);
    rd_fill_i16((Word16 *)&p->filterScale, 1);
    rd_fill_i16((Word16 *)&p->synGain, 1);
    rd_fill_i16((Word16 *)&p->no_channels, 1);
    rd_fill_i16((Word16 *)&p->no_col, 1);
    rd_fill_i16((Word16 *)&p->lsb, 1);
    rd_fill_i16((Word16 *)&p->usb, 1);
    rd_fill_i16((Word16 *)&p->zeros, 1);
    rd_fill_i16((Word16 *)&p->anaScalefactor, 1);
    rd_fill_i16((Word16 *)&p->synScalefactor, 1);
    rd_fill_i16((Word16 *)&p->outScalefactor, 1);
    rd_fill_i16((Word16 *)&p->synFilterHeadroom, 1);
    rd_fill_u16((UWord16 *)&p->flags, 1);
    rd_fill_i16((Word16 *)&p->bandsToZero, 1);
    rd_fill_i16((Word16 *)&p->filtermode, 1);
    rd_fill_i16((Word16 *)&p->type, 1);
    rd_fill_i16((Word16 *)&p->memory_length, 1);
    rd_fill_i16((Word16 *)&p->scale, 1);
}
static void rd_dump_FdCngCom(const char *pre, FD_CNG_COM *p)
{
    { char b[256]; snprintf(b, sizeof b, "%sFdCngSetup.", pre);
      rd_put_i16(b, "fftlen", &p->FdCngSetup.fftlen, 1); rd_put_i16(b, "stopFFTbin", &p->FdCngSetup.stopFFTbin, 1);
      rd_put_i16(b, "numPartitions", &p->FdCngSetup.numPartitions, 1); rd_put_rom16(b, "sidPartitions", p->FdCngSetup.sidPartitions);
      rd_put_i16(b, "numShapingPartitions", &p->FdCngSetup.numShapingPartitions, 1); rd_put_rom16(b, "shapingPartitions", p->FdCngSetup.shapingPartitions); }
    rd_put_i16(pre, "numSlots", (Word16 *)&p->numSlots, 1);
    rd_put_i16(pre, "regularStopBand", (Word16 *)&p->regularStopBand, 1);
    rd_put_i16(pre, "numCoreBands", (Word16 *)&p->numCoreBands, 1);
    rd_put_i16(pre, "stopBand", (Word16 *)&p->stopBand, 1);
    rd_put_i16(pre, "startBand", (Word16 *)&p->startBand, 1);
    rd_put_i16(pre, "stopFFTbin", (Word16 *)&p->stopFFTbin, 1);
    rd_put_i16(pre, "frameSize", (Word16 *)&p->frameSize, 1);
    rd_put_i16(pre, "fftlen", (Word16 *)&p->fftlen, 1);
    rd_put_i16(pre, "fftlenShift", (Word16 *)&p->fftlenShift, 1);
    rd_put_i16(pre, "fftlenFac", (Word16 *)&p->fftlenFac, 1);
    rd_put_i16(pre, "timeDomainBuffer", (Word16 *)&p->timeDomainBuffer, 320);
    rd_put_i32(pre, "fftBuffer", (Word32 *)&p->fftBuffer, 640);
    rd_put1(pre, "olapBufferAna", p->olapBufferAna == NULL ? -1 : (long long)(p->olapBufferAna - rd_parent_fd_cng_dec->olapBufferAna));
    rd_put_i16(pre, "olapBufferSynth", (Word16 *)&p->olapBufferSynth, 640);
    rd_put1(pre, "olapBufferSynth2", p->olapBufferSynth2 == NULL ? -1 : (long long)(p->olapBufferSynth2 - rd_parent_fd_cng_dec->olapBufferSynth2));
    rd_put_romp16(pre, "olapWinAna", (const PWord16 *)p->olapWinAna);
    rd_put_romp16(pre, "olapWinSyn", (const PWord16 *)p->olapWinSyn);
    rd_put_i16(pre, "msM_win", (Word16 *)&p->msM_win, 1);
    rd_put_i16(pre, "msM_subwin", (Word16 *)&p->msM_subwin, 1);
    rd_put_i16(pre, "msFrCnt_init_counter", (Word16 *)&p->msFrCnt_init_counter, 1);
    rd_put_i16(pre, "init_old", (Word16 *)&p->init_old, 1);
    rd_put_i16(pre, "msFrCnt_init_thresh", (Word16 *)&p->msFrCnt_init_thresh, 1);
    rd_put_i16(pre, "msFrCnt", (Word16 *)&p->msFrCnt, 1);
    rd_put_i32(pre, "msAlphaCor", (Word32 *)&p->msAlphaCor, 2);
    rd_put_i16(pre, "msSlope", (Word16 *)&p->msSlope, 2);
    rd_put_i32(pre, "msQeqInvAv", (Word32 *)&p->msQeqInvAv, 2);
    rd_put_i16(pre, "msQeqInvAv_exp", (Word16 *)&p->msQeqInvAv_exp, 2);
    rd_put_i16(pre, "msMinBufferPtr", (Word16 *)&p->msMinBufferPtr, 1);
    rd_put_i32(pre, "msPsdSum", (Word32 *)&p->msPsdSum, 2);
    rd_put_i32(pre, "msPeriodogSum", (Word32 *)&p->msPeriodogSum, 2);
    rd_put_i16(pre, "msPeriodogSum_exp", (Word16 *)&p->msPeriodogSum_exp, 2);
    rd_put_i16(pre, "offsetflag", (Word16 *)&p->offsetflag, 1);
    rd_put_i32(pre, "periodog", (Word32 *)&p->periodog, 318);
    rd_put_i16(pre, "periodog_exp", (Word16 *)&p->periodog_exp, 1);
    rd_put_i16(pre, "exp_cldfb_periodog", (Word16 *)&p->exp_cldfb_periodog, 1);
    rd_put_i32(pre, "cngNoiseLevel", (Word32 *)&p->cngNoiseLevel, 340);
    rd_put_i16(pre, "cngNoiseLevelExp", (Word16 *)&p->cngNoiseLevelExp, 1);
    rd_put_i16(pre, "seed", (Word16 *)&p->seed, 1);
    rd_put_i16(pre, "npart", (Word16 *)&p->npart, 1);
    rd_put_i16(pre, "midband", (Word16 *)&p->midband, 24);
    rd_put_i16(pre, "nFFTpart", (Word16 *)&p->nFFTpart, 1);
    rd_put_i16(pre, "part", (Word16 *)&p->part, 24);
    rd_put_i16(pre, "psize", (Word16 *)&p->psize, 24);
    rd_put_i16(pre, "psize_norm", (Word16 *)&p->psize_norm, 24);
    rd_put_i16(pre, "psize_norm_exp", (Word16 *)&p->psize_norm_exp, 1);
    rd_put_i16(pre, "psize_inv", (Word16 *)&p->psize_inv, 24);
    rd_put_i16(pre, "FFTscalingFactor", (Word16 *)&p->FFTscalingFactor, 1);
    rd_put_i16(pre, "scalingFactor", (Word16 *)&p->scalingFactor, 1);
    rd_put_i16(pre, "invScalingFactor", (Word16 *)&p->invScalingFactor, 1);
    rd_put_i16(pre, "nCLDFBpart", (Word16 *)&p->nCLDFBpart, 1);
    rd_put_i16(pre, "CLDFBpart", (Word16 *)&p->CLDFBpart, 10);
    rd_put_i16(pre, "CLDFBpsize_inv", (Word16 *)&p->CLDFBpsize_inv, 10);
    rd_put_i16(pre, "inactive_frame_counter", (Word16 *)&p->inactive_frame_counter, 1);
    rd_put_i16(pre, "sid_frame_counter", (Word16 *)&p->sid_frame_counter, 1);
    rd_put_i16(pre, "active_frame_counter", (Word16 *)&p->active_frame_counter, 1);
    rd_put_i32(pre, "sidNoiseEst", (Word32 *)&p->sidNoiseEst, 24);
    rd_put_i16(pre, "sidNoiseEstExp", (Word16 *)&p->sidNoiseEstExp, 1);
    rd_put_i16(pre, "frame_type_previous", (Word16 *)&p->frame_type_previous, 1);
    rd_put_i16(pre, "A_cng", (Word16 *)&p->A_cng, 17);
    rd_put_i16(pre, "exc_cng", (Word16 *)&p->exc_cng, 320);
    rd_put_i32(pre, "CngBitrate", (Word32 *)&p->CngBitrate, 1);
    rd_put_i16(pre, "CngBandwidth", (Word16 *)&p->CngBandwidth, 1);
    rd_put_i16(pre, "flag_noisy_speech", (Word16 *)&p->flag_noisy_speech, 1);
    rd_put_i16(pre, "likelihood_noisy_speech", (Word16 *)&p->likelihood_noisy_speech, 1);
}
static void rd_fill_FdCngCom(FD_CNG_COM *p)
{
    rd_fill_i16(&p->FdCngSetup.fftlen, 1); rd_fill_i16(&p->FdCngSetup.stopFFTbin, 1); rd_fill_i16(&p->FdCngSetup.numPartitions, 1); rd_fill_i16(&p->FdCngSetup.numShapingPartitions, 1);
    rd_fill_i16((Word16 *)&p->numSlots, 1);
    rd_fill_i16((Word16 *)&p->regularStopBand, 1);
    rd_fill_i16((Word16 *)&p->numCoreBands, 1);
    rd_fill_i16((Word16 *)&p->stopBand, 1);
    rd_fill_i16((Word16 *)&p->startBand, 1);
    rd_fill_i16((Word16 *)&p->stopFFTbin, 1);
    rd_fill_i16((Word16 *)&p->frameSize, 1);
    rd_fill_i16((Word16 *)&p->fftlen, 1);
    rd_fill_i16((Word16 *)&p->fftlenShift, 1);
    rd_fill_i16((Word16 *)&p->fftlenFac, 1);
    rd_fill_i16((Word16 *)&p->timeDomainBuffer, 320);
    rd_fill_i32((Word32 *)&p->fftBuffer, 640);
    rd_fill_i16((Word16 *)&p->olapBufferSynth, 640);
    rd_fill_i16((Word16 *)&p->msM_win, 1);
    rd_fill_i16((Word16 *)&p->msM_subwin, 1);
    rd_fill_i16((Word16 *)&p->msFrCnt_init_counter, 1);
    rd_fill_i16((Word16 *)&p->init_old, 1);
    rd_fill_i16((Word16 *)&p->msFrCnt_init_thresh, 1);
    rd_fill_i16((Word16 *)&p->msFrCnt, 1);
    rd_fill_i32((Word32 *)&p->msAlphaCor, 2);
    rd_fill_i16((Word16 *)&p->msSlope, 2);
    rd_fill_i32((Word32 *)&p->msQeqInvAv, 2);
    rd_fill_i16((Word16 *)&p->msQeqInvAv_exp, 2);
    rd_fill_i16((Word16 *)&p->msMinBufferPtr, 1);
    rd_fill_i32((Word32 *)&p->msPsdSum, 2);
    rd_fill_i32((Word32 *)&p->msPeriodogSum, 2);
    rd_fill_i16((Word16 *)&p->msPeriodogSum_exp, 2);
    rd_fill_i16((Word16 *)&p->offsetflag, 1);
    rd_fill_i32((Word32 *)&p->periodog, 318);
    rd_fill_i16((Word16 *)&p->periodog_exp, 1);
    rd_fill_i16((Word16 *)&p->exp_cldfb_periodog, 1);
    rd_fill_i32((Word32 *)&p->cngNoiseLevel, 340);
    rd_fill_i16((Word16 *)&p->cngNoiseLevelExp, 1);
    rd_fill_i16((Word16 *)&p->seed, 1);
    rd_fill_i16((Word16 *)&p->npart, 1);
    rd_fill_i16((Word16 *)&p->midband, 24);
    rd_fill_i16((Word16 *)&p->nFFTpart, 1);
    rd_fill_i16((Word16 *)&p->part, 24);
    rd_fill_i16((Word16 *)&p->psize, 24);
    rd_fill_i16((Word16 *)&p->psize_norm, 24);
    rd_fill_i16((Word16 *)&p->psize_norm_exp, 1);
    rd_fill_i16((Word16 *)&p->psize_inv, 24);
    rd_fill_i16((Word16 *)&p->FFTscalingFactor, 1);
    rd_fill_i16((Word16 *)&p->scalingFactor, 1);
    rd_fill_i16((Word16 *)&p->invScalingFactor, 1);
    rd_fill_i16((Word16 *)&p->nCLDFBpart, 1);
    rd_fill_i16((Word16 *)&p->CLDFBpart, 10);
    rd_fill_i16((Word16 *)&p->CLDFBpsize_inv, 10);
    rd_fill_i16((Word16 *)&p->inactive_frame_counter, 1);
    rd_fill_i16((Word16 *)&p->sid_frame_counter, 1);
    rd_fill_i16((Word16 *)&p->active_frame_counter, 1);
    rd_fill_i32((Word32 *)&p->sidNoiseEst, 24);
    rd_fill_i16((Word16 *)&p->sidNoiseEstExp, 1);
    rd_fill_i16((Word16 *)&p->frame_type_previous, 1);
    rd_fill_i16((Word16 *)&p->A_cng, 17);
    rd_fill_i16((Word16 *)&p->exc_cng, 320);
    rd_fill_i32((Word32 *)&p->CngBitrate, 1);
    rd_fill_i16((Word16 *)&p->CngBandwidth, 1);
    rd_fill_i16((Word16 *)&p->flag_noisy_speech, 1);
    rd_fill_i16((Word16 *)&p->likelihood_noisy_speech, 1);
}
static void rd_dump_FdCngDec(const char *pre, FD_CNG_DEC *p)
{
    { char b[256]; snprintf(b, sizeof b, "%shFdCngCom.", pre); rd_put1(pre, "hFdCngCom", p->hFdCngCom != NULL); if (p->hFdCngCom != NULL) { rd_parent_fd_cng_dec = p; rd_dump_FdCngCom(b, p->hFdCngCom); } }
    rd_put_i16(pre, "olapBufferAna", (Word16 *)&p->olapBufferAna, 320);
    rd_put_i16(pre, "olapBufferSynth2", (Word16 *)&p->olapBufferSynth2, 640);
    rd_put_i32(pre, "msPeriodog", (Word32 *)&p->msPeriodog, 62);
    rd_put_i16(pre, "msPeriodog_exp", (Word16 *)&p->msPeriodog_exp, 1);
    rd_put_i16(pre, "msPeriodog_exp_fft", (Word16 *)&p->msPeriodog_exp_fft, 1);
    rd_put_i16(pre, "msPeriodog_exp_cldfb", (Word16 *)&p->msPeriodog_exp_cldfb, 1);
    rd_put_i32(pre, "msBminWin", (Word32 *)&p->msBminWin, 62);
    rd_put_i32(pre, "msBminSubWin", (Word32 *)&p->msBminSubWin, 62);
    rd_put_i16(pre, "msPsd", (Word16 *)&p->msPsd, 62);
    rd_put_i16(pre, "msPsd_exp_fft", (Word16 *)&p->msPsd_exp_fft, 1);
    rd_put_i32(pre, "msAlpha", (Word32 *)&p->msAlpha, 62);
    rd_put_i32(pre, "msMinBuf", (Word32 *)&p->msMinBuf, 372);
    rd_put_i32(pre, "msCurrentMinOut", (Word32 *)&p->msCurrentMinOut, 62);
    rd_put_i32(pre, "msCurrentMin", (Word32 *)&p->msCurrentMin, 62);
    rd_put_i32(pre, "msCurrentMinSubWindow", (Word32 *)&p->msCurrentMinSubWindow, 62);
    rd_put_i16(pre, "msLocalMinFlag", (Word16 *)&p->msLocalMinFlag, 62);
    rd_put_i16(pre, "msNewMinFlag", (Word16 *)&p->msNewMinFlag, 62);
    rd_put_i16(pre, "msPsdFirstMoment", (Word16 *)&p->msPsdFirstMoment, 62);
    rd_put_i32(pre, "msPsdSecondMoment", (Word32 *)&p->msPsdSecondMoment, 62);
    rd_put_i16(pre, "msNoiseFloor", (Word16 *)&p->msNoiseFloor, 62);
    rd_put_i32(pre, "msNoiseEst", (Word32 *)&p->msNoiseEst, 62);
    rd_put_i16(pre, "msNoiseEst_exp", (Word16 *)&p->msNoiseEst_exp, 1);
    rd_put_i16(pre, "npart_shaping", (Word16 *)&p->npart_shaping, 1);
    rd_put_i16(pre, "nFFTpart_shaping", (Word16 *)&p->nFFTpart_shaping, 1);
    rd_put_i16(pre, "part_shaping", (Word16 *)&p->part_shaping, 62);
    rd_put_i16(pre, "midband_shaping", (Word16 *)&p->midband_shaping, 62);
    rd_put_i16(pre, "psize_shaping", (Word16 *)&p->psize_shaping, 62);
    rd_put_i16(pre, "psize_shaping_norm", (Word16 *)&p->psize_shaping_norm, 62);
    rd_put_i16(pre, "psize_shaping_norm_exp", (Word16 *)&p->psize_shaping_norm_exp, 1);
    rd_put_i16(pre, "psize_inv_shaping", (Word16 *)&p->psize_inv_shaping, 62);
    rd_put_i32(pre, "bandNoiseShape", (Word32 *)&p->bandNoiseShape, 320);
    rd_put_i16(pre, "bandNoiseShape_exp", (Word16 *)&p->bandNoiseShape_exp, 1);
    rd_put_i32(pre, "partNoiseShape", (Word32 *)&p->partNoiseShape, 24);
    rd_put_i16(pre, "partNoiseShape_exp", (Word16 *)&p->partNoiseShape_exp, 1);
    rd_put_i16(pre, "flag_dtx_mode", (Word16 *)&p->flag_dtx_mode, 1);
    rd_put_i32(pre, "lp_speech", (Word32 *)&p->lp_speech, 1);
    rd_put_i32(pre, "lp_noise", (Word32 *)&p->lp_noise, 1);
    rd_put_i16(pre, "msPeriodogBuf", (Word16 *)&p->msPeriodogBuf, 310);
    rd_put_i16(pre, "msPeriodogBufPtr", (Word16 *)&p->msPeriodogBufPtr, 1);
    rd_put_i16(pre, "msLogPeriodog", (Word16 *)&p->msLogPeriodog, 62);
    rd_put_i16(pre, "msLogNoiseEst", (Word16 *)&p->msLogNoiseEst, 62);
}
static void rd_fill_FdCngDec(FD_CNG_DEC *p)
{
    if (p->hFdCngCom != NULL) rd_fill_FdCngCom(p->hFdCngCom);
    rd_fill_i16((Word16 *)&p->olapBufferAna, 320);
    rd_fill_i16((Word16 *)&p->olapBufferSynth2, 640);
    rd_fill_i32((Word32 *)&p->msPeriodog, 62);
    rd_fill_i16((Word16 *)&p->msPeriodog_exp, 1);
    rd_fill_i16((Word16 *)&p->msPeriodog_exp_fft, 1);
    rd_fill_i16((Word16 *)&p->msPeriodog_exp_cldfb, 1);
    rd_fill_i32((Word32 *)&p->msBminWin, 62);
    rd_fill_i32((Word32 *)&p->msBminSubWin, 62);
    rd_fill_i16((Word16 *)&p->msPsd, 62);
    rd_fill_i16((Word16 *)&p->msPsd_exp_fft, 1);
    rd_fill_i32((Word32 *)&p->msAlpha, 62);
    rd_fill_i32((Word32 *)&p->msMinBuf, 372);
    rd_fill_i32((Word32 *)&p->msCurrentMinOut, 62);
    rd_fill_i32((Word32 *)&p->msCurrentMin, 62);
    rd_fill_i32((Word32 *)&p->msCurrentMinSubWindow, 62);
    rd_fill_i16((Word16 *)&p->msLocalMinFlag, 62);
    rd_fill_i16((Word16 *)&p->msNewMinFlag, 62);
    rd_fill_i16((Word16 *)&p->msPsdFirstMoment, 62);
    rd_fill_i32((Word32 *)&p->msPsdSecondMoment, 62);
    rd_fill_i16((Word16 *)&p->msNoiseFloor, 62);
    rd_fill_i32((Word32 *)&p->msNoiseEst, 62);
    rd_fill_i16((Word16 *)&p->msNoiseEst_exp, 1);
    rd_fill_i16((Word16 *)&p->npart_shaping, 1);
    rd_fill_i16((Word16 *)&p->nFFTpart_shaping, 1);
    rd_fill_i16((Word16 *)&p->part_shaping, 62);
    rd_fill_i16((Word16 *)&p->midband_shaping, 62);
    rd_fill_i16((Word16 *)&p->psize_shaping, 62);
    rd_fill_i16((Word16 *)&p->psize_shaping_norm, 62);
    rd_fill_i16((Word16 *)&p->psize_shaping_norm_exp, 1);
    rd_fill_i16((Word16 *)&p->psize_inv_shaping, 62);
    rd_fill_i32((Word32 *)&p->bandNoiseShape, 320);
    rd_fill_i16((Word16 *)&p->bandNoiseShape_exp, 1);
    rd_fill_i32((Word32 *)&p->partNoiseShape, 24);
    rd_fill_i16((Word16 *)&p->partNoiseShape_exp, 1);
    rd_fill_i16((Word16 *)&p->flag_dtx_mode, 1);
    rd_fill_i32((Word32 *)&p->lp_speech, 1);
    rd_fill_i32((Word32 *)&p->lp_noise, 1);
    rd_fill_i16((Word16 *)&p->msPeriodogBuf, 310);
    rd_fill_i16((Word16 *)&p->msPeriodogBufPtr, 1);
    rd_fill_i16((Word16 *)&p->msLogPeriodog, 62);
    rd_fill_i16((Word16 *)&p->msLogNoiseEst, 62);
}
static void rd_dump_AcelpConfig(const char *pre, ACELP_config *p)
{
    rd_put_i16(pre, "mode_index", (Word16 *)&p->mode_index, 1);
    rd_put_i8(pre, "midLpc", (signed char *)&p->midLpc, 1);
    rd_put_i8(pre, "midLpc_enable", (signed char *)&p->midLpc_enable, 1);
    rd_put_i8(pre, "pre_emphasis", (signed char *)&p->pre_emphasis, 1);
    rd_put_i8(pre, "pitch_sharpening", (signed char *)&p->pitch_sharpening, 1);
    rd_put_i8(pre, "phase_scrambling", (signed char *)&p->phase_scrambling, 1);
    rd_put_i16(pre, "formant_enh", (Word16 *)&p->formant_enh, 1);
    rd_put_i8(pre, "formant_tilt", (signed char *)&p->formant_tilt, 1);
    rd_put_i8(pre, "voice_tilt", (signed char *)&p->voice_tilt, 1);
    rd_put_i16(pre, "formant_enh_num", (Word16 *)&p->formant_enh_num, 1);
    rd_put_i16(pre, "formant_enh_den", (Word16 *)&p->formant_enh_den, 1);
    rd_put_i16(pre, "bpf_mode", (Word16 *)&p->bpf_mode, 1);
    rd_put_i16(pre, "nrg_mode", (Word16 *)&p->nrg_mode, 1);
    rd_put_i16(pre, "nrg_bits", (Word16 *)&p->nrg_bits, 1);
    rd_put_i16(pre, "ltp_mode", (Word16 *)&p->ltp_mode, 1);
    rd_put_i16(pre, "ltp_bits", (Word16 *)&p->ltp_bits, 1);
    rd_put_i16(pre, "ltf_mode", (Word16 *)&p->ltf_mode, 1);
    rd_put_i16(pre, "ltf_bits", (Word16 *)&p->ltf_bits, 1);
    rd_put_i16(pre, "gains_mode", (Word16 *)&p->gains_mode, 5);
    rd_put_i16(pre, "fixed_cdk_index", (Word16 *)&p->fixed_cdk_index, 5);
}
static void rd_fill_AcelpConfig(ACELP_config *p)
{
    rd_fill_i16((Word16 *)&p->mode_index, 1);
    rd_fill_i8((signed char *)&p->midLpc, 1);
    rd_fill_i8((signed char *)&p->midLpc_enable, 1);
    rd_fill_i8((signed char *)&p->pre_emphasis, 1);
    rd_fill_i8((signed char *)&p->pitch_sharpening, 1);
    rd_fill_i8((signed char *)&p->phase_scrambling, 1);
    rd_fill_i16((Word16 *)&p->formant_enh, 1);
    rd_fill_i8((signed char *)&p->formant_tilt, 1);
    rd_fill_i8((signed char *)&p->voice_tilt, 1);
    rd_fill_i16((Word16 *)&p->formant_enh_num, 1);
    rd_fill_i16((Word16 *)&p->formant_enh_den, 1);
    rd_fill_i16((Word16 *)&p->bpf_mode, 1);
    rd_fill_i16((Word16 *)&p->nrg_mode, 1);
    rd_fill_i16((Word16 *)&p->nrg_bits, 1);
    rd_fill_i16((Word16 *)&p->ltp_mode, 1);
    rd_fill_i16((Word16 *)&p->ltp_bits, 1);
    rd_fill_i16((Word16 *)&p->ltf_mode, 1);
    rd_fill_i16((Word16 *)&p->ltf_bits, 1);
    rd_fill_i16((Word16 *)&p->gains_mode, 5);
    rd_fill_i16((Word16 *)&p->fixed_cdk_index, 5);
}
static void rd_dump_STnsConfig(const char *pre, STnsConfig *p)
{
    rd_put_i16(pre, "maxOrder", (Word16 *)&p->maxOrder, 1);
    rd_put_i16(pre, "nMaxFilters", (Word16 *)&p->nMaxFilters, 1);
    rd_put1(pre, "pTnsParameters", rd_tns_table_id(p->pTnsParameters));
    rd_put_i16(pre, "iFilterBorders", (Word16 *)&p->iFilterBorders, 3);
}
static void rd_fill_STnsConfig(STnsConfig *p)
{
    rd_fill_i16((Word16 *)&p->maxOrder, 1);
    rd_fill_i16((Word16 *)&p->nMaxFilters, 1);
    rd_fill_i16((Word16 *)&p->iFilterBorders, 3);
}
static void rd_dump_TcxConfig(const char *pre, TCX_config *p)
{
    rd_put_romp16(pre, "tcx_mdct_window", (const PWord16 *)p->tcx_mdct_window);
    rd_put_romp16(pre, "tcx_mdct_window_half", (const PWord16 *)p->tcx_mdct_window_half);
    rd_put_romp16(pre, "tcx_mdct_window_minimum", (const PWord16 *)p->tcx_mdct_window_minimum);
    rd_put_romp16(pre, "tcx_mdct_window_trans", (const PWord16 *)p->tcx_mdct_window_trans);
    rd_put_i16(pre, "tcx_aldo_window_1", (Word16 *)&p->tcx_aldo_window_1, 180);
    rd_put_i16(pre, "tcx_aldo_window_1_trunc", (Word16 *)&p->tcx_aldo_window_1_trunc, 280);
    rd_put_i16(pre, "tcx_aldo_window_2", (Word16 *)&p->tcx_aldo_window_2, 280);
    rd_put_i16(pre, "last_aldo", (Word16 *)&p->last_aldo, 1);
    rd_put_i16(pre, "tcx5Size", (Word16 *)&p->tcx5Size, 1);
    rd_put_i16(pre, "tcx_mdct_window_length", (Word16 *)&p->tcx_mdct_window_length, 1);
    rd_put_i16(pre, "tcx_mdct_window_half_length", (Word16 *)&p->tcx_mdct_window_half_length, 1);
    rd_put_i16(pre, "tcx_mdct_window_min_length", (Word16 *)&p->tcx_mdct_window_min_length, 1);
    rd_put_i16(pre, "tcx_mdct_window_trans_length", (Word16 *)&p->tcx_mdct_window_trans_length, 1);
    rd_put_i16(pre, "tcx_mdct_window_delay", (Word16 *)&p->tcx_mdct_window_delay, 1);
    rd_put_i16(pre, "tcx_offset", (Word16 *)&p->tcx_offset, 1);
    rd_put_i16(pre, "tcx_mdct_window_length_old", (Word16 *)&p->tcx_mdct_window_length_old, 1);
    rd_put_romp16(pre, "tcx_mdct_windowFB", (const PWord16 *)p->tcx_mdct_windowFB);
    rd_put_romp16(pre, "tcx_mdct_window_halfFB", (const PWord16 *)p->tcx_mdct_window_halfFB);
    rd_put_romp16(pre, "tcx_mdct_window_minimumFB", (const PWord16 *)p->tcx_mdct_window_minimumFB);
    rd_put_romp16(pre, "tcx_mdct_window_transFB", (const PWord16 *)p->tcx_mdct_window_transFB);
    rd_put_i16(pre, "tcx_aldo_window_1_FB", (Word16 *)&p->tcx_aldo_window_1_FB, 270);
    rd_put_i16(pre, "tcx_aldo_window_1_FB_trunc", (Word16 *)&p->tcx_aldo_window_1_FB_trunc, 420);
    rd_put_i16(pre, "tcx_aldo_window_2_FB", (Word16 *)&p->tcx_aldo_window_2_FB, 420);
    rd_put_i16(pre, "tcx5SizeFB", (Word16 *)&p->tcx5SizeFB, 1);
    rd_put_i16(pre, "tcx_mdct_window_lengthFB", (Word16 *)&p->tcx_mdct_window_lengthFB, 1);
    rd_put_i16(pre, "tcx_mdct_window_half_lengthFB", (Word16 *)&p->tcx_mdct_window_half_lengthFB, 1);
    rd_put_i16(pre, "tcx_mdct_window_min_lengthFB", (Word16 *)&p->tcx_mdct_window_min_lengthFB, 1);
    rd_put_i16(pre, "tcx_mdct_window_trans_lengthFB", (Word16 *)&p->tcx_mdct_window_trans_lengthFB, 1);
    rd_put_i16(pre, "tcx_mdct_window_delayFB", (Word16 *)&p->tcx_mdct_window_delayFB, 1);
    rd_put_i16(pre, "tcx_offsetFB", (Word16 *)&p->tcx_offsetFB, 1);
    rd_put_i16(pre, "tcx_coded_lines", (Word16 *)&p->tcx_coded_lines, 1);
    rd_put_i16(pre, "tcx_curr_overlap_mode", (Word16 *)&p->tcx_curr_overlap_mode, 1);
    rd_put_i16(pre, "tcx_last_overlap_mode", (Word16 *)&p->tcx_last_overlap_mode, 1);
    rd_put_i16(pre, "lfacNext", (Word16 *)&p->lfacNext, 1);
    rd_put_i16(pre, "lfacNextFB", (Word16 *)&p->lfacNextFB, 1);
    rd_put_i8(pre, "fIsTNSAllowed", (signed char *)&p->fIsTNSAllowed, 1);
    for (int i0 = 0; i0 < 2; i0++) for (int i1 = 0; i1 < 2; i1++) { char b[256]; snprintf(b, sizeof b, "%stnsConfig[%d][%d].", pre, i0, i1); rd_dump_STnsConfig(b, &p->tnsConfig[i0][i1]); }
    rd_put1(pre, "pCurrentTnsConfig", p->pCurrentTnsConfig == NULL ? -1 : (long long)(p->pCurrentTnsConfig - &p->tnsConfig[0][0]));
    rd_put_i16(pre, "sq_rounding", (Word16 *)&p->sq_rounding, 1);
    rd_put_i8(pre, "tcxRateLoopOpt", (signed char *)&p->tcxRateLoopOpt, 1);
    rd_put_i16(pre, "preemph_fac", (Word16 *)&p->preemph_fac, 1);
    rd_put_i16(pre, "bandwidth", (Word16 *)&p->bandwidth, 1);
    rd_put_i8(pre, "ctx_hm", (signed char *)&p->ctx_hm, 1);
    rd_put_i8(pre, "resq", (signed char *)&p->resq, 1);
    rd_put_i16(pre, "coder_type", (Word16 *)&p->coder_type, 1);
    rd_put_i16(pre, "na_scale", (Word16 *)&p->na_scale, 1);
    rd_put_i32(pre, "SFM2", (Word32 *)&p->SFM2, 1);
}
static void rd_fill_TcxConfig(TCX_config *p)
{
    rd_fill_i16((Word16 *)&p->tcx_aldo_window_1, 180);
    rd_fill_i16((Word16 *)&p->tcx_aldo_window_1_trunc, 280);
    rd_fill_i16((Word16 *)&p->tcx_aldo_window_2, 280);
    rd_fill_i16((Word16 *)&p->last_aldo, 1);
    rd_fill_i16((Word16 *)&p->tcx5Size, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_length, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_half_length, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_min_length, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_trans_length, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_delay, 1);
    rd_fill_i16((Word16 *)&p->tcx_offset, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_length_old, 1);
    rd_fill_i16((Word16 *)&p->tcx_aldo_window_1_FB, 270);
    rd_fill_i16((Word16 *)&p->tcx_aldo_window_1_FB_trunc, 420);
    rd_fill_i16((Word16 *)&p->tcx_aldo_window_2_FB, 420);
    rd_fill_i16((Word16 *)&p->tcx5SizeFB, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_lengthFB, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_half_lengthFB, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_min_lengthFB, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_trans_lengthFB, 1);
    rd_fill_i16((Word16 *)&p->tcx_mdct_window_delayFB, 1);
    rd_fill_i16((Word16 *)&p->tcx_offsetFB, 1);
    rd_fill_i16((Word16 *)&p->tcx_coded_lines, 1);
    rd_fill_i16((Word16 *)&p->tcx_curr_overlap_mode, 1);
    rd_fill_i16((Word16 *)&p->tcx_last_overlap_mode, 1);
    rd_fill_i16((Word16 *)&p->lfacNext, 1);
    rd_fill_i16((Word16 *)&p->lfacNextFB, 1);
    rd_fill_i8((signed char *)&p->fIsTNSAllowed, 1);
    for (int i0 = 0; i0 < 2; i0++) for (int i1 = 0; i1 < 2; i1++) { rd_fill_STnsConfig(&p->tnsConfig[i0][i1]); }
    rd_fill_i16((Word16 *)&p->sq_rounding, 1);
    rd_fill_i8((signed char *)&p->tcxRateLoopOpt, 1);
    rd_fill_i16((Word16 *)&p->preemph_fac, 1);
    rd_fill_i16((Word16 *)&p->bandwidth, 1);
    rd_fill_i8((signed char *)&p->ctx_hm, 1);
    rd_fill_i8((signed char *)&p->resq, 1);
    rd_fill_i16((Word16 *)&p->coder_type, 1);
    rd_fill_i16((Word16 *)&p->na_scale, 1);
    rd_fill_i32((Word32 *)&p->SFM2, 1);
}
static void rd_dump_Pfstat(const char *pre, PFSTAT *p)
{
    rd_put_i16(pre, "on", (Word16 *)&p->on, 1);
    rd_put_i16(pre, "reset", (Word16 *)&p->reset, 1);
    rd_put_i16(pre, "mem_pf_in", (Word16 *)&p->mem_pf_in, 64);
    rd_put_i16(pre, "mem_stp", (Word16 *)&p->mem_stp, 64);
    rd_put_i16(pre, "mem_res2", (Word16 *)&p->mem_res2, 299);
    rd_put_i16(pre, "mem_zero", (Word16 *)&p->mem_zero, 16);
    rd_put_i16(pre, "gain_prec", (Word16 *)&p->gain_prec, 1);
}
static void rd_fill_Pfstat(PFSTAT *p)
{
    rd_fill_i16((Word16 *)&p->on, 1);
    rd_fill_i16((Word16 *)&p->reset, 1);
    rd_fill_i16((Word16 *)&p->mem_pf_in, 64);
    rd_fill_i16((Word16 *)&p->mem_stp, 64);
    rd_fill_i16((Word16 *)&p->mem_res2, 299);
    rd_fill_i16((Word16 *)&p->mem_zero, 16);
    rd_fill_i16((Word16 *)&p->gain_prec, 1);
}
static void rd_dump_BlockData(const char *pre, blockData *p)
{
    rd_put_i16(pre, "nSamples", (Word16 *)&p->nSamples, 1);
    rd_put_i16(pre, "nSamplesCore", (Word16 *)&p->nSamplesCore, 1);
    rd_put1(pre, "spectralData", rd_row((const Word16 *)p->spectralData, (const Word16 *)rd_parent_tonal->spectralDataBuffers[0], (const Word16 *)rd_parent_tonal->spectralDataBuffers[1]));
    rd_put_i16(pre, "spectralData_exp", (Word16 *)&p->spectralData_exp, 1);
    rd_put1(pre, "scaleFactors", rd_row((const Word16 *)p->scaleFactors, (const Word16 *)rd_parent_tonal->scaleFactorsBuffers[0], (const Word16 *)rd_parent_tonal->scaleFactorsBuffers[1]));
    rd_put1(pre, "scaleFactors_exp", rd_row((const Word16 *)p->scaleFactors_exp, (const Word16 *)rd_parent_tonal->scaleFactorsBuffers_exp[0], (const Word16 *)rd_parent_tonal->scaleFactorsBuffers_exp[1]));
    rd_put_i16(pre, "scaleFactors_max_e", (Word16 *)&p->scaleFactors_max_e, 1);
    rd_put_i16(pre, "gain_tcx_exp", (Word16 *)&p->gain_tcx_exp, 1);
    rd_put_i8(pre, "blockIsValid", (signed char *)&p->blockIsValid, 1);
    rd_put_i16(pre, "blockIsConcealed", (Word16 *)&p->blockIsConcealed, 1);
    rd_put_i8(pre, "tonalConcealmentActive", (signed char *)&p->tonalConcealmentActive, 1);
}
static void rd_fill_BlockData(blockData *p)
{
    rd_fill_i16((Word16 *)&p->nSamples, 1);
    rd_fill_i16((Word16 *)&p->nSamplesCore, 1);
    rd_fill_i16((Word16 *)&p->spectralData_exp, 1);
    rd_fill_i16((Word16 *)&p->scaleFactors_max_e, 1);
    rd_fill_i16((Word16 *)&p->gain_tcx_exp, 1);
    rd_fill_i8((signed char *)&p->blockIsValid, 1);
    rd_fill_i16((Word16 *)&p->blockIsConcealed, 1);
    rd_fill_i8((signed char *)&p->tonalConcealmentActive, 1);
}
static void rd_dump_TonalComponentsInfo(const char *pre, TonalComponentsInfo *p)
{
    rd_put_i16(pre, "numIndexes", (Word16 *)&p->numIndexes, 1);
    rd_put_i16(pre, "indexOfTonalPeak", (Word16 *)&p->indexOfTonalPeak, 30);
    rd_put_i16(pre, "lowerIndex", (Word16 *)&p->lowerIndex, 30);
    rd_put_i16(pre, "upperIndex", (Word16 *)&p->upperIndex, 30);
    rd_put_i16(pre, "phaseDiff", (Word16 *)&p->phaseDiff, 30);
    rd_put_i16(pre, "phase_currentFramePredicted", (Word16 *)&p->phase_currentFramePredicted, 210);
}
static void rd_fill_TonalComponentsInfo(TonalComponentsInfo *p)
{
    rd_fill_i16((Word16 *)&p->numIndexes, 1);
    rd_fill_i16((Word16 *)&p->indexOfTonalPeak, 30);
    rd_fill_i16((Word16 *)&p->lowerIndex, 30);
    rd_fill_i16((Word16 *)&p->upperIndex, 30);
    rd_fill_i16((Word16 *)&p->phaseDiff, 30);
    rd_fill_i16((Word16 *)&p->phase_currentFramePredicted, 210);
}
static void rd_dump_Tonalmdctconceal(const char *pre, struct tonalmdctconceal *p)
{
    rd_put1(pre, "pMDSTData", p->pMDSTData == NULL ? -1 : -2);
    rd_put_i16(pre, "nSamples", (Word16 *)&p->nSamples, 1);
    rd_put_i16(pre, "nSamplesCore", (Word16 *)&p->nSamplesCore, 1);
    rd_put_i16(pre, "nNonZeroSamples", (Word16 *)&p->nNonZeroSamples, 1);
    rd_put_i16(pre, "nScaleFactors", (Word16 *)&p->nScaleFactors, 1);
    rd_put_i32(pre, "lastPitchLag", (Word32 *)&p->lastPitchLag, 1);
    { char b[256]; snprintf(b, sizeof b, "%slastBlockData.", pre); rd_parent_tonal = p; rd_dump_BlockData(b, &p->lastBlockData); }
    { char b[256]; snprintf(b, sizeof b, "%ssecondLastBlockData.", pre); rd_parent_tonal = p; rd_dump_BlockData(b, &p->secondLastBlockData); }
    rd_put_i16(pre, "scaleFactorsBuffers", (Word16 *)&p->scaleFactorsBuffers, 128);
    rd_put_i16(pre, "scaleFactorsBuffers_exp", (Word16 *)&p->scaleFactorsBuffers_exp, 128);
    rd_put_i16(pre, "spectralDataBuffers", (Word16 *)&p->spectralDataBuffers, 1920);
    rd_put_i16(pre, "timeDataBuffer", (Word16 *)&p->timeDataBuffer, 1440);
    rd_put1(pre, "lastPcmOut", p->lastPcmOut == NULL ? -1 : (long long)(p->lastPcmOut - p->timeDataBuffer));
    rd_put1(pre, "secondLastPcmOut", p->secondLastPcmOut == NULL ? -1 : (long long)(p->secondLastPcmOut - p->timeDataBuffer));
    rd_put1(pre, "secondLastPowerSpectrum", rd_row((const Word16 *)p->secondLastPowerSpectrum, (const Word16 *)p->spectralDataBuffers[0], (const Word16 *)p->spectralDataBuffers[1]));
    rd_put_i16(pre, "secondLastPowerSpectrum_exp", (Word16 *)&p->secondLastPowerSpectrum_exp, 1);
    rd_put_i16(pre, "nFramesLost", (Word16 *)&p->nFramesLost, 1);
}
static void rd_fill_Tonalmdctconceal(struct tonalmdctconceal *p)
{
    rd_fill_i16((Word16 *)&p->nSamples, 1);
    rd_fill_i16((Word16 *)&p->nSamplesCore, 1);
    rd_fill_i16((Word16 *)&p->nNonZeroSamples, 1);
    rd_fill_i16((Word16 *)&p->nScaleFactors, 1);
    rd_fill_i32((Word32 *)&p->lastPitchLag, 1);
    { rd_fill_BlockData(&p->lastBlockData); }
    { rd_fill_BlockData(&p->secondLastBlockData); }
    rd_fill_i16((Word16 *)&p->scaleFactorsBuffers, 128);
    rd_fill_i16((Word16 *)&p->scaleFactorsBuffers_exp, 128);
    rd_fill_i16((Word16 *)&p->spectralDataBuffers, 1920);
    rd_fill_i16((Word16 *)&p->timeDataBuffer, 1440);
    rd_fill_i16((Word16 *)&p->secondLastPowerSpectrum_exp, 1);
    rd_fill_i16((Word16 *)&p->nFramesLost, 1);
}
static void rd_dump_TPLCInfo(const char *pre, T_PLCInfo *p)
{
    rd_put_i16(pre, "FrameSize", (Word16 *)&p->FrameSize, 1);
    rd_put_i16(pre, "Pitch_fx", (Word16 *)&p->Pitch_fx, 1);
    rd_put_i8(pre, "T_bfi_fx", (signed char *)&p->T_bfi_fx, 1);
    rd_put_i16(pre, "Transient", (Word16 *)&p->Transient, 3);
    rd_put_i16(pre, "TCX_Tonality", (Word16 *)&p->TCX_Tonality, 10);
    rd_put_i16(pre, "outx_new_n1_fx", (Word16 *)&p->outx_new_n1_fx, 1);
    rd_put_i16(pre, "nsapp_gain_fx", (Word16 *)&p->nsapp_gain_fx, 1);
    rd_put_i16(pre, "nsapp_gain_n_fx", (Word16 *)&p->nsapp_gain_n_fx, 1);
    rd_put_i32(pre, "data_reci2_fx", (Word32 *)&p->data_reci2_fx, 960);
    rd_put_i16(pre, "data_reci2_scale", (Word16 *)&p->data_reci2_scale, 1);
    rd_put_i16(pre, "data_noise", (Word16 *)&p->data_noise, 960);
    rd_put_i32(pre, "ener_mean_fx", (Word32 *)&p->ener_mean_fx, 1);
    rd_put_i32(pre, "ener_fx", (Word32 *)&p->ener_fx, 1);
    rd_put_i16(pre, "zp_fx", (Word16 *)&p->zp_fx, 1);
    rd_put_i16(pre, "recovery_gain", (Word16 *)&p->recovery_gain, 1);
    rd_put_i16(pre, "step_concealgain_fx", (Word16 *)&p->step_concealgain_fx, 1);
    rd_put_i16(pre, "concealment_method", (Word16 *)&p->concealment_method, 1);
    rd_put_i16(pre, "subframe_fx", (Word16 *)&p->subframe_fx, 1);
    rd_put_i32(pre, "nbLostCmpt", (Word32 *)&p->nbLostCmpt, 1);
    rd_put_i16(pre, "seed", (Word16 *)&p->seed, 1);
}
static void rd_fill_TPLCInfo(T_PLCInfo *p)
{
    rd_fill_i16((Word16 *)&p->FrameSize, 1);
    rd_fill_i16((Word16 *)&p->Pitch_fx, 1);
    rd_fill_i8((signed char *)&p->T_bfi_fx, 1);
    rd_fill_i16((Word16 *)&p->Transient, 3);
    rd_fill_i16((Word16 *)&p->TCX_Tonality, 10);
    rd_fill_i16((Word16 *)&p->outx_new_n1_fx, 1);
    rd_fill_i16((Word16 *)&p->nsapp_gain_fx, 1);
    rd_fill_i16((Word16 *)&p->nsapp_gain_n_fx, 1);
    rd_fill_i32((Word32 *)&p->data_reci2_fx, 960);
    rd_fill_i16((Word16 *)&p->data_reci2_scale, 1);
    rd_fill_i16((Word16 *)&p->data_noise, 960);
    rd_fill_i32((Word32 *)&p->ener_mean_fx, 1);
    rd_fill_i32((Word32 *)&p->ener_fx, 1);
    rd_fill_i16((Word16 *)&p->zp_fx, 1);
    rd_fill_i16((Word16 *)&p->recovery_gain, 1);
    rd_fill_i16((Word16 *)&p->step_concealgain_fx, 1);
    rd_fill_i16((Word16 *)&p->concealment_method, 1);
    rd_fill_i16((Word16 *)&p->subframe_fx, 1);
    rd_fill_i32((Word32 *)&p->nbLostCmpt, 1);
    rd_fill_i16((Word16 *)&p->seed, 1);
}
static void rd_dump_IgfGrid(const char *pre, IGF_GRID *p)
{
    rd_put_i16(pre, "swb_offset", (Word16 *)&p->swb_offset, 23);
    rd_put_i16(pre, "swb_offset_len", (Word16 *)&p->swb_offset_len, 1);
    rd_put_i16(pre, "startFrequency", (Word16 *)&p->startFrequency, 1);
    rd_put_i16(pre, "stopFrequency", (Word16 *)&p->stopFrequency, 1);
    rd_put_i16(pre, "startLine", (Word16 *)&p->startLine, 1);
    rd_put_i16(pre, "stopLine", (Word16 *)&p->stopLine, 1);
    rd_put_i16(pre, "startSfb", (Word16 *)&p->startSfb, 1);
    rd_put_i16(pre, "stopSfb", (Word16 *)&p->stopSfb, 1);
    rd_put_i16(pre, "sfbWrap", (Word16 *)&p->sfbWrap, 6);
    rd_put_i16(pre, "sbWrap", (Word16 *)&p->sbWrap, 5);
    rd_put_i16(pre, "nTiles", (Word16 *)&p->nTiles, 1);
    rd_put_i16(pre, "minSrcSubband", (Word16 *)&p->minSrcSubband, 1);
    rd_put_i16(pre, "minSrcFrequency", (Word16 *)&p->minSrcFrequency, 1);
    rd_put_i16(pre, "tile", (Word16 *)&p->tile, 5);
    rd_put_i16(pre, "infoIsRefined", (Word16 *)&p->infoIsRefined, 1);
    rd_put_i16(pre, "infoGranuleLen", (Word16 *)&p->infoGranuleLen, 1);
    rd_put_i16(pre, "infoTransFac", (Word16 *)&p->infoTransFac, 1);
    rd_put_i16(pre, "whiteningThreshold", (Word16 *)&p->whiteningThreshold, 10);
    rd_put_i16(pre, "gFactor", (Word16 *)&p->gFactor, 1);
    rd_put_i16(pre, "fFactor", (Word16 *)&p->fFactor, 1);
    rd_put_i16(pre, "lFactor", (Word16 *)&p->lFactor, 1);
}
static void rd_fill_IgfGrid(IGF_GRID *p)
{
    rd_fill_i16((Word16 *)&p->swb_offset, 23);
    rd_fill_i16((Word16 *)&p->swb_offset_len, 1);
    rd_fill_i16((Word16 *)&p->startFrequency, 1);
    rd_fill_i16((Word16 *)&p->stopFrequency, 1);
    rd_fill_i16((Word16 *)&p->startLine, 1);
    rd_fill_i16((Word16 *)&p->stopLine, 1);
    rd_fill_i16((Word16 *)&p->startSfb, 1);
    rd_fill_i16((Word16 *)&p->stopSfb, 1);
    rd_fill_i16((Word16 *)&p->sfbWrap, 6);
    rd_fill_i16((Word16 *)&p->sbWrap, 5);
    rd_fill_i16((Word16 *)&p->nTiles, 1);
    rd_fill_i16((Word16 *)&p->minSrcSubband, 1);
    rd_fill_i16((Word16 *)&p->minSrcFrequency, 1);
    rd_fill_i16((Word16 *)&p->tile, 5);
    rd_fill_i16((Word16 *)&p->infoIsRefined, 1);
    rd_fill_i16((Word16 *)&p->infoGranuleLen, 1);
    rd_fill_i16((Word16 *)&p->infoTransFac, 1);
    rd_fill_i16((Word16 *)&p->whiteningThreshold, 10);
    rd_fill_i16((Word16 *)&p->gFactor, 1);
    rd_fill_i16((Word16 *)&p->fFactor, 1);
    rd_fill_i16((Word16 *)&p->lFactor, 1);
}
static void rd_dump_IgfInfo(const char *pre, IGF_INFO *p)
{
    rd_put_i16(pre, "nfSeed", (Word16 *)&p->nfSeed, 1);
    rd_put_i32(pre, "sampleRate", (Word32 *)&p->sampleRate, 1);
    rd_put_i16(pre, "frameLength", (Word16 *)&p->frameLength, 1);
    rd_put_i16(pre, "maxHopsize", (Word16 *)&p->maxHopsize, 1);
    for (int i0 = 0; i0 < 3; i0++) { char b[256]; snprintf(b, sizeof b, "%sgrid[%d].", pre, i0); rd_dump_IgfGrid(b, &p->grid[i0]); }
    rd_put_i16(pre, "bitRateIndex", (Word16 *)&p->bitRateIndex, 1);
}
static void rd_fill_IgfInfo(IGF_INFO *p)
{
    rd_fill_i16((Word16 *)&p->nfSeed, 1);
    rd_fill_i32((Word32 *)&p->sampleRate, 1);
    rd_fill_i16((Word16 *)&p->frameLength, 1);
    rd_fill_i16((Word16 *)&p->maxHopsize, 1);
    for (int i0 = 0; i0 < 3; i0++) { rd_fill_IgfGrid(&p->grid[i0]); }
    rd_fill_i16((Word16 *)&p->bitRateIndex, 1);
}
static void rd_dump_TastatDec(const char *pre, TastatDec *p)
{
    rd_put_i32(pre, "low", (Word32 *)&p->low, 1);
    rd_put_i32(pre, "high", (Word32 *)&p->high, 1);
    rd_put_i32(pre, "vobf", (Word32 *)&p->vobf, 1);
}
static void rd_fill_TastatDec(TastatDec *p)
{
    rd_fill_i32((Word32 *)&p->low, 1);
    rd_fill_i32((Word32 *)&p->high, 1);
    rd_fill_i32((Word32 *)&p->vobf, 1);
}
static void rd_dump_IgfscfdecInstance(const char *pre, IGFSCFDEC_INSTANCE *p)
{
    rd_put_i16(pre, "bitsRead", (Word16 *)&p->bitsRead, 1);
    rd_put_i16(pre, "prev", (Word16 *)&p->prev, 64);
    rd_put_i16(pre, "scfCountLongBlock", (Word16 *)&p->scfCountLongBlock, 1);
    rd_put_i16(pre, "t", (Word16 *)&p->t, 1);
    rd_put_rom16(pre, "cf_se00", (const Word16 *)p->cf_se00);
    rd_put_rom16(pre, "cf_se01", (const Word16 *)p->cf_se01);
    rd_put_i16(pre, "cf_off_se01", (Word16 *)&p->cf_off_se01, 1);
    rd_put_rom16(pre, "cf_se02", (const Word16 *)p->cf_se02);
    rd_put_rom16(pre, "cf_off_se02", (const Word16 *)p->cf_off_se02);
    rd_put_rom16(pre, "cf_se10", (const Word16 *)p->cf_se10);
    rd_put_i16(pre, "cf_off_se10", (Word16 *)&p->cf_off_se10, 1);
    rd_put_rom16(pre, "cf_se11", (const Word16 *)p->cf_se11);
    rd_put_rom16(pre, "cf_off_se11", (const Word16 *)p->cf_off_se11);
    { char b[256]; snprintf(b, sizeof b, "%sacState.", pre); rd_dump_TastatDec(b, &p->acState); }
}
static void rd_fill_IgfscfdecInstance(IGFSCFDEC_INSTANCE *p)
{
    rd_fill_i16((Word16 *)&p->bitsRead, 1);
    rd_fill_i16((Word16 *)&p->prev, 64);
    rd_fill_i16((Word16 *)&p->scfCountLongBlock, 1);
    rd_fill_i16((Word16 *)&p->t, 1);
    rd_fill_i16((Word16 *)&p->cf_off_se01, 1);
    rd_fill_i16((Word16 *)&p->cf_off_se10, 1);
    { rd_fill_TastatDec(&p->acState); }
}
static void rd_dump_IgfdecPrivateData(const char *pre, IGFDEC_PRIVATE_DATA *p)
{
    { char b[256]; snprintf(b, sizeof b, "%sigfInfo.", pre); rd_dump_IgfInfo(b, &p->igfInfo); }
    rd_put_i32(pre, "igf_sN", (Word32 *)&p->igf_sN, 23);
    rd_put_i16(pre, "igf_sN_e", (Word16 *)&p->igf_sN_e, 23);
    rd_put_i32(pre, "igf_pN", (Word32 *)&p->igf_pN, 23);
    rd_put_i16(pre, "igf_pN_e", (Word16 *)&p->igf_pN_e, 23);
    rd_put_i16(pre, "igf_curr", (Word16 *)&p->igf_curr, 23);
    rd_put_i16(pre, "igf_prev", (Word16 *)&p->igf_prev, 23);
    rd_put_i16(pre, "igf_curr_subframe", (Word16 *)&p->igf_curr_subframe, 92);
    rd_put_i16(pre, "igf_prev_subframe", (Word16 *)&p->igf_prev_subframe, 46);
    rd_put_i16(pre, "igf_flatteningTrigger_subframe", (Word16 *)&p->igf_flatteningTrigger_subframe, 2);
    rd_put_i32(pre, "pSpecFlat", (Word32 *)&p->pSpecFlat, 800);
    rd_put_i16(pre, "pSpecFlat_exp", (Word16 *)&p->pSpecFlat_exp, 1);
    rd_put_i16(pre, "currWhiteningLevel", (Word16 *)&p->currWhiteningLevel, 5);
    rd_put_i16(pre, "prevWhiteningLevel", (Word16 *)&p->prevWhiteningLevel, 5);
    rd_put_i16(pre, "currWhiteningLevel_subframe", (Word16 *)&p->currWhiteningLevel_subframe, 10);
    rd_put_i16(pre, "prevWhiteningLevel_subframe", (Word16 *)&p->prevWhiteningLevel_subframe, 10);
    rd_put_i32(pre, "totalNoiseNrg", (Word32 *)&p->totalNoiseNrg, 1);
    rd_put_i16(pre, "n_noise_bands", (Word16 *)&p->n_noise_bands, 1);
    rd_put_i16(pre, "headroom_TCX_noise_white", (Word16 *)&p->headroom_TCX_noise_white, 1);
    rd_put_i16(pre, "headroom_TCX_noise", (Word16 *)&p->headroom_TCX_noise, 1);
    rd_put_i32(pre, "totalNoiseNrg_off", (Word32 *)&p->totalNoiseNrg_off, 1);
    rd_put_i16(pre, "n_noise_bands_off", (Word16 *)&p->n_noise_bands_off, 1);
    { char b[256]; snprintf(b, sizeof b, "%shArithSCFdec.", pre); rd_dump_IgfscfdecInstance(b, &p->hArithSCFdec); }
    rd_put_i16(pre, "frameLossCounter", (Word16 *)&p->frameLossCounter, 1);
}
static void rd_fill_IgfdecPrivateData(IGFDEC_PRIVATE_DATA *p)
{
    { rd_fill_IgfInfo(&p->igfInfo); }
    rd_fill_i32((Word32 *)&p->igf_sN, 23);
    rd_fill_i16((Word16 *)&p->igf_sN_e, 23);
    rd_fill_i32((Word32 *)&p->igf_pN, 23);
    rd_fill_i16((Word16 *)&p->igf_pN_e, 23);
    rd_fill_i16((Word16 *)&p->igf_curr, 23);
    rd_fill_i16((Word16 *)&p->igf_prev, 23);
    rd_fill_i16((Word16 *)&p->igf_curr_subframe, 92);
    rd_fill_i16((Word16 *)&p->igf_prev_subframe, 46);
    rd_fill_i16((Word16 *)&p->igf_flatteningTrigger_subframe, 2);
    rd_fill_i32((Word32 *)&p->pSpecFlat, 800);
    rd_fill_i16((Word16 *)&p->pSpecFlat_exp, 1);
    rd_fill_i16((Word16 *)&p->currWhiteningLevel, 5);
    rd_fill_i16((Word16 *)&p->prevWhiteningLevel, 5);
    rd_fill_i16((Word16 *)&p->currWhiteningLevel_subframe, 10);
    rd_fill_i16((Word16 *)&p->prevWhiteningLevel_subframe, 10);
    rd_fill_i32((Word32 *)&p->totalNoiseNrg, 1);
    rd_fill_i16((Word16 *)&p->n_noise_bands, 1);
    rd_fill_i16((Word16 *)&p->headroom_TCX_noise_white, 1);
    rd_fill_i16((Word16 *)&p->headroom_TCX_noise, 1);
    rd_fill_i32((Word32 *)&p->totalNoiseNrg_off, 1);
    rd_fill_i16((Word16 *)&p->n_noise_bands_off, 1);
    { rd_fill_IgfscfdecInstance(&p->hArithSCFdec); }
    rd_fill_i16((Word16 *)&p->frameLossCounter, 1);
}
static void rd_dump_IgfdecInstance(const char *pre, IGFDEC_INSTANCE *p)
{
    rd_put_i16(pre, "isIGFActive", (Word16 *)&p->isIGFActive, 1);
    rd_put_i16(pre, "infoIGFAllZero", (Word16 *)&p->infoIGFAllZero, 1);
    rd_put_i16(pre, "infoIGFStopLine", (Word16 *)&p->infoIGFStopLine, 1);
    rd_put_i16(pre, "infoIGFStartLine", (Word16 *)&p->infoIGFStartLine, 1);
    rd_put_i16(pre, "infoIGFStopFreq", (Word16 *)&p->infoIGFStopFreq, 1);
    rd_put_i16(pre, "infoIGFStartFreq", (Word16 *)&p->infoIGFStartFreq, 1);
    rd_put_i16(pre, "infoTCXNoise", (Word16 *)&p->infoTCXNoise, 800);
    rd_put_i16(pre, "flag_sparse", (Word16 *)&p->flag_sparse, 836);
    rd_put_i32(pre, "virtualSpec", (Word32 *)&p->virtualSpec, 836);
    rd_put_i16(pre, "virtualSpec_e", (Word16 *)&p->virtualSpec_e, 1);
    rd_put_i16(pre, "flatteningTrigger", (Word16 *)&p->flatteningTrigger, 1);
    { char b[256]; snprintf(b, sizeof b, "%sigfData.", pre); rd_dump_IgfdecPrivateData(b, &p->igfData); }
}
static void rd_fill_IgfdecInstance(IGFDEC_INSTANCE *p)
{
    rd_fill_i16((Word16 *)&p->isIGFActive, 1);
    rd_fill_i16((Word16 *)&p->infoIGFAllZero, 1);
    rd_fill_i16((Word16 *)&p->infoIGFStopLine, 1);
    rd_fill_i16((Word16 *)&p->infoIGFStartLine, 1);
    rd_fill_i16((Word16 *)&p->infoIGFStopFreq, 1);
    rd_fill_i16((Word16 *)&p->infoIGFStartFreq, 1);
    rd_fill_i16((Word16 *)&p->infoTCXNoise, 800);
    rd_fill_i16((Word16 *)&p->flag_sparse, 836);
    rd_fill_i32((Word32 *)&p->virtualSpec, 836);
    rd_fill_i16((Word16 *)&p->virtualSpec_e, 1);
    rd_fill_i16((Word16 *)&p->flatteningTrigger, 1);
    { rd_fill_IgfdecPrivateData(&p->igfData); }
}
static void rd_dump_CldfbScaleFactor(const char *pre, CLDFB_SCALE_FACTOR *p)
{
    rd_put_i16(pre, "lb_scale", (Word16 *)&p->lb_scale, 1);
    rd_put_i16(pre, "lb_scale16", (Word16 *)&p->lb_scale16, 1);
    rd_put_i16(pre, "ov_lb_scale", (Word16 *)&p->ov_lb_scale, 1);
    rd_put_i16(pre, "hb_scale", (Word16 *)&p->hb_scale, 1);
    rd_put_i16(pre, "ov_hb_scale", (Word16 *)&p->ov_hb_scale, 1);
}
static void rd_fill_CldfbScaleFactor(CLDFB_SCALE_FACTOR *p)
{
    rd_fill_i16((Word16 *)&p->lb_scale, 1);
    rd_fill_i16((Word16 *)&p->lb_scale16, 1);
    rd_fill_i16((Word16 *)&p->ov_lb_scale, 1);
    rd_fill_i16((Word16 *)&p->hb_scale, 1);
    rd_fill_i16((Word16 *)&p->ov_hb_scale, 1);
}
static void rd_dump_TemporalEnvelopeCodingDecoderFx(const char *pre, TEMPORAL_ENVELOPE_CODING_DECODER_FX *p)
{
    rd_put_i16(pre, "pGainTemp_m", (Word16 *)&p->pGainTemp_m, 16);
    rd_put_i16(pre, "pGainTemp_e", (Word16 *)&p->pGainTemp_e, 16);
    rd_put_i16(pre, "loBuffer", (Word16 *)&p->loBuffer, 22);
    rd_put_i16(pre, "cldfbExp", (Word16 *)&p->cldfbExp, 1);
    rd_put_i16(pre, "lastCldfbExp", (Word16 *)&p->lastCldfbExp, 1);
}
static void rd_fill_TemporalEnvelopeCodingDecoderFx(TEMPORAL_ENVELOPE_CODING_DECODER_FX *p)
{
    rd_fill_i16((Word16 *)&p->pGainTemp_m, 16);
    rd_fill_i16((Word16 *)&p->pGainTemp_e, 16);
    rd_fill_i16((Word16 *)&p->loBuffer, 22);
    rd_fill_i16((Word16 *)&p->cldfbExp, 1);
    rd_fill_i16((Word16 *)&p->lastCldfbExp, 1);
}
static void rd_dump_DecoderState(const char *pre, Decoder_State_fx *p)
{
    rd_put_i16(pre, "codec_mode", (Word16 *)&p->codec_mode, 1);
    rd_put_i16(pre, "mdct_sw_enable", (Word16 *)&p->mdct_sw_enable, 1);
    rd_put_i16(pre, "mdct_sw", (Word16 *)&p->mdct_sw, 1);
    rd_put_i16(pre, "last_codec_mode", (Word16 *)&p->last_codec_mode, 1);
    rd_put_i16(pre, "next_bit_pos_fx", (Word16 *)&p->next_bit_pos_fx, 1);
    rd_put_i16(pre, "bitstreamformat", (Word16 *)&p->bitstreamformat, 1);
    rd_put_i16(pre, "sdp_hf_only", (Word16 *)&p->sdp_hf_only, 1);
    rd_put_i16(pre, "amrwb_rfc4867_flag", (Word16 *)&p->amrwb_rfc4867_flag, 1);
    rd_put_i16(pre, "total_num_bits", (Word16 *)&p->total_num_bits, 1);
    rd_put_i16(pre, "BER_detect", (Word16 *)&p->BER_detect, 1);
    rd_put_i32(pre, "output_Fs_fx", (Word32 *)&p->output_Fs_fx, 1);
    rd_put_i16(pre, "output_frame_fx", (Word16 *)&p->output_frame_fx, 1);
    rd_put_i32(pre, "total_brate_fx", (Word32 *)&p->total_brate_fx, 1);
    rd_put_i32(pre, "last_total_brate_fx", (Word32 *)&p->last_total_brate_fx, 1);
    rd_put_i32(pre, "last_total_brate_ber_fx", (Word32 *)&p->last_total_brate_ber_fx, 1);
    rd_put_i16(pre, "core_fx", (Word16 *)&p->core_fx, 1);
    rd_put_i32(pre, "core_brate_fx", (Word32 *)&p->core_brate_fx, 1);
    rd_put_i32(pre, "last_core_brate_fx", (Word32 *)&p->last_core_brate_fx, 1);
    rd_put_i16(pre, "extl_fx", (Word16 *)&p->extl_fx, 1);
    rd_put_i16(pre, "last_extl_fx", (Word16 *)&p->last_extl_fx, 1);
    rd_put_i32(pre, "extl_brate_fx", (Word32 *)&p->extl_brate_fx, 1);
    rd_put_i16(pre, "L_frame_fx", (Word16 *)&p->L_frame_fx, 1);
    rd_put_i16(pre, "bwidth_fx", (Word16 *)&p->bwidth_fx, 1);
    rd_put_i16(pre, "Opt_AMR_WB_fx", (Word16 *)&p->Opt_AMR_WB_fx, 1);
    rd_put_i16(pre, "Opt_VOIP_fx", (Word16 *)&p->Opt_VOIP_fx, 1);
    rd_put_i16(pre, "ini_frame_fx", (Word16 *)&p->ini_frame_fx, 1);
    rd_put_i16(pre, "CNG_fx", (Word16 *)&p->CNG_fx, 1);
    rd_put_i16(pre, "prev_ft_speech_fx", (Word16 *)&p->prev_ft_speech_fx, 1);
    rd_put_i16(pre, "old_exc_fx", (Word16 *)&p->old_exc_fx, 480);
    rd_put_i16(pre, "old_excFB_fx", (Word16 *)&p->old_excFB_fx, 960);
    rd_put_i16(pre, "lsp_old_fx", (Word16 *)&p->lsp_old_fx, 16);
    rd_put_i16(pre, "lsf_old_fx", (Word16 *)&p->lsf_old_fx, 16);
    rd_put_i32(pre, "offset_scale1_fx", (Word32 *)&p->offset_scale1_fx, 516);
    rd_put_i32(pre, "offset_scale2_fx", (Word32 *)&p->offset_scale2_fx, 516);
    rd_put_i32(pre, "offset_scale1_p_fx", (Word32 *)&p->offset_scale1_p_fx, 584);
    rd_put_i32(pre, "offset_scale2_p_fx", (Word32 *)&p->offset_scale2_p_fx, 584);
    rd_put_i16(pre, "no_scales_fx", (Word16 *)&p->no_scales_fx, 256);
    rd_put_i16(pre, "no_scales_p_fx", (Word16 *)&p->no_scales_p_fx, 290);
    rd_put_i16(pre, "tilt_code_fx", (Word16 *)&p->tilt_code_fx, 1);
    rd_put_i16(pre, "mem_syn2_fx", (Word16 *)&p->mem_syn2_fx, 16);
    rd_put_i16(pre, "mem_syn1_fx", (Word16 *)&p->mem_syn1_fx, 16);
    rd_put_i16(pre, "mem_syn3_fx", (Word16 *)&p->mem_syn3_fx, 16);
    rd_put_i16(pre, "mem_deemph_fx", (Word16 *)&p->mem_deemph_fx, 1);
    rd_put_i32(pre, "L_mem_hp_out_fx", (Word32 *)&p->L_mem_hp_out_fx, 5);
    rd_put_i16(pre, "mem_MA_fx", (Word16 *)&p->mem_MA_fx, 16);
    rd_put_i16(pre, "mem_AR_fx", (Word16 *)&p->mem_AR_fx, 16);
    rd_put_i16(pre, "stab_fac_fx", (Word16 *)&p->stab_fac_fx, 1);
    rd_put_i16(pre, "stab_fac_smooth_fx", (Word16 *)&p->stab_fac_smooth_fx, 1);
    rd_put_i16(pre, "last_coder_type_fx", (Word16 *)&p->last_coder_type_fx, 1);
    rd_put_i16(pre, "agc_mem_fx", (Word16 *)&p->agc_mem_fx, 2);
    rd_put_i16(pre, "past_qua_en_fx", (Word16 *)&p->past_qua_en_fx, 4);
    rd_put_i16(pre, "mid_lsf_int_fx", (Word16 *)&p->mid_lsf_int_fx, 1);
    rd_put_i16(pre, "safety_net_fx", (Word16 *)&p->safety_net_fx, 1);
    rd_put_i16(pre, "seed_tcx_fx", (Word16 *)&p->seed_tcx_fx, 1);
    rd_put_i16(pre, "GSC_noisy_speech_fx", (Word16 *)&p->GSC_noisy_speech_fx, 1);
    rd_put_i16(pre, "Last_GSC_noisy_speech_flag_fx", (Word16 *)&p->Last_GSC_noisy_speech_flag_fx, 1);
    rd_put_i16(pre, "cor_strong_limit_fx", (Word16 *)&p->cor_strong_limit_fx, 1);
    rd_put_i16(pre, "old_y_gain_fx", (Word16 *)&p->old_y_gain_fx, 16);
    rd_put_i16(pre, "noise_lev_fx", (Word16 *)&p->noise_lev_fx, 1);
    rd_put_i16(pre, "lt_ener_per_band_fx", (Word16 *)&p->lt_ener_per_band_fx, 16);
    rd_put_i32(pre, "Last_frame_ener_fx", (Word32 *)&p->Last_frame_ener_fx, 1);
    rd_put_i16(pre, "Last_GSC_spectrum_fx", (Word16 *)&p->Last_GSC_spectrum_fx, 256);
    rd_put_i16(pre, "Last_GSC_pit_band_idx_fx", (Word16 *)&p->Last_GSC_pit_band_idx_fx, 1);
    rd_put_i16(pre, "last_exc_dct_in_fx", (Word16 *)&p->last_exc_dct_in_fx, 256);
    rd_put_i16(pre, "last_ener_fx", (Word16 *)&p->last_ener_fx, 1);
    rd_put_i16(pre, "last_bitallocation_band_fx", (Word16 *)&p->last_bitallocation_band_fx, 6);
    rd_put_i32(pre, "gc_threshold_fx", (Word32 *)&p->gc_threshold_fx, 1);
    { char b[256]; snprintf(b, sizeof b, "%sdm_fx.", pre); rd_dump_DispMem(b, &p->dm_fx); }
    rd_put_i16(pre, "prev_r_fx", (Word16 *)&p->prev_r_fx, 1);
    rd_put_i16(pre, "fmerit_w_sm_fx", (Word16 *)&p->fmerit_w_sm_fx, 1);
    rd_put_i16(pre, "frame_count_fx", (Word16 *)&p->frame_count_fx, 1);
    rd_put_i16(pre, "ne_min_fx", (Word16 *)&p->ne_min_fx, 1);
    rd_put_i16(pre, "fmerit_m_sm_fx", (Word16 *)&p->fmerit_m_sm_fx, 1);
    rd_put_i16(pre, "voice_fac_amr_wb_hf", (Word16 *)&p->voice_fac_amr_wb_hf, 1);
    rd_put_i16(pre, "unvoicing_fx", (Word16 *)&p->unvoicing_fx, 1);
    rd_put_i16(pre, "unvoicing_sm_fx", (Word16 *)&p->unvoicing_sm_fx, 1);
    rd_put_i16(pre, "unvoicing_flag_fx", (Word16 *)&p->unvoicing_flag_fx, 1);
    rd_put_i16(pre, "voicing_flag_fx", (Word16 *)&p->voicing_flag_fx, 1);
    rd_put_i16(pre, "start_band_old_fx", (Word16 *)&p->start_band_old_fx, 1);
    rd_put_i32(pre, "OptCrit_old_fx", (Word32 *)&p->OptCrit_old_fx, 1);
    rd_put_i16(pre, "seed2_fx", (Word16 *)&p->seed2_fx, 1);
    rd_put_i16(pre, "mem_hp400_fx", (Word16 *)&p->mem_hp400_fx, 6);
    rd_put_i16(pre, "mem_hf_fx", (Word16 *)&p->mem_hf_fx, 30);
    rd_put_i16(pre, "mem_syn_hf_fx", (Word16 *)&p->mem_syn_hf_fx, 16);
    rd_put_i16(pre, "delay_syn_hf_fx", (Word16 *)&p->delay_syn_hf_fx, 20);
    rd_put_i16(pre, "mem_hp_interp_fx", (Word16 *)&p->mem_hp_interp_fx, 13);
    rd_put_i16(pre, "unv_cnt_fx", (Word16 *)&p->unv_cnt_fx, 1);
    rd_put_i16(pre, "uv_count_fx", (Word16 *)&p->uv_count_fx, 1);
    rd_put_i16(pre, "act_count_fx", (Word16 *)&p->act_count_fx, 1);
    rd_put_i32(pre, "ge_sm_fx", (Word32 *)&p->ge_sm_fx, 1);
    rd_put_i16(pre, "lspold_s_fx", (Word16 *)&p->lspold_s_fx, 16);
    rd_put_i16(pre, "noimix_seed_fx", (Word16 *)&p->noimix_seed_fx, 1);
    rd_put_i16(pre, "min_alpha_fx", (Word16 *)&p->min_alpha_fx, 1);
    rd_put_i16(pre, "Q_stat_noise", (Word16 *)&p->Q_stat_noise, 1);
    rd_put_i16(pre, "exc_pe_fx", (Word16 *)&p->exc_pe_fx, 1);
    rd_put_i16(pre, "Q_stat_noise_ge", (Word16 *)&p->Q_stat_noise_ge, 1);
    rd_put_i16(pre, "bfi_fx", (Word16 *)&p->bfi_fx, 1);
    rd_put_i16(pre, "prev_bfi_fx", (Word16 *)&p->prev_bfi_fx, 1);
    rd_put_i16(pre, "seed_fx", (Word16 *)&p->seed_fx, 1);
    rd_put_i16(pre, "lp_ener_FER_fx", (Word16 *)&p->lp_ener_FER_fx, 1);
    rd_put_i16(pre, "last_good_fx", (Word16 *)&p->last_good_fx, 1);
    rd_put_i16(pre, "lp_gainc_fx", (Word16 *)&p->lp_gainc_fx, 1);
    rd_put_i16(pre, "lp_gainp_fx", (Word16 *)&p->lp_gainp_fx, 1);
    rd_put_i32(pre, "lp_ener_fx", (Word32 *)&p->lp_ener_fx, 1);
    rd_put_i32(pre, "enr_old_fx", (Word32 *)&p->enr_old_fx, 1);
    rd_put_i16(pre, "bfi_pitch_fx", (Word16 *)&p->bfi_pitch_fx, 1);
    rd_put_i16(pre, "bfi_pitch_frame_fx", (Word16 *)&p->bfi_pitch_frame_fx, 1);
    rd_put_i32(pre, "old_pitch_buf_fx", (Word32 *)&p->old_pitch_buf_fx, 12);
    rd_put_i16(pre, "upd_cnt_fx", (Word16 *)&p->upd_cnt_fx, 1);
    rd_put_i16(pre, "scaling_flag", (Word16 *)&p->scaling_flag, 1);
    rd_put_i32(pre, "lp_ener_FEC_av", (Word32 *)&p->lp_ener_FEC_av, 1);
    rd_put_i32(pre, "lp_ener_FEC_max", (Word32 *)&p->lp_ener_FEC_max, 1);
    rd_put_i16(pre, "old_enr_LP", (Word16 *)&p->old_enr_LP, 1);
    rd_put_i16(pre, "lsfoldbfi0_fx", (Word16 *)&p->lsfoldbfi0_fx, 16);
    rd_put_i16(pre, "lsfoldbfi1_fx", (Word16 *)&p->lsfoldbfi1_fx, 16);
    rd_put_i16(pre, "lsf_adaptive_mean_fx", (Word16 *)&p->lsf_adaptive_mean_fx, 16);
    rd_put_i16(pre, "decision_hyst_fx", (Word16 *)&p->decision_hyst_fx, 1);
    rd_put_i16(pre, "old_exc2_fx", (Word16 *)&p->old_exc2_fx, 320);
    rd_put_i16(pre, "old_syn2_fx", (Word16 *)&p->old_syn2_fx, 320);
    rd_put_i16(pre, "relax_prev_lsf_interp_fx", (Word16 *)&p->relax_prev_lsf_interp_fx, 1);
    rd_put_i16(pre, "mem_syn_clas_estim_fx", (Word16 *)&p->mem_syn_clas_estim_fx, 258);
    rd_put_i16(pre, "tilt_swb_fec_fx", (Word16 *)&p->tilt_swb_fec_fx, 1);
    rd_put_i16(pre, "cng_seed_fx", (Word16 *)&p->cng_seed_fx, 1);
    rd_put_i16(pre, "lspCNG_fx", (Word16 *)&p->lspCNG_fx, 16);
    rd_put_i16(pre, "first_CNG_fx", (Word16 *)&p->first_CNG_fx, 1);
    rd_put_i32(pre, "Enew_fx", (Word32 *)&p->Enew_fx, 1);
    rd_put_i16(pre, "old_enr_index_fx", (Word16 *)&p->old_enr_index_fx, 1);
    rd_put_i16(pre, "cng_ener_seed_fx", (Word16 *)&p->cng_ener_seed_fx, 1);
    rd_put_i16(pre, "cng_ener_seed1_fx", (Word16 *)&p->cng_ener_seed1_fx, 1);
    rd_put_i16(pre, "last_allow_cn_step_fx", (Word16 *)&p->last_allow_cn_step_fx, 1);
    rd_put_i16(pre, "ho_hist_size_fx", (Word16 *)&p->ho_hist_size_fx, 1);
    rd_put_i16(pre, "ho_hist_ptr_fx", (Word16 *)&p->ho_hist_ptr_fx, 1);
    rd_put_i32(pre, "ho_sid_bw_fx", (Word32 *)&p->ho_sid_bw_fx, 1);
    rd_put_i16(pre, "ho_lsp_hist_fx", (Word16 *)&p->ho_lsp_hist_fx, 128);
    rd_put_i32(pre, "ho_ener_hist_fx", (Word32 *)&p->ho_ener_hist_fx, 8);
    rd_put_i32(pre, "ho_env_hist_fx", (Word32 *)&p->ho_env_hist_fx, 160);
    rd_put_i16(pre, "act_cnt_fx", (Word16 *)&p->act_cnt_fx, 1);
    rd_put_i16(pre, "ho_circ_size_fx", (Word16 *)&p->ho_circ_size_fx, 1);
    rd_put_i16(pre, "ho_circ_ptr_fx", (Word16 *)&p->ho_circ_ptr_fx, 1);
    rd_put_i16(pre, "ho_lsp_circ_fx", (Word16 *)&p->ho_lsp_circ_fx, 128);
    rd_put_i32(pre, "ho_ener_circ_fx", (Word32 *)&p->ho_ener_circ_fx, 8);
    rd_put_i32(pre, "ho_env_circ_fx", (Word32 *)&p->ho_env_circ_fx, 160);
    rd_put_i16(pre, "num_ho_fx", (Word16 *)&p->num_ho_fx, 1);
    rd_put_i16(pre, "ho_16k_lsp_fx", (Word16 *)&p->ho_16k_lsp_fx, 8);
    rd_put_i16(pre, "CNG_mode_fx", (Word16 *)&p->CNG_mode_fx, 1);
    rd_put_i32(pre, "last_active_brate_fx", (Word32 *)&p->last_active_brate_fx, 1);
    rd_put_i16(pre, "last_CNG_L_frame_fx", (Word16 *)&p->last_CNG_L_frame_fx, 1);
    rd_put_i16(pre, "act_cnt2_fx", (Word16 *)&p->act_cnt2_fx, 1);
    rd_put_i16(pre, "cng_type_fx", (Word16 *)&p->cng_type_fx, 1);
    rd_put_i16(pre, "last_cng_type_fx", (Word16 *)&p->last_cng_type_fx, 1);
    rd_put_i32(pre, "old_env_fx", (Word32 *)&p->old_env_fx, 20);
    rd_put_i32(pre, "lp_env_fx", (Word32 *)&p->lp_env_fx, 20);
    rd_put_i16(pre, "exc_mem_fx", (Word16 *)&p->exc_mem_fx, 24);
    rd_put_i16(pre, "exc_mem1_fx", (Word16 *)&p->exc_mem1_fx, 30);
    rd_put_i16(pre, "bpf_off_fx", (Word16 *)&p->bpf_off_fx, 1);
    rd_put_i16(pre, "pst_old_syn_fx", (Word16 *)&p->pst_old_syn_fx, 290);
    rd_put_i16(pre, "pst_mem_deemp_err_fx", (Word16 *)&p->pst_mem_deemp_err_fx, 1);
    rd_put_i16(pre, "pst_lp_ener_fx", (Word16 *)&p->pst_lp_ener_fx, 1);
    rd_put_i16(pre, "Track_on_hist_fx", (Word16 *)&p->Track_on_hist_fx, 10);
    rd_put_i16(pre, "vibrato_hist_fx", (Word16 *)&p->vibrato_hist_fx, 10);
    rd_put_i16(pre, "psf_att_fx", (Word16 *)&p->psf_att_fx, 1);
    rd_put_i16(pre, "mem_mean_pit_fx", (Word16 *)&p->mem_mean_pit_fx, 10);
    rd_put_i16(pre, "Ng_ener_ST_fx", (Word16 *)&p->Ng_ener_ST_fx, 1);
    rd_put_i16(pre, "last_L_frame_fx", (Word16 *)&p->last_L_frame_fx, 1);
    rd_put_i16(pre, "mem_preemp_preQ_fx", (Word16 *)&p->mem_preemp_preQ_fx, 1);
    rd_put_i16(pre, "last_nq_preQ_fx", (Word16 *)&p->last_nq_preQ_fx, 1);
    rd_put_i16(pre, "use_acelp_preq", (Word16 *)&p->use_acelp_preq, 1);
    rd_put_i16(pre, "UV_cnt_fx", (Word16 *)&p->UV_cnt_fx, 1);
    rd_put_i16(pre, "LT_UV_cnt_fx", (Word16 *)&p->LT_UV_cnt_fx, 1);
    rd_put_i16(pre, "Last_ener_fx", (Word16 *)&p->Last_ener_fx, 1);
    rd_put_i16(pre, "lt_diff_etot_fx", (Word16 *)&p->lt_diff_etot_fx, 40);
    rd_put_i16(pre, "old_Aq_fx", (Word16 *)&p->old_Aq_fx, 68);
    rd_put_i16(pre, "lt_voice_fac_fx", (Word16 *)&p->lt_voice_fac_fx, 1);
    rd_put_i16(pre, "last_ppp_mode_dec_fx", (Word16 *)&p->last_ppp_mode_dec_fx, 1);
    rd_put_i16(pre, "ppp_mode_dec_fx", (Word16 *)&p->ppp_mode_dec_fx, 1);
    rd_put_i16(pre, "last_nelp_mode_dec_fx", (Word16 *)&p->last_nelp_mode_dec_fx, 1);
    rd_put_i16(pre, "nelp_mode_dec_fx", (Word16 *)&p->nelp_mode_dec_fx, 1);
    rd_put_i16(pre, "firstTime_voiceddec_fx", (Word16 *)&p->firstTime_voiceddec_fx, 1);
    rd_put_i16(pre, "dtfs_dec_a_fx", (Word16 *)&p->dtfs_dec_a_fx, 102);
    rd_put_i16(pre, "dtfs_dec_b_fx", (Word16 *)&p->dtfs_dec_b_fx, 102);
    rd_put_i16(pre, "dtfs_dec_lag_fx", (Word16 *)&p->dtfs_dec_lag_fx, 1);
    rd_put_i16(pre, "dtfs_dec_nH_fx", (Word16 *)&p->dtfs_dec_nH_fx, 1);
    rd_put_i16(pre, "dtfs_dec_nH_4kHz_fx", (Word16 *)&p->dtfs_dec_nH_4kHz_fx, 1);
    rd_put_i16(pre, "dtfs_dec_upper_cut_off_freq_of_interest_fx", (Word16 *)&p->dtfs_dec_upper_cut_off_freq_of_interest_fx, 1);
    rd_put_i16(pre, "dtfs_dec_upper_cut_off_freq_fx", (Word16 *)&p->dtfs_dec_upper_cut_off_freq_fx, 1);
    rd_put_i16(pre, "ph_offset_D_fx", (Word16 *)&p->ph_offset_D_fx, 1);
    rd_put_i16(pre, "lastLgainD_fx", (Word16 *)&p->lastLgainD_fx, 1);
    rd_put_i16(pre, "lastHgainD_fx", (Word16 *)&p->lastHgainD_fx, 1);
    rd_put_i16(pre, "lasterbD_fx", (Word16 *)&p->lasterbD_fx, 24);
    rd_put_i16(pre, "dtfs_dec_Q", (Word16 *)&p->dtfs_dec_Q, 1);
    rd_put_i32(pre, "bp1_filt_mem_nb_dec_fx", (Word32 *)&p->bp1_filt_mem_nb_dec_fx, 14);
    rd_put_i16(pre, "bp1_filt_mem_wb_dec_fx", (Word16 *)&p->bp1_filt_mem_wb_dec_fx, 8);
    rd_put_i16(pre, "shape1_filt_mem_dec_fx", (Word16 *)&p->shape1_filt_mem_dec_fx, 10);
    rd_put_i16(pre, "shape2_filt_mem_dec_fx", (Word16 *)&p->shape2_filt_mem_dec_fx, 10);
    rd_put_i16(pre, "shape3_filt_mem_dec_fx", (Word16 *)&p->shape3_filt_mem_dec_fx, 10);
    rd_put_i16(pre, "nelp_dec_seed_fx", (Word16 *)&p->nelp_dec_seed_fx, 1);
    rd_put_i16(pre, "FadeScale_fx", (Word16 *)&p->FadeScale_fx, 1);
    rd_put_i16(pre, "prev_gain_pit_dec_fx", (Word16 *)&p->prev_gain_pit_dec_fx, 1);
    rd_put_i16(pre, "prev_tilt_code_dec_fx", (Word16 *)&p->prev_tilt_code_dec_fx, 1);
    rd_put_i16(pre, "tilt_code_dec_fx", (Word16 *)&p->tilt_code_dec_fx, 5);
    rd_put_i16(pre, "rf_frame_type", (Word16 *)&p->rf_frame_type, 1);
    rd_put_i16(pre, "use_partial_copy", (Word16 *)&p->use_partial_copy, 1);
    rd_put_i16(pre, "prev_use_partial_copy", (Word16 *)&p->prev_use_partial_copy, 1);
    rd_put_i16(pre, "rf_flag", (Word16 *)&p->rf_flag, 1);
    rd_put_i16(pre, "rf_flag_last", (Word16 *)&p->rf_flag_last, 1);
    rd_put_i16(pre, "rf_fec_offset", (Word16 *)&p->rf_fec_offset, 1);
    rd_put_i16(pre, "next_coder_type", (Word16 *)&p->next_coder_type, 1);
    rd_put_i16(pre, "prev_rf_frame_type", (Word16 *)&p->prev_rf_frame_type, 1);
    rd_put_i16(pre, "rf_target_bits", (Word16 *)&p->rf_target_bits, 1);
    rd_put_i16(pre, "rf_indx_nelp_fid", (Word16 *)&p->rf_indx_nelp_fid, 1);
    rd_put_i16(pre, "rf_indx_nelp_iG1", (Word16 *)&p->rf_indx_nelp_iG1, 1);
    rd_put_i16(pre, "rf_indx_nelp_iG2", (Word16 *)&p->rf_indx_nelp_iG2, 2);
    rd_put_i16(pre, "rf_indx_tbeGainFr", (Word16 *)&p->rf_indx_tbeGainFr, 1);
    rd_put_i16(pre, "bwe_highrate_seed_fx", (Word16 *)&p->bwe_highrate_seed_fx, 1);
    rd_put_i16(pre, "t_audio_prev_fx", (Word16 *)&p->t_audio_prev_fx, 496);
    rd_put_i16(pre, "t_audio_prev_fx_exp", (Word16 *)&p->t_audio_prev_fx_exp, 4);
    rd_put_i16(pre, "old_is_transient_hr_bwe_fx", (Word16 *)&p->old_is_transient_hr_bwe_fx, 1);
    rd_put_i32(pre, "L_mem_EnergyLT_fx", (Word32 *)&p->L_mem_EnergyLT_fx, 1);
    rd_put_i16(pre, "mem_EnergyLT_fx_exp", (Word16 *)&p->mem_EnergyLT_fx_exp, 1);
    rd_put_i16(pre, "synth_history_fx", (Word16 *)&p->synth_history_fx, 2496);
    rd_put1(pre, "old_synthFB_fx", p->old_synthFB_fx == NULL ? 0 : (long long)(p->old_synthFB_fx - p->synth_history_fx));
    rd_put_i16(pre, "old_out_fx", (Word16 *)&p->old_out_fx, 960);
    rd_put_i16(pre, "old_out_LB_fx", (Word16 *)&p->old_out_LB_fx, 640);
    rd_put_i16(pre, "Q_old_wtda_LB", (Word16 *)&p->Q_old_wtda_LB, 1);
    rd_put_i16(pre, "Q_old_wtda", (Word16 *)&p->Q_old_wtda, 1);
    rd_put_i16(pre, "Q_old_postdec", (Word16 *)&p->Q_old_postdec, 1);
    rd_put_i16(pre, "Qprev_synth_buffer_fx", (Word16 *)&p->Qprev_synth_buffer_fx, 1);
    rd_put_i32(pre, "oldIMDCTout_fx", (Word32 *)&p->oldIMDCTout_fx, 80);
    rd_put_i16(pre, "prev_oldauOut_fx", (Word16 *)&p->prev_oldauOut_fx, 160);
    rd_put_i16(pre, "old_auOut_2fr_fx", (Word16 *)&p->old_auOut_2fr_fx, 320);
    rd_put_i16(pre, "old_out_pha_fx", (Word16 *)&p->old_out_pha_fx, 140);
    rd_put_i16(pre, "diff_energy_fx", (Word16 *)&p->diff_energy_fx, 1);
    rd_put_i32(pre, "old_coeffs_fx", (Word32 *)&p->old_coeffs_fx, 160);
    rd_put_i16(pre, "stat_mode_out_fx", (Word16 *)&p->stat_mode_out_fx, 1);
    rd_put_i16(pre, "stat_mode_old_fx", (Word16 *)&p->stat_mode_old_fx, 1);
    rd_put_i16(pre, "phase_mat_flag_fx", (Word16 *)&p->phase_mat_flag_fx, 1);
    rd_put_i16(pre, "phase_mat_next_fx", (Word16 *)&p->phase_mat_next_fx, 1);
    rd_put_i16(pre, "old_Min_ind_fx", (Word16 *)&p->old_Min_ind_fx, 1);
    rd_put_i16(pre, "old_is_transient_fx", (Word16 *)&p->old_is_transient_fx, 3);
    rd_put_i16(pre, "old_bfi_cnt_fx", (Word16 *)&p->old_bfi_cnt_fx, 1);
    rd_put_i16(pre, "prev_old_bfi_fx", (Word16 *)&p->prev_old_bfi_fx, 1);
    rd_put_i32(pre, "ynrm_values_fx", (Word32 *)&p->ynrm_values_fx, 21);
    rd_put_i32(pre, "r_p_values_fx", (Word32 *)&p->r_p_values_fx, 6);
    rd_put_i16(pre, "Norm_gain_fx", (Word16 *)&p->Norm_gain_fx, 18);
    rd_put_i16(pre, "HQ_FEC_seed_fx", (Word16 *)&p->HQ_FEC_seed_fx, 1);
    rd_put_i16(pre, "energy_MA_Curr_fx", (Word16 *)&p->energy_MA_Curr_fx, 2);
    rd_put_i16(pre, "last_core_fx", (Word16 *)&p->last_core_fx, 1);
    rd_put_i16(pre, "last_core_bs_fx", (Word16 *)&p->last_core_bs_fx, 1);
    rd_put_i16(pre, "prev_last_core_fx", (Word16 *)&p->prev_last_core_fx, 1);
    rd_put_i16(pre, "last_hq_core_type_fx", (Word16 *)&p->last_hq_core_type_fx, 1);
    rd_put_i16(pre, "last_L_frame_ori_fx", (Word16 *)&p->last_L_frame_ori_fx, 1);
    rd_put_i16(pre, "previoussynth_fx", (Word16 *)&p->previoussynth_fx, 960);
    rd_put_i16(pre, "old_synth_sw_fx", (Word16 *)&p->old_synth_sw_fx, 429);
    rd_put_i16(pre, "delay_buf_out_fx", (Word16 *)&p->delay_buf_out_fx, 60);
    rd_put_i16(pre, "mem_norm_fx", (Word16 *)&p->mem_norm_fx, 27);
    rd_put_i16(pre, "mem_env_delta_fx", (Word16 *)&p->mem_env_delta_fx, 1);
    rd_put_i16(pre, "no_att_hangover_fx", (Word16 *)&p->no_att_hangover_fx, 1);
    rd_put_i32(pre, "energy_lt_fx", (Word32 *)&p->energy_lt_fx, 1);
    rd_put_i16(pre, "hq_generic_seed_fx", (Word16 *)&p->hq_generic_seed_fx, 1);
    rd_put_i16(pre, "prev_noise_level_fx", (Word16 *)&p->prev_noise_level_fx, 2);
    rd_put_i16(pre, "prev_hqswb_clas_fx", (Word16 *)&p->prev_hqswb_clas_fx, 1);
    rd_put_i16(pre, "prev_R_fx", (Word16 *)&p->prev_R_fx, 1);
    rd_put_i32(pre, "prev_coeff_out_fx", (Word32 *)&p->prev_coeff_out_fx, 20);
    rd_put_i16(pre, "prev_SWB_peak_pos_fx", (Word16 *)&p->prev_SWB_peak_pos_fx, 4);
    rd_put_i16(pre, "old_Aq_12_8_fx", (Word16 *)&p->old_Aq_12_8_fx, 17);
    rd_put_i16(pre, "old_Es_pred_fx", (Word16 *)&p->old_Es_pred_fx, 1);
    rd_put_i16(pre, "HqVoicing_fx", (Word16 *)&p->HqVoicing_fx, 1);
    rd_put_i16(pre, "fer_samples_fx", (Word16 *)&p->fer_samples_fx, 960);
    rd_put_i32(pre, "prev_normq_fx", (Word32 *)&p->prev_normq_fx, 26);
    rd_put_i32(pre, "prev_env_fx", (Word32 *)&p->prev_env_fx, 26);
    rd_put_i32(pre, "last_ni_gain_fx", (Word32 *)&p->last_ni_gain_fx, 32);
    rd_put_i16(pre, "last_env_fx", (Word16 *)&p->last_env_fx, 32);
    rd_put_i16(pre, "last_max_pos_pulse_fx", (Word16 *)&p->last_max_pos_pulse_fx, 1);
    rd_put_i16(pre, "memfilt_lb_fx", (Word16 *)&p->memfilt_lb_fx, 1);
    rd_put_i32(pre, "mean_prev_hb_fx", (Word32 *)&p->mean_prev_hb_fx, 1);
    rd_put_i16(pre, "smoothmem_fx", (Word16 *)&p->smoothmem_fx, 1);
    rd_put_i32(pre, "mean_prev_fx", (Word32 *)&p->mean_prev_fx, 1);
    rd_put_i32(pre, "mean_prev_nc_fx", (Word32 *)&p->mean_prev_nc_fx, 1);
    rd_put_i16(pre, "wmold_hb_fx", (Word16 *)&p->wmold_hb_fx, 1);
    rd_put_i16(pre, "prevflag_fx", (Word16 *)&p->prevflag_fx, 1);
    rd_put_i16(pre, "pastpre_fx", (Word16 *)&p->pastpre_fx, 1);
    rd_put_i16(pre, "prev_frm_hfe2_fx", (Word16 *)&p->prev_frm_hfe2_fx, 1);
    rd_put_i16(pre, "prev_stab_hfe2_fx", (Word16 *)&p->prev_stab_hfe2_fx, 1);
    rd_put_i16(pre, "prev_ni_ratio_fx", (Word16 *)&p->prev_ni_ratio_fx, 1);
    rd_put_i16(pre, "prev_En_sb_fx", (Word16 *)&p->prev_En_sb_fx, 4);
    rd_put_u32(pre, "rc_low_fx", (UWord32 *)&p->rc_low_fx, 1);
    rd_put_u32(pre, "rc_range_fx", (UWord32 *)&p->rc_range_fx, 1);
    rd_put_u32(pre, "rc_help_fx", (UWord32 *)&p->rc_help_fx, 1);
    rd_put_i16(pre, "rc_num_bits_fx", (Word16 *)&p->rc_num_bits_fx, 1);
    rd_put_i16(pre, "rc_offset_fx", (Word16 *)&p->rc_offset_fx, 1);
    rd_put_i16(pre, "rc_end_fx", (Word16 *)&p->rc_end_fx, 1);
    rd_put_i16(pre, "prev_env_Q", (Word16 *)&p->prev_env_Q, 26);
    rd_put_i16(pre, "state_lpc_syn_fx", (Word16 *)&p->state_lpc_syn_fx, 10);
    rd_put_i32(pre, "mem_csfilt_fx", (Word32 *)&p->mem_csfilt_fx, 2);
    rd_put_i16(pre, "state_syn_shbexc_fx", (Word16 *)&p->state_syn_shbexc_fx, 20);
    rd_put_i16(pre, "syn_overlap_fx", (Word16 *)&p->syn_overlap_fx, 20);
    rd_put_i16(pre, "lsp_prevfrm_fx", (Word16 *)&p->lsp_prevfrm_fx, 10);
    rd_put_i32(pre, "GainFrame_prevfrm_fx", (Word32 *)&p->GainFrame_prevfrm_fx, 1);
    rd_put_i16(pre, "GainAttn_fx", (Word16 *)&p->GainAttn_fx, 1);
    rd_put_i16(pre, "old_bwe_exc_fx", (Word16 *)&p->old_bwe_exc_fx, 578);
    rd_put_i16(pre, "bwe_seed_fx", (Word16 *)&p->bwe_seed_fx, 2);
    rd_put_i32(pre, "bwe_non_lin_prev_scale_fx", (Word32 *)&p->bwe_non_lin_prev_scale_fx, 1);
    rd_put_i16(pre, "old_bwe_exc_extended_fx", (Word16 *)&p->old_bwe_exc_extended_fx, 12);
    rd_put_i16(pre, "last_voice_factor_fx", (Word16 *)&p->last_voice_factor_fx, 1);
    rd_put_i32(pre, "genSHBsynth_Hilbert_Mem_fx", (Word32 *)&p->genSHBsynth_Hilbert_Mem_fx, 21);
    rd_put_i16(pre, "mem_genSHBexc_filt_down_shb_fx", (Word16 *)&p->mem_genSHBexc_filt_down_shb_fx, 7);
    rd_put_i16(pre, "mem_genSHBexc_filt_down_wb2_fx", (Word16 *)&p->mem_genSHBexc_filt_down_wb2_fx, 7);
    rd_put_i16(pre, "mem_genSHBexc_filt_down_wb3_fx", (Word16 *)&p->mem_genSHBexc_filt_down_wb3_fx, 7);
    rd_put_i16(pre, "genSHBsynth_state_lsyn_filt_shb_local_fx", (Word16 *)&p->genSHBsynth_state_lsyn_filt_shb_local_fx, 6);
    rd_put_i16(pre, "state_lsyn_filt_shb_fx", (Word16 *)&p->state_lsyn_filt_shb_fx, 6);
    rd_put_i16(pre, "state_lsyn_filt_dwn_shb_fx", (Word16 *)&p->state_lsyn_filt_dwn_shb_fx, 6);
    rd_put_i16(pre, "state_32and48k_WB_upsample_fx", (Word16 *)&p->state_32and48k_WB_upsample_fx, 6);
    rd_put_i16(pre, "hb_prev_synth_buffer_fx", (Word16 *)&p->hb_prev_synth_buffer_fx, 111);
    rd_put_i16(pre, "old_bwe_delay_fx", (Word16 *)&p->old_bwe_delay_fx, 1);
    rd_put_i16(pre, "syn_dm_phase_fx", (Word16 *)&p->syn_dm_phase_fx, 1);
    rd_put_i32(pre, "fbbwe_hpf_mem_fx", (Word32 *)&p->fbbwe_hpf_mem_fx, 16);
    rd_put_i16(pre, "fbbwe_hpf_mem_fx_Q", (Word16 *)&p->fbbwe_hpf_mem_fx_Q, 4);
    rd_put_i32(pre, "prev_wb_bwe_frame_pow_fx", (Word32 *)&p->prev_wb_bwe_frame_pow_fx, 1);
    rd_put_i32(pre, "prev_swb_bwe_frame_pow_fx", (Word32 *)&p->prev_swb_bwe_frame_pow_fx, 1);
    rd_put_i32(pre, "prev_ener_fx", (Word32 *)&p->prev_ener_fx, 1);
    rd_put_i16(pre, "prev_ener_fx_Q", (Word16 *)&p->prev_ener_fx_Q, 1);
    rd_put_i16(pre, "prev_GainShape_fx", (Word16 *)&p->prev_GainShape_fx, 1);
    rd_put_i16(pre, "fb_state_lpc_syn_fx", (Word16 *)&p->fb_state_lpc_syn_fx, 10);
    rd_put_i16(pre, "prev_Q_bwe_exc_fb", (Word16 *)&p->prev_Q_bwe_exc_fb, 1);
    rd_put_i16(pre, "fb_tbe_demph_fx", (Word16 *)&p->fb_tbe_demph_fx, 1);
    rd_put_i16(pre, "prev_fbbwe_ratio_fx", (Word16 *)&p->prev_fbbwe_ratio_fx, 1);
    rd_put_i16(pre, "tilt_wb_fx", (Word16 *)&p->tilt_wb_fx, 1);
    rd_put_i16(pre, "tilt_swb_fx", (Word16 *)&p->tilt_swb_fx, 1);
    rd_put_i16(pre, "prev_ener_shb_fx", (Word16 *)&p->prev_ener_shb_fx, 1);
    rd_put_i32(pre, "enerLH_fx", (Word32 *)&p->enerLH_fx, 1);
    rd_put_i32(pre, "prev_enerLH_fx", (Word32 *)&p->prev_enerLH_fx, 1);
    rd_put_i32(pre, "enerLL_fx", (Word32 *)&p->enerLL_fx, 1);
    rd_put_i32(pre, "prev_enerLL_fx", (Word32 *)&p->prev_enerLL_fx, 1);
    rd_put_i16(pre, "prev_fractive_fx", (Word16 *)&p->prev_fractive_fx, 1);
    rd_put_i16(pre, "prev_bws_cnt_fx", (Word16 *)&p->prev_bws_cnt_fx, 1);
    rd_put_i16(pre, "bws_cnt_fx", (Word16 *)&p->bws_cnt_fx, 1);
    rd_put_i16(pre, "bws_cnt1_fx", (Word16 *)&p->bws_cnt1_fx, 1);
    rd_put_i16(pre, "attenu_fx", (Word16 *)&p->attenu_fx, 1);
    rd_put_i16(pre, "last_inner_frame_fx", (Word16 *)&p->last_inner_frame_fx, 1);
    rd_put_i16(pre, "last_bwidth_fx", (Word16 *)&p->last_bwidth_fx, 1);
    rd_put_i16(pre, "prev_weight1_fx", (Word16 *)&p->prev_weight1_fx, 1);
    rd_put_i16(pre, "t_audio_q_fx", (Word16 *)&p->t_audio_q_fx, 256);
    rd_put_i16(pre, "tbe_demph_fx", (Word16 *)&p->tbe_demph_fx, 1);
    rd_put_i16(pre, "tbe_premph_fx", (Word16 *)&p->tbe_premph_fx, 1);
    rd_put_i16(pre, "mem_stp_swb_fx", (Word16 *)&p->mem_stp_swb_fx, 10);
    rd_put1(pre, "ptr_mem_stp_swb_fx", p->ptr_mem_stp_swb_fx == NULL ? 0 : (long long)(p->ptr_mem_stp_swb_fx - p->mem_stp_swb_fx));
    rd_put_i16(pre, "gain_prec_swb_fx", (Word16 *)&p->gain_prec_swb_fx, 1);
    rd_put_i16(pre, "mem_zero_swb_fx", (Word16 *)&p->mem_zero_swb_fx, 10);
    rd_put_i16(pre, "swb_lsp_prev_interp_fx", (Word16 *)&p->swb_lsp_prev_interp_fx, 10);
    rd_put_i32(pre, "prev1_shb_ener_sf_fx", (Word32 *)&p->prev1_shb_ener_sf_fx, 1);
    rd_put_i32(pre, "prev2_shb_ener_sf_fx", (Word32 *)&p->prev2_shb_ener_sf_fx, 1);
    rd_put_i32(pre, "prev3_shb_ener_sf_fx", (Word32 *)&p->prev3_shb_ener_sf_fx, 1);
    rd_put_i16(pre, "prev_res_shb_gshape_fx", (Word16 *)&p->prev_res_shb_gshape_fx, 1);
    rd_put_i16(pre, "prev_mixFactors_fx", (Word16 *)&p->prev_mixFactors_fx, 1);
    rd_put_i16(pre, "tilt_mem_fx", (Word16 *)&p->tilt_mem_fx, 1);
    rd_put_i16(pre, "prev_lsf_diff_fx", (Word16 *)&p->prev_lsf_diff_fx, 8);
    rd_put_i16(pre, "prev_tilt_para_fx", (Word16 *)&p->prev_tilt_para_fx, 1);
    rd_put_i16(pre, "cur_sub_Aq_fx", (Word16 *)&p->cur_sub_Aq_fx, 17);
    rd_put_i16(pre, "lsf_idx_fx", (Word16 *)&p->lsf_idx_fx, 5);
    rd_put_i16(pre, "m_idx_fx", (Word16 *)&p->m_idx_fx, 1);
    rd_put_i16(pre, "grid_idx_fx", (Word16 *)&p->grid_idx_fx, 1);
    rd_put_i16(pre, "idxSubGains_fx", (Word16 *)&p->idxSubGains_fx, 1);
    rd_put_i16(pre, "idxFrameGain_fx", (Word16 *)&p->idxFrameGain_fx, 1);
    rd_put_i16(pre, "idx_shb_fr_gain_fx", (Word16 *)&p->idx_shb_fr_gain_fx, 1);
    rd_put_i16(pre, "idx_res_gs_fx", (Word16 *)&p->idx_res_gs_fx, 5);
    rd_put_i16(pre, "idx_mixFac_fx", (Word16 *)&p->idx_mixFac_fx, 1);
    rd_put_i16(pre, "lsf_WB_fx", (Word16 *)&p->lsf_WB_fx, 1);
    rd_put_i16(pre, "gFrame_WB_fx", (Word16 *)&p->gFrame_WB_fx, 1);
    rd_put_i16(pre, "idxGain_fx", (Word16 *)&p->idxGain_fx, 1);
    rd_put_i16(pre, "old_core_synth_fx", (Word16 *)&p->old_core_synth_fx, 320);
    rd_put_i16(pre, "old_tbe_synth_fx", (Word16 *)&p->old_tbe_synth_fx, 222);
    rd_put_i16(pre, "int_3_over_2_tbemem_dec_fx", (Word16 *)&p->int_3_over_2_tbemem_dec_fx, 15);
    rd_put_i16(pre, "interpol_3_2_cng_dec_fx", (Word16 *)&p->interpol_3_2_cng_dec_fx, 15);
    rd_put_i16(pre, "mem_resamp_HB_fx", (Word16 *)&p->mem_resamp_HB_fx, 13);
    rd_put_i16(pre, "mem_resamp_HB_32k_fx", (Word16 *)&p->mem_resamp_HB_32k_fx, 7);
    rd_put_i16(pre, "old_wtda_wb_fx_exp", (Word16 *)&p->old_wtda_wb_fx_exp, 1);
    rd_put_i16(pre, "L_old_wtda_swb_fx", (Word16 *)&p->L_old_wtda_swb_fx, 960);
    rd_put_i16(pre, "old_wtda_swb_fx_exp", (Word16 *)&p->old_wtda_swb_fx_exp, 1);
    rd_put_i16(pre, "mem_imdct_exp_fx", (Word16 *)&p->mem_imdct_exp_fx, 1);
    rd_put_i16(pre, "old_syn_12k8_16k_fx", (Word16 *)&p->old_syn_12k8_16k_fx, 36);
    rd_put_i16(pre, "mem_deemph_old_syn_fx", (Word16 *)&p->mem_deemph_old_syn_fx, 1);
    rd_put_i16(pre, "prev_mode_fx", (Word16 *)&p->prev_mode_fx, 1);
    rd_put_i16(pre, "prev_SWB_fenv_fx", (Word16 *)&p->prev_SWB_fenv_fx, 14);
    rd_put_i16(pre, "prev_Energy_fx", (Word16 *)&p->prev_Energy_fx, 1);
    rd_put_i32(pre, "prev_Energy_wb_fx", (Word32 *)&p->prev_Energy_wb_fx, 1);
    rd_put_i16(pre, "prev_L_swb_norm_fx", (Word16 *)&p->prev_L_swb_norm_fx, 1);
    rd_put_i16(pre, "Seed_fx", (Word16 *)&p->Seed_fx, 1);
    rd_put_i16(pre, "memExp1", (Word16 *)&p->memExp1, 1);
    rd_put_i16(pre, "prev_frica_flag_fx", (Word16 *)&p->prev_frica_flag_fx, 1);
    rd_put_i16(pre, "mem_imdct_fx", (Word16 *)&p->mem_imdct_fx, 960);
    rd_put_i16(pre, "prev_td_energy_fx", (Word16 *)&p->prev_td_energy_fx, 1);
    rd_put_i16(pre, "prev_weight_fx", (Word16 *)&p->prev_weight_fx, 1);
    rd_put_i16(pre, "prev_coder_type_fx", (Word16 *)&p->prev_coder_type_fx, 1);
    rd_put_i16(pre, "prev_flag_fx", (Word16 *)&p->prev_flag_fx, 1);
    rd_put_i16(pre, "last_wb_bwe_ener_fx", (Word16 *)&p->last_wb_bwe_ener_fx, 1);
    rd_put_i16(pre, "prev_frame_pow_exp", (Word16 *)&p->prev_frame_pow_exp, 1);
    rd_put_i16(pre, "prev_Qx", (Word16 *)&p->prev_Qx, 1);
    rd_put_i16(pre, "prev_Q_bwe_exc", (Word16 *)&p->prev_Q_bwe_exc, 1);
    rd_put_i16(pre, "prev_Q_synth", (Word16 *)&p->prev_Q_synth, 1);
    rd_put_i16(pre, "prev_fb_ener_adjust_fx", (Word16 *)&p->prev_fb_ener_adjust_fx, 1);
    rd_put_i16(pre, "shb_cng_ener_fx", (Word16 *)&p->shb_cng_ener_fx, 1);
    rd_put_i16(pre, "wb_cng_ener_fx", (Word16 *)&p->wb_cng_ener_fx, 1);
    rd_put_i16(pre, "last_wb_cng_ener_fx", (Word16 *)&p->last_wb_cng_ener_fx, 1);
    rd_put_i16(pre, "last_shb_cng_ener_fx", (Word16 *)&p->last_shb_cng_ener_fx, 1);
    rd_put_i16(pre, "swb_cng_seed_fx", (Word16 *)&p->swb_cng_seed_fx, 1);
    rd_put_i16(pre, "lsp_shb_prev_prev_fx", (Word16 *)&p->lsp_shb_prev_prev_fx, 10);
    rd_put_i16(pre, "lsp_shb_prev_fx", (Word16 *)&p->lsp_shb_prev_fx, 10);
    rd_put_i16(pre, "shb_dtx_count_fx", (Word16 *)&p->shb_dtx_count_fx, 1);
    rd_put_i16(pre, "last_vad_fx", (Word16 *)&p->last_vad_fx, 1);
    rd_put_i16(pre, "trans_cnt_fx", (Word16 *)&p->trans_cnt_fx, 1);
    rd_put_i16(pre, "burst_cnt_fx", (Word16 *)&p->burst_cnt_fx, 1);
    rd_put_i16(pre, "last_shb_ener_fx", (Word16 *)&p->last_shb_ener_fx, 1);
    rd_put1(pre, "prev_good_synth_fx", p->prev_good_synth_fx == NULL ? 0 : (long long)(p->prev_good_synth_fx - p->synth_history_fx));
    rd_put_i16(pre, "prev_sign_switch_fx", (Word16 *)&p->prev_sign_switch_fx, 16);
    rd_put_i16(pre, "prev_sign_switch_2_fx", (Word16 *)&p->prev_sign_switch_2_fx, 16);
    rd_put_i16(pre, "time_offs_fx", (Word16 *)&p->time_offs_fx, 1);
    rd_put_i16(pre, "X_sav_fx", (Word16 *)&p->X_sav_fx, 1536);
    rd_put_i16(pre, "Q_X_sav", (Word16 *)&p->Q_X_sav, 1);
    rd_put_i16(pre, "num_p_fx", (Word16 *)&p->num_p_fx, 1);
    rd_put_i16(pre, "plocs_fx", (Word16 *)&p->plocs_fx, 385);
    rd_put_i32(pre, "plocsi_fx", (Word32 *)&p->plocsi_fx, 385);
    rd_put_i16(pre, "env_stab_fx", (Word16 *)&p->env_stab_fx, 1);
    rd_put_i16(pre, "mem_norm_hqfec_fx", (Word16 *)&p->mem_norm_hqfec_fx, 27);
    rd_put_i16(pre, "mem_env_delta_hqfec_fx", (Word16 *)&p->mem_env_delta_hqfec_fx, 1);
    rd_put_i16(pre, "env_stab_plc_fx", (Word16 *)&p->env_stab_plc_fx, 1);
    rd_put_i16(pre, "env_stab_state_p_fx", (Word16 *)&p->env_stab_state_p_fx, 2);
    rd_put_i16(pre, "envstabplc_hocnt_fx", (Word16 *)&p->envstabplc_hocnt_fx, 1);
    rd_put_i16(pre, "mag_chg_1st_fx", (Word16 *)&p->mag_chg_1st_fx, 9);
    rd_put_i16(pre, "Xavg_fx", (Word16 *)&p->Xavg_fx, 9);
    rd_put_i16(pre, "beta_mute_fx", (Word16 *)&p->beta_mute_fx, 1);
    rd_put_i16(pre, "last_fec_fx", (Word16 *)&p->last_fec_fx, 1);
    rd_put_i16(pre, "ph_ecu_HqVoicing_fx", (Word16 *)&p->ph_ecu_HqVoicing_fx, 1);
    rd_put_i16(pre, "oldHqVoicing_fx", (Word16 *)&p->oldHqVoicing_fx, 1);
    rd_put_i16(pre, "oldgapsynth_fx", (Word16 *)&p->oldgapsynth_fx, 960);
    rd_put_i16(pre, "ph_ecu_active_fx", (Word16 *)&p->ph_ecu_active_fx, 1);
    rd_put_i16(pre, "ni_seed_forfec", (Word16 *)&p->ni_seed_forfec, 1);
    rd_put_i16(pre, "ber_occured_in_pvq", (Word16 *)&p->ber_occured_in_pvq, 1);
    rd_put_i16(pre, "LDm_mem_etot_fx", (Word16 *)&p->LDm_mem_etot_fx, 1);
    rd_put_i16(pre, "LDm_last_music_flag_fx", (Word16 *)&p->LDm_last_music_flag_fx, 1);
    rd_put_i16(pre, "LDm_nb_thr_1_fx", (Word16 *)&p->LDm_nb_thr_1_fx, 1);
    rd_put_i16(pre, "LDm_nb_thr_3_fx", (Word16 *)&p->LDm_nb_thr_3_fx, 1);
    rd_put_i16(pre, "dct_post_old_exc_fx", (Word16 *)&p->dct_post_old_exc_fx, 448);
    rd_put_i16(pre, "LDm_thres_fx", (Word16 *)&p->LDm_thres_fx, 4);
    rd_put_i16(pre, "LDm_lt_diff_etot_fx", (Word16 *)&p->LDm_lt_diff_etot_fx, 40);
    rd_put_i16(pre, "LDm_enh_lp_gbin_fx", (Word16 *)&p->LDm_enh_lp_gbin_fx, 640);
    rd_put_i32(pre, "LDm_enh_lf_EO_fx", (Word32 *)&p->LDm_enh_lf_EO_fx, 640);
    rd_put_i16(pre, "LDm_enh_min_ns_gain_fx", (Word16 *)&p->LDm_enh_min_ns_gain_fx, 1);
    rd_put_i32(pre, "LDm_bckr_noise_fx", (Word32 *)&p->LDm_bckr_noise_fx, 20);
    rd_put_i16(pre, "filt_lfE_fx", (Word16 *)&p->filt_lfE_fx, 640);
    rd_put_i16(pre, "last_nonfull_music_fx", (Word16 *)&p->last_nonfull_music_fx, 1);
    rd_put_i16(pre, "Old_ener_Q", (Word16 *)&p->Old_ener_Q, 1);
    rd_put_i16(pre, "Q_exc", (Word16 *)&p->Q_exc, 1);
    rd_put_i16(pre, "prev_Q_exc", (Word16 *)&p->prev_Q_exc, 1);
    rd_put_i16(pre, "Q_subfr", (Word16 *)&p->Q_subfr, 5);
    rd_put_i16(pre, "prev_Q_bwe_syn", (Word16 *)&p->prev_Q_bwe_syn, 1);
    rd_put_i16(pre, "prev_Q_bwe_syn2", (Word16 *)&p->prev_Q_bwe_syn2, 1);
    rd_put_i16(pre, "Q_syn2", (Word16 *)&p->Q_syn2, 1);
    rd_put_i16(pre, "Q_syn", (Word16 *)&p->Q_syn, 1);
    rd_put_i16(pre, "prev_Q_syn", (Word16 *)&p->prev_Q_syn, 1);
    rd_put_i16(pre, "prev_hb_synth_fx_exp", (Word16 *)&p->prev_hb_synth_fx_exp, 1);
    rd_put_i16(pre, "prev_synth_buffer_fx", (Word16 *)&p->prev_synth_buffer_fx, 51);
    rd_put_i16(pre, "prev_lpc_wb_fx", (Word16 *)&p->prev_lpc_wb_fx, 6);
    rd_put_i16(pre, "GainShape_Delay", (Word16 *)&p->GainShape_Delay, 8);
    rd_put_i16(pre, "vbr_hw_BWE_disable_dec_fx", (Word16 *)&p->vbr_hw_BWE_disable_dec_fx, 1);
    rd_put_i16(pre, "last_vbr_hw_BWE_disable_dec_fx", (Word16 *)&p->last_vbr_hw_BWE_disable_dec_fx, 1);
    { char b[256]; snprintf(b, sizeof b, "%scldfbAna_fx.", pre); rd_put1(pre, "cldfbAna_fx", p->cldfbAna_fx != NULL); if (p->cldfbAna_fx != NULL) { rd_dump_CldfbFilterBank(b, p->cldfbAna_fx); } }
    { char b[256]; snprintf(b, sizeof b, "%scldfbBPF_fx.", pre); rd_put1(pre, "cldfbBPF_fx", p->cldfbBPF_fx != NULL); if (p->cldfbBPF_fx != NULL) { rd_dump_CldfbFilterBank(b, p->cldfbBPF_fx); } }
    { char b[256]; snprintf(b, sizeof b, "%scldfbSyn_fx.", pre); rd_put1(pre, "cldfbSyn_fx", p->cldfbSyn_fx != NULL); if (p->cldfbSyn_fx != NULL) { rd_dump_CldfbFilterBank(b, p->cldfbSyn_fx); } }
    rd_put_i16(pre, "last_active_bandsToZero_bwdec", (Word16 *)&p->last_active_bandsToZero_bwdec, 1);
    rd_put_i16(pre, "flag_NB_bwddec", (Word16 *)&p->flag_NB_bwddec, 1);
    rd_put_i16(pre, "last_flag_filter_NB", (Word16 *)&p->last_flag_filter_NB, 1);
    rd_put_i16(pre, "perc_bwddec", (Word16 *)&p->perc_bwddec, 1);
    rd_put_i16(pre, "active_frame_cnt_bwddec", (Word16 *)&p->active_frame_cnt_bwddec, 1);
    rd_put_i16(pre, "flag_buffer", (Word16 *)&p->flag_buffer, 20);
    rd_put_i16(pre, "total_frame_cnt_bwddec", (Word16 *)&p->total_frame_cnt_bwddec, 1);
    rd_put_i32(pre, "avg_nrg_LT", (Word32 *)&p->avg_nrg_LT, 1);
    { char b[256]; snprintf(b, sizeof b, "%shFdCngDec_fx.", pre); rd_put1(pre, "hFdCngDec_fx", p->hFdCngDec_fx != NULL); if (p->hFdCngDec_fx != NULL) { rd_dump_FdCngDec(b, p->hFdCngDec_fx); } }
    rd_put_i16(pre, "force_lpd_reset", (Word16 *)&p->force_lpd_reset, 1);
    { char b[256]; snprintf(b, sizeof b, "%sacelp_cfg.", pre); rd_dump_AcelpConfig(b, &p->acelp_cfg); }
    { char b[256]; snprintf(b, sizeof b, "%sacelp_cfg_rf.", pre); rd_dump_AcelpConfig(b, &p->acelp_cfg_rf); }
    { char b[256]; snprintf(b, sizeof b, "%stcx_cfg.", pre); rd_dump_TcxConfig(b, &p->tcx_cfg); }
    rd_put_i16(pre, "L_frameTCX", (Word16 *)&p->L_frameTCX, 1);
    rd_put_i16(pre, "m_decodeMode", (Word16 *)&p->m_decodeMode, 1);
    rd_put_i16(pre, "m_frame_type", (Word16 *)&p->m_frame_type, 1);
    rd_put_i16(pre, "m_old_frame_type", (Word16 *)&p->m_old_frame_type, 1);
    rd_put_i16(pre, "bits_frame", (Word16 *)&p->bits_frame, 1);
    rd_put_i16(pre, "bits_frame_core", (Word16 *)&p->bits_frame_core, 1);
    rd_put_i8(pre, "narrowBand", (signed char *)&p->narrowBand, 1);
    rd_put_i16(pre, "bits_common", (Word16 *)&p->bits_common, 1);
    rd_put_i8(pre, "last_is_cng", (signed char *)&p->last_is_cng, 1);
    rd_put_i16(pre, "old_syn_Overl", (Word16 *)&p->old_syn_Overl, 320);
    rd_put_i16(pre, "syn_Overl_TDAC", (Word16 *)&p->syn_Overl_TDAC, 320);
    rd_put_i16(pre, "syn_Overl_TDACFB", (Word16 *)&p->syn_Overl_TDACFB, 480);
    rd_put_i16(pre, "syn_Overl", (Word16 *)&p->syn_Overl, 320);
    rd_put_i16(pre, "syn_OverlFB", (Word16 *)&p->syn_OverlFB, 480);
    rd_put_i16(pre, "old_synth", (Word16 *)&p->old_synth, 1280);
    rd_put_i16(pre, "old_synth_len", (Word16 *)&p->old_synth_len, 1);
    rd_put_i16(pre, "old_synth_lenFB", (Word16 *)&p->old_synth_lenFB, 1);
    rd_put_i16(pre, "syn", (Word16 *)&p->syn, 17);
    rd_put_i16(pre, "bpf_gain_param", (Word16 *)&p->bpf_gain_param, 1);
    rd_put_i16(pre, "L_frame_past", (Word16 *)&p->L_frame_past, 1);
    rd_put_i16(pre, "L_frameTCX_past", (Word16 *)&p->L_frameTCX_past, 1);
    rd_put_i16(pre, "lsfold_uw", (Word16 *)&p->lsfold_uw, 16);
    rd_put_i16(pre, "lspold_uw", (Word16 *)&p->lspold_uw, 16);
    rd_put_i16(pre, "seed_tcx_plc", (Word16 *)&p->seed_tcx_plc, 1);
    rd_put_i16(pre, "past_gpit", (Word16 *)&p->past_gpit, 1);
    rd_put_i32(pre, "past_gcode", (Word32 *)&p->past_gcode, 1);
    rd_put_i16(pre, "lsf_cng", (Word16 *)&p->lsf_cng, 16);
    rd_put_i16(pre, "lspold_cng", (Word16 *)&p->lspold_cng, 16);
    rd_put_i8(pre, "plcBackgroundNoiseUpdated", (signed char *)&p->plcBackgroundNoiseUpdated, 1);
    rd_put_i16(pre, "lsp_q_cng", (Word16 *)&p->lsp_q_cng, 16);
    rd_put_i16(pre, "old_lsp_q_cng", (Word16 *)&p->old_lsp_q_cng, 16);
    rd_put_i16(pre, "lsf_q_cng", (Word16 *)&p->lsf_q_cng, 16);
    rd_put_i16(pre, "old_lsf_q_cng", (Word16 *)&p->old_lsf_q_cng, 16);
    rd_put_i16(pre, "Aq_cng", (Word16 *)&p->Aq_cng, 102);
    rd_put_i16(pre, "mem_syn_unv_back", (Word16 *)&p->mem_syn_unv_back, 16);
    rd_put_i16(pre, "last_gain_syn_deemph", (Word16 *)&p->last_gain_syn_deemph, 1);
    rd_put_i16(pre, "last_gain_syn_deemph_e", (Word16 *)&p->last_gain_syn_deemph_e, 1);
    rd_put_i16(pre, "last_concealed_gain_syn_deemph", (Word16 *)&p->last_concealed_gain_syn_deemph, 1);
    rd_put_i16(pre, "last_concealed_gain_syn_deemph_e", (Word16 *)&p->last_concealed_gain_syn_deemph_e, 1);
    rd_put_i8(pre, "enableTcxLpc", (signed char *)&p->enableTcxLpc, 1);
    rd_put_i8(pre, "envWeighted", (signed char *)&p->envWeighted, 1);
    rd_put_i16(pre, "nb_subfr", (Word16 *)&p->nb_subfr, 1);
    rd_put_i16(pre, "fscale", (Word16 *)&p->fscale, 1);
    rd_put_i16(pre, "fscale_old", (Word16 *)&p->fscale_old, 1);
    rd_put_i32(pre, "sr_core", (Word32 *)&p->sr_core, 1);
    rd_put_i16(pre, "pit_min", (Word16 *)&p->pit_min, 1);
    rd_put_i16(pre, "pit_fr1", (Word16 *)&p->pit_fr1, 1);
    rd_put_i16(pre, "pit_fr1b", (Word16 *)&p->pit_fr1b, 1);
    rd_put_i16(pre, "pit_fr2", (Word16 *)&p->pit_fr2, 1);
    rd_put_i16(pre, "pit_max", (Word16 *)&p->pit_max, 1);
    rd_put_i16(pre, "pit_res_max", (Word16 *)&p->pit_res_max, 1);
    rd_put_i16(pre, "pit_res_max_past", (Word16 *)&p->pit_res_max_past, 1);
    rd_put_i16(pre, "pit_max_TCX", (Word16 *)&p->pit_max_TCX, 1);
    rd_put_i16(pre, "pit_min_TCX", (Word16 *)&p->pit_min_TCX, 1);
    rd_put_i16(pre, "preemph_fac", (Word16 *)&p->preemph_fac, 1);
    rd_put_i16(pre, "gamma", (Word16 *)&p->gamma, 1);
    rd_put_i16(pre, "inv_gamma", (Word16 *)&p->inv_gamma, 1);
    rd_put_i16(pre, "mem_Aq", (Word16 *)&p->mem_Aq, 85);
    rd_put_i16(pre, "last_core_bfi", (Word16 *)&p->last_core_bfi, 1);
    rd_put_i16(pre, "nbLostCmpt", (Word16 *)&p->nbLostCmpt, 1);
    rd_put_i16(pre, "prev_nbLostCmpt", (Word16 *)&p->prev_nbLostCmpt, 1);
    rd_put_i16(pre, "mode_lvq", (Word16 *)&p->mode_lvq, 1);
    rd_put_i32(pre, "old_fpitch", (Word32 *)&p->old_fpitch, 1);
    rd_put_i32(pre, "old_fpitchFB", (Word32 *)&p->old_fpitchFB, 1);
    rd_put_i16(pre, "clas_dec", (Word16 *)&p->clas_dec, 1);
    rd_put_i16(pre, "mem_pitch_gain", (Word16 *)&p->mem_pitch_gain, 12);
    rd_put_i8(pre, "plc_use_future_lag", (signed char *)&p->plc_use_future_lag, 1);
    rd_put_i16(pre, "prev_widow_left_rect", (Word16 *)&p->prev_widow_left_rect, 1);
    rd_put_i32(pre, "Mode2_lp_gainc", (Word32 *)&p->Mode2_lp_gainc, 1);
    rd_put_i32(pre, "Mode2_lp_gainp", (Word32 *)&p->Mode2_lp_gainp, 1);
    rd_put_i16(pre, "conCngLevelBackgroundTrace", (Word16 *)&p->conCngLevelBackgroundTrace, 1);
    rd_put_i16(pre, "conCngLevelBackgroundTrace_e", (Word16 *)&p->conCngLevelBackgroundTrace_e, 1);
    rd_put_i16(pre, "conNoiseLevelMemory", (Word16 *)&p->conNoiseLevelMemory, 50);
    rd_put_i16(pre, "conNoiseLevelMemory_e", (Word16 *)&p->conNoiseLevelMemory_e, 50);
    rd_put_i16(pre, "conNoiseLevelIndex", (Word16 *)&p->conNoiseLevelIndex, 1);
    rd_put_i16(pre, "conCurrLevelIndex", (Word16 *)&p->conCurrLevelIndex, 1);
    rd_put_i16(pre, "conLastFrameLevel", (Word16 *)&p->conLastFrameLevel, 1);
    rd_put_i16(pre, "conLastFrameLevel_e", (Word16 *)&p->conLastFrameLevel_e, 1);
    rd_put_i16(pre, "old_gaintcx_bfi", (Word16 *)&p->old_gaintcx_bfi, 1);
    rd_put_i16(pre, "old_gaintcx_bfi_e", (Word16 *)&p->old_gaintcx_bfi_e, 1);
    rd_put_i16(pre, "cummulative_damping_tcx", (Word16 *)&p->cummulative_damping_tcx, 1);
    rd_put_i16(pre, "cummulative_damping", (Word16 *)&p->cummulative_damping, 1);
    rd_put_i16(pre, "cngTDLevel", (Word16 *)&p->cngTDLevel, 1);
    rd_put_i16(pre, "cngTDLevel_e", (Word16 *)&p->cngTDLevel_e, 1);
    rd_put_i16(pre, "conceal_eof_gain", (Word16 *)&p->conceal_eof_gain, 1);
    rd_put_i16(pre, "damping", (Word16 *)&p->damping, 1);
    rd_put_i16(pre, "gainHelper", (Word16 *)&p->gainHelper, 1);
    rd_put_i16(pre, "gainHelper_e", (Word16 *)&p->gainHelper_e, 1);
    rd_put_i16(pre, "stepCompensate", (Word16 *)&p->stepCompensate, 1);
    rd_put_i16(pre, "stepCompensate_e", (Word16 *)&p->stepCompensate_e, 1);
    rd_put_i16(pre, "reset_mem_AR", (Word16 *)&p->reset_mem_AR, 1);
    rd_put_i16(pre, "tcxConceal_recalc_exc", (Word16 *)&p->tcxConceal_recalc_exc, 1);
    rd_put_i16(pre, "classifier_Q_mem_syn", (Word16 *)&p->classifier_Q_mem_syn, 1);
    rd_put_i16(pre, "rate_switching_init", (Word16 *)&p->rate_switching_init, 1);
    rd_put_i16(pre, "lpcQuantization", (Word16 *)&p->lpcQuantization, 1);
    rd_put_i16(pre, "numlpc", (Word16 *)&p->numlpc, 1);
    rd_put_i16(pre, "TcxBandwidth", (Word16 *)&p->TcxBandwidth, 1);
    { char b[256]; snprintf(b, sizeof b, "%spfstat.", pre); rd_dump_Pfstat(b, &p->pfstat); }
    rd_put_i16(pre, "psf_lp_noise_fx", (Word16 *)&p->psf_lp_noise_fx, 1);
    rd_put_i16(pre, "voice_fac", (Word16 *)&p->voice_fac, 1);
    rd_put_i8(pre, "tcxonly", (signed char *)&p->tcxonly, 1);
    rd_put_i16(pre, "resQBits", (Word16 *)&p->resQBits, 2);
    rd_put_i16(pre, "last_ctx_hm_enabled", (Word16 *)&p->last_ctx_hm_enabled, 1);
    rd_put_i8(pre, "tcxltp", (signed char *)&p->tcxltp, 1);
    rd_put_i16(pre, "tcxltp_gain", (Word16 *)&p->tcxltp_gain, 1);
    rd_put_i16(pre, "tcxltp_pitch_int", (Word16 *)&p->tcxltp_pitch_int, 1);
    rd_put_i16(pre, "tcxltp_pitch_fr", (Word16 *)&p->tcxltp_pitch_fr, 1);
    rd_put_i16(pre, "tcxltp_mem_in", (Word16 *)&p->tcxltp_mem_in, 12);
    rd_put_i16(pre, "tcxltp_mem_out", (Word16 *)&p->tcxltp_mem_out, 960);
    rd_put_i16(pre, "tcxltp_pitch_int_post_prev", (Word16 *)&p->tcxltp_pitch_int_post_prev, 1);
    rd_put_i16(pre, "tcxltp_pitch_fr_post_prev", (Word16 *)&p->tcxltp_pitch_fr_post_prev, 1);
    rd_put_i16(pre, "tcxltp_gain_post_prev", (Word16 *)&p->tcxltp_gain_post_prev, 1);
    rd_put_i16(pre, "tcxltp_filt_idx_prev", (Word16 *)&p->tcxltp_filt_idx_prev, 1);
    { char b[256]; snprintf(b, sizeof b, "%stonalMDCTconceal.", pre); rd_dump_Tonalmdctconceal(b, &p->tonalMDCTconceal); }
    rd_put_i8(pre, "tonal_mdct_plc_active", (signed char *)&p->tonal_mdct_plc_active, 1);
    rd_put_i8(pre, "last_tns_active", (signed char *)&p->last_tns_active, 1);
    rd_put_i8(pre, "second_last_tns_active", (signed char *)&p->second_last_tns_active, 1);
    rd_put_i16(pre, "second_last_core", (Word16 *)&p->second_last_core, 1);
    rd_put_i32(pre, "tcxltp_second_last_pitch", (Word32 *)&p->tcxltp_second_last_pitch, 1);
    rd_put_i32(pre, "tcxltp_third_last_pitch", (Word32 *)&p->tcxltp_third_last_pitch, 1);
    rd_put_i16(pre, "tcxltp_last_gain_unmodified", (Word16 *)&p->tcxltp_last_gain_unmodified, 1);
    rd_put_i16(pre, "FBTCXdelayBuf", (Word16 *)&p->FBTCXdelayBuf, 111);
    rd_put_i16(pre, "mem_syn_r", (Word16 *)&p->mem_syn_r, 60);
    rd_put_i16(pre, "rate_switching_reset", (Word16 *)&p->rate_switching_reset, 1);
    rd_put_i32(pre, "lp_error_ener", (Word32 *)&p->lp_error_ener, 1);
    rd_put_i32(pre, "mem_error", (Word32 *)&p->mem_error, 1);
    rd_put_i16(pre, "bpf_noise_buf", (Word16 *)&p->bpf_noise_buf, 320);
    rd_put1(pre, "p_bpf_noise_buf", p->p_bpf_noise_buf == NULL ? -1 : (long long)(p->p_bpf_noise_buf - p->bpf_noise_buf));
    rd_put_i8(pre, "enableGplc", (signed char *)&p->enableGplc, 1);
    rd_put_i16(pre, "flagGuidedAcelp", (Word16 *)&p->flagGuidedAcelp, 1);
    rd_put_i16(pre, "T0_4th", (Word16 *)&p->T0_4th, 1);
    rd_put_i16(pre, "guidedT0", (Word16 *)&p->guidedT0, 1);
    rd_put_i16(pre, "enablePlcWaveadjust", (Word16 *)&p->enablePlcWaveadjust, 1);
    rd_put_i16(pre, "tonality_flag", (Word16 *)&p->tonality_flag, 1);
    { char b[256]; snprintf(b, sizeof b, "%splcInfo.", pre); rd_dump_TPLCInfo(b, &p->plcInfo); }
    rd_put_i8(pre, "VAD", (signed char *)&p->VAD, 1);
    rd_put_i8(pre, "flag_cna", (signed char *)&p->flag_cna, 1);
    rd_put_i8(pre, "last_flag_cna", (signed char *)&p->last_flag_cna, 1);
    rd_put_i32(pre, "lp_noise", (Word32 *)&p->lp_noise, 1);
    rd_put_i16(pre, "seed_acelp", (Word16 *)&p->seed_acelp, 1);
    rd_put_i16(pre, "core_ext_mode", (Word16 *)&p->core_ext_mode, 1);
    rd_put_i8(pre, "dec_glr", (signed char *)&p->dec_glr, 1);
    rd_put_i16(pre, "dec_glr_idx", (Word16 *)&p->dec_glr_idx, 1);
    rd_put_i16(pre, "tcx_hm_LtpPitchLag", (Word16 *)&p->tcx_hm_LtpPitchLag, 1);
    rd_put_i16(pre, "tcx_lpc_shaped_ari", (Word16 *)&p->tcx_lpc_shaped_ari, 1);
    rd_put_i16(pre, "igf", (Word16 *)&p->igf, 1);
    { char b[256]; snprintf(b, sizeof b, "%shIGFDec.", pre); rd_dump_IgfdecInstance(b, &p->hIGFDec); }
    { char b[256]; snprintf(b, sizeof b, "%sscaleFactor.", pre); rd_dump_CldfbScaleFactor(b, &p->scaleFactor); }
    rd_put_i16(pre, "tec_tfa", (Word16 *)&p->tec_tfa, 1);
    rd_put_i16(pre, "tec_flag", (Word16 *)&p->tec_flag, 1);
    rd_put_i16(pre, "tfa_flag", (Word16 *)&p->tfa_flag, 1);
    { char b[256]; snprintf(b, sizeof b, "%stecDec_fx.", pre); rd_dump_TemporalEnvelopeCodingDecoderFx(b, &p->tecDec_fx); }
    rd_put_i16(pre, "con_tcx", (Word16 *)&p->con_tcx, 1);
    rd_put_i16(pre, "last_con_tcx", (Word16 *)&p->last_con_tcx, 1);
    rd_put_i16(pre, "old_ppp_mode_fx", (Word16 *)&p->old_ppp_mode_fx, 1);
    rd_put_i16(pre, "old_hb_synth_fx", (Word16 *)&p->old_hb_synth_fx, 960);
    rd_put_i16(pre, "prev_Q_exc_fr", (Word16 *)&p->prev_Q_exc_fr, 1);
    rd_put_i16(pre, "prev_Q_syn_fr", (Word16 *)&p->prev_Q_syn_fr, 1);
    rd_put_i16(pre, "writeFECoffset", (Word16 *)&p->writeFECoffset, 1);
}
static void rd_fill_DecoderState(Decoder_State_fx *p)
{
    rd_fill_i16((Word16 *)&p->codec_mode, 1);
    rd_fill_i16((Word16 *)&p->mdct_sw_enable, 1);
    rd_fill_i16((Word16 *)&p->mdct_sw, 1);
    rd_fill_i16((Word16 *)&p->last_codec_mode, 1);
    rd_fill_i16((Word16 *)&p->next_bit_pos_fx, 1);
    rd_fill_i16((Word16 *)&p->bitstreamformat, 1);
    rd_fill_i16((Word16 *)&p->sdp_hf_only, 1);
    rd_fill_i16((Word16 *)&p->amrwb_rfc4867_flag, 1);
    rd_fill_i16((Word16 *)&p->total_num_bits, 1);
    rd_fill_i16((Word16 *)&p->BER_detect, 1);
    rd_fill_i32((Word32 *)&p->total_brate_fx, 1);
    rd_fill_i32((Word32 *)&p->last_total_brate_fx, 1);
    rd_fill_i32((Word32 *)&p->last_total_brate_ber_fx, 1);
    rd_fill_i16((Word16 *)&p->core_fx, 1);
    rd_fill_i32((Word32 *)&p->core_brate_fx, 1);
    rd_fill_i32((Word32 *)&p->last_core_brate_fx, 1);
    rd_fill_i16((Word16 *)&p->extl_fx, 1);
    rd_fill_i16((Word16 *)&p->last_extl_fx, 1);
    rd_fill_i32((Word32 *)&p->extl_brate_fx, 1);
    rd_fill_i16((Word16 *)&p->L_frame_fx, 1);
    rd_fill_i16((Word16 *)&p->bwidth_fx, 1);
    rd_fill_i16((Word16 *)&p->Opt_AMR_WB_fx, 1);
    rd_fill_i16((Word16 *)&p->Opt_VOIP_fx, 1);
    rd_fill_i16((Word16 *)&p->ini_frame_fx, 1);
    rd_fill_i16((Word16 *)&p->CNG_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_ft_speech_fx, 1);
    rd_fill_i16((Word16 *)&p->old_exc_fx, 480);
    rd_fill_i16((Word16 *)&p->old_excFB_fx, 960);
    rd_fill_i16((Word16 *)&p->lsp_old_fx, 16);
    rd_fill_i16((Word16 *)&p->lsf_old_fx, 16);
    rd_fill_i32((Word32 *)&p->offset_scale1_fx, 516);
    rd_fill_i32((Word32 *)&p->offset_scale2_fx, 516);
    rd_fill_i32((Word32 *)&p->offset_scale1_p_fx, 584);
    rd_fill_i32((Word32 *)&p->offset_scale2_p_fx, 584);
    rd_fill_i16((Word16 *)&p->no_scales_fx, 256);
    rd_fill_i16((Word16 *)&p->no_scales_p_fx, 290);
    rd_fill_i16((Word16 *)&p->tilt_code_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_syn2_fx, 16);
    rd_fill_i16((Word16 *)&p->mem_syn1_fx, 16);
    rd_fill_i16((Word16 *)&p->mem_syn3_fx, 16);
    rd_fill_i16((Word16 *)&p->mem_deemph_fx, 1);
    rd_fill_i32((Word32 *)&p->L_mem_hp_out_fx, 5);
    rd_fill_i16((Word16 *)&p->mem_MA_fx, 16);
    rd_fill_i16((Word16 *)&p->mem_AR_fx, 16);
    rd_fill_i16((Word16 *)&p->stab_fac_fx, 1);
    rd_fill_i16((Word16 *)&p->stab_fac_smooth_fx, 1);
    rd_fill_i16((Word16 *)&p->last_coder_type_fx, 1);
    rd_fill_i16((Word16 *)&p->agc_mem_fx, 2);
    rd_fill_i16((Word16 *)&p->past_qua_en_fx, 4);
    rd_fill_i16((Word16 *)&p->mid_lsf_int_fx, 1);
    rd_fill_i16((Word16 *)&p->safety_net_fx, 1);
    rd_fill_i16((Word16 *)&p->seed_tcx_fx, 1);
    rd_fill_i16((Word16 *)&p->GSC_noisy_speech_fx, 1);
    rd_fill_i16((Word16 *)&p->Last_GSC_noisy_speech_flag_fx, 1);
    rd_fill_i16((Word16 *)&p->cor_strong_limit_fx, 1);
    rd_fill_i16((Word16 *)&p->old_y_gain_fx, 16);
    rd_fill_i16((Word16 *)&p->noise_lev_fx, 1);
    rd_fill_i16((Word16 *)&p->lt_ener_per_band_fx, 16);
    rd_fill_i32((Word32 *)&p->Last_frame_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->Last_GSC_spectrum_fx, 256);
    rd_fill_i16((Word16 *)&p->Last_GSC_pit_band_idx_fx, 1);
    rd_fill_i16((Word16 *)&p->last_exc_dct_in_fx, 256);
    rd_fill_i16((Word16 *)&p->last_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->last_bitallocation_band_fx, 6);
    rd_fill_i32((Word32 *)&p->gc_threshold_fx, 1);
    { rd_fill_DispMem(&p->dm_fx); }
    rd_fill_i16((Word16 *)&p->prev_r_fx, 1);
    rd_fill_i16((Word16 *)&p->fmerit_w_sm_fx, 1);
    rd_fill_i16((Word16 *)&p->frame_count_fx, 1);
    rd_fill_i16((Word16 *)&p->ne_min_fx, 1);
    rd_fill_i16((Word16 *)&p->fmerit_m_sm_fx, 1);
    rd_fill_i16((Word16 *)&p->voice_fac_amr_wb_hf, 1);
    rd_fill_i16((Word16 *)&p->unvoicing_fx, 1);
    rd_fill_i16((Word16 *)&p->unvoicing_sm_fx, 1);
    rd_fill_i16((Word16 *)&p->unvoicing_flag_fx, 1);
    rd_fill_i16((Word16 *)&p->voicing_flag_fx, 1);
    rd_fill_i16((Word16 *)&p->start_band_old_fx, 1);
    rd_fill_i32((Word32 *)&p->OptCrit_old_fx, 1);
    rd_fill_i16((Word16 *)&p->seed2_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_hp400_fx, 6);
    rd_fill_i16((Word16 *)&p->mem_hf_fx, 30);
    rd_fill_i16((Word16 *)&p->mem_syn_hf_fx, 16);
    rd_fill_i16((Word16 *)&p->delay_syn_hf_fx, 20);
    rd_fill_i16((Word16 *)&p->mem_hp_interp_fx, 13);
    rd_fill_i16((Word16 *)&p->unv_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->uv_count_fx, 1);
    rd_fill_i16((Word16 *)&p->act_count_fx, 1);
    rd_fill_i32((Word32 *)&p->ge_sm_fx, 1);
    rd_fill_i16((Word16 *)&p->lspold_s_fx, 16);
    rd_fill_i16((Word16 *)&p->noimix_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->min_alpha_fx, 1);
    rd_fill_i16((Word16 *)&p->Q_stat_noise, 1);
    rd_fill_i16((Word16 *)&p->exc_pe_fx, 1);
    rd_fill_i16((Word16 *)&p->Q_stat_noise_ge, 1);
    rd_fill_i16((Word16 *)&p->bfi_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_bfi_fx, 1);
    rd_fill_i16((Word16 *)&p->seed_fx, 1);
    rd_fill_i16((Word16 *)&p->lp_ener_FER_fx, 1);
    rd_fill_i16((Word16 *)&p->last_good_fx, 1);
    rd_fill_i16((Word16 *)&p->lp_gainc_fx, 1);
    rd_fill_i16((Word16 *)&p->lp_gainp_fx, 1);
    rd_fill_i32((Word32 *)&p->lp_ener_fx, 1);
    rd_fill_i32((Word32 *)&p->enr_old_fx, 1);
    rd_fill_i16((Word16 *)&p->bfi_pitch_fx, 1);
    rd_fill_i16((Word16 *)&p->bfi_pitch_frame_fx, 1);
    rd_fill_i32((Word32 *)&p->old_pitch_buf_fx, 12);
    rd_fill_i16((Word16 *)&p->upd_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->scaling_flag, 1);
    rd_fill_i32((Word32 *)&p->lp_ener_FEC_av, 1);
    rd_fill_i32((Word32 *)&p->lp_ener_FEC_max, 1);
    rd_fill_i16((Word16 *)&p->old_enr_LP, 1);
    rd_fill_i16((Word16 *)&p->lsfoldbfi0_fx, 16);
    rd_fill_i16((Word16 *)&p->lsfoldbfi1_fx, 16);
    rd_fill_i16((Word16 *)&p->lsf_adaptive_mean_fx, 16);
    rd_fill_i16((Word16 *)&p->decision_hyst_fx, 1);
    rd_fill_i16((Word16 *)&p->old_exc2_fx, 320);
    rd_fill_i16((Word16 *)&p->old_syn2_fx, 320);
    rd_fill_i16((Word16 *)&p->relax_prev_lsf_interp_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_syn_clas_estim_fx, 258);
    rd_fill_i16((Word16 *)&p->tilt_swb_fec_fx, 1);
    rd_fill_i16((Word16 *)&p->cng_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->lspCNG_fx, 16);
    rd_fill_i16((Word16 *)&p->first_CNG_fx, 1);
    rd_fill_i32((Word32 *)&p->Enew_fx, 1);
    rd_fill_i16((Word16 *)&p->old_enr_index_fx, 1);
    rd_fill_i16((Word16 *)&p->cng_ener_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->cng_ener_seed1_fx, 1);
    rd_fill_i16((Word16 *)&p->last_allow_cn_step_fx, 1);
    rd_fill_i16((Word16 *)&p->ho_hist_size_fx, 1);
    rd_fill_i16((Word16 *)&p->ho_hist_ptr_fx, 1);
    rd_fill_i32((Word32 *)&p->ho_sid_bw_fx, 1);
    rd_fill_i16((Word16 *)&p->ho_lsp_hist_fx, 128);
    rd_fill_i32((Word32 *)&p->ho_ener_hist_fx, 8);
    rd_fill_i32((Word32 *)&p->ho_env_hist_fx, 160);
    rd_fill_i16((Word16 *)&p->act_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->ho_circ_size_fx, 1);
    rd_fill_i16((Word16 *)&p->ho_circ_ptr_fx, 1);
    rd_fill_i16((Word16 *)&p->ho_lsp_circ_fx, 128);
    rd_fill_i32((Word32 *)&p->ho_ener_circ_fx, 8);
    rd_fill_i32((Word32 *)&p->ho_env_circ_fx, 160);
    rd_fill_i16((Word16 *)&p->num_ho_fx, 1);
    rd_fill_i16((Word16 *)&p->ho_16k_lsp_fx, 8);
    rd_fill_i16((Word16 *)&p->CNG_mode_fx, 1);
    rd_fill_i32((Word32 *)&p->last_active_brate_fx, 1);
    rd_fill_i16((Word16 *)&p->last_CNG_L_frame_fx, 1);
    rd_fill_i16((Word16 *)&p->act_cnt2_fx, 1);
    rd_fill_i16((Word16 *)&p->cng_type_fx, 1);
    rd_fill_i16((Word16 *)&p->last_cng_type_fx, 1);
    rd_fill_i32((Word32 *)&p->old_env_fx, 20);
    rd_fill_i32((Word32 *)&p->lp_env_fx, 20);
    rd_fill_i16((Word16 *)&p->exc_mem_fx, 24);
    rd_fill_i16((Word16 *)&p->exc_mem1_fx, 30);
    rd_fill_i16((Word16 *)&p->bpf_off_fx, 1);
    rd_fill_i16((Word16 *)&p->pst_old_syn_fx, 290);
    rd_fill_i16((Word16 *)&p->pst_mem_deemp_err_fx, 1);
    rd_fill_i16((Word16 *)&p->pst_lp_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->Track_on_hist_fx, 10);
    rd_fill_i16((Word16 *)&p->vibrato_hist_fx, 10);
    rd_fill_i16((Word16 *)&p->psf_att_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_mean_pit_fx, 10);
    rd_fill_i16((Word16 *)&p->Ng_ener_ST_fx, 1);
    rd_fill_i16((Word16 *)&p->last_L_frame_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_preemp_preQ_fx, 1);
    rd_fill_i16((Word16 *)&p->last_nq_preQ_fx, 1);
    rd_fill_i16((Word16 *)&p->use_acelp_preq, 1);
    rd_fill_i16((Word16 *)&p->UV_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->LT_UV_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->Last_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->lt_diff_etot_fx, 40);
    rd_fill_i16((Word16 *)&p->old_Aq_fx, 68);
    rd_fill_i16((Word16 *)&p->lt_voice_fac_fx, 1);
    rd_fill_i16((Word16 *)&p->last_ppp_mode_dec_fx, 1);
    rd_fill_i16((Word16 *)&p->ppp_mode_dec_fx, 1);
    rd_fill_i16((Word16 *)&p->last_nelp_mode_dec_fx, 1);
    rd_fill_i16((Word16 *)&p->nelp_mode_dec_fx, 1);
    rd_fill_i16((Word16 *)&p->firstTime_voiceddec_fx, 1);
    rd_fill_i16((Word16 *)&p->dtfs_dec_a_fx, 102);
    rd_fill_i16((Word16 *)&p->dtfs_dec_b_fx, 102);
    rd_fill_i16((Word16 *)&p->dtfs_dec_lag_fx, 1);
    rd_fill_i16((Word16 *)&p->dtfs_dec_nH_fx, 1);
    rd_fill_i16((Word16 *)&p->dtfs_dec_nH_4kHz_fx, 1);
    rd_fill_i16((Word16 *)&p->dtfs_dec_upper_cut_off_freq_of_interest_fx, 1);
    rd_fill_i16((Word16 *)&p->dtfs_dec_upper_cut_off_freq_fx, 1);
    rd_fill_i16((Word16 *)&p->ph_offset_D_fx, 1);
    rd_fill_i16((Word16 *)&p->lastLgainD_fx, 1);
    rd_fill_i16((Word16 *)&p->lastHgainD_fx, 1);
    rd_fill_i16((Word16 *)&p->lasterbD_fx, 24);
    rd_fill_i16((Word16 *)&p->dtfs_dec_Q, 1);
    rd_fill_i32((Word32 *)&p->bp1_filt_mem_nb_dec_fx, 14);
    rd_fill_i16((Word16 *)&p->bp1_filt_mem_wb_dec_fx, 8);
    rd_fill_i16((Word16 *)&p->shape1_filt_mem_dec_fx, 10);
    rd_fill_i16((Word16 *)&p->shape2_filt_mem_dec_fx, 10);
    rd_fill_i16((Word16 *)&p->shape3_filt_mem_dec_fx, 10);
    rd_fill_i16((Word16 *)&p->nelp_dec_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->FadeScale_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_gain_pit_dec_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_tilt_code_dec_fx, 1);
    rd_fill_i16((Word16 *)&p->tilt_code_dec_fx, 5);
    rd_fill_i16((Word16 *)&p->rf_frame_type, 1);
    rd_fill_i16((Word16 *)&p->use_partial_copy, 1);
    rd_fill_i16((Word16 *)&p->prev_use_partial_copy, 1);
    rd_fill_i16((Word16 *)&p->rf_flag, 1);
    rd_fill_i16((Word16 *)&p->rf_flag_last, 1);
    rd_fill_i16((Word16 *)&p->rf_fec_offset, 1);
    rd_fill_i16((Word16 *)&p->next_coder_type, 1);
    rd_fill_i16((Word16 *)&p->prev_rf_frame_type, 1);
    rd_fill_i16((Word16 *)&p->rf_target_bits, 1);
    rd_fill_i16((Word16 *)&p->rf_indx_nelp_fid, 1);
    rd_fill_i16((Word16 *)&p->rf_indx_nelp_iG1, 1);
    rd_fill_i16((Word16 *)&p->rf_indx_nelp_iG2, 2);
    rd_fill_i16((Word16 *)&p->rf_indx_tbeGainFr, 1);
    rd_fill_i16((Word16 *)&p->bwe_highrate_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->t_audio_prev_fx, 496);
    rd_fill_i16((Word16 *)&p->t_audio_prev_fx_exp, 4);
    rd_fill_i16((Word16 *)&p->old_is_transient_hr_bwe_fx, 1);
    rd_fill_i32((Word32 *)&p->L_mem_EnergyLT_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_EnergyLT_fx_exp, 1);
    rd_fill_i16((Word16 *)&p->synth_history_fx, 2496);
    rd_fill_i16((Word16 *)&p->old_out_fx, 960);
    rd_fill_i16((Word16 *)&p->old_out_LB_fx, 640);
    rd_fill_i16((Word16 *)&p->Q_old_wtda_LB, 1);
    rd_fill_i16((Word16 *)&p->Q_old_wtda, 1);
    rd_fill_i16((Word16 *)&p->Q_old_postdec, 1);
    rd_fill_i16((Word16 *)&p->Qprev_synth_buffer_fx, 1);
    rd_fill_i32((Word32 *)&p->oldIMDCTout_fx, 80);
    rd_fill_i16((Word16 *)&p->prev_oldauOut_fx, 160);
    rd_fill_i16((Word16 *)&p->old_auOut_2fr_fx, 320);
    rd_fill_i16((Word16 *)&p->old_out_pha_fx, 140);
    rd_fill_i16((Word16 *)&p->diff_energy_fx, 1);
    rd_fill_i32((Word32 *)&p->old_coeffs_fx, 160);
    rd_fill_i16((Word16 *)&p->stat_mode_out_fx, 1);
    rd_fill_i16((Word16 *)&p->stat_mode_old_fx, 1);
    rd_fill_i16((Word16 *)&p->phase_mat_flag_fx, 1);
    rd_fill_i16((Word16 *)&p->phase_mat_next_fx, 1);
    rd_fill_i16((Word16 *)&p->old_Min_ind_fx, 1);
    rd_fill_i16((Word16 *)&p->old_is_transient_fx, 3);
    rd_fill_i16((Word16 *)&p->old_bfi_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_old_bfi_fx, 1);
    rd_fill_i32((Word32 *)&p->ynrm_values_fx, 21);
    rd_fill_i32((Word32 *)&p->r_p_values_fx, 6);
    rd_fill_i16((Word16 *)&p->Norm_gain_fx, 18);
    rd_fill_i16((Word16 *)&p->HQ_FEC_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->energy_MA_Curr_fx, 2);
    rd_fill_i16((Word16 *)&p->last_core_fx, 1);
    rd_fill_i16((Word16 *)&p->last_core_bs_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_last_core_fx, 1);
    rd_fill_i16((Word16 *)&p->last_hq_core_type_fx, 1);
    rd_fill_i16((Word16 *)&p->last_L_frame_ori_fx, 1);
    rd_fill_i16((Word16 *)&p->previoussynth_fx, 960);
    rd_fill_i16((Word16 *)&p->old_synth_sw_fx, 429);
    rd_fill_i16((Word16 *)&p->delay_buf_out_fx, 60);
    rd_fill_i16((Word16 *)&p->mem_norm_fx, 27);
    rd_fill_i16((Word16 *)&p->mem_env_delta_fx, 1);
    rd_fill_i16((Word16 *)&p->no_att_hangover_fx, 1);
    rd_fill_i32((Word32 *)&p->energy_lt_fx, 1);
    rd_fill_i16((Word16 *)&p->hq_generic_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_noise_level_fx, 2);
    rd_fill_i16((Word16 *)&p->prev_hqswb_clas_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_R_fx, 1);
    rd_fill_i32((Word32 *)&p->prev_coeff_out_fx, 20);
    rd_fill_i16((Word16 *)&p->prev_SWB_peak_pos_fx, 4);
    rd_fill_i16((Word16 *)&p->old_Aq_12_8_fx, 17);
    rd_fill_i16((Word16 *)&p->old_Es_pred_fx, 1);
    rd_fill_i16((Word16 *)&p->HqVoicing_fx, 1);
    rd_fill_i16((Word16 *)&p->fer_samples_fx, 960);
    rd_fill_i32((Word32 *)&p->prev_normq_fx, 26);
    rd_fill_i32((Word32 *)&p->prev_env_fx, 26);
    rd_fill_i32((Word32 *)&p->last_ni_gain_fx, 32);
    rd_fill_i16((Word16 *)&p->last_env_fx, 32);
    rd_fill_i16((Word16 *)&p->last_max_pos_pulse_fx, 1);
    rd_fill_i16((Word16 *)&p->memfilt_lb_fx, 1);
    rd_fill_i32((Word32 *)&p->mean_prev_hb_fx, 1);
    rd_fill_i16((Word16 *)&p->smoothmem_fx, 1);
    rd_fill_i32((Word32 *)&p->mean_prev_fx, 1);
    rd_fill_i32((Word32 *)&p->mean_prev_nc_fx, 1);
    rd_fill_i16((Word16 *)&p->wmold_hb_fx, 1);
    rd_fill_i16((Word16 *)&p->prevflag_fx, 1);
    rd_fill_i16((Word16 *)&p->pastpre_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_frm_hfe2_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_stab_hfe2_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_ni_ratio_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_En_sb_fx, 4);
    rd_fill_u32((UWord32 *)&p->rc_low_fx, 1);
    rd_fill_u32((UWord32 *)&p->rc_range_fx, 1);
    rd_fill_u32((UWord32 *)&p->rc_help_fx, 1);
    rd_fill_i16((Word16 *)&p->rc_num_bits_fx, 1);
    rd_fill_i16((Word16 *)&p->rc_offset_fx, 1);
    rd_fill_i16((Word16 *)&p->rc_end_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_env_Q, 26);
    rd_fill_i16((Word16 *)&p->state_lpc_syn_fx, 10);
    rd_fill_i32((Word32 *)&p->mem_csfilt_fx, 2);
    rd_fill_i16((Word16 *)&p->state_syn_shbexc_fx, 20);
    rd_fill_i16((Word16 *)&p->syn_overlap_fx, 20);
    rd_fill_i16((Word16 *)&p->lsp_prevfrm_fx, 10);
    rd_fill_i32((Word32 *)&p->GainFrame_prevfrm_fx, 1);
    rd_fill_i16((Word16 *)&p->GainAttn_fx, 1);
    rd_fill_i16((Word16 *)&p->old_bwe_exc_fx, 578);
    rd_fill_i16((Word16 *)&p->bwe_seed_fx, 2);
    rd_fill_i32((Word32 *)&p->bwe_non_lin_prev_scale_fx, 1);
    rd_fill_i16((Word16 *)&p->old_bwe_exc_extended_fx, 12);
    rd_fill_i16((Word16 *)&p->last_voice_factor_fx, 1);
    rd_fill_i32((Word32 *)&p->genSHBsynth_Hilbert_Mem_fx, 21);
    rd_fill_i16((Word16 *)&p->mem_genSHBexc_filt_down_shb_fx, 7);
    rd_fill_i16((Word16 *)&p->mem_genSHBexc_filt_down_wb2_fx, 7);
    rd_fill_i16((Word16 *)&p->mem_genSHBexc_filt_down_wb3_fx, 7);
    rd_fill_i16((Word16 *)&p->genSHBsynth_state_lsyn_filt_shb_local_fx, 6);
    rd_fill_i16((Word16 *)&p->state_lsyn_filt_shb_fx, 6);
    rd_fill_i16((Word16 *)&p->state_lsyn_filt_dwn_shb_fx, 6);
    rd_fill_i16((Word16 *)&p->state_32and48k_WB_upsample_fx, 6);
    rd_fill_i16((Word16 *)&p->hb_prev_synth_buffer_fx, 111);
    rd_fill_i16((Word16 *)&p->old_bwe_delay_fx, 1);
    rd_fill_i16((Word16 *)&p->syn_dm_phase_fx, 1);
    rd_fill_i32((Word32 *)&p->fbbwe_hpf_mem_fx, 16);
    rd_fill_i16((Word16 *)&p->fbbwe_hpf_mem_fx_Q, 4);
    rd_fill_i32((Word32 *)&p->prev_wb_bwe_frame_pow_fx, 1);
    rd_fill_i32((Word32 *)&p->prev_swb_bwe_frame_pow_fx, 1);
    rd_fill_i32((Word32 *)&p->prev_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_ener_fx_Q, 1);
    rd_fill_i16((Word16 *)&p->prev_GainShape_fx, 1);
    rd_fill_i16((Word16 *)&p->fb_state_lpc_syn_fx, 10);
    rd_fill_i16((Word16 *)&p->prev_Q_bwe_exc_fb, 1);
    rd_fill_i16((Word16 *)&p->fb_tbe_demph_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_fbbwe_ratio_fx, 1);
    rd_fill_i16((Word16 *)&p->tilt_wb_fx, 1);
    rd_fill_i16((Word16 *)&p->tilt_swb_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_ener_shb_fx, 1);
    rd_fill_i32((Word32 *)&p->enerLH_fx, 1);
    rd_fill_i32((Word32 *)&p->prev_enerLH_fx, 1);
    rd_fill_i32((Word32 *)&p->enerLL_fx, 1);
    rd_fill_i32((Word32 *)&p->prev_enerLL_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_fractive_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_bws_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->bws_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->bws_cnt1_fx, 1);
    rd_fill_i16((Word16 *)&p->attenu_fx, 1);
    rd_fill_i16((Word16 *)&p->last_inner_frame_fx, 1);
    rd_fill_i16((Word16 *)&p->last_bwidth_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_weight1_fx, 1);
    rd_fill_i16((Word16 *)&p->t_audio_q_fx, 256);
    rd_fill_i16((Word16 *)&p->tbe_demph_fx, 1);
    rd_fill_i16((Word16 *)&p->tbe_premph_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_stp_swb_fx, 10);
    rd_fill_i16((Word16 *)&p->gain_prec_swb_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_zero_swb_fx, 10);
    rd_fill_i16((Word16 *)&p->swb_lsp_prev_interp_fx, 10);
    rd_fill_i32((Word32 *)&p->prev1_shb_ener_sf_fx, 1);
    rd_fill_i32((Word32 *)&p->prev2_shb_ener_sf_fx, 1);
    rd_fill_i32((Word32 *)&p->prev3_shb_ener_sf_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_res_shb_gshape_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_mixFactors_fx, 1);
    rd_fill_i16((Word16 *)&p->tilt_mem_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_lsf_diff_fx, 8);
    rd_fill_i16((Word16 *)&p->prev_tilt_para_fx, 1);
    rd_fill_i16((Word16 *)&p->cur_sub_Aq_fx, 17);
    rd_fill_i16((Word16 *)&p->lsf_idx_fx, 5);
    rd_fill_i16((Word16 *)&p->m_idx_fx, 1);
    rd_fill_i16((Word16 *)&p->grid_idx_fx, 1);
    rd_fill_i16((Word16 *)&p->idxSubGains_fx, 1);
    rd_fill_i16((Word16 *)&p->idxFrameGain_fx, 1);
    rd_fill_i16((Word16 *)&p->idx_shb_fr_gain_fx, 1);
    rd_fill_i16((Word16 *)&p->idx_res_gs_fx, 5);
    rd_fill_i16((Word16 *)&p->idx_mixFac_fx, 1);
    rd_fill_i16((Word16 *)&p->lsf_WB_fx, 1);
    rd_fill_i16((Word16 *)&p->gFrame_WB_fx, 1);
    rd_fill_i16((Word16 *)&p->idxGain_fx, 1);
    rd_fill_i16((Word16 *)&p->old_core_synth_fx, 320);
    rd_fill_i16((Word16 *)&p->old_tbe_synth_fx, 222);
    rd_fill_i16((Word16 *)&p->int_3_over_2_tbemem_dec_fx, 15);
    rd_fill_i16((Word16 *)&p->interpol_3_2_cng_dec_fx, 15);
    rd_fill_i16((Word16 *)&p->mem_resamp_HB_fx, 13);
    rd_fill_i16((Word16 *)&p->mem_resamp_HB_32k_fx, 7);
    rd_fill_i16((Word16 *)&p->old_wtda_wb_fx_exp, 1);
    rd_fill_i16((Word16 *)&p->L_old_wtda_swb_fx, 960);
    rd_fill_i16((Word16 *)&p->old_wtda_swb_fx_exp, 1);
    rd_fill_i16((Word16 *)&p->mem_imdct_exp_fx, 1);
    rd_fill_i16((Word16 *)&p->old_syn_12k8_16k_fx, 36);
    rd_fill_i16((Word16 *)&p->mem_deemph_old_syn_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_mode_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_SWB_fenv_fx, 14);
    rd_fill_i16((Word16 *)&p->prev_Energy_fx, 1);
    rd_fill_i32((Word32 *)&p->prev_Energy_wb_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_L_swb_norm_fx, 1);
    rd_fill_i16((Word16 *)&p->Seed_fx, 1);
    rd_fill_i16((Word16 *)&p->memExp1, 1);
    rd_fill_i16((Word16 *)&p->prev_frica_flag_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_imdct_fx, 960);
    rd_fill_i16((Word16 *)&p->prev_td_energy_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_weight_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_coder_type_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_flag_fx, 1);
    rd_fill_i16((Word16 *)&p->last_wb_bwe_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_frame_pow_exp, 1);
    rd_fill_i16((Word16 *)&p->prev_Qx, 1);
    rd_fill_i16((Word16 *)&p->prev_Q_bwe_exc, 1);
    rd_fill_i16((Word16 *)&p->prev_Q_synth, 1);
    rd_fill_i16((Word16 *)&p->prev_fb_ener_adjust_fx, 1);
    rd_fill_i16((Word16 *)&p->shb_cng_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->wb_cng_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->last_wb_cng_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->last_shb_cng_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->swb_cng_seed_fx, 1);
    rd_fill_i16((Word16 *)&p->lsp_shb_prev_prev_fx, 10);
    rd_fill_i16((Word16 *)&p->lsp_shb_prev_fx, 10);
    rd_fill_i16((Word16 *)&p->shb_dtx_count_fx, 1);
    rd_fill_i16((Word16 *)&p->last_vad_fx, 1);
    rd_fill_i16((Word16 *)&p->trans_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->burst_cnt_fx, 1);
    rd_fill_i16((Word16 *)&p->last_shb_ener_fx, 1);
    rd_fill_i16((Word16 *)&p->prev_sign_switch_fx, 16);
    rd_fill_i16((Word16 *)&p->prev_sign_switch_2_fx, 16);
    rd_fill_i16((Word16 *)&p->time_offs_fx, 1);
    rd_fill_i16((Word16 *)&p->X_sav_fx, 1536);
    rd_fill_i16((Word16 *)&p->Q_X_sav, 1);
    rd_fill_i16((Word16 *)&p->num_p_fx, 1);
    rd_fill_i16((Word16 *)&p->plocs_fx, 385);
    rd_fill_i32((Word32 *)&p->plocsi_fx, 385);
    rd_fill_i16((Word16 *)&p->env_stab_fx, 1);
    rd_fill_i16((Word16 *)&p->mem_norm_hqfec_fx, 27);
    rd_fill_i16((Word16 *)&p->mem_env_delta_hqfec_fx, 1);
    rd_fill_i16((Word16 *)&p->env_stab_plc_fx, 1);
    rd_fill_i16((Word16 *)&p->env_stab_state_p_fx, 2);
    rd_fill_i16((Word16 *)&p->envstabplc_hocnt_fx, 1);
    rd_fill_i16((Word16 *)&p->mag_chg_1st_fx, 9);
    rd_fill_i16((Word16 *)&p->Xavg_fx, 9);
    rd_fill_i16((Word16 *)&p->beta_mute_fx, 1);
    rd_fill_i16((Word16 *)&p->last_fec_fx, 1);
    rd_fill_i16((Word16 *)&p->ph_ecu_HqVoicing_fx, 1);
    rd_fill_i16((Word16 *)&p->oldHqVoicing_fx, 1);
    rd_fill_i16((Word16 *)&p->oldgapsynth_fx, 960);
    rd_fill_i16((Word16 *)&p->ph_ecu_active_fx, 1);
    rd_fill_i16((Word16 *)&p->ni_seed_forfec, 1);
    rd_fill_i16((Word16 *)&p->ber_occured_in_pvq, 1);
    rd_fill_i16((Word16 *)&p->LDm_mem_etot_fx, 1);
    rd_fill_i16((Word16 *)&p->LDm_last_music_flag_fx, 1);
    rd_fill_i16((Word16 *)&p->LDm_nb_thr_1_fx, 1);
    rd_fill_i16((Word16 *)&p->LDm_nb_thr_3_fx, 1);
    rd_fill_i16((Word16 *)&p->dct_post_old_exc_fx, 448);
    rd_fill_i16((Word16 *)&p->LDm_thres_fx, 4);
    rd_fill_i16((Word16 *)&p->LDm_lt_diff_etot_fx, 40);
    rd_fill_i16((Word16 *)&p->LDm_enh_lp_gbin_fx, 640);
    rd_fill_i32((Word32 *)&p->LDm_enh_lf_EO_fx, 640);
    rd_fill_i16((Word16 *)&p->LDm_enh_min_ns_gain_fx, 1);
    rd_fill_i32((Word32 *)&p->LDm_bckr_noise_fx, 20);
    rd_fill_i16((Word16 *)&p->filt_lfE_fx, 640);
    rd_fill_i16((Word16 *)&p->last_nonfull_music_fx, 1);
    rd_fill_i16((Word16 *)&p->Old_ener_Q, 1);
    rd_fill_i16((Word16 *)&p->Q_exc, 1);
    rd_fill_i16((Word16 *)&p->prev_Q_exc, 1);
    rd_fill_i16((Word16 *)&p->Q_subfr, 5);
    rd_fill_i16((Word16 *)&p->prev_Q_bwe_syn, 1);
    rd_fill_i16((Word16 *)&p->prev_Q_bwe_syn2, 1);
    rd_fill_i16((Word16 *)&p->Q_syn2, 1);
    rd_fill_i16((Word16 *)&p->Q_syn, 1);
    rd_fill_i16((Word16 *)&p->prev_Q_syn, 1);
    rd_fill_i16((Word16 *)&p->prev_hb_synth_fx_exp, 1);
    rd_fill_i16((Word16 *)&p->prev_synth_buffer_fx, 51);
    rd_fill_i16((Word16 *)&p->prev_lpc_wb_fx, 6);
    rd_fill_i16((Word16 *)&p->GainShape_Delay, 8);
    rd_fill_i16((Word16 *)&p->vbr_hw_BWE_disable_dec_fx, 1);
    rd_fill_i16((Word16 *)&p->last_vbr_hw_BWE_disable_dec_fx, 1);
    if (p->cldfbAna_fx != NULL) rd_fill_CldfbFilterBank(p->cldfbAna_fx);
    if (p->cldfbBPF_fx != NULL) rd_fill_CldfbFilterBank(p->cldfbBPF_fx);
    if (p->cldfbSyn_fx != NULL) rd_fill_CldfbFilterBank(p->cldfbSyn_fx);
    rd_fill_i16((Word16 *)&p->last_active_bandsToZero_bwdec, 1);
    rd_fill_i16((Word16 *)&p->flag_NB_bwddec, 1);
    rd_fill_i16((Word16 *)&p->last_flag_filter_NB, 1);
    rd_fill_i16((Word16 *)&p->perc_bwddec, 1);
    rd_fill_i16((Word16 *)&p->active_frame_cnt_bwddec, 1);
    rd_fill_i16((Word16 *)&p->flag_buffer, 20);
    rd_fill_i16((Word16 *)&p->total_frame_cnt_bwddec, 1);
    rd_fill_i32((Word32 *)&p->avg_nrg_LT, 1);
    if (p->hFdCngDec_fx != NULL) rd_fill_FdCngDec(p->hFdCngDec_fx);
    rd_fill_i16((Word16 *)&p->force_lpd_reset, 1);
    { rd_fill_AcelpConfig(&p->acelp_cfg); }
    { rd_fill_AcelpConfig(&p->acelp_cfg_rf); }
    { rd_fill_TcxConfig(&p->tcx_cfg); }
    rd_fill_i16((Word16 *)&p->L_frameTCX, 1);
    rd_fill_i16((Word16 *)&p->m_decodeMode, 1);
    rd_fill_i16((Word16 *)&p->m_frame_type, 1);
    rd_fill_i16((Word16 *)&p->m_old_frame_type, 1);
    rd_fill_i16((Word16 *)&p->bits_frame, 1);
    rd_fill_i16((Word16 *)&p->bits_frame_core, 1);
    rd_fill_i8((signed char *)&p->narrowBand, 1);
    rd_fill_i16((Word16 *)&p->bits_common, 1);
    rd_fill_i8((signed char *)&p->last_is_cng, 1);
    rd_fill_i16((Word16 *)&p->old_syn_Overl, 320);
    rd_fill_i16((Word16 *)&p->syn_Overl_TDAC, 320);
    rd_fill_i16((Word16 *)&p->syn_Overl_TDACFB, 480);
    rd_fill_i16((Word16 *)&p->syn_Overl, 320);
    rd_fill_i16((Word16 *)&p->syn_OverlFB, 480);
    rd_fill_i16((Word16 *)&p->old_synth, 1280);
    rd_fill_i16((Word16 *)&p->old_synth_len, 1);
    rd_fill_i16((Word16 *)&p->old_synth_lenFB, 1);
    rd_fill_i16((Word16 *)&p->syn, 17);
    rd_fill_i16((Word16 *)&p->bpf_gain_param, 1);
    rd_fill_i16((Word16 *)&p->L_frame_past, 1);
    rd_fill_i16((Word16 *)&p->L_frameTCX_past, 1);
    rd_fill_i16((Word16 *)&p->lsfold_uw, 16);
    rd_fill_i16((Word16 *)&p->lspold_uw, 16);
    rd_fill_i16((Word16 *)&p->seed_tcx_plc, 1);
    rd_fill_i16((Word16 *)&p->past_gpit, 1);
    rd_fill_i32((Word32 *)&p->past_gcode, 1);
    rd_fill_i16((Word16 *)&p->lsf_cng, 16);
    rd_fill_i16((Word16 *)&p->lspold_cng, 16);
    rd_fill_i8((signed char *)&p->plcBackgroundNoiseUpdated, 1);
    rd_fill_i16((Word16 *)&p->lsp_q_cng, 16);
    rd_fill_i16((Word16 *)&p->old_lsp_q_cng, 16);
    rd_fill_i16((Word16 *)&p->lsf_q_cng, 16);
    rd_fill_i16((Word16 *)&p->old_lsf_q_cng, 16);
    rd_fill_i16((Word16 *)&p->Aq_cng, 102);
    rd_fill_i16((Word16 *)&p->mem_syn_unv_back, 16);
    rd_fill_i16((Word16 *)&p->last_gain_syn_deemph, 1);
    rd_fill_i16((Word16 *)&p->last_gain_syn_deemph_e, 1);
    rd_fill_i16((Word16 *)&p->last_concealed_gain_syn_deemph, 1);
    rd_fill_i16((Word16 *)&p->last_concealed_gain_syn_deemph_e, 1);
    rd_fill_i8((signed char *)&p->enableTcxLpc, 1);
    rd_fill_i8((signed char *)&p->envWeighted, 1);
    rd_fill_i16((Word16 *)&p->nb_subfr, 1);
    rd_fill_i16((Word16 *)&p->fscale, 1);
    rd_fill_i16((Word16 *)&p->fscale_old, 1);
    rd_fill_i32((Word32 *)&p->sr_core, 1);
    rd_fill_i16((Word16 *)&p->pit_min, 1);
    rd_fill_i16((Word16 *)&p->pit_fr1, 1);
    rd_fill_i16((Word16 *)&p->pit_fr1b, 1);
    rd_fill_i16((Word16 *)&p->pit_fr2, 1);
    rd_fill_i16((Word16 *)&p->pit_max, 1);
    rd_fill_i16((Word16 *)&p->pit_res_max, 1);
    rd_fill_i16((Word16 *)&p->pit_res_max_past, 1);
    rd_fill_i16((Word16 *)&p->pit_max_TCX, 1);
    rd_fill_i16((Word16 *)&p->pit_min_TCX, 1);
    rd_fill_i16((Word16 *)&p->preemph_fac, 1);
    rd_fill_i16((Word16 *)&p->gamma, 1);
    rd_fill_i16((Word16 *)&p->inv_gamma, 1);
    rd_fill_i16((Word16 *)&p->mem_Aq, 85);
    rd_fill_i16((Word16 *)&p->last_core_bfi, 1);
    rd_fill_i16((Word16 *)&p->nbLostCmpt, 1);
    rd_fill_i16((Word16 *)&p->prev_nbLostCmpt, 1);
    rd_fill_i16((Word16 *)&p->mode_lvq, 1);
    rd_fill_i32((Word32 *)&p->old_fpitch, 1);
    rd_fill_i32((Word32 *)&p->old_fpitchFB, 1);
    rd_fill_i16((Word16 *)&p->clas_dec, 1);
    rd_fill_i16((Word16 *)&p->mem_pitch_gain, 12);
    rd_fill_i8((signed char *)&p->plc_use_future_lag, 1);
    rd_fill_i16((Word16 *)&p->prev_widow_left_rect, 1);
    rd_fill_i32((Word32 *)&p->Mode2_lp_gainc, 1);
    rd_fill_i32((Word32 *)&p->Mode2_lp_gainp, 1);
    rd_fill_i16((Word16 *)&p->conCngLevelBackgroundTrace, 1);
    rd_fill_i16((Word16 *)&p->conCngLevelBackgroundTrace_e, 1);
    rd_fill_i16((Word16 *)&p->conNoiseLevelMemory, 50);
    rd_fill_i16((Word16 *)&p->conNoiseLevelMemory_e, 50);
    rd_fill_i16((Word16 *)&p->conNoiseLevelIndex, 1);
    rd_fill_i16((Word16 *)&p->conCurrLevelIndex, 1);
    rd_fill_i16((Word16 *)&p->conLastFrameLevel, 1);
    rd_fill_i16((Word16 *)&p->conLastFrameLevel_e, 1);
    rd_fill_i16((Word16 *)&p->old_gaintcx_bfi, 1);
    rd_fill_i16((Word16 *)&p->old_gaintcx_bfi_e, 1);
    rd_fill_i16((Word16 *)&p->cummulative_damping_tcx, 1);
    rd_fill_i16((Word16 *)&p->cummulative_damping, 1);
    rd_fill_i16((Word16 *)&p->cngTDLevel, 1);
    rd_fill_i16((Word16 *)&p->cngTDLevel_e, 1);
    rd_fill_i16((Word16 *)&p->conceal_eof_gain, 1);
    rd_fill_i16((Word16 *)&p->damping, 1);
    rd_fill_i16((Word16 *)&p->gainHelper, 1);
    rd_fill_i16((Word16 *)&p->gainHelper_e, 1);
    rd_fill_i16((Word16 *)&p->stepCompensate, 1);
    rd_fill_i16((Word16 *)&p->stepCompensate_e, 1);
    rd_fill_i16((Word16 *)&p->reset_mem_AR, 1);
    rd_fill_i16((Word16 *)&p->tcxConceal_recalc_exc, 1);
    rd_fill_i16((Word16 *)&p->classifier_Q_mem_syn, 1);
    rd_fill_i16((Word16 *)&p->rate_switching_init, 1);
    rd_fill_i16((Word16 *)&p->lpcQuantization, 1);
    rd_fill_i16((Word16 *)&p->numlpc, 1);
    rd_fill_i16((Word16 *)&p->TcxBandwidth, 1);
    { rd_fill_Pfstat(&p->pfstat); }
    rd_fill_i16((Word16 *)&p->psf_lp_noise_fx, 1);
    rd_fill_i16((Word16 *)&p->voice_fac, 1);
    rd_fill_i8((signed char *)&p->tcxonly, 1);
    rd_fill_i16((Word16 *)&p->resQBits, 2);
    rd_fill_i16((Word16 *)&p->last_ctx_hm_enabled, 1);
    rd_fill_i8((signed char *)&p->tcxltp, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_gain, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_pitch_int, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_pitch_fr, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_mem_in, 12);
    rd_fill_i16((Word16 *)&p->tcxltp_mem_out, 960);
    rd_fill_i16((Word16 *)&p->tcxltp_pitch_int_post_prev, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_pitch_fr_post_prev, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_gain_post_prev, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_filt_idx_prev, 1);
    { rd_fill_Tonalmdctconceal(&p->tonalMDCTconceal); }
    rd_fill_i8((signed char *)&p->tonal_mdct_plc_active, 1);
    rd_fill_i8((signed char *)&p->last_tns_active, 1);
    rd_fill_i8((signed char *)&p->second_last_tns_active, 1);
    rd_fill_i16((Word16 *)&p->second_last_core, 1);
    rd_fill_i32((Word32 *)&p->tcxltp_second_last_pitch, 1);
    rd_fill_i32((Word32 *)&p->tcxltp_third_last_pitch, 1);
    rd_fill_i16((Word16 *)&p->tcxltp_last_gain_unmodified, 1);
    rd_fill_i16((Word16 *)&p->FBTCXdelayBuf, 111);
    rd_fill_i16((Word16 *)&p->mem_syn_r, 60);
    rd_fill_i16((Word16 *)&p->rate_switching_reset, 1);
    rd_fill_i32((Word32 *)&p->lp_error_ener, 1);
    rd_fill_i32((Word32 *)&p->mem_error, 1);
    rd_fill_i16((Word16 *)&p->bpf_noise_buf, 320);
    rd_fill_i8((signed char *)&p->enableGplc, 1);
    rd_fill_i16((Word16 *)&p->flagGuidedAcelp, 1);
    rd_fill_i16((Word16 *)&p->T0_4th, 1);
    rd_fill_i16((Word16 *)&p->guidedT0, 1);
    rd_fill_i16((Word16 *)&p->enablePlcWaveadjust, 1);
    rd_fill_i16((Word16 *)&p->tonality_flag, 1);
    { rd_fill_TPLCInfo(&p->plcInfo); }
    rd_fill_i8((signed char *)&p->VAD, 1);
    rd_fill_i8((signed char *)&p->flag_cna, 1);
    rd_fill_i8((signed char *)&p->last_flag_cna, 1);
    rd_fill_i32((Word32 *)&p->lp_noise, 1);
    rd_fill_i16((Word16 *)&p->seed_acelp, 1);
    rd_fill_i16((Word16 *)&p->core_ext_mode, 1);
    rd_fill_i8((signed char *)&p->dec_glr, 1);
    rd_fill_i16((Word16 *)&p->dec_glr_idx, 1);
    rd_fill_i16((Word16 *)&p->tcx_hm_LtpPitchLag, 1);
    rd_fill_i16((Word16 *)&p->tcx_lpc_shaped_ari, 1);
    rd_fill_i16((Word16 *)&p->igf, 1);
    { rd_fill_IgfdecInstance(&p->hIGFDec); }
    { rd_fill_CldfbScaleFactor(&p->scaleFactor); }
    rd_fill_i16((Word16 *)&p->tec_tfa, 1);
    rd_fill_i16((Word16 *)&p->tec_flag, 1);
    rd_fill_i16((Word16 *)&p->tfa_flag, 1);
    { rd_fill_TemporalEnvelopeCodingDecoderFx(&p->tecDec_fx); }
    rd_fill_i16((Word16 *)&p->con_tcx, 1);
    rd_fill_i16((Word16 *)&p->last_con_tcx, 1);
    rd_fill_i16((Word16 *)&p->old_ppp_mode_fx, 1);
    rd_fill_i16((Word16 *)&p->old_hb_synth_fx, 960);
    rd_fill_i16((Word16 *)&p->prev_Q_exc_fr, 1);
    rd_fill_i16((Word16 *)&p->prev_Q_syn_fr, 1);
    rd_fill_i16((Word16 *)&p->writeFECoffset, 1);
}
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
