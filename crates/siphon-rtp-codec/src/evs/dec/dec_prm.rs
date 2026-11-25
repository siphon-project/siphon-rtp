//! Reading the parameters of a MODE2 frame from the bit stream (TS 26.442 `lib_dec/dec_prm.c`;
//! TS 26.445 §5.2.x bit allocation and §6.1 decoding).
//!
//! `dec_prm` reads the whole parameter stream of a frame: the header (core, coder type, overlap
//! modes, concealment side information), the LPC parameters, and then the ACELP subframe indices,
//! the TCX20 / TCX10 gain, noise filling, LTP, TNS, harmonic model, IGF and spectral data, or the
//! channel-aware partial copy. The reference is one 900-line function; it is split here at its
//! section boundaries (`dec_prm_header`, `dec_prm_lpc`, `dec_prm_acelp`, `dec_prm_partial_copy`,
//! `dec_prm_tcx20`, `dec_prm_rf_tcx_side_info`, `dec_prm_tcx10`), which share the parameter vector
//! and the write position `j`.
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::cnst::{
    ACELP_CORE, ACELP_FIXED_CDK_NB, ACELP_MODE_MAX, ALDO_WINDOW, AMR_WB_CORE, DEC_NPRM_DIV,
    FRAME_SIZE_NB, FULL_OVERLAP, GENERIC, G_LPC_RECOVERY_BITS, IGF_GRID_LB_NORM, IGF_GRID_LB_SHORT,
    IGF_GRID_LB_TRAN, INACTIVE, KLTPHMFRACTIONALRESOLUTION, KTCXHMNUMGAINBITS, LTPSIZE, MODE1,
    MODE2, NBITS_NOISE_FILL_LEVEL, NPRM_CTX_HM, NPRM_RESQ, N_MAX, ONSET, RF_ALLPRED, RF_TCXFD,
    RF_TCXTD1, RF_TCXTD2, TCX_10_CORE, TCX_20_CORE, TRANSITION_OVERLAP, UNVOICED, UNVOICED_CLAS,
    UNVOICED_TRANSITION, VOICED, VOICED_CLAS, VOICED_TRANSITION,
};
use crate::evs::com::ari_hm::{configure_context_hm, ContextHmConfig};
use crate::evs::com::basop_util::imult1616;
use crate::evs::com::bits_alloc::bits_alloc_config_acelp;
use crate::evs::com::bitstream::{get_next_indice, get_next_indice_1, get_next_indice_tmp};
use crate::evs::com::lsf_tools::tcxlpc_get_cdk;
use crate::evs::com::swb_tbe_com::get_tbe_bits;
use crate::evs::com::tcx_ltp::tcx_ltp_decode_params;
use crate::evs::com::tcx_utils::set_tns_config;
use crate::evs::dec::ac_context_mapping_dec::ac_context_mapping_decode2_no_mem_s17_lc;
use crate::evs::dec::ari_hm_dec::decode_index;
use crate::evs::dec::dlpc_avq::decode_lpc_avq;
use crate::evs::dec::igf_dec::{
    igf_dec_read_data, igf_dec_read_level, igf_dec_store_tcx10_sub_frame_data,
};
use crate::evs::dec::lsf_msvq_ma_dec::{dec_lsf_tcxlpc, lsf_bctcvq_decprm, lsf_msvq_ma_decprm};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::tns_base_dec::read_tns_data;
use crate::evs::rom::{
    ACELP_BPF_BITS, ACELP_CDK_BITS, ACELP_GAINS_BITS, ACELP_GAINS_MODE, ACELP_LTP_BITS_SFR,
    ACELP_LTP_MODE, ACELP_NRG_BITS, FRAMESIZECONFIG, LSF_NUMBITS,
};
use crate::itu::basic_ops::{add, extract_l, l_shl, l_shr, l_sub, mult, shl, shr, sub};
use crate::itu::stl2009::{div_l, l_mult0, mpy_32_16_ss};

/// `RF_NOPRED` = `ACELP_MODE_MAX + 1` (not generated: the macro body has an operator)
const RF_NOPRED: i16 = ACELP_MODE_MAX + 1;
/// `RF_GENPRED` = `ACELP_MODE_MAX + 2`
const RF_GENPRED: i16 = ACELP_MODE_MAX + 2;
/// `RF_NELP` = `ACELP_MODE_MAX + 3`
const RF_NELP: i16 = ACELP_MODE_MAX + 3;

/// `table[index]` of a configuration table: the indices come from the ACELP configuration
/// (`bits_alloc`), which only stores table-bound values; one that is not (a corrupt
/// configuration) reads 0 bits where the reference reads past the table.
fn table_entry(table: &[i16], index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `ACELP_LTP_BITS_SFR[ltp_mode][sfr]`, see [`table_entry`].
fn ltp_bits(ltp_mode: i16, sfr: usize) -> i16 {
    usize::try_from(ltp_mode)
        .ok()
        .and_then(|mode| ACELP_LTP_BITS_SFR.get(mode))
        .map_or(0, |row| row[sfr])
}

/// `get_next_indice_fx` as the `Word16` the reference stores it in.
fn read(st: &mut DecoderState, nb_bits: i16) -> i16 {
    get_next_indice(st, nb_bits) as i16
}

/// `Mpy_32_16_ss(total_brate, 5243, ..)` then `extract_l(L_shr(.., 3))`: the frame size in bits.
fn frame_bits_of(total_brate: i32) -> i16 {
    // 5243 is 1/50 in Q18. (0+18-15=3)
    let (l_tmp, _lsb) = mpy_32_16_ss(total_brate, 5243);
    // Q0
    extract_l(l_shr(l_tmp, 3))
}

/// `dec_prm_hm`: read the harmonic-model side information of a TCX frame into `prm_hm[0..3]`: the
/// on/off flag, the periodicity index and, for voiced frames, the gain index. Only voiced and
/// generic frames carry it.
fn dec_prm_hm(st: &mut DecoderState, prm_hm: &mut [i16], l_frame: i16) {
    // Disable HM for non-GC,VC modes
    if sub(st.tcx_cfg.coder_type, VOICED) != 0 && sub(st.tcx_cfg.coder_type, GENERIC) != 0 {
        prm_hm[0] = 0;
        return;
    }

    prm_hm[1] = -1;
    prm_hm[2] = 0;

    // Flag
    prm_hm[0] = read(st, 1);

    if prm_hm[0] != 0 {
        let mut tmp: i16 = 0;
        if sub(l_frame, 256) >= 0 {
            tmp = 1;
        }
        // Periodicity index
        decode_index(st, tmp, &mut prm_hm[1]);

        // Gain index
        if sub(st.tcx_cfg.coder_type, VOICED) == 0 {
            prm_hm[2] = read(st, KTCXHMNUMGAINBITS);
        }
    }
}

/// The signal class of a frame whose class index `ind` (2 bits) is transmitted: unvoiced, an
/// unvoiced or voiced transition (voiced when the last good frame was one), voiced, or an onset.
fn clas_of_index(st: &mut DecoderState, ind: i16) {
    st.clas_dec = ONSET;
    if ind == 0 {
        st.clas_dec = UNVOICED_CLAS;
    } else if sub(ind, 1) == 0 {
        st.clas_dec = UNVOICED_TRANSITION;
        if sub(st.last_good, VOICED_TRANSITION) >= 0 {
            st.clas_dec = VOICED_TRANSITION;
        }
    } else if sub(ind, 2) == 0 {
        st.clas_dec = VOICED_CLAS;
    }
}

/// `dec_prm`: read the parameters of a MODE2 frame from the bit stream: `param` receives the
/// ACELP / TCX parameters (`DEC_NPRM_DIV` per TCX10 half frame), `param_lpc` the LPC parameter
/// indices, `coder_type` the coder type; `total_nbbits` is the bits of the frame and `bits_read`
/// the bits taken by what was read before (in and out: the bits read in total). `l_frame` is the
/// frame length of the core.
///
/// A frame that does not carry what it announces (too few bits) sets `BER_detect` and the read
/// position is limited to the end of the frame.
pub fn dec_prm(
    coder_type: &mut i16,
    param: &mut [i16],
    param_lpc: &mut [i16],
    total_nbbits: i16,
    st: &mut DecoderState,
    l_frame: i16,
    bits_read: &mut i16,
) {
    // INIT
    let start_bit_pos: i16;
    if sub(st.mdct_sw, MODE1) == 0 {
        // count from frame start
        start_bit_pos = 0;

        // Adjust st->bits_frame_core not to subtract MODE2 bandwidth signaling
        let num_bits = frame_bits_of(st.total_brate);
        if let Some(config) = FRAMESIZECONFIG
            .iter()
            .take(FRAME_SIZE_NB as usize)
            .find(|config| sub(config.frame_bits, num_bits) == 0)
        {
            st.bits_frame_core = add(st.bits_frame_core, i16::from(config.bandwidth_bits));
        }
    } else if sub(st.rf_flag, 1) == 0 {
        // Inherent adjustment to accommodate the compact packing used in the RF mode
        start_bit_pos = sub(st.next_bit_pos, 2);
    } else {
        start_bit_pos = st.next_bit_pos;
    }

    // Framing parameters
    let nb_subfr = st.nb_subfr;

    // Init LTP data
    st.tcx_hm_ltp_pitch_lag = -1;
    st.tcxltp_gain = 0;

    // HEADER
    dec_prm_header(st, coder_type, start_bit_pos);

    // LPC PARAMETERS
    dec_prm_lpc(st, *coder_type, param_lpc);

    st.bits_common = sub(st.next_bit_pos, start_bit_pos);

    // ACELP
    if sub(st.core, ACELP_CORE) == 0 && st.use_partial_copy == 0 {
        dec_prm_acelp(st, *coder_type, param, nb_subfr);
    } else if sub(st.rf_frame_type, RF_ALLPRED) >= 0 && st.use_partial_copy != 0 {
        dec_prm_partial_copy(st, param, nb_subfr);
    }

    // TCX20
    if sub(st.core, TCX_20_CORE) == 0 && st.use_partial_copy == 0 {
        dec_prm_tcx20(st, param, l_frame, start_bit_pos);
    }

    if sub(st.rf_frame_type, RF_TCXFD) >= 0
        && sub(st.rf_frame_type, RF_TCXTD2) <= 0
        && sub(st.use_partial_copy, 1) == 0
    {
        dec_prm_rf_tcx_side_info(st);
    }

    // TCX10
    if sub(st.core, TCX_10_CORE) == 0 {
        dec_prm_tcx10(st, param, start_bit_pos);
    }

    if st.use_partial_copy == 0 {
        if sub(
            sub(total_nbbits, *bits_read),
            sub(st.next_bit_pos, start_bit_pos),
        ) < 0
        {
            st.ber_detect = 1;
            st.next_bit_pos = add(start_bit_pos, sub(total_nbbits, *bits_read));
        }
        *bits_read = sub(st.next_bit_pos, start_bit_pos);
    }
}

/// The HEADER section of `dec_prm`: the core and coder type, the previous core, the TCX overlap
/// modes and the concealment side information (guided ACELP pitch, LPC recovery index).
fn dec_prm_header(st: &mut DecoderState, coder_type: &mut i16, start_bit_pos: i16) {
    // Modes (ACE_GC, ACE_UC, TCX20, TCX10...)
    if st.tcxonly != 0 {
        st.core = add(read(st, 1), 1);
        let ind = read(st, 2);
        clas_of_index(st, ind);
        *coder_type = INACTIVE;
        st.vad = 0;
    } else {
        if sub(st.mdct_sw, MODE1) == 0 {
            // 2 bits instead of 3 as TCX is already signaled
            st.core = TCX_20_CORE;
            st.tcx_cfg.coder_type = read(st, 2);
            *coder_type = st.tcx_cfg.coder_type;
        } else if sub(st.mdct_sw_enable, MODE2) == 0 {
            if get_next_indice_1(st) != 0 {
                // TCX
                let tmp = read(st, 3);
                // HQ_CORE encountered in dec_prm (the reference asserts it cannot be)
                st.core = TCX_20_CORE;
                st.tcx_cfg.coder_type = tmp;
                *coder_type = st.tcx_cfg.coder_type;
            } else {
                // ACELP
                st.core = ACELP_CORE;
                *coder_type = read(st, 2);
            }
        } else if sub(st.rf_flag, 1) == 0 {
            if st.use_partial_copy == 0 {
                let tmp = read(st, 1);
                if tmp == 0 {
                    st.core = ACELP_CORE;
                } else {
                    st.core = TCX_20_CORE;
                    st.tcx_cfg.coder_type = *coder_type;
                }
            }
        } else {
            st.core = ACELP_CORE;
            *coder_type = read(st, 3);
            if sub(*coder_type, ACELP_MODE_MAX) >= 0 {
                st.core = TCX_20_CORE;
                *coder_type = sub(*coder_type, ACELP_MODE_MAX);
                st.tcx_cfg.coder_type = *coder_type;
            }
        }

        if st.igf != 0 && sub(st.core, ACELP_CORE) == 0 {
            st.bits_frame_core = sub(
                st.bits_frame_core,
                get_tbe_bits(st.total_brate, st.bwidth, st.rf_flag),
            );
        }

        if sub(st.rf_flag, 1) == 0 {
            // +1 as flag-bit not considered in rf_target_bits
            st.bits_frame_core = sub(st.bits_frame_core, add(st.rf_target_bits, 1));
        }

        // Inactive frame detection on non-DTX mode
        st.vad = 1;
        if sub(*coder_type, INACTIVE) == 0 {
            st.vad = 0;
        }
    }

    // Core extended mode mapping for correct PLC classification
    st.core_ext_mode = *coder_type;

    if sub(*coder_type, INACTIVE) == 0 {
        st.core_ext_mode = UNVOICED;
    }

    // Decode previous mode for error concealment
    if (sub(st.core, ACELP_CORE) != 0 || st.tcx_cfg.lfac_next > 0) && st.use_partial_copy == 0 {
        st.last_core_bs = read(st, 1);

        // need to introduce special error handling for lost transition frames from CNG: in such
        // cases, the bitstream reader continues with CNG, setting bfi = 0, total_brate = 0 this
        // might result in a not matching last_core transmitted in the BS - we should use this
        // only for interpreting the bitstream and re-use the internal state for the proper
        // transition handling; still, for voiced onsets rather stick to wrong windowing...
        if !(st.last_total_brate == 0 && sub(st.clas_dec, VOICED_CLAS) != 0)
            && sub(st.last_core_bs, st.last_core) != 0
        {
            st.last_core = st.last_core_bs;
        }

        // for TCX 10 force last_core to be TCX since ACELP as previous core is forbidden
        if sub(st.core, TCX_10_CORE) == 0 {
            st.last_core = TCX_20_CORE;
            st.last_core_bs = TCX_20_CORE;
        }
    }

    if sub(st.rf_flag, 1) == 0 && sub(st.use_partial_copy, 1) == 0 && st.tcxonly == 0 {
        st.bits_frame_core = st.rf_target_bits;

        // offset the indices to read the acelp partial copy
        let num_bits = frame_bits_of(st.total_brate);

        // the reference computes the offset in `int` and passes it as a `Word16`
        let offset = i32::from(start_bit_pos) + i32::from(num_bits)
            - i32::from(st.rf_target_bits)
            - 3
            - i32::from(st.next_bit_pos);
        get_next_indice_tmp(st, offset as i16);
    }

    if st.use_partial_copy == 0 {
        dec_prm_header_overlap_and_concealment(st);
    }
}

/// The part of the header only a primary frame carries: the TCX overlap modes (from the previous
/// and current frame type and the coded overlap mode) and the concealment side information.
fn dec_prm_header_overlap_and_concealment(st: &mut DecoderState) {
    // Set the last overlap mode based on the previous and current frame type and coded overlap mode
    if sub(st.last_core, ACELP_CORE) == 0 || sub(st.last_core, AMR_WB_CORE) == 0 {
        st.tcx_cfg.tcx_last_overlap_mode = TRANSITION_OVERLAP;
    } else if sub(st.core, TCX_10_CORE) == 0
        && sub(st.tcx_cfg.tcx_curr_overlap_mode, ALDO_WINDOW) == 0
    {
        st.tcx_cfg.tcx_last_overlap_mode = FULL_OVERLAP;
    } else {
        st.tcx_cfg.tcx_last_overlap_mode = st.tcx_cfg.tcx_curr_overlap_mode;
        if sub(st.core, TCX_10_CORE) != 0
            && sub(st.tcx_cfg.tcx_curr_overlap_mode, FULL_OVERLAP) == 0
        {
            st.tcx_cfg.tcx_last_overlap_mode = ALDO_WINDOW;
        }
    }
    // Set the current overlap mode based on the current frame type and coded overlap mode
    st.tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;

    if sub(st.core, ACELP_CORE) != 0 {
        let mut tmp: i16 = 0;
        // if current TCX mode is not 0 (full overlap), read another bit
        if get_next_indice_1(st) != 0 {
            tmp = add(2, read(st, 1));
        }
        st.tcx_cfg.tcx_curr_overlap_mode = tmp;

        // TCX10 : always symmetric windows
        if sub(st.core, TCX_20_CORE) == 0
            && tmp == 0
            && sub(st.last_core, ACELP_CORE) != 0
            && sub(st.last_core, AMR_WB_CORE) != 0
        {
            st.tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;
        }
    }

    // SIDE INFO. DECODING
    if st.enable_gplc != 0 {
        let bits_per_subfr: i16 = 4;
        let search_range: i16 = 8;

        st.flag_guided_acelp = read(st, 1);

        let mut pitch_diff: i16 = 0;
        if st.flag_guided_acelp != 0 {
            pitch_diff = read(st, bits_per_subfr);
            st.guided_t0 = sub(pitch_diff, search_range);
        }
        if pitch_diff == 0 && st.flag_guided_acelp != 0 {
            st.flag_guided_acelp = 0;
        }
    } else {
        st.flag_guided_acelp = 0;
    }

    if st.dec_glr != 0 {
        st.dec_glr_idx = -1;
        if sub(st.core, ACELP_CORE) == 0 {
            st.dec_glr_idx = read(st, G_LPC_RECOVERY_BITS);
        }
    }
}

/// The LPC PARAMETERS section of `dec_prm`: the LSF indices of a primary frame (TCX LPC, AVQ,
/// bit-constrained TCVQ or the MA-predictive MSVQ) or of a partial copy.
fn dec_prm_lpc(st: &mut DecoderState, coder_type: i16, param_lpc: &mut [i16]) {
    // Initialization of LPC Mid flag
    st.acelp_cfg.mid_lpc = st.acelp_cfg.mid_lpc_enable;
    if (sub(st.lpc_quantization, 1) == 0 && sub(coder_type, VOICED) == 0)
        || st.use_partial_copy != 0
    {
        st.acelp_cfg.mid_lpc = 0;
    }

    if st.use_partial_copy == 0 {
        // Number of sets of LPC parameters (does not include mid-lpc)
        st.numlpc = 2;
        if st.tcxonly == 0 || sub(st.core, TCX_10_CORE) < 0 {
            st.numlpc = 1;
        }

        // Decode LPC parameters
        if st.enable_tcx_lpc != 0 && sub(st.core, ACELP_CORE) != 0 {
            let tcx_lpc_cdk = tcxlpc_get_cdk(coder_type);
            let mut indices: &mut [i16] = param_lpc;
            dec_lsf_tcxlpc(st, &mut indices, i16::from(st.narrow_band), tcx_lpc_cdk);
        } else if st.lpc_quantization == 0 {
            decode_lpc_avq(st, st.numlpc, param_lpc);
        } else if sub(st.lpc_quantization, 1) == 0 {
            if crate::itu::basic_ops::l_sub(st.sr_core, 16000) == 0
                && sub(coder_type, VOICED) == 0
                && sub(st.core, ACELP_CORE) == 0
            {
                lsf_bctcvq_decprm(st, param_lpc);
            } else {
                lsf_msvq_ma_decprm(
                    st,
                    param_lpc,
                    st.core,
                    coder_type,
                    i16::from(st.acelp_cfg.mid_lpc),
                    i16::from(st.narrow_band),
                    st.sr_core,
                );
            }
        }
        // else: "LPC quant not supported!" (the reference asserts it cannot be)
    } else {
        st.numlpc = 1;

        if sub(st.rf_frame_type, RF_TCXFD) == 0 {
            param_lpc[0] = 0;
            // VQ 1
            param_lpc[1] = read(st, LSF_NUMBITS[0]);
            // VQ 2
            param_lpc[2] = read(st, LSF_NUMBITS[1]);
            // VQ 3
            param_lpc[3] = read(st, LSF_NUMBITS[2]);
        } else if sub(st.rf_frame_type, RF_ALLPRED) >= 0 && sub(st.rf_frame_type, RF_NELP) <= 0 {
            // LSF indices
            // VQ 1
            param_lpc[0] = read(st, 8);
            // VQ 2
            param_lpc[1] = read(st, 8);
        }
    }
}

/// The ACELP section of `dec_prm`: bit allocation of the frame, the band-pass filter parameter,
/// the mean energy and, per subframe, the pitch lag, the adaptive-codebook filter flag, the
/// innovative codebook words and the gains.
fn dec_prm_acelp(st: &mut DecoderState, coder_type: i16, prm: &mut [i16], nb_subfr: i16) {
    let mut j: usize = 0;

    // Target Bits
    let acelp_target_bits = sub(st.bits_frame_core, st.bits_common);

    let acelp_bits = bits_alloc_config_acelp(
        acelp_target_bits,
        coder_type,
        &mut st.acelp_cfg,
        i16::from(st.narrow_band),
        st.nb_subfr,
    );

    if acelp_bits < 0 {
        st.ber_detect = 1;
    }

    // Adaptive BPF (2 bits)
    let n = table_entry(&ACELP_BPF_BITS, st.acelp_cfg.bpf_mode);

    st.bpf_gain_param = shl(st.acelp_cfg.bpf_mode, 1);
    if n != 0 {
        st.bpf_gain_param = read(st, n);
    }

    // Mean energy (2 or 3 bits)
    let n = table_entry(&ACELP_NRG_BITS, st.acelp_cfg.nrg_mode);
    if n != 0 {
        prm[j] = read(st, n);
        j += 1;
    }

    // Subframe parameters
    for sfr in 0..nb_subfr as usize {
        // Pitch lag (4, 5, 6, 8 or 9 bits)
        let n = ltp_bits(st.acelp_cfg.ltp_mode, sfr);

        if n != 0 {
            prm[j] = read(st, n);
            j += 1;
        }

        // Adaptive codebook filtering (1 bit)
        if sub(st.acelp_cfg.ltf_mode, 2) == 0 {
            prm[j] = read(st, 1);
            j += 1;
        }

        // Innovative codebook: Decode pulse positions.
        let j_old = j;
        // the table is indexed before the sanity check below: an index out of its range is a bit
        // error of the configuration, for which the reference reads past the table; take 0 bits
        let cdk_bits = ACELP_CDK_BITS
            .get(st.acelp_cfg.fixed_cdk_index[sfr] as usize)
            .copied()
            .unwrap_or(0);
        let wordcnt = shr(cdk_bits, 4);
        let bitcnt = cdk_bits & 0xF;

        // sanity check for testing - not instrumented
        if sub(st.acelp_cfg.fixed_cdk_index[sfr], ACELP_FIXED_CDK_NB) >= 0
            || st.acelp_cfg.fixed_cdk_index[sfr] < 0
        {
            st.acelp_cfg.fixed_cdk_index[sfr] = 0;
            st.ber_detect = 1;
        }

        for _ in 0..wordcnt {
            prm[j] = read(st, 16);
            j += 1;
        }
        if bitcnt != 0 {
            prm[j] = read(st, bitcnt);
        }

        j = add(j_old as i16, 8) as usize;

        // Gains (5b, 6b or 7b / subfr)
        let n = table_entry(&ACELP_GAINS_BITS, st.acelp_cfg.gains_mode[sfr]);

        prm[j] = read(st, n);
        j += 1;
    }
}

/// The ACELP partial copy (channel-aware RF) section of `dec_prm`: the NELP gains and filter, or
/// the energy, the pitch lags, the fixed-codebook words and the gains of the ALL / NO / GEN
/// predicted copy.
fn dec_prm_partial_copy(st: &mut DecoderState, prm: &mut [i16], nb_subfr: i16) {
    let mut j: usize = 0;

    // target bits ranges from 56 to 72 depending on rf_type; rf_frame_type is already offset by
    // 4 to parse the config elements for partial copy; acelp_cfg_rf is not used by the reference
    // here, it configures the primary frame's `acelp_cfg`; is narrowBand: 0
    let acelp_bits = bits_alloc_config_acelp(
        st.rf_target_bits,
        st.rf_frame_type,
        &mut st.acelp_cfg,
        0,
        st.nb_subfr,
    );

    if acelp_bits < 0 {
        st.ber_detect = 1;
    }

    // rf_frame_type NELP: 7
    if sub(st.rf_frame_type, RF_NELP) == 0 {
        // NELP gain indices
        st.rf_indx_nelp_i_g1 = read(st, 5);
        st.rf_indx_nelp_i_g2[0] = read(st, 6);
        st.rf_indx_nelp_i_g2[1] = read(st, 6);

        // NELP filter selection index
        st.rf_indx_nelp_fid = read(st, 2);

        // tbe gainFr
        st.rf_indx_tbe_gain_fr = read(st, 5);
    } else {
        // rf_frame_type ALL_PRED: 4, NO_PRED: 5, GEN_PRED: 6
        // ES pred
        prm[j] = read(st, 3);
        j += 1;

        let ltp_mode = table_entry(&ACELP_LTP_MODE[1][1], st.rf_frame_type);
        let gains_mode = table_entry(&ACELP_GAINS_MODE[1][1], st.rf_frame_type);

        // Subframe parameters
        for sfr in 0..nb_subfr as usize {
            // Pitch lag (5, or 8 bits)
            let n = ltp_bits(ltp_mode, sfr);
            if n != 0 {
                prm[j] = read(st, n);
                j += 1;
            }

            // Innovative codebook
            if sub(st.rf_frame_type, RF_NOPRED) == 0
                || (sub(st.rf_frame_type, RF_GENPRED) == 0 && (sfr == 0 || sfr == 2))
            {
                // NOTE: FCB actual bits need to be backed up as well
                prm[j] = read(st, 7);
                j = add(j as i16, 8) as usize;
            }

            // Gains (5b, 6b or 7b / subfr)
            if sfr == 0 || sfr == 2 {
                let n = table_entry(&ACELP_GAINS_BITS, gains_mode);
                prm[j] = read(st, n);
                j += 1;
            }
        }

        st.rf_indx_tbe_gain_fr = read(st, 2);
    }
}

/// The TCX20 section of `dec_prm`: PLC flag, gain, noise filling, LTP, TNS, harmonic model, IGF
/// and the spectral data (arithmetic-coded or raw bits).
fn dec_prm_tcx20(st: &mut DecoderState, prm: &mut [i16], l_frame: i16, start_bit_pos: i16) {
    let mut index_buffer = [0i16; N_MAX as usize + 1];
    let mut hm_cfg = ContextHmConfig::new(&mut index_buffer);
    let mut flag_ctx_hm = false;
    let mut j: usize = 0;

    if st.enable_plc_waveadjust != 0 {
        st.tonality_flag = read(st, 1);
    }

    // TCX Gain = 7 bits
    prm[j] = read(st, 7);
    j += 1;

    // TCX Noise Filling = NBITS_NOISE_FILL_LEVEL bits
    prm[j] = read(st, NBITS_NOISE_FILL_LEVEL);
    j += 1;

    // LTP data
    // PLC pitch info for HB
    if st.tcxltp != 0 || l_sub(st.sr_core, 25600) > 0 {
        prm[j] = read(st, 1);

        if prm[j] != 0 {
            prm[j + 1] = read(st, 9);
            prm[j + 2] = read(st, 2);
        }

        st.ber_detect |= tcx_ltp_decode_params(
            Some(&prm[j..j + 3]),
            &mut st.tcxltp_pitch_int,
            &mut st.tcxltp_pitch_fr,
            &mut st.tcxltp_gain,
            st.pit_min,
            st.pit_fr1,
            st.pit_fr2,
            st.pit_max,
            st.pit_res_max,
        );

        st.tcx_hm_ltp_pitch_lag = -1;
        st.tcxltp_last_gain_unmodified = st.tcxltp_gain;

        if st.tcxonly == 0 && sub(st.tcxltp_pitch_int, l_frame) < 0 {
            let tmp32 = l_shl(
                l_mult0(st.l_frame, st.pit_res_max),
                1 + KLTPHMFRACTIONALRESOLUTION + 1,
            );
            let tmp1 = add(
                imult1616(st.tcxltp_pitch_int, st.pit_res_max),
                st.tcxltp_pitch_fr,
            );
            st.tcx_hm_ltp_pitch_lag = div_l(tmp32, tmp1);
        }
    }

    j += 3;

    // TCX spectral data
    let mut lg = l_frame;
    let mut lg_fb = st.tcx_cfg.tcx_coded_lines;

    if sub(st.last_core_bs, ACELP_CORE) == 0 {
        // ACE->TCX transition
        lg = add(lg, st.tcx_cfg.tcx_offset);
        if st.tcx_cfg.lfac_next < 0 {
            lg = sub(lg, st.tcx_cfg.lfac_next);
        }

        lg_fb = add(lg_fb, shr(lg_fb, 2));
    }

    // TNS data
    let mut n_tns_params: i16 = 0;
    let mut n_tns_bits: i16 = 0;

    if st.tcx_cfg.f_is_tns_allowed != 0 {
        set_tns_config(
            &mut st.tcx_cfg,
            1,
            i8::from(sub(st.last_core_bs, ACELP_CORE) == 0),
        );
        read_tns_data_of_config(st, &mut n_tns_bits, &mut prm[j..], &mut n_tns_params);

        j = add(j as i16, n_tns_params) as usize;
    }
    let hm_size = shl(mult(st.tcx_bandwidth, lg), 1);

    if st.tcx_lpc_shaped_ari != 0 && sub(st.last_core_bs, ACELP_CORE) != 0 {
        dec_prm_hm(st, &mut prm[j..], hm_size);
    }

    let mut nbits_tcx = sub(st.bits_frame_core, sub(st.next_bit_pos, start_bit_pos));
    if st.enable_gplc != 0 {
        nbits_tcx = sub(nbits_tcx, 7);
    }

    // Context HM flag
    if st.tcx_cfg.ctx_hm != 0 && sub(st.last_core_bs, ACELP_CORE) != 0 {
        prm[j] = read(st, 1);
        nbits_tcx = sub(nbits_tcx, 1);

        if prm[j] != 0 {
            let mut tmp: i16 = 0;
            if sub(hm_size, 256) >= 0 {
                tmp = 1;
            }

            decode_index(st, tmp, &mut prm[j + 1]);

            flag_ctx_hm = true;

            configure_context_hm(
                lg_fb,
                nbits_tcx,
                prm[j + 1],
                st.tcx_hm_ltp_pitch_lag,
                &mut hm_cfg,
            );

            // the reference subtracts the index bits from `nbits_tcx` here and overwrites it below
        }
    }
    j = add(j as i16, NPRM_CTX_HM) as usize;

    // read IGF payload
    if st.igf != 0 {
        if sub(st.last_core_bs, ACELP_CORE) == 0 {
            igf_dec_read_level(st, IGF_GRID_LB_TRAN, 1);
            igf_dec_read_data(st, IGF_GRID_LB_TRAN, 1);
        } else {
            igf_dec_read_level(st, IGF_GRID_LB_NORM, 1);
            igf_dec_read_data(st, IGF_GRID_LB_NORM, 1);
        }
        // the reference subtracts the IGF bits from `nbits_tcx` here and overwrites it next
    }
    // what is left of the frame, after everything read so far (IGF included)
    nbits_tcx = sub(st.bits_frame_core, sub(st.next_bit_pos, start_bit_pos));
    if st.tcx_lpc_shaped_ari != 0 {
        // store length of buffer
        prm[j] = nbits_tcx;
        j += 1;
        // the raw bits of the arithmetic coder, `nbits_tcx` of them, then 32 ones
        for ix in 0..nbits_tcx.max(0) as usize {
            prm[j + ix] = get_next_indice_1(st) as i16;
        }
        fill_ones_after(prm, j, nbits_tcx);
        // the reference ends with `j = add(j, nbits_tcx)`; nothing follows
    } else {
        st.res_q_bits[0] = ac_context_mapping_decode2_no_mem_s17_lc(
            st,
            &mut prm[j..],
            lg_fb,
            nbits_tcx,
            NPRM_RESQ * i16::from(st.tcx_cfg.resq),
            flag_ctx_hm.then_some(&mut hm_cfg),
        );
        // the reference ends with `j = add(j, lg)`; nothing follows
    }
}

/// `set16_fx(prms + nbits_tcx, 1, 32)` for `prms = &prm[j]`: 32 ones after the `nbits_tcx` raw
/// bits. A negative `nbits_tcx` (a frame that consumed more than it was allotted) puts the start
/// before `prms`; the reference then writes before it, which is clipped to the start of `prm`.
fn fill_ones_after(prm: &mut [i16], j: usize, nbits_tcx: i16) {
    let start = (j as i32 + i32::from(nbits_tcx)).max(0) as usize;
    let end = (start + 32).min(prm.len());
    if start < end {
        prm[start..end].fill(1);
    }
}

/// `ReadTnsData(st->tcx_cfg.pCurrentTnsConfig, st, ..)`: the current TNS configuration is part
/// of the state the reader also borrows, so it is read from a copy of its (small) descriptor.
fn read_tns_data_of_config(
    st: &mut DecoderState,
    n_tns_bits: &mut i16,
    stream: &mut [i16],
    n_tns_params: &mut i16,
) {
    if let Some((frame_kind, after_acelp)) = st.tcx_cfg.p_current_tns_config {
        let config = st.tcx_cfg.tns_config[frame_kind][after_acelp].clone();
        read_tns_data(&config, st, n_tns_bits, stream, n_tns_params);
    }
}

/// The classification and gain / LTP of an RF partial copy of a TCX frame (`rf_frame_type` in
/// `RF_TCXFD..=RF_TCXTD2`).
fn dec_prm_rf_tcx_side_info(st: &mut DecoderState) {
    let mut prm_ltp = [0i16; LTPSIZE as usize];

    // classification
    let ind = read(st, 2);
    clas_of_index(st, ind);

    if sub(st.rf_frame_type, RF_TCXFD) == 0 {
        // TCX Gain = 7 bits
        st.old_gaintcx_bfi = read(st, 7);
    } else if st.tcxltp != 0
        && (sub(st.rf_frame_type, RF_TCXTD2) == 0 || sub(st.rf_frame_type, RF_TCXTD1) == 0)
    {
        // LTP data
        // LTP active
        prm_ltp[0] = 1;
        prm_ltp[1] = read(st, 9);
        // max ampl. quantizer output (2bits), anyway not used later
        prm_ltp[2] = 3;

        if st.prev_bfi == 0 {
            st.ber_detect |= tcx_ltp_decode_params(
                Some(&prm_ltp),
                &mut st.tcxltp_pitch_int,
                &mut st.tcxltp_pitch_fr,
                &mut st.tcxltp_gain,
                st.pit_min,
                st.pit_fr1,
                st.pit_fr2,
                st.pit_max,
                st.pit_res_max,
            );

            st.tcxltp_last_gain_unmodified = st.tcxltp_gain;
        }
    }
}

/// The TCX10 section of `dec_prm`: IGF payload of both halves, then per half frame the gain,
/// noise filling, LTP (first half), TNS, harmonic model flag and the spectral data. The halves'
/// parameters are `DEC_NPRM_DIV` apart in `param`.
fn dec_prm_tcx10(st: &mut DecoderState, param: &mut [i16], start_bit_pos: i16) {
    let mut index_buffer = [0i16; N_MAX as usize + 1];
    let mut hm_cfg = ContextHmConfig::new(&mut index_buffer);
    let mut tcxltp_prm_0: i16 = 0;
    let mut tcxltp_prm_1: i16 = 0;
    let mut tcxltp_prm_2: i16 = 0;
    let mut nbits_igf: i16 = 0;

    // read IGF payload
    if st.igf != 0 {
        let n = st.next_bit_pos;

        igf_dec_read_level(st, IGF_GRID_LB_SHORT, 1);
        igf_dec_read_data(st, IGF_GRID_LB_SHORT, 1);
        igf_dec_store_tcx10_sub_frame_data(&mut st.h_igf_dec, 0);

        igf_dec_read_level(st, IGF_GRID_LB_SHORT, 0);
        igf_dec_read_data(st, IGF_GRID_LB_SHORT, 0);
        igf_dec_store_tcx10_sub_frame_data(&mut st.h_igf_dec, 1);

        nbits_igf = sub(st.next_bit_pos, n);
    }
    for k in 0..2i16 {
        let mut flag_ctx_hm = false;
        // `prm = param + (k*DEC_NPRM_DIV)`
        let prm = &mut param[(k as usize) * DEC_NPRM_DIV as usize..];
        let mut j: usize = 0;

        let mut nbits_tcx = sub(st.next_bit_pos, start_bit_pos);

        if st.enable_plc_waveadjust != 0 && k != 0 {
            st.tonality_flag = read(st, 1);
        }
        // TCX Gain = 7 bits
        prm[j] = read(st, 7);
        j += 1;

        // TCX Noise Filling = NBITS_NOISE_FILL_LEVEL bits
        prm[j] = read(st, NBITS_NOISE_FILL_LEVEL);
        j += 1;

        // LTP data
        if k == 0 && (st.tcxltp != 0 || l_sub(st.sr_core, 25600) > 0) {
            prm[j] = read(st, 1);

            if prm[j] != 0 {
                prm[j + 1] = read(st, 9);
                prm[j + 2] = read(st, 2);

                tcxltp_prm_0 = prm[j];
                tcxltp_prm_1 = prm[j + 1];
                tcxltp_prm_2 = prm[j + 2];
            }

            st.ber_detect |= tcx_ltp_decode_params(
                Some(&prm[j..j + 3]),
                &mut st.tcxltp_pitch_int,
                &mut st.tcxltp_pitch_fr,
                &mut st.tcxltp_gain,
                st.pit_min,
                st.pit_fr1,
                st.pit_fr2,
                st.pit_max,
                st.pit_res_max,
            );

            st.tcxltp_last_gain_unmodified = st.tcxltp_gain;
            st.tcx_hm_ltp_pitch_lag = -1;

            j += 3;
        } else {
            prm[j] = tcxltp_prm_0;
            j += 1;
            prm[j] = tcxltp_prm_1;
            j += 1;
            prm[j] = tcxltp_prm_2;
            j += 1;
        }

        // TCX spectral data
        // the reference's `lg` (half the core frame, plus the ACE->TCX transition offset) is only
        // used for the coded-lines length `lg_fb` here
        let mut lg_fb = shr(st.tcx_cfg.tcx_coded_lines, 1);

        if k == 0 && sub(st.last_core_bs, ACELP_CORE) == 0 {
            // ACE->TCX transition
            lg_fb = add(lg_fb, shr(lg_fb, 1));
        }

        // TNS data
        let mut n_tns_params: i16 = 0;
        let mut n_tns_bits: i16 = 0;

        if st.tcx_cfg.f_is_tns_allowed != 0 {
            if sub(st.last_core_bs, ACELP_CORE) == 0 && k == 0 {
                st.ber_detect = 1;
                st.last_core = TCX_20_CORE;
                st.last_core_bs = TCX_20_CORE;
            }
            set_tns_config(
                &mut st.tcx_cfg,
                0,
                i8::from(sub(st.last_core_bs, ACELP_CORE) == 0 && k == 0),
            );

            read_tns_data_of_config(st, &mut n_tns_bits, &mut prm[j..], &mut n_tns_params);

            j = add(j as i16, n_tns_params) as usize;
        }

        let hm_size = shl(mult(st.tcx_bandwidth, lg_fb), 1);

        // compute target bits
        nbits_tcx = sub(
            shr(
                sub(
                    add(sub(sub(st.bits_frame_core, st.bits_common), nbits_igf), 1),
                    k,
                ),
                1,
            ),
            sub(sub(st.next_bit_pos, start_bit_pos), nbits_tcx),
        );

        // Context HM flag
        if st.tcx_cfg.ctx_hm != 0 && !(sub(st.last_core_bs, ACELP_CORE) == 0 && k == 0) {
            prm[j] = read(st, 1);
            nbits_tcx = sub(nbits_tcx, 1);

            // Read PeriodicityIndex
            if prm[j] != 0 {
                let num_index_bits = decode_index(st, i16::from(hm_size >= 256), &mut prm[j + 1]);

                flag_ctx_hm = true;

                configure_context_hm(lg_fb, nbits_tcx, prm[j + 1], -1, &mut hm_cfg);

                nbits_tcx = sub(nbits_tcx, num_index_bits);
            }
        }
        j = add(j as i16, NPRM_CTX_HM) as usize;
        st.res_q_bits[k as usize] = ac_context_mapping_decode2_no_mem_s17_lc(
            st,
            &mut prm[j..],
            lg_fb,
            nbits_tcx,
            NPRM_RESQ * i16::from(st.tcx_cfg.resq),
            flag_ctx_hm.then_some(&mut hm_cfg),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_bits_are_the_bit_rate_over_fifty() {
        assert_eq!(frame_bits_of(24400), 488);
        assert_eq!(frame_bits_of(9600), 192);
        assert_eq!(frame_bits_of(128000), 2560);
    }

    #[test]
    fn harmonic_model_is_off_for_non_voiced_non_generic_frames() {
        let mut st = DecoderState::zeroed();
        st.tcx_cfg.coder_type = UNVOICED;
        let mut prm_hm = [7i16; 3];
        dec_prm_hm(&mut st, &mut prm_hm, 256);
        assert_eq!(prm_hm, [0, 7, 7]);
    }

    #[test]
    fn ones_after_the_raw_bits_stay_inside_the_vector() {
        let mut prm = [0i16; 40];
        fill_ones_after(&mut prm, 4, 10);
        assert_eq!(prm[13], 0);
        assert!(prm[14..40].iter().all(|&value| value == 1));
        let mut prm = [0i16; 40];
        // a start before the vector is clipped to its first element
        fill_ones_after(&mut prm, 4, -20);
        assert!(prm[..32].iter().all(|&value| value == 1));
        assert!(prm[32..].iter().all(|&value| value == 0));
        let mut prm = [0i16; 40];
        fill_ones_after(&mut prm, 4, -3);
        assert_eq!(prm[1], 1);
    }
}
