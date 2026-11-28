//! MODE1 core and extension-layer selection from the bitstream (TS 26.442
//! `lib_dec/decision_matrix_dec_fx.c`; TS 26.445 §7.1.1).

use crate::evs::cnst::{
    ACELP_13K20, ACELP_16K40, ACELP_24K40, ACELP_32K, ACELP_48K, ACELP_64K, ACELP_8K00, ACELP_9K60,
    ACELP_CORE, AMR_WB_CORE, AUDIO, FB, FB_BWE, FB_BWE_1K8, FB_BWE_HIGHRATE, FB_TBE, FB_TBE_3K0,
    FRAME_NO_DATA, GENERIC, HQ_96K, HQ_CORE, INACTIVE, INT_FS_FX, LOW_RATE_HQ_CORE, LP_CNG,
    LRMDCT_CROSSOVER_POINT, LR_MDCT, L_FRAME, L_FRAME16K, MAX_ACELP_SIG, MIN_ACT_CNG_UPD, MODE1,
    MODE2, NB, NB_SUBFR, NB_SUBFR16K, NORMAL_HQ_CORE, PPP_NELP_2K80, SID_2K40, SWB, SWB_BWE,
    SWB_BWE_16K, SWB_BWE_1K6, SWB_BWE_HIGHRATE, SWB_CNG, SWB_TBE, SWB_TBE_1K6, SWB_TBE_2K8,
    TCX_10_CORE, TCX_20_CORE, TRANSITION, UNVOICED, VOICED, WB, WB_BWE, WB_BWE_0K35, WB_TBE,
    WB_TBE_1K05,
};
use crate::evs::com::bitstream::{get_next_indice, get_next_indice_tmp};
use crate::evs::com::core_com_config::sr2fscale;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::ACELP_SIG_TBL;
use crate::itu::basic_ops::{add, extract_l, l_sub};

/// `decision_matrix_dec_fx`: ACELP/HQ core selection, the ACELP signalling (coder type,
/// bandwidth, formant sharpening flag), the extension layer, the HQ signalling and the ACELP frame
/// length. On corrupted signalling it marks the frame bad and falls back to the last good
/// configuration.
pub fn decision_matrix_dec(
    st: &mut DecoderState,
    coder_type: &mut i16,
    sharp_flag: &mut i16,
    hq_core_type: &mut i16,
    core_switching_flag: &mut i16,
) {
    st.core = -1;
    st.core_brate = 0;
    st.extl = -1;
    st.extl_brate = 0;
    st.ppp_mode_dec = 0;
    st.nelp_mode_dec = 0;
    st.igf = 0;

    if st.total_brate > i32::from(ACELP_8K00) {
        st.vbr_hw_bwe_disable_dec = 0;
    }

    if st.mdct_sw == MODE2 {
        st.core = HQ_CORE;
    } else {
        if st.total_brate == i32::from(FRAME_NO_DATA) || st.total_brate == i32::from(SID_2K40) {
            decision_matrix_dec_cng(st);
            return;
        }
        if st.total_brate == i32::from(PPP_NELP_2K80) {
            // SC-VBR
            decision_matrix_dec_ppp_nelp(st, coder_type);
            return;
        }
        // ACELP/HQ core selection
        if st.total_brate < i32::from(ACELP_24K40) {
            st.core = ACELP_CORE;
        } else if st.total_brate <= ACELP_64K {
            // read the ACELP/HQ core selection bit
            let temp_core = get_next_indice(st, 1);
            st.core = if temp_core == 0 { ACELP_CORE } else { HQ_CORE };
        }
    }

    // Read ACELP signalling bits from the bitstream
    if st.core == ACELP_CORE && decision_matrix_dec_acelp_signalling(st, coder_type, sharp_flag) {
        return;
    }

    decision_matrix_dec_extension_layers(st);

    // set core bitrate
    st.core_brate = l_sub(st.total_brate, st.extl_brate);

    // Read HQ signalling bits from the bitstream; set HQ core type
    if st.core == HQ_CORE {
        decision_matrix_dec_hq_signalling(st, hq_core_type, core_switching_flag);
    }

    decision_matrix_dec_frame_length(st);
}

/// The NO_DATA / SID branch: CNG type and internal frame length from the SID's bits.
fn decision_matrix_dec_cng(st: &mut DecoderState) {
    st.core = ACELP_CORE;
    st.core_brate = st.total_brate;
    if st.total_brate != i32::from(FRAME_NO_DATA) {
        st.cng_type = get_next_indice(st, 1) as i16;
        if st.cng_type == LP_CNG {
            st.l_frame = L_FRAME;
            if get_next_indice(st, 1) == 1 {
                st.l_frame = L_FRAME16K;
            }
        } else {
            st.bwidth = get_next_indice(st, 2) as i16;
            let tmp16 = get_next_indice(st, 1);
            st.l_frame = if tmp16 == 0 { L_FRAME } else { L_FRAME16K };
        }
    }
    if st.output_fs >= 32000 && st.bwidth >= SWB {
        st.extl = SWB_CNG;
    }
    if st.total_brate == i32::from(FRAME_NO_DATA)
        && st.prev_bfi != 0
        && st.bfi == 0
        && st.l_frame > L_FRAME16K
    {
        st.l_frame = st.last_cng_l_frame;
    }
}

/// The SC-VBR (2.8 kbit/s PPP / NELP) branch.
fn decision_matrix_dec_ppp_nelp(st: &mut DecoderState, coder_type: &mut i16) {
    st.core = ACELP_CORE;
    st.core_brate = i32::from(PPP_NELP_2K80);
    st.l_frame = L_FRAME;
    st.fscale = sr2fscale(i32::from(INT_FS_FX));
    if st.ini_frame == 0 {
        // avoid switching of internal ACELP Fs in the very first frame
        st.last_l_frame = st.l_frame;
        st.last_core = st.core;
        st.last_core_brate = st.core_brate;
        st.last_extl = st.extl;
    }
    st.vbr_hw_bwe_disable_dec = 1;
    get_next_indice(st, 1);
    // 0 - PPP_NB, 1 - PPP_WB, 2 - NELP_NB, 3 - NELP_WB
    match get_next_indice(st, 2) {
        0 => {
            st.ppp_mode_dec = 1;
            *coder_type = VOICED;
            st.bwidth = NB;
        }
        1 => {
            st.ppp_mode_dec = 1;
            *coder_type = VOICED;
            st.bwidth = WB;
        }
        2 => {
            st.nelp_mode_dec = 1;
            *coder_type = UNVOICED;
            st.bwidth = NB;
        }
        _ => {
            st.nelp_mode_dec = 1;
            *coder_type = UNVOICED;
            st.bwidth = WB;
        }
    }
}

/// The ACELP signalling: coder type, bandwidth and sharpening flag from `acelp_sig_tbl`. Returns
/// `true` when the signalling was corrupted and the function must return (the frame is bad).
fn decision_matrix_dec_acelp_signalling(
    st: &mut DecoderState,
    coder_type: &mut i16,
    sharp_flag: &mut i16,
) -> bool {
    // find the section in the ACELP signalling table corresponding to bitrate
    let mut start_idx: i16 = 0;
    while ACELP_SIG_TBL
        .get(start_idx as usize)
        .is_some_and(|&entry| entry != st.total_brate)
    {
        start_idx = add(start_idx, 1);
        if start_idx >= MAX_ACELP_SIG {
            st.ber_detect = 1;
            start_idx = 0;
            break;
        }
    }
    // skip the bitrate
    start_idx = add(start_idx, 1);
    // retrieve the number of bits (start_idx is at most 100 here, inside the table)
    let n_bits = extract_l(ACELP_SIG_TBL.get(start_idx as usize).copied().unwrap_or(0));
    start_idx = add(start_idx, 1);
    start_idx = add(start_idx, get_next_indice(st, n_bits) as i16);

    let ind: i32 = if !(0..MAX_ACELP_SIG).contains(&start_idx) {
        // (a negative index is unreachable: the section sizes are at most 5 bits)
        st.ber_detect = 1;
        0
    } else {
        // retrieve the signalling indice
        let ind = ACELP_SIG_TBL[start_idx as usize];
        // convert signalling indice into signalling information
        *coder_type = extract_l(ind & 0x7);
        if *coder_type == LR_MDCT {
            st.core = HQ_CORE;
            st.bwidth = extract_l((ind >> 3) & 0x7);
        } else {
            st.bwidth = extract_l((ind >> 3) & 0x7);
            *sharp_flag = extract_l((ind >> 6) & 0x1);
        }
        ind
    };

    // detect corrupted signalling (due to bit errors)
    let total = st.total_brate;
    let corrupted = st.ber_detect != 0
        || ind >= 1 << 7
        || (total <= i32::from(ACELP_13K20) && st.bwidth == FB)
        || (total >= i32::from(ACELP_32K) && st.bwidth == NB)
        || (total >= i32::from(ACELP_32K)
            && !(*coder_type == GENERIC || *coder_type == TRANSITION || *coder_type == INACTIVE))
        || (total < i32::from(ACELP_13K20) && st.bwidth != NB && *coder_type == LR_MDCT)
        || (total >= i32::from(ACELP_13K20) && *coder_type == UNVOICED)
        || (total >= i32::from(ACELP_13K20) && *coder_type == AUDIO && st.bwidth == NB);
    if corrupted {
        decision_matrix_dec_ber_fallback(st, coder_type);
    }
    corrupted
}

/// Corrupted ACELP signalling: mark the frame bad and restore the last good configuration.
fn decision_matrix_dec_ber_fallback(st: &mut DecoderState, coder_type: &mut i16) {
    st.ber_detect = 0;
    st.bfi = 1;
    if st.ini_frame == 0 {
        st.core = ACELP_CORE;
        st.l_frame = L_FRAME;
        st.last_core = st.core;
        st.last_core_brate = st.core_brate;
        return;
    }
    *coder_type = st.last_coder_type;
    st.bwidth = st.last_bwidth;
    if st.last_total_brate == -1 {
        // can happen in case of BER when no good frame was received before
        st.total_brate = st.last_total_brate_ber;
        if st.last_core == AMR_WB_CORE {
            st.core = ACELP_CORE;
            st.codec_mode = MODE1;
        } else if st.last_core_bfi == TCX_20_CORE || st.last_core_bfi == TCX_10_CORE {
            st.core = st.last_core_bfi;
            st.codec_mode = MODE2;
        } else {
            st.core = st.last_core;
            st.codec_mode = MODE1;
        }
    } else {
        st.total_brate = st.last_total_brate;
        if st.last_core == AMR_WB_CORE {
            st.core = ACELP_CORE;
            st.codec_mode = MODE1;
        } else if st.last_core == TCX_20_CORE || st.last_core == TCX_10_CORE {
            st.core = st.last_core;
            st.codec_mode = MODE2;
        } else {
            st.core = st.last_core;
            st.codec_mode = MODE1;
        }
    }
    st.core_brate = st.last_core_brate;
    st.extl = st.last_extl;
    st.extl_brate = l_sub(st.total_brate, st.core_brate);
}

/// Set the extension layer (WB BWE/TBE, SWB/FB BWE/TBE) and its bit rate.
fn decision_matrix_dec_extension_layers(st: &mut DecoderState) {
    let total = st.total_brate;
    if st.core == ACELP_CORE && st.bwidth == WB && total < i32::from(ACELP_9K60) {
        if st.vbr_hw_bwe_disable_dec == 0 {
            st.extl = WB_BWE;
        }
    } else if st.core == ACELP_CORE
        && st.bwidth == WB
        && total >= i32::from(ACELP_9K60)
        && total <= i32::from(ACELP_16K40)
    {
        // read the WB TBE/BWE selection bit
        if get_next_indice(st, 1) == 1 {
            st.extl = WB_BWE;
            st.extl_brate = i32::from(WB_BWE_0K35);
        } else {
            st.extl = WB_TBE;
            st.extl_brate = i32::from(WB_TBE_1K05);
        }
    } else if st.core == ACELP_CORE
        && (st.bwidth == SWB || st.bwidth == FB)
        && total >= i32::from(ACELP_13K20)
    {
        if total >= ACELP_48K {
            st.extl = SWB_BWE_HIGHRATE;
            if st.bwidth == FB {
                st.extl = FB_BWE_HIGHRATE;
            }
            st.extl_brate = i32::from(SWB_BWE_16K);
        } else if get_next_indice(st, 1) != 0 {
            // read the SWB TBE/BWE selection bit
            st.extl = SWB_BWE;
            st.extl_brate = i32::from(SWB_BWE_1K6);
        } else {
            st.extl = SWB_TBE;
            st.extl_brate = i32::from(SWB_TBE_1K6);
            if total >= i32::from(ACELP_24K40) {
                st.extl_brate = i32::from(SWB_TBE_2K8);
            }
        }
        // set FB TBE and FB BWE extension layers
        if st.bwidth == FB && total >= i32::from(ACELP_24K40) {
            if st.extl == SWB_BWE {
                st.extl = FB_BWE;
                st.extl_brate = i32::from(FB_BWE_1K8);
            } else if st.extl == SWB_TBE {
                st.extl = FB_TBE;
                st.extl_brate = i32::from(FB_TBE_3K0);
            }
        }
    }
}

/// The HQ signalling: core switching flag, last ACELP frame length, bandwidth, bit-error
/// detection and the HQ core type.
fn decision_matrix_dec_hq_signalling(
    st: &mut DecoderState,
    hq_core_type: &mut i16,
    core_switching_flag: &mut i16,
) {
    if st.mdct_sw != MODE2 {
        // skip the HQ/TCX core switching flag
        get_next_indice_tmp(st, 1);
    }
    // read ACELP->HQ core switching flag
    *core_switching_flag = get_next_indice(st, 1) as i16;
    if *core_switching_flag == 1 {
        st.last_l_frame_ori = st.last_l_frame;
        // read ACELP L_frame info
        st.last_l_frame = if get_next_indice(st, 1) == 0 {
            L_FRAME
        } else {
            L_FRAME16K
        };
    }
    if st.mdct_sw != MODE2 && st.total_brate > i32::from(ACELP_16K40) {
        // read/set band-width (needed for different I/O sampling rate support)
        st.bwidth = match get_next_indice(st, 2) {
            0 => NB,
            1 => WB,
            2 => SWB,
            _ => FB,
        };
    }

    // detect bit errors in signalling
    if (st.total_brate >= i32::from(ACELP_24K40) && st.bwidth == NB)
        || (st.core == HQ_CORE
            && st.total_brate <= i32::from(LRMDCT_CROSSOVER_POINT)
            && st.bwidth == FB)
    {
        st.bfi = 1;
        st.core_brate = st.total_brate;
        st.extl = -1;
        st.extl_brate = 0;
        if st.last_core == AMR_WB_CORE {
            st.core = ACELP_CORE;
            st.l_frame = L_FRAME;
            st.codec_mode = MODE1;
            st.last_l_frame = L_FRAME;
            if st.total_brate >= i32::from(ACELP_16K40) {
                st.total_brate = i32::from(ACELP_13K20);
                st.core_brate = st.total_brate;
            }
        } else {
            // make sure, we are in a valid configuration wrt to bandwidth
            st.bwidth = WB;
        }
    }

    // set HQ core type
    *hq_core_type = NORMAL_HQ_CORE;
    if ((st.bwidth == SWB || st.bwidth == WB)
        && st.total_brate <= i32::from(LRMDCT_CROSSOVER_POINT))
        || st.bwidth == NB
    {
        *hq_core_type = LOW_RATE_HQ_CORE;
    }
}

/// Set the ACELP frame length, the subframe count and the output-rate extension-layer overrides.
fn decision_matrix_dec_frame_length(st: &mut DecoderState) {
    let total = st.total_brate;
    if st.core_brate == i32::from(FRAME_NO_DATA) {
        // prevent "L_frame" changes in CNG segments
        st.l_frame = st.last_l_frame;
    } else if st.core_brate == i32::from(SID_2K40)
        && st.bwidth == WB
        && st.first_cng != 0
        && st.act_cnt2 < MIN_ACT_CNG_UPD
    {
        // prevent "L_frame" changes in SID frame after short segment of active frames
        st.l_frame = st.last_cng_l_frame;
    } else if (st.core_brate == i32::from(SID_2K40)
        && total >= i32::from(ACELP_9K60)
        && st.bwidth == WB)
        || (total > i32::from(ACELP_24K40) && total < HQ_96K)
        || (total == i32::from(ACELP_24K40) && st.bwidth >= WB)
    {
        st.l_frame = L_FRAME16K;
    } else {
        st.l_frame = L_FRAME;
    }

    st.nb_subfr = NB_SUBFR;
    if st.l_frame == L_FRAME16K {
        st.nb_subfr = NB_SUBFR16K;
    }

    if st.output_fs == 8000 {
        st.extl = -1;
    } else if st.output_fs == 16000 && st.l_frame == L_FRAME16K {
        st.extl = -1;
        st.extl_brate = 0;
    }

    if st.ini_frame == 0 {
        // avoid switching of internal ACELP Fs in the very first frame
        st.last_l_frame = st.l_frame;
        st.last_core = st.core;
        st.last_core_brate = st.core_brate;
        st.last_extl = st.extl;
    }
}
