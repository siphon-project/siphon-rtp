//! Temporal noise shaping configuration (TS 26.442 `lib_com/tns_base.c`; TS 26.445 §5.3.3.2.2).
//! Only the configuration the decoder initialisation runs is ported so far.

use crate::evs::cnst::{ACELP_32K, TNS_MAX_FILTER_ORDER};
use crate::evs::com::basop_util::divide3232;
use crate::evs::dec::state::STnsConfig;
use crate::evs::rom::{
    TNSPARAMETERS16KHZ, TNSPARAMETERS16KHZ_GROUPED, TNSPARAMETERS32KHZ, TNSPARAMETERS32KHZ_GROUPED,
    TNSPARAMETERS48KHZ_GROUPED, TNSPARAMETERSIGF32KHZ_LOWBR,
};
use crate::itu::basic_ops::{extract_h, l_mult, l_shl, l_sub, norm_l, shr, sub};
use crate::itu::stl2009::{div_l, l_mult0};

/// `WORD16_BITS` (lib_com/basop_util.h).
const WORD16_BITS: i16 = 16;

/// The reference's `TNS_ERROR` values other than `TNS_NO_ERROR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TnsError {
    /// `TNS_FATAL_ERROR`: a non-positive sample rate or frame length (the reference asserts
    /// before returning it).
    Fatal,
}

/// `InitTnsConfiguration`: the TNS filter set (`pTnsParameters`, `nMaxFilters`) for a frame of
/// `frame_length` MDCT lines at `n_sample_rate`, the MDCT line each filter starts at, and the
/// upper border (`iFilterBorders[0]`, the IGF stop frequency's line when IGF runs).
///
/// # Errors
/// [`TnsError::Fatal`] for a non-positive sample rate or frame length; the configuration is then
/// left untouched.
pub fn init_tns_configuration(
    n_sample_rate: i32,
    frame_length: i16,
    p_tns_config: &mut STnsConfig,
    igf_stop_freq: i16,
    bitrate: i32,
) -> Result<(), TnsError> {
    // Sanity checks
    if n_sample_rate <= 0 || frame_length <= 0 {
        return Err(TnsError::Fatal);
    }

    // Initialize TNS filter flag and maximum order
    p_tns_config.max_order = TNS_MAX_FILTER_ORDER;

    if l_sub(bitrate, i32::from(ACELP_32K)) <= 0 {
        p_tns_config.p_tns_parameters = &TNSPARAMETERSIGF32KHZ_LOWBR;
    } else if l_sub(n_sample_rate, 32000) > 0
        && l_sub(n_sample_rate, l_mult0(100, frame_length)) == 0
    {
        p_tns_config.p_tns_parameters = &TNSPARAMETERS48KHZ_GROUPED;
    } else if l_sub(n_sample_rate, 16000) > 0 {
        p_tns_config.p_tns_parameters = &TNSPARAMETERS32KHZ;
        if l_sub(n_sample_rate, l_mult0(100, frame_length)) == 0 {
            // sub-frame length is <= 10 ms
            p_tns_config.p_tns_parameters = &TNSPARAMETERS32KHZ_GROUPED;
        }
    } else if l_sub(n_sample_rate, l_mult0(100, frame_length)) == 0 {
        // sub-frame length is <= 10 ms
        p_tns_config.p_tns_parameters = &TNSPARAMETERS16KHZ_GROUPED;
    } else {
        p_tns_config.p_tns_parameters = &TNSPARAMETERS16KHZ;
    }
    // `nMaxFilters` is the element count of the table chosen (in the 32 kHz branch the count of
    // `tnsParameters32kHz`, which its grouped variant shares); at most TNS_MAX_NUM_OF_FILTERS.
    p_tns_config.n_max_filters = p_tns_config.p_tns_parameters.len() as i16;

    // Set starting MDCT line for each filter based on the starting frequencies from the TNS table
    let n_max_filters = p_tns_config.n_max_filters as usize;
    for i_filter in 0..n_max_filters {
        let start_line_frequency = p_tns_config.p_tns_parameters[i_filter].start_line_frequency;
        // startLineFilter = &iFilterBorders[1]
        p_tns_config.i_filter_borders[1 + i_filter] = divide3232(
            l_mult0(frame_length, start_line_frequency),
            l_shl(n_sample_rate, 14),
        );
    }

    if igf_stop_freq > 0 {
        let l_tmp = l_mult(frame_length, igf_stop_freq);
        let s1 = sub(norm_l(l_tmp), 1);
        let s2 = norm_l(n_sample_rate);

        p_tns_config.i_filter_borders[0] = shr(
            div_l(l_shl(l_tmp, s1), extract_h(l_shl(n_sample_rate, s2))),
            sub(WORD16_BITS - 1, sub(s2, s1)),
        );
    } else {
        p_tns_config.i_filter_borders[0] = frame_length;
    }

    Ok(())
}
