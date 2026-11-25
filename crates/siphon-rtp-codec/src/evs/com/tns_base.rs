//! Temporal noise shaping configuration (TS 26.442 `lib_com/tns_base.c`; TS 26.445 §5.3.3.2.2).
//! Ported: the configuration, the TNS data containers, the lattice analysis / synthesis filters,
//! the inter-line (ITF) filter used for IGF, and the entropy decoders of the filter order and
//! coefficients.

use crate::evs::basop::{l_extract_lc, mpy_32_16_1};
use crate::evs::cnst::{
    ACELP_32K, IGF_START_MN, INDEX_SHIFT, ITF_MAX_FILTER_ORDER, N_MAX, PRED_GAIN_E,
    TNS_MAX_FILTER_ORDER, TNS_MAX_NUM_OF_FILTERS,
};
use crate::evs::com::basop_util::divide3232;
use crate::evs::com::basop_util::{get_scale_factor32, imult1616, norm32_norm};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::lpc_tools::e_lpc_schur;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::state::STnsConfig;
use crate::evs::rom::types::Coding;
use crate::evs::rom::{
    CODESTNSCOEFFSWBTCX10, CODESTNSCOEFFSWBTCX20, CODESTNSCOEFFWBTCX20, CODESTNSORDER,
    CODESTNSORDERTCX10, CODESTNSORDERTCX20, NTNSCOEFFCODES, NTNSORDERCODES, TNSCOEFF4,
};
use crate::evs::rom::{
    TNSPARAMETERS16KHZ, TNSPARAMETERS16KHZ_GROUPED, TNSPARAMETERS32KHZ, TNSPARAMETERS32KHZ_GROUPED,
    TNSPARAMETERS48KHZ_GROUPED, TNSPARAMETERSIGF32KHZ_LOWBR,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_h, l_deposit_l, l_mult, l_shl, l_shr, l_sub, mult,
    norm_l, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::mac_32;
use crate::itu::stl2009::{div_l, l_mac0, l_mult0};

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

/// `MAX_SUBDIVISIONS`: the number of spectrum parts `ITF_Detect_fx` measures.
const MAX_SUBDIVISIONS: usize = 3;

/// `STnsFilter`: the parameters of one TNS filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct STnsFilter {
    /// `spectrumLength`: number of subbands covered by the filter.
    pub spectrum_length: i16,
    /// `order`: filter order.
    pub order: i16,
    /// `coefIndex`: quantized filter coefficients (index minus `INDEX_SHIFT`).
    pub coef_index: [i16; TNS_MAX_FILTER_ORDER as usize],
    /// `predictionGain`: the ratio of a signal and TNS residual energy (exponent `PRED_GAIN_E`).
    pub prediction_gain: i16,
    /// `avgSqrCoef`: average squared filter coefficient (exponent 0).
    pub avg_sqr_coef: i16,
}

impl STnsFilter {
    /// All fields zero, as a `calloc`ed or `memset` reference object.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            spectrum_length: 0,
            order: 0,
            coef_index: [0; TNS_MAX_FILTER_ORDER as usize],
            prediction_gain: 0,
            avg_sqr_coef: 0,
        }
    }
}

/// `STnsData`: the TNS data describing all active filters of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct STnsData {
    /// `nFilters`: number of active filters.
    pub n_filters: i16,
    /// `filter`: the filters.
    pub filter: [STnsFilter; TNS_MAX_NUM_OF_FILTERS as usize],
}

impl STnsData {
    /// All fields zero.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            n_filters: 0,
            filter: [STnsFilter::zeroed(); TNS_MAX_NUM_OF_FILTERS as usize],
        }
    }
}

/// The reference's `TNS_NO_ERROR` as returned through a `Word16`.
pub const TNS_NO_ERROR: i16 = 0;
/// The reference's `TNS_FATAL_ERROR` as returned through a `Word16`.
pub const TNS_FATAL_ERROR: i16 = 1;

/// `TLinearPredictionFilter`: one sample through a lattice filter of `order` stages with PARCOR
/// coefficients `par_coeff` (Q15) and state `state`.
type LinearPredictionFilter = fn(i16, &[i16], &mut [i32], i32) -> i32;

/// `ClearTnsFilterCoefficients`: order and all coefficient indices to zero.
pub fn clear_tns_filter_coefficients(tns_filter: &mut STnsFilter) {
    tns_filter.order = 0;
    tns_filter.coef_index = [0; TNS_MAX_FILTER_ORDER as usize];
}

/// `ResetTnsData`: no filters, every filter cleared with a prediction gain of 1.0 (Q7).
pub fn reset_tns_data(tns_data: &mut STnsData) {
    tns_data.n_filters = 0;

    for tns_filter in &mut tns_data.filter {
        tns_filter.spectrum_length = 0;
        tns_filter.prediction_gain = 128 /* 1.0f Q7 */;
        tns_filter.avg_sqr_coef = 0;
        clear_tns_filter_coefficients(tns_filter);
    }
}

/// `Index2Parcor`: the PARCOR coefficients (Q15) of the quantisation indices `index[0..order]`.
fn index2_parcor(index: &[i16], par_coeff: &mut [i16], order: i16) {
    let values = &TNSCOEFF4;

    for i in 0..order.max(0) as usize {
        // a corrupted index would leave the 4-bit table (the reference reads out of bounds)
        par_coeff[i] = values[add(index[i], INDEX_SHIFT).clamp(0, 15) as usize];
    }
}

/// `FIRLattice`: one sample through the lattice analysis filter.
fn fir_lattice(order: i16, par_coeff: &[i16], state: &mut [i32], x: i32) -> i32 {
    let mut x = x;
    let mut tmp_save = l_add(x, 0);
    for i in 0..(order - 1).max(0) as usize {
        let tmp = l_add(state[i], mpy_32_16_1(x, par_coeff[i]));
        x = l_add(x, mpy_32_16_1(state[i], par_coeff[i])); // exponent: 31+0
        state[i] = tmp_save;
        tmp_save = l_add(tmp, 0);
    }

    // last stage: only need half operations
    let last = (order - 1) as usize;
    x = l_add(x, mpy_32_16_1(state[last], par_coeff[last]));
    state[last] = tmp_save;

    x
}

/// `IIRLattice`: one sample through the lattice synthesis filter.
fn iir_lattice(order: i16, par_coeff: &[i16], state: &mut [i32], x: i32) -> i32 {
    // first stage: no need to calculate state[order-1]
    let last = (order - 1) as usize;
    let mut x = l_sub(x, mpy_32_16_1(state[last], par_coeff[last]));

    for i in (0..last).rev() {
        x = l_sub(x, mpy_32_16_1(state[i], par_coeff[i]));
        state[i + 1] = l_add(state[i], mpy_32_16_1(x, par_coeff[i]));
    }

    state[0] = x;
    x
}

/// `TnsFilter` on a spectrum filtered in place (its only call, `output == spectrum`, so the
/// reference's copy for `order == 0` never happens): run `num_of_lines` lines through `filter`.
fn tns_filter(
    spectrum: &mut [i32],
    num_of_lines: i16,
    par_coeff: &[i16],
    order: i16,
    filter: LinearPredictionFilter,
    state: &mut [i32],
) {
    if order != 0 {
        for line in &mut spectrum[..num_of_lines.max(0) as usize] {
            *line = filter(order, par_coeff, state, *line);
        }
    }
}

/// `ApplyTnsFilter`: run the TNS filters of `tns_data` over the lines of `spectrum` their borders
/// in `tns_config` delimit, highest filter first, as analysis (`f_is_analysis`, FIR lattice) or
/// synthesis (IIR lattice). Returns `TNS_FATAL_ERROR` for a negative filter count.
pub fn apply_tns_filter(
    tns_config: &STnsConfig,
    tns_data: &STnsData,
    spectrum: &mut [i32],
    f_is_analysis: i8,
) -> i16 {
    let mut state = [0i32; TNS_MAX_FILTER_ORDER as usize];
    let filter: LinearPredictionFilter = if f_is_analysis != 0 {
        fir_lattice
    } else {
        iir_lattice
    };
    let borders = &tns_config.i_filter_borders;

    for i_filter in (0..tns_config.n_max_filters.max(0) as usize).rev() {
        let mut par_coeff = [0i16; TNS_MAX_FILTER_ORDER as usize];
        let filter_data = &tns_data.filter[i_filter];
        let stop_line = borders[i_filter];
        let start_line = borders[i_filter + 1];

        index2_parcor(&filter_data.coef_index, &mut par_coeff, filter_data.order);

        tns_filter(
            &mut spectrum[start_line as usize..],
            sub(stop_line, start_line),
            &par_coeff,
            filter_data.order,
            filter,
            &mut state,
        );
    }

    if tns_data.n_filters < 0 {
        TNS_FATAL_ERROR
    } else {
        TNS_NO_ERROR
    }
}

/// `ITF_TnsFilter_fx` on a spectrum filtered in place (its only call): the FIR filter
/// `1 + Σ A[i] z^-i` (`A` in Q`q_a`) over `num_of_lines` lines.
// the line index addresses both the output and the history behind it
#[allow(clippy::needless_range_loop)]
fn itf_tns_filter(spectrum: &mut [i32], num_of_lines: i16, a: &[i16], q_a: i16, order: i16) {
    const ORDER_MAX: usize = ITF_MAX_FILTER_ORDER as usize;
    let mut buf = [0i32; ORDER_MAX + N_MAX as usize];

    if order != 0 {
        let shift = sub(15, q_a);
        let num_of_lines = num_of_lines.max(0) as usize;

        // p = buf + ITF_MAX_FILTER_ORDER, behind a zeroed history of the filter's reach
        buf[ORDER_MAX..ORDER_MAX + num_of_lines].copy_from_slice(&spectrum[..num_of_lines]);
        for j in 0..num_of_lines {
            let p = ORDER_MAX + j;
            let mut l_tmp = l_add(buf[p], 0);
            for i in 1..order as usize {
                l_tmp = l_add(l_tmp, l_shl(mpy_32_16_1(buf[p - i], a[i]), shift));
            }
            spectrum[j] = l_tmp;
        }
    }
}

/// `ITF_Apply_fx`: filter `spectrum[start_line..stop_line]` in place with the ITF filter `a`.
pub fn itf_apply(
    spectrum: &mut [i32],
    start_line: i16,
    stop_line: i16,
    a: &[i16],
    q_a: i16,
    order: i16,
) -> i16 {
    itf_tns_filter(
        &mut spectrum[start_line as usize..],
        stop_line - start_line,
        a,
        q_a,
        order,
    );

    TNS_NO_ERROR
}

/// `ITF_GetFilterParameters_fx`: the ITF filter `a` (Q`*q_a`) of order `max_order` and its
/// prediction gain (exponent `PRED_GAIN_E`) from the autocorrelation `rxx` (scaled in place), via
/// the Schur recursion and the step-up from reflection to LPC coefficients.
fn itf_get_filter_parameters(
    rxx: &mut [i32],
    max_order: i16,
    a: &mut [i16],
    q_a: &mut i16,
    prediction_gain: &mut i16,
) {
    const ORDER_MAX: usize = ITF_MAX_FILTER_ORDER as usize;
    let mut par_coeff = [0i16; ORDER_MAX];
    let mut eps_p = [0i32; ORDER_MAX + 1];

    // compute filter in ParCor form with LeRoux-Gueguen algorithm
    let l_tmp = e_lpc_schur(rxx, &mut par_coeff, &mut eps_p, max_order);
    // Allow saturation, this value is compared against a threshold.
    *prediction_gain = crate::evs::com::basop_util::divide3232(l_shr(eps_p[0], PRED_GAIN_E), l_tmp);

    let mut a32 = [0i32; ORDER_MAX + 1];
    let order = max_order.max(0) as usize;

    // Convert ParCor / reflection coefficients to LPC
    a32[0] = 134217728 /* 1.0 Q27 */; // Q11+16
    a32[1] = l_shr(l_deposit_h(par_coeff[0]), 4); // Q11+16

    for i in 1..order {
        let i_2 = shr(i as i16, 1) as usize;
        let mut j = 0usize;
        while j < i_2 {
            let (tmp1_h, tmp1_l) = l_extract_lc(a32[i - 1 - j + 1]);
            let (tmp2_h, tmp2_l) = l_extract_lc(a32[j + 1]);
            // += parCoeff[i] * a[i-1-j+1];
            a32[j + 1] = mac_32(a32[j + 1], par_coeff[i], 0, tmp1_h, tmp1_l);
            // += parCoeff[i] * tmp;
            a32[i - 1 - j + 1] = mac_32(a32[i - 1 - j + 1], par_coeff[i], 0, tmp2_h, tmp2_l);
            j += 1;
        }
        if i & 1 != 0 {
            let (tmp2_h, tmp2_l) = l_extract_lc(a32[j + 1]);
            // += parCoeff[i] * a[j+1];
            a32[j + 1] = mac_32(a32[j + 1], par_coeff[i], 0, tmp2_h, tmp2_l);
        }

        a32[i + 1] = l_shr(l_deposit_h(par_coeff[i]), 4); // Q11+16
    }

    let mut tmp: i16 = 3; // assume Q11 -> Q14
    for &value in &a32[..order] {
        tmp = tmp.min(norm_l(value));
    }
    for i in 0..order {
        a[i] = round_word(l_shl(a32[i], tmp)); // Q11+tmp
    }
    *q_a = add(11, tmp);
}

/// `ITF_Detect_fx`: analyse `p_spectrum` (the spectrum from line `IGF_START_MN` on, Q`q`) between
/// `start_line` and `stop_line` in three parts, and when none of them is too quiet derive the ITF
/// filter (`a`, `q_a`, `prediction_gain`) from the normalised autocorrelation of the whole range,
/// setting `curr_order`. Returns 0 for `max_order <= 0`, else 1.
pub fn itf_detect(
    p_spectrum: &[i32],
    start_line: i16,
    stop_line: i16,
    max_order: i16,
    a: &mut [i16],
    q_a: &mut i16,
    prediction_gain: &mut i16,
    curr_order: &mut i16,
    q: i16,
) -> i16 {
    const N_SUBDIVISIONS: i16 = MAX_SUBDIVISIONS as i16;
    let idx0 = start_line;
    let idx1 = stop_line;
    let mut facs = [0i16; MAX_SUBDIVISIONS];
    let mut facs_e = [0i16; MAX_SUBDIVISIONS]; // exponents of facs[][]
    let mut shifts = [0i16; MAX_SUBDIVISIONS];
    let mut rxx = [0i32; ITF_MAX_FILTER_ORDER as usize + 1];
    let mut tmpbuf = [0i16; 325];

    if max_order <= 0 {
        return 0;
    }

    // The part of the spectrum [i_start_line, i_end_line) of subdivision `i_subdivisions`, as
    // lines relative to `p_spectrum` (the reference offsets its pointer by IGF_START_MN)
    let part = |i_subdivisions: i16, length: i16| -> (i16, i16) {
        let mut i_start_line = imult1616(length, i_subdivisions);
        let mut i_end_line = add(i_start_line, length);

        if sub(N_SUBDIVISIONS, 3) == 0 {
            i_start_line = mult(i_start_line, 0x2AAB);
        }
        i_start_line = add(i_start_line, idx0);

        if sub(N_SUBDIVISIONS, 3) == 0 {
            i_end_line = mult(i_end_line, 0x2AAB);
        }
        i_end_line = add(i_end_line, idx0);
        (i_start_line, i_end_line)
    };
    let relative = |line: i16| -> usize { sub(line, IGF_START_MN).max(0) as usize };

    // Calculate norms for each spectrum part
    for i_subdivisions in 0..N_SUBDIVISIONS {
        let (i_start_line, i_end_line) = part(i_subdivisions, sub(idx1, idx0));
        let length = sub(i_end_line, i_start_line);
        let band = &p_spectrum[relative(i_start_line)..];
        let headroom = get_scale_factor32(band, length);
        // Calculate norm of spectrum band
        let mut shift = 0i16;
        let mut l_tmp = norm32_norm(band, headroom, length, &mut shift);

        // Check threshold HLM_MIN_NRG
        let tmp32 = l_sub(
            l_shl(l_tmp, sub(shift, 24 - q)),
            4194304, /* HLM_MIN_NRG Q7 */
        );

        // get pre-shift for autocorrelation
        let mut tmp = sub(shift, norm_l(l_tmp)); // exponent for normalized L_tmp
        tmp = shr(sub(1, tmp), 1); // pre-shift to apply before autocorrelation
        let index = i_subdivisions as usize;
        shifts[index] = tmp.min(headroom);

        // calc normalization factor
        facs[index] = 0;
        facs_e[index] = 0;

        if tmp32 > 0 {
            facs[index] = 0x7FFF; // normalization not needed for one subdivision
        }

        if tmp32 > 0 && sub(N_SUBDIVISIONS, 1) > 0 {
            facs_e[index] = shl(sub(tmp, shifts[index]), 1);

            tmp = sub(1, shl(tmp, 1)); // exponent of autocorrelation
            l_tmp = l_shl(l_tmp, sub(shift, tmp)); // shift L_tmp to that exponent

            // calc factor (with 2 bits headroom for sum of 3 subdivisions)
            facs[index] = div_s(0x2000, round_word(l_tmp)); // L_tmp is >= 0x2000000
        }
    }

    // Calculate normalized autocorrelation for spectrum subdivision and get filter parameters
    // based on it
    let spectrum_length = sub(idx1, idx0);

    let mut i_subdivisions: i16 = 0;
    while i_subdivisions < N_SUBDIVISIONS {
        let index = i_subdivisions as usize;
        if facs[index] == 0 {
            break;
        }

        let (i_start_line, i_end_line) = part(i_subdivisions, spectrum_length);

        let shift = shifts[index];

        let n = sub(i_end_line, i_start_line);
        // the reference asserts n < the size of tmpbuf
        for i in 0..n.max(0) as usize {
            tmpbuf[i] = round_word(l_shl(p_spectrum[relative(i_start_line) + i], shift));
        }

        for lag in 0..=max_order {
            let n = sub(sub(i_end_line, lag), i_start_line);

            let mut l_tmp = l_deposit_l(0);
            for i in 0..n.max(0) as usize {
                l_tmp = l_mac0(l_tmp, tmpbuf[i], tmpbuf[i + lag as usize]);
            }

            l_tmp = mpy_32_16_1(l_tmp, facs[index]);
            l_tmp = l_shl(l_tmp, facs_e[index]);

            rxx[lag as usize] = l_add(rxx[lag as usize], l_tmp);
        }
        i_subdivisions += 1;
    }

    if sub(i_subdivisions, N_SUBDIVISIONS) == 0 {
        // meaning there is no subdivision with low energy
        // Limit the maximum order to spectrum length/4
        itf_get_filter_parameters(
            &mut rxx,
            max_order.min(shr(spectrum_length, 2)),
            a,
            q_a,
            prediction_gain,
        );

        *curr_order = max_order;
    }

    1
}

/// `DecodeUsingTable`: read the prefix code of one value of `codes` (sorted by value, `n_size`
/// entries) from the bitstream bit by bit. Returns the number of bits read; on a code that no
/// entry has within `n_size` / 16 bits it flags `BER_detect`, stores 0 and returns -1.
fn decode_using_table(
    st: &mut DecoderState,
    p_value: &mut i16,
    codes: &[Coding],
    n_size: i16,
) -> i16 {
    let mut code: i16 = 0;
    let mut n_bits: i16 = 0;
    let mut value_index = n_size;

    while value_index == n_size {
        code = add(shl(code, 1), get_next_indice(st, 1) as i16);
        n_bits = add(n_bits, 1);
        if n_bits > n_size || n_bits > 16 {
            st.ber_detect = 1;
            *p_value = 0;

            return -1;
        }

        value_index = 0;
        while value_index < n_size {
            let entry = &codes[value_index as usize];
            if (sub(i16::from(entry.n_bits), n_bits) == 0) & (sub(entry.code, code) == 0) {
                break;
            }
            value_index += 1;
        }
    }
    if value_index < n_size {
        *p_value = i16::from(codes[value_index as usize].value);
    } else {
        st.ber_detect = 1;
        *p_value = 0;

        return -1;
    }

    n_bits
}

/// `SetTnsFilterCoeff`: store the decoded coefficient `value` as the index `value - INDEX_SHIFT`
/// of coefficient `index`.
pub fn set_tns_filter_coeff(coef_index: &mut [i16], index: i16, value: i16) {
    coef_index[index as usize] = sub(value, INDEX_SHIFT);
}

/// `DecodeSWBTCX20TnsFilterCoeff`: the coefficient `index` of a 20 ms SWB/FB filter.
pub fn decode_swbtcx20_tns_filter_coeff(
    st: &mut DecoderState,
    index: i16,
    p_value: &mut i16,
) -> i16 {
    decode_using_table(
        st,
        p_value,
        CODESTNSCOEFFSWBTCX20[index as usize],
        NTNSCOEFFCODES,
    )
}

/// `DecodeSWBTCX10TnsFilterCoeff`: the coefficient `index` of a 10 ms SWB/FB filter.
pub fn decode_swbtcx10_tns_filter_coeff(
    st: &mut DecoderState,
    index: i16,
    p_value: &mut i16,
) -> i16 {
    decode_using_table(
        st,
        p_value,
        CODESTNSCOEFFSWBTCX10[index as usize],
        NTNSCOEFFCODES,
    )
}

/// `DecodeWBTCX20TnsFilterCoeff`: the coefficient `index` of a 20 ms WB filter.
pub fn decode_wbtcx20_tns_filter_coeff(
    st: &mut DecoderState,
    index: i16,
    p_value: &mut i16,
) -> i16 {
    decode_using_table(
        st,
        p_value,
        CODESTNSCOEFFWBTCX20[index as usize],
        NTNSCOEFFCODES,
    )
}

/// `SetTnsFilterOrder`: store the decoded `order` of filter `index`.
pub fn set_tns_filter_order(filters: &mut [STnsFilter], index: i16, value: i16) {
    filters[index as usize].order = value;
}

/// `DecodeTnsFilterOrderSWBTCX20`: the order of a 20 ms SWB/FB filter.
pub fn decode_tns_filter_order_swbtcx20(
    st: &mut DecoderState,
    _index: i16,
    p_value: &mut i16,
) -> i16 {
    decode_using_table(st, p_value, &CODESTNSORDERTCX20, NTNSORDERCODES)
}

/// `DecodeTnsFilterOrderSWBTCX10`: the order of a 10 ms SWB/FB filter.
pub fn decode_tns_filter_order_swbtcx10(
    st: &mut DecoderState,
    _index: i16,
    p_value: &mut i16,
) -> i16 {
    decode_using_table(st, p_value, &CODESTNSORDERTCX10, NTNSORDERCODES)
}

/// `DecodeTnsFilterOrder`: the order of a 20 ms WB filter.
pub fn decode_tns_filter_order(st: &mut DecoderState, _index: i16, p_value: &mut i16) -> i16 {
    decode_using_table(st, p_value, &CODESTNSORDER, NTNSORDERCODES)
}

/// `SetNumOfTnsFilters`: store the decoded filter count of `tns_data`.
pub fn set_num_of_tns_filters(tns_data: &mut STnsData, value: i16) {
    tns_data.n_filters = value;
}

/// `SetTnsEnabledSingleFilter`: a single-filter (WB) frame's enable flag is its filter count.
pub fn set_tns_enabled_single_filter(tns_data: &mut STnsData, value: i16) {
    tns_data.n_filters = value;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_leaves_unit_prediction_gain_and_no_filters() {
        let mut data = STnsData::zeroed();
        data.n_filters = 2;
        data.filter[1].order = 5;
        data.filter[1].coef_index[3] = -4;
        reset_tns_data(&mut data);
        assert_eq!(data.n_filters, 0);
        assert!(data
            .filter
            .iter()
            .all(|f| f.order == 0 && f.prediction_gain == 128 && f.coef_index == [0; 8]));
    }

    #[test]
    fn a_zero_order_filter_leaves_the_spectrum_alone() {
        let mut spectrum = [5, -6, 7];
        let mut state = [0; 8];
        tns_filter(&mut spectrum, 3, &[0; 8], 0, iir_lattice, &mut state);
        assert_eq!(spectrum, [5, -6, 7]);
    }

    #[test]
    fn the_lattice_synthesis_undoes_the_analysis() {
        // a lattice synthesis filter inverts the analysis filter with the same coefficients,
        // up to the rounding of the Q15 products
        let par_coeff = [6813i16, -6021, 0, 0, 0, 0, 0, 0];
        let input = [100_000i32, -80_000, 50_000, 20_000, -90_000, 70_000];
        let mut analysed = input;
        let mut state = [0i32; 8];
        tns_filter(&mut analysed, 6, &par_coeff, 2, fir_lattice, &mut state);
        let mut state = [0i32; 8];
        tns_filter(&mut analysed, 6, &par_coeff, 2, iir_lattice, &mut state);
        for (a, b) in analysed.iter().zip(&input) {
            assert!((a - b).abs() < 8);
        }
    }
}
