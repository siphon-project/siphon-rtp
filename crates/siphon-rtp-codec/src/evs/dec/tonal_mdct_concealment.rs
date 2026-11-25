//! Tonal MDCT concealment (TS 26.442 `lib_dec/tonalMDCTconcealment.c`; TS 26.445 §5.4.3.6).
//!
//! The reference overlays a `TonalComponentsInfo` on the start of `timeDataBuffer`, and the PCM
//! history pointers into the same buffer can overlap it, so the tonal components are read and
//! written through `tci_view`, never through a separate copy. The generated `tcx_cfg` pointer
//! of the state has no field: the functions that need it (`CalcMDXT`, `TonalMDCTConceal_Detect`)
//! take the owning decoder's `&TcxConfig` instead.

mod insert_noise;
mod phases;

pub use insert_noise::tonal_mdct_conceal_insert_noise;

use crate::evs::basop::{mpy_32_16_1, mpy_32_32};
use crate::evs::cnst::{
    FDNS_NPTS, FULL_OVERLAP, GROUP_LENGTH, L_FRAME_MAX, L_FRAME_PLUS, L_MDCT_OVLP_MAX,
    MAX_NUMBER_OF_IDX,
};
use crate::evs::com::basop_util::{get_cos_word16, get_scale_factor32, inv16, sqrt32};
use crate::evs::com::tcx_mdct::{tcx_mdct, tcx_mdst};
use crate::evs::com::tcx_utils::{mdct_shaping, mdct_shaping_16, window_signal};
use crate::evs::com::tools::{copy, set32};
use crate::evs::dec::state::{TcxConfig, Tonalmdctconceal};
use crate::evs::dec::tonal_component_detection::{
    detect_tonal_components, refine_tonal_components,
};
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_add, l_deposit_l, l_shl, l_shr, l_sub, mult_r, norm_s, round_word,
    shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// The reference's `TONALMDCTCONCEAL_ERROR` values other than `TONALMDCTCONCEAL_OK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TonalMdctConcealError {
    /// `TONALMDCTCONCEAL_NSAMPLES_LARGER_THAN_MAXBLOCKSIZE`: more than `L_FRAME_MAX` samples or
    /// `FDNS_NPTS` scale factors. (The reference asserts before returning it.)
    NSamplesLargerThanMaxBlockSize,
}

/// `TonalMDCTConceal_Init`: (re)configure the concealment for blocks of `n_samples` MDCT lines,
/// `n_samples_core` of them in the core band, and `n_scale_factors` scale factors.
///
/// Two pointer assignments of the reference have no field of their own here, because both always
/// alias the same storage: `self->tcx_cfg = tcx_cfg` (the caller always passes the owning
/// decoder's `tcx_cfg`, `core_dec_init.c`) and `self->pTCI = (TonalComponentsInfo *)
/// self->timeDataBuffer` (the tonal components overlay the start of `time_data_buffer`, which is
/// why `lastPcmOut` is offset towards its end). The generated `tcx_cfg` / `p_tci` fields are left
/// untouched.
///
/// # Errors
/// [`TonalMdctConcealError::NSamplesLargerThanMaxBlockSize`], with the state untouched.
pub fn tonal_mdct_conceal_init(
    this: &mut Tonalmdctconceal,
    n_samples: i16,
    n_samples_core: i16,
    n_scale_factors: i16,
) -> Result<(), TonalMdctConcealError> {
    if n_samples > L_FRAME_MAX || n_scale_factors > FDNS_NPTS {
        return Err(TonalMdctConcealError::NSamplesLargerThanMaxBlockSize);
    }

    this.last_block_data.spectral_data = Some(0);
    this.second_last_block_data.spectral_data = Some(1);
    this.second_last_power_spectrum = this.second_last_block_data.spectral_data;

    this.last_block_data.scale_factors = Some(0);
    this.second_last_block_data.scale_factors = Some(1);
    this.last_block_data.scale_factors_exp = Some(0);
    this.second_last_block_data.scale_factors_exp = Some(1);

    this.last_block_data.block_is_valid = 0;
    this.second_last_block_data.block_is_valid = 0;
    this.n_samples = 0;
    this.n_scale_factors = 0;

    this.last_block_data.block_is_concealed = 0;
    this.second_last_block_data.block_is_concealed = 0;

    this.last_pitch_lag = 0;

    // nSamples was just zeroed, so this always runs for a non-zero block length.
    if this.n_samples != n_samples {
        this.second_last_block_data.block_is_valid = 0;
        this.last_block_data.block_is_valid = 0;
    }

    this.n_samples = n_samples;
    this.n_samples_core = n_samples_core;
    this.n_scale_factors = n_scale_factors;

    // Offset the pointer to the end of buffer, so that pTCI is not destroyed when new time samples
    // are stored in lastPcmOut; just the second half of the second last pcm output is needed.
    // n_samples <= L_FRAME_MAX, so both offsets lie in 0..=1440 - n_samples.
    let samples = i32::from(L_FRAME_MAX.min(n_samples));
    let half_max = 3 * i32::from(L_FRAME_MAX) / 2;
    this.second_last_pcm_out = usize::try_from(half_max - 3 * samples / 2).ok();
    this.last_pcm_out = usize::try_from(i32::from(sub(half_max as i16, samples as i16))).ok();
    Ok(())
}

/// `TonalComponentsInfo` (`stat_dec_fx.h`) laid over the start of `timeDataBuffer`, field by
/// field: `numIndexes`, then the four `MAX_NUMBER_OF_IDX` arrays, then the predicted phases.
const TCI_INDEX_OF_TONAL_PEAK: usize = 1;
const TCI_LOWER_INDEX: usize = TCI_INDEX_OF_TONAL_PEAK + MAX_NUMBER_OF_IDX as usize;
const TCI_UPPER_INDEX: usize = TCI_LOWER_INDEX + MAX_NUMBER_OF_IDX as usize;
const TCI_PHASE_DIFF: usize = TCI_UPPER_INDEX + MAX_NUMBER_OF_IDX as usize;
const TCI_PHASE_CURRENT_FRAME_PREDICTED: usize = TCI_PHASE_DIFF + MAX_NUMBER_OF_IDX as usize;
const TCI_LENGTH: usize =
    TCI_PHASE_CURRENT_FRAME_PREDICTED + MAX_NUMBER_OF_IDX as usize * GROUP_LENGTH as usize;

/// `*self->pTCI`: the tonal components, viewed in place in `time_data_buffer`.
pub(crate) struct TciView<'a> {
    pub(crate) num_indexes: &'a mut i16,
    pub(crate) index_of_tonal_peak: &'a mut [i16],
    pub(crate) lower_index: &'a mut [i16],
    pub(crate) upper_index: &'a mut [i16],
    /// This one can be stored with 16 bits in range 0..2*PI.
    pub(crate) phase_diff: &'a mut [i16],
    /// This one can be stored with 16 bits in range [-pi;pi] 2Q13.
    pub(crate) phase_current_frame_predicted: &'a mut [i16],
}

/// Split `time_data_buffer` into the fields of the `TonalComponentsInfo` laid over its start.
pub(crate) fn tci_view(time_data_buffer: &mut [i16]) -> TciView<'_> {
    let (tci, _) = time_data_buffer.split_at_mut(TCI_LENGTH);
    let (num_indexes, rest) = tci.split_at_mut(TCI_INDEX_OF_TONAL_PEAK);
    let (index_of_tonal_peak, rest) = rest.split_at_mut(MAX_NUMBER_OF_IDX as usize);
    let (lower_index, rest) = rest.split_at_mut(MAX_NUMBER_OF_IDX as usize);
    let (upper_index, rest) = rest.split_at_mut(MAX_NUMBER_OF_IDX as usize);
    let (phase_diff, phase_current_frame_predicted) = rest.split_at_mut(MAX_NUMBER_OF_IDX as usize);
    TciView {
        num_indexes: &mut num_indexes[0],
        index_of_tonal_peak,
        lower_index,
        upper_index,
        phase_diff,
        phase_current_frame_predicted,
    }
}

/// A buffer pointer of a block (`spectralData`, `scaleFactors`, ...) as an index. `Init` assigns
/// every one of them, so `None` (the zeroed state, a NULL the reference would fault on) is only
/// reachable by using the concealment before `Init`.
fn buffer_index(pointer: Option<usize>) -> usize {
    pointer.unwrap_or(0)
}

/// `TonalMDCTConceal_SaveFreqSignal`: store the frame's MDCT spectrum (16 bit, scaled to its
/// maximum), exponent and scale factors as the last block, the previous last block becoming the
/// second last.
pub fn tonal_mdct_conceal_save_freq_signal(
    this: &mut Tonalmdctconceal,
    mdct_spectrum: &[i32],
    mdct_spectrum_exp: i16,
    n_new_samples: i16,
    n_new_samples_core: i16,
    scale_factors: &[i16],
    scale_factors_exp: &[i16],
    gain_tcx_exp: i16,
) {
    // Avoid overwriting self->secondLastPowerSpectrum stored in spectralData, because it is
    // needed if the second last and the current frame are lost and concealed using the Tonal MDCT
    // PLC.
    if this.last_block_data.tonal_concealment_active == 0
        || sub(this.last_block_data.n_samples, n_new_samples) != 0
    {
        if sub(n_new_samples, L_FRAME_MAX) <= 0 {
            // Shift the buffers
            core::mem::swap(
                &mut this.second_last_block_data.spectral_data,
                &mut this.last_block_data.spectral_data,
            );
            core::mem::swap(
                &mut this.second_last_block_data.spectral_data_exp,
                &mut this.last_block_data.spectral_data_exp,
            );
            core::mem::swap(
                &mut this.second_last_block_data.gain_tcx_exp,
                &mut this.last_block_data.gain_tcx_exp,
            );
            core::mem::swap(
                &mut this.second_last_block_data.scale_factors_max_e,
                &mut this.last_block_data.scale_factors_max_e,
            );
            core::mem::swap(
                &mut this.second_last_block_data.scale_factors,
                &mut this.last_block_data.scale_factors,
            );
            core::mem::swap(
                &mut this.second_last_block_data.scale_factors_exp,
                &mut this.last_block_data.scale_factors_exp,
            );
        } else {
            this.last_block_data.spectral_data = Some(0);
            this.second_last_block_data.spectral_data = Some(1);
            this.last_block_data.scale_factors = Some(0);
            this.second_last_block_data.scale_factors = Some(1);
            this.last_block_data.scale_factors_exp = Some(0);
            this.second_last_block_data.scale_factors_exp = Some(1);
        }

        let n_old_samples = this.last_block_data.n_samples;
        this.last_block_data.n_samples = n_new_samples;
        this.second_last_block_data.n_samples = n_old_samples;

        let n_old_samples = this.last_block_data.n_samples_core;
        this.last_block_data.n_samples_core = n_new_samples_core;
        this.second_last_block_data.n_samples_core = n_old_samples;
    }

    if n_new_samples > 0 && sub(n_new_samples, 2 * L_FRAME_MAX) <= 0 {
        // Store new data
        let s = get_scale_factor32(mdct_spectrum, n_new_samples);

        let scale_factors_exp_buffer = buffer_index(this.last_block_data.scale_factors_exp);
        let mut max_exp: i16 = 0;
        for i in 0..this.n_scale_factors as usize {
            this.scale_factors_buffers_exp[scale_factors_exp_buffer][i] = scale_factors_exp[i];
            max_exp = max_exp.max(scale_factors_exp[i]);
        }

        this.last_block_data.scale_factors_max_e = max_exp;

        // The reference writes nNewSamples lines from the start of the last block's buffer, and a
        // block can be longer than one buffer (the first TCX frame after ACELP reaches
        // `L_FRAME_MAX + L_FRAME_MAX / 4` lines): the buffer is then the first of the two, which
        // are contiguous, and the lines run on into the second.
        let spectral_data_buffer = buffer_index(this.last_block_data.spectral_data);
        let lines =
            &mut this.spectral_data_buffers.as_flattened_mut()[spectral_data_buffer * 960..];
        for (i, line) in lines.iter_mut().enumerate().take(n_new_samples as usize) {
            *line = extract_h(l_shl(mdct_spectrum[i], s));
        }
        this.last_block_data.spectral_data_exp = sub(mdct_spectrum_exp, s);
        this.last_block_data.gain_tcx_exp = gain_tcx_exp;

        let scale_factors_buffer = buffer_index(this.last_block_data.scale_factors);
        copy(
            scale_factors,
            &mut this.scale_factors_buffers[scale_factors_buffer],
            this.n_scale_factors,
        );
    }
}

/// `TonalMDCTConceal_UpdateState`: shift the validity / concealment flags of the last block to the
/// second last and store the new ones.
pub fn tonal_mdct_conceal_update_state(
    this: &mut Tonalmdctconceal,
    n_new_samples: i16,
    pitch_lag: i32,
    bad_block: i16,
    tonal_concealment_active: i8,
) {
    // The reference asserts !(!badBlock && tonalConcealmentActive).
    let new_block_is_valid: i8 = if bad_block != 0 {
        this.last_block_data.block_is_valid
    } else if sub(n_new_samples, 2 * L_FRAME_MAX) <= 0 && n_new_samples > 0 {
        1
    } else {
        0
    };

    // Shift old state
    this.second_last_block_data.block_is_concealed = this.last_block_data.block_is_concealed;
    this.second_last_block_data.block_is_valid = this.last_block_data.block_is_valid;
    this.second_last_block_data.tonal_concealment_active =
        this.last_block_data.tonal_concealment_active;

    // Store new state
    this.last_block_data.block_is_concealed = bad_block;
    this.last_block_data.block_is_valid = new_block_is_valid;
    this.last_block_data.tonal_concealment_active = tonal_concealment_active;

    this.last_pitch_lag = pitch_lag;
}

/// `TonalMDCTConceal_SaveTimeSignal`: keep the decoded time signal of the frame (and the second
/// half of the one before) for the MDCT / MDST of a later loss.
pub fn tonal_mdct_conceal_save_time_signal(
    this: &mut Tonalmdctconceal,
    time_signal: &[i16],
    n_new_samples: i16,
) {
    if sub(n_new_samples, this.n_samples) == 0 {
        // The reference asserts nNewSamples <= L_FRAME_MAX.
        let n_samples = this.n_samples as usize;
        // `lastPcmOut` / `secondLastPcmOut` are always assigned by `Init`.
        let last_pcm_out = buffer_index(this.last_pcm_out);
        let second_last_pcm_out = buffer_index(this.second_last_pcm_out);
        if this.second_last_block_data.tonal_concealment_active == 0 {
            // Copy(lastPcmOut + nSamples/2, secondLastPcmOut, nSamples/2)
            let source = last_pcm_out + n_samples / 2;
            this.time_data_buffer
                .copy_within(source..source + n_samples / 2, second_last_pcm_out);
        }
        this.time_data_buffer[last_pcm_out..last_pcm_out + n_samples]
            .copy_from_slice(&time_signal[..n_samples]);
    }
}

/// `CalcPowerSpec`: the power spectrum of the MDCT / MDST pair, at least `floor_power_spectrum`
/// per bin, with the exponent of the result in `power_spec_exp`.
fn calc_power_spec(
    mdct_spec: &[i32],
    mdct_spec_exp: i16,
    mdst_spec: &[i32],
    mdst_spec_exp: i16,
    n_samples: i16,
    floor_power_spectrum: i16,
    power_spec: &mut [i32],
    power_spec_exp: &mut i16,
) {
    let mut k = mdct_spec_exp.max(mdst_spec_exp);
    // extra 3 bits of headroom for the MA filter in getEnvelope
    *power_spec_exp = add(add(k, k), 3);
    let mut s1 = sub(*power_spec_exp, add(mdct_spec_exp, mdct_spec_exp));
    let mut s2 = sub(*power_spec_exp, add(mdst_spec_exp, mdst_spec_exp));

    k = sub(31, *power_spec_exp);
    // If the signal is below the floor, special care is needed for *powerSpec_exp
    if sub(add(16 - 3, norm_s(floor_power_spectrum)), k) < 0 {
        k = sub(k, add(16 - 3, norm_s(floor_power_spectrum)));
        *power_spec_exp = add(*power_spec_exp, k);
        s1 = add(s1, k);
        s2 = add(s2, k);
        k = add(16 - 3, norm_s(floor_power_spectrum));
    }
    let l_tmp_floor = l_shl(l_deposit_l(floor_power_spectrum), k);

    let tmp = sub(n_samples, 2);
    k = 1;
    while k <= tmp {
        let ku = k as usize;
        let mut x = mpy_32_32(mdct_spec[ku], mdct_spec[ku]); // Q31, 2*mdctSpec_exp

        let l_tmp = mpy_32_32(mdst_spec[ku], mdst_spec[ku]); // Q31, 2*mdstSpec_exp
        x = l_add(l_shr(x, s1), l_shr(l_tmp, s2)); // Q31, *powerSpec_exp

        power_spec[ku] = l_tmp_floor.max(x);
        k += 1;
    }

    power_spec[0] = l_shr(power_spec[1], 1);
    let last = n_samples as usize - 1;
    power_spec[last] = l_shr(power_spec[last - 1], 1);
}

/// `CalcPowerSpecAndDetectTonalComponents`: the power spectrum of the second last block's
/// MDCT / MDST, the tonal components found in it (into the `TonalComponentsInfo`), their phases
/// and phase differences, and the shaped amplitude spectrum stored as `secondLastPowerSpectrum`.
fn calc_power_spec_and_detect_tonal_components(
    this: &mut Tonalmdctconceal,
    second_last_mdst: &[i32],
    second_last_mdst_exp: i16,
    second_last_mdct: &[i32],
    second_last_mdct_exp: i16,
    pitch_lag: i32,
) {
    let mut power_spectrum = [0_i32; L_FRAME_MAX as usize];
    let mut inv_scale_factors = [0_i16; FDNS_NPTS as usize];
    let mut inv_scale_factors_exp = [0_i16; FDNS_NPTS as usize];
    let mut power_spectrum_exp: i16 = 0;

    let n_samples = this.n_non_zero_samples;

    // It is taken into account that the MDCT is not normalized. 1/400 = 82 Q15
    let floor_power_spectrum = extract_l(mpy_32_16_1(l_mult0(this.n_samples, this.n_samples), 82));

    calc_power_spec(
        second_last_mdct,
        second_last_mdct_exp,
        second_last_mdst,
        second_last_mdst_exp,
        n_samples,
        floor_power_spectrum,
        &mut power_spectrum,
        &mut power_spectrum_exp,
    );

    // This setting to minimal level is required because the power spectrum is used in the
    // threshold adaptation using the pitch up to self->nSamples.
    set32(
        &mut power_spectrum[n_samples as usize..],
        l_deposit_l(floor_power_spectrum),
        sub(this.n_samples, n_samples),
    );
    // This setting to zero is needed since the FDNS needs to be called with self->nSamplesCore; it
    // is relevant only for nb; it has no effect on the output.
    if sub(this.n_samples_core, this.n_samples) > 0 {
        set32(
            &mut power_spectrum[this.n_samples as usize..],
            0,
            sub(this.n_samples_core, this.n_samples),
        );
    }

    let last_spectral_data = buffer_index(this.last_block_data.spectral_data);
    let last_scale_factors = buffer_index(this.last_block_data.scale_factors);
    let last_scale_factors_exp = buffer_index(this.last_block_data.scale_factors_exp);
    {
        let tci = tci_view(&mut this.time_data_buffer);
        detect_tonal_components(
            tci.index_of_tonal_peak,
            tci.lower_index,
            tci.upper_index,
            tci.num_indexes,
            this.last_pitch_lag,
            pitch_lag,
            &this.spectral_data_buffers[last_spectral_data],
            add(
                this.last_block_data.spectral_data_exp,
                this.last_block_data.gain_tcx_exp,
            ),
            &this.scale_factors_buffers[last_scale_factors],
            &this.scale_factors_buffers_exp[last_scale_factors_exp],
            this.last_block_data.scale_factors_max_e,
            &power_spectrum,
            n_samples,
            this.n_samples_core,
            floor_power_spectrum,
        );
    }

    phases::find_phases(
        &mut tci_view(&mut this.time_data_buffer),
        second_last_mdct,
        second_last_mdst,
        sub(second_last_mdst_exp, second_last_mdct_exp),
    );

    phases::find_phase_differences(&mut tci_view(&mut this.time_data_buffer), &power_spectrum);

    if *tci_view(&mut this.time_data_buffer).num_indexes > 0 {
        this.second_last_power_spectrum = this.second_last_block_data.spectral_data;

        // sqrtFLOAT(powerSpectrum, powerSpectrum, nSamples)
        let old_exp = power_spectrum_exp;
        // remove 2 bits of headroom from CalcPowerSpec
        power_spectrum_exp = mult_r(sub(power_spectrum_exp, 2), 1 << 14);
        for line in power_spectrum.iter_mut().take(n_samples as usize) {
            let mut tmp_exp = old_exp;
            *line = sqrt32(*line, &mut tmp_exp);
            *line = l_shr(*line, sub(power_spectrum_exp, tmp_exp));
        }

        let second_last_scale_factors = buffer_index(this.second_last_block_data.scale_factors);
        let second_last_scale_factors_exp =
            buffer_index(this.second_last_block_data.scale_factors_exp);
        // The reference leaves the entries from nScaleFactors on uninitialised; nScaleFactors is
        // FDNS_NPTS whenever the concealment is used (the last entry is read below).
        for i in 0..this.n_scale_factors as usize {
            inv_scale_factors_exp[i] =
                this.scale_factors_buffers_exp[second_last_scale_factors_exp][i];
            inv_scale_factors[i] = inv16(
                this.scale_factors_buffers[second_last_scale_factors][i],
                &mut inv_scale_factors_exp[i],
            );
        }

        // here mdct_shaping() is intentionally used rather than mdct_shaping_16()
        mdct_shaping(
            &mut power_spectrum,
            this.n_samples_core,
            &inv_scale_factors,
            &inv_scale_factors_exp,
        );
        for line in power_spectrum
            .iter_mut()
            .take(n_samples as usize)
            .skip(this.n_samples_core as usize)
        {
            *line = l_shl(
                mpy_32_16_1(*line, inv_scale_factors[FDNS_NPTS as usize - 1]),
                inv_scale_factors_exp[FDNS_NPTS as usize - 1],
            );
        }

        // 16 bits are now enough for storing the power spectrum
        let second_last_power_spectrum = buffer_index(this.second_last_power_spectrum);
        for i in 0..n_samples as usize {
            this.spectral_data_buffers[second_last_power_spectrum][i] =
                round_word(power_spectrum[i]);
        }

        power_spectrum_exp = sub(power_spectrum_exp, this.second_last_block_data.gain_tcx_exp);
        this.second_last_power_spectrum_exp = power_spectrum_exp;
    }
}

/// `CalcMDXT`: the MDST (`type_ == 0`) or MDCT of the second last PCM block, windowed with the
/// full-overlap window; `mdxt_output_e` is the exponent of the result.
fn calc_mdxt(
    this: &Tonalmdctconceal,
    tcx_cfg: &TcxConfig,
    type_: i16,
    mdxt_output: &mut [i32],
    mdxt_output_e: &mut i16,
) {
    let mut windowed_time_signal = [0_i16; L_FRAME_PLUS as usize + 2 * L_MDCT_OVLP_MAX as usize];
    let mut left_overlap: i16 = 0;
    let mut right_overlap: i16 = 0;
    let mut l_frame = this.n_samples;

    window_signal(
        tcx_cfg,
        tcx_cfg.tcx_offset_fb,
        FULL_OVERLAP,
        FULL_OVERLAP,
        &mut left_overlap,
        &mut right_overlap,
        &this.time_data_buffer,
        buffer_index(this.second_last_pcm_out),
        &mut l_frame,
        &mut windowed_time_signal,
        1,
    );

    let middle = sub(l_frame, shr(add(left_overlap, right_overlap), 1));
    if type_ == 0 {
        tcx_mdst(
            &windowed_time_signal,
            mdxt_output,
            mdxt_output_e,
            left_overlap,
            middle,
            right_overlap,
        );
    } else {
        tcx_mdct(
            &windowed_time_signal,
            mdxt_output,
            mdxt_output_e,
            left_overlap,
            middle,
            right_overlap,
        );
    }
}

/// `TonalMDCTConceal_Detect`: find the tonal components of the lost frame; their number goes to
/// `num_indices`.
pub fn tonal_mdct_conceal_detect(
    this: &mut Tonalmdctconceal,
    tcx_cfg: &TcxConfig,
    pitch_lag: i32,
    num_indices: &mut i16,
) {
    let mut second_last_mdst = [0_i32; L_FRAME_MAX as usize];
    let mut second_last_mdct = [0_i32; L_FRAME_MAX as usize];
    let mut second_last_mdst_exp: i16 = 16; // time signal Q-1
    let mut second_last_mdct_exp: i16 = 16; // time signal Q-1
    let n_samples = this.n_samples;

    if this.last_block_data.block_is_valid != 0
        && this.second_last_block_data.block_is_valid != 0
        && sub(this.last_block_data.n_samples, n_samples) == 0
        && sub(this.second_last_block_data.n_samples, n_samples) == 0
        // Safety if the second last frame was concealed and tonal concealment was inactive
        && (this.second_last_block_data.block_is_concealed == 0
            || this.second_last_block_data.tonal_concealment_active != 0
            || pitch_lag != 0)
    {
        if this.last_block_data.block_is_concealed == 0 {
            if this.second_last_block_data.tonal_concealment_active == 0 {
                calc_mdxt(
                    this,
                    tcx_cfg,
                    0,
                    &mut second_last_mdst,
                    &mut second_last_mdst_exp,
                );
                calc_mdxt(
                    this,
                    tcx_cfg,
                    1,
                    &mut second_last_mdct,
                    &mut second_last_mdct_exp,
                );
                this.n_non_zero_samples = 0;
                let second_last_spectral_data =
                    buffer_index(this.second_last_block_data.spectral_data);
                for i in 0..this.n_samples {
                    if this.spectral_data_buffers[second_last_spectral_data][i as usize] != 0 {
                        this.n_non_zero_samples = i;
                    }
                }

                // 23 is the maximum length of the MA filter in getEnvelope
                this.n_non_zero_samples = this.n_samples.min(add(this.n_non_zero_samples, 23));
                let n_samples = this.n_non_zero_samples;

                let mut s = get_scale_factor32(&second_last_mdst, n_samples);
                for line in second_last_mdst.iter_mut().take(n_samples as usize) {
                    *line = l_shl(*line, s);
                }
                second_last_mdst_exp = sub(second_last_mdst_exp, s);
                s = get_scale_factor32(&second_last_mdct, n_samples);
                for line in second_last_mdct.iter_mut().take(n_samples as usize) {
                    *line = l_shl(*line, s);
                }
                second_last_mdct_exp = sub(second_last_mdct_exp, s);
                calc_power_spec_and_detect_tonal_components(
                    this,
                    &second_last_mdst,
                    second_last_mdst_exp,
                    &second_last_mdct,
                    second_last_mdct_exp,
                    pitch_lag,
                );
            } else {
                // `power_spectrum` is the reference's alias of `secondLastMDST`.
                tonal_mdct_conceal_detect_reuse_second_last(this, pitch_lag, &mut second_last_mdst);
            }
        }
    } else {
        *tci_view(&mut this.time_data_buffer).num_indexes = 0;
    }

    *num_indices = *tci_view(&mut this.time_data_buffer).num_indexes;
}

/// The branch of `TonalMDCTConceal_Detect` for a second last frame that was also concealed with
/// the tonal concealment: its stored concealed spectrum is reused (the past time signal could
/// hold a slightly different signal, e.g. with a fade-out, from the one stored by
/// `TonalMDCTConceal_SaveTimeSignal`), so the components are only refined.
fn tonal_mdct_conceal_detect_reuse_second_last(
    this: &mut Tonalmdctconceal,
    pitch_lag: i32,
    power_spectrum: &mut [i32],
) {
    let n_samples = this.n_non_zero_samples;
    let second_last_power_spectrum = buffer_index(this.second_last_power_spectrum);
    let second_last_scale_factors = buffer_index(this.second_last_block_data.scale_factors);
    let second_last_scale_factors_exp = buffer_index(this.second_last_block_data.scale_factors_exp);
    mdct_shaping_16(
        &this.spectral_data_buffers[second_last_power_spectrum],
        this.n_samples_core,
        n_samples,
        &this.scale_factors_buffers[second_last_scale_factors],
        &this.scale_factors_buffers_exp[second_last_scale_factors_exp],
        this.second_last_block_data.scale_factors_max_e,
        power_spectrum,
    );

    let mut power_spectrum_exp = get_scale_factor32(power_spectrum, n_samples);
    // extra 3 bits of headroom for the MA filter in getEnvelope
    power_spectrum_exp = sub(power_spectrum_exp, 3);

    // multFLOAT(powerSpectrum, powerSpectrum, powerSpectrum, nSamples)
    for line in power_spectrum.iter_mut().take(n_samples as usize) {
        let t = l_shl(*line, power_spectrum_exp);
        *line = mpy_32_32(t, t);
    }

    let last_spectral_data = buffer_index(this.last_block_data.spectral_data);
    let last_scale_factors = buffer_index(this.last_block_data.scale_factors);
    let last_scale_factors_exp = buffer_index(this.last_block_data.scale_factors_exp);
    let tci = tci_view(&mut this.time_data_buffer);
    refine_tonal_components(
        tci.index_of_tonal_peak,
        tci.lower_index,
        tci.upper_index,
        tci.phase_diff,
        tci.phase_current_frame_predicted,
        tci.num_indexes,
        this.last_pitch_lag,
        pitch_lag,
        &this.spectral_data_buffers[last_spectral_data],
        add(
            this.last_block_data.spectral_data_exp,
            this.last_block_data.gain_tcx_exp,
        ),
        &this.scale_factors_buffers[last_scale_factors],
        &this.scale_factors_buffers_exp[last_scale_factors_exp],
        this.last_block_data.scale_factors_max_e,
        power_spectrum,
        n_samples,
        this.n_samples_core,
        // floorPowerSpectrum
        extract_l(mpy_32_16_1(l_mult0(this.n_samples, this.n_samples), 82)),
    );
}

/// `TonalMDCTConceal_Apply`: replace the lines of the tonal groups of `mdct_spectrum` with the
/// second last block's amplitude spectrum rotated by the predicted phase.
pub fn tonal_mdct_conceal_apply(
    this: &mut Tonalmdctconceal,
    mdct_spectrum: &mut [i32],
    mdct_spectrum_exp: i16,
) {
    if this.last_block_data.block_is_valid & this.second_last_block_data.block_is_valid != 0 {
        let mut power_spectrum = [0_i32; L_FRAME_MAX as usize];
        // The reference asserts numIndexes > 0 and upperIndex[numIndexes-1] < nSamples.
        let n_samples = this.n_non_zero_samples;

        let second_last_power_spectrum = buffer_index(this.second_last_power_spectrum);
        let second_last_scale_factors = buffer_index(this.second_last_block_data.scale_factors);
        let second_last_scale_factors_exp =
            buffer_index(this.second_last_block_data.scale_factors_exp);
        mdct_shaping_16(
            &this.spectral_data_buffers[second_last_power_spectrum],
            this.n_samples_core,
            n_samples,
            &this.scale_factors_buffers[second_last_scale_factors],
            &this.scale_factors_buffers_exp[second_last_scale_factors_exp],
            this.second_last_block_data.scale_factors_max_e,
            &mut power_spectrum,
        );

        let exp = sub(
            mdct_spectrum_exp,
            add(
                add(
                    this.second_last_power_spectrum_exp,
                    add(this.second_last_block_data.gain_tcx_exp, 1),
                ),
                this.second_last_block_data.scale_factors_max_e,
            ),
        );

        if this.last_block_data.block_is_concealed == 0 {
            if this.second_last_block_data.tonal_concealment_active != 0 {
                this.n_frames_lost = add(this.n_frames_lost, 2); // Q1
            }
            if this.second_last_block_data.tonal_concealment_active == 0 {
                this.n_frames_lost = 3; // Q1
            }
        }
        // If multiple frame loss occurs use the phase from the last frame and continue rotating.
        let n_frames_lost = this.n_frames_lost;
        let tci = tci_view(&mut this.time_data_buffer);
        let mut current_phase_index = 0_usize;
        // for each index group
        for i in 0..*tci.num_indexes as usize {
            // phaseToAdd = self->nFramesLost*phaseDiff[i]; Q1*3Q12 = 2Q13
            let mut phase_to_add = l_mult0(n_frames_lost, tci.phase_diff[i]);
            // Move phaseToAdd to range -PI..PI
            while l_sub(phase_to_add, 25736) > 0 {
                phase_to_add = l_sub(phase_to_add, 51472); // EVS_PI, 2*EVS_PI in Q13
            }
            while l_sub(phase_to_add, -25736) < 0 {
                phase_to_add = l_add(phase_to_add, 51472);
            }

            for l in tci.lower_index[i]..=tci.upper_index[i] {
                let lu = l as usize;
                // *pCurrentPhase and phaseToAdd are in range -PI..PI
                let mut current_phase = l_mac0(
                    phase_to_add,
                    tci.phase_current_frame_predicted[current_phase_index],
                    1,
                ); // 2Q13+2Q13 = 3Q13
                current_phase_index += 1;

                if l_sub(current_phase, 25736) > 0 {
                    current_phase = l_sub(current_phase, 51472);
                }
                if l_sub(current_phase, -25736) < 0 {
                    current_phase = l_add(current_phase, 51472);
                }
                // getCosWord16 returns 1Q14
                mdct_spectrum[lu] =
                    mpy_32_16_1(power_spectrum[lu], get_cos_word16(extract_l(current_phase)));
                mdct_spectrum[lu] = l_shr(mdct_spectrum[lu], exp);
            }
        }
    }

    this.n_frames_lost = add(this.n_frames_lost, 2); // Q1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_block_is_refused_without_touching_the_state() {
        let mut conceal = Box::new(Tonalmdctconceal::zeroed());
        conceal.n_samples = 5;
        assert_eq!(
            tonal_mdct_conceal_init(&mut conceal, 961, 640, 64),
            Err(TonalMdctConcealError::NSamplesLargerThanMaxBlockSize)
        );
        assert_eq!(
            tonal_mdct_conceal_init(&mut conceal, 640, 640, 65),
            Err(TonalMdctConcealError::NSamplesLargerThanMaxBlockSize)
        );
        assert_eq!(conceal.n_samples, 5);
    }

    #[test]
    fn the_tonal_components_overlay_the_start_of_the_time_buffer() {
        let mut buffer = [0_i16; 1440];
        {
            let view = tci_view(&mut buffer);
            *view.num_indexes = 7;
            view.index_of_tonal_peak[0] = 11;
            view.lower_index[0] = 12;
            view.upper_index[0] = 13;
            view.phase_diff[0] = 14;
            view.phase_current_frame_predicted[0] = 15;
            view.phase_current_frame_predicted[209] = 16;
        }
        assert_eq!(buffer[..2], [7, 11]);
        assert_eq!(buffer[31], 12);
        assert_eq!(buffer[61], 13);
        assert_eq!(buffer[91], 14);
        assert_eq!(buffer[121], 15);
        assert_eq!(buffer[330], 16);
        assert_eq!(buffer[331], 0);
    }

    #[test]
    fn update_state_shifts_the_flags_and_keeps_validity_through_a_loss() {
        let mut conceal = Box::new(Tonalmdctconceal::zeroed());
        tonal_mdct_conceal_update_state(&mut conceal, 640, 5, 0, 0);
        assert_eq!(conceal.last_block_data.block_is_valid, 1);
        assert_eq!(conceal.last_pitch_lag, 5);
        tonal_mdct_conceal_update_state(&mut conceal, 640, 6, 1, 1);
        assert_eq!(conceal.second_last_block_data.block_is_valid, 1);
        assert_eq!(conceal.last_block_data.block_is_valid, 1);
        assert_eq!(conceal.last_block_data.block_is_concealed, 1);
        assert_eq!(conceal.last_block_data.tonal_concealment_active, 1);
        tonal_mdct_conceal_update_state(&mut conceal, 0, 0, 0, 0);
        assert_eq!(conceal.last_block_data.block_is_valid, 0);
        assert_eq!(conceal.second_last_block_data.tonal_concealment_active, 1);
    }

    #[test]
    fn save_time_signal_keeps_the_second_half_of_the_previous_block() {
        let mut conceal = Box::new(Tonalmdctconceal::zeroed());
        assert!(tonal_mdct_conceal_init(&mut conceal, 320, 256, 64).is_ok());
        let first: Vec<i16> = (0..320).collect();
        let second: Vec<i16> = (1000..1320).collect();
        tonal_mdct_conceal_save_time_signal(&mut conceal, &first, 320);
        tonal_mdct_conceal_save_time_signal(&mut conceal, &second, 320);
        let last = conceal.last_pcm_out.unwrap_or(usize::MAX);
        let second_last = conceal.second_last_pcm_out.unwrap_or(usize::MAX);
        assert_eq!(conceal.time_data_buffer[last..last + 320], second[..]);
        assert_eq!(
            conceal.time_data_buffer[second_last..second_last + 160],
            first[160..]
        );
        // A block of another length is ignored.
        tonal_mdct_conceal_save_time_signal(&mut conceal, &first, 160);
        assert_eq!(conceal.time_data_buffer[last..last + 320], second[..]);
    }

    #[test]
    fn noise_for_a_conceal_without_a_valid_block_is_silence() {
        let mut conceal = Box::new(Tonalmdctconceal::zeroed());
        assert!(tonal_mdct_conceal_init(&mut conceal, 320, 256, 64).is_ok());
        let mut spectrum = [7_i32; 320];
        let mut spectrum_exp = 0;
        let mut seed = 99;
        tonal_mdct_conceal_insert_noise(
            &mut conceal,
            &mut spectrum,
            &mut spectrum_exp,
            0,
            &mut seed,
            32767,
            0,
            320,
        );
        assert!(spectrum.iter().all(|&line| line == 0));
        assert_eq!(spectrum_exp, crate::evs::cnst::SPEC_EXP_DEC);
        assert_eq!(seed, 1977);
    }

    #[test]
    fn apply_without_two_valid_blocks_only_counts_the_lost_frame() {
        let mut conceal = Box::new(Tonalmdctconceal::zeroed());
        let mut spectrum = [5_i32; 320];
        tonal_mdct_conceal_apply(&mut conceal, &mut spectrum, 0);
        assert_eq!(conceal.n_frames_lost, 2);
        assert!(spectrum.iter().all(|&line| line == 5));
    }
}
