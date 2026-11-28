//! Tonal MDCT concealment (TS 26.442 `lib_dec/tonalMDCTconcealment.c`; TS 26.445 §5.4.3.6).
//! Only `TonalMDCTConceal_Init` so far.

use crate::evs::cnst::{FDNS_NPTS, L_FRAME_MAX};
use crate::evs::dec::state::Tonalmdctconceal;
use crate::itu::basic_ops::sub;

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
}
