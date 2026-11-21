//! Band configuration for HQ frame-erasure concealment (TS 26.442 `lib_dec/hq_conf_fec_fx.c`).

use crate::evs::cnst::{MAX_SB_NB, SFM_N_NB};
use crate::evs::com::tools::copy;
use crate::evs::rom::{BAND_END_WB, BAND_LEN_WB, BAND_START_WB, NUM_BANDS_NB};

/// `hq_configure_bfi_fx`: the HQ band layout used to conceal a lost frame: the band count, the
/// FEC sub-band count and its per-sub-band band counts (into `num_bands_p`), and the band size /
/// start / end tables.
pub fn hq_configure_bfi(
    nb_sfm: &mut i16,
    num_sb: &mut i16,
    num_bands_p: &mut [i16],
    sfmsize: &mut &'static [i16],
    sfm_start: &mut &'static [i16],
    sfm_end: &mut &'static [i16],
) {
    *num_sb = MAX_SB_NB;
    *nb_sfm = SFM_N_NB;
    copy(&NUM_BANDS_NB, num_bands_p, *num_sb);
    *sfmsize = &BAND_LEN_WB;
    *sfm_start = &BAND_START_WB;
    *sfm_end = &BAND_END_WB;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configures_the_wideband_layout_with_nb_sub_bands() {
        let (mut nb_sfm, mut num_sb, mut num_bands_p) = (0, 0, [0i16; 3]);
        let (mut size, mut start, mut end): (&[i16], &[i16], &[i16]) = (&[], &[], &[]);
        hq_configure_bfi(
            &mut nb_sfm,
            &mut num_sb,
            &mut num_bands_p,
            &mut size,
            &mut start,
            &mut end,
        );
        assert_eq!((nb_sfm, num_sb, num_bands_p), (18, 3, [8, 8, 2]));
        assert_eq!(size.as_ptr(), BAND_LEN_WB.as_ptr());
        assert_eq!(start.as_ptr(), BAND_START_WB.as_ptr());
        assert_eq!(end.as_ptr(), BAND_END_WB.as_ptr());
    }
}
