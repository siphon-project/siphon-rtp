//! The TCX waveform-adjustment concealment (TS 26.442 `lib_dec/waveadjust_fec_dec.c`; TS 26.445
//! §6.2.4.2). Only the state initialisation is ported so far.

use crate::evs::cnst::{
    DEC_STATE_LEN, L_FRAME_MAX, MAX_POST_LEN, TCX_NONTONAL, TCX_TONALITY_INIT_CNT,
};
use crate::evs::dec::state::TPLCInfo;

/// `concealment_init_x`: resets the waveform-adjustment concealment state for a TCX frame of `n`
/// samples.
pub fn concealment_init_x(n: i16, plc_info: &mut TPLCInfo) {
    plc_info.frame_size = n;
    plc_info.pitch = 0;
    plc_info.t_bfi = 0;
    plc_info.outx_new_n1 = 0;
    plc_info.nsapp_gain = 0;
    plc_info.nsapp_gain_n = 0;
    plc_info.ener_mean = 15213; // Q8 59.4260f*256
    plc_info.ener = 0;
    plc_info.zp = n;
    plc_info.recovery_gain = 0;
    plc_info.step_concealgain = 0;
    plc_info.concealment_method = TCX_NONTONAL;
    plc_info.subframe = 0;
    plc_info.nb_lost_cmpt = 0;
    plc_info.seed = 21845;

    let init_cnt = TCX_TONALITY_INIT_CNT as usize;
    plc_info.tcx_tonality[..init_cnt].fill(1);
    plc_info.tcx_tonality[init_cnt..DEC_STATE_LEN as usize].fill(0);
    plc_info.transient[..MAX_POST_LEN as usize].fill(1);
    plc_info.data_reci2[..L_FRAME_MAX as usize].fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concealment_init_x_sets_every_field_the_reference_sets() {
        let mut plc_info = TPLCInfo::zeroed();
        plc_info.pitch = 7;
        plc_info.t_bfi = 1;
        plc_info.outx_new_n1 = -3;
        plc_info.nsapp_gain = 5;
        plc_info.nsapp_gain_n = 6;
        plc_info.ener = 99;
        plc_info.recovery_gain = 4;
        plc_info.step_concealgain = 8;
        plc_info.concealment_method = 1;
        plc_info.subframe = 2;
        plc_info.nb_lost_cmpt = 12;
        plc_info.tcx_tonality.fill(5);
        plc_info.transient.fill(0);
        plc_info.data_reci2.fill(-1);
        plc_info.data_noise.fill(3);
        plc_info.data_reci2_scale = 9;

        concealment_init_x(640, &mut plc_info);

        assert_eq!(plc_info.frame_size, 640);
        assert_eq!(plc_info.zp, 640);
        assert_eq!(plc_info.pitch, 0);
        assert_eq!(plc_info.t_bfi, 0);
        assert_eq!(plc_info.outx_new_n1, 0);
        assert_eq!(plc_info.nsapp_gain, 0);
        assert_eq!(plc_info.nsapp_gain_n, 0);
        assert_eq!(plc_info.ener_mean, 15213);
        assert_eq!(plc_info.ener, 0);
        assert_eq!(plc_info.recovery_gain, 0);
        assert_eq!(plc_info.step_concealgain, 0);
        assert_eq!(plc_info.concealment_method, TCX_NONTONAL);
        assert_eq!(plc_info.subframe, 0);
        assert_eq!(plc_info.nb_lost_cmpt, 0);
        assert_eq!(plc_info.seed, 21845);
        assert_eq!(plc_info.tcx_tonality, [1, 1, 1, 1, 1, 1, 1, 0, 0, 0]);
        assert_eq!(plc_info.transient, [1, 1, 1]);
        assert!(plc_info.data_reci2.iter().all(|&v| v == 0));
        // untouched by the reference
        assert!(plc_info.data_noise.iter().all(|&v| v == 3));
        assert_eq!(plc_info.data_reci2_scale, 9);
    }
}
