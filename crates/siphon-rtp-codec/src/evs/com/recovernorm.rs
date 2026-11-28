//! Recovery of the reordered norm indices of a transient HQ frame (TS 26.442
//! `lib_com/recovernorm_fx.c`; TS 26.445 §6.2.2.3).

use crate::evs::cnst::{NB_SFM, SFM_N_SWB, SFM_N_WB};
use crate::evs::rom::{DICNLG2, NORM_ORDER_16, NORM_ORDER_32, NORM_ORDER_48};

/// `recovernorm_fx`: put the reordered quantization indices `idxbuf[0..nb_sfm]` back in band order
/// into `ynrm`, with their log2 norms (`dicnlg2`) into `normqlg2`.
///
/// The order table is chosen by the band count (48, 32 or 16 kHz layouts; 48 kHz otherwise). An
/// index outside the 40-entry norm dictionary (the decoder clamps every index to 0..=39 before
/// calling, so only an inconsistent caller) leaves that band's norm unchanged.
pub fn recovernorm(idxbuf: &[i16], ynrm: &mut [i16], normqlg2: &mut [i16], nb_sfm: i16) {
    let order: &[i16] = match nb_sfm {
        NB_SFM => &NORM_ORDER_48,
        SFM_N_SWB => &NORM_ORDER_32,
        SFM_N_WB => &NORM_ORDER_16,
        _ => &NORM_ORDER_48,
    };

    for (&j, &k) in order.iter().zip(idxbuf).take(nb_sfm.max(0) as usize) {
        let j = j as usize;
        ynrm[j] = k;
        if let Some(&norm) = usize::try_from(k).ok().and_then(|k| DICNLG2.get(k)) {
            normqlg2[j] = norm;
        }
    }
}
