//! Second-stage LPC dequantiser of the variable-rate LPC quantiser (TS 26.442
//! `lib_dec/vlpc_2st_dec.c`).

use crate::evs::cnst::{INT_FS_FX, M};
use crate::evs::com::lsf_tools::reorder_lsf;
use crate::evs::com::tools::sort;
use crate::evs::com::vlpc_2st_com::lsf_weight_2st;
use crate::evs::dec::avq_dec::avq_dec_lpc;
use crate::itu::basic_ops::{add, l_sub, mult_r, shl};

/// `vlpc_2st_dec`: refine the first-stage LSFs `lsfq` (14Q1, ×1.28) with the algebraic-VQ
/// residual in the 4-bit words `indx`, weighted by `lsf_weight_2st` for `mode` (0 absolute, else
/// relative), then sort them and enforce the LSF gap of the core rate `sr_core`.
pub fn vlpc_2st_dec(lsfq: &mut [i16], indx: &[i16], mode: i16, sr_core: i32) {
    let mut w = [0i16; M as usize];
    let mut xq = [0i16; M as usize];

    // weighting from the 1st stage
    lsf_weight_2st(lsfq, &mut w, mode);

    // quantize
    avq_dec_lpc(indx, &mut xq, 2);

    // quantized lsf
    for i in 0..M as usize {
        lsfq[i] = add(lsfq[i], shl(mult_r(w[i], shl(xq[i], 10)), 2)); // 14Q1*1.28
    }

    // reorder
    sort(lsfq, 0, M - 1);
    let gap: i16 = if l_sub(sr_core, 16000) == 0 {
        102
    } else if l_sub(sr_core, 25600) == 0 {
        64
    } else if l_sub(sr_core, 32000) == 0 {
        51
    } else {
        34
    };
    reorder_lsf(lsfq, gap, M, i32::from(INT_FS_FX));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_residual_keeps_ordered_lsfs_and_enforces_the_gap() {
        let mut lsfq = [0i16; 16];
        for (i, value) in lsfq.iter_mut().enumerate() {
            *value = ((i + 1) * 900) as i16;
        }
        let before = lsfq;
        vlpc_2st_dec(&mut lsfq, &[0, 0], 0, 12800);
        assert_eq!(lsfq, before);
    }
}
