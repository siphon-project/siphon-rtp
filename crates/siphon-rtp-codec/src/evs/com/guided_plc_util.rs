//! LPC helpers of the guided PLC (TS 26.442 `lib_com/guided_plc_util.c`; TS 26.447 §5.4.3):
//! the diffuse concealment of the LPC spectrum, `modify_lsf` and the file-local `reorder_lsfs`.

use crate::evs::cnst::{LSF_GAP_FX, M};
use crate::evs::com::lsf_dec_bfi::plc_get_lsf_base;
use crate::evs::com::lsf_tools::lsf2lsp;
use crate::evs::com::tools::sort;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::INVINTTABLE;
use crate::itu::basic_ops::{add, l_sub, mult_r, shl, shr, sub};

/// `RecLpcSpecPowDiffuseLc`: the LSPs for the LPC spectrum of a concealed frame, diffused towards
/// a flatter spectrum. `lsp_old` receives the last frame's LSPs after `modify_lsf`; `lspq` the
/// LSPs of `lsfq`, which is the MA memory plus the base LSFs when `reset_q` (sorted and spaced
/// with `reorder_lsfs`), else the modified input `lsfq`.
pub fn rec_lpc_spec_pow_diffuse_lc(
    lspq: &mut [i16],
    lsp_old: &mut [i16],
    lsfq: &mut [i16],
    st: &DecoderState,
    reset_q: i16,
) {
    let mu = M as usize;
    let means = plc_get_lsf_base(st.lpc_quantization, i16::from(st.narrow_band), st.sr_core);

    let mut lsf_old = [0i16; M as usize];
    lsf_old.copy_from_slice(&st.lsf_old[..mu]);

    modify_lsf(&mut lsf_old, M, st.sr_core, reset_q);

    lsf2lsp(&lsf_old, lsp_old, M, st.sr_core);

    if reset_q != 0 {
        for i in 0..mu {
            lsfq[i] = add(st.mem_ma[i], means[i]);
        }
        sort(lsfq, 0, sub(M, 1));

        reorder_lsfs(lsfq, LSF_GAP_FX, M, st.sr_core);
        lsf2lsp(lsfq, lspq, M, st.sr_core);
    } else {
        modify_lsf(lsfq, M, st.sr_core, reset_q);
        lsf2lsp(lsfq, lspq, M, st.sr_core);
    }
}

/// `modify_lsf`: replace the LSFs below the first one at or above a threshold (1900 Hz, or 2375 Hz
/// at 16 kHz; 800 / 1000 Hz without `reset_q`) with equally spaced ones rising to the last of them.
pub fn modify_lsf(lsf: &mut [i16], n: i16, sr_core: i32, reset_q: i16) {
    let mut th_x1p28_q14: i16 = 4864; // 1900.0f*1.28f Q1
    if l_sub(sr_core, 16000) == 0 {
        th_x1p28_q14 = 6080; // 2375.0f*1.28f Q1
    }

    if reset_q == 0 {
        th_x1p28_q14 = 2048; // 800.0f*1.28f Q1
        if l_sub(sr_core, 16000) == 0 {
            th_x1p28_q14 = 2560; // 1000.0f*1.28f Q1
        }
    }

    let mut i: i16 = 1;
    while i < n {
        if sub(lsf[i as usize], th_x1p28_q14) >= 0 {
            break;
        }
        i += 1;
    }

    let gap = mult_r(lsf[i as usize - 1], INVINTTABLE[i as usize]);

    let mut gap_sum = gap;
    i = sub(i, 1);
    for value in lsf.iter_mut().take(i as usize) {
        *value = gap_sum;
        gap_sum = add(gap_sum, gap);
    }
}

/// `reorder_lsfs`: enforce ascending order with frequency-dependent minimum gaps (3, 2 and 1 times
/// `min_dist0`, widened by a quarter at 16 kHz) over `lsf[0..n]`, then again downwards from
/// the top if the last LSF is too close to `fs/2`.
pub fn reorder_lsfs(lsf: &mut [i16], min_dist0: i16, n: i16, sr_core: i32) {
    let mut fs2: i16 = 16384; // 6400.0 * 1.28 Q1

    if l_sub(sr_core, 16000) == 0 {
        fs2 = 20480; // 8000.0 * 1.28 Q1
    }

    // Verify the LSF ordering and minimum GAP
    let th1: i16;
    let th2: i16;
    let min_dist: i16;
    if l_sub(sr_core, 16000) == 0 {
        th1 = 3200;
        th2 = 6080;
        min_dist = add(min_dist0, shr(min_dist0, 2));
    } else {
        th1 = 2560;
        th2 = 4864;
        min_dist = min_dist0;
    }
    let min_dist_fac2 = shl(min_dist, 1);
    let min_dist_fac3 = add(min_dist, min_dist_fac2);
    let mut curr_min_dist = min_dist_fac3;

    let mut lsf_min = curr_min_dist;

    for value in lsf.iter_mut().take(n.max(0) as usize) {
        if sub(*value, th1) > 0 {
            curr_min_dist = min_dist_fac2;
        } else if sub(*value, th2) > 0 {
            curr_min_dist = min_dist;
        }

        if sub(*value, lsf_min) < 0 {
            *value = lsf_min;
        }

        lsf_min = add(*value, curr_min_dist);
    }

    // Reverify the LSF ordering and minimum GAP in the reverse order (security)
    let mut lsf_max = sub(fs2, curr_min_dist);

    // If danger of unstable filter in case of resonance in HF
    if n > 0 && sub(lsf[n as usize - 1], lsf_max) > 0 {
        // Reverify the minimum ISF gap in the reverse direction
        for i in (0..n as usize).rev() {
            if sub(lsf[i], th2) <= 0 {
                curr_min_dist = min_dist_fac2;
            } else if sub(lsf[i], th1) <= 0 {
                curr_min_dist = min_dist_fac3;
            }

            if sub(lsf[i], lsf_max) > 0 {
                lsf[i] = lsf_max;
            }
            lsf_max = sub(lsf[i], curr_min_dist);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modify_lsf_spreads_the_low_lsfs_evenly() {
        let mut lsf = [0i16; 16];
        for (i, value) in lsf.iter_mut().enumerate() {
            *value = 500 + 700 * i as i16;
        }
        modify_lsf(&mut lsf, 16, 12800, 1);
        // The first LSF at or above 4864 is index 7 (5400); those before it are equally spaced.
        let gap = lsf[1] - lsf[0];
        assert!(gap > 0);
        for k in 1..6 {
            assert_eq!(lsf[k] - lsf[k - 1], gap);
        }
    }

    #[test]
    fn reorder_lsfs_separates_coincident_lsfs() {
        let mut lsf = [1000i16; 16];
        reorder_lsfs(&mut lsf, LSF_GAP_FX, 16, 12800);
        for k in 1..16 {
            assert!(lsf[k] > lsf[k - 1]);
        }
    }
}
