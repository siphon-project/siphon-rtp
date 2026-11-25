//! LSF concealment of lost MODE2 frames (TS 26.442 `lib_com/dlpc_bfi.c`; TS 26.447 §5.4.2).

use crate::evs::cnst::{M, MODE2};
use crate::evs::com::lsf_dec_bfi::lsf_dec_bfi;
use crate::itu::basic_ops::add;

/// `dlpc_bfi`: the concealed LSFs `lsf_q` (one `M`-vector, or two for `numlpc` 2: the second is
/// concealed from the first) of a lost frame, faded from `lsfold` towards `lsf_adaptive_mean`
/// or the base `lsf_base` by `lsf_dec_bfi`; `mem_ma` / `mem_ar` are the predictor memories it
/// updates. `stab_fac` is the LSF stability factor (the reference reads it through a pointer);
/// `lsf_cng`, `lsf_q_cng` and `old_lsf_q_cng` are the background-noise LSFs when
/// `plc_background_noise_updated`.
pub fn dlpc_bfi(
    l_frame: i16,
    lsf_q: &mut [i16],
    lsfold: &[i16],
    last_good: i16,
    nb_lost_cmpt: i16,
    mem_ma: &mut [i16],
    mem_ar: &mut [i16],
    stab_fac: i16,
    lsf_adaptive_mean: &[i16],
    numlpc: i16,
    lsf_cng: Option<&[i16]>,
    plc_background_noise_updated: i8,
    mut lsf_q_cng: Option<&mut [i16]>,
    old_lsf_q_cng: Option<&[i16]>,
    lsf_base: Option<&[i16]>,
    tcxonly: i8,
) {
    let mu = M as usize;
    lsf_dec_bfi(
        MODE2,
        &mut lsf_q[..mu],
        lsfold,
        lsf_adaptive_mean,
        lsf_base,
        mem_ma,
        mem_ar,
        stab_fac,
        0,
        l_frame,
        last_good,
        nb_lost_cmpt,
        plc_background_noise_updated,
        lsf_q_cng.as_deref_mut(),
        lsf_cng,
        old_lsf_q_cng,
        0,
        0,
        tcxonly,
        0,
    );
    if crate::itu::basic_ops::sub(numlpc, 2) == 0 {
        // Decode the second LPC
        let (first, second) = lsf_q.split_at_mut(mu);
        lsf_dec_bfi(
            MODE2,
            &mut second[..mu],
            &first[..mu],
            lsf_adaptive_mean,
            lsf_base,
            mem_ma,
            mem_ar,
            stab_fac,
            0,
            l_frame,
            last_good,
            add(nb_lost_cmpt, 1),
            plc_background_noise_updated,
            lsf_q_cng,
            lsf_cng,
            old_lsf_q_cng,
            0,
            0,
            tcxonly,
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_lpcs_conceal_the_second_from_the_first() {
        let lsfold = [0i16; 16];
        let mean = [0i16; 16];
        let mut lsf_q = [0i16; 32];
        let (mut mem_ma, mut mem_ar) = ([0i16; 16], [0i16; 16]);
        dlpc_bfi(
            256,
            &mut lsf_q,
            &lsfold,
            0,
            1,
            &mut mem_ma,
            &mut mem_ar,
            0,
            &mean,
            2,
            None,
            0,
            None,
            None,
            Some(&[0i16; 16]),
            0,
        );
        // Both vectors are concealed (a zero base, zero mean and zero history stay finite).
        assert!(lsf_q.iter().all(|&value| value.abs() < 20000));
    }
}
