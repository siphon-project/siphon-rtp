//! Perceptual weighting of the HQ norms for the 48 kHz bit allocation (TS 26.442
//! `lib_com/weight_fx.c`; TS 26.445 §6.2.2.3.2): the norms are grouped into
//! `NUM_MAP_BANDS` perceptual bands, smoothed, limited by the absolute threshold of hearing and
//! mapped back onto the bands as offsets.

use crate::evs::cnst::{NB_SFM, NUM_MAP_BANDS, SFM_N_STA_10K, SFM_N_STA_8K};
use crate::evs::rom::{A_TABLE_FX, SFM_WIDTH};
use crate::itu::basic_ops::{add, mult, norm_s, shl, shr, sub};

/// `spe[from..to]` summed with `add`.
fn sum_range(spe: &[i16], from: usize, to: usize) -> i16 {
    let mut tmp: i16 = 0;
    for &value in &spe[from..to] {
        tmp = add(tmp, value);
    }
    tmp
}

/// `sfm2mqb_fx`: map the band norms `spe` onto the perceptual bands `spe2q`.
fn sfm2mqb(spe: &[i16], spe2q: &mut [i16], nb_sfm: i16) {
    // short groups
    for i in 0..10 {
        spe2q[i] = add(spe[i], 3);
    }

    spe2q[10] = add(shr(add(spe[10], spe[11]), 1), 4);
    spe2q[11] = add(shr(add(spe[12], spe[13]), 1), 4);
    spe2q[12] = add(shr(add(spe[14], spe[15]), 1), 4);

    spe2q[13] = add(shr(add(spe[16], spe[17]), 1), 5);
    spe2q[14] = add(shr(add(spe[18], spe[19]), 1), 5);

    spe2q[15] = add(mult(sum_range(spe, 20, 24), 8192), 6);
    spe2q[16] = add(mult(sum_range(spe, 24, 27), 10923), 6);

    if sub(nb_sfm, SFM_N_STA_8K) > 0 {
        spe2q[17] = add(mult(sum_range(spe, 27, 30), 10923), 6);

        if sub(nb_sfm, SFM_N_STA_10K) > 0 {
            spe2q[18] = add(mult(sum_range(spe, 30, 35), 6553), 7);
            spe2q[19] = add(mult(sum_range(spe, 35, 44), 3641), 8);
        }
    }
}

/// `mqb2sfm_fx`: spread the perceptual bands `spe2q` back onto the bands `spe`.
fn mqb2sfm(spe2q: &[i16], spe: &mut [i16], lnb_sfm: i16) {
    spe[..10].copy_from_slice(&spe2q[..10]);

    spe[10] = spe2q[10];
    spe[11] = spe2q[10];

    spe[12] = spe2q[11];
    spe[13] = spe2q[11];

    spe[14] = spe2q[12];
    spe[15] = spe2q[12];

    spe[16] = spe2q[13];
    spe[17] = spe2q[13];

    spe[18] = spe2q[14];
    spe[19] = spe2q[14];

    spe[20..24].fill(spe2q[15]);
    spe[24..27].fill(spe2q[16]);

    if sub(lnb_sfm, SFM_N_STA_8K) > 0 {
        spe[27..30].fill(spe2q[17]);

        if sub(lnb_sfm, SFM_N_STA_10K) > 0 {
            spe[30..35].fill(spe2q[18]);
            spe[35..44].fill(spe2q[19]);
        }
    }
}

/// Replace each group of four bands by their mean (transient frames).
fn average_by_four(spe: &mut [i16]) {
    for group in spe.as_chunks_mut::<4>().0 {
        let mut sum: i16 = 0;
        for &value in group.iter() {
            sum = add(sum, value);
        }
        sum = shr(sum, 2);
        group.fill(sum);
    }
}

/// `map_quant_weight_fx`: the weighted norms `wnorm` (all `NB_SFM` bands) the 48 kHz bit
/// allocation runs on: `normqlg2` plus a perceptual offset per band.
pub fn map_quant_weight(normqlg2: &[i16], wnorm: &mut [i16], is_transient: i16) {
    const LNB_SFM: usize = NB_SFM as usize;
    const BANDS: usize = NUM_MAP_BANDS as usize;
    let mut spe2q = [0i16; BANDS];
    let mut spe = [0i16; LNB_SFM];

    spe.copy_from_slice(&normqlg2[..LNB_SFM]);
    if is_transient != 0 {
        average_by_four(&mut spe);
    }

    sfm2mqb(&spe, &mut spe2q, NB_SFM);

    for value in &mut spe2q {
        *value = sub(*value, 10);
    }

    // spectral smoothing
    for sfm in 1..BANDS {
        let tmp16 = sub(spe2q[sfm - 1], 4);
        spe2q[sfm] = spe2q[sfm].max(tmp16);
    }
    for sfm in (0..BANDS - 1).rev() {
        let tmp16 = sub(spe2q[sfm + 1], 8);
        spe2q[sfm] = spe2q[sfm].max(tmp16);
    }
    for sfm in 0..BANDS {
        spe2q[sfm] = spe2q[sfm].max(A_TABLE_FX[sfm]);
    }

    // saturate by the absolute threshold of hearing
    let mut spe2q_max = i16::MIN;
    let mut spe2q_min = i16::MAX;
    for sfm in 0..BANDS {
        spe2q[sfm] = sub(SFM_WIDTH[sfm], spe2q[sfm]);
        spe2q_max = spe2q[sfm].max(spe2q_max);
        spe2q_min = spe2q[sfm].min(spe2q_min);
    }
    for value in &mut spe2q {
        *value = sub(*value, spe2q_min);
    }
    spe2q_max = sub(spe2q_max, spe2q_min);
    let norm_max = norm_s(spe2q_max);
    let shift = sub(norm_max, 13);
    for value in &mut spe2q {
        *value = shl(*value, shift);
    }

    mqb2sfm(&spe2q, &mut spe, NB_SFM);

    if is_transient != 0 {
        average_by_four(&mut spe);
    }

    // modify the norms for bit allocation
    for sfm in 0..LNB_SFM {
        wnorm[sfm] = add(spe[sfm], normqlg2[sfm]);
    }
}
