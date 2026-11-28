//! Quantised log2 band norm (TS 26.442 `lib_com/logqnorm_fx.c`).

use crate::evs::rom::{DICNLG2, INV_TBL_FX, SQAC_HEADROOM_FX};
use crate::itu::basic_ops::{add, extract_h, l_abs, l_add, l_shl, l_sub, norm_l, shl, shr, sub};
use crate::itu::stl2009::{l_mac0, lshr, mpy_32_16_ss};

/// `logqnorm_fx`: the norm quantisation index `k` (clamped to `0..L`) of the RMS of the `N`
/// coefficients `L_x` (Q`qx`) on the reference's log2 scale; `hvq_flag` selects the finer HVQ
/// scale at low norms. Returns `k` (the reference's `*k` out-parameter).
#[must_use]
pub fn logqnorm(l_x: &[i32], qx: i16, l: i16, n: i16, hvq_flag: i16) -> i16 {
    let count = n.max(0) as usize;
    let mut coefs16 = [0_i16; 96];
    let mut lsb: u16 = 0;
    let offset = add(3, shl(qx, 1));
    let mut l_temp1: i32 = 1;
    for &value in &l_x[..count] {
        l_temp1 = l_temp1.max(l_abs(value));
    }
    let coefs_shift = sub(norm_l(l_temp1), SQAC_HEADROOM_FX[count]);
    let mut l_temp: i32 = 0;
    for i in 0..count {
        coefs16[i] = extract_h(l_shl(l_x[i], coefs_shift));
        l_temp = l_mac0(l_temp, coefs16[i], coefs16[i]);
    }
    if sub(n, 1) > 0 {
        (l_temp, lsb) = mpy_32_16_ss(l_temp, INV_TBL_FX[count]);
    }
    let power_shift = shl(sub(coefs_shift, 16), 1);
    let temp_shift = norm_l(l_temp);
    let mut m = add(temp_shift, power_shift);
    // `lsb` is a UWord16 passed to `lshr`'s Word16 parameter: reinterpreted, then shifted
    // logically.
    l_temp1 = l_add(
        l_shl(l_temp, temp_shift),
        i32::from(lshr(lsb as i16, sub(16, temp_shift))),
    );
    m = add(offset, m);
    if m < 5 && hvq_flag != 0 {
        m = shl(m, 1);
        if l_temp1 < 1_276_901_417 {
            m = add(m, 2);
        } else if l_temp1 < 1_805_811_301 {
            m = add(m, 1);
        }
    } else {
        if l_temp1 < 1_518_500_250 {
            m = add(m, 1);
        }
        if hvq_flag != 0 {
            m = add(m, 5);
        }
    }
    m.max(0).min(sub(l, 1))
}

/// `logqnorm_2_fx`: quantise the envelope `env_fl` (Q10, one value per band `n_env_band..nb_sfm`)
/// against the `L`-level threshold table `thren` (Q10, descending) by bisection; writes the index
/// and its log2 norm `dicnlg2[index]` to `ynrm` / `normqlg2` (both starting at band `n_env_band`,
/// i.e. the caller passes the slices the reference's pointers point at).
pub fn logqnorm_2(
    env_fl: &[i32],
    l: i16,
    n_env_band: i16,
    nb_sfm: i16,
    ynrm: &mut [i16],
    normqlg2: &mut [i16],
    thren: &[i32],
) {
    let mut out = 0usize;
    let mut i = n_env_band;
    while i < nb_sfm {
        let temp = env_fl[sub(i, n_env_band) as usize];
        let index = if l_sub(thren[0], temp) <= 0 {
            0
        } else if l_sub(thren[sub(l, 2) as usize], temp) > 0 {
            sub(l, 1)
        } else {
            let power = temp;
            let mut j1: i16 = 0;
            let mut j2 = sub(l, 1);
            while sub(sub(j2, j1), 1) > 0 {
                let j = shr(add(j1, j2), 1);
                if l_sub(power, thren[j as usize]) >= 0 {
                    j2 = j;
                } else {
                    j1 = j;
                }
            }
            j2
        };
        ynrm[out] = index;
        normqlg2[out] = DICNLG2[index as usize];
        out += 1;
        i += 1;
    }
}

/// `calc_norm_fx`: the norm indices (`norm`) and their log2 values (`normlg`) of bands
/// `start_band..start_band + num_bands` of `l_x` (Q`qx`); the first band uses the 32-level scale,
/// the rest the 40-level one, and bands below `start_band` get index 0.
pub fn calc_norm(
    l_x: &[i32],
    qx: i16,
    norm: &mut [i16],
    normlg: &mut [i16],
    start_band: i16,
    num_bands: i16,
    band_len: &[i16],
    band_start: &[i16],
) {
    let start = start_band as usize;
    norm[..start].fill(0);
    let nrm = logqnorm(
        &l_x[band_start[start] as usize..],
        qx,
        32,
        band_len[start],
        0,
    );
    norm[start] = nrm;
    normlg[start] = DICNLG2[nrm as usize];

    let tmp = add(start_band, num_bands);
    let mut band = add(start_band, 1);
    while band < tmp {
        let b = band as usize;
        let nrm = logqnorm(&l_x[band_start[b] as usize..], qx, 40, band_len[b], 0);
        norm[b] = nrm;
        normlg[b] = DICNLG2[nrm as usize];
        band += 1;
    }
}
