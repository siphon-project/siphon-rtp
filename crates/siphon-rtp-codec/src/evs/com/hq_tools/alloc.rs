//! Part of `lib_com/hq_tools_fx.c` (see the parent module): the band limit and noise level of the
//! harmonic mode's bit allocation, and the last band with bits.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::HQ_24K40;
use crate::itu::basic_ops::{abs_s, add, div_s, l_add, l_deposit_h, l_sub, shr, sub};

/// `limit_band_noise_level_calc_fx`: from the weighted norms `wnorm` of the `*limit` bands, the
/// highest band the allocation covers (where the cumulative norm reaches 94 % (88.5 % at
/// 24.4 kbit/s) of the total, written back to `limit`) and the harmonic mode's noise level (Q15)
/// from the band-to-band envelope variation.
pub fn limit_band_noise_level_calc(
    wnorm: &[i16],
    limit: &mut i16,
    core_brate: i32,
    noise_level: &mut i16,
) {
    let nb_sfm = *limit;
    let mut ener_limit: i16 = 0;
    *noise_level = 0;
    for i in 0..10 {
        ener_limit = add(ener_limit, wnorm[i]);
        *noise_level = add(*noise_level, abs_s(sub(wnorm[i + 1], wnorm[i])));
    }
    let mut ener_sum = ener_limit;

    let tmp = sub(nb_sfm, 1);
    for i in 10..tmp.max(10) as usize {
        ener_sum = add(ener_sum, wnorm[i]);
        *noise_level = add(*noise_level, abs_s(sub(wnorm[i + 1], wnorm[i])));
    }
    ener_sum = add(ener_sum, wnorm[(nb_sfm - 1) as usize]);

    let mut fact = l_add(2_022_929_597, 0);
    if l_sub(core_brate, i32::from(HQ_24K40)) == 0 {
        fact = l_add(1_900_523_029, 1);
    }

    fact = mult_32_16(fact, ener_sum);
    let mut i: i16 = 9;
    while l_sub(l_deposit_h(ener_limit), fact) < 0 && sub(add(i, 1), nb_sfm) < 0 {
        i += 1;
        ener_limit = add(ener_limit, wnorm[i as usize]);
    }
    *limit = i;

    // noise level for spectrum filling
    if *noise_level < 0 {
        *noise_level = 0;
    }

    if sub(*noise_level, shr(ener_sum, 2)) >= 0 {
        *noise_level = 0;
    } else if ener_sum != 0 {
        *noise_level = sub(8192, div_s(*noise_level, ener_sum));
    } else {
        *noise_level = 8192;
    }
}

/// `find_last_band_fx`: the highest band below `nb_sfm` with bits allocated, or `nb_sfm - 1` when
/// none has any.
#[must_use]
pub fn find_last_band(bitalloc: &[i16], nb_sfm: i16) -> i16 {
    let mut core_sfm = sub(nb_sfm, 1);
    let mut sfm = nb_sfm - 1;
    while sfm >= 0 {
        if bitalloc[sfm as usize] != 0 {
            core_sfm = sfm;
            break;
        }
        sfm -= 1;
    }
    core_sfm
}
