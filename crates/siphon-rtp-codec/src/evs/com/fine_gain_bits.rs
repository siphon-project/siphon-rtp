//! Gain-adjustment bit allocation for the HQ core (TS 26.442 `lib_com/fine_gain_bits_fx.c`).

use crate::evs::cnst::HQ_CORE;
use crate::evs::com::tools::set16;
use crate::evs::rom::{FINE_GAIN_BITS, INV_TBL_FX};
use crate::itu::basic_ops::{add, extract_l, l_shl, l_shr, l_sub, shl, sub};
use crate::itu::stl2009::l_mult0;

/// `subband_gain_bits_fx`: gain bits per band from the bits per sample of each band's
/// allocation (`rk`, Q3) over its size (`sfmsize`); at least one bit in total.
pub fn subband_gain_bits(rk: &[i16], n: i16, bits: &mut [i16], sfmsize: &[i16]) {
    let mut tot: i16 = 0;
    for i in 0..n.max(0) as usize {
        // bps = Rk[i] * ceil(32767/sfmsize[i]), an inexact C-integer division approximation;
        // sfmsize indexes inv_tbl_fx, which covers every band size the reference uses.
        let inverse = INV_TBL_FX
            .get(sfmsize[i].max(0) as usize)
            .copied()
            .unwrap_or(0);
        let mut bps = extract_l(l_shr(l_mult0(rk[i], inverse), 18)); // 3+15
        if l_sub(l_shl(l_mult0(sfmsize[i], add(bps, 1)), 3), i32::from(rk[i])) == 0 {
            bps = add(bps, 1);
        }
        bps = bps.min(7);
        // bps can be negative only for a negative allocation, which the reference never makes
        let b = FINE_GAIN_BITS[bps.max(0) as usize];
        bits[i] = b;
        tot = add(tot, b);
    }
    if tot == 0 {
        // If no gain bits were assigned, use one bit anyway for potential PVQ overage
        bits[0] = 1;
    }
}

/// `assign_gain_bits_fx`: assign gain adjustment bits per band (HQ core only) into
/// `gain_bits_array`, take them out of the allocation `rk` (Q3), and return their total; the
/// remaining shape budget goes to `rcalc` (Q3).
pub fn assign_gain_bits(
    core: i16,
    bands: i16,
    band_width: &[i16],
    rk: &mut [i16],
    gain_bits_array: &mut [i16],
    rcalc: &mut i16,
) -> i16 {
    // Allocate gain bits for every subband used, based on bit rate and bandwidth
    if sub(core, HQ_CORE) == 0 {
        subband_gain_bits(rk, bands, gain_bits_array, band_width);
    } else {
        set16(gain_bits_array, 0, bands);
    }

    // Re-adjust bit budget for gain quantization
    let mut gain_bits_tot: i16 = 0;
    *rcalc = 0;
    for i in 0..bands.max(0) as usize {
        if rk[i] > 0 {
            rk[i] = sub(rk[i], shl(gain_bits_array[i], 3));
            gain_bits_tot = add(gain_bits_tot, gain_bits_array[i]);
            *rcalc = add(*rcalc, rk[i]);
        }
    }
    gain_bits_tot
}
