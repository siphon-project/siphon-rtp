//! The silence descriptor's level: five bits of energy — ITU-T G.729 Annex B §4.3, reference
//! `qsidgain.c`.
//!
//! The descriptor says how loud the background is, not what it sounds like sample by sample, so the
//! quantity quantised is the residual energy of the LP fit averaged over the frames since the last
//! descriptor. Averaging matters: a descriptor is sent at most every few frames, and one frame's
//! energy would make the comfort noise pump.
//!
//! The scale is decibels, and it is deliberately non-uniform — 4 dB steps up to 14 dB and 2 dB
//! above it — because the ear resolves a change in a quiet background far better than in a loud one.

use super::dspfunc::log2;
use super::tables::{SID_ENERGY_FACTOR, SID_ENERGY_MARGIN};
use crate::itu::basic_ops::{add, l_add, l_deposit_l, l_shl, mult, mult_r, shl, shr, sub};
use crate::itu::oper_32b::{l_extract, mpy_32_16};

/// Quantise the background level from one or two frames' residual energies (`Qua_Sidgain`).
///
/// Each energy comes with its own scaling exponent, because the frames they were measured on were
/// scaled differently by the analysis. The exponent is a **negated** power of two: the quantity a
/// pair stands for is `energy · 2^-exponent`, so a larger exponent describes a quieter frame.
///
/// Returns the five-bit index and the level it decodes to, in decibels.
#[must_use]
pub fn quantise(energies: &[i16], exponents: &[i16]) -> (u16, i16) {
    debug_assert_eq!(energies.len(), exponents.len());
    debug_assert!(!energies.is_empty() && energies.len() < SID_ENERGY_FACTOR.len());
    let count = energies.len();

    // Bring every energy onto the smallest of their exponents, plus headroom for the sum.
    let mut smallest = exponents[0];
    for &value in &exponents[1..] {
        if value < smallest {
            smallest = value;
        }
    }
    let exponent = add(smallest, 16 - SID_ENERGY_MARGIN[count]);

    let mut total = 0_i32;
    for (&energy, &own) in energies.iter().zip(exponents.iter()) {
        total = l_add(total, l_shl(l_deposit_l(energy), sub(exponent, own)));
    }
    let (high, low) = l_extract(total);
    quantise_energy(mpy_32_16(high, low, SID_ENERGY_FACTOR[count]), exponent)
}

/// The decoder's form of [`quantise`] for a lost first descriptor: one saved energy with its own
/// exponent, which the reference reaches by passing a count of zero.
#[must_use]
pub fn quantise_saved(energy: i16, exponent: i16) -> (u16, i16) {
    let accumulator = l_shl(l_deposit_l(energy), exponent);
    let (high, low) = l_extract(accumulator);
    quantise_energy(mpy_32_16(high, low, SID_ENERGY_FACTOR[0]), 0)
}

/// Map an energy to the five-bit index and the decibel level it stands for (`Quant_Energy`).
fn quantise_energy(energy: i32, exponent: i16) -> (u16, i16) {
    let (whole, fraction) = log2(energy);
    // 2^10 · log2(energy · 2^-exponent), which is decibels up to the constant below.
    let mut scaled = shl(sub(whole, exponent), 10);
    scaled = add(scaled, mult_r(fraction, 1024));

    // Below -8 dB there is nothing worth describing, and above 65 dB it is not background.
    if sub(scaled, -2721) <= 0 {
        return (0, -12);
    }
    if sub(scaled, 22_111) > 0 {
        return (31, 66);
    }

    // 4 dB steps below 14 dB, where a change in a quiet background is most audible...
    if sub(scaled, 4762) <= 0 {
        let shifted = add(scaled, 3401);
        let mut index = mult(shifted, 24);
        if index < 1 {
            index = 1;
        }
        return (index as u16, sub(shl(index, 2), 8));
    }

    // ...and 2 dB steps above it.
    let shifted = sub(scaled, 340);
    let mut index = sub(shr(mult(shifted, 193), 2), 1);
    if index < 6 {
        index = 6;
    }
    (index as u16, add(shl(index, 1), 4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g729::tables::SID_GAIN;

    #[test]
    fn every_index_the_quantiser_returns_addresses_the_reconstruction_table() {
        // The index is five bits and indexes `SID_GAIN` directly on the decode side, so an index
        // outside it would be an out-of-bounds read on a frame the encoder itself produced.
        for exponent in -8..24_i16 {
            for energy in [1_i16, 7, 100, 3000, 20_000, i16::MAX] {
                let (index, _level) = quantise(&[energy], &[exponent]);
                assert!(
                    (index as usize) < SID_GAIN.len(),
                    "energy {energy} exponent {exponent} gave index {index}"
                );
            }
        }
    }

    #[test]
    fn the_level_rises_with_the_energy() {
        // Monotonic, or a background that got louder would be described as quieter.
        let mut previous = i16::MIN;
        for exponent in (-4..20_i16).rev() {
            let (_, level) = quantise(&[20_000], &[exponent]);
            assert!(
                level >= previous,
                "exponent {exponent}: {level} < {previous}"
            );
            previous = level;
        }
    }

    #[test]
    fn silence_and_a_shout_both_saturate_rather_than_wrapping() {
        // -8 dB and 65 dB are the ends of the scale; past them the index pins instead of folding
        // round, which would describe a loud background as a silent one. The exponent is negated,
        // so a large one is the quiet end.
        assert_eq!(quantise(&[1], &[40]), (0, -12));
        assert_eq!(quantise(&[i16::MAX], &[-30]), (31, 66));
    }

    #[test]
    fn averaging_two_frames_lands_between_describing_either_alone() {
        // The descriptor covers the frames since the last one, so its level must sit between them;
        // taking just the newest would make the comfort noise pump with the background.
        let (_, quiet) = quantise(&[1000], &[4]);
        let (_, loud) = quantise(&[30_000], &[4]);
        let (_, both) = quantise(&[30_000, 1000], &[4, 4]);
        assert!(quiet <= both && both <= loud, "{quiet} .. {both} .. {loud}");
    }
}
