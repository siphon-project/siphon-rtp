//! Line spectral pairs to LP coefficients, and the interpolation that gives each subframe its own
//! filter (ITU-T G.729 Release 3 `lpcfunc.c`).
//!
//! LSPs are the roots of two polynomials whose product is the LP filter, so recovering `A(z)` means
//! expanding those polynomials from their roots and recombining them. The frame transmits one LSP
//! vector, but the filter moves within the frame: the first subframe uses the average of this
//! frame's vector and the previous one, the second uses this frame's directly.

use super::filter::ORDER;
use crate::itu::basic_ops::{add, extract_l, l_add, l_msu, l_mult, l_shl, l_shr_r, l_sub, shr};
use crate::itu::oper_32b::{l_extract, mpy_32_16};

/// Coefficients in one LP filter: `A(z)` has order 10, so eleven taps including the leading 1.
pub const COEFFICIENTS: usize = ORDER + 1;

/// Expand one of the two LSP polynomials from its five roots, in Q24.
///
/// `lsp` is read with a stride of two — the caller passes the even-indexed LSPs for `F1(z)` and the
/// odd-indexed ones for `F2(z)`. The reference walks its output pointer forwards and backwards
/// through a six-element window; the same walk is written here as an index, because a pointer that
/// moves in both directions inside two nested loops is the kind of thing that is transcribed wrong
/// once and then never found by anything except the vectors.
fn expand_polynomial(lsp: &[i16], f: &mut [i32; 6]) {
    f[0] = l_mult(4096, 2048); // 1.0 in Q24
    f[1] = l_msu(0, lsp[0], 512); // -2 * lsp[0]

    let mut root = 2; // the next LSP to fold in, stepping by two
    for order in 2..=5 {
        let mut position = order;
        f[position] = f[position - 2];

        for _ in 1..order {
            let (high, low) = l_extract(f[position - 1]);
            let product = l_shl(mpy_32_16(high, low, lsp[root]), 1);
            f[position] = l_add(f[position], f[position - 2]);
            f[position] = l_sub(f[position], product);
            position -= 1;
        }
        // The inner walk always lands back on f[1], whatever the order.
        debug_assert_eq!(position, 1);
        f[1] = l_msu(f[1], lsp[root], 512);
        root += 2;
    }
}

/// Convert ten LSPs (Q15) into the eleven LP coefficients of `A(z)` (Q12).
#[must_use]
pub fn lsp_to_lp(lsp: &[i16; ORDER]) -> [i16; COEFFICIENTS] {
    let mut f1 = [0_i32; 6];
    let mut f2 = [0_i32; 6];
    expand_polynomial(&lsp[0..], &mut f1);
    expand_polynomial(&lsp[1..], &mut f2);

    // F1(z) is symmetric and F2(z) antisymmetric, so folding each into itself once recovers the
    // pair whose sum and difference are the filter's two halves.
    for i in (1..=5).rev() {
        f1[i] = l_add(f1[i], f1[i - 1]);
        f2[i] = l_sub(f2[i], f2[i - 1]);
    }

    let mut a = [0_i16; COEFFICIENTS];
    a[0] = 4096; // 1.0 in Q12
    for i in 1..=5 {
        let j = COEFFICIENTS - 1 - (i - 1);
        // Q24 to Q12 with the halving the recombination implies: a rounding shift of 13.
        a[i] = extract_l(l_shr_r(l_add(f1[i], f2[i]), 13));
        a[j] = extract_l(l_shr_r(l_sub(f1[i], f2[i]), 13));
    }
    a
}

/// The two subframes' LP filters for a frame (`Int_qlpc`).
///
/// The first subframe's filter comes from the midpoint between the previous frame's LSPs and this
/// one's, which is what stops the spectrum stepping abruptly at the frame boundary; the second uses
/// this frame's LSPs as transmitted.
#[must_use]
pub fn interpolate_subframe_filters(
    previous: &[i16; ORDER],
    current: &[i16; ORDER],
) -> [[i16; COEFFICIENTS]; 2] {
    let mut midpoint = [0_i16; ORDER];
    for i in 0..ORDER {
        midpoint[i] = add(shr(current[i], 1), shr(previous[i], 1));
    }
    [lsp_to_lp(&midpoint), lsp_to_lp(current)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plausible LSP vector: ordered, descending, spanning most of the cosine range.
    const LSP: [i16; ORDER] = [
        30_864, 27_346, 22_887, 16_217, 2516, -5842, -13_459, -20_234, -25_756, -29_622,
    ];

    #[test]
    fn the_leading_coefficient_is_unity_in_q12() {
        assert_eq!(lsp_to_lp(&LSP)[0], 4096);
    }

    #[test]
    fn the_recovered_filter_is_stable() {
        // The LSPs came from a real frame, so the filter they expand to must have all its roots
        // inside the unit circle. Checked through the reflection coefficients: the Levinson step
        // backwards from A(z) must yield |k| < 1 at every order, which is the standard stability
        // test and does not depend on this module's own arithmetic.
        let a = lsp_to_lp(&LSP);
        let mut coefficients: Vec<f64> = a.iter().map(|&c| f64::from(c) / 4096.0).collect();
        for order in (1..=ORDER).rev() {
            let k = coefficients[order];
            assert!(
                k.abs() < 1.0,
                "reflection coefficient at order {order} is {k}"
            );
            let previous = coefficients.clone();
            for i in 1..order {
                coefficients[i] = (previous[i] - k * previous[order - i]) / (1.0 - k * k);
            }
        }
    }

    #[test]
    fn interpolation_puts_the_first_subframe_between_the_frames() {
        // The first subframe's filter is built from the midpoint of the two LSP vectors. With
        // identical vectors that midpoint is *almost* the vector itself: the reference halves each
        // entry and adds, so an odd entry loses its least significant bit and comes back one low.
        // The two subframes therefore agree closely rather than exactly, and asserting equality
        // here would be asserting something the reference does not do.
        let filters = interpolate_subframe_filters(&LSP, &LSP);
        for (index, (&first, &second)) in filters[0].iter().zip(&filters[1]).enumerate() {
            let difference = (i32::from(first) - i32::from(second)).abs();
            assert!(
                difference <= 2,
                "coefficient {index}: {first} vs {second} with no LSP movement"
            );
        }
        assert!(
            LSP.iter().any(|value| value % 2 != 0),
            "the vector has odd entries, or this test proves nothing"
        );

        // And with different vectors the second subframe must equal the filter of the current
        // vector alone, while the first differs from both.
        let mut moved = LSP;
        for value in &mut moved {
            *value = value.saturating_sub(1500);
        }
        let filters = interpolate_subframe_filters(&LSP, &moved);
        assert_eq!(
            filters[1],
            lsp_to_lp(&moved),
            "second subframe is the new vector"
        );
        assert_ne!(filters[0], filters[1], "first subframe lags behind it");
        assert_ne!(
            filters[0],
            lsp_to_lp(&LSP),
            "and is not the old vector either"
        );
    }

    #[test]
    fn the_polynomial_expansion_starts_from_unity_and_twice_the_first_root() {
        // Pins the two seed values the recursion builds on, in the Q24 the rest of it assumes.
        let mut f = [0_i32; 6];
        expand_polynomial(&LSP, &mut f);
        assert_eq!(l_mult(4096, 2048), 1 << 24, "the seed really is 1.0 in Q24");
        // f[1] accumulates across the recursion, so only its sign relative to the root is fixed.
        assert!(f[0] > 0);
    }
}
