//! The two LP filters the decoder runs every subframe (ITU-T G.729 Release 3 `filter.c`):
//! synthesis `1/A(z)`, and its inverse `A(z)` which the postfilter uses to recover the residual.
//!
//! `syn_filt` is the one place in the decoder where arithmetic saturation is not a detail to be
//! swallowed. A frame whose excitation drives the synthesis filter into saturation is re-synthesised
//! from a rescaled excitation history, so this returns the [`Overflow`] the reference reads out of
//! its global after the call — see [`super::overflow`] for why observing it is exact.

use super::overflow::{self, Overflow};
use crate::itu::basic_ops::l_mult;

/// LP filter order.
pub const ORDER: usize = 10;

/// Synthesis filter `1/A(z)`: excitation in, reconstructed speech out.
///
/// `a` holds the `ORDER + 1` prediction coefficients in Q12, `mem` the filter's `ORDER` samples of
/// history. `update` writes the new history back, which the caller withholds until it knows whether
/// the subframe has to be redone.
///
/// The returned flag is raised when any step saturated. Ignoring it is a decision, not a default:
/// the decoder's response to a saturated subframe is to scale its excitation down and filter again.
#[must_use = "a saturated synthesis subframe must be rescaled and refiltered, not accepted"]
pub fn syn_filt(
    a: &[i16],
    x: &[i16],
    y: &mut [i16],
    length: usize,
    mem: &mut [i16],
    update: bool,
) -> Overflow {
    debug_assert!(a.len() > ORDER && mem.len() >= ORDER && x.len() >= length && y.len() >= length);
    let mut flag = Overflow::clear();

    // The reference filters into one buffer holding [history | output] so the recursion can index
    // backwards past the start of the subframe without a special case for the first ORDER samples.
    let mut scratch = [0_i16; ORDER + 80];
    scratch[..ORDER].copy_from_slice(&mem[..ORDER]);

    for i in 0..length {
        let mut sum = l_mult(x[i], a[0]);
        for j in 1..=ORDER {
            sum = overflow::l_msu(&mut flag, sum, a[j], scratch[ORDER + i - j]);
        }
        sum = overflow::l_shl(&mut flag, sum, 3);
        scratch[ORDER + i] = overflow::round_word(&mut flag, sum);
    }
    y[..length].copy_from_slice(&scratch[ORDER..ORDER + length]);

    if update {
        mem[..ORDER].copy_from_slice(&y[length - ORDER..length]);
    }
    flag
}

/// Inverse filter `A(z)`: speech in, LP residual out.
///
/// `x` must be positioned so that `x[-ORDER..0]` — the `ORDER` samples before the slice's start —
/// are available, which is why it takes an offset into a longer buffer rather than a bare slice.
/// Saturation here is ordinary and unobserved: the reference does not test `Overflow` around it.
pub fn residu(a: &[i16], x: &[i16], offset: usize, y: &mut [i16], length: usize) {
    debug_assert!(a.len() > ORDER && offset >= ORDER && x.len() >= offset + length);
    for i in 0..length {
        let mut sum = l_mult(x[offset + i], a[0]);
        for j in 1..=ORDER {
            sum = crate::itu::basic_ops::l_mac(sum, a[j], x[offset + i - j]);
        }
        sum = crate::itu::basic_ops::l_shl(sum, 3);
        y[i] = crate::itu::basic_ops::round_word(sum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `A(z) = 1` in Q12: the identity filter, so output is input.
    const IDENTITY: [i16; ORDER + 1] = [4096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn the_identity_filter_passes_the_signal_through_unchanged() {
        let x: Vec<i16> = (0..40).map(|i| (i * 100) as i16).collect();
        let mut y = [0_i16; 40];
        let mut mem = [0_i16; ORDER];
        let flag = syn_filt(&IDENTITY, &x, &mut y, 40, &mut mem, false);
        assert!(!flag.raised(), "a unity filter on small input cannot saturate");
        assert_eq!(&y[..], &x[..]);
    }

    #[test]
    fn synthesis_and_inverse_filtering_are_inverses_of_each_other() {
        // Residu(A) then Syn_filt(1/A) reconstructs the signal. Fixed-point rounding means "close",
        // not "equal": one round() per sample in each direction, so a couple of LSBs.
        let a: [i16; ORDER + 1] = [4096, -2048, 1024, -512, 256, -128, 64, -32, 16, -8, 4];
        let speech: Vec<i16> = (0..ORDER + 40)
            .map(|i| ((i as f32 * 0.37).sin() * 4000.0) as i16)
            .collect();

        let mut residual = [0_i16; 40];
        residu(&a, &speech, ORDER, &mut residual, 40);

        let mut reconstructed = [0_i16; 40];
        let mut mem = [0_i16; ORDER];
        mem.copy_from_slice(&speech[..ORDER]);
        let flag = syn_filt(&a, &residual, &mut reconstructed, 40, &mut mem, false);
        assert!(!flag.raised());

        for (index, (&got, &want)) in reconstructed.iter().zip(&speech[ORDER..]).enumerate() {
            assert!(
                (i32::from(got) - i32::from(want)).abs() <= 2,
                "sample {index}: {got} vs {want}"
            );
        }
    }

    #[test]
    fn the_history_is_written_back_only_when_the_caller_asks() {
        let a = IDENTITY;
        let x: Vec<i16> = (1..=40).map(|i| i as i16).collect();
        let mut y = [0_i16; 40];

        let mut mem = [0_i16; ORDER];
        let _ = syn_filt(&a, &x, &mut y, 40, &mut mem, false);
        assert_eq!(mem, [0_i16; ORDER], "no update requested, history untouched");

        let _ = syn_filt(&a, &x, &mut y, 40, &mut mem, true);
        assert_eq!(
            &mem[..],
            &x[30..40],
            "update requested, history is the last ORDER outputs"
        );
    }

    #[test]
    fn a_driven_filter_reports_saturation_rather_than_hiding_it() {
        // A filter with a large negative first tap and a full-scale excitation drives the recursion
        // past the representable range. The decoder's whole overflow path hangs on this being
        // reported, so a filter that silently clipped would look identical on a spectrum plot and
        // fail the `overflow` conformance vector.
        let a: [i16; ORDER + 1] = [4096, -32_768, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let x = [i16::MAX; 40];
        let mut y = [0_i16; 40];
        let mut mem = [i16::MAX; ORDER];
        let flag = syn_filt(&a, &x, &mut y, 40, &mut mem, false);
        assert!(flag.raised(), "runaway synthesis must report saturation");
    }

    #[test]
    fn an_ordinary_subframe_does_not_report_saturation() {
        // The counterpart to the test above: speech-level input through a realistic filter must not
        // trip the flag, or the decoder would rescale its excitation on every frame.
        let a: [i16; ORDER + 1] = [4096, -1800, 900, -400, 200, -100, 50, -25, 12, -6, 3];
        let x: Vec<i16> = (0..40).map(|i| ((i as f32 * 0.9).sin() * 2000.0) as i16).collect();
        let mut y = [0_i16; 40];
        let mut mem = [0_i16; ORDER];
        let flag = syn_filt(&a, &x, &mut y, 40, &mut mem, false);
        assert!(!flag.raised());
    }
}
