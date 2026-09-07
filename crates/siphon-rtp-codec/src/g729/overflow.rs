//! The ITU `Overflow` flag, observed rather than reimplemented.
//!
//! G.729's decoder does not merely tolerate arithmetic saturation, it *reacts* to it: after
//! synthesising a subframe it asks whether the filter saturated and, if it did, scales the whole
//! excitation history down by 4 and synthesises again (ITU-T G.729 `dec_ld8k.c`, the `Overflow`
//! test after `Syn_filt`). The `overflow` test vector exists to exercise exactly that path, so the
//! signal has to be exact — not approximately right, and not silently dropped.
//!
//! The reference carries it as a global `Flag Overflow` that the basic operators set as a side
//! effect. A process-wide mutable flag is not available here, and would be wrong anyway with more
//! than one call in flight, so the flag is a value threaded through the calls that can raise it.
//!
//! # Why these wrappers are not a second implementation of the operators
//!
//! Across the whole of `basic_op.c` the flag is raised in exactly six places — `sature`, `shl`,
//! `L_mult`, `L_add`, `L_sub` and `L_shl` — and in every one of them at the moment the result is
//! clamped to the representable range. So "the reference set `Overflow`" and "the saturating result
//! differs from the exact one" are the same statement.
//!
//! These wrappers therefore call the shared [`crate::itu::basic_ops`] operator for the value and
//! compare it against the arithmetic performed wide. The saturation logic itself is not restated,
//! which is what keeps this from being a second, drifting copy of the operators the AMR vectors
//! already prove.

use crate::itu::basic_ops;

/// The reference's `Flag Overflow`, scoped to a caller rather than the process.
///
/// Cleared by the caller before the region it wants to observe (`Overflow = 0` in the reference),
/// then read once after it (`if (Overflow != 0)`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Overflow(bool);

impl Overflow {
    /// A cleared flag — the reference's `Overflow = 0`.
    #[must_use]
    pub fn clear() -> Self {
        Self(false)
    }

    /// Whether any operation performed through this flag saturated.
    #[must_use]
    pub fn raised(self) -> bool {
        self.0
    }

    /// Record the outcome of one operation: `exact` is the result the arithmetic would have had in
    /// unlimited precision, `saturated` what the ITU operator actually returned.
    fn observe(&mut self, exact: i64, saturated: i32) -> i32 {
        if exact != i64::from(saturated) {
            self.0 = true;
        }
        saturated
    }
}

/// `L_add` (G.191), raising `flag` when the sum saturates.
pub fn l_add(flag: &mut Overflow, l_var1: i32, l_var2: i32) -> i32 {
    flag.observe(
        i64::from(l_var1) + i64::from(l_var2),
        basic_ops::l_add(l_var1, l_var2),
    )
}

/// `L_sub` (G.191), raising `flag` when the difference saturates.
pub fn l_sub(flag: &mut Overflow, l_var1: i32, l_var2: i32) -> i32 {
    flag.observe(
        i64::from(l_var1) - i64::from(l_var2),
        basic_ops::l_sub(l_var1, l_var2),
    )
}

/// `L_mult` (G.191), raising `flag` on the single input pair that saturates it (−32768 × −32768,
/// whose exact product 2^30 doubles to 2^31 and clamps).
pub fn l_mult(flag: &mut Overflow, var1: i16, var2: i16) -> i32 {
    flag.observe(
        i64::from(var1) * i64::from(var2) * 2,
        basic_ops::l_mult(var1, var2),
    )
}

/// `L_mac` (G.191) = `L_add(l_var3, L_mult(var1, var2))`, raising `flag` from either step exactly as
/// the reference's nesting does.
pub fn l_mac(flag: &mut Overflow, l_var3: i32, var1: i16, var2: i16) -> i32 {
    let product = l_mult(flag, var1, var2);
    l_add(flag, l_var3, product)
}

/// `L_msu` (G.191) = `L_sub(l_var3, L_mult(var1, var2))`, raising `flag` from either step.
pub fn l_msu(flag: &mut Overflow, l_var3: i32, var1: i16, var2: i16) -> i32 {
    let product = l_mult(flag, var1, var2);
    l_sub(flag, l_var3, product)
}

/// `L_shl` (G.191), raising `flag` when a left shift pushes significant bits out. A negative shift
/// is `L_shr`, which cannot saturate and so never raises it.
pub fn l_shl(flag: &mut Overflow, l_var1: i32, var2: i16) -> i32 {
    let saturated = basic_ops::l_shl(l_var1, var2);
    if var2 <= 0 {
        return saturated;
    }
    let exact = i64::from(l_var1) << var2.min(63);
    flag.observe(exact, saturated)
}

/// `round` (G.191) = `extract_h(L_add(l_var1, 0x8000))`, raising `flag` from the rounding addition.
pub fn round_word(flag: &mut Overflow, l_var1: i32) -> i16 {
    let rounded = l_add(flag, l_var1, 0x0000_8000);
    basic_ops::extract_h(rounded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cleared_flag_stays_down_across_arithmetic_that_does_not_saturate() {
        let mut flag = Overflow::clear();
        assert_eq!(l_add(&mut flag, 1_000, 2_000), 3_000);
        assert_eq!(l_sub(&mut flag, 2_000, 500), 1_500);
        assert_eq!(l_mult(&mut flag, 16_384, 2), 65_536);
        assert_eq!(l_shl(&mut flag, 1, 4), 16);
        assert_eq!(round_word(&mut flag, 0x0001_8000), 2);
        assert!(!flag.raised(), "nothing here saturates");
    }

    #[test]
    fn each_operator_raises_the_flag_exactly_where_the_reference_does() {
        // One case per site the reference's basic_op.c sets Overflow = 1 on the decoder's synthesis
        // path, each checked to still return the saturated value the operator always returned.
        let mut flag = Overflow::clear();
        assert_eq!(l_add(&mut flag, i32::MAX, 1), i32::MAX);
        assert!(flag.raised(), "L_add saturating high");

        let mut flag = Overflow::clear();
        assert_eq!(l_sub(&mut flag, i32::MIN, 1), i32::MIN);
        assert!(flag.raised(), "L_sub saturating low");

        // L_mult saturates for exactly one input pair: -32768 * -32768.
        let mut flag = Overflow::clear();
        assert_eq!(l_mult(&mut flag, i16::MIN, i16::MIN), i32::MAX);
        assert!(flag.raised(), "L_mult(-32768, -32768)");

        let mut flag = Overflow::clear();
        assert_eq!(l_shl(&mut flag, 0x4000_0000, 2), i32::MAX);
        assert!(flag.raised(), "L_shl pushing significant bits out");

        let mut flag = Overflow::clear();
        assert_eq!(round_word(&mut flag, i32::MAX), 0x7fff);
        assert!(flag.raised(), "round's L_add(0x8000) saturating");
    }

    #[test]
    fn a_right_shift_never_raises_the_flag() {
        // L_shl with a negative count is L_shr in the reference, which discards low bits rather
        // than clamping — losing precision is not overflow, and treating it as such would send the
        // decoder down the excitation-rescaling path on ordinary frames.
        let mut flag = Overflow::clear();
        assert_eq!(l_shl(&mut flag, i32::MIN, -1), i32::MIN / 2);
        assert_eq!(l_shl(&mut flag, 0x7fff_ffff, -8), 0x007f_ffff);
        assert!(!flag.raised());
    }

    #[test]
    fn the_wrappers_return_what_the_shared_operators_return() {
        // The wrappers exist to observe saturation, never to change a value. Sweep the corners plus
        // an arbitrary spread and require agreement with the operators the AMR vectors already pin.
        let corners = [
            i32::MIN,
            i32::MIN + 1,
            -70_000,
            -1,
            0,
            1,
            70_000,
            i32::MAX - 1,
            i32::MAX,
        ];
        for &a in &corners {
            for &b in &corners {
                let mut flag = Overflow::clear();
                assert_eq!(
                    l_add(&mut flag, a, b),
                    basic_ops::l_add(a, b),
                    "l_add {a} {b}"
                );
                let mut flag = Overflow::clear();
                assert_eq!(
                    l_sub(&mut flag, a, b),
                    basic_ops::l_sub(a, b),
                    "l_sub {a} {b}"
                );
            }
            for shift in -31..=31_i16 {
                let mut flag = Overflow::clear();
                assert_eq!(
                    l_shl(&mut flag, a, shift),
                    basic_ops::l_shl(a, shift),
                    "l_shl {a} {shift}"
                );
            }
            let mut flag = Overflow::clear();
            assert_eq!(
                round_word(&mut flag, a),
                basic_ops::round_word(a),
                "round {a}"
            );
        }
        for a in [i16::MIN, -1, 0, 1, 12_345, i16::MAX] {
            for b in [i16::MIN, -1, 0, 1, -9_876, i16::MAX] {
                let mut flag = Overflow::clear();
                assert_eq!(
                    l_mult(&mut flag, a, b),
                    basic_ops::l_mult(a, b),
                    "l_mult {a} {b}"
                );
                let mut flag = Overflow::clear();
                assert_eq!(
                    l_mac(&mut flag, 1_000, a, b),
                    basic_ops::l_mac(1_000, a, b),
                    "l_mac {a} {b}"
                );
                let mut flag = Overflow::clear();
                assert_eq!(
                    l_msu(&mut flag, 1_000, a, b),
                    basic_ops::l_msu(1_000, a, b),
                    "l_msu {a} {b}"
                );
            }
        }
    }
}
