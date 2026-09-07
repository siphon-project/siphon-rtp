//! The interpolation tables the ITU-lineage transcendental approximations index.
//!
//! Each of these appears verbatim in both reference sources this crate ports from: 3GPP TS 26.173
//! `math_op.c` / `log2_tab.h` (AMR-WB) and ITU-T G.729 Release 3 `tab_ld8k.c` (`tabsqr`, `tabpow`,
//! `tablog`). They are the same numbers to the entry, which is why they live here once rather than
//! twice.
//!
//! # The routines that index them are NOT interchangeable
//!
//! Sharing the data is safe; sharing the wrappers is not. Taking `1/sqrt` as the example, both
//! lineages perform the identical table lookup and linear interpolation and then differ in every
//! surrounding detail:
//!
//! | | AMR-WB `Isqrt` | G.729 `Inv_sqrt` |
//! |---|---|---|
//! | result format | Q31 | Q30 |
//! | exponent | `sub(31, exp)` | `sub(30, exp)` |
//! | denormalisation | shift **left** | shift **right** |
//! | non-positive input | `0x7fffffff` | `0x3fffffff` |
//!
//! `Pow2` and `Log2` differ in the same way. A codec that borrowed the other's wrapper would be
//! wrong by a factor of two on every call, and it would still decode to something that sounded like
//! speech — which is precisely the class of bug a round trip cannot see and the reference vectors
//! can. Port the wrapper against the codec's own reference; take only the table from here.

/// `1/sqrt` interpolation table, 49 entries. TS 26.173 `math_op.c`; G.729 `tab_ld8k.c` `tabsqr`.
#[rustfmt::skip]
pub static ISQRT: [i16; 49] = [
    32767, 31790, 30894, 30070, 29309, 28602, 27945, 27330, 26755, 26214,
    25705, 25225, 24770, 24339, 23930, 23541, 23170, 22817, 22479, 22155,
    21845, 21548, 21263, 20988, 20724, 20470, 20225, 19988, 19760, 19539,
    19326, 19119, 18919, 18725, 18536, 18354, 18176, 18004, 17837, 17674,
    17515, 17361, 17211, 17064, 16921, 16782, 16646, 16514, 16384,
];

/// `2^x` interpolation table, 33 entries. TS 26.173 `math_op.c`; G.729 `tab_ld8k.c` `tabpow`.
#[rustfmt::skip]
pub static POW2: [i16; 33] = [
    16384, 16743, 17109, 17484, 17867, 18258, 18658, 19066, 19484, 19911,
    20347, 20792, 21247, 21713, 22188, 22674, 23170, 23678, 24196, 24726,
    25268, 25821, 26386, 26964, 27554, 28158, 28774, 29405, 30048, 30706,
    31379, 32066, 32767,
];

/// `log2` interpolation table, 33 entries. TS 26.173 `log2_tab.h`; G.729 `tab_ld8k.c` `tablog`.
#[rustfmt::skip]
pub static LOG2: [i16; 33] = [
    0, 1455, 2866, 4236, 5568, 6863, 8124, 9352, 10549, 11716,
    12855, 13967, 15054, 16117, 17156, 18172, 19167, 20142, 21097, 22033,
    22951, 23852, 24735, 25603, 26455, 27291, 28113, 28922, 29716, 30497,
    31266, 32023, 32767,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_carry_the_reference_endpoints_and_monotonicity() {
        // Endpoint values are the cheapest guard against a transcription slip, and each table's
        // monotonicity is a structural property of what it approximates: 1/sqrt falls across the
        // interval, 2^x and log2 rise. A single mistyped entry breaks one or the other.
        assert_eq!((ISQRT[0], ISQRT[48]), (32767, 16384));
        assert_eq!((POW2[0], POW2[32]), (16384, 32767));
        assert_eq!((LOG2[0], LOG2[32]), (0, 32767));
        assert!(ISQRT.windows(2).all(|w| w[0] > w[1]), "1/sqrt decreases");
        assert!(POW2.windows(2).all(|w| w[0] < w[1]), "2^x increases");
        assert!(LOG2.windows(2).all(|w| w[0] < w[1]), "log2 increases");
    }
}
