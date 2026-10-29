//! The ITU-T G.191 STL2009 operators that the AMR/G.729 `basicop2` set does not carry.
//!
//! EVS (3GPP TS 26.442) is written against the 2009 revision of the Software Tool Library: the
//! `basop32.c` additions (`L_mult0`, `L_mac0`, `i_mult`, `div_l`, `L_mls`, the carry operators), and
//! the `enh1632.c` / `enhUL32.c` / `enh40.c` extensions (logical shifts, rounding shifts, unsigned
//! 32-bit arithmetic, and the 32x16 / 32x32 multiplies built on a 40-bit accumulator). The operators
//! the two lineages share are not restated here; they stay in [`super::basic_ops`], and every one of
//! them was checked against the STL2009 body before this file was written.
//!
//! # Two C-isms that decide the port
//!
//! - **Signed overflow wraps.** `L_add_c`, `L_lshl` and friends compute `a + b` or `a << n` on signed
//!   32-bit values and rely on two's-complement wrap-around, which C leaves undefined. The reference
//!   binaries that generated the TS 26.444 vectors wrap, so these ports use `wrapping_*` explicitly,
//!   and the out-of-tree oracle build is compiled with `-fwrapv` to match (reference/evs/README.md).
//! - **`-var2` on a `Word16` wraps too.** `var2 = -var2` promotes to `int` and stores back into a
//!   `Word16`, so `-(-32768)` is `-32768`. The shift operators mirror that with `wrapping_neg`.
//!
//! # Flags
//!
//! The reference keeps `Overflow` and `Carry` as process-wide globals that the operators write as a
//! side effect. The carry operators below are the only ones whose *result* depends on that state, so
//! they take it explicitly as a [`StlFlags`] the caller owns (one per decoder instance, the way the
//! single-instance reference effectively has one). Every other operator here is pure. Code that
//! *reads* `Overflow` after a pure operator observes it the way `g729::overflow` does, by comparing
//! the saturated result against the same arithmetic done wide.

use super::basic_ops::{extract_h, l_add, l_mac, l_mult, l_shl, l_shr, l_shr_r, l_sub, shl, shr_r};

/// The reference's `Flag Overflow` and `Flag Carry`, scoped to a caller rather than the process.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StlFlags {
    /// `Overflow`: set when an operator saturated (and, for the carry operators, cleared as well).
    pub overflow: bool,
    /// `Carry`: the carry in to, and out of, `L_add_c` / `L_sub_c` / `L_macNs` / `L_msuNs`.
    pub carry: bool,
}

/// 16x16 → 32 multiply without the left shift and without saturation (STL `L_mult0`).
#[inline]
#[must_use]
pub const fn l_mult0(var1: i16, var2: i16) -> i32 {
    var1 as i32 * var2 as i32
}

/// `L_add(L_var3, L_mult0(var1, var2))` (STL `L_mac0`).
#[inline]
#[must_use]
pub fn l_mac0(l_var3: i32, var1: i16, var2: i16) -> i32 {
    l_add(l_var3, l_mult0(var1, var2))
}

/// `L_sub(L_var3, L_mult0(var1, var2))` (STL `L_msu0`).
#[inline]
#[must_use]
pub fn l_msu0(l_var3: i32, var1: i16, var2: i16) -> i32 {
    l_sub(l_var3, l_mult0(var1, var2))
}

/// 16x16 → 16 integer multiply, saturated (STL `i_mult`).
///
/// The STL source carries two bodies: a wrapping `return a*b` under `ORIGINAL_G7231`, and
/// `saturate(a*b)` otherwise. TS 26.442 never defines `ORIGINAL_G7231`, so EVS saturates. Read raw,
/// the source suggests the opposite; the compiled reference is what decides.
#[inline]
#[must_use]
pub const fn i_mult(var1: i16, var2: i16) -> i16 {
    super::basic_ops::saturate(var1 as i32 * var2 as i32)
}

/// `extract_h(L_add(L_mac(L_var3, var1, var2), 0x8000))` (STL `mac_r`).
#[inline]
#[must_use]
pub fn mac_r(l_var3: i32, var1: i16, var2: i16) -> i16 {
    extract_h(l_add(l_mac(l_var3, var1, var2), 0x0000_8000))
}

/// `extract_h(L_add(L_msu(L_var3, var1, var2), 0x8000))` (STL `msu_r`).
#[inline]
#[must_use]
pub fn msu_r(l_var3: i32, var1: i16, var2: i16) -> i16 {
    extract_h(l_add(l_sub(l_var3, l_mult(var1, var2)), 0x0000_8000))
}

/// 32x16 multiply keeping the high part, `Lv * v >> 15` (STL `L_mls`).
#[inline]
#[must_use]
pub fn l_mls(l_v: i32, v: i16) -> i32 {
    // `(Lv & 0xffff) * v` fits in 32 bits: |65535 · -32768| < 2^31.
    let low = l_shr((l_v & 0x0000_ffff) * v as i32, 15);
    l_mac(low, v, extract_h(l_v))
}

/// Fractional division `L_num / (den << 16)` in Q15 (STL `div_l`).
///
/// Requires `L_num >= 0` and `den > 0`; the reference calls `exit(-1)` otherwise. A hostile frame
/// must not end the process, so a violated precondition saturates to `MAX_16` instead, the same
/// policy [`super::basic_ops::div_s`] already applies.
#[must_use]
pub fn div_l(l_num: i32, den: i16) -> i16 {
    if den <= 0 || l_num < 0 {
        return i16::MAX;
    }
    let mut l_den = (den as i32) << 16;
    if l_num >= l_den {
        return i16::MAX;
    }
    let mut l_num = l_shr(l_num, 1);
    l_den = l_shr(l_den, 1);
    let mut var_out = 0i16;
    for _ in 0..15 {
        var_out = shl(var_out, 1);
        l_num = l_shl(l_num, 1);
        if l_num >= l_den {
            l_num = l_sub(l_num, l_den);
            var_out = super::basic_ops::add(var_out, 1);
        }
    }
    var_out
}

/// Logical left shift of a 16-bit value; a negative count shifts logically right (STL `lshl`).
#[inline]
#[must_use]
pub fn lshl(var1: i16, var2: i16) -> i16 {
    if var2 < 0 {
        // `-(-32768)` recurses forever in the reference; any count of 16 or more clears the value.
        return if var2 == i16::MIN && var1 != 0 {
            0
        } else {
            lshr(var1, var2.wrapping_neg())
        };
    }
    if var2 == 0 || var1 == 0 {
        var1
    } else if var2 >= 16 {
        0
    } else {
        ((var1 as i32) << var2) as i16
    }
}

/// Logical right shift of a 16-bit value; a negative count shifts left (STL `lshr`).
#[inline]
#[must_use]
pub fn lshr(var1: i16, var2: i16) -> i16 {
    if var2 < 0 {
        return if var2 == i16::MIN && var1 != 0 {
            0
        } else {
            lshl(var1, var2.wrapping_neg())
        };
    }
    if var2 == 0 || var1 == 0 {
        var1
    } else if var2 >= 16 {
        0
    } else {
        ((var1 as u16) >> var2) as i16
    }
}

/// Logical left shift of a 32-bit value; a negative count shifts logically right (STL `L_lshl`).
#[inline]
#[must_use]
pub fn l_lshl(l_var1: i32, var2: i16) -> i32 {
    if var2 < 0 {
        return if var2 == i16::MIN && l_var1 != 0 {
            0
        } else {
            l_lshr(l_var1, var2.wrapping_neg())
        };
    }
    if var2 == 0 || l_var1 == 0 {
        l_var1
    } else if var2 >= 32 {
        0
    } else {
        ((l_var1 as u32) << var2) as i32
    }
}

/// Logical right shift of a 32-bit value; a negative count shifts left (STL `L_lshr`).
#[inline]
#[must_use]
pub fn l_lshr(l_var1: i32, var2: i16) -> i32 {
    if var2 < 0 {
        return if var2 == i16::MIN && l_var1 != 0 {
            0
        } else {
            l_lshl(l_var1, var2.wrapping_neg())
        };
    }
    if var2 == 0 || l_var1 == 0 {
        l_var1
    } else if var2 >= 32 {
        0
    } else {
        ((l_var1 as u32) >> var2) as i32
    }
}

/// `shl` for a non-negative count, rounding `shr_r` for a negative one (STL `shl_r`).
#[inline]
#[must_use]
pub fn shl_r(var1: i16, var2: i16) -> i16 {
    if var2 >= 0 {
        shl(var1, var2)
    } else {
        shr_r(var1, var2.wrapping_neg())
    }
}

/// `L_shl` for a non-negative count, rounding `L_shr_r` for a negative one (STL `L_shl_r`).
#[inline]
#[must_use]
pub fn l_shl_r(l_var1: i32, var2: i16) -> i32 {
    if var2 >= 0 {
        l_shl(l_var1, var2)
    } else {
        l_shr_r(l_var1, var2.wrapping_neg())
    }
}

/// Number of left shifts that bring the MSB of a non-zero unsigned value to bit 31; 0 for 0
/// (STL `norm_ul`).
#[inline]
#[must_use]
pub const fn norm_ul(ul_var1: u32) -> i16 {
    if ul_var1 == 0 {
        0
    } else {
        ul_var1.leading_zeros() as i16
    }
}

/// Unsigned 32-bit addition, wrapping, with the wrap reported (STL `UL_addNs`).
#[inline]
#[must_use]
pub const fn ul_add_ns(ul_var1: u32, ul_var2: u32) -> (u32, bool) {
    ul_var1.overflowing_add(ul_var2)
}

/// Unsigned 32-bit subtraction, wrapping, with `var1 < var2` reported as the sign (STL `UL_subNs`).
#[inline]
#[must_use]
pub const fn ul_sub_ns(ul_var1: u32, ul_var2: u32) -> (u32, bool) {
    (ul_var1.wrapping_sub(ul_var2), ul_var1 < ul_var2)
}

/// Unsigned 32x16 multiply into a 48-bit result, returned as `(bits 16..48, bits 0..16)`
/// (STL `Mpy_32_16_uu`).
#[inline]
#[must_use]
pub const fn mpy_32_16_uu(ul_var1: u32, uvar2: u16) -> (u32, u16) {
    let product = ul_var1 as u64 * uvar2 as u64;
    ((product >> 16) as u32, product as u16)
}

/// Unsigned 32x32 multiply into a 64-bit result, returned as `(high, low)` (STL `Mpy_32_32_uu`).
#[inline]
#[must_use]
pub const fn mpy_32_32_uu(ul_var1: u32, ul_var2: u32) -> (u32, u32) {
    let product = ul_var1 as u64 * ul_var2 as u64;
    ((product >> 32) as u32, product as u32)
}

/// Unsigned 32x32 multiply keeping the low 32 bits (STL `UL_Mpy_32_32`).
#[inline]
#[must_use]
pub const fn ul_mpy_32_32(ul_var1: u32, ul_var2: u32) -> u32 {
    ul_var1.wrapping_mul(ul_var2)
}

/// Signed 32x16 fractional multiply, `2·x·y` as a 48-bit value returned as
/// `(bits 16..48, bits 0..16)` (STL `Mpy_32_16_ss`, `enh40.c`).
///
/// The reference builds this on a 40-bit accumulator, but for 32x16 operands every intermediate
/// stays below 2^34, so the accumulator's bit-39 saturation can never fire and the operator is the
/// exact product split at bit 16. The one exception is `MIN_32 · MIN_16`, whose doubled product is
/// 2^47 and does not fit the signed high part; the reference special-cases it to `(MAX_32, 0xffff)`.
#[inline]
#[must_use]
pub const fn mpy_32_16_ss(l_var1: i32, var2: i16) -> (i32, u16) {
    if l_var1 == i32::MIN && var2 == i16::MIN {
        return (i32::MAX, 0xffff);
    }
    let product = 2 * l_var1 as i64 * var2 as i64;
    ((product >> 16) as i32, product as u16)
}

/// Signed 32x32 fractional multiply, `2·x·y` as a 64-bit value returned as `(high, low)`
/// (STL `Mpy_32_32_ss`, `enh40.c`).
///
/// As for [`mpy_32_16_ss`], the 40-bit accumulator never saturates for these operands (its partial
/// sums stay below 2^34), so this is the exact doubled product. `MIN_32 · MIN_32` doubles to 2^63,
/// which does not fit, and is special-cased to `(MAX_32, 0xffffffff)` exactly as the reference does.
#[inline]
#[must_use]
pub const fn mpy_32_32_ss(l_var1: i32, l_var2: i32) -> (i32, u32) {
    if l_var1 == i32::MIN && l_var2 == i32::MIN {
        return (i32::MAX, 0xffff_ffff);
    }
    let product = 2 * (l_var1 as i64 * l_var2 as i64);
    ((product >> 32) as i32, product as u32)
}

/// 32-bit addition with carry in and carry out (STL `L_add_c`).
///
/// No saturation: the sum wraps, and `Overflow` / `Carry` describe what happened. Ported branch for
/// branch, including the two corner rules for an incoming carry (a pre-carry sum of `MAX_32`
/// overflows, a pre-carry sum of `-1` carries out).
#[must_use]
pub fn l_add_c(l_var1: i32, l_var2: i32, flags: &mut StlFlags) -> i32 {
    let l_var_out = l_var1
        .wrapping_add(l_var2)
        .wrapping_add(i32::from(flags.carry));
    let l_test = l_var1.wrapping_add(l_var2);
    // Every branch assigns `Overflow` outright: this operator clears the flag as well as setting it.
    let (overflow, carry_int) = if l_var1 > 0 && l_var2 > 0 && l_test < 0 {
        (true, false)
    } else if l_var1 < 0 && l_var2 < 0 {
        (l_test >= 0, true)
    } else if (l_var1 ^ l_var2) < 0 && l_test >= 0 {
        (false, true)
    } else {
        (false, false)
    };
    flags.overflow = overflow;
    if flags.carry {
        if l_test == i32::MAX {
            flags.overflow = true;
            flags.carry = carry_int;
        } else if l_test == -1 {
            flags.carry = true;
        } else {
            flags.carry = carry_int;
        }
    } else {
        flags.carry = carry_int;
    }
    l_var_out
}

/// 32-bit subtraction with borrow in and carry out (STL `L_sub_c`).
///
/// Ported branch for branch. Note the asymmetry with [`l_add_c`]: on the no-carry path the reference
/// leaves `Overflow` untouched unless one of its three cases fires.
#[must_use]
pub fn l_sub_c(l_var1: i32, l_var2: i32, flags: &mut StlFlags) -> i32 {
    if flags.carry {
        flags.carry = false;
        if l_var2 != i32::MIN {
            return l_add_c(l_var1, -l_var2, flags);
        }
        let l_var_out = l_var1.wrapping_sub(l_var2);
        if l_var1 > 0 {
            flags.overflow = true;
            flags.carry = false;
        }
        return l_var_out;
    }
    let l_var_out = l_var1.wrapping_sub(l_var2).wrapping_sub(1);
    let l_test = l_var1.wrapping_sub(l_var2);
    let mut carry_int = false;
    if l_test < 0 && l_var1 > 0 && l_var2 < 0 {
        flags.overflow = true;
        carry_int = false;
    } else if l_test > 0 && l_var1 < 0 && l_var2 > 0 {
        flags.overflow = true;
        carry_int = true;
    } else if l_test > 0 && (l_var1 ^ l_var2) > 0 {
        flags.overflow = false;
        carry_int = true;
    }
    if l_test == i32::MIN {
        flags.overflow = true;
    }
    flags.carry = carry_int;
    l_var_out
}

/// `L_add_c(L_var3, L_mult(var1, var2))` (STL `L_macNs`).
///
/// `L_mult` raises `Overflow` when it saturates, but every path through `L_add_c` then assigns
/// `Overflow` outright, so that side effect never survives and is not modelled.
#[must_use]
pub fn l_mac_ns(l_var3: i32, var1: i16, var2: i16, flags: &mut StlFlags) -> i32 {
    l_add_c(l_var3, l_mult(var1, var2), flags)
}

/// `L_sub_c(L_var3, L_mult(var1, var2))` (STL `L_msuNs`).
///
/// Unlike [`l_mac_ns`], `L_sub_c`'s no-carry path can leave `Overflow` as `L_mult` set it, so the
/// saturating case (`MIN_16 · MIN_16`) raises the flag first, as the reference does.
#[must_use]
pub fn l_msu_ns(l_var3: i32, var1: i16, var2: i16, flags: &mut StlFlags) -> i32 {
    if var1 == i16::MIN && var2 == i16::MIN {
        flags.overflow = true;
    }
    l_sub_c(l_var3, l_mult(var1, var2), flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every expected value below was produced by the TS 26.442 STL2009 C (`basop32.c`, `enh1632.c`,
    // `enhUL32.c`, `enh40.c`) built with `-fwrapv`, not derived from this file. The exhaustive
    // differential run against the same build lives in `tests/evs_basop_oracle.rs`.

    #[test]
    fn l_mult0_and_mac0_do_not_shift_or_saturate_the_product() {
        assert_eq!(l_mult0(i16::MIN, i16::MIN), 0x4000_0000);
        assert_eq!(l_mac0(i32::MAX, 1, 1), i32::MAX);
        assert_eq!(l_msu0(i32::MIN, 1, 1), i32::MIN);
        assert_eq!(l_mac0(10, -3, 4), -2);
    }

    #[test]
    fn i_mult_saturates_the_integer_product() {
        assert_eq!(i_mult(300, 300), i16::MAX);
        assert_eq!(i_mult(i16::MIN, -1), i16::MAX);
        assert_eq!(i_mult(-7, 9), -63);
    }

    #[test]
    fn mac_r_and_msu_r_round_the_accumulator() {
        assert_eq!(mac_r(0, 0x4000, 0x4000), 0x2000);
        assert_eq!(mac_r(0x7fff_0000, 0x7fff, 0x7fff), i16::MAX);
        assert_eq!(msu_r(0, 0x4000, 0x4000), -0x2000);
        assert_eq!(msu_r(i32::MIN, 1, 1), i16::MIN);
    }

    #[test]
    fn l_mls_keeps_the_high_part_of_a_32x16_product() {
        assert_eq!(l_mls(0x4000_0000, 0x4000), 0x2000_0000);
        assert_eq!(l_mls(0x1234_5678, -12345), -115_063_740);
        assert_eq!(l_mls(-1, 0x7fff), -1);
    }

    #[test]
    fn div_l_divides_by_a_denominator_in_the_high_half() {
        assert_eq!(div_l(0x2000_0000, 0x4000), 0x4000);
        assert_eq!(div_l(0x1000_0000, 0x6000), 0x1555);
        assert_eq!(div_l(0x4000_0000, 0x4000), i16::MAX);
        assert_eq!(div_l(1, 0x7fff), 0);
    }

    #[test]
    fn div_l_saturates_on_a_violated_precondition_instead_of_exiting() {
        assert_eq!(div_l(-1, 0x4000), i16::MAX);
        assert_eq!(div_l(1, 0), i16::MAX);
        assert_eq!(div_l(1, -5), i16::MAX);
    }

    #[test]
    fn logical_shifts_fill_with_zeros() {
        assert_eq!(lshr(-1, 1), 0x7fff);
        assert_eq!(lshr(i16::MIN, 15), 1);
        assert_eq!(lshl(0x4001, 1), -0x7ffe);
        assert_eq!(lshl(1, 16), 0);
        assert_eq!(lshl(-1, -4), 0x0fff);
        assert_eq!(l_lshr(-1, 1), 0x7fff_ffff);
        assert_eq!(l_lshl(0x4000_0001, 1), i32::MIN + 2);
        assert_eq!(l_lshl(5, 32), 0);
        assert_eq!(l_lshr(i32::MIN, -1), 0);
    }

    #[test]
    fn rounding_shifts_round_only_when_shifting_right() {
        assert_eq!(shl_r(3, -1), 2);
        assert_eq!(shl_r(0x4000, 1), i16::MAX);
        assert_eq!(shl_r(-3, -1), -1);
        assert_eq!(l_shl_r(3, -1), 2);
        assert_eq!(l_shl_r(0x4000_0000, 1), i32::MAX);
        assert_eq!(l_shl_r(-5, -2), -1);
    }

    #[test]
    fn norm_ul_counts_leading_zeros_of_a_non_zero_value() {
        assert_eq!(norm_ul(0), 0);
        assert_eq!(norm_ul(1), 31);
        assert_eq!(norm_ul(0x8000_0000), 0);
        assert_eq!(norm_ul(0x0001_ffff), 15);
    }

    #[test]
    fn unsigned_add_and_subtract_report_wrap_and_sign() {
        assert_eq!(ul_add_ns(u32::MAX, 1), (0, true));
        assert_eq!(ul_add_ns(5, 6), (11, false));
        assert_eq!(ul_sub_ns(5, 6), (u32::MAX, true));
        assert_eq!(ul_sub_ns(6, 6), (0, false));
    }

    #[test]
    fn unsigned_multiplies_split_the_product() {
        assert_eq!(mpy_32_16_uu(u32::MAX, u16::MAX), (0xfffe_ffff, 1));
        assert_eq!(mpy_32_32_uu(u32::MAX, u32::MAX), (0xffff_fffe, 1));
        assert_eq!(ul_mpy_32_32(0x1_0001, 0x1_0001), 0x0002_0001);
    }

    #[test]
    fn signed_fractional_multiplies_double_and_split_the_product() {
        assert_eq!(mpy_32_16_ss(0x4000_0000, 0x4000), (0x2000_0000, 0));
        assert_eq!(mpy_32_16_ss(i32::MIN, i16::MIN), (i32::MAX, 0xffff));
        assert_eq!(mpy_32_16_ss(-1, 1), (-1, 0xfffe));
        assert_eq!(mpy_32_16_ss(0x1234_5678, -12345), (-115_063_740, 32400));
        assert_eq!(mpy_32_32_ss(0x4000_0000, 0x4000_0000), (0x2000_0000, 0));
        assert_eq!(mpy_32_32_ss(i32::MIN, i32::MIN), (i32::MAX, 0xffff_ffff));
        assert_eq!(mpy_32_32_ss(-1, 1), (-1, 0xffff_fffe));
    }

    #[test]
    fn l_add_c_carries_in_and_out_without_saturating() {
        let mut flags = StlFlags::default();
        assert_eq!(l_add_c(i32::MAX, 1, &mut flags), i32::MIN);
        assert_eq!(
            flags,
            StlFlags {
                overflow: true,
                carry: false
            }
        );

        let mut flags = StlFlags::default();
        assert_eq!(l_add_c(-1, -1, &mut flags), -2);
        assert_eq!(
            flags,
            StlFlags {
                overflow: false,
                carry: true
            }
        );
        assert_eq!(l_add_c(0, 0, &mut flags), 1);
        assert_eq!(
            flags,
            StlFlags {
                overflow: false,
                carry: false
            }
        );

        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        assert_eq!(l_add_c(i32::MAX, 0, &mut flags), i32::MIN);
        assert_eq!(
            flags,
            StlFlags {
                overflow: true,
                carry: false
            }
        );

        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        assert_eq!(l_add_c(-1, 0, &mut flags), 0);
        assert_eq!(
            flags,
            StlFlags {
                overflow: false,
                carry: true
            }
        );
    }

    #[test]
    fn l_sub_c_borrows_when_the_carry_is_clear() {
        let mut flags = StlFlags::default();
        assert_eq!(l_sub_c(5, 3, &mut flags), 1);
        assert_eq!(
            flags,
            StlFlags {
                overflow: false,
                carry: true
            }
        );

        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        assert_eq!(l_sub_c(5, 3, &mut flags), 2);
        assert_eq!(
            flags,
            StlFlags {
                overflow: false,
                carry: true
            }
        );

        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        assert_eq!(l_sub_c(1, i32::MIN, &mut flags), i32::MIN + 1);
        assert_eq!(
            flags,
            StlFlags {
                overflow: true,
                carry: false
            }
        );

        let mut flags = StlFlags {
            overflow: true,
            carry: false,
        };
        assert_eq!(l_sub_c(0, 0, &mut flags), -1);
        assert_eq!(
            flags,
            StlFlags {
                overflow: true,
                carry: false
            }
        );
    }

    #[test]
    fn mac_ns_and_msu_ns_accumulate_through_the_carry() {
        let mut flags = StlFlags::default();
        assert_eq!(l_mac_ns(i32::MAX, 1, 1, &mut flags), i32::MIN + 1);
        assert_eq!(
            flags,
            StlFlags {
                overflow: true,
                carry: false
            }
        );

        let mut flags = StlFlags::default();
        assert_eq!(l_msu_ns(0, i16::MIN, i16::MIN, &mut flags), i32::MIN);
        assert_eq!(
            flags,
            StlFlags {
                overflow: true,
                carry: false
            }
        );
    }
}
