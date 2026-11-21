//! Multi-word integer arithmetic (TS 26.442 `lib_com/longarith.c`). Only `longshr` is ported so
//! far.

use crate::itu::basic_ops::sub;
use crate::itu::stl2009::{l_lshl, l_lshr};

/// `longshr`: shift the little-endian multi-word value `a[0..len]` right by `bits` (1..=31).
/// Out-of-range `bits` (which the reference asserts against) leave `a` unchanged.
pub fn longshr(a: &mut [u32], bits: i16, len: i16) {
    if !(1..32).contains(&bits) || len <= 0 {
        return;
    }
    let fracb_u = sub(32, bits);
    let len = sub(len, 1) as usize;
    let mut k = 0;
    while k < len {
        a[k] = (l_lshr(a[k] as i32, bits) | l_lshl(a[k + 1] as i32, fracb_u)) as u32;
        k += 1;
    }
    a[k] = l_lshr(a[k] as i32, bits) as u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shifts_bits_across_word_boundaries() {
        let mut a = [0x0000_0003, 0x8000_0001, 0];
        longshr(&mut a, 2, 3);
        assert_eq!(a, [0x4000_0000, 0x2000_0000, 0]);
    }
}
