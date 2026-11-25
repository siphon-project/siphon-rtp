//! Coefficient order and context update of the context-based arithmetic coder
//! (TS 26.442 `lib_com/ACcontextMapping.c`; TS 26.445 §5.3.3.2.4 and §6.2.2.2.4).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::com::ari_hm::ContextHmConfig;
use crate::itu::basic_ops::{add, extract_l, shl, shr, sub};
use crate::itu::stl2009::l_mac0;

/// `get_next_coeff_mapped`: the next coefficient of the harmonic model's order, merging the peak
/// list (`ii[1]`) and the hole list (`ii[0]`) by index. `pp` receives 1 for a peak, 0 for a hole,
/// `idx` the position in the mapped list; returns the coefficient index (`indexBuffer[*idx]`).
///
/// A read past the end of `indexBuffer` (which a frame inside the reference's limits never makes)
/// reads 0.
pub fn get_next_coeff_mapped(
    ii: &mut [i16; 2],
    pp: &mut i16,
    idx: &mut i16,
    hm_cfg: &ContextHmConfig<'_>,
) -> i16 {
    let mut p =
        sub(ii[1], hm_cfg.num_peak_indices) & sub(index_at(hm_cfg, ii[1]), index_at(hm_cfg, ii[0]));
    if p > 0 {
        p = 0;
    }
    if p < 0 {
        p = 1;
    }
    *pp = p;
    *idx = ii[p as usize];
    ii[p as usize] = add(ii[p as usize], 1);
    index_at(hm_cfg, *idx)
}

/// `indexBuffer[i]`.
fn index_at(hm_cfg: &ContextHmConfig<'_>, i: i16) -> i16 {
    usize::try_from(i)
        .ok()
        .and_then(|i| hm_cfg.index_buffer.get(i))
        .copied()
        .unwrap_or(0)
}

/// `get_next_coeff_unmapped`: the next coefficient in natural order (`pp` and the configuration
/// are unused).
pub fn get_next_coeff_unmapped(ii: &mut [i16; 2], idx: &mut i16) -> i16 {
    *idx = ii[0];
    ii[0] = add(ii[0], 1);
    *idx
}

/// `update_mixed_context`: the context of a peak/hole sequence after a coefficient of magnitude
/// `a`.
#[must_use]
pub fn update_mixed_context(ctx: i16, a: i16) -> i16 {
    let t32 = l_mac0(1 - 13, a & !1, add(shr(a, 2), 1));
    let mut t = 0;
    if t32 <= 0 {
        t = extract_l(t32);
    }
    let a = shr(a, 3);
    if t32 > 0 {
        t = a.min(2);
    }
    add(shl(ctx & 0xf, 4), add(t, 13))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmapped_order_is_sequential() {
        let mut ii = [5, 0];
        let mut idx = 0;
        assert_eq!(get_next_coeff_unmapped(&mut ii, &mut idx), 5);
        assert_eq!(get_next_coeff_unmapped(&mut ii, &mut idx), 6);
        assert_eq!(ii[0], 7);
    }

    #[test]
    fn mapped_order_merges_peaks_and_holes() {
        // Peaks 2,3,4 then holes 0,1,5,6 and the end marker 7.
        let mut buffer = [2, 3, 4, 0, 1, 5, 6, 7];
        let mut hm_cfg = ContextHmConfig::new(&mut buffer);
        hm_cfg.num_peak_indices = 3;
        hm_cfg.hole_indices_at = 3;
        hm_cfg.num_hole_indices = 4;
        let mut ii = [3, 0];
        let (mut p, mut idx) = (0, 0);
        let mut order = Vec::new();
        for _ in 0..7 {
            order.push(get_next_coeff_mapped(&mut ii, &mut p, &mut idx, &hm_cfg));
        }
        assert_eq!(order, [0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn mixed_context_keeps_the_previous_low_nibble() {
        // a = 0: t32 = -12 -> t = -12, ctx -> (ctx & 0xf) << 4 | 1.
        assert_eq!(update_mixed_context(0x35, 0), (5 << 4) + 1);
        // A large magnitude saturates the new class at 2 (+13).
        assert_eq!(update_mixed_context(0, 100), 15);
    }
}
