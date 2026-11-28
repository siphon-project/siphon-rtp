//! Selection sort into decreasing order with an index vector (TS 26.442
//! `lib_com/reordvct_fx.c`).

use crate::itu::basic_ops::{add, sub};

/// `reordvct_fx`: rearrange `y[0..n]` in decreasing order, applying the same swaps to `idx`.
/// Equal values keep the earlier of the two in front (a later one only wins when strictly
/// larger), exactly as the reference's selection sort.
pub fn reordvct(y: &mut [i16], n: i16, idx: &mut [i16]) {
    let last = sub(n, 1);
    for i in 0..last.max(0) as usize {
        let mut im = i;
        let k = add(i as i16, 1) as usize;
        for j in k..n as usize {
            if sub(y[im], y[j]) < 0 {
                im = j;
            }
        }
        y.swap(i, im);
        idx.swap(i, im);
    }
}

#[cfg(test)]
mod tests {
    use super::reordvct;

    #[test]
    fn sorts_decreasing_and_carries_the_indices() {
        let mut y = [3, 9, -1, 9, 4];
        let mut idx = [0, 1, 2, 3, 4];
        reordvct(&mut y, 5, &mut idx);
        assert_eq!(y, [9, 9, 4, 3, -1]);
        assert_eq!(idx, [1, 3, 4, 0, 2]);
    }

    #[test]
    fn a_single_or_empty_vector_is_left_alone() {
        let mut y = [5];
        let mut idx = [7];
        reordvct(&mut y, 1, &mut idx);
        reordvct(&mut y, 0, &mut idx);
        assert_eq!((y, idx), ([5], [7]));
    }
}
