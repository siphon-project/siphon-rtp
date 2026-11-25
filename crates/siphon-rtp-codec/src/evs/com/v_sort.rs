//! In-place insertion sort of a 16-bit vector (TS 26.442 `lib_com/lsf_tools_fx.c`, `v_sort`).

use crate::itu::basic_ops::sub;

/// `v_sort`: sort `r[lo..=up]` ascending in place. Fast on almost ordered vectors; the reference
/// uses it to order the LSFs of a channel-aware partial copy.
pub fn v_sort(r: &mut [i16], lo: i16, up: i16) {
    let mut i = sub(up, 1);
    while i >= lo {
        let tempr = r[i as usize];
        let mut j = i;
        while j < up {
            if sub(tempr, r[(j + 1) as usize]) <= 0 {
                break;
            }
            r[j as usize] = r[(j + 1) as usize];
            j += 1;
        }
        r[j as usize] = tempr;
        i -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_the_range_and_leaves_the_rest() {
        let mut values = [9, 5, 3, 8, 1, 7, 2, 0];
        v_sort(&mut values, 1, 5);
        assert_eq!(values, [9, 1, 3, 5, 7, 8, 2, 0]);
    }

    #[test]
    fn keeps_a_sorted_vector_and_sorts_a_reversed_one() {
        let mut sorted = [1, 2, 3, 4];
        v_sort(&mut sorted, 0, 3);
        assert_eq!(sorted, [1, 2, 3, 4]);
        let mut reversed = [4, 3, 2, 1];
        v_sort(&mut reversed, 0, 3);
        assert_eq!(reversed, [1, 2, 3, 4]);
    }

    #[test]
    fn an_empty_range_changes_nothing() {
        let mut values = [3, 1, 2];
        v_sort(&mut values, 1, 1);
        assert_eq!(values, [3, 1, 2]);
    }
}
