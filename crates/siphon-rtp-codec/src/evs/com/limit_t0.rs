//! Closed-loop pitch search limits (TS 26.442 `lib_com/limit_t0_fx.c`; TS 26.445 §6.1.1.3.1).

use crate::evs::cnst::{
    L_FRAME, L_INTERPOL, PIT16K_MAX, PIT16K_MIN, PIT16K_MIN_EXTEND, PIT_MAX, PIT_MIN,
    PIT_MIN_DOUBLEEXTEND, PIT_MIN_EXTEND,
};
use crate::itu::basic_ops::{add, shl, sub};

/// Delta interval to extend pitch coding in relative Q (`LIMIT_PIT_REL_LOWER`).
const LIMIT_PIT_REL_LOWER: i16 = 2;
/// `LIMIT_PIT_REL_UPPER`.
const LIMIT_PIT_REL_UPPER: i16 = 0;

/// `limit_T0_fx`: the `[T0_min, T0_max]` interval of `2·delta` lags the closed-loop search (and
/// the decoder's relative pitch decoding) works in, centred on `t0` + `t0_frac`. Returns
/// `(T0_min, T0_max)`.
#[must_use]
pub fn limit_t0(
    l_frame: i16,
    delta: i16,
    pit_flag: i16,
    limit_flag: i16,
    t0: i16,
    t0_frac: i16,
) -> (i16, i16) {
    let mut t0_min;
    let mut t0_max;
    if limit_flag == 0 {
        // restrained Q limits
        let (pit_max, pit_min) = if l_frame == L_FRAME {
            (PIT_MAX, PIT_MIN)
        } else {
            (PIT16K_MAX, PIT16K_MIN)
        };
        let delta2 = sub(shl(delta, 1), 1);
        let mut t1 = t0;
        if sub(t0_frac, 2) >= 0 {
            t1 = add(t1, 1);
        }
        t0_min = sub(t1, delta).max(pit_min);
        t0_max = add(t0_min, delta2);
        if sub(t0_max, pit_max) > 0 {
            t0_max = pit_max;
            t0_min = sub(t0_max, delta2);
        }
    } else {
        // extended Q limits
        let (pit_max, pit_min) = if l_frame == L_FRAME {
            let pit_min = if limit_flag == 2 {
                PIT_MIN_DOUBLEEXTEND
            } else {
                PIT_MIN_EXTEND
            };
            (PIT_MAX, pit_min)
        } else {
            (PIT16K_MAX, PIT16K_MIN_EXTEND)
        };
        let delta2 = sub(shl(delta, 1), 1);
        let mut t1 = t0;
        if sub(t0_frac, 2) >= 0 {
            t1 = add(t1, 1);
        }
        t0_min = sub(t1, delta);
        if pit_flag == 0 {
            // subframes with absolute search: keep Q range
            t0_min = t0_min.max(pit_min);
            t0_max = add(t0_min, delta2);
            if sub(t0_max, pit_max) > 0 {
                t0_max = pit_max;
                t0_min = sub(t0_max, delta2);
            }
        } else {
            // subframes with relative search: extend Q range
            t0_min = t0_min.max(sub(pit_min, LIMIT_PIT_REL_LOWER));
            t0_min = t0_min.max(L_INTERPOL);
            // The reference adds with a plain C `+` here; the operands are small lags.
            t0_max = t0_min.wrapping_add(delta2);
            if sub(t0_max, add(pit_max, LIMIT_PIT_REL_UPPER)) > 0 {
                t0_max = add(pit_max, LIMIT_PIT_REL_UPPER);
                t0_min = sub(t0_max, delta2);
            }
        }
    }
    (t0_min, t0_max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_is_clamped_to_the_pitch_range() {
        assert_eq!(limit_t0(L_FRAME, 8, 0, 0, 30, 0), (PIT_MIN, PIT_MIN + 15));
        assert_eq!(limit_t0(L_FRAME, 8, 0, 0, 231, 3), (PIT_MAX - 15, PIT_MAX));
    }
}
