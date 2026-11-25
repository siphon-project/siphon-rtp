//! Closed-loop pitch search limits (TS 26.442 `lib_com/limit_t0_fx.c`; TS 26.445 §6.1.1.3.1).

use crate::evs::cnst::{
    L_FRAME, L_INTERPOL, PIT16K_MAX, PIT16K_MIN, PIT16K_MIN_EXTEND, PIT_MAX, PIT_MIN,
    PIT_MIN_DOUBLEEXTEND, PIT_MIN_EXTEND,
};
use crate::evs::rom::INVINTTABLE;
use crate::itu::basic_ops::{add, mult, shl, shr, sub};
use crate::itu::stl2009::i_mult;

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

/// `inv_T0_res[res]` (`InvIntTable`): `1/res` in Q15. `res` is a pitch resolution (at most 6); one
/// past the table (a corrupted frame) reads as 0.
fn inv_t0_res(res: i16) -> i16 {
    usize::try_from(res)
        .ok()
        .and_then(|index| INVINTTABLE.get(index))
        .copied()
        .unwrap_or(0)
}

/// The lag limits `limit_T0_voiced` writes, as `(T0_min, T0_min_frac, T0_max, T0_max_frac)`.
pub type VoicedLimits = (i16, i16, i16, i16);

/// `limit_T0_voiced`: the closed-loop search interval of `2^nbits` lag steps of resolution `res`
/// (2..=6) centred on `t0` + `t0_frac`/`t0_res`, clamped to `[pit_min, pit_max]`; returns
/// `(T0_min, T0_min_frac, T0_max, T0_max_frac)`.
#[must_use]
pub fn limit_t0_voiced(
    nbits: i16,
    res: i16,
    t0: i16,
    t0_frac: i16,
    t0_res: i16,
    pit_min: i16,
    pit_max: i16,
) -> VoicedLimits {
    let mut res2 = res;
    if sub(res, 6) == 0 {
        res2 = shr(res2, 1);
    }

    // Mid-point
    let mut t1 = t0;
    if sub(t0_res, 1) > 0 && sub(t0_frac, shr(t0_res, 1)) >= 0 {
        t1 = add(t1, 1);
    }

    // Lower-bound
    let mut temp1 = sub(i_mult(t1, res), shl(1, sub(nbits, 1)));

    let mut temp2 = mult(temp1, inv_t0_res(res2));
    if sub(res, 6) == 0 {
        temp2 = shr(temp2, 1);
    }

    let mut t0_min = temp2;
    let mut t0_min_frac = sub(temp1, i_mult(temp2, res));

    if sub(t0_min, pit_min) < 0 {
        t0_min = pit_min;
        t0_min_frac = 0;
    }

    // Higher-bound
    temp1 = add(i_mult(t0_min, res), add(t0_min_frac, sub(shl(1, nbits), 1)));

    temp2 = mult(temp1, inv_t0_res(res2));
    if sub(res, 6) == 0 {
        temp2 = shr(temp2, 1);
    }

    let mut t0_max = temp2;
    let mut t0_max_frac = sub(temp1, i_mult(temp2, res));

    if sub(t0_max, pit_max) > 0 {
        t0_max = pit_max;
        t0_max_frac = sub(res, 1);

        temp1 = add(i_mult(t0_max, res), sub(t0_max_frac, sub(shl(1, nbits), 1)));

        temp2 = mult(temp1, inv_t0_res(res2));
        if sub(res, 6) == 0 {
            temp2 = shr(temp2, 1);
        }
        t0_min = temp2;

        t0_min_frac = sub(temp1, i_mult(temp2, res));
    }

    (t0_min, t0_min_frac, t0_max, t0_max_frac)
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
