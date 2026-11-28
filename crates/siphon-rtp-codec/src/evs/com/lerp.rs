//! Linear-interpolation resampling of a short buffer (TS 26.442 `lib_com/lerp.c`): stretches or
//! shrinks `bufferOldSize` samples to `bufferNewSize`, used whenever the internal sample rate changes
//! and a filter memory, an overlap or an excitation history has to follow it.
//!
//! The reference takes two pointers that its callers often aim into the same array (in place, or
//! at two offsets of one memory, `mem + L - old` to `mem + L - new`). `lerp_proc` detects any
//! overlap and then computes into a local buffer before copying out; without overlap it writes
//! straight through. Either way the result is a function of the input as it was on entry, which is
//! what the Rust entry points implement: [`lerp`] for two buffers, [`lerp_within`] for two offsets
//! of one buffer, [`lerp_in_place`] for the same position.

use crate::evs::cnst::L_FRAME_MAX;
use crate::evs::com::basop_util::basop_util_divide_mant_exp;
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mult, l_shl, l_shr, l_sub,
    shl, shr, sub,
};
use crate::itu::stl2009::{lshr, msu_r};

/// `shift_e` / `pos_e`: the exponent of the interpolation position and step (Q16 in a Word32).
const SHIFT_E: i16 = 16 - 1;
/// `buf[2*L_FRAME_MAX]`, the overlap scratch of `lerp_proc`.
const LERP_BUFFER: usize = 2 * L_FRAME_MAX as usize;
/// 3.9609375 in Q12: the largest ratio one `lerp_proc` pass handles.
const MAX_RATIO_Q12: i16 = 16224;

/// `new / old` in Q12, as `lerp` derives it.
fn ratio_q12(new: i16, old: i16) -> i16 {
    let (mut tmp, mut tmpexp) = (0, 0);
    basop_util_divide_mant_exp(new, 0, old, 0, &mut tmp, &mut tmpexp);
    tmp = shr(tmp, 3); // Q12
    shl(tmp, tmpexp)
}

/// One linear-interpolation pass of `f[..old]` (plus the one sample past it the last step may
/// touch) to `buffer_new_size` samples into `out`.
fn lerp_proc(f: &[i16], out: &mut [i16], buffer_new_size: i16, buffer_old_size: i16) {
    if sub(buffer_new_size, buffer_old_size) == 0 {
        let n = buffer_new_size.max(0) as usize;
        out[..n].copy_from_slice(&f[..n]);
        return;
    }

    let shift = l_shl(
        l_deposit_l(div_s(buffer_old_size, shl(buffer_new_size, 4))),
        4 - SHIFT_E + 16,
    );

    let mut pos = l_sub(l_shr(shift, 1), 32768); // 1.0f Q15

    // Adjust interpolation shift to avoid accessing beyond end of input buffer.
    if l_sub(shift, 19661) < 0 {
        // 0.3f Q16
        pos = l_sub(pos, 8520); // 0.13f Q16
    }

    // A point between f[idx] and f[idx + 1] at fraction diff (Q15).
    let point = |idx: i16, diff: i16| -> i16 {
        let idx = idx as usize;
        add(f[idx], msu_r(l_mult(diff, f[idx + 1]), diff, f[idx]))
    };

    // first point of interpolation
    let mut ptr = 0usize;
    if pos < 0 {
        let diff = shr(extract_l(pos), 1);
        // buf[0]=f[0]+pos*(f[1]-f[0]);
        out[ptr] = point(0, diff);
    } else {
        let idx = extract_h(pos);
        let diff = lshr(extract_l(pos), 1);
        out[ptr] = point(idx, diff);
    }
    ptr += 1;

    pos = l_add(pos, shift);
    let mut idx = extract_h(pos).max(0);

    let n = sub(buffer_new_size, 1);
    for _ in 1..n {
        let mut diff = lshr(extract_l(pos), 1);
        if pos < 0 {
            diff = sub(16384, diff); // 0.5f Q15
        }
        out[ptr] = point(idx, diff);
        ptr += 1;

        pos = l_add(pos, shift);
        idx = extract_h(pos);
    }

    // last point
    if l_sub(pos, l_deposit_h(sub(buffer_old_size, 1))) > 0 {
        idx = sub(buffer_old_size, 2);
    }

    // diff = t - point;
    let diff = lshr(extract_l(l_shr(l_sub(pos, l_deposit_h(idx)), 1)), 1);
    let at = idx as usize;
    out[ptr] = add(f[at], shl(msu_r(l_mult(diff, f[at + 1]), diff, f[at]), 1));
}

/// `lerp_proc` with the input and the output both in `x`, at `f_at` and `out_at`: computed into
/// the reference's scratch and copied out, as its overlap path does.
fn lerp_proc_within(x: &mut [i16], f_at: usize, out_at: usize, new: i16, old: i16) {
    let n = new.max(0) as usize;
    // The reference's scratch is 2 * L_FRAME_MAX; a longer output would overrun it.
    if n > LERP_BUFFER {
        return;
    }
    let mut buf = [0i16; LERP_BUFFER];
    lerp_proc(&x[f_at..], &mut buf, new, old);
    x[out_at..out_at + n].copy_from_slice(&buf[..n]);
}

/// The ratio staging of `lerp`: a ratio above 3.96 runs as successive doublings (or halvings) of
/// the output, every pass after the first in place on the output. `first` runs the first pass.
fn lerp_staged(
    x_out: &mut [i16],
    out_at: usize,
    buffer_new_size: i16,
    mut buffer_old_size: i16,
    mut first: impl FnMut(&mut [i16], i16, i16),
) {
    let tmp1 = ratio_q12(buffer_new_size, buffer_old_size);
    let tmp2 = ratio_q12(buffer_old_size, buffer_new_size);

    let mut first_pass = true;
    let mut pass = |x_out: &mut [i16], new: i16, old: i16| {
        if first_pass {
            first_pass = false;
            first(x_out, new, old);
        } else {
            lerp_proc_within(x_out, out_at, out_at, new, old);
        }
    };

    if sub(tmp1, MAX_RATIO_Q12) > 0 {
        let mut tmp_new_size = shl(buffer_old_size, 1);
        while sub(buffer_new_size, buffer_old_size) > 0 {
            if sub(ratio_q12(buffer_new_size, buffer_old_size), MAX_RATIO_Q12) <= 0 {
                tmp_new_size = buffer_new_size;
            }
            pass(x_out, tmp_new_size, buffer_old_size);
            buffer_old_size = tmp_new_size;
            tmp_new_size = shl(tmp_new_size, 1);
        }
    } else if sub(tmp2, MAX_RATIO_Q12) > 0 {
        let mut tmp_new_size = shr(buffer_old_size, 1);
        while sub(buffer_new_size, buffer_old_size) < 0 {
            if sub(ratio_q12(buffer_old_size, buffer_new_size), MAX_RATIO_Q12) <= 0 {
                tmp_new_size = buffer_new_size;
            }
            pass(x_out, tmp_new_size, buffer_old_size);
            buffer_old_size = tmp_new_size;
            tmp_new_size = shr(tmp_new_size, 1);
        }
    } else {
        pass(x_out, buffer_new_size, buffer_old_size);
    }
}

/// `lerp`: resample `f[..buffer_old_size]` to `buffer_new_size` samples in `f_out`, the two
/// buffers distinct. `f` may be read one sample past `buffer_old_size`, as in the reference. A
/// reduction by more than 3.96 runs in halving stages through `f_out`, so `f_out` must then hold
/// the first stage, `buffer_old_size / 2` samples (the reference writes that far too).
pub fn lerp(f: &[i16], f_out: &mut [i16], buffer_new_size: i16, buffer_old_size: i16) {
    lerp_staged(
        f_out,
        0,
        buffer_new_size,
        buffer_old_size,
        |out, new, old| lerp_proc(f, out, new, old),
    );
}

/// `lerp(&x[f_at], &x[out_at], new, old)`: input and output at two offsets of one buffer, as the
/// callers that move a filter memory's tail (`mem + L - old` to `mem + L - new`) use it.
pub fn lerp_within(
    x: &mut [i16],
    f_at: usize,
    out_at: usize,
    buffer_new_size: i16,
    buffer_old_size: i16,
) {
    lerp_staged(
        x,
        out_at,
        buffer_new_size,
        buffer_old_size,
        |x, new, old| lerp_proc_within(x, f_at, out_at, new, old),
    );
}

/// `lerp(x, x, new, old)`.
pub fn lerp_in_place(x: &mut [i16], buffer_new_size: i16, buffer_old_size: i16) {
    lerp_within(x, 0, 0, buffer_new_size, buffer_old_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_sizes_copy() {
        let f = [1i16, 2, 3, 4];
        let mut out = [0i16; 4];
        lerp(&f, &mut out, 4, 4);
        assert_eq!(out, f);
    }

    #[test]
    fn in_place_matches_two_buffers() {
        let f: Vec<i16> = (0..400).map(|i| (i * 37 % 1000 - 500) as i16).collect();
        let mut out = vec![0i16; 960];
        lerp(&f, &mut out, 960, 256);
        let mut x = f.clone();
        x.resize(960, 0);
        lerp_in_place(&mut x, 960, 256);
        assert_eq!(out, x);
    }
}
