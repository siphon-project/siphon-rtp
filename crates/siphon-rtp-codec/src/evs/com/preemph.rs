//! Pre-emphasis `1 - mu·z^-1` (TS 26.442 `lib_com/preemph_fx.c`).

use crate::itu::basic_ops::{
    add, extract_h, l_abs, l_deposit_h, l_msu, l_mult, l_shl, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_msu0, msu_r};

/// `Q_MAX`: the highest scaling `E_UTIL_f_preemph3` applies.
const Q_MAX: i16 = 12;

/// `preemph_copy_fx` with the reference's in-place call (`x` and `y` the same buffer, as every
/// decoder call site has it): pre-emphasise `signal[0..lg]` by `mu` (Q15), the sample before the
/// frame in `mem`, and leave the frame's last *input* sample in `mem`. The loop runs backwards, so
/// in-place is exact.
pub fn preemph_copy_in_place(signal: &mut [i16], mu: i16, lg: i16, mem: &mut i16) {
    let lg = lg.max(0) as usize;
    if lg == 0 {
        // The reference would read signal[-1]; no caller passes an empty frame.
        return;
    }
    let temp = signal[lg - 1];
    for i in (1..lg).rev() {
        signal[i] = msu_r(l_deposit_h(signal[i]), signal[i - 1], mu);
    }
    signal[0] = msu_r(l_deposit_h(signal[0]), *mem, mu);
    *mem = temp;
}

/// `preemph_copy_fx`: pre-emphasise `x[0..lg]` into `y[0..lg]`; see [`preemph_copy_in_place`].
pub fn preemph_copy(x: &[i16], y: &mut [i16], mu: i16, lg: i16, mem: &mut i16) {
    let n = lg.max(0) as usize;
    y[..n].copy_from_slice(&x[..n]);
    preemph_copy_in_place(y, mu, lg, mem);
}

/// `E_UTIL_f_preemph2`: in-place pre-emphasis `1 - mu·z^-1` of `signal[0..lg]`, the output scaled
/// up by `shift`; `mem` holds the sample before the frame and is left with the last input sample.
pub fn e_util_f_preemph2(shift: i16, signal: &mut [i16], mu: i16, lg: i16, mem: &mut i16) {
    let lg = lg.max(0) as usize;
    if lg == 0 {
        // The reference would read signal[-1]; no caller passes an empty frame.
        return;
    }
    let temp = signal[lg - 1];
    for i in (1..lg).rev() {
        let mut l_tmp = l_mult(signal[i], 16384);
        l_tmp = l_msu0(l_tmp, signal[i - 1], mu);
        l_tmp = l_shl(l_tmp, add(shift, 1));
        signal[i] = round_word(l_tmp);
    }
    let mut l_tmp = l_mult(signal[0], 16384);
    l_tmp = l_msu0(l_tmp, *mem, mu);
    l_tmp = l_shl(l_tmp, add(shift, 1));
    signal[0] = round_word(l_tmp);
    *mem = temp;
}

/// `E_UTIL_f_preemph3`: in-place pre-emphasis of `signal[0..lg]` with `bits` of headroom, scaled
/// up by the largest shift (at most `Q_MAX`) the filtered frame allows; returns that shift.
pub fn e_util_f_preemph3(signal: &mut [i16], mu: i16, lg: i16, mem: &mut i16, bits: i16) -> i16 {
    let lg = lg.max(0) as usize;
    if lg == 0 {
        // The reference would read signal[-1]; no caller passes an empty frame.
        return Q_MAX;
    }
    let q_val = shl(1, sub(15, bits));
    let mus = shr(mu, bits);

    let mut l_tmp = l_mult(signal[0], q_val);
    l_tmp = l_msu(l_tmp, *mem, mus);
    let mut l_maxloc = l_abs(l_tmp);
    for i in 1..lg {
        l_tmp = l_mult(signal[i], q_val);
        l_tmp = l_msu(l_tmp, signal[i - 1], mus);
        l_tmp = l_abs(l_tmp);
        l_maxloc = l_tmp.max(l_maxloc);
    }

    let tmp_fixed = extract_h(l_maxloc);
    let mut q_new = Q_MAX;
    if tmp_fixed != 0 {
        q_new = sub(norm_s(tmp_fixed), bits);
        q_new = q_new.clamp(0, Q_MAX);
    }

    let tmp_fixed = signal[lg - 1];
    for i in (1..lg).rev() {
        l_tmp = l_mult(signal[i], q_val);
        l_tmp = l_msu(l_tmp, signal[i - 1], mus);
        l_tmp = l_shl(l_tmp, q_new);
        signal[i] = round_word(l_tmp);
    }
    l_tmp = l_mult(signal[0], q_val);
    l_tmp = l_msu(l_tmp, *mem, mus);
    l_tmp = l_shl(l_tmp, q_new);
    signal[0] = round_word(l_tmp);
    *mem = tmp_fixed;
    q_new
}
