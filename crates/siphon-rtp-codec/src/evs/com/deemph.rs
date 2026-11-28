//! De-emphasis `1 / (1 - mu·z^-1)` (TS 26.442 `lib_com/deemph_fx.c`).

use crate::evs::basop::mpy_32_16_1;
use crate::itu::basic_ops::{l_deposit_h, l_mac, l_msu, round_word, shr};

/// `deemph_fx`: de-emphasise `signal[0..l]` in place with factor `mu` (Q15), the previous output
/// in `mem` and the last output written back to it.
pub fn deemph(signal: &mut [i16], mu: i16, l: i16, mem: &mut i16) {
    let l = l.max(0) as usize;
    if l == 0 {
        // The reference would store signal[-1]; no caller passes an empty frame.
        return;
    }
    let mut l_tmp = l_mac(l_deposit_h(signal[0]), *mem, mu);
    signal[0] = round_word(l_tmp);
    for i in 1..l {
        l_tmp = l_mac(l_deposit_h(signal[i]), signal[i - 1], mu);
        signal[i] = round_word(l_tmp);
    }
    *mem = signal[l - 1];
}

/// `E_UTIL_deemph2`: de-emphasise `x[0..l]` in place through `1 / (1 - mu·z^-1)`, the input first
/// scaled by `2^-shift` and halved, the previous output in `mem` and the last output written
/// back to it.
pub fn e_util_deemph2(shift: i16, x: &mut [i16], mu: i16, l: i16, mem: &mut i16) {
    let l = l.max(0) as usize;
    if l == 0 {
        // The reference would store x[-1]; no caller passes an empty frame.
        return;
    }
    // signal[0] = signal[0] + mu * (*mem)
    let mut l_tmp = l_deposit_h(*mem);
    if shift >= 0 {
        let shift = shr(-32768, shift);
        for value in &mut x[..l] {
            l_tmp = l_msu(mpy_32_16_1(l_tmp, mu), *value, shift);
            *value = round_word(l_tmp);
        }
    } else {
        for value in &mut x[..l] {
            l_tmp = l_msu(mpy_32_16_1(l_tmp, mu), shr(*value, shift), -32768);
            *value = round_word(l_tmp);
        }
    }
    *mem = x[l - 1];
}
