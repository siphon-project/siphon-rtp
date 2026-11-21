//! LP synthesis filtering `1/A(z)` (TS 26.442 `lib_com/syn_filt_fx.c`; TS 26.445 §6.1.1.3).
//!
//! The reference unrolls the filter tap loop into `syn_kern_2 / 4 / 6 / 8 / 10 / 16 / 24`, each a
//! chain of `L_msu(acc, y[-k], a[k])` for `k = 1..=N` in increasing `k`. Saturation makes the order
//! of those accumulations part of the result, and the unrolled kernels all keep the plain
//! increasing order, so one loop ([`syn_kern`]) reproduces every one of them; the named kernels
//! are kept for traceability.
//!
//! The C reaches the filter history through negative indices (`y[-j]`, `mem[i - j]`), so the
//! kernels take the whole buffer plus the index the C pointer points at (`y_at`).

use crate::evs::cnst::{DEC, L_EXC_MEM, L_EXC_MEM_DEC, L_SYN_MEM, M};
use crate::evs::com::lerp::lerp_within;
use crate::itu::basic_ops::{add, l_msu, l_mult, l_shl, norm_s, round_word, shr, sub};

/// `L_tmp - sum_{k=1..=order} y[y_at - k] · a[k]`, accumulated with `L_msu` in increasing `k` (the
/// shape every `syn_kern_N` of the reference has).
#[inline]
#[must_use]
pub fn syn_kern(l_tmp: i32, a: &[i16], y: &[i16], y_at: usize, order: usize) -> i32 {
    let mut l_tmp = l_tmp;
    for k in 1..=order {
        l_tmp = l_msu(l_tmp, y[y_at - k], a[k]);
    }
    l_tmp
}

/// `syn_kern_2`.
#[inline]
#[must_use]
pub fn syn_kern_2(l_tmp: i32, a: &[i16], y: &[i16], y_at: usize) -> i32 {
    syn_kern(l_tmp, a, y, y_at, 2)
}

/// `syn_kern_4`.
#[inline]
#[must_use]
pub fn syn_kern_4(l_tmp: i32, a: &[i16], y: &[i16], y_at: usize) -> i32 {
    syn_kern(l_tmp, a, y, y_at, 4)
}

/// `syn_kern_8`.
#[inline]
#[must_use]
pub fn syn_kern_8(l_tmp: i32, a: &[i16], y: &[i16], y_at: usize) -> i32 {
    syn_kern(l_tmp, a, y, y_at, 8)
}

/// `syn_kern_16`.
#[inline]
#[must_use]
pub fn syn_kern_16(l_tmp: i32, a: &[i16], y: &[i16], y_at: usize) -> i32 {
    syn_kern(l_tmp, a, y, y_at, 16)
}

/// One output sample of `syn_filt_s_lc_fx`: order 16 from a zero state, so sample `i` only sees
/// the `min(i, 16)` outputs before it.
#[inline]
fn syn_filt_s_lc_sample(a: &[i16], l_tmp: i32, y: &[i16], i: usize) -> i32 {
    if i < 16 {
        let mut l_tmp = l_tmp;
        for j in 1..=i {
            l_tmp = l_msu(l_tmp, y[i - j], a[j]);
        }
        l_tmp
    } else {
        syn_kern_16(l_tmp, a, y, i)
    }
}

/// `syn_filt_s_lc_fx`: order-16 synthesis from a zero filter state over `lg` samples. `shift` is
/// the Q difference between `x` and `y`; `a` is Q12 with any normalisation of `a[0]`.
pub fn syn_filt_s_lc(shift: i16, a: &[i16], x: &[i16], y: &mut [i16], lg: i16) {
    let q = add(norm_s(a[0]), 1);
    let a0 = shr(a[0], shift);
    for i in 0..lg.max(0) as usize {
        let l_tmp = syn_filt_s_lc_sample(a, l_mult(x[i], a0), y, i);
        y[i] = round_word(l_shl(l_tmp, q));
    }
}

/// [`syn_filt_s_lc`] with the reference's in-place call (`syn_filt_s_lc_fx(.., code, code, ..)` in
/// `cb_shape_fx.c`): sample `i` reads `x[i]` before writing it and only earlier outputs after.
pub fn syn_filt_s_lc_in_place(shift: i16, a: &[i16], xy: &mut [i16], lg: i16) {
    let q = add(norm_s(a[0]), 1);
    let a0 = shr(a[0], shift);
    for i in 0..lg.max(0) as usize {
        let l_tmp = syn_filt_s_lc_sample(a, l_mult(xy[i], a0), xy, i);
        xy[i] = round_word(l_shl(l_tmp, q));
    }
}

/// One output sample of [`e_util_synthesis`]: the first `min(i, m)` taps from the outputs already
/// written to `y`, the rest from the filter memory (`mem[m + i - j]` in the reference, whose `mem`
/// pointer is advanced by `m`).
#[inline]
fn synthesis_sample(a: &[i16], m: usize, l_tmp: i32, y: &[i16], i: usize, mem: &[i16]) -> i32 {
    let mut l_tmp = l_tmp;
    let from_output = i.min(m);
    for j in 1..=from_output {
        l_tmp = l_msu(l_tmp, a[j], y[i - j]);
    }
    for j in from_output + 1..=m {
        l_tmp = l_msu(l_tmp, a[j], mem[m + i - j]);
    }
    l_tmp
}

/// `E_UTIL_synthesis`: order-`m` LP synthesis of `lg` samples of `x` into `y`, starting from the
/// filter state `mem[0..m]` (oldest first); `update != 0` writes the last `m` outputs back to
/// `mem`. `shift` is the Q difference between excitation and output.
///
/// The reference asserts `m` is 6, 10, 16 or 24 (the orders it has unrolled kernels for); the loop
/// here computes any order identically.
pub fn e_util_synthesis(
    shift: i16,
    a: &[i16],
    x: &[i16],
    y: &mut [i16],
    lg: i16,
    mem: &mut [i16],
    update: i16,
    m: i16,
) {
    let order = m.max(0) as usize;
    let lg = lg.max(0) as usize;
    let q = add(norm_s(a[0]), 1);
    let a0 = shr(a[0], shift);
    for i in 0..lg {
        let l_tmp = synthesis_sample(a, order, l_mult(a0, x[i]), y, i, mem);
        y[i] = round_word(l_shl(l_tmp, q));
    }
    if update != 0 {
        mem[..order].copy_from_slice(&y[lg - order..lg]);
    }
}

/// [`e_util_synthesis`] with the reference's in-place call (`x` and `y` the same buffer, as in
/// `E_UTIL_synthesis(.., h1, h1, ..)`). In-place is safe in the reference: sample `i` reads
/// `x[i]` before writing `y[i]` and only earlier outputs after.
pub fn e_util_synthesis_in_place(
    shift: i16,
    a: &[i16],
    xy: &mut [i16],
    lg: i16,
    mem: &mut [i16],
    update: i16,
    m: i16,
) {
    let order = m.max(0) as usize;
    let lg = lg.max(0) as usize;
    let q = add(norm_s(a[0]), 1);
    let a0 = shr(a[0], shift);
    for i in 0..lg {
        let l_tmp = synthesis_sample(a, order, l_mult(a0, xy[i]), xy, i, mem);
        xy[i] = round_word(l_shl(l_tmp, q));
    }
    if update != 0 {
        mem[..order].copy_from_slice(&xy[lg - order..lg]);
    }
}

/// `Syn_filt_s`: [`e_util_synthesis`] with the reference's other argument order.
pub fn syn_filt_s(
    shift: i16,
    a: &[i16],
    m: i16,
    x: &[i16],
    y: &mut [i16],
    lg: i16,
    mem: &mut [i16],
    update: i16,
) {
    e_util_synthesis(shift, a, x, y, lg, mem, update, m);
}

/// `synth_mem_updt2`: resamples the excitation buffer `old_exc` and the LP synthesis memory
/// `mem_syn_r` (`L_SYN_MEM`) from the core frame length `last_l_frame` to `l_frame`, and copies
/// the tail of the latter into `mem_syn2` (and `mem_syn`, when given) as the order-`M` filter
/// memory. `dec` is `DEC` for the decoder's `L_EXC_MEM_DEC` excitation (1.5 frames), else the
/// encoder's `L_EXC_MEM` (one frame).
pub fn synth_mem_updt2(
    l_frame: i16,
    last_l_frame: i16,
    old_exc: &mut [i16],
    mem_syn_r: &mut [i16],
    mem_syn2: &mut [i16],
    mem_syn: Option<&mut [i16]>,
    dec: i16,
) {
    // Residual and update old_exc
    // (plain C int arithmetic on the offsets; the core frame lengths keep every offset inside
    // the buffer)
    if sub(dec, DEC) == 0 {
        let old = last_l_frame + last_l_frame / 2;
        let new = l_frame + l_frame / 2;
        lerp_within(
            old_exc,
            (L_EXC_MEM_DEC - old).max(0) as usize,
            (L_EXC_MEM_DEC - new).max(0) as usize,
            new,
            old,
        );
    } else {
        lerp_within(
            old_exc,
            (L_EXC_MEM - last_l_frame).max(0) as usize,
            (L_EXC_MEM - l_frame).max(0) as usize,
            l_frame,
            last_l_frame,
        );
    }

    // Resamp memory
    // Size of LPC syn memory
    // 1.25/20.0 = 1.0/16.0 -> shift 4 to the right.
    let mem_syn_r_size_old = shr(last_l_frame, 4);
    let mem_syn_r_size_new = shr(l_frame, 4);

    lerp_within(
        mem_syn_r,
        (L_SYN_MEM - mem_syn_r_size_old).max(0) as usize,
        (L_SYN_MEM - mem_syn_r_size_new).max(0) as usize,
        mem_syn_r_size_new,
        mem_syn_r_size_old,
    );

    let tail = (L_SYN_MEM - M) as usize;
    mem_syn2[..M as usize].copy_from_slice(&mem_syn_r[tail..tail + M as usize]);

    if let Some(mem_syn) = mem_syn {
        mem_syn[..M as usize].copy_from_slice(&mem_syn2[..M as usize]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_filter_with_zero_memory_passes_the_input_through() {
        // a = [4096, 0, ...] (1.0 in Q12): y = x, and the update stores the last m outputs.
        let mut a = [0_i16; 17];
        a[0] = 4096;
        let x: Vec<i16> = (0..64).map(|v| v * 100 - 3000).collect();
        let mut y = [0_i16; 64];
        let mut mem = [0_i16; 16];
        e_util_synthesis(0, &a, &x, &mut y, 64, &mut mem, 1, 16);
        assert_eq!(&y[..], &x[..]);
        assert_eq!(&mem[..], &x[48..]);
        let mut xy = x.clone();
        let mut mem2 = [0_i16; 16];
        e_util_synthesis_in_place(0, &a, &mut xy, 64, &mut mem2, 1, 16);
        assert_eq!(xy, x);
    }
}
