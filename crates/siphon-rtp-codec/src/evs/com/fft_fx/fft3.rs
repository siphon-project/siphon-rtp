//! `fft3_fx` / `ifft3_fx` (TS 26.442 `lib_com/fft_fx.c`): the radix-3 real FFT of the HQ phase
//! ECU, three decimated `r_fft_fx_lc` transforms joined by order-3 butterflies. Both are only
//! called in place (`fft3_fx(x, x, n)`); the reference copies the input into a local buffer
//! before writing the output, so the in-place form is the only one ported.

use crate::evs::com::fft_rel::r_fft_fx_lc_in_place;
use crate::evs::rom::{FFT_W256, FFT_W64, SINCOS_T_RAD3_FX};
use crate::itu::basic_ops::{l_deposit_l, l_mac, l_mult, l_shl, mult_r, round_word, shl, shr, sub};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, mac_r, msu_r};

/// `PH_ECU_SPEC_SIZE` (= `Lprot48k`).
const PH_ECU_SPEC_SIZE: usize = 1536;
/// `T_SIN_PI_2` = `PH_ECU_SPEC_SIZE/4`: the index of sin(pi/2) in `sincos_t_rad3_fx`.
const T_SIN_PI_2: i16 = 384;
/// `FFT3_ONE_THIRD`: 1/3 in Q16.
const FFT3_ONE_THIRD: i16 = 21845;

/// The transform order, decimated length and table step of a length; `None` for a length the
/// reference has no table for (it only ever passes 384 and 1536).
fn layout(n: i16) -> Option<(i16, i16, i16, &'static [i16])> {
    match n {
        1536 => Some((9 - 1, 512, 1, &FFT_W256)),
        384 => Some((7 - 1, 128, 4, &FFT_W64)),
        _ => None,
    }
}

#[inline]
fn t(index: i16) -> i16 {
    SINCOS_T_RAD3_FX[index as usize]
}

/// The four sine/cosine table walkers of the forward butterflies.
struct Walk {
    c1: i16,
    s1: i16,
    c2: i16,
    s2: i16,
}

/// The read/write positions of the forward butterflies (`RY`, `IY`, `RZk`, `IZk`).
struct Ptr {
    ry: usize,
    iy: usize,
    rz0: usize,
    iz0: usize,
    rz1: usize,
    iz1: usize,
    rz2: usize,
    iz2: usize,
}

/// `fft3_fx`: forward real FFT of length `n` (384 or 1536), in place; the result keeps the real
/// parts in `x[0..=n/2]` and the imaginary parts mirrored in `x[n/2+1..]`. Any other length leaves
/// `x` unchanged (the reference's default case has no valid tables for it).
pub fn fft3(x: &mut [i16], n: i16) {
    let Some((order_minus1, m, step, phase_tbl)) = layout(n) else {
        return;
    };
    let mut z = [0i16; PH_ECU_SPEC_SIZE];
    let mu = m as usize;
    let nu = n as usize;

    // Compose decimated sequences X[3i], X[3i+1],X[3i+2], compute their FFT of length m.
    for i in 0..mu {
        z[i] = x[3 * i];
        z[mu + i] = x[3 * i + 1];
        z[2 * mu + i] = x[3 * i + 2];
    }
    let m_by2 = shr(m, 1);
    for block in z.chunks_mut(mu).take(3) {
        r_fft_fx_lc_in_place(phase_tbl, m, m_by2, order_minus1, block, 1);
    }

    // Butterflies of order 3.
    let y = x;
    let mut p = Ptr {
        ry: 0,
        iy: nu - 1,
        rz0: 0,
        iz0: mu - 1,
        rz1: mu,
        iz1: 2 * mu - 1,
        rz2: 2 * mu,
        iz2: 3 * mu - 1,
    };
    let c1_step = -step;
    let s1_step = step;
    let c2_step = shl(c1_step, 1);
    let s2_step = shl(s1_step, 1);
    let mut w = Walk {
        c1: T_SIN_PI_2 + c1_step,
        s1: s1_step,
        c2: T_SIN_PI_2 + c2_step,
        s2: s2_step,
    };

    // special case: i = 0
    let mut acc = l_mult(z[p.rz0], 0x4000);
    acc = l_mac(acc, z[p.rz1], 0x4000);
    y[p.ry] = mac_r(acc, z[p.rz2], 0x4000);
    p.rz0 += 1;
    p.rz1 += 1;
    p.rz2 += 1;
    p.ry += 1;

    fft3_first_half(
        y,
        &z,
        &mut p,
        &mut w,
        n,
        m,
        (c1_step, s1_step, c2_step, s2_step),
    );
    fft3_second_half(
        y,
        &z,
        &mut p,
        &mut w,
        n,
        m,
        (c1_step, s1_step, c2_step, s2_step),
    );
}

/// `fft3_fx` from bin 1 to the 1/3 special case.
fn fft3_first_half(
    y: &mut [i16],
    z: &[i16],
    p: &mut Ptr,
    w: &mut Walk,
    n: i16,
    m: i16,
    (c1_step, s1_step, c2_step, s2_step): (i16, i16, i16, i16),
) {
    // first 3/12-- from 1 to (3*m/8)-1
    let l = sub(shr(n, 3), 1);
    for _ in 0..l {
        let mut acc = l_shl(i32::from(z[p.rz0]), 15);
        p.rz0 += 1;
        acc = l_mac0(acc, z[p.rz1], t(w.c1));
        acc = l_mac0(acc, z[p.iz1], t(w.s1));
        acc = l_mac0(acc, z[p.rz2], t(w.c2));
        acc = l_mac0(acc, z[p.iz2], t(w.s2));
        y[p.ry] = round_word(acc);
        p.ry += 1;

        acc = l_shl(i32::from(z[p.iz0]), 15);
        p.iz0 -= 1;
        acc = l_msu0(acc, z[p.rz1], t(w.s1));
        acc = l_mac0(acc, z[p.iz1], t(w.c1));
        acc = l_msu0(acc, z[p.rz2], t(w.s2));
        acc = l_mac0(acc, z[p.iz2], t(w.c2));
        p.rz1 += 1;
        p.iz1 -= 1;
        p.rz2 += 1;
        p.iz2 -= 1;
        y[p.iy] = round_word(acc);
        p.iy -= 1;

        w.c1 += c1_step;
        w.s1 += s1_step;
        w.c2 += c2_step;
        w.s2 += s2_step;
    }

    // next 1/12-- from (3*m/8) to (4*m/8)-1
    let l = shr(m, 3);
    for _ in 0..l {
        let mut acc = l_shl(i32::from(z[p.rz0]), 15);
        p.rz0 += 1;
        acc = l_mac0(acc, z[p.rz1], t(w.c1));
        acc = l_mac0(acc, z[p.iz1], t(w.s1));
        acc = l_msu0(acc, z[p.rz2], t(w.c2));
        acc = l_mac0(acc, z[p.iz2], t(w.s2));
        y[p.ry] = round_word(acc);
        p.ry += 1;

        acc = l_shl(i32::from(z[p.iz0]), 15);
        p.iz0 -= 1;
        acc = l_msu0(acc, z[p.rz1], t(w.s1));
        acc = l_mac0(acc, z[p.iz1], t(w.c1));
        acc = l_msu0(acc, z[p.rz2], t(w.s2));
        acc = l_msu0(acc, z[p.iz2], t(w.c2));
        p.rz1 += 1;
        p.iz1 -= 1;
        p.rz2 += 1;
        p.iz2 -= 1;
        y[p.iy] = round_word(acc);
        p.iy -= 1;

        w.c1 += c1_step;
        w.s1 += s1_step;
        w.c2 -= c2_step;
        w.s2 -= s2_step;
    }

    // special case: i = m/2 i.e. 1/3
    let mut acc = l_shl(i32::from(z[p.rz0]), 15);
    p.rz0 -= 1;
    acc = l_mac0(acc, z[p.rz1], t(w.c1));
    acc = l_msu0(acc, z[p.rz2], t(w.c2));
    y[p.ry] = round_word(acc);
    p.ry += 1;

    acc = 0;
    acc = l_msu0(acc, z[p.rz1], t(w.s1));
    acc = l_msu0(acc, z[p.rz2], t(w.s2));
    p.rz1 -= 1;
    p.rz2 -= 1;
    y[p.iy] = round_word(acc);
    p.iy -= 1;
    p.iz0 += 1;
    p.iz1 += 1;
    p.iz2 += 1;

    w.c1 += c1_step;
    w.s1 += s1_step;
    w.c2 -= c2_step;
    w.s2 -= s2_step;

    // next  2/12-- from ((m/2)+1) to (6*m/8)-1
    let l = sub(shr(m, 2), 1);
    for _ in 0..l {
        let mut acc = l_shl(i32::from(z[p.rz0]), 15);
        p.rz0 -= 1;
        acc = l_mac0(acc, z[p.rz1], t(w.c1));
        acc = l_msu0(acc, z[p.iz1], t(w.s1));
        acc = l_msu0(acc, z[p.rz2], t(w.c2));
        acc = l_msu0(acc, z[p.iz2], t(w.s2));
        y[p.ry] = round_word(acc);
        p.ry += 1;

        acc = l_mult0(z[p.iz0], -32768);
        p.iz0 += 1;
        acc = l_msu0(acc, z[p.rz1], t(w.s1));
        acc = l_msu0(acc, z[p.iz1], t(w.c1));
        acc = l_msu0(acc, z[p.rz2], t(w.s2));
        acc = l_mac0(acc, z[p.iz2], t(w.c2));
        p.rz1 -= 1;
        p.iz1 += 1;
        p.rz2 -= 1;
        p.iz2 += 1;
        y[p.iy] = round_word(acc);
        p.iy -= 1;

        w.c1 += c1_step;
        w.s1 += s1_step;
        w.c2 -= c2_step;
        w.s2 -= s2_step;
    }
}

/// `fft3_fx` from 6m/8 to the last bin.
fn fft3_second_half(
    y: &mut [i16],
    z: &[i16],
    p: &mut Ptr,
    w: &mut Walk,
    n: i16,
    m: i16,
    (c1_step, s1_step, c2_step, s2_step): (i16, i16, i16, i16),
) {
    // next 2/12-- from (6*m/8) to (8*m/8) - 1
    let l = shr(m, 2);
    for _ in 0..l {
        let mut acc = l_shl(i32::from(z[p.rz0]), 15);
        p.rz0 -= 1;
        acc = l_msu0(acc, z[p.rz1], t(w.c1));
        acc = l_msu0(acc, z[p.iz1], t(w.s1));
        acc = l_msu0(acc, z[p.rz2], t(w.c2));
        acc = l_mac0(acc, z[p.iz2], t(w.s2));
        y[p.ry] = round_word(acc);
        p.ry += 1;

        acc = l_mult0(z[p.iz0], -32768);
        p.iz0 += 1;
        acc = l_msu0(acc, z[p.rz1], t(w.s1));
        acc = l_mac0(acc, z[p.iz1], t(w.c1));
        acc = l_mac0(acc, z[p.rz2], t(w.s2));
        acc = l_mac0(acc, z[p.iz2], t(w.c2));
        p.rz1 -= 1;
        p.iz1 += 1;
        p.rz2 -= 1;
        p.iz2 += 1;
        y[p.iy] = round_word(acc);
        p.iy -= 1;

        w.c1 -= c1_step;
        w.s1 -= s1_step;
        w.c2 += c2_step;
        w.s2 += s2_step;
    }

    // special case: i = m, i.e 2/3
    let mut acc = l_shl(i32::from(z[p.rz0]), 15);
    p.rz0 += 1;
    acc = l_msu0(acc, z[p.rz1], t(w.c1));
    acc = l_msu0(acc, z[p.rz2], t(w.c2));
    y[p.ry] = round_word(acc);
    p.ry += 1;

    acc = l_deposit_l(0);
    acc = l_msu0(acc, z[p.rz1], t(w.s1));
    acc = l_mac0(acc, z[p.rz2], t(w.s2));
    p.rz1 += 1;
    p.rz2 += 1;
    y[p.iy] = round_word(acc);
    p.iy -= 1;
    p.iz0 -= 1; // Just decrement the address counter
    p.iz1 -= 1;
    p.iz2 -= 1;

    w.c1 -= c1_step;
    w.s1 -= s1_step;
    w.c2 += c2_step;
    w.s2 += s2_step;

    // next 1/12-- from (m + 1) to (9*m/8) - 1
    let l = sub(shr(m, 3), 1);
    for _ in 0..l {
        let mut acc = l_shl(i32::from(z[p.rz0]), 15);
        p.rz0 += 1;
        acc = l_msu0(acc, z[p.rz1], t(w.c1));
        acc = l_mac0(acc, z[p.iz1], t(w.s1));
        acc = l_msu0(acc, z[p.rz2], t(w.c2));
        acc = l_msu0(acc, z[p.iz2], t(w.s2));
        y[p.ry] = round_word(acc);
        p.ry += 1;

        acc = l_shl(i32::from(z[p.iz0]), 15);
        p.iz0 -= 1;
        acc = l_msu0(acc, z[p.rz1], t(w.s1));
        acc = l_msu0(acc, z[p.iz1], t(w.c1));
        acc = l_mac0(acc, z[p.rz2], t(w.s2));
        acc = l_msu0(acc, z[p.iz2], t(w.c2));
        p.rz1 += 1;
        p.iz1 -= 1;
        p.rz2 += 1;
        p.iz2 -= 1;
        y[p.iy] = round_word(acc);
        p.iy -= 1;

        w.c1 -= c1_step;
        w.s1 -= s1_step;
        w.c2 += c2_step;
        w.s2 += s2_step;
    }

    // last 3/12-- from (9*m/8) to (12*m/8) - 1
    let l = shr(n, 3);
    for _ in 0..l {
        let mut acc = l_shl(i32::from(z[p.rz0]), 15);
        p.rz0 += 1;
        acc = l_msu0(acc, z[p.rz1], t(w.c1));
        acc = l_mac0(acc, z[p.iz1], t(w.s1));
        acc = l_mac0(acc, z[p.rz2], t(w.c2));
        acc = l_msu0(acc, z[p.iz2], t(w.s2));
        y[p.ry] = round_word(acc);
        p.ry += 1;

        acc = l_shl(i32::from(z[p.iz0]), 15);
        p.iz0 -= 1;
        acc = l_msu0(acc, z[p.rz1], t(w.s1));
        acc = l_msu0(acc, z[p.iz1], t(w.c1));
        acc = l_mac0(acc, z[p.rz2], t(w.s2));
        acc = l_mac0(acc, z[p.iz2], t(w.c2));
        p.rz1 += 1;
        p.iz1 -= 1;
        p.rz2 += 1;
        p.iz2 -= 1;
        y[p.iy] = round_word(acc);
        p.iy = p.iy.wrapping_sub(1);

        w.c1 -= c1_step;
        w.s1 -= s1_step;
        w.c2 -= c2_step;
        w.s2 -= s2_step;
    }

    // special case: i = 3*m/2
    let mut acc = l_shl(i32::from(z[p.rz0]), 15);
    acc = l_msu0(acc, z[p.rz1], t(w.c1));
    acc = l_mac0(acc, z[p.rz2], t(w.c2));
    y[p.ry] = round_word(acc);
}

/// The read positions into the spectrum (`RZk`, `IZk`) and write positions into the decimated
/// blocks (`RYk`, `IYk`) of the inverse butterflies.
struct InvPtr {
    rz0: usize,
    iz0: usize,
    rz1: usize,
    iz1: usize,
    rz2: usize,
    iz2: usize,
    ry: usize,
    iy: usize,
}

/// The six table walkers of the inverse butterflies.
struct InvWalk {
    c0: i16,
    s0: i16,
    c1: i16,
    s1: i16,
    c2: i16,
    s2: i16,
}

/// `ifft3_fx`: inverse of [`fft3`], in place, scaled by 1/3. Any length other than 384 or 1536
/// leaves `x` unchanged.
pub fn ifft3(x: &mut [i16], n: i16) {
    let Some((order_minus1, m, step, phase_tbl)) = layout(n) else {
        return;
    };
    let mut y = [0i16; PH_ECU_SPEC_SIZE];
    let mu = m as usize;
    let nu = n as usize;
    let n_minus_m_by2 = shr(sub(n, m), 1) as usize;
    // The zero positions of the pointers.
    let (rz00, rz10, rz20) = (0, mu, n_minus_m_by2);
    let (iz00, iz10, iz20) = (nu, nu - mu, nu - n_minus_m_by2);
    let z: &[i16] = x;

    // Construction of Y0
    let mut p = InvPtr {
        rz0: rz00,
        iz0: iz00,
        rz1: rz10,
        iz1: iz10,
        rz2: rz20,
        iz2: iz20,
        ry: 0,
        iy: mu,
    };
    let mut acc = l_mult(z[p.rz0], 0x4000);
    acc = l_mac(acc, z[p.rz1], 0x4000);
    y[p.ry] = mac_r(acc, z[p.rz2], 0x4000);
    p.rz0 += 1;
    p.rz1 += 1;
    p.rz2 -= 1;
    p.ry += 1;
    p.iz0 -= 1;
    p.iz1 -= 1;
    p.iz2 += 1;
    p.iy -= 1;

    let l = sub(shr(m, 1), 1);
    for _ in 0..l {
        let mut acc = l_mult(z[p.rz0], 0x4000);
        acc = l_mac(acc, z[p.rz1], 0x4000);
        y[p.ry] = mac_r(acc, z[p.rz2], 0x4000);
        p.rz0 += 1;
        p.rz1 += 1;
        p.rz2 -= 1;
        p.ry += 1;

        acc = l_mult(z[p.iz0], 0x4000);
        acc = l_mac(acc, z[p.iz1], 0x4000);
        y[p.iy] = msu_r(acc, z[p.iz2], 0x4000);
        p.iz0 -= 1;
        p.iz1 -= 1;
        p.iz2 += 1;
        p.iy -= 1;
    }

    // m/2
    let mut acc = l_mult(z[p.rz0], 0x4000);
    acc = l_mac(acc, z[p.rz1], 0x4000);
    y[p.ry] = mac_r(acc, z[p.rz2], 0x4000);

    let zero = InvPtr {
        rz0: rz00,
        iz0: iz00,
        rz1: rz10,
        iz1: iz10,
        rz2: rz20,
        iz2: iz20,
        ry: mu,
        iy: 2 * mu - 1,
    };
    ifft3_y1(z, &mut y, zero, m, step);
    let zero = InvPtr {
        rz0: rz00,
        iz0: iz00,
        rz1: rz10,
        iz1: iz10,
        rz2: rz20,
        iz2: iz20,
        ry: 2 * mu,
        iy: 3 * mu - 1,
    };
    ifft3_y2(z, &mut y, zero, m, step);

    // Compute the inverse FFT for all 3 blocks.
    let m_by2 = shr(m, 1);
    for block in y.chunks_mut(mu).take(3) {
        r_fft_fx_lc_in_place(phase_tbl, m, m_by2, order_minus1, block, 0); // inverse FFT
    }

    // Interlacing and scaling, scale = 1/3
    for i in 0..mu {
        x[3 * i] = shl(mult_r(y[i], FFT3_ONE_THIRD), 1);
        x[3 * i + 1] = shl(mult_r(y[mu + i], FFT3_ONE_THIRD), 1);
        x[3 * i + 2] = shl(mult_r(y[2 * mu + i], FFT3_ONE_THIRD), 1);
    }
}

/// The six-term real part of the inverse butterflies; `signs` are the signs of the `RZ1`,
/// `RZ2`, `IZ0`, `IZ1`, `IZ2` terms (the `RZ0` term is always added).
#[inline]
fn inv_re(z: &[i16], p: &InvPtr, w: &InvWalk, signs: [bool; 5]) -> i16 {
    let term = |acc: i32, x: i16, c: i16, plus: bool| {
        if plus {
            l_mac0(acc, x, t(c))
        } else {
            l_msu0(acc, x, t(c))
        }
    };
    let mut acc = l_mult0(z[p.rz0], t(w.c0));
    acc = term(acc, z[p.rz1], w.c1, signs[0]);
    acc = term(acc, z[p.rz2], w.c2, signs[1]);
    acc = term(acc, z[p.iz0], w.s0, signs[2]);
    acc = term(acc, z[p.iz1], w.s1, signs[3]);
    acc = term(acc, z[p.iz2], w.s2, signs[4]);
    round_word(acc)
}

/// The six-term imaginary part of the inverse butterflies, advancing the read positions;
/// `signs` are the signs of the `IZ1`, `IZ2`, `RZ0`, `RZ1`, `RZ2` terms.
#[inline]
fn inv_im(z: &[i16], p: &mut InvPtr, w: &InvWalk, signs: [bool; 5]) -> i16 {
    let term = |acc: i32, x: i16, c: i16, plus: bool| {
        if plus {
            l_mac0(acc, x, t(c))
        } else {
            l_msu0(acc, x, t(c))
        }
    };
    let mut acc = l_mult0(z[p.iz0], t(w.c0));
    acc = term(acc, z[p.iz1], w.c1, signs[0]);
    acc = term(acc, z[p.iz2], w.c2, signs[1]);
    acc = term(acc, z[p.rz0], w.s0, signs[2]);
    acc = term(acc, z[p.rz1], w.s1, signs[3]);
    acc = term(acc, z[p.rz2], w.s2, signs[4]);
    p.iz0 -= 1;
    p.iz1 -= 1;
    p.iz2 += 1;
    p.rz0 += 1;
    p.rz1 += 1;
    p.rz2 -= 1;
    round_word(acc)
}

impl InvWalk {
    fn start() -> Self {
        InvWalk {
            c0: T_SIN_PI_2,
            s0: 0,
            c1: T_SIN_PI_2 / 3,
            s1: T_SIN_PI_2 * 2 / 3,
            c2: T_SIN_PI_2 / 3,
            s2: T_SIN_PI_2 * 2 / 3,
        }
    }

    /// Step every walker by its signed step.
    fn advance(&mut self, steps: [i16; 6]) {
        self.c0 += steps[0];
        self.s0 += steps[1];
        self.c1 += steps[2];
        self.s1 += steps[3];
        self.c2 += steps[4];
        self.s2 += steps[5];
    }
}

/// Construction of Y1 in `ifft3_fx`.
fn ifft3_y1(z: &[i16], y: &mut [i16], mut p: InvPtr, m: i16, step: i16) {
    let mut w = InvWalk::start();
    let mut acc = l_mult0(z[p.rz0], t(w.c0));
    acc = l_msu0(acc, z[p.rz1], t(w.c1));
    acc = l_msu0(acc, z[p.rz2], t(w.c2));
    p.rz0 += 1;
    p.rz1 += 1;
    p.rz2 -= 1;
    p.iz0 -= 1;
    acc = l_msu0(acc, z[p.iz1], t(w.s1));
    acc = l_msu0(acc, z[p.iz2], t(w.s2));
    p.iz1 -= 1;
    p.iz2 += 1;
    y[p.ry] = round_word(acc);
    p.ry += 1;

    let first = [-step, step, step, -step, -step, step];
    w.advance(first);

    // From 1 to (m/4) - 1.
    let l = sub(shr(m, 2), 1);
    for _ in 0..l {
        y[p.ry] = inv_re(z, &p, &w, [false, false, false, false, false]);
        p.ry += 1;
        y[p.iy] = inv_im(z, &mut p, &w, [false, true, true, true, false]);
        p.iy -= 1;
        w.advance(first);
    }

    // From m/4 to m/2 -1.
    let l = shr(m, 2); // m/2 - m/4 = m/4
    for _ in 0..l {
        y[p.ry] = inv_re(z, &p, &w, [false, true, false, false, false]);
        p.ry += 1;
        y[p.iy] = inv_im(z, &mut p, &w, [false, false, true, true, false]);
        p.iy -= 1;
        w.advance([-step, step, step, -step, step, -step]);
    }

    // m/2
    y[p.ry] = inv_re(z, &p, &w, [false, true, false, false, false]);
}

/// Construction of Y2 in `ifft3_fx`.
fn ifft3_y2(z: &[i16], y: &mut [i16], mut p: InvPtr, m: i16, step: i16) {
    let mut w = InvWalk::start();
    let step2 = shl(step, 1);
    let mut acc = l_mult0(z[p.rz0], t(w.c0));
    acc = l_msu0(acc, z[p.rz1], t(w.c1));
    acc = l_msu0(acc, z[p.rz2], t(w.c2));
    p.rz0 += 1;
    p.rz1 += 1;
    p.rz2 -= 1;
    p.iz0 -= 1;
    acc = l_mac0(acc, z[p.iz1], t(w.s1));
    acc = l_mac0(acc, z[p.iz2], t(w.s2));
    p.iz1 -= 1;
    p.iz2 += 1;
    y[p.ry] = round_word(acc);
    p.ry += 1;

    let first = [-step2, step2, -step2, step2, step2, -step2];
    w.advance(first);

    // From 1 to (m/8) - 1.
    let l = sub(shr(m, 3), 1);
    for _ in 0..l {
        y[p.ry] = inv_re(z, &p, &w, [false, false, false, true, true]);
        p.ry += 1;
        y[p.iy] = inv_im(z, &mut p, &w, [false, true, true, false, true]);
        p.iy -= 1;
        w.advance(first);
    }

    // From (m/8) to (m/4) - 1.
    let l = shr(m, 3);
    for _ in 0..l {
        y[p.ry] = inv_re(z, &p, &w, [true, false, false, true, true]);
        p.ry += 1;
        y[p.iy] = inv_im(z, &mut p, &w, [true, true, true, false, true]);
        p.iy -= 1;
        w.advance([-step2, step2, step2, -step2, step2, -step2]);
    }

    // From m/4 to 3*m/8 - 1.
    let l = shr(m, 3);
    for _ in 0..l {
        y[p.ry] = inv_re(z, &p, &w, [true, false, false, true, false]);
        p.ry += 1;
        y[p.iy] = inv_im(z, &mut p, &w, [true, true, true, false, false]);
        p.iy -= 1;
        w.advance([-step2, step2, step2, -step2, -step2, step2]);
    }

    // From 3*m/8 to m/2 - 1
    let l = shr(m, 3);
    for _ in 0..l {
        y[p.ry] = ifft3_y2_tail_re(z, &p, &w);
        p.ry += 1;

        let mut acc = l_mult0(z[p.iz1], t(w.c1));
        acc = l_msu0(acc, z[p.iz0], t(w.c0));
        acc = l_mac0(acc, z[p.iz2], t(w.c2));
        acc = l_mac0(acc, z[p.rz0], t(w.s0));
        acc = l_msu0(acc, z[p.rz1], t(w.s1));
        acc = l_msu0(acc, z[p.rz2], t(w.s2));
        p.iz1 -= 1;
        p.iz0 -= 1;
        p.iz2 += 1;
        p.rz0 += 1;
        p.rz1 += 1;
        p.rz2 -= 1;
        y[p.iy] = round_word(acc);
        p.iy -= 1;

        w.advance([step2, -step2, step2, -step2, -step2, step2]);
    }

    // m/2
    y[p.ry] = ifft3_y2_tail_re(z, &p, &w);
}

/// The real part of Y2's last quarter, where the `RZ1` term leads and `RZ0` is subtracted.
fn ifft3_y2_tail_re(z: &[i16], p: &InvPtr, w: &InvWalk) -> i16 {
    let mut acc = l_mult0(z[p.rz1], t(w.c1));
    acc = l_msu0(acc, z[p.rz0], t(w.c0));
    acc = l_msu0(acc, z[p.rz2], t(w.c2));
    acc = l_msu0(acc, z[p.iz0], t(w.s0));
    acc = l_mac0(acc, z[p.iz1], t(w.s1));
    acc = l_msu0(acc, z[p.iz2], t(w.s2));
    round_word(acc)
}
