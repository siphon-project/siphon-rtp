//! The complex low-delay filter bank, CLDFB (TS 26.442 `lib_com/cldfb.c`; TS 26.445 §5.1.2 and
//! §6.9): a polyphase, complex-exponential-modulated filter bank of 10 to 60 bands at 1.25 ms per
//! time slot, used by the decoder to resample the core synthesis to the output rate and to carry
//! the bandwidth extension and comfort noise in the subband domain.
//!
//! Subband buffers are `[[i32; CLDFB_ROW]]` rows, one row per time slot: the reference's
//! `Word32 *rAnalysis[CLDFB_NO_COL_MAX]`, whose rows every caller points at a
//! `Word32 realBufferTmp[CLDFB_NO_COL_MAX][CLDFB_NO_CHANNELS_MAX]`. Only the first `no_channels`
//! entries of a row are read or written.
//!
//! The reference's `pWorkBuffer` argument is scratch the callers own (`Word32 workBuffer[128*3]`);
//! nothing in it survives a call or is read before it is written, so the Rust functions keep their
//! scratch on the stack and do not take it.
//!

#![allow(clippy::too_many_arguments)]

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    CLDFB_ANALYSIS, CLDFB_FLAG_2_5MS_SETUP, CLDFB_FLAG_KEEP_STATES, CLDFB_NO_CHANNELS_MAX,
    CLDFB_NO_COL_MAX, CLDFB_SYNTHESIS,
};
use crate::evs::com::basop_util::limit_scale32;
use crate::evs::com::fft::{basop_cfft, Interleaved, BASOP_CFFT_WORK_LENGTH};
use crate::evs::com::lerp::{lerp_in_place, lerp_within};
use crate::evs::com::tools::{copy, scale_sig, set16};
use crate::evs::dec::state::{CldfbFilterBank, CldfbScaleFactor};
use crate::evs::rom::{
    CLDFB_ANASCALE, CLDFB_PROTOFILTER_2_5MS, CLDFB_SCALE_2_5MS, CLDFB_SYNGAIN, CLDFB_SYNSCALE,
    IROTVECTR_10, IROTVECTR_16, IROTVECTR_20, IROTVECTR_32, IROTVECTR_40, IROTVECTR_60,
    RROTVECTR_10, RROTVECTR_16, RROTVECTR_20, RROTVECTR_32, RROTVECTR_40, RROTVECTR_60,
};
use crate::itu::basic_ops::{
    add, l_add, l_mac, l_mult, l_negate, l_shl, l_shr, l_sub, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{div_l, i_mult, l_msu0};

/// The width of one subband row, `CLDFB_NO_CHANNELS_MAX`.
pub const CLDFB_ROW: usize = CLDFB_NO_CHANNELS_MAX as usize;

/// `STATE_BUFFER_SIZE`: filter states per band of an analysis bank (half of a synthesis bank's).
const STATE_BUFFER_SIZE: i16 = 9 + 16;
/// `CLDFB_NO_POLY`: taps per polyphase branch.
const CLDFB_NO_POLY: isize = 5;
/// `CLDFB_CLDFB80_PFT_SCALE`.
const CLDFB_CLDFB80_PFT_SCALE: i16 = 1;
/// `SYN_FILTER_HEADROOM_2_5MS`.
const SYN_FILTER_HEADROOM_2_5MS: i16 = 2;
/// `CLDFB_MEM_EXPONENTS`: the time-slot exponents saved with the filter states.
const CLDFB_MEM_EXPONENTS: i16 = CLDFB_NO_COL_MAX + 9;
/// `N10`, the pointer step of `ptrUpdate20`.
const N10: isize = 5;

/// Where one `cplxMult*` reads and writes: `yr`/`yi` index the output buffer, `xr`/`xi` the input,
/// each with the reference's pointer stride.
#[derive(Clone, Copy)]
struct Lanes {
    yr: isize,
    yi: isize,
    syr: isize,
    syi: isize,
    xr: isize,
    xi: isize,
    sxr: isize,
    sxi: isize,
}

/// `cplxMult10`, `cplxMult16`, `cplxMult20`, `cplxMult30`, `cplxMult32`, `cplxMult40`,
/// `cplxMult60`: `n` successive `cplxMpyS`, `n = m / 2`. The composite ones (20 = 2 x 10, ...)
/// restart their halves at the offset the first half's pointers had reached, so each is exactly
/// one run of `n`.
///
/// `x == None` is the reference's in-place call (`&rBuffer[0]` as both input and output); each
/// step reads both inputs before writing either output, so that is well defined.
fn cplx_mult(n: usize, y: &mut [i32], x: Option<&[i32]>, lanes: Lanes, cr: &[i16], ci: &[i16]) {
    let Lanes {
        mut yr,
        mut yi,
        syr,
        syi,
        mut xr,
        mut xi,
        sxr,
        sxi,
    } = lanes;
    for k in 0..n {
        let (xr_value, xi_value) = match x {
            Some(x) => (x[xr as usize], x[xi as usize]),
            None => (y[xr as usize], y[xi as usize]),
        };
        let zr = l_sub(mpy_32_16_1(xr_value, cr[k]), mpy_32_16_1(xi_value, ci[k]));
        let zi = l_add(mpy_32_16_1(xr_value, ci[k]), mpy_32_16_1(xi_value, cr[k]));
        y[yr as usize] = zr;
        y[yi as usize] = zi;
        yr += syr;
        yi += syi;
        xr += sxr;
        xi += sxi;
    }
}

/// `calcModulation`: the unrolled complex modulation of the DST-IV (`r_*`) and DCT-IV (`i_*`)
/// halves for `m` bands. The reference asserts on any other `m`; here it does nothing.
fn calc_modulation(
    r_y: &mut [i32],
    r_x: Option<&[i32]>,
    r_lanes: Lanes,
    i_y: &mut [i32],
    i_x: Option<&[i32]>,
    i_lanes: Lanes,
    r_rot_vctr: &[i16],
    i_rot_vctr: &[i16],
    m: i16,
) {
    if !matches!(m, 10 | 16 | 20 | 32 | 40 | 60) {
        return;
    }
    let n = (m / 2) as usize;
    cplx_mult(n, r_y, r_x, r_lanes, r_rot_vctr, i_rot_vctr);
    cplx_mult(n, i_y, i_x, i_lanes, r_rot_vctr, i_rot_vctr);
}

/// Which output combination a `cplxMultAdd*` applies: the `add1` or the `add2` macro.
#[derive(Clone, Copy)]
enum Fold {
    Add1,
    Add2,
}

/// One family of pointers of `calcModulationAndFolding`: four output positions (stepping
/// +2, -2, -2, +2), four inputs (`rxr`, `rxi` into the DST half, `ixr`, `ixi` into the DCT half)
/// and one rotation-table index (the same for the real and the imaginary table).
#[derive(Clone, Copy)]
struct FoldPointers {
    y: [isize; 4],
    x: [isize; 4],
    r: isize,
}

impl FoldPointers {
    /// `ptrUpdate20`, for the family whose pointers walk down (`sign = -1`) or up (`sign = 1`).
    fn update20(&mut self, sign: isize) {
        self.y[0] += 2 * N10;
        self.y[1] -= 2 * N10;
        self.y[2] -= 2 * N10;
        self.y[3] += 2 * N10;
        self.r += sign * N10;
        for x in &mut self.x {
            *x += sign * 2 * N10;
        }
    }
}

/// `cplxMultAdd10_1`, `cplxMultAdd10_2`, `cplxMultAdd20_1`, `cplxMultAdd20_2`: `count` steps of
/// `cplxMpy` followed by `add1` / `add2`. The pointers are the callee's copies, as in C: the
/// caller's `p` is not advanced.
fn cplx_mult_add(
    count: usize,
    fold: Fold,
    r_y: &mut [i16],
    r_x: &[i32],
    i_x: &[i32],
    r_rot_vctr: &[i16],
    i_rot_vctr: &[i16],
    p: FoldPointers,
    gv: i16,
    s: i16,
    sx: isize,
    sr: isize,
) {
    let [mut y1, mut y2, mut y3, mut y4] = p.y;
    let [mut rxr, mut rxi, mut ixr, mut ixi] = p.x;
    let mut c = p.r;
    for _ in 0..count {
        let (cr, ci) = (r_rot_vctr[c as usize], i_rot_vctr[c as usize]);
        let (a, b) = (r_x[rxr as usize], r_x[rxi as usize]);
        let (d, e) = (i_x[ixr as usize], i_x[ixi as usize]);
        // cplxMpy
        let rr12 = mpy_32_16_1(l_sub(mpy_32_16_1(a, cr), mpy_32_16_1(b, ci)), gv);
        let ri12 = mpy_32_16_1(l_add(mpy_32_16_1(a, ci), mpy_32_16_1(b, cr)), gv);
        let ir12 = mpy_32_16_1(l_sub(mpy_32_16_1(d, cr), mpy_32_16_1(e, ci)), gv);
        let ii12 = mpy_32_16_1(l_add(mpy_32_16_1(d, ci), mpy_32_16_1(e, cr)), gv);
        rxr += sx;
        rxi += sx;
        ixr += sx;
        ixi += sx;
        c += sr;
        let values = match fold {
            Fold::Add1 => [
                l_negate(l_add(rr12, ii12)),
                l_negate(l_add(ri12, ir12)),
                l_sub(rr12, ii12),
                l_sub(ir12, ri12),
            ],
            Fold::Add2 => [
                l_add(ri12, ir12),
                l_add(rr12, ii12),
                l_sub(ir12, ri12),
                l_sub(rr12, ii12),
            ],
        };
        r_y[y1 as usize] = round_word(l_shl(values[0], s));
        r_y[y2 as usize] = round_word(l_shl(values[1], s));
        r_y[y3 as usize] = round_word(l_shl(values[2], s));
        r_y[y4 as usize] = round_word(l_shl(values[3], s));
        y1 += 2;
        y2 -= 2;
        y3 -= 2;
        y4 += 2;
    }
}

/// `calcModulationAndFolding`: post-modulation of the DST-IV (`r_x`) and DCT-IV (`i_x`) halves of
/// a synthesis time slot, folded into `2 * m` real samples in `r_y`. Defined for the synthesis
/// band counts 10, 20, 40 and 60; the reference asserts on any other `m`, here it does nothing.
fn calc_modulation_and_folding(
    r_y: &mut [i16],
    r_x: &[i32],
    i_x: &[i32],
    r_rot_vctr: &[i16],
    i_rot_vctr: &[i16],
    gain: i16,
    scale: i16,
    m: i16,
    m2: i16,
) {
    let (m, m2) = (m as isize, m2 as isize);
    let mut down = FoldPointers {
        y: [m + m2 + 1, m2 - 2, m + m2 - 2, m2 + 1],
        x: [m - 2, m - 1, m - 2, m - 1],
        r: m2 - 1,
    };
    let mut up = FoldPointers {
        y: [m + m2, m2 - 1, m + m2 - 1, m2],
        x: [0, 1, 0, 1],
        r: 0,
    };
    let (rounds, count) = match m {
        10 => (1, (2, 3)),
        20 => (1, (5, 5)),
        40 => (2, (5, 5)),
        60 => (3, (5, 5)),
        _ => return,
    };
    for _ in 0..rounds {
        cplx_mult_add(
            count.0,
            Fold::Add1,
            r_y,
            r_x,
            i_x,
            r_rot_vctr,
            i_rot_vctr,
            down,
            gain,
            scale,
            -2,
            -1,
        );
        cplx_mult_add(
            count.1,
            Fold::Add2,
            r_y,
            r_x,
            i_x,
            r_rot_vctr,
            i_rot_vctr,
            up,
            gain,
            scale,
            2,
            1,
        );
        // m = 10 and m = 20 break before any `ptrUpdate20`; the pointers are dead after the last
        // round either way.
        down.update20(-1);
        up.update20(1);
    }
}

/// `L_msu0` over the five polyphase taps of one branch: `-sum(filter[f + j] * states[s + j * l2])`.
#[inline]
fn prototype_branch(filter: &[i16], f: isize, states: &[i16], s: isize, l2: isize) -> i32 {
    let mut acc = 0;
    for j in 0..CLDFB_NO_POLY {
        acc = l_msu0(acc, filter[(f + j) as usize], states[(s + j * l2) as usize]);
    }
    acc
}

/// `cldfbAnalysisFiltering`: complex subband analysis of `n_time_slots * no_channels` samples of
/// `time_in` (exponent `time_in_e`) into rows `r_analysis[k]` / `i_analysis[k]`, `k <
/// n_time_slots`, updating the filter states and `scale_factor.lb_scale`.
pub fn cldfb_analysis_filtering(
    cldfb_bank: &mut CldfbFilterBank,
    r_analysis: &mut [[i32; CLDFB_ROW]],
    i_analysis: &mut [[i32; CLDFB_ROW]],
    scale_factor: &mut CldfbScaleFactor,
    time_in: &[i16],
    time_in_e: i16,
    n_time_slots: i16,
) {
    let m = cldfb_bank.no_channels;
    let l2 = shl(m, 1);
    let m2 = shr(m, 1);
    let m4 = sub(m2, shr(m, 2));

    let l3 = sub(l2, m2);
    let l4 = add(l2, m2);

    let m0m2 = sub(0, m2);
    let m2m1 = sub(m2, 1);
    let l3m1 = sub(l3, 1);
    let l4m1 = sub(l4, 1);

    let mut r_buffer = [0i32; CLDFB_ROW];
    let mut i_buffer = [0i32; CLDFB_ROW];
    let mut work_buffer = [0i32; BASOP_CFFT_WORK_LENGTH];

    let r_rot_vctr = cldfb_bank.r_rot_vctr;
    let i_rot_vctr = cldfb_bank.i_rot_vctr;

    // pStates1..6 as offsets into FilterStates (pStates6 starts before it: -m2).
    let mut p_states1 = l3m1 as isize;
    let mut p_states2 = l3 as isize;
    let mut p_states3 = m2 as isize;
    let mut p_states4 = m2m1 as isize;
    let mut p_states5 = l4m1 as isize;
    let mut p_states6 = m0m2 as isize;

    let p_stride = CLDFB_NO_POLY;
    let p_filter = cldfb_bank.p_filter;
    let p_filter1 = p_stride * l3m1 as isize;
    let p_filter2 = p_stride * l3 as isize;
    let p_filter3 = p_stride * m2 as isize;
    let p_filter4 = p_stride * m2m1 as isize;
    let p_filter5 = p_stride * l4m1 as isize;
    let p_filter6 = p_stride * m0m2 as isize;

    let n_samples = i_mult(n_time_slots, cldfb_bank.no_channels);
    let n_samples_upd = i_mult(cldfb_bank.no_col, cldfb_bank.no_channels);
    let offset = sub(
        sub(cldfb_bank.p_filter_length, cldfb_bank.no_channels),
        cldfb_bank.zeros,
    );

    // Determine states scale
    let mut scale: i16 = -15;
    let mut k: i16 = 0;
    let mut i: i16 = 0;
    while i < offset {
        cldfb_bank.filter_states_e[k as usize] =
            cldfb_bank.filter_states_e[(k + cldfb_bank.no_col) as usize];
        scale = scale.max(cldfb_bank.filter_states_e[k as usize]);
        k = add(k, 1);
        i += cldfb_bank.no_channels;
    }
    i = 0;
    while i < n_samples {
        cldfb_bank.filter_states_e[k as usize] = time_in_e;
        scale = scale.max(cldfb_bank.filter_states_e[k as usize]);
        k = add(k, 1);
        i += cldfb_bank.no_channels;
    }
    let i = scale.max(time_in_e);
    scale = sub(cldfb_bank.filter_states_eg, i);
    cldfb_bank.filter_states_eg = i;

    // if nTimeSlots==0, make sure we have a value.
    scale_factor.lb_scale = add(
        cldfb_bank.ana_scalefactor,
        add(cldfb_bank.filter_states_eg, 5),
    );

    let p_states = &mut cldfb_bank.filter_states;
    // move and scale filter states
    for i in 0..offset.max(0) as usize {
        p_states[i] = shl(p_states[i + n_samples_upd as usize], scale);
    }

    // copy and scale current time signal
    scale = sub(time_in_e, cldfb_bank.filter_states_eg);
    for i in 0..n_samples.max(0) as usize {
        p_states[offset as usize + i] = shl(time_in[i], scale);
    }

    let l2 = l2 as isize;
    for k in 0..n_time_slots.max(0) as usize {
        let states = &cldfb_bank.filter_states[..];
        for i in 0..m4 as isize {
            // prototype filter
            let r1 = prototype_branch(
                p_filter,
                p_filter1 - p_stride * 2 * i,
                states,
                p_states1 - 2 * i,
                l2,
            );
            let r2 = prototype_branch(
                p_filter,
                p_filter2 + p_stride * 2 * i,
                states,
                p_states2 + 2 * i,
                l2,
            );
            let i1 = prototype_branch(
                p_filter,
                p_filter3 + p_stride * 2 * i,
                states,
                p_states3 + 2 * i,
                l2,
            );
            let i2 = prototype_branch(
                p_filter,
                p_filter4 - p_stride * 2 * i,
                states,
                p_states4 - 2 * i,
                l2,
            );
            let index = 2 * i as usize;
            // folding
            r_buffer[index] = l_sub(r1, r2);
            r_buffer[index + 1] = l_negate(l_add(i1, i2));
            // folding
            i_buffer[index] = l_add(r1, r2);
            i_buffer[index + 1] = l_sub(i1, i2);
        }

        for i in m4 as isize..m2 as isize {
            // prototype filter
            let r1 = prototype_branch(
                p_filter,
                p_filter1 - p_stride * 2 * i,
                states,
                p_states1 - 2 * i,
                l2,
            );
            let r2 = prototype_branch(
                p_filter,
                p_filter6 + p_stride * 2 * i,
                states,
                p_states6 + 2 * i,
                l2,
            );
            let i1 = prototype_branch(
                p_filter,
                p_filter5 - p_stride * 2 * i,
                states,
                p_states5 - 2 * i,
                l2,
            );
            let i2 = prototype_branch(
                p_filter,
                p_filter3 + p_stride * 2 * i,
                states,
                p_states3 + 2 * i,
                l2,
            );
            let index = 2 * i as usize;
            // folding
            r_buffer[index] = l_add(r1, r2);
            r_buffer[index + 1] = l_sub(i1, i2);
            // folding
            i_buffer[index] = l_sub(r1, r2);
            i_buffer[index + 1] = l_add(i1, i2);
        }

        // pre modulation of DST IV and DCT IV
        let in_place = Lanes {
            yr: 0,
            yi: 1,
            syr: 2,
            syi: 2,
            xr: 0,
            xi: 1,
            sxr: 2,
            sxi: 2,
        };
        calc_modulation(
            &mut r_buffer,
            None,
            in_place,
            &mut i_buffer,
            None,
            in_place,
            r_rot_vctr,
            i_rot_vctr,
            m,
        );

        // FFT of DST IV
        let mut scale = 0;
        basop_cfft(
            &mut Interleaved {
                data: &mut r_buffer,
                at: 0,
            },
            m2,
            2,
            &mut scale,
            &mut work_buffer,
        );

        // store analysis scalefactor for cldfb
        scale_factor.lb_scale = add(
            cldfb_bank.ana_scalefactor,
            add(cldfb_bank.filter_states_eg, scale),
        );

        // FFT of DCT IV
        basop_cfft(
            &mut Interleaved {
                data: &mut i_buffer,
                at: 0,
            },
            m2,
            2,
            &mut scale,
            &mut work_buffer,
        );

        // post modulation of DST IV and DCT IV
        let last = (m - 1) as isize;
        calc_modulation(
            &mut r_analysis[k],
            Some(&r_buffer),
            Lanes {
                yr: last,
                yi: 0,
                syr: -2,
                syi: 2,
                xr: 0,
                xi: 1,
                sxr: 2,
                sxi: 2,
            },
            &mut i_analysis[k],
            Some(&i_buffer),
            Lanes {
                yr: 0,
                yi: last,
                syr: 2,
                syi: -2,
                xr: 0,
                xi: 1,
                sxr: 2,
                sxi: 2,
            },
            r_rot_vctr,
            i_rot_vctr,
            m,
        );

        // update states pointer
        let step = cldfb_bank.no_channels as isize;
        p_states1 += step;
        p_states2 += step;
        p_states3 += step;
        p_states5 += step;
        p_states4 += step;
        p_states6 += step;
    }
}

/// The subband samples of one synthesis time slot, scaled to a common exponent, as
/// `cldfbSynthesisFiltering` stages them in `rAnalysisS` / `iAnalysisS`. The even bands' imaginary
/// part is negated.
fn cldfb_synthesis_filtering_stage(
    r_analysis: &[i32; CLDFB_ROW],
    i_analysis: &[i32; CLDFB_ROW],
    r_analysis_s: &mut [i32; CLDFB_ROW],
    i_analysis_s: &mut [i32; CLDFB_ROW],
    lz: i16,
    mz: i16,
    m: i16,
    scale_lb: i16,
    scale_hb: i16,
) {
    for (first, negate_imaginary) in [(0i16, true), (1, false)] {
        let mut i = first;
        while i < lz {
            let index = i as usize;
            r_analysis_s[index] = l_shr(r_analysis[index], scale_lb);
            let imaginary = l_shr(i_analysis[index], scale_lb);
            i_analysis_s[index] = if negate_imaginary {
                l_negate(imaginary)
            } else {
                imaginary
            };
            i += 2;
        }
        while i < mz {
            let index = i as usize;
            r_analysis_s[index] = l_shr(r_analysis[index], scale_hb);
            let imaginary = l_shr(i_analysis[index], scale_hb);
            i_analysis_s[index] = if negate_imaginary {
                l_negate(imaginary)
            } else {
                imaginary
            };
            i += 2;
        }
        while i < m {
            r_analysis_s[i as usize] = 0;
            i_analysis_s[i as usize] = 0;
            i += 2;
        }
    }
}

/// `cldfbSynthesisFiltering`: inverse complex subband filtering of rows `r_analysis[k]` /
/// `i_analysis[k]`, `k < n_time_slots`, into `n_time_slots * no_channels` samples of `time_out`
/// at exponent `time_out_e`, updating the filter states.
pub fn cldfb_synthesis_filtering(
    cldfb_bank: &mut CldfbFilterBank,
    r_analysis: &[[i32; CLDFB_ROW]],
    i_analysis: &[[i32; CLDFB_ROW]],
    scale_factor: &CldfbScaleFactor,
    time_out: &mut [i16],
    time_out_e: i16,
    n_time_slots: i16,
) {
    let m = cldfb_bank.no_channels;
    let l2 = shl(m, 1);
    let m2 = shr(m, 1);
    let lz = cldfb_bank.lsb.min(sub(m, cldfb_bank.bands_to_zero));
    let mz = cldfb_bank.usb.min(sub(m, cldfb_bank.bands_to_zero));

    let channels0 = sub(m, cldfb_bank.zeros);
    let channels1 = sub(m, 1);
    let channels2 = shl(m, 1);
    let channels3 = add(m, channels2);
    let channels4 = shl(channels2, 1);

    let states_size_m1 = sub(shl(cldfb_bank.p_filter_length, 1), m);
    let states_size_m2 = sub(states_size_m1, m);

    let offset1 = sub(channels1, cldfb_bank.zeros);
    let offset2 = add(offset1, cldfb_bank.no_channels);

    let mut r_buffer = [0i32; CLDFB_ROW];
    let mut i_buffer = [0i32; CLDFB_ROW];
    let mut n_buffer = [0i16; 2 * CLDFB_ROW];
    let mut r_analysis_s = [0i32; CLDFB_ROW];
    let mut i_analysis_s = [0i32; CLDFB_ROW];
    let mut work_buffer = [0i32; BASOP_CFFT_WORK_LENGTH];

    let r_rot_vctr = cldfb_bank.r_rot_vctr;
    let i_rot_vctr = cldfb_bank.i_rot_vctr;

    let mut scale = scale_factor.lb_scale;
    if sub(lz, mz) != 0 {
        scale = scale.max(scale_factor.hb_scale);
    }
    let scale_lb = limit_scale32(sub(scale, scale_factor.lb_scale));
    let scale_hb = limit_scale32(sub(scale, scale_factor.hb_scale));

    let mut out_scale = cldfb_bank.syn_filter_headroom;

    let mut scale_mod = sub(add(scale, cldfb_bank.out_scalefactor), out_scale);

    // Increase CLDFB synthesis states for low level signals
    if sub(scale, 8) < 0 {
        scale_mod = add(scale_mod, 2);
        out_scale = sub(out_scale, 2);
    }
    scale_mod = sub(scale_mod, time_out_e);
    scale = add(out_scale, time_out_e);
    if sub(scale, cldfb_bank.filter_states_eg) != 0 {
        scale_sig(
            &mut cldfb_bank.filter_states,
            states_size_m2,
            sub(cldfb_bank.filter_states_eg, scale),
        );
        cldfb_bank.filter_states_eg = scale;
    }

    let p_filter = cldfb_bank.p_filter;
    let (channels1, channels2, channels3, channels4) = (
        channels1 as usize,
        channels2 as usize,
        channels3 as usize,
        channels4 as usize,
    );
    let m_size = m as usize;
    let last = (m - 1) as isize;
    let mut time_at = 0usize;
    for k in 0..n_time_slots.max(0) as usize {
        cldfb_synthesis_filtering_stage(
            &r_analysis[k],
            &i_analysis[k],
            &mut r_analysis_s,
            &mut i_analysis_s,
            lz,
            mz,
            m,
            scale_lb,
            scale_hb,
        );

        // pre modulation
        let lanes = Lanes {
            yr: 0,
            yi: 1,
            syr: 2,
            syi: 2,
            xr: 0,
            xi: last,
            sxr: 2,
            sxi: -2,
        };
        calc_modulation(
            &mut r_buffer,
            Some(&r_analysis_s),
            lanes,
            &mut i_buffer,
            Some(&i_analysis_s),
            lanes,
            r_rot_vctr,
            i_rot_vctr,
            m,
        );

        // FFT of DST IV
        let mut scale = 0;
        basop_cfft(
            &mut Interleaved {
                data: &mut r_buffer,
                at: 0,
            },
            m2,
            2,
            &mut scale,
            &mut work_buffer,
        );

        // FFT of DCT IV
        scale = scale_mod;
        basop_cfft(
            &mut Interleaved {
                data: &mut i_buffer,
                at: 0,
            },
            m2,
            2,
            &mut scale,
            &mut work_buffer,
        );

        // post modulation and folding
        calc_modulation_and_folding(
            &mut n_buffer,
            &r_buffer,
            &i_buffer,
            r_rot_vctr,
            i_rot_vctr,
            cldfb_bank.syn_gain,
            scale,
            m,
            m2,
        );

        // prototype filter
        let p_states = &mut cldfb_bank.filter_states[k * l2 as usize..];
        let mut p_filter_s = 0usize;
        let mut p_filter_m = shr(cldfb_bank.p_filter_length, 1) as usize;

        let mut i = 0usize;
        while (i as i16) < channels0 {
            let mut p_states_i = i;
            let mut p_states_r = i + channels3;

            let mut acc = l_mult(p_states[p_states_i], p_filter[p_filter_s]);
            acc = l_mac(acc, p_states[p_states_r], p_filter[p_filter_m]);
            p_filter_s += 1;
            p_filter_m += 1;
            p_states_r += channels4;
            p_states_i += channels4;

            for _ in 0..2 {
                acc = l_mac(acc, p_states[p_states_i], p_filter[p_filter_s]);
                acc = l_mac(acc, p_states[p_states_r], p_filter[p_filter_m]);
                p_filter_s += 1;
                p_filter_m += 1;
                p_states_r += channels4;
                p_states_i += channels4;
            }

            acc = l_mac(acc, p_states[p_states_i], p_filter[p_filter_s]);
            acc = l_mac(acc, p_states[p_states_r], p_filter[p_filter_m]);
            p_filter_s += 1;
            p_filter_m += 1;
            p_states_i += channels4;

            acc = l_mac(acc, p_states[p_states_i], p_filter[p_filter_s]);
            acc = l_mac(acc, n_buffer[channels1 - i], p_filter[p_filter_m]);
            p_filter_s += 1;
            p_filter_m += 1;

            time_out[(time_at as isize + offset1 as isize - i as isize) as usize] =
                round_word(l_shl(acc, out_scale));
            i += 1;
        }

        while i < m_size {
            let mut p_states_i = i + channels2;
            let mut p_states_r = i + channels2 + channels3;

            let mut acc = l_mult(p_states[p_states_i], p_filter[p_filter_s]);
            acc = l_mac(acc, p_states[p_states_r], p_filter[p_filter_m]);
            p_filter_s += 1;
            p_filter_m += 1;
            p_states_r += channels4;
            p_states_i += channels4;

            for _ in 0..2 {
                acc = l_mac(acc, p_states[p_states_i], p_filter[p_filter_s]);
                acc = l_mac(acc, p_states[p_states_r], p_filter[p_filter_m]);
                p_filter_s += 1;
                p_filter_m += 1;
                p_states_r += channels4;
                p_states_i += channels4;
            }

            acc = l_mac(acc, p_states[p_states_i], p_filter[p_filter_s]);
            acc = l_mac(acc, p_states[p_states_r], p_filter[p_filter_m]);
            p_filter_s += 1;
            p_filter_m += 1;

            acc = l_mac(acc, n_buffer[channels1 + m_size - i], p_filter[p_filter_s]);
            p_filter_s += 1;
            p_filter_m += 1;

            time_out[(time_at as isize + offset2 as isize - i as isize) as usize] =
                round_word(l_shl(acc, out_scale));
            i += 1;
        }

        for i in 0..m_size {
            p_states[states_size_m1 as usize + i] = n_buffer[channels1 - i];
            p_states[states_size_m2 as usize + i] = n_buffer[channels1 + m_size - i];
        }

        time_at += m_size;
    }

    // move filter states (Copy with the destination below the source copies forward, as memmove)
    let from = i_mult(n_time_slots, l2).max(0) as usize;
    let length = states_size_m2.max(0) as usize;
    cldfb_bank.filter_states.copy_within(from..from + length, 0);
    set16(
        &mut cldfb_bank.filter_states[states_size_m2 as usize..],
        0,
        l2,
    );
}

/// `configureCldfb`: set up `h_cldfb` for `no_channels` bands and `frame_size` samples per frame,
/// keeping its filter states.
pub fn configure_cldfb(h_cldfb: &mut CldfbFilterBank, no_channels: i16, frame_size: i16) {
    h_cldfb.no_channels = no_channels;
    h_cldfb.no_col = div_l(i32::from(frame_size), shr(h_cldfb.no_channels, 1));

    // was cldfbInitFilterBank()
    h_cldfb.ana_scalefactor = 0;
    h_cldfb.syn_scalefactor = 0;
    h_cldfb.bands_to_zero = 0;
    h_cldfb.filtermode = 0;
    // memory = NULL: empty is the state's NULL, and the capacity `open_cldfb` reserved stays so a
    // later save does not allocate.
    h_cldfb.memory.clear();
    h_cldfb.memory_length = 0;

    h_cldfb.p_filter_length = i_mult(10, h_cldfb.no_channels);

    h_cldfb.flags |= CLDFB_FLAG_2_5MS_SETUP as u16;
    h_cldfb.filter_scale = CLDFB_CLDFB80_PFT_SCALE;

    h_cldfb.zeros = 0;
    h_cldfb.syn_filter_headroom = SYN_FILTER_HEADROOM_2_5MS;

    cldfb_init_proto_and_twiddles(h_cldfb);

    h_cldfb.lsb = no_channels;
    h_cldfb.usb = no_channels.min(h_cldfb.no_channels);

    h_cldfb.out_scalefactor = h_cldfb.syn_scalefactor;
}

/// `openCldfb`: allocate a bank of `type` (`CLDFB_ANALYSIS` / `CLDFB_SYNTHESIS`) with filter
/// states for up to `max_cldfb_bands` bands, configured for `max_cldfb_bands` and `frame_size`.
/// Allocation happens here, once; nothing per frame allocates.
pub fn open_cldfb(
    h_cldfb: &mut Option<Box<CldfbFilterBank>>,
    r#type: i16,
    max_cldfb_bands: i16,
    frame_size: i16,
) {
    let mut hs = Box::new(CldfbFilterBank::zeroed());
    hs.r#type = r#type;

    let bands = max_cldfb_bands.max(0) as usize;
    let per_band = STATE_BUFFER_SIZE as usize;
    hs.filter_states = if r#type == CLDFB_ANALYSIS {
        vec![0; per_band * bands]
    } else {
        vec![0; 2 * per_band * bands]
    };
    hs.flags &= !(CLDFB_FLAG_KEEP_STATES as u16);

    configure_cldfb(&mut hs, max_cldfb_bands, frame_size);

    // The reference `calloc`s the save buffer in every `cldfb_save_memory`. Reserve the largest one
    // here instead (a save copies at most every filter state, plus the exponents), so no save on
    // the decode path allocates.
    hs.memory = Vec::with_capacity(hs.filter_states.len() + CLDFB_MEM_EXPONENTS as usize + 1);
    hs.memory_length = 0;

    // The states were just allocated zeroed (calloc); the reference clears them again here.
    if hs.r#type == CLDFB_ANALYSIS {
        if hs.flags & CLDFB_FLAG_KEEP_STATES as u16 == 0 {
            let length = i_mult(STATE_BUFFER_SIZE, hs.no_channels);
            set16(&mut hs.filter_states, 0, length);
            hs.filter_states_e = [0; CLDFB_MEM_EXPONENTS as usize];
            hs.filter_states_eg = 0;
        }
    } else if hs.r#type == CLDFB_SYNTHESIS {
        if hs.flags & CLDFB_FLAG_KEEP_STATES as u16 == 0 {
            let length = i_mult(shl(STATE_BUFFER_SIZE, 1), hs.no_channels);
            set16(&mut hs.filter_states, 0, length);
        }
        hs.filter_states_eg = 0;
    }

    *h_cldfb = Some(hs);
}

/// `resampleCldfb`: switch the bank to `new_cldfb_bands` bands and `frame_size` samples per
/// frame. Unless this is the first frame, the states the next frame's modulation needs are
/// resampled to the new band count by linear interpolation and moved into place.
pub fn resample_cldfb(
    hs: &mut CldfbFilterBank,
    new_cldfb_bands: i16,
    frame_size: i16,
    first_frame: i8,
) {
    let no_channels_old = hs.no_channels;
    let time_offset_old = sub(sub(hs.p_filter_length, hs.no_channels), hs.zeros);

    // change all CLDFB bank parameters that depend on the no of channels
    hs.flags |= CLDFB_FLAG_KEEP_STATES as u16;

    // new settings
    configure_cldfb(hs, new_cldfb_bands, frame_size);

    // resample cldfb state buffer
    let time_offset = sub(sub(hs.p_filter_length, hs.no_channels), hs.zeros);

    if first_frame == 0 {
        // low complexity-resampling only stored previous samples that are needed for next frame
        // modulation. The offset is C int arithmetic on the old band count and the NEW no_col.
        let at = (i32::from(no_channels_old) * i32::from(hs.no_col)).max(0) as usize;
        lerp_within(&mut hs.filter_states, at, at, time_offset, time_offset_old);
        // Copy() is memmove-safe: it copies forward when the destination is below the source.
        let length = time_offset.max(0) as usize;
        hs.filter_states
            .copy_within(at..at + length, frame_size.max(0) as usize);
    }
}

/// `deleteCldfb`: free the bank, leaving the handle empty.
pub fn delete_cldfb(h_cldfb: &mut Option<Box<CldfbFilterBank>>) {
    *h_cldfb = None;
}

/// `CLDFB_getNumChannels`: the band count of a bank at `sample_rate`, 0 for any other rate.
#[must_use]
pub fn cldfb_get_num_channels(sample_rate: i32) -> i16 {
    match sample_rate {
        48000 => 60,
        32000 => 40,
        25600 => 32,
        16000 => 20,
        12800 => 16,
        8000 => 10,
        _ => 0,
    }
}

/// `cldfb_get_memory_length`: the filter states saved for recovery.
fn cldfb_get_memory_length(hs: &CldfbFilterBank) -> i16 {
    if sub(hs.r#type, CLDFB_ANALYSIS) == 0 {
        i_mult(hs.no_channels, STATE_BUFFER_SIZE)
    } else {
        i_mult(hs.no_channels, 9 * 2)
    }
}

/// `cldfb_init_proto_and_twiddles`: point the bank at the ROM prototype filter and rotation
/// vectors of its band count. The 16- and 32-band setups only ever analyse, so they set the
/// analysis scale whatever the type; a band count without tables leaves the bank as it is.
fn cldfb_init_proto_and_twiddles(hs: &mut CldfbFilterBank) {
    let (index, r_rot, i_rot, analysis_only): (usize, &'static [i16], &'static [i16], bool) =
        match hs.no_channels {
            10 => (0, &RROTVECTR_10, &IROTVECTR_10, false),
            16 => (1, &RROTVECTR_16, &IROTVECTR_16, true),
            20 => (2, &RROTVECTR_20, &IROTVECTR_20, false),
            32 => (3, &RROTVECTR_32, &IROTVECTR_32, true),
            40 => (4, &RROTVECTR_40, &IROTVECTR_40, false),
            60 => (5, &RROTVECTR_60, &IROTVECTR_60, false),
            _ => return,
        };
    hs.r_rot_vctr = r_rot;
    hs.i_rot_vctr = i_rot;
    hs.syn_gain = CLDFB_SYNGAIN[index];
    hs.p_filter = CLDFB_PROTOFILTER_2_5MS[index];
    hs.scale = CLDFB_SCALE_2_5MS[index];
    if !analysis_only && hs.r#type == CLDFB_SYNTHESIS {
        hs.syn_scalefactor = add(CLDFB_SYNSCALE[index], hs.filter_scale);
    } else {
        hs.ana_scalefactor = add(CLDFB_ANASCALE[index], hs.filter_scale);
    }
}

/// `cldfb_save_memory`: save the filter states and their exponents, to be put back by
/// `cldfb_restore_memory`. The reference `calloc`s the buffer on every save; here it fills the
/// capacity `open_cldfb` reserved.
pub fn cldfb_save_memory(hs: &mut CldfbFilterBank) {
    hs.memory_length = cldfb_get_memory_length(hs);
    let length = hs.memory_length.max(0) as usize;
    let exponents = CLDFB_MEM_EXPONENTS as usize;
    hs.memory.clear();
    hs.memory.resize(length + exponents + 1, 0);

    // save the memory
    copy(&hs.filter_states, &mut hs.memory, hs.memory_length);
    hs.memory[length..length + exponents].copy_from_slice(&hs.filter_states_e[..exponents]);
    hs.memory[length + exponents] = hs.filter_states_eg;
}

/// `cldfb_restore_memory`: put back what `cldfb_save_memory` saved, resampling the states by
/// linear interpolation if the band count changed in the meantime, and release the save. Without
/// a save to restore (the reference would read through `NULL`) it does nothing.
pub fn cldfb_restore_memory(hs: &mut CldfbFilterBank) {
    let size = cldfb_get_memory_length(hs);
    let length = hs.memory_length.max(0) as usize;
    let exponents = CLDFB_MEM_EXPONENTS as usize;
    if hs.memory.len() < length + exponents + 1 {
        return;
    }

    // read the memory
    copy(&hs.memory, &mut hs.filter_states, hs.memory_length);
    hs.filter_states_e[..exponents].copy_from_slice(&hs.memory[length..length + exponents]);
    hs.filter_states_eg = hs.memory[length + exponents];

    // adjust sample rate if it was changed in the meanwhile
    if sub(hs.memory_length, size) != 0 {
        lerp_in_place(&mut hs.filter_states, size, hs.memory_length);
    }

    hs.memory_length = 0;
    // free(): empty is the state's NULL; the capacity stays for the next save.
    hs.memory.clear();
}

/// `cldfb_reset_memory`: clear the filter states and their exponents.
pub fn cldfb_reset_memory(hs: &mut CldfbFilterBank) {
    let length = cldfb_get_memory_length(hs);
    // erase the memory
    set16(&mut hs.filter_states, 0, length);
    hs.filter_states_e = [0; CLDFB_MEM_EXPONENTS as usize];
    hs.filter_states_eg = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_count_follows_the_sample_rate() {
        assert_eq!(cldfb_get_num_channels(48000), 60);
        assert_eq!(cldfb_get_num_channels(32000), 40);
        assert_eq!(cldfb_get_num_channels(25600), 32);
        assert_eq!(cldfb_get_num_channels(16000), 20);
        assert_eq!(cldfb_get_num_channels(12800), 16);
        assert_eq!(cldfb_get_num_channels(8000), 10);
        assert_eq!(cldfb_get_num_channels(44100), 0);
    }

    #[test]
    fn delete_empties_the_handle() {
        let mut handle = None;
        open_cldfb(&mut handle, CLDFB_SYNTHESIS, 20, 320);
        assert!(handle.is_some());
        delete_cldfb(&mut handle);
        assert!(handle.is_none());
    }

    #[test]
    fn reset_clears_states_and_exponents() {
        let mut handle = None;
        open_cldfb(&mut handle, CLDFB_ANALYSIS, 16, 256);
        let Some(bank) = handle.as_mut() else {
            panic!("open_cldfb left no bank");
        };
        bank.filter_states.fill(7);
        bank.filter_states_e = [3; 25];
        bank.filter_states_eg = 4;
        cldfb_reset_memory(bank);
        assert!(bank.filter_states.iter().all(|&v| v == 0));
        assert_eq!(bank.filter_states_e, [0; 25]);
        assert_eq!(bank.filter_states_eg, 0);
    }
}
