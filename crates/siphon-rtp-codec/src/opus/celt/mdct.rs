//! CELT inverse MDCT (IMDCT) + KISS-FFT, pure-Rust float (`f32`) port.
//!
//! This is a faithful port of libopus' `clt_mdct_backward_c` (`celt/mdct.c`)
//! and `opus_fft_impl` / `kf_bfly{2,3,4,5}` (`celt/kiss_fft.c`) for the
//! **float build** (`#ifndef FIXED_POINT`). In that build every `SHL32` /
//! `SHR32` / `PSHR32` / `VSHR32` is the identity, every `S_MUL` / `S_MUL2` /
//! `MULT*` is a plain `a * b`, and `kiss_fft_cpx` is a pair of `f32`.
//!
//! The MDCT does most of its work via an `N/4` complex FFT. For the 48 kHz
//! CELT mode the base MDCT length is `N = 1920`; the `shift` argument selects
//! the sub-transform (LM = log2 of the number of short blocks):
//!
//! | shift | N    | N/4 (= FFT size) | frame   |
//! |-------|------|------------------|---------|
//! | 0     | 1920 | 480              | LM=3 (20 ms long) |
//! | 1     |  960 | 240              | LM=2    |
//! | 2     |  480 | 120              | LM=1    |
//! | 3     |  240 |  60              | LM=0 (2.5 ms) |
//!
//! `stride = B` interleaves `B` short MDCT blocks into one output buffer.
//!
//! ## Tables (computed, not the libopus precomputed blobs)
//!
//! Standard libopus mode does not define `CUSTOM_MODES`, so it ships giant
//! precomputed twiddle / bitrev / factor tables. We compute them directly,
//! which is simpler and produces the identical transform:
//!
//! * MDCT trig table (per shift level): `trig[i] = cos(2*PI*(i + 0.125)/N)`
//!   for `i in 0..N/2`.
//! * FFT twiddles (per FFT size `nfft`): `twiddles[i] = (cos(-2*PI*i/nfft),
//!   sin(-2*PI*i/nfft))`.
//! * Radix factorisation via libopus' `kf_factor` rule (peel 4s, then 2/3/5;
//!   a `p == 2` factor in stage > 1 becomes a `4` with sub-factor `2`), then
//!   the recursive `compute_bitrev_table`.
//!
//! ## Scaling
//!
//! There is **no `1/N` scaling**: `opus_fft_impl` does not scale and the MDCT
//! header explicitly documents "no scaling". The decoder applies any gain
//! elsewhere. The TDAC fold would conceptually scale up by 2 at the post-rotate
//! step but libopus folds that factor into the window mixing instead, so we
//! match that exactly (no explicit factor anywhere).
//!
//! ## References
//!
//! * libopus `celt/mdct.c` `clt_mdct_backward_c`
//! * libopus `celt/kiss_fft.c` `opus_fft_impl`, `kf_bfly2/3/4/5`, `kf_factor`,
//!   `compute_bitrev_table`, `compute_twiddles`
//! * RFC 6716 (Opus); the CELT MDCT is described in §4.3.7.

/// Maximum number of FFT radix stages (matches libopus `MAXFACTORS`).
const MAX_FACTORS: usize = 8;

/// A single complex value (`kiss_fft_cpx` in the float build).
///
/// `#[repr(C)]` with two `f32` fields gives it the exact layout of `[f32; 2]`
/// (re first, then im), which lets the IMDCT run the FFT in place over the f32
/// output buffer with no per-call allocation (see `as_complex_mut`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Complex {
    pub re: f32,
    pub im: f32,
}

impl Complex {
    #[inline]
    const fn new(re: f32, im: f32) -> Self {
        Self { re, im }
    }
}

/// Errors that can occur while building an MDCT/FFT state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdctError {
    /// `nfft` could not be factored into radices 2/3/4/5.
    Unfactorable,
    /// `nfft` needed more than `MAX_FACTORS` stages.
    TooManyFactors,
}

impl core::fmt::Display for MdctError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MdctError::Unfactorable => {
                write!(f, "FFT size is not factorable into radices 2/3/4/5")
            }
            MdctError::TooManyFactors => write!(f, "FFT size needs more than MAX_FACTORS stages"),
        }
    }
}

impl std::error::Error for MdctError {}

/// Precomputed state for one complex FFT of a given size.
///
/// Mirrors libopus' `kiss_fft_state`, except `shift` is always effectively 0
/// because each size owns a full twiddle table sized to itself (rather than
/// sharing a single oversized base table).
#[derive(Clone, Debug)]
pub struct FftState {
    nfft: usize,
    /// `twiddles[i] = (cos(-2*PI*i/nfft), sin(-2*PI*i/nfft))`.
    twiddles: Vec<Complex>,
    /// `(radix, m)` pairs, exactly libopus' `factors[2*stage], factors[2*stage+1]`.
    factors: Vec<(usize, usize)>,
    /// Bit-reversal permutation (`compute_bitrev_table`).
    bitrev: Vec<usize>,
}

impl FftState {
    /// Build the FFT state for a transform of size `nfft`.
    fn new(nfft: usize) -> Result<Self, MdctError> {
        let mut twiddles = Vec::with_capacity(nfft);
        // compute_twiddles: phase = (-2*pi/nfft) * i, r = cos, i = sin.
        // Uses f64 internally then narrows, exactly like libopus.
        for i in 0..nfft {
            let phase = (-2.0_f64 * std::f64::consts::PI / nfft as f64) * i as f64;
            twiddles.push(Complex::new(phase.cos() as f32, phase.sin() as f32));
        }

        let factors = kf_factor(nfft)?;

        let mut bitrev = vec![0usize; nfft];
        compute_bitrev_table(0, &mut bitrev, 0, 1, 1, &factors);

        Ok(Self {
            nfft,
            twiddles,
            factors,
            bitrev,
        })
    }
}

/// libopus `kf_factor`: factor `n` into radices, peeling 4s first, then 2/3/5,
/// then remaining primes; reverse so the radix-4 stages run last; record `m`.
///
/// The `p == 2 && stage > 1 -> becomes 4 (with facbuf[2]=2)` rule is the exact
/// libopus quirk: a stray radix-2 after the first stage is merged so the inner
/// transform stays radix-4-friendly.
fn kf_factor(n: usize) -> Result<Vec<(usize, usize)>, MdctError> {
    // facbuf[2*stage] = radix; facbuf[2*stage+1] = m (filled in second pass).
    let mut facbuf = [0usize; 2 * MAX_FACTORS];
    let mut p = 4usize;
    let mut stages = 0usize;
    let mut work = n;
    let nbak = n;

    loop {
        while !work.is_multiple_of(p) {
            match p {
                4 => p = 2,
                2 => p = 3,
                _ => p += 2,
            }
            if p > 32000 || p * p > work {
                p = work; // no more factors, skip to end
            }
        }
        work /= p;
        if p > 5 {
            return Err(MdctError::Unfactorable);
        }
        if stages >= MAX_FACTORS {
            return Err(MdctError::TooManyFactors);
        }
        facbuf[2 * stages] = p;
        // p==2 in stages>1 becomes a 4 with sub-factor 2.
        if p == 2 && stages > 1 {
            facbuf[2 * stages] = 4;
            facbuf[2] = 2;
        }
        stages += 1;
        if work <= 1 {
            break;
        }
    }

    // Reverse the radix order so radix-4 ends up at the end (fast degenerate
    // case) — also improves noise behaviour per the libopus comment.
    for i in 0..(stages / 2) {
        facbuf.swap(2 * i, 2 * (stages - i - 1));
    }

    // Second pass: m[i] = n / prod(radix[0..=i]).
    let mut m = nbak;
    let mut out = Vec::with_capacity(stages);
    for i in 0..stages {
        m /= facbuf[2 * i];
        facbuf[2 * i + 1] = m;
        out.push((facbuf[2 * i], facbuf[2 * i + 1]));
    }
    Ok(out)
}

/// libopus `compute_bitrev_table` (recursive). `f_off` is the write offset into
/// `f`; `factor_idx` indexes into `factors` (each recursion descends one stage).
fn compute_bitrev_table(
    fout: usize,
    f: &mut [usize],
    f_off: usize,
    fstride: usize,
    in_stride: usize,
    factors: &[(usize, usize)],
) {
    let (p, m) = factors[0];
    if m == 1 {
        for j in 0..p {
            f[f_off + j * fstride * in_stride] = fout + j;
        }
    } else {
        let mut fo = fout;
        for j in 0..p {
            compute_bitrev_table(
                fo,
                f,
                f_off + j * fstride * in_stride,
                fstride * p,
                in_stride,
                &factors[1..],
            );
            fo += m;
        }
    }
}

// --------------------------------------------------------------------------
// FFT butterflies (float build). Faithful ports of kf_bfly{2,3,4,5}.
// `fout` is the whole working buffer; `base` is the offset of this radix
// group's first element. In libopus `Fout` is a moving pointer; here we pass
// an explicit base index and index relative to it.
// --------------------------------------------------------------------------

/// Radix-2 butterfly. In non-custom modes `m == 4` always (radix-2 only ever
/// runs immediately after a radix-4), so the twiddles are the fixed 8th-roots.
fn kf_bfly2(fout: &mut [Complex], base: usize, n: usize) {
    const TW: f32 = 0.707_106_77_f32; // QCONST32(0.7071067812f, ...) -> 1/sqrt(2)
    let mut f = base;
    for _ in 0..n {
        // Fout2 = Fout + 4
        let f2 = f + 4;

        // index 0: t = Fout2[0]; Fout2[0] = Fout[0]-t; Fout[0] += t;
        let t = fout[f2];
        fout[f2] = Complex::new(fout[f].re - t.re, fout[f].im - t.im);
        fout[f].re += t.re;
        fout[f].im += t.im;

        // index 1
        let a = fout[f2 + 1];
        let t = Complex::new((a.re + a.im) * TW, (a.im - a.re) * TW);
        fout[f2 + 1] = Complex::new(fout[f + 1].re - t.re, fout[f + 1].im - t.im);
        fout[f + 1].re += t.re;
        fout[f + 1].im += t.im;

        // index 2: t.r = Fout2[2].i; t.i = -Fout2[2].r;
        let a = fout[f2 + 2];
        let t = Complex::new(a.im, -a.re);
        fout[f2 + 2] = Complex::new(fout[f + 2].re - t.re, fout[f + 2].im - t.im);
        fout[f + 2].re += t.re;
        fout[f + 2].im += t.im;

        // index 3: t.r = (Fout2[3].i - Fout2[3].r)*tw; t.i = -(Fout2[3].i + Fout2[3].r)*tw
        let a = fout[f2 + 3];
        let t = Complex::new((a.im - a.re) * TW, -(a.im + a.re) * TW);
        fout[f2 + 3] = Complex::new(fout[f + 3].re - t.re, fout[f + 3].im - t.im);
        fout[f + 3].re += t.re;
        fout[f + 3].im += t.im;

        f += 8;
    }
}

/// Radix-4 butterfly.
fn kf_bfly4(
    fout: &mut [Complex],
    base: usize,
    fstride: usize,
    twiddles: &[Complex],
    m: usize,
    n: usize,
    mm: usize,
) {
    if m == 1 {
        // Degenerate case: all twiddles are 1.
        let mut f = base;
        for _ in 0..n {
            let scratch0 = Complex::new(fout[f].re - fout[f + 2].re, fout[f].im - fout[f + 2].im);
            fout[f].re += fout[f + 2].re;
            fout[f].im += fout[f + 2].im;
            let scratch1 = Complex::new(
                fout[f + 1].re + fout[f + 3].re,
                fout[f + 1].im + fout[f + 3].im,
            );
            fout[f + 2] = Complex::new(fout[f].re - scratch1.re, fout[f].im - scratch1.im);
            fout[f].re += scratch1.re;
            fout[f].im += scratch1.im;
            let scratch1 = Complex::new(
                fout[f + 1].re - fout[f + 3].re,
                fout[f + 1].im - fout[f + 3].im,
            );

            fout[f + 1] = Complex::new(scratch0.re + scratch1.im, scratch0.im - scratch1.re);
            fout[f + 3] = Complex::new(scratch0.re - scratch1.im, scratch0.im + scratch1.re);
            f += 4;
        }
    } else {
        let m2 = 2 * m;
        let m3 = 3 * m;
        let mut scratch = [Complex::default(); 6];
        for i in 0..n {
            let f_beg = base + i * mm;
            // tw{1,2,3} step by fstride*{1,2,3} per j; f steps by 1 per j.
            for j in 0..m {
                let f = f_beg + j;
                let tw1 = j * fstride;
                let tw2 = j * fstride * 2;
                let tw3 = j * fstride * 3;
                scratch[0] = c_mul(fout[f + m], twiddles[tw1]);
                scratch[1] = c_mul(fout[f + m2], twiddles[tw2]);
                scratch[2] = c_mul(fout[f + m3], twiddles[tw3]);

                scratch[5] = Complex::new(fout[f].re - scratch[1].re, fout[f].im - scratch[1].im);
                fout[f].re += scratch[1].re;
                fout[f].im += scratch[1].im;
                scratch[3] =
                    Complex::new(scratch[0].re + scratch[2].re, scratch[0].im + scratch[2].im);
                scratch[4] =
                    Complex::new(scratch[0].re - scratch[2].re, scratch[0].im - scratch[2].im);
                fout[f + m2] = Complex::new(fout[f].re - scratch[3].re, fout[f].im - scratch[3].im);
                fout[f].re += scratch[3].re;
                fout[f].im += scratch[3].im;

                fout[f + m] =
                    Complex::new(scratch[5].re + scratch[4].im, scratch[5].im - scratch[4].re);
                fout[f + m3] =
                    Complex::new(scratch[5].re - scratch[4].im, scratch[5].im + scratch[4].re);
            }
        }
    }
}

/// Radix-3 butterfly.
fn kf_bfly3(
    fout: &mut [Complex],
    base: usize,
    fstride: usize,
    twiddles: &[Complex],
    m: usize,
    n: usize,
    mm: usize,
) {
    let m2 = 2 * m;
    // epi3 = twiddles[fstride*m]; only epi3.i is used.
    let epi3_i = twiddles[fstride * m].im;
    let mut scratch = [Complex::default(); 5];
    for i in 0..n {
        let f_beg = base + i * mm;
        // The libopus `do { ... } while(--k)` runs exactly m times (k=m..1).
        for j in 0..m {
            let f = f_beg + j;
            let tw1 = j * fstride;
            let tw2 = j * fstride * 2;
            scratch[1] = c_mul(fout[f + m], twiddles[tw1]);
            scratch[2] = c_mul(fout[f + m2], twiddles[tw2]);

            scratch[3] = Complex::new(scratch[1].re + scratch[2].re, scratch[1].im + scratch[2].im);
            scratch[0] = Complex::new(scratch[1].re - scratch[2].re, scratch[1].im - scratch[2].im);

            fout[f + m] = Complex::new(
                fout[f].re - 0.5 * scratch[3].re,
                fout[f].im - 0.5 * scratch[3].im,
            );

            // C_MULBYSCALAR(scratch[0], epi3.i)
            scratch[0].re *= epi3_i;
            scratch[0].im *= epi3_i;

            fout[f].re += scratch[3].re;
            fout[f].im += scratch[3].im;

            fout[f + m2] = Complex::new(
                fout[f + m].re + scratch[0].im,
                fout[f + m].im - scratch[0].re,
            );

            fout[f + m] = Complex::new(
                fout[f + m].re - scratch[0].im,
                fout[f + m].im + scratch[0].re,
            );
        }
    }
}

/// Radix-5 butterfly.
fn kf_bfly5(
    fout: &mut [Complex],
    base: usize,
    fstride: usize,
    twiddles: &[Complex],
    m: usize,
    n: usize,
    mm: usize,
) {
    let ya = twiddles[fstride * m];
    let yb = twiddles[fstride * 2 * m];
    let mut scratch = [Complex::default(); 13];
    for i in 0..n {
        let f0 = base + i * mm;
        let f1 = f0 + m;
        let f2 = f0 + 2 * m;
        let f3 = f0 + 3 * m;
        let f4 = f0 + 4 * m;
        for u in 0..m {
            scratch[0] = fout[f0 + u];

            scratch[1] = c_mul(fout[f1 + u], twiddles[u * fstride]);
            scratch[2] = c_mul(fout[f2 + u], twiddles[2 * u * fstride]);
            scratch[3] = c_mul(fout[f3 + u], twiddles[3 * u * fstride]);
            scratch[4] = c_mul(fout[f4 + u], twiddles[4 * u * fstride]);

            scratch[7] = Complex::new(scratch[1].re + scratch[4].re, scratch[1].im + scratch[4].im);
            scratch[10] =
                Complex::new(scratch[1].re - scratch[4].re, scratch[1].im - scratch[4].im);
            scratch[8] = Complex::new(scratch[2].re + scratch[3].re, scratch[2].im + scratch[3].im);
            scratch[9] = Complex::new(scratch[2].re - scratch[3].re, scratch[2].im - scratch[3].im);

            fout[f0 + u].re += scratch[7].re + scratch[8].re;
            fout[f0 + u].im += scratch[7].im + scratch[8].im;

            scratch[5] = Complex::new(
                scratch[0].re + (scratch[7].re * ya.re + scratch[8].re * yb.re),
                scratch[0].im + (scratch[7].im * ya.re + scratch[8].im * yb.re),
            );

            scratch[6] = Complex::new(
                scratch[10].im * ya.im + scratch[9].im * yb.im,
                -(scratch[10].re * ya.im + scratch[9].re * yb.im),
            );

            fout[f1 + u] =
                Complex::new(scratch[5].re - scratch[6].re, scratch[5].im - scratch[6].im);
            fout[f4 + u] =
                Complex::new(scratch[5].re + scratch[6].re, scratch[5].im + scratch[6].im);

            scratch[11] = Complex::new(
                scratch[0].re + (scratch[7].re * yb.re + scratch[8].re * ya.re),
                scratch[0].im + (scratch[7].im * yb.re + scratch[8].im * ya.re),
            );
            scratch[12] = Complex::new(
                scratch[9].im * ya.im - scratch[10].im * yb.im,
                scratch[10].re * yb.im - scratch[9].re * ya.im,
            );

            fout[f2 + u] = Complex::new(
                scratch[11].re + scratch[12].re,
                scratch[11].im + scratch[12].im,
            );
            fout[f3 + u] = Complex::new(
                scratch[11].re - scratch[12].re,
                scratch[11].im - scratch[12].im,
            );
        }
    }
}

/// Complex multiply `m = a * b` (`C_MUL` in the float build).
#[inline]
fn c_mul(a: Complex, b: Complex) -> Complex {
    Complex::new(a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re)
}

/// Reinterpret a `[f32]` region of even length as `[Complex]` (re, im pairs).
///
/// Sound because `Complex` is `#[repr(C)]` with two `f32` fields — identical
/// layout and alignment to `[f32; 2]`. The caller guarantees `buf.len()` is
/// even; `Vec<f32>`/slice storage is 4-byte aligned, which is `Complex`'s
/// alignment. This lets `clt_mdct_backward` run the FFT in place with no
/// per-call heap allocation.
#[inline]
fn as_complex_mut(buf: &mut [f32]) -> &mut [Complex] {
    debug_assert_eq!(buf.len() % 2, 0, "complex view needs even length");
    debug_assert_eq!(
        (buf.as_ptr() as usize) % core::mem::align_of::<Complex>(),
        0,
        "complex view needs 4-byte alignment"
    );
    let len = buf.len() / 2;
    // SAFETY: Complex is #[repr(C)] { f32, f32 } == [f32; 2] in layout and
    // alignment; len*2 == buf.len(); the lifetime is tied to `buf`.
    unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut Complex, len) }
}

/// libopus `opus_fft_impl`: in-place complex FFT, **no scaling, no bit-reversal**
/// (the caller performs bit-reversal). Operates on `fout[base .. base+nfft]`.
fn opus_fft_impl(st: &FftState, fout: &mut [Complex], base: usize) {
    // shift is always 0 for us (each size owns a twiddle table of its own size).
    debug_assert!(
        fout.len() >= base + st.nfft,
        "FFT buffer too small for nfft"
    );
    let l_count = st.factors.len();
    let mut fstride = [0usize; MAX_FACTORS + 1];
    fstride[0] = 1;

    // Build fstride and find the last stage L where m becomes 1.
    let mut l = 0usize;
    loop {
        let (p, m) = st.factors[l];
        fstride[l + 1] = fstride[l] * p;
        l += 1;
        if m == 1 {
            break;
        }
    }
    debug_assert_eq!(l, l_count);

    let mut m = st.factors[l - 1].1; // factors[2*L-1]
    for i in (0..l).rev() {
        let m2 = if i != 0 { st.factors[i - 1].1 } else { 1 };
        let (radix, _) = st.factors[i];
        match radix {
            2 => kf_bfly2(fout, base, fstride[i]),
            4 => kf_bfly4(fout, base, fstride[i], &st.twiddles, m, fstride[i], m2),
            3 => kf_bfly3(fout, base, fstride[i], &st.twiddles, m, fstride[i], m2),
            5 => kf_bfly5(fout, base, fstride[i], &st.twiddles, m, fstride[i], m2),
            // infallible: `kf_factor` (the only producer of `st.factors`) returns
            // `MdctError::Unfactorable` for any radix > 5, and the FFT sizes are fixed by the CELT
            // mode/config at construction — never bitstream-controlled — so `radix` is always one of
            // 2/3/4/5 here.
            _ => unreachable!("kf_factor only yields radices 2/3/4/5"),
        }
        m = m2;
    }
}

// --------------------------------------------------------------------------
// MDCT state + clt_mdct_backward
// --------------------------------------------------------------------------

/// Precomputed MDCT state for one base length `N` and all `shift` levels
/// `0..=max_shift`. Holds the per-shift trig tables and per-shift FFT states.
#[derive(Clone, Debug)]
pub struct MdctLookup {
    /// Base MDCT length (e.g. 1920 for the 48 kHz mode).
    n: usize,
    max_shift: usize,
    /// Per-shift trig table: `trig[shift][i] = cos(2*PI*(i+0.125)/N_shift)`,
    /// length `N_shift/2` where `N_shift = N >> shift`.
    trig: Vec<Vec<f32>>,
    /// Per-shift FFT state for size `N_shift/4`.
    kfft: Vec<FftState>,
}

impl MdctLookup {
    /// Build the MDCT lookup for base length `n` and shifts `0..=max_shift`.
    ///
    /// For the 48 kHz CELT mode use `n = 1920`, `max_shift = 3`.
    pub fn new(n: usize, max_shift: usize) -> Result<Self, MdctError> {
        let mut trig = Vec::with_capacity(max_shift + 1);
        let mut kfft = Vec::with_capacity(max_shift + 1);
        for shift in 0..=max_shift {
            let n_shift = n >> shift;
            let n2 = n_shift >> 1;
            // trig[i] = cos(2*PI*(i + 0.125)/N_shift), i in 0..N_shift/2.
            // f64 internally then narrow, like libopus.
            let mut t = Vec::with_capacity(n2);
            for i in 0..n2 {
                let phase = 2.0_f64 * std::f64::consts::PI * (i as f64 + 0.125) / n_shift as f64;
                t.push(phase.cos() as f32);
            }
            trig.push(t);
            kfft.push(FftState::new(n_shift >> 2)?);
        }
        Ok(Self {
            n,
            max_shift,
            trig,
            kfft,
        })
    }

    /// Base MDCT length.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Maximum shift level this lookup supports.
    pub fn max_shift(&self) -> usize {
        self.max_shift
    }
}

/// Inverse MDCT: faithful port of libopus `clt_mdct_backward_c` (float build).
///
/// * `input`: frequency-domain coefficients, read with `stride`
///   (`input[i*stride]`, `i in 0..N/2`). For a single block use `stride = 1`;
///   the decoder uses `stride = B` to read one of `B` interleaved short blocks.
/// * `output`: time-domain output, written **contiguously** (not strided — the
///   decoder gives each block its own contiguous output region). The function
///   writes `output[0 .. overlap/2 + N/2]` in place, matching libopus exactly.
///   The buffer must therefore be at least `overlap/2 + N/2` long; libopus then
///   reconstructs the final `N/4` samples via the mirror symmetry
///   `out[N-1-k] = out[N/2+k]` (TDAC), so size the buffer to `N` if you want
///   the full frame.
/// * `window`: the window of length `overlap` (CELT uses `overlap = 120` for
///   the 48 kHz long frame).
/// * `shift`: selects the sub-transform (see the module table).
/// * `stride`: `B`, the number of interleaved short blocks.
///
/// Stages (all verbatim from `mdct.c`):
/// 1. pre-rotate `input` by `trig` into bit-reversed order at `out+overlap/2`,
/// 2. `opus_fft_impl` (in-place complex FFT of size `N/4`, no scaling/bitrev),
/// 3. post-rotate + de-shuffle in place from both ends,
/// 4. windowed TDAC mirror-fold at both ends using `window`.
pub fn clt_mdct_backward(
    state: &MdctLookup,
    input: &[f32],
    output: &mut [f32],
    window: &[f32],
    overlap: usize,
    shift: usize,
    stride: usize,
) {
    let n = state.n >> shift;
    let n2 = n >> 1;
    let n4 = n >> 2;
    let trig = &state.trig[shift];
    let st = &state.kfft[shift];
    let half_overlap = overlap >> 1;

    // ----- Stage 1: pre-rotate into bit-reversed order at out[overlap/2..] ---
    // xp1 walks forward from in[0], xp2 backward from in[stride*(N2-1)],
    // both by 2*stride.  Result is written at yp = out + overlap/2 in the
    // FFT-input layout, placed directly in bit-reversed slots.
    {
        let mut xp1 = 0usize; // forward cursor into `input` (steps by 2*stride)
        let mut xp2 = stride * (n2 - 1); // backward cursor (steps by -2*stride)
        let yp = half_overlap; // base index into `output`
        for i in 0..n4 {
            let rev = st.bitrev[i];
            let x1 = input[xp1];
            let x2 = input[xp2];
            // yr = x2*t[i]   + x1*t[N4+i]
            // yi = x1*t[i]   - x2*t[N4+i]
            let yr = x2 * trig[i] + x1 * trig[n4 + i];
            let yi = x1 * trig[i] - x2 * trig[n4 + i];
            // We swap real and imag because we use an FFT instead of an IFFT.
            // yp[2*rev+1] = yr; yp[2*rev] = yi;
            output[yp + 2 * rev + 1] = yr;
            output[yp + 2 * rev] = yi;
            xp1 += 2 * stride;
            xp2 = xp2.wrapping_sub(2 * stride);
        }
    }

    // ----- Stage 2: N/4 complex FFT in place (no scaling, no bitrev) ---------
    // The FFT buffer is the N4 complex pairs starting at out[overlap/2]. We
    // reinterpret output[half_overlap .. half_overlap+2*N4] as &mut [Complex]
    // (re, im pairs) and transform in place — zero per-call allocation.
    {
        let complex = as_complex_mut(&mut output[half_overlap..half_overlap + 2 * n4]);
        opus_fft_impl(st, complex, 0);
    }

    // ----- Stage 3: post-rotate + de-shuffle from both ends ------------------
    {
        let yp0_base = half_overlap;
        let yp1_base = half_overlap + n2 - 2;
        for i in 0..((n4 + 1) >> 1) {
            // yp0 = out + overlap/2 + 2*i ; yp1 = out + overlap/2 + N2-2 - 2*i
            let yp0 = yp0_base + 2 * i;
            let yp1 = yp1_base - 2 * i;

            // We swap real and imag because we're using an FFT instead of IFFT.
            let mut re = output[yp0 + 1];
            let mut im = output[yp0];
            let mut t0 = trig[i];
            let mut t1 = trig[n4 + i];
            let yr = re * t0 + im * t1;
            let yi = re * t1 - im * t0;

            re = output[yp1 + 1];
            im = output[yp1];
            output[yp0] = yr;
            output[yp1 + 1] = yi;

            t0 = trig[n4 - i - 1];
            t1 = trig[n2 - i - 1];
            let yr = re * t0 + im * t1;
            let yi = re * t1 - im * t0;
            output[yp1] = yr;
            output[yp0 + 1] = yi;
        }
    }

    // ----- Stage 4: windowed TDAC mirror-fold on both ends -------------------
    {
        // xp1 = out + overlap-1 (walks down); yp1 = out (walks up).
        // wp1 = window[0..], wp2 = window[overlap-1..] (down).
        for i in 0..(overlap / 2) {
            let xp1 = overlap - 1 - i;
            let yp1 = i;
            let wp1 = i;
            let wp2 = overlap - 1 - i;
            let x1 = output[xp1];
            let x2 = output[yp1];
            output[yp1] = x2 * window[wp2] - x1 * window[wp1];
            output[xp1] = x2 * window[wp1] + x1 * window[wp2];
        }
    }
}

/// Largest `N/2` any 48 kHz forward MDCT needs as scratch (`1920 >> 0` → 960).
const MAX_MDCT_N2: usize = 960;
/// Largest `N/4` any 48 kHz forward MDCT needs as scratch (`1920 >> 0` → 480).
const MAX_MDCT_N4: usize = MAX_MDCT_N2 / 2;

/// Forward MDCT: faithful port of libopus `clt_mdct_forward_c` (float build, `mdct.c:118`).
///
/// The exact transpose of [`clt_mdct_backward`], and the analysis half of the CELT encoder.
///
/// * `input`: the pre-emphasised, prefiltered time signal for this block, read **contiguously**.
///   The window/shuffle/fold stage touches `input[0 .. N/2 + overlap]`, so the caller's per-block
///   slice must be at least that long (`celt_encoder.c:484` hands each of the `B` blocks
///   `in + b*N` out of a `B*N + overlap` buffer, which is exactly `N/2 + overlap` per block since
///   the MDCT length is twice the block's sample count).
/// * `output`: the frequency-domain coefficients, written with `stride` (`out[i*stride]`,
///   `i in 0..N/2`) so `B` interleaved short blocks share one buffer.
/// * `window`: the analysis window of length `overlap` (48 kHz mode: 120).
/// * `shift`: selects the sub-transform (see the module table); `stride`: `B`.
///
/// Stages, verbatim from `mdct.c`:
/// 1. window / shuffle / fold the four quarters `[a, b, c, d]` into `N/2` reals,
/// 2. pre-rotate by `trig` and scale by `1/nfft` into bit-reversed order (`st->scale`, which the
///    float build sets to `1.f/nfft` — `kiss_fft.c:kiss_fft_alloc_twiddles`),
/// 3. `opus_fft_impl` (in-place complex FFT of size `N/4`, no scaling/bitrev),
/// 4. post-rotate, writing forward from `out[0]` and backward from `out[stride*(N/2-1)]`.
pub fn clt_mdct_forward(
    state: &MdctLookup,
    input: &[f32],
    output: &mut [f32],
    window: &[f32],
    overlap: usize,
    shift: usize,
    stride: usize,
) {
    let n = state.n >> shift;
    let n2 = n >> 1;
    let n4 = n >> 2;
    let trig = &state.trig[shift];
    let st = &state.kfft[shift];
    // float build: `st->scale = 1.f/nfft`, and `PSHR32(MULT16_32_Q16(scale, x), scale_shift)`
    // reduces to `scale * x` (`scale_shift` exists only under FIXED_POINT).
    let scale = 1.0f32 / st.nfft as f32;

    // Caller-owned-equivalent stack scratch (`ALLOC(f, N2)` / `ALLOC(f2, N4)`): no heap on the
    // per-frame path.
    debug_assert!(n2 <= MAX_MDCT_N2);
    let mut f = [0f32; MAX_MDCT_N2];
    let mut f2 = [Complex::default(); MAX_MDCT_N4];

    // ----- Stage 1: window, shuffle, fold (mdct.c:161) -----------------------
    // The input is four blocks [a, b, c, d]; the folded result is the real part
    // `-d-cR` / imaginary part `-b+aR` in the first quarter-overlap, the plain
    // `a-bR` / `-c-dR` in the middle, and the mirrored windowed pair at the end.
    // The C walks five pointers; we index off `i` instead, which is equivalent and keeps every
    // index in range (the C's cursors step one past their range on the final iteration).
    {
        let half_overlap = overlap >> 1;
        let quarter = (overlap + 3) >> 2;
        let tail_start = n4 - quarter;
        for i in 0..n4 {
            let xp1 = half_overlap + 2 * i; // in + (overlap>>1), stepping by 2
            let xp2 = n2 - 1 + half_overlap - 2 * i; // in + N2-1+(overlap>>1), stepping by -2
            let yp = 2 * i;
            if i < quarter {
                // Real part arranged as -d-cR, imaginary part as -b+aR (mdct.c:169).
                let wp1 = half_overlap + 2 * i;
                let wp2 = half_overlap - 1 - 2 * i;
                f[yp] = window[wp2] * input[xp1 + n2] + window[wp1] * input[xp2];
                f[yp + 1] = window[wp1] * input[xp1] - window[wp2] * input[xp2 - n2];
            } else if i < tail_start {
                // Real part arranged as a-bR, imaginary part as -c-dR (mdct.c:180).
                f[yp] = input[xp2];
                f[yp + 1] = input[xp1];
            } else {
                // Mirrored windowed pair (mdct.c:186); the window cursors restart at 0/overlap-1.
                let j = i - tail_start;
                let wp1 = 2 * j;
                let wp2 = overlap - 1 - 2 * j;
                f[yp] = -window[wp1] * input[xp1 - n2] + window[wp2] * input[xp2];
                f[yp + 1] = window[wp2] * input[xp1] + window[wp1] * input[xp2 + n2];
            }
        }
    }

    // ----- Stage 2: pre-rotation + scale, into bit-reversed order (mdct.c:199) ----
    for i in 0..n4 {
        let t0 = trig[i];
        let t1 = trig[n4 + i];
        let re = f[2 * i];
        let im = f[2 * i + 1];
        let yr = re * t0 - im * t1;
        let yi = im * t0 + re * t1;
        f2[st.bitrev[i]] = Complex::new(scale * yr, scale * yi);
    }

    // ----- Stage 3: N/4 complex FFT in place (mdct.c:215) -------------------
    opus_fft_impl(st, &mut f2[..n4], 0);

    // ----- Stage 4: post-rotation, strided from both ends (mdct.c:218) ------
    for i in 0..n4 {
        let fp = f2[i];
        let t0 = trig[i];
        let t1 = trig[n4 + i];
        let yr = fp.im * t1 - fp.re * t0;
        let yi = fp.re * t1 + fp.im * t0;
        output[2 * stride * i] = yr;
        output[stride * (n2 - 1) - 2 * stride * i] = yi;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    /// 48 kHz CELT mode: base MDCT length and its four shift levels.
    const N_BASE: usize = 1920;
    const MAX_SHIFT: usize = 3;

    /// Naive O(n^2) forward DFT with the libopus/KISS kernel `exp(-2*pi*i*k*n/N)`.
    /// `opus_fft_c` (and thus `opus_fft_impl` on bit-reversed input) computes
    /// exactly this forward transform with no scaling.
    fn naive_dft(input: &[Complex]) -> Vec<Complex> {
        let nfft = input.len();
        let mut out = vec![Complex::default(); nfft];
        for (k, o) in out.iter_mut().enumerate() {
            let mut re = 0.0_f64;
            let mut im = 0.0_f64;
            for (n, x) in input.iter().enumerate() {
                let phase = -2.0 * PI * (k as f64) * (n as f64) / nfft as f64;
                let (s, c) = phase.sin_cos();
                re += x.re as f64 * c - x.im as f64 * s;
                im += x.re as f64 * s + x.im as f64 * c;
            }
            *o = Complex::new(re as f32, im as f32);
        }
        out
    }

    /// Run the libopus FFT pipeline: bit-reverse the input, then `opus_fft_impl`
    /// — exactly `opus_fft_c` in the float build (with scale folded in as 1.0,
    /// i.e. no scaling, which is what `opus_fft_impl` itself does).
    fn run_fft(st: &FftState, input: &[Complex]) -> Vec<Complex> {
        assert_eq!(input.len(), st.nfft);
        let mut fout = vec![Complex::default(); st.nfft];
        for i in 0..st.nfft {
            fout[st.bitrev[i]] = input[i];
        }
        opus_fft_impl(st, &mut fout, 0);
        fout
    }

    fn max_abs_diff(a: &[Complex], b: &[Complex]) -> f64 {
        let mut m = 0.0_f64;
        for (x, y) in a.iter().zip(b.iter()) {
            m = m.max((x.re - y.re).abs() as f64);
            m = m.max((x.im - y.im).abs() as f64);
        }
        m
    }

    /// Cheap deterministic LCG so tests never depend on `rand` or wall-clock.
    struct Lcg(u32);
    impl Lcg {
        fn next_f32(&mut self) -> f32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (self.0 >> 8) as f32 / (1u32 << 24) as f32 - 0.5
        }
    }

    // ---- FFT validated against the naive DFT (the task's requirement (a)) ----

    #[test]
    fn fft_matches_naive_dft_for_celt_sizes() {
        // The CELT N4 (= FFT) sizes for shift 3/2/1/0 at 48 kHz: 60, 120, 240, 480.
        for &nfft in &[60usize, 120, 240, 480] {
            let st = FftState::new(nfft).expect("factorable");
            let mut rng = Lcg(0x1234_5678 ^ nfft as u32);
            let input: Vec<Complex> = (0..nfft)
                .map(|_| Complex::new(rng.next_f32(), rng.next_f32()))
                .collect();
            let got = run_fft(&st, &input);
            let want = naive_dft(&input);
            let diff = max_abs_diff(&got, &want);
            // Output magnitudes are O(sqrt(N) * amp); scale tolerance with N.
            let tol = 1e-3 * (nfft as f64);
            assert!(
                diff < tol,
                "nfft={nfft}: FFT vs naive DFT max diff {diff} exceeds tol {tol}"
            );
        }
    }

    #[test]
    fn fft_matches_naive_for_pure_tones() {
        // A pure complex exponential `exp(+i 2pi bin n / N)` must concentrate
        // into a single bin. Under the DFT kernel exp(-i...),
        //   X[k] = sum_n exp(i 2pi (bin-k) n / N) = N when k == bin, else 0.
        for &nfft in &[60usize, 120, 240, 480] {
            let st = FftState::new(nfft).expect("factorable");
            for bin in [1usize, 3, 7] {
                let input: Vec<Complex> = (0..nfft)
                    .map(|n| {
                        let phase = 2.0 * PI * (bin as f64) * (n as f64) / nfft as f64;
                        Complex::new(phase.cos() as f32, phase.sin() as f32)
                    })
                    .collect();
                let got = run_fft(&st, &input);
                for (k, g) in got.iter().enumerate() {
                    let mag = ((g.re * g.re + g.im * g.im) as f64).sqrt();
                    if k == bin {
                        assert!(
                            (mag - nfft as f64).abs() < 1e-2 * nfft as f64,
                            "nfft={nfft} bin={bin}: peak mag {mag} != {nfft}"
                        );
                    } else {
                        assert!(
                            mag < 1e-2 * nfft as f64,
                            "nfft={nfft} bin={bin}: leakage at k={k} mag={mag}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn fft_roundtrip_via_ifft_is_identity() {
        // FFT then conjugate-IFFT (the opus_ifft identity, no scaling) returns
        // N * input, confirming internal self-consistency independent of the
        // naive DFT.
        for &nfft in &[60usize, 120, 240, 480] {
            let st = FftState::new(nfft).expect("factorable");
            let mut rng = Lcg(0xBEEF ^ nfft as u32);
            let input: Vec<Complex> = (0..nfft)
                .map(|_| Complex::new(rng.next_f32(), rng.next_f32()))
                .collect();
            let fwd = run_fft(&st, &input);
            // IFFT(x) = conj(FFT(conj(x))) / N ; opus_ifft does the conj trick
            // without scaling, so we divide by N here.
            let conj: Vec<Complex> = fwd.iter().map(|c| Complex::new(c.re, -c.im)).collect();
            let back = run_fft(&st, &conj);
            for (i, b) in back.iter().enumerate() {
                let re = b.re / nfft as f32; // conj of result, /N
                let im = -b.im / nfft as f32;
                assert!(
                    (re - input[i].re).abs() < 1e-3,
                    "nfft={nfft} i={i} re {re} != {}",
                    input[i].re
                );
                assert!(
                    (im - input[i].im).abs() < 1e-3,
                    "nfft={nfft} i={i} im {im} != {}",
                    input[i].im
                );
            }
        }
    }

    // ---- factorization / bitrev structural invariants ----

    #[test]
    fn kf_factor_celt_sizes() {
        for &nfft in &[60usize, 120, 240, 480] {
            let factors = kf_factor(nfft).expect("factorable");
            let prod: usize = factors.iter().map(|&(p, _)| p).product();
            assert_eq!(prod, nfft, "radix product mismatch for {nfft}");
            assert_eq!(factors.last().expect("nonempty").1, 1, "last m must be 1");
        }
    }

    #[test]
    fn bitrev_is_a_permutation() {
        for &nfft in &[60usize, 120, 240, 480] {
            let st = FftState::new(nfft).expect("factorable");
            let mut seen = vec![false; nfft];
            for &b in &st.bitrev {
                assert!(b < nfft, "bitrev out of range for {nfft}");
                assert!(!seen[b], "bitrev not a permutation for {nfft}");
                seen[b] = true;
            }
        }
    }

    #[test]
    fn build_rejects_unfactorable() {
        // A prime > 5 cannot be factored into radices 2/3/4/5.
        assert_eq!(FftState::new(7).unwrap_err(), MdctError::Unfactorable);
        assert_eq!(FftState::new(11).unwrap_err(), MdctError::Unfactorable);
    }

    // ---- IMDCT validated against the libopus reference (task requirement (b)) ----
    //
    // This mirrors libopus' own celt/tests/test_unit_mdct.c `check_inv`:
    //   window = all ones, overlap = nfft/2,
    //   clt_mdct_backward(cfg, in, out, window, nfft/2, shift, 1),
    //   then manual TDAC: out[nfft-1-k] = out[nfft/2+k] for k in 0..nfft/4,
    //   reference: out[bin] = sum_{k<nfft/2} in[k]
    //                * cos(2*pi*(bin + 0.5 + nfft/4)*(k + 0.5)/nfft),
    //   require SNR > 60 dB.
    //
    // NOTE on the cosine offsets: the internal MDCT trig table uses (i + 0.125),
    // but the *overall* analytic IMDCT basis is the standard MDCT cosine with
    // (k + 0.5) and (bin + 0.5 + nfft/4) — the 1/8 offset is an internal
    // artifact that cancels across the pre/FFT/post rotation. This (k+0.5)
    // basis is libopus' own reference; do not "fix" it to (k+1/8).

    /// Reference inverse MDCT — the exact transpose libopus validates against.
    fn reference_imdct(input: &[f32], nfft: usize) -> Vec<f64> {
        let n2 = nfft / 2;
        (0..nfft)
            .map(|bin| {
                let mut acc = 0.0_f64;
                for (k, &x) in input.iter().take(n2).enumerate() {
                    let phase =
                        2.0 * PI * (bin as f64 + 0.5 + 0.25 * nfft as f64) * (k as f64 + 0.5)
                            / nfft as f64;
                    acc += x as f64 * phase.cos();
                }
                acc
            })
            .collect()
    }

    fn imdct_snr_for_shift(lookup: &MdctLookup, shift: usize, seed: u32) -> f64 {
        let nfft = lookup.n() >> shift;
        let n2 = nfft / 2;
        let overlap = nfft / 2;
        let window = vec![1.0f32; overlap];

        let mut rng = Lcg(seed);
        // Match the test's input magnitude range (~[-16384, 16384)).
        let input: Vec<f32> = (0..n2).map(|_| rng.next_f32() * 32768.0).collect();

        // Output buffer length nfft: backward writes out[0 .. 3*nfft/4],
        // the manual TDAC fills out[3*nfft/4 .. nfft].
        let mut out = vec![0.0f32; nfft];
        clt_mdct_backward(lookup, &input, &mut out, &window, overlap, shift, 1);
        for k in 0..(nfft / 4) {
            out[nfft - k - 1] = out[nfft / 2 + k];
        }

        let want = reference_imdct(&input, nfft);
        let mut errpow = 0.0_f64;
        let mut sigpow = 0.0_f64;
        for (bin, &g) in out.iter().enumerate() {
            let d = want[bin] - g as f64;
            errpow += d * d;
            sigpow += want[bin] * want[bin];
        }
        10.0 * (sigpow / errpow.max(1e-300)).log10()
    }

    #[test]
    fn imdct_matches_libopus_reference_all_lm() {
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build 48k mode");
        for shift in 0..=MAX_SHIFT {
            let seed = 0x00C0_FFEEu32 ^ (shift as u32).wrapping_mul(2_654_435_761);
            let snr = imdct_snr_for_shift(&lookup, shift, seed);
            let nfft = N_BASE >> shift;
            // libopus gate is 60 dB; f32 gives ~138 dB here. Use a strict 100 dB
            // floor so a real sign/phase bug (which collapses SNR to ~0 dB)
            // can never sneak through.
            assert!(
                snr > 100.0,
                "shift={shift} (nfft={nfft}): IMDCT SNR {snr:.2} dB below 100 dB floor"
            );
        }
    }

    #[test]
    fn imdct_reference_basis_is_exact_for_impulse() {
        // A single nonzero MDCT coefficient must reproduce one cosine basis
        // vector exactly (post manual-TDAC). This pins the basis offsets
        // (k+0.5), (bin+0.5+nfft/4) directly, not just statistically.
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build");
        let shift = 3usize;
        let nfft = N_BASE >> shift; // 240
        let n2 = nfft / 2;
        let overlap = nfft / 2;
        let window = vec![1.0f32; overlap];

        for bin_in in [0usize, 1, 5, n2 / 2, n2 - 1] {
            let mut input = vec![0.0f32; n2];
            input[bin_in] = 1.0;
            let mut out = vec![0.0f32; nfft];
            clt_mdct_backward(&lookup, &input, &mut out, &window, overlap, shift, 1);
            for k in 0..(nfft / 4) {
                out[nfft - k - 1] = out[nfft / 2 + k];
            }
            let want = reference_imdct(&input, nfft);
            let mut max_diff = 0.0_f64;
            for (bin, &g) in out.iter().enumerate() {
                max_diff = max_diff.max((want[bin] - g as f64).abs());
            }
            assert!(
                max_diff < 1e-3,
                "bin_in={bin_in}: impulse IMDCT vs reference cosine max diff {max_diff}"
            );
        }
    }

    #[test]
    fn imdct_stride_matches_per_block() {
        // The decoder interleaves B short blocks: block `b` reads input with
        // stride B starting at offset b, and writes a contiguous output. Verify
        // a stride-B run reproduces the stride-1 result for each de-interleaved
        // block, bit-for-bit (same arithmetic, just a different read stride).
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build");
        let shift = 2usize;
        let nfft = N_BASE >> shift; // 480
        let n2 = nfft / 2;
        let overlap = nfft / 2;
        let window = vec![1.0f32; overlap];
        let b = 2usize;

        let mut rng = Lcg(999);
        let coeffs: Vec<Vec<f32>> = (0..b)
            .map(|_| (0..n2).map(|_| rng.next_f32() * 32768.0).collect())
            .collect();

        // Interleave: inter_in[i*B + block] = coeffs[block][i].
        let mut inter_in = vec![0.0f32; n2 * b];
        for (block, blk) in coeffs.iter().enumerate() {
            for (i, &c) in blk.iter().enumerate() {
                inter_in[i * b + block] = c;
            }
        }

        for (block, blk) in coeffs.iter().enumerate() {
            let mut ref_out = vec![0.0f32; nfft];
            clt_mdct_backward(&lookup, blk, &mut ref_out, &window, overlap, shift, 1);

            let mut got = vec![0.0f32; nfft];
            clt_mdct_backward(
                &lookup,
                &inter_in[block..],
                &mut got,
                &window,
                overlap,
                shift,
                b,
            );

            for (j, (&a, &c)) in ref_out.iter().zip(got.iter()).enumerate() {
                assert!(
                    (a - c).abs() < 1e-3,
                    "block={block} j={j}: stride-{b} {c} != stride-1 {a}"
                );
            }
        }
    }

    #[test]
    fn imdct_is_linear() {
        // L(a*x + b*y) == a*L(x) + b*L(y): a structural property the transform
        // must satisfy; cheap and catches accidental nonlinearity.
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build");
        let shift = 3usize;
        let nfft = N_BASE >> shift;
        let n2 = nfft / 2;
        let overlap = nfft / 2;
        let window = vec![1.0f32; overlap];

        let mut rng = Lcg(0xABCD);
        let x: Vec<f32> = (0..n2).map(|_| rng.next_f32()).collect();
        let y: Vec<f32> = (0..n2).map(|_| rng.next_f32()).collect();
        let (alpha, beta) = (1.5f32, -0.75f32);
        let combo: Vec<f32> = x
            .iter()
            .zip(y.iter())
            .map(|(&a, &b)| alpha * a + beta * b)
            .collect();

        let run = |inp: &[f32]| {
            let mut o = vec![0.0f32; nfft];
            clt_mdct_backward(&lookup, inp, &mut o, &window, overlap, shift, 1);
            o
        };
        let ox = run(&x);
        let oy = run(&y);
        let oc = run(&combo);
        for j in 0..nfft {
            let lhs = oc[j];
            let rhs = alpha * ox[j] + beta * oy[j];
            assert!(
                (lhs - rhs).abs() < 1e-2,
                "nonlinear at j={j}: {lhs} != {rhs}"
            );
        }
    }

    // ---- forward MDCT validated against the libopus reference basis ----
    //
    // Mirrors libopus' own `celt/tests/test_unit_mdct.c` `check()` (the forward half):
    //   window = all ones, overlap = nfft/2, input length nfft,
    //   clt_mdct_forward(cfg, in, out, window, nfft/2, shift, 1),
    //   reference: out[bin] = sum_{k<nfft} in[k]
    //                * cos(2*pi*(k + 0.5 + nfft/4)*(bin + 0.5)/nfft) / (nfft/4),
    //   require SNR > 60 dB.

    /// Reference forward MDCT — the exact basis libopus validates against
    /// (`test_unit_mdct.c` `check`), including its `1/(nfft/4)` normalisation.
    fn reference_mdct(input: &[f32], nfft: usize) -> Vec<f64> {
        (0..nfft / 2)
            .map(|bin| {
                let mut acc = 0.0_f64;
                for (k, &x) in input.iter().take(nfft).enumerate() {
                    let phase =
                        2.0 * PI * (k as f64 + 0.5 + 0.25 * nfft as f64) * (bin as f64 + 0.5)
                            / nfft as f64;
                    acc += x as f64 * phase.cos() / (nfft as f64 / 4.0);
                }
                acc
            })
            .collect()
    }

    fn mdct_snr_for_shift(lookup: &MdctLookup, shift: usize, seed: u32) -> f64 {
        let nfft = lookup.n() >> shift;
        let overlap = nfft / 2;
        let window = vec![1.0f32; overlap];

        let mut rng = Lcg(seed);
        let input: Vec<f32> = (0..nfft).map(|_| rng.next_f32() * 32768.0).collect();

        let mut out = vec![0.0f32; nfft / 2];
        clt_mdct_forward(lookup, &input, &mut out, &window, overlap, shift, 1);

        let want = reference_mdct(&input, nfft);
        let mut errpow = 0.0_f64;
        let mut sigpow = 0.0_f64;
        for (bin, &g) in out.iter().enumerate() {
            let d = want[bin] - g as f64;
            errpow += d * d;
            sigpow += want[bin] * want[bin];
        }
        10.0 * (sigpow / errpow.max(1e-300)).log10()
    }

    #[test]
    fn mdct_forward_matches_libopus_reference_all_lm() {
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build 48k mode");
        for shift in 0..=MAX_SHIFT {
            let seed = 0x0BAD_F00Du32 ^ (shift as u32).wrapping_mul(2_654_435_761);
            let snr = mdct_snr_for_shift(&lookup, shift, seed);
            let nfft = N_BASE >> shift;
            // libopus gate is 60 dB; f32 reaches ~130 dB. A strict 100 dB floor so any real
            // sign/phase/scale bug (which collapses SNR toward 0 dB) cannot slip through.
            assert!(
                snr > 100.0,
                "shift={shift} (nfft={nfft}): forward MDCT SNR {snr:.2} dB below 100 dB floor"
            );
        }
    }

    #[test]
    fn mdct_forward_basis_is_exact_for_impulse() {
        // A single nonzero time sample must produce exactly one column of the analysis basis.
        // This pins the fold offsets and the 1/nfft scale directly, not statistically.
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build");
        let shift = 3usize;
        let nfft = N_BASE >> shift; // 240
        let overlap = nfft / 2;
        let window = vec![1.0f32; overlap];

        for k_in in [0usize, 1, 37, nfft / 2, nfft - 1] {
            let mut input = vec![0.0f32; nfft];
            input[k_in] = 1000.0;
            let mut out = vec![0.0f32; nfft / 2];
            clt_mdct_forward(&lookup, &input, &mut out, &window, overlap, shift, 1);
            let want = reference_mdct(&input, nfft);
            let mut max_diff = 0.0_f64;
            for (bin, &g) in out.iter().enumerate() {
                max_diff = max_diff.max((want[bin] - g as f64).abs());
            }
            assert!(
                max_diff < 1e-2,
                "k_in={k_in}: impulse forward MDCT vs reference cosine max diff {max_diff}"
            );
        }
    }

    /// Forward → inverse over two consecutive 50 %-overlapping frames must reconstruct the middle
    /// frame (time-domain alias cancellation). Uses the real CELT window, which satisfies the
    /// Princen-Bradley condition, so this is the property the codec actually relies on.
    #[test]
    fn mdct_forward_then_backward_reconstructs_via_tdac() {
        use crate::opus::celt::tables::WINDOW120;
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build");
        let shift = 0usize; // long 20 ms block: mdct N = 1920, frame = 960
        let n = N_BASE >> shift;
        let n2 = n >> 1; // 960 samples per frame
        let overlap = 120usize;

        // Three frames of signal so the middle one has both neighbours.
        let total = 3 * n2 + overlap;
        let mut rng = Lcg(0x5EED);
        let signal: Vec<f32> = (0..total).map(|_| rng.next_f32() * 8000.0).collect();

        // Analyse frames 0 and 1 (each reads n2 + overlap samples starting at frame*n2).
        let analyse = |offset: usize| {
            let mut coeffs = vec![0.0f32; n2];
            clt_mdct_forward(
                &lookup,
                &signal[offset..],
                &mut coeffs,
                &WINDOW120,
                overlap,
                shift,
                1,
            );
            coeffs
        };
        let c0 = analyse(0);
        let c1 = analyse(n2);

        // Synthesise with overlap-add: each backward MDCT writes overlap/2 + n2/2 samples and
        // adds into the preserved tail, exactly as `celt_synthesis` does through the decode ring.
        let mut ring = vec![0.0f32; 2 * n2 + overlap];
        clt_mdct_backward(&lookup, &c0, &mut ring, &WINDOW120, overlap, shift, 1);
        // Mirror-fold the second half of block 0 (TDAC), which the decoder's ring gets for free
        // from the next block's front overlap.
        for k in 0..(n / 4) {
            ring[n - k - 1] = ring[n / 2 + k];
        }
        let mut ring2 = vec![0.0f32; 2 * n2 + overlap];
        ring2[..overlap / 2].copy_from_slice(&ring[n2..n2 + overlap / 2]);
        clt_mdct_backward(&lookup, &c1, &mut ring2, &WINDOW120, overlap, shift, 1);

        // The reconstructed region is ring2[overlap/2 .. n2] plus the previous block's tail; the
        // core (well away from the block edges) must match the input scaled by the MDCT gain.
        // clt_mdct_forward normalises by 1/nfft and the reference basis by 1/(nfft/4), so the
        // round trip gain is nfft/4 / (nfft/2) ... rather than derive it, measure it once from
        // the middle sample and require the whole core to follow the same single scale factor.
        let probe = 400usize;
        let gain = ring2[probe] / signal[n2 + probe];
        assert!(
            gain.is_finite() && gain.abs() > 1e-6,
            "degenerate gain {gain}"
        );
        let mut errpow = 0.0f64;
        let mut sigpow = 0.0f64;
        for j in overlap..n2 {
            let want = signal[n2 + j] * gain;
            let d = f64::from(ring2[j] - want);
            errpow += d * d;
            sigpow += f64::from(want) * f64::from(want);
        }
        let snr = 10.0 * (sigpow / errpow.max(1e-300)).log10();
        assert!(
            snr > 80.0,
            "TDAC reconstruction SNR {snr:.2} dB below 80 dB"
        );
    }

    #[test]
    fn mdct_forward_stride_matches_per_block() {
        // The encoder interleaves B short blocks into one output with stride B; each block reads
        // its own contiguous input slice. A stride-B run must reproduce the stride-1 result.
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build");
        let shift = 2usize;
        let nfft = N_BASE >> shift; // 480
        let n2 = nfft / 2;
        let overlap = nfft / 2;
        let window = vec![1.0f32; overlap];
        let b = 2usize;

        let mut rng = Lcg(4242);
        let blocks: Vec<Vec<f32>> = (0..b)
            .map(|_| (0..nfft).map(|_| rng.next_f32() * 32768.0).collect())
            .collect();

        let mut interleaved = vec![0.0f32; b * n2];
        for (block, blk) in blocks.iter().enumerate() {
            clt_mdct_forward(
                &lookup,
                blk,
                &mut interleaved[block..],
                &window,
                overlap,
                shift,
                b,
            );
        }
        for (block, blk) in blocks.iter().enumerate() {
            let mut want = vec![0.0f32; n2];
            clt_mdct_forward(&lookup, blk, &mut want, &window, overlap, shift, 1);
            for (i, &w) in want.iter().enumerate() {
                let got = interleaved[i * b + block];
                assert!(
                    (got - w).abs() < 1e-4,
                    "block={block} i={i}: stride-{b} {got} != stride-1 {w}"
                );
            }
        }
    }

    #[test]
    fn build_48k_mode_tables_have_expected_sizes() {
        let lookup = MdctLookup::new(N_BASE, MAX_SHIFT).expect("build");
        assert_eq!(lookup.n(), 1920);
        assert_eq!(lookup.max_shift(), 3);
        // Per-shift FFT sizes must be 480/240/120/60 (= (N>>shift)/4).
        for shift in 0..=MAX_SHIFT {
            let expect = (1920usize >> shift) / 4;
            assert_eq!(lookup.kfft[shift].nfft, expect, "shift {shift} N4");
            assert_eq!(lookup.trig[shift].len(), (1920usize >> shift) / 2);
        }
    }
}
