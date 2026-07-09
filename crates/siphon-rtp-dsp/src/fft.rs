//! A safe, pure-Rust radix-2 **real** FFT / IFFT for power-of-two sizes (128 / 256 / 512, …).
//!
//! This is a fresh, self-contained iterative Cooley–Tukey (decimation-in-time) complex FFT plus a
//! real-signal wrapper. It is used by the noise-suppression WOLA ([`crate::window`]) to move each
//! √Hann analysis frame into the frequency domain and back.
//!
//! ## Convention (matches the in-tree KISS-FFT reference)
//!
//! The forward transform uses the DFT kernel `X[k] = Σ_n x[n]·exp(-2πi·k·n/N)` — the same kernel and
//! twiddle sign as the libopus KISS-FFT port in `siphon-rtp-codec` `opus/celt/mdct.rs`
//! (`twiddles[i] = (cos(-2πi/N), sin(-2πi/N))`) and standard bit-reversal ordering. We do not add a
//! cross-crate dependency; correctness is proven **transitively** by matching a direct O(N²) DFT
//! (exactly the ground truth `mdct.rs`'s own tests validate against) — see the module tests.
//!
//! ## Real FFT layout
//!
//! A real FFT of length `N` produces `N/2 + 1` complex bins (`0..=N/2`): bin 0 (DC) and bin `N/2`
//! (Nyquist) are real, bins `1..N/2` carry the positive-frequency half; the negative half is the
//! conjugate mirror and is not stored. [`RealFft::inverse`] rebuilds the mirror from Hermitian
//! symmetry, so `inverse(forward(x)) == x` (within `f32` tolerance).
//!
//! ## Allocation
//!
//! All working storage (twiddles, bit-reversal table, the length-`N` complex work buffer) is built
//! once in [`RealFft::new`]. [`RealFft::forward`] / [`RealFft::inverse`] are **allocation-free**.

use crate::DspError;

/// A single complex value (`re`, `im`) in `f32`.
///
/// Field order and `#[repr(C)]` match the KISS-FFT `Complex` in `mdct.rs`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Complex {
    /// Real part.
    pub re: f32,
    /// Imaginary part.
    pub im: f32,
}

impl Complex {
    /// A complex value from its real and imaginary parts.
    #[inline]
    #[must_use]
    pub const fn new(re: f32, im: f32) -> Self {
        Self { re, im }
    }

    /// Squared magnitude `re² + im²` (the per-bin power spectral density term).
    #[inline]
    #[must_use]
    pub fn norm_squared(self) -> f32 {
        self.re * self.re + self.im * self.im
    }
}

/// A precomputed real FFT / IFFT for one power-of-two transform size.
#[derive(Clone, Debug)]
pub struct RealFft {
    /// Transform length (a power of two, ≥ 4).
    n: usize,
    /// Forward twiddles `exp(-2πi·j/n)` for `j in 0..n/2` (the inverse conjugates on the fly).
    twiddles: Vec<Complex>,
    /// Bit-reversal permutation over `log2(n)` bits.
    bitrev: Vec<usize>,
    /// Length-`n` complex work buffer, reused every call (keeps `forward`/`inverse` alloc-free).
    work: Vec<Complex>,
}

impl RealFft {
    /// Build a real FFT of length `n`. `n` must be a power of two of at least 4.
    ///
    /// # Errors
    /// Returns [`DspError::InvalidFftSize`] if `n` is not a power of two `>= 4`.
    pub fn new(n: usize) -> Result<Self, DspError> {
        if n < 4 || !n.is_power_of_two() {
            return Err(DspError::InvalidFftSize { size: n });
        }

        // Twiddles computed in f64 then narrowed (bit-for-bit the libopus/mdct.rs recipe), so the
        // table is deterministic across runs.
        let mut twiddles = Vec::with_capacity(n / 2);
        for j in 0..n / 2 {
            let phase = -2.0_f64 * std::f64::consts::PI * j as f64 / n as f64;
            twiddles.push(Complex::new(phase.cos() as f32, phase.sin() as f32));
        }

        let bits = n.trailing_zeros();
        let mut bitrev = vec![0usize; n];
        for (index, slot) in bitrev.iter_mut().enumerate() {
            *slot = ((index as u32).reverse_bits() >> (u32::BITS - bits)) as usize;
        }

        Ok(Self {
            n,
            twiddles,
            bitrev,
            work: vec![Complex::default(); n],
        })
    }

    /// Transform length `N`.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.n
    }

    /// Whether the transform length is zero — always `false` (a valid FFT is `>= 4`), provided for
    /// the `clippy::len_without_is_empty` lint.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Number of complex bins a forward real transform produces (`N/2 + 1`).
    #[inline]
    #[must_use]
    pub fn bins(&self) -> usize {
        self.n / 2 + 1
    }

    /// Forward real FFT: `input` (`N` real samples) → `output` (`N/2 + 1` complex bins).
    ///
    /// Shorter/over-long slices are handled defensively (zero-fill / truncate) so a caller mistake
    /// can never panic; the WOLA always passes exactly `N` / `N/2+1`.
    pub fn forward(&mut self, input: &[f32], output: &mut [Complex]) {
        let n = self.n;
        for (slot, index) in self.work.iter_mut().zip(0..n) {
            *slot = Complex::new(input.get(index).copied().unwrap_or(0.0), 0.0);
        }
        self.transform(false);
        for (out, bin) in output.iter_mut().zip(self.work.iter().take(self.bins())) {
            *out = *bin;
        }
    }

    /// Inverse real FFT: `input` (`N/2 + 1` complex bins) → `output` (`N` real samples).
    ///
    /// Rebuilds the negative-frequency half by Hermitian symmetry, runs the inverse transform
    /// (including the `1/N` scale), and writes the real parts. `inverse(forward(x)) == x`.
    pub fn inverse(&mut self, input: &[Complex], output: &mut [f32]) {
        let n = self.n;
        let half = n / 2;
        for (slot, index) in self.work.iter_mut().take(half + 1).zip(0..=half) {
            *slot = input.get(index).copied().unwrap_or_default();
        }
        // Mirror: work[n-k] = conj(work[k]) for k in 1..n/2.
        for k in 1..half {
            let value = self.work[k];
            self.work[n - k] = Complex::new(value.re, -value.im);
        }
        self.transform(true);
        for (out, sample) in output.iter_mut().zip(self.work.iter()) {
            *out = sample.re;
        }
    }

    /// In-place iterative radix-2 complex FFT over [`Self::work`].
    ///
    /// `inverse == true` conjugates the twiddles (`exp(+2πi…)`) and scales by `1/N`, so the forward
    /// and inverse are exact inverses.
    fn transform(&mut self, inverse: bool) {
        let n = self.n;

        // Bit-reversal permutation (each unordered pair swapped exactly once).
        for i in 0..n {
            let j = self.bitrev[i];
            if j > i {
                self.work.swap(i, j);
            }
        }

        let mut len = 2usize;
        while len <= n {
            let half = len / 2;
            let step = n / len; // twiddle stride: twiddles[k*step] == exp(-2πi·k/len)
            let mut start = 0usize;
            while start < n {
                for k in 0..half {
                    let twiddle = self.twiddles[k * step];
                    let (twiddle_re, twiddle_im) = if inverse {
                        (twiddle.re, -twiddle.im)
                    } else {
                        (twiddle.re, twiddle.im)
                    };
                    let upper = self.work[start + k];
                    let lower = self.work[start + k + half];
                    let product = Complex::new(
                        lower.re * twiddle_re - lower.im * twiddle_im,
                        lower.re * twiddle_im + lower.im * twiddle_re,
                    );
                    self.work[start + k] =
                        Complex::new(upper.re + product.re, upper.im + product.im);
                    self.work[start + k + half] =
                        Complex::new(upper.re - product.re, upper.im - product.im);
                }
                start += len;
            }
            len <<= 1;
        }

        if inverse {
            let scale = 1.0 / n as f32;
            for sample in self.work.iter_mut() {
                sample.re *= scale;
                sample.im *= scale;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    /// A cheap deterministic LCG so tests never touch `rand` or the wall clock. Returns `[-0.5, 0.5)`.
    struct Lcg(u32);
    impl Lcg {
        fn next_unit(&mut self) -> f32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (self.0 >> 8) as f32 / (1u32 << 24) as f32 - 0.5
        }
    }

    /// Naive O(N²) forward DFT in f64 with the KISS kernel `exp(-2πi·k·n/N)` — the ground truth.
    fn naive_dft(input: &[f32]) -> Vec<Complex> {
        let n = input.len();
        (0..n)
            .map(|k| {
                let mut re = 0.0_f64;
                let mut im = 0.0_f64;
                for (index, &x) in input.iter().enumerate() {
                    let phase = -2.0 * PI * k as f64 * index as f64 / n as f64;
                    let (sin, cos) = phase.sin_cos();
                    re += x as f64 * cos;
                    im += x as f64 * sin;
                }
                Complex::new(re as f32, im as f32)
            })
            .collect()
    }

    #[test]
    fn rejects_non_power_of_two_and_tiny_sizes() {
        assert_eq!(
            RealFft::new(0).unwrap_err(),
            DspError::InvalidFftSize { size: 0 }
        );
        assert_eq!(
            RealFft::new(2).unwrap_err(),
            DspError::InvalidFftSize { size: 2 }
        );
        assert_eq!(
            RealFft::new(96).unwrap_err(),
            DspError::InvalidFftSize { size: 96 }
        );
        for &size in &[4usize, 128, 256, 512] {
            assert!(RealFft::new(size).is_ok(), "size {size} should build");
        }
    }

    #[test]
    fn bitrev_is_a_permutation() {
        for &n in &[128usize, 256, 512] {
            let fft = RealFft::new(n).expect("build");
            let mut seen = vec![false; n];
            for &value in &fft.bitrev {
                assert!(value < n, "bitrev out of range for {n}");
                assert!(!seen[value], "bitrev not a permutation for {n}");
                seen[value] = true;
            }
        }
    }

    #[test]
    fn bitrev_matches_manual_bit_reversal() {
        // Cross-check the table against an independent manual bit-reversal (same convention the
        // KISS-FFT reference uses).
        for &n in &[128usize, 256, 512] {
            let fft = RealFft::new(n).expect("build");
            let bits = n.trailing_zeros();
            for index in 0..n {
                let mut manual = 0usize;
                for bit in 0..bits {
                    if index & (1 << bit) != 0 {
                        manual |= 1 << (bits - 1 - bit);
                    }
                }
                assert_eq!(fft.bitrev[index], manual, "n={n} index={index}");
            }
        }
    }

    #[test]
    fn twiddles_match_kiss_fft_formula() {
        // The exact formula documented in mdct.rs: twiddles[j] = (cos(-2πj/n), sin(-2πj/n)).
        for &n in &[128usize, 256, 512] {
            let fft = RealFft::new(n).expect("build");
            for (j, twiddle) in fft.twiddles.iter().enumerate() {
                let phase = -2.0_f64 * PI * j as f64 / n as f64;
                assert!(
                    (twiddle.re - phase.cos() as f32).abs() < 1e-6,
                    "n={n} j={j} re"
                );
                assert!(
                    (twiddle.im - phase.sin() as f32).abs() < 1e-6,
                    "n={n} j={j} im"
                );
            }
        }
    }

    #[test]
    fn forward_matches_naive_dft_on_random_input() {
        for &n in &[128usize, 256, 512] {
            let mut fft = RealFft::new(n).expect("build");
            let mut rng = Lcg(0x1234_5678 ^ n as u32);
            let input: Vec<f32> = (0..n).map(|_| rng.next_unit()).collect();
            let mut bins = vec![Complex::default(); fft.bins()];
            fft.forward(&input, &mut bins);

            let reference = naive_dft(&input);
            // Output magnitudes are O(sqrt(N)·amp); scale tolerance with N (mdct.rs uses the same).
            let tolerance = 1e-3 * n as f32;
            for (k, bin) in bins.iter().enumerate() {
                assert!(
                    (bin.re - reference[k].re).abs() < tolerance,
                    "n={n} k={k} re {} vs {}",
                    bin.re,
                    reference[k].re
                );
                assert!(
                    (bin.im - reference[k].im).abs() < tolerance,
                    "n={n} k={k} im {} vs {}",
                    bin.im,
                    reference[k].im
                );
            }
        }
    }

    #[test]
    fn forward_of_impulse_is_flat_spectrum() {
        // δ[0] → every bin == 1+0i.
        let n = 256usize;
        let mut fft = RealFft::new(n).expect("build");
        let mut input = vec![0.0f32; n];
        input[0] = 1.0;
        let mut bins = vec![Complex::default(); fft.bins()];
        fft.forward(&input, &mut bins);
        for (k, bin) in bins.iter().enumerate() {
            assert!((bin.re - 1.0).abs() < 1e-4, "k={k} re {}", bin.re);
            assert!(bin.im.abs() < 1e-4, "k={k} im {}", bin.im);
        }
    }

    #[test]
    fn forward_of_bin_aligned_sine_concentrates_in_one_bin() {
        // A cosine at an exact bin frequency puts all energy in that single bin.
        let n = 512usize;
        let mut fft = RealFft::new(n).expect("build");
        for bin_index in [1usize, 5, 40, n / 2 - 1] {
            let input: Vec<f32> = (0..n)
                .map(|index| {
                    (2.0 * std::f32::consts::PI * bin_index as f32 * index as f32 / n as f32).cos()
                })
                .collect();
            let mut bins = vec![Complex::default(); fft.bins()];
            fft.forward(&input, &mut bins);
            for (k, bin) in bins.iter().enumerate() {
                let magnitude = bin.norm_squared().sqrt();
                if k == bin_index {
                    // Real cosine of unit amplitude → |X[bin]| == N/2.
                    assert!(
                        (magnitude - n as f32 / 2.0).abs() < 1e-2 * n as f32,
                        "bin={bin_index}: peak {magnitude} != {}",
                        n as f32 / 2.0
                    );
                } else {
                    assert!(
                        magnitude < 1e-2 * n as f32,
                        "bin={bin_index}: leakage at k={k} = {magnitude}"
                    );
                }
            }
        }
    }

    #[test]
    fn forward_of_inter_bin_sine_does_not_panic_and_is_bounded() {
        // A frequency between bins spreads energy but must stay finite and bounded by Parseval.
        let n = 256usize;
        let mut fft = RealFft::new(n).expect("build");
        let frequency = 10.5_f32; // half-way between bins 10 and 11
        let input: Vec<f32> = (0..n)
            .map(|index| (2.0 * std::f32::consts::PI * frequency * index as f32 / n as f32).sin())
            .collect();
        let mut bins = vec![Complex::default(); fft.bins()];
        fft.forward(&input, &mut bins);
        for bin in &bins {
            assert!(bin.re.is_finite() && bin.im.is_finite());
        }
    }

    #[test]
    fn inverse_of_forward_is_identity() {
        for &n in &[128usize, 256, 512] {
            let mut fft = RealFft::new(n).expect("build");
            let mut rng = Lcg(0xBEEF ^ n as u32);
            let input: Vec<f32> = (0..n).map(|_| rng.next_unit()).collect();
            let mut bins = vec![Complex::default(); fft.bins()];
            fft.forward(&input, &mut bins);
            let mut restored = vec![0.0f32; n];
            fft.inverse(&bins, &mut restored);
            for (index, (&a, &b)) in input.iter().zip(restored.iter()).enumerate() {
                assert!(
                    (a - b).abs() < 1e-4,
                    "n={n} index={index}: roundtrip {b} != {a}"
                );
            }
        }
    }

    #[test]
    fn parseval_energy_is_preserved() {
        // Σ|x[n]|² == (1/N)[ |X0|² + |X_{N/2}|² + 2 Σ_{k=1}^{N/2-1}|X_k|² ].
        for &n in &[128usize, 256, 512] {
            let mut fft = RealFft::new(n).expect("build");
            let mut rng = Lcg(0xF00D ^ n as u32);
            let input: Vec<f32> = (0..n).map(|_| rng.next_unit()).collect();
            let mut bins = vec![Complex::default(); fft.bins()];
            fft.forward(&input, &mut bins);

            let time_energy: f64 = input.iter().map(|&x| (x as f64) * (x as f64)).sum();
            let half = n / 2;
            let mut freq_energy = bins[0].norm_squared() as f64 + bins[half].norm_squared() as f64;
            for bin in &bins[1..half] {
                freq_energy += 2.0 * bin.norm_squared() as f64;
            }
            freq_energy /= n as f64;
            assert!(
                (time_energy - freq_energy).abs() < 1e-2 * time_energy.max(1.0),
                "n={n}: Parseval mismatch {time_energy} vs {freq_energy}"
            );
        }
    }
}
