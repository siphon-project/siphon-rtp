//! CELT recursive band decode (RFC 6716 §4.3.4; libopus `bands.c`, float decoder path).
//!
//! **Phase 3f (core).** The heart of CELT band decoding: [`compute_theta`] decodes the mid/side (or
//! time-) split angle, and [`quant_partition`] recursively splits a band in half (coding the energy
//! split with `theta`) down to leaves where [`alg_unquant`](crate::opus::celt::vq::alg_unquant)
//! decodes the PVQ shape (or noise/folding fills an empty band). [`quant_band_n1`] handles the
//! single-coefficient case. These drive bits out of the shared [`BandCtx`] budget; the wrappers
//! (`quant_band`/`quant_all_bands`) sit above and orchestrate tf-resolution + the per-band loop.

use crate::opus::celt::bands::{
    bitexact_cos, bitexact_log2tan, compute_qn, deinterleave_hadamard, frac_mul16, haar1,
    interleave_hadamard, isqrt32,
};
use crate::opus::celt::rate::{bits2pulses, cache_max_bits, get_pulses, pulses2bits};
use crate::opus::celt::synthesis::celt_lcg_rand;
use crate::opus::celt::tables::{E_BANDS, LOG_N, NB_BANDS, SPREAD_AGGRESSIVE};
use crate::opus::celt::vq::{alg_unquant, renormalise_vector};
use crate::opus::range_coder::RangeDecoder;

const BITRES: i32 = 3;
const QTHETA_OFFSET: i32 = 4;
const QTHETA_OFFSET_TWOPHASE: i32 = 16;
/// Largest band dimension (scratch size) — 48 kHz max is 176.
const MAX_BAND: usize = 256;

/// Shared per-band decode context (libopus `band_ctx`, decoder-relevant fields). `resynth` is always
/// true for a decoder, so it's implicit.
pub struct BandCtx {
    /// Current band index `i`.
    pub band: usize,
    /// First band coded with intensity stereo.
    pub intensity: usize,
    /// PVQ spreading parameter.
    pub spread: u32,
    /// Per-band time-frequency change flag.
    pub tf_change: i32,
    /// Bits left in the frame budget (1/8-bit units); drawn down as bands decode.
    pub remaining_bits: i32,
    /// Anti-collapse / fold PRNG state (carried across bands and frames).
    pub seed: u32,
    /// Disable the stereo inversion flag (downmix safety).
    pub disable_inv: bool,
}

/// The decoded mid/side split decision (libopus `split_ctx`).
#[derive(Default)]
struct SplitCtx {
    inv: bool,
    imid: i32,
    iside: i32,
    delta: i32,
    itheta: i32,
    qalloc: i32,
}

/// Decode the split angle `theta` and derive the mid/side gains + bit-split `delta` (libopus
/// `compute_theta`, decoder path). Consumes bits from `*b` and may mask `*fill`.
#[allow(clippy::too_many_arguments)]
fn compute_theta(
    ctx: &BandCtx,
    sctx: &mut SplitCtx,
    n: usize,
    b: &mut i32,
    big_b: usize,
    b0: usize,
    lm: i32,
    stereo: bool,
    fill: &mut i32,
    dec: &mut RangeDecoder,
) {
    let pulse_cap = i32::from(LOG_N[ctx.band]) + lm * (1 << BITRES);
    let offset = (pulse_cap >> 1)
        - if stereo && n == 2 {
            QTHETA_OFFSET_TWOPHASE
        } else {
            QTHETA_OFFSET
        };
    let mut qn = compute_qn(n as i32, *b, offset, pulse_cap, stereo);
    if stereo && ctx.band >= ctx.intensity {
        qn = 1;
    }
    let tell = dec.tell_frac() as i32;
    let mut inv = false;
    let mut itheta = 0i32;
    if qn != 1 {
        // Decode the angle: a step pdf for stereo, uniform for a time split, triangular otherwise.
        if stereo && n > 2 {
            let p0 = 3i32;
            let x0 = qn / 2;
            let ft = p0 * (x0 + 1) + x0;
            let fs = dec.decode(ft as u32) as i32;
            let x = if fs < (x0 + 1) * p0 {
                fs / p0
            } else {
                x0 + 1 + (fs - (x0 + 1) * p0)
            };
            let (fl, fh) = if x <= x0 {
                (p0 * x, p0 * (x + 1))
            } else {
                ((x - 1 - x0) + (x0 + 1) * p0, (x - x0) + (x0 + 1) * p0)
            };
            dec.dec_update(fl as u32, fh as u32, ft as u32);
            itheta = x;
        } else if b0 > 1 || stereo {
            itheta = dec.dec_uint((qn + 1) as u32) as i32;
        } else {
            let ft = ((qn >> 1) + 1) * ((qn >> 1) + 1);
            let fm = dec.decode(ft as u32) as i32;
            let (fl, fs);
            if fm < (((qn >> 1) * ((qn >> 1) + 1)) >> 1) {
                itheta = ((isqrt32((8 * fm + 1) as u32) as i32) - 1) >> 1;
                fs = itheta + 1;
                fl = (itheta * (itheta + 1)) >> 1;
            } else {
                itheta = (2 * (qn + 1) - (isqrt32((8 * (ft - fm - 1) + 1) as u32) as i32)) >> 1;
                fs = qn + 1 - itheta;
                fl = ft - (((qn + 1 - itheta) * (qn + 2 - itheta)) >> 1);
            }
            dec.dec_update(fl as u32, (fl + fs) as u32, ft as u32);
        }
        itheta = (itheta * 16384) / qn;
    } else if stereo {
        if *b > 2 << BITRES && ctx.remaining_bits > 2 << BITRES {
            inv = dec.dec_bit_logp(2);
        }
        if ctx.disable_inv {
            inv = false;
        }
        itheta = 0;
    }
    let qalloc = dec.tell_frac() as i32 - tell;
    *b -= qalloc;

    let (imid, iside, delta);
    if itheta == 0 {
        imid = 32767;
        iside = 0;
        *fill &= (1 << big_b) - 1;
        delta = -16384;
    } else if itheta == 16384 {
        imid = 0;
        iside = 32767;
        *fill &= ((1 << big_b) - 1) << big_b;
        delta = 16384;
    } else {
        imid = i32::from(bitexact_cos(itheta as i16));
        iside = i32::from(bitexact_cos((16384 - itheta) as i16));
        delta = frac_mul16((n as i32 - 1) << 7, bitexact_log2tan(iside, imid));
    }

    sctx.inv = inv;
    sctx.imid = imid;
    sctx.iside = iside;
    sctx.delta = delta;
    sctx.itheta = itheta;
    sctx.qalloc = qalloc;
}

/// Decode a single-coefficient band: a sign bit per channel (libopus `quant_band_n1`).
pub fn quant_band_n1(
    ctx: &mut BandCtx,
    x: &mut [f32],
    y: Option<&mut [f32]>,
    lowband_out: Option<&mut [f32]>,
    dec: &mut RangeDecoder,
) -> u32 {
    let mut sign = 0u32;
    if ctx.remaining_bits >= 1 << BITRES {
        sign = dec.dec_bits(1);
        ctx.remaining_bits -= 1 << BITRES;
    }
    x[0] = if sign != 0 { -1.0 } else { 1.0 };
    if let Some(y) = y {
        let mut sign = 0u32;
        if ctx.remaining_bits >= 1 << BITRES {
            sign = dec.dec_bits(1);
            ctx.remaining_bits -= 1 << BITRES;
        }
        y[0] = if sign != 0 { -1.0 } else { 1.0 };
    }
    if let Some(lo) = lowband_out {
        lo[0] = x[0];
    }
    1
}

/// Recursively decode a mono band partition (libopus `quant_partition`): split in half coding the
/// energy `theta`, recurse, or decode the PVQ shape (or noise-fill) at the leaf. Returns the
/// anti-collapse mask.
#[allow(clippy::too_many_arguments)]
pub fn quant_partition(
    ctx: &mut BandCtx,
    x: &mut [f32],
    n: usize,
    mut b: i32,
    big_b: usize,
    lowband: Option<&[f32]>,
    lm: i32,
    gain: f32,
    mut fill: i32,
    dec: &mut RangeDecoder,
) -> u32 {
    let b0 = big_b;
    // Split if we'd need ~1.5 more bits than the band's cache can produce.
    if lm != -1 && n > 2 && b > cache_max_bits(ctx.band, lm) + 12 {
        let half = n >> 1;
        let new_lm = lm - 1;
        if big_b == 1 {
            fill = (fill & 1) | (fill << 1);
        }
        let new_big_b = (big_b + 1) >> 1;

        let mut sctx = SplitCtx::default();
        compute_theta(ctx, &mut sctx, half, &mut b, new_big_b, b0, new_lm, false, &mut fill, dec);
        let mid = sctx.imid as f32 / 32768.0;
        let side = sctx.iside as f32 / 32768.0;
        let mut delta = sctx.delta;
        let itheta = sctx.itheta;

        // Give more bits to low-energy MDCTs (pre/forward-echo masking).
        if b0 > 1 && (itheta & 0x3fff) != 0 {
            if itheta > 8192 {
                delta -= delta >> (4 - new_lm);
            } else {
                delta = (delta + (((half as i32) << BITRES) >> (5 - new_lm))).min(0);
            }
        }
        let mbits = b.min((b - delta) / 2).max(0);
        let sbits = b - mbits;
        ctx.remaining_bits -= sctx.qalloc;

        let (x_lo, x_hi) = x.split_at_mut(half);
        let lb_lo = lowband.map(|lb| &lb[..half]);
        let lb_hi = lowband.map(|lb| &lb[half..]);

        let mut rebalance = ctx.remaining_bits;
        let cm;
        if mbits >= sbits {
            let mut cm0 = quant_partition(
                ctx, x_lo, half, mbits, new_big_b, lb_lo, new_lm, gain * mid, fill, dec,
            );
            rebalance = mbits - (rebalance - ctx.remaining_bits);
            let sbits = if rebalance > 3 << BITRES && itheta != 0 {
                sbits + rebalance - (3 << BITRES)
            } else {
                sbits
            };
            cm0 |= quant_partition(
                ctx, x_hi, half, sbits, new_big_b, lb_hi, new_lm, gain * side, fill >> new_big_b,
                dec,
            ) << (b0 >> 1);
            cm = cm0;
        } else {
            let mut cm0 = quant_partition(
                ctx, x_hi, half, sbits, new_big_b, lb_hi, new_lm, gain * side, fill >> new_big_b,
                dec,
            ) << (b0 >> 1);
            rebalance = sbits - (rebalance - ctx.remaining_bits);
            let mbits = if rebalance > 3 << BITRES && itheta != 16384 {
                mbits + rebalance - (3 << BITRES)
            } else {
                mbits
            };
            cm0 |= quant_partition(
                ctx, x_lo, half, mbits, new_big_b, lb_lo, new_lm, gain * mid, fill, dec,
            );
            cm = cm0;
        }
        cm
    } else {
        // Leaf: convert the bit budget to a pulse count, never busting the budget.
        let mut q = bits2pulses(ctx.band, lm, b);
        let mut curr_bits = pulses2bits(ctx.band, lm, q);
        ctx.remaining_bits -= curr_bits;
        while ctx.remaining_bits < 0 && q > 0 {
            ctx.remaining_bits += curr_bits;
            q -= 1;
            curr_bits = pulses2bits(ctx.band, lm, q);
            ctx.remaining_bits -= curr_bits;
        }

        if q != 0 {
            let k = get_pulses(q);
            alg_unquant(x, n, k as usize, ctx.spread, big_b, dec, gain)
        } else {
            // No pulses: fill the band with folded spectrum or noise, else clear it.
            let cm_mask = (1u32 << big_b) - 1;
            fill &= cm_mask as i32;
            if fill == 0 {
                x[..n].fill(0.0);
                0
            } else {
                let cm = if let Some(lb) = lowband {
                    for j in 0..n {
                        ctx.seed = celt_lcg_rand(ctx.seed);
                        let tmp = if ctx.seed & 0x8000 != 0 { 1.0 / 256.0 } else { -1.0 / 256.0 };
                        x[j] = lb[j] + tmp;
                    }
                    fill as u32
                } else {
                    for v in x.iter_mut().take(n) {
                        ctx.seed = celt_lcg_rand(ctx.seed);
                        *v = ((ctx.seed as i32) >> 20) as f32;
                    }
                    cm_mask
                };
                renormalise_vector(x, n, gain);
                cm
            }
        }
    }
}

/// Decode one mono band — handles tf-resolution recombine + Hadamard reordering around the
/// recursive [`quant_partition`] (libopus `quant_band`, decoder/resynth path). Returns the
/// anti-collapse mask; writes the (sqrt-scaled) folding reference into `lowband_out` when provided.
#[allow(clippy::too_many_arguments)]
pub fn quant_band(
    ctx: &mut BandCtx,
    x: &mut [f32],
    n: usize,
    b: i32,
    big_b: usize,
    lowband: Option<&[f32]>,
    lm: i32,
    lowband_out: Option<&mut [f32]>,
    gain: f32,
    fill: i32,
    dec: &mut RangeDecoder,
) -> u32 {
    const BIT_INTERLEAVE: [u8; 16] = [0, 1, 1, 1, 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3];
    const BIT_DEINTERLEAVE: [u8; 16] = [
        0x00, 0x03, 0x0c, 0x0f, 0x30, 0x33, 0x3c, 0x3f, 0xc0, 0xc3, 0xcc, 0xcf, 0xf0, 0xf3, 0xfc,
        0xff,
    ];
    let n0 = n;
    let b_orig = big_b;
    let long_blocks = b_orig == 1;
    let mut n_b = n / big_b;

    if n == 1 {
        return quant_band_n1(ctx, x, None, lowband_out, dec);
    }

    let mut tf_change = ctx.tf_change;
    let recombine = if tf_change > 0 { tf_change } else { 0 };
    let mut big_b = big_b;
    let mut fill = fill;
    let mut time_divide = 0i32;

    // Mutable working copy of the lowband, only when we'll actually transform it.
    let needs_lb = lowband.is_some()
        && (recombine != 0 || ((n / b_orig) & 1 == 0 && tf_change < 0) || b_orig > 1);
    let mut lb_buf = [0f32; MAX_BAND];
    if needs_lb {
        if let Some(lb) = lowband {
            lb_buf[..n].copy_from_slice(&lb[..n]);
        }
    }

    // Band recombining (increase frequency resolution).
    for k in 0..recombine {
        if needs_lb {
            haar1(&mut lb_buf, n >> k, 1usize << k);
        }
        fill = i32::from(BIT_INTERLEAVE[(fill & 0xF) as usize])
            | (i32::from(BIT_INTERLEAVE[((fill >> 4) & 0xF) as usize]) << 2);
    }
    big_b >>= recombine as usize;
    n_b <<= recombine as usize;

    // Increase time resolution.
    while n_b & 1 == 0 && tf_change < 0 {
        if needs_lb {
            haar1(&mut lb_buf, n_b, big_b);
        }
        fill |= fill << big_b;
        big_b <<= 1;
        n_b >>= 1;
        time_divide += 1;
        tf_change += 1;
    }
    let b0_new = big_b;
    let n_b0 = n_b;

    // Reorganise into time order for the partition decode.
    if b0_new > 1 && needs_lb {
        deinterleave_hadamard(
            &mut lb_buf,
            n_b >> recombine as usize,
            b0_new << recombine as usize,
            long_blocks,
        );
    }

    let working_lb: Option<&[f32]> = if lowband.is_some() {
        if needs_lb {
            Some(&lb_buf[..n])
        } else {
            lowband
        }
    } else {
        None
    };

    let mut cm = quant_partition(ctx, x, n, b, big_b, working_lb, lm, gain, fill, dec);

    // Resynth: undo the reorganisation on the decoded X.
    if b0_new > 1 {
        interleave_hadamard(x, n_b >> recombine as usize, b0_new << recombine as usize, long_blocks);
    }
    let mut n_b = n_b0;
    let mut big_b = b0_new;
    for _ in 0..time_divide {
        big_b >>= 1;
        n_b <<= 1;
        cm |= cm >> big_b;
        haar1(x, n_b, big_b);
    }
    for k in 0..recombine {
        cm = u32::from(BIT_DEINTERLEAVE[cm as usize]);
        haar1(x, n0 >> k, 1usize << k);
    }
    big_b <<= recombine as usize;

    if let Some(lo) = lowband_out {
        let nn = (n0 as f32).sqrt();
        for j in 0..n0 {
            lo[j] = nn * x[j];
        }
    }
    cm &= (1u32 << big_b) - 1;
    cm
}

/// Duplicate first-band folding data so the second band can fold (libopus `special_hybrid_folding`).
/// A no-op for CELT-only (`start == 0`), where `n2 == n1`.
fn special_hybrid_folding(norm: &mut [f32], start: usize, m: usize) {
    let n1 = m * (E_BANDS[start + 1] - E_BANDS[start]) as usize;
    let n2 = m * (E_BANDS[start + 2] - E_BANDS[start + 1]) as usize;
    if n2 > n1 {
        norm.copy_within((2 * n1 - n2)..n1, n1);
    }
}

/// Decode all CELT bands `start..end` into the normalised coefficient buffer `x_` (libopus
/// `quant_all_bands`, mono decoder path). Manages the `norm` fold buffer and per-band bit balance,
/// calling [`quant_band`] per band and recording each band's collapse mask. `*seed` is advanced.
#[allow(clippy::too_many_arguments)]
pub fn quant_all_bands(
    start: usize,
    end: usize,
    x_: &mut [f32],
    collapse_masks: &mut [u8],
    pulses: &[i32],
    short_blocks: bool,
    spread: u32,
    intensity: usize,
    tf_res: &[i32],
    total_bits: i32,
    mut balance: i32,
    lm: i32,
    coded_bands: usize,
    seed: &mut u32,
    disable_inv: bool,
    dec: &mut RangeDecoder,
) {
    let m = 1usize << lm;
    let big_b = if short_blocks { m } else { 1 };
    let norm_offset = m * E_BANDS[start] as usize;
    let norm_len = m * E_BANDS[NB_BANDS - 1] as usize - norm_offset;
    let mut norm_buf = [0f32; 1024];
    let norm = &mut norm_buf[..norm_len];

    let mut ctx = BandCtx {
        band: start,
        intensity,
        spread,
        tf_change: 0,
        remaining_bits: 0,
        seed: *seed,
        disable_inv,
    };
    let mut lowband_offset = 0usize;
    let mut update_lowband = true;

    for i in start..end {
        ctx.band = i;
        let last = i == end - 1;
        let band_lo = m * E_BANDS[i] as usize;
        let band_hi = m * E_BANDS[i + 1] as usize;
        let n = band_hi - band_lo;
        let tell = dec.tell_frac() as i32;
        if i != start {
            balance -= tell;
        }
        ctx.remaining_bits = total_bits - tell - 1;
        let b = if i < coded_bands {
            let curr_balance = balance / (3.min(coded_bands - i) as i32);
            (total_bits - tell - 1 + 1)
                .min(pulses[i] + curr_balance)
                .clamp(0, 16383)
        } else {
            0
        };

        if (band_lo >= n + norm_offset || i == start + 1) && (update_lowband || lowband_offset == 0) {
            lowband_offset = i;
        }
        if i == start + 1 {
            special_hybrid_folding(norm, start, m);
        }

        let tf_change = tf_res[i];
        ctx.tf_change = tf_change;

        // Conservative collapse-mask estimate of the bands we'll fold from.
        let mut effective_lowband: i32 = -1;
        let fill_init: u32;
        if lowband_offset != 0 && (spread != SPREAD_AGGRESSIVE || big_b > 1 || tf_change < 0) {
            effective_lowband = ((m * E_BANDS[lowband_offset] as usize) as i32
                - norm_offset as i32
                - n as i32)
                .max(0);
            let thresh = effective_lowband as usize + norm_offset;
            let mut fold_start = lowband_offset;
            loop {
                fold_start -= 1;
                if m * E_BANDS[fold_start] as usize <= thresh {
                    break;
                }
            }
            let mut fold_end = lowband_offset - 1;
            loop {
                fold_end += 1;
                if !(fold_end < i && (m * E_BANDS[fold_end] as usize) < thresh + n) {
                    break;
                }
            }
            let mut cm = 0u32;
            let mut fold_i = fold_start;
            loop {
                cm |= u32::from(collapse_masks[fold_i]);
                fold_i += 1;
                if fold_i >= fold_end {
                    break;
                }
            }
            fill_init = cm;
        } else {
            fill_init = (1u32 << big_b) - 1;
        }

        // Mono: split the fold buffer into read (earlier bands) + write (this band) halves.
        let cur_norm = band_lo - norm_offset;
        let (norm_lo, norm_hi) = norm.split_at_mut(cur_norm);
        let lowband: Option<&[f32]> = if effective_lowband >= 0 {
            Some(&norm_lo[effective_lowband as usize..])
        } else {
            None
        };
        let lowband_out: Option<&mut [f32]> = if last { None } else { Some(&mut norm_hi[..n]) };

        let x = &mut x_[band_lo..band_hi];
        let x_cm = quant_band(
            &mut ctx, x, n, b, big_b, lowband, lm, lowband_out, 1.0, fill_init as i32, dec,
        );
        collapse_masks[i] = x_cm as u8;
        balance += pulses[i] + tell;
        update_lowband = b > (n as i32) << BITRES;
    }
    *seed = ctx.seed;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;

    /// Smoke test: `quant_partition` must decode an arbitrary bitstream without panicking, draw down
    /// the bit budget, and produce finite, normalised output (no NaN/Inf). Real correctness comes
    /// from end-to-end `opus_compare`; this guards the recursion + indexing.
    #[test]
    fn quant_partition_decodes_without_panic_and_stays_finite() {
        for &(n, lm, big_b) in &[(16usize, 2i32, 1usize), (32, 3, 1), (8, 1, 2), (4, 1, 1), (48, 3, 4)] {
            // A deterministic, plausible bitstream.
            let mut buf = vec![0u8; 256];
            {
                let mut enc = RangeEncoder::new(&mut buf);
                for k in 0..40u32 {
                    enc.enc_bits((k.wrapping_mul(2_654_435_761) >> 24) & 0xff, 8);
                }
                enc.done();
            }
            let mut ctx = BandCtx {
                band: 10,
                intensity: 0,
                spread: 2,
                tf_change: 0,
                remaining_bits: 400,
                seed: 0xCAFE_BABE,
                disable_inv: true,
            };
            let mut x = vec![0.0f32; n];
            let mut dec = RangeDecoder::new(&buf);
            let _cm = quant_partition(&mut ctx, &mut x, n, 300, big_b, None, lm, 1.0, (1 << big_b) - 1, &mut dec);
            assert!(x.iter().all(|v| v.is_finite()), "n={n} lm={lm}: non-finite output");
            assert!(ctx.remaining_bits < 400, "n={n} lm={lm}: budget not drawn down");
        }
    }

    #[test]
    fn quant_band_decodes_without_panic_and_stays_finite() {
        for &(n, lm, big_b, tf) in &[
            (16usize, 2i32, 1usize, 0i32),
            (32, 3, 2, 0),
            (24, 2, 1, 0),
            (8, 1, 1, 0),
        ] {
            let mut buf = vec![0u8; 256];
            {
                let mut enc = RangeEncoder::new(&mut buf);
                for k in 0..40u32 {
                    enc.enc_bits(k.wrapping_mul(40_503) & 0xff, 8);
                }
                enc.done();
            }
            let mut ctx = BandCtx {
                band: 12,
                intensity: 0,
                spread: 2,
                tf_change: tf,
                remaining_bits: 600,
                seed: 0xBEEF_F00D,
                disable_inv: true,
            };
            let mut x = vec![0.0f32; n];
            let lowband = vec![0.05f32; n];
            let mut lowband_out = vec![0.0f32; n];
            let mut dec = RangeDecoder::new(&buf);
            let _cm = quant_band(
                &mut ctx,
                &mut x,
                n,
                400,
                big_b,
                Some(&lowband),
                lm,
                Some(&mut lowband_out),
                1.0,
                (1 << big_b) - 1,
                &mut dec,
            );
            assert!(x.iter().all(|v| v.is_finite()), "n={n}: non-finite X");
            assert!(lowband_out.iter().all(|v| v.is_finite()), "n={n}: non-finite lowband_out");
        }
    }

    #[test]
    fn quant_all_bands_decodes_full_frame_without_panic() {
        use crate::opus::celt::tables::NB_BANDS;
        let lm = 3i32;
        let m = 1usize << lm;
        let n_total = m * 100; // M * eBands[NB_BANDS]
        let mut x = vec![0.0f32; n_total];
        let mut collapse = vec![0u8; NB_BANDS];
        let pulses = vec![60i32; NB_BANDS];
        let tf_res = vec![0i32; NB_BANDS];
        let mut buf = vec![0u8; 1024];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for k in 0..240u32 {
                enc.enc_bits((k.wrapping_mul(2_654_435_761) >> 24) & 0xff, 8);
            }
            enc.done();
        }
        let mut seed = 0xABCD_1234u32;
        let mut dec = RangeDecoder::new(&buf);
        quant_all_bands(
            0, NB_BANDS, &mut x, &mut collapse, &pulses, false, 2, 0, &tf_res, 6000, 0, lm,
            NB_BANDS, &mut seed, true, &mut dec,
        );
        assert!(x.iter().all(|v| v.is_finite()), "non-finite coefficients");
        let _ = seed; // (the fold/noise PRNG only advances when a band gets zero pulses)
    }

    #[test]
    fn quant_band_n1_decodes_sign() {
        let mut buf = vec![0u8; 16];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            enc.enc_bits(1, 1); // sign bit
            enc.done();
        }
        let mut ctx = BandCtx {
            band: 0,
            intensity: 0,
            spread: 2,
            tf_change: 0,
            remaining_bits: 64,
            seed: 1,
            disable_inv: true,
        };
        let mut x = [0.0f32];
        let mut lo = [0.0f32];
        let mut dec = RangeDecoder::new(&buf);
        let cm = quant_band_n1(&mut ctx, &mut x, None, Some(&mut lo), &mut dec);
        assert_eq!(cm, 1);
        assert!(x[0] == 1.0 || x[0] == -1.0);
        assert_eq!(lo[0], x[0]);
        assert_eq!(ctx.remaining_bits, 64 - (1 << BITRES));
    }
}
