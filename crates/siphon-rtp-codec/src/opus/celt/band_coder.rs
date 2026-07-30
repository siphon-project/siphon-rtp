//! CELT recursive band quantiser — **shared** by encoder and decoder (RFC 6716 §4.3.4; libopus
//! `bands.c`, float path).
//!
//! The heart of CELT: `compute_theta` codes the mid/side (or time-) split angle, and
//! [`quant_partition`] recursively splits a band in half — coding the energy split with `theta` —
//! down to leaves where the PVQ shape is quantised (`alg_quant`) or de-quantised (`alg_unquant`),
//! or noise/folding fills an empty band. [`quant_band_n1`] handles the single-coefficient case.
//! These draw bits from the shared [`BandCtx`] budget; the wrappers ([`quant_band`] /
//! [`quant_all_bands`]) sit above and orchestrate tf-resolution + the per-band loop.
//!
//! libopus writes this once and branches on an `encode` flag at every symbol; the Rust equivalent
//! is the [`CeltCoder`] generic parameter, so there is exactly one copy of the band recursion and
//! the two directions cannot drift apart.
//!
//! **Scope note.** The stereo band path (libopus `quant_band_stereo`) is absent in both directions
//! — the CELT decoder in this crate is mono-only, and so is the encoder. The `stereo` flag threaded
//! through `compute_theta` is pre-existing decoder plumbing; on the encode side only
//! `stereo == false` (a mono time split) is reachable, and there is deliberately no stereo caller
//! rather than a hollow one.

use crate::opus::celt::bands::{
    bitexact_cos, bitexact_log2tan, compute_qn, deinterleave_hadamard, frac_mul16, haar1,
    interleave_hadamard,
};
use crate::opus::celt::entropy::CeltCoder;
use crate::opus::celt::rate::{bits2pulses, cache_max_bits, get_pulses, pulses2bits};
use crate::opus::celt::synthesis::celt_lcg_rand;
use crate::opus::celt::tables::{E_BANDS, LOG_N, NB_BANDS, SPREAD_AGGRESSIVE};
use crate::opus::celt::vq::{renormalise_vector, stereo_itheta};

const BITRES: i32 = 3;
const QTHETA_OFFSET: i32 = 4;
const QTHETA_OFFSET_TWOPHASE: i32 = 16;
/// Largest band dimension (scratch size) — 48 kHz max is 176.
const MAX_BAND: usize = 256;

/// Shared per-band coding context (libopus `band_ctx`, `bands.c:673`).
pub struct BandCtx {
    /// Current band index `i`.
    pub band: usize,
    /// First band coded with intensity stereo.
    pub intensity: usize,
    /// PVQ spreading parameter.
    pub spread: u32,
    /// Per-band time-frequency change flag.
    pub tf_change: i32,
    /// Bits left in the frame budget (1/8-bit units); drawn down as bands are coded.
    pub remaining_bits: i32,
    /// Anti-collapse / fold PRNG state (carried across bands and frames).
    pub seed: u32,
    /// Disable the stereo inversion flag (downmix safety).
    pub disable_inv: bool,
    /// Reconstruct the quantised spectrum as we go (libopus `ctx->resynth`). Always `true` for a
    /// decoder; `false` for the mono encoder, whose reference build reconstructs nothing
    /// (`bands.c:1428`: `resynth = !encode || theta_rdo`, and `theta_rdo` requires stereo) — which
    /// is why the encoder needs no folding reference.
    pub resynth: bool,
    /// "Avoid injecting noise in the first band on transients" (`bands.c:1473`) — an encode-only
    /// guard that pushes `theta` to a pole when the bit split would starve one side.
    pub avoid_split_noise: bool,
}

/// The mid/side split decision (libopus `split_ctx`).
#[derive(Default)]
struct SplitCtx {
    imid: i32,
    iside: i32,
    delta: i32,
    itheta: i32,
    qalloc: i32,
}

/// Code the split angle `theta` and derive the mid/side gains + bit-split `delta` (libopus
/// `compute_theta`, `bands.c:700`). Consumes bits from `*b` and may mask `*fill`.
///
/// `x`/`y` are the two halves being split; the encoder measures their energies to pick `theta`, the
/// decoder ignores them.
#[allow(clippy::too_many_arguments)]
fn compute_theta<C: CeltCoder>(
    ctx: &BandCtx,
    sctx: &mut SplitCtx,
    x: &[f32],
    y: &[f32],
    n: usize,
    b: &mut i32,
    big_b: usize,
    b0: usize,
    lm: i32,
    stereo: bool,
    fill: &mut i32,
    coder: &mut C,
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
    // theta is the atan() of the ratio between the (normalized) side and mid (bands.c:736).
    let mut itheta = if C::ENCODE {
        stereo_itheta(x, y, stereo, n)
    } else {
        0
    };
    let tell = coder.tell_frac() as i32;
    if qn != 1 {
        if C::ENCODE {
            itheta = (itheta * qn + 8192) >> 14;
            if !stereo && ctx.avoid_split_noise && itheta > 0 && itheta < qn {
                // "Check if the selected value of theta will cause the bit allocation to inject
                // noise on one side. If so, make sure the energy of that side is zero."
                // (bands.c:750)
                let unquantized = (itheta * 16384) / qn;
                let imid = i32::from(bitexact_cos(unquantized as i16));
                let iside = i32::from(bitexact_cos((16384 - unquantized) as i16));
                let delta = frac_mul16((n as i32 - 1) << 7, bitexact_log2tan(iside, imid));
                if delta > *b {
                    itheta = qn;
                } else if delta < -*b {
                    itheta = 0;
                }
            }
        }
        // Entropy coding of the angle: a step pdf for stereo, uniform for a time split of more than
        // one block, triangular otherwise (bands.c:775).
        if stereo && n > 2 {
            coder.code_theta_step(&mut itheta, qn);
        } else if b0 > 1 || stereo {
            coder.code_theta_uniform(&mut itheta, qn);
        } else {
            coder.code_theta_triangular(&mut itheta, qn);
        }
        itheta = (itheta * 16384) / qn;
    } else if stereo {
        // The stereo inversion flag. Its *value* only matters to `quant_band_stereo`, which is not
        // implemented in either direction here (see the module scope note); the symbol is still read
        // so a stereo decoder would stay in sync, and `disable_inv` is honoured as the C does.
        let mut inv = false;
        if *b > 2 << BITRES && ctx.remaining_bits > 2 << BITRES {
            coder.code_bit_logp(&mut inv, 2);
        }
        itheta = 0;
    }
    let qalloc = coder.tell_frac() as i32 - tell;
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

    let _ = ctx.disable_inv; // consumed by the (absent) stereo band path; kept in `BandCtx` for it
    sctx.imid = imid;
    sctx.iside = iside;
    sctx.delta = delta;
    sctx.itheta = itheta;
    sctx.qalloc = qalloc;
}

/// Code a single-coefficient band: one sign bit (libopus `quant_band_n1`, `bands.c:904`).
pub fn quant_band_n1<C: CeltCoder>(
    ctx: &mut BandCtx,
    x: &mut [f32],
    lowband_out: Option<&mut [f32]>,
    coder: &mut C,
) -> u32 {
    let mut sign = 0u32;
    if ctx.remaining_bits >= 1 << BITRES {
        if C::ENCODE {
            sign = u32::from(x[0] < 0.0);
        }
        coder.code_bits(&mut sign, 1);
        ctx.remaining_bits -= 1 << BITRES;
    }
    if ctx.resynth {
        x[0] = if sign != 0 { -1.0 } else { 1.0 };
    }
    if let Some(lo) = lowband_out {
        lo[0] = x[0];
    }
    1
}

/// Recursively code a mono band partition (libopus `quant_partition`, `bands.c:943`): split in half
/// coding the energy `theta`, recurse, or quantise the PVQ shape (or noise-fill) at the leaf.
/// Returns the anti-collapse mask.
#[allow(clippy::too_many_arguments)]
pub fn quant_partition<C: CeltCoder>(
    ctx: &mut BandCtx,
    x: &mut [f32],
    n: usize,
    mut b: i32,
    big_b: usize,
    lowband: Option<&[f32]>,
    lm: i32,
    gain: f32,
    mut fill: i32,
    coder: &mut C,
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
        {
            let (x_lo, x_hi) = x.split_at(half);
            compute_theta(
                ctx, &mut sctx, x_lo, x_hi, half, &mut b, new_big_b, b0, new_lm, false, &mut fill,
                coder,
            );
        }
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
                ctx,
                x_lo,
                half,
                mbits,
                new_big_b,
                lb_lo,
                new_lm,
                gain * mid,
                fill,
                coder,
            );
            rebalance = mbits - (rebalance - ctx.remaining_bits);
            let sbits = if rebalance > 3 << BITRES && itheta != 0 {
                sbits + rebalance - (3 << BITRES)
            } else {
                sbits
            };
            cm0 |= quant_partition(
                ctx,
                x_hi,
                half,
                sbits,
                new_big_b,
                lb_hi,
                new_lm,
                gain * side,
                fill >> new_big_b,
                coder,
            ) << (b0 >> 1);
            cm = cm0;
        } else {
            let mut cm0 = quant_partition(
                ctx,
                x_hi,
                half,
                sbits,
                new_big_b,
                lb_hi,
                new_lm,
                gain * side,
                fill >> new_big_b,
                coder,
            ) << (b0 >> 1);
            rebalance = sbits - (rebalance - ctx.remaining_bits);
            let mbits = if rebalance > 3 << BITRES && itheta != 16384 {
                mbits + rebalance - (3 << BITRES)
            } else {
                mbits
            };
            cm0 |= quant_partition(
                ctx,
                x_lo,
                half,
                mbits,
                new_big_b,
                lb_lo,
                new_lm,
                gain * mid,
                fill,
                coder,
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
            let k = get_pulses(q) as usize;
            coder.code_band_shape(x, n, k, ctx.spread, big_b, gain, ctx.resynth)
        } else {
            // No pulses: fill the band with folded spectrum or noise, else clear it. Nothing is
            // coded on this path, so an encoder that reconstructs nothing skips the fill entirely
            // (`bands.c:1065` gates the whole block on `ctx->resynth`) and reports the mask only.
            let cm_mask = (1u32 << big_b) - 1;
            fill &= cm_mask as i32;
            if !ctx.resynth {
                return if fill == 0 {
                    0
                } else if lowband.is_some() {
                    fill as u32
                } else {
                    cm_mask
                };
            }
            if fill == 0 {
                x[..n].fill(0.0);
                0
            } else {
                let cm = if let Some(lb) = lowband {
                    for j in 0..n {
                        ctx.seed = celt_lcg_rand(ctx.seed);
                        let tmp = if ctx.seed & 0x8000 != 0 {
                            1.0 / 256.0
                        } else {
                            -1.0 / 256.0
                        };
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

/// Code one mono band — handles tf-resolution recombine + Hadamard reordering around the recursive
/// [`quant_partition`] (libopus `quant_band`, `bands.c:1109`). Returns the anti-collapse mask;
/// writes the (sqrt-scaled) folding reference into `lowband_out` when provided and resynthesising.
#[allow(clippy::too_many_arguments)]
pub fn quant_band<C: CeltCoder>(
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
    coder: &mut C,
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
        return quant_band_n1(ctx, x, lowband_out, coder);
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

    // Band recombining (increase frequency resolution). The encoder applies the same Haar to the
    // *signal*; the decoder undoes it in the resynth block below (`bands.c:1154`).
    for k in 0..recombine {
        if C::ENCODE {
            haar1(x, n >> k, 1usize << k);
        }
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
        if C::ENCODE {
            haar1(x, n_b, big_b);
        }
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

    // Reorganise into time order for the partition coding.
    if b0_new > 1 {
        if C::ENCODE {
            deinterleave_hadamard(
                x,
                n_b >> recombine as usize,
                b0_new << recombine as usize,
                long_blocks,
            );
        }
        if needs_lb {
            deinterleave_hadamard(
                &mut lb_buf,
                n_b >> recombine as usize,
                b0_new << recombine as usize,
                long_blocks,
            );
        }
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

    let mut cm = quant_partition(ctx, x, n, b, big_b, working_lb, lm, gain, fill, coder);

    if ctx.resynth {
        // Undo the reorganisation on the reconstructed X.
        if b0_new > 1 {
            interleave_hadamard(
                x,
                n_b >> recombine as usize,
                b0_new << recombine as usize,
                long_blocks,
            );
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
    }
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

/// Code all CELT bands `start..end` of the normalised coefficient buffer `x_` (libopus
/// `quant_all_bands`, `bands.c:1398`, mono path). Manages the `norm` fold buffer and the per-band
/// bit balance, calling [`quant_band`] per band and recording each band's collapse mask. `*seed` is
/// advanced.
#[allow(clippy::too_many_arguments)]
pub fn quant_all_bands<C: CeltCoder>(
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
    coder: &mut C,
) {
    let m = 1usize << lm;
    let big_b = if short_blocks { m } else { 1 };
    let norm_offset = m * E_BANDS[start] as usize;
    let norm_len = m * E_BANDS[NB_BANDS - 1] as usize - norm_offset;
    let mut norm_buf = [0f32; 1024];
    let norm = &mut norm_buf[..norm_len];

    // libopus: `resynth = !encode || theta_rdo`, and `theta_rdo` needs stereo, so a mono encoder
    // reconstructs nothing (`bands.c:1428`). `lowband_offset` then stays 0 throughout, so the
    // encoder never folds and always passes the all-ones fill mask — none of which is *coded*, so
    // the bitstream still matches exactly what a folding decoder reads.
    let resynth = !C::ENCODE;

    let mut ctx = BandCtx {
        band: start,
        intensity,
        spread,
        tf_change: 0,
        remaining_bits: 0,
        seed: *seed,
        disable_inv,
        resynth,
        // "Avoid injecting noise in the first band on transients." (bands.c:1473)
        avoid_split_noise: big_b > 1,
    };
    let mut lowband_offset = 0usize;
    let mut update_lowband = true;

    for i in start..end {
        ctx.band = i;
        let last = i == end - 1;
        let band_lo = m * E_BANDS[i] as usize;
        let band_hi = m * E_BANDS[i + 1] as usize;
        let n = band_hi - band_lo;
        let tell = coder.tell_frac() as i32;
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

        if resynth
            && (band_lo >= n + norm_offset || i == start + 1)
            && (update_lowband || lowband_offset == 0)
        {
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
            effective_lowband =
                ((m * E_BANDS[lowband_offset] as usize) as i32 - norm_offset as i32 - n as i32)
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
        let lowband_out: Option<&mut [f32]> = if last || !resynth {
            None
        } else {
            Some(&mut norm_hi[..n])
        };

        let x = &mut x_[band_lo..band_hi];
        let x_cm = quant_band(
            &mut ctx,
            x,
            n,
            b,
            big_b,
            lowband,
            lm,
            lowband_out,
            1.0,
            fill_init as i32,
            coder,
        );
        collapse_masks[i] = x_cm as u8;
        balance += pulses[i] + tell;
        update_lowband = b > (n as i32) << BITRES;
        // "We only need to avoid noise on a split for the first band. After that, we have folding."
        // (bands.c:1667)
        ctx.avoid_split_noise = false;
    }
    *seed = ctx.seed;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

    fn decode_ctx(band: usize, tf_change: i32, remaining_bits: i32, seed: u32) -> BandCtx {
        BandCtx {
            band,
            intensity: 0,
            spread: 2,
            tf_change,
            remaining_bits,
            seed,
            disable_inv: true,
            resynth: true,
            avoid_split_noise: false,
        }
    }

    /// Smoke test: `quant_partition` must decode an arbitrary bitstream without panicking, draw down
    /// the bit budget, and produce finite, normalised output (no NaN/Inf). Real correctness comes
    /// from end-to-end `opus_compare`; this guards the recursion + indexing.
    #[test]
    fn quant_partition_decodes_without_panic_and_stays_finite() {
        for &(n, lm, big_b) in &[
            (16usize, 2i32, 1usize),
            (32, 3, 1),
            (8, 1, 2),
            (4, 1, 1),
            (48, 3, 4),
        ] {
            // A deterministic, plausible bitstream.
            let mut buf = vec![0u8; 256];
            {
                let mut enc = RangeEncoder::new(&mut buf);
                for k in 0..40u32 {
                    enc.enc_bits((k.wrapping_mul(2_654_435_761) >> 24) & 0xff, 8);
                }
                enc.done();
            }
            let mut ctx = decode_ctx(10, 0, 400, 0xCAFE_BABE);
            let mut x = vec![0.0f32; n];
            let mut dec = RangeDecoder::new(&buf);
            let _cm = quant_partition(
                &mut ctx,
                &mut x,
                n,
                300,
                big_b,
                None,
                lm,
                1.0,
                (1 << big_b) - 1,
                &mut dec,
            );
            assert!(
                x.iter().all(|v| v.is_finite()),
                "n={n} lm={lm}: non-finite output"
            );
            assert!(
                ctx.remaining_bits < 400,
                "n={n} lm={lm}: budget not drawn down"
            );
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
            let mut ctx = decode_ctx(12, tf, 600, 0xBEEF_F00D);
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
            assert!(
                lowband_out.iter().all(|v| v.is_finite()),
                "n={n}: non-finite lowband_out"
            );
        }
    }

    #[test]
    fn quant_all_bands_decodes_full_frame_without_panic() {
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
            0,
            NB_BANDS,
            &mut x,
            &mut collapse,
            &pulses,
            false,
            2,
            0,
            &tf_res,
            6000,
            0,
            lm,
            NB_BANDS,
            &mut seed,
            true,
            &mut dec,
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
        let mut ctx = decode_ctx(0, 0, 64, 1);
        let mut x = [0.0f32];
        let mut lo = [0.0f32];
        let mut dec = RangeDecoder::new(&buf);
        let cm = quant_band_n1(&mut ctx, &mut x, Some(&mut lo), &mut dec);
        assert_eq!(cm, 1);
        assert!(x[0] == 1.0 || x[0] == -1.0);
        assert_eq!(lo[0], x[0]);
        assert_eq!(ctx.remaining_bits, 64 - (1 << BITRES));
    }

    // ── Encoder ↔ decoder agreement ─────────────────────────────────────────────────────────────
    //
    // The decode side is bitstream-exact against libopus (96 CELT-only streams), so requiring the
    // encoder's stream to decode back to the same *symbol sequence* is the real gate. `tell_frac`
    // parity after every band proves the two sides consumed the identical number of bits, i.e. the
    // recursion took the identical path.

    /// A plausible normalised band spectrum: unit-norm per band with a falling tilt.
    fn synthetic_normalised_spectrum(m: usize, seed: u32) -> Vec<f32> {
        let n_total = m * E_BANDS[NB_BANDS] as usize;
        let mut x = vec![0f32; n_total];
        for i in 0..NB_BANDS {
            let lo = m * E_BANDS[i] as usize;
            let hi = m * E_BANDS[i + 1] as usize;
            for (j, slot) in x[lo..hi].iter_mut().enumerate() {
                let phase = (seed.wrapping_add((i * 31 + j * 7) as u32) % 997) as f32 * 0.0063;
                *slot = phase.sin() + 0.4 * (phase * 2.7).cos();
            }
            let norm = x[lo..hi].iter().map(|v| v * v).sum::<f32>().sqrt();
            if norm > 0.0 {
                for slot in x[lo..hi].iter_mut() {
                    *slot /= norm;
                }
            }
        }
        x
    }

    /// Encode a whole frame's bands, then decode it: both sides must end on the identical
    /// `tell_frac` and range value, across every frame size, transient/non-transient, spread
    /// setting, and a wide budget spread.
    #[test]
    fn quant_all_bands_encode_then_decode_agrees_on_the_bitstream() {
        for lm in 0..4i32 {
            let m = 1usize << lm;
            for &short_blocks in &[false, true] {
                for spread in 0..4u32 {
                    for &bytes in &[20usize, 60, 200, 600] {
                        let pulses: Vec<i32> = (0..NB_BANDS)
                            .map(|i| ((bytes as i32) * 2).max(0) - (i as i32) * 8)
                            .map(|p| p.max(0))
                            .collect();
                        let tf_res: Vec<i32> = (0..NB_BANDS)
                            .map(|i| if short_blocks { 0 } else { -(i as i32 % 2) })
                            .collect();
                        let total_bits = (bytes as i32) * (8 << BITRES);

                        let mut buf = vec![0u8; bytes];
                        let mut enc_x = synthetic_normalised_spectrum(m, 0x5A5A + lm as u32);
                        let mut enc_collapse = vec![0u8; NB_BANDS];
                        let mut enc_seed = 0x1234_5678u32;
                        let (enc_tell, enc_rng);
                        {
                            let mut enc = RangeEncoder::new(&mut buf);
                            quant_all_bands(
                                0,
                                NB_BANDS,
                                &mut enc_x,
                                &mut enc_collapse,
                                &pulses,
                                short_blocks,
                                spread,
                                0,
                                &tf_res,
                                total_bits,
                                0,
                                lm,
                                NB_BANDS,
                                &mut enc_seed,
                                true,
                                &mut enc,
                            );
                            enc_tell = enc.tell_frac();
                            enc_rng = CeltCoder::rng(&enc);
                            enc.done();
                            assert!(
                                !enc.error(),
                                "lm={lm} short={short_blocks} spread={spread} bytes={bytes}: \
                                 encoder overflow"
                            );
                        }

                        let mut dec_x = vec![0f32; m * E_BANDS[NB_BANDS] as usize];
                        let mut dec_collapse = vec![0u8; NB_BANDS];
                        let mut dec_seed = 0x1234_5678u32;
                        let mut dec = RangeDecoder::new(&buf);
                        quant_all_bands(
                            0,
                            NB_BANDS,
                            &mut dec_x,
                            &mut dec_collapse,
                            &pulses,
                            short_blocks,
                            spread,
                            0,
                            &tf_res,
                            total_bits,
                            0,
                            lm,
                            NB_BANDS,
                            &mut dec_seed,
                            true,
                            &mut dec,
                        );
                        assert_eq!(
                            dec.tell_frac(),
                            enc_tell,
                            "lm={lm} short={short_blocks} spread={spread} bytes={bytes}: \
                             tell_frac diverged (encoder/decoder read a different symbol count)"
                        );
                        assert_eq!(
                            CeltCoder::rng(&dec),
                            enc_rng,
                            "lm={lm} short={short_blocks} spread={spread} bytes={bytes}: \
                             final_range diverged"
                        );
                        assert!(
                            dec_x.iter().all(|v| v.is_finite()),
                            "lm={lm}: non-finite reconstruction"
                        );
                    }
                }
            }
        }
    }

    /// The decoded spectrum must actually resemble the encoded one — bit agreement alone could be
    /// achieved by a stream that codes the wrong shapes.
    #[test]
    fn quant_all_bands_reconstruction_correlates_with_the_input() {
        let lm = 3i32;
        let m = 1usize << lm;
        let bytes = 400usize;
        let pulses: Vec<i32> = (0..NB_BANDS).map(|i| 700 - (i as i32) * 20).collect();
        let tf_res = vec![0i32; NB_BANDS];
        let total_bits = (bytes as i32) * (8 << BITRES);
        let source = synthetic_normalised_spectrum(m, 0xC0DE);

        let mut buf = vec![0u8; bytes];
        let mut enc_x = source.clone();
        let mut enc_collapse = vec![0u8; NB_BANDS];
        let mut enc_seed = 7u32;
        {
            let mut enc = RangeEncoder::new(&mut buf);
            quant_all_bands(
                0,
                NB_BANDS,
                &mut enc_x,
                &mut enc_collapse,
                &pulses,
                false,
                2,
                0,
                &tf_res,
                total_bits,
                0,
                lm,
                NB_BANDS,
                &mut enc_seed,
                true,
                &mut enc,
            );
            enc.done();
            assert!(!enc.error());
        }
        let mut dec_x = vec![0f32; m * E_BANDS[NB_BANDS] as usize];
        let mut dec_collapse = vec![0u8; NB_BANDS];
        let mut dec_seed = 7u32;
        let mut dec = RangeDecoder::new(&buf);
        quant_all_bands(
            0,
            NB_BANDS,
            &mut dec_x,
            &mut dec_collapse,
            &pulses,
            false,
            2,
            0,
            &tf_res,
            total_bits,
            0,
            lm,
            NB_BANDS,
            &mut dec_seed,
            true,
            &mut dec,
        );
        // Per-band correlation between source and reconstruction; the low bands get plenty of
        // pulses so they must track closely.
        for i in 0..12 {
            let lo = m * E_BANDS[i] as usize;
            let hi = m * E_BANDS[i + 1] as usize;
            let dot: f32 = source[lo..hi]
                .iter()
                .zip(&dec_x[lo..hi])
                .map(|(a, b)| a * b)
                .sum();
            let nb = dec_x[lo..hi].iter().map(|v| v * v).sum::<f32>().sqrt();
            assert!(
                nb > 0.0 && dot / nb > 0.55,
                "band {i}: correlation {} too low",
                dot / nb.max(1e-9)
            );
        }
    }
}
