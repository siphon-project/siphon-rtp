//! CELT recursive band quantiser — **shared** by encoder and decoder (RFC 6716 §4.3.4; libopus
//! `bands.c`, float path).
//!
//! The heart of CELT: `compute_theta` codes the mid/side (or time-) split angle, and
//! [`quant_partition`] recursively splits a band in half — coding the energy split with `theta` —
//! down to leaves where the PVQ shape is quantised (`alg_quant`) or de-quantised (`alg_unquant`),
//! or noise/folding fills an empty band. [`quant_band_n1`] handles the single-coefficient case and
//! [`quant_band_stereo`] the two-channel one. These draw bits from the shared [`BandCtx`] budget;
//! the wrappers ([`quant_band`] / [`quant_all_bands`]) sit above and orchestrate tf-resolution + the
//! per-band loop.
//!
//! libopus writes this once and branches on an `encode` flag at every symbol; the Rust equivalent
//! is the [`CeltCoder`] generic parameter, so there is exactly one copy of the band recursion and
//! the two directions cannot drift apart. The same holds across channel counts: mono and stereo
//! share `quant_partition`/`quant_band`, and `quant_band_stereo` is the one extra body libopus has.

use crate::opus::celt::bands::{
    bitexact_cos, bitexact_log2tan, compute_channel_weights, compute_qn, deinterleave_hadamard,
    frac_mul16, haar1, intensity_stereo, interleave_hadamard, stereo_merge, stereo_split,
};
use crate::opus::celt::entropy::CeltCoder;
use crate::opus::celt::mathops::celt_inner_prod;
use crate::opus::celt::rate::{bits2pulses, cache_max_bits, get_pulses, pulses2bits};
use crate::opus::celt::synthesis::celt_lcg_rand;
use crate::opus::celt::tables::{E_BANDS, LOG_N, NB_BANDS, SPREAD_AGGRESSIVE};
use crate::opus::celt::vq::{renormalise_vector, stereo_itheta};

const BITRES: i32 = 3;
const QTHETA_OFFSET: i32 = 4;
const QTHETA_OFFSET_TWOPHASE: i32 = 16;
/// Largest band dimension (scratch size) — 48 kHz max is 176.
const MAX_BAND: usize = 256;
/// Largest per-channel fold buffer: `M*eBands[NB_BANDS-1]` at `M = 8`, `start = 0`, i.e. 624.
const MAX_NORM: usize = 640;
/// Largest Opus packet (RFC 6716 §3.4) — the widest byte range a theta trial can dirty.
const MAX_PACKET_BYTES: usize = 1275;

/// Shared per-band coding context (libopus `band_ctx`, `bands.c:673`).
#[derive(Clone, Copy)]
pub struct BandCtx<'a> {
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
    /// decoder; for an encoder it is `theta_rdo` (`bands.c:1428`: `resynth = !encode || theta_rdo`),
    /// which needs stereo — so a mono encoder reconstructs nothing and needs no folding reference.
    pub resynth: bool,
    /// "Avoid injecting noise in the first band on transients" (`bands.c:1473`) — an encode-only
    /// guard that pushes `theta` to a pole when the bit split would starve one side.
    pub avoid_split_noise: bool,
    /// Per-band amplitudes, `2*NB_BANDS` (libopus `ctx->bandE`) — the mixing weights
    /// [`intensity_stereo`] uses. Only ever read on a **stereo encode**; a decoder and a mono
    /// encoder pass an empty slice, which no reachable path indexes.
    pub band_energy: &'a [f32],
    /// Rounding direction for the stereo theta rate-distortion trial (libopus `ctx->theta_round`):
    /// 0 = nearest (the normal path), -1 = round down, +1 = round up.
    pub theta_round: i32,
}

/// The mid/side split decision (libopus `split_ctx`).
#[derive(Default)]
struct SplitCtx {
    /// Stereo phase-inversion flag; only the stereo band path acts on it.
    inv: bool,
    imid: i32,
    iside: i32,
    delta: i32,
    itheta: i32,
    qalloc: i32,
}

/// Code the split angle `theta` and derive the mid/side gains + bit-split `delta` (libopus
/// `compute_theta`, `bands.c:700`). Consumes bits from `*b` and may mask `*fill`.
///
/// `x`/`y` are the two halves being split (mono time split) or the two channels (stereo). The
/// decoder only reads the coded angle; the encoder measures their energies to pick it, and on the
/// stereo path additionally rewrites `x`/`y` in place — either collapsing them with
/// [`intensity_stereo`] or rotating them with [`stereo_split`], exactly as `bands.c:836` does.
#[allow(clippy::too_many_arguments)]
fn compute_theta<C: CeltCoder>(
    ctx: &BandCtx,
    sctx: &mut SplitCtx,
    x: &mut [f32],
    y: &mut [f32],
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
    let mut inv = false;
    if qn != 1 {
        if C::ENCODE {
            if !stereo || ctx.theta_round == 0 {
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
            } else {
                // "Bias quantization towards itheta=0 and itheta=16384" for the RD trial's two
                // rounding directions (bands.c:764).
                let bias = if itheta > 8192 {
                    32767 / qn
                } else {
                    -32767 / qn
                };
                let down = (qn - 1).min(0.max((itheta * qn + bias) >> 14));
                itheta = if ctx.theta_round < 0 { down } else { down + 1 };
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
        if C::ENCODE && stereo {
            // The encoder now has to *produce* what the decoder will reconstruct: either the
            // intensity-collapsed mono band, or the mid/side rotation (bands.c:836).
            if itheta == 0 {
                intensity_stereo(x, y, ctx.band_energy, ctx.band, n);
            } else {
                stereo_split(x, y, n);
            }
        }
    } else if stereo {
        // Pure intensity stereo: no angle, just the phase-inversion flag (bands.c:845).
        if C::ENCODE {
            inv = itheta > 8192 && !ctx.disable_inv;
            if inv {
                for v in y[..n].iter_mut() {
                    *v = -*v;
                }
            }
            intensity_stereo(x, y, ctx.band_energy, ctx.band, n);
        }
        if *b > 2 << BITRES && ctx.remaining_bits > 2 << BITRES {
            coder.code_bit_logp(&mut inv, 2);
        } else {
            inv = false;
        }
        // "inv flag override to avoid problems with downmixing." (bands.c:862)
        if ctx.disable_inv {
            inv = false;
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

    sctx.inv = inv;
    sctx.imid = imid;
    sctx.iside = iside;
    sctx.delta = delta;
    sctx.itheta = itheta;
    sctx.qalloc = qalloc;
}

/// One channel of the single-coefficient band: its sign bit (libopus `quant_band_n1`'s loop body).
fn quant_band_n1_channel<C: CeltCoder>(ctx: &mut BandCtx, x: &mut [f32], coder: &mut C) {
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
}

/// Code a single-coefficient band: one sign bit per channel (libopus `quant_band_n1`,
/// `bands.c:904`). `y` carries the second channel on a stereo band.
pub fn quant_band_n1<C: CeltCoder>(
    ctx: &mut BandCtx,
    x: &mut [f32],
    y: Option<&mut [f32]>,
    lowband_out: Option<&mut [f32]>,
    coder: &mut C,
) -> u32 {
    quant_band_n1_channel(ctx, x, coder);
    if let Some(y) = y {
        quant_band_n1_channel(ctx, y, coder);
    }
    if let Some(lo) = lowband_out {
        // `SHR16(X[0],4)` — the identity in the float build (`arch.h`).
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
            let (x_lo, x_hi) = x.split_at_mut(half);
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
        return quant_band_n1(ctx, x, None, lowband_out, coder);
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

/// Code one **stereo** band (libopus `quant_band_stereo`, `bands.c:1235`): code the mid/side angle,
/// then hand the mid and the side to the mono [`quant_band`] with the bit split `theta` implies, and
/// (when resynthesising) undo the rotation with [`stereo_merge`].
///
/// `N == 2` is a special case: mid and side are orthogonal there, so the side costs a single sign
/// bit and the pair is reconstructed directly rather than merged (`bands.c:1281`).
#[allow(clippy::too_many_arguments)]
pub fn quant_band_stereo<C: CeltCoder>(
    ctx: &mut BandCtx,
    x: &mut [f32],
    y: &mut [f32],
    n: usize,
    b: i32,
    big_b: usize,
    lowband: Option<&[f32]>,
    lm: i32,
    lowband_out: Option<&mut [f32]>,
    fill: i32,
    coder: &mut C,
) -> u32 {
    if n == 1 {
        return quant_band_n1(ctx, x, Some(y), lowband_out, coder);
    }
    let orig_fill = fill;
    let mut fill = fill;
    let mut b = b;

    let mut sctx = SplitCtx::default();
    compute_theta(
        ctx, &mut sctx, x, y, n, &mut b, big_b, big_b, lm, true, &mut fill, coder,
    );
    let inv = sctx.inv;
    let mid = sctx.imid as f32 / 32768.0;
    let side = sctx.iside as f32 / 32768.0;
    let itheta = sctx.itheta;
    let delta = sctx.delta;
    let qalloc = sctx.qalloc;

    let cm;
    if n == 2 {
        // "This is a special case for N=2 that only works for stereo and takes advantage of the
        // fact that mid and side are orthogonal to encode the side with just one bit."
        // (bands.c:1277)
        let sbits = if itheta != 0 && itheta != 16384 {
            1 << BITRES
        } else {
            0
        };
        let mbits = b - sbits;
        let swap = itheta > 8192;
        ctx.remaining_bits -= qalloc + sbits;
        {
            let (x2, y2): (&mut [f32], &mut [f32]) = if swap {
                (&mut *y, &mut *x)
            } else {
                (&mut *x, &mut *y)
            };
            let mut sign = 0u32;
            if sbits != 0 {
                if C::ENCODE {
                    // Only the side's sign is left to code.
                    sign = u32::from(x2[0] * y2[1] - x2[1] * y2[0] < 0.0);
                }
                coder.code_bits(&mut sign, 1);
            }
            let signed = 1.0 - 2.0 * sign as f32;
            // "We use orig_fill here because we want to fold the side, but if itheta==16384, we'll
            // have cleared the low bits of fill." (bands.c:1305)
            cm = quant_band(
                ctx,
                x2,
                n,
                mbits,
                big_b,
                lowband,
                lm,
                lowband_out,
                1.0,
                orig_fill,
                coder,
            );
            y2[0] = -signed * x2[1];
            y2[1] = signed * x2[0];
        }
        if ctx.resynth {
            x[0] *= mid;
            x[1] *= mid;
            y[0] *= side;
            y[1] *= side;
            let tmp = x[0];
            x[0] = tmp - y[0];
            y[0] += tmp;
            let tmp = x[1];
            x[1] = tmp - y[1];
            y[1] += tmp;
        }
    } else {
        // "Normal" split code (bands.c:1329).
        let mut mbits = b.min((b - delta) / 2).max(0);
        let mut sbits = b - mbits;
        ctx.remaining_bits -= qalloc;
        let rebalance_before = ctx.remaining_bits;
        if mbits >= sbits {
            // "In stereo mode, we do not apply a scaling to the mid because we need the normalized
            // mid for folding later."
            let mut cm0 = quant_band(
                ctx,
                x,
                n,
                mbits,
                big_b,
                lowband,
                lm,
                lowband_out,
                1.0,
                fill,
                coder,
            );
            let rebalance = mbits - (rebalance_before - ctx.remaining_bits);
            if rebalance > 3 << BITRES && itheta != 0 {
                sbits += rebalance - (3 << BITRES);
            }
            // "For a stereo split, the high bits of fill are always zero, so no folding will be
            // done to the side."
            cm0 |= quant_band(
                ctx,
                y,
                n,
                sbits,
                big_b,
                None,
                lm,
                None,
                side,
                fill >> big_b,
                coder,
            );
            cm = cm0;
        } else {
            let mut cm0 = quant_band(
                ctx,
                y,
                n,
                sbits,
                big_b,
                None,
                lm,
                None,
                side,
                fill >> big_b,
                coder,
            );
            let rebalance = sbits - (rebalance_before - ctx.remaining_bits);
            if rebalance > 3 << BITRES && itheta != 16384 {
                mbits += rebalance - (3 << BITRES);
            }
            cm0 |= quant_band(
                ctx,
                x,
                n,
                mbits,
                big_b,
                lowband,
                lm,
                lowband_out,
                1.0,
                fill,
                coder,
            );
            cm = cm0;
        }
    }

    // Used by the decoder and by the resynthesis-enabled encoder (bands.c:1370).
    if ctx.resynth {
        if n != 2 {
            stereo_merge(x, y, mid, n);
        }
        if inv {
            for v in y[..n].iter_mut() {
                *v = -*v;
            }
        }
    }
    cm
}

/// Duplicate first-band folding data so the second band can fold (libopus
/// `special_hybrid_folding`). A no-op for CELT-only (`start == 0`), where `n2 == n1`.
fn special_hybrid_folding(norm: &mut [f32], norm2: &mut [f32], start: usize, m: usize, dual: bool) {
    let n1 = m * (E_BANDS[start + 1] - E_BANDS[start]) as usize;
    let n2 = m * (E_BANDS[start + 2] - E_BANDS[start + 1]) as usize;
    if n2 > n1 {
        norm.copy_within((2 * n1 - n2)..n1, n1);
        if dual {
            norm2.copy_within((2 * n1 - n2)..n1, n1);
        }
    }
}

/// Caller-owned scratch for the encoder's stereo theta rate-distortion trial (libopus keeps the
/// same buffers on the stack of `quant_all_bands`, `bands.c:1409`).
///
/// It lives in the encoder state rather than on the stack of [`quant_all_bands`] so the decode and
/// mono paths — which never run the trial — pay nothing for it, not even the zeroing.
pub struct ThetaRdo {
    x_save: [f32; MAX_BAND],
    y_save: [f32; MAX_BAND],
    x_save2: [f32; MAX_BAND],
    y_save2: [f32; MAX_BAND],
    norm_save2: [f32; MAX_BAND],
    bytes: [u8; MAX_PACKET_BYTES],
}

impl ThetaRdo {
    /// A zeroed trial buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            x_save: [0.0; MAX_BAND],
            y_save: [0.0; MAX_BAND],
            x_save2: [0.0; MAX_BAND],
            y_save2: [0.0; MAX_BAND],
            norm_save2: [0.0; MAX_BAND],
            bytes: [0; MAX_PACKET_BYTES],
        }
    }
}

impl Default for ThetaRdo {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything the stereo band path needs that the mono path does not — libopus threads these
/// through `band_ctx` plus the `quant_all_bands` argument list. Passing `None` for the whole struct
/// is what `Y_ == NULL` means in the C: a mono frame.
pub struct StereoBands<'a> {
    /// Per-band amplitudes, `2*NB_BANDS` (libopus `bandE`), feeding [`intensity_stereo`]. Read only
    /// on the encode side; a decoder passes an empty slice.
    pub band_energy: &'a [f32],
    /// First band coded with intensity stereo (libopus `st->intensity`).
    pub intensity: usize,
    /// Code L/R independently instead of mid/side (libopus `dual_stereo`).
    pub dual_stereo: bool,
    /// Encoder analysis depth; `>= 8` turns on the theta rate-distortion trial (`bands.c:1425`).
    pub complexity: i32,
    /// Caller-owned scratch for that trial. `None` disables it, which is what a decoder wants —
    /// `theta_rdo` is gated on `encode` in the reference too.
    pub rdo: Option<&'a mut ThetaRdo>,
}

/// The per-band folding buffers (libopus `norm` / `norm2`), one per coded channel.
struct FoldBuffers {
    norm: [f32; MAX_NORM],
    norm2: [f32; MAX_NORM],
}

/// Run the stereo band twice — rounding `theta` down, then up — and keep whichever reconstruction is
/// closer to the original in the channel-weighted inner-product sense (libopus `bands.c:1580`).
///
/// This is the one place the encoder must be able to *undo* coded symbols, which is why
/// [`CeltCoder`] carries a snapshot/rollback pair.
#[allow(clippy::too_many_arguments)]
fn quant_band_stereo_rdo<C: CeltCoder>(
    ctx: &mut BandCtx,
    rdo: &mut ThetaRdo,
    x: &mut [f32],
    y: &mut [f32],
    n: usize,
    b: i32,
    big_b: usize,
    lm: i32,
    fill: i32,
    weights: [f32; 2],
    hybrid_refold: Option<(usize, usize)>,
    norm: &mut [f32],
    cur_norm: usize,
    effective_lowband: i32,
    last: bool,
    coder: &mut C,
) -> u32 {
    /// One trial at the given rounding: the fold source (below `cur_norm`) and the fold destination
    /// (at `cur_norm`) are disjoint halves of `norm`, so they are re-split per trial.
    #[allow(clippy::too_many_arguments)]
    fn trial<C: CeltCoder>(
        ctx: &mut BandCtx,
        round: i32,
        x: &mut [f32],
        y: &mut [f32],
        n: usize,
        b: i32,
        big_b: usize,
        lm: i32,
        fill: i32,
        norm: &mut [f32],
        cur_norm: usize,
        effective_lowband: i32,
        last: bool,
        coder: &mut C,
    ) -> u32 {
        ctx.theta_round = round;
        let (norm_lo, norm_hi) = norm.split_at_mut(cur_norm);
        let lowband: Option<&[f32]> = if effective_lowband >= 0 {
            Some(&norm_lo[effective_lowband as usize..])
        } else {
            None
        };
        let out: Option<&mut [f32]> = if last { None } else { Some(&mut norm_hi[..n]) };
        quant_band_stereo(ctx, x, y, n, b, big_b, lowband, lm, out, fill, coder)
    }

    rdo.x_save[..n].copy_from_slice(&x[..n]);
    rdo.y_save[..n].copy_from_slice(&y[..n]);
    let coder_save = coder.save_state();
    let ctx_save = *ctx;
    let nstart = coder.coded_bytes();
    let nend = coder.buffer_len();

    // Trial 1: round theta down.
    let cm_down = trial(
        ctx,
        -1,
        x,
        y,
        n,
        b,
        big_b,
        lm,
        fill,
        norm,
        cur_norm,
        effective_lowband,
        last,
        coder,
    );
    let dist_down = weights[0] * celt_inner_prod(&rdo.x_save, x, n)
        + weights[1] * celt_inner_prod(&rdo.y_save, y, n);

    // Save trial 1's result before trying the other rounding.
    rdo.x_save2[..n].copy_from_slice(&x[..n]);
    rdo.y_save2[..n].copy_from_slice(&y[..n]);
    if !last {
        rdo.norm_save2[..n].copy_from_slice(&norm[cur_norm..cur_norm + n]);
    }
    let coder_after_down = coder.save_state();
    let saved = coder.snapshot_bytes(nstart, &mut rdo.bytes[..nend.saturating_sub(nstart)]);

    // Restore and run trial 2: round theta up.
    coder.restore_state(&coder_save);
    *ctx = ctx_save;
    x[..n].copy_from_slice(&rdo.x_save[..n]);
    y[..n].copy_from_slice(&rdo.y_save[..n]);
    if let Some((start, m)) = hybrid_refold {
        // `theta_rdo` implies `!dual_stereo`, so the second channel's fold buffer is untouched here.
        special_hybrid_folding(norm, &mut [], start, m, false);
    }
    let cm_up = trial(
        ctx,
        1,
        x,
        y,
        n,
        b,
        big_b,
        lm,
        fill,
        norm,
        cur_norm,
        effective_lowband,
        last,
        coder,
    );
    let dist_up = weights[0] * celt_inner_prod(&rdo.x_save, x, n)
        + weights[1] * celt_inner_prod(&rdo.y_save, y, n);

    // A *larger* inner product with the original is a better reconstruction, so keep trial 1 unless
    // trial 2 strictly beat it (`bands.c:1626`).
    if dist_down >= dist_up {
        coder.restore_state(&coder_after_down);
        x[..n].copy_from_slice(&rdo.x_save2[..n]);
        y[..n].copy_from_slice(&rdo.y_save2[..n]);
        if !last {
            norm[cur_norm..cur_norm + n].copy_from_slice(&rdo.norm_save2[..n]);
        }
        coder.restore_bytes(nstart, &rdo.bytes[..saved]);
        // `ctx` is left as trial 2 left it, matching `ctx = ctx_save2` in the C — the two trials
        // differ only in the bits they consumed, which the coder rollback already undid.
        cm_down
    } else {
        cm_up
    }
}

/// Code all CELT bands `start..end` of the normalised coefficient buffer `x_` (libopus
/// `quant_all_bands`, `bands.c:1398`). `x_` holds `channels * frame_len` coefficients, channel-major
/// (`Y_ = X_ + N` in the C); `stereo` is `Some` exactly when a second channel is present. Manages
/// the `norm` fold buffers and the per-band bit balance, calling [`quant_band`] /
/// [`quant_band_stereo`] per band and recording each band's collapse mask (`collapse_masks[i*C+c]`).
/// `*seed` is advanced.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn quant_all_bands<C: CeltCoder>(
    start: usize,
    end: usize,
    x_: &mut [f32],
    frame_len: usize,
    stereo: Option<&mut StereoBands<'_>>,
    collapse_masks: &mut [u8],
    pulses: &[i32],
    short_blocks: bool,
    spread: u32,
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
    let mut folds = FoldBuffers {
        norm: [0f32; MAX_NORM],
        norm2: [0f32; MAX_NORM],
    };

    let (channels, band_energy, intensity, mut dual_stereo, complexity, mut rdo) = match stereo {
        Some(s) => (
            2usize,
            s.band_energy,
            s.intensity,
            s.dual_stereo,
            s.complexity,
            s.rdo.as_deref_mut(),
        ),
        None => (1usize, &[][..], 0usize, false, 0i32, None),
    };
    // libopus: `theta_rdo = encode && Y_ != NULL && !dual_stereo && complexity >= 8`
    // (`bands.c:1425`), and `resynth = !encode || theta_rdo` (`bands.c:1428`) — so a mono encoder
    // reconstructs nothing, never folds, and always passes the all-ones fill mask. None of that is
    // *coded*, so the bitstream still matches exactly what a folding decoder reads.
    let theta_rdo = C::ENCODE && channels == 2 && !dual_stereo && complexity >= 8 && rdo.is_some();
    let resynth = !C::ENCODE || theta_rdo;

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
        band_energy,
        theta_round: 0,
    };
    let mut lowband_offset = 0usize;
    let mut update_lowband = true;

    let (x_ch0, x_ch1) = x_.split_at_mut(frame_len.min(x_.len()));

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
            special_hybrid_folding(
                &mut folds.norm[..norm_len],
                &mut folds.norm2[..norm_len],
                start,
                m,
                dual_stereo,
            );
        }

        let tf_change = tf_res[i];
        ctx.tf_change = tf_change;

        // Conservative collapse-mask estimate of the bands we'll fold from.
        let mut effective_lowband: i32 = -1;
        let (mut x_cm, mut y_cm);
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
            let (mut cm_x, mut cm_y) = (0u32, 0u32);
            let mut fold_i = fold_start;
            loop {
                cm_x |= u32::from(collapse_masks[fold_i * channels]);
                cm_y |= u32::from(collapse_masks[fold_i * channels + channels - 1]);
                fold_i += 1;
                if fold_i >= fold_end {
                    break;
                }
            }
            x_cm = cm_x;
            y_cm = cm_y;
        } else {
            x_cm = (1u32 << big_b) - 1;
            y_cm = x_cm;
        }

        // Switching off dual stereo to do intensity has to fold the two channels' references
        // together first (bands.c:1560).
        if dual_stereo && i == intensity {
            dual_stereo = false;
            if resynth {
                for j in 0..(band_lo - norm_offset) {
                    folds.norm[j] = 0.5 * (folds.norm[j] + folds.norm2[j]);
                }
            }
        }

        let cur_norm = band_lo - norm_offset;
        let x = &mut x_ch0[band_lo..band_hi];

        if channels == 2 {
            let y = &mut x_ch1[band_lo..band_hi];
            if dual_stereo {
                let (norm_lo, norm_hi) = folds.norm[..norm_len].split_at_mut(cur_norm);
                let (norm2_lo, norm2_hi) = folds.norm2[..norm_len].split_at_mut(cur_norm);
                let lowband: Option<&[f32]> = if effective_lowband >= 0 {
                    Some(&norm_lo[effective_lowband as usize..])
                } else {
                    None
                };
                let lowband2: Option<&[f32]> = if effective_lowband >= 0 {
                    Some(&norm2_lo[effective_lowband as usize..])
                } else {
                    None
                };
                let out: Option<&mut [f32]> = if last || !resynth {
                    None
                } else {
                    Some(&mut norm_hi[..n])
                };
                let out2: Option<&mut [f32]> = if last || !resynth {
                    None
                } else {
                    Some(&mut norm2_hi[..n])
                };
                x_cm = quant_band(
                    &mut ctx,
                    x,
                    n,
                    b / 2,
                    big_b,
                    lowband,
                    lm,
                    out,
                    1.0,
                    x_cm as i32,
                    coder,
                );
                y_cm = quant_band(
                    &mut ctx,
                    y,
                    n,
                    b / 2,
                    big_b,
                    lowband2,
                    lm,
                    out2,
                    1.0,
                    y_cm as i32,
                    coder,
                );
            } else {
                let fill = (x_cm | y_cm) as i32;
                let run_rdo = theta_rdo && i < intensity;
                if run_rdo {
                    // `rdo` is `Some` whenever `theta_rdo` is set (it is part of the condition).
                    if let Some(rdo) = rdo.as_deref_mut() {
                        let weights =
                            compute_channel_weights(band_energy[i], band_energy[i + NB_BANDS]);
                        let hybrid_refold = if i == start + 1 {
                            Some((start, m))
                        } else {
                            None
                        };
                        x_cm = quant_band_stereo_rdo(
                            &mut ctx,
                            rdo,
                            x,
                            y,
                            n,
                            b,
                            big_b,
                            lm,
                            fill,
                            weights,
                            hybrid_refold,
                            &mut folds.norm[..norm_len],
                            cur_norm,
                            effective_lowband,
                            last,
                            coder,
                        );
                    }
                } else {
                    let (norm_lo, norm_hi) = folds.norm[..norm_len].split_at_mut(cur_norm);
                    let lowband: Option<&[f32]> = if effective_lowband >= 0 {
                        Some(&norm_lo[effective_lowband as usize..])
                    } else {
                        None
                    };
                    let out: Option<&mut [f32]> = if last || !resynth {
                        None
                    } else {
                        Some(&mut norm_hi[..n])
                    };
                    ctx.theta_round = 0;
                    x_cm = quant_band_stereo(
                        &mut ctx, x, y, n, b, big_b, lowband, lm, out, fill, coder,
                    );
                }
                y_cm = x_cm;
            }
        } else {
            let (norm_lo, norm_hi) = folds.norm[..norm_len].split_at_mut(cur_norm);
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
            x_cm = quant_band(
                &mut ctx,
                x,
                n,
                b,
                big_b,
                lowband,
                lm,
                lowband_out,
                1.0,
                (x_cm | y_cm) as i32,
                coder,
            );
            y_cm = x_cm;
        }

        collapse_masks[i * channels] = x_cm as u8;
        collapse_masks[i * channels + channels - 1] = y_cm as u8;
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

    fn decode_ctx<'a>(band: usize, tf_change: i32, remaining_bits: i32, seed: u32) -> BandCtx<'a> {
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
            band_energy: &[],
            theta_round: 0,
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
        let n_total = m * 120; // N = M*shortMdctSize
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
            n_total,
            None,
            &mut collapse,
            &pulses,
            false,
            2,
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
        let cm = quant_band_n1(&mut ctx, &mut x, None, Some(&mut lo), &mut dec);
        assert_eq!(cm, 1);
        assert!(x[0] == 1.0 || x[0] == -1.0);
        assert_eq!(lo[0], x[0]);
        assert_eq!(ctx.remaining_bits, 64 - (1 << BITRES));
    }

    /// A stereo `N == 1` band spends one sign bit *per channel* (`bands.c:912` loops over
    /// `1 + stereo`), and the fold reference still comes from the first channel.
    #[test]
    fn quant_band_n1_stereo_codes_both_channel_signs() {
        let mut buf = vec![0u8; 16];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            enc.enc_bits(1, 1);
            enc.enc_bits(0, 1);
            enc.done();
        }
        let mut ctx = decode_ctx(0, 0, 64, 1);
        let mut x = [0.0f32];
        let mut y = [0.0f32];
        let mut lo = [0.0f32];
        let mut dec = RangeDecoder::new(&buf);
        let cm = quant_band_n1(&mut ctx, &mut x, Some(&mut y), Some(&mut lo), &mut dec);
        assert_eq!(cm, 1);
        assert_eq!(lo[0], x[0]);
        assert_eq!(
            ctx.remaining_bits,
            64 - 2 * (1 << BITRES),
            "two sign bits must be charged"
        );
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

    /// A two-channel normalised spectrum whose channels correlate by `correlation`.
    fn synthetic_stereo_spectrum(m: usize, seed: u32, correlation: f32) -> Vec<f32> {
        let frame = m * 120;
        let left = synthetic_normalised_spectrum(m, seed);
        let right = synthetic_normalised_spectrum(m, seed ^ 0x5EED);
        let mut out = vec![0f32; 2 * frame];
        for i in 0..NB_BANDS {
            let lo = m * E_BANDS[i] as usize;
            let hi = m * E_BANDS[i + 1] as usize;
            for j in lo..hi {
                out[j] = left[j];
                out[frame + j] = correlation * left[j] + (1.0 - correlation.abs()) * right[j];
            }
        }
        // Renormalise the right channel per band so both are unit-norm, as `normalise_bands` leaves
        // them.
        for i in 0..NB_BANDS {
            let lo = frame + m * E_BANDS[i] as usize;
            let hi = frame + m * E_BANDS[i + 1] as usize;
            let norm = out[lo..hi].iter().map(|v| v * v).sum::<f32>().sqrt();
            if norm > 0.0 {
                for slot in out[lo..hi].iter_mut() {
                    *slot /= norm;
                }
            }
        }
        out
    }

    /// Per-band amplitudes to drive `intensity_stereo`'s mixing weights.
    fn synthetic_band_energy(tilt: f32) -> Vec<f32> {
        (0..2 * NB_BANDS)
            .map(|i| {
                let band = i % NB_BANDS;
                let channel = i / NB_BANDS;
                (1.0 + band as f32 * 0.3) * if channel == 0 { 1.0 } else { tilt }
            })
            .collect()
    }

    /// Encode a whole frame's bands, then decode it: both sides must end on the identical
    /// `tell_frac` and range value, across every frame size, transient/non-transient, spread
    /// setting, and a wide budget spread.
    #[test]
    fn quant_all_bands_encode_then_decode_agrees_on_the_bitstream() {
        for lm in 0..4i32 {
            let m = 1usize << lm;
            let frame = m * 120;
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
                        enc_x.resize(frame, 0.0);
                        let mut enc_collapse = vec![0u8; NB_BANDS];
                        let mut enc_seed = 0x1234_5678u32;
                        let (enc_tell, enc_rng);
                        {
                            let mut enc = RangeEncoder::new(&mut buf);
                            quant_all_bands(
                                0,
                                NB_BANDS,
                                &mut enc_x,
                                frame,
                                None,
                                &mut enc_collapse,
                                &pulses,
                                short_blocks,
                                spread,
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

                        let mut dec_x = vec![0f32; frame];
                        let mut dec_collapse = vec![0u8; NB_BANDS];
                        let mut dec_seed = 0x1234_5678u32;
                        let mut dec = RangeDecoder::new(&buf);
                        quant_all_bands(
                            0,
                            NB_BANDS,
                            &mut dec_x,
                            frame,
                            None,
                            &mut dec_collapse,
                            &pulses,
                            short_blocks,
                            spread,
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

    /// The same gate for **stereo**, swept over the mid/side and dual-stereo modes, the whole
    /// intensity range (0 collapses every band to intensity stereo; `NB_BANDS` codes none that way),
    /// the phase-inversion flag, and complexity 8 (the theta rate-distortion trial). A stereo
    /// desync would show up here as a `tell_frac` or `final_range` mismatch.
    #[test]
    fn quant_all_bands_stereo_encode_then_decode_agrees_on_the_bitstream() {
        for lm in 0..4i32 {
            let m = 1usize << lm;
            let frame = m * 120;
            for &short_blocks in &[false, true] {
                for &dual in &[false, true] {
                    for &intensity in &[0usize, 6, 14, NB_BANDS] {
                        for &disable_inv in &[false, true] {
                            for &complexity in &[5i32, 8] {
                                for &bytes in &[24usize, 80, 300, 800] {
                                    let pulses: Vec<i32> = (0..NB_BANDS)
                                        .map(|i| ((bytes as i32) * 2).max(0) - (i as i32) * 8)
                                        .map(|p| p.max(0))
                                        .collect();
                                    let tf_res: Vec<i32> = (0..NB_BANDS)
                                        .map(|i| if short_blocks { 0 } else { -(i as i32 % 2) })
                                        .collect();
                                    let total_bits = (bytes as i32) * (8 << BITRES);
                                    let band_energy = synthetic_band_energy(0.4);
                                    let source =
                                        synthetic_stereo_spectrum(m, 0xA11CE + lm as u32, 0.6);

                                    let mut buf = vec![0u8; bytes];
                                    let mut enc_x = source.clone();
                                    let mut enc_collapse = vec![0u8; 2 * NB_BANDS];
                                    let mut enc_seed = 0x1234_5678u32;
                                    let mut rdo = ThetaRdo::new();
                                    let (enc_tell, enc_rng);
                                    {
                                        let mut enc = RangeEncoder::new(&mut buf);
                                        let mut stereo = StereoBands {
                                            band_energy: &band_energy,
                                            intensity,
                                            dual_stereo: dual,
                                            complexity,
                                            rdo: Some(&mut rdo),
                                        };
                                        quant_all_bands(
                                            0,
                                            NB_BANDS,
                                            &mut enc_x,
                                            frame,
                                            Some(&mut stereo),
                                            &mut enc_collapse,
                                            &pulses,
                                            short_blocks,
                                            2,
                                            &tf_res,
                                            total_bits,
                                            0,
                                            lm,
                                            NB_BANDS,
                                            &mut enc_seed,
                                            disable_inv,
                                            &mut enc,
                                        );
                                        enc_tell = enc.tell_frac();
                                        enc_rng = CeltCoder::rng(&enc);
                                        enc.done();
                                        assert!(!enc.error(), "encoder overflow");
                                    }

                                    let mut dec_x = vec![0f32; 2 * frame];
                                    let mut dec_collapse = vec![0u8; 2 * NB_BANDS];
                                    let mut dec_seed = 0x1234_5678u32;
                                    let mut dec = RangeDecoder::new(&buf);
                                    let mut stereo = StereoBands {
                                        band_energy: &[],
                                        intensity,
                                        dual_stereo: dual,
                                        complexity: 0,
                                        rdo: None,
                                    };
                                    quant_all_bands(
                                        0,
                                        NB_BANDS,
                                        &mut dec_x,
                                        frame,
                                        Some(&mut stereo),
                                        &mut dec_collapse,
                                        &pulses,
                                        short_blocks,
                                        2,
                                        &tf_res,
                                        total_bits,
                                        0,
                                        lm,
                                        NB_BANDS,
                                        &mut dec_seed,
                                        disable_inv,
                                        &mut dec,
                                    );
                                    let tag = format!(
                                        "lm={lm} short={short_blocks} dual={dual} \
                                         intensity={intensity} inv_off={disable_inv} \
                                         complexity={complexity} bytes={bytes}"
                                    );
                                    assert_eq!(
                                        dec.tell_frac(),
                                        enc_tell,
                                        "{tag}: tell_frac diverged"
                                    );
                                    assert_eq!(
                                        CeltCoder::rng(&dec),
                                        enc_rng,
                                        "{tag}: final_range diverged"
                                    );
                                    // The encoder only masks `cm` down to `(1<<B)-1` when it
                                    // resynthesises (`bands.c:1219` is inside the resynth block),
                                    // and it only resynthesises for the theta trial. Elsewhere its
                                    // masks are write-only — `lowband_offset` stays 0 without
                                    // resynth, so nothing ever folds from them — so they are only
                                    // comparable when the trial is on.
                                    if complexity >= 8 && !dual {
                                        assert_eq!(
                                            dec_collapse, enc_collapse,
                                            "{tag}: collapse masks diverged"
                                        );
                                    }
                                    assert!(
                                        dec_x.iter().all(|v| v.is_finite()),
                                        "{tag}: non-finite reconstruction"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Both stereo channels must actually be reconstructed — bit agreement alone would also hold
    /// for a coder that dropped the side and duplicated the mid.
    #[test]
    fn quant_all_bands_stereo_reconstructs_both_channels() {
        let lm = 3i32;
        let m = 1usize << lm;
        let frame = m * 120;
        let bytes = 500usize;
        let pulses: Vec<i32> = (0..NB_BANDS).map(|i| 900 - (i as i32) * 20).collect();
        let tf_res = vec![0i32; NB_BANDS];
        let total_bits = (bytes as i32) * (8 << BITRES);
        let band_energy = synthetic_band_energy(1.0);
        // Deliberately *uncorrelated* channels, so a mid-only reconstruction cannot pass.
        let source = synthetic_stereo_spectrum(m, 0xBEEF, 0.0);

        let mut buf = vec![0u8; bytes];
        let mut enc_x = source.clone();
        let mut enc_collapse = vec![0u8; 2 * NB_BANDS];
        let mut enc_seed = 11u32;
        {
            let mut enc = RangeEncoder::new(&mut buf);
            let mut stereo = StereoBands {
                band_energy: &band_energy,
                intensity: NB_BANDS,
                dual_stereo: false,
                complexity: 5,
                rdo: None,
            };
            quant_all_bands(
                0,
                NB_BANDS,
                &mut enc_x,
                frame,
                Some(&mut stereo),
                &mut enc_collapse,
                &pulses,
                false,
                2,
                &tf_res,
                total_bits,
                0,
                lm,
                NB_BANDS,
                &mut enc_seed,
                false,
                &mut enc,
            );
            enc.done();
            assert!(!enc.error());
        }
        let mut dec_x = vec![0f32; 2 * frame];
        let mut dec_collapse = vec![0u8; 2 * NB_BANDS];
        let mut dec_seed = 11u32;
        let mut dec = RangeDecoder::new(&buf);
        let mut stereo = StereoBands {
            band_energy: &[],
            intensity: NB_BANDS,
            dual_stereo: false,
            complexity: 0,
            rdo: None,
        };
        quant_all_bands(
            0,
            NB_BANDS,
            &mut dec_x,
            frame,
            Some(&mut stereo),
            &mut dec_collapse,
            &pulses,
            false,
            2,
            &tf_res,
            total_bits,
            0,
            lm,
            NB_BANDS,
            &mut dec_seed,
            false,
            &mut dec,
        );
        let correlation = |a: &[f32], b: &[f32]| -> f32 {
            let dot: f32 = a.iter().zip(b).map(|(p, q)| p * q).sum();
            let na = a.iter().map(|v| v * v).sum::<f32>().sqrt();
            let nb = b.iter().map(|v| v * v).sum::<f32>().sqrt();
            if na * nb > 0.0 {
                dot / (na * nb)
            } else {
                0.0
            }
        };
        for i in 0..10 {
            let lo = m * E_BANDS[i] as usize;
            let hi = m * E_BANDS[i + 1] as usize;
            let left = correlation(&source[lo..hi], &dec_x[lo..hi]);
            let right = correlation(
                &source[frame + lo..frame + hi],
                &dec_x[frame + lo..frame + hi],
            );
            assert!(left > 0.5, "band {i}: left channel correlation {left}");
            assert!(right > 0.5, "band {i}: right channel correlation {right}");
        }
    }

    /// The decoded spectrum must actually resemble the encoded one — bit agreement alone could be
    /// achieved by a stream that codes the wrong shapes.
    #[test]
    fn quant_all_bands_reconstruction_correlates_with_the_input() {
        let lm = 3i32;
        let m = 1usize << lm;
        let frame = m * 120;
        let bytes = 400usize;
        let pulses: Vec<i32> = (0..NB_BANDS).map(|i| 700 - (i as i32) * 20).collect();
        let tf_res = vec![0i32; NB_BANDS];
        let total_bits = (bytes as i32) * (8 << BITRES);
        let mut source = synthetic_normalised_spectrum(m, 0xC0DE);
        source.resize(frame, 0.0);

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
                frame,
                None,
                &mut enc_collapse,
                &pulses,
                false,
                2,
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
        let mut dec_x = vec![0f32; frame];
        let mut dec_collapse = vec![0u8; NB_BANDS];
        let mut dec_seed = 7u32;
        let mut dec = RangeDecoder::new(&buf);
        quant_all_bands(
            0,
            NB_BANDS,
            &mut dec_x,
            frame,
            None,
            &mut dec_collapse,
            &pulses,
            false,
            2,
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
