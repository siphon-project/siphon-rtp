//! CELT bit allocation (RFC 6716 §4.3.3; libopus `celt/rate.c` + `init_caps` from `celt.c`).
//!
//! **Phase 3e.** Converts the decoded per-band dynalloc boosts, the allocation `trim`, and the frame
//! bit budget into a per-band PVQ bit count (`pulses`), fine-energy bit count (`ebits`), and
//! `fine_priority`, plus the stereo `intensity`/`dual_stereo` parameters — returning the number of
//! coded bands. A faithful port of `clt_compute_allocation` + `interp_bits2pulses` (decoder path):
//! a two-level bisection (over the static allocation matrix, then a fine interpolation) that fits the
//! allocation to the budget, with per-band skip decisions read from the range coder.
//!
//! All arithmetic is in 1/8-bit units (`BITRES = 3`); shifts mix with arithmetic exactly as in the C
//! (explicit parens preserve the C precedence). The cache lookup that turns a band's bit count into a
//! pulse count `K` lives in `quant_all_bands` (`bits2pulses`), not here.

use crate::opus::celt::energy::MAX_FINE_BITS;
use crate::opus::celt::entropy::CeltCoder;
use crate::opus::celt::tables::{BAND_ALLOCATION, CACHE_CAPS50, E_BANDS, LOG_N, NB_BANDS};

/// Bisection steps for the fine interpolation (libopus `ALLOC_STEPS`).
const ALLOC_STEPS: i32 = 6;
/// Fine-energy bit offset relative to the "fair share" (libopus `FINE_OFFSET`).
const FINE_OFFSET: i32 = 21;
/// Bit-resolution shift (libopus `BITRES`).
const BITRES: i32 = 3;
/// Number of allocation preset vectors (libopus `nbAllocVectors`).
const NB_ALLOC_VECTORS: i32 = 11;

/// Bit cost (1/8 bits) to skip-signal each remaining band span (libopus `LOG2_FRAC_TABLE`).
const LOG2_FRAC_TABLE: [u8; 24] = [
    0, 8, 13, 16, 19, 21, 23, 24, 26, 27, 28, 29, 30, 31, 32, 32, 33, 34, 34, 35, 36, 36, 37, 37,
];

/// Binary-search depth for [`bits2pulses`] (libopus `LOG_MAX_PSEUDO`).
const LOG_MAX_PSEUDO: usize = 6;

/// Per-`(LM,band)` offsets into [`CACHE_BITS50`] (libopus `cache_index50`, `static_modes_float.h`),
/// indexed `(LM+1)*NB_BANDS + band`. The `-1` entries are unused `(LM,band)` combinations.
const CACHE_INDEX50: [i16; 105] = [
    -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 41, 41, 41, 82, 82, 123, 164, 200, 222, 0, 0, 0, 0,
    0, 0, 0, 0, 41, 41, 41, 41, 123, 123, 123, 164, 164, 240, 266, 283, 295, 41, 41, 41, 41, 41,
    41, 41, 41, 123, 123, 123, 123, 240, 240, 240, 266, 266, 305, 318, 328, 336, 123, 123, 123,
    123, 123, 123, 123, 123, 240, 240, 240, 240, 305, 305, 305, 318, 318, 343, 351, 358, 364, 240,
    240, 240, 240, 240, 240, 240, 240, 305, 305, 305, 305, 343, 343, 343, 351, 351, 370, 376, 382,
    387,
];

/// Per-band PVQ bit-cost cache (libopus `cache_bits50`). At a band's offset `c` (from
/// [`CACHE_INDEX50`]), `c[0]` is the entry count and `c[k]` is the cost (in bits−1) of
/// `get_pulses(k)` pulses; costs increase monotonically with `k`.
const CACHE_BITS50: [u8; 392] = [
    40, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 40, 15, 23, 28, 31, 34, 36, 38, 39, 41, 42, 43, 44, 45, 46, 47,
    47, 49, 50, 51, 52, 53, 54, 55, 55, 57, 58, 59, 60, 61, 62, 63, 63, 65, 66, 67, 68, 69, 70, 71,
    71, 40, 20, 33, 41, 48, 53, 57, 61, 64, 66, 69, 71, 73, 75, 76, 78, 80, 82, 85, 87, 89, 91, 92,
    94, 96, 98, 101, 103, 105, 107, 108, 110, 112, 114, 117, 119, 121, 123, 124, 126, 128, 40, 23,
    39, 51, 60, 67, 73, 79, 83, 87, 91, 94, 97, 100, 102, 105, 107, 111, 115, 118, 121, 124, 126,
    129, 131, 135, 139, 142, 145, 148, 150, 153, 155, 159, 163, 166, 169, 172, 174, 177, 179, 35,
    28, 49, 65, 78, 89, 99, 107, 114, 120, 126, 132, 136, 141, 145, 149, 153, 159, 165, 171, 176,
    180, 185, 189, 192, 199, 205, 211, 216, 220, 225, 229, 232, 239, 245, 251, 21, 33, 58, 79, 97,
    112, 125, 137, 148, 157, 166, 174, 182, 189, 195, 201, 207, 217, 227, 235, 243, 251, 17, 35,
    63, 86, 106, 123, 139, 152, 165, 177, 187, 197, 206, 214, 222, 230, 237, 250, 25, 31, 55, 75,
    91, 105, 117, 128, 138, 146, 154, 161, 168, 174, 180, 185, 190, 200, 208, 215, 222, 229, 235,
    240, 245, 255, 16, 36, 65, 89, 110, 128, 144, 159, 173, 185, 196, 207, 217, 226, 234, 242, 250,
    11, 41, 74, 103, 128, 151, 172, 191, 209, 225, 241, 255, 9, 43, 79, 110, 138, 163, 186, 207,
    227, 246, 12, 39, 71, 99, 123, 144, 164, 182, 198, 214, 228, 241, 253, 9, 44, 81, 113, 142,
    168, 192, 214, 235, 255, 7, 49, 90, 127, 160, 191, 220, 247, 6, 51, 95, 134, 170, 203, 234, 7,
    47, 87, 123, 155, 184, 212, 237, 6, 52, 97, 137, 174, 208, 240, 5, 57, 106, 151, 192, 231, 5,
    59, 111, 158, 202, 243, 5, 55, 103, 147, 187, 224, 5, 60, 113, 161, 206, 248, 4, 65, 122, 175,
    224, 4, 67, 127, 182, 234,
];

/// Per-band maximum bit allocation for the frame size (`lm`) and channel count (libopus
/// `init_caps`, `celt.c`). `cap[i]` is in eighth-bits.
pub fn init_caps(cap: &mut [i32; NB_BANDS], lm: usize, channels: usize) {
    let c = channels as i32;
    for (i, cap_i) in cap.iter_mut().enumerate() {
        let n = i32::from(E_BANDS[i + 1] - E_BANDS[i]) << lm;
        let caps = i32::from(CACHE_CAPS50[NB_BANDS * (2 * lm + channels - 1) + i]);
        *cap_i = ((caps + 64) * c * n) >> 2;
    }
}

/// Pseudo-pulse index → actual pulse count `K` (libopus `get_pulses`): identity below 8, then
/// geometrically spaced.
#[must_use]
pub fn get_pulses(i: usize) -> i32 {
    if i < 8 {
        i as i32
    } else {
        ((8 + (i & 7)) << ((i >> 3) - 1)) as i32
    }
}

/// The band's pulse-cost cache slice for frame size `lm` (`lm` may be −1 deep in the band-split
/// recursion → row 0).
#[inline]
fn band_cache(band: usize, lm: i32) -> &'static [u8] {
    let cache_off = CACHE_INDEX50[(lm + 1) as usize * NB_BANDS + band] as usize;
    &CACHE_BITS50[cache_off..]
}

/// Map a band's allocated bit budget to a pseudo-pulse index via the cost cache (libopus
/// `bits2pulses`). Feed the result through [`get_pulses`] to get the actual pulse count `K`.
#[must_use]
pub fn bits2pulses(band: usize, lm: i32, bits: i32) -> usize {
    let cache = band_cache(band, lm);
    let mut lo = 0usize;
    let mut hi = cache[0] as usize;
    let bits = bits - 1;
    for _ in 0..LOG_MAX_PSEUDO {
        let mid = (lo + hi + 1) >> 1;
        if i32::from(cache[mid]) >= bits {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    let lo_cost = if lo == 0 { -1 } else { i32::from(cache[lo]) };
    if bits - lo_cost <= i32::from(cache[hi]) - bits {
        lo
    } else {
        hi
    }
}

/// Map a pseudo-pulse index back to its bit cost for a band (libopus `pulses2bits`).
#[must_use]
pub fn pulses2bits(band: usize, lm: i32, pulses: usize) -> i32 {
    let cache = band_cache(band, lm);
    if pulses == 0 {
        0
    } else {
        i32::from(cache[pulses]) + 1
    }
}

/// The bit cost of the band's maximum pulse count (libopus `cache[cache[0]]`) — the band-split
/// decision threshold in `quant_partition`.
#[must_use]
pub fn cache_max_bits(band: usize, lm: i32) -> i32 {
    let cache = band_cache(band, lm);
    i32::from(cache[cache[0] as usize])
}

/// Interpolate the fine allocation point and split each band's budget into PVQ bits + fine-energy
/// bits, coding the skip / intensity / dual-stereo decisions (libopus `interp_bits2pulses`,
/// `rate.c:263`). Returns the number of coded (non-skipped) bands.
///
/// The skip loop is the only part of the allocator that is *not* mandated by the bitstream: an
/// encoder chooses which bands to drop and signals each choice, a decoder just reads the flags
/// (`rate.c:346-372`). `prev` (the previous frame's coded-band count) and `signal_bandwidth` feed
/// that encoder-only decision.
#[allow(clippy::too_many_arguments)]
fn interp_bits2pulses<C: CeltCoder>(
    start: usize,
    end: usize,
    skip_start: usize,
    bits1: &[i32],
    bits2: &[i32],
    thresh: &[i32],
    cap: &[i32],
    mut total: i32,
    balance: &mut i32,
    skip_rsv: i32,
    intensity: &mut usize,
    mut intensity_rsv: i32,
    dual_stereo: &mut bool,
    mut dual_stereo_rsv: i32,
    bits: &mut [i32],
    ebits: &mut [i32],
    fine_priority: &mut [i32],
    channels: usize,
    lm: usize,
    prev: usize,
    signal_bandwidth: usize,
    coder: &mut C,
) -> usize {
    let c = channels as i32;
    let alloc_floor = c << BITRES;
    let stereo_shift = i32::from(channels > 1);
    let log_m = (lm as i32) << BITRES;

    // Bisect for the interpolation point between bits1 and bits2.
    let mut lo = 0i32;
    let mut hi = 1 << ALLOC_STEPS;
    for _ in 0..ALLOC_STEPS {
        let mid = (lo + hi) >> 1;
        let mut psum = 0i32;
        let mut done = false;
        for j in (start..end).rev() {
            let tmp = bits1[j] + ((mid * bits2[j]) >> ALLOC_STEPS);
            if tmp >= thresh[j] || done {
                done = true;
                psum += tmp.min(cap[j]); // don't allocate more than usable
            } else if tmp >= alloc_floor {
                psum += alloc_floor;
            }
        }
        if psum > total {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    // Final per-band allocation at the chosen `lo`.
    let mut psum = 0i32;
    let mut done = false;
    for j in (start..end).rev() {
        let mut tmp = bits1[j] + ((lo * bits2[j]) >> ALLOC_STEPS);
        if tmp < thresh[j] && !done {
            tmp = if tmp >= alloc_floor { alloc_floor } else { 0 };
        } else {
            done = true;
        }
        tmp = tmp.min(cap[j]);
        bits[j] = tmp;
        psum += tmp;
    }

    // Decide which bands to skip, working backwards from the end.
    let mut coded_bands = end;
    loop {
        let j = coded_bands - 1;
        if j <= skip_start {
            total += skip_rsv; // give back the reserved end-of-skip bit
            break;
        }
        let mut left = total - psum;
        let span = E_BANDS[coded_bands] as i32 - E_BANDS[start] as i32;
        let percoeff = left / span;
        left -= span * percoeff;
        let rem = (left - (E_BANDS[j] as i32 - E_BANDS[start] as i32)).max(0);
        let band_width = E_BANDS[coded_bands] as i32 - E_BANDS[j] as i32;
        let mut band_bits = bits[j] + percoeff * band_width + rem;
        // Only code a skip decision if we're above the threshold for this band; otherwise it is
        // force-skipped (this ensures we have enough bits to code the skip flag).
        if band_bits >= thresh[j].max(alloc_floor + (1 << BITRES)) {
            let mut stop = false;
            if C::ENCODE {
                // "We choose a threshold with some hysteresis to keep bands from fluctuating in and
                // out, but we try not to fold below a certain point." (rate.c:352)
                let depth_threshold = if coded_bands > 17 {
                    if j < prev {
                        7
                    } else {
                        9
                    }
                } else {
                    0
                };
                stop = coded_bands <= start + 2
                    || (band_bits > ((depth_threshold * band_width) << lm << BITRES) >> 4
                        && j <= signal_bandwidth);
            }
            coder.code_bit_logp(&mut stop, 1);
            if stop {
                break;
            }
            psum += 1 << BITRES; // a bit was spent on the skip flag
            band_bits -= 1 << BITRES;
        }
        // Reclaim this band's bits.
        psum -= bits[j] + intensity_rsv;
        if intensity_rsv > 0 {
            intensity_rsv = i32::from(LOG2_FRAC_TABLE[j - start]);
        }
        psum += intensity_rsv;
        if band_bits >= alloc_floor {
            psum += alloc_floor;
            bits[j] = alloc_floor;
        } else {
            bits[j] = 0;
        }
        coded_bands -= 1;
    }

    // Intensity / dual-stereo parameters.
    if intensity_rsv > 0 {
        if C::ENCODE {
            *intensity = (*intensity).min(coded_bands);
        }
        let mut value = (*intensity).saturating_sub(start) as u32;
        coder.code_uint(&mut value, (coded_bands + 1 - start) as u32);
        *intensity = start + value as usize;
    } else {
        *intensity = 0;
    }
    if *intensity <= start {
        total += dual_stereo_rsv;
        dual_stereo_rsv = 0;
    }
    if dual_stereo_rsv > 0 {
        coder.code_bit_logp(dual_stereo, 1);
    } else {
        *dual_stereo = false;
    }

    // Distribute the remaining bits proportionally across the coded bands.
    let mut left = total - psum;
    let span = E_BANDS[coded_bands] as i32 - E_BANDS[start] as i32;
    let percoeff = left / span;
    left -= span * percoeff;
    for j in start..coded_bands {
        bits[j] += percoeff * (E_BANDS[j + 1] as i32 - E_BANDS[j] as i32);
    }
    for j in start..coded_bands {
        let tmp = left.min(E_BANDS[j + 1] as i32 - E_BANDS[j] as i32);
        bits[j] += tmp;
        left -= tmp;
    }

    // Split each band into fine-energy bits + PVQ bits.
    let mut balance_val = 0i32;
    for j in start..coded_bands {
        let n0 = E_BANDS[j + 1] as i32 - E_BANDS[j] as i32;
        let n = n0 << lm;
        let bit = bits[j] + balance_val;
        let mut excess;
        if n > 1 {
            excess = (bit - cap[j]).max(0);
            bits[j] = bit - excess;
            // Extra degree of freedom for stereo intensity bands.
            let extra = i32::from(channels == 2 && n > 2 && !*dual_stereo && j < *intensity);
            let den = c * n + extra;
            let nclogn = den * (LOG_N[j] as i32 + log_m);
            let mut offset = (nclogn >> 1) - den * FINE_OFFSET;
            if n == 2 {
                offset += (den << BITRES) >> 2;
            }
            if bits[j] + offset < (den * 2) << BITRES {
                offset += nclogn >> 2;
            } else if bits[j] + offset < (den * 3) << BITRES {
                offset += nclogn >> 3;
            }
            ebits[j] = (bits[j] + offset + (den << (BITRES - 1))).max(0);
            ebits[j] = (ebits[j] / den) >> BITRES;
            if c * ebits[j] > (bits[j] >> BITRES) {
                ebits[j] = (bits[j] >> stereo_shift) >> BITRES;
            }
            ebits[j] = ebits[j].min(MAX_FINE_BITS);
            fine_priority[j] = i32::from(ebits[j] * (den << BITRES) >= bits[j] + offset);
            bits[j] -= (c * ebits[j]) << BITRES;
        } else {
            // N=1: all bits to fine energy except a single sign bit.
            excess = (bit - (c << BITRES)).max(0);
            bits[j] = bit - excess;
            ebits[j] = 0;
            fine_priority[j] = 1;
        }
        // Re-balance the excess (over-cap) bits into fine energy here.
        if excess > 0 {
            let extra_fine = (excess >> (stereo_shift + BITRES)).min(MAX_FINE_BITS - ebits[j]);
            ebits[j] += extra_fine;
            let extra_bits = (extra_fine * c) << BITRES;
            fine_priority[j] = i32::from(extra_bits >= excess - balance_val);
            excess -= extra_bits;
        }
        balance_val = excess;
    }
    *balance = balance_val;

    // Skipped bands spend all their bits on fine energy.
    for j in coded_bands..end {
        ebits[j] = (bits[j] >> stereo_shift) >> BITRES;
        bits[j] = 0;
        fine_priority[j] = i32::from(ebits[j] < 1);
    }
    coded_bands
}

/// Compute the full per-band bit allocation (libopus `clt_compute_allocation`, `rate.c:534`) —
/// **shared by encoder and decoder**, exactly as in libopus, so the two can never disagree on the
/// budget. Fills `pulses` (PVQ bits), `ebits` (fine bits), `fine_priority`, and
/// `intensity`/`dual_stereo`; returns the number of coded bands.
///
/// `offsets` are the dynalloc boosts, `cap` from [`init_caps`], `total` the remaining bit budget in
/// 1/8 bits. `prev` (last frame's coded-band count) and `signal_bandwidth` only affect the
/// encoder's band-skip decision; a decoder passes anything (they are unread when `!C::ENCODE`).
#[allow(clippy::too_many_arguments)]
pub fn clt_compute_allocation<C: CeltCoder>(
    start: usize,
    end: usize,
    offsets: &[i32],
    cap: &[i32],
    alloc_trim: i32,
    intensity: &mut usize,
    dual_stereo: &mut bool,
    mut total: i32,
    balance: &mut i32,
    pulses: &mut [i32],
    ebits: &mut [i32],
    fine_priority: &mut [i32],
    channels: usize,
    lm: usize,
    prev: usize,
    signal_bandwidth: usize,
    coder: &mut C,
) -> usize {
    let c = channels as i32;
    total = total.max(0);
    let mut skip_start = start;
    // Reserve a bit to signal the end of manually-skipped bands.
    let skip_rsv = if total >= 1 << BITRES { 1 << BITRES } else { 0 };
    total -= skip_rsv;
    // Reserve bits for the intensity and dual-stereo parameters.
    let mut intensity_rsv = 0i32;
    let mut dual_stereo_rsv = 0i32;
    if channels == 2 {
        intensity_rsv = i32::from(LOG2_FRAC_TABLE[end - start]);
        if intensity_rsv > total {
            intensity_rsv = 0;
        } else {
            total -= intensity_rsv;
            dual_stereo_rsv = if total >= 1 << BITRES { 1 << BITRES } else { 0 };
            total -= dual_stereo_rsv;
        }
    }

    let mut bits1 = [0i32; NB_BANDS];
    let mut bits2 = [0i32; NB_BANDS];
    let mut thresh = [0i32; NB_BANDS];
    let mut trim_offset = [0i32; NB_BANDS];

    for j in start..end {
        let n0 = E_BANDS[j + 1] as i32 - E_BANDS[j] as i32;
        // Below this threshold, no PVQ bits are allocated.
        thresh[j] = (c << BITRES).max(((3 * n0) << lm << BITRES) >> 4);
        // Tilt of the allocation curve.
        trim_offset[j] = ((c * n0 * (alloc_trim - 5 - lm as i32) * (end as i32 - j as i32 - 1))
            * (1 << (lm + BITRES as usize)))
            >> 6;
        // Single-coefficient bands benefit more from a coarse value per coefficient.
        if (n0 << lm) == 1 {
            trim_offset[j] -= c << BITRES;
        }
    }

    // Bisect over the static allocation presets.
    let mut lo = 1i32;
    let mut hi = NB_ALLOC_VECTORS - 1;
    loop {
        let mut done = false;
        let mut psum = 0i32;
        let mid = (lo + hi) >> 1;
        for j in (start..end).rev() {
            let n = E_BANDS[j + 1] as i32 - E_BANDS[j] as i32;
            let mut bitsj = ((c * n * i32::from(BAND_ALLOCATION[mid as usize][j])) << lm) >> 2;
            if bitsj > 0 {
                bitsj = (bitsj + trim_offset[j]).max(0);
            }
            bitsj += offsets[j];
            if bitsj >= thresh[j] || done {
                done = true;
                psum += bitsj.min(cap[j]);
            } else if bitsj >= c << BITRES {
                psum += c << BITRES;
            }
        }
        if psum > total {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
        if lo > hi {
            break;
        }
    }
    hi = lo;
    lo -= 1;

    for j in start..end {
        let n = E_BANDS[j + 1] as i32 - E_BANDS[j] as i32;
        let mut bits1j = ((c * n * i32::from(BAND_ALLOCATION[lo as usize][j])) << lm) >> 2;
        let mut bits2j = if hi >= NB_ALLOC_VECTORS {
            cap[j]
        } else {
            ((c * n * i32::from(BAND_ALLOCATION[hi as usize][j])) << lm) >> 2
        };
        if bits1j > 0 {
            bits1j = (bits1j + trim_offset[j]).max(0);
        }
        if bits2j > 0 {
            bits2j = (bits2j + trim_offset[j]).max(0);
        }
        if lo > 0 {
            bits1j += offsets[j];
        }
        bits2j += offsets[j];
        if offsets[j] > 0 {
            skip_start = j;
        }
        bits2j = (bits2j - bits1j).max(0);
        bits1[j] = bits1j;
        bits2[j] = bits2j;
    }

    interp_bits2pulses(
        start,
        end,
        skip_start,
        &bits1,
        &bits2,
        &thresh,
        cap,
        total,
        balance,
        skip_rsv,
        intensity,
        intensity_rsv,
        dual_stereo,
        dual_stereo_rsv,
        pulses,
        ebits,
        fine_priority,
        channels,
        lm,
        prev,
        signal_bandwidth,
        coder,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

    fn cache_count(band: usize, lm: i32) -> usize {
        CACHE_BITS50[CACHE_INDEX50[(lm + 1) as usize * NB_BANDS + band] as usize] as usize
    }

    #[test]
    fn get_pulses_known_values() {
        assert_eq!(get_pulses(0), 0);
        assert_eq!(get_pulses(7), 7);
        assert_eq!(get_pulses(8), 8); // (8+0)<<0
        assert_eq!(get_pulses(9), 9); // (8+1)<<0
        assert_eq!(get_pulses(16), 16); // (8+0)<<1
        assert_eq!(get_pulses(40), 128); // MAX_PSEUDO=40 → CELT_MAX_PULSES=128
    }

    /// `bits2pulses` is bounded `[0, count]`, monotonic non-decreasing in the budget, and
    /// cost-consistent: feeding a pulse's own cost back recovers an index of *equal cost* (an exact
    /// pulse-index round-trip only holds where the cache is strictly increasing — degenerate
    /// low-N bands share one cost across all pulse counts).
    #[test]
    fn bits2pulses_is_monotonic_bounded_and_cost_consistent() {
        for lm in 0..4i32 {
            for band in 0..NB_BANDS {
                let count = cache_count(band, lm);
                let mut prev = 0usize;
                for bits in 0..220 {
                    let q = bits2pulses(band, lm, bits);
                    assert!(
                        q <= count,
                        "lm={lm} band={band} bits={bits}: q {q} > count {count}"
                    );
                    assert!(q >= prev, "lm={lm} band={band} bits={bits}: {q} < {prev}");
                    prev = q;
                }
                for q in 1..=count {
                    let bits = pulses2bits(band, lm, q);
                    let q2 = bits2pulses(band, lm, bits);
                    assert_eq!(pulses2bits(band, lm, q2), bits, "lm={lm} band={band} q={q}");
                }
            }
        }
    }

    #[test]
    fn init_caps_known_values() {
        let mut cap = [0i32; NB_BANDS];
        init_caps(&mut cap, 3, 1);
        assert_eq!(cap[0], 514);
        assert_eq!(cap[20], 4532);
        let mut cap2 = [0i32; NB_BANDS];
        init_caps(&mut cap2, 0, 2);
        assert_eq!(cap2[0], 144);
        for lm in 0..4 {
            for channels in 1..=2 {
                let mut c = [0i32; NB_BANDS];
                init_caps(&mut c, lm, channels);
                assert!(c.iter().all(|&x| x > 0), "lm={lm} c={channels}");
            }
        }
    }

    /// Structural invariants of the allocation over a spread of budgets / configs: it never panics,
    /// `codedBands` is in range, every band's PVQ bits are ≥ 0, fine bits are in `0..=MAX_FINE_BITS`,
    /// `fine_priority` is a flag, and the total allocated PVQ bits never exceed the budget.
    #[test]
    fn allocation_invariants_hold() {
        for &lm in &[0usize, 1, 2, 3] {
            for &channels in &[1usize, 2] {
                for &total in &[200i32, 1500, 4000, 12000] {
                    let mut cap = [0i32; NB_BANDS];
                    init_caps(&mut cap, lm, channels);
                    let offsets = [0i32; NB_BANDS];
                    let mut intensity = 0usize;
                    let mut dual_stereo = false;
                    let mut pulses = [0i32; NB_BANDS];
                    let mut ebits = [0i32; NB_BANDS];
                    let mut fine_priority = [0i32; NB_BANDS];
                    let mut balance = 0i32;
                    let buf = [0xA5u8; 128];
                    let mut dec = RangeDecoder::new(&buf);
                    let coded = clt_compute_allocation(
                        0,
                        NB_BANDS,
                        &offsets,
                        &cap,
                        5,
                        &mut intensity,
                        &mut dual_stereo,
                        total,
                        &mut balance,
                        &mut pulses,
                        &mut ebits,
                        &mut fine_priority,
                        channels,
                        lm,
                        0,
                        0,
                        &mut dec,
                    );
                    assert!(
                        coded <= NB_BANDS,
                        "lm={lm} c={channels} total={total}: coded {coded}"
                    );
                    let mut pvq_sum = 0i64;
                    for j in 0..NB_BANDS {
                        assert!(pulses[j] >= 0, "band {j} pulses {}", pulses[j]);
                        assert!(
                            (0..=MAX_FINE_BITS).contains(&ebits[j]),
                            "band {j} ebits {}",
                            ebits[j]
                        );
                        assert!(fine_priority[j] == 0 || fine_priority[j] == 1);
                        pvq_sum += pulses[j] as i64;
                    }
                    // The PVQ bits handed out can't exceed the original budget.
                    assert!(
                        pvq_sum <= total as i64 + 8,
                        "lm={lm} c={channels} total={total}: pvq_sum {pvq_sum}"
                    );
                }
            }
        }
    }

    /// The allocator is a **single** shared implementation, so encoder and decoder must land on
    /// byte-identical allocations for the same budget: the encoder decides which bands to skip and
    /// signals them, and the decoder reading those flags must reproduce every `pulses`, `ebits`,
    /// `fine_priority`, `balance`, `intensity`/`dual_stereo` and the coded-band count.
    #[test]
    fn allocation_encode_then_decode_produces_identical_allocations() {
        for &lm in &[0usize, 1, 2, 3] {
            for &channels in &[1usize, 2] {
                for &total in &[120i32, 700, 2500, 9000, 40000] {
                    for &boost in &[0i32, 60] {
                        for &signal_bandwidth in &[NB_BANDS - 1, 13] {
                            let mut cap = [0i32; NB_BANDS];
                            init_caps(&mut cap, lm, channels);
                            let offsets: [i32; NB_BANDS] =
                                core::array::from_fn(|j| if j % 5 == 0 { boost } else { 0 });

                            let mut buf = vec![0u8; 1500];
                            let mut enc_intensity = channels;
                            let mut enc_dual = channels == 2;
                            let mut enc_pulses = [0i32; NB_BANDS];
                            let mut enc_ebits = [0i32; NB_BANDS];
                            let mut enc_prio = [0i32; NB_BANDS];
                            let mut enc_balance = 0i32;
                            let enc_coded;
                            {
                                let mut enc = RangeEncoder::new(&mut buf);
                                enc_coded = clt_compute_allocation(
                                    0,
                                    NB_BANDS,
                                    &offsets,
                                    &cap,
                                    5,
                                    &mut enc_intensity,
                                    &mut enc_dual,
                                    total,
                                    &mut enc_balance,
                                    &mut enc_pulses,
                                    &mut enc_ebits,
                                    &mut enc_prio,
                                    channels,
                                    lm,
                                    NB_BANDS,
                                    signal_bandwidth,
                                    &mut enc,
                                );
                                enc.done();
                                assert!(!enc.error(), "lm={lm} total={total}: encoder overflow");
                            }

                            let mut dec_intensity = 0usize;
                            let mut dec_dual = false;
                            let mut dec_pulses = [0i32; NB_BANDS];
                            let mut dec_ebits = [0i32; NB_BANDS];
                            let mut dec_prio = [0i32; NB_BANDS];
                            let mut dec_balance = 0i32;
                            let mut dec = RangeDecoder::new(&buf);
                            let dec_coded = clt_compute_allocation(
                                0,
                                NB_BANDS,
                                &offsets,
                                &cap,
                                5,
                                &mut dec_intensity,
                                &mut dec_dual,
                                total,
                                &mut dec_balance,
                                &mut dec_pulses,
                                &mut dec_ebits,
                                &mut dec_prio,
                                channels,
                                lm,
                                0,
                                0,
                                &mut dec,
                            );

                            let tag = format!(
                                "lm={lm} c={channels} total={total} boost={boost} \
                                 sb={signal_bandwidth}"
                            );
                            assert_eq!(dec_coded, enc_coded, "{tag}: coded bands");
                            assert_eq!(dec_pulses, enc_pulses, "{tag}: pulses");
                            assert_eq!(dec_ebits, enc_ebits, "{tag}: ebits");
                            assert_eq!(dec_prio, enc_prio, "{tag}: fine_priority");
                            assert_eq!(dec_balance, enc_balance, "{tag}: balance");
                            assert_eq!(dec_intensity, enc_intensity, "{tag}: intensity");
                            assert_eq!(dec_dual, enc_dual, "{tag}: dual_stereo");
                        }
                    }
                }
            }
        }
    }

    /// The encoder's skip decision must actually respond to `signal_bandwidth`: forcing a low
    /// bandwidth has to drop bands the wide setting keeps (otherwise the knob is decorative).
    #[test]
    fn signal_bandwidth_narrows_the_coded_band_count() {
        let lm = 3usize;
        let channels = 1usize;
        let total = 3000i32;
        let mut cap = [0i32; NB_BANDS];
        init_caps(&mut cap, lm, channels);
        let offsets = [0i32; NB_BANDS];

        let run = |signal_bandwidth: usize| -> usize {
            let mut buf = vec![0u8; 1500];
            let mut intensity = 0usize;
            let mut dual = false;
            let mut pulses = [0i32; NB_BANDS];
            let mut ebits = [0i32; NB_BANDS];
            let mut prio = [0i32; NB_BANDS];
            let mut balance = 0i32;
            let mut enc = RangeEncoder::new(&mut buf);
            clt_compute_allocation(
                0,
                NB_BANDS,
                &offsets,
                &cap,
                5,
                &mut intensity,
                &mut dual,
                total,
                &mut balance,
                &mut pulses,
                &mut ebits,
                &mut prio,
                channels,
                lm,
                NB_BANDS,
                signal_bandwidth,
                &mut enc,
            )
        };
        let wide = run(NB_BANDS - 1);
        let narrow = run(8);
        assert!(
            narrow < wide,
            "signal_bandwidth had no effect: narrow {narrow} vs wide {wide}"
        );
    }
}
