//! The 14-bit arithmetic decoder of the MODE2 core (TS 26.442 `lib_dec/ari_dec.c`; TS 26.445
//! §5.3.3.2.8.1 and §6.2.2.2.x). The IGF scale-factor decoder uses the same routines.
//!
//! The reference's `Overflow` flag is not read anywhere in this file.

use crate::evs::cnst::{ARI_Q4NEW, CBITSNEW, STAT_BITSNEW};
use crate::evs::com::ari::{l_multi31x16_x2, mul_sbc_14bits};
use crate::evs::com::bitstream::{get_next_indice, get_next_indice_1};
use crate::evs::dec::state::{DecoderState, TastatDec};
use crate::evs::rom::TAB_ARI_QNEW;
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_deposit_l, l_msu, l_shl, l_shr, l_sub, mult_r, shl, shr, sub,
};
use crate::itu::stl2009::l_mac0;

/// The look-up of one symbol of a table-driven model: `(cum, range, cum_freq) -> symbol`.
type LookupFn = fn(i32, i32, &[u16]) -> i16;

/// `ari_decode_overflow`: no range is left (`high - 1 <= low`).
#[must_use]
pub fn ari_decode_overflow(s: &TastatDec) -> bool {
    l_sub(l_sub(s.high, 1), s.low) <= 0
}

/// `ari_start_decoding_14bits`: initialise the decoder from the next `cbitsnew` bits of the
/// bitstream.
pub fn ari_start_decoding_14bits(st: &mut DecoderState, s: &mut TastatDec) {
    let val = l_deposit_l(get_next_indice(st, CBITSNEW) as i16) & 0xffff;
    s.low = l_deposit_l(0);
    s.high = ARI_Q4NEW + 1;
    s.vobf = val;
}

/// `ari_start_decoding_14bits_prm`: [`ari_start_decoding_14bits`] reading the bits from a
/// parameter array (one bit per word) at `bp`; returns the position after them. The caller sizes
/// `ptr` for the frame's bit budget plus the `cbitsnew` look-ahead; a bit past its end reads as 0
/// (the reference would read the neighbouring array, which no valid frame reaches).
#[must_use]
pub fn ari_start_decoding_14bits_prm(ptr: &[i16], bp: i16, s: &mut TastatDec) -> i16 {
    let mut val = l_deposit_l(0);
    let base = i32::from(bp);
    let mut i: i16 = 0;
    while i < CBITSNEW {
        val = l_shl(val, 1);
        if prm_bit(ptr, base + i32::from(i)) != 0 {
            val = l_add(val, 1);
        }
        i += 1;
    }
    s.low = l_deposit_l(0);
    s.high = ARI_Q4NEW + 1;
    s.vobf = val;
    add(bp, i)
}

/// `ptr[index]` of a parameter array; see [`ari_start_decoding_14bits_prm`] for the out-of-range
/// case.
fn prm_bit(ptr: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| ptr.get(index))
        .copied()
        .unwrap_or(0)
}

/// `ari_lookup_s17`: binary search of the 17-symbol model, one `p += step` test per level.
fn ari_lookup_s17(cum: i32, range: i32, cum_freq: &[u16]) -> i16 {
    let mut p: usize = 0;

    // max value in p[x] is 16384 => 14 bits
    let range_l = extract_l(range & 0x7FFF);
    let range_h = extract_l(l_shr(range, 15));

    let mut tmp = l_multi31x16_x2(range_h, range_l, cum_freq[p + 8] as i16);
    if l_sub(tmp, cum) > 0 {
        p += 8;
    }
    tmp = l_multi31x16_x2(range_h, range_l, cum_freq[p + 4] as i16);
    if l_sub(tmp, cum) > 0 {
        p += 4;
    }
    tmp = l_multi31x16_x2(range_h, range_l, cum_freq[p + 2] as i16);
    if l_sub(tmp, cum) > 0 {
        p += 2;
    }
    tmp = l_multi31x16_x2(range_h, range_l, cum_freq[p + 1] as i16);
    if l_sub(tmp, cum) > 0 {
        p += 1;
        tmp = l_multi31x16_x2(range_h, range_l, cum_freq[p + 1] as i16);
        if p == 15 && l_sub(tmp, cum) > 0 {
            p += 1;
        }
    }
    p as i16
}

/// `ari_lookup_s27`: binary search of the 27-symbol model over the interval `[il, ih)`, four
/// bisection steps then, if two symbols remain, one comparison at `il + 1`.
fn ari_lookup_s27(cum: i32, range: i32, cum_freq: &[u16]) -> i16 {
    // max value in p[x] is 16384 => 14 bits
    let range_l = extract_l(range & 0x7FFF);
    let range_h = extract_l(l_shr(range, 15));

    let mut il: i16 = 0;
    let mut ih: i16 = 27;

    let mut im: i16 = 13; // (il + ih) >> 1
    for step in 0..4 {
        if step > 0 {
            im = shr(add(il, ih), 1);
        }
        let tmp = l_sub(
            l_multi31x16_x2(range_h, range_l, cum_freq[im as usize] as i16),
            cum,
        );
        if tmp > 0 {
            il = im;
        }
        if tmp <= 0 {
            ih = im;
        }
    }

    if sub(sub(ih, il), 1) > 0 {
        // if the interval has more than one symbol; here, only ih == il + 2 is possible, which
        // means two symbols in the interval
        im = add(il, 1); // (il + ih) >> 1
        let tmp = l_sub(
            l_multi31x16_x2(range_h, range_l, cum_freq[im as usize] as i16),
            cum,
        );
        if tmp > 0 {
            il = im;
        }
    }

    il
}

/// `ari_lookup_bit`: the uniform one-bit model `{16384, 8192, 0}`.
fn ari_lookup_bit(cum: i32, range: i32, _cum_freq: &[u16]) -> i16 {
    let range = l_shl(range, 13); // L_multi31x16_X2(range_h, range_l, 8192)
    let cum = l_sub(range, cum);
    i16::from(cum > 0)
}

/// `ari_decode_14bits_ext`: decode one symbol of the model `cum_freq` with `lookup_fn` and
/// renormalise, reading the new bits from the bitstream.
fn ari_decode_14bits_ext(
    st: &mut DecoderState,
    s: &mut TastatDec,
    cum_freq: &[u16],
    lookup_fn: LookupFn,
) -> i16 {
    let mut low = l_add(0, s.low);
    let mut high = l_add(0, s.high);
    let mut value = l_add(0, s.vobf);

    let range = l_sub(high, low);

    let mut cum = l_add(
        l_shl(l_sub(value, low), STAT_BITSNEW),
        i32::from(sub(shl(1, STAT_BITSNEW), 1)),
    );
    if cum < 0 {
        cum = l_add(0, 0x7fff_ffff);
    }

    let symbol = lookup_fn(cum, range, cum_freq);

    // The symbol is bounded by the model's size, so `symbol + 1` indexes inside `cum_freq`.
    high = l_add(low, mul_sbc_14bits(range, cum_freq[symbol as usize] as i16));
    low = l_add(
        low,
        mul_sbc_14bits(range, cum_freq[symbol as usize + 1] as i16),
    );

    ari_renormalise(st, &mut low, &mut high, &mut value);

    s.low = low;
    s.high = high;
    s.vobf = value;

    symbol
}

/// The renormalisation loop of `ari_decode_14bits_ext`: shift out settled bits of `low`, `high`
/// and `value`, reading one new bit per step from the bitstream.
fn ari_renormalise(st: &mut DecoderState, low: &mut i32, high: &mut i32, value: &mut i32) {
    for _ in 0..0x7FFF {
        let l_msb_high = l_shr(l_sub(*high, 1), 14);
        let l_msb_low = l_shr(*low, 14);
        let l_msb_diff = l_sub(l_msb_high, l_msb_low);
        if l_sub(l_msb_diff, 2) >= 0 {
            break;
        }
        let Some(q) = tab_ari_qnew(l_msb_high, l_msb_low) else {
            break;
        };
        *low = l_msu(*low, 1, q);
        *low = l_shl(*low, 1);
        *high = l_msu(*high, 1, q);
        *high = l_shl(*high, 1);
        *value = l_msu(*value, 1, q);
        *value = l_mac0(l_shl(*value, 1), 1, get_next_indice_1(st) as i16);
    }
}

/// `tab_ari_qnew[high][low]`. `high` stays below `2^16 + 1` and `low` below `high`, so both
/// indices are 0..=3; the guard keeps an unreachable state inside the table (the reference
/// asserts on the two marker values and would read out of bounds).
fn tab_ari_qnew(l_msb_high: i32, l_msb_low: i32) -> Option<i16> {
    let row = usize::try_from(l_msb_high).ok()?;
    let column = usize::try_from(l_msb_low).ok()?;
    TAB_ARI_QNEW.get(row)?.get(column).copied()
}

/// `ari_decode_14bits_s17_ext`: a symbol of a 17-symbol model (18 cumulative frequencies).
pub fn ari_decode_14bits_s17_ext(
    st: &mut DecoderState,
    s: &mut TastatDec,
    cum_freq: &[u16],
) -> i16 {
    ari_decode_14bits_ext(st, s, cum_freq, ari_lookup_s17)
}

/// `ari_decode_14bits_s27_ext`: a symbol of a 27-symbol model (28 cumulative frequencies).
pub fn ari_decode_14bits_s27_ext(
    st: &mut DecoderState,
    s: &mut TastatDec,
    cum_freq: &[u16],
) -> i16 {
    ari_decode_14bits_ext(st, s, cum_freq, ari_lookup_s27)
}

/// `ari_decode_14bits_bit_ext`: one bit of uniform probability, the model `{16384, 8192, 0}`.
pub fn ari_decode_14bits_bit_ext(st: &mut DecoderState, s: &mut TastatDec) -> i16 {
    static CUM_FREQ: [u16; 3] = [16384, 8192, 0];
    ari_decode_14bits_ext(st, s, &CUM_FREQ, ari_lookup_bit)
}

/// `ari_lookup_pow`: the symbol of the exponential distribution of ratio `base` (Q15) the value
/// falls in; narrows `s.low` / `s.high` to its interval.
fn ari_lookup_pow(s: &mut TastatDec, base: i16) -> i16 {
    let range = l_sub(s.high, s.low);
    let cum = l_add(
        l_shl(l_sub(s.vobf, s.low), STAT_BITSNEW),
        i32::from(sub(shl(1, STAT_BITSNEW), 1)),
    );

    let range_h = extract_l(l_shr(range, 15));
    let range_l = extract_l(range & 0x7FFF);

    let mut pows = [0_i16; 12]; // "base" to the power of 2, 4, 8,... 2^12
    let mut symbol: i16 = 0;
    let mut lowlim = shr(base, 1);
    let mut highlim: i16 = 16384;

    // search for the interval where "cum" fits
    if l_sub(l_multi31x16_x2(range_h, range_l, lowlim), cum) > 0 {
        // below pow-1
        pows[0] = base;
        let mut testval = base;
        // increase exponent until it is smaller than "cum"
        let mut k: i16 = 1;
        while k < 12 {
            highlim = testval;
            pows[k as usize] = mult_r(pows[k as usize - 1], pows[k as usize - 1]);
            testval = mult_r(pows[k as usize], base);

            if l_sub(l_multi31x16_x2(range_h, range_l, shr(testval, 1)), cum) <= 0 {
                // found! big range is [lowlim,testval], (now narrow it down)
                lowlim = testval;
                k = sub(k, 1);
                symbol = shl(1, k);
                break;
            }
            k += 1;
        }
        // The reference asserts k < 12 (maximum 2^10-1); a hostile stream that finds no interval
        // leaves k at 12 and narrows from there, exactly as the loop below does.

        // narrow the range down
        k = sub(k, 2);
        while k >= 0 {
            testval = mult_r(highlim, pows[k as usize + 1]);

            if l_sub(l_multi31x16_x2(range_h, range_l, shr(testval, 1)), cum) <= 0 {
                lowlim = testval;
                symbol = sub(symbol, shl(1, k));
            } else {
                highlim = testval;
            }
            k -= 1;
        }

        highlim = shr(highlim, 1);
        lowlim = shr(lowlim, 1);
    }

    s.high = l_add(s.low, mul_sbc_14bits(range, highlim));
    s.low = l_add(s.low, mul_sbc_14bits(range, lowlim));

    symbol
}

/// `ari_lookup_sign`: a sign of equal probabilities (1 = negative); halves the range.
fn ari_lookup_sign(s: &mut TastatDec, _base: i16) -> i16 {
    let mut range = l_sub(s.high, s.low);
    let cum = l_sub(s.vobf, s.low);
    range = l_shr(range, 1);

    if l_sub(range, cum) > 0 {
        s.high = l_add(s.low, range);
        1
    } else {
        s.low = l_add(s.low, range);
        0
    }
}

/// Which `lookup_fn` `ari_decode_14bits_notbl` runs (the reference passes a function pointer and
/// tests it against `ari_lookup_sign`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum NotblLookup {
    Pow,
    Sign,
}

/// `ari_decode_14bits_notbl`: decode a symbol without a table, then renormalise reading the bits
/// from the parameter array `ptr` at `bp` (up to `bits`). Returns the new position, or -1 with
/// everything zeroed when a bit error leaves the decoder in the state the reference rejects.
fn ari_decode_14bits_notbl(
    ptr: &[i16],
    mut bp: i16,
    bits: i16,
    res: &mut i16,
    s: &mut TastatDec,
    base: i16,
    lookup: NotblLookup,
) -> i16 {
    let symbol = match lookup {
        NotblLookup::Pow => ari_lookup_pow(s, base),
        NotblLookup::Sign => ari_lookup_sign(s, base),
    };

    let mut low = l_add(s.low, 0);
    let mut high = l_add(s.high, 0);
    let mut value = l_add(s.vobf, 0);

    while bp < bits {
        let l_msb_high = l_shr(l_sub(high, 1), 14);
        let l_msb_low = l_shr(low, 14);
        let l_msb_diff = l_sub(l_msb_high, l_msb_low);
        if l_sub(l_msb_diff, 2) >= 0 {
            break;
        }
        let Some(q) = tab_ari_qnew(l_msb_high, l_msb_low) else {
            break;
        };
        low = l_msu(low, 1, q);
        low = l_shl(low, 1);
        high = l_msu(high, 1, q);
        high = l_shl(high, 1);
        value = l_msu(value, 1, q);
        value = l_mac0(l_shl(value, 1), 1, prm_bit(ptr, i32::from(bp)));
        bp += 1;
    }

    if lookup != NotblLookup::Sign
        && !(sub(bp, bits) != 0
            || !(l_sub(s.low, low) == 0
                && l_sub(s.high, l_sub(high, 1)) == 0
                && l_sub(s.vobf, value) == 0))
    {
        // This should not happen except of bit errors.
        s.high = 0;
        s.low = 0;
        *res = 0;
        return -1;
    }

    s.low = low;
    s.high = high;
    s.vobf = value;

    *res = symbol;

    bp
}

/// `ari_decode_14bits_pow`: decode a symbol of the exponential distribution
///
/// `p(x = 0) = 1 - exp(-0.5 * base * 2)`, `p(x = q > 0) = exp(-(q - 0.5) * base * 2) -
/// exp(-(q + 0.5) * base * 2)`.
pub fn ari_decode_14bits_pow(
    ptr: &[i16],
    bp: i16,
    bits: i16,
    res: &mut i16,
    s: &mut TastatDec,
    base: i16,
) -> i16 {
    ari_decode_14bits_notbl(ptr, bp, bits, res, s, base, NotblLookup::Pow)
}

/// `ari_decode_14bits_sign`: decode a sign with equal probabilities.
pub fn ari_decode_14bits_sign(
    ptr: &[i16],
    bp: i16,
    bits: i16,
    res: &mut i16,
    s: &mut TastatDec,
) -> i16 {
    ari_decode_14bits_notbl(ptr, bp, bits, res, s, 0, NotblLookup::Sign)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_bits(bits: &[u16]) -> Box<DecoderState> {
        let mut st = Box::new(DecoderState::zeroed());
        st.bit_stream[..bits.len()].copy_from_slice(bits);
        st.total_num_bits = 256;
        st.codec_mode = crate::evs::cnst::MODE2;
        st
    }

    #[test]
    fn start_decoding_reads_sixteen_bits() {
        let mut bits = [0_u16; 32];
        bits[0] = 1;
        bits[15] = 1;
        let mut st = state_with_bits(&bits);
        let mut s = TastatDec::zeroed();
        ari_start_decoding_14bits(&mut st, &mut s);
        assert_eq!((s.low, s.high, s.vobf), (0, 65536, 0x8001));
        assert_eq!(st.next_bit_pos, 16);
    }

    #[test]
    fn start_decoding_prm_matches_the_bitstream_reader() {
        let prm: [i16; 20] = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1];
        let mut s = TastatDec::zeroed();
        assert_eq!(ari_start_decoding_14bits_prm(&prm, 1, &mut s), 17);
        assert_eq!(s.vobf, 0x8003);
    }

    #[test]
    fn overflow_when_the_range_is_exhausted() {
        let mut s = TastatDec::zeroed();
        s.low = 10;
        s.high = 11;
        assert!(ari_decode_overflow(&s));
        s.high = 12;
        assert!(!ari_decode_overflow(&s));
    }

    #[test]
    fn sign_halves_the_range() {
        let mut s = TastatDec {
            low: 0,
            high: 65536,
            vobf: 100,
        };
        let mut sign = -1;
        let bp = ari_decode_14bits_sign(&[0; 8], 0, 4, &mut sign, &mut s);
        // The upper half is kept (32768) and renormalised once, reading one bit.
        assert_eq!((sign, s.low, s.high, bp), (1, 0, 65536, 1));
    }

    #[test]
    fn bit_model_decodes_both_values() {
        let mut st = state_with_bits(&[0; 64]);
        let mut s = TastatDec {
            low: 0,
            high: 65536,
            vobf: 0,
        };
        assert_eq!(ari_decode_14bits_bit_ext(&mut st, &mut s), 1);
        let mut s = TastatDec {
            low: 0,
            high: 65536,
            vobf: 65535,
        };
        assert_eq!(ari_decode_14bits_bit_ext(&mut st, &mut s), 0);
    }
}
