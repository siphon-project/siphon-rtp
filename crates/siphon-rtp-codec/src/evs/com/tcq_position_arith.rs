//! Arithmetic decoding of TCQ / USQ pulse positions, magnitudes and signs for the low-rate HQ core
//! (TS 26.442 `lib_com/tcq_position_arith_fx.c`; TS 26.445 §6.2.3.2.2).
//!
//! Only the decoder half is ported. The reference keeps the arithmetic decoder (`ARCODEC_FX`) and
//! the byte buffer it reads (`BITSTREAM_FX`) as two structs joined by a pointer; here the decoder
//! owns its bitstream ([`ArCodec::bs_inst`]), which the caller fills before
//! [`ar_decoder_start`].
//!
//! The reference multiplies some `Word32` values with plain C `*` (`cum * MAX_AR_FREQ`,
//! `range * model[i]`): those wrap (the reference is built with `-fwrapv`) and are written as
//! `wrapping_mul` here.
//!
//! `Overflow`: nothing in this file reads it. `tcq_core_dec_fx` (the caller) clears it on entry and
//! does not read it afterwards either, so whatever these operators set is unobserved.

use crate::evs::basop::{mult_32_16, mult_32_32};
use crate::evs::cnst::{
    AR_BITS, AR_TOP, MAX_16, MAX_AR_FREQ, MAX_PULSES, MAX_SIZEBUF_PBITSTREAM, TCQ_AMP,
    TCQ_MAX_BAND_SIZE,
};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::pow2;
use crate::evs::rom::{
    DDEC_FX, DDEC_LSB_FX, DDP_FX, DSTEP_LSB_FX, NEXTSTATE, POW_GETBITSFROMPULSES_FX,
    TABLE_LOGCUM_FX, TAB_ARI_QNEW, UNIFORM_MODEL_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu,
    l_mult, l_negate, l_shl, l_shr, l_sub, mult, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{div_l, l_mult0};

/// `TCQ_MAX_BAND_SIZE + 1`: the reference sizes its position models `TCQ_MAX_BAND_SIZE`, but a
/// model for a band of `size` positions has `size + 1` entries, so a 120-wide band would write one
/// past the end. No configuration has a band that wide; the extra entry only makes the bound
/// hold by construction.
const POSITION_MODEL_LEN: usize = TCQ_MAX_BAND_SIZE as usize + 1;

/// The reference's `BITSTREAM_FX`: the bytes the arithmetic decoder reads, most significant bit
/// first.
#[derive(Debug, Clone)]
pub struct Bitstream {
    /// `buf`
    pub buf: [u8; MAX_SIZEBUF_PBITSTREAM as usize],
    /// `curPos`: the next bit within `buf[num_byte]` (7 = most significant).
    pub cur_pos: i16,
    /// `numByte`
    pub num_byte: i32,
    /// `numbits`
    pub numbits: i32,
    /// `maxBytes`: reads at or beyond this byte return 0.
    pub max_bytes: i32,
}

impl Bitstream {
    /// All zero, as the reference's stack struct before `tcq_core_dec_fx` sets it up.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_SIZEBUF_PBITSTREAM as usize],
            cur_pos: 0,
            num_byte: 0,
            numbits: 0,
            max_bytes: 0,
        }
    }
}

impl Default for Bitstream {
    fn default() -> Self {
        Self::new()
    }
}

/// The reference's `ARCODEC_FX` (decoder use), owning the bitstream its `bsInst` points at.
#[derive(Debug, Clone, Default)]
pub struct ArCodec {
    /// `bsInst`
    pub bs_inst: Bitstream,
    /// `low`
    pub low: i32,
    /// `high`
    pub high: i32,
    /// `value`
    pub value: i32,
    /// `bits_to_follow` (encoder only)
    pub bits_to_follow: i16,
    /// `num_bits` (encoder only)
    pub num_bits: i32,
    /// `max_bits` (encoder only)
    pub max_bits: i32,
}

impl ArCodec {
    /// All zero, with an empty bitstream.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bs_inst: Bitstream::new(),
            low: 0,
            high: 0,
            value: 0,
            bits_to_follow: 0,
            num_bits: 0,
            max_bits: 0,
        }
    }
}

/// `ar_div`: `num / denum` truncated, by restoring shift-subtract division. `|num| < |denum|` or
/// `denum == 0` gives 0 and `|num| == |denum|` gives 1, both without the sign (as the reference).
#[must_use]
pub fn ar_div(num: i32, denum: i32) -> i32 {
    let sign = (num ^ denum) & i32::MIN;
    let mut num = l_abs(num);
    let mut denum = l_abs(denum);
    if l_sub(num, denum) < 0 || denum == 0 {
        return 0;
    }
    if l_sub(num, denum) == 0 {
        return 1;
    }
    let exp1 = norm_l(num);
    let exp2 = norm_l(denum);
    let mut exp = sub(exp2, exp1);
    denum = l_shl(denum, exp);
    exp = add(exp, 1);
    let mut varout = l_deposit_l(0);
    for _ in 0..exp {
        num = l_sub(num, denum);
        varout = l_shl(varout, 1);
        if num >= 0 {
            num = l_shl(num, 1);
            varout = l_add(varout, 1);
        } else {
            num = l_add(num, denum);
            num = l_shl(num, 1);
        }
    }
    if sign != 0 {
        varout = l_negate(varout);
    }
    varout
}

/// `bitstream_load_bit`: the next bit, or 0 at or past `maxBytes`.
pub fn bitstream_load_bit(bs: &mut Bitstream) -> u32 {
    // safety check in case of bit errors
    if l_sub(bs.num_byte, bs.max_bytes) >= 0 {
        return 0;
    }
    // A byte index outside the buffer is a read past the reference's array; only a caller-set
    // `max_bytes` beyond the buffer (or a rollback before its start) can produce one.
    let Some(&byte) = usize::try_from(bs.num_byte)
        .ok()
        .and_then(|index| bs.buf.get(index))
    else {
        return 0;
    };
    let bit = (u32::from(byte) >> bs.cur_pos.clamp(0, 31)) & 1;
    bs.cur_pos = bs.cur_pos.wrapping_sub(1);
    if bs.cur_pos < 0 {
        bs.num_byte = l_add(bs.num_byte, 1);
        bs.cur_pos = 7;
    }
    bit
}

/// `bitstream_rollback`: step back `num_bits` bits.
pub fn bitstream_rollback(bs: &mut Bitstream, mut num_bits: i32) {
    while num_bits > 0 {
        bs.cur_pos = bs.cur_pos.wrapping_add(1);
        bs.numbits = l_sub(bs.numbits, 1);
        if sub(bs.cur_pos, 8) == 0 {
            bs.cur_pos = 0;
            bs.num_byte = l_sub(bs.num_byte, 1);
        }
        num_bits -= 1;
    }
}

/// `ar_make_model_fx`: the cumulative-frequency model (`len + 1` entries, `model[len] = 0`, strictly
/// decreasing) for the symbol frequencies `freq[0..len]`. Returns 0 for an all-zero `freq`
/// (leaving `model` untouched), else `model[0] > model[1]`.
pub fn ar_make_model(freq: &[i16], model: &mut [i16], len: i16) -> i32 {
    let len_us = len.max(0) as usize;
    let mut sum: i32 = 0;
    let mut cum: i32 = 0;
    for &value in &freq[..len_us] {
        sum = l_add(sum, i32::from(value));
    }
    if sum == 0 {
        return 0;
    }
    for i in (0..=len_us).rev() {
        // model[i] = (short)((cum * MAX_AR_FREQ) / sum); the product is plain C and wraps.
        model[i] = extract_l(ar_div(cum.wrapping_mul(i32::from(MAX_AR_FREQ)), sum));
        if i != 0 {
            cum = l_add(cum, i32::from(freq[i - 1]));
        }
    }
    let tmp = sub(len, 1);
    for i in 0..tmp.max(0) as usize {
        let dist = sub(model[i], model[i + 1]);
        if dist <= 0 {
            model[i + 1] = add(model[i + 1], sub(dist, 1));
        }
    }
    for i in (1..=len_us).rev() {
        let dist = sub(model[i - 1], model[i]);
        if dist <= 0 {
            model[i - 1] = sub(model[i - 1], sub(dist, 1));
        }
    }
    i32::from(model[0] > model[1])
}

/// `ar_decoder_start_fx`: start decoding the bitstream the caller has filled into
/// `ar_inst.bs_inst` (the reference passes it as `bsInst`), reading the first `AR_BITS` bits.
pub fn ar_decoder_start(ar_inst: &mut ArCodec) {
    ar_inst.low = l_deposit_l(0);
    ar_inst.high = AR_TOP;
    ar_inst.value = l_deposit_l(0);
    for _ in 0..AR_BITS {
        let bit = bitstream_load_bit(&mut ar_inst.bs_inst) as i32;
        ar_inst.value = l_add(l_shl(ar_inst.value, 1), bit);
    }
}

/// `ar_decode_fx`: decode one symbol against the cumulative model `model` (`model[0]` the total,
/// decreasing to a 0 entry) and renormalise.
pub fn ar_decode(ar_inst: &mut ArCodec, model: &[i16]) -> i16 {
    let mut high = l_add(ar_inst.high, 0);
    let mut low = l_add(ar_inst.low, 0);
    let mut value = l_add(ar_inst.value, 0);

    let range = l_add(l_sub(high, low), 1);
    let cum = extract_l(ar_div(
        l_sub(
            l_add(l_sub(value, low), 1).wrapping_mul(i32::from(model[0])),
            1,
        ),
        range,
    ));

    // The reference scans until an entry at or below `cum`; every model ends in a 0 entry and a
    // value inside [low, high] keeps `cum` >= 0, so the scan stops within the model. Bounding it by
    // the slice only matters for a state the arithmetic coder cannot reach.
    let last = model.len().saturating_sub(1);
    let mut symbol: usize = 1;
    while symbol < last && sub(model[symbol], cum) > 0 {
        symbol += 1;
    }

    high = l_sub(
        l_add(
            low,
            ar_div(
                range.wrapping_mul(i32::from(model[symbol - 1])),
                i32::from(model[0]),
            ),
        ),
        1,
    );
    low = l_add(
        low,
        ar_div(
            range.wrapping_mul(i32::from(model[symbol])),
            i32::from(model[0]),
        ),
    );

    for _ in 0..0x7FFF {
        let l_msb_high = l_shr(high, 14);
        let l_msb_low = l_shr(low, 14);
        let l_msb_diff = l_sub(l_msb_high, l_msb_low);
        if l_sub(l_msb_diff, 2) >= 0 {
            break;
        }
        // `high` stays below 2^16 (it starts at AR_TOP and only shrinks or renormalises back
        // under it), so both indices are 0..=3; the guard keeps an unreachable state in bounds.
        let (Ok(row), Ok(column)) = (usize::try_from(l_msb_high), usize::try_from(l_msb_low))
        else {
            break;
        };
        let Some(&q) = TAB_ARI_QNEW.get(row).and_then(|r| r.get(column)) else {
            break;
        };
        low = l_msu(low, 1, q);
        low = l_shl(low, 1);
        high = l_msu(high, 1, q);
        high = l_add(l_shl(high, 1), 1);
        value = l_msu(value, 1, q);
        let bit = bitstream_load_bit(&mut ar_inst.bs_inst) as i32;
        value = l_add(l_shl(value, 1), bit);
    }

    ar_inst.low = low;
    ar_inst.high = high;
    ar_inst.value = value;

    (symbol - 1) as i16
}

/// `ar_decoder_done_fx`: return the `AR_BITS - 2` bits of look-ahead to the bitstream.
pub fn ar_decoder_done(ar_inst: &mut ArCodec) {
    bitstream_rollback(&mut ar_inst.bs_inst, i32::from(AR_BITS - 2));
}

/// `quantize_fx`: the TCQ reconstruction of `val` (Q10) on the union of cosets selected by `d`.
#[must_use]
pub fn quantize(val: i16, d: i16) -> i16 {
    let val = val.min(32255); // limit input by (2^15 - 1)-2^9
    let qval4_fx = shr(abs_s(add(val, 512)), 12);
    // `d` comes from `ddec_fx`, 0..=3.
    let mut retval_fx = add(shl(qval4_fx, 2), DDP_FX[(d & 3) as usize]);
    // 2nd zero check
    if d == 0
        && sub(
            abs_s(sub(shl(abs_s(retval_fx), 10), abs_s(val))),
            abs_s(val),
        ) > 0
    {
        retval_fx = 0;
    }
    retval_fx
}

/// `GetBitsFromPulses_fx`: log2 of the number of ways to place `m` unit pulses on `n` positions
/// (Q16).
#[must_use]
pub fn get_bits_from_pulses(m: i16, n: i16) -> i32 {
    let mut exp: i16 = 0;
    let mut mantissa_fx: i32 = 0;
    if m == 0 {
        return 0;
    }
    let logcum = |index: i32| {
        usize::try_from(index)
            .ok()
            .and_then(|i| TABLE_LOGCUM_FX.get(i))
            .copied()
            .unwrap_or(0)
    };
    let (m32, n32) = (i32::from(m), i32::from(n));
    let tmp = m.min(n);
    for i in 0..i32::from(tmp.max(0)) {
        let mut log_coeff_fx = l_add(
            l_shl(i + 1, 16),
            l_sub(logcum(n32 + 1), l_add(logcum(i + 2), logcum(n32 - i))),
        );
        log_coeff_fx = l_add(
            log_coeff_fx,
            l_sub(logcum(m32), l_add(logcum(i + 1), logcum(m32 - i))),
        ); // Q16
        let integer_fx = extract_h(log_coeff_fx); // Q0
        let mut frac_fx32 = l_sub(log_coeff_fx, l_shl(i32::from(integer_fx), 16)); // Q16

        // frac = pow(2.0, temp1 * 0.0625) * (1 + 0.693 * temp2 + 0.480 * temp2 * temp2 * 0.5)
        let temp_fx1 = extract_h(l_shl(frac_fx32, 4));
        let temp_fx2 = extract_l(frac_fx32 & 0xfff); // Q16

        frac_fx32 = l_mac(
            mult_32_16(l_mult0(temp_fx2, temp_fx2), 7864),
            temp_fx2,
            22708,
        ); // Q32
        frac_fx32 = l_add(0x4000_0000, l_shr(frac_fx32, 2)); // 30

        // `temp_fx1` is the top four bits of a Q16 fraction, 0..=15.
        let pow = POW_GETBITSFROMPULSES_FX[(temp_fx1 & 15) as usize];
        let exp1 = norm_l(pow);
        let exp2 = norm_l(frac_fx32);
        frac_fx32 = mult_32_32(l_shl(pow, exp1), l_shl(frac_fx32, exp2)); // 21 + exp1 + 30 + exp2 - 31
        frac_fx32 = l_shr(frac_fx32, exp1 + exp2).wrapping_add(1); // 20

        if sub(exp, integer_fx) < 0 {
            mantissa_fx = l_shr(mantissa_fx, sub(integer_fx, exp));
            mantissa_fx = l_add(mantissa_fx, frac_fx32);
            exp = integer_fx;
        } else {
            mantissa_fx = l_add(mantissa_fx, l_shr(frac_fx32, sub(exp, integer_fx)));
        }
        if l_sub(mantissa_fx, 0x20_0000) >= 0 {
            exp += 1;
            mantissa_fx = l_shr(mantissa_fx, 1);
        }
    }

    mantissa_fx = l_shl(mantissa_fx, 2); // 22
    let mut temp_fx1 = extract_h(mantissa_fx);
    let mut temp32 = l_shl(l_sub(mantissa_fx, l_deposit_h(temp_fx1)), 15); // 31
    let exp1 = sub(norm_l(temp32), 1);
    temp32 = ar_div(l_shl(temp32, exp1), i32::from(temp_fx1)); // 31 + exp1
    temp32 = l_shr(temp32, exp1 + 1); // 30

    let mut frac_fx32 = l_sub(0x4000_0000, l_shr(temp32, 1)); // 30
    frac_fx32 = mult_32_32(frac_fx32, temp32); // 29
    frac_fx32 = l_shr(frac_fx32, 13); // 16
    let exp1 = norm_l(i32::from(temp_fx1));
    temp_fx1 = log2_norm_lc(l_shl(i32::from(temp_fx1), exp1)); // 15
    frac_fx32 = frac_fx32.wrapping_add(mult_32_32(frac_fx32, 950_680_361)); // frac_fx32 *= 1/ln(2)
    l_add(
        l_deposit_h(exp),
        l_add(l_shl(i32::from(temp_fx1), 1), frac_fx32),
    )
}

/// `TCQLSBdec_fx`: expand the decoded trellis path `dpath[0..bcount/2]` into `bcount` LSB
/// corrections (±1) in `mbuffer`.
pub fn tcq_lsb_dec(dpath: &[i16], mbuffer: &mut [i16], bcount: i16) {
    let q: i16 = 1; // x5
    let mut state: usize = 0;
    let tmp = shr(bcount, 1);
    for i in 0..tmp.max(0) as usize {
        // A path entry is a decoded binary symbol, 0 or 1.
        let branch = (dpath[i] & 1) as usize;
        let lsb = DDEC_LSB_FX[state][branch];
        mbuffer[2 * i] = if lsb & 0x1 != 0 { q } else { negate(q) };
        mbuffer[2 * i + 1] = if lsb & 0x2 != 0 { q } else { negate(q) };
        state = DSTEP_LSB_FX[state][branch] as usize;
    }
}

/// `RestoreTCQdec_fx`: scale the band's magnitudes by 5 and, in a band with more than one pulse
/// and a magnitude above 1, add the next LSB corrections from `mbuffer`.
pub fn restore_tcq_dec(magn: &mut [i16], size: i16, bcount: &mut i16, mbuffer: &mut [i16]) {
    let size = size.max(0) as usize;
    let mut nzpos: i16 = 0;
    let mut flag_g1 = false;
    for value in &mut magn[..size] {
        if *value != 0 {
            nzpos = add(nzpos, 1);
            if sub(abs_s(*value), 1) > 0 {
                flag_g1 = true;
            }
            *value = extract_l(l_mult0(*value, 5));
        }
    }
    if sub(nzpos, 1) > 0 {
        for value in &mut magn[..size] {
            if !(flag_g1 && sub(*bcount, 2 * TCQ_AMP) < 0) {
                break;
            }
            if *value != 0 {
                // `*bcount` < 2·TCQ_AMP here.
                let slot = *bcount as usize;
                mbuffer[slot] = add(*value, mbuffer[slot]);
                *value = mbuffer[slot];
                *bcount = add(*bcount, 1);
            }
        }
    }
}

/// `LoadTCQdata_fx`: decode `bcount` binary trellis-path symbols into `dpath`.
pub fn load_tcq_data(ar_inst: &mut ArCodec, dpath: &mut [i16], bcount: i16) {
    for slot in &mut dpath[..bcount.max(0) as usize] {
        *slot = ar_decode(ar_inst, &UNIFORM_MODEL_FX);
    }
}

/// `round_fx(L_shr(L_deposit_h(div_l(L_deposit_h(size - i - 1), size)), 1))`: the uniform
/// single-pulse position model entry `i + 1`.
fn uniform_position_entry(size: i16, i: i16) -> i16 {
    round_word(l_shr(
        l_deposit_h(div_l(l_deposit_h(size - i - 1), size)),
        1,
    ))
}

/// Set `position[index] = 1` for a decoded index; an index past the band (only a corrupt stream
/// produces one) would write into the next band in the reference, and is dropped here.
fn mark_position(position: &mut [i16], size: i16, index: i32) {
    if (0..i32::from(size)).contains(&index) {
        if let Some(slot) = position.get_mut(index as usize) {
            *slot = 1;
        }
    }
}

/// `decode_position_ari_fx`: decode the number of non-zero positions `nz` and the positions
/// themselves (`position[0..size]` set to 0/1) of `npulses` pulses in a band of `size`.
pub fn decode_position_ari(
    pardec: &mut ArCodec,
    size: i16,
    npulses: i16,
    nz: &mut i16,
    position: &mut [i16],
) {
    let mut mode_num_nz = [0_i16; POSITION_MODEL_LEN];
    let mut prob = [0_i16; POSITION_MODEL_LEN];
    let fxone: i32 = 32768;
    let fxp1: i32 = 512 * 32768;
    let mut stpos: i16 = 0;

    position[..size.max(0) as usize].fill(0);

    if l_sub(i32::from(npulses), 1) > 0 {
        let btcq_fx = get_bits_from_pulses(npulses, size);
        // `npulses` <= MAX_PULSES and `size` <= TCQ_MAX_BAND_SIZE keep every index in the table.
        let logcum = |index: i16| {
            usize::try_from(index)
                .ok()
                .and_then(|i| TABLE_LOGCUM_FX.get(i))
                .copied()
                .unwrap_or(0)
        };
        let tmp = npulses.min(size);
        for i in 0..tmp.max(0) {
            // calculate the probability of #nz
            let mut pnzp_fx = l_sub(l_deposit_h(add(i, 1)), btcq_fx);
            pnzp_fx = l_add(
                pnzp_fx,
                l_add(
                    l_sub(logcum(size + 1), l_add(logcum(i + 2), logcum(size - i))),
                    l_sub(logcum(npulses), l_add(logcum(i + 1), logcum(npulses - i))),
                ),
            );
            pnzp_fx = l_add(pnzp_fx, 917_498); // 16
            let slot = &mut prob[i as usize];
            if l_sub(pnzp_fx, 0) > 0 {
                let integer = extract_h(pnzp_fx);
                let frac = extract_l(l_shr(l_sub(pnzp_fx, l_deposit_h(integer)), 1)); // 15
                *slot = extract_h(l_shl(pow2(integer, frac), 16)); // 0
                if *slot == 0 {
                    *slot = 1;
                }
            } else {
                *slot = 1;
            }
        }

        ar_make_model(&prob, &mut mode_num_nz, npulses.min(size));
        *nz = add(1, ar_decode(pardec, &mode_num_nz)); // get #nz
        let mut nzp = *nz;
        if nzp == 1 {
            mode_num_nz[0] = MAX_AR_FREQ;
            for i in 0..size.max(0) {
                mode_num_nz[i as usize + 1] = uniform_position_entry(size, i);
            }
            let index = ar_decode(pardec, &mode_num_nz);
            mark_position(position, size, i32::from(index));
        } else {
            mode_num_nz[0] = MAX_AR_FREQ;
            // `ovrflag` lives at function scope in the reference: a pass whose scan loop does not
            // run (`stpos >= size`) sees the previous pass's value.
            let mut ovrflag = false;
            while nzp > 0 {
                if !decode_position_ari_next(
                    pardec,
                    size,
                    nzp,
                    &mut stpos,
                    &mut ovrflag,
                    &mut mode_num_nz,
                    position,
                    fxone,
                    fxp1,
                ) {
                    return;
                }
                nzp -= 1;
            }
        }
    } else if l_sub(i32::from(npulses), 1) == 0 {
        *nz = npulses;
        mode_num_nz[0] = MAX_AR_FREQ;
        for i in 0..size.max(0) {
            mode_num_nz[i as usize + 1] = uniform_position_entry(size, i);
        }
        let index = ar_decode(pardec, &mode_num_nz);
        mark_position(position, size, i32::from(index));
    } else {
        *nz = 0;
    }
}

/// One pass of `decode_position_ari_fx`'s `for (; nzp > 0; nzp--)` loop: decode the distance from
/// `stpos` to the next non-zero position. Returns `false` when a corrupt stream drives a model index
/// out of range (the reference would read or write outside its arrays).
fn decode_position_ari_next(
    pardec: &mut ArCodec,
    size: i16,
    nzp: i16,
    stpos: &mut i16,
    ovrflag: &mut bool,
    mode_num_nz: &mut [i16; POSITION_MODEL_LEN],
    position: &mut [i16],
    fxone: i32,
    fxp1: i32,
) -> bool {
    let mut scp = l_add(fxp1, 0);
    let mut storepos: i16 = 0;
    let model_index = |value: i32| {
        usize::try_from(value)
            .ok()
            .filter(|&v| v < POSITION_MODEL_LEN)
    };

    let mut i = *stpos;
    while i < size {
        *ovrflag = false;
        let cp = if i32::from(nzp) == i32::from(size) - i32::from(i) {
            l_deposit_l(0)
        } else {
            l_sub(
                fxone,
                i32::from(div_l(l_deposit_h(nzp), size.wrapping_sub(i))),
            )
        };
        scp = mult_32_16(scp, extract_l(cp));
        let base = i32::from(i) - i32::from(storepos) - i32::from(*stpos);
        let (Some(next), Some(current)) = (model_index(base + 1), model_index(base)) else {
            return false;
        };
        mode_num_nz[next] = round_word(l_shl(scp, 6));

        if (mode_num_nz[next] == 0 && scp > 0) || mode_num_nz[current] == mode_num_nz[next] {
            mode_num_nz[next] = 0;
            *ovrflag = true;
            let temppos = ar_decode(pardec, &mode_num_nz[..]);
            storepos = storepos.wrapping_add(temppos);
            scp = l_add(fxp1, 0);
            if temppos == i.wrapping_sub(*stpos) {
                // esc transmitted
                i -= 1;
            } else {
                break;
            }
        }
        i += 1;
    }
    let pos = if *ovrflag {
        storepos
    } else {
        ar_decode(pardec, &mode_num_nz[..]).wrapping_add(storepos)
    };
    mark_position(position, size, i32::from(*stpos) + i32::from(pos));
    *stpos = stpos.wrapping_add(pos.wrapping_add(1));
    true
}

/// `decode_magnitude_usq_fx`: decode the magnitudes of `npulses` pulses over the `nzpos` non-zero
/// `positions[0..size]` of a USQ band into `out`.
pub fn decode_magnitude_usq(
    pardec: &mut ArCodec,
    size: i16,
    npulses: i16,
    nzpos: i16,
    positions: &[i16],
    out: &mut [i16],
) {
    let size_us = size.max(0) as usize;
    let mut mmodel = [0_i16; MAX_PULSES as usize + 2];
    let fxone: i32 = 32768;
    let fxp1: i32 = 512 * 32768;
    let mut ovrflag = false;

    if sub(nzpos, npulses) == 0 {
        out[..size_us].copy_from_slice(&positions[..size_us]);
        return;
    } else if sub(nzpos, 1) == 0 {
        for i in 0..size_us {
            if positions[i] != 0 {
                out[i] = npulses;
                return;
            }
        }
    }

    let mut magnzp = sub(nzpos, 1);
    let mut magnp = sub(npulses, 1);
    out[..size_us].fill(0);
    mmodel[0] = MAX_AR_FREQ;
    let mut magncout: usize = 0;
    let model_index = |value: i32| {
        usize::try_from(value)
            .ok()
            .filter(|&v| v < MAX_PULSES as usize + 2)
    };

    let mut pos: usize = 0;
    while pos < size_us {
        if positions[pos] != 0 {
            let mut scp = l_add(fxp1, 0);
            let mut storemagn: i16 = 0;
            let mut i: i16 = 0;
            while i < magnp {
                ovrflag = false;
                let cp = if magnzp == magnp.wrapping_sub(i) {
                    l_deposit_l(0)
                } else {
                    l_sub(
                        fxone,
                        i32::from(div_l(l_deposit_h(magnzp), magnp.wrapping_sub(i))),
                    )
                };
                if cp == fxone {
                    break;
                }
                scp = mult_32_16(scp, extract_l(cp));
                let base = i32::from(i) - i32::from(storemagn);
                let (Some(next), Some(current)) = (model_index(base + 1), model_index(base)) else {
                    // Only a corrupt stream walks the model index out of range.
                    return;
                };
                mmodel[next] = round_word(l_shl(scp, 6));

                if (mmodel[next] == 0 && scp > 0) || mmodel[current] == mmodel[next] {
                    mmodel[next] = 0;
                    // read data
                    let tempmagn = ar_decode(pardec, &mmodel);
                    storemagn = storemagn.wrapping_add(tempmagn);
                    if tempmagn < i {
                        // just magnitude
                        ovrflag = true;
                        break;
                    }
                    // esc code
                    scp = l_add(fxp1, 0);
                    i -= 1;
                }
                i += 1;
            }

            let magnitude = if ovrflag {
                storemagn.wrapping_add(1)
            } else {
                ar_decode(pardec, &mmodel)
                    .wrapping_add(storemagn)
                    .wrapping_add(1)
            };
            let Some(slot) = out.get_mut(magncout) else {
                return;
            };
            *slot = magnitude;
            magnp = magnp.wrapping_sub(magnitude);
            magnzp = magnzp.wrapping_sub(1);
            magncout += 1;

            if magnzp == 0 {
                // last magnitude generation
                pos += 1;
                while pos < size_us {
                    if positions[pos] != 0 {
                        out[magncout] = magnp.wrapping_add(1);
                        return;
                    }
                    out[magncout] = 0;
                    magncout += 1;
                    pos += 1;
                }
            } else if magnzp == magnp {
                // rest magnitudes generation
                pos += 1;
                while pos < size_us {
                    out[magncout] = positions[pos];
                    magncout += 1;
                    pos += 1;
                }
                return;
            }
        } else {
            out[magncout] = 0;
            magncout += 1;
        }
        pos += 1;
    }
}

/// `decode_mangitude_tcq_fx` (sic): decode the magnitudes of `npulses` pulses over the `nzpos`
/// non-zero `positions[0..size]` of a TCQ band into `out` along the trellis, and add the bits the
/// trellis saved to `surplus_fx` (Q16).
pub fn decode_mangitude_tcq(
    pardec: &mut ArCodec,
    size: i16,
    npulses: i16,
    nzpos: i16,
    positions: &[i16],
    out: &mut [i16],
    surplus_fx: &mut i32,
) {
    let size_us = size.max(0) as usize;
    let mut bits_fx: i32 = l_deposit_l(0);
    let mut leftp = npulses; // pulsesnum
    let mut leftnz = nzpos; // nzpos
    let mut magn_mode: [i16; 3] = [MAX_AR_FREQ, 0, 0];
    let logcum = |index: i32| {
        usize::try_from(index)
            .ok()
            .and_then(|i| TABLE_LOGCUM_FX.get(i))
            .copied()
            .unwrap_or(0)
    };
    let tcq_bits_fx = l_sub(
        logcum(i32::from(npulses)),
        l_add(
            logcum(i32::from(nzpos)),
            logcum(i32::from(npulses) - (i32::from(nzpos) - 1)),
        ),
    );

    if sub(nzpos, npulses) == 0 {
        out[..size_us].copy_from_slice(&positions[..size_us]);
        return;
    } else if sub(nzpos, 1) == 0 {
        for i in 0..size_us {
            if positions[i] != 0 {
                out[i] = npulses;
                return;
            }
        }
    }

    let mut st: usize = 0;
    let mut i: usize = 0;
    while i < size_us {
        if sub(leftnz, 1) <= 0 {
            break;
        }
        out[i] = positions[i];
        if positions[i] != 0 {
            // generate the trellis path
            let mut symbol: i16 = 0;
            let mut j: i16 = 0;
            while j < leftp {
                let num = sub(leftnz, 1);
                let denum = sub(leftp, add(j, 1));
                let mut prob1_fx;
                let mut prob0_fx;
                if sub(num, denum) >= 0 {
                    prob1_fx = MAX_16;
                    prob0_fx = 0;
                } else {
                    let exp1 = sub(norm_s(num), 1);
                    let exp2 = norm_s(denum);
                    prob1_fx = div_s(shl(num, exp1), shl(denum, exp2)); // 15 + exp1 - exp2
                    let exp = 15 + exp1 - exp2;
                    prob1_fx = shl(prob1_fx, sub(15, exp));
                    prob0_fx = sub(MAX_16, prob1_fx);
                }
                if l_sub(i32::from(sub(leftp, j)), i32::from(leftnz)) == 0 {
                    symbol = add(j, 1);
                    break;
                }

                let quantum1_fx = quantize(shl(add(j, 1), 10), DDEC_FX[st][0]);
                let quantum2_fx = quantize(shl(add(j, 1), 10), DDEC_FX[st][1]);
                if sub(quantum1_fx, add(j, 1)) != 0 && sub(quantum2_fx, add(j, 1)) != 0 {
                    prob0_fx = MAX_16;
                    prob1_fx = 0;
                }
                if sub(prob0_fx, MAX_16) == 0 || sub(prob1_fx, MAX_16) == 0 {
                    symbol = add(j, 1);
                    j += 1;
                    continue;
                }

                // magn_mode[1] = (short)(prob1 * MAX_AR_FREQ);
                magn_mode[1] = mult(prob1_fx, MAX_AR_FREQ);
                if ar_decode(pardec, &magn_mode) != 0 {
                    bits_fx = decode_mangitude_tcq_bits(bits_fx, prob1_fx);
                    symbol = add(j, 1);
                    break;
                }
                bits_fx = decode_mangitude_tcq_bits(bits_fx, prob0_fx);
                j += 1;
            }
            out[i] = symbol;
            leftp = sub(leftp, symbol);
            leftnz = sub(leftnz, 1);
        }

        let quantum1_fx = quantize(out[i], DDEC_FX[st][0]);
        // generate the next state
        st = if sub(quantum1_fx, out[i]) == 0 {
            NEXTSTATE[st][0] as usize
        } else {
            NEXTSTATE[st][1] as usize
        };
        i += 1;
    }

    // generate the magnitudes
    while i < size_us {
        out[i] = 0;
        if positions[i] != 0 {
            out[i] = add(sub(leftp, leftnz), 1);
        }
        i += 1;
    }

    if sub(nzpos, npulses) != 0 && sub(nzpos, 1) > 0 {
        // update the surplus
        *surplus_fx = l_add(*surplus_fx, l_sub(tcq_bits_fx, l_shl(bits_fx, 1)));
    }
}

/// `bits_fx -= log2(prob)` (Q15) for a branch probability `prob` (Q15), as
/// `decode_mangitude_tcq_fx` accumulates it.
fn decode_mangitude_tcq_bits(bits_fx: i32, prob: i16) -> i32 {
    let exp1 = norm_s(prob);
    let tmp32 = l_deposit_h(shl(prob, exp1)); // exp1 + 15 + 16
    let tmp16 = log2_norm_lc(tmp32); // 15
    l_sub(
        bits_fx,
        l_sub(i32::from(tmp16), l_shl(i32::from(add(exp1, 1)), 15)),
    ) // 15
}

/// `decode_signs_fx`: one equiprobable sign per non-zero `out[0..size]` (0 = negative).
pub fn decode_signs(pardec: &mut ArCodec, size: i16, out: &mut [i16]) {
    for value in &mut out[..size.max(0) as usize] {
        if *value != 0 {
            let tmp = ar_decode(pardec, &UNIFORM_MODEL_FX);
            if tmp <= 0 {
                *value = negate(*value);
            }
        }
    }
}

/// `GetScale_fx`: the largest pulse count (at most `MAX_PULSES`, -1 if none fits) whose position
/// coding costs no more than `bits_fx` (Q16) in a band of `blen`; the unused bits are added to
/// `surplus_fx` (the reference skips that for a null pointer).
pub fn get_scale(blen: i16, bits_fx: i32, surplus_fx: Option<&mut i32>) -> i16 {
    let magicnum: i16 = 24773; // Q17: 0.188992013101951f
    let mut estbits_fx: i32 = 0;

    let t = l_shr(l_mult(magicnum, blen), 2);
    let exp = norm_l(t);
    let a = l_shl(14 - i32::from(exp), 15).wrapping_add(i32::from(log2_norm_lc(l_shl(t, exp))));

    let exp1 = sub(norm_l(bits_fx), 1);
    let exp2 = norm_s(blen.wrapping_sub(1));
    let b = l_shr(
        l_deposit_l(div_l(l_shl(bits_fx, exp1), shl(blen.wrapping_sub(1), exp2))),
        exp1.wrapping_sub(exp2),
    );

    let ab = l_add(a, b);
    // enable saturation of pow2 result
    let p_est = extract_h(l_shl(
        pow2(extract_l(l_shr(ab, 15)), (ab & 0x7FFF) as i16),
        16,
    ));

    let mut pulses = p_est.min(MAX_PULSES);
    while pulses >= 0 {
        estbits_fx = get_bits_from_pulses(pulses, blen);
        if l_sub(bits_fx, estbits_fx) >= 0 {
            break;
        }
        pulses -= 1;
    }

    if let Some(surplus_fx) = surplus_fx {
        *surplus_fx = l_add(*surplus_fx, l_sub(bits_fx, estbits_fx));
    }
    pulses
}

/// `srt_vec_ind_fx`: `srt = linear[0..length]` sorted ascending (exchange sort, so equal values
/// keep the reference's order) and `i[k]` the source index of `srt[k]`.
pub fn srt_vec_ind(linear: &[i32], srt: &mut [i32], i: &mut [i16], length: i16) {
    let length = length.max(0) as usize;
    for (pos, slot) in i[..length].iter_mut().enumerate() {
        *slot = pos as i16;
    }
    srt[..length].copy_from_slice(&linear[..length]);
    for pos in 0..length.saturating_sub(1) {
        for npos in pos + 1..length {
            if l_sub(srt[npos], srt[pos]) < 0 {
                i.swap(pos, npos);
                srt.swap(pos, npos);
            }
        }
    }
}
