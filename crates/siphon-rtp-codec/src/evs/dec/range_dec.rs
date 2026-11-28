//! The range decoder of the PVQ / HQ path (TS 26.442 `lib_dec/range_dec_fx.c`; TS 26.445
//! §6.2.3.2.1). Symbols are read MSB first from the bitstream front; raw bits (`rc_dec_bits`) are
//! read backwards from the end of the range-coded segment.

use crate::evs::com::bitstream::{get_indice, get_next_indice};
use crate::evs::com::tools::{ul_div, ul_inverse};
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, shl, sub};
use crate::itu::stl2009::{mpy_32_32_uu, norm_ul, ul_lshl, ul_lshr, ul_mpy_32_32, ul_sub_ns};

/// `rc_dec_init_fx`: start a range-coded segment of `tot_bits` bits at the current bit position.
pub fn rc_dec_init(st: &mut DecoderState, tot_bits: i16) {
    st.rc_low = 0;
    st.rc_range = 0xffff_ffff;
    st.rc_num_bits = 0;
    st.rc_offset = add(tot_bits, st.next_bit_pos);
    st.rc_end = st.rc_offset;

    for _ in 0..4 {
        st.rc_low = ul_lshl(st.rc_low, 8).wrapping_add(u32::from(rc_dec_read(st) as u16));
    }
}

/// `rc_decode_fx`: the cumulative frequency of the next symbol under total `tot`. A value at or
/// past `tot` (only a corrupted frame produces one) flags `BER_detect` and decodes as 0.
pub fn rc_decode(st: &mut DecoderState, tot: u32) -> u32 {
    let mut exp: i16 = 0;
    let inv = ul_inverse(tot, &mut exp);
    st.rc_help = mpy_32_32_uu(st.rc_range, inv).0; // 0+exp-32
    st.rc_help = ul_lshr(st.rc_help, sub(exp, 32));
    let exp_den = norm_ul(st.rc_help);
    let mut ul_tmp2 = ul_lshl(st.rc_help, exp_den);
    let exp_num = sub(norm_ul(st.rc_low), 1);
    let mut ul_tmp1 = ul_lshl(st.rc_low, exp_num);
    exp = add(32, sub(exp_num, exp_den));

    let mut val = ul_div(ul_tmp1, ul_tmp2);
    val = ul_lshr(val, exp);

    ul_tmp1 = ul_mpy_32_32(val, st.rc_help);
    ul_tmp2 = ul_mpy_32_32(val.wrapping_add(1), st.rc_help);
    ul_tmp1 = st.rc_low.wrapping_sub(ul_tmp1);
    ul_tmp2 = st.rc_low.wrapping_sub(ul_tmp2);
    if ul_tmp2 < ul_tmp1 {
        val = val.wrapping_add(1);
    }

    // safety check in case of bit errors
    if ul_sub_ns(tot, val).1 {
        st.ber_detect = 1;
        return 0;
    }

    val
}

/// `rc_dec_update_fx`: consume the symbol `[cum_freq, cum_freq + sym_freq)` and renormalise.
pub fn rc_dec_update(st: &mut DecoderState, cum_freq: u32, sym_freq: u32) {
    st.rc_low = st.rc_low.wrapping_sub(ul_mpy_32_32(cum_freq, st.rc_help)); // 0+0
    st.rc_range = ul_mpy_32_32(st.rc_help, sym_freq);

    while st.rc_range < 1 << 24 {
        st.rc_num_bits = add(st.rc_num_bits, 8);
        st.rc_low = ul_lshl(st.rc_low, 8).wrapping_add(u32::from(rc_dec_read(st) as u16));
        st.rc_range = ul_lshl(st.rc_range, 8);
    }
}

/// `rc_dec_bits_fx`: `bits` (at most 32) raw bits, read backwards from the end of the segment.
pub fn rc_dec_bits(st: &mut DecoderState, bits: i16) -> i32 {
    st.rc_num_bits = add(st.rc_num_bits, bits);

    if sub(bits, 16) > 0 {
        st.rc_offset = sub(st.rc_offset, sub(bits, 16));
        let mut value = ul_lshl(u32::from(get_indice(st, st.rc_offset, sub(bits, 16))), 16);
        st.rc_offset = sub(st.rc_offset, 16);
        value |= u32::from(get_indice(st, st.rc_offset, 16));
        value as i32
    } else {
        st.rc_offset = sub(st.rc_offset, bits);
        i32::from(get_indice(st, st.rc_offset, bits))
    }
}

/// `rc_dec_uniform_fx`: a value uniform in `[0, tot)`; above 8 bits of range the low bits are raw.
pub fn rc_dec_uniform(st: &mut DecoderState, tot: u32) -> u32 {
    let mut n = sub(32, norm_ul(tot.wrapping_sub(1)));

    if sub(n, 8) <= 0 {
        let value = rc_decode(st, tot);
        rc_dec_update(st, value, 1);
        value
    } else {
        n = sub(n, 8);
        let mut value = rc_decode(st, ul_lshr(tot, n).wrapping_add(1));
        rc_dec_update(st, value, 1);
        value = ul_lshl(value, n);
        value | rc_dec_bits(st, n) as u32
    }
}

/// `rc_dec_finish_fx`: move the bit position past the range-coded segment.
pub fn rc_dec_finish(st: &mut DecoderState) {
    st.next_bit_pos = st.rc_end;
}

/// `rc_dec_read_fx`: the next byte of the segment, zero-padded at its end.
fn rc_dec_read(st: &mut DecoderState) -> i16 {
    let bits = sub(st.rc_end, st.next_bit_pos);

    // If the end of the buffer has been reached, pad the last byte with zeros
    if sub(bits, 8) < 0 {
        shl(get_next_indice(st, bits) as i16, sub(8, bits))
    } else {
        get_next_indice(st, 8) as i16
    }
}
