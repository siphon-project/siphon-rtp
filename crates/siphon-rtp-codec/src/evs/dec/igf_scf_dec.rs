//! Arithmetic decoding of the IGF spectral-envelope scale factors (TS 26.442
//! `lib_dec/igf_scf_dec.c`; TS 26.445 clause 6.2.2.3.9).
//!
//! The raw arithmetic-decoder primitives (`ari_start_decoding_14bits`, `ari_decode_14bits_s27_ext`,
//! `ari_decode_14bits_bit_ext`) belong to `lib_dec/ari_dec.c` ([`crate::evs::dec::ari_dec`]). The
//! reference passes the decoder state and the instance (whose `acState` the primitives advance)
//! separately even though the instance lives inside the decoder state; here the caller hands over
//! the instance as its own value for the duration of a call, so the two never alias.

use crate::evs::cnst::{
    IGF_CTX_COUNT, IGF_CTX_OFFSET, IGF_MAX_ENC_SEPARATE, IGF_MIN_ENC_SEPARATE, IGF_SYMBOLS_IN_TABLE,
};
use crate::evs::com::bitstream::get_next_indice_tmp;
use crate::evs::com::igf_base::{igf_common_funcs_igf_get_cf_tables, IgfCfTables};
use crate::evs::com::tools::copy;
use crate::evs::dec::ari_dec::{
    ari_decode_14bits_bit_ext, ari_decode_14bits_s27_ext, ari_start_decoding_14bits,
};
use crate::evs::dec::state::{DecoderState, IgfscfdecInstance};
use crate::itu::basic_ops::{abs_s, add, negate, sub};
use crate::itu::stl2009::{l_mac0, lshl};

/// Entries of a cumulative-frequency table the arithmetic decoder reads: one more than the
/// alphabet size.
const CUMULATIVE_FREQUENCY_ENTRIES: usize = IGF_SYMBOLS_IN_TABLE as usize + 1;

/// `IGFSCFDecoderOpen`: initialise the SCF decoder of a bit rate and bandwidth mode.
pub fn igf_scf_decoder_open(
    h_public_data: &mut IgfscfdecInstance,
    scf_count_long_block: i16,
    bit_rate: i32,
    mode: i16,
    rf_mode: i16,
) {
    h_public_data.scf_count_long_block = scf_count_long_block;
    h_public_data.t = 0; // protect against the invalid request of starting decoding with a dependent block

    // The reference's out-pointers keep their value when the bit rate has no tables.
    let mut tables = IgfCfTables {
        cf_se00: h_public_data.cf_se00,
        cf_se01: h_public_data.cf_se01,
        cf_off_se01: h_public_data.cf_off_se01,
        cf_se02: h_public_data.cf_se02,
        cf_off_se02: h_public_data.cf_off_se02,
        cf_se10: h_public_data.cf_se10,
        cf_off_se10: h_public_data.cf_off_se10,
        cf_se11: h_public_data.cf_se11,
        cf_off_se11: h_public_data.cf_off_se11,
    };
    igf_common_funcs_igf_get_cf_tables(bit_rate, mode, rf_mode, &mut tables);
    h_public_data.cf_se00 = tables.cf_se00;
    h_public_data.cf_se01 = tables.cf_se01;
    h_public_data.cf_off_se01 = tables.cf_off_se01;
    h_public_data.cf_se02 = tables.cf_se02;
    h_public_data.cf_off_se02 = tables.cf_off_se02;
    h_public_data.cf_se10 = tables.cf_se10;
    h_public_data.cf_off_se10 = tables.cf_off_se10;
    h_public_data.cf_se11 = tables.cf_se11;
    h_public_data.cf_off_se11 = tables.cf_off_se11;
}

/// `quant_ctx_fx`: quantise a context value, `-3 -3 -3 -2 -1 0 1 2 3 3 3` for `-5 .. 5`.
fn quant_ctx(ctx: i16) -> i16 {
    let mut result = abs_s(ctx).min(IGF_CTX_OFFSET); // limit the absolute value to IGF_CTX_OFFSET
    if ctx < 0 {
        // add the sign back, if needed
        result = negate(result);
    }

    result
}

/// A cumulative-frequency table as the arithmetic decoder's `UWord16` view of it (the reference
/// casts the pointer; the values are cumulative counts up to 2^14 and read the same either way).
fn cumulative_frequencies(table: &[i16]) -> [u16; CUMULATIVE_FREQUENCY_ENTRIES] {
    let mut out = [0u16; CUMULATIVE_FREQUENCY_ENTRIES];
    for (destination, source) in out.iter_mut().zip(table) {
        *destination = *source as u16;
    }
    out
}

/// `arith_decode_bits_fx`: `n_bits` raw bits through the arithmetic decoder, MSB first.
fn arith_decode_bits(
    h_private_data: &mut IgfscfdecInstance,
    st: &mut DecoderState,
    n_bits: i16,
) -> i16 {
    let mut x: i16 = 0;
    for _ in 0..n_bits {
        // nBits > 0
        x = lshl(x, 1);
        // decode one bit using the new raw AC function
        let bit = ari_decode_14bits_bit_ext(st, &mut h_private_data.ac_state);
        if bit != 0 {
            x |= 1;
        }
    }

    x
}

/// `arith_decode_residual_fx`: one residual, a table symbol or an escape followed by raw bits.
fn arith_decode_residual(
    h_private_data: &mut IgfscfdecInstance,
    st: &mut DecoderState,
    cumulative_frequency_table: &[i16],
    table_offset: i16,
) -> i16 {
    let mut x: i16 = 0; // to avoid a compiler warning (potentially uninitialized local variable used)

    // decode one of the IGF_SYMBOLS_IN_TABLE == 27 alphabet symbols using the new raw AC function
    let val = ari_decode_14bits_s27_ext(
        st,
        &mut h_private_data.ac_state,
        &cumulative_frequencies(cumulative_frequency_table),
    );

    // meaning of the values of val:
    // esc_{0} IGF_MIN_ENC_SEPARATE ... IGF_MAX_ENC_SEPARATE esc_{IGF_SYMBOLS_IN_TABLE - 1}
    if val != 0 && sub(val, IGF_SYMBOLS_IN_TABLE - 1) != 0 {
        x = add(val, -1 + IGF_MIN_ENC_SEPARATE); // (val - 1) + IGF_MIN_ENC_SEPARATE

        x = sub(x, table_offset);

        return x;
    }

    // decode one of the tails of the distribution
    // decode extra with 4 bits
    let mut extra = arith_decode_bits(h_private_data, st, 4);
    if sub(extra, 15) == 0 {
        // escape code 15 to indicate extra >= 15
        // decode addtional extra with 6 bits
        extra = arith_decode_bits(h_private_data, st, 6);
        if sub(extra, 63) == 0 {
            // escape code 63 to indicate extra >= 63
            // decode safety extra with 7 bits
            extra = arith_decode_bits(h_private_data, st, 7);
            extra = add(63, extra);
        }
        extra = add(15, extra);
    }

    if val == 0 {
        // escape code 0 to indicate x <= IGF_MIN_ENC_SEPARATE - 1
        x = sub(IGF_MIN_ENC_SEPARATE - 1, extra);
    }
    if sub(val, IGF_SYMBOLS_IN_TABLE - 1) == 0 {
        // escape code (IGF_SYMBOLS_IN_TABLE - 1) to indicate x >= IGF_MAX_ENC_SEPARATE + 1
        x = add(IGF_MAX_ENC_SEPARATE + 1, extra);
    }

    x = sub(x, table_offset);

    x
}

/// `arith_decode_flush_fx`: hand the last 14 bits the arithmetic decoder read ahead back to the
/// bitstream.
fn arith_decode_flush(st: &mut DecoderState) {
    get_next_indice_tmp(st, -14); // return back the least significant 14 bits to the bitstream
}

/// `decode_sfe_vector_fx`: decode `length` scale factors `x` of a block, predicted from the
/// previous block `prev_x` when `t` is 1 and from the previous element otherwise.
///
/// ```text
///    f
///    ^
///    |  d a x
///    |    c b
///    |      e  --> t
/// ```
fn decode_sfe_vector(
    h_private_data: &mut IgfscfdecInstance,
    st: &mut DecoderState,
    t: i16,
    prev_x: &[i16],
    x: &mut [i16],
    length: i16,
) {
    let symbols = IGF_SYMBOLS_IN_TABLE + 1;

    for f in 0..length {
        let fu = f as usize;
        if t == 0 {
            if f == 0 {
                // (t == 0) && (f == 0)
                // decode one of the IGF_SYMBOLS_IN_TABLE == 27 alphabet symbols using the new raw AC function
                let cumulative_frequency_table = cumulative_frequencies(h_private_data.cf_se00);
                let res = ari_decode_14bits_s27_ext(
                    st,
                    &mut h_private_data.ac_state,
                    &cumulative_frequency_table,
                );

                let pred = arith_decode_bits(h_private_data, st, 2); // LSBs as 2 bit raw
                x[fu] = add(crate::itu::basic_ops::shl(res, 2), pred);
            } else if sub(f, 1) == 0 {
                // (t == 0) && (f == 1)
                let table = h_private_data.cf_se01;
                let offset = h_private_data.cf_off_se01;
                let res = arith_decode_residual(h_private_data, st, table, offset);
                x[fu] = add(x[0], res); // f - increment is 0, pred = b
            } else {
                // (t == 0) && (f >= 2)
                let prev_offset = (f - 1) as usize;
                let ctx = quant_ctx(sub(x[prev_offset], x[prev_offset - 1])); // Q(b - e)
                                                                              // index1 is (IGF_SYMBOLS_IN_TABLE + 1) * (CTX_OFFSET + ctx)
                let index1 = l_mac0(i32::from(symbols * IGF_CTX_OFFSET), symbols, ctx) as usize;
                // index2 is IGF_CTX_OFFSET + ctx
                let index2 = l_mac0(i32::from(IGF_CTX_OFFSET), 1, ctx) as usize;
                let cf_se02 = h_private_data.cf_se02;
                let table = &cf_se02[index1..];
                let offset = h_private_data.cf_off_se02[index2];
                let res = arith_decode_residual(h_private_data, st, table, offset);
                x[fu] = add(x[prev_offset], res); // pred = b
            }
        } else {
            // t == 1
            if f == 0 {
                // (t == 1) && (f == 0)
                let table = h_private_data.cf_se10;
                let offset = h_private_data.cf_off_se10;
                let res = arith_decode_residual(h_private_data, st, table, offset);
                x[fu] = add(prev_x[fu], res); // pred = a
            } else {
                // (t == 1) && (f >= 1)
                let prev_offset = (f - 1) as usize;
                let mut pred = add(prev_x[fu], x[prev_offset]);
                pred = sub(pred, prev_x[prev_offset]); // pred = a + b - c
                let ctx_f = quant_ctx(sub(prev_x[fu], prev_x[prev_offset])); // Q(a - c)
                let ctx_t = quant_ctx(sub(x[prev_offset], prev_x[prev_offset])); // Q(b - c)
                                                                                 // index1 is (IGF_SYMBOLS_IN_TABLE + 1) * IGF_CTX_COUNT * (IGF_CTX_OFFSET + ctx_t)
                                                                                 //          + (IGF_SYMBOLS_IN_TABLE + 1) * (IGF_CTX_OFFSET + ctx_f)
                let mut index1 = l_mac0(
                    i32::from((symbols * IGF_CTX_COUNT + symbols) * IGF_CTX_OFFSET),
                    symbols * IGF_CTX_COUNT,
                    ctx_t,
                );
                index1 = l_mac0(index1, symbols, ctx_f);
                // index2 is IGF_CTX_COUNT * (IGF_CTX_OFFSET + ctx_t) + (IGF_CTX_OFFSET + ctx_f)
                let mut index2 = l_mac0(
                    i32::from((IGF_CTX_COUNT + 1) * IGF_CTX_OFFSET),
                    IGF_CTX_COUNT,
                    ctx_t,
                );
                index2 = l_mac0(index2, 1, ctx_f);
                let cf_se11 = h_private_data.cf_se11;
                let table = &cf_se11[index1 as usize..];
                let offset = h_private_data.cf_off_se11[index2 as usize];
                let res = arith_decode_residual(h_private_data, st, table, offset);
                x[fu] = add(pred, res);
            }
        }

        if x[fu] < 0 {
            x[fu] = 0;
            st.ber_detect = 1;
        }

        if sub(x[fu], 91) > 0 {
            x[fu] = 91;
            st.ber_detect = 1;
        }
    }
}

/// `IGFSCFDecoderReset`: reset the context memory, so that the next block is decoded as an
/// independent one.
pub fn igf_scf_decoder_reset(h_public_data: &mut IgfscfdecInstance) {
    // reset of coder
    h_public_data.t = 0; // indicate that an independent block follows
                         // we do not need to fill hPublicData->prev with zeros, because when t = 0 no previous information is used
}

/// `IGFSCFDecoderDecode`: decode the `scfCountLongBlock` quantised scale factors of a block into
/// `sfe`; `indep_flag` is 1 for an independent block (no prediction from the previous one).
pub fn igf_scf_decoder_decode(
    h_public_data: &mut IgfscfdecInstance,
    st: &mut DecoderState,
    sfe: &mut [i16],
    indep_flag: i16,
) {
    // insert data
    h_public_data.bits_read = st.next_bit_pos;
    ari_start_decoding_14bits(st, &mut h_public_data.ac_state); // start AC decoding

    // check if coder needs a reset and do it if necessary
    if indep_flag != 0 {
        // reset of coder
        igf_scf_decoder_reset(h_public_data);
    }

    // decoding reads the previous block (`prev`) and the arithmetic decoder state of the same
    // instance; the previous block is only read, so work from a copy of it
    let prev = h_public_data.prev;
    let t = h_public_data.t;
    let length = h_public_data.scf_count_long_block;
    decode_sfe_vector(h_public_data, st, t, &prev, sfe, length);

    arith_decode_flush(st); // finish AC decoding

    // advance history
    copy(
        sfe,
        &mut h_public_data.prev,
        h_public_data.scf_count_long_block,
    );
    h_public_data.t = add(h_public_data.t, 1);

    h_public_data.bits_read = sub(st.next_bit_pos, h_public_data.bits_read);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::IGF_MODE_SWB;

    #[test]
    fn quantised_context_saturates_at_the_offset_with_its_sign() {
        let quantised: Vec<i16> = (-5..=5).map(quant_ctx).collect();
        assert_eq!(quantised, [-3, -3, -3, -2, -1, 0, 1, 2, 3, 3, 3]);
    }

    #[test]
    fn open_selects_the_tables_and_clears_the_block_counter() {
        let mut instance = IgfscfdecInstance::zeroed();
        instance.t = 5;
        igf_scf_decoder_open(&mut instance, 12, 24400, IGF_MODE_SWB, 0);
        assert_eq!(instance.scf_count_long_block, 12);
        assert_eq!(instance.t, 0);
        assert_eq!(instance.cf_se00.len(), 28);
        assert_eq!(instance.cf_off_se02.len(), 7);
        // a bit rate without tables keeps the previous selection
        let before = instance.cf_se01;
        igf_scf_decoder_open(&mut instance, 3, 7200, IGF_MODE_SWB, 0);
        assert_eq!(instance.scf_count_long_block, 3);
        assert_eq!(instance.cf_se01, before);
    }

    #[test]
    fn reset_marks_the_next_block_independent() {
        let mut instance = IgfscfdecInstance::zeroed();
        instance.t = 1;
        igf_scf_decoder_reset(&mut instance);
        assert_eq!(instance.t, 0);
    }

    #[test]
    fn cumulative_frequencies_reinterpret_the_bits() {
        let table = [1i16, -1, 16384];
        let out = cumulative_frequencies(&table);
        assert_eq!(&out[..3], &[1, 65535, 16384]);
        assert_eq!(out[3], 0);
    }
}
