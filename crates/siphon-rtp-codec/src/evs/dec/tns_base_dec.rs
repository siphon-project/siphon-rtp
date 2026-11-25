//! Reading and decoding the TNS parameters of a TCX frame (TS 26.442 `lib_dec/tns_base_dec.c`;
//! TS 26.445 §6.2.2.1.3 and §5.3.3.2.2).
//!
//! The reference drives both through a generic, table-driven walker (`ReadFromBitstream` /
//! `SetParameters` over the `ParamsBitMap` tables `tnsEnabledSWBTCX20BitMap`,
//! `tnsEnabledSWBTCX10BitMap` and `tnsEnabledWBTCX20BitMap`, whose entries are function
//! pointers). The only parameter tables the decoder ever walks are these three, and their shape
//! is fixed: an enable bit, for the SWB / FB maps a filter count (one raw bit, plus one), then per
//! filter an order (prefix coded) and per coefficient an index (prefix coded). The walks are
//! written out for that shape here, calling the map's own callbacks (`DecodeTnsFilterOrder*`,
//! `Decode*TnsFilterCoeff`, `SetNumOfTnsFilters`, `SetTnsFilterOrder`, `SetTnsFilterCoeff`,
//! `SetTnsEnabledSingleFilter`) in the walker's order, and keep the walker's bookkeeping (`*pnSize`
//! counts one parameter per map entry visited).

use crate::evs::cnst::{TNS_MAX_FILTER_ORDER, TNS_MAX_NUM_OF_FILTERS};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::tns_base::{
    decode_swbtcx10_tns_filter_coeff, decode_swbtcx20_tns_filter_coeff, decode_tns_filter_order,
    decode_tns_filter_order_swbtcx10, decode_tns_filter_order_swbtcx20,
    decode_wbtcx20_tns_filter_coeff, reset_tns_data, set_num_of_tns_filters,
    set_tns_enabled_single_filter, set_tns_filter_coeff, set_tns_filter_order, STnsData,
    TNS_NO_ERROR,
};
use crate::evs::dec::state::{DecoderState, STnsConfig};
use crate::itu::basic_ops::{add, sub};
use crate::itu::stl2009::i_mult;

/// Which of the three `ParamsBitMap` trees a configuration selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TnsMap {
    /// `tnsEnabledSWBTCX20BitMap`: several filters, 20 ms frame.
    Swb20,
    /// `tnsEnabledSWBTCX10BitMap`: several filters, 10 ms frames.
    Swb10,
    /// `tnsEnabledWBTCX20BitMap`: one filter.
    Wb20,
}

impl TnsMap {
    fn of(tns_config: &STnsConfig) -> Self {
        if sub(tns_config.n_max_filters, 1) > 0 {
            if sub(tns_config.i_filter_borders[0], 512) < 0 {
                Self::Swb10
            } else {
                Self::Swb20
            }
        } else {
            Self::Wb20
        }
    }

    /// The map's `DecodeValue` for the filter order.
    fn decode_order(self, st: &mut DecoderState, index: i16, value: &mut i16) {
        match self {
            Self::Swb20 => decode_tns_filter_order_swbtcx20(st, index, value),
            Self::Swb10 => decode_tns_filter_order_swbtcx10(st, index, value),
            Self::Wb20 => decode_tns_filter_order(st, index, value),
        };
    }

    /// The map's `DecodeValue` for coefficient `index`.
    fn decode_coeff(self, st: &mut DecoderState, index: i16, value: &mut i16) {
        match self {
            Self::Swb20 => decode_swbtcx20_tns_filter_coeff(st, index, value),
            Self::Swb10 => decode_swbtcx10_tns_filter_coeff(st, index, value),
            Self::Wb20 => decode_wbtcx20_tns_filter_coeff(st, index, value),
        };
    }

    /// Whether the map has the filter-count level between the enable bit and the filters.
    fn has_filter_count(self) -> bool {
        self != Self::Wb20
    }
}

/// `ReadFromBitstream` of the coefficient map (`tns*FilterCoeffBitMap`) for `n_array_length`
/// coefficients: each is decoded by the map's table and stored in the stream.
fn read_coefficients(
    map: TnsMap,
    st: &mut DecoderState,
    n_array_length: i16,
    stream: &mut [i16],
    position: &mut usize,
    pn_size: &mut i16,
) {
    for index in 0..n_array_length {
        let mut value = 0;
        map.decode_coeff(st, index, &mut value);
        stream[*position] = value;
        *position += 1;
    }
    *pn_size = add(*pn_size, i_mult(1, n_array_length));
}

/// `ReadFromBitstream` of the filter map (`tns*FilterBitMap`) for `n_array_length` filters: the
/// order of each, then that many coefficients.
fn read_filters(
    map: TnsMap,
    st: &mut DecoderState,
    n_array_length: i16,
    stream: &mut [i16],
    position: &mut usize,
    pn_size: &mut i16,
) {
    for index in 0..n_array_length {
        let mut value = 0;
        map.decode_order(st, index, &mut value);
        stream[*position] = value;
        *position += 1;

        if value > 0 {
            read_coefficients(map, st, value, stream, position, pn_size);
        }
    }
    *pn_size = add(*pn_size, i_mult(1, n_array_length));
}

/// `ReadTnsData`: read the TNS parameters of a frame from the bitstream into `stream` (the
/// frame's parameter vector from the TNS entry on), counting the parameters in `*pn_size` and the
/// bits read in `*pn_bits`. Always `TNS_NO_ERROR`.
pub fn read_tns_data(
    tns_config: &STnsConfig,
    st: &mut DecoderState,
    pn_bits: &mut i16,
    stream: &mut [i16],
    pn_size: &mut i16,
) -> i16 {
    let start_bit_pos = st.next_bit_pos;
    let map = TnsMap::of(tns_config);
    let mut position = 0usize;

    // the enable bit (`fZeroAllowed`: no offset)
    let enabled = get_next_indice(st, 1) as i16;
    stream[position] = enabled;
    position += 1;

    if enabled > 0 {
        if map.has_filter_count() {
            // the filter count: one raw bit, plus one (`fZeroAllowed == 0`, no `DecodeValue`)
            let raw = get_next_indice(st, 1) as i16;
            stream[position] = raw;
            position += 1;
            let n_filters = add(raw, 1);
            read_filters(map, st, n_filters, stream, &mut position, pn_size);
            *pn_size = add(*pn_size, i_mult(1, enabled));
        } else {
            read_filters(map, st, enabled, stream, &mut position, pn_size);
        }
    }
    *pn_size = add(*pn_size, i_mult(1, 1));

    *pn_bits = sub(st.next_bit_pos, start_bit_pos);

    TNS_NO_ERROR
}

/// `SetParameters` of the coefficient map: `n_array_length` coefficient indices from the stream.
fn set_coefficients(
    coef_index: &mut [i16],
    n_array_length: i16,
    stream: &[i16],
    position: &mut usize,
    pn_size: &mut i16,
) {
    // a filter has at most TNS_MAX_FILTER_ORDER coefficients; read_tns_data never writes more
    for index in 0..n_array_length.min(TNS_MAX_FILTER_ORDER) {
        let value = stream[*position];
        *position += 1;
        set_tns_filter_coeff(coef_index, index, value);
        *pn_size = add(*pn_size, 1);
    }
}

/// `SetParameters` of the filter map: `n_array_length` filters, each an order and that many
/// coefficients, from the stream.
fn set_filters(
    tns_data: &mut STnsData,
    n_array_length: i16,
    stream: &[i16],
    position: &mut usize,
    pn_size: &mut i16,
) {
    // a frame has at most TNS_MAX_NUM_OF_FILTERS filters; read_tns_data never writes more
    for index in 0..n_array_length.min(TNS_MAX_NUM_OF_FILTERS) {
        let value = stream[*position];
        *position += 1;
        set_tns_filter_order(&mut tns_data.filter, index, value);
        *pn_size = add(*pn_size, 1);

        if value > 0 {
            set_coefficients(
                &mut tns_data.filter[index as usize].coef_index,
                value,
                stream,
                position,
                pn_size,
            );
        }
    }
}

/// `DecodeTnsData`: turn the parameter vector `stream` that [`read_tns_data`] wrote into the TNS
/// filters `tns_data`, counting the parameters used in `*pn_size`. Returns whether any filter is
/// active (`TRUE` / `FALSE`).
pub fn decode_tns_data(
    tns_config: &STnsConfig,
    stream: &[i16],
    pn_size: &mut i16,
    tns_data: &mut STnsData,
) -> i16 {
    reset_tns_data(tns_data);
    let map = TnsMap::of(tns_config);
    let mut position = 0usize;

    // the enable bit: `SetTnsEnabled` stores nothing
    let enabled = stream[position];
    position += 1;
    *pn_size = add(*pn_size, 1);

    if enabled > 0 {
        if map.has_filter_count() {
            // the filter count (`fZeroAllowed == 0`: the stream holds it minus one)
            let n_filters = add(1, stream[position]);
            position += 1;
            set_num_of_tns_filters(tns_data, n_filters);
            *pn_size = add(*pn_size, 1);
            set_filters(tns_data, n_filters, stream, &mut position, pn_size);
        } else {
            // the single filter: the enable flag is its count
            set_tns_enabled_single_filter(tns_data, enabled);
            set_filters(tns_data, enabled, stream, &mut position, pn_size);
        }
    }

    i16::from(tns_data.n_filters > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_frame_decodes_to_no_filters() {
        let mut config = STnsConfig::zeroed();
        config.n_max_filters = 1;
        let mut data = STnsData::zeroed();
        data.n_filters = 2;
        let mut size = 0;
        assert_eq!(decode_tns_data(&config, &[0], &mut size, &mut data), 0);
        assert_eq!((data.n_filters, size), (0, 1));
    }

    #[test]
    fn the_map_follows_the_configuration() {
        let mut config = STnsConfig::zeroed();
        config.n_max_filters = 2;
        config.i_filter_borders[0] = 320;
        assert_eq!(TnsMap::of(&config), TnsMap::Swb10);
        config.i_filter_borders[0] = 640;
        assert_eq!(TnsMap::of(&config), TnsMap::Swb20);
        config.n_max_filters = 1;
        assert_eq!(TnsMap::of(&config), TnsMap::Wb20);
    }
}
