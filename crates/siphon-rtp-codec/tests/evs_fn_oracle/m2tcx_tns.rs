//! TNS (`lib_com/tns_base.c`, `lib_dec/tns_base_dec.c`) against `fn_m2tcx_tns`: applying the
//! filters, the ITF filter used with IGF, and reading and decoding the TNS parameters of a frame
//! for all three parameter maps. The static helpers and the entropy-coding callbacks are proven
//! through these.

use siphon_rtp_codec::evs::com::tns_base::{
    apply_tns_filter, init_tns_configuration, itf_apply, itf_detect, reset_tns_data, STnsData,
};
use siphon_rtp_codec::evs::dec::state::{DecoderState, STnsConfig};
use siphon_rtp_codec::evs::dec::tns_base_dec::{decode_tns_data, read_tns_data};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// The oracle's `put_tns_data`: filter count, then per filter the order, the prediction gain and
/// the eight coefficient indices.
fn check_tns_data(case: &Case, data: &STnsData, outputs: bool) {
    let read = |name: &str| {
        if outputs {
            case.out_i16s(name)
        } else {
            case.i16s(name)
        }
    };
    let n_filters = if outputs {
        case.out_i16("n_filters")
    } else {
        case.i16("n_filters")
    };
    check(case, "n_filters", &data.n_filters, &n_filters);
    for (index, filter) in data.filter.iter().enumerate() {
        let mut flat = vec![filter.order, filter.prediction_gain];
        flat.extend_from_slice(&filter.coef_index);
        check(case, "filter", &flat, &read(&format!("filter{index}")));
    }
}

fn tns_data_from(case: &Case) -> STnsData {
    let mut data = STnsData::zeroed();
    data.n_filters = case.i16("n_filters");
    for (index, filter) in data.filter.iter_mut().enumerate() {
        let flat = case.i16s(&format!("filter{index}"));
        filter.order = flat[0];
        filter.prediction_gain = flat[1];
        filter.coef_index.copy_from_slice(&flat[2..]);
    }
    data
}

#[test]
fn apply_tns_filter_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_tns", "ApplyTnsFilter") else {
        return;
    };
    for case in &cases {
        let mut config = STnsConfig::zeroed();
        init_tns_configuration(
            case.i32("sr"),
            case.i16("frame_length"),
            &mut config,
            case.i16("igf"),
            case.i32("brate"),
        )
        .unwrap();
        check(
            case,
            "n_max_filters",
            &config.n_max_filters,
            &case.i16("n_max_filters"),
        );
        check(
            case,
            "borders",
            &config.i_filter_borders.to_vec(),
            &case.i16s("borders"),
        );
        let data = tns_data_from(case);
        let mut spectrum = case.i32s("spectrum");
        let result = apply_tns_filter(&config, &data, &mut spectrum, case.i16("analysis") as i8);
        check(case, "result", &result, &case.out_i16("result"));
        check(case, "spectrum", &spectrum, &case.out_i32s("spectrum"));
    }
}

#[test]
fn itf_detect_and_apply_match_the_reference() {
    let Some(cases) = corpus("m2tcx_tns", "ITF") else {
        return;
    };
    for case in &cases {
        let x = case.i32s("x");
        let (start_line, stop_line) = (case.i16("start_line"), case.i16("stop_line"));
        let mut a = [0x5555i16; 17];
        let (mut q_a, mut prediction_gain, mut curr_order) = (0x5555, 0, 0);
        let result = itf_detect(
            &x[164..],
            start_line,
            stop_line,
            case.i16("max_order"),
            &mut a,
            &mut q_a,
            &mut prediction_gain,
            &mut curr_order,
            case.i16("q"),
        );
        let mut x_apply = x.clone();
        itf_apply(&mut x_apply, start_line, stop_line, &a, q_a, curr_order);
        check(case, "result", &result, &case.out_i16("result"));
        check(case, "a", &a.to_vec(), &case.out_i16s("a"));
        check(case, "q_a", &q_a, &case.out_i16("q_a"));
        check(
            case,
            "prediction_gain",
            &prediction_gain,
            &case.out_i16("prediction_gain"),
        );
        check(case, "curr_order", &curr_order, &case.out_i16("curr_order"));
        check(case, "x_apply", &x_apply, &case.out_i32s("x_apply"));
    }
}

#[test]
fn read_and_decode_tns_data_match_the_reference() {
    let Some(cases) = corpus("m2tcx_tns", "read_decode") else {
        return;
    };
    for case in &cases {
        let mut config = STnsConfig::zeroed();
        config.max_order = 8;
        match case.i16("map") {
            0 => (config.n_max_filters, config.i_filter_borders[0]) = (2, 640),
            1 => (config.n_max_filters, config.i_filter_borders[0]) = (2, 320),
            _ => (config.n_max_filters, config.i_filter_borders[0]) = (1, 320),
        }
        let mut st = Box::new(DecoderState::zeroed());
        for (slot, bit) in st.bit_stream.iter_mut().zip(case.i16s("bits")) {
            *slot = bit as u16;
        }
        // the oracle prints the first 160 bits; the rest of the buffer is zero in Rust and
        // random in C, so no read may reach past them (total_bits <= 120 and start < 20)
        st.total_num_bits = case.i16("total_bits");
        st.next_bit_pos = case.i16("start");
        let mut stream = [0x5555i16; 40];
        let (mut n_bits, mut n_size) = (0x1111, 0);
        let result = read_tns_data(&config, &mut st, &mut n_bits, &mut stream, &mut n_size);
        check(case, "read_result", &result, &case.out_i16("read_result"));
        check(case, "n_bits", &n_bits, &case.out_i16("n_bits"));
        check(case, "n_size", &n_size, &case.out_i16("n_size"));
        check(
            case,
            "next_bit_pos",
            &st.next_bit_pos,
            &case.out_i16("next_bit_pos"),
        );
        check(
            case,
            "ber_detect",
            &st.ber_detect,
            &case.out_i16("ber_detect"),
        );
        check(case, "stream", &stream.to_vec(), &case.out_i16s("stream"));

        let mut data = STnsData::zeroed();
        let mut n_size_decode = 0;
        let used = decode_tns_data(&config, &stream, &mut n_size_decode, &mut data);
        check(case, "decode_result", &used, &case.out_i16("decode_result"));
        check(
            case,
            "n_size_decode",
            &n_size_decode,
            &case.out_i16("n_size_decode"),
        );
        check_tns_data(case, &data, true);
    }
    let _ = reset_tns_data;
}
