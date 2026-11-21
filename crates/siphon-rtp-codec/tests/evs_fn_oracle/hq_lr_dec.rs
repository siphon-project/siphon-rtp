//! The local functions of `lib_dec/hq_lr_dec_fx.c` against `fn_hq_lr_dec`: band-energy, p2a and
//! fine-gain dequantisation over layouts from `hq2_core_configure_fx`, on random coded bits.

use siphon_rtp_codec::evs::dec::hq_lr_dec::{
    band_energy_dequant, calc_inv, decode_huff_8s, large_symbol_dec, mdct_spectrum_fine_gain_dec,
    p2a_threshold_dequant, small_symbol_dec, small_symbol_dec_tran, spt_shorten_domain_set_dec,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::rom::HESTABLE_FX;

use std::collections::BTreeMap;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn stream(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    let bits = case.i16s("bits");
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
        *slot = bit as u16;
    }
    st.total_num_bits = bits.len() as i16;
    st.next_bit_pos = 0;
    st.codec_mode = 1;
    st
}

fn check_stream(case: &Case, st: &DecoderState) {
    check(
        case,
        "next_bit_pos/ber_detect",
        &vec![st.next_bit_pos, st.ber_detect],
        &vec![case.out_i16("next_bit_pos"), case.out_i16("ber_detect")],
    );
}

#[test]
fn calc_inv_matches_the_reference() {
    let Some(cases) = corpus("hq_lr_dec", "calc_inv") else {
        return;
    };
    for case in &cases {
        let mut exp = -99;
        let r = calc_inv(case.i32("x"), &mut exp);
        check(
            case,
            "r/exp",
            &vec![r, exp],
            &vec![case.out_i16("r"), case.out_i16("exp")],
        );
    }
}

#[test]
fn spt_shorten_domain_set_dec_matches_the_reference() {
    let Some(cases) = corpus("hq_lr_dec", "spt_shorten_domain_set_dec") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut band_start = case.i16s("band_start");
        let mut band_end = case.i16s("band_end");
        let mut band_width = case.i16s("band_width");
        let mut bit_budget = case.i16("bit_budget");
        spt_shorten_domain_set_dec(
            &mut st,
            &case.i16s("p2a_flags"),
            &case.i16s("nbs"),
            &case.i16s("nbe"),
            &case.i16s("nbw"),
            case.i16("bands"),
            &mut band_start,
            &mut band_end,
            &mut band_width,
            &mut bit_budget,
        );
        check(
            case,
            "band_start",
            &band_start,
            &case.out_i16s("band_start"),
        );
        check(case, "band_end", &band_end, &case.out_i16s("band_end"));
        check(
            case,
            "band_width",
            &band_width,
            &case.out_i16s("band_width"),
        );
        check(case, "bit_budget", &bit_budget, &case.out_i16("bit_budget"));
        check_stream(case, &st);
    }
}

fn symbol_case(function: &str) {
    let Some(cases) = corpus("hq_lr_dec", function) else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut qbidx = [-7i16; 32];
        let bands = case.i16("bands");
        let is_transient = case.i16("is_transient");
        let cnt = match function {
            "small_symbol_dec_tran" => {
                small_symbol_dec_tran(&mut st, &mut qbidx, bands, is_transient)
            }
            "small_symbol_dec" => small_symbol_dec(&mut st, &mut qbidx, bands, is_transient),
            _ => large_symbol_dec(&mut st, &mut qbidx, bands),
        };
        check(case, "cnt", &cnt, &case.out_i16("cnt"));
        // entries the decoder did not write are uninitialised in the reference's caller, but the
        // harness pre-fills them like this test does, so all 32 compare
        check(case, "qbidx", &qbidx.to_vec(), &case.out_i16s("qbidx"));
        check_stream(case, &st);
    }
}

#[test]
fn small_symbol_dec_tran_matches_the_reference() {
    symbol_case("small_symbol_dec_tran");
}

#[test]
fn small_symbol_dec_matches_the_reference() {
    symbol_case("small_symbol_dec");
}

#[test]
fn large_symbol_dec_matches_the_reference() {
    symbol_case("large_symbol_dec");
}

#[test]
fn decode_huff_8s_matches_the_reference() {
    let Some(cases) = corpus("hq_lr_dec", "decode_huff_8s") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut rbits = case.i16("rbits");
        let sym = decode_huff_8s(&mut st, &HESTABLE_FX, &mut rbits);
        check(
            case,
            "sym/rbits",
            &vec![sym, rbits],
            &vec![case.out_i16("sym"), case.out_i16("rbits")],
        );
        check_stream(case, &st);
    }
}

#[test]
fn band_energy_dequant_matches_the_reference() {
    let Some(cases) = corpus("hq_lr_dec", "band_energy_dequant") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut energy = [-7i32; 32];
        let cnt = band_energy_dequant(
            &mut st,
            &mut energy,
            case.i16("bands"),
            case.i32("qint"),
            case.i16("eref"),
            case.i16("is_transient"),
        );
        check(case, "cnt", &cnt, &case.out_i16("cnt"));
        check(case, "energy", &energy.to_vec(), &case.out_i32s("energy"));
        check_stream(case, &st);
    }
}

#[test]
fn p2a_threshold_dequant_matches_the_reference() {
    let Some(cases) = corpus("hq_lr_dec", "p2a_threshold_dequant") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut flags = [-7i16; 32];
        let cnt = p2a_threshold_dequant(
            &mut st,
            &mut flags,
            case.i16("bands"),
            case.i16("p2a_bands"),
        );
        check(case, "cnt", &cnt, &case.out_i16("cnt"));
        check(case, "flags", &flags.to_vec(), &case.out_i16s("flags"));
        check_stream(case, &st);
    }
}

#[test]
fn mdct_spectrum_fine_gain_dec_matches_the_reference() {
    let Some(cases) = corpus("hq_lr_dec", "mdct_spectrum_fine_gain_dec") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut y2 = case.i32s("y2");
        mdct_spectrum_fine_gain_dec(
            &mut st,
            &mut y2,
            &case.i16s("band_start"),
            &case.i16s("band_end"),
            &case.i16s("k_sort"),
            case.i16("bands"),
            case.i32("qint"),
            case.i16("ngq"),
            case.i16("gqlevs"),
            case.i16("gqbits"),
        );
        check(case, "y2", &y2, &case.out_i32s("y2"));
        check_stream(case, &st);
    }
}

/// `hq_lr_dec_fx` over four consecutive frames on one decoder (`init_decoder_fx`, then the LR-HQ
/// memories randomised): NB, WB and SWB at the LR-HQ rates, every class, on random bits. The
/// oracle prints the whole state before the first frame ("in.") and, after each frame, the fields
/// that differ from it ("fN."); the whole state is compared after every frame.
#[test]
fn hq_lr_dec_matches_the_reference_over_whole_frames() {
    use siphon_rtp_codec::evs::dec::hq_lr_dec::hq_lr_dec;
    use siphon_rtp_codec::evs::dec::init_dec::init_decoder;

    let Some(cases) = crate::common::corpus_sized("hq_lr_dec", "hq_lr_dec_frames", 150) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = Box::new(DecoderState::zeroed());
        st.output_fs = case.i32("output_fs");
        st.output_frame = case.i16("output_frame");
        init_decoder(&mut st);
        crate::state_dump::load(&mut st, &case.inputs, "in.");
        for f in 0..4 {
            let mode = case.i32s(&format!("f{f}_mode"));
            let bits = case.i16s(&format!("f{f}_bits"));
            for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
                *slot = bit as u16;
            }
            st.bwidth = mode[0] as i16;
            st.core_brate = mode[2];
            st.total_num_bits = bits.len() as i16;
            st.next_bit_pos = mode[4] as i16;
            st.ber_detect = 0;
            let mut yout = vec![-7i32; 960];
            let mut is_transient = -7;
            hq_lr_dec(
                &mut st,
                &mut yout,
                mode[1] as i16,
                mode[3] as i16,
                &mut is_transient,
            );
            let context = format!(
                "case {index} frame {f}: bwidth {}, inner_frame {}, core_brate {}",
                mode[0], mode[1], mode[2]
            );
            check(
                case,
                &format!("{context} yout"),
                &yout,
                &case.i32s(&format!("f{f}_yout")),
            );
            check(
                case,
                &format!("{context} is_transient"),
                &is_transient,
                &case.i16(&format!("f{f}_is_transient")),
            );
            let prefix = format!("f{f}.");
            let mut after: BTreeMap<String, Vec<i64>> = case
                .inputs
                .iter()
                .filter_map(|(key, values)| {
                    key.strip_prefix("in.")
                        .map(|rest| (format!("st.{rest}"), values.clone()))
                })
                .collect();
            for (key, values) in &case.inputs {
                if let Some(rest) = key.strip_prefix(&prefix) {
                    after.insert(format!("st.{rest}"), values.clone());
                }
            }
            crate::state_dump::check(&mut st, &after, "st.", &context);
        }
    }
}

/// One `stream`-mode line of `fn_hq_lr_dec`.
fn parse_stream_line(line: &str) -> Case {
    let side = |text: &str| -> BTreeMap<String, Vec<i64>> {
        text.split_whitespace()
            .map(|pair| {
                let (name, values) = pair.split_once('=').expect("name=values");
                let values = if values.is_empty() {
                    Vec::new()
                } else {
                    values
                        .split(',')
                        .map(|v| v.parse().expect("integer"))
                        .collect()
                };
                (name.to_owned(), values)
            })
            .collect()
    };
    let (inputs, outputs) = line.split_once(" ->").expect("an arrow");
    Case {
        line: format!("{} ...", &line[..line.len().min(200)]),
        inputs: side(inputs),
        outputs: side(outputs),
    }
}

/// `hq_lr_dec_fx` exactly where the reference decoder calls it on the TS 26.444 conformance
/// bitstreams (NB, WB and SWB at the LR-HQ rates, clean and with frame loss): `fn_hq_lr_dec stream`
/// runs the whole reference decoder and prints the whole state before every n-th call, the bits,
/// and after the call its outputs and the state fields it changed. Needs the sequences
/// (`$SIPHON_RTP_EVS_VECTORS` or `reference/evs/testvec`); skips without them, like
/// `bitstream::read_indices_follows_real_bitstreams`.
#[test]
fn hq_lr_dec_matches_the_reference_on_conformance_bitstreams() {
    use siphon_rtp_codec::evs::dec::hq_lr_dec::hq_lr_dec;
    use siphon_rtp_codec::evs::dec::init_dec::init_decoder;

    let vectors = std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        std::path::PathBuf::from,
    );
    let oracle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/evs/build/fn_hq_lr_dec");
    if !vectors.is_dir() || !oracle.is_file() {
        eprintln!("skipping: no conformance bitstreams or fn_hq_lr_dec");
        return;
    }
    let mut checked = 0;
    for (name, rate, every) in [
        ("nb/stv8c_7200_8kHz.COD", 8000, 40),
        ("nb/stv8c_8000_8kHz.b10.COD", 8000, 40),
        ("nb/stv8c_13200_8kHz.COD", 8000, 20),
        ("nb/stv8c_16400_8kHz.COD", 8000, 6),
        ("nb/stv8n1_13200_8kHz.COD", 8000, 1),
        ("wb/stv16c_13200_16kHz.COD", 16000, 15),
        ("wb/stv16c_13200_16kHz.b10.COD", 16000, 15),
        ("wb/stv16c_16400_16kHz.COD", 16000, 2),
        ("wb/stv16n2_16400_16kHz.COD", 16000, 1),
        ("swb/stv32c_13200_32kHz.COD", 32000, 25),
        ("swb/stv32c_13200_32kHz.f06.COD", 32000, 15),
        ("swb/stv32c_16400_32kHz.COD", 32000, 1),
        ("swb/stv32n2_13200_32kHz.COD", 32000, 1),
        ("swb/stv32n2_16400_32kHz.COD", 48000, 1),
    ] {
        let path = vectors.join("testv/bitstreams").join(name);
        if !path.is_file() {
            continue;
        }
        let output = std::process::Command::new(&oracle)
            .arg("stream")
            .arg(&path)
            .arg(rate.to_string())
            .arg(every.to_string())
            .output()
            .expect("run fn_hq_lr_dec");
        assert!(output.status.success(), "fn_hq_lr_dec stream {name} failed");
        let text = String::from_utf8(output.stdout).expect("ASCII");
        for (index, line) in text.lines().enumerate() {
            let case = parse_stream_line(line);
            let mut st = Box::new(DecoderState::zeroed());
            st.output_fs = case.i32("output_fs");
            st.output_frame = case.i16("output_frame");
            init_decoder(&mut st);
            crate::state_dump::load(&mut st, &case.inputs, "in.");
            // ROM pointers a load cannot set (the FD-CNG tables the decoder's last configuration
            // chose): taken as the Rust state has them, unless the call changed them
            let unloadable: BTreeMap<String, Vec<i64>> = crate::state_dump::dump(&mut st)
                .into_iter()
                .filter(|(key, values)| {
                    let input = format!("in.{}", &key[3..]);
                    case.inputs.get(&input) != Some(values)
                })
                .collect();
            for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.inputs["bits"]) {
                *slot = bit as u16;
            }
            let mut yout = case.i32s("yout_in");
            let mut is_transient = -7;
            hq_lr_dec(
                &mut st,
                &mut yout,
                case.i16("inner_frame"),
                case.i16("num_bits"),
                &mut is_transient,
            );
            let context = format!("{name} line {index}");
            check(
                &case,
                &format!("{context} yout"),
                &yout,
                &case.out_i32s("yout"),
            );
            check(
                &case,
                &format!("{context} is_transient"),
                &is_transient,
                &case.out_i16("is_transient"),
            );
            let mut after: BTreeMap<String, Vec<i64>> = case
                .inputs
                .iter()
                .filter_map(|(key, values)| {
                    key.strip_prefix("in.")
                        .map(|rest| (format!("st.{rest}"), values.clone()))
                })
                .collect();
            for (key, values) in &unloadable {
                after.insert(key.clone(), values.clone());
            }
            for (key, values) in &case.outputs {
                if key.starts_with("st.") {
                    after.insert(key.clone(), values.clone());
                }
            }
            crate::state_dump::check(&mut st, &after, "st.", &context);
            checked += 1;
        }
    }
    eprintln!("hq_lr_dec checked on {checked} conformance calls");
}
