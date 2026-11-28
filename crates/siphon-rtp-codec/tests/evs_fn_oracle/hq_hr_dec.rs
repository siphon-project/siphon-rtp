//! `hq_hr_dec_fx` (`lib_dec/hq_hr_dec_fx.c`) against `fn_hq_hr_dec`: the whole decoder state and
//! every output over consecutive frames on one decoder (random bits at 24.4 to 128 kbit/s, all
//! HQ classes), and on calls captured from the reference decoder running real conformance
//! bitstreams.

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::dec::hq_hr_dec::hq_hr_dec;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn hq_hr_dec_matches_the_reference_over_whole_frames() {
    let Some(cases) = crate::common::corpus_sized("hq_hr_dec", "hq_hr_dec_frames", 150) else {
        return;
    };
    let mut classes = [0usize; 6];
    let mut frames = 0usize;
    for (index, case) in cases.iter().enumerate() {
        let mut st = Box::new(DecoderState::zeroed());
        st.output_fs = case.i32("output_fs");
        st.output_frame = case.i16("output_frame");
        init_decoder(&mut st);
        crate::state_dump::load(&mut st, &case.inputs, "in.");
        for f in 0..4 {
            if case.inputs.contains_key(&format!("f{f}_skip")) {
                break;
            }
            let mode = case.i32s(&format!("f{f}_mode"));
            let bits = case.i16s(&format!("f{f}_bits"));
            for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
                *slot = bit as u16;
            }
            st.core_brate = mode[0];
            st.core = 3; // HQ_CORE
            st.total_num_bits = bits.len() as i16;
            st.next_bit_pos = mode[3] as i16;
            st.ber_detect = 0;
            let mut audio = vec![0i32; 960];
            let mut ynrm = [39i16; 44];
            let mut fenv = [0i16; 17];
            let (mut is_transient, mut hqswb_clas) = (-7i16, -7i16);
            hq_hr_dec(
                &mut st,
                &mut audio,
                mode[1] as i16,
                mode[2] as i16,
                &mut ynrm,
                &mut is_transient,
                &mut hqswb_clas,
                &mut fenv,
            );
            let context = format!(
                "case {index} frame {f}: length {}, core_brate {}, class {hqswb_clas}",
                mode[1], mode[0]
            );
            check(
                case,
                &format!("{context} audio"),
                &audio,
                &case.i32s(&format!("f{f}_audio")),
            );
            check(
                case,
                &format!("{context} ynrm"),
                &ynrm.to_vec(),
                &case.i16s(&format!("f{f}_ynrm")),
            );
            check(
                case,
                &format!("{context} is_transient"),
                &is_transient,
                &case.i16(&format!("f{f}_is_transient")),
            );
            check(
                case,
                &format!("{context} hqswb_clas"),
                &hqswb_clas,
                &case.i16(&format!("f{f}_hqswb_clas")),
            );
            check(
                case,
                &format!("{context} swb_fenv"),
                &fenv.to_vec(),
                &case.i16s(&format!("f{f}_fenv")),
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
            classes[(hqswb_clas as usize).min(5)] += 1;
            frames += 1;
        }
    }
    assert!(
        classes.iter().all(|&count| count > 5),
        "every HQ class must be reached: {classes:?} over {frames} frames"
    );
}

/// One `stream`-mode line of `fn_hq_hr_dec`.
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

/// `hq_hr_dec_fx` exactly where the reference decoder calls it on the TS 26.444 conformance
/// bitstreams at 24.4 to 128 kbit/s (clean and with frame loss): `fn_hq_hr_dec stream` runs the
/// whole reference decoder and prints the state before each sampled call, the bits and, after the
/// call, the outputs and the state fields it changed. Skips without the sequences
/// (`$SIPHON_RTP_EVS_VECTORS`), fails with `SIPHON_RTP_REQUIRE_VECTORS=1`.
#[test]
fn hq_hr_dec_matches_the_reference_on_conformance_bitstreams() {
    let vectors = std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        std::path::PathBuf::from,
    );
    let oracle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/evs/build/fn_hq_hr_dec");
    if !vectors.is_dir() || !oracle.is_file() {
        assert!(
            std::env::var_os("SIPHON_RTP_REQUIRE_VECTORS").is_none(),
            "no conformance bitstreams or fn_hq_hr_dec"
        );
        eprintln!("skipping: no conformance bitstreams or fn_hq_hr_dec");
        return;
    }
    let mut checked = 0;
    let mut classes = [0usize; 6];
    for (name, rate, every) in [
        ("swb/stv32c_24400_32kHz.COD", 32000, 6),
        ("swb/stv32c_32000_32kHz.COD", 32000, 6),
        ("swb/stv32c_32000_32kHz.f06.COD", 32000, 6),
        ("swb/stv32c_48000_32kHz.COD", 32000, 6),
        ("swb/stv32c_64000_32kHz.COD", 32000, 10),
        ("swb/stv32c_96000_32kHz.COD", 32000, 10),
        ("swb/stv32n1_24400_32kHz.COD", 32000, 4),
        ("swb/stv32n1_32000_32kHz.COD", 32000, 4),
        ("swb/stv32n1_128000_32kHz.COD", 32000, 10),
        ("wb/stv16c_32000_16kHz.COD", 16000, 4),
        ("wb/stv16n1_32000_16kHz.COD", 16000, 3),
        ("wb/stv16c_64000_16kHz.COD", 16000, 10),
        ("fb/stv48c_24400_48kHz.COD", 48000, 6),
        ("fb/stv48c_24400_48kHz.f06.COD", 48000, 6),
        ("fb/stv48c_32000_48kHz.COD", 48000, 6),
        ("fb/stv48c_32000_48kHz.b10.COD", 48000, 6),
        ("fb/stv48c_48000_48kHz.COD", 48000, 8),
        ("fb/stv48c_64000_48kHz.COD", 48000, 10),
        ("fb/stv48c_96000_48kHz.COD", 48000, 10),
        ("fb/stv48c_128000_48kHz.COD", 48000, 12),
        ("fb/stv48n1_24400_48kHz.COD", 48000, 4),
        ("fb/stv48n1_32000_48kHz.COD", 48000, 4),
        ("fb/stv48n1_32000_48kHz.f06.COD", 48000, 4),
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
            .expect("run fn_hq_hr_dec");
        assert!(output.status.success(), "fn_hq_hr_dec stream {name} failed");
        let text = String::from_utf8(output.stdout).expect("ASCII");
        for (index, line) in text.lines().enumerate() {
            let case = parse_stream_line(line);
            let mut st = Box::new(DecoderState::zeroed());
            st.output_fs = case.i32("output_fs");
            st.output_frame = case.i16("output_frame");
            init_decoder(&mut st);
            crate::state_dump::load(&mut st, &case.inputs, "in.");
            // ROM pointers a load cannot set: taken as the Rust state has them, unless changed
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
            let mut audio = case.i32s("audio_in");
            let mut ynrm = case.i16s("ynrm_in");
            let mut fenv = case.i16s("fenv_in");
            let (mut is_transient, mut hqswb_clas) = (-7i16, -7i16);
            hq_hr_dec(
                &mut st,
                &mut audio,
                case.i16("length"),
                case.i16("num_bits"),
                &mut ynrm,
                &mut is_transient,
                &mut hqswb_clas,
                &mut fenv,
            );
            let context = format!("{name} line {index}");
            check(
                &case,
                &format!("{context} audio"),
                &audio,
                &case.out_i32s("audio"),
            );
            check(
                &case,
                &format!("{context} ynrm"),
                &ynrm,
                &case.out_i16s("ynrm"),
            );
            check(
                &case,
                &format!("{context} is_transient"),
                &is_transient,
                &case.out_i16("is_transient"),
            );
            check(
                &case,
                &format!("{context} hqswb_clas"),
                &hqswb_clas,
                &case.out_i16("hqswb_clas"),
            );
            check(
                &case,
                &format!("{context} fenv"),
                &fenv,
                &case.out_i16s("fenv"),
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
            classes[(hqswb_clas as usize).min(5)] += 1;
            checked += 1;
        }
    }
    eprintln!("hq_hr_dec checked on {checked} conformance calls, classes {classes:?}");
    assert!(checked > 0, "no conformance call reached hq_hr_dec_fx");
}
