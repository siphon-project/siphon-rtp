//! `lib_dec/core_switching_dec_fx.c` against `fn_core_switching_dec`: `bandwidth_switching_detect_fx`,
//! `bw_switching_pre_proc_fx`, `core_switching_pre_dec_fx` and `core_switching_post_dec_fx`.
//!
//! Synthetic cases are decoders built by `init_decoder_fx` whose per-frame state was randomised for
//! every switch direction (ACELP / HQ / AMR-WB IO, MODE1 / MODE2 with a TCX last frame and a lost
//! frame, bandwidth up and down, FD-CNG reconfiguration); the oracle prints the whole state before
//! the call and the fields that changed after it, and the whole state after is compared, so every
//! field the function writes, and every field it must leave alone, is checked. The conformance test
//! replays the calls the reference decoder makes on the switching bitstreams.

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::com::cldfb::configure_cldfb;
use siphon_rtp_codec::evs::com::rom_basop_util::basop_get_tables;
use siphon_rtp_codec::evs::dec::core_switching_dec::{
    bandwidth_switching_detect, bw_switching_pre_proc, core_switching_post_dec,
    core_switching_pre_dec,
};
use siphon_rtp_codec::evs::dec::fd_cng_dec::configure_fd_cng_dec;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::rom::{
    FDCNGSETUP_NB, FDCNGSETUP_SWB1, FDCNGSETUP_SWB2, FDCNGSETUP_WB1, FDCNGSETUP_WB2, FDCNGSETUP_WB3,
};

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_case::state_after;
use crate::state_dump;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// The decoder the case's "before" dump describes; the FD-CNG configured first when the oracle
/// did (the ROM pointers the configuration sets are not in the loadable dump).
fn state_before(case: &Case, fd_cng: Option<(i16, i32, i16)>) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("in.output_Fs_fx");
    st.output_frame = case.i16("in.output_frame_fx");
    init_decoder(&mut st);
    if let Some((bandwidth, bitrate, l_frame)) = fd_cng {
        if let Some(hs) = st.h_fd_cng_dec.as_deref_mut() {
            configure_fd_cng_dec(hs, bandwidth, bitrate, l_frame);
        }
    }
    state_dump::load(&mut st, &case.inputs, "in.");
    st
}

#[test]
fn bandwidth_switching_detect_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("core_switching_dec", "bandwidth_switching_detect", 2000) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = state_before(case, None);
        bandwidth_switching_detect(&mut st);
        let context = format!(
            "case {index}: bwidth {} last {}, bws_cnt {} bws_cnt1 {}",
            case.i16("in.bwidth_fx"),
            case.i16("in.last_bwidth_fx"),
            case.i16("in.bws_cnt_fx"),
            case.i16("in.bws_cnt1_fx")
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}

#[test]
fn bw_switching_pre_proc_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("core_switching_dec", "bw_switching_pre_proc", 1500) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = state_before(case, None);
        let old_syn = case.i16s("old_syn");
        bw_switching_pre_proc(&old_syn, &mut st);
        let context = format!(
            "case {index}: core {} last_core {} L_frame {} extl {} last_extl {}",
            case.i16("in.core_fx"),
            case.i16("in.last_core_fx"),
            case.i16("in.L_frame_fx"),
            case.i16("in.extl_fx"),
            case.i16("in.last_extl_fx")
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}

#[test]
fn core_switching_pre_dec_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("core_switching_dec", "core_switching_pre_dec", 1500) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = state_before(
            case,
            Some((
                case.i16("fd_cng_bandwidth"),
                case.i32("fd_cng_brate"),
                case.i16("fd_cng_l_frame"),
            )),
        );
        let output_frame = case.i16("output_frame");
        core_switching_pre_dec(&mut st, output_frame);
        let context = format!(
            "case {index}: output {} Hz, codec_mode {} -> core {} last_core {}, L_frame {} last {}, \
             core_brate {}, prev_bfi {}",
            st.output_fs,
            case.i16("in.last_codec_mode"),
            case.i16("in.core_fx"),
            case.i16("in.last_core_fx"),
            case.i16("in.L_frame_fx"),
            case.i16("in.last_L_frame_fx"),
            case.i32("in.core_brate_fx"),
            case.i16("in.prev_bfi_fx")
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}

#[test]
fn core_switching_post_dec_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("core_switching_dec", "core_switching_post_dec", 2500) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let fd_cng = (case.i16("in.flag_cna") != 0).then(|| {
            (
                case.i16("cna_bandwidth"),
                case.i32("cna_brate"),
                case.i16("cna_l_frame"),
            )
        });
        let mut st = state_before(case, fd_cng);
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.inputs["bits"]) {
            *slot = bit as u16;
        }
        let mut synth = case.i16s("synth");
        let mut qsynth = case.i16("qsynth");
        let output_frame = case.i16("output_frame");
        core_switching_post_dec(
            &mut st,
            &mut synth,
            output_frame,
            case.i16("core_switching_flag"),
            case.i16("coder_type"),
            &mut qsynth,
        );
        let context = format!(
            "case {index}: output {} Hz, core {} last_core {}, flag {}, bfi {} prev_bfi {}, \
             L_frame {} last {} ori {}, extl {} last {}",
            st.output_fs,
            case.i16("in.core_fx"),
            case.i16("in.last_core_fx"),
            case.i16("core_switching_flag"),
            case.i16("in.bfi_fx"),
            case.i16("in.prev_bfi_fx"),
            case.i16("in.L_frame_fx"),
            case.i16("in.last_L_frame_fx"),
            case.i16("in.last_L_frame_ori_fx"),
            case.i16("in.extl_fx"),
            case.i16("in.last_extl_fx")
        );
        check(
            case,
            &format!("{context}: synth"),
            &synth,
            &case.out_i16s("synth"),
        );
        check(
            case,
            &format!("{context}: qsynth"),
            &qsynth,
            &case.out_i16("qsynth"),
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}

/// The ROM tables the reference decoder's configuration had picked, which a state load cannot
/// restore: the CLDFB rotation vectors of each bank's band count, and the FD-CNG partition tables
/// and overlap windows of its set-up (identified by its partition counts) and FFT length.
fn restore_rom_pointers(st: &mut DecoderState, case: &Case) {
    for bank in [&mut st.cldfb_ana, &mut st.cldfb_bpf, &mut st.cldfb_syn] {
        if let Some(bank) = bank.as_deref_mut() {
            let frame_size = bank.no_col * (bank.no_channels / 2);
            configure_cldfb(bank, bank.no_channels, frame_size);
        }
    }
    // configuring reset the bank's scalar fields: put the dumped ones back
    state_dump::load(st, &case.inputs, "in.");
    let Some(com) = st
        .h_fd_cng_dec
        .as_deref_mut()
        .and_then(|hs| hs.h_fd_cng_com.as_deref_mut())
    else {
        return;
    };
    let setup = [
        &FDCNGSETUP_NB,
        &FDCNGSETUP_WB1,
        &FDCNGSETUP_WB2,
        &FDCNGSETUP_WB3,
        &FDCNGSETUP_SWB1,
        &FDCNGSETUP_SWB2,
    ]
    .into_iter()
    .find(|candidate| {
        candidate.num_partitions == com.fd_cng_setup.num_partitions
            && candidate.num_shaping_partitions == com.fd_cng_setup.num_shaping_partitions
    });
    if let Some(setup) = setup {
        com.fd_cng_setup.sid_partitions = setup.sid_partitions;
        com.fd_cng_setup.shaping_partitions = setup.shaping_partitions;
        com.olap_win_ana = basop_get_tables(com.fftlen / 2).twiddle;
        com.olap_win_syn = basop_get_tables(com.fftlen / 4).twiddle;
    }
}

/// One `stream`-mode line of `fn_core_switching_dec`.
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

/// The four functions exactly where the reference decoder calls them on conformance bitstreams that
/// switch the core, the bandwidth or the codec mode: `fn_core_switching_dec stream` runs the whole
/// reference decoder and prints the whole state before every n-th call (and every call of a frame
/// that switches), and after it the outputs and the state fields the call changed. Skips without
/// the sequences (`$SIPHON_RTP_EVS_VECTORS` or `reference/evs/testvec`).
#[test]
fn core_switching_matches_the_reference_on_conformance_bitstreams() {
    let vectors = std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        std::path::PathBuf::from,
    );
    let oracle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/evs/build/fn_core_switching_dec");
    if !vectors.is_dir() || !oracle.is_file() {
        assert!(
            std::env::var("SIPHON_RTP_REQUIRE_VECTORS").map_or(true, |value| value != "1"),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but the conformance bitstreams or {oracle:?} are missing"
        );
        eprintln!("skipping: no conformance bitstreams or fn_core_switching_dec");
        return;
    }
    let mut checked = [0usize; 4];
    for (name, rate, every) in STREAMS {
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
            .expect("run fn_core_switching_dec");
        assert!(
            output.status.success(),
            "fn_core_switching_dec stream {name} failed"
        );
        let text = String::from_utf8(output.stdout).expect("ASCII");
        for (index, line) in text.lines().enumerate() {
            let case = parse_stream_line(line);
            let which = case.i32("which") as usize;
            let mut st = Box::new(DecoderState::zeroed());
            st.output_fs = case.i32("output_fs");
            st.output_frame = case.i16("output_frame");
            init_decoder(&mut st);
            state_dump::load(&mut st, &case.inputs, "in.");
            restore_rom_pointers(&mut st, &case);
            if let Some(bits) = case.inputs.get("bits") {
                for (slot, &bit) in st.bit_stream.iter_mut().zip(bits) {
                    *slot = bit as u16;
                }
            }
            // ROM pointers a load cannot set and `restore_rom_pointers` does not know (the TCX
            // windows, untouched by MODE1): taken as the Rust state has them, unless the call
            // changed them
            let unloadable: BTreeMap<String, Vec<i64>> = state_dump::dump(&mut st)
                .into_iter()
                .filter(|(key, values)| {
                    let input = format!("in.{}", &key[3..]);
                    case.inputs.get(&input) != Some(values)
                })
                .collect();
            let context = format!("{name} line {index} (function {which})");
            match which {
                0 => bandwidth_switching_detect(&mut st),
                1 => bw_switching_pre_proc(&case.i16s("old_syn"), &mut st),
                2 => core_switching_pre_dec(&mut st, case.i16("output_frame")),
                _ => {
                    let mut synth = case.i16s("synth");
                    let mut qsynth = case.i16("qsynth");
                    core_switching_post_dec(
                        &mut st,
                        &mut synth,
                        case.i16("output_frame"),
                        case.i16("core_switching_flag"),
                        case.i16("coder_type"),
                        &mut qsynth,
                    );
                    check(
                        &case,
                        &format!("{context}: synth"),
                        &synth,
                        &case.out_i16s("synth"),
                    );
                    check(
                        &case,
                        &format!("{context}: qsynth"),
                        &qsynth,
                        &case.out_i16("qsynth"),
                    );
                }
            }
            let mut after = state_after(&case);
            for (key, values) in &unloadable {
                if !case.outputs.contains_key(key) {
                    after.insert(key.clone(), values.clone());
                }
            }
            state_dump::check(&mut st, &after, "st.", &context);
            checked[which] += 1;
        }
    }
    eprintln!("core_switching checked on conformance calls: {checked:?}");
}

/// Sequences that switch cores, bandwidths, rates and codec modes (rate switching 7.2 to 128
/// kbit/s, bandwidth switching, EVS to AMR-WB IO switching, DTX), clean and with frame loss, and
/// the constant-rate 13.2 / 16.4 / 24.4 / 32 kbit/s sequences (ACELP / HQ switching on the content):
/// (file under `testv/bitstreams`, output rate, record every n-th call).
const STREAMS: [(&str, u32, u32); 14] = [
    ("nb/stv8c_sw_72_244_8kHz.COD", 8000, 800),
    ("nb/stv8c_dtx_sw_59_244_8kHz.f06.COD", 8000, 800),
    ("wb/stv16c_sw_72_1280_16kHz.f06.COD", 16000, 800),
    ("wb/stv16c_dtx_sw_59_1280_16kHz.b10.COD", 16000, 800),
    ("wb/stv16c_16400_16kHz.COD", 16000, 500),
    ("swb/stv32c_sw_96_1280_32kHz.f06.COD", 32000, 800),
    ("swb/stv32c_bw_59_1280_32kHz.COD", 32000, 800),
    ("swb/stv32c_bw_59_1280_evs_amrwb_32kHz.COD", 32000, 800),
    (
        "swb/stv32c_dtx_bw_59_1280_evs_amrwb_32kHz.f06.COD",
        32000,
        800,
    ),
    ("swb/stv32c_13200_32kHz.f06.COD", 32000, 500),
    ("fb/stv48c_bw_59_1280_48kHz.COD", 48000, 800),
    ("fb/stv48c_bw_59_1280_evs_amrwb_48kHz.f06.COD", 48000, 800),
    ("fb/stv48c_sw_164_1280_48kHz.COD", 48000, 800),
    ("fb/stv48c_32000_48kHz.f06.COD", 48000, 500),
];
