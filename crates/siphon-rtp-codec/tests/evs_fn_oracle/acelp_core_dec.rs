//! `lib_dec/acelp_core_dec_fx.c` against `fn_acelp_core_dec`, on the calls the reference decoder
//! makes over the TS 26.444 conformance bitstreams.
//!
//! `fn_acelp_core_dec stream FILE FS EVERY` runs the whole reference decoder over a bitstream and
//! prints, for the first calls of every distinct frame situation (bad frame, SID / no-data, NELP,
//! PPP, each coder type, frame length, bandwidth, after a loss or a SID, ...) and then every
//! EVERY-th call, the whole decoder state before the call, the bits and the caller's buffers, and
//! after it the outputs and the state fields it changed. Each call is replayed on a Rust decoder
//! loaded with that state; the outputs and the whole state afterwards must match. Needs the
//! sequences (`$SIPHON_RTP_EVS_VECTORS` or `reference/evs/testvec`); skips without them.

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::dec::acelp_core_dec::acelp_core_dec;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{mismatch, Case};

fn parse_line(line: &str) -> Case {
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

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// The FD-CNG window tables are ROM pointers a load cannot set: the decoder chose them when it
/// configured the FD-CNG (`configureFdCngDec`, with the frame length of that time). Configure the
/// loaded decoder from its own bandwidth and bit rate with the frame length that gives the loaded
/// FFT length, then load the state again over what the configuration rewrote.
fn restore_fd_cng_tables(st: &mut DecoderState, case: &Case) {
    use siphon_rtp_codec::evs::dec::fd_cng_dec::configure_fd_cng_dec;
    let Some(fd) = st.h_fd_cng_dec.as_mut() else {
        return;
    };
    let Some((bandwidth, bitrate, fftlen)) = fd
        .h_fd_cng_com
        .as_ref()
        .map(|com| (com.cng_bandwidth, com.cng_bitrate, com.fftlen))
    else {
        return;
    };
    for l_frame in [256, 320] {
        configure_fd_cng_dec(fd, bandwidth, bitrate, l_frame);
        if fd
            .h_fd_cng_com
            .as_ref()
            .is_some_and(|com| com.fftlen == fftlen)
        {
            break;
        }
    }
    crate::state_dump::load(st, &case.inputs, "in.");
}

/// The prototype filter and rotation vectors of the CLDFB banks are ROM pointers a load cannot set:
/// they follow the band count the bank was last resampled to. Configure each loaded bank for its
/// own band count (which sets them), then load the state again over the rest of what that rewrote.
fn restore_cldfb_tables(st: &mut DecoderState, case: &Case) {
    use siphon_rtp_codec::evs::com::cldfb::configure_cldfb;
    for bank in [&mut st.cldfb_ana, &mut st.cldfb_bpf, &mut st.cldfb_syn]
        .into_iter()
        .flatten()
    {
        let (channels, columns) = (bank.no_channels, bank.no_col);
        configure_cldfb(bank, channels, columns * (channels / 2));
    }
    crate::state_dump::load(st, &case.inputs, "in.");
}

/// Replay one recorded call; returns a short description of its situation for the statistics.
fn replay(name: &str, index: usize, case: &Case) -> String {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);
    crate::state_dump::load(&mut st, &case.inputs, "in.");
    restore_fd_cng_tables(&mut st, case);
    restore_cldfb_tables(&mut st, case);
    // ROM pointers a load cannot set (the FD-CNG tables the decoder's last configuration chose):
    // taken as the Rust state has them, unless the call changed them
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
    let situation = format!(
        "bfi {} brate {} coder {} nelp {} ppp {} l_frame {}",
        st.bfi,
        st.core_brate,
        case.i16("coder_type"),
        st.nelp_mode_dec,
        st.ppp_mode_dec,
        st.l_frame
    );

    let output_frame = st.output_frame as usize;
    let mut synth_out = vec![0i16; 960];
    let mut bwe_exc_extended = case.i32s("bwe_in");
    let mut voice_factors = case.i16s("voice_in");
    let mut old_syn_12k8_16k = case.i16s("syn_in");
    let mut pitch_buf = case.i16s("pitch_in");
    let mut unbits = case.i16("unbits_in");
    let mut sid_bw = case.i16("sid_in");
    acelp_core_dec(
        &mut st,
        &mut synth_out,
        &mut bwe_exc_extended,
        &mut voice_factors,
        &mut old_syn_12k8_16k,
        case.i16("coder_type"),
        case.i16("sharp_flag"),
        &mut pitch_buf,
        &mut unbits,
        &mut sid_bw,
    );

    let context = format!("{name} call {index} ({situation})");
    check(
        case,
        &format!("{context} synth_out"),
        &synth_out[..output_frame].to_vec(),
        &case.out_i16s("synth_out"),
    );
    check(
        case,
        &format!("{context} bwe_exc_extended"),
        &bwe_exc_extended,
        &case.out_i32s("bwe_out"),
    );
    check(
        case,
        &format!("{context} voice_factors"),
        &voice_factors,
        &case.out_i16s("voice_out"),
    );
    check(
        case,
        &format!("{context} old_syn_12k8_16k"),
        &old_syn_12k8_16k,
        &case.out_i16s("syn_out"),
    );
    check(
        case,
        &format!("{context} pitch_buf"),
        &pitch_buf,
        &case.out_i16s("pitch_out"),
    );
    check(
        case,
        &format!("{context} unbits"),
        &unbits,
        &case.out_i16("unbits_out"),
    );
    check(
        case,
        &format!("{context} sid_bw"),
        &sid_bw,
        &case.out_i16("sid_out"),
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
    situation
}

#[test]
fn acelp_core_dec_matches_the_reference_on_conformance_bitstreams() {
    let vectors = std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        std::path::PathBuf::from,
    );
    let oracle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/evs/build/fn_acelp_core_dec");
    if !vectors.is_dir() || !oracle.is_file() {
        eprintln!("skipping: no conformance bitstreams or fn_acelp_core_dec");
        return;
    }
    let only = std::env::var("ACELP_CORE_DEC_ONLY").ok();
    let mut checked = 0;
    let mut situations: BTreeMap<String, usize> = BTreeMap::new();
    for (name, rate, every) in SEQUENCES {
        if only
            .as_deref()
            .is_some_and(|only| !only.split(',').any(|part| name.contains(part)))
        {
            continue;
        }
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
            .expect("run fn_acelp_core_dec");
        assert!(
            output.status.success(),
            "fn_acelp_core_dec stream {name} failed"
        );
        eprintln!("{name}");
        let text = String::from_utf8(output.stdout).expect("ASCII");
        for (index, line) in text.lines().enumerate() {
            let case = parse_line(line);
            let situation = replay(name, index, &case);
            *situations.entry(situation).or_default() += 1;
            checked += 1;
        }
    }
    for (situation, count) in &situations {
        eprintln!("  {count:4} calls: {situation}");
    }
    eprintln!("acelp_core_dec checked on {checked} conformance calls");
}

/// The sequences (name under `testv/bitstreams`, output rate, sampling interval): the 5.9 kbit/s
/// SC-VBR ones (NELP, PPP), the 7.2 / 8.0 / 13.2 kbit/s ACELP ones clean, with frame loss and with
/// DTX, the higher ACELP rates at WB / SWB / FB output and the bit-rate / bandwidth switching ones.
const SEQUENCES: &[(&str, u32, u32)] = &[
    ("nb/stv8c_7200_8kHz.COD", 8000, 60),
    ("nb/stv8c_7200_8kHz.f06.COD", 8000, 60),
    ("nb/stv8c_8000_8kHz.COD", 8000, 60),
    ("nb/stv8c_8000_8kHz.b10.COD", 8000, 60),
    ("nb/stv8c_dtx_7200_8kHz.COD", 8000, 60),
    ("nb/stv8c_dtx_8000_8kHz.f06.COD", 8000, 60),
    ("nb/stv8c_13200_8kHz.COD", 8000, 80),
    ("nb/stv8c_13200_8kHz.f06.COD", 8000, 80),
    ("nb/stv8c_dtx_13200_8kHz.COD", 8000, 80),
    ("nb/stv8c_dtx_13200_8kHz.f06.COD", 8000, 80),
    ("nb/stv8n1_13200_8kHz.COD", 8000, 80),
    ("nb/stv8c_9600_8kHz.COD", 8000, 100),
    ("nb/stv8c_dtx_5900_8kHz.COD", 8000, 12),
    ("nb/stv8c_dtx_5900_8kHz.b10.COD", 8000, 12),
    ("nb/stv8c_dtx_5900_8kHz.f06.COD", 8000, 12),
    ("nb/stv8c_sw_72_244_8kHz.COD", 8000, 100),
    ("nb/stv8c_dtx_sw_59_244_8kHz.f06.COD", 8000, 60),
    ("wb/stv16c_7200_16kHz.COD", 16000, 60),
    ("wb/stv16c_8000_16kHz.f06.COD", 16000, 60),
    ("wb/stv16c_13200_16kHz.COD", 16000, 80),
    ("wb/stv16c_13200_16kHz.f06.COD", 16000, 80),
    ("wb/stv16c_dtx_13200_16kHz.COD", 16000, 80),
    ("wb/stv16c_dtx_13200_16kHz.f06.COD", 16000, 80),
    ("wb/stv16c_dtx_5900_16kHz.COD", 16000, 12),
    ("wb/stv16c_dtx_5900_16kHz.f06.COD", 16000, 12),
    ("wb/stv16c_16400_16kHz.COD", 16000, 100),
    ("wb/stv16c_24400_16kHz.COD", 16000, 100),
    ("wb/stv16c_32000_16kHz.COD", 16000, 100),
    ("wb/stv16c_32000_16kHz.f06.COD", 16000, 100),
    ("swb/stv32c_13200_32kHz.COD", 32000, 80),
    ("swb/stv32c_13200_32kHz.f06.COD", 32000, 80),
    ("swb/stv32c_24400_32kHz.COD", 32000, 100),
    ("swb/stv32c_dtx_13200_32kHz.COD", 32000, 80),
    ("swb/stv32c_dtx_24400_32kHz.f06.COD", 32000, 80),
    ("swb/stv32c_sw_72_164_32kHz.COD", 32000, 100),
    ("swb/stv32c_dtx_sw_59_164_32kHz.f06.COD", 32000, 100),
    ("fb/stv48c_24400_48kHz.COD", 48000, 100),
    ("fb/stv48c_dtx_sw_59_244_48kHz.COD", 48000, 100),
];
