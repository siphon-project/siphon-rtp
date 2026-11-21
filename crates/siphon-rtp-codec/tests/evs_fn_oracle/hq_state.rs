//! Helpers for the frame-loss concealment oracles, which compare the whole decoder state around
//! every call (`fn/stream_mode.h`): the oracle prints the state before a sequence with prefix
//! `in.` and, around each call, only the fields that differ from it under a call prefix.

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::Case;
use crate::state_dump;

/// The state keyed `st.<C path>`: the initial state (`in.`) with the fields printed under
/// `prefix` laid over it.
pub fn overlay(case: &Case, prefix: &str) -> BTreeMap<String, Vec<i64>> {
    let mut state: BTreeMap<String, Vec<i64>> = case
        .inputs
        .iter()
        .filter_map(|(key, values)| {
            key.strip_prefix("in.")
                .map(|rest| (format!("st.{rest}"), values.clone()))
        })
        .collect();
    for (key, values) in case.inputs.iter().chain(case.outputs.iter()) {
        if let Some(rest) = key.strip_prefix(prefix) {
            state.insert(format!("st.{rest}"), values.clone());
        }
    }
    state
}

/// The state after a call of a `stream` line: the state before (`in.`) with the changed fields
/// (`st.`) laid over it.
pub fn state_after(case: &Case) -> BTreeMap<String, Vec<i64>> {
    let mut state = overlay(case, "\u{0}never");
    for (key, values) in &case.outputs {
        if key.starts_with("st.") {
            state.insert(key.clone(), values.clone());
        }
    }
    state
}

/// A decoder at the case's `output_fs` / `output_frame`, built by `init_decoder`, loaded with
/// `state`.
pub fn decoder_with(case: &Case, state: &BTreeMap<String, Vec<i64>>) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);
    state_dump::load(&mut st, state, "st.");
    st
}

/// Load `state` into `st` and return the ROM-pointer fields a load cannot set (taken as the Rust
/// state has them), to be laid over the expected state before comparing.
pub fn reload(st: &mut DecoderState, state: &BTreeMap<String, Vec<i64>>) {
    state_dump::load(st, state, "st.");
}

/// Compare the whole state with `expected`, except the ROM-pointer fields, which the Rust state
/// keeps from `init_decoder` (their value is proven by the `init_dec` oracle).
pub fn check_state(st: &mut DecoderState, expected: &BTreeMap<String, Vec<i64>>, context: &str) {
    state_dump::check(st, expected, "st.", context);
}

/// The conformance sequences the stream tests run, with the decoder output rate each needs.
pub fn vectors_dir() -> Option<std::path::PathBuf> {
    let vectors = std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        std::path::PathBuf::from,
    );
    vectors.is_dir().then_some(vectors)
}

/// Parse one `stream`-mode line of an oracle (`name=v,v ... -> name=v ...`).
pub fn parse_line(line: &str) -> Case {
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

/// Run `fn_<module> stream <file> <rate> <every>` over the conformance sequence `name` and hand
/// every recorded call to `body`. Returns how many calls ran; `None` (after a note) when the
/// oracle or the sequences are absent, unless `SIPHON_RTP_REQUIRE_VECTORS=1`.
pub fn each_stream_call(
    module: &str,
    name: &str,
    rate: u32,
    every: u32,
    mut body: impl FnMut(usize, &Case),
) -> Option<usize> {
    let required = std::env::var("SIPHON_RTP_REQUIRE_VECTORS").is_ok_and(|v| v == "1");
    let oracle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/evs/build")
        .join(format!("fn_{module}"));
    let Some(vectors) = vectors_dir().filter(|_| oracle.is_file()) else {
        assert!(!required, "no conformance bitstreams or fn_{module}");
        eprintln!("skipping: no conformance bitstreams or fn_{module}");
        return None;
    };
    let path = vectors.join("testv/bitstreams").join(name);
    if !path.is_file() {
        assert!(!required, "{path:?} is missing");
        return None;
    }
    let output = std::process::Command::new(&oracle)
        .arg("stream")
        .arg(&path)
        .arg(rate.to_string())
        .arg(every.to_string())
        .output()
        .expect("run the oracle");
    assert!(output.status.success(), "fn_{module} stream {name} failed");
    let text = String::from_utf8(output.stdout).expect("ASCII");
    let mut calls = 0;
    for (index, line) in text.lines().enumerate() {
        body(index, &parse_line(line));
        calls += 1;
    }
    Some(calls)
}

/// ROM-pointer fields a load cannot set (the FD-CNG tables the decoder's last configuration
/// chose) keep the value `init_decoder` gave them: right after the load, lay those over
/// `after` unless the call changed them (`before` and `after` differing there).
pub fn keep_unloadable(
    st: &mut DecoderState,
    before: &BTreeMap<String, Vec<i64>>,
    after: &mut BTreeMap<String, Vec<i64>>,
) {
    for (key, values) in state_dump::dump(st) {
        if before.get(&key) != Some(&values) && after.get(&key) == before.get(&key) {
            after.insert(key, values);
        }
    }
}
