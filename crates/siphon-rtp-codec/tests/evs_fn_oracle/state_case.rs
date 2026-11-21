//! Helpers for the oracles that compare the whole decoder state (`fn/state_capture.h`): the
//! oracle prints the state before the call with prefix `in.` and only the fields that changed
//! after it with prefix `st.`.

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::Case;
use crate::state_dump;

/// The whole state after the call: the "before" state (`in.`) with the changed fields (`st.`)
/// overlaid, keyed `st.<C path>`.
pub fn state_after(case: &Case) -> BTreeMap<String, Vec<i64>> {
    let mut after: BTreeMap<String, Vec<i64>> = case
        .inputs
        .iter()
        .filter_map(|(key, values)| {
            key.strip_prefix("in.")
                .map(|rest| (format!("st.{rest}"), values.clone()))
        })
        .collect();
    for (key, values) in &case.outputs {
        if key.starts_with("st.") {
            after.insert(key.clone(), values.clone());
        }
    }
    after
}

/// A decoder built by `init_decoder` at the case's `output_fs` / `output_frame`, loaded with the
/// "before" state, and its bit stream from the case's `bits`.
pub fn decoder_before(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);
    state_dump::load(&mut st, &case.inputs, "in.");
    if let Some(bits) = case.inputs.get("bits") {
        for (slot, &bit) in st.bit_stream.iter_mut().zip(bits) {
            *slot = bit as u16;
        }
    }
    st
}
