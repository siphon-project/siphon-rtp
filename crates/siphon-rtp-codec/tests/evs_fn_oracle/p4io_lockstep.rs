//! The AMR-WB IO decoder (`amr_wb_dec_fx` and everything it reaches: `decod_amr_wb_fx`,
//! `gain_dec_amr_wb_fx`, `improv_amr_wb_gs_fx`, `hf_synth_amr_wb_fx`, `updt_IO_switch_dec_fx`) against
//! `fn_p4io_lockstep`.
//!
//! The functions need a decoder that has run (ROM pointers, filter banks, FD-CNG and the concealment
//! memories are configured by earlier frames, and a state dump does not restore them), so the oracle
//! runs the reference decoder loop over TS 26.444 sequences that reach AMR-WB IO (every bit rate, DTX,
//! frame erasures, switching to and from the EVS primary modes) and prints the whole decoder state and
//! the output after chosen frames. This test runs the same bit streams through the port in step (the
//! `decoder.c` loop of [`siphon_rtp_codec::evs::decoder::EvsDecoder`], with the state in reach) and
//! compares the output and every state field after each printed frame, so the first wrong field is
//! named.

use siphon_rtp_codec::evs::basop::mult_32_16;
use siphon_rtp_codec::evs::cnst::{L_FRAME48K, MAX_FRAME_COUNTER, MODE1};
use siphon_rtp_codec::evs::com::bitstream::{
    read_indices_frame, reset_indices_dec, FRAMEMODE_MISSING, FRAMEMODE_NORMAL,
};
use siphon_rtp_codec::evs::dec::amr_wb_dec::amr_wb_dec;
use siphon_rtp_codec::evs::dec::evs_dec::evs_dec;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::io_dec::configure_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::g192::G192Reader;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::common::{corpus_sized, Case};
use crate::state_dump;

const MODULE: &str = "p4io_lockstep";
/// Printed frames: four of each of the oracle's 24 sequences.
const COUNT: usize = 96;

/// The directory holding `testv/`, as the oracle finds it.
fn vectors_root() -> PathBuf {
    std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        PathBuf::from,
    )
}

fn path_of(case: &Case) -> String {
    case.inputs["path"]
        .iter()
        .map(|&code| char::from(code as u8))
        .collect()
}

/// A decoder as `EvsDecoder::new` makes it, with its state in reach.
fn new_decoder(khz: i32) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    configure_decoder(&mut st, khz * 1000).expect("output rate");
    st.output_frame = (mult_32_16(st.output_fs, 0x0290)) as i16;
    reset_indices_dec(&mut st);
    init_decoder(&mut st);
    st
}

/// Decode one frame the way `decoder.c` does.
fn decode_frame(st: &mut DecoderState, output: &mut [i16]) {
    if st.codec_mode == MODE1 {
        if st.opt_amr_wb != 0 {
            amr_wb_dec(st, output);
        } else {
            evs_dec(st, output, FRAMEMODE_NORMAL).expect("decodes");
        }
    } else {
        let mode = if st.bfi == 0 {
            FRAMEMODE_NORMAL
        } else {
            FRAMEMODE_MISSING
        };
        evs_dec(st, output, mode).expect("decodes");
    }
    if st.ini_frame < MAX_FRAME_COUNTER {
        st.ini_frame += 1;
    }
}

/// Run the port over `cases` of one sequence (frames ascending) and compare after each.
/// Returns (frames checked, AMR-WB IO frames, concealed frames).
pub(crate) fn replay(path: &str, cases: &[&Case]) -> (usize, usize, usize) {
    let bytes =
        std::fs::read(vectors_root().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
    let mut st = new_decoder(cases[0].i32("khz"));
    let mut output = [0i16; L_FRAME48K as usize];
    let mut wanted = cases.iter().peekable();
    let (mut checked, mut io_frames, mut concealed) = (0, 0, 0);
    for (index, frame) in G192Reader::new(&bytes).enumerate() {
        let frame = frame.expect("well-formed G.192");
        read_indices_frame(&mut st, &frame).expect("indices");
        decode_frame(&mut st, &mut output);
        let Some(case) = wanted.next_if(|case| case.i32("frame") as usize == index) else {
            continue;
        };
        let context = format!("{path} frame {index}");
        let frame_len = usize::from(st.output_frame as u16);
        let expected_output = case.i16s("output");
        if output[..frame_len] != expected_output[..] {
            let first = output[..frame_len]
                .iter()
                .zip(&expected_output)
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            // the state is more telling than the samples: report both
            let message = format!(
                "{context}: output differs from sample {first} (rust {} ref {})",
                output[first], expected_output[first]
            );
            state_dump::check(&mut st, &case.inputs, "in.", &message);
            panic!("{message}: the state matches");
        }
        state_dump::check(&mut st, &case.inputs, "in.", &context);
        checked += 1;
        io_frames += usize::from(st.opt_amr_wb != 0 && st.codec_mode == MODE1);
        concealed += usize::from(st.bfi != 0);
    }
    assert!(wanted.peek().is_none(), "{path}: sequence ended early");
    (checked, io_frames, concealed)
}

#[test]
fn the_amr_wb_io_decoder_keeps_the_whole_state_of_the_reference_over_real_sequences() {
    let Some(cases) = corpus_sized(MODULE, "decode", COUNT) else {
        return;
    };
    // cases of one sequence follow each other, frames ascending
    let mut groups: BTreeMap<usize, Vec<&Case>> = BTreeMap::new();
    for case in &cases {
        groups
            .entry(case.i32("sequence") as usize)
            .or_default()
            .push(case);
    }
    let (mut checked, mut io_frames, mut concealed) = (0usize, 0usize, 0usize);
    for group in groups.values() {
        let path = path_of(group[0]);
        let (frames, io, lost) = replay(&path, group);
        checked += frames;
        io_frames += io;
        concealed += lost;
    }
    assert_eq!(checked, cases.len());
    assert!(
        io_frames > 40 && concealed > 10,
        "AMR-WB IO frames {io_frames} concealed {concealed}"
    );
}
