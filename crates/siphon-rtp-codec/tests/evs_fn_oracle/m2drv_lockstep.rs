//! The MODE2 driver (`decoder_LPD`, `dec_acelp_tcx_frame` and the MODE2 part of `evs_dec`) against
//! `fn_m2drv_lockstep`.
//!
//! The functions need a decoder that has run (ROM pointers, filter banks, FD-CNG and the concealment
//! memories are configured by earlier frames, and a state dump does not restore them), so the oracle
//! runs the reference decoder loop over TS 26.444 sequences and prints the whole decoder state and the
//! output after chosen frames. This test runs the same bit streams through the port in step (the
//! `decoder.c` loop of [`siphon_rtp_codec::evs::decoder::EvsDecoder`], with the state in reach) and
//! compares the output and every state field after each printed frame, so the first wrong field is
//! named.

use siphon_rtp_codec::evs::basop::mult_32_16;
use siphon_rtp_codec::evs::cnst::{ACELP_CORE, L_FRAME48K, MAX_FRAME_COUNTER, MODE1, MODE2};
use siphon_rtp_codec::evs::com::bitstream::{
    read_indices_frame, reset_indices_dec, FRAMEMODE_MISSING, FRAMEMODE_NORMAL,
};
use siphon_rtp_codec::evs::dec::evs_dec::evs_dec;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::io_dec::configure_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::g192::G192Reader;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::common::{corpus_sized, Case};
use crate::state_dump;

const MODULE: &str = "m2drv_lockstep";
/// Printed frames: four of each of the oracle's 48 sequences.
const COUNT: usize = 192;

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

#[test]
fn the_mode2_decoder_keeps_the_whole_state_of_the_reference_over_real_sequences() {
    let Some(cases) = corpus_sized(MODULE, "decode", COUNT) else {
        return;
    };
    let root = vectors_root();
    // cases of one sequence follow each other, frames ascending
    let mut groups: BTreeMap<usize, Vec<&Case>> = BTreeMap::new();
    for case in &cases {
        groups
            .entry(case.i32("sequence") as usize)
            .or_default()
            .push(case);
    }
    let (mut mode2_frames, mut checked, mut concealed) = (0usize, 0usize, 0usize);
    for group in groups.values() {
        let path = path_of(group[0]);
        let bytes =
            std::fs::read(root.join(&path)).unwrap_or_else(|error| panic!("{path}: {error}"));
        let mut st = new_decoder(group[0].i32("khz"));
        let mut output = [0i16; L_FRAME48K as usize];
        let mut wanted = group.iter().peekable();
        for (index, frame) in G192Reader::new(&bytes).enumerate() {
            let frame = frame.expect("well-formed G.192");
            read_indices_frame(&mut st, &frame).expect("indices");
            let mode = if st.codec_mode == MODE1 || st.bfi == 0 {
                FRAMEMODE_NORMAL
            } else {
                FRAMEMODE_MISSING
            };
            evs_dec(&mut st, &mut output, mode).expect("decodes");
            if st.ini_frame < MAX_FRAME_COUNTER {
                st.ini_frame += 1;
            }
            let Some(case) = wanted.next_if(|case| case.i32("frame") as usize == index) else {
                continue;
            };
            let context = format!("{path} frame {index}");
            let frame_len = usize::from(st.output_frame as u16);
            assert_eq!(
                &output[..frame_len],
                &case.i16s("output")[..],
                "{context}: output"
            );
            let mut expected = case.inputs.clone();
            if st.tcxonly != 0 && st.core == ACELP_CORE {
                // A TCX-only stream conceals a lost frame like ACELP, and `decoder_LPD` then copies
                // `Aq`, which no TCX-only path fills (it is an uninitialised local of the reference),
                // into `mem_Aq`. Nothing reads it back there, so only the garbage differs: the port
                // keeps zeros.
                expected.insert(
                    "in.mem_Aq".to_owned(),
                    st.mem_aq.iter().map(|&value| i64::from(value)).collect(),
                );
            }
            state_dump::check(&mut st, &expected, "in.", &context);
            checked += 1;
            mode2_frames += usize::from(st.codec_mode == MODE2);
            concealed += usize::from(st.bfi != 0);
            if wanted.peek().is_none() {
                break;
            }
        }
        assert!(wanted.peek().is_none(), "{path}: sequence ended early");
    }
    assert_eq!(checked, COUNT);
    assert!(
        mode2_frames > 40 && concealed > 10,
        "mode2 {mode2_frames} concealed {concealed}"
    );
}
