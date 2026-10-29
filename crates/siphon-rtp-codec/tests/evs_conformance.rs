//! Conformance of the EVS port against the 3GPP TS 26.444 fixed-point sequences.
//!
//! The acceptance criterion is TS 26.444 §7.1: for an implementation of the fixed-point reference,
//! decoding each `*.COD` must reproduce its `*.OUT` bit-exactly. The cases are not restated here;
//! they are read from the package's own `Readme_EVS_dec.txt` and `Readme_AMRWB_IO_dec.txt`, the
//! shell scripts upstream ships to run them, so the set under test is exactly upstream's.
//!
//! There is no decoder yet, so what this checks today is the ground the decoder will stand on:
//! every bitstream those scripts name is a well-formed G.192 stream of legal EVS frames, and every
//! reference output is exactly one 20 ms frame at the requested rate per input frame. The
//! byte-for-byte decoder gate joins this file with the decoder, one bit rate at a time.
//!
//! The sequences are copyrighted and gitignored, so this skips when they are absent (a fresh
//! checkout stays green) and `SIPHON_RTP_REQUIRE_VECTORS=1` turns that skip into a failure, and also
//! demands the complete set. `sh reference/evs/fetch.sh` installs them;
//! `$SIPHON_RTP_EVS_VECTORS` points at a `testvec` directory elsewhere.

#![cfg(feature = "evs")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::evs::frame::FrameKind;
use siphon_rtp_codec::evs::g192::G192Reader;

/// Decoder cases in each upstream script, so a partial download cannot pass for the whole set.
const SCRIPTS: &[(&str, usize)] = &[
    ("Readme_EVS_dec.txt", 979),
    ("Readme_AMRWB_IO_dec.txt", 1590),
];

/// One `$DEC_BIN rate in out` line and the `$DIFF_BIN reference out` line that follows it.
struct Case {
    output_khz: usize,
    bitstream: PathBuf,
    reference: PathBuf,
}

fn vectors_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SIPHON_RTP_EVS_VECTORS") {
        let path = PathBuf::from(path);
        return path.is_dir().then_some(path);
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec");
    dir.is_dir().then_some(dir)
}

fn required() -> bool {
    std::env::var("SIPHON_RTP_REQUIRE_VECTORS").is_ok_and(|value| value == "1")
}

fn cases(root: &Path, script: &str) -> Vec<Case> {
    let text = std::fs::read_to_string(root.join(script))
        .unwrap_or_else(|error| panic!("reading {script}: {error}"));
    let mut cases = Vec::new();
    let mut pending: Option<(usize, PathBuf)> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first() {
            Some(&"$DEC_BIN") => {
                // `$DEC_BIN <kHz> <in> <out>`. Every decoder case upstream ships takes the output
                // rate and nothing else; an option appearing here means the script changed under
                // us, and is refused rather than silently ignored.
                assert_eq!(
                    fields.len(),
                    4,
                    "{script}: unexpected decoder options in {line:?}"
                );
                let output_khz = fields[1]
                    .parse()
                    .unwrap_or_else(|_| panic!("{script}: {line:?}"));
                pending = Some((output_khz, root.join(fields[2])));
            }
            Some(&"$DIFF_BIN") => {
                if let Some((output_khz, bitstream)) = pending.take() {
                    cases.push(Case {
                        output_khz,
                        bitstream,
                        reference: root.join(fields[1]),
                    });
                }
            }
            _ => {}
        }
    }
    cases
}

#[test]
fn every_decoder_sequence_is_well_formed_g192_and_one_output_frame_per_input_frame() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        eprintln!("skipping: EVS conformance sequences not installed (sh reference/evs/fetch.sh)");
        return;
    };

    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad_frames = 0usize;
    let mut checked = 0usize;
    let mut missing = Vec::new();
    for &(script, expected_cases) in SCRIPTS {
        let cases = cases(&root, script);
        assert_eq!(
            cases.len(),
            expected_cases,
            "{script} changed its case count"
        );
        for case in cases {
            let (Ok(bitstream), Ok(reference_bytes)) = (
                std::fs::read(&case.bitstream),
                std::fs::metadata(&case.reference).map(|m| m.len()),
            ) else {
                missing.push(case.bitstream.display().to_string());
                continue;
            };
            assert!(
                matches!(case.output_khz, 8 | 16 | 32 | 48),
                "{}: output rate {} kHz",
                case.bitstream.display(),
                case.output_khz
            );
            let mut frames = 0usize;
            let mut bits = [0u8; FrameKind::MAX_BITS];
            for frame in G192Reader::new(&bitstream) {
                let frame =
                    frame.unwrap_or_else(|error| panic!("{}: {error}", case.bitstream.display()));
                assert_eq!(frame.unpack_bits(&mut bits), Ok(frame.kind.bits()));
                *kinds.entry(format!("{:?}", frame.kind)).or_default() += 1;
                bad_frames += usize::from(!frame.good);
                frames += 1;
            }
            // One 20 ms frame of 16-bit PCM at the requested rate per input frame.
            let expected_bytes = frames * case.output_khz * 20 * 2;
            assert_eq!(
                reference_bytes as usize,
                expected_bytes,
                "{}: {frames} frames at {} kHz",
                case.reference.display(),
                case.output_khz
            );
            checked += 1;
        }
    }

    eprintln!(
        "checked {checked} sequences, {} absent; frame kinds {kinds:?}, {bad_frames} bad",
        missing.len()
    );
    if required() {
        assert!(
            missing.is_empty(),
            "{} sequences absent, e.g. {}",
            missing.len(),
            missing[0]
        );
        // The full set exercises every kind of frame the decoder has to handle.
        for kind in ["NoData", "PrimarySid", "AmrWbIoSid"] {
            assert!(
                kinds.contains_key(kind),
                "no {kind} frame anywhere in the set"
            );
        }
        assert!(bad_frames > 0, "no frame-erasure case anywhere in the set");
    }
    assert!(checked > 0 || !required(), "no sequence checked");
}
