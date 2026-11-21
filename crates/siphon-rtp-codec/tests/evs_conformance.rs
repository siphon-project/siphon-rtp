//! Conformance of the EVS port against the 3GPP TS 26.444 fixed-point sequences.
//!
//! The acceptance criterion is TS 26.444 §7.1: for an implementation of the fixed-point reference,
//! decoding each `*.COD` must reproduce its `*.OUT` bit-exactly. The cases are not restated here;
//! they are read from the package's own `Readme_EVS_dec.txt` and `Readme_AMRWB_IO_dec.txt`, the
//! shell scripts upstream ships to run them, so the set under test is exactly upstream's.
//!
//! Two checks. Every bitstream those scripts name is a well-formed G.192 stream of legal EVS frames,
//! and every reference output is exactly one 20 ms frame at the requested rate per input frame.
//! And the decoder gate: the sequences of every rate in [`DECODER_DONE`] (clean, frame-erased and
//! DTX alike) must decode byte for byte to the reference `.OUT`. A later phase adds its rates to
//! that list.
//!
//! The sequences are copyrighted and gitignored, so this skips when they are absent (a fresh
//! checkout stays green) and `SIPHON_RTP_REQUIRE_VECTORS=1` turns that skip into a failure, and also
//! demands the complete set. `sh reference/evs/fetch.sh` installs them;
//! `$SIPHON_RTP_EVS_VECTORS` points at a `testvec` directory elsewhere.

#![cfg(feature = "evs")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::evs::decoder::EvsDecoder;
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

/// The bit rates (bit/s) whose NB and WB sequences (7.2 and 8.0 kbit/s ACELP; 32 and 64 kbit/s HQ,
/// which also run the high-rate HQ core and, with frame erasures, the HQ concealment) the decoder is declared done for. Every case of
/// `Readme_EVS_dec.txt` with an 8 or 16 kHz output at one of these rates (plain, DTX, `.b10` and
/// `.f06` frame-erased) is decoded and compared. Extend it as the later phases land.
const DECODER_DONE: &[u32] = &[7200, 8000, 32000, 64000];

/// The (rate, output kHz) a `stv{8,16}c[_dtx]_<rate>_<kHz>kHz[.b10|.f06].COD` name encodes, or
/// `None` for the other sequence families (switching, network simulations, other bandwidths).
fn done_case(case: &Case) -> Option<u32> {
    let name = case.bitstream.file_name()?.to_str()?;
    if !matches!(case.output_khz, 8 | 16) {
        return None;
    }
    let stem = name.strip_suffix(".COD")?;
    let stem = stem
        .strip_suffix(".b10")
        .or(stem.strip_suffix(".f06"))
        .unwrap_or(stem);
    let stem = stem
        .strip_prefix("stv8c_")
        .or(stem.strip_prefix("stv16c_"))?;
    let stem = stem.strip_prefix("dtx_").unwrap_or(stem);
    let rate: u32 = stem.split('_').next()?.parse().ok()?;
    DECODER_DONE.contains(&rate).then_some(rate)
}

/// Decode `case` and return the first differing sample (frame, offset) or `None` when identical.
fn decode_case(case: &Case) -> Result<Option<(usize, usize)>, String> {
    let bitstream = std::fs::read(&case.bitstream).map_err(|error| error.to_string())?;
    let reference = std::fs::read(&case.reference).map_err(|error| error.to_string())?;
    let mut decoder =
        EvsDecoder::new(case.output_khz as u32 * 1000).map_err(|error| error.to_string())?;
    let frame_samples = decoder.frame_samples();
    let mut out = vec![0i16; frame_samples];
    let mut pcm: Vec<u8> = Vec::with_capacity(reference.len());
    for (index, frame) in G192Reader::new(&bitstream).enumerate() {
        let frame = frame.map_err(|error| error.to_string())?;
        let written = decoder
            .decode_frame(&frame, &mut out)
            .map_err(|error| format!("frame {index}: {error}"))?;
        for sample in &out[..written] {
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
    }
    let written = decoder.flush(&mut out).map_err(|error| error.to_string())?;
    for sample in &out[..written] {
        pcm.extend_from_slice(&sample.to_le_bytes());
    }
    if pcm.len() != reference.len() {
        return Err(format!(
            "{} bytes, reference {}",
            pcm.len(),
            reference.len()
        ));
    }
    Ok(pcm
        .iter()
        .zip(&reference)
        .position(|(a, b)| a != b)
        .map(|byte| {
            let sample = byte / 2;
            (sample / frame_samples, sample % frame_samples)
        }))
}

#[test]
fn declared_done_decoder_sequences_decode_byte_identical() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        eprintln!("skipping: EVS conformance sequences not installed (sh reference/evs/fetch.sh)");
        return;
    };
    let mut failures = Vec::new();
    let mut passed = 0usize;
    for case in cases(&root, "Readme_EVS_dec.txt") {
        if done_case(&case).is_none() {
            continue;
        }
        let name = case.bitstream.display().to_string();
        match decode_case(&case) {
            Ok(None) => passed += 1,
            Ok(Some((frame, offset))) => {
                failures.push(format!(
                    "{name}: first difference in frame {frame} sample {offset}"
                ));
            }
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }
    eprintln!(
        "{passed} sequences byte-identical, {} failed",
        failures.len()
    );
    for failure in &failures {
        eprintln!("FAIL {failure}");
    }
    assert!(failures.is_empty(), "{} sequences differ", failures.len());
    // 7.2 and 8.0 kbit/s: NB and WB; 32 and 64 kbit/s: WB only; each plain and DTX, clean, .b10
    // and .f06
    assert!(
        passed == 0 && !required() || passed == 36,
        "expected 36 sequences, ran {passed}"
    );
}

#[test]
fn a_mode2_sequence_is_refused_not_decoded() {
    use siphon_rtp_codec::evs::error::{EvsError, UnsupportedMode};
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        return;
    };
    // 9.6 kbit/s wideband is a TCX (MODE2) stream
    let bytes = std::fs::read(root.join("testv/bitstreams/wb/stv16c_9600_16kHz.COD"))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut decoder = EvsDecoder::new(16000).unwrap_or_else(|error| panic!("{error}"));
    let mut out = vec![0i16; decoder.frame_samples()];
    let frame = G192Reader::new(&bytes)
        .next()
        .and_then(Result::ok)
        .unwrap_or_else(|| panic!("no frame"));
    assert!(matches!(
        decoder.decode_frame(&frame, &mut out),
        Err(EvsError::Unsupported {
            mode: UnsupportedMode::Mode2,
            ..
        })
    ));
}
