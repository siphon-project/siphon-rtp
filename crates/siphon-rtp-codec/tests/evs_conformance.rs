//! Conformance of the EVS port against the 3GPP TS 26.444 fixed-point sequences.
//!
//! The acceptance criterion is TS 26.444 §7.1: for an implementation of the fixed-point reference,
//! decoding each `*.COD` must reproduce its `*.OUT` bit-exactly. The cases are not restated here;
//! they are read from the package's own `Readme_EVS_dec.txt` and `Readme_AMRWB_IO_dec.txt`, the
//! shell scripts upstream ships to run them, so the set under test is exactly upstream's.
//!
//! Two checks. Every bitstream those scripts name is a well-formed G.192 stream of legal EVS frames,
//! and every reference output is exactly one 20 ms frame at the requested rate per input frame.
//! And the decoder gate: every decoder sequence either decodes byte for byte to the reference
//! `.OUT` or stops at a named [`EvsError::Unsupported`] boundary of the port, and the number that
//! decode identically matches [`DECODER_IDENTICAL`], which each later phase raises.
//!
//! The sequences are copyrighted and gitignored, so this skips when they are absent (a fresh
//! checkout stays green) and `SIPHON_RTP_REQUIRE_VECTORS=1` turns that skip into a failure, and also
//! demands the complete set. `sh reference/evs/fetch.sh` installs them;
//! `$SIPHON_RTP_EVS_VECTORS` points at a `testvec` directory elsewhere.

#![cfg(feature = "evs")]

use std::collections::BTreeMap;

mod evs_cases;

use evs_cases::{cases, required, vectors_dir, Case};
use siphon_rtp_codec::evs::decoder::EvsDecoder;
use siphon_rtp_codec::evs::error::EvsError;
use siphon_rtp_codec::evs::frame::FrameKind;
use siphon_rtp_codec::evs::g192::G192Reader;

/// Decoder cases in each upstream script, so a partial download cannot pass for the whole set.
const SCRIPTS: &[(&str, usize)] = &[
    ("Readme_EVS_dec.txt", 979),
    ("Readme_AMRWB_IO_dec.txt", 1590),
];

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

/// How many sequences of `Readme_EVS_dec.txt` decode byte-identical, per (bit rate, output kHz).
/// The bit rate is the one a `..._<rate>_<kHz>kHz` sequence name carries (`stv16c_dtx_13200_16kHz`);
/// the switching, network-simulation and channel-aware families name no single rate and count as
/// `0`. Every other sequence must stop at a named [`EvsError::Unsupported`] boundary: a decoder
/// that emits audio which differs from the reference, or fails any other way, fails the gate.
/// Exact counts rather than a floor, so a case that moves from identical to refused is caught too.
/// A later phase raises the counts it unlocks.
const DECODER_IDENTICAL: &[((u32, usize), usize)] = &[
    ((5900, 8), 9),
    ((5900, 16), 9),
    ((7200, 8), 18),
    ((7200, 16), 18),
    ((8000, 8), 18),
    ((8000, 16), 18),
    ((13200, 8), 12),
    ((13200, 16), 6),
    ((13200, 32), 6),
    ((32000, 16), 18),
    ((64000, 16), 18),
    ((64000, 32), 18),
    ((64000, 48), 18),
];

/// The (bit rate, output kHz) bucket of `case` in [`DECODER_IDENTICAL`]: the first `_<digits>_`
/// field of four or more digits in the sequence name, or `0` when it has none.
fn rate_bucket(case: &Case) -> (u32, usize) {
    let name = case
        .bitstream
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let rate = name
        .split('_')
        .skip(1)
        .find(|field| field.len() >= 4 && field.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|field| field.parse().ok())
        .unwrap_or(0);
    (rate, case.output_khz)
}

/// What decoding one sequence came to.
enum Outcome {
    Identical,
    /// Stopped at a boundary of the port that is not built yet.
    Refused(String),
    /// Audio that differs from the reference, or any other failure.
    Failed(String),
}

fn outcome(case: &Case) -> Outcome {
    match decode_case(case) {
        Ok(None) => Outcome::Identical,
        Ok(Some((frame, offset))) => {
            Outcome::Failed(format!("first difference in frame {frame} sample {offset}"))
        }
        Err(DecodeFailure::Unsupported(reason)) => Outcome::Refused(reason),
        Err(DecodeFailure::Other(reason)) => Outcome::Failed(reason),
    }
}

/// Why [`decode_case`] did not produce a comparable output.
enum DecodeFailure {
    /// [`EvsError::Unsupported`]: a frame needs a part of the decoder not ported yet.
    Unsupported(String),
    Other(String),
}

impl From<String> for DecodeFailure {
    fn from(reason: String) -> Self {
        Self::Other(reason)
    }
}

/// Decode `case` and return the first differing sample (frame, offset) or `None` when identical.
fn decode_case(case: &Case) -> Result<Option<(usize, usize)>, DecodeFailure> {
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
            .map_err(|error| match error {
                EvsError::Unsupported { .. } => {
                    DecodeFailure::Unsupported(format!("frame {index}: {error}"))
                }
                other => DecodeFailure::Other(format!("frame {index}: {other}")),
            })?;
        for sample in &out[..written] {
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
    }
    let written = decoder.flush(&mut out).map_err(|error| error.to_string())?;
    for sample in &out[..written] {
        pcm.extend_from_slice(&sample.to_le_bytes());
    }
    if pcm.len() != reference.len() {
        return Err(DecodeFailure::Other(format!(
            "{} bytes, reference {}",
            pcm.len(),
            reference.len()
        )));
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
fn every_decoder_sequence_decodes_byte_identical_or_is_refused_at_a_named_boundary() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        eprintln!("skipping: EVS conformance sequences not installed (sh reference/evs/fetch.sh)");
        return;
    };
    let all = cases(&root, "Readme_EVS_dec.txt");
    // One sequence per worker at a time: each holds a decoder and two whole files.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = std::sync::Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(4, |count| count.get().min(16));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(case) = all.get(index) else { break };
                let result = (
                    rate_bucket(case),
                    case.bitstream.display().to_string(),
                    outcome(case),
                );
                results
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(result);
            });
        }
    });
    let results = results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut identical: BTreeMap<(u32, usize), usize> = BTreeMap::new();
    let (mut refused, mut failures) = (BTreeMap::<String, usize>::new(), Vec::new());
    for (bucket, name, result) in results {
        match result {
            Outcome::Identical => *identical.entry(bucket).or_default() += 1,
            Outcome::Refused(reason) => {
                // `frame N: <what is not supported>`: count by the boundary, not the frame
                let boundary = reason
                    .split_once(": ")
                    .map_or(reason.as_str(), |(_, boundary)| boundary);
                *refused.entry(boundary.to_owned()).or_default() += 1;
            }
            Outcome::Failed(reason) => failures.push(format!("{name}: {reason}")),
        }
    }
    eprintln!(
        "{} sequences byte-identical, {} refused at a boundary, {} failed",
        identical.values().sum::<usize>(),
        refused.values().sum::<usize>(),
        failures.len()
    );
    for (boundary, count) in &refused {
        eprintln!("  {count} refused: {boundary}");
    }
    for failure in &failures {
        eprintln!("FAIL {failure}");
    }
    assert!(failures.is_empty(), "{} sequences failed", failures.len());
    let expected: BTreeMap<(u32, usize), usize> = DECODER_IDENTICAL.iter().copied().collect();
    assert_eq!(
        identical, expected,
        "byte-identical sequences per (bit rate, output kHz) changed"
    );
}

#[test]
fn a_mode2_sequence_is_refused_not_decoded() {
    use siphon_rtp_codec::evs::error::UnsupportedMode;
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
