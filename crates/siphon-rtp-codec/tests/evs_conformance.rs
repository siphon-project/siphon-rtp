//! Conformance of the EVS port against the 3GPP TS 26.444 fixed-point sequences.
//!
//! The acceptance criterion is TS 26.444 §7.1: for an implementation of the fixed-point reference,
//! decoding each `*.COD` must reproduce its `*.OUT` bit-exactly. The cases are not restated here;
//! they are read from the package's own `Readme_EVS_dec.txt` and `Readme_AMRWB_IO_dec.txt`, the
//! shell scripts upstream ships to run them, so the set under test is exactly upstream's.
//!
//! Two checks. Every bitstream those scripts name is a well-formed G.192 stream of legal EVS frames,
//! and every reference output is exactly one 20 ms frame at the requested rate per input frame.
//! And the decoder gate: every decoder sequence of both scripts, EVS and AMR-WB IO alike, decodes
//! byte for byte to the reference `.OUT`, and the number that do matches [`DECODER_IDENTICAL`] and
//! [`AMR_WB_IO_IDENTICAL`].
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
/// `0`. Every one of the 979 sequences must decode byte for byte: a decoder that emits audio which
/// differs from the reference, or fails any other way, fails the gate. Exact counts rather than a
/// floor, so a case the script gains, loses or moves between buckets is caught too.
const DECODER_IDENTICAL: &[((u32, usize), usize)] = &[
    ((0, 8), 18),
    ((0, 32), 20),
    ((0, 48), 18),
    ((1280, 8), 37),
    ((1280, 16), 56),
    ((1280, 32), 90),
    ((1280, 48), 55),
    ((5900, 8), 9),
    ((5900, 16), 9),
    ((7200, 8), 18),
    ((7200, 16), 18),
    ((8000, 8), 18),
    ((8000, 16), 18),
    ((9600, 8), 18),
    ((9600, 16), 18),
    ((9600, 32), 18),
    ((13200, 8), 18),
    ((13200, 16), 54),
    ((13200, 32), 54),
    ((16400, 8), 18),
    ((16400, 16), 18),
    ((16400, 32), 18),
    ((16400, 48), 18),
    ((24400, 8), 18),
    ((24400, 16), 19),
    ((24400, 32), 18),
    ((24400, 48), 18),
    ((32000, 16), 18),
    ((32000, 32), 18),
    ((32000, 48), 18),
    ((48000, 16), 18),
    ((48000, 32), 18),
    ((48000, 48), 18),
    ((64000, 16), 18),
    ((64000, 32), 18),
    ((64000, 48), 18),
    ((96000, 16), 18),
    ((96000, 32), 18),
    ((96000, 48), 18),
    ((128000, 16), 18),
    ((128000, 32), 18),
    ((128000, 48), 18),
];

/// The same for the 1590 sequences of `Readme_AMRWB_IO_dec.txt` (the AMR-WB interoperable mode,
/// all at 16 kHz): per AMR-WB bit rate 159 sequences (clean, 10 % and 6 % frame erasure, with and
/// without DTX, over the test items), and 318 switching streams (AMR-WB IO to and from the EVS
/// primary modes) that name no single rate. Every one must decode byte for byte.
const AMR_WB_IO_IDENTICAL: &[((u32, usize), usize)] = &[
    ((0, 16), 318),
    ((6600, 16), 159),
    ((8850, 16), 159),
    ((12650, 16), 159),
    ((14250, 16), 159),
    ((15850, 16), 159),
    ((19850, 16), 159),
    ((23050, 16), 159),
    ((23850, 16), 159),
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

/// What decoding one sequence came to: `None` when it is byte-identical to the reference, the
/// reason otherwise.
fn outcome(case: &Case) -> Option<String> {
    match decode_case(case) {
        Ok(None) => None,
        Ok(Some((frame, offset))) => {
            Some(format!("first difference in frame {frame} sample {offset}"))
        }
        Err(reason) => Some(reason),
    }
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

/// Decode every case of `script` (a sequence per worker at a time: each holds a decoder and two
/// whole files) and return how many were byte-identical per bucket, and the failures.
fn decode_script(
    root: &std::path::Path,
    script: &str,
) -> (BTreeMap<(u32, usize), usize>, Vec<String>) {
    let all = cases(root, script);
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
    let mut failures = Vec::new();
    for (bucket, name, failure) in results {
        match failure {
            None => *identical.entry(bucket).or_default() += 1,
            Some(reason) => failures.push(format!("{name}: {reason}")),
        }
    }
    (identical, failures)
}

#[test]
fn every_decoder_sequence_decodes_byte_identical() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        eprintln!("skipping: EVS conformance sequences not installed (sh reference/evs/fetch.sh)");
        return;
    };
    for (script, table) in [
        ("Readme_EVS_dec.txt", DECODER_IDENTICAL),
        ("Readme_AMRWB_IO_dec.txt", AMR_WB_IO_IDENTICAL),
    ] {
        let (identical, failures) = decode_script(&root, script);
        eprintln!(
            "{script}: {} sequences byte-identical, {} failed",
            identical.values().sum::<usize>(),
            failures.len()
        );
        for failure in &failures {
            eprintln!("FAIL {failure}");
        }
        assert!(
            failures.is_empty(),
            "{script}: {} sequences failed",
            failures.len()
        );
        let expected: BTreeMap<(u32, usize), usize> = table.iter().copied().collect();
        assert_eq!(
            identical, expected,
            "{script}: byte-identical sequences per (bit rate, output kHz) changed"
        );
    }
}

#[test]
fn an_evs_to_amr_wb_io_switching_sequence_decodes_to_the_reference_output() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        return;
    };
    // the stream switches from EVS frames to AMR-WB IO frames and back
    let case = Case {
        output_khz: 32,
        bitstream: root.join("testv/bitstreams/swb/stv32c_bw_59_1280_evs_amrwb_32kHz.COD"),
        reference: root.join("testv/decoded/swb/stv32c_bw_59_1280_evs_amrwb_32kHz.OUT"),
    };
    assert!(matches!(decode_case(&case), Ok(None)));
    // and it does carry AMR-WB IO frames
    let bytes = std::fs::read(&case.bitstream).unwrap_or_else(|error| panic!("{error}"));
    assert!(G192Reader::new(&bytes)
        .filter_map(Result::ok)
        .any(|frame| matches!(frame.kind, FrameKind::AmrWbIo(_) | FrameKind::AmrWbIoSid)));
}

#[test]
fn a_mode2_sequence_decodes_to_the_reference_output() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        return;
    };
    // 9.6 kbit/s wideband is a TCX (MODE2) stream
    let case = Case {
        output_khz: 16,
        bitstream: root.join("testv/bitstreams/wb/stv16c_9600_16kHz.COD"),
        reference: root.join("testv/decoded/wb/stv16c_9600_16kHz.OUT"),
    };
    assert!(matches!(decode_case(&case), Ok(None)));
}
