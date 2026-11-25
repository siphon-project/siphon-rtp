//! The EVS RTP path against the TS 26.444 reference outputs.
//!
//! Every sequence in the sample is read from its G.192 bitstream, wrapped into RTP payloads in
//! both formats of TS 26.445 Annex A (header-full with `hf-only=1`, and compact where the format
//! has a compact form), and decoded through the codec factory's [`Decoder`], the path the engine
//! runs. The PCM must be byte for byte the reference `.OUT`, so a frame mapped to the wrong type,
//! bit order, quality or DTX state anywhere in a sequence shows as a difference.
//!
//! The decoder here is the streaming one, which does not drop the decoder delay from the start of
//! the stream as the reference's file decoder does; the test removes it, and appends the zeros the
//! reference appends at the end, so the comparison is against the unmodified `.OUT`.
//!
//! **Where the reference disagrees with itself.** The `.OUT` files were made by the reference's G.192
//! decoder. For the sequences that combine DTX with frame erasure (`*_dtx_*.b10` and `*.f06`)
//! the reference's own storage-format decoder (`EVS_dec -mime`, the RTP side of its code) gives a
//! different output from its G.192 decoder, by a least-significant bit in the comfort noise or a
//! concealed frame, because an RTP frame says what it is (SPEECH_LOST, NO_DATA, a SID's STI bit)
//! where a G.192 file leaves the decoder to infer it. For those, when the reference decoder is
//! built (`sh reference/evs/oracle/build.sh`), the RTP path must equal *its* output; without it the
//! case is counted as unverified. 108 of the 2569 sequences are in this class, and every one of
//! them was checked equal to the storage-format decoder.
//!
//! Like `evs_conformance` this skips when the sequences are absent and
//! `SIPHON_RTP_REQUIRE_VECTORS=1` turns that into a failure. `SIPHON_RTP_EVS_RTP_STRIDE=1` runs
//! every sequence of both scripts instead of the sample (hours in a debug build, minutes in
//! release).

#![cfg(feature = "evs")]

mod evs_cases;

use evs_cases::packetize::{Format, Packetizer};
use evs_cases::{cases, oracle, required, vectors_dir, Case};
use siphon_rtp_codec::evs::cnst::DEC;
use siphon_rtp_codec::evs::com::delay_comp::get_delay;
use siphon_rtp_codec::evs::g192::G192Reader;
use siphon_rtp_codec::evs::macros::ns2sa_fx2;
use siphon_rtp_codec::factory::{decoder_for, CodecSpec, EvsParams};

/// How a sequence came out.
enum Outcome {
    /// The PCM is the `.OUT`, byte for byte; the frames decoded.
    Identical(usize),
    /// The PCM is what the reference's storage-format decoder makes of the same frames, which is
    /// not the `.OUT` (see the module documentation).
    MatchesStorageDecoder(usize),
    /// A sequence of that class, with no reference decoder built to say what is right.
    Unverified(usize),
}

/// The sequences whose `.OUT` the reference's storage-format decoder does not reproduce.
fn is_dtx_with_erasures(case: &Case) -> bool {
    let name = case
        .bitstream
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    name.contains("_dtx_") && (name.contains(".b10.") || name.contains(".f06."))
}

/// Decode `case` through the RTP path in `format`, and return the first difference from the
/// reference output as a message.
fn check(case: &Case, format: Format) -> Result<Outcome, String> {
    let bitstream = std::fs::read(&case.bitstream).map_err(|error| error.to_string())?;
    let reference = std::fs::read(&case.reference).map_err(|error| error.to_string())?;
    let band = match case.output_khz {
        8 => "nb",
        16 => "wb",
        32 => "swb",
        _ => "fb",
    };
    let hf_only = if format == Format::HeaderFull {
        ";hf-only=1"
    } else {
        ""
    };
    let params =
        EvsParams::parse(&format!("bw-send={band}{hf_only}")).map_err(|e| e.to_string())?;
    let spec = CodecSpec::new(96, "EVS", 16_000, 1, 20).with_evs_params(Some(params));
    let mut decoder = decoder_for(&spec).map_err(|error| error.to_string())?;
    assert_eq!(
        decoder.params().sample_rate_hz,
        case.output_khz as u32 * 1000
    );
    let frame_len = decoder.frame_samples();

    let mut packetizer = Packetizer::new(format);
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut pcm: Vec<i16> = Vec::new();
    let mut out = vec![0i16; frame_len];
    let mut frames = 0;
    for frame in G192Reader::new(&bitstream) {
        let frame = frame.map_err(|error| error.to_string())?;
        let payload = packetizer.payload(&frame);
        let written = decoder
            .decode(&payload, &mut out)
            .map_err(|error| format!("frame {frames}: {error}"))?;
        assert_eq!(written, frame_len);
        pcm.extend_from_slice(&out);
        payloads.push(payload);
        frames += 1;
    }
    let decoded = pcm.clone();
    // the reference file decoder drops the decoder delay from the start and zero-pads the end
    let fs = case.output_khz as i32 * 1000;
    let delay = usize::try_from(ns2sa_fx2(fs, get_delay(DEC, fs))).map_err(|e| e.to_string())?;
    pcm.drain(..delay);
    pcm.extend(std::iter::repeat_n(0i16, delay));
    let expected: Vec<i16> = reference
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_le_bytes(*pair))
        .collect();
    if pcm.len() != expected.len() {
        return Err(format!(
            "{} samples, reference has {}",
            pcm.len(),
            expected.len()
        ));
    }
    let Some(at) = pcm
        .iter()
        .zip(&expected)
        .position(|(left, right)| left != right)
    else {
        return Ok(Outcome::Identical(frames));
    };
    if is_dtx_with_erasures(case) && format == Format::HeaderFull {
        // the storage format is a header-full payload of one frame without the CMR octet
        let Some(reference) = oracle::decoder() else {
            assert!(
                !oracle::required(),
                "SIPHON_RTP_REQUIRE_ORACLE=1 but reference/evs/build/EVS_dec is not built"
            );
            return Ok(Outcome::Unverified(frames));
        };
        let storage = oracle::storage_file(&payloads);
        let said = oracle::decode_storage(&reference, &storage, case.output_khz);
        return if said == decoded {
            Ok(Outcome::MatchesStorageDecoder(frames))
        } else {
            Err(format!(
                "neither the .OUT nor the storage-format decoder: {} samples against {}",
                decoded.len(),
                said.len()
            ))
        };
    }
    if is_dtx_with_erasures(case) {
        // compact packets carry the same frames: the header-full run decides, once, with the oracle
        return Ok(Outcome::Unverified(frames));
    }
    Err(format!(
        "first difference at sample {at} (frame {}): {} against {}",
        at / frame_len,
        pcm[at],
        expected[at]
    ))
}

fn stride() -> usize {
    std::env::var("SIPHON_RTP_EVS_RTP_STRIDE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Run the sample (every `stride`-th case, from `offset`) of one script in both formats.
fn run(script: &str, default_stride: usize, offset: usize) {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        eprintln!("skipping: EVS conformance sequences not installed (sh reference/evs/fetch.sh)");
        return;
    };
    let step = match stride() {
        0 => default_stride,
        every => every,
    };
    let selected: Vec<Case> = cases(&root, script)
        .into_iter()
        .enumerate()
        .filter(|(index, _)| index % step == offset % step)
        .map(|(_, case)| case)
        .collect();
    assert!(!selected.is_empty());
    let mut failures = Vec::new();
    let (mut frames, mut by_storage_decoder, mut unverified) = (0, 0, 0);
    for case in &selected {
        for format in [Format::HeaderFull, Format::Compact] {
            match check(case, format) {
                Ok(Outcome::Identical(count)) => frames += count,
                Ok(Outcome::MatchesStorageDecoder(count)) => {
                    frames += count;
                    by_storage_decoder += 1;
                }
                Ok(Outcome::Unverified(count)) => {
                    frames += count;
                    unverified += 1;
                }
                Err(message) => failures.push(format!(
                    "{} ({format:?}): {message}",
                    case.bitstream.display()
                )),
            }
        }
    }
    eprintln!(
        "{script}: {} sequences in two formats, {frames} frames; {by_storage_decoder} equal the \
         reference storage-format decoder instead of the .OUT, {unverified} unverified, {} differ",
        selected.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} differ: {failures:#?}",
        failures.len()
    );
}

#[test]
fn evs_sequences_decode_identically_through_both_rtp_formats() {
    run("Readme_EVS_dec.txt", 100, 0);
}

#[test]
fn amr_wb_io_sequences_decode_identically_through_both_rtp_formats() {
    run("Readme_AMRWB_IO_dec.txt", 120, 0);
}
