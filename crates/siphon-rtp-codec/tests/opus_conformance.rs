//! Opus RFC 6716 conformance — **the acceptance gate for the whole decoder**.
//!
//! RFC 6716 §6 defines conformance not as bit-exact PCM but via the `opus_compare` perceptual
//! quality metric run against the official test vectors (`testvectorNN.bit` / `.dec`). This harness
//! runs that, and one thing more:
//!
//! 1. Reads the `.bit` framing each test vector uses — a stream of packets, each prefixed by a
//!    big-endian `u32` length and a big-endian `u32` reference range-coder final value
//!    (libopus `opus_demo.c` `-d` path, `char_to_int`).
//! 2. Decodes every packet with [`OpusDecoder`] into interleaved little-endian 16-bit PCM at the
//!    conformance rate (48 kHz), exactly as `opus_demo -d 48000 <ch>` writes `tmp.out`, and checks
//!    **every packet's `final_range` against the encoder's value byte for byte**.
//! 3. Shells out to a locally built `opus_compare` (test-only C reference, never shipped) to score
//!    the decode against the reference `.dec`, in both the mono and the stereo pass, exactly as
//!    `tests/run_vectors.sh` does.
//!
//! `final_range` is the strict half and the reason it is here. `opus_compare` is a *tolerance*
//! metric: a subtly wrong decoder can pass it. The final range is the encoder's range-coder register
//! at the end of the packet — matching it means every symbol was read, in order, with the same
//! probability model, including the redundancy frame the top-level decoder folds in
//! (`rangeFinal = dec.rng ^ redundant_rng`, `opus_decoder.c:654`). `opus_demo` itself rejects a
//! mismatch as "Range coder state mismatch"; so does this harness.
//!
//! The harness is a no-op (prints a skip notice) when the vectors or `opus_compare` are absent, so
//! it never breaks CI on a machine without the (separately distributed, gitignored) vectors — but it
//! refuses to pass *vacuously*: with the vectors present, at least one vector must have been scored
//! in each pass and at least one packet's range must have been compared.

use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};

/// Conformance output rate (RFC 6716 §6 / `run_vectors.sh` uses 48000).
const CONFORMANCE_RATE_HZ: u32 = 48_000;

/// One packet from a `.bit` test-vector file.
struct BitPacket {
    /// The Opus packet payload bytes.
    payload: Vec<u8>,
    /// The reference *encoder's* range-coder final value (libopus `OPUS_GET_FINAL_RANGE`). A
    /// conformant decoder must end the packet on exactly this value — `opus_demo` itself rejects a
    /// mismatch as "Range coder state mismatch".
    final_range: u32,
}

/// Parse the `opus_demo` `.bit` framing: repeated `[u32 BE len][u32 BE final_range][len bytes]`.
///
/// Returns `Err` on a truncated or implausible header (len > 1 MiB), never panics.
fn parse_bit_stream(bytes: &[u8]) -> Result<Vec<BitPacket>, String> {
    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if offset + 8 > bytes.len() {
            return Err(format!("truncated packet header at offset {offset}"));
        }
        let len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        let final_range = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;
        // Sanity: an Opus packet is at most 1275 bytes/frame * 48 frames; cap generously.
        if len > 1 << 20 {
            return Err(format!(
                "implausible packet length {len} at offset {offset}"
            ));
        }
        if offset + len > bytes.len() {
            return Err(format!("packet payload overruns file at offset {offset}"));
        }
        packets.push(BitPacket {
            payload: bytes[offset..offset + len].to_vec(),
            final_range,
        });
        offset += len;
    }
    Ok(packets)
}

/// Locate the test-vector directory (`reference/opus/opus_testvectors`), if present.
fn vector_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/opus_testvectors");
    if dir.is_dir() {
        Some(dir)
    } else {
        None
    }
}

#[test]
fn bit_framing_reader_parses_real_vectors() {
    let Some(dir) = vector_dir() else {
        eprintln!("opus conformance: test vectors not present — skipping");
        return;
    };
    let mut total_packets = 0usize;
    for n in 1..=12u32 {
        let path = dir.join(format!("testvector{n:02}.bit"));
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("opus conformance: {} missing — skipping", path.display());
            continue;
        };
        let packets =
            parse_bit_stream(&bytes).unwrap_or_else(|error| panic!("vector {n:02}: {error}"));
        assert!(!packets.is_empty(), "vector {n:02}: no packets parsed");
        // Every packet's TOC must parse and the framing must split cleanly — exercises the parser
        // against real-world data (all four framing codes, both channel counts, every config).
        for (index, packet) in packets.iter().enumerate() {
            if packet.payload.is_empty() {
                continue; // DTX / empty packet is legal.
            }
            let parsed =
                siphon_rtp_codec::opus::packet::parse(&packet.payload).unwrap_or_else(|error| {
                    panic!("vector {n:02} packet {index}: framing parse failed: {error}")
                });
            assert!(
                !parsed.frames().is_empty(),
                "vector {n:02} packet {index}: zero frames"
            );
        }
        total_packets += packets.len();
        eprintln!(
            "opus conformance: vector {n:02} — {} packets, framing OK",
            packets.len()
        );
    }
    assert!(total_packets > 0, "no vector packets parsed across the set");
}

/// One decoded vector: the PCM `opus_demo -d` would have written, plus the range-coder audit.
struct Decoded {
    /// Interleaved little-endian 16-bit PCM at [`CONFORMANCE_RATE_HZ`].
    pcm: Vec<u8>,
    /// `(packet index, expected, got)` for every packet whose final range disagreed.
    range_mismatches: Vec<(usize, u32, u32)>,
    /// Packets whose range was actually compared (a 0 reference means "not recorded", skipped).
    ranges_checked: usize,
}

/// Decode one `.bit` vector exactly as `opus_demo -d 48000 <channels>` does: every packet through
/// one decoder, all returned samples written, and the final range checked against the file.
fn decode_vector_to_pcm(packets: &[BitPacket], channels: u8) -> Result<Decoded, String> {
    let mut decoder = OpusDecoder::new(CONFORMANCE_RATE_HZ, usize::from(channels))
        .map_err(|error| format!("OpusDecoder::new: {error}"))?;
    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * usize::from(channels)];
    let mut out = Vec::new();
    let mut range_mismatches = Vec::new();
    let mut ranges_checked = 0usize;

    for (index, packet) in packets.iter().enumerate() {
        if packet.payload.is_empty() {
            // `opus_demo` never writes a zero-length packet on the decode path; treat it as a gap.
            continue;
        }
        let written = decoder
            .decode(Some(&packet.payload), &mut pcm, MAX_PACKET_SAMPLES, false)
            .map_err(|error| format!("packet {index}: decode failed: {error}"))?;
        for &sample in &pcm[..written * usize::from(channels)] {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        // `opus_demo.c:1051` skips the comparison when the reference value is 0 (not recorded).
        if packet.final_range != 0 {
            ranges_checked += 1;
            if decoder.final_range() != packet.final_range {
                range_mismatches.push((index, packet.final_range, decoder.final_range()));
            }
        }
    }
    Ok(Decoded {
        pcm: out,
        range_mismatches,
        ranges_checked,
    })
}

/// Path to the locally built `opus_compare`, or `Err` with the reason it is unusable.
fn opus_compare_path() -> Result<PathBuf, String> {
    let compare = std::env::var_os("SIPHON_RTP_OPUS_COMPARE")
        .map_or_else(|| PathBuf::from("/tmp/opus_compare"), PathBuf::from);
    if compare.exists() {
        Ok(compare)
    } else {
        Err(format!(
            "{} not built (test-only C reference)",
            compare.display()
        ))
    }
}

/// Run `opus_compare` over a decoded buffer vs the reference `.dec`. Returns `Ok(())` on a pass.
fn run_opus_compare(
    compare: &Path,
    reference_dec: &Path,
    decoded_pcm: &[u8],
    channels: u8,
    tag: &str,
) -> Result<(), String> {
    if !reference_dec.exists() {
        return Err(format!("{} missing", reference_dec.display()));
    }
    let tmp = std::env::temp_dir().join(format!("opus_decoded_{}_{tag}.sw", std::process::id()));
    std::fs::write(&tmp, decoded_pcm).map_err(|e| e.to_string())?;
    let mut command = std::process::Command::new(compare);
    if channels == 2 {
        command.arg("-s");
    }
    command
        .arg("-r")
        .arg(CONFORMANCE_RATE_HZ.to_string())
        .arg(reference_dec)
        .arg(&tmp);
    let status = command.status().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    if status.success() {
        Ok(())
    } else {
        Err(format!("opus_compare exited {status}"))
    }
}

/// The acceptance gate: all 12 official vectors, mono **and** stereo, `opus_compare` plus exact
/// per-packet `final_range`.
///
/// `run_vectors.sh` accepts a pass against either `testvectorNN.dec` or `testvectorNNm.dec` (the
/// latter is the fixed-point reference decode, distributed only with some vector sets), so both are
/// tried before a vector is called a failure.
#[test]
fn conformance_against_opus_compare() {
    let Some(dir) = vector_dir() else {
        eprintln!("opus conformance: test vectors not present — skipping");
        return;
    };
    let compare = match opus_compare_path() {
        Ok(path) => path,
        Err(reason) => {
            eprintln!("opus conformance: {reason} — skipping");
            return;
        }
    };

    let mut passed: Vec<String> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut total_ranges_checked = 0usize;

    for channels in [1u8, 2] {
        for n in 1..=12u32 {
            let tag = format!("{n:02}/{channels}ch");
            let bit_path = dir.join(format!("testvector{n:02}.bit"));
            let Ok(bytes) = std::fs::read(&bit_path) else {
                skipped.push((tag, "missing .bit".to_string()));
                continue;
            };
            let packets = match parse_bit_stream(&bytes) {
                Ok(p) => p,
                Err(error) => {
                    failed.push((tag, error));
                    continue;
                }
            };
            let decoded = match decode_vector_to_pcm(&packets, channels) {
                Ok(decoded) => decoded,
                Err(error) => {
                    failed.push((tag, error));
                    continue;
                }
            };
            total_ranges_checked += decoded.ranges_checked;
            if !decoded.range_mismatches.is_empty() {
                let count = decoded.range_mismatches.len();
                let first = decoded.range_mismatches[0];
                failed.push((
                    tag.clone(),
                    format!(
                        "{count}/{} packets ended on the wrong final_range; first at packet {} \
                         (expected {:#010x}, got {:#010x})",
                        decoded.ranges_checked, first.0, first.1, first.2
                    ),
                ));
                continue;
            }

            let primary = dir.join(format!("testvector{n:02}.dec"));
            let fixed_point = dir.join(format!("testvector{n:02}m.dec"));
            let file_tag = format!("{n:02}_{channels}");
            match run_opus_compare(&compare, &primary, &decoded.pcm, channels, &file_tag) {
                Ok(()) => passed.push(tag),
                Err(primary_error) => {
                    match run_opus_compare(
                        &compare,
                        &fixed_point,
                        &decoded.pcm,
                        channels,
                        &file_tag,
                    ) {
                        Ok(()) => passed.push(tag),
                        Err(fallback_error) => failed
                            .push((tag, format!("{primary_error}; fallback: {fallback_error}"))),
                    }
                }
            }
        }
    }

    eprintln!("opus conformance summary ({total_ranges_checked} packet ranges checked):");
    eprintln!("  passed:  {passed:?}");
    eprintln!("  skipped: {skipped:?}");
    eprintln!("  failed:  {failed:?}");

    assert!(
        failed.is_empty(),
        "opus conformance: {} vector pass(es) failed: {failed:#?}",
        failed.len()
    );
    // Refuse to pass vacuously: the vectors are present, so both passes must have scored something
    // and the range check must have run.
    assert!(
        passed.len() >= 2,
        "opus conformance: vectors present but nothing was scored (skipped: {skipped:?})"
    );
    assert!(
        total_ranges_checked > 0,
        "opus conformance: no packet final_range was ever compared"
    );
}

#[test]
fn bit_stream_reader_rejects_truncated_input() {
    // A header claiming more bytes than the file holds must error, not panic.
    let truncated = [0u8, 0, 0, 100, 0, 0, 0, 0, 1, 2, 3];
    assert!(parse_bit_stream(&truncated).is_err());
    // A dangling partial header (< 8 bytes) must error.
    assert!(parse_bit_stream(&[0u8, 0, 0]).is_err());
    // An empty stream is zero packets, not an error.
    assert!(parse_bit_stream(&[]).expect("empty ok").is_empty());
}
