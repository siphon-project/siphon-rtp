//! Opus RFC 6716 conformance harness.
//!
//! RFC 6716 §6 defines conformance not as bit-exact PCM but via the `opus_compare` perceptual
//! quality metric run against the official test vectors (`testvectorNN.bit` / `.dec`). This harness:
//!
//! 1. Reads the `.bit` framing each test vector uses — a stream of packets, each prefixed by a
//!    big-endian `u32` length and a big-endian `u32` reference range-coder final value
//!    (libopus `opus_demo.c` `-d` path, `char_to_int`).
//! 2. Decodes every packet with our [`OpusDecoder`] into interleaved little-endian 16-bit PCM at the
//!    conformance rate (48 kHz), exactly as `opus_demo -d 48000 <ch>` writes `tmp.out`.
//! 3. Shells out to a locally built `opus_compare` (test-only C reference, never shipped) to score
//!    the decode against the reference `.dec`, asserting a pass for the vectors our decoder handles.
//!
//! Until the SILK + CELT decoders land, the decode step reports `Unsupported`; the harness then
//! reports each vector as **skipped** (with the gating reason) rather than failing, and the `.bit`
//! framing reader is exercised directly against the real vector files so the reader + packet parser
//! are validated against real data now. As decoder tiers land, vectors flip from skipped to
//! pass/fail and the harness prints the running tally.
//!
//! The harness is a no-op (prints a skip notice) when the vectors or `opus_compare` are absent, so
//! it never breaks CI on a machine without the (separately distributed, gitignored) vectors.

use std::path::{Path, PathBuf};

/// Conformance output rate (RFC 6716 §6 / `run_vectors.sh` uses 48000).
const CONFORMANCE_RATE_HZ: u32 = 48_000;

/// One packet from a `.bit` test-vector file.
struct BitPacket {
    /// The Opus packet payload bytes.
    payload: Vec<u8>,
    /// The reference *encoder's* range-coder final value (libopus `OPUS_GET_FINAL_RANGE`). A
    /// conformant decoder must end the packet on exactly this value — `opus_demo` itself rejects a
    /// mismatch as "Range coder state mismatch". This is the exact companion to the `opus_compare`
    /// tolerance metric and is asserted per packet once `OpusDecoder` exists; see
    /// `celt_only_conformance.rs` for the CELT-layer version already doing it.
    #[allow(dead_code)]
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

/// Decode one `.bit` vector to interleaved little-endian 16-bit PCM at [`CONFORMANCE_RATE_HZ`].
///
/// Returns `Err(reason)` when the decoder cannot yet handle the stream (any frame returns
/// `Unsupported`), so the caller can report the vector as *skipped* rather than failed.
#[allow(dead_code)]
fn decode_vector_to_pcm(packets: &[BitPacket], channels: u8) -> Result<Vec<u8>, String> {
    // Wired once OpusDecoder exists (Tier 5). For now, all vectors are gated as Unsupported.
    let _ = (packets, channels, CONFORMANCE_RATE_HZ);
    Err("OpusDecoder not yet implemented (SILK/CELT decode pending)".to_string())
}

/// Run `opus_compare` over a decoded buffer vs the reference `.dec`. Returns `Ok(())` on a pass.
#[allow(dead_code)]
fn run_opus_compare(reference_dec: &Path, decoded_pcm: &[u8], channels: u8) -> Result<(), String> {
    let compare = std::env::var_os("SIPHON_RTP_OPUS_COMPARE")
        .map_or_else(|| PathBuf::from("/tmp/opus_compare"), PathBuf::from);
    if !compare.exists() {
        return Err(format!(
            "{} not built (test-only C reference)",
            compare.display()
        ));
    }
    let tmp = std::env::temp_dir().join(format!("opus_decoded_{}.sw", std::process::id()));
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

#[test]
fn conformance_against_opus_compare() {
    let Some(dir) = vector_dir() else {
        eprintln!("opus conformance: test vectors not present — skipping");
        return;
    };
    let mut passed = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    for n in 1..=12u32 {
        let bit_path = dir.join(format!("testvector{n:02}.bit"));
        let dec_path = dir.join(format!("testvector{n:02}.dec"));
        let Ok(bytes) = std::fs::read(&bit_path) else {
            skipped.push((n, "missing .bit".to_string()));
            continue;
        };
        let packets = match parse_bit_stream(&bytes) {
            Ok(p) => p,
            Err(error) => {
                failed.push((n, error));
                continue;
            }
        };
        // Conformance vectors are decoded as mono (channels=1) per run_vectors.sh's first pass.
        match decode_vector_to_pcm(&packets, 1) {
            Ok(pcm) => match run_opus_compare(&dec_path, &pcm, 1) {
                Ok(()) => passed.push(n),
                Err(error) => failed.push((n, error)),
            },
            Err(reason) => skipped.push((n, reason)),
        }
    }

    eprintln!("opus conformance summary:");
    eprintln!("  passed:  {passed:?}");
    eprintln!("  skipped: {skipped:?}");
    eprintln!("  failed:  {failed:?}");

    // A vector that *attempted* a full decode but failed opus_compare is a real regression.
    assert!(
        failed.is_empty(),
        "opus conformance: {} vector(s) failed: {failed:?}",
        failed.len()
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
