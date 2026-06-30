//! CELT-only conformance: decode pure-CELT (mono, 48 kHz) Opus streams with our [`CeltDecoder`] and
//! score them against libopus' own decode via `opus_compare` (RFC 6716 §6 tolerance metric).
//!
//! The RFC's official `testvectorNN` streams are full Opus (SILK + hybrid + CELT interleaved), so
//! they cannot validate the CELT layer alone until the SILK decoder lands. To validate CELT *now*,
//! a libopus oracle (`OPUS_SET_FORCE_MODE(MODE_CELT_ONLY)`) generates CELT-only `.bit` streams plus
//! libopus' reference decode `.dec` under `reference/opus/celt_only/` (gitignored, separately
//! generated). This harness decodes each `.bit` with the pure-Rust CELT decoder and asserts an
//! `opus_compare` pass — the first end-to-end validation of the whole CELT decode path.
//!
//! Like the main conformance harness, it is a no-op (prints a skip notice) when the vectors or
//! `opus_compare` are absent, so it never breaks CI on a machine without them.

use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::celt::decoder::CeltDecoder;
use siphon_rtp_codec::opus::packet::{self, Mode};

/// Conformance output rate (RFC 6716 §6 / `run_vectors.sh` uses 48000).
const CONFORMANCE_RATE_HZ: u32 = 48_000;

/// One packet from a `.bit` file: `[u32 BE len][u32 BE final_range][payload]` (libopus `opus_demo`).
struct BitPacket {
    payload: Vec<u8>,
}

/// Parse the `opus_demo` `.bit` framing. Returns `Err` on a truncated/implausible header.
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
        offset += 8; // skip len + final_range
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
        });
        offset += len;
    }
    Ok(packets)
}

/// The CELT-only vector directory (`reference/opus/celt_only`), if present.
fn vector_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/celt_only");
    dir.is_dir().then_some(dir)
}

/// Decode one CELT-only `.bit` stream to interleaved little-endian 16-bit mono PCM, statefully
/// across packets (the CELT decode ring + energy history persist). `Err(reason)` if a packet is not
/// a mono CELT-only frame our decoder handles.
fn decode_celt_only(packets: &[BitPacket]) -> Result<Vec<u8>, String> {
    let mut celt = CeltDecoder::new().map_err(|e| format!("CeltDecoder::new: {e:?}"))?;
    let mut pcm_bytes = Vec::new();
    let mut frame_pcm = vec![0i16; 5760]; // ≥ max Opus frame (120 ms @ 48 kHz)
    for (index, bp) in packets.iter().enumerate() {
        if bp.payload.is_empty() {
            continue; // DTX / empty packet
        }
        let parsed = packet::parse(&bp.payload).map_err(|e| format!("packet {index}: {e:?}"))?;
        if parsed.toc.mode() != Mode::Celt {
            return Err(format!(
                "packet {index}: not CELT-only (mode {:?})",
                parsed.toc.mode()
            ));
        }
        if parsed.toc.channels() != 1 {
            return Err(format!("packet {index}: not mono"));
        }
        let frame_size = parsed.toc.samples_per_frame(CONFORMANCE_RATE_HZ);
        for frame in parsed.frames() {
            if frame.is_empty() {
                continue;
            }
            let n = celt
                .decode(frame, &mut frame_pcm[..frame_size], frame_size)
                .map_err(|e| format!("packet {index}: decode: {e:?}"))?;
            for &sample in &frame_pcm[..n] {
                pcm_bytes.extend_from_slice(&sample.to_le_bytes());
            }
        }
    }
    Ok(pcm_bytes)
}

/// Run `opus_compare` over decoded PCM vs the reference `.dec` (mono). `Ok(())` on a pass.
fn run_opus_compare(reference_dec: &Path, decoded_pcm: &[u8]) -> Result<(), String> {
    let compare = Path::new("/tmp/opus_compare");
    if !compare.exists() {
        return Err("/tmp/opus_compare not built".to_string());
    }
    let tmp = std::env::temp_dir().join(format!("celt_only_{}.sw", std::process::id()));
    std::fs::write(&tmp, decoded_pcm).map_err(|e| e.to_string())?;
    let status = std::process::Command::new(compare)
        .arg("-r")
        .arg(CONFORMANCE_RATE_HZ.to_string())
        .arg(reference_dec)
        .arg(&tmp)
        .status()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    if status.success() {
        Ok(())
    } else {
        Err(format!("opus_compare exited {status}"))
    }
}

#[test]
fn celt_only_streams_match_libopus() {
    let Some(dir) = vector_dir() else {
        eprintln!("celt-only conformance: vectors not present — skipping");
        return;
    };
    let mut bit_files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "bit"))
                .collect()
        })
        .unwrap_or_default();
    bit_files.sort();
    if bit_files.is_empty() {
        eprintln!(
            "celt-only conformance: no .bit files in {} — skipping",
            dir.display()
        );
        return;
    }

    let mut passed = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    for bit_path in &bit_files {
        let name = bit_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let dec_path = bit_path.with_extension("dec");
        let Ok(bytes) = std::fs::read(bit_path) else {
            skipped.push((name, "unreadable .bit".to_string()));
            continue;
        };
        let packets = match parse_bit_stream(&bytes) {
            Ok(p) => p,
            Err(error) => {
                failed.push((name, error));
                continue;
            }
        };
        let pcm = match decode_celt_only(&packets) {
            Ok(pcm) => pcm,
            Err(reason) => {
                failed.push((name, format!("decode: {reason}")));
                continue;
            }
        };
        match run_opus_compare(&dec_path, &pcm) {
            Ok(()) => passed.push(name),
            Err(reason) if reason.contains("not built") => skipped.push((name, reason)),
            Err(reason) => failed.push((name, reason)),
        }
    }

    eprintln!("celt-only conformance: passed={passed:?} skipped={skipped:?} failed={failed:?}");
    assert!(
        failed.is_empty(),
        "celt-only: {} stream(s) failed: {failed:?}",
        failed.len()
    );
}
