//! The SILK-only oracle streams decoded through the **top-level** [`OpusDecoder`], with nothing
//! excluded — the gate that finally covers RFC 6716 §4.5.1 redundancy frames.
//!
//! `tests/silk_only_conformance.rs` drives [`SilkDecoder`] directly, and for that reason has to drop
//! a handful of packets from its comparison. A SILK-only packet with 17 or more bits left over
//! carries a redundancy flag and, behind it, a 5 ms CELT frame that libopus cross-fades over the
//! last 2.5 ms of the packet's output (`opus_decoder.c:452-480, 594-617`). None of that is the SILK
//! layer's work: it happens after SILK has finished, in bytes SILK never reads, and it also makes
//! whole-packet `final_range` unusable there, because libopus reports
//! `dec.rng ^ redundant_rng` (`opus_decoder.c:654`). Those packets were left out of that harness
//! rather than papered over, and this file is where they come back — at **full** strength, not as
//! an exemption:
//!
//! * every packet of every stream, redundancy-bearing or not, decoded through [`OpusDecoder`];
//! * whole-packet `final_range` compared exactly against the encoder value in the `.bit` file, which
//!   only matches if the redundancy frame was decoded *and* folded in;
//! * the resulting PCM held to within one LSB of libopus' own decode (`<name>.dec`), so the
//!   cross-fade has to land on the right samples with the right window, not merely consume the
//!   right bits.
//!
//! The streams are `reference/opus/silk_only/*.bit` (`reference/opus/gen_silk_only.sh`; recipe in
//! CONTRIBUTING.md): both source signals, NB/MB/WB, 10/20/40/60 ms, mono and stereo, LBRR-bearing.
//! `<name>.dec` beside each one is libopus' *stereo* 48 kHz decode, so the decoder here is built
//! stereo — which for a mono stream also exercises the mono-to-stereo arm.
//!
//! Skips gracefully when the vectors are absent, and refuses to pass vacuously: it requires that
//! streams were scored, that packet ranges were compared, and — the point of the file — that
//! redundancy-bearing packets were actually seen.
//!
//! [`SilkDecoder`]: siphon_rtp_codec::opus::silk::decoder::SilkDecoder

use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};

/// What `gen_silk_only.sh` decoded the reference with.
const REFERENCE_RATE_HZ: u32 = 48_000;
/// The `.dec` files are libopus' stereo decode; see the module docs.
const REFERENCE_CHANNELS: usize = 2;
/// A sample may sit at most this far from libopus' own decode. Same reasoning as
/// `opus_conformance.rs`: the redundancy frame is CELT, i.e. float, so its last bit may round the
/// other way; anything larger is a real divergence.
const MAX_LSB_DIFFERENCE: i32 = 1;

/// One packet from a `.bit` file: `[u32 BE len][u32 BE final_range][payload]` (libopus `opus_demo`).
struct BitPacket {
    payload: Vec<u8>,
    final_range: u32,
}

/// Parse the `opus_demo` `.bit` framing. Returns `Err` on a truncated/implausible header.
fn parse_bit_stream(bytes: &[u8]) -> Result<Vec<BitPacket>, String> {
    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if offset + 8 > bytes.len() {
            return Err(format!("truncated packet header at offset {offset}"));
        }
        let length = u32::from_be_bytes([
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
        if length > 1 << 20 {
            return Err(format!(
                "implausible packet length {length} at offset {offset}"
            ));
        }
        if offset + length > bytes.len() {
            return Err(format!("packet payload overruns file at offset {offset}"));
        }
        packets.push(BitPacket {
            payload: bytes[offset..offset + length].to_vec(),
            final_range,
        });
        offset += length;
    }
    Ok(packets)
}

/// Locate `reference/opus/silk_only`, if present.
fn stream_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_only");
    dir.is_dir().then_some(dir)
}

/// Read a little-endian 16-bit PCM file.
fn read_pcm16(path: &Path) -> Result<Vec<i16>, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

/// What one stream's decode proved.
#[derive(Default)]
struct StreamResult {
    packets: usize,
    ranges_checked: usize,
    redundancy_packets: usize,
    differing_samples: usize,
    total_samples: usize,
    worst_lsb: i32,
}

/// Decode one stream through [`OpusDecoder`] and check it against everything the oracle carries.
fn check_stream(bit_path: &Path, dec_path: &Path) -> Result<StreamResult, String> {
    let bytes = std::fs::read(bit_path).map_err(|error| format!("{error}"))?;
    let packets = parse_bit_stream(&bytes)?;
    let reference = read_pcm16(dec_path)?;

    let mut decoder = OpusDecoder::new(REFERENCE_RATE_HZ, REFERENCE_CHANNELS)
        .map_err(|error| format!("OpusDecoder::new: {error}"))?;
    let mut frame_pcm = vec![0i16; MAX_PACKET_SAMPLES * REFERENCE_CHANNELS];
    let mut decoded: Vec<i16> = Vec::with_capacity(reference.len());
    let mut result = StreamResult::default();

    for (index, packet) in packets.iter().enumerate() {
        if packet.payload.is_empty() {
            continue; // `opus_demo` writes nothing for a zero-length packet on the decode path.
        }
        let written = decoder
            .decode(
                Some(&packet.payload),
                &mut frame_pcm,
                MAX_PACKET_SAMPLES,
                false,
            )
            .map_err(|error| format!("packet {index}: decode failed: {error}"))?;
        decoded.extend_from_slice(&frame_pcm[..written * REFERENCE_CHANNELS]);
        result.packets += 1;
        if decoder.last_frame_had_redundancy() {
            result.redundancy_packets += 1;
        }
        // The encoder's value already includes `^ redundant_rng`, so this only matches if the
        // redundancy frame was decoded too — no exclusions, unlike the SILK-layer harness.
        if packet.final_range != 0 {
            result.ranges_checked += 1;
            if decoder.final_range() != packet.final_range {
                return Err(format!(
                    "packet {index}: final_range {:#010x}, expected {:#010x}{}",
                    decoder.final_range(),
                    packet.final_range,
                    if decoder.last_frame_had_redundancy() {
                        " (this packet carries a redundancy frame)"
                    } else {
                        ""
                    }
                ));
            }
        }
    }

    if decoded.len() != reference.len() {
        return Err(format!(
            "sample count differs: ours {}, libopus {}",
            decoded.len(),
            reference.len()
        ));
    }
    result.total_samples = decoded.len();
    for (index, (&ours, &theirs)) in decoded.iter().zip(reference.iter()).enumerate() {
        let delta = (i32::from(ours) - i32::from(theirs)).abs();
        if delta != 0 {
            result.differing_samples += 1;
            if delta > result.worst_lsb {
                result.worst_lsb = delta;
            }
            if delta > MAX_LSB_DIFFERENCE {
                return Err(format!(
                    "sample {index} differs by {delta} LSB (ours {ours}, libopus {theirs})"
                ));
            }
        }
    }
    Ok(result)
}

#[test]
fn silk_streams_decode_through_the_opus_layer_including_their_redundancy_frames() {
    let Some(dir) = stream_dir() else {
        eprintln!("opus redundancy conformance: reference/opus/silk_only absent — skipping");
        return;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "opus redundancy conformance: {} unreadable — skipping",
            dir.display()
        );
        return;
    };
    let mut streams: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "bit"))
        .collect();
    streams.sort();
    if streams.is_empty() {
        eprintln!("opus redundancy conformance: no .bit streams present — skipping");
        return;
    }

    let mut passed = 0usize;
    let mut skipped = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut total = StreamResult::default();

    for bit_path in &streams {
        let name = bit_path.file_stem().map_or_else(
            || "?".to_string(),
            |stem| stem.to_string_lossy().into_owned(),
        );
        let dec_path = bit_path.with_extension("dec");
        if !dec_path.exists() {
            skipped.push(name);
            continue;
        }
        match check_stream(bit_path, &dec_path) {
            Ok(result) => {
                passed += 1;
                total.packets += result.packets;
                total.ranges_checked += result.ranges_checked;
                total.redundancy_packets += result.redundancy_packets;
                total.differing_samples += result.differing_samples;
                total.total_samples += result.total_samples;
                total.worst_lsb = total.worst_lsb.max(result.worst_lsb);
            }
            Err(error) => failed.push((name, error)),
        }
    }

    eprintln!(
        "opus redundancy conformance: {passed} streams, {} packets, {} ranges checked, \
         {} redundancy-bearing packets; {}/{} samples differ from libopus (worst {} LSB)",
        total.packets,
        total.ranges_checked,
        total.redundancy_packets,
        total.differing_samples,
        total.total_samples,
        total.worst_lsb,
    );
    if !skipped.is_empty() {
        eprintln!("  skipped (no .dec): {skipped:?}");
    }

    assert!(
        failed.is_empty(),
        "opus redundancy conformance: {} stream(s) failed: {failed:#?}",
        failed.len()
    );
    assert!(
        passed > 0,
        "opus redundancy conformance: streams present but none were scored (skipped: {skipped:?})"
    );
    assert!(
        total.ranges_checked > 0,
        "opus redundancy conformance: no packet final_range was compared — the whole point of this \
         file is that the top-level decoder makes that check possible"
    );
    // The reason this file exists. If the generator ever stops producing redundancy-bearing packets
    // the gate is silently covering nothing, and that must be loud.
    assert!(
        total.redundancy_packets > 0,
        "opus redundancy conformance: not one packet carried a redundancy frame, so RFC 6716 \
         §4.5.1 went unexercised. Regenerate reference/opus/silk_only (gen_silk_only.sh)."
    );
}
