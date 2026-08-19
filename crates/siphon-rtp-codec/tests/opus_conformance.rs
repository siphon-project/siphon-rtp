//! Opus RFC 6716 conformance — **the acceptance gate for the whole decoder**.
//!
//! All 12 official test vectors, in the mono and the stereo pass, decoded by [`OpusDecoder`] and
//! held to three checks. Read the `.bit` framing (a stream of packets, each prefixed by a big-endian
//! `u32` length and a big-endian `u32` reference range value — libopus `opus_demo.c` `-d`,
//! `char_to_int`), decode every packet at 48 kHz exactly as `opus_demo -d 48000 <ch>` writes
//! `tmp.out`, and then:
//!
//! 1. **Exact `final_range` on every packet.** This is the strict one. `opus_compare` is a
//!    *tolerance* metric that a subtly wrong decoder can pass; the final range is the encoder's
//!    range-coder register at the end of the packet, so matching it means every symbol was read, in
//!    order, under the same probability model — including the redundancy frame the top-level decoder
//!    folds in (`rangeFinal = dec.rng ^ redundant_rng`, `opus_decoder.c:654`). `opus_demo` itself
//!    rejects a mismatch as "Range coder state mismatch"; so does this harness, on every packet of
//!    every vector.
//! 2. **Within one LSB of libopus' own decode** of the same bitstream, produced by running the
//!    locally built `opus_demo` over the same `.bit` file. RFC 6716 §6 accepts a float and a
//!    fixed-point decoder as equally conformant, so it does not *require* this — but this port is of
//!    libopus' float build, so anything beyond a last-bit rounding difference in the `i16`
//!    conversion is a bug, and this catches what the tolerance metric would wave through.
//! 3. **The RFC 6716 §6 `opus_compare` metric** against the reference `.dec`, exactly as
//!    `tests/run_vectors.sh` runs it (mono without `-s`, stereo with; `testvectorNN.dec` first, then
//!    the `testvectorNNm.dec` companion).
//!
//! ## When the reference decode itself does not pass
//!
//! `run_vectors.sh` accepts a pass against *either* `testvectorNN.dec` *or* `testvectorNNm.dec`,
//! because a given vector's distributed `.dec` may be the other build's reference. A vector set
//! carrying only one of the two therefore has passes that **libopus' own decoder fails**. That is a
//! gap in the vector set, not in the decoder, and the harness says so explicitly instead of either
//! failing on it or quietly excluding it: it scores libopus' decode through the same `opus_compare`
//! invocation, and
//!
//! * libopus passes and we do not → **failure**, a real regression;
//! * neither passes → reported as a reference-set gap, and check 2 (within one LSB of that same
//!   libopus decode) is what stands in for it — a strictly harder bar than the metric it replaces.
//!
//! Without `opus_demo` that arm cannot run, and a vector whose reference does not pass is reported
//! as skipped rather than assumed good.
//!
//! The harness is a no-op (prints a skip notice) when the vectors or the C tools are absent, so it
//! never breaks CI on a machine without the (separately distributed, gitignored) vectors — but it
//! refuses to pass *vacuously*: with everything present, every vector must have been decoded, every
//! packet's range compared, and at least one vector scored by `opus_compare` in each pass.

mod common;

use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};

/// Conformance output rate (RFC 6716 §6 / `run_vectors.sh` uses 48000).
const CONFORMANCE_RATE_HZ: u32 = 48_000;

/// How far a sample may sit from libopus' own decode of the same bitstream.
///
/// One LSB of a 16-bit sample. Both decoders run the same float synthesis and round with the same
/// `FLOAT2INT16`, so the only legitimate difference is a value landing either side of a rounding
/// boundary after a differently-ordered float accumulation. Anything larger is a real divergence:
/// a wrong coefficient, a missed state update, a mis-timed cross-fade.
const MAX_LSB_DIFFERENCE: i32 = 1;

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
    common::opus_compare_or_reason()
}

/// Path to the locally built `opus_demo`, which is what produces libopus' own decode of a vector.
/// Defaults to `opus_demo` beside `opus_compare`, since the same build emits both.
fn opus_demo_path(compare: &Path) -> Option<PathBuf> {
    let demo = std::env::var_os("SIPHON_RTP_OPUS_DEMO")
        .map_or_else(|| compare.with_file_name("opus_demo"), PathBuf::from);
    demo.exists().then_some(demo)
}

/// Decode a `.bit` vector with libopus itself: `opus_demo -d 48000 <channels> <bit> <out>`.
fn libopus_decode(
    demo: &Path,
    bit_path: &Path,
    channels: u8,
    tag: &str,
) -> Result<Vec<u8>, String> {
    let tmp = std::env::temp_dir().join(format!("opus_libopus_{}_{tag}.sw", std::process::id()));
    let status = std::process::Command::new(demo)
        .arg("-d")
        .arg(CONFORMANCE_RATE_HZ.to_string())
        .arg(channels.to_string())
        .arg(bit_path)
        .arg(&tmp)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("opus_demo: {error}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("opus_demo exited {status}"));
    }
    let pcm = std::fs::read(&tmp).map_err(|error| error.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    Ok(pcm)
}

/// Compare our interleaved 16-bit PCM with libopus' own, requiring the same length and no sample
/// further than [`MAX_LSB_DIFFERENCE`] away. Returns a one-line summary of how close it actually is.
fn compare_with_libopus(ours: &[u8], theirs: &[u8]) -> Result<String, String> {
    if ours.len() != theirs.len() {
        return Err(format!(
            "sample count differs: ours {} bytes, libopus {} bytes",
            ours.len(),
            theirs.len()
        ));
    }
    let sample = |bytes: &[u8], index: usize| -> i32 {
        i32::from(i16::from_le_bytes([bytes[2 * index], bytes[2 * index + 1]]))
    };
    let count = ours.len() / 2;
    let mut differing = 0usize;
    let mut worst = 0i32;
    let mut worst_at = 0usize;
    for index in 0..count {
        let delta = (sample(ours, index) - sample(theirs, index)).abs();
        if delta != 0 {
            differing += 1;
            if delta > worst {
                worst = delta;
                worst_at = index;
            }
        }
    }
    let summary = format!(
        "vs libopus: {differing}/{count} samples differ ({:.4} %), worst {worst} LSB at sample \
         {worst_at}",
        100.0 * differing as f64 / count as f64
    );
    if worst > MAX_LSB_DIFFERENCE {
        Err(summary)
    } else {
        Ok(summary)
    }
}

/// Run `opus_compare` over a decoded buffer vs the reference `.dec`, returning the tool's own
/// verdict line — the quality percentage on a pass, the weighted error on a failure. Reporting the
/// number rather than just the exit status is what makes a regression readable: "96.5 %" is a
/// borderline decode, "0.39 weighted error" is a broken one, and the two need different debugging.
fn run_opus_compare(
    compare: &Path,
    reference_dec: &Path,
    decoded_pcm: &[u8],
    channels: u8,
    tag: &str,
) -> Result<String, String> {
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
    let output = command.output().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = stdout
        .lines()
        .chain(stderr.lines())
        .filter(|line| !line.starts_with("Test vector"))
        .collect::<Vec<_>>()
        .join(" | ");
    if output.status.success() {
        Ok(report)
    } else {
        Err(format!("opus_compare exited {}: {report}", output.status))
    }
}

/// Score a decoded buffer against whichever reference decode the vector set carries — `.dec` first,
/// then the `m.dec` companion, exactly as `run_vectors.sh` does.
fn score_against_references(
    compare: &Path,
    dir: &Path,
    vector: u32,
    pcm: &[u8],
    channels: u8,
    file_tag: &str,
) -> Result<String, String> {
    let primary = dir.join(format!("testvector{vector:02}.dec"));
    let companion = dir.join(format!("testvector{vector:02}m.dec"));
    match run_opus_compare(compare, &primary, pcm, channels, file_tag) {
        Ok(report) => Ok(report),
        Err(primary_error) => {
            match run_opus_compare(compare, &companion, pcm, channels, file_tag) {
                Ok(report) => Ok(report),
                Err(companion_error) => {
                    Err(format!("{primary_error}; companion: {companion_error}"))
                }
            }
        }
    }
}

/// The acceptance gate: all 12 official vectors, mono **and** stereo. See the module docs for the
/// three checks and for how a vector whose reference decode libopus itself fails is handled.
#[test]
#[allow(clippy::too_many_lines)]
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
    let demo = opus_demo_path(&compare);
    if demo.is_none() {
        eprintln!(
            "opus conformance: opus_demo not built beside opus_compare — the within-one-LSB check \
             and the reference-set-gap arm are unavailable"
        );
    }

    let mut passed: Vec<String> = Vec::new();
    let mut reference_gaps: Vec<String> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut total_ranges_checked = 0usize;
    let mut decoded_passes = 0usize;
    let mut lsb_checked = 0usize;

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
            decoded_passes += 1;
            total_ranges_checked += decoded.ranges_checked;
            // Debugging hook: `SIPHON_RTP_OPUS_DUMP=<dir>` writes each decoded stream out so it can
            // be diffed against `opus_demo -d 48000 <ch>` by hand. `opus_compare` scores a whole
            // file; finding *which packet* first diverges needs the raw PCM.
            if let Some(dump) = std::env::var_os("SIPHON_RTP_OPUS_DUMP") {
                let path =
                    PathBuf::from(dump).join(format!("ours_testvector{n:02}_{channels}ch.sw"));
                let _ = std::fs::write(path, &decoded.pcm);
            }

            // ── Check 1: exact per-packet final_range ────────────────────────────────────────────
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

            let file_tag = format!("{n:02}_{channels}");
            // ── Check 2: within one LSB of libopus' own decode ───────────────────────────────────
            let libopus_pcm = match demo.as_ref() {
                Some(demo) => match libopus_decode(demo, &bit_path, channels, &file_tag) {
                    Ok(pcm) => Some(pcm),
                    Err(error) => {
                        failed.push((tag.clone(), format!("libopus reference decode: {error}")));
                        continue;
                    }
                },
                None => None,
            };
            let mut lsb_report = String::new();
            if let Some(theirs) = libopus_pcm.as_ref() {
                match compare_with_libopus(&decoded.pcm, theirs) {
                    Ok(report) => {
                        lsb_checked += 1;
                        lsb_report = report;
                    }
                    Err(report) => {
                        failed.push((tag.clone(), report));
                        continue;
                    }
                }
            }

            // ── Check 3: the RFC 6716 §6 opus_compare metric ─────────────────────────────────────
            match score_against_references(&compare, &dir, n, &decoded.pcm, channels, &file_tag) {
                Ok(report) => passed.push(format!("{tag} {report} | {lsb_report}")),
                Err(our_error) => {
                    // Does libopus' own decode pass the references this vector set carries?
                    let Some(theirs) = libopus_pcm.as_ref() else {
                        skipped.push((
                            tag,
                            format!("{our_error} (no opus_demo to check the reference set)"),
                        ));
                        continue;
                    };
                    let reference_tag = format!("ref_{file_tag}");
                    match score_against_references(
                        &compare,
                        &dir,
                        n,
                        theirs,
                        channels,
                        &reference_tag,
                    ) {
                        // libopus passes and we do not: a real regression.
                        Ok(their_report) => failed.push((
                            tag,
                            format!("libopus passes this reference ({their_report}) but we do not: {our_error}"),
                        )),
                        // Neither passes: this vector set has no reference decode for this build.
                        // Check 2 above already held us to within one LSB of libopus.
                        Err(their_error) => reference_gaps.push(format!(
                            "{tag} neither decode passes the shipped reference (ours: {our_error}) \
                             (libopus: {their_error}) — {lsb_report}"
                        )),
                    }
                }
            }
        }
    }

    eprintln!("opus conformance summary ({total_ranges_checked} packet ranges checked):");
    for entry in &passed {
        eprintln!("  pass   {entry}");
    }
    for entry in &reference_gaps {
        eprintln!("  refgap {entry}");
    }
    for (tag, reason) in &skipped {
        eprintln!("  skip   {tag}: {reason}");
    }
    for (tag, reason) in &failed {
        eprintln!("  FAIL   {tag}: {reason}");
    }

    assert!(
        failed.is_empty(),
        "opus conformance: {} vector pass(es) failed: {failed:#?}",
        failed.len()
    );
    // Refuse to pass vacuously. With the vectors present every pass must have decoded, every
    // packet's range must have been compared, and `opus_compare` must have scored something in each
    // of the mono and stereo passes.
    assert_eq!(
        decoded_passes, 24,
        "opus conformance: {decoded_passes}/24 vector passes decoded (skipped: {skipped:?})"
    );
    assert!(
        total_ranges_checked > 0,
        "opus conformance: no packet final_range was ever compared"
    );
    if demo.is_some() {
        assert_eq!(
            lsb_checked, 24,
            "opus conformance: only {lsb_checked}/24 passes were checked against libopus' own decode"
        );
    }
    assert!(
        passed.iter().any(|entry| entry.contains("/1ch"))
            && passed.iter().any(|entry| entry.contains("/2ch")),
        "opus conformance: opus_compare scored nothing in one of the two passes \
         (passed: {passed:?}, reference gaps: {reference_gaps:?})"
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
