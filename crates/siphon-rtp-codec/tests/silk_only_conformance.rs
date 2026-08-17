//! SILK-only conformance: decode pure-SILK Opus streams end to end with [`SilkDecoder`] and check
//! the PCM against libopus' own decode — first sample for sample, then through `opus_compare` (the
//! RFC 6716 §6 tolerance metric).
//!
//! This is the acceptance gate for the whole SILK layer. Everything upstream of synthesis already
//! has an intermediate-state oracle (`silk_header_conformance`, `silk_nlsf_conformance`,
//! `silk_excitation_conformance` — the last of which also pins the range coder's `rng`/`tell` at the
//! end of **every** SILK frame, which is this layer's own `final_range` check at finer than
//! per-packet resolution). What none of those can say is whether the decoded *audio* is right: the
//! synthesis filters, the stereo unmixing and the resampler produce no entropy-coder state at all.
//! This harness is what covers them.
//!
//! The vectors are `reference/opus/silk_only/*.bit` with libopus' reference decode beside them
//! (`reference/opus/gen_silk_only.sh`; recipe in CONTRIBUTING.md). They span both source signals,
//! NB/MB/WB, 10/20/40/60 ms, mono and stereo, and LBRR-bearing streams.
//!
//! Three things about the comparison are deliberate:
//!
//! * **Bit-exactness is the primary check.** RFC 6716 §6 only requires passing `opus_compare`, which
//!   a subtly wrong decoder can do. This port is integer-faithful to the reference fixed-point
//!   arithmetic all the way through the resampler, so it produces libopus' output *exactly*, and
//!   that is what is asserted. `opus_compare` runs afterwards as the standard-defined gate.
//! * **Decode to stereo, compare with `-s`.** The reference `.dec` is `opus_demo -d 48000 2`, i.e.
//!   always 2-channel; `opus_compare` reads its *reference* file as 2-channel unconditionally. Our
//!   decode therefore runs with `nChannelsAPI = 2` — which for a mono stream is a duplication and
//!   for a stereo stream exercises the §4.2.8 unmixing — and the comparison is run in stereo mode so
//!   a broken side channel cannot hide behind a mono fold.
//! * **Packets carrying an Opus-layer redundancy frame are excluded, not fudged.** When a SILK-only
//!   packet has 17 or more bits left over, libopus reads a redundancy flag and a 5 ms CELT frame
//!   *after* the SILK layer and cross-fades it over the last 2.5 ms of the output
//!   (`opus_decoder.c:452-480, 594-600`). That is the top-level Opus decoder's behaviour, not this
//!   layer's, and it is also why whole-packet `final_range` is unusable here. Those packets are
//!   detected from the spare-bit count, and their samples are dropped from **both** sides of the
//!   comparison rather than being papered over — the run reports how many. They are covered by
//!   `opus_conformance` once the top-level decoder lands.
//!
//! Like the other conformance harnesses it skips gracefully when the vectors or `opus_compare` are
//! absent, and refuses to pass vacuously: with vectors present at least one stream must have been
//! scored, and the run must have covered every internal rate, every frame duration, both channel
//! counts and at least one LBRR-bearing stream.

use std::collections::BTreeSet;
use std::ops::Range;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::packet::{self, Mode};
use siphon_rtp_codec::opus::range_coder::RangeDecoder;
use siphon_rtp_codec::opus::silk::decoder::SilkDecoder;
use siphon_rtp_codec::opus::silk::frame::LossFlag;
use siphon_rtp_codec::opus::silk::types::InternalRate;

/// Conformance output rate — what `gen_silk_only.sh` decoded the reference with.
const REFERENCE_RATE_HZ: u32 = 48_000;
/// Output channels. The reference `.dec` is always 2-channel; see the module docs.
const REFERENCE_CHANNELS: usize = 2;
/// `opus_decoder.c:454` — the spare-bit threshold above which libopus looks for a redundancy frame.
const REDUNDANCY_SPARE_BITS: i32 = 17;

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
        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
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
        });
        offset += length;
    }
    Ok(packets)
}

/// What the run exercised, so it can refuse to pass vacuously.
#[derive(Debug, Default)]
struct Coverage {
    rates: BTreeSet<usize>,
    durations: BTreeSet<usize>,
    channel_counts: BTreeSet<usize>,
    packets: usize,
    samples: usize,
    lbrr_streams: usize,
    redundancy_packets: usize,
}

impl Coverage {
    fn absorb(&mut self, other: &Coverage) {
        self.rates.extend(other.rates.iter());
        self.durations.extend(other.durations.iter());
        self.channel_counts.extend(other.channel_counts.iter());
        self.packets += other.packets;
        self.samples += other.samples;
        self.lbrr_streams += other.lbrr_streams;
        self.redundancy_packets += other.redundancy_packets;
    }
}

/// One decoded stream: interleaved 48 kHz stereo PCM, plus the interleaved-sample ranges the
/// top-level Opus decoder would have overwritten with a redundancy frame.
struct Decoded {
    pcm: Vec<i16>,
    excluded: Vec<Range<usize>>,
    coverage: Coverage,
}

/// Decode one SILK-only `.bit` stream.
fn decode_silk_only(packets: &[BitPacket]) -> Result<Decoded, String> {
    let mut silk = SilkDecoder::new(REFERENCE_RATE_HZ, REFERENCE_CHANNELS)
        .map_err(|error| format!("SilkDecoder::new: {error:?}"))?;
    let mut coverage = Coverage::default();
    let mut pcm: Vec<i16> = Vec::new();
    let mut excluded: Vec<Range<usize>> = Vec::new();
    // 60 ms at 48 kHz, stereo.
    let mut frame_pcm = vec![0i16; 2880 * REFERENCE_CHANNELS];
    let mut saw_lbrr = false;

    for (index, bit_packet) in packets.iter().enumerate() {
        if bit_packet.payload.is_empty() {
            continue; // DTX / dropped packet: libopus emits no side info for it.
        }
        let parsed = packet::parse(&bit_packet.payload)
            .map_err(|error| format!("packet {index}: {error:?}"))?;
        if parsed.toc.mode() != Mode::Silk {
            return Err(format!(
                "packet {index}: not SILK-only (mode {:?}) — the generator must only produce SILK",
                parsed.toc.mode()
            ));
        }
        if parsed.frame_count() != 1 {
            return Err(format!(
                "packet {index}: {} Opus frames; the SILK-only generator emits one per packet",
                parsed.frame_count()
            ));
        }
        let frame = parsed.frames()[0];
        if frame.is_empty() {
            continue;
        }

        let channel_count = usize::from(parsed.toc.channels());
        let rate = InternalRate::from_bandwidth(parsed.toc.bandwidth());
        let duration_ms =
            parsed.toc.samples_per_frame(REFERENCE_RATE_HZ) / (REFERENCE_RATE_HZ as usize / 1000);
        silk.configure(channel_count, rate, duration_ms)
            .map_err(|error| format!("packet {index}: configure: {error:?}"))?;

        let start = pcm.len();
        let mut range = RangeDecoder::new(frame);
        let produced = silk
            .decode(Some(&mut range), LossFlag::Normal, &mut frame_pcm)
            .map_err(|error| format!("packet {index}: decode: {error:?}"))?;
        pcm.extend_from_slice(&frame_pcm[..produced * REFERENCE_CHANNELS]);

        // The SILK layer left this many bits unread. Above the threshold the top-level decoder reads
        // a redundancy flag and folds a CELT frame into the tail of this packet's output.
        if range.tell() + REDUNDANCY_SPARE_BITS <= 8 * frame.len() as i32 {
            excluded.push(start..pcm.len());
            coverage.redundancy_packets += 1;
        }

        if silk
            .channel(0)
            .map(|channel| channel.lbrr_flag)
            .unwrap_or(false)
        {
            saw_lbrr = true;
        }
        coverage.rates.insert(rate.khz());
        coverage.durations.insert(duration_ms);
        coverage.channel_counts.insert(channel_count);
        coverage.packets += 1;
        coverage.samples += produced;
    }
    if saw_lbrr {
        coverage.lbrr_streams = 1;
    }
    Ok(Decoded {
        pcm,
        excluded,
        coverage,
    })
}

/// Drop every excluded range from `samples`, in interleaved-sample units.
fn without_excluded(samples: &[i16], excluded: &[Range<usize>]) -> Vec<i16> {
    if excluded.is_empty() {
        return samples.to_vec();
    }
    let mut kept = Vec::with_capacity(samples.len());
    let mut cursor = 0usize;
    for range in excluded {
        let end = range.start.min(samples.len());
        if cursor < end {
            kept.extend_from_slice(&samples[cursor..end]);
        }
        cursor = range.end.min(samples.len()).max(cursor);
    }
    if cursor < samples.len() {
        kept.extend_from_slice(&samples[cursor..]);
    }
    kept
}

/// Little-endian 16-bit PCM bytes.
fn to_bytes(samples: &[i16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(samples.len() * 2);
    for &sample in samples {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    bytes
}

/// Run `opus_compare -s` over two in-memory PCM buffers. `Ok(())` on a pass.
///
/// The locally built, test-only C reference. Its location is `$SIPHON_RTP_OPUS_COMPARE`, falling
/// back to `/tmp/opus_compare` — the override matters because each worktree has its own untracked
/// `reference/` tree, so the oracle is normally built once and shared.
fn run_opus_compare(reference: &[i16], decoded: &[i16], label: &str) -> Result<(), String> {
    let compare = std::env::var_os("SIPHON_RTP_OPUS_COMPARE")
        .map_or_else(|| PathBuf::from("/tmp/opus_compare"), PathBuf::from);
    if !compare.exists() {
        return Err(format!("{} not built", compare.display()));
    }
    let stem = label.replace(['/', '.'], "_");
    let reference_path =
        std::env::temp_dir().join(format!("silk_only_ref_{}_{stem}.sw", std::process::id()));
    let decoded_path =
        std::env::temp_dir().join(format!("silk_only_out_{}_{stem}.sw", std::process::id()));
    std::fs::write(&reference_path, to_bytes(reference)).map_err(|error| error.to_string())?;
    std::fs::write(&decoded_path, to_bytes(decoded)).map_err(|error| error.to_string())?;
    let status = std::process::Command::new(&compare)
        .arg("-s")
        .arg("-r")
        .arg(REFERENCE_RATE_HZ.to_string())
        .arg(&reference_path)
        .arg(&decoded_path)
        .status()
        .map_err(|error| error.to_string())?;
    let _ = std::fs::remove_file(&reference_path);
    let _ = std::fs::remove_file(&decoded_path);
    if status.success() {
        Ok(())
    } else {
        Err(format!("opus_compare exited {status}"))
    }
}

/// `reference/opus/silk_only`, if present.
fn vector_dir() -> Option<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_only");
    directory.is_dir().then_some(directory)
}

/// Score one stream: bit-exactness first, then the RFC 6716 §6 metric.
fn score_stream(bit_path: &Path, name: &str) -> Result<Coverage, String> {
    let bytes = std::fs::read(bit_path).map_err(|error| format!("unreadable .bit: {error}"))?;
    let packets = parse_bit_stream(&bytes)?;
    let decoded = decode_silk_only(&packets)?;

    let reference_bytes = std::fs::read(bit_path.with_extension("dec"))
        .map_err(|error| format!("unreadable .dec: {error}"))?;
    let reference: Vec<i16> = reference_bytes
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    if reference.len() != decoded.pcm.len() {
        return Err(format!(
            "sample count {} != libopus {} — the decode produced the wrong number of samples",
            decoded.pcm.len(),
            reference.len()
        ));
    }

    let ours = without_excluded(&decoded.pcm, &decoded.excluded);
    let theirs = without_excluded(&reference, &decoded.excluded);

    // The exact check. A single differing sample names itself.
    if let Some((index, (&mine, &theirs_sample))) = ours
        .iter()
        .zip(theirs.iter())
        .enumerate()
        .find(|(_, (a, b))| a != b)
    {
        return Err(format!(
            "sample {index} is {mine}, libopus says {theirs_sample} \
             ({} of {} samples differ)",
            ours.iter()
                .zip(theirs.iter())
                .filter(|(a, b)| a != b)
                .count(),
            ours.len()
        ));
    }

    run_opus_compare(&theirs, &ours, name)?;
    Ok(decoded.coverage)
}

#[test]
fn silk_only_streams_match_libopus() {
    let Some(directory) = vector_dir() else {
        eprintln!("silk-only conformance: vectors not present — skipping");
        return;
    };
    let mut bit_files: Vec<PathBuf> = std::fs::read_dir(&directory)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "bit"))
                .collect()
        })
        .unwrap_or_default();
    bit_files.sort();
    if bit_files.is_empty() {
        eprintln!(
            "silk-only conformance: no .bit files in {} — skipping",
            directory.display()
        );
        return;
    }

    let mut passed = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    let mut total = Coverage::default();

    for bit_path in &bit_files {
        let name = bit_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        match score_stream(bit_path, &name) {
            Ok(coverage) => {
                total.absorb(&coverage);
                passed.push(name);
            }
            Err(reason) if reason.contains("not built") => skipped.push((name, reason)),
            Err(reason) => failed.push((name, reason)),
        }
    }

    eprintln!(
        "silk-only conformance: {} passed, {} skipped, {} failed",
        passed.len(),
        skipped.len(),
        failed.len()
    );
    eprintln!(
        "  coverage: {} packets, {} samples/channel, rates {:?} kHz, durations {:?} ms, \
         channel counts {:?}, {} LBRR-bearing streams; {} packet(s) excluded as carrying an \
         Opus-layer redundancy frame",
        total.packets,
        total.samples,
        total.rates,
        total.durations,
        total.channel_counts,
        total.lbrr_streams,
        total.redundancy_packets,
    );
    if !failed.is_empty() {
        eprintln!("  failed: {failed:?}");
    }
    assert!(
        failed.is_empty(),
        "silk-only: {} stream(s) failed: {failed:?}",
        failed.len()
    );
    // Vectors were present, so at least one stream must actually have been scored. Without this the
    // test passes vacuously when `opus_compare` is missing and everything skips.
    assert!(
        !passed.is_empty(),
        "silk-only: {} stream(s) present but none scored — is opus_compare built? skipped={skipped:?}",
        bit_files.len()
    );
    // And it must have been a real sweep, not one lucky configuration.
    assert_eq!(
        total.rates,
        BTreeSet::from([8usize, 12, 16]),
        "every internal rate must have been decoded"
    );
    assert_eq!(
        total.durations,
        BTreeSet::from([10usize, 20, 40, 60]),
        "every SILK frame duration must have been decoded"
    );
    assert_eq!(
        total.channel_counts,
        BTreeSet::from([1usize, 2]),
        "both mono and stereo streams must have been decoded"
    );
    assert!(
        total.lbrr_streams > 0,
        "at least one LBRR-bearing stream must have been decoded"
    );
    // The exclusion is meant to be a handful of packets, not a way to skip half the corpus.
    assert!(
        total.redundancy_packets * 1000 < total.packets,
        "{} of {} packets were excluded as redundancy-bearing — that is too many to be the \
         documented Opus-layer corner case",
        total.redundancy_packets,
        total.packets
    );
}
