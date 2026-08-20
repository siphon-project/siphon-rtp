//! The **bandwidth-switch** path of the Opus encoder, held to the same bar as everything else:
//! libopus must end every packet of a switching stream on exactly the range value our encoder
//! reported, and the redundancy frame that hides the seam must actually be there.
//!
//! # Why this needs its own file
//!
//! `opus_encode_conformance.rs` sweeps 111 fixed configurations and one mode-switching stream. A
//! *bandwidth* switch is a different mechanism and neither of those reaches it:
//!
//! * A fixed configuration decides its bandwidth on the first packet and never revisits it.
//! * A mode switch (SILK ↔ CELT) is decided at the Opus layer and signalled by `celt_to_silk`. A
//!   bandwidth switch is decided *inside SILK*, which owns its internal rate, ramps its input
//!   bandwidth down over 256 frames before it will move, and then asks the Opus layer for a
//!   redundancy frame by raising `switchReady` (`silk/control_audio_bandwidth.c:88`, `:116`). The
//!   Opus layer answers with `opusCanSwitch`, emits a 5 ms CELT frame **after** the payload of the
//!   packet that asked, sets `silk_bw_switch`, and emits a second one **before** the payload of the
//!   next packet — the one where the new rate actually starts (`opus_encoder.c:2065-2082`,
//!   `:1765-1772`). Two redundancy frames, one on each side of the seam, in opposite positions.
//!
//! Get any of that wrong and the stream is either illegal or silently seamful. Both show up here:
//!
//! 1. **Exact `final_range`, every packet, through libopus.** `opus_demo -d` aborts with "Range
//!    coder state mismatch" unless its decoder ends each packet on the value our encoder wrote
//!    beside it. That is what proves the redundancy frames are where libopus expects them and carry
//!    what libopus expects, because their own range value is XORed into the packet's
//!    (`opus_decoder.c:654`).
//! 2. **The redundancy actually fires.** Counted, and required to be non-zero — on a stream whose
//!    TOC *mode* never changes, so a mode switch cannot be what produced it. Without this the whole
//!    path could stop being exercised and every other check here would still pass.
//! 3. **Both decoders agree on the audio.** Our [`OpusDecoder`] and `opus_demo -d` decode the same
//!    stream and must produce the same samples — sample-exact on the SILK-only sweeps, within one
//!    LSB once CELT is in the packet. `final_range` cannot see a cross-fade applied over the wrong
//!    window; this can.
//!
//! Skips gracefully when the reference tree is absent, and refuses to pass vacuously: it requires
//! that bandwidths actually changed, that redundancy actually fired, and that a non-trivial number
//! of packets were scored.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};
use siphon_rtp_codec::opus::enc::decision::{Application, SignalHint};
use siphon_rtp_codec::opus::enc::encoder::{OpusEncoder, RateControl};
use siphon_rtp_codec::opus::packet::{self, Bandwidth, Mode};

/// Everything here runs at 48 kHz, the rate `opus_demo` was driven at.
const REFERENCE_RATE_HZ: u32 = 48_000;

/// 20 ms packets: the SILK transition ramp is defined in 20 ms frames, so this is the duration at
/// which one packet is one step of it.
const FRAME_SIZE: usize = 960;

/// libopus' complexity for the comparison runs, matching `opus_encode_conformance.rs`: the highest
/// setting at which it does not run the tonality analysis this encoder does not implement.
const COMPARISON_COMPLEXITY: i32 = 6;

/// The reference vector opens with near-silence; skip past it.
const SKIP_MS: usize = 2_000;

/// How far a sample of our decode may sit from libopus' decode of the same stream once CELT is
/// involved. Zero is enforced on the SILK-only sweeps; see `opus_encode_conformance.rs` for why the
/// split is the right bar and not a relaxation.
const MAX_LSB_DIFFERENCE: i32 = 1;

fn reference_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus");
    dir.is_dir().then_some(dir)
}

fn opus_demo() -> Option<PathBuf> {
    let path = reference_dir()?.join("build/opus_demo");
    path.is_file().then_some(path)
}

fn read_pcm(path: &Path) -> Result<Vec<i16>, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    Ok(bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

/// One encoded packet with the encoder's own final range.
struct EncodedPacket {
    payload: Vec<u8>,
    final_range: u32,
}

/// How a stream's coded bandwidth is driven from packet to packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sweep {
    /// Alternate the *cap* between two bandwidths. A cap is the softer of the two knobs: lowering
    /// it takes effect at once at the Opus layer, but raising it only matters once SILK's own
    /// `allowBandwidthSwitch` lets the automatic choice run again — which is exactly the path a
    /// `maxplaybackrate` renegotiation takes.
    Cap(Bandwidth, Bandwidth),
    /// Walk the *forced* bandwidth up and down the whole NB→MB→WB→SWB→FB ladder
    /// (`OPUS_SET_BANDWIDTH`), which also drags the mode across the SILK/hybrid boundary.
    ForcedLadder,
}

/// One switching stream.
struct Stream {
    label: &'static str,
    channels: usize,
    application: Application,
    bitrate_bps: i32,
    /// Packets per step of the sweep. The downward half of a SILK rate change is a 256-frame ramp
    /// walked two frames per frame, so a step shorter than ~128 packets can never complete one.
    period: usize,
    sweep: Sweep,
    /// Whether every packet of this stream must stay in one mode. True for the sweeps that isolate
    /// the bandwidth path from the mode-switch path.
    single_mode: bool,
}

/// The streams. The first two are the ones that *prove* the bandwidth path: they never leave
/// SILK-only, so any redundancy frame in them came from a bandwidth switch and nothing else.
const STREAMS: [Stream; 4] = [
    Stream {
        label: "silk_mono_wb_nb",
        channels: 1,
        application: Application::Voip,
        bitrate_bps: 24_000,
        period: 150,
        sweep: Sweep::Cap(Bandwidth::Wideband, Bandwidth::Narrowband),
        single_mode: true,
    },
    Stream {
        label: "silk_mono_wb_mb",
        channels: 1,
        application: Application::Voip,
        bitrate_bps: 20_000,
        period: 200,
        sweep: Sweep::Cap(Bandwidth::Wideband, Bandwidth::Mediumband),
        single_mode: true,
    },
    Stream {
        label: "ladder_mono",
        channels: 1,
        application: Application::Voip,
        bitrate_bps: 32_000,
        period: 60,
        sweep: Sweep::ForcedLadder,
        single_mode: false,
    },
    Stream {
        label: "ladder_stereo",
        channels: 2,
        application: Application::Audio,
        bitrate_bps: 64_000,
        period: 60,
        sweep: Sweep::ForcedLadder,
        single_mode: false,
    },
];

/// The five bandwidths in ladder order.
const LADDER: [Bandwidth; 5] = [
    Bandwidth::Narrowband,
    Bandwidth::Mediumband,
    Bandwidth::Wideband,
    Bandwidth::SuperWideband,
    Bandwidth::Fullband,
];

fn bandwidth_name(bandwidth: Bandwidth) -> &'static str {
    match bandwidth {
        Bandwidth::Narrowband => "NB",
        Bandwidth::Mediumband => "MB",
        Bandwidth::Wideband => "WB",
        Bandwidth::SuperWideband => "SWB",
        Bandwidth::Fullband => "FB",
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Silk => "silk",
        Mode::Hybrid => "hybrid",
        Mode::Celt => "celt",
    }
}

/// Encode one switching stream.
fn encode_stream(stream: &Stream, source: &[i16]) -> Result<Vec<EncodedPacket>, String> {
    let mut encoder = OpusEncoder::new(REFERENCE_RATE_HZ, stream.channels, stream.application)
        .map_err(|error| format!("OpusEncoder::new: {error:?}"))?;
    encoder
        .set_bitrate(Some(stream.bitrate_bps))
        .map_err(|error| format!("set_bitrate: {error:?}"))?;
    encoder.set_rate_control(RateControl::ConstrainedVariable);
    encoder
        .set_complexity(COMPARISON_COMPLEXITY)
        .map_err(|error| format!("set_complexity: {error:?}"))?;
    encoder.set_signal_hint(SignalHint::Auto);

    let per_packet = FRAME_SIZE * stream.channels;
    let count = source.len() / per_packet;
    let mut packets = Vec::with_capacity(count);
    for index in 0..count {
        match stream.sweep {
            Sweep::Cap(first, second) => {
                let step = index / stream.period;
                encoder.set_max_bandwidth(if step.is_multiple_of(2) {
                    first
                } else {
                    second
                });
            }
            Sweep::ForcedLadder => {
                // Up the ladder and back down again, so both switch directions are covered.
                let step = (index / stream.period) % (2 * LADDER.len() - 2);
                let rung = if step < LADDER.len() {
                    step
                } else {
                    2 * LADDER.len() - 2 - step
                };
                encoder.set_bandwidth(Some(LADDER[rung]));
            }
        }
        let start = index * per_packet;
        let mut buffer = vec![0u8; 1500];
        let result = encoder
            .encode(&source[start..start + per_packet], FRAME_SIZE, &mut buffer)
            .map_err(|error| format!("packet {index}: {error:?}"))?;
        packets.push(EncodedPacket {
            payload: buffer[..result.bytes].to_vec(),
            final_range: result.final_range,
        });
    }
    if packets.len() < 4 * stream.period {
        return Err(format!(
            "only {} packets, which is fewer than four sweep steps",
            packets.len()
        ));
    }
    Ok(packets)
}

/// `opus_demo`'s `.bit` framing: per packet `[u32 BE len][u32 BE final_range][packet]`.
fn write_bit_file(path: &Path, packets: &[EncodedPacket]) -> Result<(), String> {
    let mut bytes = Vec::new();
    for packet in packets {
        bytes.extend_from_slice(&(packet.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&packet.final_range.to_be_bytes());
        bytes.extend_from_slice(&packet.payload);
    }
    std::fs::write(path, &bytes).map_err(|error| format!("writing {}: {error}", path.display()))
}

/// Run `opus_demo -d`. Its own complaint is returned, including "Range coder state mismatch".
fn decode_with_libopus(
    bit_path: &Path,
    output_path: &Path,
    channels: usize,
) -> Result<Vec<i16>, String> {
    let demo = opus_demo().ok_or_else(|| "opus_demo not built".to_string())?;
    let output = Command::new(&demo)
        .arg("-d")
        .arg(REFERENCE_RATE_HZ.to_string())
        .arg(channels.to_string())
        .arg(bit_path)
        .arg(output_path)
        .output()
        .map_err(|error| format!("running opus_demo -d: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "opus_demo -d failed ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    read_pcm(output_path)
}

/// What one stream proved.
#[derive(Default)]
struct StreamResult {
    packets: usize,
    bandwidth_changes: usize,
    mode_changes: usize,
    redundancy_packets: usize,
    bandwidths: BTreeSet<&'static str>,
    modes: BTreeSet<&'static str>,
    samples: usize,
    differing: usize,
    worst_lsb: i32,
}

/// Decode `packets` with both decoders and check everything this file exists to check.
fn score(
    scratch: &Path,
    stream: &Stream,
    packets: &[EncodedPacket],
) -> Result<StreamResult, String> {
    let bit_path = scratch.join(format!("bwswitch_{}.bit", stream.label));
    let dec_path = scratch.join(format!("bwswitch_{}.dec", stream.label));
    write_bit_file(&bit_path, packets)?;
    // Check 1: libopus consumed exactly the bits we said, packet for packet, or this fails.
    let theirs = decode_with_libopus(&bit_path, &dec_path, stream.channels)?;

    let mut decoder = OpusDecoder::new(REFERENCE_RATE_HZ, stream.channels)
        .map_err(|error| format!("OpusDecoder::new: {error}"))?;
    let mut frame = vec![0i16; MAX_PACKET_SAMPLES * stream.channels];
    let mut ours: Vec<i16> = Vec::with_capacity(theirs.len());
    let mut result = StreamResult::default();
    let mut previous_bandwidth = None;
    let mut previous_mode = None;

    for (index, packet) in packets.iter().enumerate() {
        let written = decoder
            .decode(Some(&packet.payload), &mut frame, MAX_PACKET_SAMPLES, false)
            .map_err(|error| format!("packet {index}: our decode failed: {error}"))?;
        ours.extend_from_slice(&frame[..written * stream.channels]);
        if decoder.final_range() != packet.final_range {
            return Err(format!(
                "packet {index}: our decoder ended on {:#010x}, our encoder said {:#010x}",
                decoder.final_range(),
                packet.final_range
            ));
        }
        // Check 2: a redundancy frame the decoder had to consume. On a `single_mode` stream this
        // can only have come from the bandwidth path.
        if decoder.last_frame_had_redundancy() {
            result.redundancy_packets += 1;
        }
        let toc = packet::Toc::parse(packet.payload[0]);
        if previous_bandwidth.is_some_and(|previous| previous != toc.bandwidth()) {
            result.bandwidth_changes += 1;
        }
        if previous_mode.is_some_and(|previous| previous != toc.mode()) {
            result.mode_changes += 1;
        }
        previous_bandwidth = Some(toc.bandwidth());
        previous_mode = Some(toc.mode());
        result.bandwidths.insert(bandwidth_name(toc.bandwidth()));
        result.modes.insert(mode_name(toc.mode()));
        result.packets += 1;
    }

    if stream.single_mode && result.mode_changes != 0 {
        return Err(format!(
            "{} was meant to stay in one mode so that redundancy could only come from a bandwidth \
             switch, but the mode changed {} times ({:?}) — retune its bitrate",
            stream.label, result.mode_changes, result.modes
        ));
    }

    // Check 3: the two decoders must agree on the audio.
    if ours.len() != theirs.len() {
        return Err(format!(
            "sample count differs: ours {}, libopus {}",
            ours.len(),
            theirs.len()
        ));
    }
    // Zero tolerance is the bar wherever it exists, and on a SILK-only stream it normally does —
    // both decoders are integer fixed-point there. A redundancy frame is **CELT**, though, and CELT
    // is float in both implementations, so a stream whose TOC never leaves SILK still contains float
    // arithmetic the moment one is present. That is the whole point of these streams, so the bar has
    // to account for it rather than pretend otherwise.
    let silk_only = result.modes.len() == 1 && result.modes.contains("silk");
    let allowed = if silk_only && result.redundancy_packets == 0 {
        0
    } else {
        MAX_LSB_DIFFERENCE
    };
    for (index, (&our_sample, &their_sample)) in ours.iter().zip(theirs.iter()).enumerate() {
        let delta = (i32::from(our_sample) - i32::from(their_sample)).abs();
        if delta == 0 {
            continue;
        }
        result.differing += 1;
        result.worst_lsb = result.worst_lsb.max(delta);
        if delta > allowed {
            return Err(format!(
                "sample {index} of {} differs by {delta} (ours {our_sample}, libopus \
                 {their_sample}); this stream's modes are {:?}, which allows {allowed}",
                ours.len(),
                result.modes
            ));
        }
    }
    result.samples = ours.len();
    Ok(result)
}

struct Fixture {
    mono: Vec<i16>,
    stereo: Vec<i16>,
    scratch: PathBuf,
}

fn fixture() -> Option<Fixture> {
    let dir = reference_dir()?;
    opus_demo()?;
    let skip = SKIP_MS * REFERENCE_RATE_HZ as usize / 1000;
    let mono = read_pcm(&dir.join("src01.sw")).ok()?;
    let stereo = read_pcm(&dir.join("src01_stereo.sw")).ok()?;
    if mono.len() <= skip || stereo.len() <= 2 * skip {
        return None;
    }
    let scratch = std::env::temp_dir().join("siphon_opus_bandwidth_switch");
    std::fs::create_dir_all(&scratch).ok()?;
    Some(Fixture {
        mono: mono[skip..].to_vec(),
        stereo: stereo[2 * skip..].to_vec(),
        scratch,
    })
}

/// The encoder's algorithmic delay at 48 kHz for VoIP and audio — `Fs/400 + Fs/250`. `opus_demo -d`
/// cannot know it, so its output is written unshifted and has to be aligned before it is scored.
const CODEC_DELAY_SAMPLES: usize = 120 + 192;

/// How far either side of [`CODEC_DELAY_SAMPLES`] the alignment is searched, in samples. A single
/// sample of misalignment costs several dB of segmental SNR, so a fixed shift would compare two
/// builds' delays rather than their quality.
const ALIGNMENT_SEARCH: usize = 24;

/// Segmental SNR in dB over 20 ms frames, voiced frames only, clamped per frame to [-10, 35]. The
/// same metric `opus_encode_conformance.rs` and the DSP suite use.
fn segmental_snr_db(reference: &[i16], test: &[i16], frame: usize) -> f64 {
    let length = reference.len().min(test.len());
    if length < frame {
        return f64::NEG_INFINITY;
    }
    let mut total = 0.0f64;
    let mut counted = 0usize;
    for start in (0..length - frame).step_by(frame) {
        let mut signal = 0.0f64;
        let mut noise = 0.0f64;
        for index in start..start + frame {
            let clean = f64::from(reference[index]);
            let error = clean - f64::from(test[index]);
            signal += clean * clean;
            noise += error * error;
        }
        if signal < 1e3 {
            continue;
        }
        total += (10.0 * (signal / noise.max(1e-9)).log10()).clamp(-10.0, 35.0);
        counted += 1;
    }
    if counted == 0 {
        f64::NEG_INFINITY
    } else {
        total / counted as f64
    }
}

/// **Quality across the seam.** A bandwidth switch is exactly where a codec sounds worst, so the
/// machinery that hides it has to be measured and not merely asserted to exist.
///
/// Two numbers are reported per stream, and both are chosen so that they can be compared against a
/// build that handles the switch differently:
///
/// * the segmental SNR over the whole sweeping stream — the control, because a change that improved
///   the seam by wrecking everything else would be no improvement at all;
/// * the segmental SNR over a ±200 ms window anchored at each point where the *request* changed —
///   the packet where `set_max_bandwidth` moved, not the packet where the encoder chose to act on
///   it. Anchoring on the request is what makes the number comparable at all: the encoder's response
///   is exactly what is under test, so a window anchored on the response would be measuring
///   different audio in each build.
#[test]
fn switching_bandwidth_does_not_cost_quality_at_the_seam() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };

    // The two SILK-only sweeps: the bandwidth path with nothing else moving.
    for stream in STREAMS.iter().filter(|stream| stream.single_mode) {
        let source = &fixture.mono;
        let packets = encode_stream(stream, source).expect("encode");
        let bit_path = fixture.scratch.join(format!("snr_{}.bit", stream.label));
        let dec_path = fixture.scratch.join(format!("snr_{}.dec", stream.label));
        write_bit_file(&bit_path, &packets).expect("write");
        let decoded =
            decode_with_libopus(&bit_path, &dec_path, stream.channels).expect("libopus decode");
        assert!(decoded.len() > CODEC_DELAY_SAMPLES + ALIGNMENT_SEARCH);

        // `OPUS_GET_LOOKAHEAD` is the nominal delay, but segmental SNR is sensitive to a *single*
        // sample of misalignment, and the point of these numbers is to compare two builds of the
        // encoder — one of which may legitimately delay its input by a different amount. So the
        // shift is searched, sample by sample, around the nominal value and the best is used;
        // otherwise the comparison would be measuring alignment rather than quality.
        let mut best = f64::NEG_INFINITY;
        let mut best_shift = CODEC_DELAY_SAMPLES;
        for shift in
            (CODEC_DELAY_SAMPLES - ALIGNMENT_SEARCH)..=(CODEC_DELAY_SAMPLES + ALIGNMENT_SEARCH)
        {
            let candidate = &decoded[shift..];
            let length = candidate.len().min(source.len());
            let snr = segmental_snr_db(&source[..length], &candidate[..length], 20 * 48);
            if snr > best {
                best = snr;
                best_shift = shift;
            }
        }
        let aligned = &decoded[best_shift..];

        let scored = aligned.len().min(source.len());
        let whole = best;

        // How many times the coded bandwidth actually moved — reported, not scored, because it is
        // precisely what differs between builds.
        let mut coded_changes = 0usize;
        let mut previous = None;
        for packet in &packets {
            let bandwidth = packet::Toc::parse(packet.payload[0]).bandwidth();
            if previous.is_some_and(|before| before != bandwidth) {
                coded_changes += 1;
            }
            previous = Some(bandwidth);
        }

        // ±10 packets of 20 ms around each *requested* change.
        const WINDOW_PACKETS: usize = 10;
        let mut seam_total = 0.0f64;
        let mut seam_count = 0usize;
        let mut request = stream.period;
        while request + WINDOW_PACKETS < packets.len() {
            let start = (request - WINDOW_PACKETS) * FRAME_SIZE;
            let end = ((request + WINDOW_PACKETS) * FRAME_SIZE).min(scored);
            if end > start + 20 * 48 {
                let snr = segmental_snr_db(&source[start..end], &aligned[start..end], 20 * 48);
                if snr.is_finite() {
                    seam_total += snr;
                    seam_count += 1;
                }
            }
            request += stream.period;
        }
        assert!(seam_count > 0, "{}: no seam window scored", stream.label);
        let seam_snr = seam_total / seam_count as f64;

        eprintln!(
            "  {}: whole-stream segmental SNR {whole:.2} dB; {seam_count} request windows \
             {seam_snr:.2} dB; the coded bandwidth moved {coded_changes} times (best alignment \
             {} samples off nominal)",
            stream.label,
            best_shift as i64 - CODEC_DELAY_SAMPLES as i64,
        );
        // Floors, not comparisons: the comparison against another build is a number to be read, and
        // it is printed above. These catch a future change that makes either one catastrophic.
        assert!(
            seam_snr > 0.0,
            "{}: segmental SNR around the bandwidth requests collapsed to {seam_snr:.2} dB",
            stream.label
        );
        assert!(
            whole > 0.0,
            "{}: whole-stream segmental SNR collapsed to {whole:.2} dB",
            stream.label
        );
    }
}

#[test]
fn a_stream_that_switches_bandwidth_mid_call_matches_libopus_and_carries_its_redundancy() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };

    let mut failures: Vec<String> = Vec::new();
    let mut scored = 0usize;
    let mut total = StreamResult::default();
    let mut silk_only_redundancy = 0usize;
    let mut silk_only_bandwidth_changes = 0usize;

    for stream in &STREAMS {
        let source = if stream.channels == 2 {
            &fixture.stereo
        } else {
            &fixture.mono
        };
        let packets = match encode_stream(stream, source) {
            Ok(packets) => packets,
            Err(error) => {
                failures.push(format!("{}: encode: {error}", stream.label));
                continue;
            }
        };
        match score(&fixture.scratch, stream, &packets) {
            Ok(result) => {
                eprintln!(
                    "  {}: {} packets, {} bandwidth changes {:?}, {} mode changes {:?}, {} \
                     redundancy-bearing packets; {}/{} samples differ (worst {} LSB)",
                    stream.label,
                    result.packets,
                    result.bandwidth_changes,
                    result.bandwidths,
                    result.mode_changes,
                    result.modes,
                    result.redundancy_packets,
                    result.differing,
                    result.samples,
                    result.worst_lsb,
                );
                if stream.single_mode {
                    silk_only_redundancy += result.redundancy_packets;
                    silk_only_bandwidth_changes += result.bandwidth_changes;
                }
                total.packets += result.packets;
                total.bandwidth_changes += result.bandwidth_changes;
                total.mode_changes += result.mode_changes;
                total.redundancy_packets += result.redundancy_packets;
                total.samples += result.samples;
                total.differing += result.differing;
                total.worst_lsb = total.worst_lsb.max(result.worst_lsb);
                total.bandwidths.extend(result.bandwidths);
                total.modes.extend(result.modes);
                scored += 1;
            }
            Err(error) => failures.push(format!("{}: {error}", stream.label)),
        }
    }

    assert!(
        failures.is_empty(),
        "bandwidth-switch conformance failures:\n  {}",
        failures.join("\n  ")
    );
    assert_eq!(scored, STREAMS.len(), "not every stream was scored");
    assert!(
        total.packets > 3_000,
        "only {} packets scored",
        total.packets
    );
    // The sweeps have to have actually moved the bandwidth, or every check above is vacuous.
    assert!(
        silk_only_bandwidth_changes > 0,
        "the SILK-only sweeps never changed bandwidth, so nothing here was tested"
    );
    assert!(
        total.bandwidths.len() >= 4,
        "only {:?} bandwidths were reached",
        total.bandwidths
    );
    // The point of the file. On a stream whose mode never moved, a redundancy frame can only have
    // come from `silk_bw_switch`, so a zero here means that path is dead again.
    assert!(
        silk_only_redundancy > 0,
        "not one packet of the single-mode sweeps carried a redundancy frame, so the SILK \
         bandwidth-switch path (opus_encoder.c:2065-2082, :1765-1772) never fired"
    );
    assert!(
        total.worst_lsb <= MAX_LSB_DIFFERENCE,
        "worst sample difference {} LSB",
        total.worst_lsb
    );
    eprintln!(
        "Opus bandwidth switching: {scored} streams, {} packets, {} bandwidth changes, {} mode \
         changes, {} redundancy-bearing packets ({silk_only_redundancy} of them on a stream that \
         never changed mode), bandwidths {:?} — libopus agreed on every packet's range state",
        total.packets,
        total.bandwidth_changes,
        total.mode_changes,
        total.redundancy_packets,
        total.bandwidths,
    );
}
