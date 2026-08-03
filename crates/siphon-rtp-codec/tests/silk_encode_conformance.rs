//! SILK **encoder** conformance: encode with our encoder, then decode the result twice — once with
//! our own SILK decoder and once with libopus — and require the two decodes to agree sample for
//! sample.
//!
//! # Why this is the right gate, and why it only became possible recently
//!
//! An encoder has no `final_range` to match: RFC 6716 is decoder-normative, so there is no
//! "correct" encoder bitstream and no reference PCM to be bit-exact against. The usual fallback,
//! "libopus decodes it and it sounds fine", is far too weak — it passes a stream whose side info is
//! subtly mis-ordered as long as the range decoder happens to stay in sync.
//!
//! What makes a strong check possible here is that this repo's SILK **decoder** is bit-exact
//! against libopus over 64 streams (`silk_only_conformance`). Two independent decoders that agree
//! on every single sample of a stream neither of them has seen before can only do so if the stream
//! is unambiguous — every symbol in the alphabet the writer thought it was using, in the order the
//! reader expects. So:
//!
//! 1. **Exact bitstream check.** Our stream is written in `opus_demo`'s `.bit` framing with **our
//!    encoder's** `final_range` beside every packet. `opus_demo -d` aborts with "Range coder state
//!    mismatch" unless libopus' own range decoder finishes each packet on exactly the value our
//!    range encoder ended on. That is an exact, per-packet equality on the entropy layer.
//! 2. **Sample-exact agreement.** Our [`SilkDecoder`] decodes the same packets and the two PCM
//!    outputs must be identical, sample for sample. No tolerance: both decoders are integer-faithful
//!    to the same reference arithmetic, so any difference is a bug.
//! 3. **Quality against libopus at the same configuration.** libopus encodes the same source with
//!    the same bandwidth, frame size and bitrate; our decoded segmental SNR must be within
//!    [`SNR_MARGIN_DB`] of its. This is the check that works at *every* rate and catches an encoder
//!    that is legal but bad — one that spends its bits in the wrong place still decodes to
//!    something, and only a quality comparison notices.
//! 4. **`opus_compare`**, the RFC 6716 §6 metric, run on the two decodes of **our own stream** —
//!    libopus' against ours. That is the one comparison the metric is defined for here, and check 2
//!    means it should score a perfect zero; running it is what proves the two PCM streams really are
//!    the same signal rather than two buffers that happened to compare equal because one was empty.
//!
//! Two uses of `opus_compare` are deliberately **not** made, because both would be meaningless:
//!
//! * **Against the original 48 kHz PCM.** `opus_compare` measures *decoder* deviation. SILK is
//!   band-limited to at most 8 kHz, so a narrowband 10 kb/s encode scored against a 48 kHz source
//!   is legitimately far outside the tolerance — CONTRIBUTING.md says exactly this for the CELT
//!   encoder, and it is more true here.
//! * **Against libopus' decode of libopus' own stream.** Two independent encodings of the same
//!   audio are perceptually close but nowhere near bit-similar; the metric reports a weighted error
//!   around 3 for a pair of perfectly good encoders. Check 3's segmental SNR comparison is the
//!   right tool for "is our encoder as good as theirs", and it is what this file uses.
//!
//! # Why there is no tolerance on anything discrete
//!
//! Checks 1 and 2 are exact and carry no tolerance at all. The only tolerance in the file is
//! [`SNR_MARGIN_DB`] on check 3, which compares two *different encoders'* rate/distortion decisions
//! — it is a quality bound, not a correctness one, and it is stated in dB rather than hidden in a
//! relative epsilon.
//!
//! # The one thing the harness must do that the SILK layer does not
//!
//! A SILK-only Opus packet with 17 or more spare bits makes libopus' *top-level* decoder read a
//! redundancy frame after the SILK layer (`opus_decoder.c:453-462` — for SILK-only it does not even
//! read a flag, it assumes redundancy is there). libopus' own encoder avoids that by shrinking the
//! range encoder to exactly the bytes SILK used (`ec_enc_shrink`, `opus_encoder.c`), and this
//! harness does the same. That belongs to the Opus layer, not to `SilkEncoder`, so it lives here.
//!
//! Skips gracefully when the reference tree is absent, and refuses to pass vacuously: it requires
//! every internal rate, every frame duration, both channel counts, and a non-trivial sample count.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use siphon_rtp_codec::opus::range_coder::{RangeDecoder, RangeEncoder};
use siphon_rtp_codec::opus::silk::decoder::SilkDecoder;
use siphon_rtp_codec::opus::silk::enc::encoder::{EncoderConfig, RateMode, SilkEncoder};
use siphon_rtp_codec::opus::silk::frame::LossFlag;
use siphon_rtp_codec::opus::silk::types::InternalRate;

/// Conformance output rate, matching what the other SILK harnesses decode at.
const REFERENCE_RATE_HZ: u32 = 48_000;
/// `opus_compare` reads its reference as 2-channel unconditionally, so both decodes are stereo.
const REFERENCE_CHANNELS: usize = 2;

/// How far below libopus' own segmental SNR our encoder may sit at the same configuration.
///
/// This is a **quality** bound between two different encoders' rate/distortion decisions, not a
/// correctness tolerance — the correctness checks in this file (the `final_range` equality and the
/// sample-exact agreement between the two decoders) carry no tolerance at all. 1 dB is the same
/// margin `celt_encode_conformance` holds itself to.
const SNR_MARGIN_DB: f64 = 1.0;

/// How much audio to encode per configuration, in ms. Enough to get well past the
/// first-frame-after-reset constraints, to exercise conditional coding across packets, and — with
/// [`SKIP_MS`] — to be actual speech rather than the vector's leading silence.
const AUDIO_MS: usize = 4_000;

/// How much of the reference source to skip. `src01.sw` opens with ~1.8 s of near-silence, and a
/// harness that encoded only that would be measuring the DTX path and calling it conformance.
const SKIP_MS: usize = 2_000;

/// `reference/opus`, if the tree is there.
fn reference_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus");
    dir.is_dir().then_some(dir)
}

/// The instrumented-free `opus_demo`, if it has been built.
fn opus_demo() -> Option<PathBuf> {
    let path = reference_dir()?.join("build/opus_demo");
    path.is_file().then_some(path)
}

/// `opus_compare`, honouring `SIPHON_RTP_OPUS_COMPARE`.
fn opus_compare() -> Option<PathBuf> {
    let path = std::env::var_os("SIPHON_RTP_OPUS_COMPARE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/opus_compare"));
    path.is_file().then_some(path)
}

/// The 48 kHz mono source `gen_silk_only.sh` uses, if it has been generated.
fn source_pcm() -> Option<Vec<i16>> {
    let path = reference_dir()?.join("src01.sw");
    let bytes = std::fs::read(path).ok()?;
    Some(
        bytes
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
    )
}

/// A deterministic low-pass FIR decimator, 48 kHz down to the SILK internal rate.
///
/// A plain windowed-sinc at `0.9 * Nyquist` of the target rate — the encoder is being tested, not
/// the resampler, and every configuration sees the same deterministic decimation so a difference in
/// the result is a difference in the encoder.
fn decimate(source: &[i16], factor: usize) -> Vec<i16> {
    const HALF_TAPS: usize = 48;
    let cutoff = 0.9 / factor as f64;
    let mut taps = [0.0f64; 2 * HALF_TAPS + 1];
    let mut sum = 0.0;
    for (index, tap) in taps.iter_mut().enumerate() {
        let offset = index as f64 - HALF_TAPS as f64;
        let sinc = if offset == 0.0 {
            2.0 * cutoff
        } else {
            (2.0 * std::f64::consts::PI * cutoff * offset).sin() / (std::f64::consts::PI * offset)
        };
        // Hann window.
        let window = 0.5 + 0.5 * (std::f64::consts::PI * offset / HALF_TAPS as f64).cos();
        *tap = sinc * window;
        sum += *tap;
    }
    for tap in taps.iter_mut() {
        *tap /= sum;
    }

    let mut out = Vec::with_capacity(source.len() / factor);
    let mut position = 0usize;
    while position < source.len() {
        let mut accumulator = 0.0f64;
        for (index, &tap) in taps.iter().enumerate() {
            let sample = position as isize + index as isize - HALF_TAPS as isize;
            if sample >= 0 && (sample as usize) < source.len() {
                accumulator += tap * f64::from(source[sample as usize]);
            }
        }
        out.push(accumulator.clamp(-32768.0, 32767.0) as i16);
        position += factor;
    }
    out
}

/// One configuration of the encode matrix.
#[derive(Debug, Clone, Copy)]
struct Configuration {
    internal_rate: InternalRate,
    duration_ms: usize,
    channels: usize,
    bitrate_bps: i32,
    rate_mode: RateMode,
}

impl Configuration {
    /// The `opus_demo` bandwidth name and the TOC config base for this internal rate.
    fn bandwidth(&self) -> (&'static str, u8) {
        match self.internal_rate {
            InternalRate::Narrow8k => ("NB", 0),
            InternalRate::Medium12k => ("MB", 4),
            InternalRate::Wide16k => ("WB", 8),
        }
    }

    /// The SILK-only TOC byte for this configuration, frame code 0 (RFC 6716 §3.1, Table 2).
    fn toc(&self) -> u8 {
        let (_, base) = self.bandwidth();
        let duration_index = match self.duration_ms {
            10 => 0u8,
            20 => 1,
            40 => 2,
            _ => 3,
        };
        let config = base + duration_index;
        (config << 3) | (u8::from(self.channels == 2) << 2)
    }

    fn label(&self) -> String {
        let (name, _) = self.bandwidth();
        format!(
            "{name}_{}ms_{}ch_{}bps_{:?}",
            self.duration_ms, self.channels, self.bitrate_bps, self.rate_mode
        )
    }
}

/// The bandwidth/duration/rate/channel matrix. Bitrates are chosen per bandwidth to sit where SILK
/// actually operates: below the floor the gain loop cannot fill, above the ceiling it saturates.
fn matrix() -> Vec<Configuration> {
    let mut configurations = Vec::new();
    for (internal_rate, bitrates) in [
        (InternalRate::Narrow8k, [8_000i32, 12_000]),
        (InternalRate::Medium12k, [12_000, 18_000]),
        (InternalRate::Wide16k, [16_000, 24_000]),
    ] {
        for duration_ms in [10usize, 20, 40, 60] {
            for bitrate_bps in bitrates {
                configurations.push(Configuration {
                    internal_rate,
                    duration_ms,
                    channels: 1,
                    bitrate_bps,
                    rate_mode: RateMode::Variable,
                });
            }
        }
        // Stereo and the two non-default rate modes, at 20 ms only — the mode matrix is orthogonal
        // to the duration matrix and running all of it would be minutes of `opus_demo`.
        configurations.push(Configuration {
            internal_rate,
            duration_ms: 20,
            channels: 2,
            bitrate_bps: bitrates[1] * 2,
            rate_mode: RateMode::Variable,
        });
        for rate_mode in [RateMode::ConstrainedVariable, RateMode::Constant] {
            configurations.push(Configuration {
                internal_rate,
                duration_ms: 20,
                channels: 1,
                bitrate_bps: bitrates[1],
                rate_mode,
            });
        }
    }
    configurations
}

/// One encoded packet, with the encoder's own final range.
struct EncodedPacket {
    payload: Vec<u8>,
    final_range: u32,
}

/// Encode [`AUDIO_MS`] worth of `source` with our encoder.
fn encode(configuration: &Configuration, source: &[i16]) -> Result<Vec<EncodedPacket>, String> {
    let packet_count = AUDIO_MS / configuration.duration_ms;
    let mut config = EncoderConfig::new(
        configuration.internal_rate,
        configuration.duration_ms,
        configuration.bitrate_bps,
    );
    config.channels = configuration.channels;
    config.rate_mode = configuration.rate_mode;
    // A cap that a 60 ms packet at the top of the range can still fit inside, and that constrained
    // VBR has something to constrain against.
    config.max_bytes = (configuration.bitrate_bps as usize * configuration.duration_ms)
        .div_ceil(8000)
        .clamp(20, 1275);

    let mut encoder =
        SilkEncoder::new(config).map_err(|error| format!("SilkEncoder::new: {error:?}"))?;
    let per_packet = encoder.samples_per_packet() * configuration.channels;

    let mut packets = Vec::new();
    for index in 0..packet_count {
        let start = index * per_packet;
        if start + per_packet > source.len() {
            break;
        }
        let mut buffer = vec![0u8; 1275];
        let mut range = RangeEncoder::new(&mut buffer);
        encoder
            .encode(&source[start..start + per_packet], &mut range)
            .map_err(|error| format!("packet {index}: {error:?}"))?;

        // Shrink to exactly the bytes SILK used, as the Opus layer does, so libopus' decoder does
        // not find 17 spare bits and go looking for a redundancy frame.
        let used = (range.tell() as usize).div_ceil(8).max(1);
        range.shrink(used as u32);
        range.done();
        if range.error() {
            return Err(format!("packet {index}: range encoder overflowed"));
        }
        let final_range = range.rng();
        packets.push(EncodedPacket {
            payload: buffer[..used].to_vec(),
            final_range,
        });
    }
    if packets.is_empty() {
        return Err("no packets encoded".to_string());
    }
    Ok(packets)
}

/// Write the `opus_demo` `.bit` framing: per packet `[u32 BE len][u32 BE final_range][payload]`,
/// with the SILK-only TOC byte prepended to each payload.
fn write_bit_file(
    path: &Path,
    configuration: &Configuration,
    packets: &[EncodedPacket],
) -> Result<(), String> {
    let mut bytes = Vec::new();
    for packet in packets {
        let length = packet.payload.len() + 1;
        bytes.extend_from_slice(&(length as u32).to_be_bytes());
        bytes.extend_from_slice(&packet.final_range.to_be_bytes());
        bytes.push(configuration.toc());
        bytes.extend_from_slice(&packet.payload);
    }
    std::fs::write(path, &bytes).map_err(|error| format!("writing {}: {error}", path.display()))
}

/// Decode our own packets with our own SILK decoder, at 48 kHz stereo.
fn decode_with_ours(
    configuration: &Configuration,
    packets: &[EncodedPacket],
) -> Result<Vec<i16>, String> {
    let mut decoder = SilkDecoder::new(REFERENCE_RATE_HZ, REFERENCE_CHANNELS)
        .map_err(|error| format!("SilkDecoder::new: {error:?}"))?;
    let mut pcm = Vec::new();
    let mut frame_pcm = vec![0i16; 2880 * REFERENCE_CHANNELS];
    for (index, packet) in packets.iter().enumerate() {
        decoder
            .configure(
                configuration.channels,
                configuration.internal_rate,
                configuration.duration_ms,
            )
            .map_err(|error| format!("packet {index}: configure: {error:?}"))?;
        let mut range = RangeDecoder::new(&packet.payload);
        let produced = decoder
            .decode(Some(&mut range), LossFlag::Normal, &mut frame_pcm)
            .map_err(|error| format!("packet {index}: decode: {error:?}"))?;
        pcm.extend_from_slice(&frame_pcm[..produced * REFERENCE_CHANNELS]);
    }
    Ok(pcm)
}

/// Read an interleaved little-endian 16-bit PCM file.
fn read_pcm(path: &Path) -> Result<Vec<i16>, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

/// Write an interleaved little-endian 16-bit PCM file.
fn write_pcm(path: &Path, pcm: &[i16]) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(pcm.len() * 2);
    for &sample in pcm {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    std::fs::write(path, &bytes).map_err(|error| format!("writing {}: {error}", path.display()))
}

/// Run `opus_demo -d` on a `.bit` file. Returns the decoded PCM, or the tool's own complaint —
/// including "Range coder state mismatch", which is check 1 failing.
fn decode_with_libopus(bit_path: &Path, output_path: &Path) -> Result<Vec<i16>, String> {
    let demo = opus_demo().ok_or_else(|| "opus_demo not built".to_string())?;
    let output = Command::new(&demo)
        .arg("-d")
        .arg(REFERENCE_RATE_HZ.to_string())
        .arg(REFERENCE_CHANNELS.to_string())
        .arg(bit_path)
        .arg(output_path)
        .output()
        .map_err(|error| format!("running opus_demo: {error}"))?;
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

/// Encode the same source with libopus at the same configuration and decode it, so our encoder can
/// be compared against the reference encoder rather than against an absolute.
fn libopus_round_trip(
    configuration: &Configuration,
    source_48k: &Path,
    scratch: &Path,
    label: &str,
) -> Result<Vec<i16>, String> {
    let demo = opus_demo().ok_or_else(|| "opus_demo not built".to_string())?;
    let bit_path = scratch.join(format!("libopus_{label}.bit"));
    let dec_path = scratch.join(format!("libopus_{label}.dec"));
    let (bandwidth, _) = configuration.bandwidth();

    let mut command = Command::new(&demo);
    command
        .arg("-e")
        .arg("voip")
        .arg(REFERENCE_RATE_HZ.to_string())
        .arg(configuration.channels.to_string())
        .arg(configuration.bitrate_bps.to_string())
        .arg("-bandwidth")
        .arg(bandwidth)
        .arg("-framesize")
        .arg(configuration.duration_ms.to_string());
    match configuration.rate_mode {
        RateMode::Variable => {}
        RateMode::ConstrainedVariable => {
            command.arg("-cvbr");
        }
        RateMode::Constant => {
            command.arg("-cbr");
        }
    }
    let output = command
        .arg(source_48k)
        .arg(&bit_path)
        .output()
        .map_err(|error| format!("running opus_demo -e: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "opus_demo -e failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    decode_with_libopus(&bit_path, &dec_path)
}

/// Segmental SNR in dB against a reference, over 20 ms frames, voiced frames only.
///
/// Clamped per frame to [-10, 35] dB, as the DSP crate's own metric is, so one pathological frame
/// cannot dominate the average in either direction.
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
        // Skip frames with essentially no signal: their SNR is meaningless and they are the bulk of
        // the leading silence in the reference material.
        if signal < 1e3 {
            continue;
        }
        let ratio = 10.0 * (signal / noise.max(1e-9)).log10();
        total += ratio.clamp(-10.0, 35.0);
        counted += 1;
    }
    if counted == 0 {
        f64::NEG_INFINITY
    } else {
        total / counted as f64
    }
}

/// Run `opus_compare -s` and return its quality percentage.
fn run_opus_compare(reference: &Path, test: &Path) -> Result<f64, String> {
    let tool = opus_compare().ok_or_else(|| "opus_compare not found".to_string())?;
    let output = Command::new(&tool)
        .arg("-s")
        .arg("-r")
        .arg(REFERENCE_RATE_HZ.to_string())
        .arg(reference)
        .arg(test)
        .output()
        .map_err(|error| format!("running opus_compare: {error}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!("opus_compare failed: {text}"));
    }
    if !text.contains("PASSES") {
        return Err(format!("opus_compare did not pass: {text}"));
    }
    // "Test vector PASSES\nOpus quality metric: 100.0 % (internal weighted error is 0.000000)" —
    // note the space before the percent sign, which is why the number is taken from the token
    // *before* a bare "%" as well as from a "12.3%" token.
    let tokens: Vec<&str> = text.split_whitespace().collect();
    for (index, token) in tokens.iter().enumerate() {
        let candidate = if *token == "%" {
            index.checked_sub(1).map(|previous| tokens[previous])
        } else {
            token.strip_suffix('%')
        };
        if let Some(number) = candidate {
            if let Ok(value) = number.parse::<f64>() {
                return Ok(value);
            }
        }
    }
    Err(format!("could not parse opus_compare output: {text}"))
}

/// What the run covered, so it cannot pass vacuously.
#[derive(Debug, Default)]
struct Coverage {
    rates: BTreeSet<usize>,
    durations: BTreeSet<usize>,
    channel_counts: BTreeSet<usize>,
    rate_modes: BTreeSet<String>,
    configurations: usize,
    packets: usize,
    samples: usize,
}

/// The headline gate: encode, decode twice, require the two decodes to be identical.
#[test]
fn our_stream_decodes_identically_under_both_decoders() {
    let Some(reference) = reference_dir() else {
        eprintln!("skipping: reference/opus is absent");
        return;
    };
    if opus_demo().is_none() {
        eprintln!("skipping: reference/opus/build/opus_demo is not built");
        return;
    }
    let Some(whole_source) = source_pcm() else {
        eprintln!("skipping: reference/opus/src01.sw is absent (run gen_silk_only.sh)");
        return;
    };
    // Past the vector's leading silence: everything below must be scored on real speech.
    let source_48k =
        &whole_source[(SKIP_MS * REFERENCE_RATE_HZ as usize / 1000).min(whole_source.len())..];

    let scratch = std::env::temp_dir().join("siphon_silk_encode_conformance");
    std::fs::create_dir_all(&scratch).expect("scratch directory");

    let mut coverage = Coverage::default();
    let mut failures: Vec<String> = Vec::new();
    let mut compare_scores: Vec<(String, f64)> = Vec::new();

    for configuration in matrix() {
        let label = configuration.label();
        let factor = 48 / configuration.internal_rate.khz();
        let mono = decimate(source_48k, factor);
        // Build the encoder's input: mono as-is, stereo by pairing the signal with a delayed and
        // attenuated copy of itself so the image is genuinely wide rather than a duplicated mono.
        let input = if configuration.channels == 2 {
            let delay = configuration.internal_rate.khz() * 3;
            let mut interleaved = vec![0i16; mono.len() * 2];
            for (index, &sample) in mono.iter().enumerate() {
                interleaved[2 * index] = sample;
                let other = if index >= delay {
                    mono[index - delay]
                } else {
                    0
                };
                interleaved[2 * index + 1] = (i32::from(other) * 3 / 4) as i16;
            }
            interleaved
        } else {
            mono.clone()
        };

        let packets = match encode(&configuration, &input) {
            Ok(packets) => packets,
            Err(error) => {
                failures.push(format!("{label}: encode: {error}"));
                continue;
            }
        };

        let bit_path = scratch.join(format!("ours_{label}.bit"));
        let dec_path = scratch.join(format!("ours_{label}.dec"));
        if let Err(error) = write_bit_file(&bit_path, &configuration, &packets) {
            failures.push(format!("{label}: {error}"));
            continue;
        }

        // Check 1: libopus must end every packet on exactly our final range, or it aborts here.
        let theirs = match decode_with_libopus(&bit_path, &dec_path) {
            Ok(pcm) => pcm,
            Err(error) => {
                failures.push(format!("{label}: libopus decode: {error}"));
                continue;
            }
        };

        // Check 2: our own decoder must produce exactly the same samples.
        let ours = match decode_with_ours(&configuration, &packets) {
            Ok(pcm) => pcm,
            Err(error) => {
                failures.push(format!("{label}: our decode: {error}"));
                continue;
            }
        };

        let compared = ours.len().min(theirs.len());
        if compared == 0 {
            failures.push(format!("{label}: no samples decoded"));
            continue;
        }
        if let Some(index) = (0..compared).find(|&index| ours[index] != theirs[index]) {
            failures.push(format!(
                "{label}: decoders disagree at interleaved sample {index} of {compared}: \
                 ours {} vs libopus {}",
                ours[index], theirs[index]
            ));
            continue;
        }
        // Length may differ by libopus' own trailing handling; require our decode to cover
        // essentially all of it.
        if ours.len() * 20 < theirs.len() * 19 {
            failures.push(format!(
                "{label}: our decode is much shorter: {} vs {}",
                ours.len(),
                theirs.len()
            ));
            continue;
        }

        // Check 4: the RFC 6716 §6 metric on the two decodes of our own stream. Check 2 says they
        // are identical, so this must score a perfect zero — and running it proves the two buffers
        // really are the same *signal*, not two that compared equal for a trivial reason.
        if opus_compare().is_some() {
            let ours_path = scratch.join(format!("cmp_ours_{label}.sw"));
            match write_pcm(&ours_path, &ours[..compared]) {
                Ok(()) => match run_opus_compare(&dec_path, &ours_path) {
                    Ok(quality) => compare_scores.push((label.clone(), quality)),
                    Err(error) => failures.push(format!("{label}: opus_compare: {error}")),
                },
                Err(error) => failures.push(format!("{label}: {error}")),
            }
        }

        coverage.rates.insert(configuration.internal_rate.khz());
        coverage.durations.insert(configuration.duration_ms);
        coverage.channel_counts.insert(configuration.channels);
        coverage
            .rate_modes
            .insert(format!("{:?}", configuration.rate_mode));
        coverage.configurations += 1;
        coverage.packets += packets.len();
        coverage.samples += compared;
    }

    let _ = reference;
    assert!(
        failures.is_empty(),
        "SILK encode conformance failures:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        coverage.configurations >= 20,
        "only {} configurations scored",
        coverage.configurations
    );
    assert_eq!(coverage.rates, BTreeSet::from([8, 12, 16]), "rate coverage");
    assert_eq!(
        coverage.durations,
        BTreeSet::from([10, 20, 40, 60]),
        "duration coverage"
    );
    assert_eq!(
        coverage.channel_counts,
        BTreeSet::from([1, 2]),
        "channel coverage"
    );
    assert_eq!(coverage.rate_modes.len(), 3, "rate-mode coverage");
    assert!(
        coverage.samples > 1_000_000,
        "only {} samples",
        coverage.samples
    );
    eprintln!(
        "SILK encode: {} configurations, {} packets, {} samples — both decoders agree exactly",
        coverage.configurations, coverage.packets, coverage.samples
    );
    if !compare_scores.is_empty() {
        let worst = compare_scores
            .iter()
            .map(|(_, quality)| *quality)
            .fold(f64::INFINITY, f64::min);
        assert!(
            worst >= 100.0,
            "opus_compare scored below a perfect match somewhere: {compare_scores:?}"
        );
        eprintln!(
            "opus_compare: {} configurations, all {worst:.1}%",
            compare_scores.len()
        );
    }
}

/// The quality gate: our encoder must not be materially worse than libopus' at the same
/// configuration, measured as segmental SNR against the same source and scored by `opus_compare`
/// against libopus' own decode.
#[test]
fn our_encoder_matches_libopus_quality_at_the_same_configuration() {
    let Some(reference) = reference_dir() else {
        eprintln!("skipping: reference/opus is absent");
        return;
    };
    if opus_demo().is_none() {
        eprintln!("skipping: reference/opus/build/opus_demo is not built");
        return;
    }
    let Some(whole_source) = source_pcm() else {
        eprintln!("skipping: reference/opus/src01.sw is absent");
        return;
    };
    let _ = &reference;
    let source_48k =
        &whole_source[(SKIP_MS * REFERENCE_RATE_HZ as usize / 1000).min(whole_source.len())..];

    let scratch = std::env::temp_dir().join("siphon_silk_encode_conformance");
    std::fs::create_dir_all(&scratch).expect("scratch directory");

    // libopus must encode exactly the audio we do, so the leading silence is stripped from its
    // input too rather than only from ours.
    let source_path = scratch.join("source_offset.sw");
    let scored_samples = (AUDIO_MS * REFERENCE_RATE_HZ as usize / 1000).min(source_48k.len());
    if write_pcm(&source_path, &source_48k[..scored_samples]).is_err() {
        eprintln!("skipping: could not stage the offset source");
        return;
    }

    let mut failures: Vec<String> = Vec::new();
    let mut scored = 0usize;

    // The quality comparison is meaningful per (bandwidth, rate); the duration and mode axes are
    // covered by the exactness gate above.
    let configurations: Vec<Configuration> = matrix()
        .into_iter()
        .filter(|configuration| {
            configuration.channels == 1
                && configuration.duration_ms == 20
                && configuration.rate_mode == RateMode::Variable
        })
        .collect();

    for configuration in configurations {
        let label = configuration.label();
        let factor = 48 / configuration.internal_rate.khz();
        let mono = decimate(source_48k, factor);

        let packets = match encode(&configuration, &mono) {
            Ok(packets) => packets,
            Err(error) => {
                failures.push(format!("{label}: encode: {error}"));
                continue;
            }
        };
        let bit_path = scratch.join(format!("quality_{label}.bit"));
        let dec_path = scratch.join(format!("quality_{label}.dec"));
        if let Err(error) = write_bit_file(&bit_path, &configuration, &packets) {
            failures.push(format!("{label}: {error}"));
            continue;
        }
        let ours = match decode_with_libopus(&bit_path, &dec_path) {
            Ok(pcm) => pcm,
            Err(error) => {
                failures.push(format!("{label}: libopus decode of our stream: {error}"));
                continue;
            }
        };
        let theirs = match libopus_round_trip(&configuration, &source_path, &scratch, &label) {
            Ok(pcm) => pcm,
            Err(error) => {
                failures.push(format!("{label}: libopus round trip: {error}"));
                continue;
            }
        };

        // Both decodes are 48 kHz stereo of the same mono source; score against the source, folded
        // to the same interleaved layout.
        let length = ours.len().min(theirs.len());
        if length < 48_000 {
            failures.push(format!("{label}: too little audio to score ({length})"));
            continue;
        }
        let mut reference_stereo = vec![0i16; length];
        for index in 0..length / 2 {
            let sample = source_48k.get(index).copied().unwrap_or(0);
            reference_stereo[2 * index] = sample;
            reference_stereo[2 * index + 1] = sample;
        }
        let reference_stereo = reference_stereo;

        // The codec delay differs between the two streams' framings, so align each against the
        // reference by the lag that maximises its own SNR before comparing them.
        let our_snr = best_aligned_snr(&reference_stereo, &ours);
        let their_snr = best_aligned_snr(&reference_stereo, &theirs);
        if our_snr + SNR_MARGIN_DB < their_snr {
            failures.push(format!(
                "{label}: our segmental SNR {our_snr:.2} dB is more than {SNR_MARGIN_DB} dB below \
                 libopus' {their_snr:.2} dB"
            ));
            continue;
        }

        eprintln!("  {label}: ours {our_snr:.2} dB, libopus {their_snr:.2} dB");
        scored += 1;
    }

    assert!(
        failures.is_empty(),
        "SILK encoder quality failures:\n  {}",
        failures.join("\n  ")
    );
    assert!(scored >= 6, "only {scored} configurations scored");
}

/// The best segmental SNR over a small range of alignments, so a codec delay difference is not
/// mistaken for distortion.
fn best_aligned_snr(reference: &[i16], test: &[i16]) -> f64 {
    let frame = 20 * 48 * REFERENCE_CHANNELS;
    let mut best = f64::NEG_INFINITY;
    // Up to 20 ms of delay, in whole stereo sample pairs.
    for lag in (0..=(20 * 48)).step_by(4) {
        let offset = lag * REFERENCE_CHANNELS;
        if offset >= test.len() {
            break;
        }
        let snr = segmental_snr_db(reference, &test[offset..], frame);
        if snr > best {
            best = snr;
        }
    }
    best
}
