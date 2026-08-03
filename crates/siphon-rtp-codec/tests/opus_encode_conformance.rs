//! Top-level **Opus encoder** conformance: encode with [`OpusEncoder`], then hold the result up
//! against libopus five different ways.
//!
//! # Why five checks and not one
//!
//! RFC 6716 is decoder-normative, so an encoder has no reference bitstream and no `final_range` of
//! its own to match. Each check below closes a different hole, and none of them is redundant:
//!
//! 1. **Exact bitstream check.** Our stream is written in `opus_demo`'s `.bit` framing with **our
//!    encoder's** `final_range` beside every packet. `opus_demo -d` aborts with "Range coder state
//!    mismatch" unless libopus' own decoder finishes each packet on exactly the value our range
//!    encoder ended on. This is an *equality*, per packet, and it is the only check that reaches
//!    inside a hybrid frame: SILK and CELT share one range coder there with no length field between
//!    them, so a single mis-ordered symbol at the seam moves the final range and is caught here.
//!    [`the_range_check_is_live`] corrupts a byte and confirms the check really fails.
//! 2. **Discrete decisions against libopus'.** Every choice this layer makes — mode, bandwidth,
//!    stream channels, frame duration — is written into the TOC byte, so at the same configuration
//!    and the same input our TOC bytes must be libopus' TOC bytes, packet for packet. libopus is run
//!    at complexity 6, which is the setting at which it does *not* run its tonality analysis
//!    (`opus_encoder.c:1117`) — the one subsystem this encoder does not implement — so the two are
//!    making the decision from the same information. Any tolerance here would be a bug: these are
//!    discrete values, not measurements.
//! 3. **Quality against libopus at the same configuration.** libopus encodes the same source with
//!    the same application, bitrate, frame size and rate mode; our decoded segmental SNR must be
//!    within [`SNR_MARGIN_DB`] of its. This is the check that works at *every* rate and catches an
//!    encoder that is legal but bad — one that spends its bits in the wrong place decodes cleanly
//!    and only a quality comparison notices.
//! 4. **`opus_compare`**, the RFC 6716 §6 metric, against the original PCM — but only where it
//!    means something. It measures *decoder* deviation, so a 12 kb/s narrowband encode is
//!    legitimately far outside its tolerance; it is run at fullband and a high rate, where a
//!    transparent encode is the expectation, with the 120-sample codec delay compensated first.
//! 5. **Two independent decoders on the same audio.** Checks 1-4 score the *bitstream*; this scores
//!    what comes out of it. The same stream is decoded by [`OpusDecoder`] and by `opus_demo -d` and
//!    the two outputs are compared. Check 1 says libopus consumed the same bits we wrote; this says
//!    both decoders turn those bits into the same audio, which is the part `final_range` cannot
//!    see — a mis-scaled gain, a redundancy frame cross-faded over the wrong window, a resampler
//!    off by a phase all leave the range coder in exactly the right place. Our decoder is itself
//!    gated on the 12 official RFC 6716 vectors and 75 166 redundancy-bearing packets, so two
//!    independently written decoders agreeing on a stream *neither has seen before* is the
//!    strongest statement available about that stream. It is **sample-exact on SILK-only streams**
//!    and within one LSB where CELT's float arithmetic is involved; see
//!    [`our_decoder_and_libopus_agree_sample_for_sample_on_our_own_stream`] and
//!    [`MAX_LSB_DIFFERENCE`] for why that split is the correct bar and not a relaxation.
//!
//! # The tolerances, and why they are where they are
//!
//! [`SNR_MARGIN_DB`] on check 3 compares two *different encoders'* rate/distortion decisions. It is
//! a quality bound, not a correctness one, and it is stated in dB rather than hidden in a relative
//! epsilon. [`MAX_LSB_DIFFERENCE`] on check 5 is the float/fixed-point latitude RFC 6716 §6 grants
//! a *decoder*, and it applies only to arithmetic downstream of an entropy decode that checks 1 and
//! 5 have already proven identical. Checks 1 and 2 are exact equalities and carry no tolerance at
//! all, and neither does check 5 on a stream that never leaves SILK.
//!
//! Skips gracefully when the reference tree is absent, and refuses to pass vacuously: it requires
//! all three modes, every frame duration, both channel counts, all three rate modes, and a
//! non-trivial packet count.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};
use siphon_rtp_codec::opus::enc::decision::{Application, SignalHint};
use siphon_rtp_codec::opus::enc::encoder::{OpusEncoder, RateControl};
use siphon_rtp_codec::opus::packet::{self, Bandwidth, Mode};

/// The rate everything is compared at.
const REFERENCE_RATE_HZ: u32 = 48_000;

/// How far below libopus' own segmental SNR our encoder may sit at the same configuration. The same
/// margin `celt_encode_conformance` and `silk_encode_conformance` hold themselves to.
const SNR_MARGIN_DB: f64 = 1.0;

/// libopus' complexity for the comparison runs: the highest setting at which it does **not** run the
/// tonality analysis (`opus_encoder.c:1117` gates it on `complexity >= 7`), which is the subsystem
/// this encoder deliberately does not implement. Comparing against a libopus that *is* running it
/// would be comparing against a different encoder.
const COMPARISON_COMPLEXITY: i32 = 6;

/// How much audio to encode per configuration, in ms.
const AUDIO_MS: usize = 3_000;

/// The reference vector opens with near-silence; skip past it so nothing is scored on the DTX path.
const SKIP_MS: usize = 2_000;

/// The encoder's algorithmic delay in samples at 48 kHz — `OPUS_GET_LOOKAHEAD`, which is
/// `Fs/400 + delay_compensation` = 120 + 192 for VoIP and audio, and 120 alone for restricted low
/// delay (which has no delay compensation).
///
/// `opus_demo -d` cannot know it — only the encoder reports it — so it writes the decode unshifted,
/// and `opus_compare` is very sensitive to misalignment: even libopus' own 256 kb/s fullband round
/// trip fails unaligned.
const CODEC_DELAY_SAMPLES: usize = 120 + 192;

/// How far a sample of *our* decode of *our own* stream may sit from libopus' decode of the same
/// stream, once a CELT or hybrid packet is in it.
///
/// Zero is the bar wherever it is attainable, and check 5 enforces zero on every SILK-only stream —
/// SILK is integer fixed-point in both decoders, so a rounding difference there is a bug. CELT is
/// **float** in both (libopus is built here without `OPUS_FIXED_POINT`), and two independent float
/// implementations of the same transform do not agree on the last bit: the operation order differs,
/// GCC's default `-ffp-contract=fast` fuses multiply-adds that Rust never fuses, and `libm` differs
/// in the last ulp. That is not a defect to be fixed but the reason RFC 6716 §6 defines conformance
/// as an `opus_compare` pass rather than as bit-exact PCM — a fixed-point and a float decoder are
/// both conformant and cannot be sample-identical.
///
/// What keeps this from being a hole is that it is *only* the arithmetic after entropy decoding that
/// is in scope. Every packet's `final_range` is checked exactly, from both sides — `opus_demo -d`
/// against our encoder's value and our decoder against it too — so the two decoders provably read
/// the identical symbol sequence before a single sample is compared. The same bound, for the same
/// reason, is what `opus_conformance` and `opus_redundancy_conformance` hold the decoder to.
const MAX_LSB_DIFFERENCE: i32 = 1;

/// The largest fraction of samples allowed to differ at all, across the whole run. A bound of one
/// LSB cannot by itself distinguish "float rounds the other way now and then" from a systematic
/// half-LSB bias, so the *rate* is bounded too. The observed rate is ~0.025 %.
const MAX_DIFFERING_FRACTION: f64 = 0.005;

fn reference_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus");
    dir.is_dir().then_some(dir)
}

fn opus_demo() -> Option<PathBuf> {
    let path = reference_dir()?.join("build/opus_demo");
    path.is_file().then_some(path)
}

fn opus_compare() -> Option<PathBuf> {
    let path = std::env::var_os("SIPHON_RTP_OPUS_COMPARE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/opus_compare"));
    path.is_file().then_some(path)
}

/// The 48 kHz mono source `gen_silk_only.sh` writes.
fn source_mono() -> Option<Vec<i16>> {
    read_pcm(&reference_dir()?.join("src01.sw")).ok()
}

/// The 48 kHz stereo source `gen_celt_only.sh` writes.
fn source_stereo() -> Option<Vec<i16>> {
    read_pcm(&reference_dir()?.join("src01_stereo.sw")).ok()
}

fn read_pcm(path: &Path) -> Result<Vec<i16>, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

fn write_pcm(path: &Path, pcm: &[i16]) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(pcm.len() * 2);
    for &sample in pcm {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    std::fs::write(path, &bytes).map_err(|error| format!("writing {}: {error}", path.display()))
}

/// One configuration of the encode matrix.
#[derive(Debug, Clone, Copy)]
struct Configuration {
    application: Application,
    channels: usize,
    bitrate_bps: i32,
    duration_ms: f32,
    rate_control: RateControl,
    bandwidth: Option<Bandwidth>,
    in_band_fec: bool,
    dtx: bool,
    packet_loss_percent: i32,
}

impl Configuration {
    fn label(&self) -> String {
        format!(
            "{}_{}ch_{}bps_{}ms_{}{}{}{}",
            match self.application {
                Application::Voip => "voip",
                Application::Audio => "audio",
                Application::RestrictedLowdelay => "lowdelay",
            },
            self.channels,
            self.bitrate_bps,
            self.duration_ms,
            match self.rate_control {
                RateControl::Variable => "vbr",
                RateControl::ConstrainedVariable => "cvbr",
                RateControl::Constant => "cbr",
            },
            match self.bandwidth {
                None => String::new(),
                Some(bandwidth) => format!("_{}", bandwidth_name(bandwidth)),
            },
            if self.in_band_fec { "_fec" } else { "" },
            if self.dtx { "_dtx" } else { "" },
        )
    }

    fn frame_size(&self) -> usize {
        (REFERENCE_RATE_HZ as f32 * self.duration_ms / 1000.0) as usize
    }

    fn application_name(&self) -> &'static str {
        match self.application {
            Application::Voip => "voip",
            Application::Audio => "audio",
            Application::RestrictedLowdelay => "restricted-lowdelay",
        }
    }
}

fn bandwidth_name(bandwidth: Bandwidth) -> &'static str {
    match bandwidth {
        Bandwidth::Narrowband => "NB",
        Bandwidth::Mediumband => "MB",
        Bandwidth::Wideband => "WB",
        Bandwidth::SuperWideband => "SWB",
        Bandwidth::Fullband => "FB",
    }
}

/// The full matrix: 3 modes (reached by rate and application rather than forced), 5 bandwidths, all
/// six frame durations, mono and stereo, all three rate modes, plus DTX and FEC.
fn matrix() -> Vec<Configuration> {
    let base = Configuration {
        application: Application::Voip,
        channels: 1,
        bitrate_bps: 24_000,
        duration_ms: 20.0,
        rate_control: RateControl::ConstrainedVariable,
        bandwidth: None,
        in_band_fec: false,
        dtx: false,
        packet_loss_percent: 0,
    };
    let mut configurations = Vec::new();

    // Rate sweep at every duration, both applications, both channel counts: this is what walks the
    // mode decision across SILK, hybrid and CELT-only without ever forcing it.
    for &application in &[Application::Voip, Application::Audio] {
        for &channels in &[1usize, 2] {
            for &duration_ms in &[2.5f32, 5.0, 10.0, 20.0, 40.0, 60.0] {
                for &bitrate_bps in &[12_000i32, 24_000, 48_000, 96_000] {
                    configurations.push(Configuration {
                        application,
                        channels,
                        bitrate_bps: bitrate_bps * channels as i32,
                        duration_ms,
                        ..base
                    });
                }
            }
        }
    }
    // Restricted low delay, which is CELT-only by construction.
    for &duration_ms in &[2.5f32, 5.0, 10.0, 20.0] {
        configurations.push(Configuration {
            application: Application::RestrictedLowdelay,
            duration_ms,
            bitrate_bps: 64_000,
            ..base
        });
    }
    // Every bandwidth, forced, so the TOC sweep covers all five rather than only the ones the rate
    // ladder happens to pick.
    for bandwidth in [
        Bandwidth::Narrowband,
        Bandwidth::Mediumband,
        Bandwidth::Wideband,
        Bandwidth::SuperWideband,
        Bandwidth::Fullband,
    ] {
        configurations.push(Configuration {
            bandwidth: Some(bandwidth),
            bitrate_bps: 32_000,
            ..base
        });
    }
    // The two non-default rate modes, and the FEC and DTX paths.
    for rate_control in [RateControl::Variable, RateControl::Constant] {
        for &channels in &[1usize, 2] {
            configurations.push(Configuration {
                rate_control,
                channels,
                bitrate_bps: 32_000 * channels as i32,
                ..base
            });
        }
    }
    configurations.push(Configuration {
        in_band_fec: true,
        packet_loss_percent: 20,
        bitrate_bps: 24_000,
        ..base
    });
    configurations.push(Configuration {
        dtx: true,
        bitrate_bps: 24_000,
        ..base
    });
    configurations
}

/// One encoded packet with the encoder's own final range.
struct EncodedPacket {
    payload: Vec<u8>,
    final_range: u32,
}

/// Build an encoder for a configuration.
fn build(configuration: &Configuration) -> Result<OpusEncoder, String> {
    let mut encoder = OpusEncoder::new(
        REFERENCE_RATE_HZ,
        configuration.channels,
        configuration.application,
    )
    .map_err(|error| format!("OpusEncoder::new: {error:?}"))?;
    encoder
        .set_bitrate(Some(configuration.bitrate_bps))
        .map_err(|error| format!("set_bitrate: {error:?}"))?;
    encoder.set_rate_control(configuration.rate_control);
    encoder
        .set_complexity(COMPARISON_COMPLEXITY)
        .map_err(|error| format!("set_complexity: {error:?}"))?;
    encoder.set_bandwidth(configuration.bandwidth);
    encoder.set_in_band_fec(configuration.in_band_fec);
    encoder.set_dtx(configuration.dtx);
    encoder
        .set_packet_loss_percent(configuration.packet_loss_percent)
        .map_err(|error| format!("set_packet_loss_percent: {error:?}"))?;
    encoder.set_signal_hint(SignalHint::Auto);
    Ok(encoder)
}

/// Encode [`AUDIO_MS`] of `source` with our encoder.
fn encode(configuration: &Configuration, source: &[i16]) -> Result<Vec<EncodedPacket>, String> {
    let mut encoder = build(configuration)?;
    let frame_size = configuration.frame_size();
    let per_packet = frame_size * configuration.channels;
    let packet_count = (AUDIO_MS as f32 / configuration.duration_ms) as usize;

    let mut packets = Vec::new();
    for index in 0..packet_count {
        let start = index * per_packet;
        if start + per_packet > source.len() {
            break;
        }
        let mut buffer = vec![0u8; 1500];
        let result = encoder
            .encode(&source[start..start + per_packet], frame_size, &mut buffer)
            .map_err(|error| format!("packet {index}: {error:?}"))?;
        packets.push(EncodedPacket {
            payload: buffer[..result.bytes].to_vec(),
            final_range: result.final_range,
        });
    }
    if packets.is_empty() {
        return Err("no packets encoded".to_string());
    }
    Ok(packets)
}

/// The three mode-switching streams the exactness gates are driven over, as
/// `(label, channels, application, half-period in packets)`.
const SWITCHING_STREAMS: [(&str, usize, Application, usize); 3] = [
    ("mono_voip_fast", 1, Application::Voip, 3),
    ("mono_audio_slow", 1, Application::Audio, 11),
    ("stereo_audio", 2, Application::Audio, 5),
];

/// How many 20 ms packets each switching stream encodes.
const SWITCHING_PACKETS: usize = 120;

/// Encode a stream that **switches mode mid-flight**: the rate is swept back and forth across the
/// SILK/CELT crossing on `period`-packet half-cycles, with FEC, packet loss and DTX turned on and
/// off underneath it so the mode moves for several different reasons rather than one.
///
/// Returns the packets and how many times the mode actually changed, so a caller can refuse to pass
/// on a sweep that never switched.
fn encode_switching(
    channels: usize,
    application: Application,
    period: usize,
    with_dtx: bool,
    source: &[i16],
) -> Result<(Vec<EncodedPacket>, usize), String> {
    let frame_size = 960usize;
    let mut encoder = OpusEncoder::new(REFERENCE_RATE_HZ, channels, application)
        .map_err(|error| format!("OpusEncoder::new: {error:?}"))?;
    encoder
        .set_complexity(COMPARISON_COMPLEXITY)
        .map_err(|error| format!("set_complexity: {error:?}"))?;
    encoder.set_rate_control(RateControl::ConstrainedVariable);

    let mut packets = Vec::new();
    let mut previous_mode = None;
    let mut mode_changes = 0usize;
    for index in 0..SWITCHING_PACKETS {
        let start = index * frame_size * channels;
        if start + frame_size * channels > source.len() {
            break;
        }
        let low = (index / period).is_multiple_of(2);
        let bitrate = if low { 10_000 } else { 140_000 } * channels as i32;
        encoder
            .set_bitrate(Some(bitrate))
            .map_err(|error| format!("set_bitrate: {error:?}"))?;
        encoder.set_in_band_fec(index % 17 < 6);
        encoder
            .set_packet_loss_percent(if index % 17 < 6 { 25 } else { 0 })
            .map_err(|error| format!("set_packet_loss_percent: {error:?}"))?;
        encoder.set_dtx(with_dtx && index % 23 < 4);

        let mut buffer = vec![0u8; 1500];
        let result = encoder
            .encode(
                &source[start..start + frame_size * channels],
                frame_size,
                &mut buffer,
            )
            .map_err(|error| format!("packet {index}: {error:?}"))?;
        if previous_mode.is_some_and(|mode| mode != result.mode) {
            mode_changes += 1;
        }
        previous_mode = Some(result.mode);
        packets.push(EncodedPacket {
            payload: buffer[..result.bytes].to_vec(),
            final_range: result.final_range,
        });
    }
    Ok((packets, mode_changes))
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

/// Read a `.bit` file back into packets, so libopus' own TOC bytes can be compared with ours.
fn read_bit_file(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    let mut packets = Vec::new();
    let mut cursor = 0usize;
    while cursor + 8 <= bytes.len() {
        let length = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        cursor += 8;
        if cursor + length > bytes.len() {
            break;
        }
        packets.push(bytes[cursor..cursor + length].to_vec());
        cursor += length;
    }
    Ok(packets)
}

/// Run `opus_demo -d`. Its own complaint is returned, including "Range coder state mismatch", which
/// is check 1 failing.
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

/// Encode the same source with libopus at the same configuration.
fn libopus_encode(
    configuration: &Configuration,
    source_path: &Path,
    bit_path: &Path,
) -> Result<(), String> {
    let demo = opus_demo().ok_or_else(|| "opus_demo not built".to_string())?;
    let mut command = Command::new(&demo);
    command
        .arg("-e")
        .arg(configuration.application_name())
        .arg(REFERENCE_RATE_HZ.to_string())
        .arg(configuration.channels.to_string())
        .arg(configuration.bitrate_bps.to_string())
        .arg("-complexity")
        .arg(COMPARISON_COMPLEXITY.to_string())
        .arg("-framesize")
        .arg(format!("{}", configuration.duration_ms))
        .arg("-max_payload")
        .arg("1500");
    match configuration.rate_control {
        RateControl::Variable => {}
        RateControl::ConstrainedVariable => {
            command.arg("-cvbr");
        }
        RateControl::Constant => {
            command.arg("-cbr");
        }
    }
    if let Some(bandwidth) = configuration.bandwidth {
        command.arg("-bandwidth").arg(bandwidth_name(bandwidth));
    }
    if configuration.in_band_fec {
        command.arg("-inbandfec");
    }
    if configuration.dtx {
        command.arg("-dtx");
    }
    if configuration.packet_loss_percent > 0 {
        // `-loss` also *simulates* loss on the decode side, which we never run here; on the encode
        // side it is what sets `packetLossPercentage`.
        command
            .arg("-loss")
            .arg(configuration.packet_loss_percent.to_string());
    }
    let output = command
        .arg(source_path)
        .arg(bit_path)
        .output()
        .map_err(|error| format!("running opus_demo -e: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "opus_demo -e failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Segmental SNR in dB over 20 ms frames, voiced frames only, clamped per frame to [-10, 35].
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

/// The best segmental SNR over a small range of alignments, so a codec-delay difference is not
/// mistaken for distortion.
fn best_aligned_snr(reference: &[i16], test: &[i16], channels: usize) -> f64 {
    let frame = 20 * 48 * channels;
    let mut best = f64::NEG_INFINITY;
    for lag in (0..=(20 * 48)).step_by(4) {
        let offset = lag * channels;
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

/// Run `opus_compare` and return its quality percentage.
fn run_opus_compare(reference: &Path, test: &Path, stereo: bool) -> Result<f64, String> {
    let tool = opus_compare().ok_or_else(|| "opus_compare not found".to_string())?;
    let mut command = Command::new(&tool);
    if stereo {
        command.arg("-s");
    }
    let output = command
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
    if !output.status.success() || !text.contains("PASSES") {
        return Err(format!("opus_compare did not pass: {text}"));
    }
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
    modes: BTreeSet<&'static str>,
    bandwidths: BTreeSet<&'static str>,
    durations: BTreeSet<String>,
    channel_counts: BTreeSet<usize>,
    rate_modes: BTreeSet<&'static str>,
    configurations: usize,
    packets: usize,
    dtx_packets: usize,
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Silk => "silk",
        Mode::Hybrid => "hybrid",
        Mode::Celt => "celt",
    }
}

/// The staged source for a configuration, and the scratch directory.
struct Fixture {
    mono: Vec<i16>,
    stereo: Vec<i16>,
    scratch: PathBuf,
}

fn fixture() -> Option<Fixture> {
    reference_dir()?;
    opus_demo()?;
    let skip = SKIP_MS * REFERENCE_RATE_HZ as usize / 1000;
    let mono = source_mono()?;
    let stereo = source_stereo()?;
    if mono.len() <= skip || stereo.len() <= 2 * skip {
        return None;
    }
    let scratch = std::env::temp_dir().join("siphon_opus_encode_conformance");
    std::fs::create_dir_all(&scratch).ok()?;
    Some(Fixture {
        mono: mono[skip..].to_vec(),
        stereo: stereo[2 * skip..].to_vec(),
        scratch,
    })
}

impl Fixture {
    fn source(&self, channels: usize) -> &[i16] {
        if channels == 2 {
            &self.stereo
        } else {
            &self.mono
        }
    }
}

/// **Checks 1 and 2**, over the whole matrix: libopus must end every packet exactly where we said,
/// and must have made the same discrete decisions.
#[test]
fn our_packets_match_libopus_on_range_state_and_on_every_discrete_decision() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };

    let mut coverage = Coverage::default();
    let mut failures: Vec<String> = Vec::new();
    let mut toc_mismatches: Vec<String> = Vec::new();

    for configuration in matrix() {
        let label = configuration.label();
        let source = fixture.source(configuration.channels);
        let scored_samples = (AUDIO_MS * REFERENCE_RATE_HZ as usize / 1000
            * configuration.channels)
            .min(source.len());
        let source_path = fixture
            .scratch
            .join(format!("source_{}ch.sw", configuration.channels));
        if let Err(error) = write_pcm(&source_path, &source[..scored_samples]) {
            failures.push(format!("{label}: {error}"));
            continue;
        }

        let packets = match encode(&configuration, source) {
            Ok(packets) => packets,
            Err(error) => {
                failures.push(format!("{label}: encode: {error}"));
                continue;
            }
        };

        // Check 1: libopus decodes and agrees on every packet's final range, or aborts.
        let bit_path = fixture.scratch.join(format!("ours_{label}.bit"));
        let dec_path = fixture.scratch.join(format!("ours_{label}.dec"));
        if let Err(error) = write_bit_file(&bit_path, &packets) {
            failures.push(format!("{label}: {error}"));
            continue;
        }
        if let Err(error) = decode_with_libopus(&bit_path, &dec_path, configuration.channels) {
            failures.push(format!("{label}: libopus decode of our stream: {error}"));
            continue;
        }

        // Check 2: the same discrete decisions as libopus, packet for packet.
        let their_bit = fixture.scratch.join(format!("libopus_{label}.bit"));
        match libopus_encode(&configuration, &source_path, &their_bit) {
            Ok(()) => match read_bit_file(&their_bit) {
                Ok(theirs) => {
                    let compared = theirs.len().min(packets.len());
                    let mut mismatch = None;
                    for index in 0..compared {
                        let ours = packets[index].payload.first().copied().unwrap_or(0);
                        let them = theirs[index].first().copied().unwrap_or(0);
                        // The frame-count code is a packing choice driven by the frame *sizes*, not
                        // a coding decision, so only the config and stereo bits are compared.
                        if ours & 0xFC != them & 0xFC {
                            mismatch = Some((index, ours, them));
                            break;
                        }
                    }
                    if let Some((index, ours, them)) = mismatch {
                        let ours_toc = packet::Toc::parse(ours);
                        let their_toc = packet::Toc::parse(them);
                        toc_mismatches.push(format!(
                            "{label}: packet {index} of {compared}: ours {:?}/{:?}/{}ch vs libopus \
                             {:?}/{:?}/{}ch",
                            ours_toc.mode(),
                            ours_toc.bandwidth(),
                            ours_toc.channels(),
                            their_toc.mode(),
                            their_toc.bandwidth(),
                            their_toc.channels(),
                        ));
                    }
                }
                Err(error) => {
                    failures.push(format!("{label}: reading libopus' bitstream: {error}"))
                }
            },
            Err(error) => failures.push(format!("{label}: libopus encode: {error}")),
        }

        for packet_bytes in &packets {
            let toc = packet::Toc::parse(packet_bytes.payload[0]);
            coverage.modes.insert(mode_name(toc.mode()));
            coverage.bandwidths.insert(bandwidth_name(toc.bandwidth()));
            coverage.channel_counts.insert(usize::from(toc.channels()));
            if packet_bytes.payload.len() <= 2 {
                coverage.dtx_packets += 1;
            }
        }
        coverage
            .durations
            .insert(format!("{}", configuration.duration_ms));
        coverage
            .rate_modes
            .insert(match configuration.rate_control {
                RateControl::Variable => "vbr",
                RateControl::ConstrainedVariable => "cvbr",
                RateControl::Constant => "cbr",
            });
        coverage.configurations += 1;
        coverage.packets += packets.len();
    }

    assert!(
        failures.is_empty(),
        "Opus encode conformance failures:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        toc_mismatches.is_empty(),
        "our discrete decisions diverged from libopus':\n  {}",
        toc_mismatches.join("\n  ")
    );
    assert!(
        coverage.configurations >= 100,
        "only {} configurations scored",
        coverage.configurations
    );
    assert_eq!(
        coverage.modes,
        BTreeSet::from(["celt", "hybrid", "silk"]),
        "all three modes must be reached by the rate ladder, not forced"
    );
    assert_eq!(
        coverage.bandwidths,
        BTreeSet::from(["FB", "MB", "NB", "SWB", "WB"]),
        "bandwidth coverage"
    );
    assert_eq!(
        coverage.durations,
        BTreeSet::from([
            "2.5".to_string(),
            "5".to_string(),
            "10".to_string(),
            "20".to_string(),
            "40".to_string(),
            "60".to_string(),
        ]),
        "duration coverage"
    );
    assert_eq!(
        coverage.channel_counts,
        BTreeSet::from([1, 2]),
        "channel coverage"
    );
    assert_eq!(coverage.rate_modes.len(), 3, "rate-mode coverage");
    assert!(
        coverage.packets > 5_000,
        "only {} packets",
        coverage.packets
    );
    eprintln!(
        "Opus encode: {} configurations, {} packets, modes {:?}, bandwidths {:?}, {} DTX packets — \
         libopus agreed on every packet's range state and on every TOC",
        coverage.configurations,
        coverage.packets,
        coverage.modes,
        coverage.bandwidths,
        coverage.dtx_packets
    );
}

/// A stream that **switches mode mid-flight** must still satisfy check 1, packet for packet.
///
/// This is the path the fixed matrix cannot reach: every configuration there holds one bitrate, so
/// the mode is decided once and never changes. A switch is the hardest thing this layer does —
/// libopus signals it with a redundancy flag inside the range coder (unconditionally in hybrid,
/// whether or not redundancy follows) and bridges the seam with a 5 ms CELT frame appended after the
/// main payload, whose own range value is XORed into the packet's. Get any of that wrong — the flag,
/// the redundancy length, the order of the two frames, the XOR — and libopus' decoder either
/// desynchronises or ends the packet on a different value. Both show up here.
///
/// Both switch directions are covered: the rate sweep crosses in both, and DTX-driven and
/// FEC-driven mode changes are swept alongside so the redundancy decision is reached from more than
/// one cause.
#[test]
fn a_stream_that_switches_mode_mid_flight_still_matches_libopus_on_range_state() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };

    let mut failures: Vec<String> = Vec::new();
    let mut scored = 0usize;
    let mut mode_changes = 0usize;

    for &(label, channels, application, period) in &SWITCHING_STREAMS {
        let source = fixture.source(channels);
        let (packets, changes) = match encode_switching(channels, application, period, true, source)
        {
            Ok(encoded) => encoded,
            Err(error) => {
                failures.push(format!("{label}: {error}"));
                continue;
            }
        };
        mode_changes += changes;
        if packets.len() < SWITCHING_PACKETS / 2 {
            failures.push(format!("{label}: only {} packets encoded", packets.len()));
            continue;
        }

        let bit_path = fixture.scratch.join(format!("switch_{label}.bit"));
        let dec_path = fixture.scratch.join(format!("switch_{label}.dec"));
        if let Err(error) = write_bit_file(&bit_path, &packets) {
            failures.push(format!("{label}: {error}"));
            continue;
        }
        match decode_with_libopus(&bit_path, &dec_path, channels) {
            Ok(_) => scored += 1,
            Err(error) => failures.push(format!("{label}: libopus decode: {error}")),
        }
    }

    assert!(
        failures.is_empty(),
        "mode-switch conformance failures:\n  {}",
        failures.join("\n  ")
    );
    assert_eq!(scored, 3, "not every switching stream was scored");
    assert!(
        mode_changes >= 30,
        "the sweep only changed mode {mode_changes} times, so the switch path is barely covered"
    );
    eprintln!(
        "Opus mode switching: 3 streams, {mode_changes} mode changes, all accepted by libopus"
    );
}

/// Check 1 has to be *live*: corrupt one byte of one packet and libopus must reject the stream.
/// Without this, a harness that silently wrote a broken `.bit` file would pass for the wrong reason.
#[test]
fn the_range_check_is_live() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };
    let configuration = Configuration {
        application: Application::Voip,
        channels: 1,
        bitrate_bps: 32_000,
        duration_ms: 20.0,
        rate_control: RateControl::ConstrainedVariable,
        bandwidth: None,
        in_band_fec: false,
        dtx: false,
        packet_loss_percent: 0,
    };
    let mut packets = encode(&configuration, fixture.source(1)).expect("encode");

    let clean_bit = fixture.scratch.join("live_clean.bit");
    let clean_dec = fixture.scratch.join("live_clean.dec");
    write_bit_file(&clean_bit, &packets).expect("write");
    decode_with_libopus(&clean_bit, &clean_dec, 1).expect("the clean stream must decode");

    // Flip a bit inside the range-coded body of a packet in the middle of the stream.
    let victim = packets.len() / 2;
    let offset = packets[victim].payload.len() / 2;
    packets[victim].payload[offset] ^= 0x40;
    let dirty_bit = fixture.scratch.join("live_dirty.bit");
    let dirty_dec = fixture.scratch.join("live_dirty.dec");
    write_bit_file(&dirty_bit, &packets).expect("write");
    let result = decode_with_libopus(&dirty_bit, &dirty_dec, 1);
    assert!(
        result.is_err(),
        "libopus accepted a corrupted packet against our stated final range, so check 1 proves \
         nothing"
    );
}

/// **Check 3**: our encoder must not be materially worse than libopus' at the same configuration.
#[test]
fn our_quality_matches_libopus_at_the_same_configuration() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };

    // The quality comparison is meaningful per (application, rate, channels); the duration and mode
    // axes are covered by the exactness gate above.
    let configurations: Vec<Configuration> = matrix()
        .into_iter()
        .filter(|configuration| {
            configuration.duration_ms == 20.0
                && configuration.bandwidth.is_none()
                && !configuration.in_band_fec
                && !configuration.dtx
                && configuration.rate_control == RateControl::ConstrainedVariable
        })
        .collect();

    let mut failures: Vec<String> = Vec::new();
    let mut scored = 0usize;

    for configuration in configurations {
        let label = configuration.label();
        let source = fixture.source(configuration.channels);
        let scored_samples = (AUDIO_MS * REFERENCE_RATE_HZ as usize / 1000
            * configuration.channels)
            .min(source.len());
        let source_path = fixture
            .scratch
            .join(format!("quality_source_{}ch.sw", configuration.channels));
        if let Err(error) = write_pcm(&source_path, &source[..scored_samples]) {
            failures.push(format!("{label}: {error}"));
            continue;
        }

        let packets = match encode(&configuration, source) {
            Ok(packets) => packets,
            Err(error) => {
                failures.push(format!("{label}: encode: {error}"));
                continue;
            }
        };
        let our_bit = fixture.scratch.join(format!("quality_ours_{label}.bit"));
        let our_dec = fixture.scratch.join(format!("quality_ours_{label}.dec"));
        if let Err(error) = write_bit_file(&our_bit, &packets) {
            failures.push(format!("{label}: {error}"));
            continue;
        }
        let ours = match decode_with_libopus(&our_bit, &our_dec, configuration.channels) {
            Ok(pcm) => pcm,
            Err(error) => {
                failures.push(format!("{label}: libopus decode of our stream: {error}"));
                continue;
            }
        };

        let their_bit = fixture.scratch.join(format!("quality_theirs_{label}.bit"));
        let their_dec = fixture.scratch.join(format!("quality_theirs_{label}.dec"));
        if let Err(error) = libopus_encode(&configuration, &source_path, &their_bit) {
            failures.push(format!("{label}: libopus encode: {error}"));
            continue;
        }
        let theirs = match decode_with_libopus(&their_bit, &their_dec, configuration.channels) {
            Ok(pcm) => pcm,
            Err(error) => {
                failures.push(format!(
                    "{label}: libopus decode of its own stream: {error}"
                ));
                continue;
            }
        };

        let length = ours.len().min(theirs.len()).min(scored_samples);
        if length < 48_000 {
            failures.push(format!("{label}: too little audio to score ({length})"));
            continue;
        }
        let reference = &source[..length];
        let our_snr = best_aligned_snr(reference, &ours[..length], configuration.channels);
        let their_snr = best_aligned_snr(reference, &theirs[..length], configuration.channels);
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
        "Opus encoder quality failures:\n  {}",
        failures.join("\n  ")
    );
    assert!(scored >= 12, "only {scored} configurations scored");
}

/// **Check 4**: `opus_compare` against the original PCM, at the rates and bandwidths where a
/// transparent encode is the expectation.
#[test]
fn high_rate_fullband_encodes_pass_opus_compare() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };
    if opus_compare().is_none() {
        eprintln!("skipping: opus_compare not found (set SIPHON_RTP_OPUS_COMPARE)");
        return;
    }

    let mut scores: Vec<(String, f64)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for &channels in &[1usize, 2] {
        for &bitrate_bps in &[128_000i32, 256_000] {
            let configuration = Configuration {
                application: Application::Audio,
                channels,
                bitrate_bps: bitrate_bps * channels as i32,
                duration_ms: 20.0,
                rate_control: RateControl::Variable,
                bandwidth: Some(Bandwidth::Fullband),
                in_band_fec: false,
                dtx: false,
                packet_loss_percent: 0,
            };
            let label = configuration.label();
            let source = fixture.source(channels);
            let scored_samples =
                (AUDIO_MS * REFERENCE_RATE_HZ as usize / 1000 * channels).min(source.len());

            let packets = match encode(&configuration, source) {
                Ok(packets) => packets,
                Err(error) => {
                    failures.push(format!("{label}: encode: {error}"));
                    continue;
                }
            };
            let bit_path = fixture.scratch.join(format!("compare_{label}.bit"));
            let dec_path = fixture.scratch.join(format!("compare_{label}.dec"));
            if let Err(error) = write_bit_file(&bit_path, &packets) {
                failures.push(format!("{label}: {error}"));
                continue;
            }
            // `opus_compare` reads its *reference* as 2-channel unconditionally and its *test* file
            // at the `-s` channel count (`opus_compare.c:231-236`), so the decode stays at the
            // encode's channel count and only the reference is widened.
            let decoded = match decode_with_libopus(&bit_path, &dec_path, channels) {
                Ok(pcm) => pcm,
                Err(error) => {
                    failures.push(format!("{label}: libopus decode: {error}"));
                    continue;
                }
            };

            // `opus_demo -d` cannot know the encoder's look-ahead, so its output is shifted by the
            // codec delay; unaligned, even libopus' own 256 kb/s round trip fails.
            let shift = CODEC_DELAY_SAMPLES * channels;
            if decoded.len() <= shift {
                failures.push(format!("{label}: decode too short"));
                continue;
            }
            let aligned = &decoded[shift..];
            let frames = (aligned.len() / channels).min(scored_samples / channels);
            // The reference, widened to stereo when the encode was mono, so both files present the
            // same number of *frames* to the tool.
            let mut reference: Vec<i16> = Vec::with_capacity(frames * 2);
            for index in 0..frames {
                if channels == 2 {
                    reference.push(source[2 * index]);
                    reference.push(source[2 * index + 1]);
                } else {
                    reference.push(source[index]);
                    reference.push(source[index]);
                }
            }
            let reference_path = fixture.scratch.join(format!("compare_ref_{label}.sw"));
            let test_path = fixture.scratch.join(format!("compare_test_{label}.sw"));
            if write_pcm(&reference_path, &reference).is_err()
                || write_pcm(&test_path, &aligned[..frames * channels]).is_err()
            {
                failures.push(format!("{label}: staging the comparison failed"));
                continue;
            }
            match run_opus_compare(&reference_path, &test_path, channels == 2) {
                Ok(quality) => scores.push((label, quality)),
                Err(error) => failures.push(format!("{label}: {error}")),
            }
        }
    }

    assert!(
        failures.is_empty(),
        "opus_compare failures:\n  {}",
        failures.join("\n  ")
    );
    assert!(scores.len() >= 4, "only {} scores", scores.len());
    for (label, quality) in &scores {
        eprintln!("  {label}: opus_compare {quality:.1}%");
    }
}

/// What one stream's cross-decode proved.
#[derive(Default)]
struct CrossDecode {
    packets: usize,
    samples: usize,
    differing: usize,
    worst_lsb: i32,
    worst_at: usize,
    modes: BTreeSet<&'static str>,
    channel_counts: BTreeSet<usize>,
}

/// Decode `packets` with [`OpusDecoder`] and with `opus_demo -d`, and require the two to be
/// identical — same sample count, same samples, and the same range state at the end of every packet.
///
/// The two decoders are driven at the same rate and channel count so nothing about the comparison
/// is resampled or downmixed, and `opus_demo -d` applies no skip on the decode-only path
/// (`opus_demo.c:382`, where `skip` is only assigned from `OPUS_GET_LOOKAHEAD` on the encode side),
/// so the two outputs are aligned sample zero to sample zero with no shift to compensate.
fn cross_decode(
    fixture: &Fixture,
    label: &str,
    channels: usize,
    packets: &[EncodedPacket],
) -> Result<CrossDecode, String> {
    // `opus_demo` treats a zero-length packet as a *loss* and conceals it (`opus_demo.c:981`),
    // which would put samples in its output that came from no packet at all. Our encoder never
    // emits one — DTX is a bare one-byte TOC (RFC 6716 §3.1) — so this is a guard, not a filter.
    if let Some(index) = packets.iter().position(|packet| packet.payload.is_empty()) {
        return Err(format!(
            "packet {index} is zero-length, which opus_demo would conceal rather than decode"
        ));
    }

    let bit_path = fixture.scratch.join(format!("cross_{label}.bit"));
    let dec_path = fixture.scratch.join(format!("cross_{label}.dec"));
    write_bit_file(&bit_path, packets)?;
    let theirs = decode_with_libopus(&bit_path, &dec_path, channels)?;

    let mut decoder = OpusDecoder::new(REFERENCE_RATE_HZ, channels)
        .map_err(|error| format!("OpusDecoder::new: {error}"))?;
    let mut frame = vec![0i16; MAX_PACKET_SAMPLES * channels];
    let mut ours: Vec<i16> = Vec::with_capacity(theirs.len());
    let mut result = CrossDecode::default();

    for (index, packet) in packets.iter().enumerate() {
        let written = decoder
            .decode(Some(&packet.payload), &mut frame, MAX_PACKET_SAMPLES, false)
            .map_err(|error| format!("packet {index}: our decode failed: {error}"))?;
        ours.extend_from_slice(&frame[..written * channels]);
        // Both directions on one packet: our decoder must land on the value our encoder reported,
        // which `opus_demo -d` has already checked from its side. A divergence here names the
        // packet, which a sample diff further down the stream would not.
        if decoder.final_range() != packet.final_range {
            return Err(format!(
                "packet {index}: our decoder ended on {:#010x}, our encoder said {:#010x}",
                decoder.final_range(),
                packet.final_range
            ));
        }
        let toc = packet::Toc::parse(packet.payload[0]);
        result.modes.insert(mode_name(toc.mode()));
        result.packets += 1;
    }
    result.channel_counts.insert(channels);

    if ours.len() != theirs.len() {
        return Err(format!(
            "sample count differs: ours {}, libopus {}",
            ours.len(),
            theirs.len()
        ));
    }

    // A stream every one of whose packets is SILK-only is held to *zero*: both decoders are integer
    // fixed-point all the way through, so there is nothing for them to round differently and a
    // single differing sample is a bug. This is the same bar `silk_encode_conformance` holds against
    // `SilkDecoder`, raised to the Opus layer, and it is met on every SILK-only stream here.
    let silk_only = result.modes.len() == 1 && result.modes.contains("silk");
    let allowed = if silk_only { 0 } else { MAX_LSB_DIFFERENCE };

    for (index, (&ours_sample, &their_sample)) in ours.iter().zip(theirs.iter()).enumerate() {
        let delta = (i32::from(ours_sample) - i32::from(their_sample)).abs();
        if delta == 0 {
            continue;
        }
        result.differing += 1;
        if delta > result.worst_lsb {
            result.worst_lsb = delta;
            result.worst_at = index;
        }
        if delta > allowed {
            return Err(format!(
                "sample {index} of {} differs by {delta} (ours {ours_sample}, libopus \
                 {their_sample}); this stream's modes are {:?}, which allows {allowed}",
                ours.len(),
                result.modes
            ));
        }
    }
    result.samples = ours.len();
    Ok(result)
}

/// **Check 5**: our decoder and libopus' must turn our encoder's stream into **the same audio**,
/// over the whole matrix and over a stream that switches mode mid-flight.
///
/// This is the check the encoder could not be held to while the top-level decoder lived on another
/// branch. It reaches everything `final_range` structurally cannot: the redundancy frame's
/// cross-fade window, the SILK↔CELT sum in hybrid, the resampler, the stereo unmixing and the PLC
/// state a mode switch leaves behind. Two decoders that were written independently agreeing on a
/// stream neither has seen before is a very strong statement about that stream — and our decoder is
/// itself gated on the 12 official RFC 6716 vectors and 75 166 redundancy-bearing packets.
///
/// The bar is **sample-exact wherever sample-exactness exists**, and it is not one number:
///
/// * a **SILK-only** stream must be identical, sample for sample, with no tolerance at all — both
///   decoders are integer fixed-point there. Every SILK-only stream in this matrix meets that.
/// * a stream carrying a **CELT or hybrid** packet is held to [`MAX_LSB_DIFFERENCE`] and to
///   [`MAX_DIFFERING_FRACTION`]. CELT is float in both implementations, which RFC 6716 §6 accounts
///   for by defining conformance as an `opus_compare` pass rather than as bit-exact PCM. See
///   [`MAX_LSB_DIFFERENCE`] for why that is not a hole: every packet's range state is still an exact
///   equality checked from both sides, so only post-entropy arithmetic is in the tolerance.
#[test]
fn our_decoder_and_libopus_agree_sample_for_sample_on_our_own_stream() {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: reference/opus, opus_demo or the source vectors are absent");
        return;
    };

    let mut failures: Vec<String> = Vec::new();
    let mut total = CrossDecode::default();
    let mut streams = 0usize;
    let mut silk_only_streams = 0usize;

    for configuration in matrix() {
        let label = configuration.label();
        let packets = match encode(&configuration, fixture.source(configuration.channels)) {
            Ok(packets) => packets,
            Err(error) => {
                failures.push(format!("{label}: encode: {error}"));
                continue;
            }
        };
        match cross_decode(&fixture, &label, configuration.channels, &packets) {
            Ok(scored) => {
                if scored.differing > 0 {
                    eprintln!(
                        "  {label}: {}/{} differ, worst {} LSB at {}, modes {:?}",
                        scored.differing,
                        scored.samples,
                        scored.worst_lsb,
                        scored.worst_at,
                        scored.modes
                    );
                }
                if scored.modes.len() == 1 && scored.modes.contains("silk") {
                    silk_only_streams += 1;
                }
                total.packets += scored.packets;
                total.samples += scored.samples;
                total.differing += scored.differing;
                total.worst_lsb = total.worst_lsb.max(scored.worst_lsb);
                total.modes.extend(scored.modes);
                total.channel_counts.extend(scored.channel_counts);
                streams += 1;
            }
            Err(error) => failures.push(format!("{label}: {error}")),
        }
    }

    // The mode-switching stream, which the fixed matrix cannot reach: every configuration above
    // holds one bitrate, so its mode is decided once. DTX is left off here — not because it is
    // untested (the switching gate above sweeps it) but because it is the one setting that could
    // produce a packet `opus_demo` conceals instead of decoding, and this comparison is only
    // meaningful when both decoders are fed exactly the same frames.
    let mut switching_changes = 0usize;
    for &(label, channels, application, period) in &SWITCHING_STREAMS {
        let (packets, changes) = match encode_switching(
            channels,
            application,
            period,
            false,
            fixture.source(channels),
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                failures.push(format!("switch_{label}: {error}"));
                continue;
            }
        };
        switching_changes += changes;
        match cross_decode(&fixture, &format!("switch_{label}"), channels, &packets) {
            Ok(scored) => {
                if scored.differing > 0 {
                    eprintln!(
                        "  switch_{label}: {}/{} differ, worst {} LSB at {}",
                        scored.differing, scored.samples, scored.worst_lsb, scored.worst_at
                    );
                }
                total.packets += scored.packets;
                total.samples += scored.samples;
                total.differing += scored.differing;
                total.worst_lsb = total.worst_lsb.max(scored.worst_lsb);
                total.modes.extend(scored.modes);
                total.channel_counts.extend(scored.channel_counts);
                streams += 1;
            }
            Err(error) => failures.push(format!("switch_{label}: {error}")),
        }
    }

    assert!(
        failures.is_empty(),
        "our decoder and libopus disagreed on our own stream:\n  {}",
        failures.join("\n  ")
    );
    assert!(streams >= 100, "only {streams} streams cross-decoded");
    assert_eq!(
        total.modes,
        BTreeSet::from(["celt", "hybrid", "silk"]),
        "all three modes must be cross-decoded"
    );
    assert_eq!(
        total.channel_counts,
        BTreeSet::from([1, 2]),
        "both channel counts must be cross-decoded"
    );
    assert!(
        switching_changes >= 30,
        "the switching streams only changed mode {switching_changes} times"
    );
    assert!(
        total.samples > 10_000_000,
        "only {} samples compared",
        total.samples
    );
    assert!(
        total.worst_lsb <= MAX_LSB_DIFFERENCE,
        "worst sample difference {} LSB",
        total.worst_lsb
    );
    let differing_fraction = total.differing as f64 / total.samples as f64;
    assert!(
        differing_fraction <= MAX_DIFFERING_FRACTION,
        "{:.4} % of samples differ, over the {:.4} % bound — a bound of one LSB alone cannot tell \
         float rounding from a systematic bias",
        differing_fraction * 100.0,
        MAX_DIFFERING_FRACTION * 100.0
    );
    assert!(
        silk_only_streams > 0,
        "no SILK-only stream was cross-decoded, so the zero-tolerance arm covered nothing"
    );
    eprintln!(
        "Opus encode cross-decode: {streams} streams ({silk_only_streams} SILK-only, all \
         sample-exact), {} packets, {} samples, {} differing ({:.4} %), worst {} LSB, modes {:?}, \
         {switching_changes} mode changes",
        total.packets,
        total.samples,
        total.differing,
        differing_fraction * 100.0,
        total.worst_lsb,
        total.modes,
    );
}
