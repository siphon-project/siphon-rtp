//! Validate the Ogg Opus writer against **independent** decoders.
//!
//! A round trip through the in-tree Opus decoder and our own page parser proves nothing about the
//! container: a shared CRC, lacing or granule bug passes it. These tests hand the bytes we write to
//! opus-tools (`opusinfo`, `opusdec`, which read through libogg and libopusfile) and to `ffprobe`,
//! and assert what they read back.
//!
//! Skips (rather than fails) when a tool is absent, matching the Wireshark-backed tests. Install
//! `opus-tools` (and `ffmpeg` for the `ffprobe` check) to enable them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use siphon_rtp_media::ogg_opus::{OggOpusConfig, OggOpusWriter, PACKETS_PER_PAGE};
use siphon_rtp_media::player::WavSource;

/// Whether an external tool runs.
fn tool_available(tool: &str, version_flag: &str) -> bool {
    Command::new(tool)
        .arg(version_flag)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn opus_tools() -> bool {
    for tool in ["opusinfo", "opusdec"] {
        if !tool_available(tool, "-V") {
            eprintln!("skipping: {tool} not available (install opus-tools)");
            return false;
        }
    }
    true
}

fn config(rate: u32, channels: u8) -> OggOpusConfig<'static> {
    OggOpusConfig {
        sample_rate_hz: rate,
        channels,
        bitrate_bps: 16_000 * u32::from(channels),
        serial: 0x5150_4F4E,
        vendor: "siphon-rtp test",
    }
}

/// A sine at `hz` and amplitude 8000, interleaved; `None` channels carry silence.
fn tone(rate: u32, per_channel: &[Option<f32>], samples: usize) -> Vec<i16> {
    let mut pcm = Vec::with_capacity(samples * per_channel.len());
    for index in 0..samples {
        for hz in per_channel {
            pcm.push(hz.map_or(0, |hz| {
                let phase = 2.0 * std::f32::consts::PI * hz * index as f32 / rate as f32;
                (phase.sin() * 8000.0) as i16
            }));
        }
    }
    pcm
}

/// Write a complete stream, pushing in `chunk`-sample pieces.
fn write_stream(rate: u32, channels: u8, pcm: &[i16], chunk: usize) -> Vec<u8> {
    let mut writer = OggOpusWriter::new(config(rate, channels)).expect("writer");
    let mut out = Vec::new();
    writer.write_headers(&mut out).expect("headers");
    for piece in pcm.chunks(chunk.max(1)) {
        writer.push(piece, &mut out).expect("push");
    }
    writer.finish(&mut out).expect("finish");
    out
}

fn save(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, bytes).expect("write");
    path
}

/// `opusinfo`'s full report and whether it exited cleanly.
fn opusinfo(path: &Path) -> (bool, String) {
    let output = Command::new("opusinfo")
        .arg(path)
        .output()
        .expect("opusinfo");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

/// Decode with `opusdec` at 48 kHz (no resampler in the way) and return the interleaved samples and
/// channel count.
fn opusdec(path: &Path) -> (Vec<i16>, u16) {
    let wav = path.with_extension("decoded.wav");
    let output = Command::new("opusdec")
        .args(["--quiet", "--rate", "48000", "--force-wav"])
        .arg(path)
        .arg(&wav)
        .output()
        .expect("opusdec");
    assert!(
        output.status.success(),
        "opusdec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = WavSource::parse(&std::fs::read(&wav).expect("decoded")).expect("opusdec wav");
    assert_eq!(parsed.sample_rate_hz(), 48_000);
    (parsed.samples().to_vec(), parsed.channels())
}

/// One channel out of interleaved samples.
fn channel(samples: &[i16], channels: u16, index: usize) -> Vec<i16> {
    samples
        .iter()
        .skip(index)
        .step_by(usize::from(channels))
        .copied()
        .collect()
}

/// The frequency with the most energy, searched at 1 Hz steps over `low..=high`.
fn dominant_frequency(samples: &[i16], rate: f64, low: u32, high: u32) -> u32 {
    (low..=high)
        .max_by(|&a, &b| {
            power_at(samples, rate, f64::from(a)).total_cmp(&power_at(samples, rate, f64::from(b)))
        })
        .expect("range")
}

fn power_at(samples: &[i16], rate: f64, hz: f64) -> f64 {
    let step = 2.0 * std::f64::consts::PI * hz / rate;
    let (mut real, mut imaginary) = (0.0, 0.0);
    for (index, &sample) in samples.iter().enumerate() {
        let phase = step * index as f64;
        real += f64::from(sample) * phase.cos();
        imaginary += f64::from(sample) * phase.sin();
    }
    real * real + imaginary * imaginary
}

fn rms(samples: &[i16]) -> f64 {
    let sum: f64 = samples.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
    (sum / samples.len().max(1) as f64).sqrt()
}

#[test]
fn opusinfo_reads_the_stream_without_complaint() {
    // opusinfo walks every page through libogg (which drops a page whose CRC is wrong), checks the
    // header layout, granule monotonicity and the end-of-stream flag, and prints a WARNING for any
    // violation. A clean report on mono and stereo at both voice rates is the container check.
    if !opus_tools() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    for (rate, channels) in [(8_000u32, 1u8), (16_000, 1), (16_000, 2), (48_000, 2)] {
        let hz: Vec<Option<f32>> = vec![Some(440.0); usize::from(channels)];
        let pcm = tone(rate, &hz, rate as usize * 3);
        let path = save(
            directory.path(),
            &format!("info-{rate}-{channels}.opus"),
            &write_stream(
                rate,
                channels,
                &pcm,
                (rate / 50) as usize * usize::from(channels),
            ),
        );
        let (ok, report) = opusinfo(&path);
        assert!(ok, "opusinfo failed: {report}");
        let lowered = report.to_lowercase();
        assert!(
            !lowered.contains("warning") && !lowered.contains("error"),
            "{rate} Hz × {channels}: {report}"
        );
        assert!(report.contains("Pre-skip: 312"), "{report}");
        assert!(
            report.contains(&format!("Channels: {channels}")),
            "{report}"
        );
        assert!(
            report.contains(&format!("Original sample rate: {rate} Hz")),
            "{report}"
        );
        assert!(report.contains("Playback length: 0m:03.000s"), "{report}");
        assert!(report.contains("Logical stream 1 ended"), "{report}");
    }
}

#[test]
fn opusdec_returns_exactly_the_audio_written() {
    // Pre-skip and end trimming, checked by the reference decoder: a stream of N samples decodes to
    // N samples — not N plus the lookahead, and not N rounded up to a frame.
    if !opus_tools() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    for (rate, channels, samples) in [
        (8_000u32, 1u8, 8_000usize),
        (8_000, 1, 8_001),
        (8_000, 1, 7_919),
        (16_000, 2, 16_000 + 37),
        (16_000, 1, 1),
    ] {
        let hz: Vec<Option<f32>> = vec![Some(300.0); usize::from(channels)];
        let pcm = tone(rate, &hz, samples);
        let path = save(
            directory.path(),
            &format!("length-{rate}-{channels}-{samples}.opus"),
            &write_stream(rate, channels, &pcm, 480),
        );
        let (decoded, decoded_channels) = opusdec(&path);
        assert_eq!(decoded_channels, u16::from(channels));
        assert_eq!(
            decoded.len() / usize::from(channels),
            samples * (48_000 / rate as usize),
            "{rate} Hz × {channels}, {samples} samples"
        );
    }
}

#[test]
fn the_audio_lines_up_with_the_input_after_pre_skip() {
    // A wrong pre-skip still decodes to the right length if the trim compensates, so check the
    // timing too: silence, then a tone from exactly 200 ms. The decoded onset must land at 200 ms,
    // not 6.5 ms early or late (the lookahead) — which is what a hardcoded or missing pre-skip
    // gives.
    if !opus_tools() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let rate = 16_000u32;
    let onset = 3_200usize; // 200 ms
    let mut pcm = vec![0i16; onset];
    pcm.extend(tone(rate, &[Some(1_000.0)], 8_000));
    let path = save(
        directory.path(),
        "onset.opus",
        &write_stream(rate, 1, &pcm, 320),
    );
    let (decoded, _) = opusdec(&path);
    let first_loud = decoded
        .iter()
        .position(|&sample| sample.unsigned_abs() > 2_000)
        .expect("the tone is decoded");
    let expected = onset * 3; // at 48 kHz
    let tolerance = 48; // 1 ms, a sixth of the lookahead
    assert!(
        first_loud.abs_diff(expected) <= tolerance,
        "onset at {first_loud}, expected {expected} ± {tolerance}"
    );
}

#[test]
fn a_tone_decodes_at_its_frequency_and_stereo_channels_stay_apart() {
    // The audio is the audio: a 440 Hz caller on the left and a 1000 Hz callee on the right come
    // back at those frequencies on those channels; a silent right channel stays silent.
    if !opus_tools() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let rate = 8_000u32;
    let pcm = tone(rate, &[Some(440.0), Some(1_000.0)], 16_000);
    let path = save(
        directory.path(),
        "stereo.opus",
        &write_stream(rate, 2, &pcm, 320),
    );
    let (decoded, channels) = opusdec(&path);
    assert_eq!(channels, 2);
    let window = 48_000 / 2..48_000; // a steady half second
    let left = channel(&decoded, 2, 0)[window.clone()].to_vec();
    let right = channel(&decoded, 2, 1)[window.clone()].to_vec();
    assert_eq!(dominant_frequency(&left, 48_000.0, 200, 1_500), 440);
    assert_eq!(dominant_frequency(&right, 48_000.0, 200, 1_500), 1_000);

    let pcm = tone(rate, &[Some(440.0), None], 16_000);
    let path = save(
        directory.path(),
        "left-only.opus",
        &write_stream(rate, 2, &pcm, 320),
    );
    let (decoded, _) = opusdec(&path);
    let left = rms(&channel(&decoded, 2, 0)[window.clone()]);
    let right = rms(&channel(&decoded, 2, 1)[window]);
    let separation_db = 20.0 * (left / right.max(1.0)).log10();
    assert!(
        separation_db > 40.0,
        "cross-talk: left {left:.0} rms, right {right:.0} rms ({separation_db:.1} dB)"
    );
}

#[test]
fn a_stream_cut_off_mid_page_plays_up_to_its_last_whole_page() {
    // What a killed writer leaves: complete pages, then part of one, and no end-of-stream page.
    // Every complete page is decodable on its own, so the reference decoder plays the file up to
    // there.
    if !opus_tools() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let rate = 8_000u32;
    let mut writer = OggOpusWriter::new(config(rate, 1)).expect("writer");
    let mut out = Vec::new();
    writer.write_headers(&mut out).expect("headers");
    // Three full pages are written once the 151st frame is encoded; push 3.5 s to be sure.
    writer
        .push(&tone(rate, &[Some(440.0)], 28_000), &mut out)
        .expect("push");
    let complete = out.len();
    let mut rest = Vec::new();
    writer
        .push(&tone(rate, &[Some(440.0)], 8_000), &mut rest)
        .expect("push");
    out.extend_from_slice(&rest[..rest.len() / 2]);
    let path = save(directory.path(), "killed.opus", &out);

    let (decoded, _) = opusdec(&path);
    let pages_of_audio = 3;
    assert!(complete > 0, "the headers and pages were written");
    assert_eq!(
        decoded.len(),
        pages_of_audio * PACKETS_PER_PAGE * 960 - 312,
        "every whole page, less pre-skip"
    );
}

#[test]
fn ffprobe_sees_opus_with_the_right_channels_and_duration() {
    if !tool_available("ffprobe", "-version") {
        eprintln!("skipping: ffprobe not available (install ffmpeg)");
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    for (rate, channels, samples) in [(8_000u32, 1u8, 20_000usize), (16_000, 2, 16_000 * 7 + 5)] {
        let hz: Vec<Option<f32>> = vec![Some(440.0); usize::from(channels)];
        let pcm = tone(rate, &hz, samples);
        let path = save(
            directory.path(),
            &format!("probe-{rate}-{channels}.opus"),
            &write_stream(rate, channels, &pcm, 640),
        );
        let output = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=codec_name,channels:format=duration",
                "-of",
                "default=noprint_wrappers=1",
            ])
            .arg(&path)
            .output()
            .expect("ffprobe");
        let report = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(output.status.success(), "{report}");
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(report.contains("codec_name=opus"), "{report}");
        assert!(report.contains(&format!("channels={channels}")), "{report}");
        let duration: f64 = report
            .lines()
            .find_map(|line| line.strip_prefix("duration="))
            .expect("duration")
            .parse()
            .expect("number");
        let expected = samples as f64 / f64::from(rate);
        assert!(
            (duration - expected).abs() <= 0.020,
            "duration {duration}, expected {expected} within one frame"
        );
    }
}
