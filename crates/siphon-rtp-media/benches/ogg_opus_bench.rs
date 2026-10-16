//! Criterion perf gate for the Ogg Opus recording writer (`cargo bench -p siphon-rtp-media`).
//!
//! The per-frame cost of an `ogg_opus` recording: encode one 20 ms frame of interleaved L16 into an
//! Opus packet and add it to the open Ogg page (a page is framed and checksummed once every 50
//! frames, so that cost is amortised in). Reported as µs per 20 ms frame. This runs in the
//! recording's writer task, never on the media path, but it is the number that sizes how many
//! concurrent recordings a core sustains.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::ogg_opus::{OggOpusConfig, OggOpusWriter};

/// Ten seconds of a speech-like signal: a 120 Hz harmonic stack under a 4 Hz syllable envelope,
/// plus a little deterministic noise, so the encoder's decisions move the way they do on a voice.
fn speech(rate: u32, channels: usize) -> Vec<i16> {
    let samples = rate as usize * 10;
    let mut noise = 0x1234_5678u32;
    let mut pcm = Vec::with_capacity(samples * channels);
    for index in 0..samples {
        let time = index as f32 / rate as f32;
        let envelope = 0.5 + 0.5 * (2.0 * std::f32::consts::PI * 4.0 * time).sin();
        let mut value = 0.0;
        for harmonic in 1..=12 {
            let hz = 120.0 * harmonic as f32;
            if hz < rate as f32 / 2.0 {
                value += (2.0 * std::f32::consts::PI * hz * time).sin() / harmonic as f32;
            }
        }
        for channel in 0..channels {
            noise = noise.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let jitter = ((noise >> 16) as f32 / 65_536.0 - 0.5) * 400.0;
            let gain = if channel == 0 { 1.0 } else { 0.6 };
            pcm.push((value * envelope * 5_000.0 * gain + jitter) as i16);
        }
    }
    pcm
}

fn bench_case(criterion: &mut Criterion, name: &str, rate: u32, channels: u8) {
    let pcm = speech(rate, usize::from(channels));
    let frame = (rate / 50) as usize * usize::from(channels);
    let mut writer = OggOpusWriter::new(OggOpusConfig {
        sample_rate_hz: rate,
        channels,
        bitrate_bps: 16_000 * u32::from(channels),
        serial: 1,
        vendor: "bench",
    })
    .expect("writer");
    let mut out = Vec::with_capacity(64 * 1024);
    writer.write_headers(&mut out).expect("headers");
    let mut offset = 0;
    criterion.bench_function(name, |bencher| {
        bencher.iter(|| {
            out.clear();
            writer
                .push(black_box(&pcm[offset..offset + frame]), &mut out)
                .expect("push");
            offset = (offset + frame) % pcm.len();
            black_box(out.len())
        });
    });
}

fn bench_ogg_opus(criterion: &mut Criterion) {
    bench_case(criterion, "ogg_opus_write_20ms/mono_8k", 8_000, 1);
    bench_case(criterion, "ogg_opus_write_20ms/stereo_8k", 8_000, 2);
    bench_case(criterion, "ogg_opus_write_20ms/mono_16k", 16_000, 1);
    bench_case(criterion, "ogg_opus_write_20ms/stereo_16k", 16_000, 2);
}

criterion_group!(benches, bench_ogg_opus);
criterion_main!(benches);
