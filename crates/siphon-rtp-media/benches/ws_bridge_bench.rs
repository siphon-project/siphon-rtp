//! Criterion perf gate for the WS voice-AI bridge tick (`BridgeSession::tick`) — the per-frame cost a
//! bridged leg pays. Benches the same tick with local-VAD turn-taking **off vs on** at 8 kHz (µ-law),
//! so the delta is exactly the added energy-VAD + turn-edge logic, plus the echo-cancelling tick
//! (whose far-end reference is preallocated on the core) and a **long-ptime** leg at 48 kHz / 60 ms,
//! the frame shape a WebRTC/Opus peer produces.
//!
//! It also gates the **selectable WS wire rate**: `ws_bridge_tick_wire_rate` measures a duplex tick
//! with no conversion (the control), against one converting uplink *and* downlink, so the price of
//! asking for a rate the leg does not run at is a measured number rather than a guess — and the
//! control proves a bridge that did not ask pays nothing. `ws_tee_write_pcm_20ms/mono_8k_to_16k` is
//! the same cost isolated to a single (send-only) direction. `cargo bench -p siphon-rtp-media`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::l16::L16;
use siphon_rtp_codec::Encoder as _;
use siphon_rtp_dsp::{EchoCanceller, VoiceDetector};
use siphon_rtp_media::bridge::protocol::{Direction, Encoding, Endianness, MediaFormat};
use siphon_rtp_media::bridge::BridgeSession;
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, FIXED_HEADER_LEN};

/// 8 kHz / 20 ms frame.
const FRAME_SAMPLES: usize = 160;
/// 48 kHz / 60 ms frame — three 48 kHz 20 ms frames, the long-ptime shape.
const LONG_FRAME_SAMPLES: usize = 2880;

/// A µ-law RTP packet carrying `pcm` (12-byte header + 160-byte payload).
fn ulaw_packet(sequence: u16, pcm: &[i16]) -> Vec<u8> {
    let mut encoder = G711::ulaw();
    let mut payload = [0u8; 160];
    let len = encoder.encode(pcm, &mut payload).expect("encode");
    let header = RtpHeader {
        marker: false,
        payload_type: 0,
        sequence,
        timestamp: u32::from(sequence) * 160,
        ssrc: 1,
    };
    let mut buffer = vec![0u8; FIXED_HEADER_LEN + len];
    let written = write_packet(&header, &payload[..len], &mut buffer).expect("write");
    buffer.truncate(written);
    buffer
}

fn session(vad: bool) -> BridgeSession {
    let leg = MediaLeg::new(
        Box::new(G711::ulaw()),
        Box::new(G711::ulaw()),
        JitterBuffer::new(1, 16),
        0x5555_6666,
        0,
    );
    let session = BridgeSession::new(
        leg,
        MediaFormat::telephony_default(),
        "str_1",
        "call_1",
        Direction::Duplex,
        8,
    );
    if vad {
        // threshold 1e6, hangover 5 frames (~100 ms) — the engine's defaults.
        session.with_vad(1_000_000, 5, true)
    } else {
        session
    }
}

fn bench_tick(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("ws_bridge_tick_8k_20ms");
    let loud = [4000i16; FRAME_SAMPLES];
    for (label, detector) in [
        ("vad_off", None),
        ("vad_on", Some(false)),
        // The neural detector on the narrowband path: an 8 → 16 kHz polyphase resample of every
        // frame plus the network on each completed 512-sample window (one every 1.6 frames). This is
        // the whole extra per-tick cost a leg pays for choosing it over the energy gate.
        ("vad_neural", Some(true)),
    ] {
        group.bench_function(label, |bencher| {
            let mut session = match detector {
                None => session(false),
                Some(false) => session(true),
                Some(true) => session(false).with_voice_detector(
                    VoiceDetector::neural(8_000).expect("neural detector for an 8 kHz leg"),
                    1,
                    true,
                ),
            };
            // One pre-built packet whose sequence we bump in place each tick (monotonic, no per-iter
            // allocation), keeping the leg fed one loud frame per tick so `next_pcm` decodes real audio.
            let mut packet = ulaw_packet(0, &loud);
            let mut sequence: u16 = 0;
            let mut uplink = [0u8; 1024];
            let mut downlink = [0u8; 1024];
            bencher.iter(|| {
                sequence = sequence.wrapping_add(1);
                packet[2..4].copy_from_slice(&sequence.to_be_bytes());
                session.on_rtp(&packet);
                let result = session.tick(&mut uplink, &mut downlink);
                black_box(result)
            });
        });
    }
    group.finish();
}

/// The echo-cancelling tick: the same 8 kHz path with an `EchoCanceller` on the uplink. Its far-end
/// reference lives on the core (preallocated), so the only per-tick work here is the zero-fill of the
/// reference tail plus the cancellation itself — no ceiling-sized stack array to clear.
fn bench_tick_with_echo_canceller(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("ws_bridge_tick_8k_20ms");
    let loud = [4000i16; FRAME_SAMPLES];
    group.bench_function("aec_on", |bencher| {
        let leg = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x5555_6666,
            0,
        );
        let mut session = BridgeSession::new(
            leg,
            MediaFormat::telephony_default(),
            "str_1",
            "call_1",
            Direction::Duplex,
            8,
        )
        .with_echo_canceller(Some(
            EchoCanceller::with_mdf_delay_estimation(8_000, 512, 1_024)
                .expect("build 8k aec")
                .with_two_path_dtd(),
        ));
        let mut packet = ulaw_packet(0, &loud);
        let mut sequence: u16 = 0;
        let mut uplink = [0u8; 1024];
        let mut downlink = [0u8; 1024];
        bencher.iter(|| {
            sequence = sequence.wrapping_add(1);
            packet[2..4].copy_from_slice(&sequence.to_be_bytes());
            session.on_rtp(&packet);
            let result = session.tick(&mut uplink, &mut downlink);
            black_box(result)
        });
    });
    group.finish();
}

/// The **long-ptime** tick: an `L16/48000` leg at `a=ptime:60`, 2880 samples per frame. This shape
/// used to produce nothing at all (the staging slot was one 48 kHz 20 ms frame, so every decode
/// failed and the uplink was silent), so there is no older number to compare against — it is a new
/// floor for the path a WebRTC-shaped leg takes.
fn bench_long_ptime_tick(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("ws_bridge_tick_48k_60ms");
    let loud = [4000i16; LONG_FRAME_SAMPLES];
    for (label, vad) in [("vad_off", false), ("vad_on", true)] {
        group.bench_function(label, |bencher| {
            let leg = MediaLeg::new(
                Box::new(L16::new(48_000, 60)),
                Box::new(L16::new(48_000, 60)),
                JitterBuffer::new(1, 16),
                0x5555_6666,
                11,
            );
            let session = BridgeSession::new(
                leg,
                MediaFormat {
                    encoding: Encoding::L16,
                    sample_rate: 48_000,
                    channels: 1,
                    bit_depth: 16,
                    endianness: Endianness::Little,
                    ptime: 60,
                },
                "str_1",
                "call_1",
                Direction::Duplex,
                8,
            );
            let mut session = if vad {
                session.with_vad(1_000_000, 5, true)
            } else {
                session
            };
            let mut packet = l16_packet(0, &loud);
            let mut sequence: u16 = 0;
            let mut uplink = vec![0u8; 2 * LONG_FRAME_SAMPLES];
            let mut downlink = vec![0u8; 1600];
            bencher.iter(|| {
                sequence = sequence.wrapping_add(1);
                packet[2..4].copy_from_slice(&sequence.to_be_bytes());
                session.on_rtp(&packet);
                let result = session.tick(&mut uplink, &mut downlink);
                black_box(result)
            });
        });
    }
    group.finish();
}

/// The **wire-rate conversion** cost on a duplex takeover tick. All three variants do identical work
/// apart from the conversion — one µ-law ingress packet in, one L16 wire frame queued for playout,
/// one tick that frames the uplink and encodes the downlink — so the delta against `identity_8k` is
/// exactly what a leg pays for streaming at a rate it does not natively run at. Each converting
/// variant engages **both** directions (leg→wire on the uplink, wire→leg on the downlink), which is
/// what a real bridge at that rate does.
fn bench_wire_rate_tick(criterion: &mut Criterion) {
    use siphon_rtp_media::bridge::pcm_to_l16_le;
    use siphon_rtp_media::bridge::wire_rate::wire_resampler;

    const LEG_RATE_HZ: u32 = 8_000;
    let mut group = criterion.benchmark_group("ws_bridge_tick_wire_rate");
    let loud = [4000i16; FRAME_SAMPLES];

    for (label, wire_rate) in [
        ("identity_8k", 8_000u32),
        ("wire_16k", 16_000),
        ("wire_24k", 24_000),
    ] {
        group.bench_function(label, |bencher| {
            let leg = MediaLeg::new(
                Box::new(G711::ulaw()),
                Box::new(G711::ulaw()),
                JitterBuffer::new(1, 16),
                0x5555_6666,
                0,
            );
            let mut session = BridgeSession::new(
                leg,
                MediaFormat {
                    encoding: Encoding::L16,
                    sample_rate: wire_rate,
                    channels: 1,
                    bit_depth: 16,
                    endianness: Endianness::Little,
                    ptime: 20,
                },
                "str_1",
                "call_1",
                Direction::Duplex,
                4,
            )
            .with_rate_conversion(
                wire_resampler(LEG_RATE_HZ, wire_rate).expect("uplink conversion"),
                wire_resampler(wire_rate, LEG_RATE_HZ).expect("downlink conversion"),
            );

            // One pre-built ingress packet whose sequence is bumped in place, and one pre-built wire
            // frame at the negotiated rate — so the measured loop allocates nothing of its own beyond
            // what the bridge itself does.
            let wire_samples = wire_rate as usize / 1000 * 20;
            let mut wire_frame = vec![0u8; wire_samples * 2];
            pcm_to_l16_le(&vec![1500i16; wire_samples], &mut wire_frame);
            let mut packet = ulaw_packet(0, &loud);
            let mut sequence: u16 = 0;
            let mut uplink = vec![0u8; 4096];
            let mut downlink = vec![0u8; 4096];
            bencher.iter(|| {
                sequence = sequence.wrapping_add(1);
                packet[2..4].copy_from_slice(&sequence.to_be_bytes());
                session.on_rtp(&packet);
                session.on_ws_binary(black_box(&wire_frame));
                let result = session.tick(&mut uplink, &mut downlink);
                black_box(result)
            });
        });
    }
    group.finish();
}

/// An RTP packet carrying `pcm` as an L16 payload (RFC 3551 §4.5.11: network byte order).
fn l16_packet(sequence: u16, pcm: &[i16]) -> Vec<u8> {
    let mut payload = vec![0u8; pcm.len() * 2];
    for (sample, chunk) in pcm.iter().zip(payload.as_chunks_mut::<2>().0) {
        chunk.copy_from_slice(&sample.to_be_bytes());
    }
    let header = RtpHeader {
        marker: false,
        payload_type: 11,
        sequence,
        timestamp: u32::from(sequence) * pcm.len() as u32,
        ssrc: 1,
    };
    let mut buffer = vec![0u8; FIXED_HEADER_LEN + payload.len()];
    let written = write_packet(&header, &payload, &mut buffer).expect("write");
    buffer.truncate(written);
    buffer
}

/// The WS **tee**'s per-frame cost — what a relaying call pays per decoded ingress frame for having a
/// tee attached (`MediaSink::write_pcm`: ring push → interleave/mix → L16 → bounded `try_send`). Three
/// shapes: a single-leg monologue, a stereo (both-legs) tee whose emit also interleaves, and a leg that
/// must resample into the tee rate. Each iteration drains + recycles as the transport task does, so the
/// measured cost is the steady-state, allocation-free path.
fn bench_tee(criterion: &mut Criterion) {
    use siphon_rtp_media::bridge::protocol::{Encoding, Endianness};
    use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};
    use siphon_rtp_media::fanout::MediaSink;

    let format = |sample_rate: u32, channels: u8| MediaFormat {
        encoding: Encoding::L16,
        sample_rate,
        channels,
        bit_depth: 16,
        endianness: Endianness::Little,
        ptime: 20,
    };

    let mut group = criterion.benchmark_group("ws_tee_write_pcm_20ms");
    let frame = [4321i16; FRAME_SAMPLES];

    group.bench_function("mono_8k", |bencher| {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee", None);
        bencher.iter(|| {
            sink.write_pcm(black_box(&frame));
            if let Ok(buffer) = plan.frames.try_recv() {
                let _ = plan.recycle.send(buffer);
            }
        });
    });

    group.bench_function("stereo_8k", |bencher| {
        let plan = plan_ws_tee(format(8000, 2), true, false);
        let mut caller = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee", None);
        let mut callee = WsTeeSink::new(TeeChannel::Callee, plan.mixer.clone(), "tee", None);
        bencher.iter(|| {
            caller.write_pcm(black_box(&frame));
            callee.write_pcm(black_box(&frame));
            if let Ok(buffer) = plan.frames.try_recv() {
                let _ = plan.recycle.send(buffer);
            }
        });
    });

    group.bench_function("mono_8k_to_16k", |bencher| {
        // The selectable-wire-rate shape: a narrowband leg upsampled into a wideband tee. Send-only,
        // so this is the uplink conversion cost on its own, with no downlink in the measurement.
        let plan = plan_ws_tee(format(16_000, 1), false, false);
        let resampler =
            siphon_rtp_dsp::resample::Resampler::new(8_000, 16_000).expect("build resampler");
        let mut sink = WsTeeSink::new(
            TeeChannel::Caller,
            plan.mixer.clone(),
            "tee",
            Some(resampler),
        );
        bencher.iter(|| {
            sink.write_pcm(black_box(&frame));
            if let Ok(buffer) = plan.frames.try_recv() {
                let _ = plan.recycle.send(buffer);
            }
        });
    });

    group.bench_function("mono_16k_resampled_to_8k", |bencher| {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let resampler =
            siphon_rtp_dsp::resample::Resampler::new(16_000, 8_000).expect("build resampler");
        let mut sink = WsTeeSink::new(
            TeeChannel::Caller,
            plan.mixer.clone(),
            "tee",
            Some(resampler),
        );
        let wideband = [4321i16; 2 * FRAME_SAMPLES];
        bencher.iter(|| {
            sink.write_pcm(black_box(&wideband));
            if let Ok(buffer) = plan.frames.try_recv() {
                let _ = plan.recycle.send(buffer);
            }
        });
    });
    group.finish();
}

/// The **long-ptime tee**: a 48 kHz / 60 ms wire frame, whose length used to be clamped to one 20 ms
/// frame at 48 kHz — so this is the cost of assembling the frame the tee actually announced.
fn bench_long_ptime_tee(criterion: &mut Criterion) {
    use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};
    use siphon_rtp_media::fanout::MediaSink;

    let mut group = criterion.benchmark_group("ws_tee_write_pcm_60ms");
    let frame = [4321i16; LONG_FRAME_SAMPLES];
    group.bench_function("mono_48k", |bencher| {
        let plan = plan_ws_tee(
            MediaFormat {
                encoding: Encoding::L16,
                sample_rate: 48_000,
                channels: 1,
                bit_depth: 16,
                endianness: Endianness::Little,
                ptime: 60,
            },
            false,
            false,
        );
        let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee", None);
        bencher.iter(|| {
            sink.write_pcm(black_box(&frame));
            if let Ok(buffer) = plan.frames.try_recv() {
                let _ = plan.recycle.send(buffer);
            }
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_tick,
    bench_tick_with_echo_canceller,
    bench_long_ptime_tick,
    bench_wire_rate_tick,
    bench_tee,
    bench_long_ptime_tee
);
criterion_main!(benches);
