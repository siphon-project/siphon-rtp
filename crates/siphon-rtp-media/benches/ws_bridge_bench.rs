//! Criterion perf gate for the WS voice-AI bridge tick (`BridgeSession::tick`) — the per-frame cost a
//! bridged leg pays. Benches the same tick with local-VAD turn-taking **off vs on** at 8 kHz (µ-law),
//! so the delta is exactly the added energy-VAD + turn-edge logic. `cargo bench -p siphon-rtp-media`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Encoder as _;
use siphon_rtp_media::bridge::protocol::{Direction, MediaFormat};
use siphon_rtp_media::bridge::BridgeSession;
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, FIXED_HEADER_LEN};

/// 8 kHz / 20 ms frame.
const FRAME_SAMPLES: usize = 160;

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
    for (label, vad) in [("vad_off", false), ("vad_on", true)] {
        group.bench_function(label, |bencher| {
            let mut session = session(vad);
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

criterion_group!(benches, bench_tick);
criterion_main!(benches);
