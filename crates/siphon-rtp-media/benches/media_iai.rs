//! Deterministic instruction-count gate (valgrind/callgrind) for the userspace relay hot path and the
//! WS voice-AI bridge tick.
//!
//! The wall-clock numbers live in `relay_bench.rs` / `ws_bridge_bench.rs`; this counts instructions,
//! which are stable enough on a shared CI runner (or a loaded dev box, where a criterion number is
//! worthless) to fail on a `>10%` regression. Setup — seed packet, output buffers, a bridge session
//! with its jitter pre-filled — runs in a `setup` fn and is not counted. See the CI `perf-gate` job.

use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, EventKind, LibraryBenchmarkConfig,
};
use std::hint::black_box;

use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Encoder as _;
use siphon_rtp_media::bridge::protocol::{Direction, MediaFormat};
use siphon_rtp_media::bridge::BridgeSession;
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket, FIXED_HEADER_LEN};

/// A G.711 µ-law RTP packet: 12-byte header + 160-byte (20 ms @ 8 kHz) payload, plus a 1500-byte out.
fn relay_setup() -> (Vec<u8>, Vec<u8>) {
    let header = RtpHeader {
        marker: false,
        payload_type: 0,
        sequence: 0x1234,
        timestamp: 0xDEAD_BEEF,
        ssrc: 0x0102_0304,
    };
    let payload = [0xABu8; 160];
    let mut input = vec![0u8; FIXED_HEADER_LEN + payload.len()];
    let len = write_packet(&header, &payload, &mut input).expect("seed packet");
    input.truncate(len);
    (input, vec![0u8; 1500])
}

#[library_benchmark]
#[bench::g711(setup = relay_setup)]
fn rtp_parse_rewrite_write(input: (Vec<u8>, Vec<u8>)) {
    let (packet_bytes, mut out) = input;
    let packet = RtpPacket::parse(black_box(&packet_bytes)).expect("parse");
    let header = RtpHeader {
        marker: packet.marker,
        payload_type: packet.payload_type,
        sequence: packet.sequence.wrapping_add(1),
        timestamp: packet.timestamp,
        ssrc: 0xCAFE_BABE, // re-originated SSRC (topology hiding)
    };
    let len = write_packet(black_box(&header), packet.payload, black_box(&mut out)).expect("write");
    black_box(len);
}

/// Ticks per measured body. The session's construction happens in `setup` (uncounted) but its drop
/// lands inside the measured function, so amortize both over enough ticks that the number reads as
/// per-tick instructions rather than as setup noise.
const TICKS: usize = 100;

/// A bridged µ-law leg with `TICKS` + headroom frames already queued in its jitter buffer, plus the
/// uplink/downlink scratch — so the measured body is nothing but pop → decode → stage → clean →
/// frame, the per-ptime cost a bridged call actually pays.
fn bridge_setup() -> (BridgeSession, Vec<u8>, Vec<u8>) {
    let leg = MediaLeg::new(
        Box::new(G711::ulaw()),
        Box::new(G711::ulaw()),
        JitterBuffer::new(1, TICKS + 64),
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
    .with_vad(1_000_000, 5, true);

    let loud = [4000i16; 160]; // 20 ms @ 8 kHz, mean-square energy well past the VAD threshold
    let mut encoder = G711::ulaw();
    let mut payload = [0u8; 160];
    let length = encoder.encode(&loud, &mut payload).expect("encode");
    for sequence in 0..TICKS + 16 {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence: sequence as u16,
            timestamp: sequence as u32 * 160,
            ssrc: 1,
        };
        let mut packet = vec![0u8; FIXED_HEADER_LEN + length];
        let written = write_packet(&header, &payload[..length], &mut packet).expect("write");
        packet.truncate(written);
        session.on_rtp(&packet);
    }
    // One tick outside the measured body pays the jitter priming and the single silence→speech edge.
    let (mut uplink, mut downlink) = (vec![0u8; 12_288], vec![0u8; 1_600]);
    session.tick(&mut uplink, &mut downlink);
    (session, uplink, downlink)
}

#[library_benchmark]
#[bench::g711_8k_20ms(setup = bridge_setup)]
fn ws_bridge_tick(input: (BridgeSession, Vec<u8>, Vec<u8>)) {
    let (mut session, mut uplink, mut downlink) = input;
    for _ in 0..TICKS {
        black_box(session.tick(black_box(&mut uplink), black_box(&mut downlink)));
    }
}

library_benchmark_group!(name = relay; benchmarks = rtp_parse_rewrite_write);
library_benchmark_group!(name = bridge; benchmarks = ws_bridge_tick);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 10.0)]));
    library_benchmark_groups = relay, bridge
);
