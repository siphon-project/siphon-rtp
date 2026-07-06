//! Deterministic instruction-count gate (valgrind/callgrind) for the userspace relay hot path.
//!
//! The wall-clock numbers live in `relay_bench.rs`; this counts instructions, which are stable enough
//! on a shared CI runner to fail on a `>10%` regression. Setup (seed packet, output buffer) runs in a
//! `setup` fn and is not counted; only the parse -> rewrite -> write per packet is measured. See the
//! CI `perf-gate` job.

use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, EventKind, LibraryBenchmarkConfig,
};
use std::hint::black_box;

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

library_benchmark_group!(name = relay; benchmarks = rtp_parse_rewrite_write);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 10.0)]));
    library_benchmark_groups = relay
);
