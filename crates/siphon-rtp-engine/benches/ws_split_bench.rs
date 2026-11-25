//! Criterion perf gate for the **split bridge**: what one 20 ms tick of a two-party call costs while
//! both parties are isolated and played a bot, against the same call transcoding plainly.
//!
//! One iteration is one ptime of the whole call, the unit a controller prices a call in: both
//! parties' packets are decoded, and then
//!
//! - `transcode` re-encodes each toward the other (the plain G.711 call, the baseline),
//! - `split` feeds the uplink forks (both parties, 8 kHz up to a 16 kHz stereo frame), pushes the
//!   bot's stereo frame into the two playout queues, and plays each party a chunk, 16 kHz down to the
//!   legs' 8 kHz.
//!
//! The uplink frame is drained and its buffer handed back, as the transport does, so no point
//! measures a queue filling up.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use std::net::SocketAddr;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Encoder;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::media_pipeline::{DirectionConfig, MediaCall, SplitAttach};
use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
use siphon_rtp_media::bridge::split::{playout, PlayoutWriter};
use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeePlan, WsTeeSink};
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

const A_ADDR: &str = "127.0.0.2:5000";
const B_ADDR: &str = "127.0.0.3:6000";

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

fn ulaw_call() -> MediaCall {
    let make = |ingress: u64, source: &str, egress: u64, dst: &str, ssrc: u32| DirectionConfig {
        ingress_endpoint: EndpointId(ingress),
        accepted_source: SourceFilter::Exact(addr(source).ip()),
        egress_endpoint: EndpointId(egress),
        egress_dst: addr(dst),
        decoder: Box::new(G711::ulaw()),
        encoder: Box::new(G711::ulaw()),
        egress_ssrc: ssrc,
        egress_payload_type: 0,
        telephone_event_in: None,
        telephone_event_out: None,
        ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        noise_suppression: false,
        echo: siphon_rtp_engine::media_pipeline::EchoProfile::default(),
        beep_detection: false,
        beep_cadence_guard_ms: None,
        produce_echo_reference: false,
    };
    MediaCall::new(
        "split-bench",
        "tag-a",
        Some("tag-b".to_string()),
        make(1, A_ADDR, 2, B_ADDR, 0xB000_0001),
        make(2, B_ADDR, 1, A_ADDR, 0xA000_0001),
        true,
    )
}

fn packet(endpoint: u64, source: &str, sequence: u16, ssrc: u32) -> RxPacket {
    let mut pcm = [0i16; 160];
    for (index, sample) in pcm.iter_mut().enumerate() {
        *sample = ((index as i32 * 97 + i32::from(sequence) * 13) % 6000 - 3000) as i16;
    }
    let mut payload = [0u8; 160];
    G711::ulaw().encode(&pcm, &mut payload).expect("encode");
    let header = RtpHeader {
        marker: false,
        payload_type: 0,
        sequence,
        timestamp: u32::from(sequence) * 160,
        ssrc,
    };
    let mut buffer = vec![0u8; 12 + payload.len()];
    let len = write_packet(&header, &payload, &mut buffer).expect("write");
    buffer.truncate(len);
    RxPacket {
        endpoint: EndpointId(endpoint),
        source: addr(source),
        arrival: u64::from(sequence) * 20_000,
        data: Bytes::from(buffer),
    }
}

fn split_call() -> (MediaCall, WsTeePlan, PlayoutWriter) {
    let mut call = ulaw_call();
    let wire = MediaFormat {
        encoding: Encoding::L16,
        sample_rate: 16_000,
        channels: 2,
        bit_depth: 16,
        endianness: Endianness::Little,
        ptime: 20,
    };
    let uplink = plan_ws_tee(wire, true, false);
    let up = || siphon_rtp_media::bridge::wire_resampler(8_000, 16_000).expect("rate");
    call.add_fork(
        true,
        Box::new(WsTeeSink::new(
            TeeChannel::Caller,
            uplink.mixer.clone(),
            "split",
            up(),
        )),
    );
    call.add_fork(
        false,
        Box::new(WsTeeSink::new(
            TeeChannel::Callee,
            uplink.mixer.clone(),
            "split",
            up(),
        )),
    );
    let (downlink, [toward_a, toward_b]) = playout(16_000);
    call.attach_split(SplitAttach {
        toward_a,
        toward_b,
        wire_rate_hz: 16_000,
        noise_suppression: [false, false],
        epoch: Default::default(),
    });
    (call, uplink, downlink)
}

fn bench(criterion: &mut Criterion) {
    let packets: Vec<(RxPacket, RxPacket)> = (0..512u16)
        .map(|sequence| {
            (
                packet(1, A_ADDR, sequence, 0xA111_0001),
                packet(2, B_ADDR, sequence, 0xB222_0001),
            )
        })
        .collect();
    let mut stereo = Vec::with_capacity(320 * 4);
    for index in 0..320 {
        let left = ((index * 31) % 4000) as i16 - 2000;
        stereo.extend_from_slice(&left.to_le_bytes());
        stereo.extend_from_slice(&(-left).to_le_bytes());
    }

    let mut group = criterion.benchmark_group("ws_split_tick");
    group.throughput(Throughput::Elements(1));

    let mut plain = ulaw_call();
    let (mut out, mut events) = (Vec::new(), Vec::new());
    let mut cursor = 0usize;
    group.bench_function("transcode", |bencher| {
        bencher.iter(|| {
            let (a, b) = &packets[cursor % packets.len()];
            cursor += 1;
            out.clear();
            plain.process(a, &mut out, &mut events);
            plain.process(b, &mut out, &mut events);
            plain.tick(&mut out, &mut events);
            std::hint::black_box(&out);
        });
    });

    let (mut split, uplink, mut downlink) = split_call();
    let mut cursor = 0usize;
    group.bench_function("split", |bencher| {
        bencher.iter(|| {
            let (a, b) = &packets[cursor % packets.len()];
            cursor += 1;
            out.clear();
            downlink.push_wire(&stereo);
            split.process(a, &mut out, &mut events);
            split.process(b, &mut out, &mut events);
            split.tick(&mut out, &mut events);
            while let Ok(wire) = uplink.frames.try_recv() {
                let _ = uplink.recycle.send(wire);
            }
            std::hint::black_box(&out);
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
