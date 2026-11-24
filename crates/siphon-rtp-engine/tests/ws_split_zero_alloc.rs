//! A split bridge's steady-state tick allocates nothing of its own.
//!
//! One loop drives both directions of a two-party call through everything a split does per 20 ms:
//! each party's packet is decoded and goes no further than the uplink sinks, the bot's stereo frame
//! is deinterleaved into the two playout queues, the actor's tick takes a chunk per party off its
//! queue and sends it, and the transport drains the uplink frame and hands its buffer back. A
//! counting global allocator proves the only heap use left is the datagram each sent packet carries
//! (`Bytes::copy_from_slice`, exactly what the plain transcode path pays): allocations never exceed
//! packets sent. Queue chunks, uplink frames and the resample scratch are all recycled or
//! preallocated.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Encoder;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::media_pipeline::{DirectionConfig, MediaCall, SplitAttach};
use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
use siphon_rtp_media::bridge::split::playout;
use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: delegates straight to the system allocator; only bumps a relaxed counter when armed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

const A_ADDR: &str = "127.0.0.2:5000";
const B_ADDR: &str = "127.0.0.3:6000";

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
        "split-alloc",
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

fn stereo_frame(samples: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(samples * 4);
    for index in 0..samples {
        let left = ((index * 31) % 4000) as i16 - 2000;
        bytes.extend_from_slice(&left.to_le_bytes());
        bytes.extend_from_slice(&(-left).to_le_bytes());
    }
    bytes
}

#[test]
fn a_split_tick_allocates_only_the_datagrams_it_sends() {
    let mut call = ulaw_call();
    let wire = MediaFormat {
        encoding: Encoding::L16,
        sample_rate: 16_000,
        channels: 2,
        bit_depth: 16,
        endianness: Endianness::Little,
        ptime: 20,
    };
    // Uplink: a stereo frame assembler over both parties' decoded audio, at 16 kHz.
    let uplink = plan_ws_tee(wire, true, false);
    let resampler = |rate| siphon_rtp_media::bridge::wire_resampler(rate, 16_000).expect("rate");
    call.add_fork(
        true,
        Box::new(WsTeeSink::new(
            TeeChannel::Caller,
            uplink.mixer.clone(),
            "split",
            resampler(8_000),
        )),
    );
    call.add_fork(
        false,
        Box::new(WsTeeSink::new(
            TeeChannel::Callee,
            uplink.mixer.clone(),
            "split",
            resampler(8_000),
        )),
    );
    // Downlink: the bot's 16 kHz stereo into two playout queues, played at the legs' 8 kHz.
    let (mut downlink, [toward_a, toward_b]) = playout(16_000);
    call.attach_split(SplitAttach {
        toward_a,
        toward_b,
        wire_rate_hz: 16_000,
        noise_suppression: [false, false],
        epoch: Default::default(),
    });

    let frame = stereo_frame(320);
    let packets: Vec<(RxPacket, RxPacket)> = (0..600u16)
        .map(|sequence| {
            (
                packet(1, A_ADDR, sequence, 0xA111_0001),
                packet(2, B_ADDR, sequence, 0xB222_0001),
            )
        })
        .collect();
    let (mut out, mut events) = (Vec::new(), Vec::new());
    let mut step = |call: &mut MediaCall, a: &RxPacket, b: &RxPacket| -> usize {
        out.clear();
        events.clear();
        downlink.push_wire(&frame);
        call.process(a, &mut out, &mut events);
        call.process(b, &mut out, &mut events);
        call.tick(&mut out, &mut events);
        // The transport: drain the uplink frame and hand its buffer back.
        while let Ok(wire) = uplink.frames.try_recv() {
            let _ = uplink.recycle.send(wire);
        }
        std::hint::black_box(&out);
        out.len()
    };
    // Warm up: the scratch vectors and queues reach their steady-state capacity.
    for (a, b) in packets.iter().take(200) {
        step(&mut call, a, b);
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut sent = 0usize;
    for (a, b) in packets.iter().skip(200) {
        sent += step(&mut call, a, b);
    }
    let allocated = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));

    assert!(sent >= 700, "the tick sends to both parties: {sent}");
    assert_eq!(
        allocated, sent,
        "{allocated} allocations for {sent} packets: one is the datagram each carries, anything more is the split's"
    );
}
