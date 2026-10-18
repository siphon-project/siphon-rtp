//! Decoding a relay-only call's ingress for a sink (a WS tee, a decoded recording) must add **zero**
//! per-frame heap allocation, whether the frame decodes or not: the decoder and its PCM buffer are
//! built when the sink attaches, and each packet decodes into that buffer. A counting global
//! allocator proves a steady-state loop over a relay with a sink allocates exactly as often as the
//! same relay without one, the relay's own per-packet forward included in both.

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
use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::media_pipeline::{MediaCall, RelayConfig};
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

/// A pass-through allocator that counts allocations on the armed thread only.
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

const A_ADDR: &str = "127.0.0.2:5000";
const B_ADDR: &str = "127.0.0.3:6000";

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

/// A sink that keeps nothing, so only the relay's own decode is measured.
struct DiscardingSink;

impl MediaSink for DiscardingSink {
    fn write_pcm(&mut self, pcm: &[i16]) {
        std::hint::black_box(pcm);
    }
}

/// A GSM relay (both legs on PT 3), with a sink on leg A's ingress when `with_sink`.
fn gsm_relay(with_sink: bool) -> MediaCall {
    let gsm = CodecSpec::new(3, "GSM", 8000, 1, 20);
    let make = |ingress: u64, source: &str, egress: u64, dst: &str| RelayConfig {
        ingress_endpoint: EndpointId(ingress),
        accepted_source: SourceFilter::Exact(addr(source).ip()),
        egress_endpoint: EndpointId(egress),
        egress_dst: addr(dst),
        telephone_event: None,
        tap_codec: Some(gsm.clone()),
    };
    let mut call = MediaCall::new_relay(
        "relay-tap-alloc",
        "tag-a",
        Some("tag-b".to_string()),
        make(1, A_ADDR, 2, B_ADDR),
        make(2, B_ADDR, 1, A_ADDR),
        true,
    );
    if with_sink {
        call.add_fork(true, Box::new(DiscardingSink));
    }
    call
}

/// Leg A's packets: mostly 33-octet GSM frames, every fifth one 32 octets (undecodable).
fn packets() -> Vec<RxPacket> {
    (0..2_000u16)
        .map(|sequence| {
            let mut payload = vec![0u8; if sequence % 5 == 4 { 32 } else { 33 }];
            payload[0] = 0xD0;
            payload[1] = sequence as u8;
            let header = RtpHeader {
                marker: false,
                payload_type: 3,
                sequence,
                timestamp: u32::from(sequence) * 160,
                ssrc: 0x0A11_0001,
            };
            let mut buffer = vec![0u8; 12 + payload.len()];
            let len = write_packet(&header, &payload, &mut buffer).expect("write");
            buffer.truncate(len);
            RxPacket {
                endpoint: EndpointId(1),
                source: addr(A_ADDR),
                arrival: u64::from(sequence) * 20_000,
                data: Bytes::from(buffer),
            }
        })
        .collect()
}

fn allocations_over_loop(call: &mut MediaCall, packets: &[RxPacket]) -> usize {
    let mut out = Vec::new();
    let mut events = Vec::new();
    for packet in packets.iter().take(64) {
        out.clear();
        call.process(packet, &mut out, &mut events);
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for packet in packets {
        out.clear();
        events.clear();
        call.process(packet, &mut out, &mut events);
        std::hint::black_box(&out);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn decoding_a_relay_for_its_sink_adds_no_per_frame_heap_allocation() {
    let packets = packets();
    let bare = allocations_over_loop(&mut gsm_relay(false), &packets);
    let tapped = allocations_over_loop(&mut gsm_relay(true), &packets);
    assert_eq!(
        tapped,
        bare,
        "the sink's decode allocated {} extra time(s) across the loop (must be zero)",
        tapped.saturating_sub(bare),
    );
}
