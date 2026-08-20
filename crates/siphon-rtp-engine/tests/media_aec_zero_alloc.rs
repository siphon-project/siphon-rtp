//! Wiring the echo canceller into the media-pipeline hot path must add **zero** per-frame heap
//! allocation: the [`EchoCanceller`] (MDF + delay-estimation + two-path) and the per-party far-end
//! reference ring are both preallocated at call setup, the reference is drained into a caller-owned
//! stack buffer, and `cancel` runs in place. A counting global allocator proves a steady-state
//! `process(A) → process(B)` loop over a two-party [`MediaCall`] allocates exactly the same number of
//! times with echo cancellation enabled as without — the canceller + ring contribute nothing on the
//! datapath.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Encoder;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::media_pipeline::{DirectionConfig, MediaCall};
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn during
    // the same window is not miscounted. `const`-initialised so `alloc` never itself allocates.
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

/// Deterministic LCG (fixed seed) — reproducible white noise, never `rand` / the wall clock.
struct Lcg(u32);
impl Lcg {
    fn next_bipolar(&mut self) -> f32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (self.0 >> 8) as f32 / (1u32 << 23) as f32 - 1.0
    }
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

const A_ADDR: &str = "127.0.0.2:5000";
const B_ADDR: &str = "127.0.0.3:6000";

/// A µ-law ↔ µ-law (same codec, no resampler) two-party media call, echo cancellation `aec` on both
/// directions (symmetric: each cancels its uplink and produces the reference the other reads).
fn ulaw_call(aec: bool) -> MediaCall {
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
        recorder: None,
        ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        noise_suppression: false,
        echo_cancellation: aec,
        beep_detection: false,
        beep_cadence_guard_ms: None,
        produce_echo_reference: aec,
    };
    MediaCall::new(
        "aec-alloc",
        "tag-a",
        Some("tag-b".to_string()),
        make(1, A_ADDR, 2, B_ADDR, 0xB000_0001),
        make(2, B_ADDR, 1, A_ADDR, 0xA000_0001),
        true,
        None,
    )
}

/// One 20 ms µ-law RTP packet of deterministic white noise (160 samples @ 8 kHz).
fn noisy_ulaw_packet(
    endpoint: u64,
    source: &str,
    sequence: u16,
    ssrc: u32,
    rng: &mut Lcg,
) -> RxPacket {
    let mut pcm = [0i16; 160];
    for sample in pcm.iter_mut() {
        *sample = (4000.0 * rng.next_bipolar()) as i16;
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

/// Count allocations across a steady-state `process(B) → process(A)` loop over prebuilt packets (their
/// construction is not measured). Party B forwards the far-end (the reference toward A) then party A's
/// echo-laden uplink is transcoded — the exact per-frame path `Direction::handle` runs.
fn allocations_over_loop(call: &mut MediaCall, packets: &[(RxPacket, RxPacket)]) -> usize {
    let mut out = Vec::new();
    let mut events = Vec::new();
    // Warm up: converge the delay estimator / MDF and grow the reused scratch Vecs before arming, so a
    // one-off capacity growth is not counted as a per-frame allocation.
    for (b_packet, a_packet) in packets.iter().take(64) {
        out.clear();
        events.clear();
        call.process(b_packet, &mut out, &mut events);
        call.process(a_packet, &mut out, &mut events);
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for (b_packet, a_packet) in packets {
        out.clear();
        events.clear();
        call.process(b_packet, &mut out, &mut events);
        call.process(a_packet, &mut out, &mut events);
        std::hint::black_box(&out);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn echo_cancellation_adds_no_per_frame_heap_allocation_on_the_media_datapath() {
    // The same prebuilt two-party stream drives both calls, so the only difference in their steady
    // loops is the in-place canceller + the preallocated reference ring. Their allocation counts must
    // match exactly.
    let mut rng = Lcg(0x0EC0_A110);
    let packets: Vec<(RxPacket, RxPacket)> = (0..2_000u16)
        .map(|sequence| {
            (
                noisy_ulaw_packet(2, B_ADDR, sequence, 0xB222_0001, &mut rng),
                noisy_ulaw_packet(1, A_ADDR, sequence, 0xA111_0001, &mut rng),
            )
        })
        .collect();

    let plain_allocations = allocations_over_loop(&mut ulaw_call(false), &packets);
    let cancelled_allocations = allocations_over_loop(&mut ulaw_call(true), &packets);

    assert_eq!(
        cancelled_allocations,
        plain_allocations,
        "enabling echo cancellation allocated {} extra time(s) across the loop (must be zero — the \
         canceller and reference ring are preallocated)",
        cancelled_allocations.saturating_sub(plain_allocations),
    );
}
