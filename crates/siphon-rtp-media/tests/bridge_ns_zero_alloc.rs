//! Wiring the uplink noise suppressor into the WS voice-AI bridge must add **zero** per-frame heap
//! allocation: the [`NoiseSuppressor`] is preallocated at construction and runs in place on the
//! decoded PCM frame. A counting global allocator proves a steady-state `on_rtp → tick` loop
//! allocates exactly the same number of times with the suppressor attached as without — the
//! suppressor contributes nothing on the datapath.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Encoder;
use siphon_rtp_dsp::NoiseSuppressor;
use siphon_rtp_media::bridge::protocol::Direction;
use siphon_rtp_media::bridge::{BridgeSession, MediaFormat};
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;
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

fn ulaw_session(with_suppressor: bool) -> BridgeSession {
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
    if with_suppressor {
        session.with_noise_suppressor(Some(
            NoiseSuppressor::new(8_000).expect("build 8k suppressor"),
        ))
    } else {
        session
    }
}

/// One 20 ms µ-law RTP packet of deterministic white noise at `sequence`.
fn noisy_ulaw_packet(sequence: u16, rng: &mut Lcg) -> Vec<u8> {
    let mut pcm = [0i16; 160];
    for sample in pcm.iter_mut() {
        *sample = (2000.0 * rng.next_bipolar()) as i16;
    }
    let mut payload = [0u8; 160];
    G711::ulaw().encode(&pcm, &mut payload).expect("encode");
    let header = RtpHeader {
        marker: false,
        payload_type: 0,
        sequence,
        timestamp: u32::from(sequence) * 160,
        ssrc: 1,
    };
    let mut buffer = vec![0u8; 172];
    let len = write_packet(&header, &payload, &mut buffer).expect("write");
    buffer.truncate(len);
    buffer
}

/// Count allocations across a steady-state `on_rtp → tick` loop over `packets` (already built, so
/// their construction is not measured). `uplink`/`downlink` are caller-owned scratch buffers.
fn allocations_over_loop(session: &mut BridgeSession, packets: &[Vec<u8>]) -> usize {
    let mut uplink = [0u8; 1024];
    let mut downlink = [0u8; 1024];
    // Warm up: prime the jitter buffer and converge the suppressor before arming.
    for packet in packets.iter().take(64) {
        session.on_rtp(packet);
        session.tick(&mut uplink, &mut downlink);
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for packet in packets {
        session.on_rtp(packet);
        let result = session.tick(&mut uplink, &mut downlink);
        std::hint::black_box(&uplink[..result.uplink_bytes]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn uplink_noise_suppression_adds_no_heap_allocation() {
    // The same pre-built noisy stream drives both sessions, so the only difference in their steady
    // loops is the in-place suppressor call. Their allocation counts must match exactly.
    let mut rng = Lcg(0x51A9_2E17);
    let packets: Vec<Vec<u8>> = (0..2_000u16)
        .map(|sequence| noisy_ulaw_packet(sequence, &mut rng))
        .collect();

    let plain_allocations = allocations_over_loop(&mut ulaw_session(false), &packets);
    let suppressed_allocations = allocations_over_loop(&mut ulaw_session(true), &packets);

    assert_eq!(
        suppressed_allocations,
        plain_allocations,
        "attaching the uplink suppressor allocated {} extra time(s) across the loop (must be zero)",
        suppressed_allocations.saturating_sub(plain_allocations),
    );
}
