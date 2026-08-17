//! The WS voice-AI bridge tick must add **zero per-frame heap allocation** when local-VAD turn-taking
//! is enabled (the performance invariant): the energy VAD and turn-edge detection allocate only on a
//! turn boundary, never on the steady-state per-frame path. A counting global allocator proves that
//! enabling VAD adds no allocation over the baseline tick across a long steady-speech run — the leg's
//! jitter is pre-filled outside the armed window, so the measured ticks are pure pop → decode → VAD.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Encoder as _;
use siphon_rtp_media::bridge::protocol::{Direction, MediaFormat};
use siphon_rtp_media::bridge::BridgeSession;
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, FIXED_HEADER_LEN};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the sample is this loop's allocations — not the
    // libtest harness's background churn. `const`-initialised so `alloc` never itself allocates.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: every call delegates straight to the system allocator; we only bump a relaxed counter, and
// only when the current thread has armed counting.
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

/// A µ-law RTP packet carrying `pcm`.
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

/// Count allocations across `MEASURED` steady-state (continuous-speech) ticks of a bridge session
/// whose jitter is pre-filled outside the armed window, so the measured ticks only pop → decode →
/// (optionally) VAD.
fn tick_allocations(vad: bool) -> usize {
    const MEASURED: usize = 1000;
    const PREFILL: usize = MEASURED + 64;
    let loud = [4000i16; 160]; // mean-square energy 16e6 ≫ threshold

    let leg = MediaLeg::new(
        Box::new(G711::ulaw()),
        Box::new(G711::ulaw()),
        JitterBuffer::new(1, PREFILL + 16),
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
    );
    if vad {
        session = session.with_vad(1_000_000, 5, true);
    }

    // Pre-fill the jitter with loud frames (allocates freely; before arming).
    for sequence in 0..PREFILL {
        session.on_rtp(&ulaw_packet(sequence as u16, &loud));
    }
    let mut uplink = [0u8; 1024];
    let mut downlink = [0u8; 1024];
    // Warm up one tick: pays jitter priming and the single silence→speech edge (its one allocation),
    // so the measured window is pure sustained speech with no edges.
    session.tick(&mut uplink, &mut downlink);

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..MEASURED {
        let result = session.tick(&mut uplink, &mut downlink);
        std::hint::black_box(result);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    after - before
}

#[test]
fn vad_adds_no_per_frame_allocation() {
    let baseline = tick_allocations(false);
    let with_vad = tick_allocations(true);
    assert_eq!(
        with_vad, baseline,
        "enabling WS VAD changed per-frame allocations: {with_vad} with VAD vs {baseline} baseline over 1000 ticks"
    );
}

/// One RTP packet carrying `pcm` as an L16 payload (RFC 3551 §4.5.11: network byte order).
fn l16_packet(sequence: u16, pcm: &[i16], payload_type: u8) -> Vec<u8> {
    let mut payload = vec![0u8; pcm.len() * 2];
    for (sample, chunk) in pcm.iter().zip(payload.chunks_exact_mut(2)) {
        chunk.copy_from_slice(&sample.to_be_bytes());
    }
    let header = RtpHeader {
        marker: false,
        payload_type,
        sequence,
        timestamp: u32::from(sequence) * pcm.len() as u32,
        ssrc: 1,
    };
    let mut buffer = vec![0u8; FIXED_HEADER_LEN + payload.len()];
    let written = write_packet(&header, &payload, &mut buffer).expect("write");
    buffer.truncate(written);
    buffer
}

/// The same invariant on a **long-ptime** leg (`L16/48000` at `a=ptime:60` — 2880 samples per frame,
/// three times a 48 kHz 20 ms frame). The staging slot and the echo reference are preallocated on the
/// core, so a leg at the long end of the ptime range still ticks without touching the heap: the fix
/// for the silent long-frame uplink must not have bought its correctness with a per-tick allocation.
#[test]
fn a_long_ptime_leg_ticks_without_per_frame_allocation() {
    const FRAME_SAMPLES: usize = 2880; // 48 kHz × 60 ms
    const MEASURED: usize = 200;
    const PREFILL: usize = MEASURED + 64;

    let leg = MediaLeg::new(
        Box::new(siphon_rtp_codec::l16::L16::new(48_000, 60)),
        Box::new(siphon_rtp_codec::l16::L16::new(48_000, 60)),
        JitterBuffer::new(1, PREFILL + 16),
        0x5555_6666,
        11,
    );
    let mut session = BridgeSession::new(
        leg,
        MediaFormat {
            encoding: siphon_rtp_media::bridge::protocol::Encoding::L16,
            sample_rate: 48_000,
            channels: 1,
            bit_depth: 16,
            endianness: siphon_rtp_media::bridge::protocol::Endianness::Little,
            ptime: 60,
        },
        "str_1",
        "call_1",
        Direction::Duplex,
        8,
    )
    .with_vad(1_000_000, 5, true);

    let loud = [4000i16; FRAME_SAMPLES];
    for sequence in 0..PREFILL {
        session.on_rtp(&l16_packet(sequence as u16, &loud, 11));
    }
    let mut uplink = vec![0u8; 2 * FRAME_SAMPLES];
    let mut downlink = vec![0u8; 4096];
    // One warm-up tick pays the jitter priming and the single silence→speech edge.
    session.tick(&mut uplink, &mut downlink);

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..MEASURED {
        let result = session.tick(&mut uplink, &mut downlink);
        std::hint::black_box(result);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        session.uplink_decode_errors(),
        0,
        "the long-ptime leg must decode, not fail silently"
    );
    assert_eq!(
        after,
        before,
        "long-ptime bridge tick allocated {} times across {MEASURED} ticks (must be zero)",
        after - before
    );
}
