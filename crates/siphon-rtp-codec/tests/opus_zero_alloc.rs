//! Zero-per-packet-allocation gate for the top-level Opus decoder (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --test opus_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`.
//!
//! A **counting** allocator, not a jemalloc byte delta: the invariant is about the number of calls
//! into the allocator, and allocate-then-free churn (invisible to a live-bytes delta) is exactly the
//! kind of regression a `Vec` slipped into `decode_frame` would cause.
//!
//! [`OpusDecoder`] allocates exactly once, at construction, for the whole-packet float scratch the
//! 16-bit entry point needs; everything else — the SILK PCM staging buffer, the redundancy frame,
//! the mode-transition cross-fade buffer, both layers' state — is a fixed-size array on the stack or
//! on the decoder. So a warmed-up decode loop must make **zero** allocations, in every mode, in both
//! entry points, and on the concealment and FEC paths too. Those last two matter most: they are the
//! paths a lossy leg takes under load, which is exactly when an allocator round-trip is least
//! affordable.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

thread_local! {
    // Both the arm flag *and* the counter are thread-local: libtest runs the tests in this binary
    // concurrently, and a global counter would let one test's allocations be charged to another's
    // measurement window. `const`-initialised so touching them inside `alloc` never itself allocates.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call delegates straight to the system allocator; we only bump a thread-local
// counter, and only when the current thread has armed counting.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.with(|counter| counter.set(counter.get() + 1));
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Run `body` `iterations` times with allocation counting armed, returning the allocator-call count.
fn count_allocations(iterations: usize, mut body: impl FnMut()) -> usize {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..iterations {
        body();
    }
    let after = ALLOCATIONS.with(Cell::get);
    ARMED.with(|armed| armed.set(false));
    after - before
}

/// Config numbers for the three modes at 20 ms (RFC 6716 §3.1, Table 2).
const SILK_WB_20MS: u8 = 9;
const HYBRID_FB_20MS: u8 = 15;
const CELT_FB_20MS: u8 = 31;

/// A deterministic pseudo-random payload behind a TOC byte. The range coder reads any byte string,
/// so this drives every decode stage without needing an encoder or a gitignored vector — which is
/// what lets this gate run on a bare checkout.
fn packet(config: u8, stereo: bool) -> Vec<u8> {
    let mut payload = Vec::with_capacity(61);
    payload.push((config << 3) | (u8::from(stereo) << 2));
    for i in 0..60u32 {
        payload.push((i.wrapping_mul(2_654_435_761) >> 24) as u8);
    }
    payload[1] &= 0x7f; // bias away from the CELT silence flag so the full pipeline runs
    payload
}

/// Decoding a packet must not touch the allocator, in any mode, at any output rate or channel count.
#[test]
fn decoding_a_packet_allocates_nothing() {
    for (label, config) in [
        ("silk", SILK_WB_20MS),
        ("hybrid", HYBRID_FB_20MS),
        ("celt", CELT_FB_20MS),
    ] {
        for stereo in [false, true] {
            for rate in [8_000u32, 16_000, 48_000] {
                for channels in [1usize, 2] {
                    let mut decoder = OpusDecoder::new(rate, channels).expect("decoder");
                    let data = packet(config, stereo);
                    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * channels];
                    // Warm up outside the measurement: the first packet is what configures both
                    // layers, and construction is allowed to allocate.
                    decoder
                        .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
                        .expect("warm-up decode");

                    let allocations = count_allocations(32, || {
                        decoder
                            .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
                            .expect("decode");
                    });
                    assert_eq!(
                        allocations, 0,
                        "{label} stereo={stereo} {rate} Hz {channels}ch: {allocations} allocations \
                         across 32 packets"
                    );
                }
            }
        }
    }
}

/// The float entry point skips the 16-bit conversion but must be just as allocation-free.
#[test]
fn the_float_entry_point_allocates_nothing() {
    for config in [SILK_WB_20MS, HYBRID_FB_20MS, CELT_FB_20MS] {
        let mut decoder = OpusDecoder::new(48_000, 2).expect("decoder");
        let data = packet(config, true);
        let mut pcm = vec![0f32; MAX_PACKET_SAMPLES * 2];
        decoder
            .decode_float(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("warm-up decode");

        let allocations = count_allocations(32, || {
            decoder
                .decode_float(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
                .expect("decode");
        });
        assert_eq!(allocations, 0, "config {config}: {allocations} allocations");
    }
}

/// Concealment is the path a lossy leg takes under load — including the pitch-based CELT PLC, which
/// is the heaviest of them — so it must be allocation-free too.
#[test]
fn concealment_allocates_nothing() {
    for config in [SILK_WB_20MS, HYBRID_FB_20MS, CELT_FB_20MS] {
        let mut decoder = OpusDecoder::new(48_000, 2).expect("decoder");
        let data = packet(config, true);
        let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * 2];
        // Two good packets, so the CELT PLC clears `skip_plc` and the first concealed frame takes
        // the pitch path rather than the cheaper noise one.
        decoder
            .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("decode");
        decoder
            .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("decode");
        decoder.decode(None, &mut pcm, 960, false).expect("warm-up");

        let allocations = count_allocations(32, || {
            decoder.decode(None, &mut pcm, 960, false).expect("conceal");
        });
        assert_eq!(
            allocations, 0,
            "config {config}: {allocations} allocations across 32 concealed frames"
        );

        // A gap longer than 20 ms recurses through the splitter; that must not allocate either.
        let allocations = count_allocations(8, || {
            decoder
                .decode(None, &mut pcm, 2880, false)
                .expect("conceal");
        });
        assert_eq!(
            allocations, 0,
            "config {config}: {allocations} allocations across 8 long concealed gaps"
        );
    }
}

/// In-band FEC decodes the previous frame from the LBRR copy *and* conceals the head of the request,
/// so it exercises both paths in one call. Neither may allocate.
#[test]
fn fec_decode_allocates_nothing() {
    let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
    let data = packet(SILK_WB_20MS, false);
    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES];
    decoder
        .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
        .expect("prime the decoder");
    decoder
        .decode(Some(&data), &mut pcm, 1920, true)
        .expect("warm-up fec");

    let allocations = count_allocations(32, || {
        decoder
            .decode(Some(&data), &mut pcm, 1920, true)
            .expect("fec decode");
    });
    assert_eq!(
        allocations, 0,
        "{allocations} allocations across 32 FEC decodes"
    );
}

/// Switching mode packet to packet runs the transition cross-fade, which conceals 5 ms of the
/// previous mode into a scratch buffer. That buffer is on the stack, so the switch is free too.
#[test]
fn mode_switching_allocates_nothing() {
    let order = [
        CELT_FB_20MS,
        SILK_WB_20MS,
        HYBRID_FB_20MS,
        CELT_FB_20MS,
        HYBRID_FB_20MS,
        SILK_WB_20MS,
    ];
    let packets: Vec<Vec<u8>> = order.iter().map(|&config| packet(config, false)).collect();
    let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES];
    for data in &packets {
        decoder
            .decode(Some(data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("warm-up");
    }

    let allocations = count_allocations(8, || {
        for data in &packets {
            decoder
                .decode(Some(data), &mut pcm, MAX_PACKET_SAMPLES, false)
                .expect("decode");
        }
    });
    assert_eq!(
        allocations, 0,
        "{allocations} allocations across 8 passes over 6 mode switches"
    );
}

/// The counting allocator must actually see allocations, or every assertion above is vacuous.
#[test]
fn the_counting_allocator_is_wired() {
    let allocations = count_allocations(4, || {
        let buffer: Vec<u8> = Vec::with_capacity(4096);
        std::hint::black_box(&buffer);
    });
    assert!(
        allocations >= 4,
        "the counting allocator saw {allocations} allocations for 4 explicit `Vec::with_capacity` \
         calls — the gate is not measuring anything"
    );
}
