//! Zero-per-frame-allocation gate for the EVS RTP path: depacketize and decode, through the
//! factory's [`Decoder`] the engine runs.
//!
//! `cargo test -p siphon-rtp-codec --features evs --test evs_rtp_zero_alloc` (release is faster).
//!
//! The input is the reference encoder's frames of `evs_rtp_kat/frames.txt` (every EVS primary rate,
//! every AMR-WB IO mode, both SIDs and NO_DATA), wrapped as header-full payloads and, where the
//! format has one, compact; with a payload no EVS decoder takes, a lost packet to conceal, and a
//! two-frame payload. A counting global allocator measures the allocator calls from the first
//! payload to the last: the decoder allocates its state when it is built and nothing afterwards, so
//! there is no warm-up to allow.
#![cfg(feature = "evs")]
#![allow(clippy::expect_used, reason = "test harness: a panic reports failure")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_codec::factory::{decoder_for, CodecSpec, EvsParams};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
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

fn count_allocations(body: impl FnOnce()) -> usize {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    body();
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn depacketizing_and_decoding_evs_makes_no_heap_allocation() {
    let storage: Vec<Vec<u8>> = include_str!("evs_rtp_kat/frames.txt")
        .lines()
        .map(|line| unhex(line.split('|').nth(5).expect("storage frame")))
        .collect();
    // header-full payloads, with a CMR octet on every other one
    let mut payloads: Vec<Vec<u8>> = storage
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            let mut payload: Vec<u8> = if index % 2 == 0 {
                vec![0xFF]
            } else {
                Vec::new()
            };
            payload.extend_from_slice(frame);
            // keep a header-full payload from being the size of a compact one
            payload.push(0);
            payload
        })
        .collect();
    // compact: EVS primary frames are the frame bits, so the storage frame minus its table of
    // contents octet is the compact payload when that is a compact size
    for frame in &storage {
        let bits = &frame[1..];
        if frame[0] & 0x20 == 0
            && [6, 18, 20, 24, 33, 41, 61, 80, 120, 160, 240, 320].contains(&bits.len())
        {
            payloads.push(bits.to_vec());
        }
    }
    // a two-frame payload, and what is no payload
    payloads.push([&[0x44u8, 0x0F][..], &storage[0][1..], &[0u8; 3][..]].concat());
    payloads.push(vec![0x4F]);
    payloads.push(Vec::new());

    for fmtp in ["bw=wb", "bw=nb-fb;hf-only=1"] {
        let spec = CodecSpec::new(96, "EVS", 16_000, 1, 20)
            .with_evs_params(Some(EvsParams::parse(fmtp).expect("fmtp")));
        let mut decoder = decoder_for(&spec).expect("EVS decoder");
        let mut out = vec![0i16; 12 * decoder.frame_samples()];
        let mut decoded = 0usize;
        let mut refused = 0usize;
        let allocations = count_allocations(|| {
            for _ in 0..3 {
                for payload in &payloads {
                    match decoder.decode(payload, &mut out) {
                        Ok(_) => decoded += 1,
                        Err(_) => refused += 1,
                    }
                }
                let _ = decoder.conceal(&mut out);
            }
        });
        assert_eq!(
            allocations, 0,
            "{fmtp}: allocator calls over {decoded} decoded payloads"
        );
        assert!(decoded > 150, "{fmtp}: only {decoded} payloads decoded");
        assert!(refused > 0, "{fmtp}: the refusal path was not exercised");
    }
}
