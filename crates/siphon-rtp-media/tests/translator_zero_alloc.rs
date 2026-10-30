#![allow(clippy::unwrap_used, reason = "test harness")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::rtp::{write_packet, RtpHeader};
use siphon_rtp_media::translator::Translator;

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

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

#[test]
fn translate_makes_no_heap_allocation_including_rebases() {
    let mut translators = [
        Translator::new(0xE000_0001, 1, 1),
        Translator::new(0xE000_0002, 2, 2),
    ];
    let mut out = [0u8; 256];
    let payload = [0x5Au8; 160];
    let mut packet_a = vec![0u8; 172];
    let mut packet_b = vec![0u8; 172];
    let mut sequence = 0u16;
    let mut timestamp = 0u32;

    let mut cycle = |translators: &mut [Translator; 2]| {
        sequence = sequence.wrapping_add(1);
        timestamp = timestamp.wrapping_add(160);
        for (buffer, ssrc) in [(&mut packet_a, 0xAu32), (&mut packet_b, 0xBu32)] {
            let header = RtpHeader {
                marker: false,
                payload_type: 96,
                sequence,
                timestamp,
                ssrc,
            };
            write_packet(&header, &payload, buffer).unwrap();
        }
        // Alternate talkers in blocks of 4 cycles so rebases are exercised too.
        let packet = if (sequence / 4).is_multiple_of(2) {
            &packet_a
        } else {
            &packet_b
        };
        for translator in translators.iter_mut() {
            std::hint::black_box(translator.translate(packet, timestamp, &mut out).unwrap());
        }
    };

    for _ in 0..64 {
        cycle(&mut translators);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..10_000 {
        cycle(&mut translators);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "translator loop allocated {} times across 10000 cycles (must be zero)",
        after - before
    );
}
