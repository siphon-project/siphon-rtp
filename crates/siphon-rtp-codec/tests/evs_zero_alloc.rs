//! Zero-per-frame-allocation gate for the EVS decoder (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --features evs --test evs_zero_alloc`
//!
//! There is no EVS encoder yet to make input, so the decoder is fed every TS 26.444 decoder
//! sequence upstream's `Readme_EVS_dec.txt` and `Readme_AMRWB_IO_dec.txt` list, at the output rate
//! each names, to the end: every path the decoder can take is measured, whatever bit rate,
//! bandwidth, output rate or mode (MODE1, MODE2, AMR-WB IO) reaches it. Like
//! `evs_conformance`, it skips when the sequences are absent and `SIPHON_RTP_REQUIRE_VECTORS=1`
//! turns that skip into a failure.
//!
//! A counting global allocator measures what the invariant is about, the number of allocator calls.
//! The count runs from the first frame of a freshly built decoder through `flush`: the decoder
//! allocates its state in `EvsDecoder::new` and nothing afterwards, so there is no warm-up to allow.
#![cfg(feature = "evs")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

// The conformance test is the one that reads the reference outputs.
#[allow(dead_code)]
mod evs_cases;

use evs_cases::{cases, required, vectors_dir};
use siphon_rtp_codec::evs::decoder::EvsDecoder;
use siphon_rtp_codec::evs::g192::G192Reader;

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn is
    // not miscounted. `const`-initialised so touching it inside `alloc` never itself allocates.
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

/// Run `body` with allocation counting armed on this thread and return the number of allocator
/// calls it made.
fn count_allocations(body: impl FnOnce()) -> usize {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    body();
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn evs_decode_makes_no_heap_allocation_on_any_decodable_frame() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        eprintln!("skipping: EVS conformance sequences not installed (sh reference/evs/fetch.sh)");
        return;
    };

    let evs = cases(&root, "Readme_EVS_dec.txt");
    let amr_wb_io = cases(&root, "Readme_AMRWB_IO_dec.txt");
    let (mut frames_decoded, mut whole_sequences) = (0usize, 0usize);
    let mut offenders = Vec::new();
    for case in evs.iter().chain(&amr_wb_io) {
        let name = case.bitstream.display().to_string();
        let bytes = std::fs::read(&case.bitstream).expect("read bitstream");
        let frames: Vec<_> = G192Reader::new(&bytes)
            .map(|frame| frame.expect("well-formed G.192"))
            .collect();
        // an empty (truncated or placeholder) sequence would count without decoding anything
        assert!(!frames.is_empty(), "{name}: no frames");
        let mut decoder = EvsDecoder::new(case.output_khz as u32 * 1000).expect("decoder");
        let mut out = vec![0i16; decoder.frame_samples()];

        // Counted per frame, so a failure names where the first allocation happened.
        let mut allocations = 0usize;
        let mut first: Option<String> = None;
        for (index, frame) in frames.iter().enumerate() {
            let mut result = Ok(0);
            let made = count_allocations(|| result = decoder.decode_frame(frame, &mut out));
            if let Err(error) = result {
                panic!("{name} frame {index}: {error}");
            }
            frames_decoded += 1;
            if made != 0 && first.is_none() {
                first = Some(format!("frame {index}"));
            }
            allocations += made;
        }
        let made = count_allocations(|| {
            decoder.flush(&mut out).expect("flush");
        });
        if made != 0 && first.is_none() {
            first = Some("flush".to_owned());
        }
        allocations += made;
        whole_sequences += 1;
        if let Some(first) = first {
            offenders.push(format!(
                "{name}: {allocations} allocations, the first in {first}"
            ));
        }
    }

    eprintln!(
        "{} sequences, {whole_sequences} decoded to the end, {frames_decoded} frames decoded",
        evs.len() + amr_wb_io.len()
    );
    assert!(
        offenders.is_empty(),
        "EVS decode allocated on the hot path: {offenders:?}"
    );
    // Every sequence of both scripts runs to its end (`evs_conformance` gates each as
    // byte-identical): 979 EVS and 1590 AMR-WB IO.
    assert!(
        whole_sequences == 979 + 1590 || evs.is_empty() && !required(),
        "expected 979 + 1590 whole sequences, ran {whole_sequences}"
    );
}
