//! Zero-per-frame-allocation gate for the EVS decoder (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --features evs --test evs_zero_alloc`
//!
//! There is no EVS encoder yet to make input, so the decoder is fed the TS 26.444 conformance
//! bitstreams of every rate it is declared done for: ACELP at 7.2 and 8.0 kbit/s, the HQ core at
//! 32 and 64 kbit/s, each plain and DTX (comfort noise), clean and frame-erased (concealment). Like
//! `evs_conformance`, it skips when the sequences are absent and `SIPHON_RTP_REQUIRE_VECTORS=1`
//! turns that skip into a failure.
//!
//! A counting global allocator measures what the invariant is about, the number of allocator calls.
//! The count runs from the first frame of a freshly built decoder through `flush`: the decoder
//! allocates its state in `EvsDecoder::new` and nothing afterwards, so there is no warm-up to allow.
#![cfg(feature = "evs")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn vectors_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SIPHON_RTP_EVS_VECTORS") {
        let path = PathBuf::from(path);
        return path.is_dir().then_some(path);
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec");
    dir.is_dir().then_some(dir)
}

fn required() -> bool {
    std::env::var("SIPHON_RTP_REQUIRE_VECTORS").is_ok_and(|value| value == "1")
}

/// The rates (bit/s) the decoder is declared done for; kept equal to `DECODER_DONE` in
/// `evs_conformance.rs`.
const DECODER_DONE: &[u32] = &[7200, 8000, 32000, 64000];

/// The output rate (Hz) of a `stv{8,16}c[_dtx]_<rate>_<kHz>kHz[.b10|.f06].COD` sequence at a done
/// rate, or `None` for any other file.
fn done_output_rate(name: &str) -> Option<u32> {
    let stem = name.strip_suffix(".COD")?;
    let stem = stem
        .strip_suffix(".b10")
        .or(stem.strip_suffix(".f06"))
        .unwrap_or(stem);
    let stem = stem
        .strip_prefix("stv8c_")
        .or(stem.strip_prefix("stv16c_"))?;
    let stem = stem.strip_prefix("dtx_").unwrap_or(stem);
    let mut fields = stem.split('_');
    let rate: u32 = fields.next()?.parse().ok()?;
    let output_khz: u32 = fields.next()?.strip_suffix("kHz")?.parse().ok()?;
    (DECODER_DONE.contains(&rate) && matches!(output_khz, 8 | 16)).then_some(output_khz * 1000)
}

#[test]
fn evs_decode_makes_no_heap_allocation_on_any_done_sequence() {
    let Some(root) = vectors_dir() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but reference/evs/testvec is absent"
        );
        eprintln!("skipping: EVS conformance sequences not installed (sh reference/evs/fetch.sh)");
        return;
    };

    let mut sequences = 0usize;
    let mut frames_decoded = 0usize;
    let mut offenders = Vec::new();
    for band in ["nb", "wb"] {
        let dir = root.join("testv/bitstreams").join(band);
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let Some(output_rate) = done_output_rate(name) else {
                continue;
            };
            let bytes = std::fs::read(&path).expect("read bitstream");
            let frames: Vec<_> = G192Reader::new(&bytes)
                .map(|frame| frame.expect("well-formed G.192"))
                .collect();
            // an empty (truncated or placeholder) sequence would count without decoding anything
            assert!(!frames.is_empty(), "{name}: no frames");
            let mut decoder = EvsDecoder::new(output_rate).expect("decoder");
            let mut out = vec![0i16; decoder.frame_samples()];

            // Counted per frame, so a failure names where the first allocation happened.
            let mut allocations = 0usize;
            let mut first: Option<String> = None;
            for (index, frame) in frames.iter().enumerate() {
                let made = count_allocations(|| {
                    decoder
                        .decode_frame(frame, &mut out)
                        .unwrap_or_else(|error| panic!("{name} frame {index}: {error}"));
                });
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
            if let Some(first) = first {
                offenders.push(format!(
                    "{name}: {allocations} allocations, the first in {first}"
                ));
            }
            sequences += 1;
            frames_decoded += frames.len();
        }
    }

    eprintln!("{sequences} sequences, {frames_decoded} frames decoded");
    assert!(
        offenders.is_empty(),
        "EVS decode allocated on the hot path: {offenders:?}"
    );
    // 7.2 and 8.0 kbit/s: NB and WB; 32 and 64 kbit/s: WB only; each plain and DTX, clean, .b10
    // and .f06 (the same 36 sequences `evs_conformance` compares)
    assert!(
        sequences == 36 || sequences == 0 && !required(),
        "expected 36 sequences, ran {sequences}"
    );
}
