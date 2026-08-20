//! Fuzz the call-progress **tone spec** grammar — `siphon_rtp_media::tone::ToneSpec::resolve`.
//!
//! The tone string arrives verbatim from the control plane (`play_media` with a `tone` source), so
//! it is untrusted input by the project's rule that every parser eating untrusted bytes gets a
//! target. A malformed spec must resolve or return a typed `ToneSpecError` — never panic, never
//! read out of bounds, never spin.
//!
//! Whatever *does* parse is then rendered, because a spec that parses but drives the generator into
//! a divide-by-zero, an out-of-bounds segment index or a non-terminating loop would be just as bad
//! as a parser panic. The render is bounded to a fixed frame budget so an endless (`*inf`) tone
//! cannot hang the fuzzer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use siphon_rtp_media::tone::{ToneGenerator, ToneSpec};

/// Frames rendered per accepted spec. 200 × 20 ms = 4 s, past every preset's cadence boundary and
/// past a couple of repeats of a short one, while staying fast enough for a fuzz iteration.
const RENDER_FRAMES: usize = 200;

fuzz_target!(|data: &[u8]| {
    // Only valid UTF-8 can reach the parser: the control frame is JSON, so a non-UTF-8 tone string
    // is rejected by serde long before this. Fuzzing invalid UTF-8 here would test serde, not us.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(spec) = ToneSpec::resolve(text) else {
        return;
    };

    // The grammar's own invariants must hold for anything that parsed.
    assert!(!spec.segments().is_empty(), "an accepted spec has segments");
    for segment in spec.segments() {
        assert!(segment.duration_ms() > 0, "an accepted segment has a duration");
        for &frequency in segment.frequencies_hz() {
            assert!(frequency > 0, "a sounding component has a frequency");
        }
    }

    // Render at each rate the egress selects, into frames of different lengths, so a segment
    // boundary lands both on and off a frame boundary.
    for (rate_hz, frame_samples) in [(8_000u32, 160usize), (16_000, 320), (48_000, 137)] {
        let mut generator = ToneGenerator::new(spec, rate_hz);
        let mut frame = vec![0i16; frame_samples];
        for _ in 0..RENDER_FRAMES {
            let Some(written) = generator.next_frame(&mut frame) else {
                break;
            };
            assert!(written <= frame.len());
        }
    }
});
