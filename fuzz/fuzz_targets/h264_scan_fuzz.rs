#![no_main]
//! Fuzz the H.264 RTP payload classifier (RFC 6184 §5): a seat's video payload is whatever the
//! network hands the room. The classifier must decode-or-nothing on any bytes, never panic, never
//! read past the payload, never spin; and what it returns must lie inside the input.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_media::h264;

fuzz_target!(|data: &[u8]| {
    let found = h264::scan(data);
    for part in [found.sps, found.pps].into_iter().flatten() {
        let start = part.as_ptr() as usize - data.as_ptr() as usize;
        assert!(start + part.len() <= data.len());
    }
});
