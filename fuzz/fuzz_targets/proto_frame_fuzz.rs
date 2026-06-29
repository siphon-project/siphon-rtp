#![no_main]
//! Fuzz the native JSON-over-TCP control framing, which eats a length-prefixed JSON stream from the
//! SIPhon control connection.
//!
//! CLAUDE.md hard rule: a corrupt length prefix or JSON body must decode-or-error — never panic,
//! never read out of bounds, never spin. The frame is a big-endian `u32` length followed by a JSON
//! [`Request`](siphon_rtp_proto::Request) body; an oversized length must be rejected
//! ([`MAX_FRAME_LEN`](siphon_rtp_proto::MAX_FRAME_LEN)), not used to slice past the buffer.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_proto::{frame, Request};

fuzz_target!(|data: &[u8]| {
    // One decode of the front of the buffer (the server loops this over a growing read buffer).
    let _ = frame::decode::<Request>(data);
});
