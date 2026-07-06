#![no_main]
//! Fuzz the rtpengine NG/bencode control path, which eats `<cookie> <bencode-dict>` datagrams off
//! the UDP control port from any source.
//!
//! House rule: a hostile control datagram must decode-or-error — never panic, never read
//! out of bounds, never spin (and never overflow the recursive-descent stack on a deeply-nested
//! value: that is a real, fixed bug — see `bencode::MAX_DEPTH`). We exercise the whole untrusted
//! path: the bencode decoder, then the cookie split + NG command mapping (RFC-free, rtpengine NG
//! wire as rtpengine defines it).

use libfuzzer_sys::fuzz_target;
use siphon_rtp_ngcompat::{bencode, ng};

fuzz_target!(|data: &[u8]| {
    // The bencode decoder, both entry points (whole-value and prefix framing).
    if let Ok(value) = bencode::decode(data) {
        // A decoded value drives the NG command mapping — that path must not panic either.
        let _ = ng::parse_command(&value);
    }
    let _ = bencode::decode_prefix(data);

    // The full NG datagram path: split the cookie, decode the body, map the command.
    if let Ok((_cookie, body)) = ng::split_cookie(data) {
        if let Ok(value) = bencode::decode(body) {
            let _ = ng::parse_command(&value);
        }
    }
});
