#![no_main]
//! Fuzz the AMR-WB decode path with a hostile RTP payload (3GPP TS 26.171 / RFC 4867).
//!
//! House rule: a hostile codec bitstream off the network must decode-or-error, never panic,
//! never read out of bounds, never spin. `Decoder::decode` runs the full RFC 4867 payload parse
//! (ToC + frame un-sort) and the ACELP decode, so feeding it arbitrary bytes exercises both. The
//! concealment path (bad-frame PLC) is fuzzed too, since a jitter buffer drives it from lost frames.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_codec::amr::AmrWb;
use siphon_rtp_codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut codec = AmrWb::new();
    // Oversized so a well-formed multi-frame payload never errors purely on buffer size; the point is
    // to reach the decode logic, not to bounce on a short output.
    let mut out = [0i16; 8192];
    let _ = codec.decode(data, &mut out);
    // PLC: conceal from whatever state the (possibly partial) decode left behind.
    let _ = codec.conceal(&mut out);
});
