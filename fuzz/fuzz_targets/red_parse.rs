#![no_main]
//! Fuzz the RFC 2198 RED depacketizer and the RFC 4103 T.140 reassembler on raw network bytes.
//!
//! House rule: a malformed / truncated / hostile RED payload must decode-or-error — never panic,
//! never read out of bounds, never spin. We parse the bytes as RED and also drive the reassembler
//! over them as both a RED payload and a bare T.140 payload (an `m=text` socket can see either).

use libfuzzer_sys::fuzz_target;
use siphon_rtp_media::t140::{RedPacket, T140Reassembler};

fuzz_target!(|data: &[u8]| {
    // The stateless depacketizer must never panic on any input.
    let _ = RedPacket::parse(data);

    // The reassembler must survive arbitrary bytes on either the RED or the bare t140 path.
    let mut red = T140Reassembler::new();
    let _ = red.on_packet(0, 0, data, true);

    let mut bare = T140Reassembler::new();
    let _ = bare.on_packet(1, 20, data, false);
});
