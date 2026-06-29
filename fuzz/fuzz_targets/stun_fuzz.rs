#![no_main]
//! Fuzz the STUN/TURN message decoder, which eats untrusted datagrams on the media socket (ICE
//! connectivity checks and the built-in TURN server share the port via the layer-1 demux).
//!
//! CLAUDE.md hard rule: a hostile datagram on the media port must decode-or-error — never panic,
//! never read out of bounds, never spin. We exercise the STUN header + attribute TLV parser
//! (RFC 5389 §6/§15), the accessors a parsed message feeds (XOR-MAPPED-ADDRESS, the TURN
//! attributes), MESSAGE-INTEGRITY verification over arbitrary bytes, and the TURN ChannelData
//! framing (RFC 5766 §11) — every path that touches bytes straight off the wire.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_stun::{self as stun, turn};

fuzz_target!(|data: &[u8]| {
    // STUN header + attribute parse, then every accessor that walks the parsed attributes.
    if let Ok(message) = stun::parse(data) {
        let _ = message.is_binding_request();
        let _ = message.username();
        let _ = message.xor_mapped_address();
        // TURN attribute accessors over the same parsed message.
        let _ = turn::requested_transport(&message);
        let _ = turn::lifetime(&message);
        let _ = turn::channel_number(&message);
        let _ = turn::xor_peer_address(&message);
        let _ = turn::xor_peer_addresses(&message);
        let _ = turn::xor_relayed_address(&message);
        let _ = turn::data(&message);
        let _ = turn::error_code(&message);
        let _ = turn::realm(&message);
        let _ = turn::nonce(&message);
    }
    // MESSAGE-INTEGRITY verification walks the raw bytes itself — must also never panic.
    let _ = stun::verify_message_integrity(data, b"fuzz-key");

    // TURN ChannelData framing (the other thing the TURN listener sees on the wire).
    let _ = turn::parse_channel_data(data);
});
