#![no_main]
//! Fuzz the EVS RTP payload parser and the `a=fmtp` parser with hostile bytes (3GPP TS 26.445
//! Annex A).
//!
//! House rule: a malformed or truncated packet off the network must parse-or-error, never panic,
//! never read out of bounds, never spin. The same bytes go through the payload reader in both modes
//! (`hf-only` 0 and 1), every frame of what parses has its bits read in the decoder's order, and
//! the bytes are also read as an `a=fmtp` parameter list.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_codec::evs::rtp::{Cmr, Packet, MAX_FRAMES_PER_PACKET};
use siphon_rtp_codec::evs_fmtp::EvsParams;

fuzz_target!(|data: &[u8]| {
    for header_full_only in [false, true] {
        if let Ok(packet) = Packet::parse(data, header_full_only) {
            assert!((1..=MAX_FRAMES_PER_PACKET).contains(&packet.frame_count()));
            let mut bits = [0u8; 2560];
            let mut frames = 0;
            for frame in packet.frames() {
                let count = frame.decoder_bits(&mut bits);
                assert_eq!(count, frame.frame_type.speech_bits());
                let _ = (frame.sid_update(), frame.codec_mode_indication());
                frames += 1;
            }
            assert_eq!(frames, packet.frame_count());
        }
    }
    // the CMR octet table never fails, whatever the octet
    if let Some(&octet) = data.first() {
        let _ = Cmr::from_octet(octet);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(params) = EvsParams::parse(text) {
            // what is written reads back as what it was
            assert_eq!(EvsParams::parse(&params.to_fmtp()), Ok(params));
        }
    }
});
