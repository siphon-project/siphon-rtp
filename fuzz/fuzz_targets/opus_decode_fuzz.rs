#![no_main]
//! Fuzz the whole Opus decoder with a hostile payload (RFC 6716).
//!
//! House rule: a hostile codec bitstream off the network must decode-or-error, never panic, never
//! read out of bounds, never spin. Opus is the most reachable of these — an Opus leg is exactly a
//! WebRTC peer sending whatever it likes — and it has several distinct attack surfaces:
//!
//! * **The packet layer (§3)** — the TOC byte plus the four framing codes, including code 3's frame
//!   count, padding chain and CBR/VBR split. `parse` walks attacker-controlled lengths, so it is
//!   fuzzed directly rather than only through a decoder.
//! * **SILK (§4.2)** — the LP-layer header, the NLSF and LTP indices and the shell coder, every one
//!   of which indexes a table with a decoded symbol.
//! * **CELT (§4.3)** — range decoding, band allocation and PVQ. Every symbol is derived from the
//!   payload, so a malformed stream drives the decoder far off the paths a real encoder produces.
//! * **The layer boundary (§4.5)** — Hybrid runs both of the above off one range decoder, and the
//!   redundancy path lets the payload choose how many of its own trailing bytes are handed to a
//!   *second* CELT decoder. A byte count read from the stream that then indexes the stream is the
//!   classic shape of a memory-safety bug, and it is only reachable through the top-level decoder.
//!
//! Driving [`OpusDecoder`] rather than one layer is what reaches all of that. The first byte of the
//! input picks the decoder geometry — output rate, channel count, and whether each packet is decoded
//! normally, as in-band FEC, or alternated with a concealed loss — and the rest is split into a
//! *sequence* of packets. That matters: mode switching, the redundancy carry-over and the "previous
//! mode" the PLC conceals in are all cross-packet state, so a packet's effect depends on what came
//! before it and a single-packet target cannot reach any of it.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};
use siphon_rtp_codec::opus::packet;

/// The output rates RFC 6716 §2 defines.
const RATES: [u32; 5] = [8_000, 12_000, 16_000, 24_000, 48_000];

fuzz_target!(|data: &[u8]| {
    // The framing parser on its own: it must reject or split, never panic on a truncated length,
    // an implausible frame count, or a padding chain that runs off the end.
    let _ = packet::parse(data);

    // The first byte selects the decoder geometry, so one corpus covers the whole matrix rather than
    // a single configuration. The rest is the packet stream.
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let rate = RATES[usize::from(selector) % RATES.len()];
    let channels = 1 + (usize::from(selector >> 3) & 1);
    let Ok(mut decoder) = OpusDecoder::new(rate, channels) else {
        return;
    };

    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * channels];
    let capacity = pcm.len() / channels;
    // 20 ms — the FEC and concealment paths require a 2.5 ms multiple.
    let concealed = rate as usize / 50;
    // Split on a selector-chosen stride so the corpus explores both long single packets and long
    // runs of short ones.
    let stride = (1 + (usize::from(selector >> 4) & 0x7) * 16).max(1);

    for (index, chunk) in payload.chunks(stride).enumerate() {
        match (selector >> 1) & 0x3 {
            // Normal decode.
            0 | 3 => {
                let _ = decoder.decode(Some(chunk), &mut pcm, capacity, false);
            }
            // In-band FEC: re-decode the previous frame from this packet's LBRR copy.
            1 => {
                let _ = decoder.decode(Some(chunk), &mut pcm, concealed, true);
            }
            // Alternate a real packet with a concealed loss, which puts the decoder through the
            // PLC-then-recover path in whatever mode it was last left in.
            _ => {
                if index % 2 == 0 {
                    let _ = decoder.decode(Some(chunk), &mut pcm, capacity, false);
                } else {
                    let _ = decoder.decode(None, &mut pcm, concealed, false);
                }
            }
        }
    }
});
