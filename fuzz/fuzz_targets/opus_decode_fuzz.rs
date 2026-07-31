#![no_main]
//! Fuzz the Opus packet framing and the CELT decode path with a hostile payload (RFC 6716).
//!
//! House rule: a hostile codec bitstream off the network must decode-or-error, never panic, never
//! read out of bounds, never spin. Opus is the most reachable of these — an Opus leg is exactly a
//! WebRTC peer sending whatever it likes — and it has two distinct attack surfaces:
//!
//! * **The packet layer (§3)** — the TOC byte plus the four framing codes, including code 3's frame
//!   count, padding chain and CBR/VBR split. `parse` walks attacker-controlled lengths, so it is
//!   fuzzed directly rather than only through a decoder.
//! * **The CELT layer (§4.3)** — range decoding, band allocation and PVQ. Every symbol is derived
//!   from the payload, so a malformed stream drives the decoder far off the paths a real encoder
//!   produces.
//!
//! The band range is set from the packet's own bandwidth, exactly as `opus_decode_native` does
//! (`opus_decoder.c:498-523`) — decoding a narrowband packet as fullband desynchronises the range
//! decoder, so pinning it here would fuzz a configuration the decoder never actually runs in.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_codec::opus::celt::decoder::CeltDecoder;
use siphon_rtp_codec::opus::packet::{self, Mode};

fuzz_target!(|data: &[u8]| {
    // The framing parser on its own: it must reject or split, never panic on a truncated length,
    // an implausible frame count, or a padding chain that runs off the end.
    let Ok(parsed) = packet::parse(data) else {
        return;
    };
    // A well-formed TOC still has to survive the decode. Only CELT-only mono is wired today; the
    // SILK and Hybrid arms join this target as they land.
    if parsed.toc.mode() != Mode::Celt || parsed.toc.channels() != 1 {
        return;
    }
    let Ok(mut celt) = CeltDecoder::new() else {
        return;
    };
    if celt
        .set_band_range(0, CeltDecoder::end_band_for_bandwidth(parsed.toc.bandwidth()))
        .is_err()
    {
        return;
    }
    // 20 ms at 48 kHz is the largest CELT frame; the buffer is sized for it so a valid frame never
    // errors purely on output length — the point is to reach the decode logic.
    let mut pcm = [0i16; 960];
    let frame_size = parsed.toc.samples_per_frame(48_000);
    if frame_size == 0 || frame_size > pcm.len() {
        return;
    }
    for frame in parsed.frames() {
        // Decode every frame of a multi-frame packet from the same decoder, so the cross-frame
        // energy history and decode ring are driven by hostile input too, not just one frame.
        let _ = celt.decode(frame, &mut pcm[..frame_size], frame_size);
    }
});
