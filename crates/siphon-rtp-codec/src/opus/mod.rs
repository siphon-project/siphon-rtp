//! Pure-Rust Opus (RFC 6716) — a SILK (speech) + CELT (music/wideband) hybrid over a shared
//! range/entropy coder.
//!
//! [`decoder::OpusDecoder`] is the entry point: hand it a packet, get PCM at whatever rate and
//! channel count you asked for. Everything else here is a layer beneath it:
//!
//! | Layer | What it does |
//! |---|---|
//! | [`range_coder`] | The entropy coder both codecs sit on (§4.1) — decoder and encoder |
//! | [`packet`] | TOC byte and frame packing (§3): mode, bandwidth, duration, all four framing codes |
//! | [`silk`] | The linear-prediction speech layer (§4.2), plus concealment and comfort noise (§4.4) |
//! | [`celt`] | The MDCT/PVQ transform layer (§4.3), plus its own concealment |
//! | [`decoder`] | Mode dispatch, Hybrid, redundancy, mode transitions, FEC, rate and channel conversion (§4.5) |
//! | [`codec`] | [`codec::OpusCodec`], the crate's [`crate::Decoder`] over [`decoder::OpusDecoder`] — what [`crate::factory`] builds for a leg |
//!
//! The **decoder is complete**: all three modes, all five bandwidths, every frame duration from
//! 2.5 ms to 120 ms multi-frame packets, full stereo, all five output rates, PLC, in-band FEC and
//! DTX. On the encode side CELT is complete and SILK's analysis front end has landed; the rest of
//! the encoder is still being built.
//!
//! # Conformance
//!
//! RFC 6716 §6 defines conformance as a pass of the `opus_compare` perceptual metric, *not* as
//! bit-exact PCM — float and fixed-point decoders both conform. We hold the decoder to more than
//! that: `tests/opus_conformance.rs` runs all 12 official vectors mono and stereo and additionally
//! requires the encoder's `final_range` on **every packet** (bitstream-exactness, which the
//! tolerance metric cannot see) and sample proximity to libopus' own decode. See CONTRIBUTING.md
//! for the oracle build.
//!
//! # Not implemented, deliberately
//!
//! Opus multistream / surround (RFC 7845 — a separate API for >2 channels, and RFC 7587 defines
//! Opus over RTP as mono or stereo), and libopus 1.5's `ENABLE_DEEP_PLC` / `ENABLE_QEXT` vendor
//! extensions. None is part of RFC 6716.

pub mod celt;
pub mod codec;
pub mod decoder;
pub mod packet;
pub mod range_coder;
pub mod silk;
