//! The **Opus layer** of the encoder (libopus `src/opus_encoder.c`) — the dispatcher that turns a
//! SILK encoder and a CELT encoder into an Opus encoder.
//!
//! The two codec layers below this one each produce a legal, validated bitstream on their own. What
//! this layer adds is everything that is *not* either codec: the decision of which of them runs, at
//! what bandwidth, over how many channels; the API-rate resampling and high-pass the SILK encoder
//! deliberately left to its caller; the hybrid split where both run into one range coder; and the
//! packet the result is wrapped in.
//!
//! ```text
//!   pcm (8/12/16/24/48 kHz, 1-2 ch)
//!     -> high-pass            highpass.rs   pitch-tracking (VoIP) or 3 Hz DC block
//!     -> decisions            decision.rs   mode, bandwidth, stream channels, FEC, rate split
//!     -> SILK  (low band)     silk::enc     at 8/12/16 kHz, via the API-rate resampler
//!     -> CELT  (band 17+)     celt::encoder into the *same* RangeEncoder
//!     -> TOC + framing        packer.rs     codes 0-3, multi-frame packets, CBR padding
//! ```

pub mod decision;

pub mod encoder;
pub mod highpass;
pub mod packer;
