//! Pure-Rust Opus (RFC 6716) — **decoder-first, phased** (a multi-stage sub-project).
//!
//! Opus is the strategic long pole: a SILK (speech) + CELT (music/wideband) hybrid over a shared
//! range/entropy coder. It's built up in phases, each validated as it lands:
//!
//! 1. **Range coder** ([`range_coder`]) — the entropy foundation both SILK and CELT sit on
//!    (RFC 6716 §4.1). Validated by encode↔decode round-trip (the coder is exactly invertible). ← here.
//! 2. Packet / TOC framing (§3) — config byte, stereo flag, frame packing.
//! 3. CELT decoder (§4.3) — MDCT + PVQ + band decoding.
//! 4. SILK decoder (§4.2) — LP-based speech decoding.
//! 5. Hybrid mode + mode-switching + resampling.
//!
//! Full-codec conformance is the official RFC 6716 / opus_codec.org test vectors checked with the
//! `opus_compare` tolerance metric (a perceptual spectral comparison, *not* bit-exact PCM — a
//! conformant Opus decoder need not be sample-identical), wired once CELT + SILK decode exist.

pub mod celt;
pub mod packet;
pub mod range_coder;
