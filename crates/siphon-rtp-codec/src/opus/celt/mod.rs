//! CELT decoder (RFC 6716 §4.3) — the MDCT-domain "music / low-delay" layer of Opus.
//!
//! **Phase 3** of the pure-Rust Opus port. CELT (Constrained-Energy Lapped Transform) decodes the
//! CELT-only Opus configs (16–31) and the high band of Hybrid. Pipeline (RFC 6716 §4.3 / libopus
//! `celt_decode_with_ec`): decode per-band energy (coarse Laplace + fine bits) and the PVQ band
//! shapes from the range coder, denormalise (energy × unit-norm shape), inverse-MDCT + overlap-add,
//! then comb post-filter + de-emphasis to PCM.
//!
//! Built in sub-phases: **3a mode tables** ([`tables`]) → 3b entropy scalar params + bit allocation
//! → 3c PVQ/cwrs codebook → 3d synthesis (IMDCT / overlap-add / de-emphasis). ← 3a here.
//!
//! **Float path, `f32`.** Per RFC 6716 §6, Opus conformance is the `opus_compare` *tolerance* metric
//! (a perceptual spectral comparison), not bit-exact PCM — float and fixed-point decoders both
//! conform, so the usual codec bit-exact rule does not apply to Opus. We port libopus's float build
//! (the `#ifndef FIXED_POINT` branches). The `ENABLE_QEXT` (quality-extension) and `ENABLE_DEEP_PLC`
//! (neural PLC) paths are not part of RFC 6716 and are omitted.

pub mod analysis;
pub mod anti_collapse;
pub mod band_analysis;
pub mod band_coder;
pub mod bands;
pub mod decoder;
pub mod energy;
pub mod entropy;
pub mod laplace;
pub mod mathops;
pub mod mdct;
pub mod postfilter;
pub mod pvq;
pub mod rate;
pub mod synthesis;
pub mod tables;
pub mod tf;
pub mod vq;
