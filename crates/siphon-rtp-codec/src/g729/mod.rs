//! G.729 — 8 kbit/s speech coding using conjugate-structure algebraic-code-excited linear
//! prediction (CS-ACELP), ITU-T G.729 with Annex A and Annex B.
//!
//! Ported from the ITU-T G.729 Release 3 fixed-point reference C, function by function, and
//! validated bit-exact against the official test vectors that ship with it: decoding each `*.bit`
//! must reproduce the corresponding `*.pst` byte for byte. `reference/g729/README.md` records where
//! that material comes from and why a round trip is not accepted in its place.
//!
//! The frame is 10 ms — 80 samples at 8 kHz, carried in 80 bits, so 10 octets — split into two
//! 40-sample subframes (RFC 3551 §4.5.6 assigns it static payload type 18). Its arithmetic is the
//! shared ITU fixed-point substrate in [`crate::itu`]; only the routines whose Q formats differ
//! between codec lineages are restated here.
//!
//! Gated behind the off-by-default `g729` Cargo feature, which gates **transcoding** only:
//! relaying G.729 never executes a codec and never reaches this module. See
//! `docs/codec-licensing.md`.

pub mod bitstream;
pub mod overflow;
