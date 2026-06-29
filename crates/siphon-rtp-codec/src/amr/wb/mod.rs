//! AMR-WB decoder (3GPP TS 26.173) — pure-Rust bit-exact port, built leaf-first against the official
//! `tst_mN.cod` → `tst_mN.out` vectors. The shared fixed-point layer ([`crate::amr::basic_ops`],
//! [`crate::amr::math_op`], [`crate::amr::oper_32b`]) underpins these decoder tiers.
//!
//! See `reference/amr-wb/DECODER_PORTING.md` for the tier roadmap and per-frame pipeline.

pub mod bitstream;
pub mod codebook;
pub mod constants;
pub mod dec_main;
pub mod enhance;
pub mod filters;
pub mod gains;
pub mod homing;
pub mod isf_dequant;
mod isf_tables;
pub mod lpc;
pub mod pitch;
mod tables;
