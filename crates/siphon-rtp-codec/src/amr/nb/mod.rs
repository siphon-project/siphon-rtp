//! AMR-NB codec (3GPP TS 26.073, RTP RFC 4867) — pure-Rust bit-exact port, built decoder-first
//! against the official 3GPP TS 26.074 `T_<mode>` vectors (`*.COD` → `*.OUT`).
//!
//! The shared fixed-point layer ([`crate::amr::basic_ops`], [`crate::amr::math_op`],
//! [`crate::amr::oper_32b`]) underpins these tiers, exactly as for AMR-WB.
//!
//! Build order (each tier unit-tested + committed): bitstream (de)packing → LSP/LSF → pitch →
//! algebraic codebook → gains → decoder main (+ post-filter / homing) → encoder.

pub mod bitstream;
pub mod codebook;
pub mod constants;
pub mod dec_main;
pub mod enc_cb;
pub mod enc_gain;
pub mod enc_lpc;
pub mod enc_lsp;
pub mod enc_main;
pub mod enc_pitch_cl;
pub mod enc_pitch_ol;
pub mod enc_tables;
pub mod filters;
mod gain_tables;
mod gain_vq_tables;
pub mod gains;
pub mod lpc;
mod lpc_tables;
mod math_nb;
pub mod pitch;
pub mod postfilter;
pub mod support;
