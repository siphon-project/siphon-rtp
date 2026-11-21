//! EVS — the 3GPP Enhanced Voice Services codec (TS 26.441 family), the VoLTE successor to AMR-WB.
//!
//! Being ported from the TS 26.442 fixed-point ("BASOP") reference C, function by function, and
//! validated bit-exact against the TS 26.444 conformance sequences generated with that same code:
//! decoding each `*.COD` must reproduce its `*.OUT` byte for byte. The float reference (TS 26.443)
//! is not followed, because its conformance is a tolerance test and only the fixed-point one is
//! exact. `reference/evs/README.md` records where that material comes from, how the out-of-tree
//! oracle build is made, and why it is compiled with `-fwrapv`.
//!
//! **Status: the MODE1 decoder runs end to end, for the frames it covers.** [`decoder::EvsDecoder`]
//! is the `decoder.c` loop over a G.192 stream (bit reading, `evs_dec_fx`, output conversion,
//! start-of-stream delay compensation); [`dec::evs_dec`] is the per-frame dispatcher and
//! [`dec::hq_core_dec`] the HQ core. The NB and WB sequences of TS 26.444 at 7.2, 8.0 (ACELP) and
//! 32, 64 kbit/s (HQ), clean, frame-erased and DTX, decode byte for byte to the reference output
//! (`tests/evs_conformance.rs` lists them). Not ported yet, and refused with
//! [`error::EvsError::Unsupported`] naming the reference call (never decoded to silence): MODE2
//! (TCX; `dec_acelp_tcx_frame`), AMR-WB IO (`amr_wb_dec_fx`, `updt_IO_switch_dec_fx`), and the
//! bandwidth-extension decoders `wb_tbe_dec_fx`, `swb_tbe_dec_fx` / `fb_tbe_dec_fx`,
//! `swb_bwe_dec_fx`, `swb_bwe_dec_hr_fx` and `swb_CNG_dec_fx`. The codec factory does not offer
//! EVS until the decoder passes every TS 26.444 decoder sequence.
//!
//! Gated behind the off-by-default `evs` Cargo feature, which gates **transcoding** only: relaying
//! EVS never executes a codec and never reaches this module. EVS is covered by an active patent
//! pool; enabling the feature is the operator's statement that they hold a licence. See
//! `docs/codec-licensing.md`.

// Ported functions keep the reference signatures, which often carry more than 12 parameters.
#![allow(clippy::too_many_arguments)]

pub mod basop;
pub mod cnst;
pub mod com;
pub mod dec;
pub mod decoder;
pub mod error;
pub mod frame;
pub mod g192;
pub mod macros;
pub mod rom;
