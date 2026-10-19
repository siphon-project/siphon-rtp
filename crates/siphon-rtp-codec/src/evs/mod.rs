//! EVS — the 3GPP Enhanced Voice Services codec (TS 26.441 family), the VoLTE successor to AMR-WB.
//!
//! Being ported from the TS 26.442 fixed-point ("BASOP") reference C, function by function, and
//! validated bit-exact against the TS 26.444 conformance sequences generated with that same code:
//! decoding each `*.COD` must reproduce its `*.OUT` byte for byte. The float reference (TS 26.443)
//! is not followed, because its conformance is a tolerance test and only the fixed-point one is
//! exact. `reference/evs/README.md` records where that material comes from, how the out-of-tree
//! oracle build is made, and why it is compiled with `-fwrapv`.
//!
//! **Status: groundwork only.** This module holds what every later stage stands on: the frame-size
//! table ([`frame`]), the G.192 container the vectors are stored in ([`g192`]), and the EVS
//! multiply/divide helpers ([`basop`]) on top of the shared STL operators in
//! [`crate::itu::stl2009`]. There is no decoder yet, and the codec factory does not offer EVS until
//! the decoder passes every TS 26.444 decoder sequence.
//!
//! Gated behind the off-by-default `evs` Cargo feature, which gates **transcoding** only: relaying
//! EVS never executes a codec and never reaches this module. EVS is covered by an active patent
//! pool; enabling the feature is the operator's statement that they hold a licence. See
//! `docs/codec-licensing.md`.

pub mod basop;
pub mod frame;
pub mod g192;
