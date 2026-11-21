//! Core switching on the decoder side (TS 26.442 `lib_dec/core_switching_dec_fx.c`), one
//! submodule per group of functions.

mod hq_prepare;
mod switching;

pub use hq_prepare::*;
pub use switching::*;
