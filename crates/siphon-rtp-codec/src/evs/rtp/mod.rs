//! The EVS RTP payload format, 3GPP TS 26.445 Annex A: reading a payload ([`payload`]), its codec
//! mode request ([`cmr`]) and the AMR-WB IO bit order ([`sort`]).
//!
//! The `a=fmtp` parameters that select between the two payload formats and describe the stream are
//! [`crate::evs_fmtp`], which is not behind the `evs` feature.

pub mod cmr;
pub mod payload;
pub mod sort;

pub use cmr::{Cmr, RequestedRate};
pub use payload::{
    Frame, FrameType, Frames, Packet, PayloadError, PayloadFormat, MAX_FRAMES_PER_PACKET,
};
