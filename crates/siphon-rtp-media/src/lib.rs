//! siphon-rtp-media — the media plane.
//!
//! Pure, synchronous, allocation-light building blocks for the slow path: RTP/RTCP packet
//! handling ([`rtp`], [`rtcp`]), and — landing incrementally — jitter buffer/PLC, resampling,
//! the per-leg pipeline, fan-out/fork, the mixer, and the stream bridges. Everything here is
//! NIC-free and unit-testable; the datapath and engine wire it to sockets.
#![forbid(unsafe_code)]

pub mod bridge;
pub mod dtmf;
pub mod fanout;
pub mod fork;
pub mod ingress;
pub mod jitter;
pub mod leg;
pub mod mixer;
pub mod pcap;
pub mod player;
pub mod repacketize;
pub mod rtcp;
pub mod rtp;
pub mod t140;
pub mod text_mixer;
pub mod wav;
