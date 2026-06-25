//! siphon-rtp-engine — the media engine daemon library.
//!
//! M1 walking skeleton: the JSON-over-TCP control front-end ([`server`]), the session
//! [`Engine`] that turns control verbs into datapath relay flows, and a minimal SDP rewrite
//! ([`sdp`]). The engine is generic over [`siphon_rtp_datapath::Datapath`], so the same control
//! logic drives the UDP-loopback backend today and the XDP backend once it lands.
#![forbid(unsafe_code)]

pub mod engine;
pub mod sdp;
pub mod server;

pub use engine::Engine;
