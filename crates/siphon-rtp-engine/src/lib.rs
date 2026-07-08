//! siphon-rtp-engine — the media engine daemon library.
//!
//! The JSON-over-TCP control front-end ([`server`]), the session [`Engine`] that turns control
//! verbs into datapath relay flows, and a minimal SDP rewrite ([`sdp`]). The engine is generic over
//! [`siphon_rtp_datapath::Datapath`], so the same control logic drives the UDP-loopback backend and
//! the XDP/AF_XDP kernel fast path over identical wiring.
//!
//! The reusable daemon runtime lives in [`daemon`]: [`run_with_datapath`] drives every post-datapath
//! subsystem (control server, TURN, redirect dispatcher, sweeper, metrics/HEP/NG, graceful drain)
//! over **any** [`siphon_rtp_datapath::Datapath`] backend. The default UDP-only `siphon-rtp` binary
//! builds the loopback backend and calls it; the separate `siphon-rtp-xdp-daemon` binary (in the
//! excluded `crates/siphon-rtp-xdp` workspace) probes/attaches the kernel datapath and calls the same
//! runner. The engine crate itself **never** depends on the XDP crate — the kernel path lives above
//! it, so the stable workspace and `cargo test` never touch nightly/eBPF.
#![forbid(unsafe_code)]

pub mod cluster;
pub mod conference;
pub mod config;
pub mod daemon;
pub mod dtls_bridge;
pub mod engine;
pub mod ha;
pub mod ice;
pub mod media_pipeline;
pub mod metrics;
pub mod sdp;
pub mod server;
pub mod shutdown;
pub mod srtp_bridge;
pub mod ws_bridge;

pub use daemon::{run_with_datapath, EngineArgs, RunConfig};
pub use engine::{ClientId, Engine};
pub use metrics::Metrics;
