//! siphon-rtp-ngcompat — the rtpengine NG/bencode control front-end.
//!
//! Speaks the *actual* rtpengine NG protocol (`<cookie> <bencode-dict>` over UDP), so existing
//! Kamailio/OpenSIPS/FreeSWITCH deployments and SIPhon's bencode rtpengine client drive siphon-rtp
//! unchanged. It parses NG commands into the internal `Command` and serializes results back —
//! control-protocol parity only; the in-kernel path is our own XDP, never the rtpengine kmod.
//!
//! [`bencode`] is the wire encoding; the NG command mapping and UDP listener layer on top.
#![forbid(unsafe_code)]

pub mod bencode;
