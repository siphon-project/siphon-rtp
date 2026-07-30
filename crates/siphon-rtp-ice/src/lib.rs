//! Pure-Rust ICE (RFC 8445) agent core — **no I/O, no clock, no runtime**.
//!
//! This crate owns the parts of ICE that are pure computation, so they can be validated against the
//! specification rather than against a live peer: the candidate model with its RFC 8445 §5.1.2
//! priority and §5.1.1.3 foundation rules, and the RFC 8839 SDP grammar that carries them.
//!
//! Nothing here opens a socket, spawns a task, or reads a clock. The engine drives it and executes
//! whatever it returns. That separation is what lets the checklist and nomination milestones be
//! tested on a logical tick clock with no network at all.
//!
//! # Scope
//!
//! UDP only. TCP candidates (RFC 6544) are deliberately out of scope — a peer on a TCP-only network
//! is served through the engine's built-in TURN server, not by offering `tcp` candidates of our own.
//!
//! # Specifications
//!
//! - RFC 8445 — Interactive Connectivity Establishment (candidates, priorities, foundations).
//! - RFC 8839 — SDP offer/answer for ICE (`a=candidate`, `a=ice-options`, `a=end-of-candidates`).
//! - RFC 8421 — guidelines for multihomed and dual-stack ICE.
//! - RFC 5245 — the obsoleted predecessor, still what many deployed SIP UAs implement.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod candidate;
pub mod gather;

pub use candidate::{
    interleaved_local_preferences, priority, Candidate, CandidateKind, CandidateParseError,
    IceOptions, Transport, END_OF_CANDIDATES_ATTRIBUTE, MAX_COMPONENT_ID,
};
pub use gather::{GatherAction, GatherConfig, Gatherer};
