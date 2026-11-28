//! What the engine says about its own ICE in an SDP it writes.

use siphon_rtp_ice::Candidate;

/// The engine's ICE identity to advertise in a rewritten SDP: `a=ice-ufrag` / `a=ice-pwd`, the
/// **gathered** candidate set, and `a=ice-lite` (session-level) when the leg is served by the lite
/// responder.
#[derive(Debug, Clone, Copy)]
pub struct IceAdvertisement<'a> {
    /// Whether the leg is served by the ICE-lite responder, and so says `a=ice-lite`. RFC 8445
    /// §5.1.1 / RFC 8839 §5.3 make the attribute a statement about the implementation on this leg:
    /// a **full** agent must not make it, because the peer then takes the controlling role against
    /// a "lite" peer (§6.1.1) and the two agents contend for it.
    pub lite: bool,
    /// The engine's local ICE username fragment.
    pub ufrag: &'a str,
    /// The engine's local ICE password.
    pub pwd: &'a str,
    /// The candidates gathered for this leg (RFC 8445 §5.1.1), emitted in order as `a=candidate`
    /// lines. Always at least the host candidate — gathering produces that without touching the
    /// network — plus a server-reflexive one per STUN server that answered.
    pub candidates: &'a [Candidate],
}
