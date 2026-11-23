//! The near leg's DTLS-SRTP state on a call whose offerer the engine terminates (RFC 5764).

use siphon_rtp_dtls::DtlsRole;

use crate::sdp;

/// A DTLS-SRTP offerer the engine terminates (RFC 5764): A's keying from its offer, and what the
/// engine settled toward A when it answered. The near-leg twin of the far leg's DTLS state.
#[derive(Debug, Clone)]
pub(super) struct NearDtls {
    /// A's certificate fingerprint (`a=fingerprint`, RFC 8122), which the handshake verifies
    /// (RFC 5763 §5).
    pub(super) peer_fingerprint: sdp::Fingerprint,
    /// A's `a=setup`, `None` when A sent none (RFC 4145 §4.1 then defaults the offer to `active`).
    pub(super) peer_setup: Option<sdp::Setup>,
    /// A's `a=tls-id` (RFC 8842 §4), `None` when A sent none.
    pub(super) peer_tls_id: Option<String>,
    /// The engine's DTLS role toward A, settled at answer. `None` before an answer.
    pub(super) role: Option<DtlsRole>,
    /// The engine's own `a=tls-id` toward A: assigned for a new association when A signalled one, and
    /// repeated for as long as that association is kept (RFC 8842 §5.3). `None` when A sent none.
    pub(super) local_tls_id: Option<String>,
    /// The `a=mid` of A's audio section and of the WebRTC data channel section it bundles with it
    /// (RFC 8841, RFC 8843), when A offered one. The engine terminates the channel on A's leg (it
    /// carries A's MCPTT floor); B was offered the section declined and never sees it.
    pub(super) data_channel: Option<(String, String)>,
}

impl NearDtls {
    /// Take A's keying from a subsequent offer (RFC 8842 §5.5). A different certificate fingerprint or
    /// `a=tls-id` is a new association (RFC 8842 §3.1): the settled role and the engine's own
    /// `a=tls-id` are dropped, so the answer settles both afresh (RFC 8842 §5.3). A re-offer without a
    /// fingerprint changes nothing here; the re-offer refuses it before any state is touched.
    pub(super) fn restate(&mut self, offer: &sdp::MediaInfo) {
        let Some(fingerprint) = offer.fingerprint.clone() else {
            return;
        };
        let (setup, tls_id) = (offer.setup, offer.tls_id.clone());
        let same_association = self
            .peer_fingerprint
            .hash_function
            .eq_ignore_ascii_case(&fingerprint.hash_function)
            && self.peer_fingerprint.bytes == fingerprint.bytes
            && self.peer_tls_id == tls_id;
        if !same_association {
            self.role = None;
            self.local_tls_id = None;
        }
        self.peer_fingerprint = fingerprint;
        self.peer_setup = setup;
        self.peer_tls_id = tls_id;
    }

    /// Take A's keying from its answer to the engine's subsequent offer, which offered `actpass`
    /// (RFC 8842 §5.5). The answerer picks, so the engine takes the complement of A's `a=setup`, and an
    /// answer without one is `passive` (RFC 4145 §4.1). An `actpass` or `holdconn` answer picks
    /// nothing, and the role in force is kept.
    pub(super) fn answered(
        &mut self,
        fingerprint: sdp::Fingerprint,
        setup: Option<sdp::Setup>,
        tls_id: Option<String>,
    ) {
        self.role = match setup {
            Some(sdp::Setup::Active) => Some(DtlsRole::Server),
            Some(sdp::Setup::Passive) | None => Some(DtlsRole::Client),
            Some(sdp::Setup::Actpass | sdp::Setup::Holdconn) => self.role,
        };
        self.peer_fingerprint = fingerprint;
        self.peer_setup = setup;
        self.peer_tls_id = tls_id;
    }
}
