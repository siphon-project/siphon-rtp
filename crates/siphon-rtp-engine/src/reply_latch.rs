//! The SSRC-consistent reply latch every userspace `Redirect` consumer runs: the transcode pipeline,
//! the conference, the text relay and the WebSocket takeover (docs/security-and-nat.md §4 layer 3).
//!
//! It is the datapath's own state machine, [`source_latch_verdict`], held per stream, with the drop the
//! datapath's `Forward` path makes on a rejected source: each consumer decides it after SRTP
//! authentication and before anything consumes the packet.

use std::net::SocketAddr;

use siphon_rtp_datapath::{source_latch_verdict, SourceLatch, SourceLatchVerdict};

/// The SSRC-consistent symmetric-RTP latch for a `Redirect`-path leg (RFC 3550 §8, RFC 4961). The
/// reverse egress destination follows a genuine NAT rebind (a new source that keeps the stream's
/// SSRC), and a hijack spray (a new source with a different SSRC) is dropped. Only **authenticated**
/// datagrams are ever offered here — on a secure leg the caller offers a packet only *after* SRTP
/// `unprotect` succeeds — so a forged, auth-failing packet can never move the reply direction (the
/// fix for the pre-auth, no-SSRC-check re-latch).
#[derive(Default)]
pub(crate) struct SymmetricLatch {
    latch: Option<SourceLatch<SocketAddr>>,
}

/// What the reply latch decides for one authenticated datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyLatch {
    /// Accept the datagram. `Some` is the address the reverse direction should now reply to: the
    /// latched source.
    Accept(Option<SocketAddr>),
    /// Drop the datagram: a new source that cannot prove it is the latched stream, dropped exactly as
    /// the datapath's `Forward` path drops it, before anything consumes it.
    Reject,
}

impl SymmetricLatch {
    /// Admit one authenticated datagram from `source`, whose
    /// [`rtp_media_ssrc`](siphon_rtp_datapath::rtp_media_ssrc) is `ssrc` (`None` for RTCP and anything
    /// else that is not RTP media). The state machine decides, with one restriction the kernel adapter
    /// shares: a source learned from a datagram carrying no SSRC is not stored, so RTCP arriving before
    /// any RTP never aims the reply.
    pub(crate) fn admit(&mut self, source: SocketAddr, ssrc: Option<u32>) -> ReplyLatch {
        match source_latch_verdict(self.latch, source, ssrc) {
            SourceLatchVerdict::Keep => ReplyLatch::Accept(Some(source)),
            SourceLatchVerdict::Learn(SourceLatch { ssrc: None, .. }) => ReplyLatch::Accept(None),
            SourceLatchVerdict::Learn(latch) => {
                self.latch = Some(latch);
                ReplyLatch::Accept(Some(source))
            }
            SourceLatchVerdict::Reject => ReplyLatch::Reject,
        }
    }
}

/// The latch for a relayed stream that carries **no SSRC at all** — a T.38 fax over UDPTL.
///
/// [`SymmetricLatch`] cannot be reused for one. It deliberately does not *store* a source learned
/// from an SSRC-less datagram (the carve-out that keeps RTCP arriving before RTP from aiming the
/// reply), so on a stream that never has an SSRC it returns `Accept(None)` forever and never latches
/// at all. Paired with `SourceFilter::Any` — which is what the opt-in `symmetric` flag installs, and
/// where the latch is then the only constraint left — that degrades to no gate whatever: exactly the
/// RTPBleed-class hole docs/security-and-nat.md §4 layer 3 records as already fixed once for RTP.
///
/// So this one stores it. The underlying state machine already gives the right answer for
/// `ssrc: None` and needs no new policy: the first datagram learns its source, and **every** later
/// source is rejected, because nothing can prove a new one is the same stream. That is the posture
/// the design already describes for an SSRC-less latch — "confirmed by its own source but never
/// moved" — and the only safe reading for an opaque stream. A genuine mid-call NAT rebind therefore
/// kills a fax rather than following it, which is the correct trade: a fax that stops is retried,
/// and a fax that follows an attacker is not a fax.
///
/// It is the same [`source_latch_verdict`] the RTP path uses, called with `ssrc: None`, so the two
/// cannot drift on what counts as a rebind.
#[derive(Default)]
pub(crate) struct OpaqueLatch {
    latch: Option<SourceLatch<SocketAddr>>,
}

impl OpaqueLatch {
    /// Admit one datagram from `source`, having already passed the layer-2 signalled-source gate.
    /// Returns the address the reverse direction should reply to, or [`ReplyLatch::Reject`] to drop.
    pub(crate) fn admit(&mut self, source: SocketAddr) -> ReplyLatch {
        match source_latch_verdict(self.latch, source, Option::None) {
            SourceLatchVerdict::Keep => ReplyLatch::Accept(Some(source)),
            SourceLatchVerdict::Learn(latch) => {
                self.latch = Some(latch);
                ReplyLatch::Accept(Some(source))
            }
            SourceLatchVerdict::Reject => ReplyLatch::Reject,
        }
    }

    /// The latched source, once one datagram has been accepted.
    pub(crate) fn latched(&self) -> Option<SocketAddr> {
        self.latch.map(|latch| latch.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    #[test]
    fn the_reply_latch_keeps_the_first_ssrc_through_a_same_source_ssrc_change() {
        // The datapath's own state machine: the latched source may change SSRC and stays latched, but
        // the change does not re-pin the latch, so only the stream's first SSRC can move the reply to
        // a new source.
        let first = address("127.0.0.2:5000");
        let rebound = address("127.0.0.2:5002");
        let mut latch = SymmetricLatch::default();
        assert_eq!(
            latch.admit(first, Some(0x1111_1111)),
            ReplyLatch::Accept(Some(first))
        );
        assert_eq!(
            latch.admit(first, Some(0x2222_2222)),
            ReplyLatch::Accept(Some(first))
        );
        assert_eq!(
            latch.admit(rebound, Some(0x2222_2222)),
            ReplyLatch::Reject,
            "a later SSRC is not the rebind key"
        );
        assert_eq!(
            latch.admit(rebound, Some(0x1111_1111)),
            ReplyLatch::Accept(Some(rebound)),
            "the first SSRC is"
        );
    }

    #[test]
    fn the_reply_latch_never_pins_on_rtcp_but_drops_it_from_a_new_source_once_latched() {
        let first = address("127.0.0.2:5000");
        let other = address("127.0.0.9:5000");
        let mut latch = SymmetricLatch::default();
        assert_eq!(
            latch.admit(other, None),
            ReplyLatch::Accept(None),
            "RTCP before any RTP aims nothing"
        );
        assert_eq!(
            latch.admit(first, Some(0x1111_1111)),
            ReplyLatch::Accept(Some(first)),
            "so the first RTP still latches"
        );
        assert_eq!(
            latch.admit(other, None),
            ReplyLatch::Reject,
            "and a datagram with no SSRC cannot come from anywhere else once it has"
        );
        assert_eq!(latch.admit(first, None), ReplyLatch::Accept(Some(first)));
    }

    #[test]
    fn the_opaque_latch_learns_once_and_never_moves() {
        // A T.38 stream carries no SSRC, so nothing can ever prove a new source is the same stream.
        // The first datagram pins the source and every later one is dropped.
        let fax = address("127.0.0.2:5004");
        let attacker = address("127.0.0.9:5004");
        let mut latch = OpaqueLatch::default();
        assert_eq!(latch.admit(fax), ReplyLatch::Accept(Some(fax)));
        assert_eq!(latch.latched(), Some(fax));
        assert_eq!(
            latch.admit(fax),
            ReplyLatch::Accept(Some(fax)),
            "same source"
        );
        assert_eq!(
            latch.admit(attacker),
            ReplyLatch::Reject,
            "a spray from another source cannot take the stream"
        );
        assert_eq!(latch.latched(), Some(fax), "and cannot move the latch");
        // Even the real peer coming back on a new port is refused: a mid-stream rebind is
        // indistinguishable from a hijack without an SSRC, so the fax stops rather than follows.
        assert_eq!(latch.admit(address("127.0.0.2:5006")), ReplyLatch::Reject);
    }

    #[test]
    fn the_opaque_latch_is_a_gate_where_the_symmetric_one_would_not_be() {
        // The reason `OpaqueLatch` exists at all. `SymmetricLatch` never stores an SSRC-less learn,
        // so on a stream that never carries an SSRC it accepts every source forever — which under
        // the opt-in `symmetric` flag (`SourceFilter::Any`) is the only constraint there is.
        let first = address("127.0.0.2:5004");
        let other = address("127.0.0.9:5004");
        let mut symmetric = SymmetricLatch::default();
        assert_eq!(symmetric.admit(first, None), ReplyLatch::Accept(None));
        assert_eq!(
            symmetric.admit(other, None),
            ReplyLatch::Accept(None),
            "an SSRC-less stream never pins the symmetric latch"
        );

        let mut opaque = OpaqueLatch::default();
        assert_eq!(opaque.admit(first), ReplyLatch::Accept(Some(first)));
        assert_eq!(opaque.admit(other), ReplyLatch::Reject);
    }
}
