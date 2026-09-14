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
}
