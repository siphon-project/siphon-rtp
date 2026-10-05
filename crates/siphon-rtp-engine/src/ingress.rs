//! What a userspace `Redirect` consumer did with one datagram, and what the datapath is told about it.
//!
//! The datapath counts a redirected datagram as received and hands it on; the `Forward` fast path
//! counts its own drops, but a `Redirect` consumer decides admission itself (docs/security-and-nat.md
//! §4), so a refusal there is invisible unless the consumer reports it. Every consumer — the media
//! pipeline, the SRTP and DTLS bridges, the conference, the text and fax relays, the WebSocket
//! takeover — reports through [`Ingress::record`], so `packets_dropped` means the same thing on every
//! path, and logs through `RefusalLog`, so the first refusal of each kind on a flow is a `warn` that
//! names both addresses rather than a `debug` nobody sees.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};

use siphon_rtp_datapath::{Datapath, EndpointId, SourceFilter};

/// The outcome of one redirected datagram, and the two per-endpoint counters it drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    /// Admitted: stamps the endpoint's liveness for the idle sweep.
    Accepted,
    /// Dropped, but after the source gate admitted it: a failed SRTP authentication, or a DTLS leg
    /// the handshake has not keyed yet. Counted as dropped. It still stamps liveness, because the
    /// source is the signalled peer and a transient rekey or reorder must not reap a live call — the
    /// posture the media and text pipelines took before these drops were counted, kept as it was.
    DroppedFromPeer,
    /// Refused outright — an unsignalled source, a latch rejection, an unowned endpoint. Counted as
    /// dropped, and never liveness: a spoofed spray must not hold an idle call open.
    Refused,
}

impl Ingress {
    /// Whether the datagram is evidence the flow is alive (stamps the idle sweep's `last_seen`).
    #[must_use]
    pub fn is_live(self) -> bool {
        !matches!(self, Self::Refused)
    }

    /// Whether the datagram was dropped rather than admitted (counts in `packets_dropped`).
    #[must_use]
    pub fn is_dropped(self) -> bool {
        !matches!(self, Self::Accepted)
    }

    /// Report this outcome for `endpoint` to `datapath`.
    pub fn record<D: Datapath + ?Sized>(self, datapath: &D, endpoint: EndpointId) {
        if self.is_live() {
            datapath.note_activity(endpoint);
        }
        if self.is_dropped() {
            datapath.note_dropped(endpoint);
        }
    }
}

/// Why a consumer refused a datagram, for [`RefusalLog`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The source is not the one the SDP signalled (docs/security-and-nat.md §4 layer 2).
    UnsignalledSource,
    /// A new source that could not prove it is the latched stream (§4 layer 3).
    NewSource,
    /// The datagram failed SRTP authentication or replay protection (RFC 3711 §3.3).
    NotAuthenticated,
    /// The datagram is not SRTP at all: too short to hold a header and an authentication tag, or
    /// not RTP version 2 (RFC 3550 §5.1). A NAT keepalive on the media port is the usual one. It
    /// says nothing about the peer's key, so it is kept apart from [`Self::NotAuthenticated`] — a
    /// keepalive that arrives first must not use up the one warning a real key mismatch gets.
    NotSrtp,
    /// The datagram's MKI is not the one the peer's `a=crypto` signalled (RFC 3711 §3.3 step 1).
    UnknownMki,
}

impl Refusal {
    const fn bit(self) -> u8 {
        match self {
            Self::UnsignalledSource => 1,
            Self::NewSource => 2,
            Self::NotAuthenticated => 4,
            Self::NotSrtp => 8,
            Self::UnknownMki => 16,
        }
    }

    /// The refusal an SRTP `unprotect` failure amounts to. `None` for a replay, which is routine
    /// (a duplicated datagram) and never worth a warning.
    pub(crate) const fn of_unprotect(error: &siphon_rtp_srtp::SrtpError) -> Option<Self> {
        use siphon_rtp_srtp::SrtpError;
        match error {
            SrtpError::Replayed => None,
            SrtpError::TooShort | SrtpError::BadVersion => Some(Self::NotSrtp),
            SrtpError::UnknownMki => Some(Self::UnknownMki),
            SrtpError::AuthFailed => Some(Self::NotAuthenticated),
        }
    }

    /// What this refusal means for the call, for the one `warn` it gets per flow.
    const fn explanation(self) -> &'static str {
        match self {
            Self::UnsignalledSource => {
                "refused media from a source the SDP did not signal; the direction stays dropped \
                 until the peer sends from the signalled address (a NATed peer that signals its \
                 private address needs the symmetric flag)"
            }
            Self::NewSource => {
                "refused media from a new source that could not prove it is the latched stream"
            }
            Self::NotAuthenticated => {
                "refused media that failed SRTP authentication; the peer is not sending under \
                 the key its a=crypto carried in this negotiation, so this direction is dropped"
            }
            Self::NotSrtp => {
                "dropped a datagram that is not SRTP (too short for a header and tag, or not RTP \
                 version 2), typically a NAT keepalive on the media port; it says nothing about \
                 the peer's key"
            }
            Self::UnknownMki => {
                "refused SRTP whose MKI is not the one the peer's a=crypto signalled; this \
                 direction is dropped"
            }
        }
    }
}

/// Logs the first refusal of each [`Refusal`] kind on one flow at `warn` and the rest at `debug`, so a
/// direction that is silently dropping says so once — naming the address it expected and the one the
/// datagrams came from — without a hostile stream being able to flood the log.
///
/// Atomic so it can sit on state the bridges only ever read through a shared map guard. One per
/// ingress flow, rebuilt with the flow, so a renegotiation that re-gates the flow warns afresh.
#[derive(Debug, Default)]
pub(crate) struct RefusalLog {
    warned: AtomicU8,
}

impl Clone for RefusalLog {
    fn clone(&self) -> Self {
        Self {
            warned: AtomicU8::new(self.warned.load(Ordering::Relaxed)),
        }
    }
}

/// Where a refusal happened, for the log line.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RefusalContext<'a> {
    /// The consumer, e.g. `"media-pipeline"`.
    pub(crate) component: &'static str,
    /// The call (or conference) the flow belongs to.
    pub(crate) call_id: &'a str,
    pub(crate) endpoint: EndpointId,
    /// Where the refused datagram came from.
    pub(crate) source: SocketAddr,
    /// The flow's signalled-source gate.
    pub(crate) expected: SourceFilter,
}

impl RefusalLog {
    /// Whether this is the flow's first `refusal` of its kind, marking it seen.
    pub(crate) fn first(&self, refusal: Refusal) -> bool {
        // A plain load first: after the first refusal every later one is on this branch, and a flood
        // of refused datagrams must stay cheap to refuse. The locked read-modify-write only runs the
        // first time, where it also settles a race between two threads to the one warning.
        if self.warned.load(Ordering::Relaxed) & refusal.bit() != 0 {
            return false;
        }
        self.warned.fetch_or(refusal.bit(), Ordering::Relaxed) & refusal.bit() == 0
    }

    /// Log one refusal: `warn` the first time this kind is seen on the flow, `debug` after that.
    pub(crate) fn log(&self, refusal: Refusal, context: RefusalContext<'_>) {
        let RefusalContext {
            component,
            call_id,
            endpoint,
            source,
            expected,
        } = context;
        if !self.first(refusal) {
            tracing::debug!(
                target: "siphon_rtp::media",
                component,
                call_id,
                ?endpoint,
                %source,
                ?refusal,
                "redirected datagram refused"
            );
            return;
        }
        let what = refusal.explanation();
        tracing::warn!(
            target: "siphon_rtp::media",
            component,
            call_id,
            ?endpoint,
            %source,
            ?expected,
            "{what} (counted in packets_dropped, logged once per flow)"
        );
    }

    /// Log a datagram from the signalled peer that SRTP `unprotect` refused.
    ///
    /// Each *reason* gets its own first `warn` on the flow, carrying what tells one cause from
    /// another without a capture: the datagram's size, and the SSRC and sequence number its header
    /// carries in the clear. One shared warning for every reason hid the reason that mattered: a
    /// four-byte keepalive logged `packet too short` and every authentication failure after it
    /// went to `debug`.
    pub(crate) fn log_undecryptable(
        &self,
        error: &siphon_rtp_srtp::SrtpError,
        datagram: &[u8],
        party: &'static str,
        context: RefusalContext<'_>,
    ) {
        let RefusalContext {
            component,
            call_id,
            endpoint,
            source,
            ..
        } = context;
        let refusal = Refusal::of_unprotect(error);
        if !refusal.is_some_and(|refusal| self.first(refusal)) {
            tracing::debug!(
                target: "siphon_rtp::media",
                component,
                call_id,
                ?endpoint,
                %source,
                party,
                %error,
                "datagram from the secure peer dropped"
            );
            return;
        }
        // RFC 3550 §5.1: both sit in the fixed header, which SRTP leaves in the clear.
        let header = (datagram.len() >= 12 && datagram[0] >> 6 == 2).then(|| {
            (
                u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]),
                u16::from_be_bytes([datagram[2], datagram[3]]),
            )
        });
        let what = refusal.map_or("", Refusal::explanation);
        tracing::warn!(
            target: "siphon_rtp::media",
            component,
            call_id,
            ?endpoint,
            %source,
            party,
            %error,
            bytes = datagram.len(),
            ssrc = ?header.map(|(ssrc, _)| ssrc),
            sequence = ?header.map(|(_, sequence)| sequence),
            "{what} (counted in packets_dropped, logged once per reason per flow)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn each_refusal_kind_warns_once_per_flow() {
        let log = RefusalLog::default();
        assert!(log.first(Refusal::UnsignalledSource));
        assert!(!log.first(Refusal::UnsignalledSource));
        assert!(
            log.first(Refusal::NewSource),
            "another kind still gets its own first warning"
        );
        assert!(log.first(Refusal::NotAuthenticated));
        assert!(!log.first(Refusal::NewSource));
        assert!(!log.first(Refusal::NotAuthenticated));
    }

    fn context() -> RefusalContext<'static> {
        RefusalContext {
            component: "test",
            call_id: "call",
            endpoint: EndpointId(1),
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 4000),
            expected: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        }
    }

    #[test]
    fn a_keepalive_does_not_use_up_the_warning_a_key_mismatch_gets() {
        // A phone's NAT keepalive reaches the media port ahead of its audio. It is too short to
        // be SRTP, and it used to take the flow's only decrypt warning, so the authentication
        // failure on every packet after it was logged at `debug` and never seen.
        use siphon_rtp_srtp::SrtpError;
        let log = RefusalLog::default();
        log.log_undecryptable(&SrtpError::TooShort, &[0u8; 4], "far", context());
        assert!(!log.first(Refusal::NotSrtp), "the keepalive was reported");
        assert!(
            log.first(Refusal::NotAuthenticated),
            "and the key mismatch still has its own first warning"
        );
    }

    #[test]
    fn each_unprotect_failure_is_reported_as_what_it_is() {
        use siphon_rtp_srtp::SrtpError;
        assert_eq!(
            Refusal::of_unprotect(&SrtpError::TooShort),
            Some(Refusal::NotSrtp)
        );
        assert_eq!(
            Refusal::of_unprotect(&SrtpError::BadVersion),
            Some(Refusal::NotSrtp)
        );
        assert_eq!(
            Refusal::of_unprotect(&SrtpError::AuthFailed),
            Some(Refusal::NotAuthenticated)
        );
        assert_eq!(
            Refusal::of_unprotect(&SrtpError::UnknownMki),
            Some(Refusal::UnknownMki)
        );
        assert_eq!(Refusal::of_unprotect(&SrtpError::Replayed), None);
    }

    #[test]
    fn a_replay_is_never_a_warning_and_uses_up_none() {
        use siphon_rtp_srtp::SrtpError;
        let log = RefusalLog::default();
        log.log_undecryptable(&SrtpError::Replayed, &[0x80; 182], "far", context());
        for refusal in [
            Refusal::NotAuthenticated,
            Refusal::NotSrtp,
            Refusal::UnknownMki,
        ] {
            assert!(log.first(refusal));
        }
    }

    #[test]
    fn every_reason_warns_once_and_a_short_datagram_is_read_safely() {
        use siphon_rtp_srtp::SrtpError;
        let log = RefusalLog::default();
        for datagram in [&[][..], &[0x80; 11], &[0x80; 12], &[0x00; 40]] {
            log.log_undecryptable(&SrtpError::AuthFailed, datagram, "near", context());
            log.log_undecryptable(&SrtpError::UnknownMki, datagram, "near", context());
        }
        assert!(!log.first(Refusal::NotAuthenticated));
        assert!(!log.first(Refusal::UnknownMki));
        assert!(log.first(Refusal::NotSrtp));
    }

    #[test]
    fn the_bit_of_each_refusal_is_its_own() {
        let all = [
            Refusal::UnsignalledSource,
            Refusal::NewSource,
            Refusal::NotAuthenticated,
            Refusal::NotSrtp,
            Refusal::UnknownMki,
        ];
        let combined = all.iter().fold(0u8, |bits, refusal| bits | refusal.bit());
        assert_eq!(combined.count_ones() as usize, all.len());
    }

    #[test]
    fn a_cloned_log_keeps_what_it_has_already_warned_about() {
        let log = RefusalLog::default();
        assert!(log.first(Refusal::UnsignalledSource));
        let cloned = log.clone();
        assert!(!cloned.first(Refusal::UnsignalledSource));
        assert!(cloned.first(Refusal::NewSource));
    }

    #[test]
    fn logging_a_refusal_marks_it_seen() {
        let log = RefusalLog::default();
        let context = RefusalContext {
            component: "test",
            call_id: "call",
            endpoint: EndpointId(1),
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 4000),
            expected: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
        };
        log.log(Refusal::UnsignalledSource, context);
        assert!(!log.first(Refusal::UnsignalledSource));
    }

    #[tokio::test]
    async fn each_outcome_drives_exactly_its_counters() {
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        let dropped = |datapath: &UdpLoopbackDatapath| {
            datapath.stats(endpoint.id).expect("stats").packets_dropped
        };

        let before = datapath.last_activity(endpoint.id);
        Ingress::Refused.record(&datapath, endpoint.id);
        assert_eq!(dropped(&datapath), 1);
        assert_eq!(
            datapath.last_activity(endpoint.id),
            before,
            "a refusal is never liveness"
        );

        Ingress::DroppedFromPeer.record(&datapath, endpoint.id);
        assert_eq!(dropped(&datapath), 2);

        Ingress::Accepted.record(&datapath, endpoint.id);
        assert_eq!(dropped(&datapath), 2, "an accepted datagram is not a drop");
    }
}
