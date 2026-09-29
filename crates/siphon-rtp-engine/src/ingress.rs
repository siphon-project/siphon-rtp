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
}

impl Refusal {
    const fn bit(self) -> u8 {
        match self {
            Self::UnsignalledSource => 1,
            Self::NewSource => 2,
            Self::NotAuthenticated => 4,
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
        let what = match refusal {
            Refusal::UnsignalledSource => {
                "refused media from a source the SDP did not signal; the direction stays dropped \
                 until the peer sends from the signalled address (a NATed peer that signals its \
                 private address needs the symmetric flag)"
            }
            Refusal::NewSource => {
                "refused media from a new source that could not prove it is the latched stream"
            }
            Refusal::NotAuthenticated => {
                "refused media that failed SRTP authentication; the peer's key does not match the \
                 negotiated one"
            }
        };
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
