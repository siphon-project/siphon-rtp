//! Counters of the built-in TURN server, for the host's metrics exposition.
//!
//! Plain atomics (relaxed, no locks): the allocation actor bumps them on its own task and any
//! other task reads them at scrape time. Nothing here allocates or blocks, so counting a relayed
//! packet costs one atomic add.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::TransportProtocol;

/// Which way a relayed payload went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayDirection {
    /// From the TURN client toward the peer (Send indication, ChannelData).
    ClientToPeer,
    /// From the peer toward the TURN client (Data indication, ChannelData).
    PeerToClient,
}

impl RelayDirection {
    /// Both directions, in the order [`TurnMetricsSnapshot`] reports them.
    pub const ALL: [RelayDirection; 2] =
        [RelayDirection::ClientToPeer, RelayDirection::PeerToClient];

    /// The metric label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            RelayDirection::ClientToPeer => "client_to_peer",
            RelayDirection::PeerToClient => "peer_to_client",
        }
    }

    const fn index(self) -> usize {
        match self {
            RelayDirection::ClientToPeer => 0,
            RelayDirection::PeerToClient => 1,
        }
    }
}

/// Why the server refused a request or dropped a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    /// 401 Unauthorized: no credentials, or an integrity check that failed (RFC 8656 §7.2). The
    /// first request of every long-term-credential exchange is answered this way by design
    /// (RFC 5389 §10.2), so one successful allocation counts one.
    Unauthorized,
    /// 438 Stale Nonce (RFC 8656 §7.2).
    StaleNonce,
    /// 486 Allocation Quota Reached (RFC 8656 §7.2).
    Quota,
    /// 403 Forbidden for a peer the denylist refuses (RFC 8656 §9.2, §11.2, §21), and every relayed
    /// packet dropped for the same reason.
    PeerDenied,
}

impl RefusalReason {
    /// Every reason, in the order [`TurnMetricsSnapshot`] reports them.
    pub const ALL: [RefusalReason; 4] = [
        RefusalReason::Unauthorized,
        RefusalReason::StaleNonce,
        RefusalReason::Quota,
        RefusalReason::PeerDenied,
    ];

    /// The metric label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            RefusalReason::Unauthorized => "unauthorized",
            RefusalReason::StaleNonce => "stale_nonce",
            RefusalReason::Quota => "quota",
            RefusalReason::PeerDenied => "peer_denied",
        }
    }

    const fn index(self) -> usize {
        match self {
            RefusalReason::Unauthorized => 0,
            RefusalReason::StaleNonce => 1,
            RefusalReason::Quota => 2,
            RefusalReason::PeerDenied => 3,
        }
    }
}

impl TransportProtocol {
    /// Every client transport, in the order [`TurnMetricsSnapshot`] reports them.
    pub const ALL: [TransportProtocol; 3] = [
        TransportProtocol::Udp,
        TransportProtocol::Tcp,
        TransportProtocol::Tls,
    ];

    /// The metric label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            TransportProtocol::Udp => "udp",
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Tls => "tls",
        }
    }

    const fn index(self) -> usize {
        match self {
            TransportProtocol::Udp => 0,
            TransportProtocol::Tcp => 1,
            TransportProtocol::Tls => 2,
        }
    }
}

/// The live counters. Shared by `Arc` between the allocation actor (the only writer) and whoever
/// renders them.
#[derive(Debug, Default)]
pub struct TurnMetrics {
    allocations: [AtomicU64; 3],
    relayed_bytes: [AtomicU64; 2],
    refused: [AtomicU64; 4],
}

impl TurnMetrics {
    /// An allocation was created over `transport`.
    pub(crate) fn allocation_opened(&self, transport: TransportProtocol) {
        self.allocations[transport.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// An allocation over `transport` ended (deleted, refreshed to zero, or expired).
    pub(crate) fn allocation_closed(&self, transport: TransportProtocol) {
        // Saturating: a close can never take the gauge below zero. A compare-exchange loop rather
        // than `fetch_update`, which newer toolchains deprecate under a name the MSRV lacks.
        let counter = &self.allocations[transport.index()];
        let mut live = counter.load(Ordering::Relaxed);
        while live > 0 {
            match counter.compare_exchange_weak(
                live,
                live - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => live = actual,
            }
        }
    }

    /// `bytes` of payload were relayed in `direction`.
    pub(crate) fn relayed(&self, direction: RelayDirection, bytes: usize) {
        self.relayed_bytes[direction.index()].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// A request was refused, or a packet dropped, for `reason`.
    pub(crate) fn refused(&self, reason: RefusalReason) {
        self.refused[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// A point-in-time read of every counter.
    #[must_use]
    pub fn snapshot(&self) -> TurnMetricsSnapshot {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        TurnMetricsSnapshot {
            allocations: [
                read(&self.allocations[0]),
                read(&self.allocations[1]),
                read(&self.allocations[2]),
            ],
            relayed_bytes: [read(&self.relayed_bytes[0]), read(&self.relayed_bytes[1])],
            refused: [
                read(&self.refused[0]),
                read(&self.refused[1]),
                read(&self.refused[2]),
                read(&self.refused[3]),
            ],
        }
    }
}

/// A point-in-time read of [`TurnMetrics`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TurnMetricsSnapshot {
    allocations: [u64; 3],
    relayed_bytes: [u64; 2],
    refused: [u64; 4],
}

impl TurnMetricsSnapshot {
    /// Live allocations whose client reached the server over `transport`.
    #[must_use]
    pub fn allocations(&self, transport: TransportProtocol) -> u64 {
        self.allocations[transport.index()]
    }

    /// Payload bytes relayed in `direction` since start.
    #[must_use]
    pub fn relayed_bytes(&self, direction: RelayDirection) -> u64 {
        self.relayed_bytes[direction.index()]
    }

    /// Requests refused and packets dropped for `reason` since start.
    #[must_use]
    pub fn refused(&self, reason: RefusalReason) -> u64 {
        self.refused[reason.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allocation_gauge_is_per_transport_and_never_goes_below_zero() {
        let metrics = TurnMetrics::default();
        metrics.allocation_opened(TransportProtocol::Udp);
        metrics.allocation_opened(TransportProtocol::Udp);
        metrics.allocation_opened(TransportProtocol::Tls);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.allocations(TransportProtocol::Udp), 2);
        assert_eq!(snapshot.allocations(TransportProtocol::Tcp), 0);
        assert_eq!(snapshot.allocations(TransportProtocol::Tls), 1);
        metrics.allocation_closed(TransportProtocol::Udp);
        metrics.allocation_closed(TransportProtocol::Tcp);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.allocations(TransportProtocol::Udp), 1);
        assert_eq!(snapshot.allocations(TransportProtocol::Tcp), 0, "saturates");
    }

    #[test]
    fn bytes_and_refusals_count_by_label() {
        let metrics = TurnMetrics::default();
        metrics.relayed(RelayDirection::ClientToPeer, 160);
        metrics.relayed(RelayDirection::ClientToPeer, 40);
        metrics.relayed(RelayDirection::PeerToClient, 7);
        metrics.refused(RefusalReason::Quota);
        metrics.refused(RefusalReason::PeerDenied);
        metrics.refused(RefusalReason::PeerDenied);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.relayed_bytes(RelayDirection::ClientToPeer), 200);
        assert_eq!(snapshot.relayed_bytes(RelayDirection::PeerToClient), 7);
        assert_eq!(snapshot.refused(RefusalReason::Quota), 1);
        assert_eq!(snapshot.refused(RefusalReason::PeerDenied), 2);
        assert_eq!(snapshot.refused(RefusalReason::Unauthorized), 0);
        assert_eq!(snapshot.refused(RefusalReason::StaleNonce), 0);
    }

    #[test]
    fn labels_are_the_documented_values_and_all_lists_are_complete() {
        let transports: Vec<_> = TransportProtocol::ALL.iter().map(|t| t.label()).collect();
        assert_eq!(transports, ["udp", "tcp", "tls"]);
        let directions: Vec<_> = RelayDirection::ALL.iter().map(|d| d.label()).collect();
        assert_eq!(directions, ["client_to_peer", "peer_to_client"]);
        let reasons: Vec<_> = RefusalReason::ALL.iter().map(|r| r.label()).collect();
        assert_eq!(
            reasons,
            ["unauthorized", "stale_nonce", "quota", "peer_denied"]
        );
        // Every index is distinct and in range, so no two labels share a counter.
        for (position, transport) in TransportProtocol::ALL.iter().enumerate() {
            assert_eq!(transport.index(), position);
        }
        for (position, direction) in RelayDirection::ALL.iter().enumerate() {
            assert_eq!(direction.index(), position);
        }
        for (position, reason) in RefusalReason::ALL.iter().enumerate() {
            assert_eq!(reason.index(), position);
        }
    }
}
