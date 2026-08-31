//! Turning a datapath receive-clock reading into the absolute time a delivery timestamp needs.
//!
//! Conditional attribute 9 (TS 103 221-2 V1.4.1 §5.3) is an **absolute** Unix time: seconds since
//! the epoch plus a nanosecond remainder. The engine's per-datagram arrival stamp is not that. It
//! is documented as "a relative timeline" — a *logical* clock on the loopback datapath and a
//! *monotonic* clock on XDP — so handing it through unchanged would deliver a since-boot counter
//! to the agency as the moment of interception.
//!
//! [`WallClockAnchor`] resolves it: read the wall clock **once** per delivery session, pair it with
//! the receive-clock reading of the same packet, and derive every later timestamp as
//! `anchor + (arrival - anchor_arrival)`. That keeps the precise inter-packet spacing the receive
//! clock is good at, anchors it to absolute time with a single syscall per session, and stays
//! deterministic under test because the anchor is injectable.
//!
//! The two clocks drift apart at the host's NTP correction rate, which is sub-millisecond over a
//! call. Re-anchoring mid-session is deliberately **not** done: it would let a wall-clock step
//! reorder delivered timestamps, and a monotonic spacing that is a millisecond stale is worth more
//! than one that can go backwards.

use std::time::{SystemTime, UNIX_EPOCH};

/// Nanoseconds in one second.
const NANOS_PER_SECOND: u128 = 1_000_000_000;
/// Nanoseconds in one microsecond — the datapath receive clock's unit.
const NANOS_PER_MICROSECOND: u128 = 1_000;

/// Pairs one wall-clock reading with the datapath receive-clock reading taken at the same instant,
/// so later receive-clock readings can be expressed as absolute time.
///
/// Cheap to copy; a delivery session holds one for its lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallClockAnchor {
    /// Wall-clock time at the anchor, as nanoseconds since the Unix epoch.
    wall_unix_nanos: u128,
    /// The datapath receive-clock reading at the anchor, in microseconds.
    arrival_micros: u64,
}

impl WallClockAnchor {
    /// Anchor an explicit wall-clock time to a receive-clock reading.
    ///
    /// This is the constructor tests use: passing a fixed `wall_unix_nanos` makes every derived
    /// timestamp exact, so the delivery path can be asserted byte-for-byte without a real clock.
    #[must_use]
    pub const fn new(wall_unix_nanos: u128, arrival_micros: u64) -> Self {
        Self {
            wall_unix_nanos,
            arrival_micros,
        }
    }

    /// Anchor the *current* wall clock to `arrival_micros`, the receive-clock reading of the packet
    /// being anchored on. Call once per delivery session, on its first packet.
    ///
    /// A system clock set before the Unix epoch yields an anchor of zero rather than panicking: an
    /// implausible timestamp is a better failure than a dropped intercept.
    #[must_use]
    pub fn anchored_now(arrival_micros: u64) -> Self {
        let wall_unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since_epoch| since_epoch.as_nanos());
        Self::new(wall_unix_nanos, arrival_micros)
    }

    /// The absolute time of a packet whose receive-clock reading is `arrival_micros`, as the
    /// `(Unix seconds, nanoseconds)` pair attribute 9 carries.
    ///
    /// A reading *earlier* than the anchor clamps to the anchor. The production receive clocks are
    /// monotonic so that cannot happen there; a rewound logical clock in a test would otherwise
    /// wrap into an absurd future time, which is a worse failure than a repeated timestamp.
    ///
    /// Seconds saturate at [`u32::MAX`] (the year 2106), the bound of the 4-byte field.
    #[must_use]
    pub fn timestamp(&self, arrival_micros: u64) -> (u32, u32) {
        let elapsed_micros = u128::from(arrival_micros.saturating_sub(self.arrival_micros));
        let wall_nanos = self
            .wall_unix_nanos
            .saturating_add(elapsed_micros.saturating_mul(NANOS_PER_MICROSECOND));
        let seconds = u32::try_from(wall_nanos / NANOS_PER_SECOND).unwrap_or(u32::MAX);
        // Bounded by NANOS_PER_SECOND, so it always fits.
        let nanoseconds = (wall_nanos % NANOS_PER_SECOND) as u32;
        (seconds, nanoseconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-08-31T12:00:00Z, as Unix seconds — a fixed, readable anchor for the tests below.
    const ANCHOR_SECONDS: u128 = 1_788_177_600;
    const ANCHOR_NANOS: u128 = ANCHOR_SECONDS * NANOS_PER_SECOND;

    #[test]
    fn resolves_the_anchor_packet_to_the_anchor_time() {
        let anchor = WallClockAnchor::new(ANCHOR_NANOS, 5_000_000);
        assert_eq!(anchor.timestamp(5_000_000), (ANCHOR_SECONDS as u32, 0));
    }

    #[test]
    fn advances_by_the_receive_clock_delta_not_by_the_wall_clock() {
        // The point of the anchor: inter-packet spacing comes from the receive clock, so a 20 ms
        // RTP cadence lands as exactly 20 ms of delivered timestamp regardless of what the host
        // clock did in between.
        let anchor = WallClockAnchor::new(ANCHOR_NANOS, 1_000_000);
        assert_eq!(
            anchor.timestamp(1_020_000),
            (ANCHOR_SECONDS as u32, 20_000_000)
        );
        assert_eq!(
            anchor.timestamp(1_040_000),
            (ANCHOR_SECONDS as u32, 40_000_000)
        );
    }

    #[test]
    fn carries_into_the_seconds_field() {
        let anchor = WallClockAnchor::new(ANCHOR_NANOS + 900_000_000, 0);
        // 0.9 s past the anchor second, plus 200 ms, rolls the second over.
        assert_eq!(
            anchor.timestamp(200_000),
            (ANCHOR_SECONDS as u32 + 1, 100_000_000)
        );
    }

    #[test]
    fn keeps_microsecond_resolution() {
        let anchor = WallClockAnchor::new(ANCHOR_NANOS, 0);
        assert_eq!(anchor.timestamp(1), (ANCHOR_SECONDS as u32, 1_000));
    }

    #[test]
    fn clamps_a_reading_earlier_than_the_anchor() {
        // A rewound logical clock must not wrap into the far future.
        let anchor = WallClockAnchor::new(ANCHOR_NANOS, 10_000_000);
        assert_eq!(anchor.timestamp(9_000_000), (ANCHOR_SECONDS as u32, 0));
    }

    #[test]
    fn saturates_rather_than_overflowing_the_four_byte_seconds_field() {
        let anchor = WallClockAnchor::new(u128::MAX - 1, 0);
        let (seconds, nanoseconds) = anchor.timestamp(u64::MAX);
        assert_eq!(seconds, u32::MAX);
        assert!(nanoseconds < 1_000_000_000);
    }

    #[test]
    fn anchored_now_reads_a_plausible_wall_clock() {
        let anchor = WallClockAnchor::anchored_now(0);
        let (seconds, nanoseconds) = anchor.timestamp(0);
        // Sometime after 2020-01-01 and before 2106 — enough to catch a monotonic since-boot
        // reading leaking through, which is the defect this type exists to prevent.
        assert!(
            seconds > 1_577_836_800,
            "wall clock must be absolute Unix time, got {seconds}"
        );
        assert!(nanoseconds < 1_000_000_000);
    }

    #[test]
    fn nanoseconds_always_stay_below_one_second() {
        let anchor = WallClockAnchor::new(ANCHOR_NANOS + 999_999_999, 0);
        for arrival in [0u64, 1, 999, 1_000, 1_000_000, 123_456_789] {
            let (_, nanoseconds) = anchor.timestamp(arrival);
            assert!(nanoseconds < 1_000_000_000, "arrival {arrival}");
        }
    }
}
