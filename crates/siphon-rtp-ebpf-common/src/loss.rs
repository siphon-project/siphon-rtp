//! Pure RFC 3550 §A.1-style forward-gap RTP loss estimate, shared by the XDP kernel fast path and the
//! UDP-loopback backend. `no_std`, allocation-free, branch-only — safe on the per-packet hot path.

/// Sentinel `last_rtp_seq` meaning "no RTP sequence observed yet on this flow".
pub const RTP_SEQ_NONE: u64 = u64::MAX;
/// Largest forward step still treated as in-stream (RFC 3550 §A.1 MAX_DROPOUT); a larger forward jump
/// is a discontinuity (SSRC restart / huge burst) and resyncs the baseline rather than counting loss.
const MAX_DROPOUT: u16 = 3000;
/// Backward window still treated as a reorder / late packet (RFC 3550 §A.1 MAX_MISORDER), not loss.
const MAX_MISORDER: u16 = 100;

/// Fold one accepted RTP media packet's 16-bit sequence into a flow's forward-gap loss estimate.
/// `last` is the previously observed sequence, `RTP_SEQ_NONE` before the first packet. Returns
/// `(updated_last, loss_delta)` — the number of packets to ADD to the cumulative loss counter:
/// - first packet (`last == RTP_SEQ_NONE`): establish baseline, loss 0, updated_last = seq.
/// - forward step in `1..MAX_DROPOUT`: `step - 1` missed → loss `step-1`, updated_last = seq.
/// - step == 0 (duplicate of last): loss 0, updated_last = last (no advance).
/// - backward step within MAX_MISORDER (wrapping step in `(u16::MAX - MAX_MISORDER)..=u16::MAX`):
///   reorder / late → loss 0, updated_last = last (keep the higher sequence).
/// - otherwise (large discontinuity): resync baseline, loss 0, updated_last = seq.
///
/// 16-bit wraparound handled via `wrapping_sub`. This is a fast-path ESTIMATE: it may over-count under
/// heavy reordering (a later in-window arrival does not reclaim an already-counted gap); the exact
/// expected-minus-received model runs on the userspace transcode path (`IngressStats`).
#[inline(always)]
#[must_use]
pub fn rtp_loss_update(last: u64, seq: u16) -> (u64, u64) {
    if last == RTP_SEQ_NONE {
        return (seq as u64, 0);
    }
    let last_seq = last as u16;
    let step = seq.wrapping_sub(last_seq);
    if step == 0 {
        (last, 0)
    } else if step < MAX_DROPOUT {
        (seq as u64, (step - 1) as u64)
    } else if step > u16::MAX - MAX_MISORDER {
        (last, 0)
    } else {
        (seq as u64, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_establishes_the_baseline_with_no_loss() {
        assert_eq!(rtp_loss_update(RTP_SEQ_NONE, 100), (100, 0));
    }

    #[test]
    fn in_order_step_counts_no_loss() {
        assert_eq!(rtp_loss_update(100, 101), (101, 0));
    }

    #[test]
    fn forward_gap_counts_the_missed_packets() {
        // 101, 102, 103 never arrived — three packets lost.
        assert_eq!(rtp_loss_update(100, 104), (104, 3));
    }

    #[test]
    fn duplicate_of_last_counts_no_loss_and_does_not_advance() {
        assert_eq!(rtp_loss_update(100, 100), (100, 0));
    }

    #[test]
    fn reorder_within_window_counts_no_loss_and_keeps_the_higher_sequence() {
        assert_eq!(rtp_loss_update(100, 98), (100, 0));
    }

    #[test]
    fn wraparound_in_order_counts_no_loss() {
        assert_eq!(rtp_loss_update(65535, 0), (0, 0));
    }

    #[test]
    fn wraparound_forward_gap_counts_across_the_16_bit_boundary() {
        // 65534 -> 1 crosses the wrap: 65535 and 0 are the two missed sequences.
        assert_eq!(rtp_loss_update(65534, 1), (1, 2));
    }

    #[test]
    fn large_discontinuity_resyncs_the_baseline_with_no_loss() {
        assert_eq!(rtp_loss_update(100, 40000), (40000, 0));
    }

    #[test]
    fn edge_of_the_dropout_window_still_counts_loss() {
        // step == MAX_DROPOUT - 1 (2999) is the last forward step counted as in-stream loss.
        assert_eq!(rtp_loss_update(0, 2999), (2999, 2998));
        // step == MAX_DROPOUT (3000) is a discontinuity — resync, no loss.
        assert_eq!(rtp_loss_update(0, 3000), (3000, 0));
    }

    #[test]
    fn edge_of_the_misorder_window_counts_no_loss() {
        // step == u16::MAX - MAX_MISORDER + 1 (i.e. a backward step of MAX_MISORDER, 100): reorder.
        assert_eq!(rtp_loss_update(100, 100u16.wrapping_sub(100)), (100, 0));
        // A backward step of MAX_MISORDER + 1 (101) falls out of the reorder window — resync.
        assert_eq!(
            rtp_loss_update(200, 200u16.wrapping_sub(101)),
            (200u16.wrapping_sub(101) as u64, 0)
        );
    }
}
