//! Which speech mode the encoder sends next: the negotiated mode set, the peer's codec mode
//! requests, and the restrictions on when and how far the mode may move.
//!
//! The rules, all from the negotiation (RFC 4867 §8.1) and the request in each received payload
//! (§4.3.1):
//!
//! - **`mode-set`**: "frames encoded with modes outside of the subset MUST NOT be sent".
//! - **Default mode**: 3GPP TS 26.114 §7.5.2.1.2.1, "the highest codec mode of the negotiated
//!   mode-set (or of all modes, if no mode-set was included in the SDP answer) should be used,
//!   unless it is restricted by the most recently received CMR". A preferred mode below that caps it.
//! - **CMR**: TS 26.114 §7.5.2.1.2.2, a sender "shall not use higher modes in media-encoding than
//!   indicated by the most recently received CMR". A request for a mode outside the mode set "MUST
//!   be ignored" (RFC 4867 §4.3.1), and so must one that is neither a speech mode nor 15.
//! - **`mode-change-period=2`**: mode changes only on every second frame.
//! - **`mode-change-neighbor=1`**: a change goes "to the neighboring modes in the active codec
//!   mode set", one step at a time.

use super::rtp::NO_MODE_REQUEST;

/// The mode decision for one encoder. Small and `Copy`: it rides on the codec state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeControl {
    /// The highest speech mode of the codec: 7 for AMR, 8 for AMR-WB.
    highest_mode: u8,
    /// The modes that may be sent, bit *i* for mode *i*. Never zero.
    allowed: u16,
    /// The mode asked for when nothing restricts it; `unrestricted` is where that lands in the set.
    preferred: u8,
    /// The mode used when nothing restricts it: the highest allowed one at or below the preference.
    unrestricted: u8,
    /// The most recent valid codec mode request, `None` while the peer asks for nothing.
    requested: Option<u8>,
    /// The mode of the frame sent last.
    current: u8,
    /// Frames between two mode changes: 1 or 2.
    change_period: u8,
    /// Whether a change may only reach the next mode of the set.
    neighbor_only: bool,
    /// Frames encoded so far, for the phase of a two-frame change period.
    frame_count: u8,
}

impl ModeControl {
    /// A decision over every mode up to `highest_mode`, preferring `preferred` (read as
    /// `highest_mode` when above it).
    #[must_use]
    pub fn unrestricted(highest_mode: u8, preferred: u8) -> Self {
        let highest_mode = highest_mode.min(8);
        let mut control = Self {
            highest_mode,
            allowed: (1u16 << (highest_mode + 1)) - 1,
            preferred: preferred.min(highest_mode),
            unrestricted: 0,
            requested: None,
            current: 0,
            change_period: 1,
            neighbor_only: false,
            frame_count: 0,
        };
        control.settle();
        control
    }

    /// A decision over `mode_set` (every mode up to `highest_mode` when empty), starting at the
    /// highest allowed mode at or below `preferred` (the highest of all when `None`).
    ///
    /// `None` when the mode set names a mode the codec does not have, or `preferred` is not a
    /// speech mode: neither is a stream this encoder can send.
    #[must_use]
    pub fn new(highest_mode: u8, mode_set: &[u8], preferred: Option<u8>) -> Option<Self> {
        let preferred = preferred.unwrap_or(highest_mode);
        if preferred > highest_mode || mode_set.iter().any(|&mode| mode > highest_mode) {
            return None;
        }
        Some(Self::unrestricted(highest_mode, preferred).restricted_to(mode_set))
    }

    /// The same decision restricted to `mode_set`; modes the codec does not have are skipped, and
    /// an empty set (or one with none of the codec's modes) allows every mode.
    #[must_use]
    pub fn restricted_to(mut self, mode_set: &[u8]) -> Self {
        let every_mode = (1u16 << (self.highest_mode + 1)) - 1;
        let allowed = mode_set
            .iter()
            .filter(|&&mode| mode <= self.highest_mode)
            .fold(0u16, |mask, &mode| mask | (1 << mode));
        self.allowed = if allowed == 0 { every_mode } else { allowed };
        self.settle();
        self
    }

    /// The same decision preferring `preferred` (read as the codec's highest mode when above it).
    #[must_use]
    pub fn preferring(mut self, preferred: u8) -> Self {
        self.preferred = preferred.min(self.highest_mode);
        self.settle();
        self
    }

    /// Start again from the unrestricted mode: where the preference lands in the mode set.
    fn settle(&mut self) {
        self.unrestricted = self.highest_allowed_up_to(self.preferred);
        self.current = self.unrestricted;
        self.requested = None;
    }

    /// Restrict mode changes to every `period` frames (RFC 4867 §8.1 `mode-change-period`, 1 or 2)
    /// and, with `neighbor_only`, to the next mode of the set (`mode-change-neighbor`).
    #[must_use]
    pub fn with_change_restrictions(mut self, period: u8, neighbor_only: bool) -> Self {
        self.change_period = period.clamp(1, 2);
        self.neighbor_only = neighbor_only;
        self
    }

    /// Whether `mode` is in the negotiated mode set.
    #[must_use]
    pub fn is_allowed(&self, mode: u8) -> bool {
        mode < 16 && self.allowed & (1 << mode) != 0
    }

    /// The highest allowed mode at or below `ceiling`, else the lowest allowed mode.
    fn highest_allowed_up_to(&self, ceiling: u8) -> u8 {
        (0..=ceiling.min(15))
            .rev()
            .find(|&mode| self.is_allowed(mode))
            .unwrap_or_else(|| self.allowed.trailing_zeros() as u8)
    }

    /// Take a codec mode request from a received payload.
    ///
    /// A speech mode of the mode set caps what is sent from now on; 15 lifts the cap. Anything
    /// else is ignored, and the previous request stays in force.
    pub fn request(&mut self, cmr: u8) {
        if cmr == NO_MODE_REQUEST {
            self.requested = None;
        } else if self.is_allowed(cmr) {
            self.requested = Some(cmr);
        }
    }

    /// The mode the encoder is heading for.
    #[must_use]
    pub fn target(&self) -> u8 {
        match self.requested {
            Some(requested) => self.highest_allowed_up_to(requested.min(self.unrestricted)),
            None => self.unrestricted,
        }
    }

    /// The mode of the frame sent last.
    #[must_use]
    pub fn current(&self) -> u8 {
        self.current
    }

    /// The mode for the next frame. Call once per frame encoded.
    pub fn next_frame_mode(&mut self) -> u8 {
        let target = self.target();
        // A two-frame period keeps one phase for the whole stream (RFC 4867 §4.5: the encoder
        // "may arbitrarily select the initial phase ... but then SHOULD stick to that phase").
        let may_change = self.frame_count.is_multiple_of(self.change_period);
        if may_change && target != self.current {
            self.current = if self.neighbor_only {
                self.neighbor_towards(target)
            } else {
                target
            };
        }
        self.frame_count = (self.frame_count + 1) % 2;
        self.current
    }

    /// The allowed mode next to the current one in the direction of `target`.
    fn neighbor_towards(&self, target: u8) -> u8 {
        let step = if target > self.current {
            (self.current + 1..=target).find(|&mode| self.is_allowed(mode))
        } else {
            (target..self.current)
                .rev()
                .find(|&mode| self.is_allowed(mode))
        };
        step.unwrap_or(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modes(control: &mut ModeControl, frames: usize) -> Vec<u8> {
        (0..frames).map(|_| control.next_frame_mode()).collect()
    }

    #[test]
    fn the_default_is_the_highest_mode_of_the_set() {
        assert_eq!(ModeControl::new(7, &[], None).map(|c| c.target()), Some(7));
        assert_eq!(ModeControl::new(8, &[], None).map(|c| c.target()), Some(8));
        assert_eq!(
            ModeControl::new(7, &[0, 2, 4, 7], None).map(|c| c.target()),
            Some(7)
        );
        assert_eq!(
            ModeControl::new(8, &[0, 1, 2], None).map(|c| c.target()),
            Some(2)
        );
        assert_eq!(
            ModeControl::new(7, &[2, 0], None).map(|c| c.target()),
            Some(2)
        );
    }

    #[test]
    fn a_preferred_mode_caps_the_default_inside_the_set() {
        // The highest allowed mode at or below the preference.
        assert_eq!(
            ModeControl::new(8, &[], Some(2)).map(|c| c.target()),
            Some(2)
        );
        assert_eq!(
            ModeControl::new(8, &[0, 1, 4, 8], Some(2)).map(|c| c.target()),
            Some(1)
        );
        // A preference below the whole set cannot be met: the lowest allowed mode is sent.
        assert_eq!(
            ModeControl::new(8, &[4, 5], Some(2)).map(|c| c.target()),
            Some(4)
        );
    }

    #[test]
    fn a_mode_set_or_preference_the_codec_does_not_have_is_refused() {
        assert_eq!(ModeControl::new(7, &[0, 8], None), None);
        assert_eq!(ModeControl::new(8, &[9], None), None);
        assert_eq!(ModeControl::new(7, &[], Some(8)), None);
    }

    #[test]
    fn a_request_caps_the_mode_and_fifteen_lifts_the_cap() {
        let mut control = ModeControl::new(7, &[0, 2, 4, 7], None).expect("control");
        assert_eq!(modes(&mut control, 2), [7, 7]);
        control.request(2);
        assert_eq!(modes(&mut control, 2), [2, 2]);
        // No new request: the last one stays in force.
        assert_eq!(modes(&mut control, 2), [2, 2]);
        control.request(NO_MODE_REQUEST);
        assert_eq!(modes(&mut control, 2), [7, 7]);
    }

    #[test]
    fn a_request_outside_the_mode_set_is_ignored() {
        // RFC 4867 §4.3.1: "If the received CMR value is outside the signalled subset of modes,
        // it MUST be ignored."
        let mut control = ModeControl::new(7, &[0, 2, 4, 7], None).expect("control");
        control.request(3);
        assert_eq!(control.next_frame_mode(), 7);
        control.request(2);
        control.request(5);
        assert_eq!(
            control.next_frame_mode(),
            2,
            "the earlier valid request stands"
        );
        // Neither a speech mode nor 15: "the CMR MUST be ignored by the receiver".
        for reserved in [8, 9, 12, 14] {
            control.request(reserved);
        }
        assert_eq!(control.next_frame_mode(), 2);
    }

    #[test]
    fn a_request_above_the_preferred_mode_does_not_raise_it() {
        let mut control = ModeControl::new(8, &[], Some(2)).expect("control");
        control.request(8);
        assert_eq!(control.next_frame_mode(), 2);
        control.request(0);
        assert_eq!(control.next_frame_mode(), 0);
    }

    #[test]
    fn a_two_frame_period_changes_mode_on_every_second_frame_only() {
        let mut control = ModeControl::new(7, &[0, 2, 4, 7], None)
            .expect("control")
            .with_change_restrictions(2, false);
        assert_eq!(modes(&mut control, 3), [7, 7, 7]);
        // Asked on an odd frame: the change waits for the next even one.
        control.request(0);
        assert_eq!(modes(&mut control, 3), [7, 0, 0]);
        control.request(4);
        assert_eq!(modes(&mut control, 2), [4, 4]);
        control.request(NO_MODE_REQUEST);
        assert_eq!(modes(&mut control, 2), [7, 7]);
    }

    #[test]
    fn neighbor_changes_walk_the_mode_set_one_step_at_a_time() {
        let mut control = ModeControl::new(7, &[0, 2, 4, 7], None)
            .expect("control")
            .with_change_restrictions(1, true);
        control.request(0);
        assert_eq!(modes(&mut control, 4), [4, 2, 0, 0]);
        control.request(NO_MODE_REQUEST);
        assert_eq!(modes(&mut control, 4), [2, 4, 7, 7]);
    }

    #[test]
    fn neighbor_changes_under_a_two_frame_period_step_every_second_frame() {
        // 3GPP TS 26.114 Table A.2.1: mode-set=0,2,4,7; mode-change-period=2;
        // mode-change-neighbor=1.
        let mut control = ModeControl::new(7, &[0, 2, 4, 7], None)
            .expect("control")
            .with_change_restrictions(2, true);
        control.request(0);
        assert_eq!(modes(&mut control, 8), [4, 4, 2, 2, 0, 0, 0, 0]);
    }

    proptest::proptest! {
        /// Whatever is requested, in whatever order, no frame leaves the mode set, and under the
        /// restrictions no change breaks them.
        #[test]
        fn no_request_sequence_leaves_the_mode_set_or_breaks_the_restrictions(
            mask in 1u16..512,
            period in 1u8..=2,
            neighbor_only: bool,
            requests in proptest::collection::vec(0u8..16, 1..64),
        ) {
            let mode_set: Vec<u8> = (0..9).filter(|mode| mask & (1 << mode) != 0).collect();
            let mut control = ModeControl::new(8, &mode_set, None)
                .expect("control")
                .with_change_restrictions(period, neighbor_only);
            let mut previous = control.current();
            for (frame, request) in requests.into_iter().enumerate() {
                control.request(request);
                let mode = control.next_frame_mode();
                proptest::prop_assert!(mode_set.contains(&mode));
                if mode != previous {
                    proptest::prop_assert_eq!(frame % usize::from(period), 0);
                    if neighbor_only {
                        let between = mode_set
                            .iter()
                            .filter(|&&other| other > mode.min(previous) && other < mode.max(previous))
                            .count();
                        proptest::prop_assert_eq!(between, 0);
                    }
                }
                previous = mode;
            }
        }
    }
}
