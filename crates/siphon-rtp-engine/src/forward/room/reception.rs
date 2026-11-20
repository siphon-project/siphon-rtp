//! What a seat receives, per stream (3GPP TS 24.581 §6.3.7: the receiver's Active SSRC List).
//!
//! A seat joins receiving everything. [`ForwardRoom::set_reception`] switches its audio and its
//! video off or on; the room actor applies it between two packets, so it takes effect on the next
//! one. Only what is *sent to* the seat is gated: its own media is still taken in (it may be the
//! source), and its control stream (the floor stream, the floor data channel, RTCP APP and the
//! reports) is never gated, because that is how a manual-reception client is told it was granted or
//! ended.

//! Reports to a seat whose stream is off follow RFC 3550 §6.4 like any other: see
//! [`SenderActivity`]. The seat's control stream is never gated, and the reception report block
//! about its own media (RFC 3550 §6.4.1) goes out in the RR as it does in an SR.

use super::{ForwardError, ForwardRoom};

/// Which streams a seat is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Reception {
    pub(super) audio: bool,
    pub(super) video: bool,
}

impl Default for Reception {
    /// A seat joins received.
    fn default() -> Self {
        Self {
            audio: true,
            video: true,
        }
    }
}

impl ForwardRoom {
    /// Switch what seat `tag` is sent: its audio (`audio`) and its video (`video`). Idempotent.
    ///
    /// # Errors
    /// [`ForwardError::UnknownTag`] for a tag no seat has.
    pub fn set_reception(
        &mut self,
        tag: &str,
        audio: bool,
        video: bool,
    ) -> Result<(), ForwardError> {
        let index = self
            .index_of(tag)
            .ok_or_else(|| ForwardError::UnknownTag(tag.to_string()))?;
        let seat = &mut self.seats[index];
        let before = seat.reception;
        seat.reception = Reception { audio, video };
        if audio && !before.audio {
            // Rebase as at a source switch: the next packet starts a new run on the seat's own
            // stream, its sequence number and timestamp carrying on (RFC 3550 §5.1).
            seat.translator.switch_source();
        }
        if video && !before.video {
            if let Some(stream) = seat.video.as_mut() {
                stream.switch_source();
            }
            // The late-joiner path: wait for a keyframe of the source, and ask it for one.
            self.start_receiver_on_keyframe(index);
        }
        Ok(())
    }
}

/// Whether the room is a *sender* of one egress stream, for choosing the report to send it.
///
/// RFC 3550 §6.4: "The sender report is sent if the site has sent any data packets during the interval
/// since issuing the last report or the previous one, otherwise the receiver report is sent." The
/// packet count at the last two reports is kept, so a stream the room stopped sending (a seat whose
/// reception is off, a room with no source) is reported with an SR for two more reports and with an RR
/// from then on (§6.4.2: the same reception blocks, no sender information).
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct SenderActivity {
    /// The stream's packet count at the last report, and at the one before it.
    at_last: u32,
    at_previous: u32,
}

impl SenderActivity {
    /// Note that a report is being issued with `packets_sent` data packets sent so far; `true` when
    /// it is an SR (a packet was sent since the previous report was issued, or the one before).
    pub(super) fn sending(&mut self, packets_sent: u32) -> bool {
        let sending = packets_sent != self.at_previous;
        self.at_previous = self.at_last;
        self.at_last = packets_sent;
        sending
    }
}
