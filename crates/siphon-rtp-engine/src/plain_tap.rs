//! The consumers of one crypto-bridge endpoint's plaintext RTP.
//!
//! A crypto bridge relays without decoding, so anything that wants a bridged call's audio — a
//! WebSocket tee, a decoded recording — takes a copy of the plaintext the bridge holds between its
//! two transforms and decodes it in a task of its own. Several can want it at once (a recorded call
//! that is also being transcribed), so an endpoint carries a *set* of taps keyed by the consumer's
//! own tag, and attaching or detaching one never disturbs another.

use std::sync::Arc;

/// Where a tap's copies go. Bounded by its owner: the bridge never waits on a consumer.
pub type PlainTapSender = flume::Sender<bytes::Bytes>;

/// One endpoint's plaintext taps.
///
/// The bridge snapshots its flow on every datagram, so this clones as one reference-count bump
/// (or nothing at all on an untapped endpoint) rather than a `Vec` copy. Mutation happens only on
/// the control path and rebuilds the list.
#[derive(Clone, Default)]
pub struct PlainTaps(Option<Arc<[(String, PlainTapSender)]>>);

impl PlainTaps {
    /// Add the tap labelled `tag`, replacing one already carrying that tag.
    pub fn add(&mut self, tag: &str, tap: PlainTapSender) {
        let mut taps = self.without(tag);
        taps.push((tag.to_string(), tap));
        self.0 = Some(taps.into());
    }

    /// Remove the tap labelled `tag`, leaving every other one in place. Idempotent.
    pub fn remove(&mut self, tag: &str) {
        let taps = self.without(tag);
        self.0 = (!taps.is_empty()).then(|| taps.into());
    }

    /// Every tap but the one labelled `tag`.
    fn without(&self, tag: &str) -> Vec<(String, PlainTapSender)> {
        self.0
            .iter()
            .flat_map(|taps| taps.iter())
            .filter(|(existing, _)| existing != tag)
            .cloned()
            .collect()
    }

    /// Whether no consumer is attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// Offer one accepted plaintext RTP datagram to every tap: copied once, shared between them.
    /// A tap that has fallen behind loses the datagram rather than delaying the relay — late audio
    /// is worthless.
    pub fn offer(&self, plaintext: &[u8]) {
        let Some(taps) = &self.0 else {
            return;
        };
        let copy = bytes::Bytes::copy_from_slice(plaintext);
        for (_, tap) in taps.iter() {
            let _ = tap.try_send(copy.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untapped_endpoint_offers_to_nobody() {
        let taps = PlainTaps::default();
        assert!(taps.is_empty());
        taps.offer(&[0x80, 0x00]);
    }

    #[test]
    fn every_tap_receives_each_datagram() {
        let mut taps = PlainTaps::default();
        let (tee, tee_received) = flume::bounded(4);
        let (recording, recording_received) = flume::bounded(4);
        taps.add("tee-1", tee);
        taps.add("rec-1", recording);
        taps.offer(&[0x80, 0x00, 0x01]);
        assert_eq!(
            tee_received.try_recv().expect("tee copy").as_ref(),
            [0x80, 0x00, 0x01]
        );
        assert_eq!(
            recording_received
                .try_recv()
                .expect("recording copy")
                .as_ref(),
            [0x80, 0x00, 0x01]
        );
    }

    #[test]
    fn removing_one_tap_leaves_the_other_attached() {
        let mut taps = PlainTaps::default();
        let (tee, tee_received) = flume::bounded(4);
        let (recording, recording_received) = flume::bounded(4);
        taps.add("tee-1", tee);
        taps.add("rec-1", recording);
        taps.remove("tee-1");
        taps.offer(&[0x80]);
        assert!(
            tee_received.try_recv().is_err(),
            "the removed tap hears nothing"
        );
        assert!(recording_received.try_recv().is_ok());
        assert!(!taps.is_empty());
        taps.remove("rec-1");
        assert!(taps.is_empty());
        taps.remove("rec-1");
        assert!(taps.is_empty(), "removing an absent tap is a no-op");
    }

    #[test]
    fn adding_a_tag_twice_replaces_the_earlier_tap() {
        let mut taps = PlainTaps::default();
        let (first, first_received) = flume::bounded(4);
        let (second, second_received) = flume::bounded(4);
        taps.add("tee-1", first);
        taps.add("tee-1", second);
        taps.offer(&[0x80]);
        assert!(first_received.try_recv().is_err());
        assert!(second_received.try_recv().is_ok());
    }

    #[test]
    fn a_full_tap_drops_the_datagram_without_starving_the_others() {
        let mut taps = PlainTaps::default();
        let (stalled, stalled_received) = flume::bounded(1);
        let (healthy, healthy_received) = flume::bounded(4);
        taps.add("stalled", stalled);
        taps.add("healthy", healthy);
        taps.offer(&[0x01]);
        taps.offer(&[0x02]);
        assert_eq!(stalled_received.len(), 1, "bounded: the second was dropped");
        assert_eq!(healthy_received.len(), 2);
    }

    #[test]
    fn a_snapshot_keeps_delivering_after_the_tap_is_removed_from_the_flow() {
        // The bridge clones the set out of the map before it works on a datagram; a detach racing
        // that datagram must not panic or lose the copy already in flight.
        let mut taps = PlainTaps::default();
        let (tap, received) = flume::bounded(4);
        taps.add("rec-1", tap);
        let snapshot = taps.clone();
        taps.remove("rec-1");
        snapshot.offer(&[0x80]);
        assert!(received.try_recv().is_ok());
    }
}
