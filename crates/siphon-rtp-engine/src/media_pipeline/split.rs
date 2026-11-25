//! The actor's half of the **split bridge**: isolating the two parties from each other and playing
//! each of them the audio a bot sends back for it.
//!
//! While a split is attached each direction of the call is *isolated*: it still decodes what its
//! party says, which feeds the uplink forks, the recordings, the interception taps and the DTMF
//! detector exactly as before, but nothing it decodes is re-encoded toward the other party. What the
//! party hears instead is rendered on the actor's 20 ms playout tick ([`Direction::tick_split`]): one
//! chunk from its playout queue ([`PlayoutReader`]), or silence when the queue is empty, encoded in
//! the codec the leg negotiated and sent on the egress stream the direction already runs, so the
//! sequence numbers, timestamps and SRTP index carry on without a seam. The tick is the clock, so the
//! two directions never wait on each other and a queue the bot leaves empty is silence, not a stall.
//!
//! A direction is isolated **before** it is fed: [`MediaRegistry::mark_split`] makes
//! [`MediaRegistry::register`] start every actor registered for the call isolated and silent, so an
//! actor built mid-split (a re-offer, a promotion) never lets one party's audio reach the other in the
//! moment before its playout queues are attached.

use siphon_rtp_dsp::resample::Resampler;
use siphon_rtp_dsp::NoiseSuppressor;
use siphon_rtp_media::bridge::split::PlayoutReader;
use siphon_rtp_media::bridge::wire_resampler;

use super::{
    Direction, MediaCall, MediaControl, MediaInput, MediaRegistry, Outbound, MAX_FRAME_SAMPLES,
};

/// What a [`MediaControl::SplitAttach`](super::MediaControl::SplitAttach) hands the actor: the playout
/// queue of each party and the wire rate their chunks are at.
pub struct SplitAttach {
    /// The queue played to the offerer (leg A): what the bot sends on channel 0.
    pub toward_a: PlayoutReader,
    /// The queue played to the answerer (leg B): what the bot sends on channel 1.
    pub toward_b: PlayoutReader,
    /// The L16 rate of the queued chunks, in Hz.
    pub wire_rate_hz: u32,
    /// Whether to suppress noise on the offerer's uplink, and on the answerer's.
    pub noise_suppression: [bool; 2],
    /// The split's generation: shared with the engine, read before any control lifts the isolation.
    pub epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// One direction's split state. Present means the direction is isolated.
pub(super) struct SplitEgress {
    /// The party's playout queue; `None` until [`SplitAttach`] arrives, when it plays silence.
    reader: Option<PlayoutReader>,
    /// Wire rate to egress rate; `None` when they are equal.
    resampler: Option<Resampler>,
    /// Scratch the tick renders into: one chunk at the egress rate. Allocated once.
    pcm: Vec<i16>,
    /// A noise suppressor this attach added to the direction's ingress (so a detach removes it).
    added_noise_suppressor: bool,
    /// The generation this isolation belongs to (see [`MediaControl::SplitDetach`]).
    epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Scratch for converting what the direction decoded into the rate its egress taps expect.
    tap_pcm: Vec<i16>,
}

impl SplitEgress {
    fn isolated(epoch: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
        Self {
            epoch,
            reader: None,
            resampler: None,
            pcm: Vec::with_capacity(MAX_FRAME_SAMPLES),
            added_noise_suppressor: false,
            tap_pcm: Vec::with_capacity(MAX_FRAME_SAMPLES),
        }
    }
}

/// How long a control that changes what a call's parties hear may take to reach and be applied by its
/// actor: past it the caller is told it is not known to have been, and keeps its own state.
pub const CONTROL_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// What a [`MediaControl::SplitDetach`] did, as the actor answers it in the same step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachOutcome {
    /// The isolation was lifted by this control.
    Lifted,
    /// The call was not isolated: an earlier detach had already been applied.
    AlreadyOpen,
    /// The control was issued under an earlier generation and was ignored; the isolation stands.
    Stale,
}

/// Why a control could not be confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfirmError {
    /// The call has no media actor.
    #[error("the call has no media actor")]
    NoActor,
    /// The actor's mailbox stayed full, or the actor did not apply the controls, within
    /// [`CONTROL_CONFIRM_TIMEOUT`].
    #[error("the media actor did not confirm within {} ms", CONTROL_CONFIRM_TIMEOUT.as_millis())]
    TimedOut,
    /// The actor stopped while the controls were on their way.
    #[error("the media actor stopped")]
    Gone,
}

impl MediaRegistry {
    /// Mark `call_id` as carrying a split bridge: every actor registered for it from now on starts
    /// isolated. Cleared by [`Self::unmark_split`].
    pub fn mark_split(&self, call_id: &str) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.split_calls
            .entry(call_id.to_string())
            .or_default()
            .clone()
    }

    /// The generation of the split marked on `call_id`, shared with the actors that carry it.
    #[must_use]
    pub fn split_epoch(
        &self,
        call_id: &str,
    ) -> Option<std::sync::Arc<std::sync::atomic::AtomicU64>> {
        self.split_calls.get(call_id).map(|epoch| epoch.clone())
    }

    /// Start a new generation of `call_id`'s split: a control issued under an earlier one that an
    /// actor applies late is ignored. Called whenever a control that lifts isolation could not be
    /// confirmed, so it cannot take effect after the caller has been told it failed.
    pub fn bump_split_epoch(&self, call_id: &str) {
        if let Some(epoch) = self.split_calls.get(call_id) {
            epoch.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Clear [`Self::mark_split`].
    pub fn unmark_split(&self, call_id: &str) {
        self.split_calls.remove(call_id);
    }

    /// How many calls are marked as carrying a split bridge (zero once every split is gone).
    #[must_use]
    pub fn split_marked_count(&self) -> usize {
        self.split_calls.len()
    }

    /// Whether `call_id` is marked as carrying a split bridge.
    #[must_use]
    pub fn is_split_marked(&self, call_id: &str) -> bool {
        self.split_calls.contains_key(call_id)
    }

    /// Ask a call's actor to take a split off ([`MediaControl::SplitDetach`]) under the generation it is
    /// at now, and return what it did. The check and the un-isolation are one step in the actor and it
    /// answers on the control itself, so there is no gap between "applied" and "confirmed" for a
    /// barrier to lose: a timeout means the answer was not heard, not that nothing happened, and a
    /// retry asks again ([`DetachOutcome::AlreadyOpen`] says it had).
    pub async fn split_detach(
        &self,
        call_id: &str,
        tag: &str,
    ) -> Result<DetachOutcome, ConfirmError> {
        let mailbox = self
            .calls
            .get(call_id)
            .map(|handle| handle.mailbox.clone())
            .ok_or(ConfirmError::NoActor)?;
        let epoch = self
            .split_epoch(call_id)
            .map_or(0, |epoch| epoch.load(std::sync::atomic::Ordering::Acquire));
        let (reply, answered) = tokio::sync::oneshot::channel();
        let control = MediaControl::SplitDetach {
            epoch,
            tag: tag.to_string(),
            reply: Some(reply),
        };
        let delivery = async {
            mailbox
                .send_async(MediaInput::Control(control))
                .await
                .map_err(|_| ConfirmError::Gone)?;
            answered.await.map_err(|_| ConfirmError::Gone)
        };
        tokio::time::timeout(CONTROL_CONFIRM_TIMEOUT, delivery)
            .await
            .map_err(|_| ConfirmError::TimedOut)?
    }

    /// Send `controls` to a call's actor and return once it has **applied** them, in order.
    ///
    /// [`MediaRegistry::control`] is `try_send` into a mailbox the call's packets share, so under
    /// packet pressure it can lose a control, and for one that changes who hears whom that is not an
    /// option. This waits for room (bounded), then for a [`MediaControl::Barrier`] queued behind them,
    /// which the actor answers only after everything before it. On `Err` the controls may have been
    /// applied in part; the caller treats the state as unknown and tries again.
    pub async fn control_confirmed(
        &self,
        call_id: &str,
        controls: Vec<MediaControl>,
    ) -> Result<(), ConfirmError> {
        // The guard is dropped before anything is awaited.
        let mailbox = self
            .calls
            .get(call_id)
            .map(|handle| handle.mailbox.clone())
            .ok_or(ConfirmError::NoActor)?;
        let (reply, applied) = tokio::sync::oneshot::channel();
        let delivery = async {
            for control in controls {
                mailbox
                    .send_async(MediaInput::Control(control))
                    .await
                    .map_err(|_| ConfirmError::Gone)?;
            }
            mailbox
                .send_async(MediaInput::Control(MediaControl::Barrier { reply }))
                .await
                .map_err(|_| ConfirmError::Gone)?;
            applied.await.map_err(|_| ConfirmError::Gone)
        };
        tokio::time::timeout(CONTROL_CONFIRM_TIMEOUT, delivery)
            .await
            .map_err(|_| ConfirmError::TimedOut)?
    }
}

#[cfg(test)]
impl MediaRegistry {
    /// Test double of an actor that has stopped reading: swap `call_id`'s mailbox for one with room for
    /// a single more control and nobody draining it. Returns the real mailbox, for [`Self::unwedge_mailbox`], and the receiver that
    /// keeps the stand-in open.
    pub(crate) fn wedge_mailbox(
        &self,
        call_id: &str,
    ) -> Option<(flume::Sender<MediaInput>, flume::Receiver<MediaInput>)> {
        let mut handle = self.calls.get_mut(call_id)?;
        let (stalled, unread) = flume::bounded(2);
        stalled
            .try_send(MediaInput::Control(MediaControl::Silence(false)))
            .ok()?;
        Some((std::mem::replace(&mut handle.mailbox, stalled), unread))
    }

    /// [`Self::wedge_mailbox`] with room for everything a teardown may send: nothing is read, and
    /// nothing is refused, so a test can see which controls were sent.
    pub(crate) fn wedge_mailbox_unbounded(
        &self,
        call_id: &str,
    ) -> Option<(flume::Sender<MediaInput>, flume::Receiver<MediaInput>)> {
        let mut handle = self.calls.get_mut(call_id)?;
        let (stalled, unread) = flume::unbounded();
        Some((std::mem::replace(&mut handle.mailbox, stalled), unread))
    }

    /// Put back the mailbox [`Self::wedge_mailbox`] took out.
    pub(crate) fn unwedge_mailbox(&self, call_id: &str, mailbox: flume::Sender<MediaInput>) {
        if let Some(mut handle) = self.calls.get_mut(call_id) {
            handle.mailbox = mailbox;
        }
    }
}

impl Direction {
    /// Isolate this direction: nothing it decodes is sent toward the other party from here on, and the
    /// party it faces hears silence until a playout queue is attached. A relay-only direction forwards
    /// verbatim and cannot be isolated; the engine promotes a split call to a processing actor first.
    fn isolate(&mut self, epoch: std::sync::Arc<std::sync::atomic::AtomicU64>) {
        if self.relay_only {
            tracing::error!(
                target: "siphon_rtp::media",
                "a relay-only direction cannot be isolated for a split; its audio still crosses"
            );
            return;
        }
        if self.split.is_none() {
            self.split = Some(Box::new(SplitEgress::isolated(epoch)));
        }
        // Whatever of the other party's audio is still waiting to be framed must not go out.
        self.repacketizer.clear();
        self.pending_marker = false;
    }

    /// Play `reader`'s chunks (at `wire_rate_hz`) to the party this direction's egress faces.
    fn attach_playout(
        &mut self,
        reader: PlayoutReader,
        wire_rate_hz: u32,
        epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) {
        self.isolate(epoch);
        let egress_rate = self.egress_sample_rate;
        let resampler = match wire_resampler(wire_rate_hz, egress_rate) {
            Ok(resampler) => resampler,
            Err(error) => {
                tracing::error!(
                    target: "siphon_rtp::media",
                    %error,
                    wire_rate_hz,
                    egress_rate,
                    "split playout cannot be converted to the leg's rate; the party hears silence"
                );
                return;
            }
        };
        if let Some(split) = self.split.as_mut() {
            split.reader = Some(reader);
            split.resampler = resampler;
        }
    }

    /// Suppress noise on this direction's decoded ingress, which is the uplink the bot receives.
    fn enable_uplink_noise_suppression(&mut self) {
        if self.noise_suppressor.is_some() {
            return;
        }
        match NoiseSuppressor::new(self.decoder.params().sample_rate_hz) {
            Ok(suppressor) => {
                self.noise_suppressor = Some(suppressor);
                if let Some(split) = self.split.as_mut() {
                    split.added_noise_suppressor = true;
                }
            }
            Err(error) => tracing::warn!(
                target: "siphon_rtp::media",
                %error,
                "uplink noise suppression is not available at this leg's rate"
            ),
        }
    }

    /// Whether this direction is isolated under generation `issued`.
    fn split_is_current(&self, issued: u64) -> bool {
        self.split
            .as_ref()
            .is_some_and(|split| split.epoch.load(std::sync::atomic::Ordering::Acquire) == issued)
    }

    /// End the isolation: this direction carries its party's audio to the other again.
    fn end_split(&mut self) {
        if let Some(split) = self.split.take() {
            if split.added_noise_suppressor {
                self.noise_suppressor = None;
            }
            self.repacketizer.clear();
        }
    }

    /// Keep an egress tap meaning what it meant before the split. A tap on a party's egress records
    /// what the other party said as the party would have heard it (a `both` recording of a two-party
    /// call takes its second channel there), so while the split plays the party the bot instead, the
    /// tap is fed what this direction decoded, converted to the egress rate as the direct path would
    /// have done. A recording thereby keeps the parties' own voices, never the bot's.
    pub(super) fn feed_split_taps(&mut self, decoded: &[i16]) {
        if self.egress_taps.is_empty() {
            return;
        }
        let Some(mut split) = self.split.take() else {
            return;
        };
        let mut converted = std::mem::take(&mut split.tap_pcm);
        converted.clear();
        let frame: &[i16] = match self.resampler.as_mut() {
            Some(resampler) => {
                resampler.process(decoded, &mut converted);
                &converted
            }
            None => decoded,
        };
        for tap in &mut self.egress_taps {
            tap.write_pcm(frame);
        }
        split.tap_pcm = converted;
        self.split = Some(split);
    }

    /// One playout tick of an isolated direction: a chunk of the party's playout queue, or silence,
    /// rendered at the egress rate and sent as however many egress frames it makes. A blocked
    /// direction sends nothing; a silenced one (`silence_media`) sends silence whatever is queued.
    pub(super) fn tick_split(&mut self, out: &mut Vec<Outbound>) {
        if self.blocked {
            return;
        }
        let Some(mut split) = self.split.take() else {
            return;
        };
        let mut pcm = std::mem::take(&mut split.pcm);
        pcm.clear();
        if let Some(reader) = split.reader.as_ref() {
            if let Some(chunk) = reader.pop() {
                if !self.silenced {
                    match split.resampler.as_mut() {
                        Some(resampler) => resampler.process(&chunk, &mut pcm),
                        None => pcm.extend_from_slice(&chunk),
                    }
                }
                reader.recycle(chunk);
            }
        }
        if pcm.is_empty() {
            // Nothing queued for this party: a 20 ms frame of digital silence keeps its stream going.
            let silence = self.egress_sample_rate as usize / 1000 * 20;
            pcm.resize(silence.min(MAX_FRAME_SAMPLES), 0);
        }
        // The isolation is back in place before the frame is sent, so the egress it is sent on knows
        // the call is split: that is what delivers the frame to an interception as what the party
        // hears (media_pipeline/x3_split.rs).
        self.split = Some(split);
        // What the bot sends is not what an egress tap records (see `feed_split_taps`).
        let taps = std::mem::take(&mut self.egress_taps);
        self.repacketize(&pcm, false, out);
        self.egress_taps = taps;
        if let Some(split) = self.split.as_mut() {
            split.pcm = pcm;
        }
    }
}

impl MediaCall {
    /// Attach a split's playout queues ([`MediaControl::SplitAttach`](super::MediaControl)): isolate
    /// both directions and play each party its own queue. `toward_a` is the direction whose egress
    /// faces A (`b_to_a`); an uplink option applies to the direction that decodes the party.
    pub fn attach_split(&mut self, attach: SplitAttach) {
        let SplitAttach {
            toward_a,
            toward_b,
            wire_rate_hz,
            noise_suppression,
            epoch,
        } = attach;
        self.b_to_a
            .attach_playout(toward_a, wire_rate_hz, epoch.clone());
        self.a_to_b.attach_playout(toward_b, wire_rate_hz, epoch);
        if noise_suppression[0] {
            self.a_to_b.enable_uplink_noise_suppression();
        }
        if noise_suppression[1] {
            self.b_to_a.enable_uplink_noise_suppression();
        }
    }

    /// Start a call isolated and silent: what [`MediaRegistry::register`](super::MediaRegistry) does
    /// to an actor registered for a call with a split on it.
    pub fn begin_split(&mut self, epoch: std::sync::Arc<std::sync::atomic::AtomicU64>) {
        self.a_to_b.isolate(epoch.clone());
        self.b_to_a.isolate(epoch);
    }

    /// End the split ([`MediaControl::SplitDetach`](super::MediaControl)): take the split's forks
    /// (`tag`) off and let both directions carry their party's audio to the other again, on the
    /// egress streams they were already sending, **only** if the isolation is still the generation
    /// `issued` names. A detach the engine gave up on bumped the generation before it reported
    /// failure, so applying it late would reconnect two parties its controller was told were still
    /// isolated; it is ignored. A call that is not isolated at all has nothing to lift.
    pub fn end_split(&mut self, issued: u64, tag: &str) -> DetachOutcome {
        if !self.is_split() {
            // Already open (a detach that was applied and then not heard, or never needed): the forks
            // still come off, and the engine finishes its side.
            self.remove_forks_tagged(true, tag);
            self.remove_forks_tagged(false, tag);
            return DetachOutcome::AlreadyOpen;
        }
        if !(self.a_to_b.split_is_current(issued) || self.b_to_a.split_is_current(issued)) {
            tracing::warn!(
                target: "siphon_rtp::media",
                call_id = %self.call_id,
                issued,
                "a stale split detach was ignored: the split has moved on since it was issued"
            );
            return DetachOutcome::Stale;
        }
        self.remove_forks_tagged(true, tag);
        self.remove_forks_tagged(false, tag);
        self.a_to_b.end_split();
        self.b_to_a.end_split();
        DetachOutcome::Lifted
    }

    /// Whether either direction is isolated for a split.
    #[must_use]
    pub fn is_split(&self) -> bool {
        self.a_to_b.split.is_some() || self.b_to_a.split.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::ulaw_alaw_call;
    use super::super::CallHandle;
    use super::*;
    use siphon_rtp_media::bridge::split::playout;

    fn epoch() -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::default()
    }

    fn interleaved(left: i16, right: i16, frames: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..frames {
            bytes.extend_from_slice(&left.to_le_bytes());
            bytes.extend_from_slice(&right.to_le_bytes());
        }
        bytes
    }

    fn attach(call: &mut MediaCall, rate: u32) -> siphon_rtp_media::bridge::PlayoutWriter {
        let (writer, [first, second]) = playout(rate);
        call.attach_split(SplitAttach {
            toward_a: first,
            toward_b: second,
            wire_rate_hz: rate,
            noise_suppression: [false, false],
            epoch: epoch(),
        });
        writer
    }

    #[test]
    fn a_call_begun_isolated_plays_silence_to_both_parties() {
        let mut call = ulaw_alaw_call();
        call.begin_split(epoch());
        assert!(call.is_split());
        let mut out = Vec::new();
        call.a_to_b.tick_split(&mut out);
        call.b_to_a.tick_split(&mut out);
        assert_eq!(out.len(), 2, "one egress frame per direction, per tick");
    }

    #[test]
    fn each_party_is_played_its_own_channel() {
        let mut call = ulaw_alaw_call();
        let mut writer = attach(&mut call, 8_000);
        writer.push_wire(&interleaved(8_000, -8_000, 160));
        let (mut toward_b, mut toward_a) = (Vec::new(), Vec::new());
        call.a_to_b.tick_split(&mut toward_b);
        call.b_to_a.tick_split(&mut toward_a);
        assert_eq!(toward_b.len(), 1);
        assert_eq!(toward_a.len(), 1);
        // µ-law: positive samples have the top bit set, negative ones do not.
        let b_payload = toward_b[0].data[12];
        let a_payload = toward_a[0].data[12];
        assert_ne!(
            b_payload & 0x80,
            a_payload & 0x80,
            "opposite signs on the two channels"
        );
        assert_ne!(toward_b[0].endpoint, toward_a[0].endpoint);
    }

    #[test]
    fn an_empty_queue_is_silence_and_the_stream_keeps_numbering() {
        let mut call = ulaw_alaw_call();
        let mut writer = attach(&mut call, 8_000);
        writer.push_wire(&interleaved(9_000, 9_000, 160));
        let mut out = Vec::new();
        for _ in 0..3 {
            call.a_to_b.tick_split(&mut out);
        }
        assert_eq!(out.len(), 3, "the tick is the clock: a frame every tick");
        let sequences: Vec<u16> = out
            .iter()
            .map(|packet| u16::from_be_bytes([packet.data[2], packet.data[3]]))
            .collect();
        assert_eq!(sequences[1], sequences[0].wrapping_add(1));
        assert_eq!(sequences[2], sequences[1].wrapping_add(1));
        assert!(
            out[1].data[12..]
                .iter()
                .all(|byte| *byte == out[2].data[12]),
            "the frames after the queued one are flat silence"
        );
    }

    #[test]
    fn a_blocked_direction_sends_nothing() {
        let mut call = ulaw_alaw_call();
        call.begin_split(epoch());
        call.set_blocked(true);
        let mut out = Vec::new();
        call.a_to_b.tick_split(&mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn a_wider_wire_rate_is_converted_to_the_leg_rate() {
        let mut call = ulaw_alaw_call();
        let mut writer = attach(&mut call, 16_000);
        writer.push_wire(&interleaved(5_000, 5_000, 320));
        let mut out = Vec::new();
        call.a_to_b.tick_split(&mut out);
        call.a_to_b.tick_split(&mut out);
        assert!(!out.is_empty());
        assert_eq!(out[0].data.len(), 12 + 160, "20 ms of 8 kHz G.711");
    }

    #[test]
    fn ending_the_split_ends_the_isolation() {
        let mut call = ulaw_alaw_call();
        let _writer = attach(&mut call, 8_000);
        assert!(call.is_split());
        call.end_split(0, "split");
        assert!(!call.is_split());
        let mut out = Vec::new();
        call.a_to_b.tick_split(&mut out);
        assert!(
            out.is_empty(),
            "a direction that is not split plays nothing"
        );
    }

    /// A detach issued under an earlier generation, applied late, does not reconnect the parties.
    #[test]
    fn a_stale_detach_is_ignored_and_the_current_one_lifts_the_isolation() {
        let mut call = ulaw_alaw_call();
        let generation = epoch();
        call.begin_split(generation.clone());
        let issued = generation.load(std::sync::atomic::Ordering::Acquire);
        // The sender gave up on it and moved the generation on.
        generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        assert_eq!(call.end_split(issued, "split"), DetachOutcome::Stale);
        assert!(call.is_split(), "the stale detach changed nothing");
        let current = generation.load(std::sync::atomic::Ordering::Acquire);
        call.end_split(current, "split");
        assert!(
            !call.is_split(),
            "the retry under the new generation lifts it"
        );
    }

    #[test]
    fn uplink_noise_suppression_is_added_for_the_split_and_removed_with_it() {
        let mut call = ulaw_alaw_call();
        let (_writer, [first, second]) = playout(8_000);
        call.attach_split(SplitAttach {
            toward_a: first,
            toward_b: second,
            wire_rate_hz: 8_000,
            noise_suppression: [true, false],
            epoch: epoch(),
        });
        assert!(call.a_to_b.noise_suppressor.is_some());
        assert!(call.b_to_a.noise_suppressor.is_none());
        call.end_split(0, "split");
        assert!(call.a_to_b.noise_suppressor.is_none());
    }

    fn registry_with_mailbox(capacity: usize) -> (MediaRegistry, flume::Receiver<MediaInput>) {
        let registry = MediaRegistry::default();
        let (mailbox, inbox) = flume::bounded(capacity);
        registry.calls.insert(
            "stub".to_string(),
            CallHandle {
                mailbox,
                endpoints: [
                    siphon_rtp_datapath::EndpointId(1),
                    siphon_rtp_datapath::EndpointId(2),
                ],
                rtcp_endpoints: Vec::new(),
                task: tokio::spawn(std::future::pending::<()>()),
                relay_only: false,
                secure_leg: None,
                near_secure_leg: None,
            },
        );
        (registry, inbox)
    }

    #[tokio::test(start_paused = true)]
    async fn a_control_to_a_full_mailbox_that_is_never_drained_is_reported_not_dropped() {
        let (registry, _unread) = registry_with_mailbox(1);
        assert!(registry.control("stub", MediaControl::Silence(false)));
        assert!(
            !registry.control(
                "stub",
                MediaControl::SplitDetach {
                    epoch: 0,
                    tag: String::new(),
                    reply: None,
                }
            ),
            "try_send loses a control into a full mailbox"
        );
        let outcome = registry
            .control_confirmed(
                "stub",
                vec![MediaControl::SplitDetach {
                    epoch: 0,
                    tag: String::new(),
                    reply: None,
                }],
            )
            .await;
        assert_eq!(outcome, Err(super::ConfirmError::TimedOut));
    }

    #[tokio::test(start_paused = true)]
    async fn a_confirmed_control_waits_for_room_and_returns_once_the_actor_applied_it() {
        let (registry, inbox) = registry_with_mailbox(1);
        assert!(registry.control("stub", MediaControl::Silence(false)));
        let actor = tokio::spawn(async move {
            // Slow to start reading, then applies everything in order, as the real actor does.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let mut applied = Vec::new();
            while let Ok(MediaInput::Control(control)) = inbox.recv_async().await {
                match control {
                    MediaControl::Barrier { reply } => {
                        let _ = reply.send(());
                        break;
                    }
                    MediaControl::SplitDetach { .. } => applied.push("detach"),
                    MediaControl::Silence(_) => applied.push("silence"),
                    _ => applied.push("other"),
                }
            }
            applied
        });
        let outcome = registry
            .control_confirmed(
                "stub",
                vec![MediaControl::SplitDetach {
                    epoch: 0,
                    tag: String::new(),
                    reply: None,
                }],
            )
            .await;
        assert_eq!(outcome, Ok(()));
        assert_eq!(actor.await.expect("actor"), vec!["silence", "detach"]);
    }

    #[tokio::test]
    async fn a_confirmed_control_to_no_actor_or_a_gone_one_is_an_error() {
        let registry = MediaRegistry::default();
        assert_eq!(
            registry.control_confirmed("nobody", Vec::new()).await,
            Err(super::ConfirmError::NoActor)
        );
        let (registry, inbox) = registry_with_mailbox(4);
        drop(inbox);
        assert_eq!(
            registry
                .control_confirmed(
                    "stub",
                    vec![MediaControl::SplitDetach {
                        epoch: 0,
                        tag: String::new(),
                        reply: None,
                    }]
                )
                .await,
            Err(super::ConfirmError::Gone)
        );
    }
}
