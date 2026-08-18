//! The conference **text mix bus** (RFC 9071 multiparty real-time text): each participant's RFC 4103
//! T.140 text in, one RFC 2198 RED packet per *other* participant out, each labelled with its
//! contributing source — pure, synchronous, allocation-free after construction.
//!
//! Where the audio [`crate::mixer::Mixer`] **sums** PCM (mixed-minus-self), text is never summed —
//! two people typing at once produce two separable streams, not one blended waveform. So this is a
//! **queue-drain-and-tag** model, a sibling to (not an extension of) the audio mixer:
//!
//! * Each participant has an inbound T.140 queue, fed the reassembled text increments from its leg
//!   ([`TextMixer::push_text`]).
//! * On a flush tick ([`TextMixer::flush`], ~300 ms — RFC 4103 §5.2 caps buffering at 300 ms) every
//!   source with pending text is distributed to **every other** participant (mix-minus-self, RFC 9071
//!   §4.2): one emitted packet per (receiver, source), carrying the source's identity in the RTP CSRC
//!   list so the receiver can separate and present each source (RFC 9071 §4.2 / RFC 3550 §5.1), and
//!   reusing RFC 2198 RED ([`crate::t140::RedBuilder`]) for redundancy.
//!
//! Source identification is the CSRC, exactly as RFC 9071 §4.2 specifies: the mixer re-originates one
//! RTP stream toward each receiver (its own SSRC/sequence, owned by the conference actor) and stamps
//! the *contributing* participant's stable identifier as CSRC 0. One source per packet keeps every
//! packet unambiguously attributable — the receiver de-interleaves the mixed stream by CSRC.
//!
//! ## Determinism & allocation
//! The RTP timestamp is a single logical 1000 Hz text clock (`flush_counter × flush_interval_ms`,
//! RFC 4103 §4.1 — T.140 timestamps are the millisecond sampling clock), shared by every egress
//! stream so all streams' timestamps and every RED offset stay mutually consistent; it is never
//! `Instant::now()`, so a room's text output is reproducible from its flush schedule alone. All
//! per-flush scratch (the emit list, the payload arena, the RED build buffer) lives on the mixer and
//! is reused, so a warm flush allocates nothing; the per-participant queues are bounded (drop-oldest
//! on overflow).

use crate::t140::{RedBuilder, RedGeneration};

/// The largest room the text mixer supports — matches the audio mixer's participant cap.
pub const MAX_TEXT_PARTICIPANTS: usize = 64;

/// Redundant generations carried per RED packet (RFC 4103 §4 recommends up to two prior generations).
pub const MAX_TEXT_REDUNDANCY: usize = 2;

/// The most buffered T.140 bytes a single participant queue holds between flushes (a burst past it
/// drops the oldest buffered bytes — drop-oldest policy). A flush turns the whole queue into one
/// generation; with [`MAX_TEXT_REDUNDANCY`] redundant copies the worst-case RED packet is
/// `MAX_TEXT_REDUNDANCY × (4 + this) + 1 + this` bytes, kept well under a 1500-byte MTU so a text
/// packet never IP-fragments (and each block stays under the RFC 2198 §3 1023-byte limit). Real-time
/// text is a few characters per 300 ms flush, so this is a generous safety bound, not a live limit.
pub const MAX_PENDING_TEXT_BYTES: usize = 300;

/// How the mixer formats — and labels — one participant's text stream. Held per seated participant and
/// used two ways: `source_id` is the CSRC stamped on this participant's text when it reaches others
/// (RFC 9071 §4.2, its identity as a *source*); `t140_payload_type` / `red_payload_type` are the
/// payload types the mixer uses when it sends text *to* this participant (its identity as a
/// *receiver* — RFC 3264 §6.1, a sender uses the payload type the receiver expects). The conference
/// sets `source_id` to the participant's synthesized text egress SSRC, a stable identifier the mixer
/// owns from the moment the seat is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextSourceConfig {
    /// The contributing-source identifier stamped as CSRC 0 when this participant's text reaches
    /// others (RFC 9071 §4.2). Stable for the life of the seat.
    pub source_id: u32,
    /// The T.140 payload type this participant expects to receive (`a=rtpmap:<pt> t140/1000`).
    pub t140_payload_type: u8,
    /// The RFC 2198 RED payload type this participant expects to receive (`a=rtpmap:<pt> red/1000`),
    /// or `None` if it did not offer redundancy — then it receives bare T.140 (RFC 4103 §4).
    pub red_payload_type: Option<u8>,
}

/// One prior transmitted generation of a source's text, kept for RFC 2198 redundancy. The `data`
/// buffer is reused across flushes (pre-sized to [`MAX_PENDING_TEXT_BYTES`]) so advancing the history
/// never allocates.
#[derive(Debug)]
struct Generation {
    /// The RTP timestamp this generation was transmitted with (the logical text clock at that flush).
    timestamp: u32,
    /// The generation's T.140 bytes.
    data: Vec<u8>,
}

/// One seated participant's text state: its receiving/labelling config (`None` for a participant with
/// no text leg — it neither sends nor receives text, but keeps the mixer index aligned with the
/// conference's participant vector), its pending inbound queue, and its transmitted-generation history.
#[derive(Debug)]
struct TextSource {
    /// `None` ⇒ this participant has no text leg (audio-only): skipped as both source and receiver.
    config: Option<TextSourceConfig>,
    /// Reassembled T.140 text received since the last flush — becomes the next transmitted generation.
    pending: Vec<u8>,
    /// Prior transmitted generations, oldest first, for redundancy (a fixed reused ring).
    generations: [Generation; MAX_TEXT_REDUNDANCY],
    /// Valid entries in `generations` (`0..=MAX_TEXT_REDUNDANCY`).
    generation_count: usize,
    /// Whether this source distributed text on the previous flush — so the next packet after an idle
    /// interval sets the RTP marker (RFC 4103 §4.1, first packet of a new text transmission).
    active_last_flush: bool,
}

impl TextSource {
    fn new(config: Option<TextSourceConfig>) -> Self {
        Self {
            config,
            pending: Vec::with_capacity(MAX_PENDING_TEXT_BYTES),
            generations: std::array::from_fn(|_| Generation {
                timestamp: 0,
                data: Vec::with_capacity(MAX_PENDING_TEXT_BYTES),
            }),
            generation_count: 0,
            active_last_flush: false,
        }
    }
}

/// One packet the mixer wants transmitted this flush: source `source_csrc`'s text toward participant
/// `receiver`, as a ready-to-frame payload. The conference stamps it into an RTP packet with the
/// receiver leg's own SSRC/sequence, `source_csrc` as CSRC 0, `payload_type`, `timestamp`, and
/// `marker`. The payload bytes live in the mixer's arena — read them with [`TextMixer::payload_of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextEmit {
    /// Index of the participant this packet is for (its text leg's egress stream).
    pub receiver: usize,
    /// The contributing source's identifier, stamped as CSRC 0 (RFC 9071 §4.2 / RFC 3550 §5.1).
    pub source_csrc: u32,
    /// The RTP header payload type: the receiver's RED payload type when redundancy is used, else its
    /// bare T.140 payload type.
    pub payload_type: u8,
    /// The RTP timestamp (1000 Hz T.140 clock, RFC 4103 §4.1).
    pub timestamp: u32,
    /// Whether to set the RTP marker (first packet of a new text transmission, RFC 4103 §4.1).
    pub marker: bool,
    /// Start of this packet's payload in the mixer arena.
    payload_start: usize,
    /// Length of this packet's payload in the mixer arena.
    payload_len: usize,
}

/// The conference text mix bus. Owns per-participant queues + redundancy history and all per-flush
/// scratch, so [`TextMixer::flush`] allocates nothing after warm-up.
#[derive(Debug)]
pub struct TextMixer {
    /// Per-participant text state, kept **index-aligned** with the conference's participant vector by
    /// the caller (add/remove in lockstep).
    sources: Vec<TextSource>,
    /// The logical text-clock step per flush, in milliseconds — the RTP timestamp advances by this
    /// each flush (1000 Hz → ms, RFC 4103 §4.1).
    flush_interval_ms: u32,
    /// Emits produced by the last flush (reused, cleared each flush).
    emits: Vec<TextEmit>,
    /// Payload bytes for the last flush's emits (reused, cleared each flush).
    arena: Vec<u8>,
    /// RFC 2198 RED build buffer (reused; [`RedBuilder::write_into`] clears it).
    red_scratch: Vec<u8>,
}

impl TextMixer {
    /// Build an empty text mixer whose logical clock advances `flush_interval_ms` per flush (the
    /// conference's text flush cadence, ~300 ms).
    #[must_use]
    pub fn new(flush_interval_ms: u32) -> Self {
        Self {
            sources: Vec::new(),
            flush_interval_ms: flush_interval_ms.max(1),
            emits: Vec::new(),
            arena: Vec::new(),
            red_scratch: Vec::new(),
        }
    }

    /// Seat a participant, appended at the next index (kept aligned with the conference's participant
    /// vector). `config` is `None` for an audio-only participant — it holds the index but never sends
    /// or receives text. Returns `false` if the room is already at [`MAX_TEXT_PARTICIPANTS`].
    pub fn add_participant(&mut self, config: Option<TextSourceConfig>) -> bool {
        if self.sources.len() >= MAX_TEXT_PARTICIPANTS {
            return false;
        }
        self.sources.push(TextSource::new(config));
        true
    }

    /// Remove the participant at `index` (mirrors the conference's `participants.remove(index)`),
    /// keeping the two vectors aligned. Returns `false` for an out-of-range index.
    pub fn remove_participant(&mut self, index: usize) -> bool {
        if index >= self.sources.len() {
            return false;
        }
        self.sources.remove(index);
        true
    }

    /// The number of seated participants (text and audio-only alike).
    #[must_use]
    pub fn participant_count(&self) -> usize {
        self.sources.len()
    }

    /// Whether the participant at `index` has a text leg (so it sends/receives conference text).
    #[must_use]
    pub fn has_text_leg(&self, index: usize) -> bool {
        self.sources
            .get(index)
            .is_some_and(|source| source.config.is_some())
    }

    /// Queue a reassembled T.140 increment from participant `index` for the next flush. A no-op for an
    /// out-of-range index or a participant with no text leg. The queue is bounded to
    /// [`MAX_PENDING_TEXT_BYTES`]: a burst past it drops the **oldest** buffered bytes (so a paste
    /// storm cannot grow the queue without bound) and logs.
    pub fn push_text(&mut self, index: usize, text: &str) {
        let Some(source) = self.sources.get_mut(index) else {
            return;
        };
        if source.config.is_none() {
            return;
        }
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            return;
        }
        // A single burst larger than the whole cap keeps only its newest `cap` bytes.
        let incoming = if bytes.len() > MAX_PENDING_TEXT_BYTES {
            &bytes[bytes.len() - MAX_PENDING_TEXT_BYTES..]
        } else {
            bytes
        };
        let overflow =
            (source.pending.len() + incoming.len()).saturating_sub(MAX_PENDING_TEXT_BYTES);
        if overflow > 0 {
            source.pending.drain(0..overflow);
            tracing::debug!(
                index,
                overflow,
                "text mixer queue overflow; dropped oldest buffered text (drop-oldest policy)"
            );
        }
        source.pending.extend_from_slice(incoming);
    }

    /// Distribute every source's pending text to every other participant (RFC 9071 §4.2
    /// mix-minus-self), building one RED packet per (receiver, source) into the mixer arena and
    /// returning the number of emits produced. `flush_counter` drives the logical 1000 Hz text clock,
    /// so the output is a pure function of the flush schedule (deterministic). Read the emits with
    /// [`TextMixer::emits`] and each payload with [`TextMixer::payload_of`].
    pub fn flush(&mut self, flush_counter: u64) -> usize {
        self.emits.clear();
        self.arena.clear();
        let now_ts = flush_counter.wrapping_mul(u64::from(self.flush_interval_ms)) as u32;
        let count = self.sources.len();
        for source_index in 0..count {
            let Some(source_cfg) = self.sources[source_index].config else {
                continue; // audio-only participant: not a source
            };
            if self.sources[source_index].pending.is_empty() {
                // Idle this interval. Drop the redundancy history — a resumed burst must not reference
                // a generation on the far side of an idle gap (the RFC 2198 §3 14-bit offset would
                // overflow) — and mark the source idle so its next packet sets the RTP marker
                // (RFC 4103 §4.1).
                self.sources[source_index].generation_count = 0;
                self.sources[source_index].active_last_flush = false;
                continue;
            }
            let marker = !self.sources[source_index].active_last_flush;
            for receiver in 0..count {
                if receiver == source_index {
                    continue; // RFC 9071 §4.2: a participant never receives its own text back
                }
                let Some(receiver_cfg) = self.sources[receiver].config else {
                    continue; // audio-only participant: not a receiver
                };
                let (payload_type, payload_start, payload_len) = self.build_payload(
                    source_index,
                    receiver_cfg.t140_payload_type,
                    receiver_cfg.red_payload_type,
                    now_ts,
                );
                self.emits.push(TextEmit {
                    receiver,
                    source_csrc: source_cfg.source_id,
                    payload_type,
                    timestamp: now_ts,
                    marker,
                    payload_start,
                    payload_len,
                });
            }
            self.advance_generation(source_index, now_ts);
        }
        self.emits.len()
    }

    /// The emits produced by the most recent [`TextMixer::flush`].
    #[must_use]
    pub fn emits(&self) -> &[TextEmit] {
        &self.emits
    }

    /// The T.140/RED payload bytes for one emit (borrowed from the mixer arena; valid until the next
    /// flush).
    #[must_use]
    pub fn payload_of(&self, emit: &TextEmit) -> &[u8] {
        &self.arena[emit.payload_start..emit.payload_start + emit.payload_len]
    }

    /// Build source `source_index`'s text as the payload the participant with the given payload types
    /// expects, appending it to the arena and returning `(rtp_payload_type, start, len)`. Uses RFC
    /// 2198 RED when the receiver negotiated it (header PT = its RED PT; inner blocks on its T.140 PT),
    /// else a bare T.140 payload on its T.140 PT (RFC 4103 §4). The payload is receiver-specific
    /// because the inner payload type must be the one *that receiver* expects (RFC 3264 §6.1).
    fn build_payload(
        &mut self,
        source_index: usize,
        receiver_t140_pt: u8,
        receiver_red_pt: Option<u8>,
        now_ts: u32,
    ) -> (u8, usize, usize) {
        let start = self.arena.len();
        let payload_type = match receiver_red_pt {
            Some(red_pt) => {
                self.build_red(source_index, receiver_t140_pt, now_ts);
                self.arena.extend_from_slice(&self.red_scratch);
                red_pt
            }
            None => {
                // Bare T.140 (RFC 4103 §4): the raw reassembled text on the T.140 payload type.
                self.arena
                    .extend_from_slice(&self.sources[source_index].pending);
                receiver_t140_pt
            }
        };
        (payload_type, start, self.arena.len() - start)
    }

    /// Build source `source_index`'s RFC 2198 RED payload into `red_scratch`: primary = its pending
    /// text at `now_ts`, redundant = its prior generations (oldest first) on `t140_pt`.
    fn build_red(&mut self, source_index: usize, t140_pt: u8, now_ts: u32) {
        let source = &self.sources[source_index];
        // Stack-allocated generation table (no per-flush heap): the redundant blocks reference the
        // source's own history buffers.
        let mut generations: [RedGeneration<'_>; MAX_TEXT_REDUNDANCY] = [RedGeneration {
            payload_type: 0,
            rtp_timestamp: 0,
            data: &[],
        };
            MAX_TEXT_REDUNDANCY];
        let mut generation_count = 0;
        for generation in &source.generations[..source.generation_count] {
            generations[generation_count] = RedGeneration {
                payload_type: t140_pt,
                rtp_timestamp: generation.timestamp,
                data: &generation.data,
            };
            generation_count += 1;
        }
        let builder = RedBuilder {
            primary_payload_type: t140_pt,
            primary_rtp_timestamp: now_ts,
            primary_data: &source.pending,
            redundant: &generations[..generation_count],
        };
        if builder.write_into(&mut self.red_scratch).is_err() {
            // Redundancy did not fit the RFC 2198 §3 fields (an offset or block over the field width).
            // Fall back to a primary-only RED payload — which has no redundant blocks and so cannot
            // overflow — rather than drop the source's live text.
            let primary_only = RedBuilder {
                primary_payload_type: t140_pt,
                primary_rtp_timestamp: now_ts,
                primary_data: &source.pending,
                redundant: &[],
            };
            let _ = primary_only.write_into(&mut self.red_scratch);
        }
    }

    /// Record this flush's pending text as source `source_index`'s newest transmitted generation
    /// (dropping the oldest when the ring is full), clear its pending queue, and mark it active.
    fn advance_generation(&mut self, source_index: usize, now_ts: u32) {
        let source = &mut self.sources[source_index];
        let target = if source.generation_count < MAX_TEXT_REDUNDANCY {
            let index = source.generation_count;
            source.generation_count += 1;
            index
        } else {
            // Full ring: drop the oldest, reuse its buffer as the newest slot (no allocation).
            source.generations.rotate_left(1);
            MAX_TEXT_REDUNDANCY - 1
        };
        source.generations[target].timestamp = now_ts;
        // Disjoint field borrows: copy pending into the target generation buffer without allocating.
        let (generations, pending) = (&mut source.generations, &source.pending);
        generations[target].data.clear();
        generations[target].data.extend_from_slice(pending);
        source.pending.clear();
        source.active_last_flush = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::t140::RedPacket;

    /// RFC-document dynamic payload types for a text leg (RFC 4103 §5 / RFC 2198): t140 + its RED wrap.
    const T140_PT: u8 = 98;
    const RED_PT: u8 = 99;

    /// A text participant on the standard t140=98 / red=99 payload types, identified by `source_id`.
    fn red_source(source_id: u32) -> Option<TextSourceConfig> {
        Some(TextSourceConfig {
            source_id,
            t140_payload_type: T140_PT,
            red_payload_type: Some(RED_PT),
        })
    }

    /// A three-text-participant room (source ids 0xA/0xB/0xC), all RED-capable.
    fn three_text_room() -> TextMixer {
        let mut mixer = TextMixer::new(300);
        assert!(mixer.add_participant(red_source(0xAAAA)));
        assert!(mixer.add_participant(red_source(0xBBBB)));
        assert!(mixer.add_participant(red_source(0xCCCC)));
        mixer
    }

    /// Collect (receiver, csrc, primary-text) for every emit, RED-parsing the payload's primary block.
    fn decode_emits(mixer: &TextMixer) -> Vec<(usize, u32, String)> {
        mixer
            .emits()
            .iter()
            .map(|emit| {
                let payload = mixer.payload_of(emit);
                let packet = RedPacket::parse(payload).expect("emit payload parses as RED");
                let text = String::from_utf8(packet.primary().data.to_vec()).expect("utf8");
                (emit.receiver, emit.source_csrc, text)
            })
            .collect()
    }

    #[test]
    fn two_sources_mix_minus_self_with_per_source_csrc() {
        // A and B each type; C is silent this interval. Each receiver gets the OTHER speakers' text,
        // labelled by the speaker's CSRC — and never its own (RFC 9071 §4.2 mix-minus-self).
        let mut mixer = three_text_room();
        mixer.push_text(0, "Hi");
        mixer.push_text(1, "Yo");
        let count = mixer.flush(1);
        // A (0) → B,C ; B (1) → A,C : four emits (C sent nothing).
        assert_eq!(count, 4);
        let decoded = decode_emits(&mixer);

        // A's "Hi" reaches B and C tagged with A's CSRC; never reaches A.
        assert!(decoded.contains(&(1, 0xAAAA, "Hi".to_string())));
        assert!(decoded.contains(&(2, 0xAAAA, "Hi".to_string())));
        assert!(!decoded
            .iter()
            .any(|(r, csrc, _)| *r == 0 && *csrc == 0xAAAA));
        // B's "Yo" reaches A and C tagged with B's CSRC; never reaches B.
        assert!(decoded.contains(&(0, 0xBBBB, "Yo".to_string())));
        assert!(decoded.contains(&(2, 0xBBBB, "Yo".to_string())));
        assert!(!decoded
            .iter()
            .any(|(r, csrc, _)| *r == 1 && *csrc == 0xBBBB));
    }

    #[test]
    fn a_third_source_stays_separable_at_the_receiver() {
        // All three type at once. Receiver A must get B's and C's text as two separately-labelled
        // packets (different CSRCs), never blended (RFC 9071 §4.2 — text is not summed).
        let mut mixer = three_text_room();
        mixer.push_text(0, "a");
        mixer.push_text(1, "b");
        mixer.push_text(2, "c");
        mixer.flush(1);
        let decoded = decode_emits(&mixer);

        // What A (receiver 0) hears, grouped by source CSRC.
        let to_a: Vec<(u32, String)> = decoded
            .iter()
            .filter(|(receiver, ..)| *receiver == 0)
            .map(|(_, csrc, text)| (*csrc, text.clone()))
            .collect();
        assert!(
            to_a.contains(&(0xBBBB, "b".to_string())),
            "A hears B, labelled B"
        );
        assert!(
            to_a.contains(&(0xCCCC, "c".to_string())),
            "A hears C, labelled C"
        );
        assert!(
            !to_a.iter().any(|(csrc, _)| *csrc == 0xAAAA),
            "A never hears itself"
        );
        // 3 sources × 2 other receivers = 6 emits.
        assert_eq!(mixer.emits().len(), 6);
    }

    #[test]
    fn redundancy_carries_the_prior_generation() {
        // A types across two consecutive flushes. The second flush's packet must carry the first
        // generation as an RFC 2198 redundant block, so a single lost packet is recoverable.
        let mut mixer = three_text_room();
        mixer.push_text(0, "H");
        mixer.flush(1);
        // First flush: no redundancy yet.
        let first = mixer.emits()[0];
        let first_packet = RedPacket::parse(mixer.payload_of(&first)).expect("parse");
        assert_eq!(first_packet.generation_count(), 0);
        assert_eq!(first_packet.primary().data, b"H");
        assert!(
            first.marker,
            "first packet of the transmission sets the marker"
        );

        mixer.push_text(0, "i");
        mixer.flush(2);
        let second = mixer.emits()[0];
        let second_packet = RedPacket::parse(mixer.payload_of(&second)).expect("parse");
        assert_eq!(
            second_packet.generation_count(),
            1,
            "carries one redundant generation"
        );
        assert_eq!(second_packet.redundant_blocks()[0].data, b"H");
        // 1000 Hz clock: flush 2 − flush 1 = one 300 ms interval.
        assert_eq!(second_packet.redundant_blocks()[0].timestamp_offset, 300);
        assert_eq!(second_packet.primary().data, b"i");
        assert_eq!(second.timestamp, 600, "flush 2 × 300 ms");
        assert!(!second.marker, "steady-state packet clears the marker");
    }

    #[test]
    fn marker_sets_again_after_an_idle_interval() {
        // Marker on the first packet, cleared while typing continues, set again after an idle gap
        // (RFC 4103 §4.1 — first packet of a new transmission).
        let mut mixer = three_text_room();
        mixer.push_text(0, "a");
        mixer.flush(1);
        assert!(mixer.emits()[0].marker);
        mixer.push_text(0, "b");
        mixer.flush(2);
        assert!(!mixer.emits()[0].marker);
        // Idle flush (A sends nothing): no emits, redundancy reset.
        assert_eq!(mixer.flush(3), 0);
        // A types again → marker set again.
        mixer.push_text(0, "c");
        mixer.flush(4);
        assert!(mixer.emits()[0].marker, "first packet after idle re-marks");
        let packet = RedPacket::parse(mixer.payload_of(&mixer.emits()[0])).expect("parse");
        assert_eq!(
            packet.generation_count(),
            0,
            "redundancy was reset across the idle gap"
        );
    }

    #[test]
    fn audio_only_participant_neither_sends_nor_receives_text() {
        // Index 1 is audio-only (no text leg). It must not receive text, and cannot originate it.
        let mut mixer = TextMixer::new(300);
        assert!(mixer.add_participant(red_source(0xAAAA)));
        assert!(mixer.add_participant(None)); // audio-only
        assert!(mixer.add_participant(red_source(0xCCCC)));
        assert!(!mixer.has_text_leg(1));
        mixer.push_text(0, "hello");
        mixer.push_text(1, "ignored"); // no text leg: dropped
        mixer.flush(1);
        let decoded = decode_emits(&mixer);
        // A's text reaches only C (index 2), never the audio-only index 1.
        assert_eq!(decoded, vec![(2usize, 0xAAAA, "hello".to_string())]);
    }

    #[test]
    fn bare_t140_receiver_gets_no_red_wrapper() {
        // A receiver that negotiated only t140 (no RED) gets a bare T.140 payload on its t140 PT.
        let mut mixer = TextMixer::new(300);
        assert!(mixer.add_participant(red_source(0xAAAA)));
        assert!(mixer.add_participant(Some(TextSourceConfig {
            source_id: 0xBBBB,
            t140_payload_type: 100,
            red_payload_type: None,
        })));
        mixer.push_text(0, "hey");
        mixer.flush(1);
        let emit = mixer.emits()[0];
        assert_eq!(emit.receiver, 1);
        assert_eq!(emit.payload_type, 100, "bare t140 PT, not a RED PT");
        // The payload is the raw text — not a RED envelope.
        assert_eq!(mixer.payload_of(&emit), b"hey");
    }

    #[test]
    fn heterogeneous_payload_types_are_receiver_specific() {
        // Two receivers with different t140/red PTs get the same source text framed for each of them.
        let mut mixer = TextMixer::new(300);
        assert!(mixer.add_participant(red_source(0xAAAA))); // t140=98 red=99
        assert!(mixer.add_participant(Some(TextSourceConfig {
            source_id: 0xBBBB,
            t140_payload_type: 111,
            red_payload_type: Some(112),
        })));
        assert!(mixer.add_participant(Some(TextSourceConfig {
            source_id: 0xCCCC,
            t140_payload_type: 96,
            red_payload_type: None,
        })));
        mixer.push_text(0, "x");
        mixer.flush(1);
        let by_receiver: std::collections::HashMap<usize, u8> = mixer
            .emits()
            .iter()
            .map(|emit| (emit.receiver, emit.payload_type))
            .collect();
        assert_eq!(by_receiver[&1], 112, "receiver B uses its own RED PT");
        assert_eq!(by_receiver[&2], 96, "receiver C uses its own bare t140 PT");
    }

    #[test]
    fn duplicate_flush_after_drain_emits_nothing() {
        // A flush drains the queue: a second flush with no new text produces nothing.
        let mut mixer = three_text_room();
        mixer.push_text(0, "hi");
        assert_eq!(mixer.flush(1), 2, "A → B and C");
        assert_eq!(mixer.flush(2), 0, "queue already drained");
    }

    #[test]
    fn output_is_deterministic_over_a_fixed_schedule() {
        // The same push/flush schedule on two independent mixers yields byte-identical output — no
        // wall clock anywhere (RFC 4103 §4.1 timestamps come from the flush counter).
        fn run() -> Vec<(usize, u32, u8, u32, bool, Vec<u8>)> {
            let mut mixer = three_text_room();
            let mut trace = Vec::new();
            for (flush_index, pushes) in [
                (1u64, vec![(0usize, "He"), (1, "Yo")]),
                (2, vec![(0, "llo")]),
                (3, vec![]),
                (4, vec![(2, "!")]),
            ] {
                for (index, text) in pushes {
                    mixer.push_text(index, text);
                }
                mixer.flush(flush_index);
                for emit in mixer.emits() {
                    trace.push((
                        emit.receiver,
                        emit.source_csrc,
                        emit.payload_type,
                        emit.timestamp,
                        emit.marker,
                        mixer.payload_of(emit).to_vec(),
                    ));
                }
            }
            trace
        }
        assert_eq!(run(), run());
    }

    #[test]
    fn queue_overflow_drops_oldest_and_stays_bounded() {
        // A burst well past the cap keeps only the newest MAX_PENDING_TEXT_BYTES.
        let mut mixer = TextMixer::new(300);
        assert!(mixer.add_participant(red_source(0xAAAA)));
        assert!(mixer.add_participant(red_source(0xBBBB)));
        let huge = "x".repeat(MAX_PENDING_TEXT_BYTES * 3);
        mixer.push_text(0, &huge);
        mixer.flush(1);
        let packet = RedPacket::parse(mixer.payload_of(&mixer.emits()[0])).expect("parse");
        assert_eq!(
            packet.primary().data.len(),
            MAX_PENDING_TEXT_BYTES,
            "queue bounded to the cap, oldest dropped"
        );
    }

    #[test]
    fn remove_participant_keeps_indices_aligned() {
        let mut mixer = three_text_room();
        assert_eq!(mixer.participant_count(), 3);
        assert!(mixer.remove_participant(1)); // B leaves
        assert_eq!(mixer.participant_count(), 2);
        mixer.push_text(0, "z");
        mixer.flush(1);
        // Only A and C remain: A → C is the sole emit, now at index 1.
        let decoded = decode_emits(&mixer);
        assert_eq!(decoded, vec![(1usize, 0xAAAA, "z".to_string())]);
        assert!(
            !mixer.remove_participant(9),
            "out-of-range remove is a no-op"
        );
    }
}
