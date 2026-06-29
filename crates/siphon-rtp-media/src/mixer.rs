//! The conference **mix bus** (MCU): N participants' decoded PCM in, each participant's
//! mixed-minus-self PCM out — pure, synchronous, allocation-free after construction.
//!
//! This is the room math only: it consumes frames already decoded to a single common **room rate**
//! (the [`crate::leg::MediaLeg`] + resampler work happens in the engine's conference actor) and
//! produces the PCM each participant should hear. It owns no codecs, sockets, or clock, so it
//! unit-tests as plain arithmetic. Inputs arrive as **parallel slices** ([`MixInputs`]) — views into
//! the caller's reused buffers — so a tick allocates nothing.
//!
//! ## Mixed-minus-self, O(N)
//! The room sum is computed once: `room_total = Σ pcm_j` over the **active contributors** (in `i32`,
//! so 64 full-scale `i16` frames cannot overflow). A participant that contributes hears
//! `saturate(room_total − own)` (so it never hears itself — this is also the in-room echo handling);
//! everyone else hears `saturate(room_total)`. That keeps the common path one Σ pass plus one
//! subtraction per active talker, not the O(N²) of an explicit per-pair matrix.
//!
//! ## Active-speaker / top-M gating
//! Only **speaking** talkers (VAD incl. hangover, decided by the caller) contribute, and at most the
//! `top_m` loudest of them (by caller-supplied energy). Non-contributing talkers fall back to hearing
//! the room like a listener this tick. The active set is returned as a bitset so the caller can emit
//! an active-speaker change event.
//!
//! ## Shared-encode output model
//! Every listener (and every inactive talker) hears the **same** [`Mixer::listener_mix`] frame, so the
//! engine encodes it once per codec class and fans the payload out (one encode, N sends). Only the few
//! active talkers get a distinct `saturate(room_total − own)` frame ([`Mixer::output_for`]). The mixer
//! therefore never materialises N identical listener frames.
//!
//! ## Audio routing matrix (sparse)
//! [`Whisper`] (a source audible only to one target — supervisor coaching) and [`Monitor`] (a listener
//! hears one target directly, the target unaware) are layered as sparse per-participant overrides on
//! top of the symmetric room; when both lists are empty the common path never touches them.

/// The largest room the mixer supports — the active-speaker set is a `u64` bitmask.
pub const MAX_PARTICIPANTS: usize = 64;

/// The largest `top_m` the fixed-size active-speaker selection keeps without heap allocation. A
/// conference rarely has more than a handful of simultaneous speakers; callers clamp to this.
pub const MAX_ACTIVE_SPEAKERS: usize = 8;

/// A participant's role in the room. The symmetric "everyone hears everyone else" conference is the
/// all-[`Role::Talker`] case; the other roles are the call-centre/PBX routing matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Contributes to the room sum (subject to active-speaker gating) and hears mixed-minus-self.
    Talker,
    /// Hears the room, contributes nothing (music-on-hold, a webinar attendee, a supervisor monitor).
    Listener,
    /// Hears the room, contributes nothing — distinct from [`Role::Listener`] only so the control
    /// plane can tell "muted talker" from "listen-only" for UI/state.
    Muted,
}

/// The per-participant inputs to one mix tick, as **parallel slices** (the caller passes views into
/// its own reused buffers, so [`Mixer::mix`] allocates nothing). All four slices are indexed by the
/// same participant index and must have the same length; each `pcm[i]` holds at least `frame_len`
/// samples at the room rate (a starved participant passes a zero-filled frame).
pub struct MixInputs<'a> {
    /// Each participant's decoded frame at the room rate.
    pub pcm: &'a [Vec<i16>],
    /// Each participant's role this tick.
    pub roles: &'a [Role],
    /// Each participant's frame energy (e.g. `siphon_rtp_simd::sum_sq_i16`), for ranking speakers.
    pub energy: &'a [i64],
    /// Whether each participant is speaking (energy VAD including hangover). Only speaking talkers
    /// contribute.
    pub speaking: &'a [bool],
    /// An optional extra room-rate frame summed into the room total — a **bridged room's** mix. It is
    /// heard by everyone (added to `room_total`) but is not a participant, so no one is
    /// mixed-minus-self against it. `None` for a standalone room.
    pub external: Option<&'a [i16]>,
    /// Samples per frame this tick (≤ the mixer's frame capacity).
    pub frame_len: usize,
}

impl MixInputs<'_> {
    fn participant_count(&self) -> usize {
        self.pcm.len()
    }
}

/// A private one-to-one route: `from`'s audio is audible only to `to` (supervisor whisper / coach).
/// The whisperer is **excluded** from the public room sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Whisper {
    /// Index of the participant whose audio is whispered.
    pub from: usize,
    /// Index of the sole participant who hears it.
    pub to: usize,
}

/// A one-way monitor: `listener` hears `target` directly, the target unaware (barge-in prep /
/// supervisor listen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Monitor {
    /// Index of the participant doing the listening.
    pub listener: usize,
    /// Index of the participant being listened to.
    pub target: usize,
}

/// The conference mix bus. Owns all per-tick scratch, sized once at construction so [`Mixer::mix`] is
/// allocation-free.
pub struct Mixer {
    participant_capacity: usize,
    frame_capacity: usize,
    /// `room_total` accumulator (`i32` so 64 full-scale `i16` frames cannot overflow).
    accum: Vec<i32>,
    /// `saturate(room_total)` — the shared frame every listener hears (includes any bridged room).
    listener_buf: Vec<i16>,
    /// `saturate(Σ local participants)` — the room's own audio *excluding* the bridged room. This is
    /// what is fed onward to a bridged room, so a bridge never echoes a room's audio back to itself.
    participant_buf: Vec<i16>,
    /// Per-participant distinct output (mixed-minus-self for active talkers, or a routing override).
    own: Vec<Vec<i16>>,
    /// Whether `own[i]` holds a distinct output for participant `i` this tick.
    has_own: Vec<bool>,
    /// Samples written this tick.
    frame_len: usize,
    /// Participants this tick.
    participant_count: usize,
}

#[inline]
fn saturate_i16(value: i32) -> i16 {
    value.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

impl Mixer {
    /// Build a mixer sized for up to `participant_capacity` participants (capped at
    /// [`MAX_PARTICIPANTS`]) and `frame_capacity` samples per frame (the room-rate frame size, e.g.
    /// 320 for 16 kHz / 20 ms). All scratch is allocated here; [`Mixer::mix`] never allocates.
    #[must_use]
    pub fn new(participant_capacity: usize, frame_capacity: usize) -> Self {
        let participant_capacity = participant_capacity.min(MAX_PARTICIPANTS);
        Self {
            participant_capacity,
            frame_capacity,
            accum: vec![0; frame_capacity],
            listener_buf: vec![0; frame_capacity],
            participant_buf: vec![0; frame_capacity],
            own: (0..participant_capacity).map(|_| vec![0; frame_capacity]).collect(),
            has_own: vec![false; participant_capacity],
            frame_len: 0,
            participant_count: 0,
        }
    }

    /// Mix one tick. `whispers`/`monitors` are sparse routing overrides; `top_m` caps the number of
    /// simultaneous active speakers (`0` = no cap, clamped to [`MAX_ACTIVE_SPEAKERS`] otherwise).
    /// Returns the active-speaker bitset (bit `i` set ⇒ participant `i` contributed). After this call
    /// read each participant's output via [`Mixer::output_for`] and the shared listener frame via
    /// [`Mixer::listener_mix`].
    pub fn mix(
        &mut self,
        inputs: &MixInputs<'_>,
        whispers: &[Whisper],
        monitors: &[Monitor],
        top_m: usize,
    ) -> u64 {
        let participant_count = inputs.participant_count();
        assert!(
            participant_count <= self.participant_capacity,
            "mixer: {participant_count} participants exceeds capacity {}",
            self.participant_capacity
        );
        assert!(
            inputs.roles.len() == participant_count
                && inputs.energy.len() == participant_count
                && inputs.speaking.len() == participant_count,
            "mixer: parallel input slices must have equal length"
        );
        let frame_len = inputs.frame_len;
        assert!(frame_len <= self.frame_capacity, "mixer: frame exceeds capacity");
        self.frame_len = frame_len;
        self.participant_count = participant_count;
        for slot in self.has_own[..participant_count].iter_mut() {
            *slot = false;
        }

        // Private whisper sources are excluded from the public room sum (their audio is one-to-one).
        let mut private_sources: u64 = 0;
        for whisper in whispers {
            if whisper.from < participant_count {
                private_sources |= 1 << whisper.from;
            }
        }

        let active_mask = select_active_speakers(inputs, private_sources, top_m);

        // room_total = Σ active, non-private contributors (i32, cannot overflow 64 i16 frames).
        {
            let accum = &mut self.accum[..frame_len];
            for slot in accum.iter_mut() {
                *slot = 0;
            }
            for (index, row) in inputs.pcm.iter().enumerate() {
                if active_mask & (1 << index) != 0 {
                    for (slot, &sample) in accum.iter_mut().zip(row[..frame_len].iter()) {
                        *slot += i32::from(sample);
                    }
                }
            }
            // The local-participants-only mix, captured before any bridged audio is added — this is
            // what feeds onward to a bridged room (so a bridge never echoes a room back to itself).
            for (dst, &total) in self.participant_buf[..frame_len].iter_mut().zip(accum.iter()) {
                *dst = saturate_i16(total);
            }
            // A bridged room's mix is heard by everyone — sum it in before computing outputs (so a
            // talker hears the bridged room too, since minus-self only subtracts its own audio).
            if let Some(external) = inputs.external {
                for (slot, &sample) in accum.iter_mut().zip(external.iter()) {
                    *slot += i32::from(sample);
                }
            }
        }

        // The shared listener frame.
        for (dst, &total) in self.listener_buf[..frame_len]
            .iter_mut()
            .zip(self.accum[..frame_len].iter())
        {
            *dst = saturate_i16(total);
        }

        // Each active talker hears the room minus itself.
        for (index, row) in inputs.pcm.iter().enumerate() {
            if active_mask & (1 << index) != 0 {
                let own = &mut self.own[index][..frame_len];
                for ((dst, &total), &own_sample) in own
                    .iter_mut()
                    .zip(self.accum[..frame_len].iter())
                    .zip(row[..frame_len].iter())
                {
                    *dst = saturate_i16(total - i32::from(own_sample));
                }
                self.has_own[index] = true;
            }
        }

        // Sparse routing overrides (common path skips these when both lists are empty).
        for monitor in monitors {
            if monitor.listener < participant_count && monitor.target < participant_count {
                let target = &inputs.pcm[monitor.target][..frame_len];
                let own = &mut self.own[monitor.listener][..frame_len];
                for (dst, &sample) in own.iter_mut().zip(target.iter()) {
                    *dst = sample; // hears the target directly
                }
                self.has_own[monitor.listener] = true;
            }
        }
        for whisper in whispers {
            if whisper.from < participant_count && whisper.to < participant_count {
                let to_active = active_mask & (1 << whisper.to) != 0;
                let from_pcm = &inputs.pcm[whisper.from][..frame_len];
                let to_pcm = &inputs.pcm[whisper.to][..frame_len];
                let own = &mut self.own[whisper.to][..frame_len];
                for (((dst, &total), &whisper_sample), &to_sample) in own
                    .iter_mut()
                    .zip(self.accum[..frame_len].iter())
                    .zip(from_pcm.iter())
                    .zip(to_pcm.iter())
                {
                    // The target's own base (room minus self if it is a talker) plus the whisper.
                    let base = if to_active { total - i32::from(to_sample) } else { total };
                    *dst = saturate_i16(base + i32::from(whisper_sample));
                }
                self.has_own[whisper.to] = true;
            }
        }

        active_mask
    }

    /// The shared frame every listener (and inactive talker) hears: `saturate(room_total)`. Encode it
    /// once per codec class and fan the payload out.
    #[must_use]
    pub fn listener_mix(&self) -> &[i16] {
        &self.listener_buf[..self.frame_len]
    }

    /// The room's **local participants only** mix (excludes any bridged room) — the frame to feed
    /// onward to a bridged room, so the bridge never echoes a room's own audio back to it.
    #[must_use]
    pub fn participant_mix(&self) -> &[i16] {
        &self.participant_buf[..self.frame_len]
    }

    /// The frame participant `participant` should hear this tick: its distinct mixed-minus-self (or
    /// routing-override) frame if it has one, otherwise the shared [`Mixer::listener_mix`].
    #[must_use]
    pub fn output_for(&self, participant: usize) -> &[i16] {
        if participant < self.participant_count && self.has_own[participant] {
            &self.own[participant][..self.frame_len]
        } else {
            &self.listener_buf[..self.frame_len]
        }
    }

    /// Whether participant `participant` has a distinct output this tick (an active talker or a
    /// routing-override target) — i.e. it cannot share a listener-class encode.
    #[must_use]
    pub fn has_distinct_output(&self, participant: usize) -> bool {
        participant < self.participant_count && self.has_own[participant]
    }
}

/// Pick the active speakers: the `top_m` highest-energy speaking talkers (excluding private whisper
/// sources). `top_m == 0` ⇒ every speaking talker is active. Zero-allocation fixed-size selection.
fn select_active_speakers(inputs: &MixInputs<'_>, private_sources: u64, top_m: usize) -> u64 {
    let is_candidate = |index: usize, role: Role| -> bool {
        matches!(role, Role::Talker)
            && inputs.speaking[index]
            && (private_sources & (1 << index) == 0)
    };

    if top_m == 0 {
        let mut mask = 0u64;
        for (index, &role) in inputs.roles.iter().enumerate() {
            if is_candidate(index, role) {
                mask |= 1 << index;
            }
        }
        return mask;
    }

    let capacity = top_m.min(MAX_ACTIVE_SPEAKERS);
    let mut best: [(i64, usize); MAX_ACTIVE_SPEAKERS] = [(i64::MIN, usize::MAX); MAX_ACTIVE_SPEAKERS];
    let mut count = 0usize;
    for (index, &role) in inputs.roles.iter().enumerate() {
        if !is_candidate(index, role) {
            continue;
        }
        let energy = inputs.energy[index];
        if count < capacity {
            best[count] = (energy, index);
            count += 1;
        } else {
            // Replace the weakest kept speaker if this one is louder.
            let weakest = (0..capacity).min_by_key(|&slot| best[slot].0).unwrap_or(0);
            if energy > best[weakest].0 {
                best[weakest] = (energy, index);
            }
        }
    }

    let mut mask = 0u64;
    for &(_, index) in best.iter().take(count) {
        mask |= 1 << index;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build talker inputs from a set of constant-valued frames, all speaking, energy = sample².
    fn all_talkers(frames: &[Vec<i16>]) -> (Vec<Role>, Vec<i64>, Vec<bool>) {
        let roles = vec![Role::Talker; frames.len()];
        let energy = frames
            .iter()
            .map(|frame| frame.first().map_or(0, |&s| i64::from(s) * i64::from(s)))
            .collect();
        let speaking = vec![true; frames.len()];
        (roles, energy, speaking)
    }

    fn inputs<'a>(
        pcm: &'a [Vec<i16>],
        roles: &'a [Role],
        energy: &'a [i64],
        speaking: &'a [bool],
        frame_len: usize,
    ) -> MixInputs<'a> {
        MixInputs { pcm, roles, energy, speaking, external: None, frame_len }
    }

    #[test]
    fn three_way_mixed_minus_self() {
        // Three talkers a/b/c — each hears the sum of the OTHER two, never itself.
        let pcm = vec![vec![100i16; 4], vec![200i16; 4], vec![40i16; 4]];
        let (roles, energy, speaking) = all_talkers(&pcm);
        let mut mixer = Mixer::new(3, 4);
        let active = mixer.mix(&inputs(&pcm, &roles, &energy, &speaking, 4), &[], &[], 0);

        assert_eq!(active, 0b111, "all three speaking talkers are active");
        assert_eq!(mixer.output_for(0), &[240i16; 4], "party 0 hears b + c = 200 + 40");
        assert_eq!(mixer.output_for(1), &[140i16; 4], "party 1 hears a + c = 100 + 40");
        assert_eq!(mixer.output_for(2), &[300i16; 4], "party 2 hears a + b = 100 + 200");
        assert_eq!(mixer.listener_mix(), &[340i16; 4], "a pure listener would hear a + b + c");
    }

    #[test]
    fn silent_room_yields_silence() {
        let pcm = vec![vec![0i16; 4], vec![0i16; 4]];
        let roles = vec![Role::Talker; 2];
        let energy = vec![0i64; 2];
        let speaking = vec![false; 2];
        let mut mixer = Mixer::new(2, 4);
        let active = mixer.mix(&inputs(&pcm, &roles, &energy, &speaking, 4), &[], &[], 0);
        assert_eq!(active, 0, "no one speaking → no contributors");
        assert_eq!(mixer.output_for(0), &[0i16; 4]);
        assert_eq!(mixer.listener_mix(), &[0i16; 4]);
    }

    #[test]
    fn sum_saturates_to_i16_range() {
        // Two near-full-scale talkers: the listener mix clamps, it never wraps.
        let pcm = vec![vec![30000i16; 4], vec![30000i16; 4]];
        let (roles, energy, speaking) = all_talkers(&pcm);
        let mut mixer = Mixer::new(2, 4);
        mixer.mix(&inputs(&pcm, &roles, &energy, &speaking, 4), &[], &[], 0);
        assert_eq!(mixer.listener_mix(), &[i16::MAX; 4], "60000 clamps to i16::MAX");
        // Party 0 hears only b (30000) — within range, no clamp.
        assert_eq!(mixer.output_for(0), &[30000i16; 4]);
    }

    #[test]
    fn muted_and_listener_contribute_nothing_but_hear_the_room() {
        let pcm = vec![vec![500i16; 4], vec![9999i16; 4], vec![8888i16; 4]];
        let roles = vec![Role::Talker, Role::Muted, Role::Listener];
        let energy = vec![250_000i64, 1, 1];
        let speaking = vec![true, true, true];
        let mut mixer = Mixer::new(3, 4);
        let active = mixer.mix(&inputs(&pcm, &roles, &energy, &speaking, 4), &[], &[], 0);
        assert_eq!(active, 0b001, "only the talker contributes");
        // Muted and listen-only both hear just the one talker.
        assert_eq!(mixer.output_for(1), &[500i16; 4]);
        assert_eq!(mixer.output_for(2), &[500i16; 4]);
        // The talker hears the room minus itself = nothing (it was the only contributor).
        assert_eq!(mixer.output_for(0), &[0i16; 4]);
    }

    #[test]
    fn top_m_gates_to_the_loudest_speakers() {
        // Four talkers, top_m = 2 → only the two loudest contribute; the quiet two become listeners.
        let pcm = vec![vec![1000i16; 4], vec![900i16; 4], vec![10i16; 4], vec![20i16; 4]];
        let roles = vec![Role::Talker; 4];
        let energy = vec![1_000_000i64, 810_000, 100, 400];
        let speaking = vec![true; 4];
        let mut mixer = Mixer::new(4, 4);
        let active = mixer.mix(&inputs(&pcm, &roles, &energy, &speaking, 4), &[], &[], 2);
        assert_eq!(active.count_ones(), 2, "exactly top-2 active");
        assert_eq!(active, 0b0011, "the two loudest (indices 0,1)");
        // A gated-out talker hears the room (loud1 + loud2) like a listener.
        assert!(!mixer.has_distinct_output(2));
        assert_eq!(mixer.output_for(2), &[1900i16; 4]);
        // A contributing talker still hears minus-self.
        assert_eq!(mixer.output_for(0), &[900i16; 4]);
    }

    #[test]
    fn whisper_is_private_to_the_target() {
        // Supervisor (1) whispers to agent (0); customer (2) must NOT hear the supervisor.
        let pcm = vec![vec![100i16; 4], vec![700i16; 4], vec![300i16; 4]];
        let (roles, energy, speaking) = all_talkers(&pcm);
        let mut mixer = Mixer::new(3, 4);
        let active = mixer.mix(
            &inputs(&pcm, &roles, &energy, &speaking, 4),
            &[Whisper { from: 1, to: 0 }],
            &[],
            0,
        );

        // The supervisor is excluded from the public room sum.
        assert_eq!(active, 0b101, "agent + customer contribute; supervisor is private");
        // Agent hears the room-minus-self (customer) PLUS the supervisor's whisper.
        assert_eq!(mixer.output_for(0), &[1000i16; 4], "customer 300 + supervisor 700");
        // Customer hears only the agent — never the supervisor.
        assert_eq!(mixer.output_for(2), &[100i16; 4]);
    }

    #[test]
    fn monitor_hears_target_directly_target_unaware() {
        let pcm = vec![vec![120i16; 4], vec![340i16; 4], vec![0i16; 4]];
        let roles = vec![Role::Talker, Role::Talker, Role::Listener];
        let energy = vec![14_400i64, 115_600, 0];
        let speaking = vec![true, true, false];
        let mut mixer = Mixer::new(3, 4);
        mixer.mix(
            &inputs(&pcm, &roles, &energy, &speaking, 4),
            &[],
            &[Monitor { listener: 2, target: 1 }],
            0,
        );
        // Supervisor hears exactly the customer's audio.
        assert_eq!(mixer.output_for(2), &[340i16; 4]);
        // The customer's own output is unaffected by being monitored (hears the agent).
        assert_eq!(mixer.output_for(1), &[120i16; 4]);
    }

    #[test]
    fn external_bridged_room_is_heard_by_everyone() {
        // A bridged room contributes 1000 to the total; both local talkers hear it on top of each
        // other, and a pure listener hears the whole room plus the bridge.
        let pcm = vec![vec![100i16; 4], vec![200i16; 4]];
        let (roles, energy, speaking) = all_talkers(&pcm);
        let bridged = [1000i16; 4];
        let mut mixer = Mixer::new(2, 4);
        let mut request = inputs(&pcm, &roles, &energy, &speaking, 4);
        request.external = Some(&bridged);
        mixer.mix(&request, &[], &[], 0);
        // Party 0 hears party 1 (200) + the bridged room (1000) = 1200; never its own 100.
        assert_eq!(mixer.output_for(0), &[1200i16; 4]);
        assert_eq!(mixer.output_for(1), &[1100i16; 4], "party 1: 100 + 1000");
        assert_eq!(mixer.listener_mix(), &[1300i16; 4], "100 + 200 + 1000 bridged");
        // The bridge feed is the local participants only (300) — never the bridged 1000 echoed back.
        assert_eq!(mixer.participant_mix(), &[300i16; 4], "100 + 200, no bridged audio");
    }

    #[test]
    fn output_for_falls_back_to_listener_mix() {
        let pcm = vec![vec![50i16; 4], vec![0i16; 4]];
        let roles = vec![Role::Talker, Role::Listener];
        let energy = vec![2_500i64, 0];
        let speaking = vec![true, false];
        let mut mixer = Mixer::new(2, 4);
        mixer.mix(&inputs(&pcm, &roles, &energy, &speaking, 4), &[], &[], 0);
        assert!(!mixer.has_distinct_output(1));
        assert_eq!(mixer.output_for(1), mixer.listener_mix());
    }

    proptest::proptest! {
        /// With no clipping (bounded inputs) every contributing talker's output plus its own frame
        /// equals the full room sum — the defining invariant of mixed-minus-self.
        #[test]
        fn minus_self_reconstructs_the_room_total(
            samples in proptest::collection::vec(-1000i16..=1000, 8usize),
        ) {
            let pcm = vec![samples[..4].to_vec(), samples[4..].to_vec()];
            let (roles, energy, speaking) = all_talkers(&pcm);
            let mut mixer = Mixer::new(2, 4);
            let active = mixer.mix(&inputs(&pcm, &roles, &energy, &speaking, 4), &[], &[], 0);
            proptest::prop_assert_eq!(active, 0b11);
            let out0 = mixer.output_for(0);
            let out1 = mixer.output_for(1);
            for (((&a, &b), &o0), &o1) in
                pcm[0].iter().zip(pcm[1].iter()).zip(out0.iter()).zip(out1.iter())
            {
                let total = i32::from(a) + i32::from(b);
                proptest::prop_assert_eq!(i32::from(o0) + i32::from(a), total);
                proptest::prop_assert_eq!(i32::from(o1) + i32::from(b), total);
            }
        }
    }
}
