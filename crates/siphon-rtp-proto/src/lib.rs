//! siphon-rtp control protocol — the wire contract between SIPhon and `siphon-rtp-engine`.
//!
//! This crate is shared by both ends (SIPhon depends on it directly), so the types here
//! *are* the contract. The native transport is length-prefixed JSON over a persistent TCP
//! connection: each frame is a big-endian `u32` byte length followed by a JSON body.
//!
//! Request/response are correlated by [`Request::id`]; asynchronous [`Event`]s are
//! server-initiated and carry no id. The verb set and session keying
//! (`call_id` / `from_tag` / `to_tag`) mirror the rtpengine NG semantics SIPhon already
//! speaks — only the encoding (JSON, not bencode) differs.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped on any breaking change to the message schema.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard ceiling on a single control frame (1 MiB). Guards against a corrupt length prefix.
/// SDP and play-media blobs are the only large payloads and stay well under this.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// serde `default` for a `bool` field that should default to `true`.
fn default_true() -> bool {
    true
}

/// A control request from SIPhon to the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Correlation id, echoed back in the matching [`Response`].
    pub id: u64,
    #[serde(flatten)]
    pub command: Command,
}

/// The control verbs. Internally tagged on `"command"`; a near-mechanical translation of
/// the rtpengine NG verb set SIPhon emits today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// SDP offer (A→B). Allocates media ports, rewrites SDP, returns the rewritten SDP.
    Offer {
        call_id: String,
        from_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// SDP **re-offer** on a live call (a SIP re-INVITE, RFC 3264 §8): renegotiate *on the existing
    /// media ports* rather than replacing the call.
    ///
    /// The distinction from a repeated [`Command::Offer`] matters. An `Offer` on a live call-id
    /// *replaces* it — the old call is torn down and the replacement binds fresh ports, so the peer
    /// must be told a new address. A `Reoffer` keeps the ports, so the dialog continues uninterrupted.
    /// That is what a re-INVITE needs, and it is what an RFC 8445 §9 **ICE restart** is detected from:
    /// a re-offer whose `a=ice-ufrag`/`a=ice-pwd` differ from the current ones restarts ICE while
    /// media keeps flowing on the previously selected pair.
    ///
    /// Owner-only, like every verb that touches a live call. Returns the rewritten SDP, advertising
    /// the same ports it already advertised (plus fresh ICE credentials when a restart was detected).
    Reoffer {
        call_id: String,
        from_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// A **trickled** ICE candidate from a peer, arriving after its offer or answer (RFC 8838).
    ///
    /// Browsers trickle: they send an offer immediately and stream candidates as they are gathered,
    /// rather than holding the offer until gathering finishes. Each one is paired against our local
    /// candidates and checked promptly (as a triggered check), so a path that only becomes known
    /// late is still used — including one that arrives after every earlier pair has failed.
    ///
    /// `to_tag` selects the side: absent for the offerer's (near) leg, present for the answerer's
    /// (far) leg — the same keying [`Command::Answer`] uses. Owner-only.
    ///
    /// The engine does not trickle candidates of its own: it gathers to completion before it answers
    /// (see `a=end-of-candidates` in its SDP), so there are none to send afterwards. It advertises
    /// `a=ice-options:trickle` because it *accepts* them — which is the half of RFC 8838 that
    /// matters against a browser.
    IceCandidate {
        call_id: String,
        from_tag: String,
        #[serde(default)]
        to_tag: Option<String>,
        /// The peer's `a=candidate:` lines, as they appeared in its signalling.
        #[serde(default)]
        candidates: Vec<String>,
        /// The peer signalled `a=end-of-candidates` — no more are coming.
        #[serde(default)]
        end_of_candidates: bool,
    },
    /// SDP answer (B→A). Completes negotiation; returns the rewritten SDP.
    Answer {
        call_id: String,
        from_tag: String,
        to_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Single-leg UAS answer — the engine *is* the far side (IVR / echo / announcement). Given the
    /// offerer's SDP (`sdp`) and no peer to answer for it, the engine allocates media, picks **one**
    /// negotiated audio codec from the offer (honouring `profile`'s codec policy and constrained to a
    /// codec this build can *encode* — RFC 3264 §6.1: the answer selects from the offered formats),
    /// synthesises the RFC 3264 answer advertising that single codec plus the telephone-event PT, and
    /// engages the transcoder now (PCM prompt → the chosen codec) rather than waiting for an answer
    /// that never comes. Returns the answer SDP on [`CmdResult::Ok`]. When no offered codec is
    /// encodable in this build it returns [`CmdResult::Error`] (the controller renders 488) — never a
    /// codec it cannot produce. Unlike [`Command::Answer`] there is no `to_tag`: there is no far leg.
    AnswerLocal {
        call_id: String,
        from_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Tear down a session (or one leg when `to_tag` is given).
    Delete {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Retrieve session statistics.
    Query {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Liveness check — answered with [`CmdResult::Pong`].
    Ping,
    /// Enumerate the live call-ids this engine is handling — answered with [`CmdResult::List`].
    /// A read-only census of the session registry (rtpengine NG `list`). Scoped to the calling
    /// control client: only the caller's own calls are returned (A3 — the same ownership gate that
    /// hides a call from `query`/`delete` by a non-owner; docs/security-and-nat.md §5).
    List,
    /// Read the engine's global process counters (calls offered/answered/deleted, current live
    /// sessions, control errors) — answered with [`CmdResult::Statistics`]. A read-only snapshot of
    /// the operational metrics surface (rtpengine NG `statistics`); process-wide, not per-client.
    Statistics,
    /// Report this engine's live load for cluster placement — answered with [`CmdResult::Load`]. The
    /// read-only snapshot a SIP media dispatcher polls to rank a pool of engines: live vs. maximum
    /// sessions, a normalized load score, the transcoding-call subset, allocator live bytes, host CPU
    /// (best effort), and whether the node is draining. Process-wide, not per-client.
    Load,
    /// Describe this engine's static identity and capabilities — answered with
    /// [`CmdResult::NodeInfo`]. Lets a dispatcher route a call only to a *capable* node: node id,
    /// advertised media addresses, supported codecs and features, session capacity, and version. It
    /// changes rarely, so a dispatcher reads it once and caches it (unlike [`Command::Load`]).
    NodeInfo,
    /// Enter drain mode: stop admitting **new** sessions ([`Command::Offer`] / [`Command::ConferenceJoin`]
    /// are rejected) while every live call runs to completion untouched — the primitive behind a
    /// zero-downtime rolling upgrade. Idempotent; answered with [`CmdResult::Ok`]. Reversed by
    /// [`Command::Undrain`].
    Drain,
    /// Leave drain mode: resume admitting new sessions. Idempotent; answered with [`CmdResult::Ok`].
    Undrain,
    /// Snapshot a live call's state for HA warm-standby failover — answered with
    /// [`CmdResult::Checkpoint`]. The reply carries an **opaque** blob (the engine owns its format);
    /// the SIP proxy stores it keyed by `call_id` and hands it back to [`Command::Restore`] on a
    /// standby if this node dies. Ownership-gated like [`Command::Query`]: only the owning client may
    /// checkpoint its call.
    Checkpoint { call_id: String, from_tag: String },
    /// Rebuild a call on this (standby) node from a blob produced by [`Command::Checkpoint`] —
    /// answered with [`CmdResult::Ok`]. (Handler lands in the restore slice; the verb is defined here
    /// so the contract is stable.)
    Restore { snapshot: String },
    /// Inject an audio prompt into a leg. Answers immediately (accept-on-start) with a
    /// [`CmdResult::Ok`] carrying a `play_id`; the eventual [`Event::PlayFinished`] carries the same
    /// `play_id` when the prompt ends (drained / stopped / superseded / aborted). A controller that
    /// wants to sequence a following action (e.g. echo) after the prompt awaits that event's
    /// `Completed` reason — the accept alone means "started", not "finished". The rtpengine NG
    /// front-end never consumes the event (fire-and-forget). Whether to await the completion is a
    /// controller-side concern; there is no on-the-wire "wait" flag.
    ///
    /// By default a prompt **supersedes** the party's egress: it replaces what that party hears, and
    /// starting a second one reports the first as [`PlayEndReason::Superseded`]. Set `overlay` to mix
    /// it *under* the live stream instead — ringback beneath a ringing leg, hold music beneath
    /// silence, a background bed beneath a conversation. Several overlays can run at once on one leg
    /// (see `overlay`); a superseding prompt is still one at a time.
    PlayMedia {
        call_id: String,
        from_tag: String,
        source: PlayMediaSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repeat_times: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        start_pos_ms: Option<u64>,
        /// Hard playout cap in milliseconds. The playback ends with [`PlayEndReason::Completed`]
        /// when the cap is reached, whichever comes first with the source running out. The only
        /// bound, short of a stop, on an endless ([`PlayMediaSource::Tone`] `*inf`) source.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        /// Mix this playback **under** the party's live egress instead of replacing it.
        ///
        /// Up to four overlays run concurrently per direction, each addressed by its own `play_id`
        /// for [`Command::StopMedia`] and [`Command::SetPlayGain`], and each ending with its own
        /// [`Event::PlayFinished`]. Starting a fifth is rejected with [`CmdResult::Error`] rather
        /// than displacing one — a controller that loses a playback it believes is running has no
        /// way to notice. An overlay never supersedes anything, including another overlay.
        #[serde(default, skip_serializing_if = "is_false")]
        overlay: bool,
        /// Playout gain in whole decibels, relative to the source's own level. Clamped to
        /// −60..=+12 dB; omitted means 0 dB (the source plays at its own level). Applies to
        /// superseding and overlay playback alike, and is adjustable in flight with
        /// [`Command::SetPlayGain`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gain_decibels: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Stop prompt playback on a leg.
    ///
    /// With no `play_id`, stops **everything** playing on the call — the superseding prompt, any
    /// DTMF burst, and every overlay — which is the original behaviour. With a `play_id`, stops only
    /// that one playback and leaves the others running, which is how one overlay is taken down
    /// without disturbing the bed underneath it. Each stopped playback reports
    /// [`PlayEndReason::Stopped`] on its own [`Event::PlayFinished`].
    StopMedia {
        call_id: String,
        from_tag: String,
        /// Stop only this playback (from a [`Command::PlayMedia`] accept). Absent ⇒ stop all.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        play_id: Option<u64>,
    },
    /// Retune the playout gain of a playback that is already running, addressed by the `play_id` its
    /// [`Command::PlayMedia`] accept returned — how a controller ducks a music bed under a prompt
    /// and lifts it again afterwards.
    ///
    /// A separate verb rather than a field on `play_media` because `play_media` is a *start*: reusing
    /// it would mean "start another playback", not "change this one". `play_id` is already the
    /// contract's handle on a running playback (it is what [`Event::PlayFinished`] correlates and
    /// what [`Command::StopMedia`] targets), so gain is addressed the same way. Answered with
    /// [`CmdResult::Ok`], or [`CmdResult::Error`] when no playback on the call holds that id.
    SetPlayGain {
        call_id: String,
        from_tag: String,
        /// The running playback to retune.
        play_id: u64,
        /// New gain in whole decibels, clamped to −60..=+12 the same way the start value is.
        gain_decibels: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Inject DTMF (RFC 4733 telephone-events) toward a leg. `code` is played in full as a sequence,
    /// one telephone-event per digit (`0`-`9`, `*`, `#`, `A`-`D`), each `duration_ms` long at
    /// `volume_dbm0`, separated by `pause_ms` of inter-digit silence (each digit is a distinct event
    /// with its own start timestamp, RFC 4733 §2.5.1.2). The target leg is the one named by `from_tag`
    /// or `to_tag` (the call's to-tag ⇒ leg B). A non-DTMF character in `code` is rejected.
    PlayDtmf {
        call_id: String,
        from_tag: String,
        /// The digit string to play, e.g. `"1234#"` — every character is played, not just the first.
        code: String,
        /// Per-digit event length in milliseconds (default 250).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        /// Playout level as a (negative) dBm0 power; the generator uses its magnitude (0..=63).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        volume_dbm0: Option<i64>,
        /// Inter-digit silence in milliseconds between consecutive events (default 40).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pause_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Replace outgoing audio with comfort silence.
    SilenceMedia { call_id: String, from_tag: String },
    /// Resume forwarding original audio after [`Command::SilenceMedia`].
    UnsilenceMedia { call_id: String, from_tag: String },
    /// Drop outgoing packets entirely (no audio, not even silence).
    BlockMedia { call_id: String, from_tag: String },
    /// Resume forwarding after [`Command::BlockMedia`].
    UnblockMedia { call_id: String, from_tag: String },
    /// Stop relaying one leg's RFC 4733 telephone-event (DTMF) packets to the peer while still
    /// detecting them (rtpengine `block DTMF`). `from_tag` names the blocked source leg; `to_tag`,
    /// when present, disambiguates which dialog side is meant (it matches the call's to-tag ⇒ leg B).
    /// The digit is still surfaced to the controller as an `Event::Dtmf` (observability) — only the
    /// egress relay toward the peer is suppressed. v1 = drop mode (rtpengine's replace-with-tone/PCM
    /// modes are a follow-up). Rejected on a secure (SRTP) or WebSocket-bridged call, whose DTMF is
    /// not carried as clear telephone-events.
    BlockDtmf {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Resume relaying a leg's telephone-events after [`Command::BlockDtmf`] (rtpengine `unblock DTMF`).
    UnblockDtmf {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Loop a leg's inbound audio straight back to itself (the classic echo test).
    /// `enabled` defaults to `true`; send `false` to stop echoing and resume normal
    /// forwarding. A single-leg IVR/echo call is a plain relay; enabling echo promotes it
    /// into the userspace media pipeline (decode → re-encode) so its audio can be looped —
    /// the same way [`Command::StartRecording`] promotes a relay so it can be tapped — then
    /// demotes it back to the fast path when disabled. DTMF detection and media-timeout
    /// still fire while echoing.
    Echo {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        #[serde(default = "default_true")]
        enabled: bool,
    },
    /// Begin recording an established call's media to a `.pcap` at runtime (rtpengine
    /// `start recording`). Unlike the offer/answer `record_call` flag, this toggles recording on a
    /// live call: a plain relay is promoted to the userspace media pipeline so its packets can be
    /// tapped, and each accepted RTP/RTCP datagram is captured verbatim (raw wire bytes, any codec).
    /// The pcap is written under `recording_dir` (the request's `recording-dir` flag). Rejected on a
    /// secure (SRTP) or WebSocket-bridged call, whose on-the-wire bytes are not the clear media.
    StartRecording {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recording_dir: Option<String>,
    },
    /// Stop a runtime recording started with [`Command::StartRecording`] (rtpengine `stop recording`):
    /// finalize the `.pcap` and demote the relay back to the fast path if nothing else holds it.
    StopRecording { call_id: String, from_tag: String },
    /// Create a media subscription (SIPREC / MPTY). `from_tags` may list multiple legs.
    SubscribeRequest {
        call_id: String,
        from_tags: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp: Option<String>,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Complete a subscription's SDP negotiation.
    SubscribeAnswer {
        call_id: String,
        from_tag: String,
        to_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Tear down a subscription.
    Unsubscribe {
        call_id: String,
        from_tag: String,
        to_tag: String,
    },
    /// Join (or lazily create) an audio conference (MCU). The participant offers SDP and, on the
    /// answer, hears the room's mixed-minus-self audio; `role` places it in the audio routing matrix.
    ConferenceJoin {
        conference_id: String,
        from_tag: String,
        sdp: String,
        #[serde(default)]
        role: ConferenceRole,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Leave a conference (by participant `from_tag`). The room is torn down when its last participant
    /// leaves.
    ConferenceLeave {
        conference_id: String,
        from_tag: String,
    },
    /// Live-update a participant's conference role / routing (mute, whisper, supervisor monitor, …).
    ConferenceRoute {
        conference_id: String,
        from_tag: String,
        role: ConferenceRole,
    },
    /// Bridge two conferences (plan §7 room bridging) so each room hears the other's participants,
    /// in the given direction(s).
    ConferenceBridge {
        conference_id_a: String,
        conference_id_b: String,
        #[serde(default)]
        direction: BridgeDirection,
    },
    /// Attach a **WebSocket tee** to a live call: stream its decoded audio to `ws_uri` while the call
    /// keeps relaying. Unlike `ProfileFlags::ws_uri` (takeover — the WS server *becomes* leg A's far
    /// side and A↔B is not wired), a tee is send-only and additive: the relay/transcode path, any
    /// SIPREC subscription, and the recording all continue untouched. A plain in-kernel relay is
    /// promoted to the userspace media pipeline for the tee's lifetime and demoted again on detach.
    /// A native siphon-rtp extension — the NG/bencode front-end does not carry it.
    AttachWsTee {
        call_id: String,
        from_tag: String,
        /// `ws://` or `wss://` URI of the media server the engine dials as a client.
        ws_uri: String,
        /// Which leg(s) to stream (default: both).
        #[serde(default)]
        direction: WsTeeDirection,
        /// Wire channel count: `2` interleaves caller/callee as stereo, `1` mixes them to mono. Only
        /// meaningful with `direction = both`; a single-leg tee is always mono. `None` ⇒ 2 for both
        /// legs, 1 for one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channels: Option<u8>,
        /// L16 wire sample rate in Hz, **independent of the leg's codec rate**: the engine resamples
        /// each tapped leg's decoded PCM into it, so an 8 kHz G.711 call can be streamed at 16 kHz.
        /// Must be a multiple of 1000 within 8000–48000; anything else is rejected at attach time
        /// rather than clamped, and the call keeps relaying untouched. `None` ⇒ today's behaviour:
        /// follow the tapped leg's own codec PCM rate (no conversion, no cost). Whatever is
        /// negotiated is what the WS `start` frame's `media.sampleRate` and the `ws_tee_started`
        /// event's `sample_rate` report.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sample_rate: Option<u32>,
    },
    /// Detach the WebSocket tee from a call, closing its stream. Idempotent: detaching a call with no
    /// tee is not an error.
    DetachWsTee { call_id: String, from_tag: String },
    /// Authenticate the control connection with the server's shared secret. Handled by the control
    /// server (not the session engine); required as the first command when a secret is configured.
    Authenticate { token: String },
}

/// Which leg(s) of a call a [`Command::AttachWsTee`] streams. "Caller" is the offerer (leg A, the
/// `from_tag` side); "callee" is the answerer (leg B).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsTeeDirection {
    /// Both legs — stereo (channel 0 = caller, channel 1 = callee) unless `channels = 1` mixes them.
    #[default]
    Both,
    /// Only the caller's (offerer's) audio, as a mono monologue.
    Caller,
    /// Only the callee's (answerer's) audio, as a mono monologue.
    Callee,
}

/// Which voice-activity detector the WS uplink runs (`ProfileFlags::ws_vad_engine`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsVadEngine {
    /// Mean-square energy against a threshold, with a trailing hangover. Cheap and exact, but it
    /// answers "is something loud here", so breathing, mains hum, fan noise and uncancelled echo
    /// all read as speech. The default, and the right choice when a false turn start is harmless.
    #[default]
    Energy,
    /// A neural speech classifier (the Silero v5 network, hand-written in pure Rust and embedded —
    /// no inference runtime, no extra deployment artifact). Answers "is what is here speech", so it
    /// does not turn-start on non-speech noise. Runs on its own 32 ms cadence fed from the frame
    /// clock, which puts the turn-detection floor at 32 ms plus up to one media frame; costs tens
    /// of microseconds per window per call. Pick it for turn taking and barge-in.
    Neural,
}

/// Why a WebSocket tee stream ended, carried by [`Event::WsTeeEnded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsTeeEndReason {
    /// The controller detached it ([`Command::DetachWsTee`]) or the call was torn down.
    Detached,
    /// The WS server closed the connection.
    ServerClosed,
    /// The WS server sent a `stop` control frame.
    ServerStopped,
    /// The call's media path went away, so no further audio can be teed.
    CallEnded,
    /// A WebSocket/transport error ended the stream.
    TransportError,
}

/// A participant's role in a conference — the audio routing matrix (call-centre / PBX). Tagged on
/// `"role"`. The symmetric "everyone hears everyone" conference is the [`ConferenceRole::Talker`] case.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum ConferenceRole {
    /// Hears the room (mixed-minus-self) and is heard — a normal participant (the default).
    #[default]
    Talker,
    /// Hears the room, contributes nothing (a webinar attendee / music-on-hold).
    Listener,
    /// Seated but muted — hears the room, contributes nothing.
    Muted,
    /// Whispers privately to one participant (supervisor coaching). Excluded from the public room mix.
    Whisper { target: String },
    /// Monitors one participant directly (supervisor listen), the target unaware; may also whisper.
    Monitor {
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        whisper_target: Option<String>,
    },
}

/// The direction(s) audio flows across a conference bridge ([`Command::ConferenceBridge`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    /// Both rooms hear each other (the default).
    #[default]
    Both,
    /// Only room A's participants are heard in room B.
    AToB,
    /// Only room B's participants are heard in room A.
    BToA,
}

/// Source for [`Command::PlayMedia`]. Tagged on `"source"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum PlayMediaSource {
    /// A path on the engine host.
    File { path: String },
    /// Raw audio bytes carried inline.
    Blob {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    /// A prompt id in the engine's media database.
    DbId { id: u64 },
    /// A synthesised call-progress tone — no audio file to ship or provision.
    ///
    /// `tone` is either a **preset name** (`ringback_eu`, `busy_na`, `dial_uk`, …) or an explicit
    /// **cadence spec** in the engine's tone grammar, e.g. `425/1000,0/4000*inf` for 425 Hz one
    /// second on, four seconds off, forever. The two are told apart by the `/`: a preset name never
    /// contains one and a cadence spec is never valid without one. A tone is rendered directly at
    /// the leg's codec rate, so it is never resampled. See `docs/control/json.md` for the preset
    /// table (with the standard each entry comes from) and the grammar.
    Tone { tone: String },
    /// A WAV fetched over HTTP or HTTPS by the **engine**, from the engine's own network position.
    ///
    /// The fetch is bounded — connect timeout, first-byte timeout, overall deadline, response-size
    /// cap and a redirect cap, all configurable on the daemon — and runs off the media path, so a
    /// URL that never answers can never stall the leg. `play_media` accepts immediately with a
    /// `play_id` and `duration_ms` absent (the length is not known until the body has arrived); a
    /// fetch that fails for any reason ends the playback with
    /// [`Event::PlayFinished`]`{ reason: error }` carrying that `play_id`.
    ///
    /// Only `http://` and `https://` are accepted. The engine fetches from wherever it sits, so an
    /// operator who does not fully trust the controller should restrict the reachable hosts — see
    /// the security note in `docs/control/json.md`.
    Http { url: String },
}

/// Per-leg media-handling flags. JSON twin of SIPhon's `NgFlags` (rtpengine profile).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFlags {
    /// e.g. `RTP/AVP`, `RTP/SAVP`, `RTP/AVPF`, `RTP/SAVPF`, `UDP/TLS/RTP/SAVPF`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_protocol: Option<String>,
    /// `remove` | `force` | `force-relay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ice: Option<String>,
    /// `passive` | `active` | `off`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtls: Option<String>,
    /// SDP fields to rewrite (e.g. `["origin"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replace: Vec<String>,
    /// Address family for the **far** (outbound) leg's engine endpoints (`"IP4"` | `"IP6"`), for
    /// IPv4↔IPv6 interworking — e.g. a v6 VoLTE access leg bridged to a v4 PSTN core. When unset the
    /// far leg uses the offer's family (single-family relay). The near leg always follows the offerer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_family: Option<String>,
    /// Behavioral flags (e.g. `trust-address`, `symmetric`, `port-latching`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// NAT leg designation pair (e.g. `["external", "internal"]`), reversed on answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direction: Vec<String>,
    /// Whether to record this call leg.
    #[serde(default, skip_serializing_if = "is_false")]
    pub record_call: bool,
    /// Recording output directory/path, when recording.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_path: Option<String>,
    /// Apply single-channel noise suppression to this call's decoded ingress audio before it is
    /// transcoded/relayed toward the peer (and captured by recording/forks). Engaged only where the
    /// leg is transcoded through userspace and the ingress codec's native rate is 8 or 16 kHz (the
    /// rates the suppressor supports) — inert on an in-kernel passthrough or a 48 kHz codec. Setting
    /// it forces the call out of the in-kernel fast path onto the media slow path, exactly as
    /// `record_call` does. A native siphon-rtp extension — the NG/bencode front-end does not set it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub noise_suppression: bool,
    /// Apply acoustic/line echo cancellation (`siphon-rtp-dsp`'s `EchoCanceller`) to this leg's
    /// **send** path, using the audio played *toward* that party as the far-end reference. On a
    /// transcoding (or promoted same-codec) call the engine cancels each party's decoded uplink echo
    /// in the near-end codec domain (pre-resample/re-encode) before it is forwarded to the peer, the
    /// reference being the reverse direction's egress PCM (what the engine sent toward that party);
    /// on a WebSocket voice-AI bridge it cancels the phone uplink toward the AI using the AI downlink
    /// as the reference. The canceller runs at the codec's native rate — narrowband 8 kHz or wideband
    /// 16 kHz (G.711, AMR-WB, G.722) — so a codec at another rate passes through uncancelled. Like
    /// `noise_suppression`, setting it on a same-codec plaintext call promotes it from the in-kernel
    /// relay to the userspace media pipeline (decode → cancel → re-encode). A native siphon-rtp
    /// extension — the NG/bencode front-end does not set it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub echo_cancellation: bool,
    /// Watch this call's decoded ingress audio for the short single tone an answering machine plays
    /// before it starts recording (the "voicemail beep"), and report it as [`Event::BeepDetected`].
    /// The media half of answering-machine detection: a controller that gets the event can abort an
    /// attended transfer instead of bridging the caller into a voicemail box.
    ///
    /// Set per leg — the flag arms the detector on the leg the `offer`/`answer` carrying it names, so
    /// arming it on the outbound (callee) leg is what watches the party that might be a machine. Like
    /// `noise_suppression` / `echo_cancellation` it needs decoded audio, so setting it promotes a
    /// same-codec plaintext call from the in-kernel relay to the userspace media pipeline; it is
    /// inert on a codec whose native rate is neither 8 nor 16 kHz. The event fires **once** per leg
    /// per call — there is no mid-call re-arm. A native siphon-rtp extension — the NG/bencode
    /// front-end does not set it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub beep_detection: bool,
    /// How long, in milliseconds, the beep detector waits after a candidate tone ends to confirm no
    /// repeat follows it — the discriminator that keeps a cadenced ringback / busy / congestion /
    /// special-information tone from reading as a record tone. It is also the detection latency: the
    /// event arrives this long after the beep. `None` uses the engine default (4500 ms, longer than
    /// the 4 s silent interval of the slowest widely deployed ringback cadence). Lower it to trade
    /// cadence robustness for latency. Inert without `beep_detection`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beep_cadence_guard_ms: Option<u32>,
    /// Attach this call's offerer (leg A) audio to an external WebSocket media server (the
    /// mod_audio_stream / voice-AI integration). When set on `offer`/`answer`, the engine dials this
    /// URI as a WebSocket client and bridges leg A's RTP to it (decode → L16 uplink, L16 downlink →
    /// encode); the A↔B relay/transcode path is not wired in this mode (the WS server is A's far
    /// side). A native siphon-rtp extension — the NG/bencode front-end does not set it. Both `ws://`
    /// and `wss://` (TLS on ring/rustls, trust from the webpki-roots CA bundle) are dialled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_uri: Option<String>,
    /// Run a local energy-VAD on the WS voice-AI uplink (`ws_uri`): the bridge emits
    /// `speech_started` / `speech_stopped` control frames on the caller's speech edges, so the
    /// inference server gets turn boundaries (and the turn **endpoint**) without running its own VAD —
    /// lower turn latency. Inert without `ws_uri`. A native siphon-rtp extension; the NG/bencode
    /// front-end does not set it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ws_vad: bool,
    /// Local barge-in on the WS voice-AI leg: when the caller starts speaking, the bridge flushes the
    /// queued downlink playout in the same tick (no server round-trip) and notifies the server via
    /// `speech_started`. Implies `ws_vad`. Inert without `ws_uri`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ws_barge_in: bool,
    /// Mean-square energy threshold for the WS uplink VAD. `None` uses a sensible 8/16 kHz L16 default
    /// (~1_000_000); higher is less sensitive. Only meaningful with `ws_vad` / `ws_barge_in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_threshold: Option<i64>,
    /// Trailing hangover for the WS uplink VAD, in milliseconds — how long speech is held after energy
    /// drops before `speech_stopped` (the turn endpoint) fires. `None` uses ~200 ms. Only meaningful
    /// with `ws_vad` / `ws_barge_in`, and only with the `energy` detector (the `neural` one holds
    /// speech with its own probability hysteresis instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_hangover_ms: Option<u32>,
    /// L16 wire sample rate in Hz for the `ws_uri` takeover bridge, **independent of the leg's codec
    /// rate** and applied in **both** directions: the engine resamples leg A's decoded uplink into it
    /// and resamples the server's downlink playout back into the leg's codec rate before re-encoding.
    /// So an 8 kHz G.711 call can speak 16 kHz L16 to the server, and a server rendering 24 kHz audio
    /// into that call is played at the right speed and pitch instead of the wrong one. It is also the
    /// domain the uplink noise suppressor and echo canceller run in — the audio the far side actually
    /// hears — and those engage only at 8 or 16 kHz, so another rate leaves them off without changing
    /// the wire rate. Must be a multiple of 1000 within 8000–48000; anything else fails the
    /// offer/answer rather than being clamped. `None` ⇒ today's behaviour: the leg codec's own PCM
    /// rate (8000 for G.711, 16000 for G.722/AMR-WB), with no conversion in either direction. Inert
    /// without `ws_uri`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_sample_rate: Option<u32>,
    /// Which detector the WS uplink VAD runs. `None` ⇒ [`WsVadEngine::Energy`], the historical
    /// behaviour. Only meaningful with `ws_vad` / `ws_barge_in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_engine: Option<WsVadEngine>,
    /// **Leading** minimum-speech run, in milliseconds: how long the uplink must read as speech
    /// *continuously* before the `speech_started` edge (and barge-in) fires. `None` ⇒ no leading
    /// requirement, i.e. the edge fires on the first speech frame, which is what lets a cough, a
    /// door or one burst of echo interrupt a prompt. Rounded up to whole ptime frames, and it adds
    /// directly to turn-start latency, so 60–120 ms is the useful range. Works with either
    /// detector. Only meaningful with `ws_vad` / `ws_barge_in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_min_speech_ms: Option<u32>,
    /// Observe this call's RFC 4103 Real-Time Text (`m=text`) stream at the control plane: when set (and
    /// the call negotiated a plaintext text stream and the owner has an event sink), the engine promotes
    /// **only** the low-rate text stream to a userspace processor that RED-depacketizes + reassembles it
    /// and emits [`Event::Text`] per recovered increment, plus per-leg [`TextStreamStats`] in the
    /// end-of-call [`Event::CallSummary`]. The audio relay/transcode path is untouched — text
    /// observability never promotes audio. Inert on an audio-only call. Recording (`start recording`)
    /// promotes the text stream too, independently of this flag. A native siphon-rtp extension — the
    /// NG/bencode front-end does not set it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub text_events: bool,
    /// The real post-NAT source IP the SIP proxy saw this request arrive from (rtpengine's
    /// `received-from`). When a NATed UA advertises a private `c=` address, its media actually
    /// originates from its NAT's *public* IP — this is that IP. The engine gates the leg's ingress to
    /// it, a **tighter** RTPBleed source gate than the (unusable) signalled private address would
    /// yield (docs/security-and-nat.md §4 layer 2). Only the IP is carried — the media port differs
    /// from the signalling port, so the port is never gated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_from: Option<std::net::IpAddr>,
    /// Attach a **WebSocket tee** to this call at offer/answer time — the declarative twin of
    /// [`Command::AttachWsTee`], so a controller does not need a second round-trip. Unlike `ws_uri`
    /// (takeover), a tee is send-only and leaves the A↔B relay/transcode path wired: the call relays
    /// normally *and* streams its decoded audio to this URI. Applied once the call's media path exists
    /// (i.e. on `answer` / `answer_local`), and torn down with the call. A native siphon-rtp extension
    /// — the NG/bencode front-end does not set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_tee: Option<String>,
    /// Which leg(s) `ws_tee` streams. `None` ⇒ both. Inert without `ws_tee`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_tee_direction: Option<WsTeeDirection>,
    /// Wire channel count for `ws_tee`: `2` = stereo caller/callee, `1` = mixed mono. `None` ⇒ 2 when
    /// both legs are teed, 1 for a single leg. Inert without `ws_tee`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_tee_channels: Option<u8>,
    /// L16 wire sample rate in Hz for `ws_tee` — the declarative twin of
    /// [`Command::AttachWsTee`]'s `sample_rate`, and independent of either leg's codec rate: each
    /// tapped leg's decoded PCM is resampled into it before framing. Must be a multiple of 1000
    /// within 8000–48000; anything else fails the answer rather than being clamped. `None` ⇒ today's
    /// behaviour: follow the tapped leg's own codec PCM rate. Inert without `ws_tee`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_tee_sample_rate: Option<u32>,
    /// rtpengine `rtcp-mux` directive list (`offer` | `require` | `demux` | `accept` | `reject` |
    /// `remove`), letting the controller override the mux decision derived from the offered SDP
    /// (RFC 5761). Empty ⇒ mirror the offer (the default). See [`crate`] callers / the engine's
    /// `offer`/`answer` for the per-side resolution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rtcp_mux: Vec<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A response to a [`Request`], correlated by [`Response::id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(flatten)]
    pub result: CmdResult,
}

/// The result payload of a [`Response`]. Tagged on `"result"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CmdResult {
    /// Success. Fields are populated per the originating command.
    Ok {
        /// Rewritten SDP (offer / answer / subscribe).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp: Option<String>,
        /// Duration of injected media (play_media).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        /// The accepted playback's identifier (play_media). Unique per active playback on a
        /// `(call_id, from_tag)` leg; the matching [`Event::PlayFinished`] carries the same value so a
        /// controller correlates the completion with the accept it awaited.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        play_id: Option<u64>,
        /// UAS To-tag (subscribe_request / siprec).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        /// Session statistics (query).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stats: Option<SessionStats>,
    },
    /// Answer to [`Command::Ping`].
    Pong,
    /// Answer to [`Command::List`]: the live call-ids the calling client owns. Order is unspecified
    /// (the registry is unordered); an empty list means the client has no live calls.
    List { call_ids: Vec<String> },
    /// Answer to [`Command::Statistics`]: the engine's global process counters.
    Statistics { statistics: EngineStatistics },
    /// Answer to [`Command::Load`]: this engine's live load snapshot for cluster placement.
    Load { load: NodeLoad },
    /// Answer to [`Command::NodeInfo`]: this engine's static identity and capabilities.
    NodeInfo { node: NodeInfo },
    /// Answer to [`Command::Checkpoint`]: the opaque HA snapshot blob for the call. The engine owns
    /// the format; the proxy stores it verbatim and returns it via [`Command::Restore`].
    Checkpoint { snapshot: String },
    /// Failure with a human-readable reason.
    Error { reason: String },
}

/// Global, process-wide engine counters returned by [`Command::Statistics`]. A read-only snapshot of
/// the operational metrics surface (the same monotonic counters the `/metrics` endpoint renders),
/// plus the live session gauge — never per-call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStatistics {
    /// Total `offer` commands accepted since start (monotonic).
    pub offers_total: u64,
    /// Total `answer` commands accepted since start (monotonic).
    pub answers_total: u64,
    /// Total `delete` commands accepted since start (monotonic).
    pub deletes_total: u64,
    /// Total control commands that returned an error result since start (monotonic).
    pub control_errors_total: u64,
    /// Live calls currently in the session registry (a gauge, not a running total).
    pub sessions: u64,
}

/// This engine's live load, returned by [`Command::Load`] — the cluster-placement view a SIP media
/// dispatcher polls to pick the least-loaded node capable of a call. Every figure is an integer, so
/// the payload compares exactly across the wire (no float ambiguity in a dispatcher's ranking).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLoad {
    /// Stable identifier for this engine instance (config `node_id`).
    pub node_id: String,
    /// Live calls currently in the session registry (a gauge).
    pub sessions: u64,
    /// Configured maximum concurrent sessions; `0` means "unlimited / not advertised".
    pub max_sessions: u64,
    /// Normalized load in per-mille (0..=1000), where 1000 means at or over capacity. A dispatcher
    /// ranks nodes by this single figure; it folds session utilization with host CPU (when known),
    /// taking whichever is higher — the tighter of the two constraints.
    pub load_permille: u16,
    /// The subset of live sessions that are transcoding — the expensive calls, distinct from plain
    /// relay — so a dispatcher can weight a node's real cost, not just its raw call count.
    pub transcode_sessions: u64,
    /// Host CPU utilization in per-mille (0..=1000), best effort; `None` when unavailable (no sampler
    /// running yet, or a platform without `/proc/stat`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_permille: Option<u16>,
    /// Live bytes allocated (jemalloc `stats.allocated`); `0` when the allocator surface is
    /// unavailable. A steady climb at flat session count signals a leak (see the memory-leak gate).
    pub jemalloc_allocated_bytes: u64,
    /// Whether this node is draining (rejecting new sessions); skip a draining node for placement
    /// even at low load.
    pub draining: bool,
}

/// This engine's static identity and capabilities, returned by [`Command::NodeInfo`]. A dispatcher
/// reads it once (it rarely changes) to route a call only to a node that can actually serve it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Stable identifier for this engine instance (config `node_id`).
    pub node_id: String,
    /// Engine software version (the daemon crate version).
    pub version: String,
    /// Media addresses this engine advertises for relayed RTP — the reachable IPs a peer sends to.
    pub media_addresses: Vec<String>,
    /// Codecs this build can relay/transcode (RTP payload names, e.g. `PCMU`, `AMR-WB`).
    pub codecs: Vec<String>,
    /// Capability flags this build ships (e.g. `relay`, `transcode`, `srtp`, `conference`).
    pub features: Vec<String>,
    /// Configured maximum concurrent sessions; `0` means "unlimited / not advertised".
    pub max_sessions: u64,
    /// Whether this node is currently draining.
    pub draining: bool,
}

/// Session statistics returned by [`Command::Query`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Packets dropped (jitter overflow, late, malformed).
    pub packets_lost: u64,
}

/// One leg's end-of-call figures in an [`Event::CallSummary`]: the datapath byte/packet counters,
/// plus — when a userspace media actor measured it — the RFC 3550 reception quality and ITU-T G.107
/// MOS. The quality fields are omitted (`None`) on a leg with no actor (a plain in-kernel relay) or one
/// that never received media, so a consumer can tell "counters only" from "measured". `mos_basis` is
/// `"full"` when the MOS includes the G.107 delay term (an RTT was measured), else `"loss+jitter"`.
///
/// (No `Eq`: the MOS / loss / jitter figures are `f64`. `PartialEq` still derives.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegSummary {
    /// The leg's tag: the offerer's `from_tag` (near) or the answerer's `to_tag` (far). On a
    /// single-leg call the sole entry carries the caller's `from_tag`.
    pub tag: String,
    /// The leg's negotiated audio codec name, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    pub packets_in: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub bytes_out: u64,
    /// Packets dropped on the engine's side of this leg (source-gate / latch / jitter overflow), not
    /// network loss — see `packets_lost` for the RFC 3550 network-loss estimate.
    pub packets_dropped: u64,
    /// The inbound stream's SSRC (RFC 3550), when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssrc: Option<u32>,
    /// Cumulative network packets lost on the inbound stream (RFC 3550 §6.4.1), when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_lost: Option<u32>,
    /// Inbound network packet loss as a percentage, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_percent: Option<f64>,
    /// Inbound interarrival jitter in milliseconds (RFC 3550 §6.4.1), when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<f64>,
    /// Engine↔peer round-trip time in milliseconds, when a reception report yielded one (absent on the
    /// relay/transcode path without RTCP RTT — the MOS is then `loss+jitter`-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    /// Mean / lowest / highest ITU-T G.107 MOS across the call, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mos_average: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mos_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mos_max: Option<f64>,
    /// `"full"` (MOS includes the G.107 delay term) or `"loss+jitter"` — how the MOS was derived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mos_basis: Option<String>,
    /// RFC 4103 Real-Time Text reception counters for this leg's **inbound** T.140 stream, present only
    /// when the call negotiated a plaintext `m=text` stream *and* a text-observability feature promoted
    /// it to the userspace text processor (recording, or `text_events`). `None` for an audio-only call,
    /// or a text stream left on the in-kernel relay (which contributes datapath packet/byte counts but
    /// no content-level text QoS — that is only measured when text is promoted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<TextStreamStats>,
}

/// RFC 4103 Real-Time Text reception counters for one leg's inbound T.140 stream, measured by the
/// userspace text processor (RED depacketization + T.140 reassembly) when text observability is active.
/// A content-level QoS surface distinct from the datapath's packet/byte counters: it reports what the
/// receiver actually recovered, including redundancy recovery and unrecoverable-loss markers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextStreamStats {
    /// RTP packets accepted on this leg's inbound text stream (post source-gate).
    pub packets: u64,
    /// UTF-8 characters delivered to the far side after reassembly — includes characters recovered from
    /// RED redundancy and the U+FFFD missing-text markers (a consumer sees where loss occurred).
    pub characters: u64,
    /// Missing-text markers (U+FFFD) inserted for gaps redundancy could not recover (RFC 4103 §5.3).
    pub missing_markers: u64,
    /// Generations recovered from RFC 2198 RED redundancy (RFC 4103 §4.2 / §5) — loss the redundant
    /// copies repaired before it reached the receiver.
    pub recovered_from_redundancy: u64,
}

/// How a [`Command::PlayMedia`] playback ended, carried by [`Event::PlayFinished`]. Only
/// [`PlayEndReason::Completed`] means the prompt played out in full; the others resolve a controller's
/// await as *not* completed (the prompt did not finish on its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlayEndReason {
    /// The prompt drained naturally — all repeats done, or the `duration_ms` cap was hit.
    Completed,
    /// Ended by [`Command::StopMedia`].
    Stopped,
    /// A newer [`Command::PlayMedia`] replaced this one on the same leg.
    Superseded,
    /// Playback aborted — a decode / source error, or the leg was torn down mid-play.
    Error,
}

/// An asynchronous event pushed from the engine to SIPhon (no request correlation).
/// `#[serde(other)]` keeps forward-compatibility: SIPhon tolerates new event kinds.
///
/// (No `Eq`: [`Event::CallQuality`] carries `f64` quality figures. `PartialEq` still derives, so
/// `assert_eq!` in tests and value comparisons keep working.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A DTMF digit was detected on a leg. Deserializes 1:1 into SIPhon's `DtmfEvent`.
    Dtmf {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        digit: String,
        duration_ms: u32,
        volume: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    /// Newly-recovered RFC 4103 Real-Time Text (T.140) on a call's `m=text` stream, emitted by the
    /// userspace text processor as it RED-depacketizes + reassembles the stream. `text` is the UTF-8
    /// increment newly delivered by *this* packet ([`crate`] emits only non-empty increments, so a
    /// duplicate/reordered packet or idle keepalive produces no event); any U+FFFD marker stays in the
    /// text so a consumer sees where loss occurred (RFC 4103 §5.3). `from_tag` identifies the leg that
    /// *sent* the text; `direction` is `"a_to_b"` / `"b_to_a"` for the observed direction. Additive,
    /// snake_case-tagged, forward-compatible — the same `Vec<Event>` plumbing as [`Event::Dtmf`].
    Text {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        direction: Option<String>,
    },
    /// A call's media went silent past the timeout and the engine tore it down (dead-path
    /// detection). Lets SIPhon release its own per-call state.
    MediaTimeout { call_id: String, from_tag: String },
    /// A [`Command::PlayMedia`] playback ended. Carries the `play_id` the play's accept returned, so a
    /// controller awaiting a specific prompt matches the completion to the accept it holds — the
    /// load-bearing correlation, since a leg may play several prompts in sequence. `reason` says *how*
    /// it ended: only [`PlayEndReason::Completed`] means the prompt played out in full (all repeats /
    /// the `duration_ms` cap); `Stopped` / `Superseded` / `Error` resolve the await as not-completed so
    /// a script does not run its next step on a prompt that never finished.
    PlayFinished {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        /// Correlates with the `play_id` returned by the [`Command::PlayMedia`] accept.
        play_id: u64,
        reason: PlayEndReason,
        /// Actual played duration in milliseconds, for observability / CDR. `None` when not tracked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        played_ms: Option<u64>,
    },
    /// The active (dominant) speaker in a conference changed. `from_tag` is the new speaker's leg
    /// tag, or `None` when the floor went silent (no one speaking). Drives floor control / UI.
    ActiveSpeaker {
        conference_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_tag: Option<String>,
    },
    /// Periodic per-leg reception-quality estimate (RFC 3550 RTCP statistics + ITU-T G.107 MOS), so
    /// SIPhon surfaces live call quality without parsing RTCP itself. Emitted every few seconds for
    /// every relayed leg — a conference participant, a 2-party plain-relay call, or a transcode call.
    ///
    /// The event carries **exactly one** stream identifier: `conference_id` for a conference
    /// participant, or `call_id` for a 2-party (relay/transcode) call — never both, never neither.
    /// Both are optional and `skip_serializing_if` the absent one, so a conference event's wire form
    /// stays byte-identical to before this field split (a consumer that ignores the absent field is
    /// unaffected — additive, backward-compatible).
    CallQuality {
        /// The conference this participant belongs to, for a conference-leg quality report. `None`
        /// on a 2-party (relay/transcode) call, where `call_id` identifies the stream instead.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conference_id: Option<String>,
        /// The call this leg belongs to, for a 2-party plain-relay or transcode quality report. `None`
        /// on a conference participant, where `conference_id` identifies the stream instead.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_id: Option<String>,
        from_tag: String,
        /// Interarrival jitter in milliseconds (RFC 3550 §6.4.1).
        jitter_ms: f64,
        /// Residual inbound packet loss, as a percentage.
        loss_percent: f64,
        /// Estimated MOS-CQE (ITU-T G.107), in `1.0..=4.5`.
        mos: f64,
    },
    /// End-of-call summary (CDR), emitted once when a call is torn down (controller `delete` or the
    /// media-timeout reaper). Carries the per-leg byte/packet counters and, for a transcode/relay call
    /// with a userspace media actor, the RFC 3550 loss/jitter and ITU-T G.107 MOS shape across the
    /// call — the structured twin of the `siphon_rtp::cdr` log block, so SIPhon writes one merged CDR
    /// (its SIP side plus this media side) without scraping logs. Additive: a consumer predating this
    /// variant decodes it as [`Event::Unknown`] and ignores it.
    CallSummary {
        call_id: String,
        /// Why the call ended: `"delete"` (controller teardown) or `"media_timeout"` (dead-path reap).
        reason: String,
        /// Call lifetime in milliseconds (logical-clock resolution, ~1 s granularity).
        duration_ms: u64,
        /// One entry per **party**, not per socket. A two-party call has two: index 0 the near
        /// (offerer, `from_tag`) leg, index 1 the far (answerer, `to_tag`) leg. A **single-leg** call —
        /// one answered by the engine itself with no far party (IVR / announcement / echo / voice-AI,
        /// i.e. `answer_local` or an offer the controller answered itself) — has exactly **one**: the
        /// caller, carrying that call's whole packet/byte total and its measured quality. Match on
        /// `tag`, and iterate rather than indexing.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        legs: Vec<LegSummary>,
    },
    /// A WebSocket tee started streaming ([`Command::AttachWsTee`] or `ProfileFlags::ws_tee`): the
    /// engine dialled the server, sent `start`, and the call's decoded audio is now flowing. Carries
    /// the negotiated wire shape so a controller can decode the binary frames without guessing.
    WsTeeStarted {
        call_id: String,
        from_tag: String,
        /// The tee's `streamId`, matching the `start` frame on the WebSocket — the correlator between
        /// this control event and the media stream.
        stream_id: String,
        ws_uri: String,
        direction: WsTeeDirection,
        /// Wire channels: 1 = mono/mixed, 2 = caller/callee interleaved.
        channels: u8,
        /// Wire sample rate in Hz (L16, little-endian).
        sample_rate: u32,
    },
    /// A record tone (the "voicemail beep" an answering machine plays before it starts recording)
    /// was detected on a leg armed with `ProfileFlags::beep_detection`. The media half of
    /// answering-machine detection — a controller can abort an attended transfer on this rather than
    /// bridging the caller into a voicemail box.
    ///
    /// Emitted **once** per leg per call: the engine drops the detector after the first tone, so the
    /// controller never has to de-duplicate and there is no mid-call re-arm (a fresh `offer`/`answer`
    /// with the flag set re-arms it). `from_tag` names the leg the tone was heard *on*, matching the
    /// `call_id` / `from_tag` / `to_tag` triple of [`Event::Dtmf`]. Additive: a consumer predating
    /// this variant decodes it as [`Event::Unknown`] and ignores it.
    BeepDetected {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        /// Measured tone frequency in Hz (sub-bin accurate, typically within a few Hz).
        frequency_hz: f32,
        /// Measured tone length in milliseconds, accurate to about one analysis window (±32 ms).
        duration_ms: u32,
        /// Milliseconds of decoded audio seen on this leg before the tone *started*. This is the
        /// offset of the tone itself, not of the event — the event is emitted after the detector's
        /// cadence guard (`ProfileFlags::beep_cadence_guard_ms`) has elapsed.
        offset_ms: u64,
    },
    /// A WebSocket tee stopped. Emitted exactly once per started tee — including when the *server*
    /// ends it — so a controller learns the stream died rather than silently losing audio.
    WsTeeEnded {
        call_id: String,
        from_tag: String,
        stream_id: String,
        reason: WsTeeEndReason,
        /// Wire frames handed to the transport over the tee's lifetime.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frames_sent: Option<u64>,
        /// Frames dropped because the server stalled (bounded queue full) or a channel ring overflowed.
        /// A non-zero value means the consumer could not keep up — the call itself was never affected.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frames_dropped: Option<u64>,
    },
    /// Unknown / future event kind (forward-compat).
    #[serde(other)]
    Unknown,
}

/// Errors from the framing helpers.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// JSON (de)serialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// A frame's declared length exceeds [`MAX_FRAME_LEN`].
    #[error("frame length {len} exceeds maximum {max}")]
    FrameTooLarge { len: usize, max: usize },
}

/// Frame helpers: big-endian `u32` length prefix + JSON body.
///
/// The async TCP server uses these to read/write frames off a stream; they are kept
/// transport-agnostic (operate on byte slices/vecs) so they are trivially unit-testable.
pub mod frame {
    use super::{ProtoError, MAX_FRAME_LEN};
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    /// Length-prefix header size in bytes.
    pub const HEADER_LEN: usize = 4;

    /// Serialize `value` to a complete length-prefixed JSON frame.
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
        let body = serde_json::to_vec(value)?;
        if body.len() > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge {
                len: body.len(),
                max: MAX_FRAME_LEN,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Try to decode one frame from the front of `buffer`.
    ///
    /// Returns `Ok(Some((value, consumed)))` when a whole frame is present (the caller should
    /// drop `consumed` bytes from the front), `Ok(None)` when more bytes are needed, or an
    /// error on an oversized or malformed frame.
    pub fn decode<T: DeserializeOwned>(buffer: &[u8]) -> Result<Option<(T, usize)>, ProtoError> {
        if buffer.len() < HEADER_LEN {
            return Ok(None);
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&buffer[..HEADER_LEN]);
        let len = u32::from_be_bytes(header) as usize;
        if len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge {
                len,
                max: MAX_FRAME_LEN,
            });
        }
        let total = HEADER_LEN + len;
        if buffer.len() < total {
            return Ok(None);
        }
        let value = serde_json::from_slice(&buffer[HEADER_LEN..total])?;
        Ok(Some((value, total)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, &back, "roundtrip mismatch via {json}");
    }

    #[test]
    fn offer_roundtrip_and_wire_shape() {
        let request = Request {
            id: 7,
            command: Command::Offer {
                call_id: "abc@host".to_string(),
                from_tag: "ft1".to_string(),
                sdp: "v=0\r\n".to_string(),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".to_string()),
                    ice: Some("remove".to_string()),
                    replace: vec!["origin".to_string()],
                    direction: vec!["external".to_string(), "internal".to_string()],
                    ws_uri: Some("ws://127.0.0.1:9001/stream".to_string()),
                    ..Default::default()
                },
            },
        };
        roundtrip(&request);

        // Lock the flattened, internally-tagged wire shape.
        let json = serde_json::to_value(&request).expect("to_value");
        assert_eq!(json["id"], 7);
        assert_eq!(json["command"], "offer");
        assert_eq!(json["call_id"], "abc@host");
        assert_eq!(json["profile"]["transport_protocol"], "RTP/SAVP");
        assert_eq!(json["profile"]["ws_uri"], "ws://127.0.0.1:9001/stream");
    }

    #[test]
    fn call_summary_event_roundtrip_and_wire_shape() {
        let event = Event::CallSummary {
            call_id: "abc@host".to_string(),
            reason: "delete".to_string(),
            duration_ms: 94_000,
            legs: vec![
                // A measured (transcode) leg carries the full quality set.
                LegSummary {
                    tag: "ft-a".to_string(),
                    codec: Some("PCMA".to_string()),
                    packets_in: 2720,
                    bytes_in: 467_840,
                    packets_out: 3469,
                    bytes_out: 596_468,
                    packets_dropped: 0,
                    ssrc: Some(0x8a8b_25c0),
                    packets_lost: Some(1),
                    loss_percent: Some(0.04),
                    jitter_ms: Some(0.8),
                    rtt_ms: Some(37.8),
                    mos_average: Some(4.30),
                    mos_min: Some(4.21),
                    mos_max: Some(4.40),
                    mos_basis: Some("full".to_string()),
                    text: None,
                },
                // A counters-only leg (no media actor) omits every quality field.
                LegSummary {
                    tag: "ft-b".to_string(),
                    codec: None,
                    packets_in: 0,
                    bytes_in: 0,
                    packets_out: 32,
                    bytes_out: 5388,
                    packets_dropped: 0,
                    ssrc: None,
                    packets_lost: None,
                    loss_percent: None,
                    jitter_ms: None,
                    rtt_ms: None,
                    mos_average: None,
                    mos_min: None,
                    mos_max: None,
                    mos_basis: None,
                    text: Some(TextStreamStats {
                        packets: 5,
                        characters: 11,
                        missing_markers: 1,
                        recovered_from_redundancy: 2,
                    }),
                },
            ],
        };
        roundtrip(&event);

        let json = serde_json::to_value(&event).expect("to_value");
        assert_eq!(json["event"], "call_summary", "snake_case event tag");
        assert_eq!(json["duration_ms"], 94_000);
        assert_eq!(json["legs"][0]["mos_basis"], "full");
        assert!(
            json["legs"][1].get("mos_average").is_none(),
            "a counters-only leg omits its quality fields on the wire"
        );
        // The RFC 4103 text QoS rides the far leg (it received text); an audio-only leg omits it.
        assert!(
            json["legs"][0].get("text").is_none(),
            "a leg with no text stream omits the text QoS block"
        );
        assert_eq!(json["legs"][1]["text"]["characters"], 11);
        assert_eq!(json["legs"][1]["text"]["missing_markers"], 1);
        assert_eq!(json["legs"][1]["text"]["recovered_from_redundancy"], 2);

        // Forward-compat (the property that lets a not-yet-updated SIPhon tolerate this new event): an
        // unrecognized event tag decodes to `Unknown` via `#[serde(other)]`, never a hard error.
        let future: Event =
            serde_json::from_str(r#"{"event":"some_future_kind","x":1}"#).expect("tolerated");
        assert_eq!(future, Event::Unknown);
    }

    #[test]
    fn ws_uri_defaults_to_none_and_is_omitted_when_unset() {
        // Additive, optional: an offer without ws_uri deserializes fine and the field is omitted from
        // the wire when unset (skip_serializing_if), so the native extension stays invisible to the
        // NG/bencode front-end which never sets it.
        let json = r#"{"command":"offer","call_id":"c","from_tag":"f","sdp":"v=0\r\n"}"#;
        let command: Command = serde_json::from_str(json).expect("deserialize");
        match command {
            Command::Offer { profile, .. } => assert_eq!(profile.ws_uri, None),
            other => panic!("expected offer, got {other:?}"),
        }
        let serialized = serde_json::to_value(ProfileFlags::default()).expect("to_value");
        assert!(
            serialized.get("ws_uri").is_none(),
            "ws_uri omitted when unset"
        );
        // The voice-AI turn-taking knobs are all off/omitted by default, so an existing ws_uri user
        // (or the NG front-end) is unaffected.
        for field in [
            "ws_vad",
            "ws_barge_in",
            "ws_vad_threshold",
            "ws_vad_hangover_ms",
            "ws_vad_engine",
            "ws_vad_min_speech_ms",
        ] {
            assert!(
                serialized.get(field).is_none(),
                "{field} omitted when unset"
            );
        }
        let profile = ProfileFlags::default();
        assert!(!profile.ws_vad);
        assert!(!profile.ws_barge_in);
        assert_eq!(profile.ws_vad_threshold, None);
        assert_eq!(profile.ws_vad_hangover_ms, None);
        assert_eq!(profile.ws_vad_engine, None);
        assert_eq!(profile.ws_vad_min_speech_ms, None);
    }

    #[test]
    fn default_profile_serializes_to_an_empty_object() {
        // The strongest statement of "additive": a controller that sets nothing produces byte-identical
        // JSON before and after the detector-selection fields were added. Any new field that forgets
        // `skip_serializing_if` breaks this, not just a review.
        let serialized = serde_json::to_string(&ProfileFlags::default()).expect("to_string");
        assert_eq!(serialized, "{}");
    }

    #[test]
    fn ws_vad_engine_selects_the_detector_and_round_trips_in_snake_case() {
        // Default stays the energy detector: an existing controller's JSON means what it always did.
        assert_eq!(WsVadEngine::default(), WsVadEngine::Energy);

        let json = concat!(
            r#"{"command":"offer","call_id":"c","from_tag":"f","sdp":"v=0\r\n","#,
            r#""profile":{"ws_uri":"ws://[2001:db8::1]:8080/","ws_vad":true,"ws_barge_in":true,"#,
            r#""ws_vad_engine":"neural","ws_vad_min_speech_ms":80}}"#
        );
        let command: Command = serde_json::from_str(json).expect("deserialize");
        match command {
            Command::Offer { profile, .. } => {
                assert_eq!(profile.ws_vad_engine, Some(WsVadEngine::Neural));
                assert_eq!(profile.ws_vad_min_speech_ms, Some(80));
                assert!(profile.ws_vad);
                assert!(profile.ws_barge_in);
            }
            other => panic!("expected offer, got {other:?}"),
        }

        let profile = ProfileFlags {
            ws_vad_engine: Some(WsVadEngine::Neural),
            ws_vad_min_speech_ms: Some(80),
            ..Default::default()
        };
        let value = serde_json::to_value(&profile).expect("to_value");
        assert_eq!(value["ws_vad_engine"], "neural");
        assert_eq!(value["ws_vad_min_speech_ms"], 80);
        let energy = ProfileFlags {
            ws_vad_engine: Some(WsVadEngine::Energy),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&energy).expect("to_value")["ws_vad_engine"],
            "energy"
        );

        // An unrecognised detector name is a hard error, not a silent fall back to energy: a
        // controller asking for a detector this engine does not have must be told, not quietly
        // given the one it was trying to avoid.
        let unknown = r#"{"ws_vad_engine":"telepathy"}"#;
        assert!(serde_json::from_str::<ProfileFlags>(unknown).is_err());
    }

    #[test]
    fn attach_ws_tee_wire_shape_and_defaults() {
        // `direction` defaults to both and `channels` is optional, so the minimal form is three fields.
        let json =
            r#"{"command":"attach_ws_tee","call_id":"c","from_tag":"f","ws_uri":"ws://h/s"}"#;
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::AttachWsTee {
                call_id,
                from_tag,
                ws_uri,
                direction,
                channels,
                sample_rate,
            } => {
                assert_eq!(call_id, "c");
                assert_eq!(from_tag, "f");
                assert_eq!(ws_uri, "ws://h/s");
                assert_eq!(direction, WsTeeDirection::Both, "both legs by default");
                assert_eq!(channels, None);
                assert_eq!(sample_rate, None, "unset ⇒ follow the leg codec's rate");
            }
            other => panic!("expected attach_ws_tee, got {other:?}"),
        }

        let explicit = Command::AttachWsTee {
            call_id: "c".into(),
            from_tag: "f".into(),
            ws_uri: "wss://h/s".into(),
            direction: WsTeeDirection::Caller,
            channels: Some(1),
            sample_rate: None,
        };
        let value = serde_json::to_value(&explicit).expect("to_value");
        assert_eq!(value["command"], "attach_ws_tee");
        assert_eq!(value["direction"], "caller");
        assert_eq!(value["channels"], 1);

        match serde_json::from_str::<Command>(
            r#"{"command":"detach_ws_tee","call_id":"c","from_tag":"f"}"#,
        )
        .expect("deserialize")
        {
            Command::DetachWsTee { call_id, from_tag } => {
                assert_eq!((call_id.as_str(), from_tag.as_str()), ("c", "f"));
            }
            other => panic!("expected detach_ws_tee, got {other:?}"),
        }
    }

    #[test]
    fn ws_tee_profile_flags_are_additive_and_omitted_when_unset() {
        let serialized = serde_json::to_value(ProfileFlags::default()).expect("to_value");
        for field in ["ws_tee", "ws_tee_direction", "ws_tee_channels"] {
            assert!(
                serialized.get(field).is_none(),
                "{field} omitted when unset"
            );
        }
        let json = concat!(
            r#"{"command":"offer","call_id":"c","from_tag":"f","sdp":"v=0\r\n",""#,
            r#"profile":{"ws_tee":"ws://h/tee","ws_tee_direction":"callee","ws_tee_channels":1}}"#
        );
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::Offer { profile, .. } => {
                assert_eq!(profile.ws_tee.as_deref(), Some("ws://h/tee"));
                assert_eq!(profile.ws_tee_direction, Some(WsTeeDirection::Callee));
                assert_eq!(profile.ws_tee_channels, Some(1));
                // A tee is additive: it never implies takeover.
                assert_eq!(profile.ws_uri, None);
            }
            other => panic!("expected offer, got {other:?}"),
        }
    }

    /// The three selectable-wire-rate fields are strictly **additive**: absent from the serialization
    /// when unset, so an existing controller's JSON round-trips byte-identically, and `None`
    /// everywhere means "follow the leg codec's rate" — exactly the behaviour that shipped before.
    #[test]
    fn ws_wire_sample_rate_fields_are_additive_and_omitted_when_unset() {
        let flags = serde_json::to_value(ProfileFlags::default()).expect("to_value");
        for field in ["ws_sample_rate", "ws_tee_sample_rate"] {
            assert!(flags.get(field).is_none(), "{field} omitted when unset");
        }
        // The whole default profile still serializes to the empty object it always did.
        assert_eq!(
            serde_json::to_string(&ProfileFlags::default()).expect("to_string"),
            "{}",
            "an unset wire rate must not change one byte of an existing controller's profile"
        );

        let attach = Command::AttachWsTee {
            call_id: "c".into(),
            from_tag: "f".into(),
            ws_uri: "ws://h/tee".into(),
            direction: WsTeeDirection::Both,
            channels: None,
            sample_rate: None,
        };
        let value = serde_json::to_value(&attach).expect("to_value");
        assert!(
            value.get("sample_rate").is_none(),
            "attach_ws_tee omits sample_rate when unset"
        );
    }

    /// An existing controller's JSON — written before the field existed — still deserializes, and
    /// leaves every wire rate `None` (the "follow the codec rate" default).
    #[test]
    fn a_pre_wire_rate_controllers_json_still_means_follow_the_codec_rate() {
        let json = concat!(
            r#"{"command":"attach_ws_tee","call_id":"c","from_tag":"f","#,
            r#""ws_uri":"ws://h/tee","direction":"both"}"#
        );
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::AttachWsTee {
                sample_rate,
                channels,
                ..
            } => {
                assert_eq!(sample_rate, None, "no rate requested ⇒ follow the codec");
                assert_eq!(channels, None);
            }
            other => panic!("expected attach_ws_tee, got {other:?}"),
        }

        let offer = concat!(
            r#"{"command":"offer","call_id":"c","from_tag":"f","sdp":"v=0\r\n",""#,
            r#"profile":{"ws_uri":"ws://h/s","ws_tee":"ws://h/tee"}}"#
        );
        match serde_json::from_str::<Command>(offer).expect("deserialize") {
            Command::Offer { profile, .. } => {
                assert_eq!(profile.ws_sample_rate, None);
                assert_eq!(profile.ws_tee_sample_rate, None);
            }
            other => panic!("expected offer, got {other:?}"),
        }
    }

    #[test]
    fn a_requested_wire_sample_rate_survives_the_wire() {
        let attach = Command::AttachWsTee {
            call_id: "c".into(),
            from_tag: "f".into(),
            ws_uri: "ws://h/tee".into(),
            direction: WsTeeDirection::Caller,
            channels: Some(1),
            sample_rate: Some(16_000),
        };
        let value = serde_json::to_value(&attach).expect("to_value");
        assert_eq!(value["sample_rate"], 16_000);
        assert_eq!(
            serde_json::from_value::<Command>(value).expect("roundtrip"),
            attach
        );

        let json = concat!(
            r#"{"command":"answer","call_id":"c","from_tag":"f","to_tag":"t","sdp":"v=0\r\n",""#,
            r#"profile":{"ws_uri":"ws://h/s","ws_sample_rate":24000,"#,
            r#""ws_tee":"ws://h/tee","ws_tee_sample_rate":16000}}"#
        );
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::Answer { profile, .. } => {
                assert_eq!(profile.ws_sample_rate, Some(24_000));
                assert_eq!(profile.ws_tee_sample_rate, Some(16_000));
            }
            other => panic!("expected answer, got {other:?}"),
        }
    }

    #[test]
    fn ws_tee_events_wire_shape() {
        let started = Event::WsTeeStarted {
            call_id: "c".into(),
            from_tag: "f".into(),
            stream_id: "tee-c".into(),
            ws_uri: "ws://h/s".into(),
            direction: WsTeeDirection::Both,
            channels: 2,
            sample_rate: 8000,
        };
        let value = serde_json::to_value(&started).expect("to_value");
        assert_eq!(value["event"], "ws_tee_started");
        assert_eq!(value["stream_id"], "tee-c");
        assert_eq!(value["channels"], 2);
        assert_eq!(
            serde_json::from_value::<Event>(value).expect("roundtrip"),
            started
        );

        let ended = Event::WsTeeEnded {
            call_id: "c".into(),
            from_tag: "f".into(),
            stream_id: "tee-c".into(),
            reason: WsTeeEndReason::ServerClosed,
            frames_sent: Some(1500),
            frames_dropped: Some(0),
        };
        let value = serde_json::to_value(&ended).expect("to_value");
        assert_eq!(value["event"], "ws_tee_ended");
        assert_eq!(value["reason"], "server_closed");
        assert_eq!(
            serde_json::from_value::<Event>(value).expect("roundtrip"),
            ended
        );
    }

    #[test]
    fn ws_vad_flags_parse_when_set() {
        let json = concat!(
            r#"{"command":"offer","call_id":"c","from_tag":"f","sdp":"v=0\r\n",""#,
            r#"profile":{"ws_uri":"ws://h/s","ws_vad":true,"ws_barge_in":true,"#,
            r#""ws_vad_threshold":2000000,"ws_vad_hangover_ms":300}}"#
        );
        let command: Command = serde_json::from_str(json).expect("deserialize");
        match command {
            Command::Offer { profile, .. } => {
                assert!(profile.ws_vad);
                assert!(profile.ws_barge_in);
                assert_eq!(profile.ws_vad_threshold, Some(2_000_000));
                assert_eq!(profile.ws_vad_hangover_ms, Some(300));
            }
            other => panic!("expected offer, got {other:?}"),
        }
    }

    #[test]
    fn all_commands_roundtrip() {
        let commands = vec![
            Command::Answer {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: "t".into(),
                sdp: "v=0".into(),
                profile: ProfileFlags::default(),
            },
            Command::AnswerLocal {
                call_id: "c".into(),
                from_tag: "f".into(),
                sdp: "v=0".into(),
                profile: ProfileFlags::default(),
            },
            Command::Delete {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: Some("t".into()),
            },
            Command::Query {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: None,
            },
            Command::Ping,
            Command::List,
            Command::Statistics,
            Command::Load,
            Command::NodeInfo,
            Command::Drain,
            Command::Undrain,
            Command::Checkpoint {
                call_id: "c".into(),
                from_tag: "f".into(),
            },
            Command::Restore {
                snapshot: "{\"version\":1}".into(),
            },
            Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::File {
                    path: "/p.wav".into(),
                },
                repeat_times: Some(2),
                start_pos_ms: None,
                duration_ms: Some(5000),
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
            Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::Tone {
                    tone: "ringback_eu".into(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: Some(30_000),
                overlay: true,
                gain_decibels: Some(-9),
                to_tag: None,
            },
            Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::Http {
                    url: "https://example.invalid/hold.wav".into(),
                },
                repeat_times: Some(0),
                start_pos_ms: None,
                duration_ms: None,
                overlay: true,
                gain_decibels: Some(-15),
                to_tag: None,
            },
            Command::StopMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                play_id: None,
            },
            Command::StopMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                play_id: Some(3),
            },
            Command::SetPlayGain {
                call_id: "c".into(),
                from_tag: "f".into(),
                play_id: 3,
                gain_decibels: -6,
                to_tag: Some("t".into()),
            },
            Command::PlayDtmf {
                call_id: "c".into(),
                from_tag: "f".into(),
                code: "123#".into(),
                duration_ms: Some(100),
                volume_dbm0: Some(-8),
                pause_ms: Some(60),
                to_tag: None,
            },
            Command::SilenceMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
            },
            Command::BlockDtmf {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: Some("t".into()),
            },
            Command::UnblockDtmf {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: None,
            },
            Command::Echo {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: None,
                enabled: true,
            },
            Command::SubscribeRequest {
                call_id: "c".into(),
                from_tags: vec!["a".into(), "b".into()],
                sdp: Some("v=0".into()),
                profile: ProfileFlags::default(),
            },
            Command::Unsubscribe {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: "t".into(),
            },
            Command::Authenticate {
                token: "s3cret".into(),
            },
        ];
        for command in &commands {
            roundtrip(&Request {
                id: 1,
                command: command.clone(),
            });
        }
    }

    #[test]
    fn echo_enabled_defaults_to_true_and_wire_shape() {
        // Minimal echo frame (no to_tag, no enabled) — `enabled` must default to true so
        // `rtpengine.echo(call)` turns echo on with the smallest possible payload.
        let json = r#"{"command":"echo","call_id":"c","from_tag":"f"}"#;
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::Echo {
                enabled, to_tag, ..
            } => {
                assert!(enabled, "enabled must default to true");
                assert_eq!(to_tag, None);
            }
            other => panic!("expected echo, got {other:?}"),
        }

        // Explicit disable roundtrips and keeps the snake_case verb tag.
        let request = Request {
            id: 9,
            command: Command::Echo {
                call_id: "abc@host".into(),
                from_tag: "ft".into(),
                to_tag: Some("tt".into()),
                enabled: false,
            },
        };
        roundtrip(&request);
        let value = serde_json::to_value(&request).expect("to_value");
        assert_eq!(value["command"], "echo");
        assert_eq!(value["enabled"], false);
        assert_eq!(value["to_tag"], "tt");
    }

    #[test]
    fn answer_local_wire_shape_and_no_to_tag() {
        // Minimal single-leg answer frame: call_id + from_tag + offer sdp, profile omitted (defaults).
        // No `to_tag` field — there is no far leg (RFC 3264: the engine answers for itself).
        let json = r#"{"command":"answer_local","call_id":"c","from_tag":"f","sdp":"v=0\r\n"}"#;
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::AnswerLocal {
                call_id,
                from_tag,
                sdp,
                profile,
            } => {
                assert_eq!(call_id, "c");
                assert_eq!(from_tag, "f");
                assert_eq!(sdp, "v=0\r\n");
                assert_eq!(profile, ProfileFlags::default());
            }
            other => panic!("expected answer_local, got {other:?}"),
        }

        // A codec-policy profile roundtrips and keeps the snake_case verb tag.
        let request = Request {
            id: 11,
            command: Command::AnswerLocal {
                call_id: "abc@host".into(),
                from_tag: "ft".into(),
                sdp: "v=0\r\n".into(),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/AVP".into()),
                    flags: vec!["codec-transcode-PCMU".into()],
                    ..Default::default()
                },
            },
        };
        roundtrip(&request);
        let value = serde_json::to_value(&request).expect("to_value");
        assert_eq!(value["command"], "answer_local");
        assert_eq!(value["profile"]["flags"][0], "codec-transcode-PCMU");
        assert!(
            value.get("to_tag").is_none(),
            "answer_local carries no to_tag"
        );
    }

    #[test]
    fn play_media_blob_roundtrip() {
        let request = Request {
            id: 3,
            command: Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::Blob {
                    data: vec![0u8, 1, 2, 255, 128],
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        };
        roundtrip(&request);
    }

    #[test]
    fn play_media_tolerates_the_removed_wait_field() {
        // `wait` was an early on-the-wire field; it is now purely a controller-side concept (await the
        // completion event, or don't). An older frame that still carries `wait` must deserialize fine —
        // serde ignores the now-unknown key, so a mixed-version deployment never fails to parse a play.
        let json = r#"{"command":"play_media","call_id":"c","from_tag":"f","source":{"source":"file","path":"/p.wav"},"wait":true}"#;
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::PlayMedia { call_id, .. } => assert_eq!(call_id, "c"),
            other => panic!("expected play_media, got {other:?}"),
        }
    }

    #[test]
    fn play_media_without_the_overlay_extensions_keeps_its_original_wire_shape() {
        // The overlay/gain/tone additions are strictly additive: a controller that does not use them
        // must serialize byte-for-byte what it serialized before. `overlay` is `skip_serializing_if`
        // false and `gain_decibels` is an `Option`, so neither key appears; and a frame written by an
        // older controller still deserializes with the new fields at their defaults.
        let request = Request {
            id: 11,
            command: Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::File {
                    path: "/prompt.wav".into(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        };
        let json = serde_json::to_string(&request).expect("serialize");
        assert_eq!(
            json,
            concat!(
                r#"{"id":11,"command":"play_media","call_id":"c","from_tag":"f","#,
                r#""source":{"source":"file","path":"/prompt.wav"}}"#
            ),
            "an unset overlay/gain must not appear on the wire"
        );
        // The pre-extension frame, verbatim, still parses — with the new fields defaulted.
        let legacy = r#"{"id":11,"command":"play_media","call_id":"c","from_tag":"f","source":{"source":"file","path":"/prompt.wav"}}"#;
        let parsed: Request = serde_json::from_str(legacy).expect("deserialize");
        assert_eq!(parsed, request);
        match parsed.command {
            Command::PlayMedia {
                overlay,
                gain_decibels,
                ..
            } => {
                assert!(
                    !overlay,
                    "overlay defaults off — supersede stays the default"
                );
                assert_eq!(
                    gain_decibels, None,
                    "gain defaults to the source's own level"
                );
            }
            other => panic!("expected play_media, got {other:?}"),
        }
    }

    #[test]
    fn play_media_overlay_and_gain_appear_only_when_set() {
        let request = Request {
            id: 12,
            command: Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::Tone {
                    tone: "ringback_eu".into(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: Some(30_000),
                overlay: true,
                gain_decibels: Some(-12),
                to_tag: Some("t".into()),
            },
        };
        roundtrip(&request);
        let value = serde_json::to_value(&request).expect("to_value");
        assert_eq!(value["command"], "play_media");
        assert_eq!(value["overlay"], true);
        assert_eq!(value["gain_decibels"], -12);
        assert_eq!(value["duration_ms"], 30_000);
        assert_eq!(value["source"]["source"], "tone");
        assert_eq!(value["source"]["tone"], "ringback_eu");
    }

    #[test]
    fn play_media_sources_keep_their_tags() {
        // Every source variant, so a rename or a re-tag is caught here rather than by a controller.
        for (source, expected_tag) in [
            (
                PlayMediaSource::File {
                    path: "/p.wav".into(),
                },
                "file",
            ),
            (PlayMediaSource::Blob { data: vec![1, 2] }, "blob"),
            (PlayMediaSource::DbId { id: 9 }, "db_id"),
            (
                PlayMediaSource::Tone {
                    tone: "425/1000,0/4000*inf".into(),
                },
                "tone",
            ),
            (
                PlayMediaSource::Http {
                    url: "https://example.invalid/p.wav".into(),
                },
                "http",
            ),
        ] {
            roundtrip(&source);
            let value = serde_json::to_value(&source).expect("to_value");
            assert_eq!(value["source"], expected_tag);
        }
    }

    #[test]
    fn stop_media_targets_one_playback_only_when_a_play_id_is_given() {
        // No `play_id` ⇒ the original call-wide stop, and the original wire shape.
        let all = Request {
            id: 13,
            command: Command::StopMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                play_id: None,
            },
        };
        let json = serde_json::to_string(&all).expect("serialize");
        assert_eq!(
            json,
            r#"{"id":13,"command":"stop_media","call_id":"c","from_tag":"f"}"#
        );
        let legacy: Request = serde_json::from_str(
            r#"{"id":13,"command":"stop_media","call_id":"c","from_tag":"f"}"#,
        )
        .expect("deserialize");
        assert_eq!(legacy, all);

        let one = Request {
            id: 14,
            command: Command::StopMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                play_id: Some(4),
            },
        };
        roundtrip(&one);
        let value = serde_json::to_value(&one).expect("to_value");
        assert_eq!(value["play_id"], 4);
    }

    #[test]
    fn set_play_gain_roundtrip_and_wire_shape() {
        let request = Request {
            id: 15,
            command: Command::SetPlayGain {
                call_id: "c".into(),
                from_tag: "f".into(),
                play_id: 4,
                gain_decibels: -18,
                to_tag: None,
            },
        };
        roundtrip(&request);
        let json = serde_json::to_string(&request).expect("serialize");
        assert_eq!(
            json,
            concat!(
                r#"{"id":15,"command":"set_play_gain","call_id":"c","from_tag":"f","#,
                r#""play_id":4,"gain_decibels":-18}"#
            )
        );
    }

    #[test]
    fn play_media_accept_carries_a_play_id() {
        // The accept answers immediately (accept-on-start) with the playback's `play_id` and the total
        // duration; the matching PlayFinished later carries the same `play_id`.
        let response = Response {
            id: 3,
            result: CmdResult::Ok {
                sdp: None,
                duration_ms: Some(4000),
                play_id: Some(7),
                to_tag: None,
                stats: None,
            },
        };
        roundtrip(&response);
        let value = serde_json::to_value(&response).expect("to_value");
        assert_eq!(value["result"], "ok");
        assert_eq!(value["play_id"], 7);
        assert_eq!(value["duration_ms"], 4000);
        // An `ok` with no play (offer/answer) omits `play_id` on the wire.
        let no_play = serde_json::to_value(CmdResult::Ok {
            sdp: Some("v=0".into()),
            duration_ms: None,
            play_id: None,
            to_tag: None,
            stats: None,
        })
        .expect("to_value");
        assert!(
            no_play.get("play_id").is_none(),
            "play_id omitted when absent"
        );
    }

    #[test]
    fn results_roundtrip() {
        roundtrip(&Response {
            id: 1,
            result: CmdResult::Ok {
                sdp: Some("v=0".into()),
                duration_ms: None,
                play_id: None,
                to_tag: None,
                stats: None,
            },
        });
        roundtrip(&Response {
            id: 2,
            result: CmdResult::Pong,
        });
        roundtrip(&Response {
            id: 3,
            result: CmdResult::Error {
                reason: "no such call".into(),
            },
        });
        roundtrip(&Response {
            id: 5,
            result: CmdResult::List {
                call_ids: vec!["a@host".into(), "b@host".into()],
            },
        });
        // An empty list (no live calls) round-trips too.
        roundtrip(&Response {
            id: 6,
            result: CmdResult::List {
                call_ids: Vec::new(),
            },
        });
        roundtrip(&Response {
            id: 7,
            result: CmdResult::Statistics {
                statistics: EngineStatistics {
                    offers_total: 10,
                    answers_total: 9,
                    deletes_total: 8,
                    control_errors_total: 1,
                    sessions: 2,
                },
            },
        });
        roundtrip(&Response {
            id: 8,
            result: CmdResult::Load {
                load: NodeLoad {
                    node_id: "rtp-node-1".into(),
                    sessions: 812,
                    max_sessions: 4000,
                    load_permille: 203,
                    transcode_sessions: 140,
                    cpu_permille: Some(247),
                    jemalloc_allocated_bytes: 734_003_200,
                    draining: false,
                },
            },
        });
        // A load snapshot with no CPU sample omits `cpu_permille` on the wire and round-trips.
        roundtrip(&Response {
            id: 9,
            result: CmdResult::Load {
                load: NodeLoad {
                    node_id: "rtp-node-2".into(),
                    sessions: 0,
                    max_sessions: 0,
                    load_permille: 0,
                    transcode_sessions: 0,
                    cpu_permille: None,
                    jemalloc_allocated_bytes: 0,
                    draining: true,
                },
            },
        });
        roundtrip(&Response {
            id: 10,
            result: CmdResult::NodeInfo {
                node: NodeInfo {
                    node_id: "rtp-node-1".into(),
                    version: "0.1.0".into(),
                    media_addresses: vec!["203.0.113.10".into(), "2001:db8::10".into()],
                    codecs: vec!["PCMU".into(), "PCMA".into(), "AMR-WB".into()],
                    features: vec!["relay".into(), "transcode".into(), "srtp".into()],
                    max_sessions: 4000,
                    draining: false,
                },
            },
        });
        roundtrip(&Response {
            id: 11,
            result: CmdResult::Checkpoint {
                snapshot: "{\"version\":1,\"call_id\":\"c\"}".into(),
            },
        });
        roundtrip(&Response {
            id: 4,
            result: CmdResult::Ok {
                sdp: None,
                duration_ms: None,
                play_id: None,
                to_tag: None,
                stats: Some(SessionStats {
                    packets_in: 100,
                    packets_out: 99,
                    bytes_in: 16000,
                    bytes_out: 15840,
                    packets_lost: 1,
                }),
            },
        });
    }

    #[test]
    fn list_and_statistics_wire_shape() {
        // The verbs are bare, internally-tagged on "command" in snake_case.
        let list = serde_json::to_value(&Request {
            id: 1,
            command: Command::List,
        })
        .expect("to_value");
        assert_eq!(list["command"], "list");
        let statistics = serde_json::to_value(&Request {
            id: 2,
            command: Command::Statistics,
        })
        .expect("to_value");
        assert_eq!(statistics["command"], "statistics");

        // The minimal verbs deserialize from just their command tag.
        assert_eq!(
            serde_json::from_str::<Command>(r#"{"command":"list"}"#).expect("list"),
            Command::List
        );
        assert_eq!(
            serde_json::from_str::<Command>(r#"{"command":"statistics"}"#).expect("statistics"),
            Command::Statistics
        );

        // The results tag on "result" in snake_case and carry their payload fields.
        let list_result = serde_json::to_value(&Response {
            id: 3,
            result: CmdResult::List {
                call_ids: vec!["c1".into()],
            },
        })
        .expect("to_value");
        assert_eq!(list_result["result"], "list");
        assert_eq!(list_result["call_ids"][0], "c1");

        let stats_result = serde_json::to_value(&Response {
            id: 4,
            result: CmdResult::Statistics {
                statistics: EngineStatistics {
                    offers_total: 3,
                    sessions: 1,
                    ..Default::default()
                },
            },
        })
        .expect("to_value");
        assert_eq!(stats_result["result"], "statistics");
        assert_eq!(stats_result["statistics"]["offers_total"], 3);
        assert_eq!(stats_result["statistics"]["sessions"], 1);
        // A field left at its default still serializes (no skip on the counters).
        assert_eq!(stats_result["statistics"]["answers_total"], 0);
    }

    #[test]
    fn cluster_commands_wire_shape() {
        // The cluster verbs are bare, internally-tagged on "command" in snake_case.
        for (command, tag) in [
            (Command::Load, "load"),
            (Command::NodeInfo, "node_info"),
            (Command::Drain, "drain"),
            (Command::Undrain, "undrain"),
        ] {
            let value = serde_json::to_value(&Request {
                id: 1,
                command: command.clone(),
            })
            .expect("to_value");
            assert_eq!(value["command"], tag, "{command:?} serializes as {tag}");
            let json = format!(r#"{{"command":"{tag}"}}"#);
            assert_eq!(
                serde_json::from_str::<Command>(&json).expect("deserialize bare verb"),
                command,
            );
        }
    }

    #[test]
    fn cluster_results_wire_shape() {
        // `load` tags on "result":"load" and nests the snapshot under "load"; a present CPU sample is
        // carried and an absent one is omitted (skip_serializing_if).
        let load = serde_json::to_value(&Response {
            id: 1,
            result: CmdResult::Load {
                load: NodeLoad {
                    node_id: "rtp-node-1".into(),
                    sessions: 812,
                    max_sessions: 4000,
                    load_permille: 203,
                    transcode_sessions: 140,
                    cpu_permille: Some(247),
                    jemalloc_allocated_bytes: 734_003_200,
                    draining: false,
                },
            },
        })
        .expect("to_value");
        assert_eq!(load["result"], "load");
        assert_eq!(load["load"]["node_id"], "rtp-node-1");
        assert_eq!(load["load"]["load_permille"], 203);
        assert_eq!(load["load"]["cpu_permille"], 247);
        assert_eq!(load["load"]["draining"], false);

        let no_cpu = serde_json::to_value(&CmdResult::Load {
            load: NodeLoad {
                cpu_permille: None,
                ..Default::default()
            },
        })
        .expect("to_value");
        assert!(
            no_cpu["load"].get("cpu_permille").is_none(),
            "cpu_permille omitted when unsampled"
        );

        // `node_info` tags on "result":"node_info" and nests under "node".
        let info = serde_json::to_value(&Response {
            id: 2,
            result: CmdResult::NodeInfo {
                node: NodeInfo {
                    node_id: "rtp-node-1".into(),
                    version: "0.1.0".into(),
                    media_addresses: vec!["203.0.113.10".into()],
                    codecs: vec!["PCMU".into(), "AMR-WB".into()],
                    features: vec!["relay".into(), "srtp".into()],
                    max_sessions: 4000,
                    draining: false,
                },
            },
        })
        .expect("to_value");
        assert_eq!(info["result"], "node_info");
        assert_eq!(info["node"]["codecs"][1], "AMR-WB");
        assert_eq!(info["node"]["max_sessions"], 4000);
    }

    #[test]
    fn checkpoint_wire_shape() {
        // The command tags on "command":"checkpoint" and carries the call keys.
        let command = serde_json::to_value(&Request {
            id: 1,
            command: Command::Checkpoint {
                call_id: "call-x".into(),
                from_tag: "ft".into(),
            },
        })
        .expect("to_value");
        assert_eq!(command["command"], "checkpoint");
        assert_eq!(command["call_id"], "call-x");
        assert_eq!(command["from_tag"], "ft");

        // The result tags on "result":"checkpoint" and carries the opaque blob under "snapshot".
        let result = serde_json::to_value(&Response {
            id: 2,
            result: CmdResult::Checkpoint {
                snapshot: "{\"version\":1}".into(),
            },
        })
        .expect("to_value");
        assert_eq!(result["result"], "checkpoint");
        assert_eq!(result["snapshot"], "{\"version\":1}");
    }

    #[test]
    fn dtmf_event_roundtrip() {
        roundtrip(&Event::Dtmf {
            call_id: "c".into(),
            from_tag: "f".into(),
            to_tag: None,
            digit: "5".into(),
            duration_ms: 120,
            volume: -8,
            source: Some("rtp".into()),
        });
    }

    #[test]
    fn text_event_roundtrip_and_snake_case_tagged() {
        let event = Event::Text {
            call_id: "c@host".into(),
            from_tag: "ft-a".into(),
            to_tag: Some("tt-b".into()),
            text: "Hi \u{FFFD}there".into(),
            direction: Some("a_to_b".into()),
        };
        roundtrip(&event);

        let json = serde_json::to_value(&event).expect("to_value");
        assert_eq!(json["event"], "text", "snake_case event tag");
        assert_eq!(json["call_id"], "c@host");
        assert_eq!(json["from_tag"], "ft-a");
        assert_eq!(json["to_tag"], "tt-b");
        assert_eq!(json["text"], "Hi \u{FFFD}there");
        assert_eq!(json["direction"], "a_to_b");

        // The optional fields are omitted on the wire when absent (forward-compatible minimal form).
        let minimal = Event::Text {
            call_id: "c".into(),
            from_tag: "ft".into(),
            to_tag: None,
            text: "x".into(),
            direction: None,
        };
        roundtrip(&minimal);
        let minimal_json = serde_json::to_value(&minimal).expect("to_value");
        assert!(minimal_json.get("to_tag").is_none(), "to_tag omitted");
        assert!(minimal_json.get("direction").is_none(), "direction omitted");
    }

    #[test]
    fn beep_detected_event_wire_shape() {
        let event = Event::BeepDetected {
            call_id: "c@host".into(),
            from_tag: "ft-a".into(),
            to_tag: Some("tt-b".into()),
            frequency_hz: 1402.5,
            duration_ms: 496,
            offset_ms: 8_144,
        };
        roundtrip(&event);

        let json = serde_json::to_value(&event).expect("to_value");
        assert_eq!(json["event"], "beep_detected", "snake_case event tag");
        assert_eq!(json["call_id"], "c@host");
        assert_eq!(json["from_tag"], "ft-a");
        assert_eq!(json["to_tag"], "tt-b");
        assert_eq!(json["frequency_hz"], 1402.5);
        assert_eq!(json["duration_ms"], 496);
        assert_eq!(json["offset_ms"], 8_144);

        // The optional leg tag is omitted when absent (minimal, forward-compatible form).
        let minimal = Event::BeepDetected {
            call_id: "c".into(),
            from_tag: "ft".into(),
            to_tag: None,
            frequency_hz: 1000.0,
            duration_ms: 320,
            offset_ms: 0,
        };
        roundtrip(&minimal);
        let minimal_json = serde_json::to_value(&minimal).expect("to_value");
        assert!(minimal_json.get("to_tag").is_none(), "to_tag omitted");
    }

    #[test]
    fn an_unrecognised_event_tag_decodes_to_unknown() {
        // A controller pinned to an older contract must not hard-fail on a newer engine's event —
        // `#[serde(other)]` is what makes `beep_detected` safe to add.
        let json = concat!(
            r#"{"event":"beep_detected","call_id":"c","from_tag":"f","frequency_hz":1000.0,"#,
            r#""duration_ms":320,"offset_ms":0}"#
        );
        assert!(matches!(
            serde_json::from_str::<Event>(json).expect("deserialize"),
            Event::BeepDetected { .. }
        ));
        let future = r#"{"event":"a_verb_from_a_newer_engine","whatever":1}"#;
        assert_eq!(
            serde_json::from_str::<Event>(future).expect("deserialize"),
            Event::Unknown
        );
    }

    #[test]
    fn beep_detection_profile_flags_are_additive_and_omitted_when_unset() {
        // Existing controller JSON must deserialize unchanged...
        let json = r#"{"command":"offer","call_id":"c","from_tag":"f","sdp":"v=0\r\n"}"#;
        match serde_json::from_str::<Command>(json).expect("deserialize") {
            Command::Offer { profile, .. } => {
                assert!(!profile.beep_detection);
                assert_eq!(profile.beep_cadence_guard_ms, None);
                assert_eq!(profile, ProfileFlags::default());
            }
            other => panic!("expected offer, got {other:?}"),
        }
        // ...and re-serialize byte-identically: the new fields never appear while unset.
        let serialized = serde_json::to_value(ProfileFlags::default()).expect("to_value");
        for field in ["beep_detection", "beep_cadence_guard_ms"] {
            assert!(
                serialized.get(field).is_none(),
                "{field} omitted when unset"
            );
        }
        assert_eq!(
            serde_json::to_string(&ProfileFlags::default()).expect("to_string"),
            "{}",
            "an all-default profile still serializes to the empty object"
        );

        // And both are honoured when a controller does set them.
        let armed = concat!(
            r#"{"command":"offer","call_id":"c","from_tag":"f","sdp":"v=0\r\n","#,
            r#""profile":{"beep_detection":true,"beep_cadence_guard_ms":1500}}"#
        );
        match serde_json::from_str::<Command>(armed).expect("deserialize") {
            Command::Offer { profile, .. } => {
                assert!(profile.beep_detection);
                assert_eq!(profile.beep_cadence_guard_ms, Some(1500));
            }
            other => panic!("expected offer, got {other:?}"),
        }
    }

    #[test]
    fn media_timeout_event_roundtrip() {
        roundtrip(&Event::MediaTimeout {
            call_id: "c".into(),
            from_tag: "f".into(),
        });
    }

    #[test]
    fn play_finished_event_roundtrip_for_each_reason() {
        for reason in [
            PlayEndReason::Completed,
            PlayEndReason::Stopped,
            PlayEndReason::Superseded,
            PlayEndReason::Error,
        ] {
            roundtrip(&Event::PlayFinished {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: Some("t".into()),
                play_id: 42,
                reason,
                played_ms: Some(1234),
            });
        }
        // The wire tag is snake_case (SIPhon dispatches on "play_finished"), the reason is snake_case,
        // and an absent `to_tag` / `played_ms` are omitted.
        let event = Event::PlayFinished {
            call_id: "c".into(),
            from_tag: "f".into(),
            to_tag: None,
            play_id: 9,
            reason: PlayEndReason::Superseded,
            played_ms: None,
        };
        roundtrip(&event);
        let value = serde_json::to_value(&event).expect("to_value");
        assert_eq!(value["event"], "play_finished");
        assert_eq!(value["play_id"], 9);
        assert_eq!(value["reason"], "superseded");
        assert!(value.get("to_tag").is_none(), "absent to_tag omitted");
        assert!(value.get("played_ms").is_none(), "absent played_ms omitted");
    }

    #[test]
    fn call_quality_event_roundtrip() {
        let event = Event::CallQuality {
            conference_id: Some("room".into()),
            call_id: None,
            from_tag: "party-0".into(),
            jitter_ms: 1.125,
            loss_percent: 0.0,
            mos: 4.41,
        };
        roundtrip(&event);
        // The wire tag is snake_case, so SIPhon dispatches on "call_quality".
        assert!(serde_json::to_string(&event)
            .expect("serialize")
            .contains("\"event\":\"call_quality\""));
    }

    #[test]
    fn conference_call_quality_serializes_byte_identical_after_the_call_id_split() {
        // Backward-compat regression: adding the optional `call_id` must not change a conference
        // event's wire form. `conference_id` is `Some` (serializes as the bare string, as it did when
        // it was a plain `String`), and the absent `call_id` is `skip_serializing_if`'d — so the JSON
        // is exactly what a pre-split consumer expects (field order + contents unchanged).
        let event = Event::CallQuality {
            conference_id: Some("room".into()),
            call_id: None,
            from_tag: "party-0".into(),
            jitter_ms: 1.125,
            loss_percent: 0.0,
            mos: 4.41,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert_eq!(
            json,
            r#"{"event":"call_quality","conference_id":"room","from_tag":"party-0","jitter_ms":1.125,"loss_percent":0.0,"mos":4.41}"#
        );
        // No `call_id` key leaks onto a conference event.
        assert!(!json.contains("call_id"), "absent call_id must be omitted");
    }

    #[test]
    fn call_id_call_quality_roundtrips_with_conference_id_absent() {
        // A 2-party (relay/transcode) quality event carries `call_id` and omits `conference_id`.
        let event = Event::CallQuality {
            conference_id: None,
            call_id: Some("call-42".into()),
            from_tag: "caller".into(),
            jitter_ms: 3.5,
            loss_percent: 1.25,
            mos: 4.2,
        };
        roundtrip(&event);
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(
            json.contains(r#""call_id":"call-42""#),
            "call_id present: {json}"
        );
        assert!(
            !json.contains("conference_id"),
            "absent conference_id must be omitted: {json}"
        );
    }

    #[test]
    fn call_quality_deserializes_either_identifier_alone() {
        // A consumer receiving only `conference_id` (old wire) or only `call_id` (new wire) decodes
        // with the other identifier defaulting to `None` (forward/backward compatible).
        let conference: Event = serde_json::from_str(
            r#"{"event":"call_quality","conference_id":"room","from_tag":"p","jitter_ms":0.0,"loss_percent":0.0,"mos":4.4}"#,
        )
        .expect("deserialize conference quality");
        assert!(matches!(
            conference,
            Event::CallQuality { conference_id: Some(ref id), call_id: None, .. } if id == "room"
        ));
        let call: Event = serde_json::from_str(
            r#"{"event":"call_quality","call_id":"c1","from_tag":"p","jitter_ms":0.0,"loss_percent":0.0,"mos":4.4}"#,
        )
        .expect("deserialize call quality");
        assert!(matches!(
            call,
            Event::CallQuality { conference_id: None, call_id: Some(ref id), .. } if id == "c1"
        ));
    }

    #[test]
    fn unknown_event_is_forward_compatible() {
        let json = r#"{"event":"some_future_event","detail":"x"}"#;
        let event: Event = serde_json::from_str(json).expect("deserialize unknown");
        assert_eq!(event, Event::Unknown);
    }

    #[test]
    fn frame_roundtrip() {
        let request = Request {
            id: 42,
            command: Command::Ping,
        };
        let bytes = frame::encode(&request).expect("encode");
        let (decoded, consumed): (Request, usize) =
            frame::decode(&bytes).expect("decode").expect("complete");
        assert_eq!(decoded, request);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn frame_partial_returns_none() {
        let request = Request {
            id: 1,
            command: Command::Ping,
        };
        let bytes = frame::encode(&request).expect("encode");
        // Header present but body truncated.
        let decoded: Option<(Request, usize)> =
            frame::decode(&bytes[..bytes.len() - 1]).expect("decode");
        assert!(decoded.is_none());
        // Only part of the header.
        let decoded: Option<(Request, usize)> = frame::decode(&bytes[..2]).expect("decode");
        assert!(decoded.is_none());
    }

    #[test]
    fn frame_decodes_consecutive_frames() {
        let first = Request {
            id: 1,
            command: Command::Ping,
        };
        let second = Request {
            id: 2,
            command: Command::Delete {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: None,
            },
        };
        let mut buffer = frame::encode(&first).expect("encode");
        buffer.extend(frame::encode(&second).expect("encode"));

        let (decoded_first, consumed): (Request, usize) =
            frame::decode(&buffer).expect("decode").expect("complete");
        assert_eq!(decoded_first, first);

        let (decoded_second, _): (Request, usize) = frame::decode(&buffer[consumed..])
            .expect("decode")
            .expect("complete");
        assert_eq!(decoded_second, second);
    }

    #[test]
    fn frame_rejects_oversized_length() {
        let mut buffer = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes().to_vec();
        buffer.extend_from_slice(b"{}");
        let result: Result<Option<(Request, usize)>, _> = frame::decode(&buffer);
        assert!(matches!(result, Err(ProtoError::FrameTooLarge { .. })));
    }

    use proptest::prelude::*;

    proptest! {
        /// The control framing eats untrusted bytes — arbitrary input must decode-or-error, never
        /// panic (a corrupt length prefix or body is an `Err`, not a crash).
        #[test]
        fn frame_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let _ = frame::decode::<Request>(&bytes);
        }

        /// `decode(encode(request))` round-trips over arbitrary ids/tags.
        #[test]
        fn request_survives_frame_roundtrip(
            id in any::<u64>(),
            call_id in "[a-z0-9@._-]{0,40}",
            from_tag in "[a-z0-9]{0,20}",
        ) {
            let request = Request {
                id,
                command: Command::Delete { call_id, from_tag, to_tag: None },
            };
            let bytes = frame::encode(&request).expect("encode");
            let (decoded, consumed): (Request, usize) =
                frame::decode(&bytes).expect("decode").expect("complete");
            prop_assert_eq!(decoded, request);
            prop_assert_eq!(consumed, bytes.len());
        }
    }
}
