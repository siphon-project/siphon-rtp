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
    /// SDP answer (B→A). Completes negotiation; returns the rewritten SDP.
    Answer {
        call_id: String,
        from_tag: String,
        to_tag: String,
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
    /// Inject an audio prompt into a leg.
    PlayMedia {
        call_id: String,
        from_tag: String,
        source: PlayMediaSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repeat_times: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        start_pos_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Stop prompt playback on a leg.
    StopMedia { call_id: String, from_tag: String },
    /// Inject DTMF (RFC 4733) toward a leg.
    PlayDtmf {
        call_id: String,
        from_tag: String,
        code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        volume_dbm0: Option<i64>,
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
    /// forwarding. Requires a media-processing (transcoding) call, the same gate as
    /// [`Command::PlayMedia`]. DTMF detection and media-timeout still fire while echoing.
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
    /// Authenticate the control connection with the server's shared secret. Handled by the control
    /// server (not the session engine); required as the first command when a secret is configured.
    Authenticate { token: String },
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
    /// Attach this call's offerer (leg A) audio to an external WebSocket media server (the
    /// mod_audio_stream / voice-AI integration). When set on `offer`/`answer`, the engine dials this
    /// URI as a WebSocket client and bridges leg A's RTP to it (decode → L16 uplink, L16 downlink →
    /// encode); the A↔B relay/transcode path is not wired in this mode (the WS server is A's far
    /// side). A native siphon-rtp extension — the NG/bencode front-end does not set it. `ws://` only
    /// for v1 (`wss://` is a follow-up).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_uri: Option<String>,
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
    /// A call's media went silent past the timeout and the engine tore it down (dead-path
    /// detection). Lets SIPhon release its own per-call state.
    MediaTimeout { call_id: String, from_tag: String },
    /// The active (dominant) speaker in a conference changed. `from_tag` is the new speaker's leg
    /// tag, or `None` when the floor went silent (no one speaking). Drives floor control / UI.
    ActiveSpeaker {
        conference_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_tag: Option<String>,
    },
    /// Periodic per-leg reception-quality estimate (RFC 3550 RTCP statistics + ITU-T G.107 MOS), so
    /// SIPhon surfaces live call quality without parsing RTCP itself. Emitted every few seconds per
    /// conference participant.
    CallQuality {
        conference_id: String,
        from_tag: String,
        /// Interarrival jitter in milliseconds (RFC 3550 §6.4.1).
        jitter_ms: f64,
        /// Residual inbound packet loss, as a percentage.
        loss_percent: f64,
        /// Estimated MOS-CQE (ITU-T G.107), in `1.0..=4.5`.
        mos: f64,
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
                to_tag: None,
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
                to_tag: None,
            },
        };
        roundtrip(&request);
    }

    #[test]
    fn results_roundtrip() {
        roundtrip(&Response {
            id: 1,
            result: CmdResult::Ok {
                sdp: Some("v=0".into()),
                duration_ms: None,
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
    fn media_timeout_event_roundtrip() {
        roundtrip(&Event::MediaTimeout {
            call_id: "c".into(),
            from_tag: "f".into(),
        });
    }

    #[test]
    fn call_quality_event_roundtrip() {
        let event = Event::CallQuality {
            conference_id: "room".into(),
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
