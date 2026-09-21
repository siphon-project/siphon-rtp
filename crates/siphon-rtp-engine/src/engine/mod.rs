//! The session engine: maps control [`Command`]s onto datapath endpoints and relay flows.
//!
//! The port model mirrors rtpengine. A call owns two **legs**:
//! - `near` — the offerer (A) side;
//! - `far` — the answerer (B) side.
//!
//! Each leg owns an RTP endpoint and, unless the stream is `a=rtcp-mux`, a companion RTCP
//! endpoint. `offer` allocates the leg endpoints, records A's RTP/RTCP addresses, and returns SDP
//! advertising the `far` leg. `answer` records B's addresses, returns SDP advertising the `near`
//! leg, and installs the relay flows (RTP↔RTP and, when not muxed, RTCP↔RTCP). Each flow latches,
//! so once a party's packets are seen the relay replies to their observed source (symmetric RTP).
//! Under rtcp-mux the single endpoint relays RTP and RTCP alike — the datapath is payload-agnostic.
//!
//! The per-call **actor** (flume mailbox + owned media pipeline) arrives with the slow-path media
//! work; for plain relay the datapath's per-endpoint receive tasks are the data-plane workers.
//!
//! [`Command`]: siphon_rtp_proto::Command

mod admin;
mod answer;
mod answer_local;
mod configure;
mod dispatch;
mod fork;
mod gather;
mod inject;
mod install;
mod intercept;
mod negotiate;
mod offer;
mod play;
mod promote;
mod record;
mod reoffer;
mod room;
mod snapshot;
mod sweep;
mod takeover;
mod teardown;
mod tee;
mod telemetry;

use dashmap::DashMap;
use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, EndpointId, FlowAction};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole};
use siphon_rtp_proto::{CmdResult, Event};
use siphon_rtp_srtp::sdes::CryptoAttribute;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cluster::ClusterState;
use crate::conference::ConferenceRegistry;
use crate::ice::driver::{AgentSupervisor, ConsentSupervisor};
use crate::ice::IceCredentials;
use crate::interface::{Interface, InterfaceTable};
use crate::media_fetch::MediaFetchLimits;
use crate::media_pipeline::MediaRegistry;
use crate::metrics::Metrics;
use crate::sdp::{self, EngineMedia, TextRewrite};
use crate::srtp_bridge::SrtpBridge;
use crate::text_pipeline::TextRegistry;
use crate::ws_bridge::WsRegistry;
use crate::x3::X3Config;

use fork::Subscription;
use gather::TurnAllocation;
use intercept::X3Session;
use play::PendingFetch;
use record::AudioRecording;
use snapshot::{
    codec_snapshot, crypto_snapshot, latch_snapshot, leg_snapshot, pipeline_snapshot,
    source_filter_snapshot,
};
use takeover::WsBridge;
use tee::WsTee;
use telemetry::HepExport;

/// Where relayed ICE candidates are allocated from (RFC 5766), and the long-term credentials to do
/// it with. A coturn REST deployment supplies a timestamped username and its derived password here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnServerConfig {
    /// The TURN server's transport address.
    pub server: SocketAddr,
    /// Long-term-credential username (RFC 5766 §4).
    pub username: String,
    /// Long-term-credential password.
    pub password: String,
}

/// Identity of a control client. A call is owned by the client that created it via `offer`; only
/// that client may answer, query, or delete it (A3 — docs/security-and-nat.md §5).
///
/// A connection that presents no `controller_id` at `Authenticate` gets one of these per accepted
/// connection, so its identity dies with the socket. A connection that does present one resolves to
/// the `ClientId` already minted for that identity ([`Engine::attach_controller`]), so a reconnect
/// re-attaches to the calls, the event sink and the quota row it already owned. Without that, a TCP
/// blip strands every call that was live at the moment it happened: `delete` answers `unknown call`,
/// a re-offer cannot renegotiate, the call-id cannot be reused, and the `CallSummary` CDR is pushed
/// to a client that is gone.
///
/// Still one live connection per identity: a controller *pool* sharing one identity needs the event
/// sink to become a set, which this does not do (the second connection wins and the first is closed).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientId(pub u64);

/// Which registration of a [`ClientId`]'s event sink a control connection holds.
///
/// A reconnecting controller resolves to the *same* `ClientId` as the connection it replaces, so
/// without this the old connection's teardown would remove the new connection's sink — and the
/// engine would silently drop every event for that client, `CallSummary` included. Every release is
/// therefore conditional on the generation the releasing connection registered.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientGeneration(u64);

/// One control client's event channel, stamped with the registration that installed it.
///
/// The engine keeps **both** halves, and the channel belongs to the `ClientId` rather than to the
/// connection draining it: a reconnecting controller re-registers over the same entry and gets a
/// clone of the same receiver. That is what keeps a live call's events flowing across a control
/// blip — the slow-path actors (media pipeline, conference, recording, WS bridge/tee, X3) are
/// handed a *cloned sender* when their pipeline is installed and hold it for the pipeline's life,
/// so a channel replaced underneath them would leave them emitting into a socket that is gone.
///
/// Bounded, so an event pushed while no connection is attached is queued for the reconnect rather
/// than blocking the engine — and dropped once the queue fills, as it already is for a connection
/// that cannot keep up.
struct ClientSink {
    generation: ClientGeneration,
    sender: flume::Sender<Event>,
    receiver: flume::Receiver<Event>,
}

/// A stable controller identity and the connection currently attached to it.
struct ControllerIdentity {
    /// The `ClientId` every connection presenting this controller id resolves to. Minted from the
    /// ordinal of the first connection that presented it, and then fixed for the row's life.
    client: ClientId,
    /// The connection attached right now: the generation of the event sink it registered, and the
    /// trigger that closes it when a newer connection claims the same identity. `None` between
    /// connections, which is what lets [`Engine::release_client_call`] reap the row.
    attached: Option<(ClientGeneration, crate::shutdown::ShutdownTrigger)>,
}

/// What a control connection gets back when it claims a stable controller identity.
pub struct ControllerAttachment {
    /// The `ClientId` every verb on the connection is keyed by from now on.
    pub client: ClientId,
    /// The generation to hand [`Engine::deregister_client`] / [`Engine::detach_controller`] when
    /// the connection ends.
    pub generation: ClientGeneration,
    /// The event receiver, re-registered under [`Self::client`].
    pub events: flume::Receiver<Event>,
    /// Trips when a newer connection claims the same identity, at which point this one must close.
    pub evicted: crate::shutdown::Shutdown,
}

/// Why a control connection's `controller_id` claim was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControllerAttachError {
    /// An empty id is a provisioning mistake, not an identity.
    #[error("controller id must not be empty")]
    Empty,
    /// Longer than [`siphon_rtp_proto::MAX_CONTROLLER_ID_LEN`].
    #[error(
        "controller id must be at most {} bytes",
        siphon_rtp_proto::MAX_CONTROLLER_ID_LEN
    )]
    TooLong,
    /// The connection already created calls under its connection identity. Moving it to a stable
    /// identity now would strand exactly those calls — the failure this whole mechanism exists to
    /// prevent — so the claim is refused instead.
    #[error("controller id must be claimed before the connection creates a call")]
    CallsAlreadyOwned,
    /// A second, different id on a connection that already claimed one. The identity decides which
    /// calls the connection owns, so it is claimed once or not at all.
    #[error("controller id already claimed by this connection")]
    AlreadyClaimed,
}

/// Milliseconds since the Unix epoch by the wall clock, for reports that must line up with other
/// network records (RFC 6035 §4.6.2.2). Never for the media-timeout sweep, which runs on the
/// datapath's logical clock. `None` only for a clock set before 1970.
fn unix_time_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

/// One side of a call: an RTP endpoint, an optional companion RTCP endpoint (absent under
/// rtcp-mux), and the remote addresses learned from that side's SDP.
#[derive(Debug, Clone, Copy)]
struct Leg {
    rtp: Endpoint,
    rtcp: Option<Endpoint>,
    remote_rtp: Option<std::net::SocketAddr>,
    remote_rtcp: Option<std::net::SocketAddr>,
    /// The IP advertised for this leg in rewritten SDP (`c=`/`o=`/ICE candidate) — the named
    /// interface's advertised address, or the bound `rtp.local_addr.ip()` when no interface overrides
    /// it. Presentation-only: it never feeds the source gate or latch (not an RTPbleed vector). Kept
    /// so `answer()` (which re-advertises the stored near leg, no re-allocation) uses the same IP the
    /// offer did, and so an HA checkpoint can carry it forward.
    advertised_ip: std::net::IpAddr,
    /// The engine's RTP endpoint for this leg's RFC 4103 Real-Time Text stream, when the call
    /// negotiated a plaintext `m=text` alongside the audio. `None` for an audio-only call (or a secure
    /// text stream, which is declined in PR 1). One port per leg — text RTCP is not separately
    /// endpointed here (single text port; text RTCP relay is a follow-up).
    text: Option<Endpoint>,
    /// This side's signalled text RTP address (the `m=text`/`c=` transport), when text was negotiated —
    /// the forward destination and source-gate anchor for the sibling leg's text relay (mirrors
    /// `remote_rtp`). `None` until known (the far leg's is filled at answer, like `remote_rtp`).
    text_remote_rtp: Option<std::net::SocketAddr>,
}

impl Leg {
    /// The **audio** datapath endpoints this leg owns (RTP + companion RTCP). Feeds the per-leg CDR
    /// counters and the HA endpoint-role map, which are audio-only in PR 1 — the text stream's counters
    /// and HA restore are deliberately not folded in here (see [`Leg::all_endpoint_ids`]).
    fn endpoint_ids(&self) -> impl Iterator<Item = EndpointId> {
        std::iter::once(self.rtp.id).chain(self.rtcp.map(|endpoint| endpoint.id))
    }

    /// Every datapath endpoint this leg owns, including the RFC 4103 text stream — for teardown, the
    /// media-timeout sweep, and the call-id index, so text ports are freed and text activity keeps the
    /// call alive. Kept separate from [`Leg::endpoint_ids`] so text is not counted into the audio CDR.
    fn all_endpoint_ids(&self) -> impl Iterator<Item = EndpointId> {
        self.endpoint_ids()
            .chain(self.text.map(|endpoint| endpoint.id))
    }

    /// The engine endpoints this leg presents in SDP: its RTP port, its RTCP port unless muxed, and
    /// the leg's advertised address (the named interface's, which need not be the bound one).
    fn engine_media(&self) -> EngineMedia {
        EngineMedia {
            rtp: self.rtp.local_addr,
            rtcp: self.rtcp.map(|endpoint| endpoint.local_addr),
            advertised_ip: self.advertised_ip,
        }
    }

    /// This leg's RFC 4103 text stream anchored at its own text endpoint and advertised address —
    /// SDES-secured with the engine's `crypto` when the leg keys text (RFC 4568), plain otherwise.
    /// `None` when the leg has no text endpoint.
    fn text_anchor(&self, crypto: Option<CryptoAttribute>) -> Option<TextRewrite> {
        let engine = EngineMedia {
            rtp: self.text?.local_addr,
            rtcp: None,
            advertised_ip: self.advertised_ip,
        };
        Some(match crypto {
            Some(crypto) => TextRewrite::AnchorSecure { engine, crypto },
            None => TextRewrite::Anchor(engine),
        })
    }
}

/// One of a call's two parties, named by the leg that faces it: **near** is A, the offerer of the
/// call's `offer` (`from_tag`), and **far** is B, the answerer (`to_tag`). Fixed at offer for the life
/// of the dialog — a re-offer from B does not make B "the offerer" of the call, it is B's SDP recorded
/// on B's leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Party {
    /// A, facing the near leg.
    Near,
    /// B, facing the far leg.
    Far,
}

impl Party {
    fn label(self) -> &'static str {
        match self {
            Party::Near => "near",
            Party::Far => "far",
        }
    }
}

/// Which leg the **caller's** media rides on a call with no far party. `offer` must allocate both legs
/// before it knows whether a B side will ever answer, and its rewritten SDP — the one a UAS puts in its
/// own 200 OK — advertises the far leg, so an offer-only IVR/echo call reaches the engine on `far`
/// while `near` holds the caller's signalled address. A WebSocket takeover on the same verb instead
/// bridges `near_rtp`. [`Engine::answer_local`], which knows from the start that no B leg is coming,
/// allocates one leg and is always [`CallerMediaLeg::Near`].
///
/// The single source of truth for "where the one stream is", consumed by
/// [`Engine::promote_to_processing`] (which reflects on that endpoint) and by [`Engine::finish_call`]
/// (which books the caller's counters against the caller's own leg record). Meaningless — and never
/// read — once a call is answered: a 2-leg call's parties each own their own leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CallerMediaLeg {
    /// The caller reaches the **near** socket: every [`Engine::answer_local`] call, and the `offer` +
    /// `ws_uri` WebSocket takeover, whose bridge redirects `near_rtp`.
    Near,
    /// The caller reaches the **far** socket — the offer-only UAS shape, where the controller answers
    /// the caller with the engine's rewritten *offer*, and that advertises the far leg.
    Far,
}

/// A negotiated (or half-negotiated) call: its owner and its leg(s).
#[derive(Debug)]
struct Call {
    /// The control client that created the call; only it may answer/query/delete it.
    owner: ClientId,
    /// Logical-clock tick at creation (offer), the media-timeout baseline before any media arrives.
    created_tick: u64,
    /// Wall-clock creation time in milliseconds since the Unix epoch, for the `Timestamps` an RFC 6035
    /// report correlates with other records (§4.6.2.2). `None` on a call restored from an HA
    /// checkpoint, which does not carry the original.
    started_at_unix_ms: Option<u64>,
    /// The engine's own ICE-lite credentials for this call (its identity as the ICE server), or
    /// `None` for a non-ICE call.
    ice: Option<IceCredentials>,
    /// The **near** (offerer, A) peer's ICE credentials, from its offer's `a=ice-ufrag`/`a=ice-pwd`.
    /// Kept because an outbound check is signed with the *peer's* password and addressed
    /// `<peer-ufrag>:<our-ufrag>` (RFC 8445 §7.1.2) — our own credentials are not enough to talk to
    /// it. `None` when A offered no ICE.
    near_remote_ice: Option<IceCredentials>,
    /// The **far** (answerer, B) peer's ICE credentials, from its answer. Same purpose as
    /// [`Self::near_remote_ice`], for the other leg; `None` until a B answer carrying ICE lands.
    far_remote_ice: Option<IceCredentials>,
    /// A's ICE candidates from its offer — the remote set the near leg's agent pairs against
    /// (RFC 8445 §6.1.2.2). Empty for a non-ICE offer.
    near_remote_candidates: Vec<siphon_rtp_ice::Candidate>,
    /// Whether A advertised `a=ice-lite`. A lite agent can never be controlling (RFC 8445 §6.1.1), so
    /// this decides our role on the near leg.
    near_peer_is_lite: bool,
    /// The candidates gathered for the **far** leg at offer time, kept because the far agent is only
    /// started at answer (when B's own set arrives) and re-gathering would change what we advertised.
    /// A re-offer from A presents these to B again, unchanged — the ports have not moved.
    far_local_candidates: Vec<siphon_rtp_ice::Candidate>,
    /// The candidates gathered for the **near** leg at answer time — what A was told. A re-offer from
    /// B presents these to A again, for the same reason [`Self::far_local_candidates`] exists. Empty
    /// before an answer, and for a non-ICE call.
    near_local_candidates: Vec<siphon_rtp_ice::Candidate>,
    /// Whether `ice: remove` took ICE off the **far** leg, at offer or on a re-offer from A since.
    /// B is then presented no ICE and its leg is never armed with it, whatever B's own SDP carries,
    /// while [`Self::ice`] may still hold the engine's credentials for an ICE offerer on the near leg
    /// (RFC 8839 §4.2.5 — A cannot use ICE unless its answer carries them). Kept because those
    /// credentials alone no longer say whether B's leg uses ICE.
    far_ice_removed: bool,
    from_tag: String,
    to_tag: Option<String>,
    near: Leg,
    /// The B-facing leg, or `None` when this call has no second party *and never will*: an
    /// [`Engine::answer_local`] call is a UAS answer the engine itself wrote (IVR / announcement /
    /// echo / voice-AI), so it allocates the caller's leg alone rather than binding a second socket
    /// pair that nothing is ever told about. `offer` still allocates both — a B side may yet answer —
    /// so an unanswered offer keeps a far leg it may never use.
    far: Option<Leg>,
    /// Which leg the caller's media rides while this call is single-leg (see [`CallerMediaLeg`]).
    /// Read only when [`Call::is_single_leg`] holds; a 2-leg call's parties own a leg each.
    caller_media_leg: CallerMediaLeg,
    /// When the far (answerer) leg is offered as secure (`RTP/SAVP`), the engine's own SDES key
    /// advertised to B — kept to key the SRTP bridge once B's answer brings its key. `None` for a
    /// plain relay. (Scenario 1: AVP near ↔ SAVP far; the reverse, a secure near, is a follow-up.)
    far_local_crypto: Option<CryptoAttribute>,
    /// The far (answerer) peer's SDES key from its `RTP/SAVP` answer — kept (alongside
    /// `far_local_crypto`) so an HA checkpoint can re-key the SRTP bridge on a standby. `None` until a
    /// secure answer lands (and `None` for a plain relay).
    far_remote_crypto: Option<CryptoAttribute>,
    /// Whether the far (answerer) leg is DTLS-SRTP (`UDP/TLS/RTP/SAVPF`, RFC 5764) — the engine offered
    /// its `a=fingerprint`/`a=setup` and, on the answer, keys the leg from the DTLS handshake rather
    /// than SDES. Mutually exclusive with `far_local_crypto`.
    far_dtls: bool,
    /// The engine's DTLS role on the far leg once B has answered (RFC 5763 §5: the complement of the
    /// answerer's `a=setup`). Kept so the engine, answering a re-offer *from* B, keeps the role in
    /// force rather than re-deciding it — a role change is a new association. `None` before an
    /// answer, and for a non-DTLS far leg.
    far_dtls_role: Option<DtlsRole>,
    /// Whether the offer forced the far leg to plaintext `RTP/AVP` (`dtls: off` on a `UDP/TLS`
    /// transport, stripping the offerer's DTLS keying). Kept because nothing else records it —
    /// `far_local_crypto` and `far_dtls` are both empty for it, exactly as for a far leg that simply
    /// passes the offerer's transport through — and a re-offer from A must present B the same.
    far_downgraded_to_plain: bool,
    /// Whether B's leg holds a fallback RTCP port offered beside `a=rtcp-mux` for a terminated
    /// DTLS-SRTP offerer (RFC 5761 §5.1.1), not yet settled by B's answer: kept if B declines
    /// multiplexing, released if B multiplexes. Cleared by the first answer either way.
    far_rtcp_fallback: bool,
    /// Whether the **offerer's own** `m=audio` was a secure profile (`RTP/SAVP[F]` or
    /// `UDP/TLS/RTP/SAVP[F]`), captured at offer. Distinct from `far_local_crypto`/`far_dtls`, which
    /// describe the leg the engine *offers* to B. Read by `answer` to refuse a WebSocket takeover
    /// arriving late on a secure offerer: the two-leg answer is rewritten from B's SDP and cannot
    /// carry the engine's own keying, so the takeover would terminate no SRTP.
    near_secure: bool,
    /// The engine's **own** SDES key advertised to A, minted at offer when A offered `RTP/SAVP`
    /// (RFC 4568). `Some` means the engine is A's cryptographic far side and terminates A's SRTP —
    /// the near-leg twin of `far_local_crypto`. `None` for a plaintext or DTLS offerer.
    near_local_crypto: Option<CryptoAttribute>,
    /// A's own SDES key, from its offer — what decrypts A's ingress. The near twin of
    /// `far_remote_crypto`.
    near_remote_crypto: Option<CryptoAttribute>,
    /// A DTLS-SRTP offerer the engine terminates: `Some` means the engine is A's DTLS peer and answers
    /// A with its own fingerprint, the DTLS twin of `near_local_crypto`. `None` for any other offerer,
    /// including a DTLS one whose keying is passed through to B untouched.
    near_dtls: Option<NearDtls>,
    /// The near (offerer) leg's primary audio codec, captured at offer — paired with the answer's
    /// codec to decide whether the call transcodes (the media slow path). Replaced at answer by the
    /// codec B actually selected whenever that codec is one A offered (RFC 3264 §6.1 — see
    /// [`negotiated_near_codec`]), so it always names the codec A is really sending.
    near_codec: Option<CodecSpec>,
    /// Every audio codec A offered, in offer order, captured at offer and refreshed on a re-offer.
    /// Read at answer to tell an answer A can simply be relayed (B picked one of these — a plain
    /// relay) from one that genuinely diverges (B picked a codec a codec policy put in the far offer,
    /// which A never offered — the transcoder). Empty for a call restored from an HA snapshot, which
    /// is already answered and never re-runs the decision.
    near_offered_codecs: Vec<CodecSpec>,
    /// Whether the profile's codec policy removed A's own primary codec from the offer B saw
    /// (`codec-mask-X` / `codec-consume-X`, or a `codec-offer` whitelist that omits it). That is the
    /// operator asking to hold A on that codec and transcode, so the answer-time adoption of B's
    /// selection is skipped for such a call — see [`negotiated_near_codec`].
    near_codec_withheld: bool,
    /// The far (answerer) leg's primary audio codec, captured at answer — the fork codec for a
    /// `subscribe_request` that forks leg B. `None` until the call is answered.
    far_codec: Option<CodecSpec>,
    /// The direction the **near** (offerer) party declared for itself (RFC 4566 §6 / RFC 8866 §6.7),
    /// captured at offer / `answer_local` and refreshed on each of that party's re-offers. Read only by
    /// the idle reaper, which must not judge a party's silence when the party told us it would be
    /// silent (RFC 3264 §8.4 — a held party may send nothing at all). `SendRecv` for a call restored
    /// from an HA snapshot, whose SDP the standby never saw; that is the conservative default, since it
    /// keeps the shorter dead-path ceiling rather than granting a restored call the held one.
    near_direction: sdp::MediaDirection,
    /// The direction the **far** (answerer) party declared for itself, captured at answer and refreshed
    /// on its re-offers. `SendRecv` until the call is answered — an unanswered call has no far party
    /// whose silence could be expected.
    far_direction: sdp::MediaDirection,
    /// The near leg's negotiated RFC 4733 telephone-event payload type, if any.
    near_telephone_event: Option<u8>,
    /// The far leg's negotiated RFC 4733 telephone-event payload type, captured at answer. Paired
    /// with `near_telephone_event` so `block DTMF` can gate the telephone-event PT of either leg even
    /// on a plain (untranscoded) relay. `None` until the call is answered / if the far leg has none.
    far_telephone_event: Option<u8>,
    /// How this call's media is handled once answered (set in `answer`).
    pipeline: PipelineKind,
    /// For a passthrough relay, the forward actions installed at answer — kept so `block`/`unblock`
    /// can flip the endpoints to `Drop` and restore them. Empty for media/SRTP calls.
    relay_flows: Vec<(EndpointId, FlowAction)>,
    /// Runtime features that hold a *promoted* passthrough relay in the userspace media pipeline —
    /// recording and DTMF-block (SIPREC subscriptions are the fourth reason, tracked by their own
    /// `subscriptions` map). A plain relay is promoted off the in-kernel `Forward` fast path on the
    /// first reason and demoted back only when the last one clears. Always empty for a call set up as
    /// a transcoding/secure Media call — demotion is additionally gated on `is_relay_call`, so a
    /// genuine media call is never demoted even if a reason is recorded here.
    promotion_reasons: HashSet<PromotionReason>,
    /// The offer's rtpengine `received-from` — the real post-NAT source IP the proxy saw A's request
    /// arrive from (`ProfileFlags.received_from`). Stored at offer so the **near** (A) leg's ingress
    /// source gate can be tightened to A's public IP at answer time, when A's `c=` advertised an
    /// unusable private address (docs/security-and-nat.md §4 layer 2). `None` when the offer carried
    /// no `received-from`. Replaced by a re-offer from A that carries one (the app changed network),
    /// and kept when it carries none.
    offer_received_from: Option<std::net::IpAddr>,
    /// The **far** (B) leg's `received-from`, from B's answer — the far-side twin of
    /// [`Self::offer_received_from`]. Stored so a later renegotiation can keep or refresh it: an answer
    /// or a re-offer from B that carries one replaces it, one that carries none keeps it. Without it an
    /// answer re-run with no hint would fall back to gating a NATed B on the private `c=` it signalled.
    far_received_from: Option<std::net::IpAddr>,
    /// B's re-offer SDP while it waits for A's answer (RFC 3264 §8). A re-offer from B is recorded on
    /// the far leg straight away, but the media path is only re-wired once A answers — and that answer
    /// arrives with the dialog's tags reversed, which [`Engine::answer`] accepts only while this holds
    /// a re-offer, so a stray reversed answer cannot rewrite a live call. Cleared by any answer and by
    /// a re-offer from A.
    pending_far_reoffer: Option<String>,
    /// The RFC 3389 comfort-noise payload type negotiated in a **single-leg** local answer
    /// (`answer_local`), when the caller offered CN at the chosen codec's clock rate. Carried so the
    /// promoted single-leg [`MediaCall`] emits real CN packets on it while idle instead of looping the
    /// caller's audio back (self-echo); `None` ⇒ audio-encoded low-level comfort noise. Unused by
    /// 2-leg calls.
    comfort_noise_payload_type: Option<u8>,
    /// The negotiated RFC 4103 T.140 payload type of a relayed text stream (from the offer's
    /// `a=rtpmap:<pt> t140/1000`), captured for observability and the follow-up RED/T.140 decode.
    /// `None` for an audio-only call or a declined/secure text stream.
    text_t140_payload_type: Option<u8>,
    /// The negotiated RFC 2198 redundancy payload type of a relayed text stream
    /// (`a=rtpmap:<pt> red/1000`), when the offer wrapped T.140 in RED. `None` otherwise.
    text_red_payload_type: Option<u8>,
    /// The two in-kernel text `Forward` flows installed at `answer()` (near text, then far text),
    /// mirroring `relay_flows` for the audio relay — kept so a text-observability feature can promote
    /// the text stream to the userspace [`crate::text_pipeline`] (reconstructing the exact gate/latch)
    /// and demote it back to these in-kernel flows when the last feature clears. Empty for a call with
    /// no plaintext text stream.
    text_relay_flows: Vec<(EndpointId, FlowAction)>,
    /// Runtime reasons the RFC 4103 text stream is promoted to the userspace text processor — parallel
    /// to `promotion_reasons`, which governs the *audio* relay. Text-only: promoting text never promotes
    /// audio (the maintainer's hard constraint). Empty ⇒ text stays on the PR-1 in-kernel `Forward`
    /// relay. Populated by `text_events` (at answer) and/or a runtime recording.
    text_promotion_reasons: HashSet<PromotionReason>,
    /// Whether the controller asked to observe this call's text at the control plane
    /// (`ProfileFlags.text_events`), captured at offer. When set (and a plaintext text stream is
    /// negotiated and the owner has an event sink), `answer()` promotes the text stream so it emits
    /// [`Event::Text`] for the call's life. `false` ⇒ no control-plane text events (recording can still
    /// promote text independently).
    text_events: bool,
    /// Whether the negotiated RFC 4103 text stream is **secure** (SDES-SRTP, `RTP/SAVP`). A secure text
    /// stream is anchored as a per-leg `SecureLeg` bridge and runs in the userspace text processor
    /// **from the start** (SRTP cannot relay on the in-kernel `Forward` fast path), so it has no
    /// `text_relay_flows` and is never demoted back to the kernel. `false` for a plaintext text stream
    /// or an audio-only call. Set at `answer()` once both legs' keys are known.
    text_secure: bool,
    /// The near (offerer, A) leg's SDES key from its secure `m=text` offer — the peer key the near text
    /// `SecureLeg` decrypts A's ingress with (RFC 4568). `None` for a plaintext / audio-only call.
    /// Captured at offer, consumed at answer to build the near text leg.
    near_text_remote_crypto: Option<CryptoAttribute>,
    /// The engine's own SDES key advertised to the far (answerer, B) leg in the secure `m=text` offer —
    /// the local key the far text `SecureLeg` encrypts egress toward B with (RFC 4568). `None` for a
    /// plaintext / audio-only call. Minted at offer, consumed at answer, and re-presented to B by a
    /// re-offer from A (a re-offer re-presents the existing key, it never mints a new one).
    far_text_local_crypto: Option<CryptoAttribute>,
    /// The engine's own SDES key advertised to the near (offerer, A) leg in the secure `m=text` **answer**
    /// — the local key the near text `SecureLeg` encrypts egress toward A with (RFC 4568), minted at
    /// `answer()`. Kept so a re-offer from B re-presents the SAME `a=crypto` to A, and A's answer to it
    /// is keyed against that one. It protects the engine's text toward A, so it is never shown to B.
    /// `None` for a plaintext / audio-only call. (HA follow-up: the HA `CallSnapshot` does not yet carry
    /// this — secure-text HA restore is deferred.)
    near_text_local_crypto: Option<CryptoAttribute>,
}

/// A DTLS-SRTP offerer the engine terminates (RFC 5764): A's keying from its offer, and what the
/// engine settled toward A when it answered. The near-leg twin of the far leg's DTLS state.
#[derive(Debug, Clone)]
struct NearDtls {
    /// A's certificate fingerprint (`a=fingerprint`, RFC 8122), which the handshake verifies
    /// (RFC 5763 §5).
    peer_fingerprint: sdp::Fingerprint,
    /// A's `a=setup`, `None` when A sent none (RFC 4145 §4.1 then defaults the offer to `active`).
    peer_setup: Option<sdp::Setup>,
    /// A's `a=tls-id` (RFC 8842 §4), `None` when A sent none.
    peer_tls_id: Option<String>,
    /// The engine's DTLS role toward A, settled at answer. `None` before an answer.
    role: Option<DtlsRole>,
    /// The engine's own `a=tls-id` toward A: assigned for a new association when A signalled one, and
    /// repeated for as long as that association is kept (RFC 8842 §5.3). `None` when A sent none.
    local_tls_id: Option<String>,
}

impl NearDtls {
    /// Take A's keying from a subsequent offer (RFC 8842 §5.5). A different certificate fingerprint or
    /// `a=tls-id` is a new association (RFC 8842 §3.1): the settled role and the engine's own
    /// `a=tls-id` are dropped, so the answer settles both afresh (RFC 8842 §5.3). A re-offer without a
    /// fingerprint changes nothing here; the re-offer refuses it before any state is touched.
    fn restate(&mut self, offer: &sdp::MediaInfo) {
        let Some(fingerprint) = offer.fingerprint.clone() else {
            return;
        };
        let (setup, tls_id) = (offer.setup, offer.tls_id.clone());
        let same_association = self
            .peer_fingerprint
            .hash_function
            .eq_ignore_ascii_case(&fingerprint.hash_function)
            && self.peer_fingerprint.bytes == fingerprint.bytes
            && self.peer_tls_id == tls_id;
        if !same_association {
            self.role = None;
            self.local_tls_id = None;
        }
        self.peer_fingerprint = fingerprint;
        self.peer_setup = setup;
        self.peer_tls_id = tls_id;
    }

    /// Take A's keying from its answer to the engine's subsequent offer, which offered `actpass`
    /// (RFC 8842 §5.5). The answerer picks, so the engine takes the complement of A's `a=setup`, and an
    /// answer without one is `passive` (RFC 4145 §4.1). An `actpass` or `holdconn` answer picks
    /// nothing, and the role in force is kept.
    fn answered(
        &mut self,
        fingerprint: sdp::Fingerprint,
        setup: Option<sdp::Setup>,
        tls_id: Option<String>,
    ) {
        self.role = match setup {
            Some(sdp::Setup::Active) => Some(DtlsRole::Server),
            Some(sdp::Setup::Passive) | None => Some(DtlsRole::Client),
            Some(sdp::Setup::Actpass | sdp::Setup::Holdconn) => self.role,
        };
        self.peer_fingerprint = fingerprint;
        self.peer_setup = setup;
        self.peer_tls_id = tls_id;
    }
}

/// A runtime reason a plain passthrough relay is held in the userspace media pipeline (promoted off
/// the in-kernel `Forward` fast path so a per-packet feature can attach). SIPREC subscriptions hold a
/// relay up too, but are tracked by the `subscriptions` map; these are the reasons with no other home.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum PromotionReason {
    /// A raw-RTP pcap recording is active (`start recording`).
    Recording,
    /// A **decoded-audio** recording is active (`start_recording` with `format: "wav"`). Distinct
    /// from `Recording` because that one is a *relay-only* hold — a pcap forwards RTP verbatim and
    /// never decodes — while this one taps the post-decode fan-out and so needs a **processing**
    /// pipeline. Sharing the variant would let stopping one demote the other's pipeline out from
    /// under it, and would make `upgrade_relay_to_processing` refuse over a hold that does not
    /// conflict with it.
    AudioRecording,
    /// A per-leg RFC 4733 telephone-event (DTMF) relay block is active (`block DTMF`) — the relay is
    /// held in userspace so the actor can gate the telephone-event PT per direction.
    DtmfBlock,
    /// Control-plane RFC 4103 text-event observability is on (`ProfileFlags.text_events`) — holds the
    /// **text** stream (never audio) in the userspace [`crate::text_pipeline`] so it emits
    /// [`Event::Text`]. Only ever appears in a call's `text_promotion_reasons`, never `promotion_reasons`.
    TextEvents,
    /// The RFC 4103 text stream is **secure** (SDES-SRTP) — it must terminate SRTP in the userspace
    /// text processor (SRTP cannot relay in-kernel), so it is held there for the call's whole life and
    /// never demoted. A permanent hold, inserted at `answer()` and never released (unlike `TextEvents` /
    /// `Recording`). Only ever appears in a call's `text_promotion_reasons`.
    Secure,
    /// Echo-test mode is on (`Command::Echo`) — the relay is held in a **processing** MediaCall so the
    /// actor can decode each party's ingress and re-emit it back to the sender (a relay-only promotion
    /// forwards opaque payloads to the peer and cannot loop them home).
    Echo,
    /// A WebSocket **tee** is streaming this call's audio (`attach_ws_tee`). The tee taps the
    /// post-decode fan-out, so a plain relay must be held in a **processing** MediaCall — a relay-only
    /// promotion forwards RTP verbatim and never decodes, which would leave the tee with nothing.
    WsTee,
    /// Lawful-interception content delivery is active on this call (`attach_x3`). The X3 tap sits in
    /// `Direction::handle` on the decrypted ingress, *before* the relay/transcode split, so a
    /// **relay-only** promotion is enough — an intercepted plain relay is not forced into a decode
    /// and re-encode it did not otherwise need.
    X3,
    /// A userspace media op (`play_media`) needs a **processing** MediaCall to synthesize egress
    /// audio on an offer-only single-leg IVR call (or a plain relay). Unlike `Echo`, this hold is
    /// never released on its own — once a prompt has played, the call is a media-processing call for
    /// the rest of its dialog and is torn down by `delete` (an IVR call does not fall back to a
    /// kernel relay). Harmless on an already-transcoding call (demotion is gated on `relay_flows`).
    MediaOp,
}

/// How [`Engine::hold_in_userspace`] promotes a plain passthrough relay into the userspace media
/// pipeline. A relay-only promotion forwards RTP verbatim to the peer (enough for recording / a raw
/// SIPREC tee / gating a telephone-event PT); a processing promotion decodes and re-encodes, which
/// echo needs to reflect audio back to the sender.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PromoteMode {
    /// Forward ingress RTP verbatim to the peer (recording / DTMF-block / SIPREC tee).
    RelayOnly,
    /// Decode ingress → re-encode (echo reflects each party's audio back to itself).
    Processing,
}

impl Call {
    /// Whether this call has **one** RTP party rather than two: no `answer` ever arrived, so there is
    /// no far peer and no `to_tag` (RFC 3264 — a dialog's answerer tag is what makes the second party
    /// real). True for `answer_local` (IVR / announcement / echo / voice-AI: the engine *is* the far
    /// side) and for an offer-only call the controller answered itself; false the moment `answer`
    /// records a `to_tag`. `to_tag` alone is sufficient — it is only ever set together with the far
    /// leg's `remote_rtp`, and never cleared.
    fn is_single_leg(&self) -> bool {
        self.to_tag.is_none()
    }

    /// The leg whose socket the caller actually reaches on a single-leg call — the one the engine
    /// advertised and the one the media rides (see [`CallerMediaLeg`]). Falls back to the near leg if
    /// a call somehow claims `Far` without owning one, which cannot happen: only `offer` records
    /// `Far`, and `offer` always allocates both legs. Meaningless on an answered call; guard with
    /// [`Call::is_single_leg`].
    fn caller_leg(&self) -> &Leg {
        match (self.caller_media_leg, self.far.as_ref()) {
            (CallerMediaLeg::Far, Some(far)) => far,
            _ => &self.near,
        }
    }

    /// Every audio endpoint this call owns, near leg first — the CDR counters, the media-timeout
    /// sweep, and teardown all walk this rather than assuming two legs exist.
    fn endpoint_ids(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.near
            .endpoint_ids()
            .chain(self.far.iter().flat_map(Leg::endpoint_ids))
    }

    /// As [`Call::endpoint_ids`], including each leg's RFC 4103 text endpoint — teardown and the
    /// call-id index, which must free text ports and let text activity keep the call alive.
    fn all_endpoint_ids(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.near
            .all_endpoint_ids()
            .chain(self.far.iter().flat_map(Leg::all_endpoint_ids))
    }

    /// The far leg of a call a test has already driven through `answer`, so it has one.
    #[cfg(test)]
    fn far_leg(&self) -> &Leg {
        self.far.as_ref().expect("an answered call has a far leg")
    }

    /// Whether the signalling has taken this call off two-way media — hold, park or queue — so that
    /// nobody owes us a packet and silence proves nothing about the path.
    ///
    /// RFC 3264 §8.4 is the whole basis: a party places a call on hold by offering `sendonly` (answered
    /// `recvonly`), or `inactive` when both ends hold it, and in **every** one of those shapes the spec
    /// permits the remaining direction to carry nothing at all — *"the party placing the call on hold
    /// MAY send media (e.g., music on hold) or MAY send nothing"*. So `sendonly` guarantees a packet no
    /// more than `recvonly` does, and a per-direction flow analysis would still reap the commonest hold
    /// of all (a handset that marks the stream `sendonly` and then simply stops transmitting).
    ///
    /// The test is therefore "has either party taken the stream off `sendrecv`". On a two-party call a
    /// direction attribute other than `sendrecv` exists precisely to suspend the two-way flow, and that
    /// is exactly the state whose silence must not be read as a dead path. On a single-leg call
    /// (`answer_local`: IVR, announcement, voicemail) there is no second party — `far_direction` stays
    /// at its `sendrecv` default and the caller's own attribute decides.
    fn is_held(&self) -> bool {
        self.near_direction != sdp::MediaDirection::SendRecv
            || self.far_direction != sdp::MediaDirection::SendRecv
    }

    /// The role of one of this call's four possible endpoints, or `None` if the id is not one of
    /// them. Used to snapshot flows by role (the node-independent stand-in for a datapath id).
    fn endpoint_role(&self, id: EndpointId) -> Option<crate::ha::EndpointRole> {
        use crate::ha::EndpointRole;
        if id == self.near.rtp.id {
            Some(EndpointRole::NearRtp)
        } else if self.near.rtcp.map(|endpoint| endpoint.id) == Some(id) {
            Some(EndpointRole::NearRtcp)
        } else if self.far.as_ref().is_some_and(|far| id == far.rtp.id) {
            Some(EndpointRole::FarRtp)
        } else if self
            .far
            .as_ref()
            .and_then(|far| far.rtcp)
            .map(|endpoint| endpoint.id)
            == Some(id)
        {
            Some(EndpointRole::FarRtcp)
        } else {
            None
        }
    }

    /// This call's `(endpoint id, role)` pairs, in a fixed order — so the checkpoint handler can map
    /// the SRTP bridge's flow ids back to roles and reach the shared secure leg.
    fn endpoint_roles(&self) -> Vec<(EndpointId, crate::ha::EndpointRole)> {
        use crate::ha::EndpointRole;
        let mut roles = vec![(self.near.rtp.id, EndpointRole::NearRtp)];
        if let Some(endpoint) = self.near.rtcp {
            roles.push((endpoint.id, EndpointRole::NearRtcp));
        }
        if let Some(far) = &self.far {
            roles.push((far.rtp.id, EndpointRole::FarRtp));
            if let Some(endpoint) = far.rtcp {
                roles.push((endpoint.id, EndpointRole::FarRtcp));
            }
        }
        roles
    }

    /// Capture this call's replicable negotiated state as a portable [`crate::ha::CallSnapshot`] for
    /// HA failover. Node-local handles (sockets, ids) and ephemeral media state are excluded; a secure
    /// call's live SRTP state (rollover + bridge flows) lives in the bridge, so the checkpoint handler
    /// folds it in afterwards (this method only sees the `Call`).
    ///
    /// `None` for a single-leg call: the snapshot format is a two-leg record, and a single-leg IVR /
    /// echo / voice-AI call has no far leg to fill it with. Refusing beats emitting a blob a standby
    /// would "restore" into a two-party relay that never existed — the caller is told plainly instead.
    fn to_snapshot(&self) -> Option<crate::ha::CallSnapshot> {
        use crate::ha;
        let far = self.far.as_ref()?;
        let flows = self
            .relay_flows
            .iter()
            .filter_map(|(endpoint, action)| {
                // Only `Forward` rules are portable; `Redirect`/`Drop` carry no reconstructable state.
                let FlowAction::Forward(rule) = action else {
                    return None;
                };
                Some(ha::FlowSnapshot {
                    installed_on: self.endpoint_role(*endpoint)?,
                    out: self.endpoint_role(rule.out_endpoint)?,
                    out_dst: rule.out_dst,
                    accepted_source: source_filter_snapshot(rule.accepted_source),
                    latch: latch_snapshot(rule.latch),
                })
            })
            .collect();
        Some(ha::CallSnapshot {
            version: ha::SNAPSHOT_VERSION,
            call_id: String::new(), // filled by the caller, which holds the registry key
            from_tag: self.from_tag.clone(),
            to_tag: self.to_tag.clone(),
            pipeline: pipeline_snapshot(self.pipeline),
            ice: self.ice.as_ref().map(|ice| ha::IceSnapshot {
                ufrag: ice.ufrag.clone(),
                pwd: ice.pwd.clone(),
            }),
            far_local_crypto: self.far_local_crypto.as_ref().map(crypto_snapshot),
            near_codec: self.near_codec.as_ref().map(codec_snapshot),
            far_codec: self.far_codec.as_ref().map(codec_snapshot),
            near_telephone_event: self.near_telephone_event,
            near: leg_snapshot(&self.near),
            far: leg_snapshot(far),
            flows,
            // Populated by the checkpoint handler for a secure call (it has the SRTP bridge);
            // `to_snapshot` only sees the `Call`, which does not hold the live crypto state.
            secure: None,
        })
    }
}

/// How a call's media is carried once answered. The resolver picks this from the profile + the two
/// legs' negotiated codecs (see [`Engine::resolve_pipeline`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelineKind {
    /// Plain in-datapath relay (the `Forward` fast path) — both legs share a codec, no record/stream.
    Passthrough,
    /// Userspace SRTP bridge (an `RTP/AVP` ↔ `RTP/SAVP` secure leg) — the **far** (answerer) leg is
    /// the secure one.
    Srtp,
    /// Userspace SRTP bridge where the **near** (offerer) leg is the secure one: a secure caller
    /// toward a plain callee. The mirror of [`PipelineKind::Srtp`] — the same flows with the
    /// endpoints and crypto ops swapped — over the engine's own key toward A.
    SrtpOfferer,
    /// Userspace media slow path: transcode / record / DTMF-extraction via a [`MediaCall`] actor.
    Media,
    /// Secure **and** transcoding: the far (`RTP/SAVP`) leg's codec differs from the near (plaintext)
    /// leg's, so the [`MediaCall`] actor decrypts the secure ingress, transcodes, and encrypts the
    /// secure egress — one shared SRTP leg threaded into both directions (BGCF/SBC PSTN breakout).
    SrtpMedia,
    /// WebSocket bridge: leg A's audio is attached to an external WS media server (mod_audio_stream /
    /// voice-AI). The A↔B relay/transcode path is not wired — the WS server is A's far side.
    Ws,
    /// Userspace DTLS-SRTP bridge (an `RTP/AVP` ↔ `UDP/TLS/RTP/SAVPF` secure leg, RFC 5764): like
    /// [`PipelineKind::Srtp`] but the far leg is keyed by a DTLS handshake, not SDES.
    Dtls,
    /// DTLS-SRTP **and** media-processing: the DTLS analogue of [`PipelineKind::SrtpMedia`]. The
    /// far (`UDP/TLS/RTP/SAVPF`) leg's media reaches the [`MediaCall`] actor instead of being relayed
    /// opaquely, so a WebRTC leg can be transcoded, recorded, noise-suppressed, WS-bridged or teed.
    /// The [`crate::dtls_bridge::DtlsBridge`] keeps the RFC 7983 demux and the handshake; the actor
    /// owns the crypto and is keyed asynchronously when the handshake completes.
    DtlsMedia,
    /// Userspace DTLS-SRTP bridge where the **near** (offerer) leg is the DTLS one: a WebRTC caller
    /// toward a plain callee. The mirror of [`PipelineKind::Dtls`], with the bridge's secure side
    /// facing A and the engine's own fingerprint in A's answer, as [`PipelineKind::SrtpOfferer`]
    /// mirrors [`PipelineKind::Srtp`].
    DtlsOfferer,
}

impl PipelineKind {
    /// Whether the call's media runs through a crypto bridge, which relays SRTP without decoding it.
    /// Nothing that needs the decoded audio (a recording, a tee, a SIPREC fork, a DTMF block) has
    /// anything to attach to on such a call.
    fn is_crypto_bridge(self) -> bool {
        matches!(
            self,
            Self::Srtp | Self::SrtpOfferer | Self::Dtls | Self::DtlsOfferer
        )
    }
}

/// The session engine, generic over a [`Datapath`] backend.
///
/// The backend must be `Clone + 'static` (already true of every backend): the media slow path
/// spawns a per-call actor that owns a datapath handle.
pub struct Engine<D: Datapath> {
    datapath: D,
    calls: DashMap<String, Call>,
    /// Maximum concurrent calls per control client; `usize::MAX` is unbounded.
    max_calls_per_client: usize,
    /// Live call count per client, for the per-client quota.
    client_calls: DashMap<ClientId, usize>,
    /// Per-client async event channels, registered by the control server as each connection
    /// arrives. Keyed by [`ClientId`], not by connection, so a reconnecting controller re-registers
    /// over the same channel — see [`ClientSink`].
    events: DashMap<ClientId, ClientSink>,
    /// Stamps each event-sink registration so a superseded connection cannot release its
    /// successor's sink. See [`ClientGeneration`].
    next_client_generation: std::sync::atomic::AtomicU64,
    /// Stable control-client identity: the `controller_id` a connection presents at `Authenticate`
    /// → the [`ClientId`] ownership, the quota and event delivery are keyed by. A row outlives the
    /// connection that created it, which is what makes a reconnect re-attach to its own calls.
    controllers: DashMap<Arc<str>, ControllerIdentity>,
    /// Reverse index of [`Self::controllers`], so releasing a client's last call can reap its
    /// identity row once no connection is attached to it.
    controller_ids: DashMap<ClientId, Arc<str>>,
    /// Reverse index endpoint → call-id, correlating observed RTCP back to its call (HEP telemetry).
    endpoint_calls: DashMap<EndpointId, String>,
    /// The userspace SRTP bridge: the `Redirect`-path crypto for secure (`RTP/SAVP`) legs. Shared
    /// with the redirect dispatcher (see [`crate::srtp_bridge`]).
    bridge: Arc<SrtpBridge<D>>,
    /// The userspace media slow path: per-call transcode / record / DTMF actors. Shared with the
    /// redirect dispatcher, which routes media-owned endpoints' datagrams here (see
    /// [`crate::media_pipeline`]).
    media: Arc<MediaRegistry>,
    /// The WebSocket-bridge slow path: per-call WS bridges (mod_audio_stream / voice-AI). Shared with
    /// the redirect dispatcher, which routes WS-owned endpoints' datagrams here (see
    /// [`crate::ws_bridge`]).
    ws: Arc<WsRegistry>,
    /// The conference (MCU) slow path: per-room N-party mixers. Shared with the redirect dispatcher,
    /// which routes conference-owned participant endpoints' datagrams here (see [`crate::conference`]).
    conference: Arc<ConferenceRegistry>,
    /// Per conference seat, the task following its ICE-validated source into the room's egress. Only
    /// an ICE seat has one, and it is aborted wherever the seat is dropped (leave, ICE failure, idle
    /// reap), so it never outlives the participant.
    seat_ice_followers: DashMap<EndpointId, tokio::task::JoinHandle<()>>,
    /// The RFC 4103 Real-Time Text observability slow path: per-call text processors that RED/T.140
    /// observe a promoted `m=text` stream (recording / `text_events`) then forward it verbatim. Shared
    /// with the redirect dispatcher, which routes text-owned endpoints' datagrams here (see
    /// [`crate::text_pipeline`]). Only the low-rate text stream is ever promoted here — audio is never
    /// promoted for text observability.
    text: Arc<TextRegistry>,
    /// SIPREC / monitor media subscriptions, keyed by call-id (RFC 7866). Each entry's source leg is
    /// forked to a send-only subscriber endpoint; freed alongside the parent call on delete/reap.
    subscriptions: DashMap<String, Vec<Subscription>>,
    /// Operational counters (offers/answers/deletes/errors), incremented on the control path and
    /// rendered by the `/metrics` HTTP endpoint. Shared so the metrics server reads the same surface.
    metrics: Arc<Metrics>,
    /// Cluster identity, capacity, and drain flag — the state behind the `load` / `node_info` /
    /// `drain` / `undrain` control commands (see [`crate::cluster`]). Shared so the CPU sampler and
    /// the control path see one surface.
    cluster: Arc<ClusterState>,
    /// The engine's DTLS-SRTP certificate (self-signed; RFC 5763 §5), whose fingerprint is advertised
    /// in `a=fingerprint` on a DTLS leg. Generated once at startup and reused for every leg; `None`
    /// only if generation failed, in which case DTLS-SRTP offers are rejected.
    dtls_certificate: Option<DtlsCertificate>,
    /// TLS client configuration for `wss://` WebSocket-bridge dials (mod_audio_stream / voice-AI).
    /// Built lazily once on the first bridge dial (the ring/rustls provider — the project's zero-C
    /// TLS stack, never aws-lc-rs — with its trust store seeded from the webpki-roots Mozilla CA
    /// bundle) and reused for every leg. A `ws://` dial ignores it. Tests may pre-seed it to trust a
    /// self-signed server certificate.
    ws_tls_config: std::sync::OnceLock<Arc<rustls::ClientConfig>>,
    /// Named-interface policy (rtpengine-style): maps the control `direction` pair to each leg's bind
    /// and advertised address at SDP-rewrite time. The zero-config default is a single loopback
    /// interface (advertise whatever the datapath bound), so existing tests are behaviour-preserving;
    /// the daemon replaces it via [`Self::with_interfaces`] from config. Shared read-only (`Arc`).
    interfaces: Arc<InterfaceTable>,
    /// Monotonic source of `play_media` playback ids. Each accepted play draws the next value, echoed
    /// in the accept's `play_id` and in the matching [`Event::PlayFinished`], so a controller
    /// correlates a completion with the specific prompt it started (a leg may play several in sequence).
    play_id_counter: std::sync::atomic::AtomicU64,
    /// Bounds on a [`PlayMediaSource::Http`] fetch — connect / first-byte / overall timeouts, the
    /// body-size cap, the redirect cap and the optional host allow-list. Defaults are the ones
    /// documented on [`MediaFetchLimits`]; the daemon replaces them from config
    /// ([`Self::with_media_fetch_limits`]).
    media_fetch_limits: MediaFetchLimits,
    /// Playbacks accepted from a URL whose fetch has not finished yet, keyed by `play_id`.
    ///
    /// A URL playback accepts before its bytes exist, so between the accept and the fetch there is a
    /// window in which the controller holds a `play_id` for something the media actor has never
    /// heard of. `stop_media` and call teardown consult this map so that window is still
    /// cancellable — otherwise a stopped playback would start playing a second later. Shared with
    /// the fetch tasks (`Arc`), which remove their own entry when they finish.
    pending_fetches: Arc<DashMap<u64, PendingFetch>>,
    /// RFC 7675 consent freshness, when the operator enabled it (`--ice-consent`). `None` ⇒ the
    /// engine only *answers* checks (the RFC 7675 §4 ICE-lite posture) and dead paths are caught by
    /// the media-timeout sweep alone. Shared with the sweeper task, which drives it once per tick.
    consent: Option<Arc<ConsentSupervisor>>,
    /// The full RFC 8445 agents, when the operator enabled `--ice full`. `None` ⇒ the ICE-lite
    /// responder posture. Shared with the driver task, which polls them on a sub-second clock.
    ice_agents: Option<Arc<AgentSupervisor>>,
    /// STUN servers asked for a server-reflexive candidate during gathering (RFC 8445 §5.1.1.2).
    /// Empty (the default) ⇒ host-only gathering, which is correct for a directly-addressable engine
    /// and costs no network round trip at call setup.
    stun_servers: Vec<SocketAddr>,
    /// The TURN server relayed candidates are allocated against (RFC 5766), with its long-term
    /// credentials. `None` disables relayed gathering entirely, which is the right default for a
    /// directly-addressable engine — a relay adds a hop and no reachability there.
    turn_server: Option<TurnServerConfig>,
    /// Live TURN allocations, one per gathering endpoint that got one. Driven on the ICE tick:
    /// refreshed before they lapse, and given a permission + channel for every remote candidate the
    /// checklist may probe.
    ice_relays: Arc<DashMap<EndpointId, TurnAllocation>>,
    /// Live WebSocket **tees**, keyed by call-id — the send-only audio streams riding a relaying call
    /// (`attach_ws_tee` / `ProfileFlags::ws_tee`). One per call; attaching again replaces the previous
    /// one. Held here (not in the media actor) because the transport task, the WS socket and the
    /// dropped/forwarded counters outlive individual control ops and must be torn down on `delete`.
    ws_tees: DashMap<String, WsTee>,
    /// Decoded host-file prompts, so a bed played to many callers is decoded once
    /// ([`crate::prompt_cache`]).
    prompts: Arc<crate::prompt_cache::PromptCache>,
    /// Live decoded-audio recordings, keyed by their `recording_id`. Several may run on one call (a
    /// per-leg pair, or an audit recording alongside a voicemail), so this is not keyed by call.
    recordings: DashMap<String, AudioRecording>,
    /// Monotonic source for `recording_id`, so two recordings on one call never collide.
    next_recording_id: std::sync::atomic::AtomicU64,
    /// Live WebSocket **takeover** bridges, keyed by call-id — the control-plane half of what the
    /// [`crate::ws_bridge::WsRegistry`] routes. One per call; attaching again re-points it. Held
    /// here for the same reason `ws_tees` is: the `ws_bridge_ended` event is emitted during teardown,
    /// after `delete` has removed the `Call` the tag and owner would have come from.
    ws_bridges: DashMap<String, WsBridge>,
    /// Operator configuration for lawful-interception content delivery (ETSI TS 103 221-2 X3), set
    /// by the daemon from the `x3_*` config keys.
    ///
    /// `None` — the default — means the node is not provisioned for interception, and `attach_x3`
    /// is **refused**. That refusal is deliberate: an intercept accepted onto a node with no
    /// delivery PKI would look wired and deliver nothing, which is the failure mode a compliance
    /// audit finds long after the warrant expired.
    x3_config: Option<Arc<X3Config>>,
    /// TLS client configuration for X3 delivery, built once from [`Self::x3_config`]. Separate from
    /// `ws_tls_config` because it needs a client certificate (the Mediation Function authenticates
    /// the network element) and a private CA (the Mozilla bundle will not contain it).
    x3_tls_config: std::sync::OnceLock<Arc<rustls::ClientConfig>>,
    /// Live interceptions, keyed by call-id. One per call; attaching again replaces the previous
    /// one. Held here rather than in the media actor because the delivery task, its TLS connection
    /// and the delivered/dropped counters outlive individual control ops and must be torn down on
    /// `delete`.
    x3_sessions: DashMap<String, X3Session>,
    /// The HEP telemetry export (VoIPmonitor / Homer), when the daemon enabled it via
    /// `SIPHON_RTP_HEP_COLLECTOR`. Set once at startup (after the engine is `Arc`-wrapped, so interior
    /// mutability), then shared read-only by the [`Self::run_rtcp_export`] task (per-interval RTCP/QoS)
    /// **and** the `finish_call` teardown path (end-of-call RFC 4103 text content QoS). `None`/unset ⇒
    /// HEP export disabled. Held so both the live RTCP loop and the teardown path reach the one exporter.
    hep_export: std::sync::OnceLock<HepExport>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The engine's DTLS certificate fingerprint as advertised in `a=fingerprint` (RFC 8122), or `None`
    /// when the engine has no certificate. The same certificate backs every DTLS leg, so every SDP
    /// presenting one — offer, re-offer or answer — carries the same value (RFC 8842 §5.5: an unchanged
    /// fingerprint set is what keeps the existing association).
    fn engine_fingerprint(&self) -> Option<sdp::Fingerprint> {
        let fingerprint = self.dtls_certificate.as_ref()?.fingerprint();
        Some(sdp::Fingerprint {
            hash_function: fingerprint.hash_function,
            bytes: fingerprint.bytes,
        })
    }

    /// Allocate `count` endpoints of `family`, rolling back all of them if any allocation fails. The
    /// family is the address family of the call's signalled `c=` line (RFC 4566 §5.7), so a
    /// `c=IN IP6` call gets v6 engine endpoints and a `c=IN IP4` call gets v4.
    ///
    /// `bind` selects the local source IP (named-interface selection): `Some(ip)` binds/emits from that
    /// exact IP via [`Datapath::alloc_endpoint_on`]; `None` uses the datapath's family default
    /// ([`Datapath::alloc_endpoint_for`]). The caller resolves `bind` from the interface table so a
    /// v6 leg on a v4-only interface still binds the datapath's v6 default rather than a wrong-family IP.
    async fn alloc_endpoints(
        &self,
        count: usize,
        family: AddressFamily,
        bind: Option<std::net::IpAddr>,
    ) -> Result<Vec<Endpoint>, String> {
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            let allocated = match bind {
                Some(ip) => self.datapath.alloc_endpoint_on(ip).await,
                None => self.datapath.alloc_endpoint_for(family).await,
            };
            match allocated {
                Ok(endpoint) => endpoints.push(endpoint),
                Err(error) => {
                    for allocated in &endpoints {
                        self.datapath.remove_endpoint(allocated.id).await;
                    }
                    return Err(format!("alloc endpoint: {error}"));
                }
            }
        }
        Ok(endpoints)
    }

    /// Resolve a leg's `(bind, advertised)` addresses for the chosen interface + family. `bind =
    /// Some(ip)` asks the datapath to source the leg from that exact IP (a same-family interface
    /// address); `None` means "use the datapath's family default". `advertised = Some(ip)` overrides
    /// the SDP address; `None` means "advertise whatever the datapath bound". Both are `None` when the
    /// interface serves no address of the leg's family, preserving the pre-interface behaviour.
    fn leg_binding(
        interface: &Interface,
        family: AddressFamily,
    ) -> (Option<std::net::IpAddr>, Option<std::net::IpAddr>) {
        match interface.exact_address_for(family) {
            Some(address) => (Some(address.bind), Some(address.advertised)),
            None => (None, None),
        }
    }

    async fn free(&self, endpoints: &[Endpoint]) {
        for endpoint in endpoints {
            self.datapath.remove_endpoint(endpoint.id).await;
        }
    }

    /// Hand each of `endpoints` to the userspace dispatcher (`FlowAction::Redirect`), refusing under
    /// `context` at the first one the datapath will not take.
    fn redirect_endpoints(
        &self,
        endpoints: impl IntoIterator<Item = EndpointId>,
        context: &str,
    ) -> Result<(), Box<CmdResult>> {
        for endpoint in endpoints {
            if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                return Err(boxed_error_result(context, &error));
            }
        }
        Ok(())
    }

    /// Current live call count for `client`.
    fn client_call_count(&self, client: ClientId) -> usize {
        self.client_calls.get(&client).map_or(0, |count| *count)
    }

    /// Release one call from `client`'s quota, dropping the entry when it reaches zero so the map
    /// does not retain rows for disconnected clients.
    fn release_client_call(&self, client: ClientId) {
        let mut drained = false;
        if let Some(mut count) = self.client_calls.get_mut(&client) {
            *count = count.saturating_sub(1);
            drained = *count == 0;
        }
        if drained {
            self.client_calls.remove_if(&client, |_, &count| count == 0);
            // A controller identity outlives its connection only so the calls it owns stay
            // reachable. With the last one released there is nothing left to re-attach to, so the
            // row goes — otherwise a control plane reachable without a secret could be made to
            // retain one row per identity it is ever shown.
            self.reap_detached_controller(client);
        }
    }

    /// Run `f` against a call the client owns, or `None` if the call is unknown or owned by another
    /// client (A3 — a call is invisible to non-owners, docs §5).
    fn owned_call<T>(
        &self,
        client: ClientId,
        call_id: &str,
        f: impl FnOnce(&Call) -> T,
    ) -> Option<T> {
        let call = self.calls.get(call_id)?;
        (call.owner == client).then(|| f(&call))
    }

    /// Run `f` against a call by id without an ownership check (an internal helper for promotion /
    /// demotion, which already validated ownership via the public verb). Returns `None` if unknown.
    fn owned_call_internal<T>(&self, call_id: &str, f: impl FnOnce(&Call) -> T) -> Option<T> {
        self.calls.get(call_id).map(|call| f(&call))
    }
}

fn ok_sdp(sdp: String, to_tag: Option<String>) -> CmdResult {
    CmdResult::Ok {
        sdp: Some(sdp),
        duration_ms: None,
        play_id: None,
        recording_id: None,
        to_tag,
        stats: None,
    }
}

/// A bare success (no SDP/stats) — the reply to control verbs like block/silence.
fn ok_empty() -> CmdResult {
    CmdResult::Ok {
        sdp: None,
        duration_ms: None,
        play_id: None,
        recording_id: None,
        to_tag: None,
        stats: None,
    }
}

fn unknown_call(call_id: &str) -> CmdResult {
    CmdResult::Error {
        reason: format!("unknown call: {call_id}"),
    }
}

fn error_result(context: &str, error: &dyn std::fmt::Display) -> CmdResult {
    CmdResult::Error {
        reason: format!("{context}: {error}"),
    }
}

/// [`error_result`], boxed for the `Err` of an internal `Result`: a `CmdResult` is too large to
/// return by value on every success path.
fn boxed_error_result(context: &str, error: &dyn std::fmt::Display) -> Box<CmdResult> {
    Box::new(error_result(context, error))
}

#[cfg(test)]
mod tests;
