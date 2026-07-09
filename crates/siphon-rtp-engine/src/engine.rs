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

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{
    AddressFamily, Datapath, Endpoint, EndpointId, FlowAction, ForwardRule, IceConfig, LatchPolicy,
    ObservedRtcp, SourceFilter,
};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, Fingerprint as DtlsFingerprint};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_hep::mos::Impairments;
use siphon_rtp_hep::report::QosReport;
use siphon_rtp_hep::{protocol_type, Capture};
use siphon_rtp_media::pcap::{self, CapturedPacket};
use siphon_rtp_media::player::{PcmPlayer, WavSource};
use siphon_rtp_media::wav::WavRecorder;
use siphon_rtp_proto::{
    BridgeDirection, CmdResult, Command, ConferenceRole, EngineStatistics, Event, PlayMediaSource,
    ProfileFlags, SessionStats,
};
use siphon_rtp_srtp::leg::{SecureLeg, SecureLegRollover};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite, SrtpKeyMaterial};
use siphon_rtp_srtp::StreamRollover;

use crate::cluster::ClusterState;
use crate::conference::{ConferenceRegistry, ParticipantConfig, Routing};
use crate::dtls_bridge::{DtlsBridge, DtlsCallPlan};
use crate::ice::{self, IceCredentials};
use crate::media_pipeline::{
    DirectionConfig, MediaCall, MediaControl, MediaRegistry, PcapCapture, RawTee, RelayConfig,
    RtcpRelay,
};
use crate::metrics::Metrics;
use crate::sdp::{self, EngineMedia, IceRewrite, SecurityAdvertisement};
use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, BridgeOp, SrtpBridge};
use crate::ws_bridge::WsRegistry;

use siphon_rtp_media::bridge::protocol::{Direction as WsDirection, MediaFormat};
use siphon_rtp_media::bridge::{run_bridge, BridgeSession};
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;
use siphon_rtp_media::mixer::Role;

/// Identity of a control client — one persistent JSON-over-TCP connection. A call is owned by the
/// client that created it via `offer`; only that client may answer, query, or delete it (A3 —
/// docs/security-and-nat.md §5). This assumes one persistent control connection per SIPhon instance;
/// a shared identity across a connection pool needs the deferred control-channel auth.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientId(pub u64);

/// One side of a call: an RTP endpoint, an optional companion RTCP endpoint (absent under
/// rtcp-mux), and the remote addresses learned from that side's SDP.
#[derive(Debug, Clone, Copy)]
struct Leg {
    rtp: Endpoint,
    rtcp: Option<Endpoint>,
    remote_rtp: Option<std::net::SocketAddr>,
    remote_rtcp: Option<std::net::SocketAddr>,
}

impl Leg {
    /// All datapath endpoints this leg owns (for teardown / stats).
    fn endpoint_ids(&self) -> impl Iterator<Item = EndpointId> {
        std::iter::once(self.rtp.id).chain(self.rtcp.map(|endpoint| endpoint.id))
    }
}

/// A negotiated (or half-negotiated) call: its owner and its two legs.
#[derive(Debug)]
struct Call {
    /// The control client that created the call; only it may answer/query/delete it.
    owner: ClientId,
    /// Logical-clock tick at creation (offer), the media-timeout baseline before any media arrives.
    created_tick: u64,
    /// The engine's own ICE-lite credentials for this call (its identity as the ICE server), or
    /// `None` for a non-ICE call.
    ice: Option<IceCredentials>,
    from_tag: String,
    to_tag: Option<String>,
    near: Leg,
    far: Leg,
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
    /// The near (offerer) leg's primary audio codec, captured at offer — paired with the answer's
    /// codec to decide whether the call transcodes (the media slow path).
    near_codec: Option<CodecSpec>,
    /// The far (answerer) leg's primary audio codec, captured at answer — the fork codec for a
    /// `subscribe_request` that forks leg B. `None` until the call is answered.
    far_codec: Option<CodecSpec>,
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
    /// no `received-from`. (The answer's own `received-from` gates the far (B) leg directly.)
    offer_received_from: Option<std::net::IpAddr>,
}

/// A runtime reason a plain passthrough relay is held in the userspace media pipeline (promoted off
/// the in-kernel `Forward` fast path so a per-packet feature can attach). SIPREC subscriptions hold a
/// relay up too, but are tracked by the `subscriptions` map; these are the reasons with no other home.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum PromotionReason {
    /// A raw-RTP pcap recording is active (`start recording`).
    Recording,
    /// A per-leg RFC 4733 telephone-event (DTMF) relay block is active (`block DTMF`) — the relay is
    /// held in userspace so the actor can gate the telephone-event PT per direction.
    DtmfBlock,
    /// Echo-test mode is on (`Command::Echo`) — the relay is held in a **processing** MediaCall so the
    /// actor can decode each party's ingress and re-emit it back to the sender (a relay-only promotion
    /// forwards opaque payloads to the peer and cannot loop them home).
    Echo,
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
    /// The role of one of this call's four possible endpoints, or `None` if the id is not one of
    /// them. Used to snapshot flows by role (the node-independent stand-in for a datapath id).
    fn endpoint_role(&self, id: EndpointId) -> Option<crate::ha::EndpointRole> {
        use crate::ha::EndpointRole;
        if id == self.near.rtp.id {
            Some(EndpointRole::NearRtp)
        } else if self.near.rtcp.map(|endpoint| endpoint.id) == Some(id) {
            Some(EndpointRole::NearRtcp)
        } else if id == self.far.rtp.id {
            Some(EndpointRole::FarRtp)
        } else if self.far.rtcp.map(|endpoint| endpoint.id) == Some(id) {
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
        roles.push((self.far.rtp.id, EndpointRole::FarRtp));
        if let Some(endpoint) = self.far.rtcp {
            roles.push((endpoint.id, EndpointRole::FarRtcp));
        }
        roles
    }

    /// Capture this call's replicable negotiated state as a portable [`crate::ha::CallSnapshot`] for
    /// HA failover. Node-local handles (sockets, ids) and ephemeral media state are excluded; a secure
    /// call's live SRTP state (rollover + bridge flows) lives in the bridge, so the checkpoint handler
    /// folds it in afterwards (this method only sees the `Call`).
    fn to_snapshot(&self) -> crate::ha::CallSnapshot {
        use crate::ha;
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
        ha::CallSnapshot {
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
            far: leg_snapshot(&self.far),
            flows,
            // Populated by the checkpoint handler for a secure call (it has the SRTP bridge);
            // `to_snapshot` only sees the `Call`, which does not hold the live crypto state.
            secure: None,
        }
    }
}

/// Map a [`Leg`] to its portable snapshot (local media ports + the peer's remote addresses).
fn leg_snapshot(leg: &Leg) -> crate::ha::LegSnapshot {
    crate::ha::LegSnapshot {
        rtp_local: leg.rtp.local_addr,
        rtcp_local: leg.rtcp.map(|endpoint| endpoint.local_addr),
        remote_rtp: leg.remote_rtp,
        remote_rtcp: leg.remote_rtcp,
    }
}

/// Map a [`CodecSpec`] to its snapshot (the wire-relevant fields).
fn codec_snapshot(codec: &CodecSpec) -> crate::ha::CodecSnapshot {
    crate::ha::CodecSnapshot {
        payload_type: codec.payload_type,
        encoding_name: codec.encoding_name.clone(),
        clock_rate_hz: codec.clock_rate_hz,
        channels: codec.channels,
        ptime_ms: codec.ptime_ms,
        encode_mode: codec.encode_mode,
    }
}

/// Reconstruct a [`CodecSpec`] from its snapshot on restore (for a transcode call's directions).
fn restore_codec(snapshot: &crate::ha::CodecSnapshot) -> CodecSpec {
    CodecSpec::new(
        snapshot.payload_type,
        &snapshot.encoding_name,
        snapshot.clock_rate_hz,
        snapshot.channels,
        snapshot.ptime_ms,
    )
    .with_encode_mode(snapshot.encode_mode)
}

/// Map an SDES [`CryptoAttribute`] to its snapshot (suite name + hex key material).
fn crypto_snapshot(crypto: &CryptoAttribute) -> crate::ha::CryptoSnapshot {
    crate::ha::CryptoSnapshot {
        tag: crypto.tag,
        suite: crypto.suite.name().to_string(),
        master_key_hex: crate::ha::to_hex(&crypto.key.master_key),
        master_salt_hex: crate::ha::to_hex(&crypto.key.master_salt),
    }
}

/// Map a [`SecureLegRollover`] (from the SRTP bridge) to its snapshot on checkpoint.
fn secure_rollover_snapshot(rollover: &SecureLegRollover) -> crate::ha::SecureLegRolloverSnapshot {
    let stream = |value: &StreamRollover| crate::ha::StreamRolloverSnapshot {
        ssrc: value.ssrc,
        roc: value.roc,
        highest_seq: value.highest_seq,
    };
    crate::ha::SecureLegRolloverSnapshot {
        inbound_rtp: rollover.inbound_rtp.iter().map(stream).collect(),
        outbound_rtp: rollover.outbound_rtp.iter().map(stream).collect(),
        outbound_rtcp_index: rollover.outbound_rtcp_index,
    }
}

/// Map the engine [`PipelineKind`] to its snapshot mirror.
fn pipeline_snapshot(pipeline: PipelineKind) -> crate::ha::PipelineSnapshot {
    use crate::ha::PipelineSnapshot;
    match pipeline {
        PipelineKind::Passthrough => PipelineSnapshot::Passthrough,
        PipelineKind::Srtp => PipelineSnapshot::Srtp,
        PipelineKind::Media => PipelineSnapshot::Media,
        PipelineKind::SrtpMedia => PipelineSnapshot::SrtpMedia,
        PipelineKind::Ws => PipelineSnapshot::Ws,
        PipelineKind::Dtls => PipelineSnapshot::Dtls,
    }
}

/// Map a datapath [`SourceFilter`] to its snapshot mirror.
fn source_filter_snapshot(filter: SourceFilter) -> crate::ha::SourceFilterSnapshot {
    use crate::ha::SourceFilterSnapshot;
    match filter {
        SourceFilter::Exact(ip) => SourceFilterSnapshot::Exact(ip),
        SourceFilter::Subnet(ip, bits) => SourceFilterSnapshot::Subnet(ip, bits),
        SourceFilter::Any => SourceFilterSnapshot::Any,
    }
}

/// Map a datapath [`LatchPolicy`] to its snapshot mirror.
fn latch_snapshot(latch: LatchPolicy) -> crate::ha::LatchSnapshot {
    use crate::ha::LatchSnapshot;
    match latch {
        LatchPolicy::Off => LatchSnapshot::Off,
        LatchPolicy::SignalledOnly => LatchSnapshot::SignalledOnly,
        LatchPolicy::Symmetric => LatchSnapshot::Symmetric,
    }
}

/// Map a snapshot source-filter back to the datapath [`SourceFilter`] on restore.
fn restore_source_filter(filter: crate::ha::SourceFilterSnapshot) -> SourceFilter {
    use crate::ha::SourceFilterSnapshot;
    match filter {
        SourceFilterSnapshot::Exact(ip) => SourceFilter::Exact(ip),
        SourceFilterSnapshot::Subnet(ip, bits) => SourceFilter::Subnet(ip, bits),
        SourceFilterSnapshot::Any => SourceFilter::Any,
    }
}

/// Map a snapshot latch policy back to the datapath [`LatchPolicy`] on restore.
fn restore_latch(latch: crate::ha::LatchSnapshot) -> LatchPolicy {
    use crate::ha::LatchSnapshot;
    match latch {
        LatchSnapshot::Off => LatchPolicy::Off,
        LatchSnapshot::SignalledOnly => LatchPolicy::SignalledOnly,
        LatchSnapshot::Symmetric => LatchPolicy::Symmetric,
    }
}

/// Reconstruct an SDES [`CryptoAttribute`] from its snapshot (hex-decoding the key/salt). Returns a
/// human-readable error for an unknown suite or malformed key material.
fn restore_crypto(snapshot: &crate::ha::CryptoSnapshot) -> Result<CryptoAttribute, String> {
    let suite = CryptoSuite::from_name(&snapshot.suite)
        .ok_or_else(|| format!("unknown crypto suite {}", snapshot.suite))?;
    let master_key: [u8; 16] = crate::ha::from_hex(&snapshot.master_key_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("invalid master key hex (want 16 bytes)")?;
    let master_salt: [u8; 14] = crate::ha::from_hex(&snapshot.master_salt_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("invalid master salt hex (want 14 bytes)")?;
    Ok(CryptoAttribute {
        tag: snapshot.tag,
        suite,
        key: SrtpKeyMaterial {
            master_key,
            master_salt,
        },
    })
}

/// Reconstruct a [`SecureLegRollover`] from its snapshot on restore.
fn restore_rollover(snapshot: &crate::ha::SecureLegRolloverSnapshot) -> SecureLegRollover {
    let stream = |value: &crate::ha::StreamRolloverSnapshot| StreamRollover {
        ssrc: value.ssrc,
        roc: value.roc,
        highest_seq: value.highest_seq,
    };
    SecureLegRollover {
        inbound_rtp: snapshot.inbound_rtp.iter().map(stream).collect(),
        outbound_rtp: snapshot.outbound_rtp.iter().map(stream).collect(),
        outbound_rtcp_index: snapshot.outbound_rtcp_index,
    }
}

/// Where a secure call's live SRTP rollover is sourced for an HA checkpoint. A plain secure leg
/// (`Srtp`) terminates SRTP in the [`crate::srtp_bridge::SrtpBridge`], so its rollover *and* the
/// in-datapath bridge flow plans are read from the bridge (via the endpoint roles). A secure
/// *transcode* leg (`SrtpMedia`) crypts inside the media actor, so only its shared `SecureLeg`
/// rollover is read (from [`crate::media_pipeline::MediaRegistry`], keyed by call-id) — there are no
/// bridge flows. Both carry the peer's answered SDES key, which lives on the `Call`, not the crypto
/// component.
enum SecureCheckpoint {
    /// A plain SDES-SRTP bridge (`Srtp`): read rollover + flow plans from the SRTP bridge.
    Bridge {
        roles: Vec<(EndpointId, crate::ha::EndpointRole)>,
        far_remote_crypto: crate::ha::CryptoSnapshot,
    },
    /// A secure transcode (`SrtpMedia`): read rollover from the media actor's shared secure leg.
    Media {
        far_remote_crypto: crate::ha::CryptoSnapshot,
    },
}

/// A SIPREC / monitor media subscription (RFC 7866): one or more source legs' **raw ingress RTP** is
/// tee'd byte-for-byte toward a send-only subscriber (a Session Recording Server, SRS). Unlike a
/// re-encode fork, the raw tee carries each leg's negotiated codec verbatim — so it works on a plain
/// G.711 relay and on a codec the engine has no encoder for (AMR-WB), with no transcode.
///
/// `subscribe_request` allocates the subscriber endpoint and records the subscription as *pending*
/// (no `srs_rtp`, no installed tee) — media cannot flow until `subscribe_answer` brings the SRS's
/// address. `subscribe_answer` installs a raw tee on each tapped leg of the call's [`MediaCall`]. The
/// subscriber is **send-only** (engine → SRS): the engine never opens a Forward/Redirect flow on
/// `subscriber_endpoint`, so it accepts no inbound media (RTPBleed has no surface here — §4).
struct Subscription {
    /// The subscription identity returned to the controller as the UAS to-tag.
    subscription_id: String,
    /// Which source legs are tee'd: each entry is a leg selector (`true` ⇒ leg A, `false` ⇒ leg B).
    /// More than one entry is an MPTY subscription (each named leg is a separate tap into this one
    /// subscriber). Mirrors [`crate::media_pipeline::MediaControl::AddRawTee`]'s `source_a`.
    taps: Vec<bool>,
    /// The engine endpoint the tee'd RTP is transmitted from (send-only toward the SRS).
    subscriber_endpoint: Endpoint,
    /// The SRS's RTP address, learned from `subscribe_answer`. `None` while the subscription is
    /// pending (offered but not yet answered) — no media flows until it is known.
    srs_rtp: Option<std::net::SocketAddr>,
}

/// How a call's media is carried once answered. The resolver picks this from the profile + the two
/// legs' negotiated codecs (see [`Engine::resolve_pipeline`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelineKind {
    /// Plain in-datapath relay (the `Forward` fast path) — both legs share a codec, no record/stream.
    Passthrough,
    /// Userspace SRTP bridge (an `RTP/AVP` ↔ `RTP/SAVP` secure leg).
    Srtp,
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
    /// Per-client async event sinks, registered by the control server one per connection.
    events: DashMap<ClientId, flume::Sender<Event>>,
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
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Create an engine over `datapath` with no per-client call quota.
    pub fn new(datapath: D) -> Self
    where
        D: Clone,
    {
        Self::with_max_calls_per_client(datapath, usize::MAX)
    }

    /// Create an engine that admits at most `max_calls_per_client` concurrent calls per control
    /// client — a soft DoS quota (the datapath media-port pool is the hard cap).
    pub fn with_max_calls_per_client(datapath: D, max_calls_per_client: usize) -> Self
    where
        D: Clone,
    {
        let bridge = Arc::new(SrtpBridge::new(datapath.clone()));
        // Mint the engine's DTLS-SRTP certificate once; its fingerprint is stable across all legs.
        let dtls_certificate = match DtlsCertificate::generate() {
            Ok(certificate) => Some(certificate),
            Err(error) => {
                tracing::error!(%error, "failed to generate DTLS certificate; DTLS-SRTP legs unavailable");
                None
            }
        };
        Self {
            datapath,
            calls: DashMap::new(),
            max_calls_per_client,
            client_calls: DashMap::new(),
            events: DashMap::new(),
            endpoint_calls: DashMap::new(),
            bridge,
            media: Arc::new(MediaRegistry::default()),
            ws: Arc::new(WsRegistry::default()),
            conference: Arc::new(ConferenceRegistry::default()),
            subscriptions: DashMap::new(),
            metrics: Arc::new(Metrics::new()),
            cluster: Arc::new(ClusterState::new("siphon-rtp".to_string(), 0, Vec::new())),
            dtls_certificate,
            ws_tls_config: std::sync::OnceLock::new(),
        }
    }

    /// Build (once) and return the ring-backed rustls client configuration for `wss://` WebSocket
    /// bridge dials. The trust store is seeded from the webpki-roots Mozilla CA bundle; the handshake
    /// runs on the **ring** crypto provider — the project's pure-Rust, zero-C TLS stack (never
    /// aws-lc-rs, whose default provider bundles C/asm). RFC 8446 / RFC 5246 over the RFC 6455 `wss`
    /// upgrade. Cached in a `OnceLock`, so it is built at most once and shared across every leg.
    fn ws_tls_client_config(&self) -> Arc<rustls::ClientConfig> {
        self.ws_tls_config
            .get_or_init(|| {
                // Install the ring provider as the process default (idempotent — reuses the same
                // sanctioned path the TURN TLS listener uses). rustls is built with
                // `default-features = false, features = ["ring"]`, so aws-lc-rs is not compiled: ring
                // is the only backend, and the config below is explicitly built on it.
                siphon_rtp_turn::tls::install_crypto_provider();
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Arc::new(config)
            })
            .clone()
    }

    /// Replace the default cluster identity/capacity with operator-configured state (`main.rs`
    /// wiring). A builder-style consuming setter so the daemon can `Engine::new(dp).with_cluster(..)`
    /// before it is wrapped in an `Arc`; tests keep the zero-config default.
    #[must_use]
    pub fn with_cluster(mut self, cluster: Arc<ClusterState>) -> Self {
        self.cluster = cluster;
        self
    }

    /// The shared cluster state (identity, capacity, drain flag) — handed to the CPU sampler so it
    /// publishes host-load samples into the same surface the `load` command reads.
    #[must_use]
    pub fn cluster(&self) -> Arc<ClusterState> {
        self.cluster.clone()
    }

    /// The shared operational metrics — handed to the `/metrics` HTTP endpoint so it renders the
    /// same counters the control path increments, alongside the live `session_count()` gauge.
    #[must_use]
    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    /// Borrow the underlying datapath (used by tests and, later, the media pipeline).
    pub fn datapath(&self) -> &D {
        &self.datapath
    }

    /// The shared SRTP bridge — handed to the redirect dispatcher so it can route bridge-owned
    /// endpoints' datagrams here (see [`crate::srtp_bridge::run_redirect_dispatcher`]).
    pub fn bridge(&self) -> Arc<SrtpBridge<D>> {
        self.bridge.clone()
    }

    /// The shared DTLS-SRTP bridge (a sibling of the SRTP bridge, reached through it), for the control
    /// path to register/deregister DTLS legs. The redirect dispatcher already routes DTLS endpoints via
    /// [`Self::bridge`], so this is only for registration.
    pub fn dtls_bridge(&self) -> Arc<DtlsBridge<D>> {
        self.bridge.dtls()
    }

    /// The shared media registry — handed to the redirect dispatcher so it can route media-owned
    /// endpoints' datagrams to the per-call transcode/record/DTMF actors.
    pub fn media(&self) -> Arc<MediaRegistry> {
        self.media.clone()
    }

    /// The shared WebSocket-bridge registry — handed to the redirect dispatcher so it can route
    /// WS-owned endpoints' datagrams to the per-call WS bridges.
    pub fn ws(&self) -> Arc<WsRegistry> {
        self.ws.clone()
    }

    /// The shared conference registry — handed to the redirect dispatcher so it can route
    /// conference-owned participant endpoints' datagrams to the per-room mixer actors.
    pub fn conference(&self) -> Arc<ConferenceRegistry> {
        self.conference.clone()
    }

    /// Number of live calls in the session registry.
    ///
    /// Used by the memory-leak soak to confirm the registry drains on teardown, and (later) by the
    /// metrics surface as the `sessions` gauge.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.calls.len()
    }

    /// Register `client`'s async event sink — one persistent control connection — and return the
    /// receiver the control server drains to the wire. Bounded: events are dropped under
    /// backpressure rather than blocking the engine on a slow control consumer.
    pub fn register_client(&self, client: ClientId) -> flume::Receiver<Event> {
        let (sender, receiver) = flume::bounded(64);
        self.events.insert(client, sender);
        receiver
    }

    /// Drop `client`'s event sink when its control connection closes.
    pub fn deregister_client(&self, client: ClientId) {
        self.events.remove(&client);
    }

    /// Push an asynchronous event to `client`, dropping it if the client is gone or its queue is
    /// full (late events are worthless — never block the engine on a slow consumer).
    fn push_event(&self, client: ClientId, event: Event) {
        if let Some(sender) = self.events.get(&client) {
            if sender.try_send(event).is_err() {
                tracing::debug!(?client, "control event dropped (queue full or closed)");
            }
        }
    }

    /// Handle one control command from `client`, producing the result to return to the caller.
    ///
    /// Increments the operational counters as a side effect: per-command totals (offer/answer/
    /// delete) before dispatch, and `control_errors_total` whenever the result is an error — so the
    /// `/metrics` surface reflects every command this engine processed (including over the NG and WS
    /// front-ends, which all funnel through here).
    pub async fn handle(&self, client: ClientId, command: Command) -> CmdResult {
        match &command {
            Command::Offer { .. } => self.metrics.record_offer(),
            Command::Answer { .. } => self.metrics.record_answer(),
            Command::Delete { .. } => self.metrics.record_delete(),
            Command::ConferenceJoin { .. } => self.metrics.record_conference_join(),
            Command::ConferenceLeave { .. } => self.metrics.record_conference_leave(),
            _ => {}
        }
        let result = self.dispatch(client, command).await;
        if matches!(result, CmdResult::Error { .. }) {
            self.metrics.record_control_error();
        }
        result
    }

    /// Dispatch one control command to its handler (the metric-free inner of [`Self::handle`]).
    async fn dispatch(&self, client: ClientId, command: Command) -> CmdResult {
        // Drain gate: a draining node runs its live calls to completion but admits no new session, so
        // it can be taken out of a rolling upgrade cleanly. Reject the two session-creating verbs;
        // everything else — query/delete/media-control on existing calls, and the cluster/census
        // verbs — still works. (Matching without binding does not move `command`.)
        if self.cluster.is_draining()
            && matches!(
                command,
                Command::Offer { .. } | Command::ConferenceJoin { .. }
            )
        {
            return CmdResult::Error {
                reason: "node is draining; not accepting new sessions".to_string(),
            };
        }
        match command {
            Command::Ping => CmdResult::Pong,
            Command::List => self.list(client),
            Command::Statistics => self.statistics(),
            Command::Load => self.load_snapshot(),
            Command::NodeInfo => self.node_info(),
            Command::Drain => {
                self.cluster.set_draining(true);
                ok_empty()
            }
            Command::Undrain => {
                self.cluster.set_draining(false);
                ok_empty()
            }
            Command::Checkpoint { call_id, .. } => self.checkpoint(client, &call_id),
            Command::Restore { snapshot } => self.restore(client, &snapshot).await,
            Command::Offer {
                call_id,
                from_tag,
                sdp,
                profile,
            } => self.offer(client, call_id, from_tag, &sdp, &profile).await,
            Command::Answer {
                call_id,
                from_tag,
                to_tag,
                sdp,
                profile,
            } => {
                self.answer(client, &call_id, &from_tag, to_tag, &sdp, &profile)
                    .await
            }
            Command::Delete { call_id, .. } => self.delete(client, &call_id).await,
            Command::Query { call_id, .. } => self.query(client, &call_id),
            Command::BlockMedia { call_id, .. } => self.set_block(client, &call_id, true).await,
            Command::UnblockMedia { call_id, .. } => self.set_block(client, &call_id, false).await,
            Command::BlockDtmf {
                call_id,
                from_tag,
                to_tag,
            } => {
                self.block_dtmf(client, &call_id, &from_tag, to_tag.as_deref(), true)
                    .await
            }
            Command::UnblockDtmf {
                call_id,
                from_tag,
                to_tag,
            } => {
                self.block_dtmf(client, &call_id, &from_tag, to_tag.as_deref(), false)
                    .await
            }
            Command::SilenceMedia { call_id, .. } => self.set_silence(client, &call_id, true),
            Command::UnsilenceMedia { call_id, .. } => self.set_silence(client, &call_id, false),
            Command::PlayMedia {
                call_id,
                from_tag,
                source,
                repeat_times,
                start_pos_ms,
                ..
            } => {
                self.play_media(
                    client,
                    &call_id,
                    &from_tag,
                    source,
                    repeat_times,
                    start_pos_ms,
                )
                .await
            }
            Command::StopMedia { call_id, from_tag } => {
                self.stop_media(client, &call_id, &from_tag)
            }
            Command::PlayDtmf {
                call_id,
                from_tag,
                code,
                duration_ms,
                volume_dbm0,
                ..
            } => self.play_dtmf(client, &call_id, &from_tag, &code, duration_ms, volume_dbm0),
            Command::SubscribeRequest {
                call_id,
                from_tags,
                sdp,
                profile,
            } => {
                self.subscribe_request(client, &call_id, &from_tags, sdp.as_deref(), &profile)
                    .await
            }
            Command::SubscribeAnswer {
                call_id,
                from_tag,
                to_tag,
                sdp,
                ..
            } => {
                self.subscribe_answer(client, &call_id, &from_tag, &to_tag, &sdp)
                    .await
            }
            Command::Unsubscribe {
                call_id,
                from_tag,
                to_tag,
            } => self.unsubscribe(client, &call_id, &from_tag, &to_tag).await,
            Command::Echo {
                call_id,
                from_tag,
                enabled,
                ..
            } => self.set_echo(client, &call_id, &from_tag, enabled).await,
            Command::StartRecording {
                call_id,
                recording_dir,
                ..
            } => self.start_recording(client, &call_id, recording_dir).await,
            Command::StopRecording { call_id, .. } => self.stop_recording(client, &call_id).await,
            Command::ConferenceJoin {
                conference_id,
                from_tag,
                sdp,
                role,
                profile,
            } => {
                self.conference_join(client, &conference_id, from_tag, &sdp, role, &profile)
                    .await
            }
            Command::ConferenceLeave {
                conference_id,
                from_tag,
            } => self.conference_leave(&conference_id, &from_tag).await,
            Command::ConferenceRoute {
                conference_id,
                from_tag,
                role,
            } => self.conference_route(&conference_id, &from_tag, role),
            Command::ConferenceBridge {
                conference_id_a,
                conference_id_b,
                direction,
            } => self.conference_bridge(&conference_id_a, &conference_id_b, direction),
            other => CmdResult::Error {
                reason: format!("unsupported command: {}", command_name(&other)),
            },
        }
    }

    /// Allocate `count` endpoints of `family`, rolling back all of them if any allocation fails. The
    /// family is the address family of the call's signalled `c=` line (RFC 4566 §5.7), so a
    /// `c=IN IP6` call gets v6 engine endpoints and a `c=IN IP4` call gets v4.
    async fn alloc_endpoints(
        &self,
        count: usize,
        family: AddressFamily,
    ) -> Result<Vec<Endpoint>, String> {
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            match self.datapath.alloc_endpoint_for(family).await {
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

    async fn free(&self, endpoints: &[Endpoint]) {
        for endpoint in endpoints {
            self.datapath.remove_endpoint(endpoint.id).await;
        }
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
        }
    }

    async fn offer(
        &self,
        client: ClientId,
        call_id: String,
        from_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        // Soft per-client call quota (the datapath media-port pool is the hard cap). Reject before
        // allocating anything. (A3 / DoS — docs/security-and-nat.md §5.)
        if self.client_call_count(client) >= self.max_calls_per_client {
            return CmdResult::Error {
                reason: "per-client call quota exceeded".to_string(),
            };
        }
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("offer SDP parse failed: {error}"),
                }
            }
        };

        // ICE-lite posture (docs/security-and-nat.md §4 layer 4): mint our own short-term credentials
        // when the leg uses ICE — advertised in the rewritten SDP and installed on the endpoints so
        // the responder can validate the peer's connectivity checks. The control `profile.ice` field
        // overrides the SDP-derived default (RFC 8445): `force`/`force-relay` mint them regardless of
        // the offer, `remove` suppresses them, otherwise mirror whether the offer carried ICE.
        let ice_directive = ice_directive(profile);
        let want_ice = match ice_directive {
            Some(IceDirective::Force) => true,
            Some(IceDirective::Remove) => false,
            None => info.is_ice(),
        };
        let ice_creds = if want_ice {
            ice::generate_credentials()
        } else {
            None
        };

        // One RTP endpoint per leg, plus a companion RTCP endpoint unless the stream is muxed. The
        // *near* leg binds the family of the offer's signalled `c=` line (RFC 4566 §5.7). The *far*
        // leg binds the same family by default, or the `address family` flag's family for IPv4↔IPv6
        // interworking (a v6 VoLTE access leg bridged to a v4 PSTN core) — the engine anchors media,
        // so a v6 near socket and a v4 far socket relay/transcode through it, and each leg's SDP is
        // rewritten in its own family (`rewrite` emits the endpoint's addrtype).
        let near_family = AddressFamily::of(info.remote_rtp.ip());
        let far_family = far_address_family(profile).unwrap_or(near_family);
        // RFC 5761 rtcp-mux: the controller's `rtcp-mux` directive can override the SDP-derived mux
        // per side (force mux, demux, or reject). This drives the per-leg port count *and* the far
        // SDP's `a=rtcp-mux` presentation — resolved once here so allocation and rewrite agree.
        let (near_mux, far_mux) = resolve_rtcp_mux(info.rtcp_mux, &profile.rtcp_mux);
        let near_per_leg = if near_mux { 1 } else { 2 };
        let far_per_leg = if far_mux { 1 } else { 2 };
        let near_endpoints = match self.alloc_endpoints(near_per_leg, near_family).await {
            Ok(endpoints) => endpoints,
            Err(reason) => return CmdResult::Error { reason },
        };
        let far_endpoints = match self.alloc_endpoints(far_per_leg, far_family).await {
            Ok(endpoints) => endpoints,
            Err(reason) => {
                self.free(&near_endpoints).await;
                return CmdResult::Error { reason };
            }
        };
        let near_rtp = near_endpoints[0];
        let far_rtp = far_endpoints[0];
        let near_rtcp = (!near_mux).then(|| near_endpoints[1]);
        let far_rtcp = (!far_mux).then(|| far_endpoints[1]);
        // Combined list for teardown on any later error path in this offer.
        let endpoints: Vec<_> = near_endpoints
            .iter()
            .chain(far_endpoints.iter())
            .copied()
            .collect();

        // The rewritten offer is delivered to B, so it advertises the `far` leg.
        let engine = EngineMedia {
            rtp: far_rtp.local_addr,
            rtcp: far_rtcp.map(|endpoint| endpoint.local_addr),
        };
        // ICE rewrite mode (RFC 8839 §5): re-originate ICE-lite when we minted creds; on `ice: remove`
        // with none minted, strip the peer's ICE without advertising our own; otherwise pass it
        // through. `IceAdvertisement` borrows `ice_creds`, so it is built here and kept alive to rewrite.
        let ice_rewrite = match (ice_creds.as_ref(), ice_directive) {
            (Some(creds), _) => IceRewrite::Reoriginate(sdp::IceAdvertisement {
                ufrag: creds.ufrag.as_str(),
                pwd: creds.pwd.as_str(),
            }),
            (None, Some(IceDirective::Remove)) => IceRewrite::Strip,
            (None, _) => IceRewrite::Keep,
        };

        // Secure far leg: when the control profile asks for a secure far leg, either DTLS-SRTP
        // (`UDP/TLS/RTP/SAVP[F]`, RFC 5764) — advertise the engine's fingerprint + `a=setup` role,
        // keyed by the handshake at answer — or SDES (`RTP/SAVP[F]`, RFC 4568) — mint an `a=crypto` key.
        // B's answer brings its keying and `answer` wires the bridge. (`UDP/TLS/...` also matches
        // "SAVP", so DTLS is tested first.) The control `profile.dtls` field refines the DTLS case:
        // `off` downgrades the leg to plaintext, `passive`/`active`/`actpass` sets the offerer role.
        let far_transport = profile.transport_protocol.as_deref().unwrap_or_default();
        let dtls_directive = dtls_directive(profile);
        let dtls_transport = far_transport.contains("UDP/TLS");
        // `dtls: off` (rtpengine DTLS=off) forces a plaintext far leg even on a UDP/TLS transport —
        // no DTLS-SRTP and no SDES fallback (SDES applies only to a plain `RTP/SAVP[F]` transport).
        let dtls_off = matches!(dtls_directive, Some(DtlsDirective::Off));
        let far_dtls = dtls_transport && !dtls_off;
        let far_sdes = !dtls_transport && far_transport.contains("SAVP");
        let far_local_crypto = if far_sdes {
            match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                Ok(crypto) => Some(crypto),
                Err(error) => {
                    self.free(&endpoints).await;
                    return error_result("generate SDES key", &error);
                }
            }
        } else {
            None
        };
        let security = if dtls_transport && dtls_off {
            // Downgrade a requested DTLS-SRTP far transport to plaintext RTP/AVP (RFC 3264): force AVP
            // and strip the offer's DTLS keying (`a=fingerprint`/`a=setup`).
            Some(SecurityAdvertisement::Plain)
        } else if far_dtls {
            let Some(certificate) = self.dtls_certificate.as_ref() else {
                self.free(&endpoints).await;
                return error_result("DTLS-SRTP offer", &"engine has no DTLS certificate");
            };
            let fingerprint = certificate.fingerprint();
            // RFC 5763 §5: the offerer defaults to `actpass` (the answerer picks active/passive); a
            // control `dtls: passive|active|actpass` overrides that offerer role (RFC 4145 §4 a=setup).
            let setup = match dtls_directive {
                Some(DtlsDirective::Role(role)) => role,
                _ => sdp::Setup::Actpass,
            };
            Some(SecurityAdvertisement::Dtls {
                fingerprint: sdp::Fingerprint {
                    hash_function: fingerprint.hash_function,
                    bytes: fingerprint.bytes,
                },
                setup,
            })
        } else {
            far_local_crypto.map(SecurityAdvertisement::Secure)
        };

        // RFC 5761: when a `rtcp-mux` directive was given, present the resolved far-side mux to B
        // explicitly (force `a=rtcp-mux` on, or strip it); otherwise mirror the offer (`None`).
        let far_mux_override = (!profile.rtcp_mux.is_empty()).then_some(far_mux);
        let mut rewritten = match sdp::rewrite(sdp, engine, ice_rewrite, security, far_mux_override)
        {
            Ok(rewritten) => rewritten,
            Err(error) => {
                self.free(&endpoints).await;
                return CmdResult::Error {
                    reason: format!("offer SDP rewrite failed: {error}"),
                };
            }
        };
        // rtpengine codec manipulation on the SDP offered to the far side: strip/mask/consume remove a
        // codec, transcode/offer add or reorder, except/accept keep it (see `parse_codec_flags`). The
        // far side may then select a transcode/offer codec, engaging the transcoder at answer.
        let codec_policy = parse_codec_flags(&profile.flags);
        if !codec_policy.is_noop() {
            rewritten.sdp = sdp::apply_codec_policy(&rewritten.sdp, &codec_policy);
        }
        // rtpengine `replace: [origin]`: rewrite the o= line to the engine's address (topology hiding).
        if profile.replace.iter().any(|field| field == "origin") {
            rewritten.sdp = sdp::rewrite_origin(&rewritten.sdp, engine.rtp.ip());
        }

        // WebSocket bridge (mod_audio_stream / voice-AI): a native siphon-rtp extension. When the
        // profile carries `ws_uri`, leg A (the offerer) is bridged to that WS server using A's
        // negotiated (primary) codec — the engine dials the WS as a client and pumps A's audio in
        // both directions. The A↔B relay/transcode path is not wired in this mode (the WS is A's far
        // side). Resolved at offer because A's codec + signalled address are both known here.
        let near_codec = info.primary_codec();
        let ws_uri = profile.ws_uri.clone();
        let pipeline = if ws_uri.is_some() {
            PipelineKind::Ws
        } else {
            PipelineKind::Passthrough
        };

        *self.client_calls.entry(client).or_insert(0) += 1;
        // Index this call's endpoints so observed RTCP can be correlated back to the call-id.
        for endpoint in [Some(near_rtp), near_rtcp, Some(far_rtp), far_rtcp]
            .into_iter()
            .flatten()
        {
            self.endpoint_calls.insert(endpoint.id, call_id.clone());
        }
        self.calls.insert(
            call_id.clone(),
            Call {
                owner: client,
                created_tick: self.datapath.now_ticks(),
                ice: ice_creds,
                from_tag,
                to_tag: None,
                near: Leg {
                    rtp: near_rtp,
                    rtcp: near_rtcp,
                    remote_rtp: Some(info.remote_rtp),
                    remote_rtcp: Some(info.remote_rtcp),
                },
                far: Leg {
                    rtp: far_rtp,
                    rtcp: far_rtcp,
                    remote_rtp: None,
                    remote_rtcp: None,
                },
                far_local_crypto,
                far_remote_crypto: None,
                far_dtls,
                near_codec: near_codec.clone(),
                far_codec: None,
                near_telephone_event: info.telephone_event_payload_type(),
                far_telephone_event: None,
                pipeline,
                relay_flows: Vec::new(),
                promotion_reasons: HashSet::new(),
                offer_received_from: profile.received_from,
            },
        );

        // Stand the WS bridge up now that the call is recorded (so a dispatch can find its route). On
        // any failure (no codec, redirect install, or dial), tear the half-built call back down.
        if let Some(ws_uri) = ws_uri {
            if let Err(reason) = self
                .setup_ws_bridge(
                    &call_id,
                    &ws_uri,
                    near_rtp,
                    info.remote_rtp,
                    near_codec.as_ref(),
                    // Gate leg A's ingress to its `received-from` public IP when the offer supplied
                    // one, else the signalled `c=` address (docs/security-and-nat.md §4 layer 2).
                    bridge_source_filter(
                        profile,
                        apply_received_from(Some(info.remote_rtp), profile.received_from)
                            .unwrap_or(info.remote_rtp),
                    ),
                )
                .await
            {
                self.teardown_call(&call_id).await;
                return error_result("ws bridge", &reason);
            }
        }

        ok_sdp(rewritten.sdp, None)
    }

    /// Stand up the WebSocket bridge for leg A: install `Redirect` on A's RTP endpoint, dial the WS
    /// server as a client, build a [`BridgeSession`] on a [`MediaLeg`] in A's codec, and spawn the
    /// bridge + the rtp_out→datapath drain task, registering both in the [`WsRegistry`]. The bridge's
    /// `rtp_in` is fed by the redirect dispatcher (gated by `accepted_source` — RTPBleed defence,
    /// `Redirect` skips the datapath gate). Dials both `ws://` and `wss://` (TLS on ring/rustls).
    async fn setup_ws_bridge(
        &self,
        call_id: &str,
        ws_uri: &str,
        endpoint_a: Endpoint,
        a_rtp: std::net::SocketAddr,
        codec: Option<&CodecSpec>,
        accepted_source: SourceFilter,
    ) -> Result<(), String> {
        let Some(codec) = codec else {
            return Err("offer carried no usable audio codec for the WS bridge".to_string());
        };
        // Build A's codec pair for the leg: decode A's RTP → L16 uplink; encode L16 downlink → A's RTP.
        let decoder = factory::decoder_for(codec).map_err(|error| error.to_string())?;
        let encoder = factory::encoder_for(codec).map_err(|error| error.to_string())?;
        let ptime = std::time::Duration::from_millis(u64::from(codec.ptime_ms.max(1)));

        // Redirect A's RTP so the dispatcher routes it here (the WS bridge owns leg A's media).
        self.datapath
            .install_flow(endpoint_a.id, FlowAction::Redirect)
            .map_err(|error| format!("install WS bridge redirect: {error}"))?;

        // Dial the WS server as a client. Supply a ring/rustls TLS connector so a `wss://` URI
        // completes the RFC 8446 handshake before the RFC 6455 upgrade; a `ws://` URI ignores the
        // connector (plain TCP). Returns the stream + the HTTP upgrade response; keep only the stream.
        let connector = tokio_tungstenite::Connector::Rustls(self.ws_tls_client_config());
        let (socket, _response) =
            tokio_tungstenite::connect_async_tls_with_config(ws_uri, None, false, Some(connector))
                .await
                .map_err(|error| format!("dial {ws_uri}: {error}"))?;

        // A jitter buffer shallow enough for low-latency voice-AI (target 1, cap 16 — the bridge
        // pops one frame per ptime tick, the consumer's cadence being the sample-tick clock).
        // The WS uplink PCM is at the codec's *native* sample rate (what the decoder emits), which is
        // not the RTP clock for G.722 (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2). Capture it
        // before the decoder is moved into the leg.
        let bridge_pcm_rate = decoder.params().sample_rate_hz;
        let leg = MediaLeg::new(
            decoder,
            encoder,
            JitterBuffer::new(1, 16),
            random_ssrc(),
            codec.payload_type,
        );
        // The WS media format advertised in `start`: L16 at the leg's native PCM rate, mono, LE.
        let format = MediaFormat {
            encoding: siphon_rtp_media::bridge::protocol::Encoding::L16,
            sample_rate: bridge_pcm_rate,
            channels: 1,
            bit_depth: 16,
            endianness: siphon_rtp_media::bridge::protocol::Endianness::Little,
            ptime: codec.ptime_ms.max(1),
        };
        let session = BridgeSession::new(
            leg,
            format,
            format!("ws-{call_id}"),
            call_id.to_string(),
            WsDirection::Duplex,
            8, // playout cap (drop-oldest): late audio is worthless
        );

        let (rtp_in_tx, rtp_in_rx) = flume::bounded::<bytes::Bytes>(1024);
        let (rtp_out_tx, rtp_out_rx) = flume::bounded::<bytes::Bytes>(1024);

        // The bridge: pump A's RTP (rtp_in) ↔ WS, render WS downlink to RTP (rtp_out).
        let bridge_task = tokio::spawn(async move {
            if let Err(error) = run_bridge(socket, session, rtp_in_rx, rtp_out_tx, ptime).await {
                tracing::debug!(%error, "ws bridge exited with error");
            }
        });
        // The drain: forward each rendered downlink RTP packet out A's endpoint toward A.
        let datapath = self.datapath.clone();
        let drain_endpoint = endpoint_a.id;
        let drain_task = tokio::spawn(async move {
            while let Ok(packet) = rtp_out_rx.recv_async().await {
                if let Err(error) = datapath.send(drain_endpoint, a_rtp, &packet).await {
                    tracing::debug!(%error, "ws bridge downlink send failed");
                }
            }
        });

        self.ws.register(
            call_id.to_string(),
            endpoint_a.id,
            accepted_source,
            rtp_in_tx,
            bridge_task,
            drain_task,
        );
        Ok(())
    }

    /// Tear down a call's datapath + slow-path state without an ownership check (an internal cleanup
    /// for a half-built call). Frees the sockets and drops any bridge / media / WS registration.
    async fn teardown_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            let endpoints: Vec<EndpointId> = call
                .near
                .endpoint_ids()
                .chain(call.far.endpoint_ids())
                .collect();
            // Free any SIPREC subscriptions first (detach forks, abort drains, free subscriber ports)
            // before the media actor is deregistered.
            self.drop_subscriptions(call_id).await;
            self.bridge.deregister(endpoints.iter().copied());
            self.media.deregister(call_id);
            self.ws.deregister(call_id);
            for endpoint in endpoints {
                self.datapath.remove_endpoint(endpoint).await;
                self.endpoint_calls.remove(&endpoint);
            }
            self.release_client_call(call.owner);
        }
    }

    async fn answer(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        to_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        // Snapshot the leg endpoints under the guard, then release it. Only the owning client may
        // answer (A3 — docs/security-and-nat.md §5); to anyone else the call is unknown.
        let (
            near,
            far,
            ice_creds,
            far_local_crypto,
            far_dtls,
            near_codec,
            near_telephone_event,
            offer_pipeline,
            offer_received_from,
        ) = match self.calls.get(call_id) {
            Some(call) if call.owner == client => {
                if call.from_tag != from_tag {
                    return CmdResult::Error {
                        reason: "from_tag mismatch on answer".to_string(),
                    };
                }
                (
                    call.near,
                    call.far,
                    call.ice.clone(),
                    call.far_local_crypto,
                    call.far_dtls,
                    call.near_codec.clone(),
                    call.near_telephone_event,
                    call.pipeline,
                    call.offer_received_from,
                )
            }
            _ => return unknown_call(call_id),
        };
        // The owner's async event sink (DTMF events flow here from the media actor), if registered.
        let owner_events = self.events.get(&client).map(|sink| sink.value().clone());

        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer SDP parse failed: {error}"),
                }
            }
        };

        // rtpengine `received-from`: the real post-NAT source the SIP proxy saw each request come
        // from. The **offer's** hint (stored on the call) tightens the near (A) leg's ingress gate;
        // the **answer's** hint tightens the far (B) leg's. Both keep the signalled port and only
        // override the gated source IP — every gate path below uses these effective addresses so the
        // source gate is uniform (docs/security-and-nat.md §4 layer 2). `None` ⇒ the signalled
        // address is used unchanged.
        let near_gate_rtp = apply_received_from(near.remote_rtp, offer_received_from);
        let near_gate_rtcp = apply_received_from(near.remote_rtcp, offer_received_from);
        let far_gate_rtp = apply_received_from(Some(info.remote_rtp), profile.received_from)
            .unwrap_or(info.remote_rtp);
        let far_gate_rtcp = apply_received_from(Some(info.remote_rtcp), profile.received_from)
            .unwrap_or(info.remote_rtcp);

        // The rewritten answer is delivered to A, so it advertises the `near` leg.
        let engine = EngineMedia {
            rtp: near.rtp.local_addr,
            rtcp: near.rtcp.map(|endpoint| endpoint.local_addr),
        };
        // The A-facing near leg re-originates ICE-lite iff the offer minted engine creds (the ICE
        // posture was decided at offer); otherwise the peer's ICE (if any) passes through unchanged.
        let ice_rewrite = match ice_creds.as_ref() {
            Some(creds) => IceRewrite::Reoriginate(sdp::IceAdvertisement {
                ufrag: creds.ufrag.as_str(),
                pwd: creds.pwd.as_str(),
            }),
            None => IceRewrite::Keep,
        };
        // The answer to A advertises the near leg; on a secure (SDES or DTLS) far leg that side is
        // plain (RTP/AVP), so force AVP and strip the peer's crypto/fingerprint. A plain relay leaves
        // transport/crypto untouched.
        let security =
            (far_local_crypto.is_some() || far_dtls).then_some(SecurityAdvertisement::Plain);
        // RFC 5761: the near (A-facing) mux state was fixed at offer — the companion RTCP endpoint
        // exists iff the near side is non-muxed. When a `rtcp-mux` directive drove that decision,
        // present it to A explicitly so the answer SDP matches the ports the engine actually bound;
        // otherwise mirror B's answer (`None`).
        let near_mux = near.rtcp.is_none();
        let near_mux_override = (!profile.rtcp_mux.is_empty()).then_some(near_mux);
        let mut rewritten =
            match sdp::rewrite(sdp, engine, ice_rewrite, security, near_mux_override) {
                Ok(rewritten) => rewritten,
                Err(error) => {
                    return CmdResult::Error {
                        reason: format!("answer SDP rewrite failed: {error}"),
                    }
                }
            };
        // rtpengine `replace: [origin]`: rewrite the o= line to the engine's address (topology hiding).
        if profile.replace.iter().any(|field| field == "origin") {
            rewritten.sdp = sdp::rewrite_origin(&rewritten.sdp, engine.rtp.ip());
        }

        // WebSocket bridge: if this call is (or is now being) bridged to a WS media server, leg A's
        // audio is already (or now) pumped to the WS — the A↔B relay/transcode path is deliberately
        // not wired (the WS server is A's far side). The bridge is normally stood up at offer; honour
        // `ws_uri` arriving first at answer too (set it up against A's stored codec/address).
        let already_ws = offer_pipeline == PipelineKind::Ws;
        if already_ws || profile.ws_uri.is_some() {
            if !already_ws {
                let Some(a_rtp) = near.remote_rtp else {
                    return error_result("ws bridge", &"near leg has no signalled address");
                };
                if let Some(ws_uri) = profile.ws_uri.clone() {
                    if let Err(reason) = self
                        .setup_ws_bridge(
                            call_id,
                            &ws_uri,
                            near.rtp,
                            a_rtp,
                            near_codec.as_ref(),
                            // Gate leg A to its offer `received-from` public IP when supplied.
                            bridge_source_filter(profile, near_gate_rtp.unwrap_or(a_rtp)),
                        )
                        .await
                    {
                        return error_result("ws bridge", &reason);
                    }
                }
            }
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.to_tag = Some(to_tag.clone());
                call.far.remote_rtp = Some(info.remote_rtp);
                call.far.remote_rtcp = Some(info.remote_rtcp);
                call.pipeline = PipelineKind::Ws;
            }
            return ok_sdp(rewritten.sdp, Some(to_tag));
        }

        // ICE applies to a leg only when both ends use it: `near` faces A (which offered ICE iff we
        // minted creds), `far` faces B (ICE iff its answer carries ICE).
        let near_ice = ice_creds.is_some();
        let far_ice = ice_creds.is_some() && info.is_ice();

        // Resolve how this call's media is carried: an SRTP bridge (secure far leg), the userspace
        // media slow path (transcode / record), or the in-datapath plain relay.
        let pipeline = resolve_pipeline(
            near_codec.as_ref(),
            &info,
            profile,
            far_local_crypto,
            far_dtls,
        );
        // rtpengine `ptime=<N>` override: force the packetization of the synthesized (transcoded)
        // egress toward both parties. Overriding the negotiated codec ptime here is the single source
        // of truth — it flows to the egress encoder's frame size and the repacketizer (the RTP cadence,
        // RFC 3550 §5.1), to the answer SDP `a=ptime` presented to A, and to the HA snapshot (so a
        // restore rebuilds at the same ptime). Inert on a plain relay / bridge (which forward RTP
        // verbatim and never re-encode); only a transcoding pipeline can re-frame.
        let ptime_override = parse_ptime_override(&profile.flags);
        let near_codec = near_codec.map(|codec| with_ptime_override(&codec, ptime_override));
        // For a passthrough relay, remember the installed forward actions so `block` can flip the
        // endpoints to `Drop` and `unblock` can restore them.
        let mut relay_flows: Vec<(EndpointId, FlowAction)> = Vec::new();

        if pipeline == PipelineKind::Srtp {
            // `resolve_pipeline` only yields `Srtp` when `far_local_crypto` is set, so this is an
            // internal invariant; answer gracefully rather than panic on the control path.
            let Some(far_local) = far_local_crypto else {
                return error_result("SRTP bridge", &"far leg has no local crypto (internal)");
            };
            // Secure far (B) leg → userspace SRTP bridge: terminate SRTP/SRTCP on B and relay
            // plaintext on A. B's answer must carry its SDES key to key the inbound contexts.
            let Some(far_remote) = info.crypto.first().copied() else {
                return error_result("SAVP answer", &"missing a=crypto in the answer");
            };
            let (Some(a_rtp), Some(a_rtcp)) = (near.remote_rtp, near.remote_rtcp) else {
                return error_result("SRTP bridge", &"near leg has no signalled address");
            };
            // Redirect every leg endpoint so the bridge sees (and crypts) both directions.
            for endpoint in near.endpoint_ids().chain(far.endpoint_ids()) {
                if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                    return error_result("install SRTP bridge redirect", &error);
                }
            }
            let mut flows = vec![
                // A (plain) ingress → encrypt for B → out the far endpoint toward B. Gated to A's
                // effective source (its `received-from` public IP when the offer supplied one).
                BridgeFlowPlan {
                    endpoint: near.rtp.id,
                    op: BridgeOp::Encrypt,
                    accepted_source: bridge_source_filter(profile, near_gate_rtp.unwrap_or(a_rtp)),
                    out_endpoint: far.rtp.id,
                    out_dst: info.remote_rtp,
                },
                // B (secure) ingress → decrypt for A → out the near endpoint toward A.
                BridgeFlowPlan {
                    endpoint: far.rtp.id,
                    op: BridgeOp::Decrypt,
                    accepted_source: bridge_source_filter(profile, far_gate_rtp),
                    out_endpoint: near.rtp.id,
                    out_dst: a_rtp,
                },
            ];
            if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
                flows.push(BridgeFlowPlan {
                    endpoint: near_rtcp.id,
                    op: BridgeOp::Encrypt,
                    accepted_source: bridge_source_filter(
                        profile,
                        near_gate_rtcp.unwrap_or(a_rtcp),
                    ),
                    out_endpoint: far_rtcp.id,
                    out_dst: info.remote_rtcp,
                });
                flows.push(BridgeFlowPlan {
                    endpoint: far_rtcp.id,
                    op: BridgeOp::Decrypt,
                    accepted_source: bridge_source_filter(profile, far_gate_rtcp),
                    out_endpoint: near_rtcp.id,
                    out_dst: a_rtcp,
                });
            }
            self.bridge.register(BridgeCallPlan {
                leg: SecureLeg::new(&far_local.key, &far_remote.key),
                flows,
            });
        } else if pipeline == PipelineKind::Dtls {
            // DTLS-SRTP far (B) leg → userspace DTLS bridge: the handshake keys the leg, then SRTP/SRTCP
            // is terminated on B and plaintext relayed on A. B's answer must carry its certificate
            // fingerprint (RFC 5763 §5) to authenticate the handshake; the engine takes the DTLS role
            // opposite the peer's `a=setup`. (rtcp-mux is assumed, as WebRTC mandates — non-muxed DTLS
            // RTCP is a follow-up.)
            let Some(certificate) = self.dtls_certificate.clone() else {
                return error_result("DTLS-SRTP answer", &"engine has no DTLS certificate");
            };
            let Some(peer_fingerprint) = info.fingerprint.clone() else {
                return error_result("DTLS-SRTP answer", &"missing a=fingerprint in the answer");
            };
            let Some(a_rtp) = near.remote_rtp else {
                return error_result("DTLS bridge", &"near leg has no signalled address");
            };
            // The answerer (B) picks the DTLS role; the engine takes the complement (RFC 5763 §5): a
            // `passive` peer makes us the client, anything else (active/actpass) makes us the server.
            let role = match info.setup {
                Some(sdp::Setup::Passive) => DtlsRole::Client,
                _ => DtlsRole::Server,
            };
            for endpoint in [near.rtp.id, far.rtp.id] {
                if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                    return error_result("install DTLS bridge redirect", &error);
                }
            }
            self.dtls_bridge().register(DtlsCallPlan {
                plain_endpoint: near.rtp.id,
                plain_source: bridge_source_filter(profile, a_rtp),
                plain_dst: a_rtp,
                secure_endpoint: far.rtp.id,
                secure_source: bridge_source_filter(profile, info.remote_rtp),
                secure_dst: info.remote_rtp,
                secure_local: far.rtp.local_addr,
                certificate,
                role,
                peer_fingerprint: DtlsFingerprint::new(
                    peer_fingerprint.hash_function,
                    peer_fingerprint.bytes,
                ),
            });
        } else if pipeline == PipelineKind::SrtpMedia {
            // Secure (RTP/SAVP) far (B) leg whose codec differs from the plaintext near (A) leg:
            // the media actor decrypts B's SRTP, transcodes, and encrypts toward B (and the reverse),
            // sharing one SecureLeg across both directions. Under rtcp-mux, RTCP rides the muxed RTP
            // endpoint and is (de)crypted there too; when not muxed, the companion RTCP endpoints are
            // redirected and SRTCP-(de)crypted through the same SecureLeg (see below +
            // docs/security-and-nat.md).
            // `resolve_pipeline` only yields `SrtpMedia` when `far_local_crypto` is set; treat a
            // missing key as an internal error rather than panicking on the control path.
            let Some(far_local) = far_local_crypto else {
                return error_result("SRTP transcode", &"far leg has no local crypto (internal)");
            };
            let Some(far_remote) = info.crypto.first().copied() else {
                return error_result("SAVP answer", &"missing a=crypto in the answer");
            };
            let Some(a_rtp) = near.remote_rtp else {
                return error_result(
                    "secure media pipeline",
                    &"near leg has no signalled address",
                );
            };
            let Some(near_codec) = near_codec.clone() else {
                return error_result(
                    "secure media pipeline",
                    &"offer carried no usable audio codec",
                );
            };
            let Some(far_codec) = info
                .primary_codec()
                .map(|codec| with_ptime_override(&codec, ptime_override))
            else {
                return error_result(
                    "secure media pipeline",
                    &"answer carried no usable audio codec",
                );
            };
            let record_path = profile
                .record_call
                .then(|| profile.record_path.clone())
                .flatten();
            let a_to_b = match build_direction(
                near.rtp.id,
                bridge_source_filter(profile, near_gate_rtp.unwrap_or(a_rtp)),
                far.rtp.id,
                info.remote_rtp,
                &near_codec,
                &far_codec,
                near_telephone_event,
                info.telephone_event_payload_type(),
                record_path.as_deref(),
            ) {
                Ok(direction) => direction,
                Err(reason) => return error_result("secure media pipeline (A→B)", &reason),
            };
            let b_to_a = match build_direction(
                far.rtp.id,
                bridge_source_filter(profile, far_gate_rtp),
                near.rtp.id,
                a_rtp,
                &far_codec,
                &near_codec,
                info.telephone_event_payload_type(),
                near_telephone_event,
                record_path.as_deref(),
            ) {
                Ok(direction) => direction,
                Err(reason) => return error_result("secure media pipeline (B→A)", &reason),
            };
            // Redirect the RTP legs to the actor. Under rtcp-mux, RTCP rides the RTP endpoint and is
            // (de)crypted inside the actor; when not muxed, the companion RTCP endpoints are redirected
            // and SRTCP-(de)crypted through the same SecureLeg below.
            for endpoint in [near.rtp.id, far.rtp.id] {
                if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                    return error_result("install secure media redirect", &error);
                }
            }
            let leg = Arc::new(Mutex::new(SecureLeg::new(&far_local.key, &far_remote.key)));

            // Non-muxed companion RTCP: redirect both RTCP endpoints into the actor and relay them
            // through the shared SecureLeg — A's RTCP encrypted toward secure B, B's SRTCP decrypted
            // toward plaintext A — so a non-muxed secure-transcode leg keeps RTCP flowing (RFC 3711
            // SRTCP; RFC 5761 keeps it on its own port). Muxed calls leave this empty.
            let mut rtcp_relays = Vec::new();
            if let (Some(near_rtcp), Some(far_rtcp), Some(a_rtcp)) =
                (near.rtcp, far.rtcp, near.remote_rtcp)
            {
                for endpoint in [near_rtcp.id, far_rtcp.id] {
                    if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                        return error_result("install secure media RTCP redirect", &error);
                    }
                }
                rtcp_relays.push(
                    RtcpRelay::new(
                        near_rtcp.id,
                        bridge_source_filter(profile, near_gate_rtcp.unwrap_or(a_rtcp)),
                        far_rtcp.id,
                        info.remote_rtcp,
                    )
                    .with_secure_egress(leg.clone()),
                );
                rtcp_relays.push(
                    RtcpRelay::new(
                        far_rtcp.id,
                        bridge_source_filter(profile, far_gate_rtcp),
                        near_rtcp.id,
                        a_rtcp,
                    )
                    .with_secure_ingress(leg.clone()),
                );
            }

            let latch = !profile.flags.iter().any(|flag| flag == "no-latch");
            let call = MediaCall::new(
                call_id.to_string(),
                from_tag.to_string(),
                Some(to_tag.clone()),
                a_to_b,
                b_to_a,
                latch,
                record_path,
            )
            .with_far_secure_leg(leg)
            .with_rtcp_relays(rtcp_relays);
            self.media
                .register(call, self.datapath.clone(), owner_events);
        } else if pipeline == PipelineKind::Media {
            // Userspace media slow path: redirect both RTP legs to a per-call transcode/record/DTMF
            // actor. A's codec is the offer's primary codec; B's is the answer's. RTCP (non-mux)
            // still relays in-datapath — it is not transcoded.
            let Some(a_rtp) = near.remote_rtp else {
                return error_result("media pipeline", &"near leg has no signalled address");
            };
            let Some(near_codec) = near_codec.clone() else {
                return error_result("media pipeline", &"offer carried no usable audio codec");
            };
            let Some(far_codec) = info
                .primary_codec()
                .map(|codec| with_ptime_override(&codec, ptime_override))
            else {
                return error_result("media pipeline", &"answer carried no usable audio codec");
            };
            let record_path = profile
                .record_call
                .then(|| profile.record_path.clone())
                .flatten();

            // Build the two transcode directions (decode ingress codec → encode peer's codec). Each
            // direction gates ingress to the effective source (its `received-from` public IP when
            // supplied), not the possibly-private signalled `c=` address.
            let a_to_b = match build_direction(
                near.rtp.id,
                bridge_source_filter(profile, near_gate_rtp.unwrap_or(a_rtp)),
                far.rtp.id,
                info.remote_rtp,
                &near_codec,
                &far_codec,
                near_telephone_event,
                info.telephone_event_payload_type(),
                record_path.as_deref(),
            ) {
                Ok(direction) => direction,
                Err(reason) => return error_result("media pipeline (A→B)", &reason),
            };
            let b_to_a = match build_direction(
                far.rtp.id,
                bridge_source_filter(profile, far_gate_rtp),
                near.rtp.id,
                a_rtp,
                &far_codec,
                &near_codec,
                info.telephone_event_payload_type(),
                near_telephone_event,
                record_path.as_deref(),
            ) {
                Ok(direction) => direction,
                Err(reason) => return error_result("media pipeline (B→A)", &reason),
            };

            // Redirect the RTP legs to the actor (mux ⇒ RTCP rides these; the actor relays it).
            for endpoint in [near.rtp.id, far.rtp.id] {
                if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                    return error_result("install media redirect", &error);
                }
            }
            // Relay companion RTCP in-datapath when not muxed (RTCP is never transcoded). The gate
            // keys on each side's effective source (`received-from` IP when supplied); the forward
            // destination stays the real signalled address.
            if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
                let _ = self.datapath.install_flow(
                    near_rtcp.id,
                    FlowAction::Forward(ingress_rule(
                        far_rtcp.id,
                        Some(info.remote_rtcp),
                        near_gate_rtcp,
                        profile,
                        near_ice,
                    )),
                );
                let _ = self.datapath.install_flow(
                    far_rtcp.id,
                    FlowAction::Forward(ingress_rule(
                        near_rtcp.id,
                        near.remote_rtcp,
                        Some(far_gate_rtcp),
                        profile,
                        far_ice,
                    )),
                );
            }

            let latch = !profile.flags.iter().any(|flag| flag == "no-latch");
            let call = MediaCall::new(
                call_id.to_string(),
                from_tag.to_string(),
                Some(to_tag.clone()),
                a_to_b,
                b_to_a,
                latch,
                record_path,
            );
            self.media
                .register(call, self.datapath.clone(), owner_events);
        } else {
            // Plain relay: the in-datapath Forward fast path. Each endpoint's rule gates its ingress
            // to the peer's effective source and latches per policy (RTPBleed fix —
            // docs/security-and-nat.md §4): `near` receives from A (`near_gate_rtp`, A's
            // `received-from` public IP when supplied, else the signalled `near.remote_rtp`); `far`
            // from B (`far_gate_rtp`). The forward destination is always the real signalled address.
            let near_action = FlowAction::Forward(ingress_rule(
                far.rtp.id,
                Some(info.remote_rtp),
                near_gate_rtp,
                profile,
                near_ice,
            ));
            if let Err(error) = self.datapath.install_flow(near.rtp.id, near_action) {
                return error_result("install near->far RTP flow", &error);
            }
            relay_flows.push((near.rtp.id, near_action));
            let far_action = FlowAction::Forward(ingress_rule(
                near.rtp.id,
                near.remote_rtp,
                Some(far_gate_rtp),
                profile,
                far_ice,
            ));
            if let Err(error) = self.datapath.install_flow(far.rtp.id, far_action) {
                return error_result("install far->near RTP flow", &error);
            }
            relay_flows.push((far.rtp.id, far_action));

            // Companion RTCP relay when not muxed. (Under mux, RTCP rides the RTP endpoints already.)
            if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
                let near_rtcp_action = FlowAction::Forward(ingress_rule(
                    far_rtcp.id,
                    Some(info.remote_rtcp),
                    near_gate_rtcp,
                    profile,
                    near_ice,
                ));
                if let Err(error) = self.datapath.install_flow(near_rtcp.id, near_rtcp_action) {
                    return error_result("install near->far RTCP flow", &error);
                }
                relay_flows.push((near_rtcp.id, near_rtcp_action));
                let far_rtcp_action = FlowAction::Forward(ingress_rule(
                    near_rtcp.id,
                    near.remote_rtcp,
                    Some(far_gate_rtcp),
                    profile,
                    far_ice,
                ));
                if let Err(error) = self.datapath.install_flow(far_rtcp.id, far_rtcp_action) {
                    return error_result("install far->near RTCP flow", &error);
                }
                relay_flows.push((far_rtcp.id, far_rtcp_action));
            }
        }

        // Enable the ICE connectivity-check responder on the RTP endpoints facing an ICE peer; the
        // datapath then answers checks and adopts the validated source (RFC 8445).
        if let Some(creds) = &ice_creds {
            let config = IceConfig {
                local_ufrag: creds.ufrag.clone(),
                local_pwd: creds.pwd.clone(),
            };
            // `near` faces A (which offered ICE); enable the responder on its RTP and, under
            // non-mux, its companion RTCP endpoint.
            for endpoint in near.endpoint_ids() {
                self.datapath.set_ice(endpoint, Some(config.clone()));
            }
            // `far` faces B; enable only when B also offered ICE.
            if info.is_ice() {
                for endpoint in far.endpoint_ids() {
                    self.datapath.set_ice(endpoint, Some(config.clone()));
                }
            }
        }

        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.to_tag = Some(to_tag.clone());
            call.far.remote_rtp = Some(info.remote_rtp);
            call.far.remote_rtcp = Some(info.remote_rtcp);
            // Store the *effective* (ptime-overridden) codecs so an HA checkpoint captures the override
            // and a restore rebuilds the transcode at the same packetization (inert for a plain relay).
            call.near_codec = near_codec.clone();
            call.far_codec = info
                .primary_codec()
                .map(|codec| with_ptime_override(&codec, ptime_override));
            // The far leg's RFC 4733 telephone-event PT from its answer, so `block DTMF` can gate leg
            // B's telephone-event even on a plain relay.
            call.far_telephone_event = info.telephone_event_payload_type();
            call.pipeline = pipeline;
            call.relay_flows = relay_flows;
            // The peer's SDES key (secure answer), kept so an HA checkpoint can re-key the bridge.
            call.far_remote_crypto = info.crypto.first().copied();
        }
        // Answer-side codec presentation: on a transcoding call (Media / SrtpMedia) the engine sends
        // A its *own* negotiated codec, so the answer relayed to A must advertise A's codec, never
        // leak B's (RFC 3264 §6). A plain relay / SRTP bridge / WS leg shares one codec across both
        // sides, so its answer already presents A's codec — leave those byte-for-byte untouched.
        if matches!(pipeline, PipelineKind::Media | PipelineKind::SrtpMedia) {
            if let Some(near_codec) = near_codec.as_ref() {
                rewritten.sdp =
                    sdp::force_answer_codec(&rewritten.sdp, near_codec, near_telephone_event);
            }
        }
        ok_sdp(rewritten.sdp, Some(to_tag))
    }

    async fn delete(&self, client: ClientId, call_id: &str) -> CmdResult {
        // Only the client that created the call may tear it down (A3 — docs §5). A non-owner (or a
        // missing call) gets `unknown_call`, so it cannot even probe for a call's existence.
        match self
            .calls
            .remove_if(call_id, |_, call| call.owner == client)
        {
            Some((_, call)) => {
                let endpoints: Vec<EndpointId> = call
                    .near
                    .endpoint_ids()
                    .chain(call.far.endpoint_ids())
                    .collect();
                // Drop any SIPREC subscriptions (detach forks, abort drains, free subscriber ports),
                // then any SRTP-bridge, media-pipeline, or WS-bridge flows (a no-op for a plain
                // relay), then free the sockets. `media.deregister` aborts the call's actor and
                // flushes any recording; `ws.deregister` aborts the bridge + drain tasks (closing the
                // WS connection).
                self.drop_subscriptions(call_id).await;
                self.bridge.deregister(endpoints.iter().copied());
                self.media.deregister(call_id);
                self.ws.deregister(call_id);
                for endpoint in endpoints {
                    self.datapath.remove_endpoint(endpoint).await;
                    self.endpoint_calls.remove(&endpoint);
                }
                self.release_client_call(call.owner);
                CmdResult::Ok {
                    sdp: None,
                    duration_ms: None,
                    to_tag: None,
                    stats: None,
                }
            }
            None => unknown_call(call_id),
        }
    }

    fn query(&self, client: ClientId, call_id: &str) -> CmdResult {
        let Some(call) = self.calls.get(call_id) else {
            return unknown_call(call_id);
        };
        // A call is invisible to clients that do not own it (A3 — docs §5).
        if call.owner != client {
            return unknown_call(call_id);
        }
        let mut stats = SessionStats::default();
        for endpoint in call.near.endpoint_ids().chain(call.far.endpoint_ids()) {
            let leg = self.datapath.stats(endpoint).unwrap_or_default();
            stats.packets_in += leg.packets_in;
            stats.packets_out += leg.packets_out;
            stats.bytes_in += leg.bytes_in;
            stats.bytes_out += leg.bytes_out;
            stats.packets_lost += leg.packets_dropped;
        }
        CmdResult::Ok {
            sdp: None,
            duration_ms: None,
            to_tag: None,
            stats: Some(stats),
        }
    }

    /// Snapshot a call's replicable state for HA failover ([`Command::Checkpoint`]) — the opaque blob
    /// the SIP proxy stores and hands back to `restore` on a standby. Ownership-gated like `query`: a
    /// non-owner gets `unknown_call`, so it cannot even probe for a call's existence (A3 — docs §5).
    fn checkpoint(&self, client: ClientId, call_id: &str) -> CmdResult {
        // `to_snapshot` only sees the `Call`; a secure call's live SRTP rollover lives in a running
        // component — the SRTP bridge for a plain secure leg (`Srtp`), the media actor for a secure
        // *transcode* leg (`SrtpMedia`) — so the closure also hands back what that later query needs
        // (the peer's SDES key, plus the endpoint roles the bridge query maps its flow ids through).
        let Some((mut snapshot, secure_ctx)) = self.owned_call(client, call_id, |call| {
            let snapshot = call.to_snapshot();
            let secure_ctx = call
                .far_remote_crypto
                .as_ref()
                .map(crypto_snapshot)
                .and_then(|far_remote_crypto| match call.pipeline {
                    PipelineKind::Srtp => Some(SecureCheckpoint::Bridge {
                        roles: call.endpoint_roles(),
                        far_remote_crypto,
                    }),
                    PipelineKind::SrtpMedia => Some(SecureCheckpoint::Media { far_remote_crypto }),
                    _ => None,
                });
            (snapshot, secure_ctx)
        }) else {
            return unknown_call(call_id);
        };
        // The registry key is the authoritative call-id (the snapshot builder left it blank).
        snapshot.call_id = call_id.to_string();
        // For a secure call, fold in the live SRTP rollover (+ bridge flow plans, for `Srtp`). Sourced
        // from the SRTP bridge for `Srtp`, from the media actor's shared `SecureLeg` for `SrtpMedia`.
        snapshot.secure = match secure_ctx {
            Some(SecureCheckpoint::Bridge {
                roles,
                far_remote_crypto,
            }) => self.build_secure_snapshot(&roles, far_remote_crypto),
            Some(SecureCheckpoint::Media { far_remote_crypto }) => {
                self.build_secure_media_snapshot(call_id, far_remote_crypto)
            }
            None => None,
        };
        match snapshot.to_json() {
            Ok(blob) => CmdResult::Checkpoint { snapshot: blob },
            Err(error) => error_result("checkpoint serialize", &error),
        }
    }

    /// Build the [`crate::ha::SecureSnapshot`] for a secure (`Srtp`) call by querying the SRTP bridge
    /// for the shared leg's rollover and the installed flow plans, mapping endpoint ids back to roles.
    /// `None` if the bridge no longer holds the call (raced a teardown).
    fn build_secure_snapshot(
        &self,
        roles: &[(EndpointId, crate::ha::EndpointRole)],
        far_remote_crypto: crate::ha::CryptoSnapshot,
    ) -> Option<crate::ha::SecureSnapshot> {
        let first = roles.first()?.0;
        let rollover = self.bridge.rollover_snapshot(first)?;
        let role_of = |id: EndpointId| roles.iter().find(|(i, _)| *i == id).map(|(_, r)| *r);
        let endpoint_ids: Vec<EndpointId> = roles.iter().map(|(id, _)| *id).collect();
        let bridge_flows = self
            .bridge
            .flow_plans(&endpoint_ids)
            .iter()
            .filter_map(|plan| {
                Some(crate::ha::BridgeFlowSnapshot {
                    endpoint: role_of(plan.endpoint)?,
                    op: match plan.op {
                        BridgeOp::Encrypt => crate::ha::BridgeOpSnapshot::Encrypt,
                        BridgeOp::Decrypt => crate::ha::BridgeOpSnapshot::Decrypt,
                    },
                    accepted_source: source_filter_snapshot(plan.accepted_source),
                    out: role_of(plan.out_endpoint)?,
                    out_dst: plan.out_dst,
                })
            })
            .collect();
        Some(crate::ha::SecureSnapshot {
            far_remote_crypto,
            rollover: secure_rollover_snapshot(&rollover),
            bridge_flows,
        })
    }

    /// Build the [`crate::ha::SecureSnapshot`] for a secure-transcode (`SrtpMedia`) call: the peer's
    /// SDES key plus the media actor's shared [`SecureLeg`] SRTP rollover (RFC 3711 §3.3.1). Unlike an
    /// `Srtp` bridge, an `SrtpMedia` call crypts *inside* the transcode actor — there are no
    /// in-datapath bridge flow plans to snapshot (restore rebuilds the two transcode directions from
    /// the codecs + addresses), so `bridge_flows` is empty. `None` if the media actor no longer holds
    /// the call (raced a teardown) or is somehow not secure.
    fn build_secure_media_snapshot(
        &self,
        call_id: &str,
        far_remote_crypto: crate::ha::CryptoSnapshot,
    ) -> Option<crate::ha::SecureSnapshot> {
        let rollover = self.media.rollover_snapshot(call_id)?;
        Some(crate::ha::SecureSnapshot {
            far_remote_crypto,
            rollover: secure_rollover_snapshot(&rollover),
            bridge_flows: Vec::new(),
        })
    }

    /// Rebuild a call on this (standby) node from a [`Command::Checkpoint`] blob — the HA takeover.
    /// Allocates endpoints at the snapshot's **exact ports** (so a floating-IP standby needs no SIP
    /// re-INVITE), reinstalls the forward rules, and registers the call under the requesting client.
    ///
    /// Restores plain relay (`Passthrough`), the SDES-SRTP bridge (`Srtp`, keys and secure leg
    /// rebuilt), plaintext transcode (`Media`, transcode actor rebuilt), and secure transcode
    /// (`SrtpMedia`, transcode actor **and** the shared SRTP leg rebuilt and re-seeded). A WebSocket
    /// leg (`Ws`, whose bridge is an external session that cannot be resumed from a snapshot) or a DTLS
    /// leg (whose keys are handshake-derived, not signalled) is not restorable and is rejected up
    /// front. Any endpoint bind or flow install that fails rolls back the endpoints already bound.
    async fn restore(&self, client: ClientId, blob: &str) -> CmdResult {
        use crate::ha::{self, EndpointRole, PipelineSnapshot};
        let snapshot = match ha::CallSnapshot::from_json(blob) {
            Ok(snapshot) => snapshot,
            Err(error) => return error_result("restore: parse snapshot", &error),
        };
        // Supported: a plain relay, a secure SDES-SRTP bridge (`Srtp`), a plaintext transcode (`Media`),
        // and a secure transcode (`SrtpMedia`). `Ws` (external WS-bridge session, unrecoverable from a
        // snapshot) and `Dtls` (handshake-derived keys, not signalled) keep their rejection.
        match snapshot.pipeline {
            PipelineSnapshot::Passthrough => {}
            PipelineSnapshot::Srtp if snapshot.secure.is_some() => {}
            PipelineSnapshot::Media
                if snapshot.near_codec.is_some() && snapshot.far_codec.is_some() => {}
            PipelineSnapshot::SrtpMedia
                if snapshot.secure.is_some()
                    && snapshot.near_codec.is_some()
                    && snapshot.far_codec.is_some() => {}
            other => {
                return CmdResult::Error {
                    reason: format!("restore of a {other:?} call is not yet supported"),
                };
            }
        }
        if self.calls.contains_key(&snapshot.call_id) {
            return CmdResult::Error {
                reason: format!("cannot restore: call {} already exists", snapshot.call_id),
            };
        }

        // Bind the endpoints at their exact ports (shared by both pipelines).
        let bound = match self.bind_snapshot_endpoints(&snapshot).await {
            Ok(bound) => bound,
            Err(reason) => return reason,
        };
        let role_endpoint = |role: EndpointRole| -> Option<Endpoint> {
            bound
                .iter()
                .find(|(role_, _)| *role_ == role)
                .map(|(_, endpoint)| *endpoint)
        };
        // Every call has a near.rtp and a far.rtp; RTCP endpoints are optional (rtcp-mux).
        let (Some(near_rtp), Some(far_rtp)) = (
            role_endpoint(EndpointRole::NearRtp),
            role_endpoint(EndpointRole::FarRtp),
        ) else {
            self.free_bound(&bound).await;
            return CmdResult::Error {
                reason: "restore: snapshot is missing a required RTP endpoint".to_string(),
            };
        };
        let near = Leg {
            rtp: near_rtp,
            rtcp: role_endpoint(EndpointRole::NearRtcp),
            remote_rtp: snapshot.near.remote_rtp,
            remote_rtcp: snapshot.near.remote_rtcp,
        };
        let far = Leg {
            rtp: far_rtp,
            rtcp: role_endpoint(EndpointRole::FarRtcp),
            remote_rtp: snapshot.far.remote_rtp,
            remote_rtcp: snapshot.far.remote_rtcp,
        };

        // Install the datapath flows and resolve the crypto per pipeline.
        let mut relay_flows: Vec<(EndpointId, FlowAction)> = Vec::new();
        let mut far_local_crypto: Option<CryptoAttribute> = None;
        let mut far_remote_crypto: Option<CryptoAttribute> = None;
        let mut near_codec_out: Option<CodecSpec> = None;
        let mut far_codec_out: Option<CodecSpec> = None;
        let pipeline;
        match snapshot.pipeline {
            PipelineSnapshot::Passthrough => {
                pipeline = PipelineKind::Passthrough;
                // Reinstall the forward rules, resolving each role to its freshly-bound id.
                for flow in &snapshot.flows {
                    let (Some(installed_on), Some(out)) =
                        (role_endpoint(flow.installed_on), role_endpoint(flow.out))
                    else {
                        self.free_bound(&bound).await;
                        return CmdResult::Error {
                            reason: "restore: a snapshot flow references an unknown endpoint role"
                                .to_string(),
                        };
                    };
                    let action = FlowAction::Forward(ForwardRule {
                        out_endpoint: out.id,
                        out_dst: flow.out_dst,
                        accepted_source: restore_source_filter(flow.accepted_source),
                        latch: restore_latch(flow.latch),
                    });
                    if let Err(error) = self.datapath.install_flow(installed_on.id, action) {
                        self.free_bound(&bound).await;
                        return error_result("restore: install forward flow", &error);
                    }
                    relay_flows.push((installed_on.id, action));
                }
            }
            PipelineSnapshot::Srtp => {
                pipeline = PipelineKind::Srtp;
                // The early validation admits `Srtp` only with `secure` present; if a hand-crafted
                // snapshot violates that, free the ports and error rather than panic (mirrors the
                // graceful returns just below for a missing/bad far_local key).
                let Some(secure) = snapshot.secure.as_ref() else {
                    self.free_bound(&bound).await;
                    return CmdResult::Error {
                        reason: "restore: secure call missing secure snapshot".to_string(),
                    };
                };
                // Reconstruct the two SDES keys (the engine's own + the peer's).
                let far_local = match snapshot.far_local_crypto.as_ref().map(restore_crypto) {
                    Some(Ok(crypto)) => crypto,
                    Some(Err(reason)) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: far_local key", &reason);
                    }
                    None => {
                        self.free_bound(&bound).await;
                        return CmdResult::Error {
                            reason: "restore: secure call missing far_local_crypto".to_string(),
                        };
                    }
                };
                let far_remote = match restore_crypto(&secure.far_remote_crypto) {
                    Ok(crypto) => crypto,
                    Err(reason) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: far_remote key", &reason);
                    }
                };
                // Rebuild the bridge flow plans (roles → freshly-bound ids).
                let mut bridge_flows = Vec::with_capacity(secure.bridge_flows.len());
                for plan in &secure.bridge_flows {
                    let (Some(endpoint), Some(out)) =
                        (role_endpoint(plan.endpoint), role_endpoint(plan.out))
                    else {
                        self.free_bound(&bound).await;
                        return CmdResult::Error {
                            reason: "restore: a secure bridge flow references an unknown role"
                                .to_string(),
                        };
                    };
                    bridge_flows.push(BridgeFlowPlan {
                        endpoint: endpoint.id,
                        op: match plan.op {
                            ha::BridgeOpSnapshot::Encrypt => BridgeOp::Encrypt,
                            ha::BridgeOpSnapshot::Decrypt => BridgeOp::Decrypt,
                        },
                        accepted_source: restore_source_filter(plan.accepted_source),
                        out_endpoint: out.id,
                        out_dst: plan.out_dst,
                    });
                }
                // Redirect every endpoint to the bridge so it crypts both directions.
                for (_, endpoint) in &bound {
                    if let Err(error) = self
                        .datapath
                        .install_flow(endpoint.id, FlowAction::Redirect)
                    {
                        self.free_bound(&bound).await;
                        return error_result("restore: install SRTP bridge redirect", &error);
                    }
                }
                // Rebuild the secure leg from the two keys and seed its rollover, then register.
                let mut leg = SecureLeg::new(&far_local.key, &far_remote.key);
                leg.seed_rollover(&restore_rollover(&secure.rollover));
                self.bridge.register(BridgeCallPlan {
                    leg,
                    flows: bridge_flows,
                });
                far_local_crypto = Some(far_local);
                far_remote_crypto = Some(far_remote);
            }
            PipelineSnapshot::Media => {
                pipeline = PipelineKind::Media;
                // Both codecs were validated present above; the two remote addresses are required to
                // target egress. Rebuild the transcoding actor — jitter/codec state restarts fresh
                // (the cold-restore glitch); the egress SSRC/seq/ts also reset, so the far side re-syncs.
                let (Some(near_codec_snap), Some(far_codec_snap)) =
                    (snapshot.near_codec.as_ref(), snapshot.far_codec.as_ref())
                else {
                    self.free_bound(&bound).await;
                    return CmdResult::Error {
                        reason: "restore: media call missing a codec".to_string(),
                    };
                };
                let (Some(a_rtp), Some(b_rtp)) = (near.remote_rtp, far.remote_rtp) else {
                    self.free_bound(&bound).await;
                    return CmdResult::Error {
                        reason: "restore: media call missing a remote address".to_string(),
                    };
                };
                let near_codec = restore_codec(near_codec_snap);
                let far_codec = restore_codec(far_codec_snap);
                let near_te = snapshot.near_telephone_event;
                let a_to_b = match build_direction(
                    near_rtp.id,
                    SourceFilter::Exact(a_rtp.ip()),
                    far_rtp.id,
                    b_rtp,
                    &near_codec,
                    &far_codec,
                    near_te,
                    None,
                    None,
                ) {
                    Ok(direction) => direction,
                    Err(reason) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: media pipeline (A→B)", &reason);
                    }
                };
                let b_to_a = match build_direction(
                    far_rtp.id,
                    SourceFilter::Exact(b_rtp.ip()),
                    near_rtp.id,
                    a_rtp,
                    &far_codec,
                    &near_codec,
                    None,
                    near_te,
                    None,
                ) {
                    Ok(direction) => direction,
                    Err(reason) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: media pipeline (B→A)", &reason);
                    }
                };
                // Redirect the RTP legs to the actor (rtcp-mux ⇒ RTCP rides them).
                for endpoint in [near_rtp.id, far_rtp.id] {
                    if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                        self.free_bound(&bound).await;
                        return error_result("restore: install media redirect", &error);
                    }
                }
                let owner_events = self.events.get(&client).map(|sink| sink.value().clone());
                let media_call = MediaCall::new(
                    snapshot.call_id.clone(),
                    snapshot.from_tag.clone(),
                    snapshot.to_tag.clone(),
                    a_to_b,
                    b_to_a,
                    true, // relay latch (the `no-latch` flag is not carried in the snapshot)
                    None, // recording restarts on the new node if the proxy re-issues it
                );
                self.media
                    .register(media_call, self.datapath.clone(), owner_events);
                near_codec_out = Some(near_codec);
                far_codec_out = Some(far_codec);
            }
            PipelineSnapshot::SrtpMedia => {
                pipeline = PipelineKind::SrtpMedia;
                // Secure transcode = the `Srtp` bridge's crypto (rebuild both SDES keys + the shared
                // SecureLeg, seed its rollover) merged with the `Media` slow path's transcode (rebuild
                // the two directions + redirect the RTP legs to the actor), threaded together by
                // `with_far_secure_leg` so the actor decrypts the secure peer's ingress and encrypts
                // its egress (BGCF/SBC PSTN breakout). Jitter / codec state and the egress SSRC-seq-ts
                // restart fresh (the cold-restore glitch); the SRTP rollover is *seeded* so the inbound
                // decrypt keeps authenticating past a sequence wrap and the outbound never re-uses an
                // index — no two-time-pad (RFC 3711 §3.3.1 / §3.4).
                let Some(secure) = snapshot.secure.as_ref() else {
                    self.free_bound(&bound).await;
                    return CmdResult::Error {
                        reason: "restore: secure transcode call missing secure snapshot"
                            .to_string(),
                    };
                };
                let (Some(near_codec_snap), Some(far_codec_snap)) =
                    (snapshot.near_codec.as_ref(), snapshot.far_codec.as_ref())
                else {
                    self.free_bound(&bound).await;
                    return CmdResult::Error {
                        reason: "restore: secure transcode call missing a codec".to_string(),
                    };
                };
                let (Some(a_rtp), Some(b_rtp)) = (near.remote_rtp, far.remote_rtp) else {
                    self.free_bound(&bound).await;
                    return CmdResult::Error {
                        reason: "restore: secure transcode call missing a remote address"
                            .to_string(),
                    };
                };
                // Reconstruct the two SDES keys (the engine's own + the peer's), as for `Srtp`.
                let far_local = match snapshot.far_local_crypto.as_ref().map(restore_crypto) {
                    Some(Ok(crypto)) => crypto,
                    Some(Err(reason)) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: far_local key", &reason);
                    }
                    None => {
                        self.free_bound(&bound).await;
                        return CmdResult::Error {
                            reason: "restore: secure transcode call missing far_local_crypto"
                                .to_string(),
                        };
                    }
                };
                let far_remote = match restore_crypto(&secure.far_remote_crypto) {
                    Ok(crypto) => crypto,
                    Err(reason) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: far_remote key", &reason);
                    }
                };
                let near_codec = restore_codec(near_codec_snap);
                let far_codec = restore_codec(far_codec_snap);
                let near_te = snapshot.near_telephone_event;
                // Build the two transcode directions (as for `Media`): A (plaintext) ↔ B (secure). The
                // source gate is reconstructed from the peer's signalled address (a Redirect pipeline
                // carries no portable `flows`), mirroring the plaintext transcode restore.
                let a_to_b = match build_direction(
                    near_rtp.id,
                    SourceFilter::Exact(a_rtp.ip()),
                    far_rtp.id,
                    b_rtp,
                    &near_codec,
                    &far_codec,
                    near_te,
                    None,
                    None,
                ) {
                    Ok(direction) => direction,
                    Err(reason) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: secure media pipeline (A→B)", &reason);
                    }
                };
                let b_to_a = match build_direction(
                    far_rtp.id,
                    SourceFilter::Exact(b_rtp.ip()),
                    near_rtp.id,
                    a_rtp,
                    &far_codec,
                    &near_codec,
                    None,
                    near_te,
                    None,
                ) {
                    Ok(direction) => direction,
                    Err(reason) => {
                        self.free_bound(&bound).await;
                        return error_result("restore: secure media pipeline (B→A)", &reason);
                    }
                };
                // Redirect the RTP legs to the actor (rtcp-mux ⇒ RTCP rides them, (de)crypted inside).
                for endpoint in [near_rtp.id, far_rtp.id] {
                    if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                        self.free_bound(&bound).await;
                        return error_result("restore: install secure media redirect", &error);
                    }
                }
                // Rebuild the shared SecureLeg from the two keys and seed its rollover *before* wrapping
                // it (the fresh leg is unshared, so no lock is needed), then thread it into both
                // directions + the RTCP relays.
                let mut secure_leg = SecureLeg::new(&far_local.key, &far_remote.key);
                secure_leg.seed_rollover(&restore_rollover(&secure.rollover));
                let leg = Arc::new(Mutex::new(secure_leg));
                // Non-muxed companion RTCP: redirect both RTCP endpoints into the actor and relay them
                // through the shared SecureLeg (A's RTCP encrypted toward secure B, B's SRTCP decrypted
                // toward plaintext A), exactly as the live builder does (RFC 3711 SRTCP; RFC 5761 keeps
                // RTCP on its own port). Muxed calls leave this empty.
                let mut rtcp_relays = Vec::new();
                if let (Some(near_rtcp), Some(far_rtcp), Some(a_rtcp), Some(b_rtcp)) =
                    (near.rtcp, far.rtcp, near.remote_rtcp, far.remote_rtcp)
                {
                    for endpoint in [near_rtcp.id, far_rtcp.id] {
                        if let Err(error) =
                            self.datapath.install_flow(endpoint, FlowAction::Redirect)
                        {
                            self.free_bound(&bound).await;
                            return error_result(
                                "restore: install secure media RTCP redirect",
                                &error,
                            );
                        }
                    }
                    rtcp_relays.push(
                        RtcpRelay::new(
                            near_rtcp.id,
                            SourceFilter::Exact(a_rtcp.ip()),
                            far_rtcp.id,
                            b_rtcp,
                        )
                        .with_secure_egress(leg.clone()),
                    );
                    rtcp_relays.push(
                        RtcpRelay::new(
                            far_rtcp.id,
                            SourceFilter::Exact(b_rtcp.ip()),
                            near_rtcp.id,
                            a_rtcp,
                        )
                        .with_secure_ingress(leg.clone()),
                    );
                }
                let owner_events = self.events.get(&client).map(|sink| sink.value().clone());
                let media_call = MediaCall::new(
                    snapshot.call_id.clone(),
                    snapshot.from_tag.clone(),
                    snapshot.to_tag.clone(),
                    a_to_b,
                    b_to_a,
                    true, // relay latch (the `no-latch` flag is not carried in the snapshot)
                    None, // recording restarts on the new node if the proxy re-issues it
                )
                .with_far_secure_leg(leg)
                .with_rtcp_relays(rtcp_relays);
                self.media
                    .register(media_call, self.datapath.clone(), owner_events);
                near_codec_out = Some(near_codec);
                far_codec_out = Some(far_codec);
                far_local_crypto = Some(far_local);
                far_remote_crypto = Some(far_remote);
            }
            _ => unreachable!("pipeline validated above"),
        }

        // Register the reconstructed call under the requesting (standby) client.
        *self.client_calls.entry(client).or_insert(0) += 1;
        for (_, endpoint) in &bound {
            self.endpoint_calls
                .insert(endpoint.id, snapshot.call_id.clone());
        }
        self.calls.insert(
            snapshot.call_id.clone(),
            Call {
                owner: client,
                created_tick: self.datapath.now_ticks(),
                ice: snapshot.ice.map(|ice| IceCredentials {
                    ufrag: ice.ufrag,
                    pwd: ice.pwd,
                }),
                from_tag: snapshot.from_tag,
                to_tag: snapshot.to_tag,
                near,
                far,
                far_local_crypto,
                far_remote_crypto,
                // A DTLS-SRTP call is never restored (rejected above), so it is always plaintext/SDES here.
                far_dtls: false,
                // Set for a transcode (`Media`) call; `None` for relay/bridge, which don't transcode.
                near_codec: near_codec_out,
                far_codec: far_codec_out,
                near_telephone_event: snapshot.near_telephone_event,
                // The far leg's telephone-event PT is not carried in the HA snapshot (a restored call
                // is not DTMF-blocked — the reason set is cleared above too); resolved only on a fresh
                // answer. `block DTMF` after a restore on a plain relay gates whichever side's PT is
                // known (near), which is the documented relay-path limitation.
                far_telephone_event: None,
                pipeline,
                relay_flows,
                promotion_reasons: HashSet::new(),
                // The source gate is reconstructed from the snapshot's per-flow `accepted_source`
                // (which already folded in any `received-from` at the original answer), so the raw
                // hint is not needed on the restored node.
                offer_received_from: None,
            },
        );
        tracing::info!(call_id = %snapshot.call_id, "restored call from HA snapshot");
        ok_empty()
    }

    /// Bind a snapshot's endpoints at their exact ports (HA restore), in role order. On any bind
    /// failure the endpoints already bound are freed and an error result is returned.
    async fn bind_snapshot_endpoints(
        &self,
        snapshot: &crate::ha::CallSnapshot,
    ) -> Result<Vec<(crate::ha::EndpointRole, Endpoint)>, CmdResult> {
        use crate::ha::EndpointRole;
        let mut targets: Vec<(EndpointRole, std::net::SocketAddr)> =
            vec![(EndpointRole::NearRtp, snapshot.near.rtp_local)];
        if let Some(addr) = snapshot.near.rtcp_local {
            targets.push((EndpointRole::NearRtcp, addr));
        }
        targets.push((EndpointRole::FarRtp, snapshot.far.rtp_local));
        if let Some(addr) = snapshot.far.rtcp_local {
            targets.push((EndpointRole::FarRtcp, addr));
        }
        let mut bound: Vec<(EndpointRole, Endpoint)> = Vec::new();
        for (role, addr) in targets {
            match self
                .datapath
                .alloc_endpoint_on_port(AddressFamily::of(addr.ip()), addr.port())
                .await
            {
                Ok(endpoint) => bound.push((role, endpoint)),
                Err(error) => {
                    self.free_bound(&bound).await;
                    return Err(error_result(
                        "restore: bind endpoint at snapshot port",
                        &error,
                    ));
                }
            }
        }
        Ok(bound)
    }

    /// Free the endpoints bound so far during a [`Self::restore`] that then failed (rollback).
    async fn free_bound(&self, bound: &[(crate::ha::EndpointRole, Endpoint)]) {
        let endpoints: Vec<Endpoint> = bound.iter().map(|(_, endpoint)| *endpoint).collect();
        self.free(&endpoints).await;
    }

    /// Enumerate the live call-ids `client` owns ([`Command::List`]) — a read-only census of the
    /// session registry (rtpengine NG `list`). Scoped to the calling client: a call is invisible to
    /// clients that do not own it (A3 — docs §5), so the listing never leaks another client's
    /// call-ids. Order is unspecified (the `DashMap` is unordered). Cheap and lock-light: a sharded
    /// scan that clones only the matching keys.
    fn list(&self, client: ClientId) -> CmdResult {
        let call_ids = self
            .calls
            .iter()
            .filter(|entry| entry.value().owner == client)
            .map(|entry| entry.key().clone())
            .collect();
        CmdResult::List { call_ids }
    }

    /// Read the engine's global process counters ([`Command::Statistics`]) — a read-only snapshot of
    /// the operational metrics surface (rtpengine NG `statistics`). The monotonic counters come from
    /// the shared [`Metrics`] (the same surface `/metrics` renders); `sessions` is the live registry
    /// gauge. Process-wide, not per-client — every client sees the same global figures.
    fn statistics(&self) -> CmdResult {
        let snapshot = self.metrics.snapshot();
        CmdResult::Statistics {
            statistics: EngineStatistics {
                offers_total: snapshot.offers_total,
                answers_total: snapshot.answers_total,
                deletes_total: snapshot.deletes_total,
                control_errors_total: snapshot.control_errors_total,
                sessions: self.session_count() as u64,
            },
        }
    }

    /// Report this engine's live load ([`Command::Load`]) for cluster placement — the live session
    /// gauges, the transcoding subset, jemalloc live bytes, host CPU (best effort), and drain state,
    /// all via the shared [`ClusterState`]. Process-wide, not per-client, like `statistics`.
    fn load_snapshot(&self) -> CmdResult {
        CmdResult::Load {
            load: self.cluster.load(
                self.session_count() as u64,
                self.transcode_session_count() as u64,
                crate::metrics::jemalloc_allocated_bytes(),
            ),
        }
    }

    /// Describe this engine's static identity and capabilities ([`Command::NodeInfo`]) so a
    /// dispatcher routes a call only to a node that can serve it (codecs, features, capacity).
    fn node_info(&self) -> CmdResult {
        CmdResult::NodeInfo {
            node: self
                .cluster
                .info(engine_version(), supported_codecs(), supported_features()),
        }
    }

    /// Live count of transcoding calls (the media slow path minus promoted relay-only passthroughs) —
    /// the expensive subset the cluster `load` command reports.
    #[must_use]
    pub fn transcode_session_count(&self) -> usize {
        self.media.transcode_call_count()
    }

    /// Drop (`block = true`) or resume (`block = false`) a call's media. A media-processing call
    /// flips its actor's egress; a plain relay flips its datapath flows to `Drop` and back. Only the
    /// owning client may control the call (A3 — docs §5).
    async fn set_block(&self, client: ClientId, call_id: &str, block: bool) -> CmdResult {
        let Some(relay_flows) = self.owned_call(client, call_id, |call| call.relay_flows.clone())
        else {
            return unknown_call(call_id);
        };
        if self.media.is_media_call(call_id) {
            self.media.control(call_id, MediaControl::Block(block));
            return ok_empty();
        }
        if relay_flows.is_empty() {
            return error_result(
                "block",
                &"call is not answered as a plain relay (SRTP-bridge block is not supported)",
            );
        }
        // Plain relay: flip each endpoint to Drop, or restore its stored forward action.
        for (endpoint, action) in &relay_flows {
            let next = if block { FlowAction::Drop } else { *action };
            if let Err(error) = self.datapath.install_flow(*endpoint, next) {
                return error_result("block: install flow", &error);
            }
        }
        ok_empty()
    }

    /// Block (`blocked = true`) or resume (`blocked = false`) relaying one leg's RFC 4733
    /// telephone-events (DTMF) to the peer (`block DTMF` / `unblock DTMF`). The named leg's
    /// telephone-events are still detected (the controller sees the digit as an `Event::Dtmf`) but not
    /// forwarded — v1 = drop mode (rtpengine's replace-with-tone/PCM modes are a follow-up).
    ///
    /// A plain relay (`Passthrough`) is promoted to the userspace media pipeline so the actor can gate
    /// the telephone-event PT per direction; a transcode / secure-transcode call already has an actor.
    /// A plain SRTP bridge (`Srtp`) or WebSocket-bridged call (`Ws`) is rejected — its DTMF is not
    /// carried as clear telephone-events (mirrors `subscribe_request` / recording). Only the owning
    /// client may. `source_a` (which leg is blocked) is resolved from the tags the same way
    /// `subscribe_request` does: `to_tag` matching the call's to-tag ⇒ leg B.
    async fn block_dtmf(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: Option<&str>,
        blocked: bool,
    ) -> CmdResult {
        // Snapshot the pipeline + the call's to-tag under the ownership guard (A3 — docs §5).
        let Some((pipeline, call_to)) =
            self.owned_call(client, call_id, |call| (call.pipeline, call.to_tag.clone()))
        else {
            return unknown_call(call_id);
        };
        // A plain SRTP bridge / WS-bridge leg's DTMF is not clear telephone-events — reject clearly.
        // (A secure *transcode* call — SrtpMedia — decrypts to clear RTP in the actor, so it is fine.)
        if matches!(pipeline, PipelineKind::Srtp | PipelineKind::Ws) {
            return error_result(
                "block_dtmf",
                &"blocking DTMF on a secure (SRTP) or WebSocket-bridged call is not supported",
            );
        }
        // Resolve which leg is blocked: the call's to_tag ⇒ leg B (source_a = false); else leg A.
        let source_a = !matches!((call_to.as_deref(), to_tag), (Some(to), Some(tag)) if to == tag);
        // A plain relay is promoted to userspace (and held) so its actor can gate the telephone-event
        // PT; a transcode / SrtpMedia call already has an actor. Holding on block, releasing on unblock.
        if blocked {
            if let Err(reason) = self
                .hold_in_userspace(call_id, PromotionReason::DtmfBlock, PromoteMode::RelayOnly)
                .await
            {
                return error_result("block_dtmf: promote relay", &reason);
            }
            if !self.media.control(
                call_id,
                MediaControl::BlockDtmf {
                    source_a,
                    blocked: true,
                },
            ) {
                // The actor vanished between promote and control — release the hold and report.
                self.release_userspace_hold(call_id, PromotionReason::DtmfBlock)
                    .await;
                return error_result("block_dtmf", &"media actor unavailable");
            }
            ok_empty()
        } else {
            // Unblock: clear the actor's gate first (no-op if no actor / never promoted), then release
            // the hold, which demotes a plain relay back to the fast path if nothing else holds it.
            self.media.control(
                call_id,
                MediaControl::BlockDtmf {
                    source_a,
                    blocked: false,
                },
            );
            self.release_userspace_hold(call_id, PromotionReason::DtmfBlock)
                .await;
            ok_empty()
        }
    }

    /// Replace a call's egress audio with comfort silence (`silence = true`) or resume it. Requires a
    /// media-processing call (decode/re-encode); a plain relay forwards opaque payloads and cannot
    /// synthesize silence. Only the owning client may control the call.
    fn set_silence(&self, client: ClientId, call_id: &str, silence: bool) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // Silence synthesizes comfort noise in the egress codec — a transcoding call only. A promoted
        // relay-only call (SIPREC on a passthrough relay) forwards opaque payloads and cannot.
        if self.media.is_transcoding_call(call_id)
            && self.media.control(call_id, MediaControl::Silence(silence))
        {
            ok_empty()
        } else {
            error_result(
                "silence",
                &"call is not a media-processing call (transcode/record/stream required)",
            )
        }
    }

    /// Enable or disable echo-test mode on a call ([`Command::Echo`]): each party's ingress audio is
    /// decoded and re-emitted straight back to itself. A single-leg IVR/echo call is a plain
    /// passthrough relay, so — like `block_dtmf` / `start_recording` — echo promotes it into the
    /// userspace media pipeline first, but into a **processing** (decode → re-encode) `MediaCall`, not a
    /// relay-only one (a relay forwards opaque payloads to the peer and cannot loop them home). An
    /// already-transcoding call is used as-is. On disable the hold is released, demoting a promoted
    /// relay back to the `Forward` fast path once nothing else holds it. Only the owning client may
    /// control the call; `from_tag` is accepted for protocol symmetry (echo applies to the whole call).
    async fn set_echo(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        enabled: bool,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        if enabled {
            // Promote a plain relay into a processing MediaCall (idempotent on an already-promoted /
            // transcoding call) and hold it, then turn echo on.
            if let Err(reason) = self
                .hold_in_userspace(call_id, PromotionReason::Echo, PromoteMode::Processing)
                .await
            {
                return error_result("echo: promote relay", &reason);
            }
            if !self.media.control(call_id, MediaControl::Echo(true)) {
                // The actor vanished between promote and control — release the hold and report.
                self.release_userspace_hold(call_id, PromotionReason::Echo)
                    .await;
                return error_result("echo", &"media actor unavailable");
            }
            ok_empty()
        } else {
            // Disable: clear the actor's echo flag (a no-op if never promoted), then release the hold,
            // which demotes a promoted relay back to the fast path if nothing else holds it.
            self.media.control(call_id, MediaControl::Echo(false));
            self.release_userspace_hold(call_id, PromotionReason::Echo)
                .await;
            ok_empty()
        }
    }

    /// Join (or lazily create) an audio conference ([`Command::ConferenceJoin`]). The participant
    /// offers SDP; the engine allocates one endpoint, seats it in the room's mixer, and answers with
    /// the engine endpoint advertising the participant's codec (sendrecv) — the participant then hears
    /// the room's mixed-minus-self audio. Each participant endpoint is a full inbound surface, so the
    /// source gate + constrained latch are enforced on ingress (RTPBleed, docs §4).
    async fn conference_join(
        &self,
        client: ClientId,
        conference_id: &str,
        from_tag: String,
        sdp: &str,
        role: ConferenceRole,
        profile: &ProfileFlags,
    ) -> CmdResult {
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => return error_result("conference_join: SDP parse", &error),
        };
        // Plain RTP/AVP and SDES RTP/SAVP conference legs are supported; ICE / DTLS-SRTP (WebRTC)
        // conference legs are a follow-up (the SDES secure leg is wired below).
        if info.is_ice() {
            return error_result(
                "conference_join",
                &"ICE / DTLS-SRTP conference legs are not supported yet (use plain RTP/AVP or SDES RTP/SAVP)",
            );
        }
        let Some(codec) = info.primary_codec() else {
            return error_result("conference_join", &"offer has no audio codec");
        };
        // Build the participant's codecs. `encoder_for` rejects a decode-only codec (AMR-WB): we can
        // mix in such a leg's audio but cannot encode the room back to it yet, so the seat is refused.
        let decoder = match factory::decoder_for(&codec) {
            Ok(decoder) => decoder,
            Err(error) => return error_result("conference_join: decoder", &error),
        };
        let encoder = match factory::encoder_for(&codec) {
            Ok(encoder) => encoder,
            Err(_) => {
                return error_result(
                    "conference_join",
                    &format!(
                        "codec {} has no encoder, so the room mix cannot be sent to this participant \
                         (AMR-WB / AMR-NB need the `amr` build feature; Opus encode is not implemented)",
                        codec.encoding_name
                    ),
                )
            }
        };
        // One engine endpoint in the offer's address family, redirected to the conference actor.
        let family = AddressFamily::of(info.remote_rtp.ip());
        let endpoint = match self.alloc_endpoints(1, family).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return error_result("conference_join", &reason),
        };
        if let Err(error) = self
            .datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
        {
            self.free(&[endpoint]).await;
            return error_result("conference_join: install redirect", &error);
        }
        // RTPBleed gate: exact signalled-source by default; accept-any only for an explicit symmetric
        // leg. The constrained latch then learns the reply address from the gated source.
        let accepted_source = if profile.flags.iter().any(|flag| flag == "symmetric") {
            SourceFilter::Any
        } else {
            SourceFilter::Exact(info.remote_rtp.ip())
        };
        // SDES-SRTP (RTP/SAVP): the participant offered a secure leg + its a=crypto. Mint our own key,
        // build the secure leg (decrypt inbound with theirs, encrypt outbound with ours), and answer
        // RTP/SAVP + a=crypto. (DTLS-SRTP / ICE WebRTC legs remain a follow-up — see the is_ice() guard.)
        let (secure, security) = if info.secure {
            let Some(remote) = info.crypto.first().copied() else {
                self.free(&[endpoint]).await;
                return error_result(
                    "conference_join",
                    &"RTP/SAVP offer without a usable a=crypto",
                );
            };
            let local = match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                Ok(local) => local,
                Err(error) => {
                    self.free(&[endpoint]).await;
                    return error_result("conference_join: generate SDES key", &error);
                }
            };
            (
                Some(SecureLeg::new(&local.key, &remote.key)),
                Some(SecurityAdvertisement::Secure(local)),
            )
        } else {
            (None, None)
        };
        let config = ParticipantConfig {
            tag: from_tag.clone(),
            decoder,
            encoder,
            ingress_endpoint: endpoint.id,
            egress_endpoint: endpoint.id,
            egress_dst: info.remote_rtp,
            accepted_source,
            latch: true,
            egress_ssrc: random_ssrc(),
            egress_payload_type: codec.payload_type,
            mos_codec: crate::conference::hep_codec_for_name(&codec.encoding_name),
            telephone_event_in: info.telephone_event_payload_type(),
            secure,
            routing: routing_of(role),
        };
        let events = self.events.get(&client).map(|sink| sink.value().clone());
        let joined_tick = self.datapath.now_ticks();
        if !self.conference.join(
            conference_id,
            config,
            joined_tick,
            self.datapath.clone(),
            events,
        ) {
            self.free(&[endpoint]).await;
            return error_result("conference_join", &"failed to seat participant");
        }
        self.endpoint_calls
            .insert(endpoint.id, conference_id.to_string());

        // Answer: advertise the engine endpoint, keep the participant's codec, sendrecv, and (for a
        // secure leg) RTP/SAVP + the engine's a=crypto.
        let engine = EngineMedia {
            rtp: endpoint.local_addr,
            rtcp: None,
        };
        // A conference leg is always RTP/RTCP-muxed onto the one participant endpoint; the mux
        // presentation mirrors the participant's offer (`None`) — the `rtcp-mux` directive is an
        // offer/answer relay concern, not a conference one.
        match sdp::rewrite(sdp, engine, IceRewrite::Keep, security, None) {
            Ok(rewritten) => ok_sdp(rewritten.sdp, Some(from_tag)),
            Err(error) => {
                let _ = self.conference.leave(conference_id, &from_tag);
                self.endpoint_calls.remove(&endpoint.id);
                self.datapath.remove_endpoint(endpoint.id).await;
                error_result("conference_join: SDP rewrite", &error)
            }
        }
    }

    /// Remove a participant from a conference ([`Command::ConferenceLeave`]), freeing its endpoint and
    /// tearing the room down once empty.
    async fn conference_leave(&self, conference_id: &str, from_tag: &str) -> CmdResult {
        match self.conference.leave(conference_id, from_tag) {
            Some(endpoint) => {
                self.endpoint_calls.remove(&endpoint);
                self.datapath.remove_endpoint(endpoint).await;
                ok_empty()
            }
            None => error_result("conference_leave", &"no such conference participant"),
        }
    }

    /// Live-update a participant's conference role / routing ([`Command::ConferenceRoute`]).
    fn conference_route(
        &self,
        conference_id: &str,
        from_tag: &str,
        role: ConferenceRole,
    ) -> CmdResult {
        if self
            .conference
            .route(conference_id, from_tag, routing_of(role))
        {
            ok_empty()
        } else {
            error_result("conference_route", &"no such conference or participant")
        }
    }

    /// Bridge two conferences ([`Command::ConferenceBridge`]) so each room hears the other's
    /// participants, in the requested direction(s).
    fn conference_bridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
        direction: BridgeDirection,
    ) -> CmdResult {
        let (a_to_b, b_to_a) = match direction {
            BridgeDirection::Both => (true, true),
            BridgeDirection::AToB => (true, false),
            BridgeDirection::BToA => (false, true),
        };
        if self
            .conference
            .bridge(conference_id_a, conference_id_b, a_to_b, b_to_a)
        {
            ok_empty()
        } else {
            error_result("conference_bridge", &"one or both conferences do not exist")
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

    /// Inject a prompt / announcement toward a leg ([`Command::PlayMedia`]). Requires a
    /// media-processing call (the actor owns the egress codec). The source is a WAV file/blob.
    async fn play_media(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        source: PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
    ) -> CmdResult {
        let Some((call_from, call_to)) = self.owned_call(client, call_id, |call| {
            (call.from_tag.clone(), call.to_tag.clone())
        }) else {
            return unknown_call(call_id);
        };
        if !self.media.is_transcoding_call(call_id) {
            return error_result(
                "play_media",
                &"requires a media-processing call (transcode/record/stream)",
            );
        }
        let bytes = match source {
            PlayMediaSource::Blob { data } => data,
            PlayMediaSource::File { path } => match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(error) => return error_result("play_media: read file", &error),
            },
            PlayMediaSource::DbId { .. } => {
                return error_result("play_media", &"db-id media source is not supported")
            }
        };
        let wav = match WavSource::parse(&bytes) {
            Ok(wav) => wav,
            Err(error) => return error_result("play_media: parse WAV", &error),
        };
        // `repeat_times` is the total play count; 0/None plays once (PcmPlayer treats 0/1 alike).
        let repeat = repeat_times.unwrap_or(0).min(u64::from(u32::MAX)) as u32;
        let start = start_pos_ms.unwrap_or(0).min(u64::from(u32::MAX)) as u32;
        let player = PcmPlayer::new(&wav, repeat, start);
        let toward_a = resolve_toward_a(from_tag, &call_from, call_to.as_deref());
        self.media.control(
            call_id,
            MediaControl::PlayAudio {
                toward_a,
                player: Box::new(player),
            },
        );
        ok_empty()
    }

    /// Stop any prompt / DTMF playback on a call ([`Command::StopMedia`]).
    fn stop_media(&self, client: ClientId, call_id: &str, _from_tag: &str) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        if self.media.control(call_id, MediaControl::StopPlay) {
            ok_empty()
        } else {
            error_result("stop_media", &"call has no active media playback")
        }
    }

    /// Inject an RFC 4733 DTMF burst toward a leg ([`Command::PlayDtmf`]). Requires a media-processing
    /// call with a negotiated telephone-event payload type on the target leg.
    fn play_dtmf(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
    ) -> CmdResult {
        let Some((call_from, call_to)) = self.owned_call(client, call_id, |call| {
            (call.from_tag.clone(), call.to_tag.clone())
        }) else {
            return unknown_call(call_id);
        };
        if !self.media.is_transcoding_call(call_id) {
            return error_result("play_dtmf", &"requires a media-processing call");
        }
        let Some(digit) = code.chars().next() else {
            return error_result("play_dtmf", &"empty DTMF code");
        };
        let duration = duration_ms.unwrap_or(250).min(u64::from(u32::MAX)) as u32;
        // `volume_dbm0` is a (negative) dBm0 power level; the generator takes its magnitude (0..=63).
        let volume = volume_dbm0
            .map(|value| value.unsigned_abs().min(63) as u8)
            .unwrap_or(10);
        let toward_a = resolve_toward_a(from_tag, &call_from, call_to.as_deref());
        if self.media.control(
            call_id,
            MediaControl::PlayDtmf {
                toward_a,
                digit,
                duration_ms: duration,
                volume,
            },
        ) {
            ok_empty()
        } else {
            error_result("play_dtmf", &"call is not a media-processing call")
        }
    }

    /// Begin a runtime raw-RTP pcap recording of an established call ([`Command::StartRecording`] /
    /// rtpengine `start recording`). A plain passthrough relay is promoted to the userspace media
    /// pipeline (so its packets can be tapped) and each accepted RTP/RTCP datagram is captured
    /// byte-for-byte — the source leg's negotiated codec, no decode — into `{recording_dir}/{call}.pcap`
    /// wrapped in synthetic Ethernet/IP/UDP so it dissects as RTP. Rejected on a secure (SRTP) or
    /// WebSocket-bridged call, whose on-the-wire bytes are ciphertext / off to a WS server rather than
    /// the clear media (mirrors `subscribe_request`; SRTP decrypt-then-record is a follow-up).
    async fn start_recording(
        &self,
        client: ClientId,
        call_id: &str,
        recording_dir: Option<String>,
    ) -> CmdResult {
        // Snapshot the pipeline + each leg's engine-local RTP address under the ownership guard (A3).
        let Some((pipeline, a_local, b_local)) = self.owned_call(client, call_id, |call| {
            (
                call.pipeline,
                call.near.rtp.local_addr,
                call.far.rtp.local_addr,
            )
        }) else {
            return unknown_call(call_id);
        };
        if matches!(
            pipeline,
            PipelineKind::Srtp | PipelineKind::SrtpMedia | PipelineKind::Ws
        ) {
            return error_result(
                "start_recording",
                &"recording a secure (SRTP) or WebSocket-bridged call is not supported yet",
            );
        }
        let Some(directory) = recording_dir else {
            return error_result(
                "start_recording",
                &"no recording directory (set recording-dir)",
            );
        };
        // Open the pcap up front so a bad path fails cleanly before we promote or spawn anything.
        let path = format!("{directory}/{call_id}.pcap");
        let file = match tokio::fs::File::create(&path).await {
            Ok(file) => file,
            Err(error) => return error_result("start_recording: open pcap", &error),
        };
        // Promote a plain relay to userspace (idempotent) and hold it for the duration of recording.
        if let Err(reason) = self
            .hold_in_userspace(call_id, PromotionReason::Recording, PromoteMode::RelayOnly)
            .await
        {
            return error_result("start_recording: promote relay", &reason);
        }
        // Hand the actor the capture sink; the engine owns the drain task that frames + streams to disk.
        let (sender, receiver) = flume::bounded::<CapturedPacket>(PCAP_CAPTURE_QUEUE);
        let capture = PcapCapture {
            sender,
            a_local,
            b_local,
        };
        if !self
            .media
            .control(call_id, MediaControl::StartRecording { capture })
        {
            // The actor vanished between promote and control — release the hold and report.
            self.release_userspace_hold(call_id, PromotionReason::Recording)
                .await;
            return error_result("start_recording", &"media actor unavailable");
        }
        tokio::spawn(run_pcap_recorder(file, receiver, path));
        ok_empty()
    }

    /// Stop a runtime recording started with [`Self::start_recording`] ([`Command::StopRecording`] /
    /// rtpengine `stop recording`): tell the actor to drop its capture sink (the drain task then
    /// finalizes the `.pcap`) and release the recording hold, demoting the relay back to the in-kernel
    /// `Forward` fast path if no other hold (a SIPREC subscription) remains.
    async fn stop_recording(&self, client: ClientId, call_id: &str) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // No-op in the actor if not recording; ignored if the call has no actor (never promoted).
        self.media.control(call_id, MediaControl::StopRecording);
        self.release_userspace_hold(call_id, PromotionReason::Recording)
            .await;
        ok_empty()
    }

    /// SIPREC / monitor `subscribe_request` (RFC 7866): the engine **offers** one or more source
    /// legs' media to a send-only subscriber (a Session Recording Server, SRS). It resolves the source
    /// legs from `from_tags` (an MPTY subscription taps every named leg), allocates one subscriber
    /// endpoint, advertises the (first) source leg's negotiated codec in the offer's `a=rtpmap`
    /// (RFC 4566 §6) with `a=sendonly` (RFC 3264 §5.1), records a *pending* subscription, and returns
    /// the offer. No media flows until `subscribe_answer` brings the SRS's address.
    ///
    /// The tee copies the source leg's **original ingress RTP byte-for-byte** — its negotiated codec,
    /// no re-encode — so it works on **any** call: a plain G.711 relay, a transcoding call, and a
    /// codec the engine cannot encode (AMR-WB). A plain passthrough relay (the in-kernel `Forward`
    /// fast path) is **promoted** to userspace here so the tee has somewhere to attach; a secure
    /// (SRTP-bridge) or WS-bridge call cannot be tee'd yet and is rejected.
    ///
    /// MPTY: each named leg becomes a separate tap into the one subscription. A true N-way *mix* into
    /// a single stream is a later feature — for now the SRS receives each leg's stream interleaved on
    /// the one subscriber endpoint (distinguishable by SSRC, RFC 3550).
    async fn subscribe_request(
        &self,
        client: ClientId,
        call_id: &str,
        from_tags: &[String],
        sdp: Option<&str>,
        _profile: &ProfileFlags,
    ) -> CmdResult {
        // The controller offers media to the SRS — it sends no SDP on the request. (An SDP-bearing
        // request, i.e. the SRS offering to the engine, is a follow-up; reject it clearly for now.)
        if sdp.is_some() {
            return error_result(
                "subscribe_request",
                &"SDP-offer-from-subscriber is not supported (the engine offers; send sdp: null)",
            );
        }
        // Snapshot the leg identity/codecs/pipeline under the ownership guard (A3 — docs §5).
        let Some((call_to, near_codec, far_codec, pipeline, family)) =
            self.owned_call(client, call_id, |call| {
                (
                    call.to_tag.clone(),
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.pipeline,
                    // The subscriber endpoint binds the call's address family (RFC 4566 §5.7), so a
                    // v6 call's SIPREC tee is offered to the SRS on a v6 endpoint (`c=IN IP6`).
                    AddressFamily::of(call.near.rtp.local_addr.ip()),
                )
            })
        else {
            return unknown_call(call_id);
        };
        // A secure (SRTP-bridge) or WS-bridge leg cannot be raw-tee'd: the on-the-wire bytes are
        // encrypted / off to a WS server, not the leg's clear negotiated codec. Reject clearly.
        if matches!(pipeline, PipelineKind::Srtp | PipelineKind::Ws) {
            return error_result(
                "subscribe_request",
                &"SIPREC on a secure (SRTP) or WebSocket-bridged call is not supported yet",
            );
        }

        // Resolve each named leg to a tap selector (`true` ⇒ leg A, `false` ⇒ leg B). An empty
        // `from_tags` defaults to leg A. Duplicate / unknown tags collapse to leg A (the offerer).
        let taps: Vec<bool> = if from_tags.is_empty() {
            vec![true]
        } else {
            let mut taps = Vec::with_capacity(from_tags.len());
            for tag in from_tags {
                // The call's to_tag ⇒ leg B; anything else (the from_tag, or unknown) ⇒ leg A.
                let source_a = !matches!(call_to.as_deref(), Some(to_tag) if to_tag == *tag);
                if !taps.contains(&source_a) {
                    taps.push(source_a);
                }
            }
            taps
        };

        // The codec advertised in the offer = the (first tapped) source leg's negotiated codec.
        let first_tap_source_a = taps.first().copied().unwrap_or(true);
        let codec = if first_tap_source_a {
            near_codec
        } else {
            far_codec
        };
        let Some(codec) = codec else {
            return error_result(
                "subscribe_request",
                &"the source leg has no negotiated codec to advertise",
            );
        };

        // Promote a plain passthrough relay to userspace so the tee has an actor to attach to.
        // Idempotent across subscriptions on the same call: a second subscribe finds it already a
        // media call and skips. On a call that already runs in the media slow path (transcode/record)
        // this is a no-op.
        if pipeline == PipelineKind::Passthrough && !self.media.is_media_call(call_id) {
            if let Err(reason) = self.promote_passthrough(call_id).await {
                return error_result("subscribe_request: promote relay", &reason);
            }
        }

        // Allocate the single send-only subscriber endpoint in the call's address family.
        let subscriber_endpoint = match self.alloc_endpoints(1, family).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return error_result("subscribe_request", &reason),
        };

        // The subscription id (returned as the UAS to-tag) names this subscription for answer/teardown.
        let subscription_id = subscription_tag();
        let offer = subscriber_offer_sdp(subscriber_endpoint.local_addr, &codec);

        self.subscriptions
            .entry(call_id.to_string())
            .or_default()
            .push(Subscription {
                subscription_id: subscription_id.clone(),
                taps,
                subscriber_endpoint,
                srs_rtp: None,
            });

        CmdResult::Ok {
            sdp: Some(offer),
            duration_ms: None,
            to_tag: Some(subscription_id),
            stats: None,
        }
    }

    /// Promote a plain passthrough relay (the in-kernel `FlowAction::Forward` fast path) to a
    /// userspace **relay-only** [`MediaCall`], so a SIPREC raw tee has an actor to attach to. The
    /// in-kernel `Forward` path has no userspace tap; here we switch each RTP endpoint from `Forward`
    /// to `Redirect`, and run a lightweight raw relay that re-enforces the exact same source gate +
    /// symmetric latch the `Forward` rule did (RTPBleed defence — `Redirect` bypasses the datapath
    /// gate, docs/security-and-nat.md §4) and forwards each packet verbatim to the original peer, plus
    /// the raw tee. Reconstructs both relay directions from the call's stored `relay_flows`.
    async fn promote_passthrough(&self, call_id: &str) -> Result<(), String> {
        // Read the two RTP forward rules + leg identity out of the stored relay flows. `relay_flows`
        // for a passthrough call is [near.rtp, far.rtp, (near.rtcp, far.rtcp)] — we tee/relay only RTP.
        // Also carry each leg's negotiated telephone-event PT so a later `block DTMF` can gate it on
        // this promoted (still untranscoded) relay: leg A's ingress uses `near_telephone_event`, leg
        // B's uses `far_telephone_event`.
        let Some((from_tag, to_tag, relay_flows, near_telephone_event, far_telephone_event)) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.from_tag.clone(),
                    call.to_tag.clone(),
                    call.relay_flows.clone(),
                    call.near_telephone_event,
                    call.far_telephone_event,
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };

        // Reconstruct the per-direction wiring from the stored `Forward` rules (near then far).
        // `near_rule` is installed on near.rtp: it gates A's source and forwards toward far/out_dst (B).
        // Build the relay-only directions: A→B forwards out far's endpoint to B; B→A out near's to A.
        let layout = relay_layout_from_flows(&relay_flows)?;
        let a_to_b = RelayConfig {
            ingress_endpoint: layout.near_endpoint,
            accepted_source: layout.near_rule.accepted_source,
            egress_endpoint: layout.near_rule.out_endpoint,
            egress_dst: layout.b_dst,
            telephone_event: near_telephone_event, // leg A's ingress
        };
        let b_to_a = RelayConfig {
            ingress_endpoint: layout.far_endpoint,
            accepted_source: layout.far_rule.accepted_source,
            egress_endpoint: layout.far_rule.out_endpoint,
            egress_dst: layout.a_dst,
            telephone_event: far_telephone_event, // leg B's ingress
        };

        // Switch both RTP endpoints to Redirect so the dispatcher routes them to the media actor.
        for endpoint in [layout.near_endpoint, layout.far_endpoint] {
            self.datapath
                .install_flow(endpoint, FlowAction::Redirect)
                .map_err(|error| format!("install relay redirect: {error}"))?;
        }
        let call = MediaCall::new_relay(
            call_id.to_string(),
            from_tag,
            to_tag,
            a_to_b,
            b_to_a,
            layout.latch,
        );
        self.media.register(call, self.datapath.clone(), None);

        // Record the promotion on the Call so demotion can restore the in-kernel Forward rules.
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Media;
        }
        Ok(())
    }

    /// Promote a plain passthrough relay (the in-kernel `Forward` fast path) to a userspace
    /// **processing** [`MediaCall`] (decode → re-encode), so echo has a real reflect path: a relay-only
    /// promotion forwards opaque payloads to the peer and cannot loop a party's audio back to itself.
    /// Builds the two transcode directions from the call's negotiated codecs over the same endpoints /
    /// source gates / egress targets the stored `Forward` rules used — so the RTPBleed defence is
    /// unchanged (`Redirect` bypasses the datapath gate, so the directions re-enforce the exact same
    /// per-leg source filter, docs/security-and-nat.md §4). A passthrough relay always shares one codec
    /// across both legs (a codec *mismatch* answers as a transcode call, not a relay), so the near/far
    /// codecs are the same here; errors only if that codec has no encoder (e.g. AMR-WB without the
    /// `amr` build feature). The owner's event sink is wired so DTMF still surfaces (the SBC ends the
    /// echo test on `#`).
    async fn promote_to_processing(&self, call_id: &str) -> Result<(), String> {
        let Some((owner, from_tag, to_tag, relay_flows, near_codec, far_codec, near_te, far_te)) =
            self.owned_call_internal(call_id, |call| {
                (
                    call.owner,
                    call.from_tag.clone(),
                    call.to_tag.clone(),
                    call.relay_flows.clone(),
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.near_telephone_event,
                    call.far_telephone_event,
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };
        let (Some(near_codec), Some(far_codec)) = (near_codec, far_codec) else {
            return Err(
                "call has no negotiated codec to echo (offer/answer not complete)".to_string(),
            );
        };
        let layout = relay_layout_from_flows(&relay_flows)?;

        // Cross the codecs the way `answer`'s Media arm does: A→B decodes A's codec / encodes B's,
        // B→A decodes B's / encodes A's — so each party's echo (decode on its ingress, re-encode on the
        // reverse egress that faces it) round-trips in that party's own codec. `build_direction` gives
        // each egress a fresh random SSRC + real timestamp increment (RFC 3550 §5.1 / §8), so the
        // reflected stream is well-formed — which a relay-only direction's zeroed egress params are not.
        let a_to_b = build_direction(
            layout.near_endpoint,
            layout.near_rule.accepted_source,
            layout.near_rule.out_endpoint,
            layout.b_dst,
            &near_codec,
            &far_codec,
            near_te,
            far_te,
            None,
        )?;
        let b_to_a = build_direction(
            layout.far_endpoint,
            layout.far_rule.accepted_source,
            layout.far_rule.out_endpoint,
            layout.a_dst,
            &far_codec,
            &near_codec,
            far_te,
            near_te,
            None,
        )?;

        // Switch both RTP endpoints to Redirect so the dispatcher routes them to the media actor.
        for endpoint in [layout.near_endpoint, layout.far_endpoint] {
            self.datapath
                .install_flow(endpoint, FlowAction::Redirect)
                .map_err(|error| format!("install processing redirect: {error}"))?;
        }
        let owner_events = self.events.get(&owner).map(|sink| sink.value().clone());
        let call = MediaCall::new(
            call_id.to_string(),
            from_tag,
            to_tag,
            a_to_b,
            b_to_a,
            layout.latch,
            None,
        );
        self.media
            .register(call, self.datapath.clone(), owner_events);

        // Record the promotion on the Call so demotion can restore the in-kernel Forward rules.
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Media;
        }
        Ok(())
    }

    /// Demote a *promoted passthrough* relay back to the in-kernel `FlowAction::Forward` fast path once
    /// nothing holds it in userspace: deregister the [`MediaCall`] actor (relay-only or processing) and
    /// reinstall the stored `Forward` rules (the same ones promotion redirected away from). Best-effort
    /// — on any install error the call is left redirected (still relaying through the actor), which is
    /// correct if slower, and logged.
    async fn demote_to_passthrough(&self, call_id: &str) {
        let Some(relay_flows) = self.owned_call_internal(call_id, |call| call.relay_flows.clone())
        else {
            return;
        };
        // Tear down the relay-only actor (drops its routes), then restore the kernel Forward rules.
        self.media.deregister(call_id);
        for (endpoint, action) in &relay_flows {
            if let Err(error) = self.datapath.install_flow(*endpoint, *action) {
                tracing::warn!(%error, call_id, "demote: failed to reinstall Forward rule; leg stays redirected");
                return;
            }
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Passthrough;
        }
    }

    /// Ensure `call_id` runs in the userspace media pipeline so a per-packet feature (pcap recording,
    /// DTMF block, echo) can attach to it: promote a plain passthrough relay off the in-kernel `Forward`
    /// fast path if it is not already promoted, and record `reason` so the relay is not demoted while
    /// the feature is active. `mode` selects the promotion — [`PromoteMode::RelayOnly`] (verbatim
    /// forward, for recording / DTMF-block) or [`PromoteMode::Processing`] (decode → re-encode, for
    /// echo). A call set up as a transcoding/secure Media call already has an actor — no promotion
    /// happens, but the reason is still recorded (harmlessly; demotion is gated on the presence of
    /// stored `relay_flows`, so a genuine media call is never demoted). Ownership must already be
    /// validated.
    async fn hold_in_userspace(
        &self,
        call_id: &str,
        reason: PromotionReason,
        mode: PromoteMode,
    ) -> Result<(), String> {
        let pipeline = self
            .owned_call_internal(call_id, |call| call.pipeline)
            .ok_or_else(|| "call no longer exists".to_string())?;
        // Mirror `subscribe_request`'s guard: promote only a plain relay not already in the pipeline.
        // After promotion the call's pipeline is `Media`, so a second hold skips this and just records.
        if pipeline == PipelineKind::Passthrough && !self.media.is_media_call(call_id) {
            match mode {
                PromoteMode::RelayOnly => self.promote_passthrough(call_id).await?,
                PromoteMode::Processing => self.promote_to_processing(call_id).await?,
            }
        } else if mode == PromoteMode::Processing && self.media.is_relay_call(call_id) {
            // A relay-only promotion (recording / DTMF-block on a plain relay) is already up, but echo
            // needs a decode → re-encode path a relay-only actor cannot provide. Reject clearly rather
            // than silently apply an Echo control that would forward opaque payloads to the peer.
            return Err(
                "echo is unsupported while a plain relay is held in userspace for recording or a \
                 DTMF block; stop those first"
                    .to_string(),
            );
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.promotion_reasons.insert(reason);
        }
        Ok(())
    }

    /// Release a userspace hold taken by [`Self::hold_in_userspace`] and demote the relay back to the
    /// `Forward` fast path if nothing else holds it up. Safe on a genuine Media call: demotion is gated
    /// on the presence of stored `relay_flows`, so only a promoted passthrough relay is ever demoted.
    async fn release_userspace_hold(&self, call_id: &str, reason: PromotionReason) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.promotion_reasons.remove(&reason);
        }
        self.demote_if_idle(call_id).await;
    }

    /// Whether a promoted passthrough relay must stay in the userspace media pipeline — it has at
    /// least one active hold: a SIPREC subscription, a recording, or a DTMF block.
    fn call_has_userspace_hold(&self, call_id: &str) -> bool {
        let has_subscription = self
            .subscriptions
            .get(call_id)
            .is_some_and(|list| !list.is_empty());
        let has_reason = self
            .calls
            .get(call_id)
            .is_some_and(|call| !call.promotion_reasons.is_empty());
        has_subscription || has_reason
    }

    /// Demote a *promoted passthrough* relay back to the in-kernel `Forward` fast path once no reason
    /// (subscription, recording, DTMF block, echo) holds it in userspace any more. A promoted relay is
    /// identified by its stored `relay_flows` (non-empty only for a passthrough; empty for a genuine
    /// transcoding/secure `Media` call, which must never be demoted) — not by `is_relay_call`, because
    /// echo promotes to a **processing** (non-relay-only) actor that must still demote when it clears.
    async fn demote_if_idle(&self, call_id: &str) {
        if self.call_has_userspace_hold(call_id) {
            return;
        }
        let promoted_from_passthrough = self.media.is_media_call(call_id)
            && self
                .owned_call_internal(call_id, |call| !call.relay_flows.is_empty())
                .unwrap_or(false);
        if promoted_from_passthrough {
            self.demote_to_passthrough(call_id).await;
        }
    }

    /// Run `f` against a call by id without an ownership check (an internal helper for promotion /
    /// demotion, which already validated ownership via the public verb). Returns `None` if unknown.
    fn owned_call_internal<T>(&self, call_id: &str, f: impl FnOnce(&Call) -> T) -> Option<T> {
        self.calls.get(call_id).map(|call| f(&call))
    }

    /// SIPREC `subscribe_answer` (RFC 7866): the SRS's answer brings its RTP address. Parse it, then
    /// install a raw-RTP tee on each tapped source leg of the call's [`MediaCall`], copying the leg's
    /// original ingress RTP byte-for-byte out the subscriber endpoint toward the SRS. The subscriber is
    /// send-only — the engine installs no inbound flow on `subscriber_endpoint`, so no RTPBleed surface
    /// exists (docs/security-and-nat.md §4).
    async fn subscribe_answer(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: &str,
        sdp: &str,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return error_result("subscribe_answer: parse SRS SDP", &error);
            }
        };
        let srs_rtp = info.remote_rtp;

        // Locate the pending subscription named by `to_tag` and read its taps + subscriber endpoint.
        let (taps, subscriber_endpoint) = {
            let Some(subscriptions) = self.subscriptions.get(call_id) else {
                return error_result("subscribe_answer", &"no subscription for this call");
            };
            let Some(subscription) = subscriptions
                .iter()
                .find(|subscription| subscription.subscription_id == to_tag)
            else {
                return error_result(
                    "subscribe_answer",
                    &format!("unknown subscription {to_tag}"),
                );
            };
            if subscription.srs_rtp.is_some() {
                return error_result("subscribe_answer", &"subscription is already answered");
            }
            (subscription.taps.clone(), subscription.subscriber_endpoint)
        };

        // Install a raw tee on each tapped leg of the running media actor (no encoder — the leg's
        // original ingress RTP is copied byte-for-byte toward the SRS, RFC 7866 §6). If the actor is
        // gone (call torn down between the ownership check and here), free the endpoint and report it.
        let tee = RawTee {
            subscriber_endpoint: subscriber_endpoint.id,
            srs_dst: srs_rtp,
        };
        let mut attached = false;
        for source_a in &taps {
            if self.media.control(
                call_id,
                MediaControl::AddRawTee {
                    source_a: *source_a,
                    tee,
                },
            ) {
                attached = true;
            }
        }
        if !attached {
            self.datapath.remove_endpoint(subscriber_endpoint.id).await;
            return error_result("subscribe_answer", &"media call is no longer active");
        }

        // Record the now-active subscription (the SRS address) for unsubscribe / teardown.
        if let Some(mut subscriptions) = self.subscriptions.get_mut(call_id) {
            if let Some(subscription) = subscriptions
                .iter_mut()
                .find(|subscription| subscription.subscription_id == to_tag)
            {
                subscription.srs_rtp = Some(srs_rtp);
            }
        }
        ok_empty()
    }

    /// SIPREC `unsubscribe` (RFC 7866): detach the raw tee from every tapped leg of the media actor,
    /// free the subscriber endpoint, drop the subscription record, and — if this was the last
    /// subscription on a promoted passthrough relay — demote the call back to the in-kernel `Forward`
    /// fast path. Only the owning client may.
    async fn unsubscribe(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: &str,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // Remove the named subscription from the call's list.
        let removed = {
            let Some(mut subscriptions) = self.subscriptions.get_mut(call_id) else {
                return error_result("unsubscribe", &"no subscription for this call");
            };
            let Some(position) = subscriptions
                .iter()
                .position(|subscription| subscription.subscription_id == to_tag)
            else {
                return error_result("unsubscribe", &format!("unknown subscription {to_tag}"));
            };
            subscriptions.remove(position)
        };
        self.subscriptions
            .remove_if(call_id, |_, list| list.is_empty());
        self.detach_subscription(call_id, removed).await;
        // Once no subscription (or other hold — recording, DTMF block) remains on a relay we promoted,
        // demote it back to the in-kernel Forward fast path (the relay leg keeps flowing throughout).
        self.demote_if_idle(call_id).await;
        ok_empty()
    }

    /// Tear one subscription down: remove its raw tee from every tapped leg (if the actor is still
    /// alive) and free its subscriber endpoint. Shared by `unsubscribe` and call teardown. (No drain
    /// task to abort — the raw tee emits through the actor's own send path.)
    async fn detach_subscription(&self, call_id: &str, subscription: Subscription) {
        for source_a in &subscription.taps {
            self.media.control(
                call_id,
                MediaControl::RemoveRawTee {
                    source_a: *source_a,
                    subscriber_endpoint: subscription.subscriber_endpoint.id,
                },
            );
        }
        self.datapath
            .remove_endpoint(subscription.subscriber_endpoint.id)
            .await;
    }

    /// Free every subscription on a call (delete / reap / half-built teardown). Detaches each tee and
    /// frees its subscriber endpoint. (No demotion here — the whole call, including any promoted relay
    /// actor, is being torn down by the caller.)
    async fn drop_subscriptions(&self, call_id: &str) {
        if let Some((_, subscriptions)) = self.subscriptions.remove(call_id) {
            for subscription in subscriptions {
                self.detach_subscription(call_id, subscription).await;
            }
        }
    }

    /// Reap calls whose media has been idle (no accepted packet) for at least `idle_ticks`, freeing
    /// their ports/FDs and registry/quota slots, and return the reaped call ids. Deterministic: it
    /// reads the datapath's logical clock, so tests drive it via `advance_clock` rather than wall
    /// time (never `Instant::now()`). (docs/security-and-nat.md §4 layer 6.)
    pub async fn reap_idle(&self, idle_ticks: u64) -> Vec<String> {
        let now = self.datapath.now_ticks();
        // First pass (no `.await`, so holding the shard guards is fine): find the idle calls.
        let mut stale = Vec::new();
        for entry in self.calls.iter() {
            let call = entry.value();
            let mut last_activity = call.created_tick;
            for endpoint in call.near.endpoint_ids().chain(call.far.endpoint_ids()) {
                if let Some(seen) = self.datapath.last_activity(endpoint) {
                    last_activity = last_activity.max(seen);
                }
            }
            if now.saturating_sub(last_activity) >= idle_ticks {
                stale.push(entry.key().clone());
            }
        }
        // Second pass: tear each idle call down (no map guard held across the awaits).
        let mut reaped = Vec::new();
        for call_id in stale {
            if let Some((_, call)) = self.calls.remove(&call_id) {
                let endpoints: Vec<EndpointId> = call
                    .near
                    .endpoint_ids()
                    .chain(call.far.endpoint_ids())
                    .collect();
                self.drop_subscriptions(&call_id).await;
                self.bridge.deregister(endpoints.iter().copied());
                self.media.deregister(&call_id);
                self.ws.deregister(&call_id);
                for endpoint in endpoints {
                    self.datapath.remove_endpoint(endpoint).await;
                    self.endpoint_calls.remove(&endpoint);
                }
                self.release_client_call(call.owner);
                self.push_event(
                    call.owner,
                    Event::MediaTimeout {
                        call_id: call_id.clone(),
                        from_tag: call.from_tag,
                    },
                );
                reaped.push(call_id);
            }
        }
        reaped
    }

    /// Propagate each in-kernel-learned peer source into the sibling leg's forward destination — the
    /// engine half of the in-kernel symmetric-RTP loop (RFC 3550 §8, docs/security-and-nat.md §4 layer
    /// 3). A split userspace/kernel backend (XDP) forwards a `Forward` flow to the static `out_dst`
    /// from the negotiated SDP but *learns* the peer's real source in its own ingress latch; unlike the
    /// loopback backend (which owns both legs and resolves the sibling latch inline when forwarding),
    /// the per-flow kernel model cannot cross-reference siblings. So a NATed peer whose real source
    /// differs from the signalled address never drives the in-kernel fast path until userspace
    /// reprograms the sibling leg's rule (rtpengine's "userspace learns → reprograms the kernel rule"
    /// model). For every installed `Forward` flow: read the learned source of the endpoint the flow
    /// forwards **to** (its ingress latch is where this flow should now send); if the backend has
    /// learned one and it differs from the flow's current `out_dst`, reinstall the flow with
    /// `out_dst = learned` and write the updated action back into `relay_flows` (so `block`/`unblock`,
    /// which restore endpoints from `relay_flows`, keep the learned destination).
    ///
    /// RTPBleed-safe: only a source the kernel already validated (its own source-gate + SSRC re-latch)
    /// is ever exposed by [`Datapath::learned_source`], so this mirrors the kernel's validated latch —
    /// it never adopts an unvalidated source. An `install_flow` failure is logged and skipped, never
    /// fatal. A no-op on the loopback backend (its `learned_source` default is `None`; it resolves the
    /// latch inline when forwarding). Driven once per daemon sweep tick — NAT rebinds are rare. Purely
    /// synchronous work (`install_flow` is sync), so no map guard is ever held across an `.await`.
    pub async fn refresh_latched_destinations(&self) {
        for mut entry in self.calls.iter_mut() {
            let call = entry.value_mut();
            // Media/SRTP/transcode calls take the Redirect+userspace path (which latches in userspace
            // already), so their `relay_flows` is empty and they are naturally skipped.
            for (installed_on, action) in call.relay_flows.iter_mut() {
                // Only in-kernel `Forward` flows carry an `out_dst` to reprogram; skip Redirect/Drop.
                let FlowAction::Forward(rule) = *action else {
                    continue;
                };
                let installed_on = *installed_on;
                // The endpoint THIS flow forwards TO — its learned ingress source is where THIS flow
                // should send (the sibling's real post-NAT source, symmetric RTP RFC 3550 §8).
                let Some(learned) = self.datapath.learned_source(rule.out_endpoint) else {
                    continue;
                };
                if rule.out_dst == Some(learned) {
                    continue; // Already pointed at the learned source — idempotent, nothing to do.
                }
                let mut updated = rule;
                updated.out_dst = Some(learned);
                let updated_action = FlowAction::Forward(updated);
                if let Err(error) = self.datapath.install_flow(installed_on, updated_action) {
                    tracing::warn!(
                        endpoint = ?installed_on,
                        out_endpoint = ?updated.out_endpoint,
                        %learned,
                        %error,
                        "failed to reprogram sibling forward destination from kernel-learned latch"
                    );
                    continue;
                }
                *action = updated_action;
            }
        }
    }

    /// Reap conference participants whose media has been idle for at least `idle_ticks`, freeing their
    /// endpoints and tearing down any room left empty (the conference analogue of [`Engine::reap_idle`]
    /// — abandoned legs / a control client that disconnected without leaving never leak a room). Driven
    /// by the datapath's logical clock, so tests advance it via `advance_clock`.
    pub async fn reap_idle_conferences(&self, idle_ticks: u64) -> usize {
        let now = self.datapath.now_ticks();
        let freed = self.conference.reap_idle(now, idle_ticks, |endpoint| {
            self.datapath.last_activity(endpoint)
        });
        for endpoint in &freed {
            self.datapath.remove_endpoint(*endpoint).await;
            self.endpoint_calls.remove(endpoint);
        }
        freed.len()
    }

    /// The call-id owning `endpoint`, if any — RTCP-telemetry correlation.
    #[must_use]
    pub fn call_for_endpoint(&self, endpoint: EndpointId) -> Option<String> {
        self.endpoint_calls
            .get(&endpoint)
            .map(|entry| entry.value().clone())
    }

    /// Drain observed relayed RTCP and export it as HEP captures to `exporter` (a VoIPmonitor / Homer
    /// collector), correlated by call-id. Each observed datagram ships **twice**: once as the raw RTCP
    /// (`protocol_type` = RTCP) for a passive collector, and once — per reception report block it
    /// carries — as a QoS/MOS report (`protocol_type` = REPORT_JSON, HEP3 type 35) built from the
    /// block's loss/jitter through the G.107 E-model (RFC 3550 §6.4.1, ITU-T G.107). Runs until the
    /// datapath's observation stream closes; fire-and-forget — export errors are logged, never
    /// propagated, so telemetry never disturbs the media path.
    ///
    /// Note: `observe_rtcp` taps only the plain-relay (in-kernel `Forward`) path, where the engine
    /// originates no Sender Report of its own, so the QoS report carries no measured RTT (one-way delay
    /// 0). Transcode/conference legs measure RTT on their own path and surface it via `CallQuality`.
    pub async fn run_rtcp_export(self: Arc<Self>, exporter: HepExporter, capture_agent_id: u32) {
        let observations = self.datapath.observe_rtcp();
        while let Ok(observed) = observations.recv_async().await {
            let Some(call_id) = self.call_for_endpoint(observed.endpoint) else {
                continue;
            };
            let (timestamp_secs, timestamp_micros) = wall_clock_now();
            // Raw RTCP passthrough (unchanged) — a passive collector still gets the bytes verbatim.
            let raw = rtcp_capture(
                &observed,
                call_id.clone(),
                capture_agent_id,
                timestamp_secs,
                timestamp_micros,
            );
            if let Err(error) = exporter.export(&raw).await {
                tracing::debug!(%error, "HEP RTCP export failed");
            }
            // ...plus a QoS/MOS report per reception report block (HEP3 type 35).
            let (codec, clock_rate_hz) = self.qos_codec_for_endpoint(observed.endpoint);
            for report in qos_captures(
                &observed,
                &call_id,
                capture_agent_id,
                timestamp_secs,
                timestamp_micros,
                codec,
                clock_rate_hz,
            ) {
                if let Err(error) = exporter.export(&report).await {
                    tracing::debug!(%error, "HEP QoS export failed");
                }
            }
            // ...and the same per-block quality natively on the control channel (RFC 3550 §6.4.1 loss/
            // jitter + G.107 MOS), so SIPhon sees this 2-party plain-relay call's quality the way it
            // sees a conference participant's — the control-channel complement to the HEP QoS export.
            if let Some((owner, from_tag)) = self.owner_and_tag_for_endpoint(observed.endpoint) {
                for event in
                    qos_quality_events(&observed, &call_id, &from_tag, codec, clock_rate_hz)
                {
                    self.push_event(owner, event);
                }
            }
        }
    }

    /// The owner client and leg tag for a call-quality event derived from RTCP observed on `endpoint`:
    /// the client that created the call (the event's recipient) and the tag of the leg the RTCP
    /// traversed — the far (answerer) leg's `to_tag` for a far endpoint, else the near (offerer) leg's
    /// `from_tag`. `None` when the endpoint maps to no live call.
    fn owner_and_tag_for_endpoint(&self, endpoint: EndpointId) -> Option<(ClientId, String)> {
        use crate::ha::EndpointRole;
        let call_id = self.call_for_endpoint(endpoint)?;
        let call = self.calls.get(&call_id)?;
        let from_tag = match call.endpoint_role(endpoint) {
            Some(EndpointRole::FarRtp | EndpointRole::FarRtcp) => {
                call.to_tag.clone().unwrap_or_else(|| call.from_tag.clone())
            }
            _ => call.from_tag.clone(),
        };
        Some((call.owner, from_tag))
    }

    /// The G.107 codec and RTP clock rate for QoS reports on `endpoint` — the negotiated codec of the
    /// leg (near/far) the endpoint belongs to, via [`crate::conference::hep_codec_for_name`]. Falls
    /// back to G.711 at 8 kHz when the call or its codec is not (yet) known.
    fn qos_codec_for_endpoint(&self, endpoint: EndpointId) -> (siphon_rtp_hep::mos::Codec, u32) {
        use crate::ha::EndpointRole;
        let fallback = (siphon_rtp_hep::mos::Codec::G711, 8000);
        let Some(call_id) = self.call_for_endpoint(endpoint) else {
            return fallback;
        };
        let Some(call) = self.calls.get(&call_id) else {
            return fallback;
        };
        let codec = match call.endpoint_role(endpoint) {
            Some(EndpointRole::FarRtp | EndpointRole::FarRtcp) => call.far_codec.as_ref(),
            _ => call.near_codec.as_ref(),
        };
        match codec {
            Some(spec) => (
                crate::conference::hep_codec_for_name(&spec.encoding_name),
                spec.clock_rate_hz.max(1),
            ),
            None => fallback,
        }
    }
}

/// Invoke `handle` for each RFC 3550 §6.4.1 reception report block in an observed compound RTCP
/// datagram — across every Sender Report and Receiver Report it carries. A malformed / unparseable
/// datagram yields nothing (telemetry never disturbs the media path). The single parse both the HEP
/// QoS export ([`qos_captures`]) and the control-channel quality events ([`qos_quality_events`]) share.
fn for_each_reception_block(
    observed: &ObservedRtcp,
    mut handle: impl FnMut(&siphon_rtp_media::rtcp::ReportBlock),
) {
    use siphon_rtp_media::rtcp::RtcpPacket;
    let Ok(packets) = siphon_rtp_media::rtcp::parse_compound(&observed.payload) else {
        return;
    };
    for packet in &packets {
        let blocks = match packet {
            RtcpPacket::SenderReport(report) => report.reports.as_slice(),
            RtcpPacket::ReceiverReport(report) => report.reports.as_slice(),
            RtcpPacket::Other { .. } => continue,
        };
        for block in blocks {
            handle(block);
        }
    }
}

/// Build HEP QoS/MOS report captures (`protocol_type` = REPORT_JSON) from an observed RTCP datagram:
/// one per reception report block (RFC 3550 §6.4.1) in any Sender/Receiver Report it carries. Each
/// block's `fraction_lost` + `jitter` drive the G.107 E-model MOS (ITU-T G.107). `rtt` is 0 — the
/// passive relay path measures none (see [`Engine::run_rtcp_export`]).
fn qos_captures(
    observed: &ObservedRtcp,
    call_id: &str,
    capture_agent_id: u32,
    timestamp_secs: u32,
    timestamp_micros: u32,
    codec: siphon_rtp_hep::mos::Codec,
    clock_rate_hz: u32,
) -> Vec<Capture> {
    let mut captures = Vec::new();
    for_each_reception_block(observed, |block| {
        // No measured RTT on the passive relay path ⇒ one-way delay 0 (RFC 3550 §6.4.1).
        let impairments =
            Impairments::from_rtcp(block.fraction_lost, block.jitter, clock_rate_hz, 0.0);
        let report = QosReport::new(call_id, block.ssrc, codec, impairments);
        captures.push(Capture::from_qos_report(
            observed.source,
            observed.destination,
            timestamp_secs,
            timestamp_micros,
            capture_agent_id,
            &report,
        ));
    });
    captures
}

/// Build per-leg [`Event::CallQuality`] control-channel events from an observed RTCP datagram — one
/// per reception report block (RFC 3550 §6.4.1), from the **same** `fraction_lost` + `jitter` +
/// G.107 MOS the HEP QoS export derives ([`qos_captures`]), but delivered natively on the control
/// channel so SIPhon sees a 2-party plain-relay call's quality without parsing RTCP itself (the
/// counterpart to what conference / transcode legs emit). `from_tag` names the leg the RTCP traversed
/// (the reporting peer). `rtt` is 0 — the passive in-kernel relay originates no Sender Report, so it
/// measures no round-trip time (matching the HEP QoS report's one-way delay of 0).
fn qos_quality_events(
    observed: &ObservedRtcp,
    call_id: &str,
    from_tag: &str,
    codec: siphon_rtp_hep::mos::Codec,
    clock_rate_hz: u32,
) -> Vec<Event> {
    let mut events = Vec::new();
    for_each_reception_block(observed, |block| {
        let impairments =
            Impairments::from_rtcp(block.fraction_lost, block.jitter, clock_rate_hz, 0.0);
        events.push(Event::CallQuality {
            conference_id: None,
            call_id: Some(call_id.to_string()),
            from_tag: from_tag.to_string(),
            jitter_ms: impairments.jitter_ms,
            loss_percent: impairments.loss_percent,
            mos: siphon_rtp_hep::mos::estimate_mos(codec, impairments),
        });
    });
    events
}

/// Build a HEP RTCP capture from an observed relayed RTCP datagram (`protocol_type` = RTCP).
fn rtcp_capture(
    observed: &ObservedRtcp,
    call_id: String,
    capture_agent_id: u32,
    timestamp_secs: u32,
    timestamp_micros: u32,
) -> Capture {
    Capture {
        src: observed.source,
        dst: observed.destination,
        timestamp_secs,
        timestamp_micros,
        protocol_type: protocol_type::RTCP,
        capture_agent_id,
        correlation_id: Some(call_id),
        payload: observed.payload.to_vec(),
    }
}

/// Wall-clock seconds + microseconds since the Unix epoch, for HEP capture timestamps (a genuine
/// real-time capture stamp — distinct from the logical media-timeout clock).
fn wall_clock_now() -> (u32, u32) {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (elapsed.as_secs() as u32, elapsed.subsec_micros()),
        Err(_) => (0, 0),
    }
}

fn ok_sdp(sdp: String, to_tag: Option<String>) -> CmdResult {
    CmdResult::Ok {
        sdp: Some(sdp),
        duration_ms: None,
        to_tag,
        stats: None,
    }
}

/// A bare success (no SDP/stats) — the reply to control verbs like block/silence.
fn ok_empty() -> CmdResult {
    CmdResult::Ok {
        sdp: None,
        duration_ms: None,
        to_tag: None,
        stats: None,
    }
}

/// Parse rtpengine codec-manipulation flags into a [`sdp::CodecPolicy`] for the SDP offered to the
/// far side. The NG/JSON front-ends flatten the `codec` dictionary
/// (`docs/ng_control_protocol.md`) into `codec-<op>-<NAME>` flag strings, which map as:
/// - `codec-strip-X` — remove X from the offer.
/// - `codec-mask-X` / `codec-consume-X` — remove X from the offer but keep it usable near-side for
///   transcoding. This engine derives the near leg's codec from the offerer's *own* offer,
///   independent of the far-offer edit, so the near side keeps X regardless (and a masked near codec
///   engages the transcoder because the near/far primaries then differ — see [`sdp::CodecPolicy`]).
/// - `codec-transcode-X` — add X to the offer; the transcoder engages when the far side selects it.
/// - `codec-except-X` / `codec-accept-X` — a keep-list: X is never stripped (the exception to
///   `strip-all` / `mask-all`).
/// - `codec-offer-X` — a whitelist that sets the far offer's codec order (only the listed codecs, in
///   flag order; the first is preferred).
/// - the special value `all` / `full` on strip/mask removes every codec except the keep-list.
///
/// Unknown / not-yet-encodable `transcode` targets are skipped so a forced codec never fails the call
/// at answer. Names are matched case-insensitively (stored uppercased).
fn parse_codec_flags(flags: &[String]) -> sdp::CodecPolicy {
    let mut policy = sdp::CodecPolicy::default();
    for flag in flags {
        if let Some(name) = flag
            .strip_prefix("codec-strip-")
            .or_else(|| flag.strip_prefix("codec-mask-"))
            .or_else(|| flag.strip_prefix("codec-consume-"))
        {
            // The special value `all` / `full` sweeps every codec (bar the keep-list).
            if name.eq_ignore_ascii_case("all") || name.eq_ignore_ascii_case("full") {
                policy.remove_all = true;
            } else {
                policy.remove.push(name.to_ascii_uppercase());
            }
        } else if let Some(name) = flag
            .strip_prefix("codec-except-")
            .or_else(|| flag.strip_prefix("codec-accept-"))
        {
            policy.keep.push(name.to_ascii_uppercase());
        } else if let Some(name) = flag.strip_prefix("codec-offer-") {
            policy.order.push(name.to_ascii_uppercase());
        } else if let Some(name) = flag.strip_prefix("codec-transcode-") {
            if let Some(spec) = transcode_codec_spec(name) {
                policy.add.push(spec);
            }
        }
    }
    policy
}

/// Upper bound on a control-`ptime` override, in milliseconds. A sane telephony ceiling (the common
/// values are 10 / 20 / 30 / 40 ms); it also keeps the egress frame within the transcode scratch
/// buffer at every codec rate the engine encodes, so an absurd value can never overflow it.
const MAX_PTIME_OVERRIDE_MS: u8 = 40;

/// Parse rtpengine's `ptime=<N>` flag into an egress packetization override in milliseconds, clamped
/// to `1..=MAX_PTIME_OVERRIDE_MS`. `None` when the flag is absent or unparseable — the negotiated
/// (SDP `a=ptime`) packetization then stands. The first well-formed `ptime=` flag wins.
fn parse_ptime_override(flags: &[String]) -> Option<u8> {
    flags.iter().find_map(|flag| {
        flag.strip_prefix("ptime=")
            .and_then(|value| value.trim().parse::<u16>().ok())
            .filter(|&value| value >= 1)
            .map(|value| (value.min(u16::from(MAX_PTIME_OVERRIDE_MS))) as u8)
    })
}

/// Apply a `ptime` override to a codec: `Some(ms)` returns a clone repacketized to `ms`, `None`
/// leaves the negotiated ptime. Sample-based codecs (G.711/G.722/G.726/L16/CN) honour any ptime;
/// a frame-based codec (AMR) keeps its native 20 ms frame regardless (its encoder emits one fixed
/// frame), so the override is inert there — building the encoder from the returned spec is what
/// re-frames the codecs that honour it.
fn with_ptime_override(codec: &CodecSpec, override_ms: Option<u8>) -> CodecSpec {
    match override_ms {
        Some(ptime_ms) => {
            let mut overridden = codec.clone();
            overridden.ptime_ms = ptime_ms.max(1);
            overridden
        }
        None => codec.clone(),
    }
}

/// Map a `codec-transcode-<NAME>` target to a [`CodecSpec`] the engine can both advertise and
/// **encode** (so the forced transcode does not fail at answer). Static codecs use their RFC 3551
/// payload type; dynamic ones use a conventional number. `None` for an unknown or not-yet-encodable
/// codec (e.g. AMR-NB, whose encoder is WIP; or AMR-WB without the `amr` build feature) — skipped.
fn transcode_codec_spec(name: &str) -> Option<CodecSpec> {
    let upper = name.to_ascii_uppercase();
    let (payload_type, clock_rate_hz) = match upper.as_str() {
        "PCMU" => (0u8, 8000u32),
        "PCMA" => (8, 8000),
        "G722" => (9, 8000),
        "GSM" => (3, 8000),
        "G726-32" => (96, 8000),
        #[cfg(feature = "amr")]
        "AMR-WB" => (96, 16000),
        _ => return None,
    };
    Some(CodecSpec::new(payload_type, &upper, clock_rate_hz, 1, 20))
}

/// The far-leg engine endpoint address family requested by the rtpengine `address family` flag
/// (`IP4`/`IP6`), for IPv4↔IPv6 interworking. `None` when unset (the far leg follows the offer).
fn far_address_family(profile: &ProfileFlags) -> Option<AddressFamily> {
    match profile.address_family.as_deref()?.trim() {
        family if family.eq_ignore_ascii_case("IP6") => Some(AddressFamily::V6),
        family if family.eq_ignore_ascii_case("IP4") => Some(AddressFamily::V4),
        _ => None,
    }
}

/// The explicit ICE posture requested by the control `profile.ice` field (rtpengine `ICE=…`),
/// overriding the SDP-derived default (mirror the offer). `None` ⇒ no directive, mirror the offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IceDirective {
    /// `force` / `force-relay` — advertise engine ICE-lite regardless of whether the offer carried
    /// ICE (RFC 8445). `force-relay` (relay-only candidates) degrades to `force`: the engine has no
    /// TURN allocator, so only its host candidate is offered — documented in `docs/control/json.md`.
    Force,
    /// `remove` — strip the peer's ICE and advertise none (RFC 8839 §5).
    Remove,
}

/// Parse `profile.ice` (case/space-insensitive). An unknown token yields `None` (no override), so a
/// controller cannot silently disable ICE with a typo.
fn ice_directive(profile: &ProfileFlags) -> Option<IceDirective> {
    match profile.ice.as_deref()?.trim().to_ascii_lowercase().as_str() {
        "force" | "force-relay" => Some(IceDirective::Force),
        "remove" => Some(IceDirective::Remove),
        _ => None,
    }
}

/// The explicit DTLS-SRTP posture requested by the control `profile.dtls` field (rtpengine `DTLS=…`)
/// for a secure (`UDP/TLS/RTP/SAVP[F]`) far leg, overriding the hardcoded offerer role. `None` ⇒ no
/// directive (the RFC 5763 §5 default, `a=setup:actpass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtlsDirective {
    /// `off` — no DTLS-SRTP; the far leg is advertised plaintext `RTP/AVP` (RFC 3264) even when a
    /// UDP/TLS transport was requested.
    Off,
    /// `passive` / `active` / `actpass` — advertise DTLS with this `a=setup` role (RFC 4145 §4).
    Role(sdp::Setup),
}

/// Parse `profile.dtls` (case/space-insensitive). An unknown token yields `None` (keep the default
/// `actpass` offerer role).
fn dtls_directive(profile: &ProfileFlags) -> Option<DtlsDirective> {
    match profile
        .dtls
        .as_deref()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "off" => Some(DtlsDirective::Off),
        "passive" => Some(DtlsDirective::Role(sdp::Setup::Passive)),
        "active" => Some(DtlsDirective::Role(sdp::Setup::Active)),
        "actpass" => Some(DtlsDirective::Role(sdp::Setup::Actpass)),
        _ => None,
    }
}

/// Decide how a call's media is carried once answered: an SRTP bridge (secure far leg), the
/// userspace media slow path (transcode requested or recording on), or the in-datapath plain relay.
fn resolve_pipeline(
    near_codec: Option<&CodecSpec>,
    info: &sdp::MediaInfo,
    profile: &ProfileFlags,
    far_local_crypto: Option<CryptoAttribute>,
    far_dtls: bool,
) -> PipelineKind {
    // Transcode when the two legs' primary codecs differ in encoding or clock rate.
    let transcode = match (near_codec, info.primary_codec()) {
        (Some(near), Some(far)) => {
            !near.encoding_name.eq_ignore_ascii_case(&far.encoding_name)
                || near.clock_rate_hz != far.clock_rate_hz
        }
        _ => false,
    };
    if far_dtls {
        // DTLS-SRTP far leg → the userspace DTLS bridge (codec passthrough). Secure transcode over
        // DTLS (the DTLS analogue of `SrtpMedia`) is a follow-up, so a codec mismatch still bridges.
        return PipelineKind::Dtls;
    }
    if far_local_crypto.is_some() {
        // Secure far leg: the plain SRTP bridge when both legs share a codec (crypto only), or the
        // secure transcoding media slow path when they differ — decrypt → transcode → encrypt
        // (BGCF/SBC: a secure AMR-WB access leg ↔ a plaintext G.711 PSTN leg).
        return if transcode {
            PipelineKind::SrtpMedia
        } else {
            PipelineKind::Srtp
        };
    }
    if profile.record_call || transcode {
        PipelineKind::Media
    } else {
        PipelineKind::Passthrough
    }
}

/// The per-direction endpoints, source gates, egress targets and latch reconstructed from a promoted
/// passthrough relay's stored `Forward` rules (`Call::relay_flows`). Shared by the relay-only promote
/// ([`Engine::promote_passthrough`]) and the processing promote ([`Engine::promote_to_processing`]) so
/// both derive the datapath wiring from the exact same rules the in-kernel fast path installed.
struct PassthroughRelayLayout {
    /// The A-facing (near) RTP endpoint and its `Forward` rule (gates A's source, forwards toward B).
    near_endpoint: EndpointId,
    near_rule: ForwardRule,
    /// The B-facing (far) RTP endpoint and its `Forward` rule (gates B's source, forwards toward A).
    far_endpoint: EndpointId,
    far_rule: ForwardRule,
    /// Egress destination toward B (`near_rule.out_dst`) and toward A (`far_rule.out_dst`).
    b_dst: std::net::SocketAddr,
    a_dst: std::net::SocketAddr,
    /// Whether either side's rule latches (the passthrough default is SignalledOnly/Symmetric).
    latch: bool,
}

/// Reconstruct a promoted passthrough relay's [`PassthroughRelayLayout`] from its stored `relay_flows`
/// (the two installed RTP `Forward` rules — near then far, per `answer`'s passthrough arm; any
/// companion RTCP rules are ignored, RTCP is not transcoded/relayed on the promote path). Errors — never
/// panics — if the two RTP rules or their egress destinations are missing.
fn relay_layout_from_flows(
    relay_flows: &[(EndpointId, FlowAction)],
) -> Result<PassthroughRelayLayout, String> {
    let rtp_flows: Vec<(EndpointId, ForwardRule)> = relay_flows
        .iter()
        .filter_map(|(endpoint, action)| match action {
            FlowAction::Forward(rule) => Some((*endpoint, *rule)),
            _ => None,
        })
        .collect();
    let (Some((near_endpoint, near_rule)), Some((far_endpoint, far_rule))) =
        (rtp_flows.first().copied(), rtp_flows.get(1).copied())
    else {
        return Err("passthrough call has no installed RTP relay flows".to_string());
    };
    let Some(b_dst) = near_rule.out_dst else {
        return Err("passthrough relay has no destination toward B".to_string());
    };
    let Some(a_dst) = far_rule.out_dst else {
        return Err("passthrough relay has no destination toward A".to_string());
    };
    // Latch when either side's policy latches (the passthrough default is SignalledOnly/Symmetric).
    let latch = near_rule.latch != LatchPolicy::Off || far_rule.latch != LatchPolicy::Off;
    Ok(PassthroughRelayLayout {
        near_endpoint,
        near_rule,
        far_endpoint,
        far_rule,
        b_dst,
        a_dst,
        latch,
    })
}

/// Build one transcode direction's config: decode the ingress codec, encode the egress codec, and
/// (when recording) capture the decoded ingress audio. Fails if either codec is unimplemented.
#[allow(clippy::too_many_arguments)]
fn build_direction(
    ingress_endpoint: EndpointId,
    accepted_source: SourceFilter,
    egress_endpoint: EndpointId,
    egress_dst: std::net::SocketAddr,
    ingress_codec: &CodecSpec,
    egress_codec: &CodecSpec,
    telephone_event_in: Option<u8>,
    telephone_event_out: Option<u8>,
    record_path: Option<&str>,
) -> Result<DirectionConfig, String> {
    let decoder = factory::decoder_for(ingress_codec).map_err(|error| error.to_string())?;
    let encoder = factory::encoder_for(egress_codec).map_err(|error| error.to_string())?;
    // Record at the codec's *native* PCM rate (what the decoder emits), not the RTP clock — they
    // differ for G.722 (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2), and a clock-rate WAV header
    // would replay the recording at the wrong pitch.
    let recorder = record_path.map(|_| WavRecorder::new(decoder.params().sample_rate_hz, 1));
    Ok(DirectionConfig {
        ingress_endpoint,
        accepted_source,
        egress_endpoint,
        egress_dst,
        decoder,
        encoder,
        egress_ssrc: random_ssrc(),
        egress_payload_type: egress_codec.payload_type,
        telephone_event_in,
        telephone_event_out,
        recorder,
        // The G.107 codec class of the stream this direction decodes (the ingress codec), for the MOS
        // in its periodic quality report — mapped the same way as the HEP QoS / conference paths.
        ingress_mos_codec: crate::conference::hep_codec_for_name(&ingress_codec.encoding_name),
    })
}

/// Which party a play/DTMF verb targets: the leg named by `from_tag`. Matching the call's `to_tag`
/// (party B) plays toward B; otherwise toward A (the offerer) — the default.
fn resolve_toward_a(from_tag: &str, _call_from: &str, call_to: Option<&str>) -> bool {
    !matches!(call_to, Some(to_tag) if to_tag == from_tag)
}

/// A fresh SSRC for a synthesized (transcoded) egress stream, from the OS CSPRNG (RFC 3550 §8 wants
/// a random SSRC). Falls back to a fixed value if the CSPRNG is unavailable — never panics.
fn random_ssrc() -> u32 {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return 0x5310_0000; // "SIP0" — a stable fallback when the CSPRNG is unavailable
    }
    u32::from_be_bytes(bytes)
}

/// A fresh subscription identity, returned to the controller as the SIPREC UAS to-tag and used to
/// name the subscription on answer / unsubscribe. Random hex from the CSPRNG (a stable fallback when
/// it is unavailable — never panics), prefixed so it is recognisable in logs.
fn subscription_tag() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return "sub-00000000".to_string();
    }
    format!("sub-{}", hex_lower(&bytes))
}

/// Lowercase-hex encode a byte slice (no external dependency; used for the subscription tag).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build the SIPREC subscriber SDP **offer** (engine → SRS): a minimal send-only audio stream
/// advertising the engine's subscriber endpoint + the fork codec (RFC 4566 §5 line order
/// `v= o= s= c= t= m=`; RFC 3264 §5.1 `a=sendonly` — the engine only transmits to the SRS, which is
/// the RTPBleed-safe posture: no inbound media is accepted on this endpoint).
fn subscriber_offer_sdp(local_addr: std::net::SocketAddr, codec: &CodecSpec) -> String {
    let payload_type = codec.payload_type;
    let mut sdp = String::new();
    use std::fmt::Write as _;
    // RFC 4566 §5: mandatory lines in order. o= uses a fixed session id/version (one offer per
    // subscription); s=- is the standard "no name"; t=0 0 is an unbounded session.
    // RFC 4566 §5.7: the addrtype (`IP4`/`IP6`) follows the subscriber endpoint's own family, so a
    // v6 SIPREC tee is offered to the SRS as `c=IN IP6`.
    let addrtype = if local_addr.is_ipv6() { "IP6" } else { "IP4" };
    let _ = write!(
        sdp,
        "v=0\r\n\
         o=- 0 0 IN {addrtype} {ip}\r\n\
         s=siphon-rtp-siprec\r\n\
         c=IN {addrtype} {ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP {payload_type}\r\n\
         a=rtpmap:{payload_type} {name}/{clock}{channels}\r\n\
         a=sendonly\r\n",
        ip = local_addr.ip(),
        port = local_addr.port(),
        name = codec.encoding_name,
        clock = codec.clock_rate_hz,
        // RFC 4566 §6: the optional /channels suffix is emitted only for multi-channel codecs.
        channels = if codec.channels > 1 {
            format!("/{}", codec.channels)
        } else {
            String::new()
        },
    );
    sdp
}

/// Bounded depth of a recording's capture channel. At telephony rates (~50 packets/s per leg) this
/// buffers several seconds per leg before the actor drops packets under a stalled disk — a recording
/// is best-effort and must never backpressure the media path.
const PCAP_CAPTURE_QUEUE: usize = 1024;

/// Drain task for a runtime pcap recording: write the libpcap global header, then one framed record
/// per captured datagram, streaming to disk with async I/O (so the actor never blocks). Exits when
/// the actor drops its capture sink (`stop recording` / teardown closes the channel), then flushes
/// and closes the file.
async fn run_pcap_recorder(
    mut file: tokio::fs::File,
    receiver: flume::Receiver<CapturedPacket>,
    path: String,
) {
    use tokio::io::AsyncWriteExt;
    if let Err(error) = file.write_all(&pcap::global_header()).await {
        tracing::warn!(%error, path, "pcap recorder: failed to write header");
        return;
    }
    while let Ok(packet) = receiver.recv_async().await {
        if let Err(error) = file.write_all(&pcap::frame(&packet)).await {
            tracing::warn!(%error, path, "pcap recorder: write failed, stopping");
            break;
        }
    }
    if let Err(error) = file.flush().await {
        tracing::warn!(%error, path, "pcap recorder: final flush failed");
    } else {
        tracing::info!(path, "pcap recording finalized");
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Offer { .. } => "offer",
        Command::Answer { .. } => "answer",
        Command::Delete { .. } => "delete",
        Command::Query { .. } => "query",
        Command::Ping => "ping",
        Command::List => "list",
        Command::Statistics => "statistics",
        Command::Load => "load",
        Command::NodeInfo => "node_info",
        Command::Drain => "drain",
        Command::Undrain => "undrain",
        Command::Checkpoint { .. } => "checkpoint",
        Command::Restore { .. } => "restore",
        Command::PlayMedia { .. } => "play_media",
        Command::StopMedia { .. } => "stop_media",
        Command::PlayDtmf { .. } => "play_dtmf",
        Command::SilenceMedia { .. } => "silence_media",
        Command::UnsilenceMedia { .. } => "unsilence_media",
        Command::Echo { .. } => "echo",
        Command::BlockMedia { .. } => "block_media",
        Command::UnblockMedia { .. } => "unblock_media",
        Command::BlockDtmf { .. } => "block_dtmf",
        Command::UnblockDtmf { .. } => "unblock_dtmf",
        Command::StartRecording { .. } => "start_recording",
        Command::StopRecording { .. } => "stop_recording",
        Command::SubscribeRequest { .. } => "subscribe_request",
        Command::SubscribeAnswer { .. } => "subscribe_answer",
        Command::Unsubscribe { .. } => "unsubscribe",
        Command::ConferenceJoin { .. } => "conference_join",
        Command::ConferenceLeave { .. } => "conference_leave",
        Command::ConferenceRoute { .. } => "conference_route",
        Command::ConferenceBridge { .. } => "conference_bridge",
        Command::Authenticate { .. } => "authenticate",
    }
}

/// This engine's software version (the daemon crate version), advertised in `node_info`.
fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The codec payload names this build can relay or transcode, advertised in `node_info` so a
/// dispatcher only routes a call to a node that can serve its codec. The always-available set (pure
/// relay + the bit-exact pure-Rust codecs) plus the AMR family under the `amr` build feature — kept
/// in step with `factory::encoder_for`.
fn supported_codecs() -> Vec<String> {
    let base = [
        "PCMU",
        "PCMA",
        "G722",
        "G726",
        "GSM",
        "CN",
        "L16",
        "telephone-event",
    ];
    // The AMR family is compiled in only under the `amr` build feature (docs/codec-licensing.md).
    #[cfg(feature = "amr")]
    let extra: &[&str] = &["AMR-WB", "AMR"];
    #[cfg(not(feature = "amr"))]
    let extra: &[&str] = &[];
    base.iter()
        .chain(extra.iter())
        .map(|name| (*name).to_string())
        .collect()
}

/// The capability flags this build ships, advertised in `node_info`.
fn supported_features() -> Vec<String> {
    vec![
        "relay".to_string(),
        "transcode".to_string(),
        "srtp".to_string(),
        "conference".to_string(),
        "record".to_string(),
        "websocket".to_string(),
        "ng".to_string(),
        "hep".to_string(),
        "ice".to_string(),
        "turn".to_string(),
    ]
}

fn unknown_call(call_id: &str) -> CmdResult {
    CmdResult::Error {
        reason: format!("unknown call: {call_id}"),
    }
}

/// Map a control-plane [`ConferenceRole`] to the conference's internal [`Routing`]. A whisperer stays
/// a talker whose audio is private to one target; a monitor is a listener that hears one target
/// directly (and may also whisper to it).
fn routing_of(role: ConferenceRole) -> Routing {
    match role {
        ConferenceRole::Talker => Routing {
            role: Role::Talker,
            whisper_target: None,
            monitor_target: None,
        },
        ConferenceRole::Listener => Routing {
            role: Role::Listener,
            whisper_target: None,
            monitor_target: None,
        },
        ConferenceRole::Muted => Routing {
            role: Role::Muted,
            whisper_target: None,
            monitor_target: None,
        },
        ConferenceRole::Whisper { target } => Routing {
            role: Role::Talker,
            whisper_target: Some(target),
            monitor_target: None,
        },
        ConferenceRole::Monitor {
            target,
            whisper_target,
        } => Routing {
            role: Role::Listener,
            whisper_target,
            monitor_target: Some(target),
        },
    }
}

fn error_result(context: &str, error: &dyn std::fmt::Display) -> CmdResult {
    CmdResult::Error {
        reason: format!("{context}: {error}"),
    }
}

/// Resolve the rtpengine `rtcp-mux` directive list into the `(near_mux, far_mux)` decision for a
/// call (RFC 5761). `offered` is whether the offer's SDP carried `a=rtcp-mux` (the near side's
/// intent). The first recognised directive wins; an empty/unknown list mirrors the offer.
///
/// - `offer` / `require`: force mux on the generated (far) SDP → 1 far port. The near side follows
///   the offer (mux iff it was offered).
/// - `demux`: present separate RTCP to the far side (2 far ports, strip `a=rtcp-mux`) while the near
///   side stays as offered — the engine bridges a muxed access leg to a non-muxed core.
/// - `reject` / `remove`: no mux either side → 2 ports both sides, `a=rtcp-mux` stripped.
/// - `accept` (or no directive): mirror the offer on both sides (the default behaviour).
fn resolve_rtcp_mux(offered: bool, directives: &[String]) -> (bool, bool) {
    for directive in directives {
        match directive.as_str() {
            "offer" | "require" => return (offered, true),
            "demux" => return (offered, false),
            "reject" | "remove" => return (false, false),
            "accept" => return (offered, offered),
            _ => continue,
        }
    }
    (offered, offered)
}

/// Build the relay rule for one ingress endpoint: gate its incoming source to the SDP-signalled
/// peer and latch `SignalledOnly` by default, or accept-any + `Symmetric` when the `symmetric`
/// profile flag is set (or the peer address is not yet known). The RTPBleed-safe default —
/// see `docs/security-and-nat.md` §4.7.
fn ingress_rule(
    out_endpoint: EndpointId,
    out_dst: Option<std::net::SocketAddr>,
    expected_source: Option<std::net::SocketAddr>,
    profile: &ProfileFlags,
    ice: bool,
) -> ForwardRule {
    if ice {
        // ICE validates the source via STUN connectivity checks (the datapath responder adopts the
        // validated candidate), so accept any source and latch it.
        return ForwardRule::symmetric(out_endpoint, out_dst);
    }
    let symmetric = profile.flags.iter().any(|flag| flag == "symmetric");
    let Some(addr) = expected_source.filter(|_| !symmetric) else {
        // Symmetric leg, or the peer's address is not yet known: accept any source and latch.
        return ForwardRule::symmetric(out_endpoint, out_dst);
    };
    // Default: exact source-IP gate (the tightest RTPBleed defence). `subnet-source` loosens it to
    // the signalled IP's /24 (v4) or /64 (v6) for carriers that re-NAT or split RTP/RTCP within a
    // block (docs/security-and-nat.md §9).
    let accepted_source = if profile.flags.iter().any(|flag| flag == "subnet-source") {
        let prefix = if addr.is_ipv4() { 24 } else { 64 };
        SourceFilter::Subnet(addr.ip(), prefix)
    } else {
        SourceFilter::Exact(addr.ip())
    };
    ForwardRule {
        out_endpoint,
        out_dst,
        accepted_source,
        latch: LatchPolicy::SignalledOnly,
    }
}

/// Apply an rtpengine `received-from` source hint to a leg's SDP-signalled address: when `hint` is
/// set (the real post-NAT source IP the SIP proxy saw the request come from), return the signalled
/// **port** paired with the hint IP; otherwise the signalled address unchanged. Only the IP the
/// source gate keys on is overridden — never the port (the media port differs from the signalling
/// port), and never the gate *policy* (Exact/Subnet/Any is still chosen by `ingress_rule` /
/// `bridge_source_filter` from the profile flags). This tightens the NAT case: a UA whose `c=`
/// advertised a private (unusable) address is gated precisely to its NAT's public IP rather than
/// forced onto a symmetric/any gate (docs/security-and-nat.md §4 layer 2, RFC 3264).
fn apply_received_from(
    signalled: Option<std::net::SocketAddr>,
    hint: Option<std::net::IpAddr>,
) -> Option<std::net::SocketAddr> {
    match (signalled, hint) {
        (Some(addr), Some(ip)) => Some(std::net::SocketAddr::new(ip, addr.port())),
        (addr, _) => addr,
    }
}

/// The source-address gate for an SRTP-bridge leg, mirroring [`ingress_rule`]'s policy: an exact
/// source-IP gate by default (the tightest RTPBleed defence), the signalled /24 (v4) or /64 (v6)
/// under `subnet-source`, or any source under `symmetric`. The bridge enforces this itself because
/// the `Redirect` path bypasses the datapath's Forward-path source gate (docs/security-and-nat.md
/// §4 layer 2).
fn bridge_source_filter(profile: &ProfileFlags, addr: std::net::SocketAddr) -> SourceFilter {
    if profile.flags.iter().any(|flag| flag == "symmetric") {
        SourceFilter::Any
    } else if profile.flags.iter().any(|flag| flag == "subnet-source") {
        let prefix = if addr.is_ipv4() { 24 } else { 64 };
        SourceFilter::Subnet(addr.ip(), prefix)
    } else {
        SourceFilter::Exact(addr.ip())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    /// The default control client for tests that don't exercise per-client isolation.
    const CLIENT: ClientId = ClientId(1);

    async fn phone() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = socket.local_addr().expect("addr");
        (socket, addr)
    }

    #[test]
    fn qos_captures_emit_type35_reports_alongside_raw_rtcp() {
        // A compound Receiver Report (RFC 3550 §6.4.2) with one reception block: fraction_lost 13/256,
        // jitter 160 timestamp units. length = 7 words (32 bytes: 4 header + 4 reporter + 24 block).
        let mut rtcp = vec![0x81, 201, 0x00, 0x07];
        rtcp.extend_from_slice(&0xAAAA_0001u32.to_be_bytes()); // reporter ssrc
        rtcp.extend_from_slice(&0x1111_2222u32.to_be_bytes()); // reported-on ssrc
        rtcp.push(13); // fraction lost (13/256 ≈ 5.08 %)
        rtcp.extend_from_slice(&[0x00, 0x00, 0x02]); // cumulative lost
        rtcp.extend_from_slice(&0u32.to_be_bytes()); // extended highest seq
        rtcp.extend_from_slice(&160u32.to_be_bytes()); // jitter (160 @ 8 kHz = 20 ms)
        rtcp.extend_from_slice(&0u32.to_be_bytes()); // LSR
        rtcp.extend_from_slice(&0u32.to_be_bytes()); // DLSR

        let observed = ObservedRtcp {
            endpoint: EndpointId(1),
            source: "198.51.100.1:6000".parse().expect("src"),
            destination: "203.0.113.1:6002".parse().expect("dst"),
            payload: bytes::Bytes::from(rtcp.clone()),
        };

        // The raw RTCP passthrough is unchanged (protocol_type RTCP, bytes verbatim).
        let raw = rtcp_capture(&observed, "call-42@host".into(), 7, 100, 0);
        assert_eq!(raw.protocol_type, protocol_type::RTCP);
        assert_eq!(raw.payload, rtcp);

        // ...and one QoS/MOS report per reception block (protocol_type REPORT_JSON = HEP3 type 35).
        let captures = qos_captures(
            &observed,
            "call-42@host",
            7,
            100,
            0,
            siphon_rtp_hep::mos::Codec::G711,
            8000,
        );
        assert_eq!(captures.len(), 1, "one QoS report per reception block");
        let capture = &captures[0];
        assert_eq!(capture.protocol_type, protocol_type::REPORT_JSON);
        assert_eq!(capture.correlation_id.as_deref(), Some("call-42@host"));
        let json = std::str::from_utf8(&capture.payload).expect("utf8 payload");
        // Reported-on SSRC 0x1111_2222 = 286335522.
        assert!(json.contains(r#""ssrc":286335522"#), "{json}");
        assert!(json.contains(r#""codec":"G711""#), "{json}");
        assert!(
            json.contains(r#""loss_percent":5.08"#),
            "13/256 → 5.08 %: {json}"
        );
        assert!(
            json.contains(r#""jitter_ms":20.00"#),
            "160 @ 8 kHz → 20 ms: {json}"
        );
        assert!(json.contains(r#""mos":"#), "{json}");

        // ...and the SAME per-block loss/jitter/MOS natively on the control channel, keyed by
        // `call_id` (not `conference_id`), for the 2-party plain-relay call.
        let events = qos_quality_events(
            &observed,
            "call-42@host",
            "caller",
            siphon_rtp_hep::mos::Codec::G711,
            8000,
        );
        assert_eq!(events.len(), 1, "one quality event per reception block");
        match &events[0] {
            Event::CallQuality {
                conference_id,
                call_id,
                from_tag,
                jitter_ms,
                loss_percent,
                mos,
            } => {
                assert!(
                    conference_id.is_none(),
                    "a 2-party relay carries no conference_id"
                );
                assert_eq!(call_id.as_deref(), Some("call-42@host"));
                assert_eq!(from_tag, "caller");
                // 13/256 → 5.078125 %, 160 @ 8 kHz → 20 ms — the exact figures the HEP report carries.
                assert!(
                    (*loss_percent - (13.0 / 256.0 * 100.0)).abs() < 1e-9,
                    "13/256 → 5.08 %, got {loss_percent}"
                );
                assert!(
                    (*jitter_ms - 20.0).abs() < 1e-9,
                    "160 @ 8 kHz → 20 ms, got {jitter_ms}"
                );
                // The MOS is the G.107 estimate for that loss/jitter — a good-but-not-perfect call.
                assert!(*mos > 1.0 && *mos < 4.5, "plausible MOS, got {mos}");
            }
            other => panic!("expected CallQuality, got {other:?}"),
        }
    }

    #[test]
    fn qos_quality_events_ignores_rtcp_without_reception_blocks() {
        // A minimal RR with reception-count 0 (no blocks) yields no quality event — nothing to report.
        let rtcp = vec![0x80, 201, 0x00, 0x01, 0xAA, 0xAA, 0x00, 0x01];
        let observed = ObservedRtcp {
            endpoint: EndpointId(1),
            source: "198.51.100.1:6000".parse().expect("src"),
            destination: "203.0.113.1:6002".parse().expect("dst"),
            payload: bytes::Bytes::from(rtcp),
        };
        let events = qos_quality_events(
            &observed,
            "call-x",
            "caller",
            siphon_rtp_hep::mos::Codec::G711,
            8000,
        );
        assert!(events.is_empty(), "no reception block ⇒ no quality event");
    }

    /// A two-port SDP: RTP at `addr`, RTCP at `addr`+1 (default), optional `a=rtcp-mux`. The
    /// addrtype (RFC 4566 §5.7) follows `rtp`'s family, so this builds an `IN IP6` offer for a v6
    /// socket and `IN IP4` for a v4 one.
    fn sdp_for(rtp: SocketAddr, mux: bool) -> String {
        let mux_line = if mux { "a=rtcp-mux\r\n" } else { "" };
        let addrtype = if rtp.is_ipv6() { "IP6" } else { "IP4" };
        format!(
            "v=0\r\no=- 1 1 IN {addrtype} {ip}\r\ns=-\r\nc=IN {addrtype} {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n{mux_line}",
            ip = rtp.ip(),
            port = rtp.port()
        )
    }

    /// A test "phone" bound to IPv6 loopback (`::1`) — the v6 counterpart of [`phone`].
    async fn phone_v6() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind v6");
        let addr = socket.local_addr().expect("v6 addr");
        (socket, addr)
    }

    fn ok_sdp_text(result: &CmdResult) -> String {
        match result {
            CmdResult::Ok { sdp: Some(sdp), .. } => sdp.clone(),
            other => panic!("expected Ok with sdp, got {other:?}"),
        }
    }

    /// A [`Datapath`] test double: it wraps the real loopback backend (so offer/answer sets up genuine
    /// relay flows) but overrides [`Datapath::learned_source`] from an injected per-endpoint map — the
    /// split userspace/kernel behaviour the XDP backend has and that `refresh_latched_destinations`
    /// consumes. It also records every `install_flow` call so a test can assert exactly which flow the
    /// sweep reprogrammed.
    // The `learned` map and `installs` log are behind `Arc` so every clone (the engine holds one)
    // shares one view — a deep-cloned `DashMap` would hide a test's injected latch from the engine.
    #[derive(Clone)]
    struct LatchLearningDatapath {
        inner: UdpLoopbackDatapath,
        /// Injected per-endpoint learned sources — what `learned_source` returns (the kernel latch).
        learned: Arc<DashMap<EndpointId, SocketAddr>>,
        /// An ordered log of every `(endpoint, action)` installed, for assertions.
        installs: Arc<Mutex<Vec<(EndpointId, FlowAction)>>>,
    }

    impl LatchLearningDatapath {
        fn new() -> Self {
            Self {
                inner: UdpLoopbackDatapath::new(),
                learned: Arc::new(DashMap::new()),
                installs: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Record that `endpoint`'s in-kernel ingress latch has learned `source`.
        fn set_learned(&self, endpoint: EndpointId, source: SocketAddr) {
            self.learned.insert(endpoint, source);
        }

        /// Drain the captured install log, so a test measures only the installs since the last drain.
        fn take_installs(&self) -> Vec<(EndpointId, FlowAction)> {
            std::mem::take(&mut self.installs.lock().expect("install log lock"))
        }
    }

    impl Datapath for LatchLearningDatapath {
        fn alloc_endpoint(
            &self,
        ) -> impl std::future::Future<Output = Result<Endpoint, siphon_rtp_datapath::DatapathError>> + Send
        {
            self.inner.alloc_endpoint()
        }

        fn alloc_endpoint_for(
            &self,
            family: AddressFamily,
        ) -> impl std::future::Future<Output = Result<Endpoint, siphon_rtp_datapath::DatapathError>> + Send
        {
            self.inner.alloc_endpoint_for(family)
        }

        fn alloc_endpoint_on_port(
            &self,
            family: AddressFamily,
            port: u16,
        ) -> impl std::future::Future<Output = Result<Endpoint, siphon_rtp_datapath::DatapathError>> + Send
        {
            self.inner.alloc_endpoint_on_port(family, port)
        }

        fn install_flow(
            &self,
            endpoint: EndpointId,
            action: FlowAction,
        ) -> Result<(), siphon_rtp_datapath::DatapathError> {
            self.installs
                .lock()
                .expect("install log lock")
                .push((endpoint, action));
            self.inner.install_flow(endpoint, action)
        }

        fn remove_flow(&self, endpoint: EndpointId) {
            self.inner.remove_flow(endpoint);
        }

        fn remove_endpoint(
            &self,
            endpoint: EndpointId,
        ) -> impl std::future::Future<Output = ()> + Send {
            self.inner.remove_endpoint(endpoint)
        }

        fn send(
            &self,
            endpoint: EndpointId,
            dst: SocketAddr,
            data: &[u8],
        ) -> impl std::future::Future<Output = Result<usize, siphon_rtp_datapath::DatapathError>> + Send
        {
            self.inner.send(endpoint, dst, data)
        }

        fn stats(&self, endpoint: EndpointId) -> Option<siphon_rtp_datapath::EndpointStats> {
            self.inner.stats(endpoint)
        }

        fn now_ticks(&self) -> u64 {
            self.inner.now_ticks()
        }

        fn advance_clock(&self, ticks: u64) {
            self.inner.advance_clock(ticks);
        }

        fn now_micros(&self) -> u64 {
            self.inner.now_micros()
        }

        fn last_activity(&self, endpoint: EndpointId) -> Option<u64> {
            self.inner.last_activity(endpoint)
        }

        fn note_activity(&self, endpoint: EndpointId) {
            self.inner.note_activity(endpoint);
        }

        // The override under test: expose the injected kernel-learned source.
        fn learned_source(&self, endpoint: EndpointId) -> Option<SocketAddr> {
            self.learned.get(&endpoint).map(|entry| *entry.value())
        }

        fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>) {
            self.inner.set_ice(endpoint, config);
        }

        fn rx(&self) -> flume::Receiver<siphon_rtp_datapath::RxPacket> {
            self.inner.rx()
        }

        fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp> {
            self.inner.observe_rtcp()
        }
    }

    /// The `out_dst` of the `Forward` flow installed on `endpoint`, read out of the call's `relay_flows`.
    fn relay_out_dst<D: Datapath>(
        engine: &Engine<D>,
        call_id: &str,
        endpoint: EndpointId,
    ) -> Option<SocketAddr> {
        let call = engine.calls.get(call_id).expect("call present");
        call.relay_flows
            .iter()
            .find_map(|(installed, action)| match action {
                FlowAction::Forward(rule) if *installed == endpoint => Some(rule.out_dst),
                _ => None,
            })
            .flatten()
    }

    #[tokio::test]
    async fn refresh_latched_destinations_reprograms_the_sibling_out_dst_from_the_kernel_latch() {
        // A NATed peer whose real source differs from the signalled address: the kernel latches it on
        // the far leg's ingress, and the engine sweep must propagate that learned source into the
        // *near→far* flow's `out_dst` (docs/security-and-nat.md §4 layer 3, RFC 3550 §8).
        let datapath = LatchLearningDatapath::new();
        let engine = Engine::new(datapath.clone());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        // A plain PCMU relay (no profile flags) → Passthrough with in-kernel `Forward` flows.
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "nat-call".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "nat-call".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;

        let (near_rtp, far_rtp) = {
            let call = engine.calls.get("nat-call").expect("call present");
            (call.near.rtp.id, call.far.rtp.id)
        };
        // Before the sweep: near→far forwards to B's signalled address; far→near to A's.
        assert_eq!(
            relay_out_dst(&engine, "nat-call", near_rtp),
            Some(addr_b),
            "near→far initially forwards to B's signalled address"
        );
        let far_out_dst_before = relay_out_dst(&engine, "nat-call", far_rtp);

        // The kernel learned B's REAL post-NAT source on the far leg's ingress (a symmetric-NAT rebind),
        // differing from the signalled address. 203.0.113.0/24 is the RFC 5737 documentation range.
        let learned_b: SocketAddr = "203.0.113.7:40004".parse().expect("addr");
        assert_ne!(
            learned_b, addr_b,
            "the learned source must differ to exercise the propagation"
        );
        datapath.set_learned(far_rtp, learned_b);
        // The near leg has NOT learned anything: the far→near flow must stay untouched.

        let _ = datapath.take_installs(); // Drop the offer/answer installs; measure only the sweep.
        engine.refresh_latched_destinations().await;

        // (a) Exactly one flow was reinstalled — the near→far flow, now aimed at B's learned source.
        let installs = datapath.take_installs();
        assert_eq!(
            installs.len(),
            1,
            "only the near→far flow is reprogrammed, got {installs:?}"
        );
        let (reinstalled_on, reinstalled_action) = installs[0];
        assert_eq!(
            reinstalled_on, near_rtp,
            "reprogrammed the near endpoint (forwards toward B)"
        );
        match reinstalled_action {
            FlowAction::Forward(rule) => {
                assert_eq!(
                    rule.out_dst,
                    Some(learned_b),
                    "out_dst set to the kernel-learned source"
                );
                assert_eq!(rule.out_endpoint, far_rtp, "still the near→far direction");
            }
            other => panic!("expected a Forward action, got {other:?}"),
        }

        // (b) relay_flows now carries the updated action (so block/unblock restores the learned dst)...
        assert_eq!(
            relay_out_dst(&engine, "nat-call", near_rtp),
            Some(learned_b),
            "relay_flows holds the learned destination after the sweep"
        );
        // ...and the far→near flow (near never learned) is untouched.
        assert_eq!(
            relay_out_dst(&engine, "nat-call", far_rtp),
            far_out_dst_before,
            "far→near untouched: near never learned a source"
        );

        // Idempotence: a second sweep with the same learned source reinstalls nothing new.
        engine.refresh_latched_destinations().await;
        assert!(
            datapath.take_installs().is_empty(),
            "idempotent: no reinstall once out_dst already equals the learned source"
        );
    }

    #[tokio::test]
    async fn refresh_latched_destinations_is_a_noop_on_the_loopback_backend() {
        // The loopback backend's `learned_source` defaults to `None` (it resolves the latch inline when
        // forwarding, owning both legs), so the sweep reprograms nothing — relay_flows are unchanged.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "loop-call".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "loop-call".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;

        let before = engine
            .calls
            .get("loop-call")
            .expect("call present")
            .relay_flows
            .clone();
        assert!(!before.is_empty(), "a plain relay installs Forward flows");
        engine.refresh_latched_destinations().await;
        let after = engine
            .calls
            .get("loop-call")
            .expect("call present")
            .relay_flows
            .clone();
        assert_eq!(
            before, after,
            "loopback learned_source is None → the sweep reprograms nothing"
        );
    }

    #[tokio::test]
    async fn offer_codec_strip_removes_the_codec_from_the_offered_sdp() {
        // rtpengine `codec-strip-PCMA`: the SDP the engine offers the far side drops PCMA (static
        // PT 8, resolved via the RFC 3551 table — `sdp_for` carries no rtpmap for it).
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let profile = ProfileFlags {
            flags: vec!["codec-strip-PCMA".into()],
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "strip".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr, true),
                    profile,
                },
            )
            .await;
        let sdp = ok_sdp_text(&offer);
        let m_line = sdp
            .lines()
            .find(|l| l.starts_with("m=audio"))
            .expect("m=audio line");
        assert!(m_line.ends_with(" 0"), "only PCMU (PT 0) remains: {m_line}");
        assert!(!m_line.contains(" 8"), "PCMA (PT 8) stripped: {m_line}");
    }

    #[tokio::test]
    async fn offer_codec_transcode_adds_the_codec_to_the_offered_sdp() {
        // rtpengine `codec-transcode-G722`: the engine adds G722 (PT 9 + rtpmap) to the offered SDP.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let profile = ProfileFlags {
            flags: vec!["codec-transcode-G722".into()],
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "xcode".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr, true),
                    profile,
                },
            )
            .await;
        let sdp = ok_sdp_text(&offer);
        let m_line = sdp
            .lines()
            .find(|l| l.starts_with("m=audio"))
            .expect("m=audio line");
        assert!(m_line.ends_with(" 9"), "G722 (PT 9) appended: {m_line}");
        assert!(
            sdp.contains("a=rtpmap:9 G722/8000"),
            "G722 rtpmap added: {sdp}"
        );
    }

    #[tokio::test]
    async fn answer_ptime_override_advertises_the_re_framed_egress_ptime() {
        // A offers PCMU; B answers PCMA → the engine transcodes (Media pipeline). A `ptime=40` override
        // on the answer must surface as `a=ptime:40` in the answer SDP presented to A (the packetization
        // A will receive), never the far side's 20 ms — end-to-end from the control flag to the wire.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ptime-call".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        // B answers PCMA (PT 8) as its primary → codec mismatch → transcode, with a=ptime:20.
        let b_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=rtcp-mux\r\na=ptime:20\r\n",
            ip = addr_b.ip(),
            port = addr_b.port()
        );
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ptime-call".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: b_sdp,
                    profile: ProfileFlags {
                        flags: vec!["ptime=40".into()],
                        ..Default::default()
                    },
                },
            )
            .await;
        let sdp = ok_sdp_text(&answer);
        assert!(
            sdp.contains("a=ptime:40"),
            "answer to A advertises the 40 ms override: {sdp}"
        );
        assert!(
            !sdp.contains("a=ptime:20"),
            "B's 20 ms ptime is not leaked to A: {sdp}"
        );
        let parsed = sdp::parse(&sdp).expect("reparse");
        assert_eq!(
            parsed.ptime_ms, 40,
            "the answer reparses to the overridden ptime"
        );
        assert_eq!(
            parsed.primary_codec().expect("codec").encoding_name,
            "PCMU",
            "A is presented its own codec at the overridden ptime"
        );
    }

    #[test]
    fn parse_codec_flags_maps_rtpengine_operations() {
        // Each rtpengine codec op (docs/ng_control_protocol.md) resolves onto the CodecPolicy.
        let policy = parse_codec_flags(&[
            "codec-mask-PCMA".into(),
            "codec-except-PCMU".into(),
            "codec-accept-GSM".into(),
            "codec-offer-G722".into(),
            "codec-strip-all".into(),
            "codec-transcode-PCMA".into(),
        ]);
        assert!(policy.remove_all, "strip-all → remove_all");
        assert_eq!(
            policy.remove,
            vec!["PCMA".to_string()],
            "mask feeds the remove set"
        );
        assert!(
            policy.keep.contains(&"PCMU".to_string()),
            "except → keep-list"
        );
        assert!(
            policy.keep.contains(&"GSM".to_string()),
            "accept → keep-list"
        );
        assert_eq!(
            policy.order,
            vec!["G722".to_string()],
            "offer → far-offer order"
        );
        assert_eq!(policy.add.len(), 1, "transcode → one added codec");
        assert_eq!(policy.add[0].encoding_name, "PCMA");
        // Lowercase names are matched case-insensitively (stored uppercased).
        let lower = parse_codec_flags(&["codec-mask-pcma".into()]);
        assert_eq!(lower.remove, vec!["PCMA".to_string()]);
    }

    #[test]
    fn parse_ptime_override_reads_the_flag_and_clamps_it() {
        assert_eq!(parse_ptime_override(&["ptime=40".into()]), Some(40));
        assert_eq!(parse_ptime_override(&["ptime=10".into()]), Some(10));
        assert_eq!(parse_ptime_override(&[]), None, "absent → no override");
        assert_eq!(
            parse_ptime_override(&["symmetric".into(), "ptime=30".into()]),
            Some(30),
            "found among other flags"
        );
        assert_eq!(
            parse_ptime_override(&["ptime=500".into()]),
            Some(MAX_PTIME_OVERRIDE_MS),
            "an absurd ptime is clamped to the ceiling"
        );
        assert_eq!(
            parse_ptime_override(&["ptime=0".into()]),
            None,
            "0 ms rejected"
        );
        assert_eq!(
            parse_ptime_override(&["ptime=".into()]),
            None,
            "empty value rejected"
        );
        assert_eq!(
            parse_ptime_override(&["ptime=abc".into()]),
            None,
            "non-numeric rejected"
        );
    }

    #[test]
    fn with_ptime_override_reframes_only_when_present() {
        let g711 = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        assert_eq!(
            with_ptime_override(&g711, Some(40)).ptime_ms,
            40,
            "override applied"
        );
        assert_eq!(
            with_ptime_override(&g711, None).ptime_ms,
            20,
            "no override → negotiated ptime stands"
        );
        // Only ptime changes; the rest of the spec is untouched.
        let overridden = with_ptime_override(&g711, Some(30));
        assert_eq!(overridden.encoding_name, "PCMU");
        assert_eq!(overridden.clock_rate_hz, 8000);
        assert_eq!(overridden.payload_type, 0);
    }

    #[tokio::test]
    async fn offer_codec_mask_hides_the_codec_from_the_far_side() {
        // rtpengine `codec-mask-PCMA` (asymmetric hide): PCMA is dropped from the offer to B (same
        // far-offer edit as strip), while the near leg keeps it usable for transcoding.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let profile = ProfileFlags {
            flags: vec!["codec-mask-PCMA".into()],
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "mask".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr, true),
                    profile,
                },
            )
            .await;
        let sdp = ok_sdp_text(&offer);
        let m_line = sdp
            .lines()
            .find(|l| l.starts_with("m=audio"))
            .expect("m=audio line");
        assert!(
            m_line.ends_with(" 0"),
            "PCMA hidden from B, PCMU offered: {m_line}"
        );
        assert!(!m_line.contains(" 8"), "PCMA (PT 8) masked: {m_line}");
    }

    #[tokio::test]
    async fn offer_codec_offer_reorders_the_far_offer() {
        // rtpengine `codec-offer`: a whitelist that sets the offered order — PCMA before PCMU here.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let profile = ProfileFlags {
            flags: vec!["codec-offer-PCMA".into(), "codec-offer-PCMU".into()],
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "reorder".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr, true),
                    profile,
                },
            )
            .await;
        let sdp = ok_sdp_text(&offer);
        let m_line = sdp
            .lines()
            .find(|l| l.starts_with("m=audio"))
            .expect("m=audio line");
        assert!(
            m_line.ends_with("RTP/AVP 8 0"),
            "PCMA (8) offered before PCMU (0): {m_line}"
        );
    }

    #[tokio::test]
    async fn offer_replace_origin_rewrites_the_o_line_to_the_engine_address() {
        // rtpengine `replace: [origin]`: the o= unicast-address is rewritten to the engine's (topology
        // hiding). The offer's o= carries a distinct 10.0.0.7 so the loopback engine address differs.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let offer_sdp = format!(
            "v=0\r\no=alice 1 1 IN IP4 10.0.0.7\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
            ip = addr.ip(),
            port = addr.port()
        );
        let profile = ProfileFlags {
            replace: vec!["origin".into()],
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ro".into(),
                    from_tag: "a".into(),
                    sdp: offer_sdp,
                    profile,
                },
            )
            .await;
        let sdp = ok_sdp_text(&offer);
        let o_line = sdp.lines().find(|l| l.starts_with("o=")).expect("o= line");
        assert!(
            !o_line.contains("10.0.0.7"),
            "the caller's origin IP is hidden: {o_line}"
        );
        assert!(
            o_line.contains(&addr.ip().to_string()),
            "o= now carries the engine's advertised (loopback) address: {o_line}"
        );
    }

    #[test]
    fn far_address_family_parses_the_flag() {
        let with = |value: &str| ProfileFlags {
            address_family: Some(value.into()),
            ..Default::default()
        };
        assert_eq!(far_address_family(&with("IP6")), Some(AddressFamily::V6));
        assert_eq!(far_address_family(&with("ip4")), Some(AddressFamily::V4));
        assert_eq!(far_address_family(&with(" IP6 ")), Some(AddressFamily::V6));
        assert_eq!(
            far_address_family(&with("IP9")),
            None,
            "unknown family ignored"
        );
        assert_eq!(far_address_family(&ProfileFlags::default()), None);
    }

    #[tokio::test]
    async fn offer_address_family_ip4_puts_the_far_leg_on_ipv4_for_a_v6_offer() {
        // IPv4↔IPv6 interworking: a v6 (VoLTE) offer with `address family = IP4` (PSTN core) allocates
        // the far leg on IPv4, advertised to B as `c=IN IP4`, while the near leg stays v6.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let offer_sdp = "v=0\r\no=- 1 1 IN IP6 ::1\r\ns=-\r\nc=IN IP6 ::1\r\nt=0 0\r\n\
                         m=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n";
        let profile = ProfileFlags {
            address_family: Some("IP4".into()),
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "xfam".into(),
                    from_tag: "a".into(),
                    sdp: offer_sdp.into(),
                    profile,
                },
            )
            .await;
        let sdp = ok_sdp_text(&offer);
        let c_line = sdp
            .lines()
            .find(|l| l.starts_with("c="))
            .expect("c= line in the far-facing offer");
        assert!(
            c_line.contains("IN IP4 127.0.0.1"),
            "the far (PSTN) leg is advertised on IPv4: {c_line}"
        );
    }

    async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0u8; 2048];
        let (len, from) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv");
        (buffer[..len].to_vec(), from)
    }

    /// A `RTP/SAVP` answer SDP at `addr` carrying `crypto` (rtcp-mux, so it is a single port).
    fn savp_answer_sdp(addr: SocketAddr, crypto: &CryptoAttribute) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={crypto_line}\r\n",
            ip = addr.ip(),
            port = addr.port(),
            crypto_line = crypto.to_attribute_value(),
        )
    }

    /// A `RTP/SAVP` answer SDP advertising a single static codec (`payload_type`/`name`) at `addr`
    /// with `crypto` (rtcp-mux). A different codec than the plaintext near leg makes the call a secure
    /// *transcode* (`PipelineKind::SrtpMedia`), not a plain SRTP bridge.
    fn savp_answer_codec(
        addr: SocketAddr,
        payload_type: u8,
        name: &str,
        crypto: &CryptoAttribute,
    ) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP {pt}\r\na=rtpmap:{pt} {name}/8000\r\na=rtcp-mux\r\na={crypto_line}\r\n",
            ip = addr.ip(),
            port = addr.port(),
            pt = payload_type,
            crypto_line = crypto.to_attribute_value(),
        )
    }

    fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"amr-wb-frame----");
        packet
    }

    #[tokio::test]
    async fn ping_pongs() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        assert_eq!(engine.handle(CLIENT, Command::Ping).await, CmdResult::Pong);
    }

    #[tokio::test]
    async fn load_reports_configured_capacity_and_gauges() {
        let cluster = std::sync::Arc::new(crate::cluster::ClusterState::new(
            "rtp-test-1".to_string(),
            4000,
            vec!["203.0.113.10".to_string()],
        ));
        let engine = Engine::new(UdpLoopbackDatapath::new()).with_cluster(cluster);
        let CmdResult::Load { load } = engine.handle(CLIENT, Command::Load).await else {
            panic!("expected load result");
        };
        assert_eq!(load.node_id, "rtp-test-1");
        assert_eq!(load.max_sessions, 4000);
        assert_eq!(load.sessions, 0, "no live calls yet");
        assert_eq!(load.load_permille, 0, "empty node is 0 load");
        assert_eq!(load.transcode_sessions, 0);
        assert!(!load.draining);
    }

    #[tokio::test]
    async fn node_info_reports_identity_and_capabilities() {
        let cluster = std::sync::Arc::new(crate::cluster::ClusterState::new(
            "rtp-test-2".to_string(),
            1000,
            vec!["203.0.113.11".to_string()],
        ));
        let engine = Engine::new(UdpLoopbackDatapath::new()).with_cluster(cluster);
        let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
            panic!("expected node_info result");
        };
        assert_eq!(node.node_id, "rtp-test-2");
        assert_eq!(node.max_sessions, 1000);
        assert_eq!(node.media_addresses, vec!["203.0.113.11".to_string()]);
        assert!(
            node.codecs.iter().any(|codec| codec == "PCMU"),
            "advertises G.711"
        );
        assert!(node.features.iter().any(|feature| feature == "relay"));
        assert_eq!(node.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn drain_refuses_new_offers_but_keeps_serving_control() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let offer = || Command::Offer {
            call_id: "drain-call".to_string(),
            from_tag: "ft".to_string(),
            sdp: sdp_for(addr, true),
            profile: ProfileFlags::default(),
        };

        // Enter drain mode: a new offer is refused with a "draining" reason...
        assert_eq!(engine.handle(CLIENT, Command::Drain).await, ok_empty());
        match engine.handle(CLIENT, offer()).await {
            CmdResult::Error { reason } => assert!(reason.contains("draining"), "{reason}"),
            other => panic!("expected drain rejection, got {other:?}"),
        }
        // ...but liveness and the cluster/census verbs still answer, and `load` shows draining.
        assert_eq!(engine.handle(CLIENT, Command::Ping).await, CmdResult::Pong);
        let CmdResult::Load { load } = engine.handle(CLIENT, Command::Load).await else {
            panic!("load");
        };
        assert!(load.draining, "load snapshot reflects drain state");

        // Undrain re-opens admission: the same offer now succeeds.
        assert_eq!(engine.handle(CLIENT, Command::Undrain).await, ok_empty());
        assert!(
            matches!(engine.handle(CLIENT, offer()).await, CmdResult::Ok { .. }),
            "offer admitted again after undrain"
        );
    }

    #[tokio::test]
    async fn checkpoint_captures_a_plain_relay_snapshot() {
        use crate::ha::{CallSnapshot, EndpointRole, PipelineSnapshot};

        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        // A plain PCMU relay: offer + answer, no profile flags → Passthrough.
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ckpt-call".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let far_local = sdp::parse(&ok_sdp_text(&offer))
            .expect("offer reply")
            .remote_rtp;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ckpt-call".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;

        // Checkpoint returns an opaque blob that deserializes to the negotiated state.
        let CmdResult::Checkpoint { snapshot } = engine
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: "ckpt-call".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await
        else {
            panic!("expected a checkpoint result");
        };
        let snapshot = CallSnapshot::from_json(&snapshot).expect("valid snapshot blob");
        assert_eq!(snapshot.call_id, "ckpt-call");
        assert_eq!(snapshot.from_tag, "tag-a");
        assert_eq!(snapshot.to_tag.as_deref(), Some("tag-b"));
        assert_eq!(snapshot.pipeline, PipelineSnapshot::Passthrough);
        // rtcp-mux ⇒ no companion RTCP endpoint; the far leg advertises the engine port A dials.
        assert!(
            snapshot.near.rtcp_local.is_none(),
            "rtcp-mux: no near RTCP port"
        );
        assert_eq!(
            snapshot.far.rtp_local, far_local,
            "far leg local port is captured"
        );
        assert_eq!(
            snapshot.near.remote_rtp,
            Some(addr_a),
            "A's address captured"
        );
        assert_eq!(
            snapshot.far.remote_rtp,
            Some(addr_b),
            "B's address captured"
        );
        // A plain relay installs Forward rules on both RTP endpoints (mux ⇒ two, not four).
        assert!(
            snapshot
                .flows
                .iter()
                .any(|flow| flow.installed_on == EndpointRole::NearRtp
                    && flow.out == EndpointRole::FarRtp),
            "near→far forward rule captured"
        );
        assert!(
            snapshot.secure.is_none(),
            "a plain relay has no secure state"
        );
    }

    #[tokio::test]
    async fn checkpoint_is_ownership_gated() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "owned".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        // A different client cannot checkpoint (nor even learn the call exists) — A3, docs §5.
        let other = ClientId(999);
        assert!(matches!(
            engine
                .handle(
                    other,
                    Command::Checkpoint {
                        call_id: "owned".into(),
                        from_tag: "tag-a".into(),
                    },
                )
                .await,
            CmdResult::Error { .. }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_resumes_a_plain_relay_on_a_standby_at_the_same_ports() {
        // Warm-standby HA end to end: a plain relay is set up on "node A", checkpointed, torn down
        // (A dies, freeing its ports), then restored on a fresh "node B" that re-binds the *same*
        // media ports (as a floating-IP standby would) — and media relays through B with no
        // re-negotiation. Both nodes use the same deterministic port range on loopback.
        let (min, max) = (46_000u16, 46_040u16);
        let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // A plain PCMU relay (offer + answer, rtcp-mux, no profile) on node A.
        let offer = engine_a
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ha-relay".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        // The engine address B will send to (advertised in the offer sent onward to B).
        let engine_far = sdp::parse(&ok_sdp_text(&offer)).expect("offer").remote_rtp;
        let answer = engine_a
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ha-relay".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        // The engine address A sends to (advertised back to A in the answer).
        let engine_near = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer")
            .remote_rtp;

        // Checkpoint the live call, then delete it on A and drop A — freeing the media ports.
        let CmdResult::Checkpoint { snapshot } = engine_a
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: "ha-relay".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await
        else {
            panic!("expected a checkpoint result");
        };
        engine_a
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "ha-relay".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        drop(engine_a);

        // Node B (same port range + bind IP) restores from the blob, re-binding the same ports.
        let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        assert!(
            matches!(
                engine_b.handle(CLIENT, Command::Restore { snapshot }).await,
                CmdResult::Ok { .. }
            ),
            "restore succeeds on the standby"
        );

        // Media now relays through B at the unchanged engine ports — no re-INVITE needed.
        // A → engine_near → B receives at addr_b.
        let a_to_b = g711_rtp(0, 1, 0x0A0A_0A0A, 0xA1);
        phone_a.send_to(&a_to_b, engine_near).await.expect("a send");
        let (got_b, _) = recv(&phone_b).await;
        assert_eq!(got_b, a_to_b, "A→B relays through the restored node");

        // B → engine_far → A receives at addr_a.
        let b_to_a = g711_rtp(0, 2, 0x0B0B_0B0B, 0xB2);
        phone_b.send_to(&b_to_a, engine_far).await.expect("b send");
        let (got_a, _) = recv(&phone_a).await;
        assert_eq!(got_a, b_to_a, "B→A relays through the restored node");
    }

    #[tokio::test]
    async fn restore_rejects_a_stale_or_duplicate_call() {
        // A blob for a call that is already live is refused (no clobbering a live call).
        let engine = Engine::new(UdpLoopbackDatapath::with_port_range(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            47_000,
            47_020,
        ));
        let (_phone_a, addr_a) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "dup".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "dup".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let CmdResult::Checkpoint { snapshot } = engine
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: "dup".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await
        else {
            panic!("checkpoint");
        };
        // The call is still live → restoring the same id is rejected.
        assert!(matches!(
            engine.handle(CLIENT, Command::Restore { snapshot }).await,
            CmdResult::Error { .. }
        ));
        // A malformed blob is a clean error, never a panic.
        assert!(matches!(
            engine
                .handle(
                    CLIENT,
                    Command::Restore {
                        snapshot: "{not valid".into(),
                    },
                )
                .await,
            CmdResult::Error { .. }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_resumes_a_secure_srtp_bridge_on_a_standby() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use siphon_rtp_srtp::SrtpContext;

        // Secure warm-standby HA: an AVP↔SAVP bridge is set up on node A, checkpointed (capturing the
        // peer's key + the leg rollover + the bridge flows), torn down, then restored on node B which
        // re-binds the same ports and rebuilds the SRTP bridge — and secure media flows through B.
        let (min, max) = (48_000u16, 48_060u16);
        let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        tokio::spawn(run_redirect_dispatcher(
            engine_a.datapath().rx(),
            engine_a.bridge(),
            engine_a.media(),
            engine_a.ws(),
            engine_a.conference(),
            None,
        ));
        let (phone_a, addr_a) = phone().await; // plain (AVP) caller A
        let (phone_b, addr_b) = phone().await; // secure (SAVP) callee B

        // A offers plaintext; the profile asks for a secure far leg. B answers RTP/SAVP with its key.
        let offer = engine_a
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ha-savp".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags {
                        transport_protocol: Some("RTP/SAVP".into()),
                        ..Default::default()
                    },
                },
            )
            .await;
        let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
        let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
        let engine_far = offer_reply.remote_rtp; // engine's B-facing port
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let answer = engine_a
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ha-savp".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: savp_answer_sdp(addr_b, &b_key),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let engine_near = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;

        // Sanity: the bridge relays on A (A plaintext → B SRTP, decryptable with the engine's key).
        let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
        let from_a = rtp_packet(100, 0x0A0A_0A0A);
        phone_a.send_to(&from_a, engine_near).await.expect("a send");
        let (srtp, _) = recv(&phone_b).await;
        let mut recovered = Vec::new();
        b_decrypt
            .unprotect(&srtp, &mut recovered)
            .expect("B decrypts on A");
        assert_eq!(recovered, from_a);

        // Checkpoint the secure call → the blob carries the secure section (peer key + bridge flows).
        let CmdResult::Checkpoint { snapshot } = engine_a
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: "ha-savp".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await
        else {
            panic!("expected a checkpoint result");
        };
        let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("parse blob");
        let secure = parsed
            .secure
            .expect("the snapshot carries the secure section");
        assert_eq!(secure.far_remote_crypto.suite, "AES_CM_128_HMAC_SHA1_80");
        assert!(
            !secure.bridge_flows.is_empty(),
            "bridge flow plans captured"
        );

        // Node A dies: delete frees its ports.
        engine_a
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "ha-savp".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        drop(engine_a);

        // Node B (same range) restores the secure call and rebuilds the SRTP bridge at the same ports.
        let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        tokio::spawn(run_redirect_dispatcher(
            engine_b.datapath().rx(),
            engine_b.bridge(),
            engine_b.media(),
            engine_b.ws(),
            engine_b.conference(),
            None,
        ));
        assert!(
            matches!(
                engine_b.handle(CLIENT, Command::Restore { snapshot }).await,
                CmdResult::Ok { .. }
            ),
            "secure restore succeeds on the standby"
        );

        // Secure media resumes through B at the unchanged ports.
        // A → engine_near → B receives SRTP (still decryptable with the engine's original key).
        let from_a2 = rtp_packet(101, 0x0A0A_0A0A);
        phone_a
            .send_to(&from_a2, engine_near)
            .await
            .expect("a send 2");
        let (srtp2, _) = recv(&phone_b).await;
        let mut recovered2 = Vec::new();
        b_decrypt
            .unprotect(&srtp2, &mut recovered2)
            .expect("B decrypts through the restored bridge");
        assert_eq!(
            recovered2, from_a2,
            "A→B secure relay resumes on the standby"
        );

        // B → engine_far as SRTP (B's key) → bridge decrypts → A receives plaintext.
        let from_b = rtp_packet(200, 0x0B0B_0B0B);
        let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
        let mut srtp_b = Vec::new();
        b_encrypt.protect(&from_b, &mut srtp_b).expect("B encrypts");
        phone_b.send_to(&srtp_b, engine_far).await.expect("b send");
        let (recovered_a, _) = recv(&phone_a).await;
        assert_eq!(
            recovered_a, from_b,
            "B→A secure relay resumes on the standby"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_resumes_a_transcode_call_on_a_standby() {
        use crate::srtp_bridge::run_redirect_dispatcher;

        // Transcode warm-standby HA: a PCMU↔PCMA transcoding call is set up on node A, checkpointed,
        // torn down, then restored on node B which re-binds the same ports and rebuilds the
        // transcoding actor — and media transcodes through B (fresh actor state, same ports).
        let (min, max) = (49_000u16, 49_040u16);
        let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        tokio::spawn(run_redirect_dispatcher(
            engine_a.datapath().rx(),
            engine_a.bridge(),
            engine_a.media(),
            engine_a.ws(),
            engine_a.conference(),
            None,
        ));
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // A offers PCMU; B answers PCMA → near=PCMU, far=PCMA → the transcoding media slow path.
        let offer = engine_a
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ha-xcode".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let engine_far = sdp::parse(&ok_sdp_text(&offer))
            .expect("offer reply")
            .remote_rtp;
        let answer = engine_a
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ha-xcode".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                    profile: Default::default(),
                },
            )
            .await;
        let engine_near = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;
        assert!(
            engine_a.media().is_media_call("ha-xcode"),
            "resolves to a transcode call"
        );

        // Checkpoint carries both codecs; then A dies (delete frees ports).
        let CmdResult::Checkpoint { snapshot } = engine_a
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: "ha-xcode".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await
        else {
            panic!("checkpoint");
        };
        let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("parse blob");
        assert_eq!(parsed.near_codec.expect("near codec").encoding_name, "PCMU");
        assert_eq!(parsed.far_codec.expect("far codec").encoding_name, "PCMA");
        engine_a
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "ha-xcode".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        drop(engine_a);

        // Node B restores the transcode call and rebuilds the actor at the same ports.
        let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        tokio::spawn(run_redirect_dispatcher(
            engine_b.datapath().rx(),
            engine_b.bridge(),
            engine_b.media(),
            engine_b.ws(),
            engine_b.conference(),
            None,
        ));
        assert!(
            matches!(
                engine_b.handle(CLIENT, Command::Restore { snapshot }).await,
                CmdResult::Ok { .. }
            ),
            "transcode restore succeeds on the standby"
        );
        assert!(
            engine_b.media().is_media_call("ha-xcode"),
            "the transcoding actor is rebuilt on the standby"
        );

        // A → engine_near → transcode → B receives A-law (PT 8), not the original µ-law.
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, engine_near).await.expect("a send");
        let (transcoded, _) = recv(&phone_b).await;
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&transcoded).expect("parse");
        assert_eq!(
            parsed.payload_type, 8,
            "B receives A-law (PT 8) through the restored actor"
        );

        // B → engine_far → transcode → A receives µ-law (PT 0).
        let from_b = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
        phone_b.send_to(&from_b, engine_far).await.expect("b send");
        let (back, _) = recv(&phone_a).await;
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&back).expect("parse");
        assert_eq!(
            parsed.payload_type, 0,
            "A receives µ-law (PT 0) through the restored actor"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_resumes_a_secure_transcode_call_on_a_standby() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use siphon_rtp_srtp::{SrtpContext, StreamRollover};

        // Secure-transcode warm-standby HA (`PipelineKind::SrtpMedia`, BGCF/SBC PSTN breakout): a
        // plaintext G.711 µ-law near leg (A) ↔ a secure RTP/SAVP G.711 A-law far leg (B). The engine
        // decrypts B's SRTP, transcodes, and encrypts toward B (and the reverse) in one actor. We set
        // it up on node A, drive a secure packet so the inbound SRTP rollover records B's SSRC,
        // checkpoint (capturing the peer's key + the actor's live rollover, from the media actor — not
        // the SRTP bridge), tear node A down, then restore on node B which re-binds the same ports,
        // rebuilds the transcode actor AND the shared SecureLeg (re-keyed + rollover re-seeded), and
        // proves media transcodes+crypts through B both ways with the SRTP rollover *continued* (no
        // ROC reset → no two-time-pad, RFC 3711 §3.3.1).
        let (min, max) = (49_100u16, 49_160u16);
        let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let b_ssrc = 0x0B0B_0B0Bu32;

        let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        tokio::spawn(run_redirect_dispatcher(
            engine_a.datapath().rx(),
            engine_a.bridge(),
            engine_a.media(),
            engine_a.ws(),
            engine_a.conference(),
            None,
        ));
        let (phone_a, addr_a) = phone().await; // plain G.711 µ-law (PSTN) A
        let (phone_b, addr_b) = phone().await; // secure G.711 A-law (SAVP) B

        // A offers plaintext PCMU; the profile secures the far leg. B answers RTP/SAVP PCMA with its
        // key → near = PCMU (8 kHz), far = PCMA (8 kHz), secure ⇒ the secure-transcode media path.
        let offer = engine_a
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ha-savp-xcode".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags {
                        transport_protocol: Some("RTP/SAVP".into()),
                        ..Default::default()
                    },
                },
            )
            .await;
        let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
        let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
        let engine_far = offer_reply.remote_rtp; // engine's B-facing port
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let answer = engine_a
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ha-savp-xcode".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: savp_answer_codec(addr_b, 8, "PCMA", &b_key),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let engine_near = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;
        assert!(
            engine_a.media().is_media_call("ha-savp-xcode"),
            "secure + transcode resolves to the media slow path"
        );

        // A → engine(near): plaintext PCMU → transcode PCMU→PCMA → encrypt → B gets SRTP it decrypts.
        let from_a0 = g711_rtp(0, 10, 0x0A0A_0A0A, 0xFF);
        phone_a
            .send_to(&from_a0, engine_near)
            .await
            .expect("a send 0");
        let (srtp0, _) = recv(&phone_b).await;
        assert_ne!(srtp0, from_a0, "B receives SRTP, not plaintext");

        // B → engine(far): PCMA SRTP (B's key), seq 60000 → the actor decrypts (recording B's SSRC +
        // highest_seq in the inbound SRTP rollover), transcodes PCMA→PCMU, and A gets plaintext.
        let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
        let mut srtp_b = Vec::new();
        b_encrypt
            .protect(&g711_rtp(8, 60_000, b_ssrc, 0x55), &mut srtp_b)
            .expect("B encrypts");
        phone_b.send_to(&srtp_b, engine_far).await.expect("b send");
        let (plain_a, _) = recv(&phone_a).await;
        let g711 = siphon_rtp_media::rtp::RtpPacket::parse(&plain_a).expect("parse plaintext");
        assert_eq!(g711.payload_type, 0, "A receives transcoded G.711 µ-law");

        // Checkpoint the secure-transcode call → the blob carries the secure section, sourced from the
        // media actor: the peer's key, the live SRTP rollover, and NO bridge flows (SrtpMedia crypts
        // inside the actor).
        let CmdResult::Checkpoint { snapshot } = engine_a
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: "ha-savp-xcode".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await
        else {
            panic!("expected a checkpoint result");
        };
        let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("parse blob");
        assert_eq!(
            parsed.pipeline,
            crate::ha::PipelineSnapshot::SrtpMedia,
            "snapshot pipeline is SrtpMedia"
        );
        assert_eq!(
            parsed.near_codec.as_ref().expect("near").encoding_name,
            "PCMU"
        );
        assert_eq!(
            parsed.far_codec.as_ref().expect("far").encoding_name,
            "PCMA"
        );
        let secure = parsed
            .secure
            .as_ref()
            .expect("the snapshot carries the secure section");
        assert_eq!(secure.far_remote_crypto.suite, "AES_CM_128_HMAC_SHA1_80");
        assert!(
            secure.bridge_flows.is_empty(),
            "a secure transcode has no in-datapath bridge flows (crypts in the actor)"
        );
        let inbound = secure
            .rollover
            .inbound_rtp
            .iter()
            .find(|stream| stream.ssrc == b_ssrc)
            .copied()
            .expect("B's inbound SRTP rollover was captured");
        assert_eq!(
            inbound.highest_seq,
            Some(60_000),
            "the captured rollover anchors at B's last-seen sequence"
        );

        // Simulate a checkpoint taken *after* B's stream had rolled over 7 times (RFC 3711 §3.3.1):
        // bump the captured inbound ROC to 7. A correct restore must carry this across so decryption
        // keeps computing the right packet index — a reset to 0 would authenticate against the wrong
        // keystream (a two-time-pad / auth failure).
        let mut mutated = parsed.clone();
        mutated
            .secure
            .as_mut()
            .expect("secure section")
            .rollover
            .inbound_rtp
            .iter_mut()
            .find(|stream| stream.ssrc == b_ssrc)
            .expect("B inbound entry")
            .roc = 7;
        let blob = mutated.to_json().expect("reserialize the mutated snapshot");

        // Node A dies: delete frees its ports, then drop the engine.
        engine_a
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "ha-savp-xcode".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        drop(engine_a);

        // Node B (same range) restores the secure-transcode call and rebuilds the actor + SecureLeg.
        let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
        tokio::spawn(run_redirect_dispatcher(
            engine_b.datapath().rx(),
            engine_b.bridge(),
            engine_b.media(),
            engine_b.ws(),
            engine_b.conference(),
            None,
        ));
        assert!(
            matches!(
                engine_b
                    .handle(CLIENT, Command::Restore { snapshot: blob })
                    .await,
                CmdResult::Ok { .. }
            ),
            "secure-transcode restore succeeds on the standby"
        );
        assert!(
            engine_b.media().is_media_call("ha-savp-xcode"),
            "the secure-transcode actor is rebuilt on the standby"
        );

        // Re-checkpoint node B immediately: the rebuilt SecureLeg must have been *seeded* — the inbound
        // ROC is still 7 and anchored at seq 60000, proving the rollover continued (no reset).
        let CmdResult::Checkpoint { snapshot: reblob } = engine_b
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: "ha-savp-xcode".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await
        else {
            panic!("expected a checkpoint result on the standby");
        };
        let reparsed = crate::ha::CallSnapshot::from_json(&reblob).expect("parse standby blob");
        let reinbound = reparsed
            .secure
            .as_ref()
            .expect("standby secure section")
            .rollover
            .inbound_rtp
            .iter()
            .find(|stream| stream.ssrc == b_ssrc)
            .copied()
            .expect("B's inbound rollover survived the restore");
        assert_eq!(
            reinbound.roc, 7,
            "the SRTP rollover counter continued (no ROC reset)"
        );
        assert_eq!(
            reinbound.highest_seq,
            Some(60_000),
            "the rollover anchor continued across the restore"
        );

        // Secure media resumes through B at the unchanged ports, both ways. To prove the *continuity*
        // (not just that some packet decrypts), advance the peer's own SRTP state to the same ROC=7 the
        // failover happened at — a real B would be there — so its next packet authenticates against
        // ROC=7. It decrypts on the standby ONLY IF the restore kept ROC=7: a reset to ROC=0 would
        // compute the wrong packet index and fail auth (a two-time-pad, RFC 3711 §3.3.1).
        b_encrypt.seed_stream(StreamRollover {
            ssrc: b_ssrc,
            roc: 7,
            highest_seq: Some(60_000),
        });
        // B → engine(far): PCMA SRTP (B's key) at seq 60001 / ROC 7 → decrypt → transcode → A gets PCMU.
        let mut srtp_b2 = Vec::new();
        b_encrypt
            .protect(&g711_rtp(8, 60_001, b_ssrc, 0x55), &mut srtp_b2)
            .expect("B encrypts 2");
        phone_b
            .send_to(&srtp_b2, engine_far)
            .await
            .expect("b send 2");
        let (plain_a2, _) = recv(&phone_a).await;
        let g711_2 = siphon_rtp_media::rtp::RtpPacket::parse(&plain_a2).expect("parse plaintext 2");
        assert_eq!(
            g711_2.payload_type, 0,
            "B→A secure transcode resumes on the standby at the continued ROC (A gets µ-law)"
        );

        // A → engine(near): plaintext PCMU → transcode PCMU→PCMA → encrypt → B gets SRTP it decrypts.
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, engine_near).await.expect("a send");
        let (srtp_to_b, from) = recv(&phone_b).await;
        assert_eq!(from, engine_far, "media leaves the engine's B-facing port");
        assert_ne!(srtp_to_b, from_a, "B receives SRTP, not plaintext");
        let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
        let mut recovered = Vec::new();
        b_decrypt
            .unprotect(&srtp_to_b, &mut recovered)
            .expect("B decrypts the engine's SRTP through the restored actor");
        let to_b = siphon_rtp_media::rtp::RtpPacket::parse(&recovered).expect("parse decrypted");
        assert_eq!(
            to_b.payload_type, 8,
            "A→B secure transcode resumes on the standby (B gets A-law)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn savp_bridge_relays_avp_plaintext_to_savp_srtp_both_ways() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use siphon_rtp_srtp::SrtpContext;

        // Scenario 1: A is plain RTP/AVP, the control asks for a secure RTP/SAVP far leg, and the
        // engine bridges the two — SRTP terminated on B, plaintext relayed to A. Driven end-to-end
        // through the control plane with the redirect dispatcher live.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await; // plain (AVP) caller A
        let (phone_b, addr_b) = phone().await; // secure (SAVP) callee B

        // A offers plaintext RTP/AVP; the profile asks for a secure far leg (rtpengine model).
        let profile = ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "savp-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile,
                },
            )
            .await;
        let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("parse offer reply");
        assert!(offer_reply.secure, "the engine offers RTP/SAVP to B");
        let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
        let far_addr = offer_reply.remote_rtp; // the engine's B-facing endpoint

        // B answers RTP/SAVP with its own SDES key.
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "savp-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: savp_answer_sdp(addr_b, &b_key),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let answer_reply = sdp::parse(&ok_sdp_text(&answer)).expect("parse answer reply");
        assert!(!answer_reply.secure, "the answer to A is plaintext RTP/AVP");
        assert!(
            answer_reply.crypto.is_empty(),
            "no crypto leaks to the plain leg"
        );
        let near_addr = answer_reply.remote_rtp; // the engine's A-facing endpoint

        // A → engine(near) → bridge encrypts → B receives SRTP, decryptable with the engine's key.
        let from_a = rtp_packet(100, 0x0A0A_0A0A);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (srtp, from) = recv(&phone_b).await;
        assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
        assert_ne!(srtp, from_a, "B receives SRTP, not plaintext");
        let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
        let mut recovered = Vec::new();
        b_decrypt
            .unprotect(&srtp, &mut recovered)
            .expect("B decrypts the engine's SRTP");
        assert_eq!(recovered, from_a);

        // B → engine(far) as SRTP (B's key) → bridge decrypts → A receives plaintext.
        let from_b = rtp_packet(200, 0x0B0B_0B0B);
        let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
        let mut srtp_b = Vec::new();
        b_encrypt.protect(&from_b, &mut srtp_b).expect("B encrypts");
        phone_b.send_to(&srtp_b, far_addr).await.expect("b send");
        let (recovered_a, from) = recv(&phone_a).await;
        assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
        assert_eq!(recovered_a, from_b, "A receives the decrypted plaintext");
    }

    /// An `RTP/SAVP` answer SDP advertising AMR-WB (PT 96, 16 kHz) at `addr` with `crypto` (rtcp-mux).
    #[cfg(feature = "amr")]
    fn savp_amr_wb_answer_sdp(addr: SocketAddr, crypto: &CryptoAttribute) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=rtcp-mux\r\na={crypto_line}\r\n",
            ip = addr.ip(),
            port = addr.port(),
            crypto_line = crypto.to_attribute_value(),
        )
    }

    /// BGCF/SBC, the secure transcode: a secure `RTP/SAVP` **AMR-WB (16 kHz)** far leg ↔ a plaintext
    /// `RTP/AVP` **G.711 µ-law (8 kHz)** near leg. The engine decrypts B's SRTP, transcodes (16↔8 kHz
    /// resample), and encrypts toward B — and the reverse — in one `MediaCall` (`PipelineKind::SrtpMedia`),
    /// driven end to end through the control plane + redirect dispatcher. `amr`-feature-gated.
    #[cfg(feature = "amr")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn savp_amr_wb_far_leg_transcodes_to_plain_g711_both_ways() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use siphon_rtp_srtp::SrtpContext;

        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await; // plain G.711 (PSTN) side
        let (phone_b, addr_b) = phone().await; // secure AMR-WB (VoLTE) side

        // A offers plaintext G.711; the profile asks the engine to secure the far (B) leg.
        let profile = ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "savp-xcode".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile,
                },
            )
            .await;
        let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
        assert!(offer_reply.secure, "engine offers RTP/SAVP to B");
        let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
        let far_addr = offer_reply.remote_rtp;

        // B answers RTP/SAVP AMR-WB with its own key → near = G.711 (8 kHz), far = AMR-WB (16 kHz),
        // secure ⇒ the secure transcoding media slow path.
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "savp-xcode".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: savp_amr_wb_answer_sdp(addr_b, &b_key),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;
        assert!(
            engine.media().is_media_call("savp-xcode"),
            "secure + transcode resolves to the media slow path"
        );

        // A → engine(near): plaintext G.711 in; B receives SRTP that decrypts to transcoded AMR-WB.
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (srtp, from) = recv(&phone_b).await;
        assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
        assert_ne!(srtp, from_a, "B receives SRTP, not plaintext");
        let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
        let mut amr = Vec::new();
        b_decrypt
            .unprotect(&srtp, &mut amr)
            .expect("B decrypts the engine's SRTP");
        let amr_rtp = siphon_rtp_media::rtp::RtpPacket::parse(&amr).expect("parse decrypted");
        assert_eq!(amr_rtp.payload_type, 96, "B receives AMR-WB (PT 96)");
        assert!(!amr_rtp.payload.is_empty(), "AMR-WB egress carries a frame");

        // B → engine(far): AMR-WB SRTP (B's key) in; A receives plaintext transcoded G.711 µ-law.
        let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
        let mut srtp_b = Vec::new();
        b_encrypt
            .protect(&amr_wb_rtp(7, 0x0B0B_0B0B), &mut srtp_b)
            .expect("B encrypts");
        phone_b.send_to(&srtp_b, far_addr).await.expect("b send");
        let (plain_a, from) = recv(&phone_a).await;
        assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
        let g711 = siphon_rtp_media::rtp::RtpPacket::parse(&plain_a).expect("parse plaintext");
        assert_eq!(g711.payload_type, 0, "A receives G.711 µ-law (PT 0)");
        assert_eq!(g711.payload.len(), 160, "20 ms at 8 kHz, 1 byte/sample");
    }

    /// A minimal RTCP sender-report-shaped datagram (version 2, PT 200) carrying `ssrc`.
    fn rtcp_sr(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0x00, 0x00];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x33; 16]);
        packet
    }

    /// The BGCF/SBC secure transcode **without rtcp-mux**: the companion RTCP endpoints are redirected
    /// into the media actor and SRTCP-(de)crypted through the shared SecureLeg (RFC 3711 / RFC 5761) —
    /// B's SRTCP is decrypted and relayed plaintext to A's RTCP port, and A's plaintext RTCP is
    /// encrypted toward B. Driven end to end through the control plane + redirect dispatcher.
    #[cfg(feature = "amr")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn savp_transcode_relays_non_muxed_srtcp_both_ways() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use siphon_rtp_srtp::srtcp::SrtcpContext;

        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        // Dedicated RTP + RTCP sockets per party (non-mux ⇒ RTCP on its own port).
        let (_phone_a, addr_a) = phone().await;
        let (rtcp_a, rtcp_a_addr) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let (rtcp_b, rtcp_b_addr) = phone().await;

        // A offers plaintext G.711, non-mux, advertising its RTCP socket; the profile secures the far leg.
        let offer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp:{rtcp}\r\n",
            ip = addr_a.ip(),
            port = addr_a.port(),
            rtcp = rtcp_a_addr.port(),
        );
        let profile = ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "savp-nonmux".into(),
                    from_tag: "tag-a".into(),
                    sdp: offer_sdp,
                    profile,
                },
            )
            .await;
        let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
        let engine_far_key = *offer_reply.crypto.first().expect("engine key to B");
        let far_rtp = offer_reply.remote_rtp;
        let far_rtcp = offer_reply.remote_rtcp;
        assert_ne!(
            far_rtcp, far_rtp,
            "non-mux: distinct RTCP port advertised to B"
        );

        // B answers RTP/SAVP AMR-WB, non-mux, advertising its RTCP socket + key.
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let answer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=rtcp:{rtcp}\r\na={crypto}\r\n",
            ip = addr_b.ip(),
            port = addr_b.port(),
            rtcp = rtcp_b_addr.port(),
            crypto = b_key.to_attribute_value(),
        );
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "savp-nonmux".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: answer_sdp,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let near_rtcp = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtcp;
        assert!(
            engine.media().is_media_call("savp-nonmux"),
            "secure transcode resolves to the media slow path"
        );

        // B → A: B encrypts an RTCP SR with its key → engine far RTCP; A's RTCP socket gets plaintext.
        let b_sr = rtcp_sr(0xB0B0_B0B0);
        let mut b_srtcp = Vec::new();
        SrtcpContext::from_key_material(&b_key.key)
            .protect(&b_sr, &mut b_srtcp)
            .expect("B encrypt SRTCP");
        rtcp_b
            .send_to(&b_srtcp, far_rtcp)
            .await
            .expect("b rtcp send");
        let (relayed, from) = recv(&rtcp_a).await;
        assert_eq!(
            from, near_rtcp,
            "RTCP relayed from the engine's near RTCP port"
        );
        assert_eq!(relayed, b_sr, "A receives B's decrypted plaintext RTCP");

        // A → B: A's plaintext RTCP → engine near RTCP; B's RTCP socket gets SRTCP it can decrypt.
        let a_sr = rtcp_sr(0xA0A0_A0A0);
        rtcp_a.send_to(&a_sr, near_rtcp).await.expect("a rtcp send");
        let (srtcp, from) = recv(&rtcp_b).await;
        assert_eq!(from, far_rtcp, "engine transmits from its far RTCP port");
        assert_ne!(srtcp, a_sr, "toward B it is encrypted (SRTCP)");
        let mut recovered = Vec::new();
        SrtcpContext::from_key_material(&engine_far_key.key)
            .unprotect(&srtcp, &mut recovered)
            .expect("B decrypt SRTCP");
        assert_eq!(recovered, a_sr, "B recovers A's RTCP");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conference_mixes_two_participants_end_to_end() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use siphon_rtp_codec::g711::G711;
        use siphon_rtp_codec::Decoder as _;
        use siphon_rtp_dsp::EnergyVad;
        use siphon_rtp_media::rtp::RtpPacket;

        // Two callers join one room over the JSON control plane, exchange loud G.711, and each hears
        // the other's audio mixed back — the full path: join → endpoint alloc → Redirect → dispatcher
        // → mixer actor → 20 ms tick → egress.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let join_a = engine
            .handle(
                CLIENT,
                Command::ConferenceJoin {
                    conference_id: "room-1".into(),
                    from_tag: "alice".into(),
                    sdp: sdp_for(addr_a, true),
                    role: ConferenceRole::Talker,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let engine_a = sdp::parse(&ok_sdp_text(&join_a))
            .expect("A answer")
            .remote_rtp;
        let join_b = engine
            .handle(
                CLIENT,
                Command::ConferenceJoin {
                    conference_id: "room-1".into(),
                    from_tag: "bob".into(),
                    sdp: sdp_for(addr_b, true),
                    role: ConferenceRole::Talker,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let engine_b = sdp::parse(&ok_sdp_text(&join_b))
            .expect("B answer")
            .remote_rtp;

        // Both speak loud G.711 (µ-law 0x00 ≈ full scale); fill the jitter buffers well past the
        // priming depth so there is a window during which each is heard.
        for sequence in 0..30 {
            phone_a
                .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x00), engine_a)
                .await
                .expect("a send");
            phone_b
                .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x00), engine_b)
                .await
                .expect("b send");
        }

        // The 20 ms room ticker mixes and sends each participant the other's audio. The first frame
        // or two are silence (before the peer's jitter buffer primes), so scan a few frames.
        let mut decoder = G711::ulaw();
        let mut heard_loud = false;
        for _ in 0..8 {
            let (mix_a, from_a) = recv(&phone_a).await;
            assert_eq!(from_a, engine_a, "A hears the mix from its engine port");
            let packet = RtpPacket::parse(&mix_a).expect("A egress RTP");
            assert_eq!(packet.payload_type, 0, "G.711 µ-law egress");
            let mut pcm = vec![0i16; 320];
            let samples = decoder.decode(packet.payload, &mut pcm).expect("decode");
            if EnergyVad::energy(&pcm[..samples]) > 1_000_000 {
                heard_loud = true;
                break;
            }
        }
        assert!(
            heard_loud,
            "A hears B's loud audio (mixed-minus-self) within a few frames"
        );
        let (_mix_b, from_b) = recv(&phone_b).await;
        assert_eq!(from_b, engine_b, "B hears the mix from its engine port");

        // Leaving releases each participant; the empty room is torn down.
        for tag in ["alice", "bob"] {
            let left = engine
                .handle(
                    CLIENT,
                    Command::ConferenceLeave {
                        conference_id: "room-1".into(),
                        from_tag: tag.into(),
                    },
                )
                .await;
            assert!(
                matches!(left, CmdResult::Ok { .. }),
                "{tag} leaves: {left:?}"
            );
        }
        assert!(
            !engine.conference().contains("room-1"),
            "empty room torn down"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conference_bridge_command_wires_two_rooms() {
        use crate::srtp_bridge::run_redirect_dispatcher;

        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        // Bridging non-existent rooms is an error.
        let missing = engine
            .handle(
                CLIENT,
                Command::ConferenceBridge {
                    conference_id_a: "ghost-1".into(),
                    conference_id_b: "ghost-2".into(),
                    direction: BridgeDirection::Both,
                },
            )
            .await;
        assert!(
            matches!(missing, CmdResult::Error { .. }),
            "no such rooms: {missing:?}"
        );

        // Seat a participant in each of two rooms, then bridge them.
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        for (room, tag, addr) in [("room-x", "alice", addr_a), ("room-y", "bob", addr_b)] {
            let joined = engine
                .handle(
                    CLIENT,
                    Command::ConferenceJoin {
                        conference_id: room.into(),
                        from_tag: tag.into(),
                        sdp: sdp_for(addr, true),
                        role: ConferenceRole::Talker,
                        profile: ProfileFlags::default(),
                    },
                )
                .await;
            assert!(
                matches!(joined, CmdResult::Ok { .. }),
                "{tag} joins {room}: {joined:?}"
            );
        }
        let bridged = engine
            .handle(
                CLIENT,
                Command::ConferenceBridge {
                    conference_id_a: "room-x".into(),
                    conference_id_b: "room-y".into(),
                    direction: BridgeDirection::Both,
                },
            )
            .await;
        assert!(
            matches!(bridged, CmdResult::Ok { .. }),
            "rooms bridge: {bridged:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conference_reaps_idle_participants() {
        use crate::srtp_bridge::run_redirect_dispatcher;

        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let mut engine_a = addr_a; // overwritten with alice's engine port below
        for (tag, addr) in [("alice", addr_a), ("bob", addr_b)] {
            let joined = engine
                .handle(
                    CLIENT,
                    Command::ConferenceJoin {
                        conference_id: "room".into(),
                        from_tag: tag.into(),
                        sdp: sdp_for(addr, true),
                        role: ConferenceRole::Talker,
                        profile: ProfileFlags::default(),
                    },
                )
                .await;
            let port = sdp::parse(&ok_sdp_text(&joined))
                .expect("answer")
                .remote_rtp;
            if tag == "alice" {
                engine_a = port;
            }
        }

        // Advance the logical clock, then alice sends media (stamping her endpoint's activity); bob
        // stays silent. With idle_ticks = 3, bob is idle since tick 0 (now 4 ⇒ reaped) but alice's
        // activity is fresh (kept).
        engine.datapath().advance_clock(4);
        phone_a
            .send_to(&g711_rtp(0, 0, 0x0A0A_0A0A, 0x00), engine_a)
            .await
            .expect("a send");
        tokio::time::sleep(Duration::from_millis(30)).await; // let the datapath stamp activity

        assert_eq!(
            engine.reap_idle_conferences(3).await,
            1,
            "the silent participant is reaped"
        );
        assert!(
            engine.conference().contains("room"),
            "the active participant keeps the room alive"
        );

        // Advance past alice's activity too — now the room drains and is torn down.
        engine.datapath().advance_clock(5);
        assert!(
            engine.reap_idle_conferences(3).await >= 1,
            "the now-idle participant is reaped"
        );
        assert!(
            !engine.conference().contains("room"),
            "empty room torn down"
        );
    }

    #[tokio::test]
    async fn conference_join_negotiates_sdes_srtp() {
        // A participant offering RTP/SAVP + a=crypto is answered with RTP/SAVP + the engine's own
        // a=crypto (SDES-SRTP secure conference leg).
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let peer_crypto =
            CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let joined = engine
            .handle(
                CLIENT,
                Command::ConferenceJoin {
                    conference_id: "secure-room".into(),
                    from_tag: "alice".into(),
                    sdp: savp_answer_sdp(addr, &peer_crypto),
                    role: ConferenceRole::Talker,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let answer = sdp::parse(&ok_sdp_text(&joined)).expect("answer");
        assert!(answer.secure, "the engine answers RTP/SAVP");
        assert!(
            !answer.crypto.is_empty(),
            "the engine advertises its own a=crypto"
        );
    }

    /// A G.711 RTP packet (160-sample frame) for transcode tests.
    fn g711_rtp(payload_type: u8, sequence: u16, ssrc: u32, payload_byte: u8) -> Vec<u8> {
        let mut packet = vec![0x80, payload_type];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[payload_byte; 160]);
        packet
    }

    /// An SDP advertising a single static audio codec (mux), for transcode answers.
    fn sdp_single_codec(rtp: SocketAddr, payload_type: u8, name: &str) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {pt}\r\na=rtpmap:{pt} {name}/8000\r\na=rtcp-mux\r\n",
            ip = rtp.ip(),
            port = rtp.port(),
            pt = payload_type,
        )
    }

    /// Encode 20 ms of 16 kHz PCM into an RFC 4867 octet-aligned AMR-WB RTP packet (PT 96) — what a
    /// VoLTE UE puts on the wire. `amr`-feature-gated (patent-licensed — docs/codec-licensing.md).
    #[cfg(feature = "amr")]
    fn amr_wb_rtp(sequence: u16, ssrc: u32) -> Vec<u8> {
        use siphon_rtp_codec::factory::{encoder_for, CodecSpec};
        let mut encoder =
            encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("amr-wb encoder");
        let pcm: Vec<i16> = (0..320)
            .map(|i| ((i as f32 * 0.20).sin() * 6000.0) as i16)
            .collect();
        let mut amr_payload = vec![0u8; 256];
        let written = encoder
            .encode(&pcm, &mut amr_payload)
            .expect("encode amr-wb");
        let mut packet = vec![0x80, 96];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 320).to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&amr_payload[..written]);
        packet
    }

    /// BGCF/SBC PSTN breakout, end to end through the control plane: A offers VoLTE **AMR-WB (16 kHz)**,
    /// B answers PSTN **G.711a (8 kHz)**. The codec + clock-rate mismatch resolves to the media slow
    /// path, which redirects both legs to a transcoding actor (decode → 16↔8 kHz resample → re-encode).
    /// Proves AMR-WB RTP in → G.711a RTP out (and the reverse) over the real datapath + redirect
    /// dispatcher — the first scenario worthy of a live siphon-sip rtpengine trial. `amr`-feature-gated.
    #[cfg(feature = "amr")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_transcodes_amr_wb_to_g711a_end_to_end() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // A offers AMR-WB on dynamic PT 96 at 16 kHz (the VoLTE leg).
        let amr_offer = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=rtcp-mux\r\n",
            ip = addr_a.ip(),
            port = addr_a.port(),
        );
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "volte-pstn".into(),
                    from_tag: "tag-a".into(),
                    sdp: amr_offer,
                    profile: Default::default(),
                },
            )
            .await;
        let far_addr = sdp::parse(&ok_sdp_text(&offer))
            .expect("offer reply")
            .remote_rtp;

        // B answers G.711a only → near = AMR-WB (16 kHz), far = PCMA (8 kHz) → transcode + resample.
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "volte-pstn".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                    profile: Default::default(),
                },
            )
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;
        assert!(
            engine.media().is_media_call("volte-pstn"),
            "AMR-WB↔G.711a resolves to the transcoding media slow path"
        );

        // A → engine(near): AMR-WB in; B receives genuinely transcoded G.711a (PT 8, 160 bytes @ 8 kHz).
        phone_a
            .send_to(&amr_wb_rtp(0, 0xAAAA_AAAA), near_addr)
            .await
            .expect("a send amr-wb");
        let (transcoded, from) = recv(&phone_b).await;
        assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&transcoded).expect("parse");
        assert_eq!(parsed.payload_type, 8, "B receives G.711a (PT 8)");
        assert_eq!(parsed.payload.len(), 160, "20 ms at 8 kHz, 1 byte/sample");
        assert!(
            parsed.payload.iter().any(|&byte| byte != 0xD5),
            "transcoded G.711a carries non-silence audio"
        );

        // B → engine(far): G.711a in; A receives re-encoded AMR-WB (PT 96).
        let from_b = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
        phone_b.send_to(&from_b, far_addr).await.expect("b send");
        let (back, from) = recv(&phone_a).await;
        assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&back).expect("parse");
        assert_eq!(parsed.payload_type, 96, "A receives AMR-WB (PT 96)");
        assert!(!parsed.payload.is_empty(), "AMR-WB egress carries a frame");

        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "volte-pstn".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_transcodes_ulaw_to_alaw_end_to_end() {
        // A offers PCMU (µ-law); B answers PCMA (A-law). The differing codecs resolve to the media
        // slow path, which redirects both legs to a transcoding actor — proven end-to-end through the
        // control plane with the redirect dispatcher live.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // A's offer advertises PCMU as its primary codec (the `sdp_for` fixture: `0 8`, rtpmap PCMU).
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "xcode-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let far_addr = sdp::parse(&ok_sdp_text(&offer))
            .expect("offer reply")
            .remote_rtp;

        // B answers PCMA only → near=PCMU, far=PCMA → transcode.
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "xcode-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                    profile: Default::default(),
                },
            )
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;

        // A → engine(near) → transcode → B receives A-law (PT 8), not the original µ-law.
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (transcoded, from) = recv(&phone_b).await;
        assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&transcoded).expect("parse");
        assert_eq!(parsed.payload_type, 8, "B receives A-law (PT 8)");
        assert_eq!(parsed.payload.len(), 160);
        assert_ne!(
            parsed.payload,
            &from_a[12..],
            "payload genuinely transcoded"
        );

        // B → engine(far) → transcode → A receives µ-law (PT 0).
        let from_b = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
        phone_b.send_to(&from_b, far_addr).await.expect("b send");
        let (back, from) = recv(&phone_a).await;
        assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&back).expect("parse");
        assert_eq!(parsed.payload_type, 0, "A receives µ-law (PT 0)");

        // The call is a media-processing call; block then unblock via the control plane.
        assert!(engine.media().is_media_call("xcode-1"));
        let blocked = engine
            .handle(
                CLIENT,
                Command::BlockMedia {
                    call_id: "xcode-1".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await;
        assert!(matches!(blocked, CmdResult::Ok { .. }));

        // Teardown frees the media actor and routes.
        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "xcode-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert!(
            !engine.media().is_media_call("xcode-1"),
            "media call deregistered"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn siprec_subscribe_forks_leg_a_to_an_srs_then_unsubscribe_and_delete() {
        // SIPREC end-to-end (RFC 7866): a transcoding media call, then subscribe_request offers leg
        // A's media to a Session Recording Server, subscribe_answer points the fork at the SRS, A's
        // RTP is forked there, unsubscribe stops it, and delete tears the call (and subscription) down.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let (srs, srs_addr) = phone().await; // the Session Recording Server's media socket

        // A offers PCMU, B answers PCMA → a transcoding media call (so there is decoded PCM to fork).
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "siprec-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "siprec-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                    profile: Default::default(),
                },
            )
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;
        assert!(engine.media().is_media_call("siprec-1"));

        // subscribe_request: the engine offers leg A's media to the SRS and returns an SDP offer + a
        // subscription to-tag. Leg A's negotiated codec is PCMU (PT 0).
        let subscribe = engine
            .handle(
                CLIENT,
                Command::SubscribeRequest {
                    call_id: "siprec-1".into(),
                    from_tags: vec!["tag-a".into()],
                    sdp: None,
                    profile: Default::default(),
                },
            )
            .await;
        let (offer_sdp, subscription_tag) = match subscribe {
            CmdResult::Ok {
                sdp: Some(sdp),
                to_tag: Some(to_tag),
                ..
            } => (sdp, to_tag),
            other => panic!("expected an SDP offer + to_tag, got {other:?}"),
        };
        let offer_info = sdp::parse(&offer_sdp).expect("parse subscriber offer");
        assert_eq!(
            offer_info.primary_codec().expect("codec").encoding_name,
            "PCMU"
        );
        assert!(
            offer_sdp.contains("a=sendonly"),
            "subscriber stream is send-only (RFC 3264)"
        );

        // subscribe_answer: the SRS answers with its own media address. The fork attaches to leg A.
        let srs_answer_sdp = sdp_single_codec(srs_addr, 0, "PCMU");
        let answered = engine
            .handle(
                CLIENT,
                Command::SubscribeAnswer {
                    call_id: "siprec-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: subscription_tag.clone(),
                    sdp: srs_answer_sdp,
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(answered, CmdResult::Ok { .. }),
            "subscribe_answer ok: {answered:?}"
        );

        // A sends µ-law RTP through the engine; B gets the A-law transcode AND the SRS gets leg A's
        // RAW ingress RTP byte-for-byte (the raw tee, not a re-encode): same SSRC, sequence, payload.
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (to_b, _) = recv(&phone_b).await; // the normal transcoded leg is undisturbed
        let (forked, from) = recv(&srs).await;
        assert_eq!(
            from, offer_info.remote_rtp,
            "fork leaves the engine's subscriber port"
        );
        assert_eq!(
            forked, from_a,
            "SRS receives leg A's ORIGINAL RTP byte-for-byte (raw tee)"
        );
        assert_ne!(
            to_b, from_a,
            "B still gets the genuinely transcoded A-law stream"
        );

        // unsubscribe: the fork stops; A's media still transcodes to B.
        let unsubscribed = engine
            .handle(
                CLIENT,
                Command::Unsubscribe {
                    call_id: "siprec-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: subscription_tag,
                },
            )
            .await;
        assert!(matches!(unsubscribed, CmdResult::Ok { .. }));

        // Drain any already-in-flight forked packets, then prove no more arrive after unsubscribe.
        let mut drain = [0u8; 2048];
        while srs.try_recv_from(&mut drain).is_ok() {}
        phone_a
            .send_to(&g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        let (_to_b_again, _) = recv(&phone_b).await; // B still receives transcoded media
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(200), srs.recv_from(&mut scratch))
                .await
                .is_err(),
            "no more forked packets reach the SRS after unsubscribe"
        );

        // delete: tears the call down cleanly (the subscription is already gone).
        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "siprec-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert!(
            !engine.media().is_media_call("siprec-1"),
            "media call deregistered"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn siprec_subscription_is_freed_when_the_parent_call_is_deleted() {
        // A subscription left open at delete must be torn down with the call (raw tees detached,
        // subscriber port freed) — no orphaned task or leaked endpoint.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let (_srs, srs_addr) = phone().await;

        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "siprec-2".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "siprec-2".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                    profile: Default::default(),
                },
            )
            .await;
        let subscribe = engine
            .handle(
                CLIENT,
                Command::SubscribeRequest {
                    call_id: "siprec-2".into(),
                    from_tags: vec!["tag-a".into()],
                    sdp: None,
                    profile: Default::default(),
                },
            )
            .await;
        let subscription_tag = match subscribe {
            CmdResult::Ok {
                to_tag: Some(to_tag),
                ..
            } => to_tag,
            other => panic!("expected a to_tag, got {other:?}"),
        };
        engine
            .handle(
                CLIENT,
                Command::SubscribeAnswer {
                    call_id: "siprec-2".into(),
                    from_tag: "tag-a".into(),
                    to_tag: subscription_tag,
                    sdp: sdp_single_codec(srs_addr, 0, "PCMU"),
                    profile: Default::default(),
                },
            )
            .await;

        // Delete the call without unsubscribing first: teardown must drain the subscription too.
        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "siprec-2".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert_eq!(
            engine.session_count(),
            0,
            "the call drained from the registry"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn siprec_subscribe_forks_a_plain_passthrough_relay_to_an_srs() {
        // The headline: SIPREC on a PLAIN G.711 RELAY (same codec both sides → Passthrough, the
        // in-kernel Forward fast path). subscribe_request promotes the relay to userspace, the raw tee
        // copies leg A's ORIGINAL RTP to the SRS byte-for-byte (no re-encode), AND the original peer B
        // keeps receiving the relayed RTP. Then unsubscribe stops the SRS feed (B still flows) and
        // demotes back to the kernel path; delete tears it down.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let (srs, srs_addr) = phone().await;

        // A offers PCMU, B answers PCMU → same codec → a plain Passthrough relay (no media actor).
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "siprec-relay".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let far_addr = sdp::parse(&ok_sdp_text(&offer))
            .expect("offer reply")
            .remote_rtp;
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "siprec-relay".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                    profile: Default::default(),
                },
            )
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;
        assert!(
            !engine.media().is_media_call("siprec-relay"),
            "a plain relay has no media actor"
        );

        // subscribe_request: the engine offers leg A's media + promotes the relay to userspace.
        let subscribe = engine
            .handle(
                CLIENT,
                Command::SubscribeRequest {
                    call_id: "siprec-relay".into(),
                    from_tags: vec!["tag-a".into()],
                    sdp: None,
                    profile: Default::default(),
                },
            )
            .await;
        let (offer_sdp, subscription_tag) = match subscribe {
            CmdResult::Ok {
                sdp: Some(sdp),
                to_tag: Some(to_tag),
                ..
            } => (sdp, to_tag),
            other => panic!("expected an SDP offer + to_tag, got {other:?}"),
        };
        let offer_info = sdp::parse(&offer_sdp).expect("parse subscriber offer");
        assert_eq!(
            offer_info.primary_codec().expect("codec").encoding_name,
            "PCMU",
            "offer advertises the source leg's actual codec (RFC 4566)"
        );
        assert!(
            offer_sdp.contains("a=sendonly"),
            "subscriber stream is send-only (RFC 3264)"
        );
        assert!(
            engine.media().is_relay_call("siprec-relay"),
            "the relay was promoted to userspace"
        );

        // subscribe_answer: the SRS answers with its media address; the raw tee attaches to leg A.
        let answered = engine
            .handle(
                CLIENT,
                Command::SubscribeAnswer {
                    call_id: "siprec-relay".into(),
                    from_tag: "tag-a".into(),
                    to_tag: subscription_tag.clone(),
                    sdp: sdp_single_codec(srs_addr, 0, "PCMU"),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(answered, CmdResult::Ok { .. }),
            "subscribe_answer ok: {answered:?}"
        );

        // A sends RTP: (1) B still receives the relayed RTP, (2) the SRS receives the byte-identical
        // original RTP (raw tee, not re-encoded).
        let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
        phone_a.send_to(&from_a, near_addr).await.expect("a send");
        let (to_b, from_b_engine) = recv(&phone_b).await;
        assert_eq!(
            from_b_engine, far_addr,
            "B's media leaves the engine's far port"
        );
        assert_eq!(to_b, from_a, "B still receives the relayed RTP verbatim");
        let (forked, from) = recv(&srs).await;
        assert_eq!(
            from, offer_info.remote_rtp,
            "tee leaves the engine's subscriber port"
        );
        assert_eq!(
            forked, from_a,
            "SRS receives leg A's ORIGINAL RTP byte-for-byte (raw tee)"
        );

        // unsubscribe: the SRS feed stops; B still flows; the call demotes back to the kernel path.
        let unsubscribed = engine
            .handle(
                CLIENT,
                Command::Unsubscribe {
                    call_id: "siprec-relay".into(),
                    from_tag: "tag-a".into(),
                    to_tag: subscription_tag,
                },
            )
            .await;
        assert!(matches!(unsubscribed, CmdResult::Ok { .. }));
        assert!(
            !engine.media().is_media_call("siprec-relay"),
            "demoted: no media actor remains"
        );

        let mut drain = [0u8; 2048];
        while srs.try_recv_from(&mut drain).is_ok() {}
        phone_a
            .send_to(&g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        let (to_b_again, _) = recv(&phone_b).await; // B still relays after demotion
        assert_eq!(
            to_b_again,
            g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF),
            "B keeps relaying post-demote"
        );
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(200), srs.recv_from(&mut scratch))
                .await
                .is_err(),
            "no more tee'd packets reach the SRS after unsubscribe"
        );

        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "siprec-relay".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert_eq!(
            engine.session_count(),
            0,
            "the call drained from the registry"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_request_rejects_a_secure_call() {
        // SIPREC on an SRTP-bridge leg is not supported (the wire bytes are ciphertext, not the leg's
        // clear codec) — subscribe_request must reject it clearly rather than tee garbage.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        let profile = ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        };
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "savp-siprec".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile,
                },
            )
            .await;
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "savp-siprec".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: savp_answer_sdp(addr_b, &b_key),
                    profile: ProfileFlags::default(),
                },
            )
            .await;

        let result = engine
            .handle(
                CLIENT,
                Command::SubscribeRequest {
                    call_id: "savp-siprec".into(),
                    from_tags: vec!["tag-a".into()],
                    sdp: None,
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "SIPREC on a secure call is rejected"
        );
    }

    /// A µ-law (PCMU, PT 0) RTP packet: a 160-sample / 20 ms frame carrying `payload_byte`.
    fn ulaw_rtp_packet(sequence: u16, ssrc: u32, payload_byte: u8) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[payload_byte; 160]);
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_attaches_leg_a_to_a_websocket_server_end_to_end() {
        // The mod_audio_stream headline: a control client sets `ws_uri`, the engine dials that WS
        // server and bridges leg A's audio to it. Driven end-to-end through the control plane with the
        // redirect dispatcher live; proves the start handshake, the uplink, the downlink, and teardown.
        use crate::srtp_bridge::run_redirect_dispatcher;
        use futures_util::{SinkExt, StreamExt};
        use siphon_rtp_media::bridge::pcm_to_l16_le;
        use siphon_rtp_media::bridge::protocol::ControlMessage;
        use tokio_tungstenite::tungstenite::Message;

        // Stand up a local WebSocket server: it relays each received frame out `ws_rx`, and forwards a
        // downlink frame requested via `down_tx` into the socket toward the engine.
        let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ws");
        let ws_addr = ws_listener.local_addr().expect("ws addr");
        let (ws_tx, ws_rx) = flume::unbounded::<Message>();
        let (down_tx, down_rx) = flume::unbounded::<Vec<u8>>();
        tokio::spawn(async move {
            let (stream, _) = ws_listener.accept().await.expect("accept ws");
            let socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("ws handshake");
            let (mut sink, mut source) = socket.split();
            loop {
                tokio::select! {
                    incoming = source.next() => match incoming {
                        Some(Ok(message)) => {
                            if ws_tx.send(message).is_err() {
                                break;
                            }
                        }
                        _ => break,
                    },
                    downlink = down_rx.recv_async() => match downlink {
                        Ok(bytes) => {
                            if sink.send(Message::binary(bytes)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                }
            }
        });

        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;

        // A offers PCMU with `ws_uri` set → the engine dials the WS and bridges leg A to it.
        let profile = ProfileFlags {
            ws_uri: Some(format!("ws://{ws_addr}/stream")),
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ws-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile,
                },
            )
            .await;
        assert!(matches!(offer, CmdResult::Ok { .. }), "ws offer succeeds");
        assert!(
            engine.ws().is_ws_call("ws-1"),
            "the call is a WS-bridge call"
        );

        // An answer (B answers PCMU too) returns the engine's A-facing endpoint without wiring A↔B.
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ws-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let near_addr = sdp::parse(&ok_sdp_text(&answer))
            .expect("answer reply")
            .remote_rtp;

        // 1. The WS server receives a `start` text frame first (the mod_audio_stream handshake).
        let first = timeout(Duration::from_secs(3), ws_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        match first {
            Message::Text(text) => assert!(
                matches!(
                    ControlMessage::from_json(text.as_str()),
                    Ok(ControlMessage::Start(_))
                ),
                "first WS frame is `start`"
            ),
            other => panic!("expected start text frame, got {other:?}"),
        }

        // 2. Uplink: phone A sends µ-law RTP to the engine's A-facing port; the WS server gets an L16
        //    binary uplink frame (8 kHz / 20 ms = 320 bytes).
        phone_a
            .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        let mut got_uplink = false;
        for _ in 0..30 {
            let frame = timeout(Duration::from_secs(2), ws_rx.recv_async())
                .await
                .expect("no timeout")
                .expect("a frame");
            if let Message::Binary(bytes) = frame {
                assert_eq!(bytes.len(), 320, "8k/20ms L16 uplink");
                got_uplink = true;
                break;
            }
        }
        assert!(got_uplink, "expected an uplink L16 binary frame on the WS");

        // 3. Downlink: the WS server sends a binary L16 frame; phone A receives an RTP packet (the
        //    bridge encodes it in A's codec and the drain task sends it toward A).
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[2000i16; 160], &mut l16);
        down_tx.send(l16.to_vec()).expect("queue downlink");
        let mut got_downlink = false;
        for _ in 0..30 {
            let mut buffer = [0u8; 2048];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
            {
                let packet =
                    siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse rtp");
                assert_eq!(
                    packet.payload_type, 0,
                    "downlink encoded in A's codec (µ-law)"
                );
                assert_eq!(packet.payload.len(), 160, "8k/20ms µ-law frame");
                got_downlink = true;
                break;
            }
        }
        assert!(
            got_downlink,
            "expected a downlink RTP packet toward phone A"
        );

        // 4. Teardown: delete frees the WS bridge (route + tasks).
        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "ws-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert!(
            !engine.ws().is_ws_call("ws-1"),
            "WS call deregistered on delete"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_attaches_leg_a_to_a_secure_websocket_server_over_wss() {
        // The `wss://` counterpart of the plain-`ws://` bridge test: a control client sets a `wss://`
        // `ws_uri`, and the engine dials it over TLS (RFC 8446 handshake on the ring/rustls provider,
        // RFC 6455 upgrade) before streaming. Proves the ring-backed connector completes the TLS +
        // WebSocket handshake end-to-end and the mod_audio_stream `start` frame flows over the tunnel.
        use crate::srtp_bridge::run_redirect_dispatcher;
        use futures_util::StreamExt;
        use siphon_rtp_media::bridge::protocol::ControlMessage;
        use tokio_tungstenite::tungstenite::Message;

        // Ring is the only crypto provider compiled (rustls `default-features = false, ["ring"]`);
        // install it as the process default so the test-side rustls configs build on it too.
        siphon_rtp_turn::tls::install_crypto_provider();

        // A fresh self-signed certificate for the loopback IP the engine will dial (IP SAN so rustls
        // validates the `ServerName::IpAddress` derived from `wss://127.0.0.1:...`).
        let certified =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).expect("gen cert");
        let cert_der = rustls_pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()),
        );
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server tls config");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

        // A TLS WebSocket server: TLS-accept the connection, run the WS handshake over the tunnel, and
        // relay every received frame out `ws_rx`.
        let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind wss");
        let ws_addr = ws_listener.local_addr().expect("wss addr");
        let (ws_tx, ws_rx) = flume::unbounded::<Message>();
        tokio::spawn(async move {
            let (stream, _) = ws_listener.accept().await.expect("accept tcp");
            let tls_stream = acceptor.accept(stream).await.expect("tls handshake");
            let socket = tokio_tungstenite::accept_async(tls_stream)
                .await
                .expect("wss handshake");
            let (_sink, mut source) = socket.split();
            while let Some(incoming) = source.next().await {
                match incoming {
                    Ok(message) => {
                        if ws_tx.send(message).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let engine = Engine::new(UdpLoopbackDatapath::new());
        // Pre-seed the engine's `wss://` client trust store with the self-signed test certificate so
        // the dial validates it (production seeds from the webpki-roots Mozilla CA bundle instead).
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("add test root");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        engine
            .ws_tls_config
            .set(std::sync::Arc::new(client_config))
            .expect("seed wss client config");

        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (_phone_a, addr_a) = phone().await;

        // A offers PCMU with a `wss://` `ws_uri` → the engine dials the TLS WS and bridges leg A.
        let profile = ProfileFlags {
            ws_uri: Some(format!("wss://127.0.0.1:{}/stream", ws_addr.port())),
            ..Default::default()
        };
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "wss-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile,
                },
            )
            .await;
        assert!(matches!(offer, CmdResult::Ok { .. }), "wss offer succeeds");
        assert!(
            engine.ws().is_ws_call("wss-1"),
            "the call is a WS-bridge call"
        );

        // The TLS WebSocket server receives the `start` text frame first — proof the TLS handshake and
        // the WS upgrade both completed over `wss://`.
        let first = timeout(Duration::from_secs(3), ws_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        match first {
            Message::Text(text) => assert!(
                matches!(
                    ControlMessage::from_json(text.as_str()),
                    Ok(ControlMessage::Start(_))
                ),
                "first WSS frame is `start`"
            ),
            other => panic!("expected start text frame over wss, got {other:?}"),
        }

        // Teardown frees the secure WS bridge.
        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "wss-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }));
        assert!(
            !engine.ws().is_ws_call("wss-1"),
            "WSS call deregistered on delete"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn play_dtmf_emits_telephone_events_on_a_media_call() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        // A offers PCMU + telephone-event 101; B answers PCMA + telephone-event 101 → a transcoding
        // media call where A's leg carries DTMF.
        let offer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
            ip = addr_a.ip(),
            port = addr_a.port(),
        );
        let answer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
            ip = addr_b.ip(),
            port = addr_b.port(),
        );
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "dtmf-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: offer_sdp,
                    profile: Default::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "dtmf-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: answer_sdp,
                    profile: Default::default(),
                },
            )
            .await;
        assert!(engine.media().is_media_call("dtmf-1"));

        // Play DTMF '7' toward A; the actor's playout clock injects RFC 4733 events out A's socket.
        let played = engine
            .handle(
                CLIENT,
                Command::PlayDtmf {
                    call_id: "dtmf-1".into(),
                    from_tag: "tag-a".into(),
                    code: "7".into(),
                    duration_ms: Some(120),
                    volume_dbm0: Some(-10),
                    pause_ms: None,
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(played, CmdResult::Ok { .. }));

        // The first telephone-event packet (PT 96) reaches A within a few playout ticks.
        let mut saw_event = false;
        for _ in 0..20 {
            let mut buffer = [0u8; 256];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(100), phone_a.recv_from(&mut buffer)).await
            {
                let packet =
                    siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse");
                if packet.payload_type == 101 {
                    assert_eq!(packet.payload[0], 7, "RFC 4733 event code for '7'");
                    saw_event = true;
                    break;
                }
            }
        }
        assert!(saw_event, "expected a telephone-event packet toward A");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silence_on_a_passthrough_call_is_rejected() {
        // A plain relay (same codec both sides) is not a media-processing call; silence needs decode.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "relay-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "relay-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let result = engine
            .handle(
                CLIENT,
                Command::SilenceMedia {
                    call_id: "relay-1".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "silence needs a media call"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_relays_rtp_then_query_and_delete() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "call-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        let far_rtp = sdp::parse(&ok_sdp_text(&offer))
            .expect("parse far")
            .remote_rtp;

        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "call-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        let near_rtp = sdp::parse(&ok_sdp_text(&answer))
            .expect("parse near")
            .remote_rtp;

        phone_a
            .send_to(&rtp(0x0A0A_0A0A), near_rtp)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A));
        assert_eq!(from, far_rtp);

        phone_b
            .send_to(&rtp(0x0B0B_0B0B), far_rtp)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, rtp(0x0B0B_0B0B));
        assert_eq!(from, near_rtp);

        // Stats: poll for packets_out to settle (counted after the forwarding send).
        let mut stats = SessionStats::default();
        for _ in 0..50 {
            if let CmdResult::Ok { stats: Some(s), .. } = engine
                .handle(
                    CLIENT,
                    Command::Query {
                        call_id: "call-1".into(),
                        from_tag: "tag-a".into(),
                        to_tag: None,
                    },
                )
                .await
            {
                stats = s;
            }
            if stats.packets_out == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(stats.packets_in, 2);
        assert_eq!(stats.packets_out, 2);

        let delete = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "call-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_relays_rtp_over_ipv6_loopback() {
        // End-to-end on IPv6 (RFC 4566 §5.7 `c=IN IP6`): an `IN IP6 ::1` offer/answer must allocate
        // v6 engine endpoints, advertise `c=IN IP6`, and relay RTP between two `::1` phones. Mirrors
        // `offer_answer_relays_rtp_then_query_and_delete` on v6 loopback. `::1` binds in this
        // environment (verified), so this test runs unconditionally; it would only need gating on a
        // host without an IPv6 loopback.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone_v6().await;
        let (phone_b, addr_b) = phone_v6().await;

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "call-v6".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        let offer_sdp = ok_sdp_text(&offer);
        assert!(
            offer_sdp.contains("c=IN IP6 ::1"),
            "v6 offer rewrite: {offer_sdp}"
        );
        let far_rtp = sdp::parse(&offer_sdp).expect("parse far").remote_rtp;
        assert!(far_rtp.is_ipv6(), "the far engine endpoint is v6");

        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "call-v6".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        let answer_sdp = ok_sdp_text(&answer);
        assert!(
            answer_sdp.contains("c=IN IP6 ::1"),
            "v6 answer rewrite: {answer_sdp}"
        );
        let near_rtp = sdp::parse(&answer_sdp).expect("parse near").remote_rtp;
        assert!(near_rtp.is_ipv6(), "the near engine endpoint is v6");

        // A -> engine -> B over v6 loopback.
        phone_a
            .send_to(&rtp(0x0A0A_0A0A), near_rtp)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A));
        assert_eq!(from, far_rtp);

        // B -> engine -> A over v6 loopback.
        phone_b
            .send_to(&rtp(0x0B0B_0B0B), far_rtp)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, rtp(0x0B0B_0B0B));
        assert_eq!(from, near_rtp);

        let delete = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "call-v6".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn companion_rtcp_relays_on_separate_ports() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        // RTP + RTCP sockets per phone (RTCP is the RTP port's logical +1 peer; here just sockets).
        let (rtp_a, addr_rtp_a) = phone().await;
        let (rtcp_a, addr_rtcp_a) = phone().await;
        let (rtp_b, addr_rtp_b) = phone().await;
        let (rtcp_b, addr_rtcp_b) = phone().await;

        // Build offers whose a=rtcp points at the dedicated RTCP socket.
        let offer_sdp = format!(
            "v=0\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=rtcp:{}\r\n",
            addr_rtp_a.port(),
            addr_rtcp_a.port()
        );
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "rtcp-call".into(),
                    from_tag: "a".into(),
                    sdp: offer_sdp,
                    profile: Default::default(),
                },
            )
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        assert_ne!(
            far.remote_rtcp.port(),
            far.remote_rtp.port() + 1,
            "engine RTCP is its own port"
        );

        let answer_sdp = format!(
            "v=0\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=rtcp:{}\r\n",
            addr_rtp_b.port(),
            addr_rtcp_b.port()
        );
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "rtcp-call".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: answer_sdp,
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // RTP relays on the RTP ports.
        rtp_a
            .send_to(&rtp(0x0A0A_0A0A), near.remote_rtp)
            .await
            .expect("rtp a");
        assert_eq!(recv(&rtp_b).await.0, rtp(0x0A0A_0A0A));

        // RTCP relays on the dedicated RTCP ports (RTCP SR, first byte 0x80 / PT 200).
        let rtcp_sr = vec![0x80u8, 0xC8, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44];
        rtcp_a
            .send_to(&rtcp_sr, near.remote_rtcp)
            .await
            .expect("rtcp a");
        let (data, from) = recv(&rtcp_b).await;
        assert_eq!(data, rtcp_sr);
        assert_eq!(
            from, far.remote_rtcp,
            "B's RTCP arrives from the engine far-RTCP port"
        );

        let _ = (addr_rtcp_a, addr_rtcp_b);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtcp_mux_relays_both_on_one_port() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "mux".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        assert!(far.rtcp_mux);
        assert!(
            !ok_sdp_text(&offer).contains("a=rtcp:"),
            "no companion port advertised under mux"
        );

        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "mux".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // Both an RTP-looking and an RTCP-looking datagram relay over the single muxed port.
        phone_a
            .send_to(b"\x80\x00rtp", near.remote_rtp)
            .await
            .expect("rtp");
        assert_eq!(recv(&phone_b).await.0, b"\x80\x00rtp");
        phone_b
            .send_to(b"\x80\xc8rtcp", far.remote_rtp)
            .await
            .expect("rtcp");
        assert_eq!(recv(&phone_a).await.0, b"\x80\xc8rtcp");
    }

    /// An offer profile carrying an `rtcp-mux` directive list.
    fn mux_profile(directive: &str) -> ProfileFlags {
        ProfileFlags {
            rtcp_mux: vec![directive.to_string()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn rtcp_mux_offer_directive_forces_mux_and_allocates_one_far_port() {
        // rtpengine `rtcp-mux: [offer]` forces the generated (far) SDP to advertise `a=rtcp-mux`
        // (RFC 5761) and allocates a single far port — even though A's offer was NOT muxed.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "mux-offer".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false), // A did NOT offer mux
                    profile: mux_profile("offer"),
                },
            )
            .await;
        let far_sdp = ok_sdp_text(&offer);
        assert!(
            far_sdp.contains("a=rtcp-mux"),
            "offer directive forces a=rtcp-mux on the far SDP: {far_sdp}"
        );
        assert!(
            !far_sdp.contains("a=rtcp:"),
            "no companion a=rtcp port under forced mux: {far_sdp}"
        );
        let far = sdp::parse(&far_sdp).expect("far");
        assert!(far.rtcp_mux);
        assert_eq!(
            far.remote_rtcp, far.remote_rtp,
            "RTCP rides the far RTP port"
        );
    }

    #[tokio::test]
    async fn rtcp_mux_demux_directive_keeps_near_muxed_but_splits_the_far_side() {
        // rtpengine `rtcp-mux: [demux]`: A offered mux; the engine presents SEPARATE RTCP to the far
        // side (2 far ports, `a=rtcp-mux` stripped from the far SDP) while the near side stays muxed.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "mux-demux".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, true), // A offered mux
                    profile: mux_profile("demux"),
                },
            )
            .await;
        let far_sdp = ok_sdp_text(&offer);
        assert!(
            !far_sdp.contains("a=rtcp-mux"),
            "demux strips a=rtcp-mux from the far SDP: {far_sdp}"
        );
        let far = sdp::parse(&far_sdp).expect("far");
        assert!(!far.rtcp_mux, "far side demuxed");
        assert_ne!(
            far.remote_rtcp, far.remote_rtp,
            "far side has a distinct RTCP port"
        );

        // The near (A-facing) answer still advertises mux (the near side was left as offered).
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "mux-demux".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false), // B answers non-muxed on its own two ports
                    profile: mux_profile("demux"),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");
        assert!(near.rtcp_mux, "near side stays muxed toward A");
    }

    #[tokio::test]
    async fn rtcp_mux_reject_directive_forces_two_ports_both_sides() {
        // rtpengine `rtcp-mux: [reject]`: no mux either side even though A offered it — 2 far ports,
        // `a=rtcp-mux` stripped from the generated SDP.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "mux-reject".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, true), // A offered mux
                    profile: mux_profile("reject"),
                },
            )
            .await;
        let far_sdp = ok_sdp_text(&offer);
        assert!(
            !far_sdp.contains("a=rtcp-mux"),
            "reject strips a=rtcp-mux: {far_sdp}"
        );
        let far = sdp::parse(&far_sdp).expect("far");
        assert!(!far.rtcp_mux);
        assert_ne!(far.remote_rtcp, far.remote_rtp, "far RTCP on its own port");

        // The near side is demuxed too: the answer to A carries no a=rtcp-mux and a distinct port.
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "mux-reject".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: mux_profile("reject"),
                },
            )
            .await;
        let near_sdp = ok_sdp_text(&answer);
        assert!(
            !near_sdp.contains("a=rtcp-mux"),
            "near side demuxed toward A: {near_sdp}"
        );
        let near = sdp::parse(&near_sdp).expect("near");
        assert!(!near.rtcp_mux);
        assert_ne!(near.remote_rtcp, near.remote_rtp);
    }

    #[tokio::test]
    async fn answer_and_delete_unknown_call_error() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "nope".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5000 RTP/AVP 0\r\n".into(),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(matches!(answer, CmdResult::Error { .. }));

        let delete = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "nope".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(delete, CmdResult::Error { .. }));
    }

    #[tokio::test]
    async fn unsupported_command_reports_error() {
        // `authenticate` is handled by the control server, not the session engine, so the engine's
        // dispatcher reports it as unsupported and names it in the error. (SubscribeRequest is now a
        // wired SIPREC verb — see the subscribe_* tests below.)
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let result = engine
            .handle(
                CLIENT,
                Command::Authenticate {
                    token: "s3cret".into(),
                },
            )
            .await;
        match result {
            CmdResult::Error { reason } => assert!(reason.contains("authenticate")),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_request_on_a_passthrough_call_promotes_and_offers() {
        // A plain relay (same codec both sides) IS now subscribable: subscribe_request promotes it to
        // userspace and returns a send-only SDP offer advertising the source leg's codec (raw tee).
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "fork-relay".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "fork-relay".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            !engine.media().is_media_call("fork-relay"),
            "starts as a plain relay"
        );
        let result = engine
            .handle(
                CLIENT,
                Command::SubscribeRequest {
                    call_id: "fork-relay".into(),
                    from_tags: vec!["tag-a".into()],
                    sdp: None,
                    profile: Default::default(),
                },
            )
            .await;
        match result {
            CmdResult::Ok {
                sdp: Some(sdp),
                to_tag: Some(_),
                ..
            } => {
                assert!(
                    sdp.contains("a=sendonly"),
                    "send-only subscriber offer (RFC 3264)"
                );
                assert!(
                    sdp.contains("PCMU"),
                    "advertises the source leg's codec (RFC 4566)"
                );
            }
            other => panic!("expected an SDP offer, got {other:?}"),
        }
        assert!(
            engine.media().is_relay_call("fork-relay"),
            "the relay was promoted to userspace"
        );
    }

    /// Parse a libpcap byte stream into `(source, destination, udp_payload)` per record, unwrapping the
    /// synthetic Ethernet(14) + IPv4(20) + UDP(8) framing. Test-only, IPv4-only.
    fn pcap_records(bytes: &[u8]) -> Vec<(SocketAddr, SocketAddr, Vec<u8>)> {
        use std::net::Ipv4Addr;
        let mut records = Vec::new();
        let mut offset = 24; // skip the global header
        while offset + 16 <= bytes.len() {
            let incl_len =
                u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
            offset += 16;
            if offset + incl_len > bytes.len() || incl_len < 42 {
                break;
            }
            let frame = &bytes[offset..offset + incl_len];
            offset += incl_len;
            let ip = &frame[14..];
            let source_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let dest_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            let udp = &ip[20..];
            let source_port = u16::from_be_bytes([udp[0], udp[1]]);
            let dest_port = u16::from_be_bytes([udp[2], udp[3]]);
            records.push((
                SocketAddr::new(source_ip.into(), source_port),
                SocketAddr::new(dest_ip.into(), dest_port),
                udp[8..].to_vec(),
            ));
        }
        records
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_recording_promotes_a_relay_and_captures_both_legs_to_pcap() {
        // End-to-end: a plain PCMU relay is `start recording`'d → promoted to userspace → each leg's
        // RTP is captured verbatim into a `.pcap` (synthetic IP/UDP framing) → `stop recording` demotes
        // it back to the fast path. (docs/security-and-nat.md: the promoted relay re-enforces the gate.)
        use crate::srtp_bridge::run_redirect_dispatcher;
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = Engine::new(UdpLoopbackDatapath::new());
        // Route redirected datagrams to the media actor (a promoted relay uses `Redirect`).
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "rec-e2e".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let far_rtp = sdp::parse(&ok_sdp_text(&offer)).expect("far").remote_rtp;
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "rec-e2e".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let near_rtp = sdp::parse(&ok_sdp_text(&answer)).expect("near").remote_rtp;
        assert!(
            !engine.media().is_media_call("rec-e2e"),
            "starts as a plain relay"
        );

        let started = engine
            .handle(
                CLIENT,
                Command::StartRecording {
                    call_id: "rec-e2e".into(),
                    from_tag: "tag-a".into(),
                    recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                },
            )
            .await;
        assert!(matches!(started, CmdResult::Ok { .. }), "recording started");
        assert!(
            engine.media().is_relay_call("rec-e2e"),
            "the relay was promoted to userspace for recording"
        );

        // Feed one datagram each way; the promoted relay still forwards, so a receipt on the peer
        // confirms the actor processed (and therefore captured) the packet.
        phone_a
            .send_to(&rtp(0x0A0A_0A0A), near_rtp)
            .await
            .expect("a send");
        let (data, _) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A), "A→B still relayed while recording");
        phone_b
            .send_to(&rtp(0x0B0B_0B0B), far_rtp)
            .await
            .expect("b send");
        let (data, _) = recv(&phone_a).await;
        assert_eq!(data, rtp(0x0B0B_0B0B), "B→A still relayed while recording");

        // Poll the pcap until the drain task has framed both captured datagrams.
        let path = dir.path().join("rec-e2e.pcap");
        let mut bytes = Vec::new();
        for _ in 0..200 {
            if let Ok(read) = std::fs::read(&path) {
                if pcap_records(&read).len() >= 2 {
                    bytes = read;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(&bytes[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "libpcap magic");
        let records = pcap_records(&bytes);
        assert_eq!(
            records.len(),
            2,
            "both captured datagrams framed to the pcap"
        );

        // A's datagram: source = A's phone, destination = the engine's near RTP socket, payload verbatim.
        let a_record = records
            .iter()
            .find(|(source, ..)| *source == addr_a)
            .expect("A's captured datagram");
        assert_eq!(
            a_record.1, near_rtp,
            "captured destination = engine near RTP"
        );
        assert_eq!(
            a_record.2,
            rtp(0x0A0A_0A0A),
            "A's RTP captured byte-for-byte"
        );
        let b_record = records
            .iter()
            .find(|(source, ..)| *source == addr_b)
            .expect("B's captured datagram");
        assert_eq!(b_record.1, far_rtp, "captured destination = engine far RTP");
        assert_eq!(
            b_record.2,
            rtp(0x0B0B_0B0B),
            "B's RTP captured byte-for-byte"
        );

        // Stop recording: the relay is demoted back to the in-kernel Forward fast path.
        let stopped = engine
            .handle(
                CLIENT,
                Command::StopRecording {
                    call_id: "rec-e2e".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await;
        assert!(matches!(stopped, CmdResult::Ok { .. }), "recording stopped");
        assert!(
            !engine.media().is_relay_call("rec-e2e") && !engine.media().is_media_call("rec-e2e"),
            "the relay was demoted back to the fast path once recording stopped"
        );
    }

    #[tokio::test]
    async fn start_recording_rejects_a_secure_call_and_unknown_call() {
        // A secure (SRTP-bridge) call's on-the-wire bytes are ciphertext, so a raw pcap of them is
        // useless — `start recording` must reject it (mirrors `subscribe_request`). An unknown call errors.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "savp-rec".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags {
                        transport_protocol: Some("RTP/SAVP".into()),
                        ..Default::default()
                    },
                },
            )
            .await;
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "savp-rec".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: savp_answer_sdp(addr_b, &b_key),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let secure = engine
            .handle(
                CLIENT,
                Command::StartRecording {
                    call_id: "savp-rec".into(),
                    from_tag: "tag-a".into(),
                    recording_dir: Some("/tmp".into()),
                },
            )
            .await;
        assert!(
            matches!(secure, CmdResult::Error { .. }),
            "recording a secure call is rejected"
        );

        let unknown = engine
            .handle(
                CLIENT,
                Command::StartRecording {
                    call_id: "nope".into(),
                    from_tag: "f".into(),
                    recording_dir: Some("/tmp".into()),
                },
            )
            .await;
        assert!(
            matches!(unknown, CmdResult::Error { .. }),
            "unknown call ⇒ error"
        );
    }

    /// Offer + answer a plain PCMU relay (both sides same codec ⇒ passthrough), with a live redirect
    /// dispatcher so a promoted relay's Redirect datagrams reach its actor. Returns the engine.
    async fn plain_relay_engine(
        call_id: &str,
        addr_a: SocketAddr,
        addr_b: SocketAddr,
    ) -> Engine<UdpLoopbackDatapath> {
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        engine
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn block_dtmf_promotes_a_relay_and_unblock_demotes_it_back() {
        // `block DTMF` on a plain relay promotes it to userspace (so the actor can gate the
        // telephone-event PT); `unblock DTMF` with no other hold demotes it back to the fast path.
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let engine = plain_relay_engine("bd-1", addr_a, addr_b).await;
        assert!(
            !engine.media().is_media_call("bd-1"),
            "starts as a plain relay"
        );

        let blocked = engine
            .handle(
                CLIENT,
                Command::BlockDtmf {
                    call_id: "bd-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(blocked, CmdResult::Ok { .. }), "block DTMF ok");
        assert!(
            engine.media().is_relay_call("bd-1"),
            "the relay was promoted to userspace for the DTMF block"
        );

        let unblocked = engine
            .handle(
                CLIENT,
                Command::UnblockDtmf {
                    call_id: "bd-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(unblocked, CmdResult::Ok { .. }), "unblock DTMF ok");
        assert!(
            !engine.media().is_relay_call("bd-1") && !engine.media().is_media_call("bd-1"),
            "the relay was demoted back to the fast path once the DTMF block cleared"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echo_promotes_a_passthrough_reflects_audio_then_disable_demotes() {
        // A single-leg IVR/echo call is a plain passthrough relay. `echo enabled=true` must promote it
        // into a *processing* MediaCall (decode → re-encode) and loop the caller's audio straight back;
        // `echo enabled=false` releases the hold and demotes it to the in-kernel Forward fast path.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        tokio::spawn(run_redirect_dispatcher(
            engine.datapath().rx(),
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        let (phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "echo-1".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        // The engine's A-facing endpoint is advertised in the answer's returned SDP — A sends there.
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "echo-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let engine_near = sdp::parse(&ok_sdp_text(&answer))
            .expect("engine near SDP")
            .remote_rtp;
        assert!(
            !engine.media().is_media_call("echo-1"),
            "starts as a plain in-kernel relay"
        );

        let enabled = engine
            .handle(
                CLIENT,
                Command::Echo {
                    call_id: "echo-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                    enabled: true,
                },
            )
            .await;
        assert!(
            matches!(enabled, CmdResult::Ok { .. }),
            "echo enabled ok, got {enabled:?}"
        );
        assert!(
            engine.media().is_transcoding_call("echo-1"),
            "the relay was promoted to a processing MediaCall (not relay-only)"
        );

        // A speaks µ-law toward the engine; with echo on it must come straight back to A. Retry to
        // absorb the tiny window between the control being applied and the first packet routing in.
        let mut echoed = None;
        for sequence in 0..25u16 {
            phone_a
                .send_to(&ulaw_rtp_packet(sequence, 0x1111_2222, 0xFF), engine_near)
                .await
                .expect("a send");
            let mut buffer = [0u8; 2048];
            if let Ok(Ok((len, from))) =
                timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
            {
                echoed = Some((buffer[..len].to_vec(), from));
                break;
            }
        }
        let (packet, from) = echoed.expect("phone A hears its own audio echoed back");
        assert_eq!(
            from, engine_near,
            "echo comes from the engine's A-facing port"
        );
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&packet).expect("parse echoed rtp");
        assert_eq!(
            parsed.payload_type, 0,
            "re-encoded in A's own codec (µ-law PT 0)"
        );
        // µ-law decode+encode is idempotent, so A hears exactly the bytes it sent.
        assert_eq!(
            parsed.payload,
            &[0xFFu8; 160][..],
            "ingress audio reflected back verbatim"
        );

        let disabled = engine
            .handle(
                CLIENT,
                Command::Echo {
                    call_id: "echo-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                    enabled: false,
                },
            )
            .await;
        assert!(
            matches!(disabled, CmdResult::Ok { .. }),
            "echo disabled ok, got {disabled:?}"
        );
        assert!(
            !engine.media().is_media_call("echo-1"),
            "demoted back to the in-kernel Forward fast path once echo cleared"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echo_on_a_transcoding_call_works_and_does_not_demote_it() {
        // A genuine transcode call (PCMU ↔ PCMA) already has a processing actor; echo must engage on it
        // as-is (no double-promote) and, when disabled, must NOT demote it — a transcode call has no
        // in-kernel Forward rules to fall back to (`relay_flows` is empty), so it stays in userspace.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "echo-tc".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true), // PCMU primary
                    profile: Default::default(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "echo-tc".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_with_conn(addr_b.ip(), addr_b.port(), 8, "PCMA"), // PCMA ⇒ transcode
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            engine.media().is_transcoding_call("echo-tc"),
            "PCMU↔PCMA answered as a transcode call"
        );

        let enabled = engine
            .handle(
                CLIENT,
                Command::Echo {
                    call_id: "echo-tc".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                    enabled: true,
                },
            )
            .await;
        assert!(matches!(enabled, CmdResult::Ok { .. }), "echo enabled ok");
        assert!(
            engine.media().is_transcoding_call("echo-tc"),
            "still the same transcode call — not double-promoted"
        );

        let disabled = engine
            .handle(
                CLIENT,
                Command::Echo {
                    call_id: "echo-tc".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                    enabled: false,
                },
            )
            .await;
        assert!(matches!(disabled, CmdResult::Ok { .. }), "echo disabled ok");
        assert!(
            engine.media().is_transcoding_call("echo-tc"),
            "a genuine transcode call is never demoted when echo clears"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echo_from_a_non_owner_is_rejected_and_leaves_the_call_untouched() {
        // Only the owning client may control a call (docs §5). A non-owner gets `unknown call` and the
        // relay is left on the fast path — echo never promotes a call for a client that does not own it.
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let engine = plain_relay_engine("echo-own", addr_a, addr_b).await;

        let rejected = engine
            .handle(
                ClientId(2), // not the owner (CLIENT == ClientId(1))
                Command::Echo {
                    call_id: "echo-own".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                    enabled: true,
                },
            )
            .await;
        assert!(
            matches!(rejected, CmdResult::Error { reason } if reason.contains("unknown call")),
            "a non-owning client gets unknown_call"
        );
        assert!(
            !engine.media().is_media_call("echo-own"),
            "the call was not promoted for a non-owner"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recording_and_block_dtmf_reason_set_holds_the_relay_until_both_release() {
        // The whole point of the promotion reason set: on one relay, start recording AND block DTMF;
        // releasing only one keeps the call promoted; releasing both demotes it back to the fast path.
        let dir = tempfile::tempdir().expect("tempdir");
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let engine = plain_relay_engine("bd-2", addr_a, addr_b).await;

        engine
            .handle(
                CLIENT,
                Command::StartRecording {
                    call_id: "bd-2".into(),
                    from_tag: "tag-a".into(),
                    recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::BlockDtmf {
                    call_id: "bd-2".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            engine.media().is_relay_call("bd-2"),
            "promoted while both recording and DTMF-block hold it"
        );

        // Release only the DTMF block: still held up by the recording.
        engine
            .handle(
                CLIENT,
                Command::UnblockDtmf {
                    call_id: "bd-2".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            engine.media().is_relay_call("bd-2"),
            "still promoted — the recording hold remains"
        );

        // Release the recording too: now nothing holds it, so it demotes back.
        engine
            .handle(
                CLIENT,
                Command::StopRecording {
                    call_id: "bd-2".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await;
        assert!(
            !engine.media().is_relay_call("bd-2") && !engine.media().is_media_call("bd-2"),
            "demoted once both the recording and the DTMF-block holds cleared"
        );
    }

    #[tokio::test]
    async fn block_dtmf_rejects_a_secure_call_and_unknown_call() {
        // A plain SRTP-bridge call's DTMF is ciphertext on the wire, not clear telephone-events, so
        // `block DTMF` must reject it (same guard as recording / subscribe_request). Unknown ⇒ error.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "bd-savp".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags {
                        transport_protocol: Some("RTP/SAVP".into()),
                        ..Default::default()
                    },
                },
            )
            .await;
        let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "bd-savp".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: savp_answer_sdp(addr_b, &b_key),
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let secure = engine
            .handle(
                CLIENT,
                Command::BlockDtmf {
                    call_id: "bd-savp".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(secure, CmdResult::Error { .. }),
            "block DTMF on a secure (SRTP) call is rejected"
        );

        let unknown = engine
            .handle(
                CLIENT,
                Command::BlockDtmf {
                    call_id: "nope".into(),
                    from_tag: "f".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(unknown, CmdResult::Error { .. }),
            "unknown call ⇒ error"
        );
    }

    #[tokio::test]
    async fn subscribe_request_on_an_unknown_call_is_unknown() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let result = engine
            .handle(
                CLIENT,
                Command::SubscribeRequest {
                    call_id: "nope".into(),
                    from_tags: vec!["f".into()],
                    sdp: None,
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "unknown call ⇒ error"
        );
    }

    #[tokio::test]
    async fn stop_media_on_unknown_call_errors() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let result = engine
            .handle(
                CLIENT,
                Command::StopMedia {
                    call_id: "nope".into(),
                    from_tag: "f".into(),
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "unknown call ⇒ error"
        );
    }

    /// A test phone bound to a specific loopback address, so the engine's signalled-source gate can
    /// be exercised with distinct peers (127.0.0.0/8 is all loopback on Linux).
    async fn phone_at(ip: Ipv4Addr) -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((ip, 0)).await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        (socket, addr)
    }

    /// A minimal RTP packet (V=2, PT=0/PCMU) carrying `ssrc` (RFC 3550 §5.1).
    fn rtp(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"audio");
        packet
    }

    /// A plaintext `RTP/AVP` offer at a fixed RFC 5737 TEST-NET-3 address. The offer control path
    /// never sends media, so no live socket is needed — only a parseable SDP body.
    fn plain_offer_sdp() -> &'static str {
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 203.0.113.7\r\n",
            "s=-\r\n",
            "c=IN IP4 203.0.113.7\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0 8\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        )
    }

    /// A plaintext offer that additionally carries ICE (`a=ice-ufrag`/`a=ice-pwd`/`a=candidate`),
    /// used to prove `ice: remove` strips the peer's ICE.
    fn plain_ice_offer_sdp() -> &'static str {
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 203.0.113.7\r\n",
            "s=-\r\n",
            "c=IN IP4 203.0.113.7\r\n",
            "t=0 0\r\n",
            "a=ice-ufrag:PEERUF\r\n",
            "a=ice-pwd:peerpassword01234567\r\n",
            "m=audio 30000 RTP/AVP 0 8\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ host\r\n",
        )
    }

    /// A DTLS-SRTP offer (`UDP/TLS/RTP/SAVPF`) carrying `a=setup`/`a=fingerprint`, used to prove
    /// `dtls: off` downgrades the far leg to plaintext and strips the DTLS keying.
    fn dtls_offer_sdp() -> &'static str {
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 203.0.113.7\r\n",
            "s=-\r\n",
            "c=IN IP4 203.0.113.7\r\n",
            "t=0 0\r\n",
            "m=audio 30000 UDP/TLS/RTP/SAVPF 0 8\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=setup:actpass\r\n",
            "a=fingerprint:sha-256 ",
            "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n",
        )
    }

    /// Drive an `offer` with `profile` and return the rewritten far-offer SDP text.
    async fn offer_far_sdp(sdp: &str, profile: ProfileFlags) -> String {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ice-dtls-profile".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp.to_string(),
                    profile,
                },
            )
            .await;
        ok_sdp_text(&offer)
    }

    #[tokio::test]
    async fn offer_dtls_off_downgrades_far_leg_to_plaintext() {
        // rtpengine DTLS=off (RFC 3264): a UDP/TLS far transport plus `dtls: off` yields plaintext
        // RTP/AVP with the offer's DTLS keying stripped — no `a=fingerprint`/`a=setup`.
        let far = offer_far_sdp(
            dtls_offer_sdp(),
            ProfileFlags {
                transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                dtls: Some("off".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(far.contains("RTP/AVP"), "{far}");
        assert!(!far.contains("UDP/TLS"), "{far}");
        assert!(!far.contains("a=fingerprint"), "{far}");
        assert!(!far.contains("a=setup"), "{far}");
        let parsed = sdp::parse(&far).expect("parse far offer");
        assert!(!parsed.dtls, "far leg is plaintext");
        assert!(!parsed.secure, "far leg is not SAVP");
    }

    #[tokio::test]
    async fn offer_dtls_passive_sets_setup_role() {
        // RFC 4145 §4 / RFC 5763 §5: `dtls: passive` makes the engine the DTLS server (a=setup:passive)
        // instead of the default offerer role `actpass`.
        let far = offer_far_sdp(
            plain_offer_sdp(),
            ProfileFlags {
                transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                dtls: Some("passive".into()),
                ..Default::default()
            },
        )
        .await;
        let parsed = sdp::parse(&far).expect("parse far offer");
        assert!(parsed.dtls, "far leg advertises DTLS-SRTP");
        assert_eq!(parsed.setup, Some(sdp::Setup::Passive), "{far}");
        assert!(parsed.fingerprint.is_some(), "engine fingerprint present");
    }

    #[tokio::test]
    async fn offer_dtls_active_sets_setup_role() {
        // `dtls: active` makes the engine the DTLS client (a=setup:active).
        let far = offer_far_sdp(
            plain_offer_sdp(),
            ProfileFlags {
                transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                dtls: Some("active".into()),
                ..Default::default()
            },
        )
        .await;
        let parsed = sdp::parse(&far).expect("parse far offer");
        assert_eq!(parsed.setup, Some(sdp::Setup::Active), "{far}");
    }

    #[tokio::test]
    async fn offer_ice_force_advertises_ice_on_non_ice_offer() {
        // rtpengine ICE=force (RFC 8445): the engine advertises ICE-lite even though the offer carried
        // none — its own `a=ice-ufrag`/`a=ice-pwd` + host candidate, not the peer's.
        let far = offer_far_sdp(
            plain_offer_sdp(),
            ProfileFlags {
                ice: Some("force".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(far.contains("a=ice-lite"), "{far}");
        assert!(far.contains("a=ice-ufrag:"), "{far}");
        assert!(far.contains("a=ice-pwd:"), "{far}");
        assert!(far.contains("typ host"), "engine host candidate: {far}");
        let parsed = sdp::parse(&far).expect("parse far offer");
        assert!(parsed.is_ice(), "far offer carries ICE");
    }

    #[tokio::test]
    async fn offer_ice_remove_strips_peer_ice_without_re_originating() {
        // rtpengine ICE=remove (RFC 8839 §5): strip the offerer's ICE and advertise none of our own.
        let far = offer_far_sdp(
            plain_ice_offer_sdp(),
            ProfileFlags {
                ice: Some("remove".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(!far.contains("a=ice-ufrag"), "{far}");
        assert!(!far.contains("a=ice-pwd"), "{far}");
        assert!(!far.contains("a=candidate"), "{far}");
        assert!(!far.contains("PEERUF"), "peer ufrag stripped: {far}");
        assert!(!far.contains("a=ice-lite"), "nothing re-originated: {far}");
        let parsed = sdp::parse(&far).expect("parse far offer");
        assert!(!parsed.is_ice(), "far offer carries no ICE");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dtls_srtp_offer_answer_bridges_media_end_to_end() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        use bytes::Bytes;
        use siphon_rtp_dtls::{handshake, DtlsCertificate, DtlsRole, DtlsTransport};
        use std::time::Duration;
        use tokio::time::timeout;

        // Full control-plane path: A offers plaintext + a DTLS far-leg profile, the engine advertises
        // its fingerprint to B, B answers with its own fingerprint, the engine stands up the DTLS
        // bridge, B completes the handshake, and B's SRTP is relayed to A as plaintext.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        tokio::spawn(run_redirect_dispatcher(
            engine.datapath().rx(),
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));

        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await; // plain caller A
        let peer_b = Arc::new(
            UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
                .await
                .expect("bind b"),
        );
        let addr_b = peer_b.local_addr().expect("addr b");

        // A offers plaintext; the profile requests a DTLS-SRTP far leg.
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "dtls-e2e".into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: ProfileFlags {
                        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                        ..Default::default()
                    },
                },
            )
            .await;
        let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
        assert!(offer_reply.dtls, "engine advertised UDP/TLS/RTP/SAVPF to B");
        assert_eq!(offer_reply.setup, Some(sdp::Setup::Actpass));
        let engine_fingerprint = offer_reply
            .fingerprint
            .clone()
            .expect("engine a=fingerprint");
        let engine_far = offer_reply.remote_rtp; // where B sends toward the engine

        // B answers DTLS with its own fingerprint and `setup:active` (so the engine is DTLS server).
        let peer_cert = DtlsCertificate::generate().expect("peer cert");
        let peer_fingerprint = peer_cert.fingerprint();
        let peer_hex = peer_fingerprint
            .bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let answer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
             a=setup:active\r\na=fingerprint:{hash} {peer_hex}\r\n",
            ip = addr_b.ip(),
            port = addr_b.port(),
            hash = peer_fingerprint.hash_function,
        );
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "dtls-e2e".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: answer_sdp,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        assert!(
            matches!(answer, CmdResult::Ok { .. }),
            "answer ok: {answer:?}"
        );

        // B drives its side of the DTLS handshake (client) against the engine's far endpoint.
        let (b_transport, b_channels) = DtlsTransport::new(addr_b, engine_far);
        let reader = {
            let socket = peer_b.clone();
            let inbound = b_channels.inbound;
            tokio::spawn(async move {
                let mut buffer = [0u8; 2048];
                while let Ok((len, _)) = socket.recv_from(&mut buffer).await {
                    if inbound
                        .send_async(Bytes::copy_from_slice(&buffer[..len]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
        };
        let writer = {
            let socket = peer_b.clone();
            let outbound = b_channels.outbound;
            tokio::spawn(async move {
                while let Ok(record) = outbound.recv_async().await {
                    if socket.send_to(&record, engine_far).await.is_err() {
                        break;
                    }
                }
            })
        };
        let engine_fingerprint = siphon_rtp_dtls::Fingerprint::new(
            engine_fingerprint.hash_function,
            engine_fingerprint.bytes,
        );
        let mut peer_leg = timeout(
            Duration::from_secs(5),
            handshake(
                Arc::new(b_transport),
                &peer_cert,
                DtlsRole::Client,
                &engine_fingerprint,
            ),
        )
        .await
        .expect("handshake did not time out")
        .expect("peer handshake");
        reader.abort();
        writer.abort();

        // B → engine SRTP is decrypted and relayed to A as plaintext. Retry to absorb the tiny window
        // between B finishing and the engine installing its leg.
        let media = rtp(0x0B0B_0B0B);
        let mut sealed = Vec::new();
        let mut relayed = None;
        for _ in 0..25 {
            sealed.clear();
            peer_leg.protect(&media, &mut sealed).expect("peer protect");
            peer_b.send_to(&sealed, engine_far).await.expect("b send");
            let mut buffer = [0u8; 2048];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
            {
                relayed = Some(buffer[..len].to_vec());
                break;
            }
        }
        assert_eq!(
            relayed.expect("phone A received the relayed media"),
            media,
            "B's DTLS-SRTP media is decrypted and relayed to A"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_answer_gates_out_an_off_path_rtpbleed_source() {
        // End-to-end: the engine must install a signalled-source gate from the SDP, so an attacker
        // on another address cannot latch the media even if it sprays the port first.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "rtpbleed".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");

        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "rtpbleed".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // Attacker sprays the A-facing port first — gated out, never reaches B.
        attacker
            .send_to(&rtp(0xAAAA_AAAA), near.remote_rtp)
            .await
            .expect("attacker send");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(150), phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "off-path attacker must be gated out end-to-end (RTPBleed)"
        );

        // The signalled peer A flows to B.
        phone_a
            .send_to(&rtp(0x1234_5678), near.remote_rtp)
            .await
            .expect("peer send");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x1234_5678));
        assert_eq!(
            from, far.remote_rtp,
            "B sees media from the engine far-RTP port"
        );
    }

    /// A single-codec (PCMU) SDP whose `c=` connection address is `conn` but whose media port is
    /// `port` — so the signalled source and the real socket can differ (the NAT case: a private `c=`
    /// with media arriving from a public address). `codec_pt`/`codec_name` pick the audio codec.
    fn sdp_with_conn(conn: IpAddr, port: u16, codec_pt: u8, codec_name: &str) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {conn}\r\ns=-\r\nc=IN IP4 {conn}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {codec_pt}\r\na=rtpmap:{codec_pt} {codec_name}/8000\r\na=rtcp-mux\r\n",
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn received_from_tightens_the_near_leg_gate_to_the_public_source() {
        // The NAT case: A advertises a *private/documentation* `c=` (203.0.113.2) that its media will
        // never actually come from, but the SIP proxy tells us (`received-from`) the real public
        // source is 127.0.0.2. The engine must gate the near leg to 127.0.0.2 — a TIGHTER RTPBleed
        // gate than the unusable signalled address (docs/security-and-nat.md §4 layer 2), so A's real
        // media flows while an off-path attacker is dropped.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;

        // A's offer advertises the documentation address 203.0.113.2 (unusable), real port = phone_a.
        let offer_sdp = sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            addr_a.port(),
            0,
            "PCMU",
        );
        let profile = ProfileFlags {
            received_from: Some(addr_a.ip()), // the proxy-observed public source
            ..Default::default()
        };
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "recvfrom".into(),
                    from_tag: "a".into(),
                    sdp: offer_sdp,
                    profile,
                },
            )
            .await;
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "recvfrom".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // An attacker on 127.0.0.9 sprays A's port — gated out by the received-from-tightened gate.
        attacker
            .send_to(&rtp(0xAAAA_AAAA), near.remote_rtp)
            .await
            .expect("attacker send");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(150), phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "off-path source gated out even though it raced the port first"
        );

        // A's real media (from the received-from IP) flows to B.
        phone_a
            .send_to(&rtp(0x1234_5678), near.remote_rtp)
            .await
            .expect("peer send");
        let (data, _from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x1234_5678), "received-from source flows through");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn received_from_tightens_the_transcode_media_gate() {
        // The same override must reach the media (transcode) slow path's `accepted_source`: A offers
        // PCMU behind a documentation `c=`, B answers PCMA (⇒ transcode). The near direction gates on
        // the received-from IP, so an off-path source is dropped by the media actor, not just the
        // datapath Forward gate.
        use crate::srtp_bridge::run_redirect_dispatcher;
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let rx = engine.datapath().rx();
        tokio::spawn(run_redirect_dispatcher(
            rx,
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;

        // A advertises the documentation address 203.0.113.2 (unusable); its real media socket is
        // phone_a, and the proxy-observed public source is passed as received-from.
        let offer_sdp = sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            addr_a.port(),
            0,
            "PCMU",
        );
        let profile = ProfileFlags {
            received_from: Some(addr_a.ip()),
            ..Default::default()
        };
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "recvfrom-media".into(),
                    from_tag: "a".into(),
                    sdp: offer_sdp,
                    profile,
                },
            )
            .await;
        // B answers PCMA only → near=PCMU, far=PCMA → transcode media path.
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "recvfrom-media".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // Off-path attacker → the media actor's accepted_source gate drops it (nothing reaches B).
        attacker
            .send_to(&g711_rtp(0, 1, 0xAAAA_AAAA, 0xFF), near.remote_rtp)
            .await
            .expect("attacker send");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(200), phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "off-path source gated out on the transcode media path too"
        );

        // A valid PCMU frame from the received-from source transcodes to PCMA and reaches B.
        phone_a
            .send_to(&g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF), near.remote_rtp)
            .await
            .expect("a send");
        let (data, _from) = recv(&phone_b).await;
        let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&data).expect("parse");
        assert_eq!(parsed.payload_type, 8, "B receives PCMA (transcoded)");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_fails_cleanly_when_port_pool_exhausted_and_frees_on_delete() {
        // A non-mux call needs four endpoints (RTP + RTCP per leg); cap the pool at exactly four.
        let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(4));
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        let first = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "c1".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(first, CmdResult::Ok { .. }),
            "first offer fits the pool"
        );

        let second = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "c2".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(second, CmdResult::Error { .. }),
            "an exhausted pool is a clean error, not a host-FD blowout"
        );

        // Tearing down the first call frees its four ports; the second offer now fits.
        let delete = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "c1".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
        let retry = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "c2".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(retry, CmdResult::Ok { .. }),
            "freed pool admits the call"
        );
    }

    #[tokio::test]
    async fn a_call_is_private_to_its_creating_client() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_phone, addr) = phone().await;
        let owner = ClientId(10);
        let intruder = ClientId(20);

        let offer = engine
            .handle(
                owner,
                Command::Offer {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(matches!(offer, CmdResult::Ok { .. }));

        // The intruder cannot see the call: both query and delete report it as unknown.
        let query = engine
            .handle(
                intruder,
                Command::Query {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(query, CmdResult::Error { .. }),
            "non-owner query is rejected"
        );
        let delete = engine
            .handle(
                intruder,
                Command::Delete {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(delete, CmdResult::Error { .. }),
            "non-owner delete is rejected"
        );

        // The intruder's delete did nothing — the owner still has its call.
        let owner_query = engine
            .handle(
                owner,
                Command::Query {
                    call_id: "private".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(owner_query, CmdResult::Ok { .. }),
            "owner still sees its call"
        );
    }

    #[tokio::test]
    async fn per_client_call_quota_is_enforced_and_freed_on_delete() {
        let engine = Engine::with_max_calls_per_client(UdpLoopbackDatapath::new(), 1);
        let client = ClientId(7);
        let (_a, addr_a) = phone().await;
        let (_b, addr_b) = phone().await;

        let first = engine
            .handle(
                client,
                Command::Offer {
                    call_id: "q1".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(matches!(first, CmdResult::Ok { .. }));

        let second = engine
            .handle(
                client,
                Command::Offer {
                    call_id: "q2".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(second, CmdResult::Error { .. }),
            "over quota is rejected"
        );

        // Freeing the first call returns the quota slot.
        let delete = engine
            .handle(
                client,
                Command::Delete {
                    call_id: "q1".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(delete, CmdResult::Ok { .. }));
        let retry = engine
            .handle(
                client,
                Command::Offer {
                    call_id: "q2".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert!(
            matches!(retry, CmdResult::Ok { .. }),
            "freed quota admits the call"
        );
    }

    /// Pull the call-ids out of a `list` result (sorted for a stable assertion — the registry is
    /// unordered).
    fn list_call_ids(result: &CmdResult) -> Vec<String> {
        match result {
            CmdResult::List { call_ids } => {
                let mut ids = call_ids.clone();
                ids.sort();
                ids
            }
            other => panic!("expected List, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_enumerates_the_callers_calls() {
        let engine = Engine::new(UdpLoopbackDatapath::new());

        // 0 calls → an empty list.
        let empty = engine.handle(CLIENT, Command::List).await;
        assert_eq!(list_call_ids(&empty), Vec::<String>::new());

        // 1 call → that call-id.
        let (_a, addr_a) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "one".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert_eq!(
            list_call_ids(&engine.handle(CLIENT, Command::List).await),
            vec!["one".to_string()]
        );

        // N calls → all of them.
        let (_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "two".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        assert_eq!(
            list_call_ids(&engine.handle(CLIENT, Command::List).await),
            vec!["one".to_string(), "two".to_string()]
        );
    }

    #[tokio::test]
    async fn list_is_scoped_to_the_owning_client() {
        // A call is invisible to clients that do not own it (A3 — docs §5); `list` honours the same
        // ownership gate as `query`/`delete`, so it never leaks another client's call-ids.
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let owner = ClientId(10);
        let intruder = ClientId(20);
        let (_a, addr_a) = phone().await;
        engine
            .handle(
                owner,
                Command::Offer {
                    call_id: "owned".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;

        assert_eq!(
            list_call_ids(&engine.handle(owner, Command::List).await),
            vec!["owned".to_string()],
            "owner sees its own call"
        );
        assert_eq!(
            list_call_ids(&engine.handle(intruder, Command::List).await),
            Vec::<String>::new(),
            "a non-owner sees none of the owner's calls"
        );
    }

    #[tokio::test]
    async fn statistics_reports_global_counters_and_live_sessions() {
        let engine = Engine::new(UdpLoopbackDatapath::new());

        // Fresh engine → all counters zero, no live sessions.
        let fresh = engine.handle(CLIENT, Command::Statistics).await;
        assert_eq!(
            fresh,
            CmdResult::Statistics {
                statistics: EngineStatistics::default(),
            }
        );

        // One accepted offer bumps offers_total and the live sessions gauge.
        let (_a, addr_a) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "stat-call".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        // An error-producing command (unknown call delete) bumps control_errors_total.
        let _ = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "no-such-call".into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;

        let CmdResult::Statistics { statistics } = engine.handle(CLIENT, Command::Statistics).await
        else {
            panic!("expected Statistics");
        };
        assert_eq!(statistics.offers_total, 1, "one offer accepted");
        assert_eq!(statistics.answers_total, 0);
        // The failed delete counts as an accepted delete attempt *and* a control error (handle
        // records the per-command total before dispatch, then the error on the error result).
        assert_eq!(statistics.deletes_total, 1, "delete attempt counted");
        assert_eq!(
            statistics.control_errors_total, 1,
            "the unknown-call delete errored"
        );
        assert_eq!(statistics.sessions, 1, "the offered call is live");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_calls_are_reaped_and_active_ones_survive() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "c".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: Default::default(),
                },
            )
            .await;
        let _far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "c".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");
        assert_eq!(engine.session_count(), 1);

        // Advance to tick 4 (within the 5-tick window) and send media — stamps activity at tick 4.
        engine.datapath().advance_clock(4);
        phone_a
            .send_to(&rtp(0x1234_5678), near.remote_rtp)
            .await
            .expect("send");
        let _ = recv(&phone_b).await;

        // Tick 8: idle since the packet (tick 4) is 4 < 5 → recent media keeps the call alive.
        engine.datapath().advance_clock(4);
        assert!(
            engine.reap_idle(5).await.is_empty(),
            "recent media defers reaping"
        );
        assert_eq!(engine.session_count(), 1);

        // Tick 13: idle since tick 4 is 9 >= 5 → the silent call is reaped and its ports freed.
        engine.datapath().advance_clock(5);
        assert_eq!(engine.reap_idle(5).await, vec!["c".to_string()]);
        assert_eq!(engine.session_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaping_pushes_a_media_timeout_event_to_the_owner() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let client = ClientId(3);
        let events = engine.register_client(client);
        let (_phone, addr) = phone().await;

        engine
            .handle(
                client,
                Command::Offer {
                    call_id: "gone".into(),
                    from_tag: "ft".into(),
                    sdp: sdp_for(addr, false),
                    profile: Default::default(),
                },
            )
            .await;

        engine.datapath().advance_clock(10);
        assert_eq!(engine.reap_idle(5).await, vec!["gone".to_string()]);

        let event = events.try_recv().expect("a media-timeout event was pushed");
        assert_eq!(
            event,
            Event::MediaTimeout {
                call_id: "gone".into(),
                from_tag: "ft".into()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_offer_advertises_lite_and_the_endpoint_answers_checks() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;

        // A offers ICE.
        let offer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:AAAAAA\r\na=ice-pwd:apasswordapasswordapas\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
            ip = addr_a.ip(),
            port = addr_a.port()
        );
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "ice".into(),
                    from_tag: "a".into(),
                    sdp: offer_sdp,
                    profile: Default::default(),
                },
            )
            .await;
        let offer_out = ok_sdp_text(&offer);
        assert!(
            offer_out.contains("a=ice-lite"),
            "engine offers ICE-lite to B"
        );
        // The engine's advertised credentials (the same identity it installs on the endpoints).
        let advertised = sdp::parse(&offer_out).expect("parse engine offer");
        let engine_ufrag = advertised.ice_ufrag.clone().expect("engine ufrag");
        let engine_pwd = advertised.ice_pwd.clone().expect("engine pwd");

        // B answers with plain RTP (non-ICE).
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "ice".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile: Default::default(),
                },
            )
            .await;
        let answer_out = ok_sdp_text(&answer);
        assert!(
            answer_out.contains("a=ice-lite"),
            "engine offers ICE-lite to A"
        );
        let near = sdp::parse(&answer_out).expect("parse engine answer");

        // A runs a valid connectivity check against the engine's A-facing endpoint, signed with the
        // engine's advertised password.
        let username = format!("{engine_ufrag}:AAAAAA");
        let check = siphon_rtp_stun::binding_request(&[7u8; 12], &username, engine_pwd.as_bytes());
        phone_a
            .send_to(&check, near.remote_rtp)
            .await
            .expect("send check");

        // The endpoint answers with a Binding success response we can verify with the engine pwd.
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv response");
        let response = siphon_rtp_stun::parse(&buffer[..len]).expect("parse response");
        assert_eq!(response.message_type, siphon_rtp_stun::BINDING_SUCCESS);
        assert!(siphon_rtp_stun::verify_message_integrity(
            &buffer[..len],
            engine_pwd.as_bytes()
        ));
    }

    /// An SDP whose `c=` claims `ip` (not necessarily where its media actually arrives from).
    fn sdp_claiming(ip: &str, port: u16) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subnet_source_flag_admits_a_same_24_source() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        // A is signalled as 127.0.0.2 but its media actually arrives from 127.0.0.50 (same /24, e.g.
        // a carrier that re-NATs within a block); B is signalled at its real address.
        let (phone_a, _addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 50)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 51)).await;
        let profile = ProfileFlags {
            flags: vec!["subnet-source".to_string()],
            ..Default::default()
        };

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "subnet".into(),
                    from_tag: "a".into(),
                    sdp: sdp_claiming("127.0.0.2", 5000),
                    profile: profile.clone(),
                },
            )
            .await;
        let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");

        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "subnet".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, false),
                    profile,
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // 127.0.0.50 shares 127.0.0.0/24 with the signalled 127.0.0.2, so the subnet gate accepts it
        // (an exact gate would reject) and A's media relays to B.
        phone_a
            .send_to(&rtp(0x00AB_00AB), near.remote_rtp)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x00AB_00AB));
        assert_eq!(from, far.remote_rtp);
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relayed_rtcp_is_exported_to_the_hep_collector() {
        let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));

        // Stand in for VoIPmonitor's HEP input with a loopback UDP socket.
        let collector = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let collector_addr = collector.local_addr().expect("collector addr");
        let exporter = HepExporter::connect(collector_addr).await.expect("connect");
        tokio::spawn(engine.clone().run_rtcp_export(exporter, 7));
        // Let the export task enable the RTCP observation tap before any media flows.
        tokio::task::yield_now().await;

        // A muxed call (RTCP rides the RTP port), so one send exercises the path.
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "qos".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let _far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "qos".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // A sends an RTCP SR through the relay (mux: on the near RTP port).
        let report = vec![0x80u8, 200, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44];
        phone_a
            .send_to(&report, near.remote_rtp)
            .await
            .expect("send rtcp");
        assert_eq!(recv(&phone_b).await.0, report, "RTCP relays to B");

        // The HEP collector receives a HEP3 packet carrying the RTCP, correlated by call-id.
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(2), collector.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv hep");
        let packet = &buffer[..len];
        assert_eq!(&packet[..4], b"HEP3");
        assert!(
            contains_bytes(packet, &report),
            "HEP carries the relayed RTCP"
        );
        assert!(
            contains_bytes(packet, b"qos"),
            "HEP correlation id = call-id"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relayed_rtcp_reception_report_emits_call_quality_on_the_control_channel() {
        // A 2-party plain-relay call: an inbound RTCP reception report (RFC 3550 §6.4.2) surfaces as
        // an `Event::CallQuality` on the owner's control channel — keyed by `call_id`, carrying the
        // same loss/jitter/MOS the HEP QoS export derives — alongside the unchanged raw-RTCP relay.
        let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
        let events = engine.register_client(CLIENT);

        // Bring up the RTCP export tap (which also pushes the control-channel quality events).
        let collector = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let exporter = HepExporter::connect(collector.local_addr().expect("addr"))
            .await
            .expect("connect");
        tokio::spawn(engine.clone().run_rtcp_export(exporter, 7));
        tokio::task::yield_now().await;

        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "quality".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, true),
                    profile: Default::default(),
                },
            )
            .await;
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "quality".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: sdp_for(addr_b, true),
                    profile: Default::default(),
                },
            )
            .await;
        let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

        // A compound Receiver Report with one reception block: fraction_lost 13/256, jitter 160 @
        // 8 kHz (= 20 ms). RC=1, PT=201, length 7 words.
        let mut report = vec![0x81u8, 201, 0x00, 0x07];
        report.extend_from_slice(&0xAAAA_0001u32.to_be_bytes()); // reporter ssrc
        report.extend_from_slice(&0x1111_2222u32.to_be_bytes()); // reported-on ssrc
        report.push(13); // fraction lost (13/256 ≈ 5.08 %)
        report.extend_from_slice(&[0x00, 0x00, 0x02]); // cumulative lost
        report.extend_from_slice(&0u32.to_be_bytes()); // extended highest seq
        report.extend_from_slice(&160u32.to_be_bytes()); // jitter
        report.extend_from_slice(&0u32.to_be_bytes()); // LSR
        report.extend_from_slice(&0u32.to_be_bytes()); // DLSR
        phone_a
            .send_to(&report, near.remote_rtp)
            .await
            .expect("send rtcp");
        // The raw RTCP still relays verbatim to B (unchanged passthrough).
        assert_eq!(recv(&phone_b).await.0, report, "RTCP relays to B");

        // ...and the owner receives a CallQuality event derived from the reception block.
        let event = timeout(Duration::from_secs(2), events.recv_async())
            .await
            .expect("no timeout")
            .expect("event");
        match event {
            Event::CallQuality {
                conference_id,
                call_id,
                from_tag,
                jitter_ms,
                loss_percent,
                mos,
            } => {
                assert!(
                    conference_id.is_none(),
                    "a plain relay carries no conference_id"
                );
                assert_eq!(call_id.as_deref(), Some("quality"), "keyed by call_id");
                assert_eq!(from_tag, "a", "tagged by the reporting (near) leg");
                assert!(
                    (loss_percent - (13.0 / 256.0 * 100.0)).abs() < 1e-9,
                    "13/256 → 5.08 %, got {loss_percent}"
                );
                assert!(
                    (jitter_ms - 20.0).abs() < 1e-9,
                    "160 @ 8 kHz → 20 ms, got {jitter_ms}"
                );
                assert!(mos > 1.0 && mos < 4.5, "plausible MOS, got {mos}");
            }
            other => panic!("expected CallQuality, got {other:?}"),
        }
    }
}
