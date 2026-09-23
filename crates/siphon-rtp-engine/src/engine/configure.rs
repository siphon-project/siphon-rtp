//! Engine construction, builder-style configuration and read-only accessors.

use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_dtls::DtlsCertificate;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cluster::ClusterState;
use crate::conference::ConferenceRegistry;
use crate::dtls_bridge::DtlsBridge;
use crate::ice::driver::{AgentSupervisor, ConsentSupervisor};
use crate::interface::InterfaceTable;
use crate::media_fetch::MediaFetchLimits;
use crate::media_pipeline::MediaRegistry;
use crate::metrics::Metrics;
use crate::srtp_bridge::SrtpBridge;
use crate::text_pipeline::TextRegistry;
use crate::udptl_pipeline::UdptlRegistry;
use crate::ws_bridge::WsRegistry;
use crate::x3::X3Config;

use super::{Engine, TurnServerConfig};

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
            next_client_generation: std::sync::atomic::AtomicU64::new(0),
            controllers: DashMap::new(),
            controller_ids: DashMap::new(),
            endpoint_calls: DashMap::new(),
            bridge,
            media: Arc::new(MediaRegistry::default()),
            ws: Arc::new(WsRegistry::default()),
            conference: Arc::new(ConferenceRegistry::default()),
            seat_ice_followers: DashMap::new(),
            text: Arc::new(TextRegistry::default()),
            udptl: Arc::new(UdptlRegistry::default()),
            subscriptions: DashMap::new(),
            metrics: Arc::new(Metrics::new()),
            cluster: Arc::new(ClusterState::new("siphon-rtp".to_string(), 0, Vec::new())),
            dtls_certificate,
            ws_tls_config: std::sync::OnceLock::new(),
            // Zero-config default: one loopback interface with no advertised override, so a leg
            // advertises exactly the address the datapath bound (behaviour-preserving for tests).
            interfaces: Arc::new(InterfaceTable::single(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                None,
            )),
            // Start at 1 so a `play_id` of 0 never appears (a controller can treat 0 as "no play").
            play_id_counter: std::sync::atomic::AtomicU64::new(1),
            media_fetch_limits: MediaFetchLimits::default(),
            pending_fetches: Arc::new(DashMap::new()),
            // Off unless the operator opts in — see `with_consent`.
            consent: None,
            ice_agents: None,
            // Host-only gathering unless the operator names a STUN server.
            stun_servers: Vec::new(),
            turn_server: None,
            ice_relays: Arc::new(DashMap::new()),
            ws_tees: DashMap::new(),
            prompts: Arc::new(crate::prompt_cache::PromptCache::new(
                DEFAULT_PROMPT_CACHE_BYTES,
            )),
            recordings: DashMap::new(),
            next_recording_id: std::sync::atomic::AtomicU64::new(1),
            ws_bridges: DashMap::new(),
            // Lawful interception is unconfigured unless the daemon supplies `x3_*`, and `attach_x3`
            // refuses while it is — never accepted and left delivering nowhere.
            x3_config: None,
            x3_tls_config: std::sync::OnceLock::new(),
            x3_sessions: DashMap::new(),
            // HEP export off unless the daemon calls `set_hep_export` from `SIPHON_RTP_HEP_COLLECTOR`.
            hep_export: std::sync::OnceLock::new(),
        }
    }

    /// Provision this node for lawful-interception content delivery (the daemon's `x3_*` config).
    ///
    /// Without it `attach_x3` is refused. Builder-style consuming setter, mirroring
    /// [`Self::with_cluster`].
    #[must_use]
    pub fn with_x3(mut self, config: X3Config) -> Self {
        self.x3_config = Some(Arc::new(config));
        self
    }

    /// Ask these STUN servers for a server-reflexive candidate when gathering (RFC 8445 §5.1.1.2).
    ///
    /// Only useful when the engine itself sits behind a NAT it cannot be addressed through — the
    /// normal deployment is a routable media address, where the host candidate is the whole story and
    /// a reflexive probe would only return the address we already advertise (and be pruned as
    /// redundant, RFC 8445 §5.1.3). Leaving this empty keeps call setup free of any network round
    /// trip. Builder-style consuming setter, mirroring [`Self::with_cluster`].
    #[must_use]
    pub fn with_stun_servers(mut self, servers: Vec<SocketAddr>) -> Self {
        self.stun_servers = servers;
        self
    }

    /// Allocate ICE **relayed** candidates against this TURN server (RFC 5766).
    ///
    /// Off unless set. A relayed candidate only earns its hop when the engine itself sits behind a
    /// NAT it cannot be addressed through; a directly-addressable engine gathers host and
    /// server-reflexive candidates and pays nothing for the relay it never uses.
    #[must_use]
    pub fn with_turn_server(mut self, config: TurnServerConfig) -> Self {
        self.turn_server = Some(config);
        self
    }

    /// The bound local address of one of a call's endpoints — where that leg's agent sources its
    /// checks from, and the local side of every pair it forms.
    pub(super) fn endpoint_address(&self, endpoint: EndpointId) -> Option<SocketAddr> {
        self.calls.iter().find_map(|entry| {
            let call = entry.value();
            [
                Some(call.near.rtp),
                call.near.rtcp,
                call.far.as_ref().map(|far| far.rtp),
                call.far.as_ref().and_then(|far| far.rtcp),
            ]
            .into_iter()
            .flatten()
            .find(|candidate| candidate.id == endpoint)
            .map(|candidate| candidate.local_addr)
        })
    }

    /// Run a full RFC 8445 ICE agent on every ICE leg instead of the ICE-lite responder: the engine
    /// forms checklists, sends connectivity checks, resolves role conflicts, discovers peer-reflexive
    /// candidates, and nominates a pair — and media only starts once a pair is selected.
    ///
    /// Off by default: `a=ice-lite` is what the engine advertises, and a lite agent is a valid and
    /// simpler posture for a server on a routable address. Builder-style consuming setter.
    /// Size the decoded-prompt cache, in bytes. `0` disables caching — every `play_media` on a file
    /// then reads and decodes it afresh, which is exactly the behaviour before the cache existed.
    ///
    /// Builder-style consuming setter, called from the daemon's `--prompt-cache-bytes`.
    #[must_use]
    pub fn with_prompt_cache_bytes(mut self, capacity_bytes: usize) -> Self {
        self.prompts = Arc::new(crate::prompt_cache::PromptCache::new(capacity_bytes));
        self
    }

    /// The decoded-prompt cache, for tests and for metrics.
    #[must_use]
    pub fn prompts(&self) -> &Arc<crate::prompt_cache::PromptCache> {
        &self.prompts
    }

    #[must_use]
    pub fn with_full_ice(mut self) -> Self {
        self.ice_agents = Some(Arc::new(AgentSupervisor::new()));
        self
    }

    /// Enable RFC 7675 consent freshness with the given cadence: every ICE leg is promoted to the
    /// datapath's full-agent seam and actively probed on its validated pair, and a peer that stops
    /// answering has its call torn down.
    ///
    /// **Off by default, deliberately.** RFC 7675 §4 is explicit that an ICE-**lite** agent does not
    /// generate consent checks, it only responds to them — and ice-lite is what the engine advertises
    /// (`a=ice-lite`) until the full agent lands. Initiating checks while advertising lite is a
    /// deviation, so it is the operator's opt-in rather than the default; the full-agent work turns it
    /// on unconditionally for legs that no longer claim lite. Builder-style consuming setter,
    /// mirroring [`Self::with_cluster`].
    #[must_use]
    pub fn with_consent(mut self, config: crate::ice::driver::ConsentConfig) -> Self {
        self.consent = Some(Arc::new(ConsentSupervisor::new(config)));
        self
    }

    /// Build (once) and return the ring-backed rustls client configuration for `wss://` WebSocket
    /// bridge dials. The trust store is seeded from the webpki-roots Mozilla CA bundle; the handshake
    /// runs on the **ring** crypto provider — the project's pure-Rust, zero-C TLS stack (never
    /// aws-lc-rs, whose default provider bundles C/asm). RFC 8446 / RFC 5246 over the RFC 6455 `wss`
    /// upgrade. Cached in a `OnceLock`, so it is built at most once and shared across every leg.
    pub(super) fn ws_tls_client_config(&self) -> Arc<rustls::ClientConfig> {
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

    /// Replace the default single-loopback interface table with the operator-configured named
    /// interfaces (`main.rs` / the XDP daemon wiring). Builder-style consuming setter, mirroring
    /// [`Self::with_cluster`]; tests keep the zero-config default.
    #[must_use]
    pub fn with_interfaces(mut self, interfaces: InterfaceTable) -> Self {
        self.interfaces = Arc::new(interfaces);
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

    /// The shared RFC 4103 text registry — handed to the redirect dispatcher so it can route
    /// text-owned endpoints' datagrams to the per-call text observers (see [`crate::text_pipeline`]).
    pub fn text(&self) -> Arc<TextRegistry> {
        self.text.clone()
    }

    /// The shared T.38 fax relay — handed to the redirect dispatcher so it can route image-owned
    /// endpoints' UDPTL datagrams to the per-call relays (see [`crate::udptl_pipeline`]).
    pub fn udptl(&self) -> Arc<UdptlRegistry> {
        self.udptl.clone()
    }

    /// Number of live calls in the session registry.
    ///
    /// Used by the memory-leak soak to confirm the registry drains on teardown, and (later) by the
    /// metrics surface as the `sessions` gauge.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.calls.len()
    }

    /// Number of stable controller identities the engine is holding.
    ///
    /// A row is retained across a control disconnect only while the identity still owns calls, so
    /// at a quiesced steady state with every call torn down this is **0**. The memory-leak soak
    /// gates on that: the retention is what keeps a reconnect able to find its own calls, and it is
    /// also the one thing here that a peer could otherwise make the engine remember without bound.
    #[must_use]
    pub fn controller_count(&self) -> usize {
        self.controllers.len()
    }

    /// Live WebSocket tees — one per teed call (the `siphon_rtp_ws_tees` gauge).
    #[must_use]
    pub fn ws_tee_count(&self) -> usize {
        self.ws_tees.len()
    }

    /// Live WebSocket **takeover** bridges — one per bridged call (the `siphon_rtp_ws_bridges`
    /// gauge). Distinct from `ws_tee_count`, and worth watching separately: a tee is a copy of a
    /// call, a takeover bridge *is* one party's far side.
    #[must_use]
    pub fn ws_bridge_count(&self) -> usize {
        self.ws_bridges.len()
    }

    /// Audio frames handed to the live tees' transports so far. Read across every live tee; a tee that
    /// has already ended has been removed, so this is a *live* sum rather than a process total.
    #[must_use]
    pub fn ws_tee_frames_sent(&self) -> u64 {
        self.ws_tees
            .iter()
            .filter_map(|tee| tee.mixer.lock().ok().map(|mixer| mixer.forwarded()))
            .sum()
    }

    /// Frames the live tees dropped because a consumer stalled. Non-zero means a WS server could not
    /// keep up — by design that costs tee frames and never the call.
    #[must_use]
    pub fn ws_tee_frames_dropped(&self) -> u64 {
        self.ws_tees
            .iter()
            .filter_map(|tee| tee.mixer.lock().ok().map(|mixer| mixer.dropped()))
            .sum()
    }

    /// Live count of transcoding calls (the media slow path minus promoted relay-only passthroughs) —
    /// the expensive subset the cluster `load` command reports.
    #[must_use]
    pub fn transcode_session_count(&self) -> usize {
        self.media.transcode_call_count()
    }

    /// Replace the default [`MediaFetchLimits`] with the operator's (`main.rs` wiring). Builder-style
    /// consuming setter, mirroring [`Self::with_cluster`].
    #[must_use]
    pub fn with_media_fetch_limits(mut self, limits: MediaFetchLimits) -> Self {
        self.media_fetch_limits = limits;
        self
    }

    /// The bounds a URL playback fetch runs under (test / observability helper).
    #[must_use]
    pub fn media_fetch_limits(&self) -> &MediaFetchLimits {
        &self.media_fetch_limits
    }

    /// How many URL playbacks are still fetching (test / observability helper).
    #[must_use]
    pub fn pending_media_fetches(&self) -> usize {
        self.pending_fetches.len()
    }
}

/// Default budget for the decoded-prompt cache: 64 MiB of samples.
///
/// Sized so an ordinary prompt library — a few dozen announcements and a hold bed, each a handful of
/// seconds at 8 kHz — fits entirely, while a directory of long files still cannot grow the daemon
/// without bound. At 8 kHz mono this is roughly an hour of audio in total.
const DEFAULT_PROMPT_CACHE_BYTES: usize = 64 * 1024 * 1024;
