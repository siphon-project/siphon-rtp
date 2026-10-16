//! Read-only census verbs: `query`, `list`, `statistics`, `load` and `node_info`.

use siphon_rtp_codec::factory;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, EngineStatistics, SessionStats};

use super::{unknown_call, ClientId, Engine};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    pub(super) fn query(&self, client: ClientId, call_id: &str) -> CmdResult {
        let Some(call) = self.calls.get(call_id) else {
            return unknown_call(call_id);
        };
        // A call is invisible to clients that do not own it (A3 — docs §5).
        if !call.admits(client, call_id) {
            return unknown_call(call_id);
        }
        let mut stats = SessionStats::default();
        for endpoint in call.endpoint_ids() {
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
            play_id: None,
            recording_id: None,
            to_tag: None,
            stats: Some(stats),
        }
    }

    /// Enumerate the live call-ids `client` owns ([`Command::List`]) — a read-only census of the
    /// session registry (rtpengine NG `list`). Scoped to the calling client: a call is invisible to
    /// clients that do not own it (A3 — docs §5), so the listing never leaks another client's
    /// call-ids. Order is unspecified (the `DashMap` is unordered). Cheap and lock-light: a sharded
    /// scan that clones only the matching keys.
    ///
    /// One scope at a time: the `call_id`s of the calls `client` created in exactly `scope`, `None`
    /// being the unscoped calls.
    ///
    /// Still the creating client's calls only, although any client naming a scope may act on a
    /// call in it. A controller reconciles this listing against its own sessions and deletes what
    /// it does not recognise, so listing a peer instance's calls would have each instance tear
    /// down the other's.
    pub(super) fn list(&self, client: ClientId, scope: Option<&str>) -> CmdResult {
        let call_ids = self
            .calls
            .iter()
            .filter(|entry| {
                entry.value().owner == client && super::scope::is_in(entry.key(), scope)
            })
            .map(|entry| super::scope::call_id(entry.key()).to_string())
            .collect();
        CmdResult::List { call_ids }
    }

    /// Read the engine's global process counters ([`Command::Statistics`]) — a read-only snapshot of
    /// the operational metrics surface (rtpengine NG `statistics`). The monotonic counters come from
    /// the shared [`Metrics`] (the same surface `/metrics` renders); `sessions` is the live registry
    /// gauge. Process-wide, not per-client — every client sees the same global figures.
    pub(super) fn statistics(&self) -> CmdResult {
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
    pub(super) fn load_snapshot(&self) -> CmdResult {
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
    pub(super) fn node_info(&self) -> CmdResult {
        CmdResult::NodeInfo {
            node: self
                .cluster
                .info(engine_version(), supported_codecs(), supported_features()),
        }
    }
}

/// This engine's software version (the daemon crate version), advertised in `node_info`.
fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The codec payload names this build can transcode, advertised in `node_info` so a dispatcher only
/// routes a call to a node that can serve its codec.
///
/// The list is not kept here. It is [`factory::available_codecs`]: every codec the factory has an
/// arm for, asked of the factory itself, which is also what the offer/answer code asks when it
/// picks a codec. A codec behind a build feature (`amr`, `g729`) is listed exactly when the feature
/// is compiled in, and one with a single direction would not be listed at all: the list has no
/// per-direction field, so advertising such a codec would let a dispatcher route a call the engine
/// then fails at setup. `telephone-event` (RFC 4733) is added because it is not a codec, the media
/// path carries it itself.
pub(super) fn supported_codecs() -> Vec<String> {
    let mut codecs: Vec<String> = factory::available_codecs()
        .into_iter()
        .map(str::to_owned)
        .collect();
    codecs.push("telephone-event".to_owned());
    codecs
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
        // A controller can tell, without trying it, whether this node understands `reoffer` — and
        // therefore whether it can renegotiate on the existing ports and restart ICE (RFC 8445 §9)
        // rather than replacing the call.
        "reoffer".to_string(),
        // We accept trickled candidates (RFC 8838); we do not send them, because gathering finishes
        // before we answer.
        "trickle".to_string(),
        "turn".to_string(),
        // A controller can tell, before it relies on it, whether this node keys a call by
        // `(scope, call_id)`. A node without the feature reads a scoped frame as an unscoped one.
        "scope".to_string(),
        // A controller can tell, before asking, whether this node writes `format: "ogg_opus"`. A
        // node without it cannot deserialize the variant, and fails the whole control frame rather
        // than recording anything.
        "record_ogg_opus".to_string(),
    ]
}
