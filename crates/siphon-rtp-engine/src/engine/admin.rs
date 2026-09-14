//! Read-only census verbs: `query`, `list`, `statistics`, `load` and `node_info`.

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, EngineStatistics, SessionStats};

use super::negotiate::OPUS_DYNAMIC_PAYLOAD_TYPE;
use super::{unknown_call, ClientId, Engine};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    pub(super) fn query(&self, client: ClientId, call_id: &str) -> CmdResult {
        let Some(call) = self.calls.get(call_id) else {
            return unknown_call(call_id);
        };
        // A call is invisible to clients that do not own it (A3 — docs §5).
        if call.owner != client {
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
    pub(super) fn list(&self, client: ClientId) -> CmdResult {
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

/// The codec payload names this build can relay or transcode, advertised in `node_info` so a
/// dispatcher only routes a call to a node that can serve its codec. The always-available set (pure
/// relay + the bit-exact pure-Rust codecs) plus the AMR family under the `amr` build feature — kept
/// in step with `factory::encoder_for`.
///
/// Opus is **not** in the static list and carries no build feature (it is royalty-free —
/// docs/codec-licensing.md). It is added only when the codec factory can build **both** a decoder and
/// an encoder for it, probed at runtime by [`opus_is_transcodable`]. The list has no per-direction
/// field, so advertising Opus while only one direction worked would let a dispatcher route a call the
/// engine then fails at setup; requiring both keeps the advertisement honest and needs no further edit
/// when the codec lands.
pub(super) fn supported_codecs() -> Vec<String> {
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
    let opus: &[&str] = if opus_is_transcodable() {
        &["opus"]
    } else {
        &[]
    };
    base.iter()
        .chain(extra.iter())
        .chain(opus.iter())
        .map(|name| (*name).to_string())
        .collect()
}

/// Whether this build can transcode Opus in **both** directions — i.e. whether `factory` yields both a
/// decoder and an encoder for an RFC 7587 Opus spec. Probed rather than assumed so the capability
/// advertisement cannot drift from the factory (see [`supported_codecs`]).
pub(super) fn opus_is_transcodable() -> bool {
    let spec = CodecSpec::new(
        OPUS_DYNAMIC_PAYLOAD_TYPE,
        "opus",
        siphon_rtp_codec::factory::OPUS_CLOCK_RATE_HZ,
        siphon_rtp_codec::factory::OPUS_RTPMAP_CHANNELS,
        20,
    );
    factory::decoder_for(&spec).is_ok() && factory::encoder_for(&spec).is_ok()
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
    ]
}
