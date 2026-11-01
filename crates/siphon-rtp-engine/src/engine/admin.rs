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
                rtcp_app_dropped_total: snapshot.rtcp_app_dropped_total,
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
            node: self.cluster.info(
                engine_version(),
                supported_codecs(),
                self.supported_features(),
            ),
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

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The capability flags this node advertises in `node_info`: what the build ships, plus what
    /// the operator configured on this node.
    fn supported_features(&self) -> Vec<String> {
        let mut features = build_features();
        // `turn_client`: relayed candidates are allocated from a TURN server this node was
        // configured with and offered on ICE legs, so a controller can tell a node that can serve
        // a peer behind a UDP-blocking NAT from one that only offers host candidates.
        if self.turn_client.is_some() {
            features.push("turn_client".to_string());
        }
        features
    }
}

/// The capability flags this build ships, advertised in `node_info`.
fn build_features() -> Vec<String> {
    vec![
        "relay".to_string(),
        "transcode".to_string(),
        "srtp".to_string(),
        "conference".to_string(),
        // `conference_seat`: a live call's leg seated in a room in place. A controller gates the
        // verb on this entry, so it is advertised only where the verb is served.
        "conference_seat".to_string(),
        // Forwarding rooms for push-to-talk group calls: `forward_join`, `forward_leave` and
        // `forward_set_source`. A controller gates the verbs on this entry, so it is advertised only
        // where they are served.
        "forward_room".to_string(),
        // `forward_offer` / `forward_answer`: the room dials a member out (a group call's fan-out),
        // on the same terms `conference_offer` / `conference_answer` dial out of a mixing room.
        "forward_dialout".to_string(),
        // A forwarding-room seat in another codec than the room's is transcoded for (decode once,
        // encode once per codec group), where it used to be refused. A controller gates seating
        // mixed-codec members on this entry.
        "forward_transcode".to_string(),
        // `media: preserve` on `forward_join` / `forward_offer`: the talker's RTP and audio SRTCP are
        // forwarded byte for byte, so end-to-end SRTP (3GPP TS 33.180 §7.5.2) survives, and
        // `profile.key_mgmt` is written as `a=key-mgmt` on the audio section. A controller gates
        // secured MCPTT media on this entry.
        "forward_preserve".to_string(),
        // The MCPTT floor-control stream (`m=application <port> udp MCPTT`, 3GPP TS 24.380) is
        // anchored on a forwarding-room seat, and RTCP APP packets travel both ways as
        // `send_rtcp_app` / `rtcp_app`. Controllers gate floor control on these entries.
        "mcptt_floor".to_string(),
        "rtcp_app".to_string(),
        // The floor stream is protected with AEAD_AES_128_GCM SRTCP (3GPP TS 33.180 §9.4) under the
        // `floor_keys` of the profile and `set_floor_keys`. Controllers gate keyed floor control on
        // this entry.
        "floor_srtcp".to_string(),
        // A browser seat's floor control runs over a WebRTC data channel labelled `mcptt-floor`
        // (`m=application … UDP/DTLS/SCTP webrtc-datachannel`, RFC 8841), because a browser cannot
        // send RTCP APP. The same `rtcp_app` / `send_rtcp_app` carry it. A controller gates offering
        // the data channel to a browser on this entry.
        "webrtc_floor_channel".to_string(),
        // `conference_join` and `conference_answer` honour a `received-from` hint, so a NATed
        // participant that advertises a private `c=` is gated on, and sent the mix at, its public
        // address. A controller gates sending the hint on this entry.
        "conference_received_from".to_string(),
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
        // A controller can tell, before relying on it, whether this node answers an `answer_local`
        // offer with the complement of its direction (RFC 3264 §6.1) and sends nothing to a caller
        // that offered `sendonly` or `inactive`. A node without it answers `sendonly` with
        // `sendonly` and sends that caller comfort noise — what a SIPREC stream answered as its own
        // call must not get — and a controller has no other way to tell, since the behaviour is the
        // engine's, not the contract crate's.
        "answer_local_direction".to_string(),
    ]
}
