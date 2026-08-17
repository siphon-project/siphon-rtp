//! HA (warm-standby) call state: a portable, serializable [`CallSnapshot`] of a live call's
//! negotiated state — enough for a standby node to rebuild the call on failover.
//!
//! # What is (and isn't) here
//!
//! The snapshot captures the state that a standby cannot otherwise reconstruct: the negotiated call
//! identity, each leg's **local media ports** (so a standby behind a floating IP re-binds the exact
//! `ip:port` — no SIP re-INVITE), the peers' remote addresses, the resolved pipeline + codecs, the
//! ICE-lite and SDES keying, and the installed forward rules (source-gate + latch + destination).
//!
//! It deliberately excludes:
//! - **node-local handles** — sockets, task mailboxes, datapath `EndpointId`s (re-allocated on
//!   restore; endpoints are referenced here by *role*, not id);
//! - **ephemeral media state** — jitter buffers, codec/resampler state, the learned latch — which
//!   restart fresh with at most a brief glitch;
//! - a secure (`Srtp`-pipeline) call additionally carries a [`SecureSnapshot`]
//!   ([`CallSnapshot::secure`]) — the peer's SDES key, the leg's SRTP rollover, and the bridge flows —
//!   so a standby can rebuild and re-key the [`SecureLeg`](siphon_rtp_srtp::leg::SecureLeg) bridge.
//!
//! The blob is **opaque to the SIP proxy**: it stores the JSON verbatim (keyed by `call_id`) and
//! hands it back to `restore`. The engine owns the format; [`SNAPSHOT_VERSION`] guards against a
//! standby reading an incompatible blob.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Snapshot wire-format version. Bumped on any breaking change to [`CallSnapshot`]; a standby rejects
/// a blob whose version it does not understand.
pub const SNAPSHOT_VERSION: u16 = 2;

/// A portable snapshot of one live call's negotiated state (see the module docs). All fields are
/// plain data (strings / integers / enums / `std::net` addresses), so the whole thing round-trips
/// through JSON and compares exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSnapshot {
    /// Format version — must equal [`SNAPSHOT_VERSION`] for a standby to accept the blob.
    pub version: u16,
    /// The call identity (the node-independent primary key).
    pub call_id: String,
    /// The offerer's SIP From-tag.
    pub from_tag: String,
    /// The answerer's SIP To-tag, once answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_tag: Option<String>,
    /// How the call's media is carried (relay / SRTP / transcode / …).
    pub pipeline: PipelineSnapshot,
    /// The engine's ICE-lite credentials, if the call negotiated ICE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ice: Option<IceSnapshot>,
    /// The engine's own SDES key offered to the secure far leg, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub far_local_crypto: Option<CryptoSnapshot>,
    /// The near leg's negotiated primary codec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_codec: Option<CodecSnapshot>,
    /// The far leg's negotiated primary codec, once answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub far_codec: Option<CodecSnapshot>,
    /// The near leg's RFC 4733 telephone-event payload type, if negotiated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_telephone_event: Option<u8>,
    /// The near (offerer) leg: local media ports + the peer's remote addresses.
    pub near: LegSnapshot,
    /// The far (answerer) leg.
    pub far: LegSnapshot,
    /// The installed forward rules (a plain relay's `Forward` rules), by endpoint role — so restore
    /// reinstalls the datapath flows without needing the original profile flags. Empty for pipelines
    /// whose media runs through a userspace actor (their flows are `Redirect`, rebuilt differently).
    #[serde(default)]
    pub flows: Vec<FlowSnapshot>,
    /// The secure (SDES-SRTP bridge) state — the peer's key, the leg's SRTP rollover, and the bridge
    /// flow plans — present only for an `Srtp` pipeline. `None` for a plain relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<SecureSnapshot>,
}

/// One side of the call: the engine's local media sockets (the exact ports to re-bind on a standby)
/// and the peer's negotiated remote addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegSnapshot {
    /// Local RTP socket address — the port (and named-interface source IP) a standby must re-bind for
    /// transparent takeover. The standby re-binds this exact `ip:port`, so a call pinned to a named
    /// interface resumes on the same source IP.
    pub rtp_local: SocketAddr,
    /// Local RTCP socket address, absent under rtcp-mux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtcp_local: Option<SocketAddr>,
    /// The peer's RTP address from its SDP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_rtp: Option<SocketAddr>,
    /// The peer's RTCP address from its SDP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_rtcp: Option<SocketAddr>,
    /// The IP this leg advertised in SDP (the named interface's advertised/public address), so a
    /// post-restore re-offer re-advertises the same public IP. Absent in a pre-interface snapshot ⇒
    /// fall back to the bound `rtp_local.ip()` (the old behaviour). Presentation-only — it never feeds
    /// the source gate or latch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertised_ip: Option<IpAddr>,
}

/// Mirror of the engine's pipeline kind (kept in step with `engine::PipelineKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineSnapshot {
    /// Plain in-datapath relay.
    Passthrough,
    /// Userspace SRTP bridge.
    Srtp,
    /// Userspace transcode / record / DTMF slow path.
    Media,
    /// Secure and transcoding.
    SrtpMedia,
    /// WebSocket bridge (voice-AI).
    Ws,
    /// Userspace DTLS-SRTP bridge — not HA-restorable (the handshake-derived keys cannot be recovered
    /// from the snapshot), so `restore` rejects it and `checkpoint` refuses to produce one.
    Dtls,
}

/// ICE-lite credentials (engine side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceSnapshot {
    /// `a=ice-ufrag`.
    pub ufrag: String,
    /// `a=ice-pwd`.
    pub pwd: String,
}

/// An SDES `a=crypto` attribute: the tag, suite name, and master key/salt (hex-encoded, to keep the
/// snapshot a plain string-and-number document).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSnapshot {
    /// The crypto tag (`a=crypto:<tag>`).
    pub tag: u32,
    /// The IANA suite name (e.g. `AES_CM_128_HMAC_SHA1_80`).
    pub suite: String,
    /// 16-byte master key, hex.
    pub master_key_hex: String,
    /// 14-byte master salt, hex.
    pub master_salt_hex: String,
}

/// A negotiated codec (mirror of `siphon_rtp_codec::factory::CodecSpec`'s wire-relevant fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecSnapshot {
    /// RTP payload type.
    pub payload_type: u8,
    /// `a=rtpmap` encoding name.
    pub encoding_name: String,
    /// RTP clock / sample rate (Hz).
    pub clock_rate_hz: u32,
    /// Channel count.
    pub channels: u8,
    /// Packetization time (ms).
    pub ptime_ms: u8,
    /// Egress encode mode for a variable-rate codec (AMR-WB `mode-set`), preserved so a restored
    /// transcode call re-encodes at the same rate. `None` = the codec default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encode_mode: Option<u8>,
    /// The full negotiated AMR `mode-set` (RFC 4867 §8.1), preserved so a restored call still clamps
    /// per-frame CMR adaptation into the set the peer permitted (without it the restored encoder
    /// would be free to answer a CMR with a mode the peer disallowed). Empty when unconstrained.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_modes: Vec<u8>,
    /// The negotiated RFC 7587 Opus `a=fmtp` parameters, preserved so a restored Opus leg keeps the
    /// channel layout, packetization ceiling, and rate-control/FEC/DTX limits it negotiated. `None`
    /// for a non-Opus codec, and for an Opus leg whose peer declared nothing (the RFC defaults apply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opus: Option<OpusSnapshot>,
}

/// The RFC 7587 §6.1 Opus `a=fmtp` parameters (mirror of `siphon_rtp_codec::factory::OpusParams`,
/// which is serde-free — the codec crate carries no serialization dependency).
///
/// Every field is `#[serde(default)]` and skipped when it holds its RFC 7587 default, so a snapshot
/// of a plain Opus leg stays compact and a snapshot written by an older node still restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpusSnapshot {
    /// `maxaveragebitrate` in bit/s (RFC 7587 §6.1); `None` = unstated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_average_bitrate: Option<u32>,
    /// `maxplaybackrate` in Hz; RFC default 48000.
    #[serde(default = "default_opus_playback_rate_hz")]
    pub max_playback_rate_hz: u32,
    /// `maxptime` in ms; RFC default 120.
    #[serde(default = "default_opus_max_ptime_ms")]
    pub max_ptime_ms: u8,
    /// `stereo` — the peer can render stereo (RFC default 0).
    #[serde(default, skip_serializing_if = "is_false")]
    pub stereo: bool,
    /// `sprop-stereo` — the peer sends stereo (RFC default 0).
    #[serde(default, skip_serializing_if = "is_false")]
    pub sprop_stereo: bool,
    /// `cbr` — constant bitrate requested (RFC default 0).
    #[serde(default, skip_serializing_if = "is_false")]
    pub cbr: bool,
    /// `useinbandfec` — the peer's decoder uses in-band FEC (RFC default 0).
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_inband_fec: bool,
    /// `usedtx` — the peer accepts DTX (RFC default 0).
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_dtx: bool,
}

/// RFC 7587 §6.1 `maxplaybackrate` default, for the serde `default` of a missing field.
fn default_opus_playback_rate_hz() -> u32 {
    siphon_rtp_codec::factory::OpusParams::default().max_playback_rate_hz
}

/// RFC 7587 §6.1 `maxptime` default, for the serde `default` of a missing field.
fn default_opus_max_ptime_ms() -> u8 {
    siphon_rtp_codec::factory::OpusParams::default().max_ptime_ms
}

/// `skip_serializing_if` predicate for a flag at its RFC 7587 default (off).
fn is_false(flag: &bool) -> bool {
    !*flag
}

/// Which of a call's four possible endpoints a rule refers to — the node-independent stand-in for a
/// datapath `EndpointId`, since the ids are re-allocated on restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    /// Near leg's RTP endpoint.
    NearRtp,
    /// Near leg's RTCP endpoint.
    NearRtcp,
    /// Far leg's RTP endpoint.
    FarRtp,
    /// Far leg's RTCP endpoint.
    FarRtcp,
}

/// A portable forward rule: which endpoint it is installed on, which it forwards to, and the
/// destination / source-gate / latch policy (mirror of `siphon_rtp_datapath::ForwardRule`, with the
/// two endpoint ids replaced by roles).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowSnapshot {
    /// The endpoint the rule is installed on (its ingress is gated + forwarded).
    pub installed_on: EndpointRole,
    /// The endpoint datagrams are transmitted from (facing the forwarded-to party).
    pub out: EndpointRole,
    /// The configured destination address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_dst: Option<SocketAddr>,
    /// The source-address gate (RTPBleed defence).
    pub accepted_source: SourceFilterSnapshot,
    /// The latch lifecycle.
    pub latch: LatchSnapshot,
}

/// Mirror of `siphon_rtp_datapath::SourceFilter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFilterSnapshot {
    /// Only this exact IP may send.
    Exact(IpAddr),
    /// Any IP inside this CIDR block.
    Subnet(IpAddr, u8),
    /// Accept any source (opt-in symmetric-NAT posture).
    Any,
}

/// Mirror of `siphon_rtp_datapath::LatchPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatchSnapshot {
    /// Never latch.
    Off,
    /// Latch only signalled-source packets, SSRC-gated re-latch (the default).
    SignalledOnly,
    /// Latch the first source (symmetric NAT).
    Symmetric,
}

/// The secure (SDES-SRTP bridge) state a standby needs to rebuild an `Srtp` call: the peer's SDES key
/// (the engine's own is [`CallSnapshot::far_local_crypto`]), the leg's SRTP rollover, and the bridge
/// flow plans. Present only for a secure call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureSnapshot {
    /// The peer's answered SDES key (keys the inbound/decrypt contexts on rebuild).
    pub far_remote_crypto: CryptoSnapshot,
    /// The secure leg's non-recoverable SRTP rollover (RFC 3711 §3.3.1 / §3.4).
    pub rollover: SecureLegRolloverSnapshot,
    /// The bridge flows (one per redirected endpoint) to reinstall on the standby.
    pub bridge_flows: Vec<BridgeFlowSnapshot>,
}

/// Portable mirror of `siphon_rtp_srtp::leg::SecureLegRollover`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureLegRolloverSnapshot {
    /// Per-SSRC rollover of the inbound (from-peer) SRTP context.
    #[serde(default)]
    pub inbound_rtp: Vec<StreamRolloverSnapshot>,
    /// Per-SSRC rollover of the outbound (to-peer) SRTP context.
    #[serde(default)]
    pub outbound_rtp: Vec<StreamRolloverSnapshot>,
    /// The outbound SRTCP index to continue from.
    pub outbound_rtcp_index: u32,
}

/// Portable mirror of `siphon_rtp_srtp::StreamRollover` (per-SSRC ROC + rollover anchor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRolloverSnapshot {
    /// The stream SSRC.
    pub ssrc: u32,
    /// The 32-bit SRTP rollover counter.
    pub roc: u32,
    /// The highest RTP sequence seen (rollover anchor), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_seq: Option<u16>,
}

/// A secure bridge flow: which endpoint role handles ingress, the crypto op, the source-gate, and
/// the peer-facing endpoint + destination. Mirror of the engine's `BridgeFlowPlan` with roles for ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFlowSnapshot {
    /// The redirected endpoint this flow crypts ingress for.
    pub endpoint: EndpointRole,
    /// Encrypt (plain→secure) or decrypt (secure→plain).
    pub op: BridgeOpSnapshot,
    /// The signalled-source gate (RTPBleed defence).
    pub accepted_source: SourceFilterSnapshot,
    /// The peer-facing endpoint the transformed datagram is transmitted from.
    pub out: EndpointRole,
    /// The peer's negotiated destination address.
    pub out_dst: SocketAddr,
}

/// Mirror of the engine's `srtp_bridge::BridgeOp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeOpSnapshot {
    /// Plain ingress → encrypt for the secure peer.
    Encrypt,
    /// Secure ingress → decrypt for the plain peer.
    Decrypt,
}

impl CallSnapshot {
    /// Serialize to the opaque JSON blob carried by the `checkpoint` control result.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a blob produced by [`Self::to_json`], rejecting an unknown [`version`](Self::version).
    pub fn from_json(blob: &str) -> Result<Self, SnapshotError> {
        let snapshot: Self = serde_json::from_str(blob)?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(SnapshotError::Version {
                found: snapshot.version,
                expected: SNAPSHOT_VERSION,
            });
        }
        Ok(snapshot)
    }
}

/// Failure parsing a [`CallSnapshot`] blob.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The blob is not valid JSON / does not match the schema.
    #[error("invalid snapshot: {0}")]
    Json(#[from] serde_json::Error),
    /// The blob's format version is not the one this build understands.
    #[error("snapshot version {found} is not supported (this build expects {expected})")]
    Version {
        /// The version found in the blob.
        found: u16,
        /// The version this build produces/consumes.
        expected: u16,
    },
}

/// Hex-encode bytes (lowercase), for the SDES key material in a [`CryptoSnapshot`].
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode a lowercase/uppercase hex string, or `None` on an odd length or a non-hex digit.
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample() -> CallSnapshot {
        CallSnapshot {
            version: SNAPSHOT_VERSION,
            call_id: "call-abc@host".into(),
            from_tag: "alice-tag".into(),
            to_tag: Some("bob-tag".into()),
            pipeline: PipelineSnapshot::Passthrough,
            ice: Some(IceSnapshot {
                ufrag: "ufrag".into(),
                pwd: "password".into(),
            }),
            far_local_crypto: Some(CryptoSnapshot {
                tag: 1,
                suite: "AES_CM_128_HMAC_SHA1_80".into(),
                master_key_hex: to_hex(&[0x11; 16]),
                master_salt_hex: to_hex(&[0x22; 14]),
            }),
            near_codec: Some(CodecSnapshot {
                payload_type: 0,
                encoding_name: "PCMU".into(),
                clock_rate_hz: 8000,
                channels: 1,
                ptime_ms: 20,
                encode_mode: None,
                allowed_modes: Vec::new(),
                opus: None,
            }),
            far_codec: None,
            near_telephone_event: Some(101),
            near: LegSnapshot {
                rtp_local: "203.0.113.10:30000".parse().unwrap(),
                rtcp_local: Some("203.0.113.10:30001".parse().unwrap()),
                remote_rtp: Some("198.51.100.1:5000".parse().unwrap()),
                remote_rtcp: Some("198.51.100.1:5001".parse().unwrap()),
                advertised_ip: None,
            },
            far: LegSnapshot {
                rtp_local: "203.0.113.10:30002".parse().unwrap(),
                rtcp_local: None,
                remote_rtp: Some("192.0.2.1:7000".parse().unwrap()),
                remote_rtcp: None,
                advertised_ip: None,
            },
            flows: vec![FlowSnapshot {
                installed_on: EndpointRole::NearRtp,
                out: EndpointRole::FarRtp,
                out_dst: Some("192.0.2.1:7000".parse().unwrap()),
                accepted_source: SourceFilterSnapshot::Exact(IpAddr::V4(Ipv4Addr::new(
                    198, 51, 100, 1,
                ))),
                latch: LatchSnapshot::SignalledOnly,
            }],
            secure: Some(SecureSnapshot {
                far_remote_crypto: CryptoSnapshot {
                    tag: 1,
                    suite: "AES_CM_128_HMAC_SHA1_80".into(),
                    master_key_hex: to_hex(&[0x33; 16]),
                    master_salt_hex: to_hex(&[0x44; 14]),
                },
                rollover: SecureLegRolloverSnapshot {
                    inbound_rtp: vec![StreamRolloverSnapshot {
                        ssrc: 0xDEAD_BEEF,
                        roc: 3,
                        highest_seq: Some(42),
                    }],
                    outbound_rtp: vec![StreamRolloverSnapshot {
                        ssrc: 0x0A0A_0A0A,
                        roc: 1,
                        highest_seq: Some(7),
                    }],
                    outbound_rtcp_index: 9,
                },
                bridge_flows: vec![BridgeFlowSnapshot {
                    endpoint: EndpointRole::NearRtp,
                    op: BridgeOpSnapshot::Encrypt,
                    accepted_source: SourceFilterSnapshot::Exact(IpAddr::V4(Ipv4Addr::new(
                        198, 51, 100, 1,
                    ))),
                    out: EndpointRole::FarRtp,
                    out_dst: "192.0.2.1:7000".parse().unwrap(),
                }],
            }),
        }
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let snapshot = sample();
        let blob = snapshot.to_json().expect("serialize");
        let back = CallSnapshot::from_json(&blob).expect("deserialize");
        assert_eq!(snapshot, back);
    }

    #[test]
    fn leg_snapshot_advertised_ip_round_trips_and_defaults_to_none() {
        // A named-interface call records its advertised IP; the field round-trips through JSON.
        let mut snapshot = sample();
        snapshot.near.advertised_ip = Some("203.0.113.99".parse().unwrap());
        let back =
            CallSnapshot::from_json(&snapshot.to_json().expect("serialize")).expect("deserialize");
        assert_eq!(
            back.near.advertised_ip,
            Some("203.0.113.99".parse().unwrap())
        );
        assert_eq!(
            back.far.advertised_ip, None,
            "unset far advertised stays None"
        );

        // A pre-interface blob (no `advertised_ip` key on the leg) deserializes to `None` (serde
        // default), so an older primary's checkpoint restores on a new standby.
        let blob = snapshot.to_json().expect("serialize");
        let stripped = blob.replace(",\"advertised_ip\":\"203.0.113.99\"", "");
        let back = CallSnapshot::from_json(&stripped).expect("legacy blob deserializes");
        assert_eq!(back.near.advertised_ip, None);
    }

    #[test]
    fn from_json_rejects_an_unknown_version() {
        let mut snapshot = sample();
        snapshot.version = SNAPSHOT_VERSION + 1;
        let blob = snapshot.to_json().expect("serialize");
        let error = CallSnapshot::from_json(&blob).expect_err("version mismatch must error");
        assert!(matches!(error, SnapshotError::Version { .. }));
    }

    #[test]
    fn from_json_rejects_malformed_blob() {
        assert!(matches!(
            CallSnapshot::from_json("{not json"),
            Err(SnapshotError::Json(_))
        ));
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let bytes = [0x00, 0x11, 0xAB, 0xFF];
        assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(from_hex("abc"), None, "odd length");
        assert_eq!(from_hex("zz"), None, "non-hex digit");
    }
}
