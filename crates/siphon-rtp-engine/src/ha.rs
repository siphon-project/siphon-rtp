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
//! - **SRTP rollover** for secure legs is a schema field ([`CallSnapshot::srtp_rollover`]) populated
//!   by the SRTP bridge alongside `restore`'s seeding (both halves of that plumbing land together).
//!
//! The blob is **opaque to the SIP proxy**: it stores the JSON verbatim (keyed by `call_id`) and
//! hands it back to `restore`. The engine owns the format; [`SNAPSHOT_VERSION`] guards against a
//! standby reading an incompatible blob.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Snapshot wire-format version. Bumped on any breaking change to [`CallSnapshot`]; a standby rejects
/// a blob whose version it does not understand.
pub const SNAPSHOT_VERSION: u16 = 1;

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
    /// Per-secure-leg SRTP rollover state (RFC 3711). Empty for a plain relay; populated for secure
    /// legs by the SRTP bridge (lands with `restore`'s seeding — see the module docs).
    #[serde(default)]
    pub srtp_rollover: Vec<SrtpRolloverSnapshot>,
}

/// One side of the call: the engine's local media sockets (the exact ports to re-bind on a standby)
/// and the peer's negotiated remote addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegSnapshot {
    /// Local RTP socket address — the port a standby must re-bind for transparent takeover.
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

/// A secure leg's SRTP rollover checkpoint (RFC 3711 §3.3.1 ROC + §3.4 SRTCP index) — the state that
/// cannot be recovered from the SDES key. Mirrors `siphon_rtp_srtp::StreamRollover` plus the SRTCP
/// index and a direction tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrtpRolloverSnapshot {
    /// Which secure context this rollover belongs to.
    pub direction: SrtpDirection,
    /// The stream SSRC.
    pub ssrc: u32,
    /// The 32-bit SRTP rollover counter.
    pub roc: u32,
    /// The highest RTP sequence seen (rollover anchor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_seq: Option<u16>,
    /// The outgoing SRTCP index for this context.
    pub srtcp_send_index: u32,
}

/// Which SRTP context an [`SrtpRolloverSnapshot`] refers to on a secure leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SrtpDirection {
    /// Decrypting the secure peer's ingress.
    Ingress,
    /// Encrypting egress toward the secure peer.
    Egress,
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
    if text.len() % 2 != 0 {
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
            }),
            far_codec: None,
            near_telephone_event: Some(101),
            near: LegSnapshot {
                rtp_local: "203.0.113.10:30000".parse().unwrap(),
                rtcp_local: Some("203.0.113.10:30001".parse().unwrap()),
                remote_rtp: Some("198.51.100.1:5000".parse().unwrap()),
                remote_rtcp: Some("198.51.100.1:5001".parse().unwrap()),
            },
            far: LegSnapshot {
                rtp_local: "203.0.113.10:30002".parse().unwrap(),
                rtcp_local: None,
                remote_rtp: Some("192.0.2.1:7000".parse().unwrap()),
                remote_rtcp: None,
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
            srtp_rollover: vec![SrtpRolloverSnapshot {
                direction: SrtpDirection::Ingress,
                ssrc: 0xDEAD_BEEF,
                roc: 3,
                highest_seq: Some(42),
                srtcp_send_index: 7,
            }],
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
