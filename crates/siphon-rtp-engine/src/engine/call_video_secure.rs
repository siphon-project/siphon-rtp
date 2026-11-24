//! SDES-SRTP on a two-party call's anchored video stream (RFC 4568, RFC 3711).
//!
//! The stream is keyed per leg exactly as audio's SDES legs are: the engine mints its own key toward
//! each secure party (the answer echoes the offered tag, RFC 4568 §5.1.2), never passes one party's
//! key to the other, and bridges in userspace. A secure video leg cannot ride the in-kernel relay, so
//! every video endpoint that carries media is `Redirect`ed and a second [`BridgeCallPlan`], over the
//! video endpoints and video [`SecureLeg`]s only, goes to the SRTP bridge, which is keyed per
//! endpoint. Plain to SDES, SDES to plain and SDES to SDES (a transcrypt) are the one mechanism the
//! audio bridge already runs, and the gated latch is the bridge's own (docs/security-and-nat.md §4).
//! RTCP is SRTCP per stream, demultiplexed by the leg.
//!
//! DTLS-SRTP video is not carried: it is declined with the reason, never relayed unkeyed.

use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction, ForwardRule, LatchPolicy};
use std::sync::{Arc, Mutex};

use siphon_rtp_srtp::leg::{SecureLeg, SecureLegRollover};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};

use super::{Engine, Party};
use crate::sdp::{VideoKeying, VideoStream};
use crate::srtp_bridge::hold::SharedBridgePlan;
use crate::srtp_bridge::{BridgeFlowPlan, BridgeLeg};

/// One party's two SDES keys for its video leg: the engine's own toward the party (what the party
/// decrypts the engine's video with) and the party's own (what the engine decrypts its video with).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SideKeys {
    pub(super) local: Option<CryptoAttribute>,
    pub(super) remote: Option<CryptoAttribute>,
}

/// Both parties' video keys. A party with no `local` key is on plain RTP.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct VideoKeys {
    pub(super) near: SideKeys,
    pub(super) far: SideKeys,
}

/// Where a stream's negotiation stands, which decides what the party's SDP is allowed to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Exchange {
    /// The first offer of this stream. `far_secure` says whether the engine offers the far party
    /// SRTP (the profile's far-leg transport asked for `RTP/SAVP`).
    FirstOffer { far_secure: bool },
    /// A later offer or re-offer of a stream already negotiated.
    Offer,
    /// An answer to an offer the engine presented.
    Answer,
}

fn mint(tag: u32) -> Result<CryptoAttribute, String> {
    CryptoAttribute::generate(tag, CryptoSuite::AesCm128HmacSha1_80)
        .map_err(|error| format!("generate SDES key: {error}"))
}

impl VideoKeys {
    fn side(&self, party: Party) -> &SideKeys {
        match party {
            Party::Near => &self.near,
            Party::Far => &self.far,
        }
    }

    fn side_mut(&mut self, party: Party) -> &mut SideKeys {
        match party {
            Party::Near => &mut self.near,
            Party::Far => &mut self.far,
        }
    }

    /// Whether either party's video is SDES-SRTP, so the stream is bridged in userspace.
    pub(super) fn is_secure(&self) -> bool {
        self.near.local.is_some() || self.far.local.is_some()
    }

    /// How the section presented **to** `party` is keyed: the engine's own key for that leg.
    pub(super) fn keying_toward(&self, party: Party) -> VideoKeying {
        self.side(party)
            .local
            .map_or(VideoKeying::Plain, VideoKeying::Sdes)
    }

    /// Settle the keys `stream`, the SDP of `party`, implies, or the reason the stream cannot be
    /// carried. Nothing is relayed unkeyed: a secure stream with no usable key, a secure answer to a
    /// plain offer and a plain answer to a secure one are all refused (RFC 4568 §7.1).
    pub(super) fn settle(
        &mut self,
        party: Party,
        stream: &VideoStream,
        exchange: Exchange,
    ) -> Result<(), String> {
        if stream.is_dtls() {
            return Err(format!(
                "video transport {} is not carried: DTLS-SRTP video is not supported, SDES-SRTP and \
                 plain RTP are",
                stream.transport
            ));
        }
        if !stream.is_plain() && !stream.is_sdes() {
            return Err(format!(
                "video transport {} is not carried: the engine anchors RTP/AVP[F] and RTP/SAVP[F] video",
                stream.transport
            ));
        }
        let secure = stream.is_sdes();
        let accepted = if secure {
            Some(
                *stream
                    .crypto
                    .first()
                    .ok_or("the secure video section carries no usable a=crypto")?,
            )
        } else {
            None
        };
        match exchange {
            Exchange::Answer => {
                let own = self.side_mut(party);
                if own.local.is_some() != secure {
                    return Err(
                        "the answer's video transport does not match the offer: secure video is \
                         never answered in the clear, nor plain video with a key"
                            .to_string(),
                    );
                }
                if let (Some(line), Some(offered)) = (accepted, own.local) {
                    // RFC 4568 §5.1.2: the answer's tag names the offered line it accepted.
                    if line.tag != offered.tag || line.suite != offered.suite {
                        return Err(
                            "the video answer selected a crypto line the engine did not offer"
                                .to_string(),
                        );
                    }
                }
                own.remote = accepted;
            }
            Exchange::Offer if party == Party::Far => {
                // The engine presented B a stream of one kind at the offer; a re-offer that moves it
                // to the other would leave the bridge keyed for the wrong one.
                let own = self.side_mut(party);
                if own.local.is_some() != secure {
                    return Err(
                        "a re-offer cannot move the video stream between plain RTP and SDES-SRTP"
                            .to_string(),
                    );
                }
                own.remote = accepted;
            }
            Exchange::Offer | Exchange::FirstOffer { .. } => {
                let own = self.side_mut(party);
                match accepted {
                    Some(line) => {
                        // RFC 4568 §6: a re-offer re-presents the key the party already holds; a new
                        // one is minted only when the offer names a different line (tag or suite).
                        let keep = own
                            .local
                            .filter(|local| local.tag == line.tag && local.suite == line.suite);
                        own.local = Some(match keep {
                            Some(local) => local,
                            None => CryptoAttribute::answer_to(&line)
                                .map_err(|error| format!("generate SDES key: {error}"))?,
                        });
                        own.remote = Some(line);
                    }
                    None => *own = SideKeys::default(),
                }
                if let Exchange::FirstOffer { far_secure } = exchange {
                    let other = self.side_mut(match party {
                        Party::Near => Party::Far,
                        Party::Far => Party::Near,
                    });
                    *other = SideKeys {
                        local: if far_secure { Some(mint(1)?) } else { None },
                        remote: None,
                    };
                }
            }
        }
        Ok(())
    }
}

/// One bridged video flow: the endpoint a party's media arrives on, which party that is, and the
/// rule (source gate, latch and destination) that the in-kernel relay would have applied.
#[derive(Debug, Clone, Copy)]
pub(super) struct VideoFlowRule {
    pub(super) endpoint: EndpointId,
    pub(super) ingress: Party,
    pub(super) rule: ForwardRule,
}

/// The video legs a bridge already holds, one per party that had keys.
pub(super) type LiveVideoLegs = (Option<Arc<Mutex<SecureLeg>>>, Option<Arc<Mutex<SecureLeg>>>);

/// The bridge plan of a secure video stream: one video [`SecureLeg`] per secure party, and one flow
/// per bridged endpoint naming which party's key decrypts its ingress and which encrypts its egress.
///
/// A party that already has a live leg keeps it and only the side whose key changed is re-keyed
/// (RFC 3711 §9.1: a key must never protect one index twice, so the live send window is what stops a
/// renegotiation from sending the same index again). Only a party with no live leg gets a new one,
/// seeded from the rollover the previous negotiation had (RFC 3711 §3.3.1) with everything at or
/// below its sent mark closed.
fn bridge_plan(
    keys: &VideoKeys,
    rules: &[VideoFlowRule],
    live: LiveVideoLegs,
    previous: (Option<SecureLegRollover>, Option<SecureLegRollover>),
) -> SharedBridgePlan {
    let build = |side: &SideKeys,
                 live: Option<Arc<Mutex<SecureLeg>>>,
                 previous: Option<SecureLegRollover>| {
        let (local, remote) = side.local.zip(side.remote)?;
        if let Some(live) = live {
            live.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .adopt(Some(&local.key), Some(&remote.key));
            return Some(live);
        }
        let mut leg = SecureLeg::new(&local.key, &remote.key);
        if let Some(rollover) = previous.as_ref() {
            leg.seed_rollover(rollover);
        }
        Some(Arc::new(Mutex::new(leg)))
    };
    let leg_of = |party: Party| match party {
        Party::Near => BridgeLeg::Near,
        Party::Far => BridgeLeg::Far,
    };
    let secure = |party: Party| keys.side(party).local.is_some();
    let flows = rules
        .iter()
        .filter_map(|flow| {
            let egress = match flow.ingress {
                Party::Near => Party::Far,
                Party::Far => Party::Near,
            };
            Some(BridgeFlowPlan {
                endpoint: flow.endpoint,
                ingress_leg: secure(flow.ingress).then(|| leg_of(flow.ingress)),
                egress_leg: secure(egress).then(|| leg_of(egress)),
                accepted_source: flow.rule.accepted_source,
                latch: flow.rule.latch != LatchPolicy::Off,
                out_endpoint: flow.rule.out_endpoint,
                out_dst: flow.rule.out_dst?,
            })
        })
        .collect();
    SharedBridgePlan {
        near_leg: build(&keys.near, live.0, previous.0),
        far_leg: build(&keys.far, live.1, previous.1),
        flows,
        carried: Vec::new(),
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The live video legs of each party, read from the bridge's flows before a renegotiation
    /// replaces them, so a renegotiation that repeats a key keeps the very leg that sent.
    pub(super) fn live_video_legs(&self, rules: &[VideoFlowRule]) -> LiveVideoLegs {
        let (mut near, mut far) = (None, None);
        for flow in rules {
            near = near.or_else(|| self.bridge.party_leg(flow.endpoint, BridgeLeg::Near));
            far = far.or_else(|| self.bridge.party_leg(flow.endpoint, BridgeLeg::Far));
        }
        (near, far)
    }

    /// The live video rollover of each secure party, read from the bridge's flows before a
    /// renegotiation replaces them. Each flow's two legs are its ingress party's and the other's.
    pub(super) fn live_video_rollover(
        &self,
        rules: &[VideoFlowRule],
    ) -> (Option<SecureLegRollover>, Option<SecureLegRollover>) {
        let (mut near, mut far) = (None, None);
        for flow in rules {
            let (ingress, egress) = self.bridge.rollover_snapshots(flow.endpoint);
            let (near_side, far_side) = match flow.ingress {
                Party::Near => (ingress, egress),
                Party::Far => (egress, ingress),
            };
            near = near.or(near_side);
            far = far.or(far_side);
        }
        (near, far)
    }

    /// Install a secure video stream: every endpoint that carries media is `Redirect`ed to the SRTP
    /// bridge and registered in one plan, and every other video endpoint (a direction the parties did
    /// not allow) is a drop. Returns the flows installed. `previous` seeds each secure leg's rollover.
    pub(super) fn install_video_bridge(
        &self,
        keys: &VideoKeys,
        rules: &[VideoFlowRule],
        endpoints: &[EndpointId],
        live: LiveVideoLegs,
        previous: (Option<SecureLegRollover>, Option<SecureLegRollover>),
    ) -> Result<Vec<(EndpointId, FlowAction)>, String> {
        let mut flows: Vec<(EndpointId, FlowAction)> = Vec::new();
        let mut unbridged = Vec::new();
        let mut actions = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let action = if rules.iter().any(|flow| flow.endpoint == *endpoint) {
                FlowAction::Redirect
            } else {
                unbridged.push(*endpoint);
                FlowAction::Drop
            };
            actions.push((*endpoint, action));
        }
        // A direction closed by this renegotiation leaves the bridge too, so its old flow cannot
        // keep decrypting what the datapath now drops.
        self.bridge.deregister(unbridged);
        // The flows are registered before any endpoint is redirected: the first datagram reaches the
        // dispatcher the instant a `Redirect` lands, and one that finds no flow there is dropped.
        // Registering opens nothing (a registry sees only what a `Redirect` routes to it), and each
        // registered flow carries its source gate and latch, so the first packet is already gated.
        if !rules.is_empty() {
            self.bridge
                .register_shared(bridge_plan(keys, rules, live, previous));
        }
        for (endpoint, action) in actions {
            if let Err(error) = self.datapath.install_flow(endpoint, action) {
                // A flow that was not installed must not stay registered.
                self.bridge
                    .deregister(rules.iter().map(|flow| flow.endpoint));
                return Err(format!("install video flow: {error}"));
            }
            flows.push((endpoint, action));
        }
        Ok(flows)
    }
}

impl VideoKeys {
    /// The keys as an HA record, without the rollover (which only the bridge knows).
    pub(super) fn snapshot(&self) -> Option<crate::ha::VideoSecureSnapshot> {
        use super::snapshot::crypto_snapshot;
        self.is_secure().then(|| crate::ha::VideoSecureSnapshot {
            near_local: self.near.local.as_ref().map(crypto_snapshot),
            near_remote: self.near.remote.as_ref().map(crypto_snapshot),
            far_local: self.far.local.as_ref().map(crypto_snapshot),
            far_remote: self.far.remote.as_ref().map(crypto_snapshot),
            near_rollover: None,
            far_rollover: None,
        })
    }

    /// The keys of a restored call, or the reason a recorded key cannot be rebuilt.
    pub(super) fn restored(
        snapshot: Option<&crate::ha::VideoSecureSnapshot>,
    ) -> Result<Self, String> {
        use super::snapshot::restore_crypto;
        let Some(snapshot) = snapshot else {
            return Ok(Self::default());
        };
        let key = |value: &Option<crate::ha::CryptoSnapshot>| {
            value.as_ref().map(restore_crypto).transpose()
        };
        Ok(Self {
            near: SideKeys {
                local: key(&snapshot.near_local)?,
                remote: key(&snapshot.near_remote)?,
            },
            far: SideKeys {
                local: key(&snapshot.far_local)?,
                remote: key(&snapshot.far_remote)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(transport: &str, crypto: Vec<CryptoAttribute>) -> VideoStream {
        VideoStream {
            remote_rtp: "192.0.2.10:6000".parse().expect("addr"),
            remote_rtcp: "192.0.2.10:6001".parse().expect("addr"),
            direction: crate::sdp::MediaDirection::SendRecv,
            rtcp_mux: false,
            transport: transport.to_string(),
            crypto,
            mid: None,
            bundled: false,
            audio_mid: None,
            payload_collision: false,
            payload_types: vec![96],
            rtpmaps: Vec::new(),
            picture_loss: false,
            fmtps: Vec::new(),
            ssrc: None,
            fingerprint: None,
            setup: None,
            ice: false,
        }
    }

    fn key(tag: u32) -> CryptoAttribute {
        mint(tag).expect("key")
    }

    #[test]
    fn a_secure_offer_mints_the_engines_key_under_the_offered_tag_and_never_reuses_the_peers() {
        let mut keys = VideoKeys::default();
        let offered = key(7);
        keys.settle(
            Party::Near,
            &stream("RTP/SAVPF", vec![offered]),
            Exchange::FirstOffer { far_secure: false },
        )
        .expect("settles");
        let local = keys.near.local.expect("engine key");
        assert_eq!(local.tag, 7, "the answer echoes the offered tag");
        assert_ne!(local.key.master_key, offered.key.master_key);
        assert_eq!(keys.near.remote.expect("peer key").tag, 7);
        assert!(keys.far.local.is_none(), "a plain far party gets no key");
    }

    #[test]
    fn a_far_secure_first_offer_mints_a_fresh_key_for_the_far_party_only() {
        let mut keys = VideoKeys::default();
        keys.settle(
            Party::Near,
            &stream("RTP/AVP", Vec::new()),
            Exchange::FirstOffer { far_secure: true },
        )
        .expect("settles");
        assert!(keys.near.local.is_none());
        let far = keys.far.local.expect("far key");
        assert_eq!(far.tag, 1);
        assert!(keys.is_secure());
    }

    #[test]
    fn a_secure_section_without_a_usable_key_and_dtls_video_are_refused() {
        let mut keys = VideoKeys::default();
        let refusal = keys
            .settle(
                Party::Near,
                &stream("RTP/SAVP", Vec::new()),
                Exchange::FirstOffer { far_secure: false },
            )
            .expect_err("no key");
        assert!(refusal.contains("a=crypto"), "{refusal}");
        let refusal = keys
            .settle(
                Party::Near,
                &stream("UDP/TLS/RTP/SAVPF", Vec::new()),
                Exchange::FirstOffer { far_secure: false },
            )
            .expect_err("dtls");
        assert!(refusal.contains("DTLS-SRTP video"), "{refusal}");
    }

    #[test]
    fn an_answer_must_keep_the_offered_security_and_name_the_offered_line() {
        let mut keys = VideoKeys::default();
        keys.settle(
            Party::Near,
            &stream("RTP/AVP", Vec::new()),
            Exchange::FirstOffer { far_secure: true },
        )
        .expect("offer");
        let offered = keys.far.local.expect("engine key");
        // A plain answer to a secure offer is never accepted.
        assert!(keys
            .settle(Party::Far, &stream("RTP/AVP", Vec::new()), Exchange::Answer)
            .is_err());
        // A line the engine did not offer is refused.
        let mut other = offered;
        other.tag = 5;
        assert!(keys
            .settle(
                Party::Far,
                &stream("RTP/SAVP", vec![other]),
                Exchange::Answer
            )
            .is_err());
        let mut answer = key(1);
        answer.suite = offered.suite;
        keys.settle(
            Party::Far,
            &stream("RTP/SAVP", vec![answer]),
            Exchange::Answer,
        )
        .expect("the offered tag is accepted");
        assert!(keys.far.remote.is_some());
    }

    #[test]
    fn a_secure_answer_to_a_plain_offer_is_refused() {
        let mut keys = VideoKeys::default();
        keys.settle(
            Party::Near,
            &stream("RTP/AVP", Vec::new()),
            Exchange::FirstOffer { far_secure: false },
        )
        .expect("offer");
        assert!(keys
            .settle(
                Party::Far,
                &stream("RTP/SAVP", vec![key(1)]),
                Exchange::Answer
            )
            .is_err());
    }

    #[test]
    fn a_re_offer_keeps_the_engines_key_and_a_far_re_offer_cannot_change_the_security() {
        let mut keys = VideoKeys::default();
        let offered = key(3);
        keys.settle(
            Party::Near,
            &stream("RTP/SAVP", vec![offered]),
            Exchange::FirstOffer { far_secure: true },
        )
        .expect("offer");
        let before = keys.near.local.expect("key");
        keys.settle(
            Party::Near,
            &stream("RTP/SAVP", vec![offered]),
            Exchange::Offer,
        )
        .expect("re-offer");
        assert_eq!(
            keys.near.local.expect("key").key.master_key,
            before.key.master_key,
            "the same line keeps the key the party already holds"
        );
        assert!(keys
            .settle(Party::Far, &stream("RTP/AVP", Vec::new()), Exchange::Offer)
            .is_err());
    }

    #[test]
    fn the_keys_survive_a_snapshot_round_trip() {
        let mut keys = VideoKeys::default();
        keys.settle(
            Party::Near,
            &stream("RTP/SAVP", vec![key(2)]),
            Exchange::FirstOffer { far_secure: true },
        )
        .expect("offer");
        let snapshot = keys.snapshot().expect("secure");
        let restored = VideoKeys::restored(Some(&snapshot)).expect("restores");
        assert_eq!(
            restored.near.local.expect("key").key.master_key,
            keys.near.local.expect("key").key.master_key
        );
        assert_eq!(restored.far.remote.is_some(), keys.far.remote.is_some());
        assert!(VideoKeys::default().snapshot().is_none());
    }
}
