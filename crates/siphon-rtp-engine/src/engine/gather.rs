//! ICE candidates: gathering host, server-reflexive and relayed candidates (RFC 8445), and
//! accepting trickled ones (RFC 8838).

use siphon_rtp_datapath::{Datapath, EndpointId, IceAgentMode, IceConfig};
use siphon_rtp_ice::{GatherAction, GatherConfig, Gatherer};
use siphon_rtp_proto::CmdResult;
use siphon_rtp_stun::turn_client::{TurnAction, TurnClient, TurnCredentials};
use std::net::SocketAddr;

use crate::ice::IceCredentials;

use super::{ok_empty, unknown_call, ClientId, Engine, Leg};

/// One endpoint's live TURN allocation, kept for the life of the leg.
///
/// The allocation is not a gathering artefact that can be dropped once the candidate is advertised:
/// it must be refreshed before its lifetime lapses, and every remote candidate the checklist may
/// probe needs a permission and a channel before anything can reach it (RFC 5766 §9, §11).
pub(super) struct TurnAllocation {
    pub(super) client: TurnClient,
    /// The channels last pushed to the datapath, so a redundant `set_turn_relay` is not issued on
    /// every tick — only when the bindings actually change.
    pub(super) published: Vec<(SocketAddr, u16)>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Accept a peer's **trickled** ICE candidates (RFC 8838 §4.2) and put them to work immediately.
    ///
    /// Each line is parsed, handed to the leg's agent, paired against our local candidates and queued
    /// as a triggered check — so a path that only becomes known after the offer/answer is probed
    /// promptly rather than waiting for the ordinary checklist order, and a candidate that arrives
    /// after every earlier pair has failed reopens the session instead of arriving too late.
    ///
    /// Owner-only (A3). `to_tag` selects the side: absent ⇒ the offerer's (near) leg, present ⇒ the
    /// answerer's (far) leg.
    ///
    /// A candidate we cannot pair with — a different family or component, an unresolvable mDNS name,
    /// a transport we do not check — is skipped and counted, never fatal: a browser mixes those in
    /// with usable ones, and rejecting the batch would cost us the usable ones too.
    pub(super) fn ice_candidate(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        to_tag: Option<&str>,
        candidates: &[String],
        end_of_candidates: bool,
    ) -> CmdResult {
        let Some(endpoints) = self.calls.get(call_id).and_then(|call| {
            (call.owner == client && call.from_tag == from_tag)
                .then(|| {
                    // A `to_tag` selects the answerer's leg — which a locally-answered call does not
                    // have, and neither does it run ICE, so there is nothing to trickle into.
                    let leg = if to_tag.is_some() {
                        call.far.as_ref()?
                    } else {
                        &call.near
                    };
                    Some(leg.endpoint_ids().collect::<Vec<_>>())
                })
                .flatten()
        }) else {
            return unknown_call(call_id);
        };
        let Some(agents) = self.ice_agents.as_ref() else {
            // Trickle only means something to a full agent: the ICE-lite responder has no checklist
            // to add a pair to. Say so rather than silently accepting and discarding.
            return CmdResult::Error {
                reason: "trickled ICE candidates require full ICE (--ice-full)".to_string(),
            };
        };

        let mut paired = 0usize;
        let mut skipped = 0usize;
        for line in candidates {
            match siphon_rtp_ice::Candidate::parse(line) {
                Ok(candidate) => {
                    // Each endpoint runs the agent for its own component, so only the matching one
                    // takes the candidate; the rest report 0 pairs.
                    let added: usize = endpoints
                        .iter()
                        .map(|endpoint| agents.add_remote_candidate(*endpoint, &candidate))
                        .sum();
                    if added == 0 {
                        skipped += 1;
                    } else {
                        paired += added;
                    }
                }
                Err(error) => {
                    skipped += 1;
                    tracing::debug!(
                        target: "siphon_rtp::control",
                        %call_id, candidate = %line.trim(), %error,
                        "skipping a trickled ICE candidate we cannot use"
                    );
                }
            }
        }
        tracing::info!(
            target: "siphon_rtp::control",
            %call_id,
            leg = if to_tag.is_some() { "far" } else { "near" },
            paired,
            skipped,
            end_of_candidates,
            "accepted trickled ICE candidates (RFC 8838)"
        );
        ok_empty()
    }

    /// The ICE candidates to present for `leg`: the ones already advertised for it when there are any
    /// (the ports have not moved, so they are still exactly right, and re-gathering would change what
    /// the peer holds), gathered now otherwise.
    pub(super) async fn leg_candidates(
        &self,
        leg: &Leg,
        stored: &[siphon_rtp_ice::Candidate],
        creds: &IceCredentials,
    ) -> Vec<siphon_rtp_ice::Candidate> {
        if !stored.is_empty() {
            return stored.to_vec();
        }
        self.gather_leg_candidates(
            leg,
            &IceConfig {
                local_ufrag: creds.ufrag.clone(),
                local_pwd: creds.pwd.clone(),
            },
        )
        .await
    }

    /// Gather the ICE candidates to advertise for one leg (RFC 8445 §5.1.1): the host candidate for
    /// its RTP endpoint, a server-reflexive one per configured STUN server that answers, and — when
    /// the leg is not muxed — the same for its companion RTCP endpoint as component 2 (RFC 8445
    /// §4.1.1.1).
    ///
    /// Runs on the offer/answer control path, so it is **bounded by construction**: with no STUN
    /// server configured it completes without a single packet, and with one it gives up at the
    /// gatherer's deadline and advertises what it has. A dead STUN server costs one bounded delay and
    /// a host-only candidate list; it never fails the call.
    ///
    /// Wall time, deliberately: this is a network deadline on the control path, not a media clock, and
    /// the datapath's logical clock only advances once per second. The *decisions* (pacing,
    /// retransmission, pruning, completion) all live in the pure [`Gatherer`], which the crate's own
    /// tests drive on a logical millisecond clock — nothing here re-implements them.
    pub(super) async fn gather_leg_candidates(
        &self,
        leg: &Leg,
        ice_config: &IceConfig,
    ) -> Vec<siphon_rtp_ice::Candidate> {
        let components = [(leg.rtp, 1u16), (leg.rtcp.unwrap_or(leg.rtp), 2u16)];
        let component_count = if leg.rtcp.is_some() { 2 } else { 1 };
        // Gather both components **concurrently**: they probe independent endpoints, and running them
        // in sequence would make a dead STUN server cost two deadlines on the control path instead of
        // one. `join_all` preserves order, so component 1's candidates still come first.
        let gathers = components
            .into_iter()
            .take(component_count)
            .map(|(endpoint, component)| {
                let config = GatherConfig {
                    component,
                    // The advertised address keeps the leg's interface policy (1:1 NAT) — the bound
                    // address is the base, the advertised one is what a peer must be able to reach.
                    advertised: SocketAddr::new(leg.advertised_ip, endpoint.local_addr.port()),
                    ..GatherConfig::host_only(endpoint.local_addr)
                        .with_stun_servers(self.stun_servers.clone())
                };
                self.run_gatherer(endpoint.id, config, ice_config)
            });
        futures_util::future::join_all(gathers)
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// Drive one endpoint's [`Gatherer`] to completion, doing its I/O.
    async fn run_gatherer(
        &self,
        endpoint: EndpointId,
        config: GatherConfig,
        ice_config: &IceConfig,
    ) -> Vec<siphon_rtp_ice::Candidate> {
        // Kept before the gatherer takes the config: the relayed candidate belongs to the same
        // component as everything else gathered on this endpoint.
        let gather_component = config.component;
        let mut gatherer = Gatherer::new(config, 0);
        // A relayed candidate is gathered on this same endpoint and needs the response sink below,
        // so "host-only" is only a fast path when there is no allocation to make either.
        let gathering_relay = self.turn_server.is_some() && self.datapath.supports_turn_relay();
        // Host-only: the answer is already known, so never touch the socket or the clock.
        if gatherer.is_complete() && !gathering_relay {
            return gatherer.candidates().to_vec();
        }
        // Reflexive gathering needs the datapath's full-agent seam to hand back the Binding
        // *responses* the ICE responder drops. The sink is replaced at answer time by the consent
        // supervisor's (or cleared, if the peer turns out not to speak ICE).
        let (events_tx, events_rx) = flume::bounded(GATHER_EVENT_QUEUE_DEPTH);
        // Gathering only needs its own Binding responses back; the datapath keeps answering inbound
        // checks meanwhile, so an early peer check is not lost while we gather.
        self.datapath.set_ice_agent(
            endpoint,
            ice_config.clone(),
            IceAgentMode::RespondAndForward,
            events_tx,
        );

        let started = tokio::time::Instant::now();
        let elapsed_ms = |start: tokio::time::Instant| start.elapsed().as_millis() as u64;
        loop {
            match gatherer.poll(elapsed_ms(started)) {
                GatherAction::Complete => break,
                GatherAction::Probe { server, datagram } => {
                    if let Err(error) = self.datapath.send(endpoint, server, &datagram).await {
                        // A send failure is not fatal: the retransmission schedule tries again and
                        // the deadline still bounds the whole thing.
                        tracing::debug!(
                            target: "siphon_rtp::control",
                            ?endpoint, %server, %error,
                            "failed to transmit ICE gathering probe"
                        );
                    }
                }
                GatherAction::Idle => {}
            }
            // Wait for a response, but never longer than the pacing slot — so a silent server still
            // gets its retransmissions on schedule.
            if let Ok(Ok(event)) = tokio::time::timeout(
                std::time::Duration::from_millis(GATHER_POLL_INTERVAL_MS),
                events_rx.recv_async(),
            )
            .await
            {
                gatherer.on_datagram(event.source, &event.datagram, elapsed_ms(started));
            }
        }
        // Relayed candidate (RFC 8445 §5.1.1.2 / RFC 5766): allocate against the configured TURN
        // server on this same endpoint, within the same bounded window. Advertised only when the
        // allocation actually comes up *and* the datapath can relay through it — an advertised
        // relayed candidate the peer nominates and we then cannot carry is worse than not offering
        // one, because it turns a call that would have failed over into one that fails outright.
        let mut relayed = self
            .gather_relayed_candidate(endpoint, gather_component, &events_rx, started)
            .await;

        let unanswered = gatherer.unanswered_servers();
        if !unanswered.is_empty() {
            // Say it out loud: the advertised set is smaller than it was meant to be.
            tracing::warn!(
                target: "siphon_rtp::control",
                ?endpoint,
                servers = ?unanswered,
                elapsed_ms = elapsed_ms(started),
                "ICE gathering: STUN server(s) did not answer — advertising without a server-reflexive candidate"
            );
        }
        let mut candidates = gatherer.candidates().to_vec();
        candidates.append(&mut relayed);
        candidates
    }

    /// Allocate a TURN relay on `endpoint` and turn it into a relayed ICE candidate, or return an
    /// empty list when there is no TURN server configured, the backend cannot relay, or the
    /// allocation does not come up inside the gathering deadline.
    ///
    /// The allocation is **kept** on success (in `ice_relays`): it needs refreshing for the life of
    /// the leg, and each remote candidate needs a permission before it can reach us.
    async fn gather_relayed_candidate(
        &self,
        endpoint: EndpointId,
        component: u16,
        events_rx: &flume::Receiver<siphon_rtp_datapath::IceDatapathEvent>,
        started: tokio::time::Instant,
    ) -> Vec<siphon_rtp_ice::Candidate> {
        let Some(turn) = self.turn_server.clone() else {
            return Vec::new();
        };
        // Never advertise a path this datapath cannot actually carry.
        if !self.datapath.supports_turn_relay() {
            tracing::warn!(
                target: "siphon_rtp::control",
                ?endpoint,
                "a TURN server is configured but this datapath backend cannot relay through an \
                 allocation — not advertising a relayed candidate"
            );
            return Vec::new();
        }
        let elapsed_ms = |start: tokio::time::Instant| start.elapsed().as_millis() as u64;
        let mut client = TurnClient::new(
            turn.server,
            TurnCredentials::new(turn.username.clone(), turn.password.clone()),
            siphon_rtp_ice::gather::DEFAULT_RTO_MS,
        );
        // Bounded exactly like STUN gathering: a dead TURN server costs one deadline and a
        // host-only candidate list, never a hung offer.
        while elapsed_ms(started) < TURN_GATHER_DEADLINE_MS && !client.is_terminal() {
            if client.is_allocated() {
                break;
            }
            if let TurnAction::Send { datagram } = client.poll(elapsed_ms(started)) {
                if let Err(error) = self.datapath.send(endpoint, turn.server, &datagram).await {
                    tracing::debug!(
                        target: "siphon_rtp::control",
                        ?endpoint, server = %turn.server, %error,
                        "failed to transmit a TURN allocation request"
                    );
                }
            }
            if let Ok(Ok(event)) = tokio::time::timeout(
                std::time::Duration::from_millis(GATHER_POLL_INTERVAL_MS),
                events_rx.recv_async(),
            )
            .await
            {
                // Only the server's own datagrams are the allocation's; a peer's early check on this
                // endpoint is not, and feeding it in would be uncorrelated noise.
                if event.source == turn.server {
                    client.on_datagram(&event.datagram, elapsed_ms(started));
                }
            }
        }
        let Some(relayed_addr) = client.relayed_address() else {
            // Say why, rather than silently shipping a smaller candidate list.
            tracing::warn!(
                target: "siphon_rtp::control",
                ?endpoint,
                server = %turn.server,
                state = ?client.state(),
                elapsed_ms = elapsed_ms(started),
                "TURN allocation did not come up — advertising without a relayed candidate"
            );
            return Vec::new();
        };
        // The allocation is live: install it on the datapath (no channels yet — they arrive as
        // remote candidates are learned) and keep the client for refreshing.
        self.datapath.set_turn_relay(
            endpoint,
            Some(siphon_rtp_datapath::TurnRelay {
                server: turn.server,
                channels: Vec::new(),
            }),
        );
        if let Some(agents) = &self.ice_agents {
            agents.set_turn_server(endpoint, Some(turn.server));
        }
        self.ice_relays.insert(
            endpoint,
            TurnAllocation {
                client,
                published: Vec::new(),
            },
        );
        tracing::info!(
            target: "siphon_rtp::control",
            ?endpoint,
            server = %turn.server,
            relayed = %relayed_addr,
            "TURN allocation established — advertising a relayed ICE candidate"
        );
        vec![siphon_rtp_ice::Candidate {
            foundation: siphon_rtp_ice::Candidate::compute_foundation(
                siphon_rtp_ice::CandidateKind::Relayed,
                relayed_addr.ip(),
                &siphon_rtp_ice::Transport::Udp,
                Some(turn.server),
            ),
            ..siphon_rtp_ice::Candidate::new(
                String::new(),
                component,
                relayed_addr,
                siphon_rtp_ice::CandidateKind::Relayed,
                siphon_rtp_ice::gather::DEFAULT_LOCAL_PREFERENCE,
            )
        }]
    }
}

/// Depth of the per-endpoint STUN queue used while gathering. Gathering sends a handful of probes and
/// drains continuously, so this only has to absorb a burst; drop-on-full costs at most one refresh.
const GATHER_EVENT_QUEUE_DEPTH: usize = 32;

/// How long the gathering loop waits for a response before re-polling the plan. Shorter than the
/// RFC 8445 §14.2 `Ta` pacing slot, so a silent STUN server still gets its retransmissions on time.
/// How long a TURN allocation may take before gathering gives up on it, in milliseconds. Matches the
/// STUN gathering deadline's intent: a dead relay costs one bounded delay, never a hung offer.
const TURN_GATHER_DEADLINE_MS: u64 = 1_500;

const GATHER_POLL_INTERVAL_MS: u64 = 10;
