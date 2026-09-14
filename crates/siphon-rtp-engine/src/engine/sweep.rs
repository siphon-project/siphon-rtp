//! Periodic engine work: idle-media reaping, latch refresh, and driving ICE agents, TURN
//! allocations and consent.

use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction};
use siphon_rtp_proto::{Event, MediaTimeoutReason};
use siphon_rtp_stun::turn_client::TurnAction;
use std::net::SocketAddr;

use crate::ice::driver::{AgentOutcome, ConsentOutcome};

use super::Engine;

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Reap calls whose media has been idle for at least `idle_ticks`, freeing their ports/FDs and
    /// registry/quota slots, and return the reaped call ids. Deterministic: it reads the datapath's
    /// logical clock, so tests drive it via `advance_clock` rather than wall time (never
    /// `Instant::now()`). (docs/security-and-nat.md §4 layer 6.)
    ///
    /// **Silence only means a dead path while someone was expected to speak.** A dead media path and a
    /// held call are indistinguishable at the packet layer — both are silence — and only the SDP says
    /// which it is. RFC 3264 §8.4 lets a party that holds a call send nothing at all, and its peer
    /// answers `recvonly` and correctly sends nothing back, so a rule that reads "no packets from
    /// anyone" tears down a call whose user is still holding the handset. Hold, park and queue are all
    /// exactly that state, and they last minutes.
    ///
    /// So a call the signalling has taken off two-way media (`Call::is_held`) is measured against
    /// `held_idle_ticks` — a much longer ceiling (`--held-media-timeout-secs`) so a call abandoned on
    /// hold still ends eventually, with `0` disabling it so such a call never ages out. Everything else
    /// keeps the dead-path rule unchanged, down to reading the same endpoint set. The
    /// [`MediaTimeoutReason`] on the event says which rule fired.
    pub async fn reap_idle(&self, idle_ticks: u64, held_idle_ticks: u64) -> Vec<String> {
        let now = self.datapath.now_ticks();
        // First pass (no `.await`, so holding the shard guards is fine): find the idle calls.
        let mut stale = Vec::new();
        for entry in self.calls.iter() {
            let call = entry.value();
            let (budget, reason) = if call.is_held() {
                (held_idle_ticks, MediaTimeoutReason::HeldTooLong)
            } else {
                (idle_ticks, MediaTimeoutReason::NoMedia)
            };
            // `0` disables the held ceiling. It is never a valid *media* timeout, so this only ever
            // spares a held call.
            if budget == 0 {
                continue;
            }
            // Measured exactly as before — the latest accepted packet across every endpoint, text
            // included (RFC 4103 text is media too, and a text-only exchange is not a dead path),
            // falling back to the call's creation. A held call that *does* carry music-on-hold refreshes
            // its own ceiling, which is right: it is demonstrably alive.
            let mut last_activity = call.created_tick;
            for endpoint in call.all_endpoint_ids() {
                if let Some(seen) = self.datapath.last_activity(endpoint) {
                    last_activity = last_activity.max(seen);
                }
            }
            if now.saturating_sub(last_activity) >= budget {
                stale.push((entry.key().clone(), reason));
            }
        }
        // Second pass: tear each idle call down (no map guard held across the awaits). Shared with
        // consent failure — both are dead-path detections and must free identical state.
        let mut reaped = Vec::new();
        for (call_id, reason) in stale {
            let cdr_reason = match reason {
                MediaTimeoutReason::HeldTooLong => "held_timeout",
                _ => "media_timeout",
            };
            if self.reap_call(&call_id, cdr_reason, reason).await {
                reaped.push(call_id);
            }
        }
        reaped
    }

    /// Drive the full RFC 8445 agents one tick at `now_ms`: hand them the STUN the datapath
    /// forwarded, let them emit checks, and act on what they decide.
    ///
    /// A no-op unless `--ice full` is set. Called on a sub-second clock (the RFC's `Ta` pacing is
    /// 50 ms and its initial RTO 500 ms — far finer than the 1 Hz media sweep), which is why it takes
    /// an explicit millisecond rather than reading the datapath's logical tick.
    pub async fn drive_ice_agents(&self, now_ms: u64) -> Vec<String> {
        let Some(agents) = self.ice_agents.clone() else {
            return Vec::new();
        };
        // Ingest first, so a check that arrived this tick is answered on this tick.
        let mut outcomes = agents.drain_events(now_ms);
        outcomes.extend(agents.poll(now_ms));

        // Keep every live allocation alive and reachable before handling this tick's outcomes: a
        // lapsed allocation or a missing permission silently stops the relay carrying anything.
        self.drive_turn_allocations(now_ms).await;

        let mut failed = Vec::new();
        for outcome in outcomes {
            match outcome {
                AgentOutcome::Send {
                    endpoint,
                    dst,
                    datagram,
                } => {
                    if let Err(error) = self.datapath.send(endpoint, dst, &datagram).await {
                        // Transient: the RFC 8489 retransmission covers it, and the checklist's own
                        // failure path covers a pair that never works.
                        tracing::debug!(
                            target: "siphon_rtp::media",
                            ?endpoint, %dst, %error,
                            "failed to transmit ICE connectivity check"
                        );
                    }
                }
                AgentOutcome::Selected {
                    endpoint,
                    call_id,
                    remote,
                } => {
                    // The one write that opens the media path. The datapath's forward rule already
                    // prefers an endpoint's adopted source over the signalled `out_dst`, so this both
                    // gates ingress to the selected pair and re-points the sibling's egress at it —
                    // and RFC 7675 consent, which resolves its target from the same adopted source,
                    // follows the selection without being told.
                    self.datapath.adopt_source(endpoint, remote);
                    // A conference seat is not a relay leg — the room, not a forward rule, owns its
                    // egress — so adopting the source is not enough: the room must be told, or it
                    // would keep sending the mix to the signalled `c=` address (for a NATed ICE peer,
                    // one it cannot receive on) and keep dropping ingress on its pending gate.
                    // A no-op for the common case of a 2-party leg.
                    self.conference.ice_selected(endpoint, remote);
                    // Same for a WebSocket-takeover leg: the bridge's drain task owns its egress, so
                    // without this the downlink would keep going to the signalled `c=` while the
                    // registry's pending gate kept dropping ingress. A no-op for any other leg.
                    self.ws.ice_selected(endpoint, remote);
                    // A DTLS-SRTP leg keys the path ICE chose: this releases a gated handshake and
                    // re-points its records and media at the selected pair (RFC 8445 §12). A no-op
                    // for a leg with no DTLS bridge.
                    self.dtls_bridge().set_ice_selected(endpoint, remote);
                    tracing::info!(
                        target: "siphon_rtp::media",
                        %call_id, ?endpoint, %remote,
                        "ICE selected a candidate pair (RFC 8445 §8.1.1) — media path open"
                    );
                }
                AgentOutcome::TurnDatagram { endpoint, datagram } => {
                    // An allocation response (Allocate / Refresh / CreatePermission / ChannelBind).
                    if let Some(mut allocation) = self.ice_relays.get_mut(&endpoint) {
                        allocation.client.on_datagram(&datagram, now_ms);
                    }
                }
                AgentOutcome::Failed { endpoint, call_id } => {
                    // RFC 8445 §8.1.2: every pair failed, so there is no path to this peer at all.
                    // A conference seat is dropped rather than reaped as a call: it has no `MediaCall`
                    // to tear down, and leaving it seated would hold a room open around a participant
                    // that can never be reached — its gate would stay pending forever.
                    if let Some((conference_id, tag)) = self.conference.participant_at(endpoint) {
                        // A seat can own more than one endpoint (audio plus an RFC 9071 text leg),
                        // so free every one `leave` hands back — not just the ICE one that failed.
                        for seat_endpoint in self.conference.leave(&conference_id, &tag) {
                            self.endpoint_calls.remove(&seat_endpoint);
                            self.datapath.remove_endpoint(seat_endpoint).await;
                        }
                        tracing::warn!(
                            target: "siphon_rtp::media",
                            conference = %conference_id, tag, ?endpoint,
                            "ICE failed for a conference seat — no candidate pair succeeded; \
                             participant removed"
                        );
                        failed.push(conference_id);
                        continue;
                    }
                    // An ICE failure is a dead path: no candidate pair ever succeeded, so there is no
                    // media path to be held on. `NoMedia`, never the held reason.
                    if self
                        .reap_call(&call_id, "ice_failed", MediaTimeoutReason::NoMedia)
                        .await
                    {
                        tracing::warn!(
                            target: "siphon_rtp::media",
                            %call_id, ?endpoint,
                            "ICE failed — no candidate pair succeeded; call torn down"
                        );
                        failed.push(call_id);
                    }
                }
            }
        }
        failed
    }

    /// Drive every live TURN allocation one tick (RFC 5766): transmit whatever the client has due,
    /// make sure each remote candidate the checklist may probe has a permission, and push any change
    /// in the bound channels down to the datapath.
    ///
    /// This is what keeps a relayed candidate *usable* rather than merely advertised. An allocation
    /// that is not refreshed lapses and the relay silently stops carrying media mid-call; a peer with
    /// no permission has its traffic dropped by the server (§9), so its pairs fail for a reason that
    /// looks like a network problem and is not.
    ///
    /// An allocation that dies is torn out and the datapath's relay cleared, so the leg falls back to
    /// its host and server-reflexive candidates instead of sending into a relay that no longer exists.
    async fn drive_turn_allocations(&self, now_ms: u64) {
        if self.ice_relays.is_empty() {
            return;
        }
        // Collected first: the sends below are `.await`s, and a `DashMap` guard must never be held
        // across one.
        let endpoints: Vec<EndpointId> = self.ice_relays.iter().map(|entry| *entry.key()).collect();
        for endpoint in endpoints {
            // Every remote candidate the agent knows about needs a permission before the server will
            // relay its traffic. Adding a peer is idempotent, so this can run every tick.
            let peers = self
                .ice_agents
                .as_ref()
                .map(|agents| agents.remote_addresses(endpoint))
                .unwrap_or_default();

            let (server, datagrams, channels, terminal) = {
                let Some(mut allocation) = self.ice_relays.get_mut(&endpoint) else {
                    continue;
                };
                for peer in peers {
                    allocation.client.add_peer(peer);
                }
                // Drain everything due this tick — an allocation refresh and several permission or
                // channel requests can fall due together.
                let server = allocation.client.server();
                // The client serialises its requests — at most one is outstanding at a time — so a
                // tick emits at most one datagram, and the next is picked up on the next tick.
                let mut datagrams = Vec::new();
                if let TurnAction::Send { datagram } = allocation.client.poll(now_ms) {
                    datagrams.push(datagram);
                }
                let channels: Vec<(SocketAddr, u16)> = allocation
                    .client
                    .peers()
                    .iter()
                    .filter_map(|binding| binding.channel.map(|channel| (binding.peer, channel)))
                    .collect();
                let changed = channels != allocation.published;
                if changed {
                    allocation.published.clone_from(&channels);
                }
                let terminal = allocation.client.is_terminal();
                (server, datagrams, changed.then_some(channels), terminal)
            };

            // A newly bound (or lost) channel changes how the datapath frames this leg's traffic.
            if let Some(channels) = channels {
                self.datapath.set_turn_relay(
                    endpoint,
                    Some(siphon_rtp_datapath::TurnRelay { server, channels }),
                );
            }
            for datagram in datagrams {
                if let Err(error) = self.datapath.send(endpoint, server, &datagram).await {
                    // Transient: the RFC 8489 retransmission covers it, and the client's own timeout
                    // covers a server that has genuinely gone away.
                    tracing::debug!(
                        target: "siphon_rtp::media",
                        ?endpoint, %server, %error,
                        "failed to transmit a TURN request"
                    );
                }
            }
            if terminal {
                // The relay is gone. Clear it rather than keep wrapping traffic for a server that is
                // no longer relaying — the leg's host / server-reflexive pairs still work.
                let state = self
                    .ice_relays
                    .remove(&endpoint)
                    .map(|(_, allocation)| format!("{:?}", allocation.client.state()));
                self.datapath.set_turn_relay(endpoint, None);
                if let Some(agents) = &self.ice_agents {
                    agents.set_turn_server(endpoint, None);
                }
                tracing::warn!(
                    target: "siphon_rtp::media",
                    ?endpoint, %server, ?state,
                    "TURN allocation ended — the relayed candidate is no longer usable"
                );
            }
        }
    }

    /// Drive RFC 7675 consent freshness one tick: correlate the STUN the datapath forwarded since the
    /// last tick, emit each due connectivity check on its endpoint's **validated** path, and tear down
    /// any call whose peer has stopped answering. Returns the call-ids torn down (for the sweeper's
    /// log). A no-op when consent is disabled (the ICE-lite posture, RFC 7675 §4).
    ///
    /// Deterministic: driven by the datapath's logical clock, exactly like [`Self::reap_idle`], so
    /// tests advance it with `advance_clock` instead of waiting on wall time.
    pub async fn drive_consent(&self) -> Vec<String> {
        let Some(consent) = self.consent.clone() else {
            return Vec::new();
        };
        let now = self.datapath.now_ticks();
        // Ingest first: a response that arrived this tick must refresh consent *before* expiry is
        // evaluated, or a live path could be failed by a check answered moments ago.
        consent.drain_events();
        let outcomes = consent.poll(|endpoint| self.datapath.ice_validated_source(endpoint), now);

        let mut failed = Vec::new();
        for outcome in outcomes {
            match outcome {
                ConsentOutcome::Send {
                    endpoint,
                    dst,
                    datagram,
                } => {
                    // Checks egress the media endpoint itself, so the peer sees them from the same
                    // transport address it validated (RFC 8445 §7.1: a check is sent from the base of
                    // the local candidate). A send failure is transient — the retransmit schedule
                    // covers it; only the RFC 7675 window declares the pair dead.
                    if let Err(error) = self.datapath.send(endpoint, dst, &datagram).await {
                        tracing::debug!(
                            target: "siphon_rtp::media",
                            ?endpoint,
                            %dst,
                            %error,
                            "failed to transmit ICE consent check"
                        );
                    }
                }
                ConsentOutcome::Failed { endpoint, call_id } => {
                    // Only tear the call down once, even though both its legs may fail on the same
                    // tick: `reap_call` removes it from the registry, so the second attempt is a
                    // no-op and must not double-count.
                    consent.unregister(endpoint);
                    // A consent failure is a dead path by definition — the peer stopped answering
                    // checks — so it reports `NoMedia` rather than either idle rule.
                    if self
                        .reap_call(&call_id, "consent_failed", MediaTimeoutReason::NoMedia)
                        .await
                    {
                        tracing::warn!(
                            target: "siphon_rtp::media",
                            %call_id,
                            ?endpoint,
                            "ICE consent freshness lost (RFC 7675) — peer stopped answering checks; call torn down"
                        );
                        failed.push(call_id);
                    }
                }
            }
        }
        failed
    }

    /// Tear down one call as a **dead path**: emit its CDR with `reason`, free every resource it
    /// holds, and notify its owner with [`Event::MediaTimeout`]. Returns whether the call was still
    /// live (so a caller can avoid double-reporting). Shared by the media-timeout sweep and consent
    /// failure so both dead-path detectors free exactly the same state.
    ///
    /// The event is `MediaTimeout` for a consent failure too: the control contract has no dedicated
    /// ICE-state event yet, and to a controller both mean the same thing — this call's media path is
    /// gone, tear the dialog down. The distinction is preserved in the CDR `reason`, the log, and (for
    /// the two idle rules) the event's own [`MediaTimeoutReason`].
    async fn reap_call(
        &self,
        call_id: &str,
        reason: &str,
        timeout_reason: MediaTimeoutReason,
    ) -> bool {
        let Some((_, call)) = self.calls.remove(call_id) else {
            return false;
        };
        self.finish_call(call_id, &call, reason).await;
        self.push_event(
            call.owner,
            Event::MediaTimeout {
                call_id: call_id.to_string(),
                from_tag: call.from_tag,
                reason: timeout_reason,
            },
        );
        true
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
    pub async fn reap_idle_conferences(&self, idle_ticks: u64, held_idle_ticks: u64) -> usize {
        let now = self.datapath.now_ticks();
        let freed = self
            .conference
            .reap_idle(now, idle_ticks, held_idle_ticks, |endpoint| {
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
}
