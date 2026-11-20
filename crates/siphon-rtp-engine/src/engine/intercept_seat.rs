//! Lawful interception of a conference seat that **joined** its room (`conference_join`,
//! `conference_answer`), ETSI TS 103 221-2 X3.
//!
//! Such a seat has no call behind it: the engine knows it by its room and its tag, and it is seated
//! by the control client whose join created it. So it is intercepted by naming the room as `call_id`
//! and the seat's tag as `from_tag` in `attach_x3` / `detach_x3`, its interception lives in a map of
//! its own keyed by that pair, and its events name the same pair.
//!
//! The interception ends when the seat does: `x3_ended` with `call_ended` at the seat's
//! `conference_leave` or when the room drops it (an idle reap, a failed ICE check) and so stops. The
//! seat's endpoint is remembered with the session, so a later seat that happens to reuse the tag is
//! never covered by the previous seat's warrant.
//!
//! A live call's leg seated by `conference_seat` is not handled here: its interception is its
//! call's ([`super::intercept`]).

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, Event, X3EndReason, X3TargetLeg, Xid};

use crate::x3::{x3_channel, X3TapFactory};

use super::intercept::{X3Selector, X3Session, X3TransportSpec};
use super::{error_result, ok_empty, unknown_call, ClientId, Engine};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Whether `client` is the control client whose join seated `tag` in `conference_id`. A seat is
    /// invisible to any other client, as a call is (docs/security-and-nat.md §5).
    fn owns_joined_seat(&self, client: ClientId, conference_id: &str, tag: &str) -> bool {
        let Some(Some(seated_by)) = self.conference.seat_owner_sink(conference_id, tag) else {
            return false;
        };
        self.event_sink(client)
            .is_some_and(|sink| sink.same_channel(&seated_by))
    }

    /// `attach_x3` on a joined seat: the seat is the target, so what it sent is `from_target` and
    /// what the room sent it is `to_target`; `target_leg` is carried into the event and has no say
    /// in a room.
    pub(super) async fn attach_x3_seat(
        &self,
        client: ClientId,
        conference_id: &str,
        tag: &str,
        delivery: &str,
        xid: Xid,
        correlation_id: u64,
        target_leg: X3TargetLeg,
    ) -> CmdResult {
        if !self.owns_joined_seat(client, conference_id, tag) {
            return unknown_call(conference_id);
        }
        // Held by `attach_x3`, which is the one entry point.
        match self
            .start_x3_seat(
                client,
                conference_id,
                tag,
                delivery,
                xid,
                correlation_id,
                target_leg,
            )
            .await
        {
            Ok(()) => ok_empty(),
            Err(reason) => error_result("attach_x3", &reason),
        }
    }

    /// Stand an interception up on a joined seat. Everything that can be refused is refused before
    /// anything is installed, exactly as for a call ([`Self::validate_x3_request`], TLS built up
    /// front), and the room's own answer to the taps is the last gate.
    #[allow(clippy::too_many_arguments)]
    async fn start_x3_seat(
        &self,
        client: ClientId,
        conference_id: &str,
        tag: &str,
        delivery: &str,
        xid: Xid,
        correlation_id: u64,
        target_leg: X3TargetLeg,
    ) -> Result<(), String> {
        let config = self.validate_x3_request(delivery, xid, correlation_id)?;
        let tls = self.x3_tls_config_for(&config)?;
        let Some(endpoint) = self.conference.joined_seat_endpoint(conference_id, tag) else {
            return Err("the seat no longer exists".to_string());
        };
        // Replacing a live delivery (same warrant, address and Correlation ID): stop that one first, so its
        // teardown cannot remove the taps just installed. The seat's other deliveries carry on.
        let key = (conference_id.to_string(), tag.to_string());
        self.end_x3_seat_where(
            conference_id,
            tag,
            |session| session.is(xid, delivery, correlation_id),
            |_| X3EndReason::Detached,
        )
        .await;

        let (factory, delivery_channel) = x3_channel(config.buffer_packets);
        // The room is installed with the whole set of the seat: the deliveries it already carries and
        // this one.
        let mut factories = self.seat_x3_factories(&key);
        let others = factories.clone();
        factories.push(factory.clone());
        if let Err(reason) = self.install_room_x3(conference_id, tag, &factories).await {
            // A refused install may have cost the other deliveries their taps.
            if !others.is_empty()
                && self
                    .install_room_x3(conference_id, tag, &others)
                    .await
                    .is_err()
            {
                self.end_x3_seat_where(
                    conference_id,
                    tag,
                    |_| true,
                    |_| X3EndReason::TransportError,
                )
                .await;
            }
            return Err(reason);
        }

        let counters = factory.counters().clone();
        let (transport, ended) = self.spawn_x3_transport(X3TransportSpec {
            delivery_channel,
            tls,
            config: &config,
            delivery,
            xid,
            correlation_id,
            owner: client,
            call_id: conference_id,
            from_tag: tag,
            counters: counters.clone(),
        });
        self.x3_seat_sessions
            .entry(key)
            .or_default()
            .push(X3Session {
                xid,
                delivery: delivery.to_string(),
                correlation_id,
                from_tag: tag.to_string(),
                owner: client,
                bridged_endpoints: Vec::new(),
                factory,
                target_is_caller: true,
                counters,
                transport,
                ended,
                joined_endpoint: Some(endpoint),
                handing_over: Default::default(),
                detach_requested: Default::default(),
            });
        self.push_event(
            client,
            Event::X3Started {
                call_id: conference_id.to_string(),
                from_tag: tag.to_string(),
                delivery: delivery.to_string(),
                xid,
                correlation_id,
                target_leg,
            },
        );
        tracing::info!(
            target: "siphon_rtp::li",
            conference = conference_id,
            tag,
            delivery,
            %xid,
            "lawful-interception content delivery attached to a conference seat"
        );
        Ok(())
    }

    /// `detach_x3` on a joined seat: the deliveries `selector` names. Idempotent for a seat that
    /// exists; an unknown or foreign seat is an unknown call. Called with the sessions lock held.
    pub(super) async fn detach_x3_seat(
        &self,
        client: ClientId,
        conference_id: &str,
        tag: &str,
        selector: X3Selector<'_>,
    ) -> CmdResult {
        if !self.owns_joined_seat(client, conference_id, tag) {
            return unknown_call(conference_id);
        }
        self.end_x3_seat_where(
            conference_id,
            tag,
            |session| selector.matches(session),
            |_| X3EndReason::Detached,
        )
        .await;
        ok_empty()
    }

    /// The tap factories of every delivery on a seat, in attach order.
    fn seat_x3_factories(&self, key: &(String, String)) -> Vec<X3TapFactory> {
        self.x3_seat_sessions
            .get(key)
            .map(|sessions| {
                sessions
                    .iter()
                    .map(|session| session.factory.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Tear every interception of a joined seat down: take the taps off, let the delivery tasks
    /// drain and report `x3_ended` once each. A no-op for a seat that is not intercepted.
    pub(super) async fn stop_x3_seat(&self, conference_id: &str, tag: &str, reason: X3EndReason) {
        let _changing = self.x3_sessions.lock.lock().await;
        self.end_x3_seat_where(conference_id, tag, |_| true, |_| reason)
            .await;
    }

    /// End the deliveries of a joined seat that `select` picks and leave the rest delivering, their
    /// taps installed again as the seat's whole set. Callers hold the sessions lock.
    async fn end_x3_seat_where(
        &self,
        conference_id: &str,
        tag: &str,
        select: impl Fn(&X3Session) -> bool,
        reason_of: impl Fn(&X3Session) -> X3EndReason,
    ) {
        let key = (conference_id.to_string(), tag.to_string());
        let mut ended: Vec<(X3Session, X3EndReason)> = Vec::new();
        if let Some(mut sessions) = self.x3_seat_sessions.get_mut(&key) {
            for session in std::mem::take(&mut *sessions) {
                if select(&session) {
                    let reason = reason_of(&session);
                    ended.push((session, reason));
                } else {
                    sessions.push(session);
                }
            }
        }
        self.x3_seat_sessions
            .remove_if(&key, |_, sessions| sessions.is_empty());
        if ended.is_empty() {
            return;
        }
        let remaining = self.seat_x3_factories(&key);
        if remaining.is_empty() {
            self.clear_room_x3(conference_id, tag).await;
        } else if let Err(reason) = self.install_room_x3(conference_id, tag, &remaining).await {
            tracing::error!(
                target: "siphon_rtp::li",
                conference = conference_id,
                tag,
                reason,
                "lawful-interception taps could not be rebuilt after a delivery ended; ending the \
                 seat's remaining deliveries rather than leaving them silently deaf"
            );
            if let Some((_, rest)) = self.x3_seat_sessions.remove(&key) {
                ended.extend(
                    rest.into_iter()
                        .map(|session| (session, X3EndReason::TransportError)),
                );
            }
            self.clear_room_x3(conference_id, tag).await;
        }
        for (session, reason) in ended {
            self.finish_x3_session(conference_id, session, reason).await;
        }
    }

    /// End the interception of every joined seat the room no longer holds: one an idle reap or a
    /// failed ICE check removed, or whose room stopped, since none of those pass through
    /// `conference_leave`. The seat's endpoint is compared too, so a new seat under a reused tag is
    /// not mistaken for the old one.
    pub(super) async fn end_orphaned_seat_x3(&self) {
        let orphans: Vec<(String, String)> = self
            .x3_seat_sessions
            .iter()
            .filter(|entry| {
                let (conference_id, tag) = entry.key();
                // Every delivery of a seat names the same endpoint.
                let endpoint = entry
                    .value()
                    .first()
                    .and_then(|session| session.joined_endpoint);
                self.conference.joined_seat_endpoint(conference_id, tag) != endpoint
            })
            .map(|entry| entry.key().clone())
            .collect();
        for (conference_id, tag) in orphans {
            self.stop_x3_seat(&conference_id, &tag, X3EndReason::CallEnded)
                .await;
        }
    }
}
