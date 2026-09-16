//! The per-leg DTLS driver: one task that owns a [`DtlsSession`] and pumps it.
//!
//! `rtc-dtls` is sans-I/O — it owns no socket, reads no clock and spawns nothing — so a leg needs
//! exactly one task to feed it inbound records, drain the records it wants sent, and fire its
//! retransmission timer. That replaces the two detached tasks the old `webrtc-dtls` bridge ran per
//! leg (a handshake task plus an outbound drain), and it is what makes the association's lifetime
//! ours: the session stays alive after the handshake completes, which is what lets a lost last flight
//! be retransmitted (RFC 6347 §4.2.4).
//!
//! The state machine **queues** records rather than sending them, so every arm of the loop is
//! followed by draining [`DtlsSession::poll_transmit`] and recomputing the deadline.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_dtls::{DtlsCertificate, DtlsEvent, DtlsRole, DtlsSession, Fingerprint};
use siphon_rtp_srtp::leg::SecureLeg;
use tokio::task::JoinHandle;

use crate::dtls_bridge::{PipelineTarget, SecureDestination, SharedSecureLeg};

/// The initial RFC 6347 §4.2.4 retransmission timeout. One second is the DTLS default and what the
/// previous stack used; the state machine backs off from here.
const RETRANSMIT_INTERVAL: Duration = Duration::from_secs(1);

/// How long a completed association stays alive to answer a peer that repeats its final flight
/// (RFC 6347 §4.2.4). Restarted on every flight we answer, so a peer still retransmitting keeps the
/// window open. Long enough to cover a full retransmission ladder, bounded so a leg cannot hold a
/// task and an `Endpoint` for the life of a long call.
const LAST_FLIGHT_RETENTION: Duration = Duration::from_secs(60);

/// At most one retransmitted flight answered per leg per this interval.
///
/// Not an anti-amplification measure — the source is already gated twice (the datapath's ICE
/// check-validated gate, then the bridge's own `accepted_source`), and our last flight is *smaller*
/// than the certificate-bearing flight that triggers it, so the factor is below one. It is a CPU and
/// bandwidth guard, and it sits on the **response** side on purpose: throttling intake instead would
/// starve the very retransmission we owe the peer.
const RESPONSE_MIN_INTERVAL: Duration = Duration::from_millis(200);

/// What to do with the keyed leg once the handshake completes. The two registration paths differ only
/// here, so they share one driver.
pub(crate) enum SessionOutcome {
    /// A relaying bridge: publish the leg for both directions of the flow to use.
    Relay { secure: SharedSecureLeg },
    /// A slow-path owner (2-party media actor, conference seat, WS takeover leg) that holds the leg
    /// itself and decrypts on its own ingress.
    Pipeline {
        target: PipelineTarget,
        keyed: Arc<std::sync::atomic::AtomicBool>,
        retained: Arc<DashMap<EndpointId, Arc<Mutex<SecureLeg>>>>,
        secure_endpoint: EndpointId,
    },
}

impl SessionOutcome {
    /// Install the keyed leg. Returns whether it reached an owner: `false` means the owner went away
    /// mid-handshake, so the leg stays unkeyed and its media keeps being dropped rather than reaching
    /// a consumer that never got the key.
    fn apply(&self, leg: SecureLeg) -> bool {
        match self {
            Self::Relay { secure } => match secure.lock() {
                Ok(mut guard) => {
                    *guard = Some(leg);
                    true
                }
                Err(_) => false,
            },
            Self::Pipeline {
                target,
                keyed,
                retained,
                secure_endpoint,
            } => {
                // Key the actor before publishing `keyed`, so its mailbox holds the key ahead of any
                // media the bridge then releases.
                if target.key(leg, retained, *secure_endpoint) {
                    keyed.store(true, std::sync::atomic::Ordering::SeqCst);
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// Block until the leg's destination is decided. `Err` when the leg is torn down first (every sender
/// dropped), so the driver exits instead of waiting forever.
pub(crate) async fn wait_for_destination(
    mut gate: tokio::sync::watch::Receiver<Option<SocketAddr>>,
) -> Result<SocketAddr, tokio::sync::watch::error::RecvError> {
    loop {
        if let Some(destination) = *gate.borrow_and_update() {
            return Ok(destination);
        }
        gate.changed().await?;
    }
}

/// Everything one driver needs. A struct because the parameter list is otherwise unreadable, and
/// because the two call sites differ only in [`SessionOutcome`].
pub(crate) struct DriverPlan<D: Datapath> {
    pub(crate) datapath: D,
    pub(crate) secure_endpoint: EndpointId,
    pub(crate) destination: SecureDestination,
    pub(crate) inbound: flume::Receiver<Bytes>,
    pub(crate) certificate: DtlsCertificate,
    pub(crate) role: DtlsRole,
    pub(crate) peer_fingerprint: Fingerprint,
    pub(crate) outcome: SessionOutcome,
}

/// Spawn the driver for one leg. The handle is stored by the bridge and aborted on retire/teardown,
/// so the task dies with the leg; it also returns on its own when the inbound channel closes or the
/// retention window expires.
pub(crate) fn spawn_session<D: Datapath + Clone + Send + Sync + 'static>(
    plan: DriverPlan<D>,
) -> JoinHandle<()> {
    tokio::spawn(async move { run(plan).await })
}

async fn run<D: Datapath + Clone + Send + Sync + 'static>(plan: DriverPlan<D>) {
    let DriverPlan {
        datapath,
        secure_endpoint,
        destination,
        inbound,
        certificate,
        role,
        peer_fingerprint,
        outcome,
    } = plan;

    // RFC 8445 §12: key the path ICE chose, not the signalled one. Records that arrive before that
    // sit in the bounded inbound channel; nothing is sent.
    if let Err(error) = wait_for_destination(destination.subscribe()).await {
        tracing::debug!(%error, "DTLS leg torn down before ICE selected a pair");
        return;
    }

    let mut session =
        match DtlsSession::new(&certificate, role, peer_fingerprint, RETRANSMIT_INTERVAL) {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(%error, "DTLS session could not be built; media stays dropped");
                return;
            }
        };
    if let Err(error) = session.start(Instant::now()) {
        tracing::warn!(%error, "DTLS handshake could not be started; media stays dropped");
        return;
    }
    let mut last_response = None;
    transmit(
        &datapath,
        secure_endpoint,
        &destination,
        &mut session,
        &mut last_response,
    )
    .await;

    let mut changed = destination.subscribe();
    let mut keyed_at: Option<Instant> = None;

    loop {
        let retransmit_at = session.poll_timeout();
        let retire_at = keyed_at.map(|at| at + LAST_FLIGHT_RETENTION);

        tokio::select! {
            // Cancellation-safe: `recv_async`, `sleep_until` and `changed` all are, and the sends
            // happen after the select rather than inside an arm, so nothing queued can be lost.
            record = inbound.recv_async() => {
                let Ok(record) = record else {
                    return; // the flow was dropped: the leg is gone
                };
                if !handle_record(&mut session, &record, &outcome, &mut keyed_at) {
                    return;
                }
            }
            () = sleep_until(retransmit_at) => {
                if let Err(error) = session.handle_timeout(Instant::now()) {
                    tracing::debug!(%error, "DTLS retransmission failed; leg stays as it is");
                    return;
                }
            }
            () = sleep_until(retire_at) => {
                tracing::debug!(
                    "DTLS last-flight retention elapsed; association closed"
                );
                return;
            }
            result = changed.changed() => {
                if result.is_err() {
                    return; // the destination publisher is gone with the leg
                }
                // Nothing to drive: the new address is read per record when transmitting.
            }
        }

        transmit(
            &datapath,
            secure_endpoint,
            &destination,
            &mut session,
            &mut last_response,
        )
        .await;
    }
}

/// Feed one inbound record and apply whatever it produced. Returns `false` when the session has died
/// and the driver should stop.
fn handle_record(
    session: &mut DtlsSession,
    record: &[u8],
    outcome: &SessionOutcome,
    keyed_at: &mut Option<Instant>,
) -> bool {
    let events = match session.handle_datagram(Instant::now(), record) {
        Ok(events) => events,
        Err(error) => {
            tracing::warn!(%error, "DTLS record rejected; media stays dropped");
            return false;
        }
    };
    for event in events {
        match event {
            DtlsEvent::Keyed => {
                // Borrow the keying rather than consuming the session: it has to stay alive to answer
                // a peer that repeats its final flight (RFC 6347 §4.2.4), which is the whole point of
                // the retention window below.
                let Some(leg) = session.keying().map(|keying| keying.to_secure_leg()) else {
                    tracing::warn!(
                        "DTLS reported Keyed without keying material; media stays dropped"
                    );
                    return false;
                };
                if outcome.apply(leg) {
                    *keyed_at = Some(Instant::now());
                    tracing::info!(
                        target: "siphon_rtp::media",
                        "DTLS-SRTP handshake complete; leg keyed"
                    );
                } else {
                    tracing::warn!(
                        target: "siphon_rtp::media",
                        "DTLS-SRTP handshake completed but its owner is gone; media stays dropped"
                    );
                }
            }
            DtlsEvent::ApplicationData(data) => {
                tracing::debug!(
                    bytes = data.len(),
                    "DTLS application data on a DTLS-SRTP leg; dropped"
                );
            }
            // `DtlsEvent` is deliberately `#[non_exhaustive]`, so a future variant must not silently
            // change this leg's behaviour. A DTLS-SRTP leg expects `Keyed` and nothing else.
            other => {
                tracing::debug!(?other, "unhandled DTLS session event; ignored");
            }
        }
    }
    true
}

/// Drain everything the session wants sent to the peer's current address.
///
/// The destination is read **per record**, so a record produced after ICE re-points the leg goes to
/// the newly selected pair. The address is copied out before the `.await`: a `watch::Ref` is not
/// `Send` and holding it across the send would both break the future and hold a lock across an await.
async fn transmit<D: Datapath + Clone + Send + Sync + 'static>(
    datapath: &D,
    secure_endpoint: EndpointId,
    destination: &SecureDestination,
    session: &mut DtlsSession,
    last_response: &mut Option<Instant>,
) {
    let keyed = session.is_keyed();
    while let Some(record) = session.poll_transmit() {
        // Post-handshake output is a retransmitted last flight; rate-limit the answer.
        if keyed {
            let now = Instant::now();
            if last_response.is_some_and(|last| now.duration_since(last) < RESPONSE_MIN_INTERVAL) {
                continue;
            }
            *last_response = Some(now);
        }
        let Some(address) = *destination.borrow() else {
            // No pair yet: a record with nowhere ICE has approved is dropped, never guessed at.
            continue;
        };
        if let Err(error) = datapath.send(secure_endpoint, address, &record).await {
            tracing::debug!(%error, "DTLS record send failed");
        }
    }
}

/// Sleep until `deadline`, or forever when there is none — the "no timer pending" arm of the select.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
        None => std::future::pending().await,
    }
}
