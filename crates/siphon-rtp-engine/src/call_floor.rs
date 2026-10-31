//! The MCPTT floor-control stream of a two-party call (3GPP TS 24.380 §8; SDP per TS 24.379).
//!
//! A call whose party offers or answers `m=application <port> udp MCPTT` gets that stream
//! **terminated** on one engine endpoint per party: unlike audio it is not relayed to the other
//! party, because the floor is the controller's to arbitrate. Every RTCP APP packet arriving on it
//! becomes an [`Event::RtcpApp`] for the controller that owns the call, and `send_rtcp_app` sends one
//! to a party.
//!
//! One actor owns the state of every call's floor legs (single-owner state, no lock over a leg): the
//! floor is low-rate, so a task per leg would cost more than the work. It is started on first use.
//! The synchronous core, [`CallFloors`], has no sockets and no tasks, so it is unit-tested directly.
//!
//! The gate is the one the forwarding room's floor stream runs (docs/security-and-nat.md §4 layer
//! 5h): the signalled source (layer 2), then the learn-once latch ([`OpaqueLatch`]) because the
//! stream has no SSRC to prove a rebind with.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;

use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_media::rtcp::{self, AppWriteError};
use siphon_rtp_proto::RtcpAppStream;
use siphon_rtp_srtp::srtcp_gcm::FloorMasterKey;

use crate::app_events::{surface_app_to_queue, AppEventQueue, AppScope};
use crate::floor_srtcp::{self, FloorDrop, FloorProtection};
use crate::forward::AppRequest;
use crate::ingress::{Ingress, Refusal, RefusalContext, RefusalLog};
use crate::reply_latch::OpaqueLatch;

/// Datagrams and control operations the actor's mailbox holds before it sheds datagrams.
const MAILBOX_CAPACITY: usize = 4096;

/// How long `send_rtcp_app` waits for the actor to put the packet on the wire.
const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The largest packet the core builds: one Ethernet MTU.
const MAX_DATAGRAM: usize = 1500;

/// One party's floor stream, as the engine resolves it when the call is answered.
pub struct CallFloorLeg {
    /// The call's key (scope-composed, as every other event names the call).
    pub call_id: String,
    /// The party's leg tag: the call's from-tag for the offerer, its to-tag for the answerer.
    pub tag: String,
    /// The engine socket the party's floor stream arrives on and is sent from.
    pub endpoint: EndpointId,
    /// Where floor control is sent until the first gated datagram latches the source: the party's
    /// signalled floor address (or the `received_from` hint with its port).
    pub destination: SocketAddr,
    /// Layer 2: the sources the stream may come from.
    pub accepted_source: SourceFilter,
    /// The SSRC this stream carries when the controller names none: the engine's own toward this
    /// party, minted once per leg (RFC 3550 §8.1: random), so it stays the same for the call's life.
    pub ssrc: u32,
    /// Where the party's APP events go: the queue of the controller that owns the call.
    pub events: Option<AppEventQueue>,
    /// The leg's SRTCP master keys (3GPP TS 33.180 §9.4): each party's own, from its own profile.
    /// Empty leaves the stream in the clear. The last protects what is sent, the newest two are
    /// accepted.
    pub keys: Vec<FloorMasterKey>,
}

struct Leg {
    config: CallFloorLeg,
    latch: OpaqueLatch,
    refusals: RefusalLog,
    raised: u64,
    malformed: u64,
    /// Datagrams a keyed leg's SRTCP refused (plaintext, unknown MKI, failed tag, replay).
    refused: u64,
    /// `Some` once the leg is keyed: every datagram in and out is AEAD_AES_128_GCM SRTCP.
    protection: Option<FloorProtection>,
}

/// Why a floor send was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallFloorError {
    /// The call has no floor stream on this leg.
    #[error("call {call_id} has no floor stream for {tag}")]
    UnknownLeg {
        /// The call.
        call_id: String,
        /// The leg tag.
        tag: String,
    },
    /// The packet is not a valid RTCP APP packet.
    #[error("{0}")]
    Packet(#[from] AppWriteError),
    /// No destination is known yet for the leg; never sent into the void.
    #[error("no floor destination known yet for {0}")]
    NoDestination(String),
    /// The datapath refused the datagram.
    #[error("floor send to {tag} failed: {reason}")]
    Send {
        /// The leg tag.
        tag: String,
        /// The datapath's reason.
        reason: String,
    },
    /// The floor actor is gone, or did not answer in time.
    #[error("the floor stream did not answer within {} ms", SEND_TIMEOUT.as_millis())]
    NoVerdict,
    /// The floor keys were refused (invalid set, or the protection could not be applied).
    #[error("floor keys: {0}")]
    Keys(String),
}

/// The synchronous core: every call's floor legs, ingress and the packet builder. No sockets.
#[derive(Default)]
pub struct CallFloors {
    legs: HashMap<EndpointId, Leg>,
    scratch: Vec<u8>,
    /// The protected form of the packet just built for a keyed leg.
    protected: Vec<u8>,
}

impl CallFloors {
    /// Add a leg. A second registration for the endpoint replaces the first.
    pub fn register(&mut self, config: CallFloorLeg) {
        let protection = FloorProtection::new(&config.keys);
        self.legs.insert(
            config.endpoint,
            Leg {
                config,
                latch: OpaqueLatch::default(),
                refusals: RefusalLog::default(),
                raised: 0,
                malformed: 0,
                refused: 0,
                protection,
            },
        );
    }

    /// Replace the SRTCP keys of the leg `tag` of `call_id` (the newest two are kept, outbound uses
    /// the last). An unkeyed leg becomes protected; an empty set removes the protection.
    ///
    /// # Errors
    /// [`CallFloorError::UnknownLeg`], or [`CallFloorError::Keys`] when the set is refused.
    pub fn set_keys(
        &mut self,
        call_id: &str,
        tag: &str,
        keys: &[FloorMasterKey],
    ) -> Result<(), CallFloorError> {
        let leg = self
            .legs
            .values_mut()
            .find(|leg| leg.config.call_id == call_id && leg.config.tag == tag)
            .ok_or_else(|| CallFloorError::UnknownLeg {
                call_id: call_id.to_string(),
                tag: tag.to_string(),
            })?;
        if keys.is_empty() {
            leg.protection = None;
            return Ok(());
        }
        match leg.protection.as_mut() {
            Some(protection) => protection
                .replace_keys(keys)
                .map_err(|error| CallFloorError::Keys(error.to_string())),
            None => {
                leg.protection = Some(FloorProtection::new(keys).ok_or_else(|| {
                    CallFloorError::Keys("the key set could not be applied".to_string())
                })?);
                Ok(())
            }
        }
    }

    /// The SRTCP state of a leg for an HA snapshot: the key set in force (oldest first) and the
    /// next outgoing index. `None` for an unkeyed or unknown leg.
    #[must_use]
    pub fn key_state(&self, call_id: &str, tag: &str) -> Option<(Vec<FloorMasterKey>, u32)> {
        let leg = self
            .legs
            .values()
            .find(|leg| leg.config.call_id == call_id && leg.config.tag == tag)?;
        let protection = leg.protection.as_ref()?;
        Some((protection.keys().to_vec(), protection.send_index()))
    }

    /// Datagrams the keyed leg on `endpoint` refused at its SRTCP gate.
    #[must_use]
    pub fn refused(&self, endpoint: EndpointId) -> Option<u64> {
        self.legs.get(&endpoint).map(|leg| leg.refused)
    }

    /// Forget every leg of `call_id`.
    pub fn deregister_call(&mut self, call_id: &str) {
        self.legs.retain(|_, leg| leg.config.call_id != call_id);
    }

    /// Live legs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.legs.len()
    }

    /// Whether no leg is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }

    /// APP packets read from, and malformed datagrams dropped from, the leg on `endpoint`.
    #[must_use]
    pub fn counters(&self, endpoint: EndpointId) -> Option<(u64, u64)> {
        self.legs
            .get(&endpoint)
            .map(|leg| (leg.raised, leg.malformed))
    }

    /// Ingress one datagram that arrived on a floor endpoint: layer 2, the learn-once latch, then one
    /// event per APP packet. Anything admitted counts as the leg being alive.
    pub fn ingest(&mut self, packet: &RxPacket) -> Ingress {
        let Some(leg) = self.legs.get_mut(&packet.endpoint) else {
            return Ingress::Refused;
        };
        let context = RefusalContext {
            component: "call-floor",
            call_id: &leg.config.call_id,
            endpoint: packet.endpoint,
            source: packet.source,
            expected: leg.config.accepted_source,
        };
        // Layer 2 (docs/security-and-nat.md §4): an unsignalled source never reaches the controller.
        if !leg.config.accepted_source.accepts(packet.source.ip()) {
            leg.refusals.log(Refusal::UnsignalledSource, context);
            return Ingress::Refused;
        }
        // Layer 5h: learn the reply address once, never move it. A keyed leg authenticates first
        // (TS 33.180 §9.4.1), so only a verified packet can latch.
        let data = match floor_srtcp::admit(
            &mut leg.protection,
            &mut leg.latch,
            &leg.refusals,
            context,
            packet,
        ) {
            Ok((data, learned)) => {
                if let Some(destination) = learned {
                    leg.config.destination = destination;
                }
                data
            }
            Err(FloorDrop::Latch) => return Ingress::Refused,
            Err(FloorDrop::Unauthenticated) => {
                leg.refused += 1;
                return Ingress::Refused;
            }
        };
        surface_app_to_queue(
            AppScope::Call(&leg.config.call_id),
            &leg.config.tag,
            leg.config.events.as_ref(),
            RtcpAppStream::Floor,
            data,
            &mut leg.raised,
            &mut leg.malformed,
        );
        Ingress::Accepted
    }

    /// Build `request` for the leg of `call_id` named `tag`: its endpoint, destination and the bytes,
    /// borrowed from the core's scratch. The SSRC is the request's, else the leg's own.
    ///
    /// # Errors
    /// [`CallFloorError`] for an unknown leg, an invalid packet, or a leg with no destination.
    pub fn build(
        &mut self,
        call_id: &str,
        tag: &str,
        request: &AppRequest,
    ) -> Result<(EndpointId, SocketAddr, &[u8]), CallFloorError> {
        let leg = self
            .legs
            .values_mut()
            .find(|leg| leg.config.call_id == call_id && leg.config.tag == tag)
            .ok_or_else(|| CallFloorError::UnknownLeg {
                call_id: call_id.to_string(),
                tag: tag.to_string(),
            })?;
        let (endpoint, destination, ssrc) = (
            leg.config.endpoint,
            leg.config.destination,
            request.ssrc.unwrap_or(leg.config.ssrc),
        );
        if self.scratch.len() < MAX_DATAGRAM {
            self.scratch.resize(MAX_DATAGRAM, 0);
        }
        // Validated before the destination so a bad request is always the packet's fault.
        let length = rtcp::write_app(
            request.subtype,
            ssrc,
            request.name,
            &request.payload,
            &mut self.scratch,
        )?;
        if destination.ip().is_unspecified() || destination.port() == 0 {
            return Err(CallFloorError::NoDestination(tag.to_string()));
        }
        // TS 33.180 §9.4.1: floor RTCP to a keyed leg is always protected (RFC 7714 §9.2, E=1).
        if let Some(protection) = leg.protection.as_mut() {
            protection
                .seal(&self.scratch[..length], &mut self.protected)
                .map_err(|error| CallFloorError::Keys(error.to_string()))?;
            return Ok((endpoint, destination, &self.protected));
        }
        Ok((endpoint, destination, &self.scratch[..length]))
    }
}

enum Input {
    Packet(RxPacket),
    Register(Box<CallFloorLeg>),
    Deregister(String),
    SetKeys {
        call_id: String,
        tag: String,
        keys: Vec<FloorMasterKey>,
        reply: tokio::sync::oneshot::Sender<Result<(), CallFloorError>>,
    },
    Send {
        call_id: String,
        tag: String,
        request: Box<AppRequest>,
        reply: tokio::sync::oneshot::Sender<Result<(), CallFloorError>>,
    },
}

/// The registry of two-party calls' floor streams: the redirect dispatcher's routing table and the
/// handle on the actor that owns the legs.
#[derive(Default)]
pub struct CallFloorRegistry {
    routes: DashMap<EndpointId, ()>,
    /// (call, leg tag) to the leg's endpoint, for a send to name its target without a round trip.
    by_leg: DashMap<(String, String), EndpointId>,
    /// The offerer's floor keys between its offer and the answer that registers its leg (the leg is
    /// registered only once the far party answers). Dropped with the call.
    offer_keys: DashMap<String, Vec<FloorMasterKey>>,
    mailbox: OnceLock<flume::Sender<Input>>,
}

impl CallFloorRegistry {
    /// Whether `endpoint` is a call's floor endpoint (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Route a redirected datagram to the actor (dropped when its mailbox is full or not started).
    pub fn dispatch(&self, packet: RxPacket) {
        if let Some(mailbox) = self.mailbox.get() {
            if mailbox.try_send(Input::Packet(packet)).is_err() {
                tracing::trace!("call floor mailbox full or closed; dropping datagram");
            }
        }
    }

    /// Live floor legs across all calls.
    #[must_use]
    pub fn leg_count(&self) -> usize {
        self.by_leg.len()
    }

    /// The mailbox, starting the actor on first use.
    fn mailbox<D: Datapath + Clone + Send + 'static>(&self, datapath: &D) -> &flume::Sender<Input> {
        self.mailbox.get_or_init(|| {
            let (mailbox, inbox) = flume::bounded(MAILBOX_CAPACITY);
            tokio::spawn(run_call_floors(inbox, datapath.clone()));
            mailbox
        })
    }

    /// Add a leg and open its route. Datagrams for the endpoint are queued behind the registration,
    /// so none is seen by an actor that has not heard of the leg.
    pub fn register<D: Datapath + Clone + Send + 'static>(&self, datapath: &D, leg: CallFloorLeg) {
        let (endpoint, key) = (leg.endpoint, (leg.call_id.clone(), leg.tag.clone()));
        if self
            .mailbox(datapath)
            .try_send(Input::Register(Box::new(leg)))
            .is_err()
        {
            tracing::error!(
                target: "siphon_rtp::media", ?endpoint,
                "call floor actor is not accepting registrations; the floor stream is not served"
            );
            return;
        }
        self.by_leg.insert(key, endpoint);
        self.routes.insert(endpoint, ());
    }

    /// Hold the offerer's floor keys until its leg is registered by the answer.
    pub fn hold_offer_keys(&self, call_id: &str, keys: Vec<FloorMasterKey>) {
        if !keys.is_empty() {
            self.offer_keys.insert(call_id.to_string(), keys);
        }
    }

    /// Take the offerer's floor keys held by [`Self::hold_offer_keys`] (empty when it had none).
    #[must_use]
    pub fn take_offer_keys(&self, call_id: &str) -> Vec<FloorMasterKey> {
        self.offer_keys
            .remove(call_id)
            .map(|(_, keys)| keys)
            .unwrap_or_default()
    }

    /// Forget every floor leg of `call_id`.
    pub fn deregister_call(&self, call_id: &str) {
        self.offer_keys.remove(call_id);
        self.by_leg.retain(|(call, _), endpoint| {
            let keep = call != call_id;
            if !keep {
                self.routes.remove(endpoint);
            }
            keep
        });
        if let Some(mailbox) = self.mailbox.get() {
            let _ = mailbox.try_send(Input::Deregister(call_id.to_string()));
        }
    }

    /// Whether the leg `tag` of `call_id` has a floor stream.
    #[must_use]
    pub fn has_leg(&self, call_id: &str, tag: &str) -> bool {
        self.by_leg
            .contains_key(&(call_id.to_string(), tag.to_string()))
    }

    /// Replace the SRTCP keys of the leg `tag` of `call_id`, answering once the actor applied them.
    ///
    /// # Errors
    /// [`CallFloorError`].
    pub async fn set_keys(
        &self,
        call_id: &str,
        tag: &str,
        keys: Vec<FloorMasterKey>,
    ) -> Result<(), CallFloorError> {
        let unknown = || CallFloorError::UnknownLeg {
            call_id: call_id.to_string(),
            tag: tag.to_string(),
        };
        if !self.has_leg(call_id, tag) {
            return Err(unknown());
        }
        let mailbox = self.mailbox.get().ok_or_else(unknown)?;
        let (reply, verdict) = tokio::sync::oneshot::channel();
        mailbox
            .try_send(Input::SetKeys {
                call_id: call_id.to_string(),
                tag: tag.to_string(),
                keys,
                reply,
            })
            .map_err(|_| CallFloorError::NoVerdict)?;
        match tokio::time::timeout(SEND_TIMEOUT, verdict).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) | Err(_) => Err(CallFloorError::NoVerdict),
        }
    }

    /// Send an APP packet on the floor stream of the leg `tag` of `call_id`, answering once the
    /// datapath has taken the datagram.
    ///
    /// # Errors
    /// [`CallFloorError`].
    pub async fn send(
        &self,
        call_id: &str,
        tag: &str,
        request: AppRequest,
    ) -> Result<(), CallFloorError> {
        let unknown = || CallFloorError::UnknownLeg {
            call_id: call_id.to_string(),
            tag: tag.to_string(),
        };
        if !self.has_leg(call_id, tag) {
            return Err(unknown());
        }
        let mailbox = self.mailbox.get().ok_or_else(unknown)?;
        let (reply, verdict) = tokio::sync::oneshot::channel();
        mailbox
            .try_send(Input::Send {
                call_id: call_id.to_string(),
                tag: tag.to_string(),
                request: Box::new(request),
                reply,
            })
            .map_err(|_| CallFloorError::NoVerdict)?;
        match tokio::time::timeout(SEND_TIMEOUT, verdict).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) | Err(_) => Err(CallFloorError::NoVerdict),
        }
    }
}

async fn run_call_floors<D: Datapath>(inbox: flume::Receiver<Input>, datapath: D) {
    let mut floors = CallFloors::default();
    while let Ok(input) = inbox.recv_async().await {
        match input {
            Input::Packet(packet) => {
                floors.ingest(&packet).record(&datapath, packet.endpoint);
            }
            Input::Register(leg) => floors.register(*leg),
            Input::Deregister(call_id) => floors.deregister_call(&call_id),
            Input::SetKeys {
                call_id,
                tag,
                keys,
                reply,
            } => {
                let _ = reply.send(floors.set_keys(&call_id, &tag, &keys));
            }
            Input::Send {
                call_id,
                tag,
                request,
                reply,
            } => {
                let outcome = match floors.build(&call_id, &tag, &request) {
                    Ok((endpoint, destination, data)) => datapath
                        .send(endpoint, destination, data)
                        .await
                        .map(drop)
                        .map_err(|error| CallFloorError::Send {
                            tag: tag.clone(),
                            reason: error.to_string(),
                        }),
                    Err(error) => Err(error),
                };
                let _ = reply.send(outcome);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use bytes::Bytes;
    use siphon_rtp_proto::Event;
    use siphon_rtp_srtp::srtcp_gcm::SrtcpGcmContext;

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn queue() -> AppEventQueue {
        AppEventQueue::new(16, std::sync::Arc::new(crate::metrics::Metrics::new()))
    }

    fn leg(endpoint: u64, tag: &str, events: &AppEventQueue) -> CallFloorLeg {
        CallFloorLeg {
            call_id: "call-1".into(),
            tag: tag.into(),
            endpoint: EndpointId(endpoint),
            destination: address("192.0.2.1:4100"),
            accepted_source: SourceFilter::Exact(address("192.0.2.1:4100").ip()),
            ssrc: 0xE000_0001,
            events: Some(events.clone()),
            keys: Vec::new(),
        }
    }

    fn rx(endpoint: u64, source: &str, data: &[u8]) -> RxPacket {
        RxPacket {
            endpoint: EndpointId(endpoint),
            source: address(source),
            arrival: 0,
            data: Bytes::copy_from_slice(data),
        }
    }

    /// TS 24.380 §8.2.4 Floor Request.
    const FLOOR_REQUEST: [u8; 16] = [
        0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05,
        0x00,
    ];

    fn granted() -> AppRequest {
        AppRequest {
            stream: RtcpAppStream::Floor,
            ssrc: None,
            name: *b"MCPT",
            subtype: 17,
            payload: vec![0, 1, 2, 3],
        }
    }

    #[test]
    fn a_floor_request_is_an_event_naming_the_call_and_the_leg() {
        let events = queue();
        let mut floors = CallFloors::default();
        floors.register(leg(7, "tag-a", &events));
        assert_eq!(
            floors.ingest(&rx(7, "192.0.2.1:4100", &FLOOR_REQUEST)),
            Ingress::Accepted
        );
        let heard: Vec<Event> = events.receiver().try_iter().collect();
        assert_eq!(
            heard,
            vec![Event::RtcpApp {
                call_id: Some("call-1".into()),
                conference_id: None,
                from_tag: "tag-a".into(),
                stream: RtcpAppStream::Floor,
                ssrc: 0x1122_3344,
                name: "MCPT".into(),
                subtype: 0,
                payload: vec![0, 2, 5, 0],
            }]
        );
        assert_eq!(floors.counters(EndpointId(7)), Some((1, 0)));
    }

    #[test]
    fn an_unsignalled_source_or_a_second_source_never_reports() {
        let events = queue();
        let mut floors = CallFloors::default();
        floors.register(leg(7, "tag-a", &events));
        assert_eq!(
            floors.ingest(&rx(7, "198.51.100.9:4100", &FLOOR_REQUEST)),
            Ingress::Refused
        );
        assert_eq!(
            floors.ingest(&rx(7, "192.0.2.1:5000", &FLOOR_REQUEST)),
            Ingress::Accepted,
            "the first gated source is learned"
        );
        assert_eq!(
            floors.ingest(&rx(7, "192.0.2.1:5002", &FLOOR_REQUEST)),
            Ingress::Refused,
            "and never moved"
        );
        assert_eq!(events.len(), 1);
        let (_, destination, _) = floors.build("call-1", "tag-a", &granted()).unwrap();
        assert_eq!(destination, address("192.0.2.1:5000"));
    }

    #[test]
    fn a_malformed_datagram_is_counted_and_raises_nothing() {
        let events = queue();
        let mut floors = CallFloors::default();
        floors.register(leg(7, "tag-a", &events));
        floors.ingest(&rx(7, "192.0.2.1:4100", &FLOOR_REQUEST[..12]));
        assert!(events.is_empty());
        assert_eq!(floors.counters(EndpointId(7)), Some((0, 1)));
    }

    #[test]
    fn a_datagram_on_an_unknown_endpoint_is_refused() {
        let mut floors = CallFloors::default();
        assert_eq!(
            floors.ingest(&rx(1, "192.0.2.1:4100", &FLOOR_REQUEST)),
            Ingress::Refused
        );
    }

    #[test]
    fn a_floor_granted_is_built_byte_exact_under_the_legs_ssrc() {
        let events = queue();
        let mut floors = CallFloors::default();
        floors.register(leg(7, "tag-a", &events));
        let (endpoint, destination, data) = floors.build("call-1", "tag-a", &granted()).unwrap();
        assert_eq!(endpoint, EndpointId(7));
        assert_eq!(destination, address("192.0.2.1:4100"));
        assert_eq!(
            data,
            [0x91, 0xCC, 0x00, 0x03, 0xE0, 0x00, 0x00, 0x01, 0x4D, 0x43, 0x50, 0x54, 0, 1, 2, 3]
        );
        let mut request = granted();
        request.ssrc = Some(0x0A0B_0C0D);
        let (_, _, data) = floors.build("call-1", "tag-a", &request).unwrap();
        assert_eq!(&data[4..8], &[0x0A, 0x0B, 0x0C, 0x0D]);
    }

    #[test]
    fn build_refuses_an_unknown_leg_a_bad_packet_and_a_void_destination() {
        let events = queue();
        let mut floors = CallFloors::default();
        floors.register(leg(7, "tag-a", &events));
        assert!(matches!(
            floors.build("call-1", "nobody", &granted()),
            Err(CallFloorError::UnknownLeg { .. })
        ));
        assert!(matches!(
            floors.build("other", "tag-a", &granted()),
            Err(CallFloorError::UnknownLeg { .. })
        ));
        let mut odd = granted();
        odd.payload.push(9);
        assert!(matches!(
            floors.build("call-1", "tag-a", &odd),
            Err(CallFloorError::Packet(AppWriteError::Unaligned(5)))
        ));
        let mut void = leg(8, "tag-b", &events);
        void.destination = address("0.0.0.0:0");
        floors.register(void);
        assert_eq!(
            floors.build("call-1", "tag-b", &granted()).unwrap_err(),
            CallFloorError::NoDestination("tag-b".into())
        );
    }

    fn floor_key(mki: u32) -> FloorMasterKey {
        FloorMasterKey::from_salt_96(mki, [0x11; 16], &[0x22; 12])
    }

    #[test]
    fn a_keyed_leg_counts_what_it_refuses_and_reports_only_what_authenticates() {
        let events = queue();
        let mut floors = CallFloors::default();
        let mut keyed = leg(7, "tag-a", &events);
        keyed.keys = vec![floor_key(5)];
        floors.register(keyed);
        // Plaintext, and the right MKI under a key that does not match.
        assert_eq!(
            floors.ingest(&rx(7, "192.0.2.1:4100", &FLOOR_REQUEST)),
            Ingress::Refused
        );
        let mut stranger =
            SrtcpGcmContext::new(&[FloorMasterKey::from_salt_96(5, [0x99; 16], &[0x22; 12])])
                .unwrap();
        let mut wire = Vec::new();
        stranger.protect(&FLOOR_REQUEST, true, &mut wire).unwrap();
        assert_eq!(
            floors.ingest(&rx(7, "192.0.2.1:4100", &wire)),
            Ingress::Refused
        );
        assert!(events.is_empty());
        assert_eq!(floors.refused(EndpointId(7)), Some(2));
        // The refused packets did not latch a source: the genuine peer, on another port, is learned.
        let mut phone = SrtcpGcmContext::new(&[floor_key(5)]).unwrap();
        phone.protect(&FLOOR_REQUEST, true, &mut wire).unwrap();
        assert_eq!(
            floors.ingest(&rx(7, "192.0.2.1:5000", &wire)),
            Ingress::Accepted
        );
        assert_eq!(events.len(), 1);
        let (_, destination, _) = floors.build("call-1", "tag-a", &granted()).unwrap();
        assert_eq!(destination, address("192.0.2.1:5000"));
    }

    #[test]
    fn a_keyed_leg_builds_a_protected_packet_the_phone_opens_and_keys_replace() {
        let events = queue();
        let mut floors = CallFloors::default();
        let mut keyed = leg(7, "tag-a", &events);
        keyed.keys = vec![floor_key(5)];
        floors.register(keyed);
        let (_, _, wire) = floors.build("call-1", "tag-a", &granted()).unwrap();
        let wire = wire.to_vec();
        let mut phone = SrtcpGcmContext::new(&[floor_key(5)]).unwrap();
        let mut plain = Vec::new();
        phone.unprotect(&wire, &mut plain).unwrap();
        assert_eq!(plain[8..12], *b"MCPT");
        assert_eq!(floors.key_state("call-1", "tag-a").unwrap().1, 1);

        floors
            .set_keys("call-1", "tag-a", &[floor_key(5), floor_key(6)])
            .unwrap();
        let (_, _, wire) = floors.build("call-1", "tag-a", &granted()).unwrap();
        assert_eq!(wire[wire.len() - 4..], 6u32.to_be_bytes());
        assert_eq!(floors.key_state("call-1", "tag-a").unwrap().1, 2);
        assert!(matches!(
            floors.set_keys("call-1", "nobody", &[floor_key(1)]),
            Err(CallFloorError::UnknownLeg { .. })
        ));
        // An unkeyed leg becomes protected; an empty set removes the protection again.
        let mut plain_leg = leg(8, "tag-b", &events);
        plain_leg.destination = address("192.0.2.2:4100");
        floors.register(plain_leg);
        assert!(floors.key_state("call-1", "tag-b").is_none());
        floors.set_keys("call-1", "tag-b", &[floor_key(9)]).unwrap();
        assert!(floors.key_state("call-1", "tag-b").is_some());
        floors.set_keys("call-1", "tag-b", &[]).unwrap();
        assert!(floors.key_state("call-1", "tag-b").is_none());
    }

    #[test]
    fn deregistering_a_call_forgets_its_legs_only() {
        let events = queue();
        let mut floors = CallFloors::default();
        floors.register(leg(7, "tag-a", &events));
        let mut other = leg(8, "tag-x", &events);
        other.call_id = "call-2".into();
        floors.register(other);
        floors.deregister_call("call-1");
        assert_eq!(floors.len(), 1);
        assert_eq!(
            floors.ingest(&rx(7, "192.0.2.1:4100", &FLOOR_REQUEST)),
            Ingress::Refused
        );
    }
}
