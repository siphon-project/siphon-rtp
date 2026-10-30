//! The forwarding-room actor and the registry that routes to it.
//!
//! One task owns one [`ForwardRoom`] (single-owner state, no lock over a seat). The redirect
//! dispatcher feeds it datagrams through a bounded `flume` mailbox with `try_send`: a full mailbox
//! drops the newest datagram, because late media is worthless and an unbounded queue is how a
//! traffic spike becomes an out-of-memory. Control operations share the mailbox, so they are ordered
//! with the media they affect (a source change takes effect between two packets, never inside one).
//!
//! The registry keeps what has to be read from outside the actor: the endpoint routing table the
//! dispatcher uses, each room's member roster (for the inactivity scan and for freeing endpoints on a
//! leave), and the client that seated each member (the destination of its inactivity event).

use dashmap::DashMap;

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket};
use siphon_rtp_proto::Event;
use siphon_rtp_srtp::leg::SecureLeg;
use std::net::SocketAddr;

use super::codec::RoomCodec;
use super::room::{ForwardError, ForwardRoom, ForwardSeatConfig};
use crate::conference::{ntp_now, send_all};

/// Datagrams and control operations a room's mailbox holds before it sheds media.
const MAILBOX_CAPACITY: usize = 4096;

/// How long a verb waits for the room actor's verdict. The actor answers between two datagrams, so
/// this bounds a wedged room, not ordinary work.
const VERDICT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// The period of the per-seat RTCP Sender Reports (RFC 3550 §6.2 default interval, 5 s).
pub const REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a verb on a forwarding room was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForwardRefusal {
    /// The room codec does not admit the seat.
    #[error("{0}")]
    Codec(String),
    /// The room itself refused.
    #[error("{0}")]
    Room(#[from] ForwardError),
    /// No such forwarding room.
    #[error("unknown forwarding room: {0}")]
    UnknownRoom(String),
    /// The room actor is gone, or did not answer in time.
    #[error("the forwarding room did not answer within {} ms", VERDICT_TIMEOUT.as_millis())]
    NoVerdict,
}

/// A control operation on a room actor.
pub enum ForwardControl {
    /// Seat a member; the verdict goes back on `reply`.
    Add {
        config: Box<ForwardSeatConfig>,
        reply: tokio::sync::oneshot::Sender<Result<(), ForwardError>>,
    },
    /// Unseat a member.
    Remove(String),
    /// Choose the source. `events` is where [`Event::ForwardSourceStarted`] goes from now on: the
    /// client that asked.
    SetSource {
        tag: Option<String>,
        events: Option<flume::Sender<Event>>,
        reply: tokio::sync::oneshot::Sender<Result<(), ForwardError>>,
    },
    /// Install a DTLS seat's key.
    AttachSecureLeg { tag: String, leg: Box<SecureLeg> },
    /// A seat's ICE agent selected a pair.
    IceSelected { tag: String, remote: SocketAddr },
    /// End the actor.
    Stop,
}

enum ForwardInput {
    Packet(RxPacket),
    Control(ForwardControl),
}

/// A member as the registry tracks it.
struct Member {
    tag: String,
    endpoint: EndpointId,
    /// The datapath tick the member was seated, the quiet baseline before it has sent anything.
    joined_tick: u64,
    /// Where this member's [`Event::ForwardSeatInactive`] goes: the client that seated it.
    events: Option<flume::Sender<Event>>,
    /// The last-activity tick an inactivity event was raised for: the member has not been heard
    /// from since, so it is not reported again. Hearing from it moves its last activity past this,
    /// which re-arms it, even between two scans.
    reported_quiet_since: Option<u64>,
}

struct Handle {
    mailbox: flume::Sender<ForwardInput>,
    members: Vec<Member>,
    codec: RoomCodec,
    task: tokio::task::JoinHandle<()>,
}

/// The registry of forwarding rooms.
#[derive(Default)]
pub struct ForwardRegistry {
    /// Seat endpoint to the owning room's mailbox: the redirect dispatcher's routing table.
    routes: DashMap<EndpointId, flume::Sender<ForwardInput>>,
    rooms: DashMap<String, Handle>,
}

impl ForwardRegistry {
    /// Whether `endpoint` is a forwarding seat's (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Route a redirected datagram to its room (dropped when the mailbox is full or closed).
    pub fn dispatch(&self, packet: RxPacket) {
        if let Some(mailbox) = self.routes.get(&packet.endpoint) {
            if mailbox.try_send(ForwardInput::Packet(packet)).is_err() {
                tracing::trace!("forwarding room mailbox full or closed; dropping datagram");
            }
        }
    }

    /// Whether a forwarding room with this id exists.
    #[must_use]
    pub fn contains(&self, room_id: &str) -> bool {
        self.rooms.contains_key(room_id)
    }

    /// Live rooms (the leak soak confirms they drain).
    #[must_use]
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Live seats across all rooms.
    #[must_use]
    pub fn seat_count(&self) -> usize {
        self.rooms.iter().map(|room| room.members.len()).sum()
    }

    /// The codec of an existing room, so a join can be refused before anything is allocated.
    #[must_use]
    pub fn room_codec(&self, room_id: &str) -> Option<RoomCodec> {
        self.rooms.get(room_id).map(|room| room.codec.clone())
    }

    /// The room and tag of the seat on `endpoint`.
    #[must_use]
    pub fn seat_at(&self, endpoint: EndpointId) -> Option<(String, String)> {
        self.rooms.iter().find_map(|room| {
            room.members
                .iter()
                .find(|member| member.endpoint == endpoint)
                .map(|member| (room.key().clone(), member.tag.clone()))
        })
    }

    /// The endpoint seating `tag` in `room_id`.
    #[must_use]
    pub fn seat_endpoint(&self, room_id: &str, tag: &str) -> Option<EndpointId> {
        self.rooms.get(room_id).and_then(|room| {
            room.members
                .iter()
                .find(|member| member.tag == tag)
                .map(|member| member.endpoint)
        })
    }

    /// Send a control operation to a room; `false` when the room is gone.
    pub fn control(&self, room_id: &str, control: ForwardControl) -> bool {
        match self.rooms.get(room_id) {
            Some(room) => room
                .mailbox
                .try_send(ForwardInput::Control(control))
                .is_ok(),
            None => false,
        }
    }

    /// Open the seat on `endpoint` on the pair its ICE agent selected. `false` when the endpoint is
    /// not a forwarding seat.
    pub fn ice_selected(&self, endpoint: EndpointId, remote: SocketAddr) -> bool {
        let Some((room_id, tag)) = self.seat_at(endpoint) else {
            return false;
        };
        self.control(&room_id, ForwardControl::IceSelected { tag, remote })
    }

    /// Seat a member, creating the room (carrying `proposed`) on the first seat, and wait for the
    /// room's verdict. When the room exists its codec decides: `seat_spec` must read its payload. A
    /// refused seat leaves no member, route or empty room behind.
    ///
    /// # Errors
    /// [`ForwardRefusal`] naming why the seat was not taken.
    pub async fn join<D>(
        &self,
        room_id: &str,
        proposed: RoomCodec,
        seat_spec: &CodecSpec,
        config: ForwardSeatConfig,
        joined_tick: u64,
        events: Option<flume::Sender<Event>>,
        datapath: D,
    ) -> Result<(), ForwardRefusal>
    where
        D: Datapath + Clone + Send + 'static,
    {
        let endpoint = config.endpoint;
        let tag = config.tag.clone();
        let member = Member {
            tag: tag.clone(),
            endpoint,
            joined_tick,
            events,
            reported_quiet_since: None,
        };
        let mailbox = {
            let mut room = self.rooms.entry(room_id.to_string()).or_insert_with(|| {
                let (mailbox, inbox) = flume::bounded(MAILBOX_CAPACITY);
                let room = ForwardRoom::new(room_id.to_string(), proposed.clone());
                let task = tokio::spawn(run_forward_room(room, inbox, datapath));
                Handle {
                    mailbox,
                    members: Vec::new(),
                    codec: proposed,
                    task,
                }
            });
            // The authority is the room's own codec, not the caller's snapshot of it: a second
            // first-seat racing the creation must be held to the codec that won.
            let admitted = room.codec.admit(std::slice::from_ref(seat_spec));
            let refusal = match admitted {
                Err(reason) => Some(ForwardRefusal::Codec(reason)),
                Ok(_) if room.members.iter().any(|seated| seated.tag == tag) => {
                    Some(ForwardError::DuplicateTag(tag.clone()).into())
                }
                Ok(_) => None,
            };
            if let Some(refusal) = refusal {
                let empty = room.members.is_empty();
                drop(room);
                if empty {
                    self.end_room(room_id);
                }
                return Err(refusal);
            }
            room.members.push(member);
            room.mailbox.clone()
        };
        let (reply, verdict) = tokio::sync::oneshot::channel();
        let add = ForwardControl::Add {
            config: Box::new(config),
            reply,
        };
        let seated = match mailbox.try_send(ForwardInput::Control(add)) {
            Ok(()) => match tokio::time::timeout(VERDICT_TIMEOUT, verdict).await {
                Ok(Ok(outcome)) => outcome.map_err(ForwardRefusal::from),
                Ok(Err(_)) | Err(_) => Err(ForwardRefusal::NoVerdict),
            },
            Err(_) => Err(ForwardRefusal::NoVerdict),
        };
        if let Err(refusal) = seated {
            self.leave(room_id, &tag);
            return Err(refusal);
        }
        self.routes.insert(endpoint, mailbox);
        Ok(())
    }

    /// Stop and forget a room.
    fn end_room(&self, room_id: &str) {
        if let Some((_, room)) = self.rooms.remove(room_id) {
            let _ = room
                .mailbox
                .try_send(ForwardInput::Control(ForwardControl::Stop));
            room.task.abort();
        }
    }

    /// Unseat a member and return its endpoint to free (empty when there is no such seat). The last
    /// leave ends the room.
    pub fn leave(&self, room_id: &str, tag: &str) -> Vec<EndpointId> {
        let (endpoint, empty) = {
            let Some(mut room) = self.rooms.get_mut(room_id) else {
                return Vec::new();
            };
            let Some(position) = room.members.iter().position(|member| member.tag == tag) else {
                return Vec::new();
            };
            let member = room.members.remove(position);
            let _ = room
                .mailbox
                .try_send(ForwardInput::Control(ForwardControl::Remove(
                    tag.to_string(),
                )));
            (member.endpoint, room.members.is_empty())
        };
        self.routes.remove(&endpoint);
        if empty {
            self.end_room(room_id);
        }
        vec![endpoint]
    }

    /// Tear a whole room down, returning every seat endpoint to free.
    pub fn deregister(&self, room_id: &str) -> Vec<EndpointId> {
        let Some((_, room)) = self.rooms.remove(room_id) else {
            return Vec::new();
        };
        let _ = room
            .mailbox
            .try_send(ForwardInput::Control(ForwardControl::Stop));
        room.task.abort();
        let endpoints: Vec<EndpointId> =
            room.members.iter().map(|member| member.endpoint).collect();
        for endpoint in &endpoints {
            self.routes.remove(endpoint);
        }
        endpoints
    }

    /// Choose a room's source (`None` for nobody) and wait for the room's verdict. `events` receives
    /// the room's [`Event::ForwardSourceStarted`] from now on.
    ///
    /// # Errors
    /// [`ForwardRefusal::UnknownRoom`], or the room's refusal of an unknown tag.
    pub async fn set_source(
        &self,
        room_id: &str,
        tag: Option<String>,
        events: Option<flume::Sender<Event>>,
    ) -> Result<(), ForwardRefusal> {
        let Some(mailbox) = self.rooms.get(room_id).map(|room| room.mailbox.clone()) else {
            return Err(ForwardRefusal::UnknownRoom(room_id.to_string()));
        };
        let (reply, verdict) = tokio::sync::oneshot::channel();
        mailbox
            .try_send(ForwardInput::Control(ForwardControl::SetSource {
                tag,
                events,
                reply,
            }))
            .map_err(|_| ForwardRefusal::NoVerdict)?;
        match tokio::time::timeout(VERDICT_TIMEOUT, verdict).await {
            Ok(Ok(outcome)) => outcome.map_err(ForwardRefusal::from),
            Ok(Err(_)) | Err(_) => Err(ForwardRefusal::NoVerdict),
        }
    }

    /// Raise [`Event::ForwardSeatInactive`] for every seat that has been quiet for `idle_ticks`,
    /// once, and re-arm a seat only after it was heard from again. Never frees a seat: a listener
    /// sends nothing for as long as others talk (3GPP TS 24.379), so silence is the controller's to
    /// judge. `last_activity` is an endpoint's last accepted-packet tick (the datapath's logical
    /// clock, so tests drive it); any accepted RTP or RTCP counts. `idle_ticks == 0` disables the
    /// scan. Returns how many events were raised.
    pub fn scan_inactive(
        &self,
        now: u64,
        idle_ticks: u64,
        last_activity: impl Fn(EndpointId) -> Option<u64>,
    ) -> usize {
        if idle_ticks == 0 {
            return 0;
        }
        let mut raised = 0;
        for mut room in self.rooms.iter_mut() {
            let room_id = room.key().clone();
            for member in &mut room.members {
                let last = last_activity(member.endpoint)
                    .unwrap_or(0)
                    .max(member.joined_tick);
                if now.saturating_sub(last) < idle_ticks
                    || member.reported_quiet_since == Some(last)
                {
                    continue;
                }
                member.reported_quiet_since = Some(last);
                raised += 1;
                tracing::warn!(
                    target: "siphon_rtp::media", room = %room_id, tag = %member.tag,
                    idle_secs = idle_ticks,
                    "forwarding seat has received nothing; reported, not freed"
                );
                if let Some(sink) = &member.events {
                    let event = Event::ForwardSeatInactive {
                        conference_id: room_id.clone(),
                        from_tag: member.tag.clone(),
                    };
                    if sink.try_send(event).is_err() {
                        tracing::debug!("forwarding seat inactivity event dropped (sink full)");
                    }
                }
            }
        }
        raised
    }
}

/// The room actor: ingest datagrams, forward, and send the periodic Sender Reports.
async fn run_forward_room<D: Datapath>(
    mut room: ForwardRoom,
    inbox: flume::Receiver<ForwardInput>,
    datapath: D,
) {
    let mut outbound = Vec::new();
    let mut source_events: Option<flume::Sender<Event>> = None;
    let mut reports = tokio::time::interval(REPORT_INTERVAL);
    reports.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            input = inbox.recv_async() => {
                let Ok(input) = input else { break };
                match input {
                    ForwardInput::Packet(packet) => {
                        room.ingest(&packet).record(&datapath, packet.endpoint);
                        while let Some((endpoint, destination, data)) = room.next_datagram(&packet) {
                            if let Err(error) = datapath.send(endpoint, destination, data).await {
                                tracing::debug!(%error, "forwarding room send failed");
                            }
                        }
                    }
                    ForwardInput::Control(ForwardControl::Add { config, reply }) => {
                        let _ = reply.send(room.add_seat(*config, datapath.now_micros()));
                    }
                    ForwardInput::Control(ForwardControl::Remove(tag)) => {
                        if room.remove_seat(&tag) && room.is_empty() {
                            break; // the last leaver ends the room
                        }
                    }
                    ForwardInput::Control(ForwardControl::SetSource { tag, events, reply }) => {
                        let outcome = room.set_source(tag.as_deref());
                        if outcome.is_ok() && events.is_some() {
                            source_events = events;
                        }
                        let _ = reply.send(outcome);
                    }
                    ForwardInput::Control(ForwardControl::AttachSecureLeg { tag, leg }) => {
                        room.attach_secure_leg(&tag, *leg);
                    }
                    ForwardInput::Control(ForwardControl::IceSelected { tag, remote }) => {
                        room.ice_selected(&tag, remote);
                    }
                    ForwardInput::Control(ForwardControl::Stop) => break,
                }
                for event in room.drain_events() {
                    if let Some(sink) = &source_events {
                        if sink.try_send(event).is_err() {
                            tracing::debug!("forwarding room event dropped (sink full or closed)");
                        }
                    }
                }
            }
            _ = reports.tick() => {
                outbound.clear();
                room.build_reports(ntp_now(), datapath.now_micros(), &mut outbound);
                send_all(&datapath, &mut outbound).await;
            }
        }
    }
}

#[cfg(test)]
mod tests;
