//! The queue a controller's `rtcp_app` events travel through.
//!
//! Ordinary control events share a small bounded queue per client and are shed under backpressure,
//! because a late `media_timeout` or quality report is worth nothing. An RTCP APP packet is different:
//! it carries a floor-control message (3GPP TS 24.380), and a lost Floor Request or Floor Release
//! leaves a group call deadlocked on a floor nobody holds. So APP events get a queue of their own,
//! drained by the same connection loop, that
//!
//! * is large enough (4096) that a controller has to be badly stuck to fill it,
//! * keeps arrival order per seat (a single FIFO, one producer per seat), and
//! * when it does fill, sheds the **oldest** event, not the newest: the floor state a controller
//!   needs is the latest one, and a stale Floor Request is the cheapest message to lose. Every shed
//!   event is an `error!` naming the call or room and the seat, and counts in the `statistics`
//!   reply (`rtcp_app_dropped_total`), so a loss is visible and never silent.

use std::sync::Arc;

use siphon_rtp_media::rtcp;
use siphon_rtp_proto::{Event, RtcpAppStream};

use crate::metrics::Metrics;

/// Events one controller's APP queue holds before it sheds the oldest.
pub const APP_EVENT_QUEUE_CAPACITY: usize = 4096;

/// The largest RTCP APP datagram the engine builds for a send: one Ethernet MTU.
pub(crate) const MAX_APP_DATAGRAM: usize = 1500;

/// A controller's `rtcp_app` queue: cheap to clone, every clone feeds the same FIFO.
#[derive(Clone)]
pub struct AppEventQueue {
    sender: flume::Sender<Event>,
    /// Kept so the producer can evict the oldest event itself when the queue is full.
    receiver: flume::Receiver<Event>,
    metrics: Arc<Metrics>,
}

impl AppEventQueue {
    /// An empty queue holding at most `capacity` events.
    #[must_use]
    pub fn new(capacity: usize, metrics: Arc<Metrics>) -> Self {
        let (sender, receiver) = flume::bounded(capacity);
        Self {
            sender,
            receiver,
            metrics,
        }
    }

    /// The end the connection loop drains.
    #[must_use]
    pub fn receiver(&self) -> flume::Receiver<Event> {
        self.receiver.clone()
    }

    /// Events waiting to be written.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    /// Queue `event`. When the queue is full the oldest queued event is dropped to make room, with
    /// an `error!` and a count; the new event is always kept (bar a pathological race with other
    /// producers that keeps refilling the queue, in which case it is the one shed).
    pub fn push(&self, event: Event) {
        let mut event = event;
        for _ in 0..4 {
            match self.sender.try_send(event) {
                Ok(()) => return,
                // The queue owns a receiver, so it cannot disconnect while this value lives.
                Err(flume::TrySendError::Disconnected(_)) => return,
                Err(flume::TrySendError::Full(returned)) => {
                    event = returned;
                    if let Ok(oldest) = self.receiver.try_recv() {
                        self.report_loss(&oldest);
                    }
                }
            }
        }
        self.report_loss(&event);
    }

    fn report_loss(&self, lost: &Event) {
        self.metrics.record_rtcp_app_dropped();
        if let Event::RtcpApp {
            call_id,
            conference_id,
            from_tag,
            subtype,
            ..
        } = lost
        {
            tracing::error!(
                target: "siphon_rtp::control",
                call_id = call_id.as_deref().unwrap_or("-"),
                conference_id = conference_id.as_deref().unwrap_or("-"),
                from_tag = %from_tag,
                subtype,
                "rtcp_app queue full; oldest event dropped (a floor message was lost)"
            );
        }
    }
}

/// [`surface_app_packets`] straight onto a controller's APP queue. A packet with nowhere to go (the
/// controller has no queue) is a `warn`, never silent.
pub(crate) fn surface_app_to_queue(
    scope: AppScope<'_>,
    tag: &str,
    queue: Option<&AppEventQueue>,
    stream: RtcpAppStream,
    data: &[u8],
    raised: &mut u64,
    malformed: &mut u64,
) {
    surface_app_packets(
        scope,
        tag,
        stream,
        data,
        raised,
        malformed,
        |event| match queue {
            Some(queue) => queue.push(event),
            None => tracing::warn!(
                target: "siphon_rtp::media", ?scope, tag,
                "RTCP APP packet from a party whose controller has no event queue; not reported"
            ),
        },
    );
}

/// Whose party an APP packet came from: a two-party call, or a forwarding room's seat.
#[derive(Debug, Clone, Copy)]
pub(crate) enum AppScope<'a> {
    /// A two-party call, by call key.
    Call(&'a str),
    /// A forwarding room, by room id.
    Room(&'a str),
}

/// An APP packet's name as the event carries it: octets outside ASCII become `?`.
fn name_text(name: [u8; 4]) -> String {
    name.iter()
        .map(|&octet| {
            if octet.is_ascii() {
                char::from(octet)
            } else {
                '?'
            }
        })
        .collect()
}

/// Raise one [`Event::RtcpApp`] for every APP packet in `data`, in order, onto `queue`.
///
/// `raised` counts the APP packets read and `malformed` the datagrams that could not be read to the
/// end (their length fields cannot be trusted, so nothing after the break is located): counted and
/// logged at `debug`, never reported, because a controller cannot act on bytes the engine could not
/// read. A packet with nowhere to go (no queue) is a `warn`.
pub(crate) fn surface_app_packets(
    scope: AppScope<'_>,
    tag: &str,
    stream: RtcpAppStream,
    data: &[u8],
    raised: &mut u64,
    malformed: &mut u64,
    mut emit: impl FnMut(Event),
) {
    for packet in rtcp::app_packets(data) {
        match packet {
            Ok(app) => {
                *raised += 1;
                let (call_id, conference_id) = match scope {
                    AppScope::Call(call) => (Some(call.to_string()), None),
                    AppScope::Room(room) => (None, Some(room.to_string())),
                };
                emit(Event::RtcpApp {
                    call_id,
                    conference_id,
                    from_tag: tag.to_string(),
                    stream,
                    ssrc: app.ssrc,
                    name: name_text(app.name),
                    subtype: app.subtype,
                    payload: app.data.to_vec(),
                });
            }
            Err(error) => {
                *malformed += 1;
                tracing::debug!(
                    target: "siphon_rtp::media", ?scope, tag, %error,
                    "malformed RTCP in an APP-bearing datagram; rest of it ignored"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use siphon_rtp_proto::RtcpAppStream;

    use super::*;

    fn app(sequence: u8) -> Event {
        Event::RtcpApp {
            call_id: None,
            conference_id: Some("room".into()),
            from_tag: "seat".into(),
            stream: RtcpAppStream::Floor,
            ssrc: 1,
            name: "MCPT".into(),
            subtype: sequence,
            payload: vec![0, 0, 0, sequence],
        }
    }

    fn subtypes(queue: &AppEventQueue) -> Vec<u8> {
        queue
            .receiver()
            .try_iter()
            .map(|event| match event {
                Event::RtcpApp { subtype, .. } => subtype,
                other => panic!("unexpected event {other:?}"),
            })
            .collect()
    }

    #[test]
    fn keeps_arrival_order_below_capacity() {
        let metrics = Arc::new(Metrics::new());
        let queue = AppEventQueue::new(4, metrics.clone());
        for sequence in 0..4 {
            queue.push(app(sequence));
        }
        assert_eq!(subtypes(&queue), vec![0, 1, 2, 3]);
        assert_eq!(metrics.snapshot().rtcp_app_dropped_total, 0);
    }

    #[test]
    fn overflow_drops_the_oldest_and_counts_each_loss() {
        let metrics = Arc::new(Metrics::new());
        let queue = AppEventQueue::new(3, metrics.clone());
        for sequence in 0..7 {
            queue.push(app(sequence));
        }
        // 0..=3 were shed to admit 4..=6; the survivors are the newest, still in order.
        assert_eq!(subtypes(&queue), vec![4, 5, 6]);
        assert_eq!(metrics.snapshot().rtcp_app_dropped_total, 4);
    }

    #[test]
    fn clones_feed_one_fifo() {
        let queue = AppEventQueue::new(8, Arc::new(Metrics::new()));
        let producer = queue.clone();
        queue.push(app(1));
        producer.push(app(2));
        assert_eq!(queue.len(), 2);
        assert_eq!(subtypes(&queue), vec![1, 2]);
        assert!(queue.is_empty());
    }
}
