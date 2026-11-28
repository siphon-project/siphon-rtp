//! Sharded probe transmission and reception; no per-call threads or packet allocations.

use super::Error;
use crate::{
    probe::{self, PACKET_LEN},
    stats::{Delivery, InterarrivalJitter, LatencyHistogram, StreamReceiver},
};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    mpsc, Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

struct ActiveStream {
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
    next: Instant,
    ordinal: u32,
}
struct SenderShard {
    active: BTreeMap<u32, ActiveStream>,
    sent: BTreeMap<u32, u64>,
    skipped: u64,
    send_errors: u64,
    epoch: Instant,
    interval: Duration,
    wheel: super::wheel::Wheel,
}
impl SenderShard {
    fn new(epoch: Instant, interval: Duration) -> Self {
        Self {
            active: BTreeMap::new(),
            sent: BTreeMap::new(),
            skipped: 0,
            send_errors: 0,
            epoch,
            interval,
            wheel: super::wheel::Wheel::new(interval.as_millis() as usize),
        }
    }
    fn add(&mut self, id: u32, socket: Arc<UdpSocket>, destination: SocketAddr, start: Instant) {
        self.active.insert(
            id,
            ActiveStream {
                socket,
                destination,
                next: start,
                ordinal: 0,
            },
        );
        self.wheel.schedule(id, due_millisecond(self.epoch, start));
    }
    fn remove(&mut self, id: u32) {
        self.wheel.remove(id);
        if let Some(stream) = self.active.remove(&id) {
            self.sent.insert(id, u64::from(stream.ordinal));
        }
    }
    fn tick(&mut self, now: Instant) {
        let mut packet = [0; PACKET_LEN];
        for id in self
            .wheel
            .due(now.duration_since(self.epoch).as_millis() as u64)
        {
            let Some(stream) = self.active.get_mut(&id) else {
                continue;
            };
            let missed = (now - stream.next).as_nanos() / self.interval.as_nanos();
            self.skipped += missed as u64;
            // Advance from the original phase; a stall never produces a catch-up burst.
            stream.next += self.interval.mul_f64((missed + 1) as f64);
            probe::write_packet(
                &mut packet,
                id,
                id,
                stream.ordinal,
                self.epoch.elapsed().as_nanos() as u64,
            );
            let timestamp = stream
                .ordinal
                .wrapping_mul((self.interval.as_micros() / 125) as u32);
            packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
            match stream.socket.send_to(&packet, stream.destination) {
                Ok(_) => stream.ordinal = stream.ordinal.wrapping_add(1),
                Err(_) => {
                    self.send_errors += 1;
                    self.skipped += 1;
                }
            }
            self.wheel
                .schedule(id, due_millisecond(self.epoch, stream.next));
        }
    }
}
fn due_millisecond(epoch: Instant, due: Instant) -> u64 {
    due.duration_since(epoch).as_nanos().div_ceil(1_000_000) as u64
}
enum Command {
    Add(u32, Arc<UdpSocket>, SocketAddr, Instant),
    Remove(u32),
    Stop,
}
#[derive(Default)]
struct ReceivedStream {
    count: u64,
    reorder: StreamReceiver,
    jitter: InterarrivalJitter,
}
#[derive(Default)]
struct ReceiverShard {
    receive_errors: u64,
    deadlines: BTreeMap<u32, Instant>,
    streams: BTreeMap<u32, ReceivedStream>,
    delivery: Delivery,
    latency: LatencyHistogram,
    jitter: LatencyHistogram,
}
impl ReceiverShard {
    fn receive_result(
        &mut self,
        result: std::io::Result<usize>,
        buffer: &[u8],
        epoch: Instant,
    ) -> bool {
        match result {
            Ok(length) => {
                self.accept(&buffer[..length], epoch);
                true
            }
            Err(error) => {
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    self.receive_errors += 1;
                }
                false
            }
        }
    }
    fn accept(&mut self, packet: &[u8], epoch: Instant) {
        let Some(probe) = probe::parse_packet(packet) else {
            self.delivery.foreign += 1;
            return;
        };
        if self
            .deadlines
            .get(&probe.stream)
            .is_some_and(|deadline| Instant::now() > *deadline)
        {
            return;
        }
        let arrival = epoch.elapsed().as_micros() as u64;
        let state = self.streams.entry(probe.stream).or_default();
        state.count += 1;
        self.delivery.received += 1;
        self.delivery.out_of_order += u64::from(state.reorder.accept(probe.ordinal));
        self.latency
            .record(arrival.saturating_sub(probe.send_nanos / 1000));
        state.jitter.record(probe.send_nanos / 1000, arrival);
        self.jitter
            .record(state.jitter.microseconds().round() as u64);
    }
}

fn partition<T>(sockets: Vec<T>, threads: usize) -> Vec<Vec<T>> {
    let mut groups: Vec<Vec<T>> = (0..threads).map(|_| Vec::new()).collect();
    for (index, socket) in sockets.into_iter().enumerate() {
        groups[index % threads].push(socket);
    }
    groups
}

// A current-thread reactor gives each std receiver thread one blocking wait for its entire
// socket group. Serial SO_RCVTIMEO waits would multiply idle latency by the pool size.
fn receive_group(
    sockets: Vec<Arc<UdpSocket>>,
    stopped: Arc<AtomicBool>,
    receiver: mpsc::Receiver<(u32, Instant)>,
    epoch: Instant,
) -> Result<ReceiverShard, Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let sockets: Vec<_> = sockets
            .iter()
            .map(|socket| tokio::net::UdpSocket::from_std(socket.try_clone()?))
            .collect::<Result<_, std::io::Error>>()?;
        let mut shard = ReceiverShard::default();
        let mut buffer = [0; 2048];
        let mut cursor = 0;
        let mut maintenance = tokio::time::interval(Duration::from_millis(5));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        while !stopped.load(Ordering::Relaxed) {
            for (id, deadline) in receiver.try_iter() {
                shard.deadlines.insert(id, deadline);
            }
            let readable = std::future::poll_fn(|context| {
                for offset in 0..sockets.len() {
                    let index = (cursor + offset) % sockets.len();
                    if let std::task::Poll::Ready(result) = sockets[index].poll_recv_ready(context)
                    {
                        cursor = (index + 1) % sockets.len();
                        return std::task::Poll::Ready((index, result));
                    }
                }
                std::task::Poll::Pending
            });
            tokio::select! {
                _ = maintenance.tick() => {},
                (index, ready) = readable => {
                    if ready.is_err() {
                        shard.receive_errors += 1;
                        continue;
                    }
                    loop {
                        let result = sockets[index].try_recv_from(&mut buffer)
                            .map(|(length, _)| length);
                        if !shard.receive_result(result, &buffer, epoch) {
                            break;
                        }
                        if stopped.load(Ordering::Relaxed) { break; }
                        for (id, deadline) in receiver.try_iter() {
                            shard.deadlines.insert(id, deadline);
                        }
                    }
                }
            }
        }
        Ok(shard)
    })
}

#[derive(Debug, Default, serde::Serialize)]
pub struct StreamTotals {
    pub sent: u64,
    pub received: u64,
}
#[derive(Default)]
pub struct MediaResult {
    pub delivery: Delivery,
    pub latency: LatencyHistogram,
    pub jitter: LatencyHistogram,
    pub skipped: u64,
    pub media_send_errors: u64,
    pub media_receive_errors: u64,
    pub streams: BTreeMap<u32, StreamTotals>,
    pub active_streams: usize,
}
/// Owns every worker. Drop stops and joins workers even when SIP setup fails.
pub struct Media {
    sockets: Vec<Vec<Arc<UdpSocket>>>,
    addresses: Vec<Vec<SocketAddrV4>>,
    senders: Vec<mpsc::Sender<Command>>,
    drains: Vec<mpsc::Sender<(u32, Instant)>>,
    sending: Vec<JoinHandle<Result<SenderShard, Error>>>,
    receiving: Vec<JoinHandle<Result<ReceiverShard, Error>>>,
    stopped: Arc<AtomicBool>,
    sequence: AtomicU32,
}
impl Media {
    pub fn new(
        local: Ipv4Addr,
        base: u16,
        count: usize,
        interval: Duration,
        threads: usize,
    ) -> Result<Self, Error> {
        if count == 0
            || count > 32767
            || interval < Duration::from_millis(1)
            || !interval.subsec_nanos().is_multiple_of(1_000_000)
            || threads == 0
            || usize::from(base) + count * 2 > 65536
        {
            return Err(Error::Plan("invalid media pool"));
        }
        let epoch = Instant::now();
        let mut media = Self {
            sockets: vec![Vec::new(), Vec::new()],
            addresses: vec![Vec::new(), Vec::new()],
            senders: Vec::new(),
            drains: Vec::new(),
            sending: Vec::new(),
            receiving: Vec::new(),
            stopped: Arc::new(AtomicBool::new(false)),
            sequence: AtomicU32::new(1),
        };
        for side in 0..2 {
            for index in 0..count {
                let port = if base == 0 {
                    0
                } else {
                    base.checked_add((side * count + index) as u16)
                        .ok_or(Error::Plan("media port range overflow"))?
                };
                let socket = Arc::new(UdpSocket::bind((local, port))?);
                socket.set_nonblocking(true)?;
                let SocketAddr::V4(address) = socket.local_addr()? else {
                    return Err(Error::Plan("IPv4 required"));
                };
                media.addresses[side].push(address);
                media.sockets[side].push(socket);
            }
        }
        let groups = partition(media.sockets.iter().flatten().cloned().collect(), threads);
        for (index, sockets) in groups.into_iter().enumerate() {
            let (sender, receiver) = mpsc::channel();
            media.senders.push(sender);
            let handle = thread::Builder::new()
                .name(format!("sipload-tx-{index}"))
                .spawn(move || {
                    let mut shard = SenderShard::new(epoch, interval);
                    let mut next_tick = Instant::now();
                    loop {
                        while let Ok(command) = receiver.try_recv() {
                            match command {
                                Command::Add(id, socket, destination, start) => {
                                    shard.add(id, socket, destination, start)
                                }
                                Command::Remove(id) => shard.remove(id),
                                Command::Stop => return Ok(shard),
                            }
                        }
                        shard.tick(Instant::now());
                        next_tick += Duration::from_millis(1);
                        let now = Instant::now();
                        if next_tick > now {
                            thread::sleep(next_tick - now);
                        } else {
                            next_tick = now;
                        }
                    }
                })?;
            media.sending.push(handle);
            let stopped = media.stopped.clone();
            let (drain_sender, drain_receiver) = mpsc::channel();
            media.drains.push(drain_sender);
            media.receiving.push(
                thread::Builder::new()
                    .name(format!("sipload-rx-{index}"))
                    .spawn(move || receive_group(sockets, stopped, drain_receiver, epoch))?,
            );
        }
        Ok(media)
    }
    pub fn address(&self, side: usize, index: usize) -> SocketAddrV4 {
        self.addresses[side][index % self.addresses[side].len()]
    }
    pub fn start(
        &self,
        side: usize,
        index: usize,
        destination: SocketAddrV4,
    ) -> Result<u32, Error> {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        self.senders[id as usize % self.senders.len()]
            .send(Command::Add(
                id,
                self.sockets[side][index % self.sockets[side].len()].clone(),
                destination.into(),
                Instant::now(),
            ))
            .map_err(|_| Error::Worker)?;
        Ok(id)
    }
    pub fn stop(&self, id: u32) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_millis(500);
        for sender in &self.drains {
            sender.send((id, deadline)).map_err(|_| Error::Worker)?;
        }
        self.senders[id as usize % self.senders.len()]
            .send(Command::Remove(id))
            .map_err(|_| Error::Worker)
    }
    pub fn finish(&mut self) -> Result<MediaResult, Error> {
        let mut result = MediaResult::default();
        for sender in &self.senders {
            let _ = sender.send(Command::Stop);
        }
        for handle in self.sending.drain(..) {
            let shard = handle.join().map_err(|_| Error::Worker)??;
            result.active_streams += shard.active.len();
            result.skipped += shard.skipped;
            result.media_send_errors += shard.send_errors;
            for (id, sent) in shard.sent {
                result.streams.entry(id).or_default().sent += sent;
                result.delivery.sent += sent;
            }
        }
        self.stopped.store(true, Ordering::Relaxed);
        for handle in self.receiving.drain(..) {
            let shard = handle.join().map_err(|_| Error::Worker)??;
            result.delivery.merge(shard.delivery);
            result.media_receive_errors += shard.receive_errors;
            result.latency.merge(&shard.latency);
            result.jitter.merge(&shard.jitter);
            for (id, received) in shard.streams {
                result.streams.entry(id).or_default().received += received.count;
            }
        }
        Ok(result)
    }
}
impl Drop for Media {
    fn drop(&mut self) {
        for sender in &self.senders {
            let _ = sender.send(Command::Stop);
        }
        self.stopped.store(true, Ordering::Relaxed);
        for handle in self.sending.drain(..) {
            let _ = handle.join();
        }
        for handle in self.receiving.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receive_error_is_counted_and_the_next_packet_is_accepted() {
        let epoch = Instant::now();
        let mut shard = ReceiverShard::default();
        let mut packet = [0; PACKET_LEN];
        probe::write_packet(&mut packet, 1, 1, 0, 0);
        let error = std::io::Error::from_raw_os_error(111);
        assert!(!shard.receive_result(Err(error), &packet, epoch));
        assert!(shard.receive_result(Ok(PACKET_LEN), &packet, epoch));
        assert_eq!(shard.receive_errors, 1);
        assert_eq!(shard.delivery.received, 1);
        assert!(!shard.receive_result(Err(std::io::ErrorKind::WouldBlock.into()), &packet, epoch,));
        assert_eq!(shard.receive_errors, 1);
    }
    #[test]
    fn due_milliseconds_round_up_to_preserve_submillisecond_phase() {
        let epoch = Instant::now();
        assert_eq!(
            due_millisecond(epoch, epoch + Duration::from_micros(2300)),
            3
        );
        assert_eq!(
            due_millisecond(epoch, epoch + Duration::from_millis(20)),
            20
        );
    }
    #[test]
    fn failed_send_does_not_stop_other_streams_on_the_shard() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let epoch = Instant::now();
        let interval = Duration::from_millis(20);
        let mut shard = SenderShard::new(epoch, interval);
        // IPv4 destination port zero deterministically fails with EINVAL on Linux.
        shard.add(1, socket.clone(), "127.0.0.1:0".parse().unwrap(), epoch);
        shard.add(2, socket, receiver.local_addr().unwrap(), epoch);
        shard.tick(epoch);
        shard.tick(epoch + interval);
        let mut packet = [0; PACKET_LEN];
        for _ in 0..2 {
            let (length, _) = receiver.recv_from(&mut packet).unwrap();
            assert_eq!(probe::parse_packet(&packet[..length]).unwrap().stream, 2);
        }
        assert_eq!(shard.send_errors, 2);
        assert_eq!(shard.active[&2].ordinal, 2);
        shard.tick(epoch + Duration::from_millis(100));
        receiver.recv_from(&mut packet).unwrap();
        assert_eq!(shard.active[&2].ordinal, 3);
        assert_eq!(shard.send_errors, 3);
        assert_eq!(shard.skipped, 9);
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(
            receiver.recv_from(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn pool_partition_assigns_each_socket_exactly_once() {
        for threads in [1, 2, 3, 9] {
            let groups = partition((0..8).collect(), threads);
            assert_eq!(groups.len(), threads);
            let mut sockets: Vec<_> = groups.into_iter().flatten().collect();
            sockets.sort();
            assert_eq!(sockets, (0..8).collect::<Vec<_>>());
        }
    }
    #[test]
    fn receiver_excludes_packets_after_stream_drain_deadline() {
        let epoch = Instant::now();
        let mut shard = ReceiverShard::default();
        let mut packet = [0; PACKET_LEN];
        probe::write_packet(&mut packet, 1, 1, 0, 0);
        shard.accept(&packet, epoch);
        shard.deadlines.insert(1, Instant::now());
        shard.accept(&packet, epoch);
        assert_eq!(shard.delivery.received, 1);
        shard.accept(&[0; 4], epoch);
        assert_eq!(shard.delivery.foreign, 1);
    }
    #[test]
    fn empty_pool_is_rejected_without_opening_sockets() {
        assert!(Media::new(Ipv4Addr::LOCALHOST, 0, 0, Duration::from_millis(20), 2).is_err());
    }
    #[test]
    fn removing_a_stream_leaves_sender_shard_empty() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let epoch = Instant::now();
        let mut shard = SenderShard::new(epoch, Duration::from_millis(20));
        shard.add(1, socket.clone(), socket.local_addr().unwrap(), epoch);
        assert_eq!(shard.active.len(), 1);
        shard.remove(1);
        assert!(shard.active.is_empty());
        assert!(shard.wheel.due(100).is_empty());
        assert_eq!(shard.sent[&1], 0);
    }
    #[test]
    fn media_pool_sends_probes_and_drains_without_leaks() {
        let mut media =
            Media::new(Ipv4Addr::LOCALHOST, 0, 1, Duration::from_millis(20), 3).unwrap();
        assert_eq!(media.sending.len(), 3);
        assert_eq!(media.receiving.len(), 3);
        let first = media.start(0, 0, media.address(1, 0)).unwrap();
        let second = media.start(1, 0, media.address(0, 0)).unwrap();
        thread::sleep(Duration::from_millis(90));
        media.stop(first).unwrap();
        media.stop(second).unwrap();
        thread::sleep(Duration::from_millis(30));
        let result = media.finish().unwrap();
        assert_eq!(result.active_streams, 0);
        assert!(result.delivery.sent > 0);
        assert_eq!(result.delivery.sent, result.delivery.received);
        assert_eq!(result.delivery.foreign, 0);
        assert_eq!(result.streams.len(), 2);
    }
}
