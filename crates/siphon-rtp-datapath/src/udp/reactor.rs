//! The relay reactor: the threads that receive on every endpoint socket.
//!
//! Endpoints are spread over a fixed set of shards by a hash of their id (see [`shard_index`]).
//! Each shard is one OS thread blocked in a level-triggered [`Epoll`] over its sockets; a wait
//! returns every socket that has a datagram, and the thread reads **one** datagram from each and
//! runs it through [`Inner::receive`] synchronously before waiting again. Against a Tokio task per
//! socket this removes, per packet, the task wake, the reschedule and the readiness bookkeeping,
//! plus the empty `recvfrom` an edge-triggered loop needs to see `EAGAIN` (see [`super::epoll`]).
//!
//! The thread owns its sockets' per-packet state (each [`Slot`] and its cached [`Route`]) outright,
//! so nothing on the packet path is shared with another thread. Control reaches a shard through a
//! command queue that the thread drains after every wait, before it touches any ready socket: a slot
//! is therefore in place before the first event for its socket can be read (the command is queued
//! before the socket is added to the epoll), and gone before a stale event harvested alongside its
//! removal could reach it. A removal also wakes the thread and waits for its acknowledgement, which
//! is what lets [`Datapath::remove_endpoint`](crate::Datapath::remove_endpoint) promise the socket
//! is closed when it returns.
//!
//! Shards start lazily, on the first endpoint that maps to them, so a backend with a handful of
//! endpoints (every test) runs a handful of threads.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::io;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::epoll::{Epoll, Events};
use super::route::Route;
use super::{Inner, StatsAtomic, MAX_DATAGRAM};
use crate::EndpointId;

/// An endpoint's socket. Received on by the reactor (which never registers it with Tokio for
/// reading), and registered with Tokio for **writability only**, so an engine-side
/// [`Datapath::send`](crate::Datapath::send) can wait out a full send buffer without the Tokio
/// driver seeing a readiness event per received packet.
pub(crate) type MediaSocket = tokio::io::unix::AsyncFd<std::net::UdpSocket>;

/// What every relay thread's name starts with (`rtp-relay-0`, `rtp-relay-1`, ...), so a profiler or
/// a CPU accountant can tell the relay's threads from the runtime's. Short enough that the index
/// survives the kernel's 15-byte thread-name limit.
pub const RELAY_THREAD_PREFIX: &str = "rtp-relay-";

/// The token of a shard's own wake socket; endpoint ids are allocated upward from zero.
const WAKE: u64 = u64::MAX;

/// How long a relay thread whose last pass found little work waits before looking again, by
/// default. See [`UdpLoopbackDatapath::with_relay_batch_window`](super::UdpLoopbackDatapath::with_relay_batch_window). 100 us: on a six-CPU relay carrying ~3,000 G.711
/// calls it cut engine CPU per relayed packet by 4.5% against no window and left the CPU the
/// signalling shares the relay with free enough that call setup stopped failing, where 250 and
/// 500 us gained no more and cap a single socket lower (one datagram per window).
pub const DEFAULT_RELAY_BATCH_WINDOW: Duration = Duration::from_micros(100);

/// A pass that read at least this many datagrams has amortised its wake-up already, so the thread
/// goes straight on instead of sleeping the batching window. Sleeping after a full pass would only
/// cut the thread's capacity while its backlog grows: under load that feedback overflowed socket
/// buffers.
const BATCH_TARGET: u64 = 32;

/// Ready sockets one `epoll_wait` can return. More stay ready and come back on the next wait.
const EVENTS_PER_WAIT: usize = 256;

/// The relay threads of one backend.
pub(super) struct Reactor {
    /// How many shards endpoints are spread over. Fixed once the first shard starts.
    threads: AtomicUsize,
    /// The shards started so far, by index.
    shards: Mutex<Vec<Option<Arc<Shard>>>>,
    /// The started shard threads, joined on shutdown.
    joins: Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// The batching window in microseconds, read by every shard on every pass (`0` = off).
    batch_window_micros: Arc<AtomicU64>,
}

/// One relay thread's handle, shared by the thread and the control path.
pub(super) struct Shard {
    epoll: Epoll,
    commands: flume::Sender<Command>,
    wake: UnixDatagram,
    batch_window_micros: Arc<AtomicU64>,
    /// `epoll_wait` calls this shard made, and datagrams it read: their ratio is the batch size.
    waits: AtomicU64,
    datagrams: AtomicU64,
}

enum Command {
    Add(Slot),
    /// Drop the slot, then acknowledge (when anyone waits for it).
    Remove {
        endpoint: EndpointId,
        done: Option<tokio::sync::oneshot::Sender<()>>,
    },
    Shutdown,
}

/// What a shard thread holds per endpoint.
struct Slot {
    endpoint: EndpointId,
    socket: Arc<MediaSocket>,
    stats: Arc<StatsAtomic>,
    route: Option<Route>,
}

impl Reactor {
    pub(super) fn new(threads: usize) -> Self {
        Self {
            threads: AtomicUsize::new(threads.max(1)),
            shards: Mutex::new(Vec::new()),
            joins: Mutex::new(Vec::new()),
            batch_window_micros: Arc::new(AtomicU64::new(micros(DEFAULT_RELAY_BATCH_WINDOW))),
        }
    }

    /// The default shard count: one per CPU this process may run on.
    pub(super) fn default_threads() -> usize {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    }

    /// Set the shard count. Applies only before the first endpoint is registered; returns whether
    /// it applied.
    pub(super) fn set_threads(&self, threads: usize) -> bool {
        let Ok(shards) = self.shards.lock() else {
            return false;
        };
        if shards.iter().any(Option::is_some) {
            return false;
        }
        self.threads.store(threads.max(1), Ordering::Relaxed);
        true
    }

    pub(super) fn threads(&self) -> usize {
        self.threads.load(Ordering::Relaxed)
    }

    /// Set the batching window: how long a relay thread whose last pass found a little work (fewer
    /// than [`BATCH_TARGET`] datagrams) sleeps before looking for more, so one wake-up serves many
    /// sockets instead of one. A thread that finds nothing blocks as before, so an idle relay adds
    /// no latency, and one that finds a full pass looks again at once, so a backlog drains at full
    /// speed; in between it adds up to the window. Because a thread reads one datagram per socket per pass, the window also caps one
    /// socket at one datagram per window (10 000 per second at 100 us), so keep it well under the
    /// packet interval of the fastest stream. Takes effect on each thread's next pass.
    pub(super) fn set_batch_window(&self, window: Duration) {
        self.batch_window_micros
            .store(micros(window), Ordering::Relaxed);
    }

    pub(super) fn batch_window(&self) -> Duration {
        Duration::from_micros(self.batch_window_micros.load(Ordering::Relaxed))
    }

    /// `epoll_wait` calls and datagrams read, summed over the started shards.
    #[cfg(test)]
    pub(super) fn counters(&self) -> (u64, u64) {
        self.shards.lock().map_or((0, 0), |shards| {
            shards
                .iter()
                .flatten()
                .fold((0, 0), |(waits, datagrams), shard| {
                    (
                        waits + shard.waits.load(Ordering::Relaxed),
                        datagrams + shard.datagrams.load(Ordering::Relaxed),
                    )
                })
        })
    }

    /// How many shard threads have started.
    #[cfg(test)]
    pub(super) fn started(&self) -> usize {
        self.shards
            .lock()
            .map_or(0, |shards| shards.iter().flatten().count())
    }

    /// Start receiving on `socket` for `endpoint`. Returns the shard, which the endpoint needs to
    /// be removed again.
    pub(super) fn register(
        &self,
        inner: &Arc<Inner>,
        endpoint: EndpointId,
        socket: Arc<MediaSocket>,
        stats: Arc<StatsAtomic>,
    ) -> io::Result<Arc<Shard>> {
        let shard = self.shard_for(inner, endpoint)?;
        // Queued before the socket is watched, so the slot exists before any event for it.
        shard.command(Command::Add(Slot {
            endpoint,
            socket: socket.clone(),
            stats,
            route: None,
        }))?;
        if let Err(error) = shard.epoll.add(socket.get_ref(), endpoint.0) {
            let _ = shard.command(Command::Remove {
                endpoint,
                done: None,
            });
            return Err(error);
        }
        Ok(shard)
    }

    fn shard_for(&self, inner: &Arc<Inner>, endpoint: EndpointId) -> io::Result<Arc<Shard>> {
        let threads = self.threads();
        let index = shard_index(endpoint, threads);
        let mut shards = self
            .shards
            .lock()
            .map_err(|_| io::Error::other("relay reactor shard table poisoned"))?;
        if shards.len() < threads {
            shards.resize_with(threads, || None);
        }
        if let Some(shard) = &shards[index] {
            return Ok(shard.clone());
        }
        let (shard, join) = Shard::start(inner.clone(), index, self.batch_window_micros.clone())?;
        if let Ok(mut joins) = self.joins.lock() {
            joins.push(join);
        }
        shards[index] = Some(shard.clone());
        Ok(shard)
    }

    /// Stop every started shard thread and wait for it to exit, so its sockets are closed and its
    /// hold on the backend released when this returns: a dropped backend frees its ports at once,
    /// as it did when the receive loops were tasks of the runtime that dropped it. A shard exits on
    /// its next wake-up, which the shutdown command sends.
    pub(super) fn shutdown(&self) {
        if let Ok(shards) = self.shards.lock() {
            for shard in shards.iter().flatten() {
                let _ = shard.command(Command::Shutdown);
            }
        }
        let joins = self
            .joins
            .lock()
            .map(|mut joins| std::mem::take(&mut *joins))
            .unwrap_or_default();
        let current = std::thread::current().id();
        for join in joins {
            // A shard never holds a handle, so it cannot be the one dropping the last of them; the
            // check only keeps a future change from turning that into a self-join deadlock.
            if join.thread().id() != current && join.join().is_err() {
                tracing::error!("a relay shard thread panicked");
            }
        }
    }
}

impl Shard {
    fn start(
        inner: Arc<Inner>,
        index: usize,
        batch_window_micros: Arc<AtomicU64>,
    ) -> io::Result<(Arc<Self>, std::thread::JoinHandle<()>)> {
        let epoll = Epoll::new()?;
        let (wake, wake_receiver) = UnixDatagram::pair()?;
        wake.set_nonblocking(true)?;
        wake_receiver.set_nonblocking(true)?;
        epoll.add(&wake_receiver, WAKE)?;
        let (commands, command_receiver) = flume::unbounded();
        let shard = Arc::new(Self {
            epoll,
            commands,
            wake,
            batch_window_micros,
            waits: AtomicU64::new(0),
            datagrams: AtomicU64::new(0),
        });
        let thread_shard = shard.clone();
        let join = std::thread::Builder::new()
            .name(format!("{RELAY_THREAD_PREFIX}{index}"))
            .spawn(move || run(&inner, &thread_shard, &command_receiver, &wake_receiver))?;
        Ok((shard, join))
    }

    /// Queue `command` and wake the thread so it is applied now, not at the next packet.
    fn command(&self, command: Command) -> io::Result<()> {
        self.commands
            .send(command)
            .map_err(|_| io::Error::other("relay reactor thread has stopped"))?;
        match self.wake.send(&[0]) {
            // A full wake socket already holds a wake-up the thread has not consumed.
            Err(error) if error.kind() != io::ErrorKind::WouldBlock => Err(error),
            _ => Ok(()),
        }
    }

    /// Stop receiving on `socket` and wait until the thread has dropped its reference to it.
    pub(super) async fn unregister(&self, endpoint: EndpointId, socket: &MediaSocket) {
        if let Err(error) = self.epoll.delete(socket.get_ref()) {
            tracing::debug!(?endpoint, %error, "socket was not watched by its relay shard");
        }
        let (done, acknowledged) = tokio::sync::oneshot::channel();
        let removal = Command::Remove {
            endpoint,
            done: Some(done),
        };
        if self.command(removal).is_ok() {
            // An error means the thread is gone, and with it every reference it held.
            let _ = acknowledged.await;
        }
    }
}

/// A shard thread: wait, apply queued commands, then read one datagram from each ready socket.
fn run(
    inner: &Arc<Inner>,
    shard: &Shard,
    commands: &flume::Receiver<Command>,
    wake: &UnixDatagram,
) {
    let mut slots: HashMap<u64, Slot, BuildHasherDefault<TokenHasher>> = HashMap::default();
    let mut events = Events::with_capacity(EVENTS_PER_WAIT);
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    // Block only when the last pass found nothing; after one that found work, sleep the batching
    // window and then look without blocking (see `Reactor::set_batch_window`).
    let mut block = true;
    loop {
        if let Err(error) = shard.epoll.wait(&mut events, if block { -1 } else { 0 }) {
            tracing::error!(%error, "relay shard epoll_wait failed; its endpoints stop receiving");
            return;
        }
        shard.waits.fetch_add(1, Ordering::Relaxed);
        // The wake-up first, the queue second. A command is queued before its wake-up is sent, so
        // anything queued after this drain has a wake-up still pending and the next wait returns at
        // once. The other order loses a wake-up: a command queued between the queue drain and the
        // wake drain has its wake-up consumed here and is not read until some packet arrives, and a
        // removal waiting on it may wait for ever.
        if events.tokens().any(|token| token == WAKE) {
            while wake.recv(&mut [0u8; 64]).is_ok() {}
        }
        while let Ok(command) = commands.try_recv() {
            match command {
                Command::Add(slot) => {
                    slots.insert(slot.endpoint.0, slot);
                }
                Command::Remove { endpoint, done } => {
                    slots.remove(&endpoint.0);
                    if let Some(done) = done {
                        let _ = done.send(());
                    }
                }
                Command::Shutdown => return,
            }
        }
        let mut received = 0u64;
        for token in events.tokens() {
            if token == WAKE {
                continue;
            }
            let Some(slot) = slots.get_mut(&token) else {
                continue; // removed after this event was harvested
            };
            match receive_one(inner, slot, &mut buffer) {
                Ok(true) => received += 1,
                Ok(false) => {}
                Err(error) => {
                    // Level-triggered: a socket left watched in a failed state would be reported (and
                    // fail) on every wait, so stop receiving on it, as the per-socket task used to end.
                    tracing::debug!(endpoint = ?slot.endpoint, %error, "endpoint receive loop ending");
                    let _ = shard.epoll.delete(slot.socket.get_ref());
                    slots.remove(&token);
                }
            }
        }
        shard.datagrams.fetch_add(received, Ordering::Relaxed);
        // Nothing found: block until something arrives. A small pass: let more arrive before the
        // next look (a command queued meanwhile waits at most the window; its wake-up stays
        // pending, so the next, non-blocking, wait reports it). A full pass: look again at once.
        block = received == 0;
        let window = shard.batch_window_micros.load(Ordering::Relaxed);
        if !block && window != 0 && received < BATCH_TARGET {
            std::thread::sleep(Duration::from_micros(window));
        }
    }
}

/// Read one datagram from a ready socket and hand it to [`Inner::receive`]. `Ok(false)` when the
/// socket had nothing after all.
fn receive_one(inner: &Inner, slot: &mut Slot, buffer: &mut [u8]) -> io::Result<bool> {
    let (len, source) = match slot.socket.get_ref().recv_from(buffer) {
        Ok(received) => received,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    slot.stats.packets_in.fetch_add(1, Ordering::Relaxed);
    slot.stats.bytes_in.fetch_add(len as u64, Ordering::Relaxed);
    inner.receive(
        slot.endpoint,
        slot.socket.get_ref(),
        &slot.stats,
        &mut slot.route,
        source,
        buffer,
        len,
    );
    Ok(true)
}

/// The shard `endpoint` is relayed on.
///
/// Hashed, not `id % threads`: endpoints are allocated in patterns (a leg's RTP endpoint, then its
/// RTCP one; often both legs of a call back to back), so the ids that carry media form an arithmetic
/// progression, and a modulus that shares a factor with its stride lands all of them on a subset of
/// the shards. The Fibonacci multiply scatters any such progression over the high bits, and the
/// multiply-shift maps those into `0..threads` without the bias a modulus of a hash keeps.
fn shard_index(endpoint: EndpointId, threads: usize) -> usize {
    let scattered = endpoint.0.wrapping_mul(FIBONACCI) >> 32;
    let index = (scattered * threads as u64) >> 32;
    usize::try_from(index).unwrap_or(0)
}

/// 2^64 / φ, odd: the multiplier of Fibonacci hashing.
const FIBONACCI: u64 = 0x9E37_79B9_7F4A_7C15;

/// Hashes a slot token (an endpoint id, allocated sequentially) with one multiply. Fibonacci
/// hashing spreads sequential ids over the high bits the table's control bytes are taken from; the
/// ids are the backend's own, so there is no attacker-chosen key to defend against.
#[derive(Default)]
struct TokenHasher(u64);

impl Hasher for TokenHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(*byte)).wrapping_mul(FIBONACCI);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value.wrapping_mul(FIBONACCI);
    }
}

/// A duration in whole microseconds, saturating.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::BuildHasher;

    /// How many of `ids` each of `threads` shards receives.
    fn spread(ids: impl Iterator<Item = u64>, threads: usize) -> Vec<usize> {
        let mut per_shard = vec![0; threads];
        for id in ids {
            per_shard[shard_index(EndpointId(id), threads)] += 1;
        }
        per_shard
    }

    #[test]
    fn the_busy_half_of_paired_endpoints_reaches_every_shard() {
        // A leg allocates its RTP endpoint and then its RTCP one, so media lives on every other id
        // (and on every fourth when both legs of a call are allocated together). `id % threads`
        // put all of it on the even shards and left the odd ones relaying RTCP: half the relay
        // threads saturated, their sockets overflowed, the other half idled.
        for threads in [2usize, 3, 4, 6, 8, 12, 24] {
            for stride in [2u64, 4] {
                let per_shard = spread((0..12_000u64).step_by(stride as usize), threads);
                let mean = per_shard.iter().sum::<usize>() as f64 / threads as f64;
                for (shard, count) in per_shard.iter().enumerate() {
                    assert!(
                        (*count as f64) > mean * 0.8 && (*count as f64) < mean * 1.2,
                        "{threads} threads, stride {stride}: shard {shard} got {count} of mean {mean}"
                    );
                }
            }
        }
    }

    #[test]
    fn one_thread_takes_every_endpoint() {
        assert_eq!(spread(0..100, 1), vec![100]);
    }

    #[test]
    fn sequential_tokens_hash_to_distinct_high_bits() {
        let hasher = BuildHasherDefault::<TokenHasher>::default();
        let top: std::collections::HashSet<u64> = (0..128u64)
            .map(|token| hasher.hash_one(token) >> 57)
            .collect();
        assert!(
            top.len() > 64,
            "only {} distinct top-7-bit values",
            top.len()
        );
    }

    #[test]
    fn the_shard_count_is_fixed_once_a_shard_has_started() {
        let reactor = Reactor::new(4);
        assert!(reactor.set_threads(2));
        assert_eq!(reactor.threads(), 2);
        assert!(reactor.set_threads(0), "zero is clamped, not refused");
        assert_eq!(reactor.threads(), 1);
    }
}
