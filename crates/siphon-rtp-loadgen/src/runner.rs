//! Boots the engine, allocates the calls, drives the traffic, and reports what happened.
//!
//! # Two runtimes, on purpose
//!
//! The engine and the load generator each get their own Tokio runtime with its own thread name
//! prefix. That is not tidiness: the generator performs the same `recv`/`send` volume the engine
//! does, so a single-runtime design would interleave both onto threads no sampler could tell apart,
//! and the per-packet cost — the whole point of the run — would be inflated by roughly the
//! generator's own share. Separate runtimes make [`crate::cpu`]'s thread-name bucketing exact.
//!
//! Sockets are bound on the runtime that uses them, because a Tokio socket is registered with the
//! IO driver of the runtime it was created on and cannot be polled from another.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{sdp, ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

use crate::cpu::{self, CpuTime};
use crate::probe::{self, PACKET_LEN};
use crate::stats::{Delivery, LatencyHistogram, StreamReceiver};

/// Thread-name prefix for the engine's runtime. Kept under 15 characters, the `comm` ceiling.
const ENGINE_THREAD_PREFIX: &str = "sr-engine";
/// Thread-name prefix for the load generator's runtime.
const LOADGEN_THREAD_PREFIX: &str = "sr-loadgen";

/// The control client the harness presents to the engine. Calls are owned per client; one is
/// enough because `Engine::new` admits `usize::MAX` calls per client.
const CLIENT: ClientId = ClientId(1);

/// Datagram receive buffer. Matches the datapath's own `MAX_DATAGRAM`.
const RECEIVE_BUFFER_LEN: usize = 2048;

/// Endpoints the engine binds per plain relay call: RTP and RTCP on each of the two legs.
const ENGINE_ENDPOINTS_PER_CALL: usize = 4;
/// Sockets the generator binds per call: one synthetic phone on each side.
const GENERATOR_SOCKETS_PER_CALL: usize = 2;

/// What to run.
#[derive(Debug, Clone)]
pub struct RunPlan {
    /// Concurrent relay calls to establish.
    pub calls: usize,
    /// How long to drive traffic once warmed up.
    pub duration: Duration,
    /// Packetisation interval; 20 ms is the G.711 frame the capacity model assumes.
    pub ptime: Duration,
    /// Traffic time discarded before the measured window, so lazily-bound state and first-packet
    /// latch decisions do not land inside the sample.
    pub warmup: Duration,
    /// Engine runtime worker threads. `None` uses Tokio's default (`available_parallelism`).
    pub engine_workers: Option<usize>,
    /// Generator runtime worker threads.
    pub generator_workers: Option<usize>,
    /// How many streams one sender task owns. Batching amortises the generator's own timer and
    /// scheduling cost so it competes with the engine as little as possible.
    pub streams_per_sender: usize,
    /// How many sockets one receive task owns. Each shard keeps one latency histogram, so this also
    /// sets the harness's own memory footprint.
    pub sockets_per_receiver: usize,
}

impl Default for RunPlan {
    fn default() -> Self {
        Self {
            calls: 100,
            duration: Duration::from_secs(20),
            ptime: Duration::from_millis(20),
            warmup: Duration::from_secs(5),
            engine_workers: None,
            generator_workers: None,
            streams_per_sender: 64,
            sockets_per_receiver: 64,
        }
    }
}

/// Everything a run produces.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Calls the engine actually admitted.
    pub calls: usize,
    /// Wall-clock length of the measured window.
    pub measured: Duration,
    /// Delivery counters over the measured window.
    pub delivery: Delivery,
    /// Latency over the measured window.
    pub latency: LatencyHistogram,
    /// CPU consumed by the engine's threads during the measured window.
    pub engine_cpu: CpuTime,
    /// CPU consumed by the generator's threads during the measured window.
    pub generator_cpu: CpuTime,
    /// CPU consumed by every thread in the process.
    pub total_cpu: CpuTime,
    /// Live sessions the engine reported at the end of the window.
    pub engine_sessions: usize,
    /// The soft `RLIMIT_NOFILE` observed, and what the run needed.
    pub file_descriptors: FileDescriptorBudget,
}

impl RunOutcome {
    /// **The headline number**: engine CPU microseconds per packet actually relayed.
    ///
    /// Attributed to the engine's own threads, so it is not inflated by the generator sharing the
    /// box, and it is independent of how close to saturation the run got — which is what makes it
    /// the right basis for a sizing table.
    #[must_use]
    pub fn engine_microseconds_per_relayed_packet(&self) -> Option<f64> {
        if self.delivery.received == 0 {
            return None;
        }
        Some(self.engine_cpu.total_microseconds() as f64 / self.delivery.received as f64)
    }

    /// Packets per second the engine actually forwarded during the window.
    #[must_use]
    pub fn relayed_packets_per_second(&self) -> f64 {
        let seconds = self.measured.as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        self.delivery.received as f64 / seconds
    }

    /// Fraction of one core the engine consumed, where 1.0 is one core fully busy.
    #[must_use]
    pub fn engine_cores_used(&self) -> f64 {
        let seconds = self.measured.as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        (self.engine_cpu.total_microseconds() as f64 / 1_000_000.0) / seconds
    }

    /// Extrapolated concurrent calls one core sustains, from the measured per-packet cost.
    ///
    /// Arithmetic on a measurement, not itself a measurement — a node running at this figure has
    /// zero headroom, so it is a ceiling to size *below*, never a target.
    #[must_use]
    pub fn calls_per_core(&self, ptime: Duration) -> Option<f64> {
        let per_packet = self.engine_microseconds_per_relayed_packet()?;
        if per_packet <= 0.0 {
            return None;
        }
        let ptime_seconds = ptime.as_secs_f64();
        if ptime_seconds <= 0.0 {
            return None;
        }
        // A relayed call carries two streams, each delivering one packet per ptime.
        let packets_per_second_per_call = 2.0 / ptime_seconds;
        let packets_per_second_per_core = 1_000_000.0 / per_packet;
        Some(packets_per_second_per_core / packets_per_second_per_call)
    }
}

/// The file-descriptor budget a run needed against what the process was allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDescriptorBudget {
    /// Soft `RLIMIT_NOFILE`, or `None` if it could not be read.
    pub soft_limit: Option<u64>,
    /// Descriptors the run required: engine endpoints plus generator sockets.
    pub required: u64,
}

impl FileDescriptorBudget {
    /// Compute the budget for `calls` against the process's current soft limit.
    #[must_use]
    pub fn for_calls(calls: usize) -> Self {
        Self {
            soft_limit: read_soft_file_limit(),
            required: required_descriptors(calls),
        }
    }

    /// Whether the soft limit is known to be too low. `false` when the limit is unknown.
    #[must_use]
    pub fn is_exceeded(self) -> bool {
        self.soft_limit.is_some_and(|limit| self.required >= limit)
    }
}

/// Descriptors a run of `calls` needs, with headroom for the control and metrics sockets.
#[must_use]
pub fn required_descriptors(calls: usize) -> u64 {
    const HEADROOM: u64 = 64;
    let per_call = (ENGINE_ENDPOINTS_PER_CALL + GENERATOR_SOCKETS_PER_CALL) as u64;
    (calls as u64)
        .saturating_mul(per_call)
        .saturating_add(HEADROOM)
}

/// Read the soft `RLIMIT_NOFILE` from `/proc/self/limits`.
///
/// Parsed from procfs rather than `getrlimit` so the crate needs no `libc` dependency.
fn read_soft_file_limit() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/limits").ok()?;
    parse_soft_file_limit(&text)
}

/// Extract the soft "Max open files" value from `/proc/self/limits` text.
fn parse_soft_file_limit(text: &str) -> Option<u64> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Max open files") else {
            continue;
        };
        // Columns are "Soft Limit  Hard Limit  Units"; the first token is the soft limit, and it is
        // the literal "unlimited" when there is none.
        let soft = rest.split_whitespace().next()?;
        if soft == "unlimited" {
            return Some(u64::MAX);
        }
        return soft.parse().ok();
    }
    None
}

/// What can go wrong running a capacity sweep.
#[derive(Debug, thiserror::Error)]
pub enum LoadgenError {
    /// A Tokio runtime could not be built.
    #[error("build {which} runtime: {detail}")]
    Runtime {
        /// Which runtime failed.
        which: &'static str,
        /// The underlying error text.
        detail: String,
    },
    /// A synthetic phone socket could not be bound.
    #[error("bind synthetic phone socket: {0}")]
    Bind(String),
    /// The engine refused a control verb.
    #[error("engine refused {verb} for call {call}: {reason}")]
    ControlRefused {
        /// The verb that was refused.
        verb: &'static str,
        /// The call it was refused for.
        call: String,
        /// The engine's stated reason.
        reason: String,
    },
    /// The engine accepted a verb but returned SDP the harness could not read an address from.
    #[error("no media address in the engine's {verb} answer for call {call}")]
    NoMediaAddress {
        /// The verb whose reply was unreadable.
        verb: &'static str,
        /// The call it belonged to.
        call: String,
    },
}

/// One synthetic relay call: both phone sockets and the engine addresses they send to.
struct Call {
    identifier: String,
    phone_a: Arc<UdpSocket>,
    phone_b: Arc<UdpSocket>,
    /// The engine's A-facing address; phone A sends here and the engine relays to phone B.
    near: SocketAddr,
    /// The engine's B-facing address; phone B sends here and the engine relays to phone A.
    far: SocketAddr,
}

/// One direction of one call — the unit the generator paces.
struct Stream {
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
    identifier: u32,
    ssrc: u32,
}

/// Build a runtime whose worker threads carry `prefix`, so their CPU can be bucketed.
fn build_runtime(prefix: &'static str, workers: Option<usize>) -> Result<Runtime, LoadgenError> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().thread_name(prefix);
    if let Some(count) = workers {
        builder.worker_threads(count.max(1));
    }
    builder.build().map_err(|error| LoadgenError::Runtime {
        which: prefix,
        detail: error.to_string(),
    })
}

/// SDP offering PCMU at `address`.
fn pcmu_sdp(address: SocketAddr, session: u32) -> String {
    format!(
        "v=0\r\no=- {session} {session} IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = address.ip(),
        port = address.port()
    )
}

/// Pull the media address out of a successful control reply.
fn media_address(result: &CmdResult) -> Option<SocketAddr> {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => sdp::parse(text).ok().map(|media| media.remote_rtp),
        _ => None,
    }
}

/// The engine's stated reason for refusing, for the error path.
fn refusal_reason(result: &CmdResult) -> Option<String> {
    match result {
        CmdResult::Error { reason } => Some(reason.clone()),
        CmdResult::Ok { .. } => None,
        other => Some(format!("unexpected result: {other:?}")),
    }
}

/// Bind one synthetic phone on loopback.
async fn bind_phone() -> Result<(Arc<UdpSocket>, SocketAddr), LoadgenError> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| LoadgenError::Bind(error.to_string()))?;
    let address = socket
        .local_addr()
        .map_err(|error| LoadgenError::Bind(error.to_string()))?;
    Ok((Arc::new(socket), address))
}

/// Establish `calls` plain relay calls, returning the sockets and engine addresses for each.
async fn establish_calls(
    engine: &Engine<UdpLoopbackDatapath>,
    calls: usize,
    phones: Vec<(Arc<UdpSocket>, SocketAddr, Arc<UdpSocket>, SocketAddr)>,
) -> Result<Vec<Call>, LoadgenError> {
    let mut established = Vec::with_capacity(calls);

    for (index, (phone_a, address_a, phone_b, address_b)) in phones.into_iter().enumerate() {
        let identifier = format!("loadgen-{index}");

        let offer = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: identifier.clone(),
                    from_tag: "tag-a".into(),
                    sdp: pcmu_sdp(address_a, 1),
                    profile: Default::default(),
                },
            )
            .await;
        if let Some(reason) = refusal_reason(&offer) {
            return Err(LoadgenError::ControlRefused {
                verb: "offer",
                call: identifier,
                reason,
            });
        }
        // The offer's reply carries the engine's far, B-facing port.
        let Some(far) = media_address(&offer) else {
            return Err(LoadgenError::NoMediaAddress {
                verb: "offer",
                call: identifier,
            });
        };

        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: identifier.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: pcmu_sdp(address_b, 2),
                    profile: Default::default(),
                },
            )
            .await;
        if let Some(reason) = refusal_reason(&answer) {
            return Err(LoadgenError::ControlRefused {
                verb: "answer",
                call: identifier,
                reason,
            });
        }
        // The answer's reply carries the engine's near, A-facing port.
        let Some(near) = media_address(&answer) else {
            return Err(LoadgenError::NoMediaAddress {
                verb: "answer",
                call: identifier,
            });
        };

        established.push(Call {
            identifier,
            phone_a,
            phone_b,
            near,
            far,
        });
    }

    Ok(established)
}

/// Tear every call down, so the run leaves the engine at zero sessions.
async fn delete_calls(engine: &Engine<UdpLoopbackDatapath>, calls: &[Call]) {
    for call in calls {
        let _ = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: call.identifier.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
    }
}

/// What one sender task reports back when the run stops.
#[derive(Debug, Default, Clone, Copy)]
struct SenderReport {
    sent: u64,
    sent_before_window: u64,
}

/// What one receive shard reports back when the run stops.
struct ReceiverReport {
    delivery: Delivery,
    latency: LatencyHistogram,
}

/// Receive-side accumulation for one shard.
///
/// One of these is shared by every socket in the shard. All of them are polled inside a *single*
/// task, so the `Mutex` is uncontended by construction — it is there to satisfy `Send` on the
/// spawned future, not to arbitrate between threads, and it is never held across an await. The
/// histogram is per shard rather than per socket because one per socket costs 160 KB each, which at
/// a few thousand sockets is hundreds of megabytes of harness overhead competing with the very
/// thing being measured.
#[derive(Default)]
struct Accumulator {
    delivery: Delivery,
    streams: BTreeMap<u32, StreamReceiver>,
    latency: Option<LatencyHistogram>,
}

impl Accumulator {
    /// Fold one arrival in.
    fn record(&mut self, probe: crate::probe::Probe, latency_microseconds: u64) {
        self.delivery.received = self.delivery.received.saturating_add(1);
        self.latency
            .get_or_insert_with(LatencyHistogram::new)
            .record(latency_microseconds);
        if self
            .streams
            .entry(probe.stream)
            .or_default()
            .accept(probe.ordinal)
        {
            self.delivery.out_of_order = self.delivery.out_of_order.saturating_add(1);
        }
    }

    /// Note a datagram that was not one of ours.
    fn record_foreign(&mut self) {
        self.delivery.foreign = self.delivery.foreign.saturating_add(1);
    }

    fn into_report(self) -> ReceiverReport {
        ReceiverReport {
            delivery: self.delivery,
            latency: self.latency.unwrap_or_default(),
        }
    }
}

/// Drive a batch of streams at one packet per `ptime`, until told to stop.
///
/// Returns packets written in total and packets written before `window_opens`, so the caller can
/// attribute only the measured window's traffic.
async fn run_sender(
    streams: Vec<Stream>,
    ptime: Duration,
    epoch: Instant,
    window_opens: Instant,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> SenderReport {
    let mut buffer = vec![0u8; PACKET_LEN];
    let mut ordinal: u32 = 0;
    let mut report = SenderReport::default();
    let mut ticker = tokio::time::interval(ptime);
    // Late ticks are skipped rather than replayed in a burst: a backlog of catch-up sends would
    // measure the generator's stall, not the engine's capacity.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = stop.changed() => break,
        }
        if *stop.borrow() {
            break;
        }

        let now = Instant::now();
        let send_nanos = now.duration_since(epoch).as_nanos() as u64;
        let in_window = now >= window_opens;

        for stream in &streams {
            if probe::write_packet(
                &mut buffer,
                stream.ssrc,
                stream.identifier,
                ordinal,
                send_nanos,
            )
            .is_none()
            {
                continue;
            }
            if stream
                .socket
                .send_to(&buffer, stream.destination)
                .await
                .is_ok()
            {
                report.sent = report.sent.saturating_add(1);
                if !in_window {
                    report.sent_before_window = report.sent_before_window.saturating_add(1);
                }
            }
        }

        ordinal = ordinal.wrapping_add(1);
    }

    report
}

/// Receive on one socket until told to stop, folding arrivals into the shard's accumulator.
async fn receive_one(
    socket: &UdpSocket,
    accumulator: &Mutex<Accumulator>,
    epoch: Instant,
    window_opens: Instant,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut buffer = vec![0u8; RECEIVE_BUFFER_LEN];

    loop {
        let received = tokio::select! {
            result = socket.recv_from(&mut buffer) => result,
            _ = stop.changed() => break,
        };
        let Ok((length, _source)) = received else {
            break;
        };

        let arrived = Instant::now();
        if arrived < window_opens {
            continue;
        }

        let Some(probe) = probe::parse_packet(&buffer[..length]) else {
            if let Ok(mut guard) = accumulator.lock() {
                guard.record_foreign();
            }
            continue;
        };

        let arrival_nanos = arrived.duration_since(epoch).as_nanos() as u64;
        let latency_microseconds = arrival_nanos.saturating_sub(probe.send_nanos) / 1_000;
        // Scoped so the guard is dropped before the loop reaches its next await point.
        if let Ok(mut guard) = accumulator.lock() {
            guard.record(probe, latency_microseconds);
        }
    }
}

/// Drive every socket in one shard from a single task, sharing one accumulator between them.
async fn run_receive_shard(
    sockets: Vec<Arc<UdpSocket>>,
    epoch: Instant,
    window_opens: Instant,
    stop: tokio::sync::watch::Receiver<bool>,
) -> ReceiverReport {
    let accumulator = Mutex::new(Accumulator::default());
    let receivers = sockets
        .iter()
        .map(|socket| receive_one(socket, &accumulator, epoch, window_opens, stop.clone()))
        .collect::<Vec<_>>();
    futures_util::future::join_all(receivers).await;
    accumulator.into_inner().unwrap_or_default().into_report()
}

/// Run one capacity measurement end to end.
pub fn run(plan: &RunPlan) -> Result<RunOutcome, LoadgenError> {
    let engine_runtime = build_runtime(ENGINE_THREAD_PREFIX, plan.engine_workers)?;
    let generator_runtime = build_runtime(LOADGEN_THREAD_PREFIX, plan.generator_workers)?;

    let file_descriptors = FileDescriptorBudget::for_calls(plan.calls);

    // Phone sockets are bound on the generator runtime, which is the runtime that will poll them.
    let phones = generator_runtime.block_on(async {
        let mut bound = Vec::with_capacity(plan.calls);
        for _ in 0..plan.calls {
            let (phone_a, address_a) = bind_phone().await?;
            let (phone_b, address_b) = bind_phone().await?;
            bound.push((phone_a, address_a, phone_b, address_b));
        }
        Ok::<_, LoadgenError>(bound)
    })?;

    // The engine and its datapath live on the engine runtime, so every endpoint receive loop it
    // spawns is attributed to the engine's threads.
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let calls = {
        let engine = Arc::clone(&engine);
        engine_runtime
            .block_on(async move { establish_calls(&engine, plan.calls, phones).await })?
    };

    // Two streams per call: A -> engine -> B, and B -> engine -> A.
    let mut streams = Vec::with_capacity(calls.len() * 2);
    for (index, call) in calls.iter().enumerate() {
        let identifier = (index as u32).saturating_mul(2);
        streams.push(Stream {
            socket: Arc::clone(&call.phone_a),
            destination: call.near,
            identifier,
            ssrc: 0x1000_0000 | identifier,
        });
        streams.push(Stream {
            socket: Arc::clone(&call.phone_b),
            destination: call.far,
            identifier: identifier | 1,
            ssrc: 0x1000_0000 | identifier | 1,
        });
    }

    let receive_sockets: Vec<Arc<UdpSocket>> = calls
        .iter()
        .flat_map(|call| [Arc::clone(&call.phone_a), Arc::clone(&call.phone_b)])
        .collect();

    let epoch = Instant::now();
    let window_opens = epoch + plan.warmup;
    let window_closes = window_opens + plan.duration;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    let streams_per_sender = plan.streams_per_sender.max(1);
    let sockets_per_receiver = plan.sockets_per_receiver.max(1);
    let ptime = plan.ptime;

    let outcome = generator_runtime.block_on(async move {
        // Split the streams into owned batches of at most `streams_per_sender`.
        let mut batches: Vec<Vec<Stream>> = Vec::new();
        for stream in streams {
            if batches
                .last()
                .is_none_or(|batch| batch.len() >= streams_per_sender)
            {
                batches.push(Vec::with_capacity(streams_per_sender));
            }
            if let Some(batch) = batches.last_mut() {
                batch.push(stream);
            }
        }

        let mut senders = Vec::with_capacity(batches.len());
        for batch in batches {
            let stop = stop_rx.clone();
            senders.push(tokio::spawn(run_sender(
                batch,
                ptime,
                epoch,
                window_opens,
                stop,
            )));
        }

        // Shard the receive sockets the way the senders are batched, so the harness spends a few
        // dozen tasks rather than one per socket — and one histogram per shard, not per socket.
        let mut receive_shards: Vec<Vec<Arc<UdpSocket>>> = Vec::new();
        for socket in receive_sockets {
            if receive_shards
                .last()
                .is_none_or(|shard| shard.len() >= sockets_per_receiver)
            {
                receive_shards.push(Vec::with_capacity(sockets_per_receiver));
            }
            if let Some(shard) = receive_shards.last_mut() {
                shard.push(socket);
            }
        }

        let mut receivers = Vec::with_capacity(receive_shards.len());
        for shard in receive_shards {
            let stop = stop_rx.clone();
            receivers.push(tokio::spawn(run_receive_shard(
                shard,
                epoch,
                window_opens,
                stop,
            )));
        }

        // Sample CPU at the window edges so warmup and teardown are outside the measurement.
        tokio::time::sleep_until(tokio::time::Instant::from_std(window_opens)).await;
        let cpu_at_open = cpu::sample();
        let measured_from = Instant::now();

        tokio::time::sleep_until(tokio::time::Instant::from_std(window_closes)).await;
        let cpu_at_close = cpu::sample();
        let measured = measured_from.elapsed();

        let _ = stop_tx.send(true);

        let mut sent_total = 0u64;
        let mut sent_before_window = 0u64;
        for sender in senders {
            if let Ok(report) = sender.await {
                sent_total = sent_total.saturating_add(report.sent);
                sent_before_window = sent_before_window.saturating_add(report.sent_before_window);
            }
        }

        let mut delivery = Delivery::default();
        let mut latency = LatencyHistogram::new();
        for receiver in receivers {
            if let Ok(report) = receiver.await {
                delivery.merge(report.delivery);
                latency.merge(&report.latency);
            }
        }
        delivery.sent = sent_total.saturating_sub(sent_before_window);

        let delta = cpu_at_close.since(&cpu_at_open);
        (delivery, latency, delta, measured)
    });

    let (delivery, latency, cpu_delta, measured) = outcome;

    let engine_sessions = engine.session_count();
    let established = calls.len();
    {
        let engine = Arc::clone(&engine);
        engine_runtime.block_on(async move { delete_calls(&engine, &calls).await });
    }

    Ok(RunOutcome {
        calls: established,
        measured,
        delivery,
        latency,
        engine_cpu: cpu_delta.bucket_starting_with(ENGINE_THREAD_PREFIX),
        generator_cpu: cpu_delta.bucket_starting_with(LOADGEN_THREAD_PREFIX),
        total_cpu: cpu_delta.total(),
        engine_sessions,
        file_descriptors,
    })
}

/// The loopback address the harness binds its synthetic phones on.
#[must_use]
pub fn generator_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_budget_counts_four_engine_endpoints_and_two_phones_per_call() {
        // 500 calls * 6 descriptors + 64 headroom.
        assert_eq!(required_descriptors(500), 3064);
        assert_eq!(required_descriptors(0), 64);
    }

    #[test]
    fn a_default_container_limit_is_exceeded_well_before_five_hundred_calls() {
        // The trap this harness exists partly to document: Docker's default soft nofile is 1024,
        // which 500 calls blow through more than threefold.
        let budget = FileDescriptorBudget {
            soft_limit: Some(1024),
            required: required_descriptors(500),
        };
        assert!(budget.is_exceeded());

        // The boundary, pinned exactly: 160 calls needs 160*6 + 64 = 1024, which *is* the limit,
        // and the last descriptor is not usable. 159 is the largest count that fits.
        assert_eq!(required_descriptors(160), 1024);
        let exactly_at_limit = FileDescriptorBudget {
            soft_limit: Some(1024),
            required: required_descriptors(160),
        };
        assert!(
            exactly_at_limit.is_exceeded(),
            "at the limit is not under it"
        );

        let fits = FileDescriptorBudget {
            soft_limit: Some(1024),
            required: required_descriptors(159),
        };
        assert!(!fits.is_exceeded());
    }

    #[test]
    fn an_unknown_limit_is_never_reported_as_exceeded() {
        let budget = FileDescriptorBudget {
            soft_limit: None,
            required: required_descriptors(100_000),
        };
        assert!(!budget.is_exceeded());
    }

    #[test]
    fn parses_the_soft_file_limit_from_real_proc_limits_text() {
        let text = concat!(
            "Limit                     Soft Limit           Hard Limit           Units\n",
            "Max cpu time              unlimited            unlimited            seconds\n",
            "Max open files            1024                 524288               files\n",
            "Max locked memory         8388608              8388608              bytes\n",
        );
        assert_eq!(parse_soft_file_limit(text), Some(1024));
    }

    #[test]
    fn an_unlimited_soft_file_limit_parses_as_the_maximum() {
        let text = "Max open files            unlimited            unlimited            files\n";
        assert_eq!(parse_soft_file_limit(text), Some(u64::MAX));
    }

    #[test]
    fn absent_or_malformed_limits_text_yields_no_limit() {
        assert_eq!(parse_soft_file_limit(""), None);
        assert_eq!(
            parse_soft_file_limit("Max cpu time unlimited unlimited seconds"),
            None
        );
        assert_eq!(parse_soft_file_limit("Max open files\n"), None);
    }

    #[test]
    fn builds_pcmu_sdp_that_names_the_given_address() {
        let sdp = pcmu_sdp("127.0.0.1:40000".parse().expect("address"), 1);
        assert!(sdp.contains("c=IN IP4 127.0.0.1\r\n"), "connection line");
        assert!(sdp.contains("m=audio 40000 RTP/AVP 0\r\n"), "media line");
        assert!(sdp.contains("a=rtpmap:0 PCMU/8000\r\n"), "payload map");
        assert!(
            sdp.ends_with("\r\n"),
            "SDP lines are CRLF-terminated (RFC 4566 §5)"
        );
    }

    #[test]
    fn reads_the_media_address_back_out_of_an_ok_reply() {
        let result = CmdResult::Ok {
            sdp: Some(pcmu_sdp("127.0.0.1:31000".parse().expect("address"), 1)),
            duration_ms: None,
            play_id: None,
            to_tag: None,
            stats: None,
        };
        assert_eq!(
            media_address(&result),
            Some("127.0.0.1:31000".parse().expect("address"))
        );
        assert_eq!(refusal_reason(&result), None);
    }

    #[test]
    fn an_error_reply_yields_its_reason_and_no_address() {
        let result = CmdResult::Error {
            reason: "pool exhausted".into(),
        };
        assert_eq!(media_address(&result), None);
        assert_eq!(refusal_reason(&result), Some("pool exhausted".to_string()));
    }

    #[test]
    fn per_packet_cost_divides_engine_cpu_by_packets_relayed() {
        let outcome = RunOutcome {
            calls: 10,
            measured: Duration::from_secs(10),
            delivery: Delivery {
                sent: 10_000,
                received: 10_000,
                out_of_order: 0,
                foreign: 0,
            },
            latency: LatencyHistogram::new(),
            engine_cpu: CpuTime {
                user_microseconds: 20_000,
                system_microseconds: 30_000,
            },
            generator_cpu: CpuTime::default(),
            total_cpu: CpuTime::default(),
            engine_sessions: 10,
            file_descriptors: FileDescriptorBudget::for_calls(10),
        };

        // 50_000 us of engine CPU over 10_000 relayed packets.
        assert_eq!(outcome.engine_microseconds_per_relayed_packet(), Some(5.0));
        assert_eq!(outcome.relayed_packets_per_second(), 1_000.0);
        // 50 ms of CPU over a 10 s window.
        assert!((outcome.engine_cores_used() - 0.005).abs() < 1e-9);

        // At 5 us/packet one core does 200_000 pps; a 20 ms call is 100 pps => 2000 calls.
        let calls = outcome
            .calls_per_core(Duration::from_millis(20))
            .expect("calls per core");
        assert!((calls - 2000.0).abs() < 1e-6, "got {calls}");
    }

    #[test]
    fn derived_figures_are_absent_rather_than_infinite_when_nothing_was_relayed() {
        let outcome = RunOutcome {
            calls: 0,
            measured: Duration::ZERO,
            delivery: Delivery::default(),
            latency: LatencyHistogram::new(),
            engine_cpu: CpuTime::default(),
            generator_cpu: CpuTime::default(),
            total_cpu: CpuTime::default(),
            engine_sessions: 0,
            file_descriptors: FileDescriptorBudget::for_calls(0),
        };
        assert_eq!(outcome.engine_microseconds_per_relayed_packet(), None);
        assert_eq!(outcome.calls_per_core(Duration::from_millis(20)), None);
        assert_eq!(outcome.relayed_packets_per_second(), 0.0);
        assert_eq!(outcome.engine_cores_used(), 0.0);
    }

    #[test]
    fn a_zero_ptime_does_not_divide_by_zero() {
        let outcome = RunOutcome {
            calls: 1,
            measured: Duration::from_secs(1),
            delivery: Delivery {
                sent: 100,
                received: 100,
                out_of_order: 0,
                foreign: 0,
            },
            latency: LatencyHistogram::new(),
            engine_cpu: CpuTime {
                user_microseconds: 100,
                system_microseconds: 0,
            },
            generator_cpu: CpuTime::default(),
            total_cpu: CpuTime::default(),
            engine_sessions: 1,
            file_descriptors: FileDescriptorBudget::for_calls(1),
        };
        assert_eq!(outcome.calls_per_core(Duration::ZERO), None);
    }
}
