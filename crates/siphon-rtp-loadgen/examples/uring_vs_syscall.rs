//! Is `io_uring` worth a production datapath backend?
//!
//! The relay's cost is two syscalls per packet, spread one-packet-per-ptime across one socket per
//! media stream. Profiling put ~13 % of engine CPU in `epoll` readiness tracking and ~7 % in
//! file-descriptor lookup and refcounting — both of which batched submission with registered files
//! removes. This measures whether that is actually true on real hardware, **before** anyone writes a
//! backend, because the backend is the expensive part and it also has to inherit the signalled-source
//! gate and the SSRC latch.
//!
//! ```sh
//! cargo run --release -p siphon-rtp-loadgen --example uring_vs_syscall -- --sockets 1000
//! ```
//!
//! # The design, and why it is shaped this way
//!
//! One feeder thread saturates `--sockets` loopback UDP sockets; one **relay** thread drains them and
//! forwards each datagram to a sink, one receive and one send per packet, exactly as the datapath
//! does. Both arms do identical work and differ only in the I/O mechanism.
//!
//! CPU is attributed **per thread**, so the feeder cannot contaminate the figure — the same technique
//! the capacity harness uses, and the reason a single-process experiment is trustworthy here.
//!
//! Saturating the sockets rather than pre-filling them is deliberate. A drained socket would make an
//! `io_uring` receive wait for data that never comes, and a pre-filled one would let the control arm
//! reap every descriptor from a single `epoll_wait` — its best case, and not the production shape. A
//! saturated socket also means the control arm never waits for readiness at all, which is *still* its
//! best case: production `epoll` pays more, at 50 pps per socket, than this measures. So any
//! advantage `io_uring` shows here is a **lower bound**.
//!
//! Both arms read the source address (`recvfrom` / `RecvMsg`), because a relay needs it for the
//! source gate. Measuring with plain `recv` would overstate the gain.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "example: a panic reports failure"
)]

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use siphon_rtp_loadgen::cpu;

/// A 12-byte RTP header plus a 160-byte G.711 frame — the datagram the datapath actually carries.
const PACKET_LEN: usize = 172;
/// Receive buffer size, matching the datapath's `MAX_DATAGRAM`.
const BUFFER_LEN: usize = 2048;
/// Thread-name prefix whose CPU is the measurement. Under the 15-character `comm` ceiling.
const RELAY_THREAD: &str = "sr-relay";
/// Thread-name prefix for the load source, excluded from the figure.
const FEEDER_THREAD: &str = "sr-feed";

/// How many receives are in flight per socket in the `io_uring` arm.
///
/// One is enough to keep the ring busy on a saturated socket and keeps the slot bookkeeping a
/// one-to-one map from socket to slot, which is what a real backend would start with.
const RECEIVES_IN_FLIGHT_PER_SOCKET: usize = 1;

fn main() {
    let mut sockets = 1000usize;
    let mut seconds = 10u64;
    // 50 pps per socket is one 20 ms G.711 frame per tick, the cadence the whole capacity model uses.
    let mut rate = 50u64;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--sockets" => {
                sockets = arguments
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(sockets)
            }
            "--seconds" => {
                seconds = arguments
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(seconds)
            }
            "--rate" => {
                rate = arguments
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(rate)
            }
            other => {
                eprintln!("unknown flag {other}; usage: --sockets N --seconds N --rate PPS");
                std::process::exit(2);
            }
        }
    }

    println!(
        "io_uring feasibility: {sockets} sockets, {seconds}s per arm, {PACKET_LEN}-byte datagrams\n"
    );

    // Part 1 — saturated sockets. Answers the narrow question: is the syscall *boundary* the cost?
    // The control arm here never waits for readiness, so it is the classic path at its absolute best.
    println!("=== PART 1: saturated sockets (isolates the syscall boundary) ===\n");
    let saturated_syscall = measure(sockets, seconds, Arm::Syscall, 0);
    let saturated_epoll = measure(sockets, seconds, Arm::Epoll, 0);
    let saturated_uring = measure(sockets, seconds, Arm::IoUring, 0);
    for measurement in [&saturated_syscall, &saturated_epoll, &saturated_uring] {
        print_measurement(measurement);
    }
    compare("saturated", &saturated_epoll, &saturated_uring);

    // Part 2 — the production shape: one packet per socket per 20 ms. Readiness tracking behaves
    // completely differently when a socket yields one datagram per wakeup instead of hundreds, and
    // that difference is the whole reason to consider a different datapath.
    println!(
        "\n=== PART 2: paced at {rate} pps per socket (the production shape) ===\n",
        rate = rate
    );
    let paced_epoll = measure(sockets, seconds, Arm::Epoll, rate);
    let paced_uring = measure(sockets, seconds, Arm::IoUring, rate);
    for measurement in [&paced_epoll, &paced_uring] {
        print_measurement(measurement);
    }
    compare("paced", &paced_epoll, &paced_uring);

    println!(
        "\nOffered load in part 2 was {offered} pps ({sockets} sockets x {rate} pps). If an arm \n\
         relayed materially less than that it could not keep up, and its per-packet figure is \n\
         measuring saturation rather than cost.",
        offered = sockets as u64 * rate
    );
}

/// Which I/O mechanism the relay thread uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    /// `recvfrom` + `sendto`, round-robin with no readiness call. The classic path's *best* case,
    /// which isolates the question "is the syscall boundary itself the cost?".
    Syscall,
    /// `epoll_wait` + `recvfrom` + `sendto` — what Tokio does underneath, and therefore the control
    /// the production comparison actually turns on.
    Epoll,
    /// Batched `RecvMsg` + `SendMsg` submissions against registered files.
    IoUring,
}

impl Arm {
    fn label(self) -> &'static str {
        match self {
            Arm::Syscall => "syscall, no readiness (recvfrom + sendto round-robin)",
            Arm::Epoll => "epoll (epoll_wait + recvfrom + sendto) -- what Tokio does",
            Arm::IoUring => "io_uring (RecvMsg + SendMsg, registered files)",
        }
    }
}

/// What one arm produced.
struct Measurement {
    arm: Arm,
    relayed: u64,
    relay_cpu_microseconds: u64,
    elapsed: Duration,
    submits: u64,
}

impl Measurement {
    /// Relay-thread CPU microseconds per packet relayed — the figure being compared.
    fn microseconds_per_packet(&self) -> Option<f64> {
        (self.relayed > 0).then(|| self.relay_cpu_microseconds as f64 / self.relayed as f64)
    }

    fn packets_per_second(&self) -> f64 {
        let seconds = self.elapsed.as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        self.relayed as f64 / seconds
    }

    /// Kernel-boundary crossings per packet: two syscalls, or one amortised `io_uring_enter`.
    fn crossings_per_packet(&self) -> Option<f64> {
        (self.relayed > 0).then(|| self.submits as f64 / self.relayed as f64)
    }
}

/// Bind `count` loopback sockets with a receive buffer large enough to stay saturated.
fn bind_ingress(count: usize) -> Vec<UdpSocket> {
    let mut bound = Vec::with_capacity(count);
    for _ in 0..count {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ingress");
        socket.set_nonblocking(true).expect("nonblocking");
        set_receive_buffer(socket.as_raw_fd(), 1 << 20);
        bound.push(socket);
    }
    bound
}

/// Raise `SO_RCVBUF`, so the feeder can keep the socket non-empty and the relay never waits.
fn set_receive_buffer(fd: RawFd, bytes: libc::c_int) {
    // SAFETY: `fd` is a live socket owned by the caller, and the option value is a correctly sized
    // `c_int` whose address and length are passed together.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(bytes).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Run one arm: start the feeder, relay for `seconds`, and report the relay thread's own CPU.
fn measure(sockets: usize, seconds: u64, arm: Arm, per_socket_rate: u64) -> Measurement {
    let ingress = bind_ingress(sockets);
    let targets: Vec<SocketAddr> = ingress
        .iter()
        .map(|socket| socket.local_addr().expect("ingress addr"))
        .collect();

    // The sink is drained by nobody; a large receive buffer keeps `sendto` from hitting ENOBUFS on
    // loopback, and whether the sink reads is irrelevant to the relay's cost.
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sink");
    set_receive_buffer(sink.as_raw_fd(), 1 << 22);
    let sink_addr = sink.local_addr().expect("sink addr");
    let egress = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind egress");

    let stop = Arc::new(AtomicBool::new(false));
    let fed = Arc::new(AtomicU64::new(0));

    let feeder = {
        let stop = Arc::clone(&stop);
        let fed = Arc::clone(&fed);
        std::thread::Builder::new()
            .name(FEEDER_THREAD.to_string())
            .spawn(move || feed(&targets, &stop, &fed, per_socket_rate))
            .expect("spawn feeder")
    };

    // Let the feeder fill every socket before the window opens, so the relay is saturated from the
    // first packet and never measures an empty-queue path.
    std::thread::sleep(Duration::from_millis(750));

    let relay = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name(RELAY_THREAD.to_string())
            .spawn(move || {
                let before = cpu::sample();
                let started = Instant::now();
                let (relayed, submits) = match arm {
                    Arm::Syscall => relay_syscall(&ingress, &egress, sink_addr, seconds),
                    Arm::Epoll => relay_epoll(&ingress, &egress, sink_addr, seconds),
                    Arm::IoUring => relay_io_uring(&ingress, &egress, sink_addr, seconds),
                };
                let elapsed = started.elapsed();
                let after = cpu::sample();
                stop.store(true, Ordering::Relaxed);
                let delta = after.since(&before);
                (
                    relayed,
                    submits,
                    elapsed,
                    delta
                        .bucket_starting_with(RELAY_THREAD)
                        .total_microseconds(),
                )
            })
            .expect("spawn relay")
    };

    let (relayed, submits, elapsed, relay_cpu_microseconds) = relay.join().expect("relay thread");
    stop.store(true, Ordering::Relaxed);
    let _ = feeder.join();

    Measurement {
        arm,
        relayed,
        relay_cpu_microseconds,
        elapsed,
        submits,
    }
}

/// Drive the ingress sockets.
///
/// `per_socket_rate` of 0 saturates them, which isolates the syscall mechanism. A non-zero rate
/// paces one datagram per socket per interval — 50 pps being the 20 ms RTP cadence — which is the
/// shape that decides whether readiness tracking or batching wins in production.
fn feed(targets: &[SocketAddr], stop: &AtomicBool, fed: &AtomicU64, per_socket_rate: u64) {
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind feeder");
    let packet = [0x80u8; PACKET_LEN];

    if per_socket_rate == 0 {
        while !stop.load(Ordering::Relaxed) {
            for target in targets {
                if sender.send_to(&packet, target).is_ok() {
                    fed.fetch_add(1, Ordering::Relaxed);
                }
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }
        }
        return;
    }

    let interval = Duration::from_secs_f64(1.0 / per_socket_rate as f64);
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        for target in targets {
            if sender.send_to(&packet, target).is_ok() {
                fed.fetch_add(1, Ordering::Relaxed);
            }
        }
        next += interval;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else {
            // Behind schedule: resynchronise rather than burst, so the offered rate stays honest.
            next = now;
        }
    }
}

/// Control arm: one `recvfrom` and one `sendto` per packet, round-robin across the sockets.
///
/// No readiness call at all — the sockets are saturated, so this is the classic path's best case.
fn relay_syscall(
    ingress: &[UdpSocket],
    egress: &UdpSocket,
    sink: SocketAddr,
    seconds: u64,
) -> (u64, u64) {
    let mut buffer = [0u8; BUFFER_LEN];
    let mut relayed = 0u64;
    let mut syscalls = 0u64;
    let deadline = Instant::now() + Duration::from_secs(seconds);

    while Instant::now() < deadline {
        for socket in ingress {
            // The source address is read because a relay needs it for the signalled-source gate.
            match socket.recv_from(&mut buffer) {
                Ok((length, _source)) => {
                    syscalls += 1;
                    if egress.send_to(&buffer[..length], sink).is_ok() {
                        syscalls += 1;
                        relayed += 1;
                    }
                }
                Err(_) => syscalls += 1,
            }
        }
    }

    (relayed, syscalls)
}

/// Production control: `epoll_wait` for readiness, then `recvfrom`/`sendto`, draining each ready
/// socket until it blocks. This is the shape Tokio's reactor drives, so it is the arm an io_uring
/// backend would actually have to beat.
fn relay_epoll(
    ingress: &[UdpSocket],
    egress: &UdpSocket,
    sink: SocketAddr,
    seconds: u64,
) -> (u64, u64) {
    // SAFETY: `epoll_create1` takes flags only and returns a new fd or -1; it touches no memory of
    // ours.
    let epoll_fd = unsafe { libc::epoll_create1(0) };
    assert!(epoll_fd >= 0, "epoll_create1 failed");

    for (index, socket) in ingress.iter().enumerate() {
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: index as u64,
        };
        // SAFETY: `epoll_fd` is live, `socket` outlives this call, and `event` is a correctly
        // initialised `epoll_event` we own for the duration of the call.
        let added = unsafe {
            libc::epoll_ctl(
                epoll_fd,
                libc::EPOLL_CTL_ADD,
                socket.as_raw_fd(),
                &mut event,
            )
        };
        assert_eq!(added, 0, "epoll_ctl ADD failed");
    }

    let mut ready = vec![libc::epoll_event { events: 0, u64: 0 }; 1024];
    let mut buffer = [0u8; BUFFER_LEN];
    let mut relayed = 0u64;
    let mut crossings = 0u64;
    let deadline = Instant::now() + Duration::from_secs(seconds);

    while Instant::now() < deadline {
        // SAFETY: `ready` is a live, correctly sized array of `epoll_event` and the length passed is
        // its true capacity.
        let count = unsafe {
            libc::epoll_wait(
                epoll_fd,
                ready.as_mut_ptr(),
                ready.len() as libc::c_int,
                100,
            )
        };
        crossings += 1;
        if count <= 0 {
            continue;
        }

        for event in &ready[..count as usize] {
            let index = event.u64 as usize;
            // Drain until it blocks, which is what an edge-triggered reactor does.
            loop {
                match ingress[index].recv_from(&mut buffer) {
                    Ok((length, _source)) => {
                        crossings += 1;
                        if egress.send_to(&buffer[..length], sink).is_ok() {
                            crossings += 1;
                            relayed += 1;
                        }
                    }
                    Err(_) => {
                        crossings += 1;
                        break;
                    }
                }
            }
        }
    }

    // SAFETY: `epoll_fd` is a live fd this function owns and no longer uses.
    unsafe { libc::close(epoll_fd) };
    (relayed, crossings)
}

/// Per-socket submission state, at a stable address for as long as the kernel may read it.
struct Slot {
    buffer: [u8; BUFFER_LEN],
    source: libc::sockaddr_storage,
    receive_iov: libc::iovec,
    receive_msghdr: libc::msghdr,
    send_iov: libc::iovec,
    send_addr: libc::sockaddr_in,
    send_msghdr: libc::msghdr,
}

impl Slot {
    fn new(sink: SocketAddr) -> Box<Self> {
        let sink_v4 = match sink {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => panic!("the experiment binds loopback IPv4 only"),
        };
        // SAFETY: `sockaddr_storage`, `iovec`, `msghdr` and `sockaddr_in` are all plain C structs
        // whose all-zero bit pattern is valid; every field is populated below before use.
        let mut slot: Box<Slot> = Box::new(unsafe { std::mem::zeroed() });
        slot.send_addr = sockaddr_in_from(sink_v4);
        // Wire the pointers only after boxing, so they refer to the final heap location.
        let slot_ptr: *mut Slot = &mut *slot;
        // SAFETY: `slot_ptr` is a valid, uniquely-owned allocation; each field is written once and
        // the pointers stored refer to sibling fields of the same allocation, which outlives them.
        unsafe {
            (*slot_ptr).receive_iov = libc::iovec {
                iov_base: std::ptr::addr_of_mut!((*slot_ptr).buffer).cast(),
                iov_len: BUFFER_LEN,
            };
            (*slot_ptr).receive_msghdr.msg_name = std::ptr::addr_of_mut!((*slot_ptr).source).cast();
            (*slot_ptr).receive_msghdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            (*slot_ptr).receive_msghdr.msg_iov = std::ptr::addr_of_mut!((*slot_ptr).receive_iov);
            (*slot_ptr).receive_msghdr.msg_iovlen = 1;

            (*slot_ptr).send_iov = libc::iovec {
                iov_base: std::ptr::addr_of_mut!((*slot_ptr).buffer).cast(),
                iov_len: 0,
            };
            (*slot_ptr).send_msghdr.msg_name = std::ptr::addr_of_mut!((*slot_ptr).send_addr).cast();
            (*slot_ptr).send_msghdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            (*slot_ptr).send_msghdr.msg_iov = std::ptr::addr_of_mut!((*slot_ptr).send_iov);
            (*slot_ptr).send_msghdr.msg_iovlen = 1;
        }
        slot
    }
}

/// Build a `sockaddr_in` for a v4 socket address.
fn sockaddr_in_from(addr: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

/// `user_data` encoding: the slot index in the high bits, the phase in the low bit.
const PHASE_RECEIVE: u64 = 0;
const PHASE_SEND: u64 = 1;
fn user_data(slot: usize, phase: u64) -> u64 {
    ((slot as u64) << 1) | phase
}
fn decode(user_data: u64) -> (usize, u64) {
    ((user_data >> 1) as usize, user_data & 1)
}

/// Experimental arm: batched `RecvMsg`/`SendMsg` against registered files.
///
/// Registered files are the point of the comparison as much as the batching: a fixed-file submission
/// skips the per-syscall descriptor table lookup and refcount that profiling put at ~7 % of engine
/// CPU.
fn relay_io_uring(
    ingress: &[UdpSocket],
    egress: &UdpSocket,
    sink: SocketAddr,
    seconds: u64,
) -> (u64, u64) {
    use io_uring::{opcode, types, IoUring};

    let socket_count = ingress.len();
    // Room for a receive and a send in flight for every socket, plus slack.
    let entries = ((socket_count * 2 * RECEIVES_IN_FLIGHT_PER_SOCKET) as u32)
        .next_power_of_two()
        .clamp(64, 32768);
    let mut ring: IoUring = IoUring::builder().build(entries).expect("build io_uring");

    // Registered files: index 0..socket_count are the ingress sockets, the last is the egress.
    let mut fds: Vec<RawFd> = ingress.iter().map(|socket| socket.as_raw_fd()).collect();
    fds.push(egress.as_raw_fd());
    let egress_index = socket_count as u32;
    ring.submitter()
        .register_files(&fds)
        .expect("register files");

    let mut slots: Vec<Box<Slot>> = (0..socket_count).map(|_| Slot::new(sink)).collect();

    let mut relayed = 0u64;
    let mut enters = 0u64;
    let deadline = Instant::now() + Duration::from_secs(seconds);

    // Prime one receive per socket.
    let mut pending: VecDeque<io_uring::squeue::Entry> = VecDeque::with_capacity(socket_count * 2);
    for (index, slot) in slots.iter_mut().enumerate() {
        let msghdr: *mut libc::msghdr = std::ptr::addr_of_mut!(slot.receive_msghdr);
        pending.push_back(
            opcode::RecvMsg::new(types::Fixed(index as u32), msghdr)
                .build()
                .user_data(user_data(index, PHASE_RECEIVE)),
        );
    }

    // Reused across batches: allocating this inside the loop would charge io_uring for a heap
    // allocation the control arm never makes.
    let mut completions: Vec<(u64, i32)> = Vec::with_capacity(entries as usize);

    while Instant::now() < deadline {
        // Fill the submission queue from the pending list.
        {
            let mut submission = ring.submission();
            while let Some(entry) = pending.pop_front() {
                // SAFETY: every entry points at a `Slot` field. The slots live in `slots` for the
                // whole loop and are never moved (they are boxed and only read through raw
                // pointers), so the kernel's view stays valid until its completion is reaped.
                if unsafe { submission.push(&entry) }.is_err() {
                    // Queue full: put it back and let the kernel drain first.
                    pending.push_front(entry);
                    break;
                }
            }
        }

        // One kernel crossing carrying every queued submission, waiting for at least one completion.
        match ring.submit_and_wait(1) {
            Ok(_) => enters += 1,
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) => panic!("io_uring submit: {error}"),
        }

        completions.clear();
        for completion in ring.completion() {
            completions.push((completion.user_data(), completion.result()));
        }

        for &(data, result) in &completions {
            let (index, phase) = decode(data);
            match phase {
                PHASE_RECEIVE => {
                    if result > 0 {
                        // Forward exactly the bytes received, from the same buffer — no copy.
                        slots[index].send_iov.iov_len = result as usize;
                        let msghdr: *const libc::msghdr =
                            std::ptr::addr_of!(slots[index].send_msghdr);
                        pending.push_back(
                            opcode::SendMsg::new(types::Fixed(egress_index), msghdr)
                                .build()
                                .user_data(user_data(index, PHASE_SEND)),
                        );
                    } else {
                        // Nothing there (or an error): re-arm this socket's receive.
                        let msghdr: *mut libc::msghdr =
                            std::ptr::addr_of_mut!(slots[index].receive_msghdr);
                        pending.push_back(
                            opcode::RecvMsg::new(types::Fixed(index as u32), msghdr)
                                .build()
                                .user_data(user_data(index, PHASE_RECEIVE)),
                        );
                    }
                }
                _ => {
                    if result > 0 {
                        relayed += 1;
                    }
                    // The send is done with the buffer; take the next packet from this socket.
                    let msghdr: *mut libc::msghdr =
                        std::ptr::addr_of_mut!(slots[index].receive_msghdr);
                    pending.push_back(
                        opcode::RecvMsg::new(types::Fixed(index as u32), msghdr)
                            .build()
                            .user_data(user_data(index, PHASE_RECEIVE)),
                    );
                }
            }
        }
    }

    (relayed, enters)
}

/// Print one arm's figures.
fn print_measurement(measurement: &Measurement) {
    println!("{}", measurement.arm.label());
    println!("  packets relayed        {}", measurement.relayed);
    println!(
        "  throughput            {:.0} pps",
        measurement.packets_per_second()
    );
    println!(
        "  relay-thread CPU      {:.3} s",
        measurement.relay_cpu_microseconds as f64 / 1_000_000.0
    );
    match measurement.microseconds_per_packet() {
        Some(cost) => println!("  CPU per packet        {cost:.3} us"),
        None => println!("  CPU per packet        n/a (nothing relayed)"),
    }
    match measurement.crossings_per_packet() {
        Some(crossings) => println!("  kernel crossings/pkt  {crossings:.3}"),
        None => println!("  kernel crossings/pkt  n/a"),
    }
    println!();
}

/// Compare the production control against io_uring for one load shape.
fn compare(shape: &str, control: &Measurement, experiment: &Measurement) {
    match (
        control.microseconds_per_packet(),
        experiment.microseconds_per_packet(),
    ) {
        (Some(base), Some(candidate)) if base > 0.0 => {
            let change = (candidate - base) / base * 100.0;
            if change < 0.0 {
                println!(
                    "VERDICT ({shape}): io_uring is {:.1}% CHEAPER per packet \
                     ({base:.3} -> {candidate:.3} us)",
                    -change
                );
            } else {
                println!(
                    "VERDICT ({shape}): io_uring is {change:.1}% MORE expensive per packet \
                     ({base:.3} -> {candidate:.3} us)"
                );
            }
        }
        _ => println!("VERDICT ({shape}): not enough data"),
    }
}
