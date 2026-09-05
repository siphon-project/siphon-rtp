//! Criterion perf gate for the **WebSocket-takeover ingress path** — the per-packet cost leg A pays
//! between the datapath's `Redirect` and the bridge's decoder.
//!
//! `WsRegistry::dispatch` is that whole transform: source gate → (on a secure leg) SRTP `unprotect`
//! → symmetric-RTP latch → mailbox. It is the only per-packet code a takeover call runs on ingress,
//! so benching it end-to-end measures exactly what one call's uplink costs. Five points:
//!
//! - `plaintext` — gate + latch + mailbox on a settled leg, which is every packet after the first.
//!   The baseline.
//! - `plaintext_no_latch` — the same leg with an ICE-managed egress, where the latch is switched off
//!   at the top. The delta against `plaintext` is the entire cost of the latch, and it is the number
//!   that matters here: it is paid by every packet of every takeover call.
//! - `rebind` — a source that moves on every packet, so the latch takes its write path (re-publishing
//!   the egress watch) rather than the settled read. The worst case, and unreachable in practice: a
//!   peer would have to rebind its NAT every 20 ms to pay it.
//! - `dropped` — an off-source packet. This keeps the gate honest about its cost the way the secure
//!   pipeline's `pending_key` point does: rejection has to be a branch on the way in, so flooding a
//!   takeover leg from an unsignalled address must be *cheaper* than sending it real media.
//! - `secure` — the same leg with SRTP (de)crypt in front of the gate's successor. The delta against
//!   `plaintext` is the crypto a secure offerer's uplink pays.
//!
//! Two things are held constant rather than optimised away, so the deltas stay comparable: every
//! accepted point drains one message from the bridge's bounded mailbox (a real bridge consumes it,
//! and without that the channel fills and `dispatch` starts measuring the drop path instead), and
//! every point clones a preallocated [`Bytes`] rather than copying the frame, so no point is
//! measuring an allocator.
//!
//! The `secure` point must build a **fresh** packet per iteration: SRTP replay protection
//! (RFC 3711 §3.3) rejects a re-sent sequence number, so dispatching one pre-sealed packet in a loop
//! silently measures the replay-reject branch and reports the crypto as free. `iter_batched` keeps
//! that sealing out of the measurement.
//!
//! `cargo bench -p siphon-rtp --bench ws_takeover_bench`.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::ws_bridge::{WsCallPlan, WsEgress, WsRegistry, WsSecureLeg};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

const ENDPOINT: EndpointId = EndpointId(1);
const PEER: &str = "127.0.0.2:41000";
const OFF_SOURCE: &str = "198.51.100.7:41000";
/// 8 kHz / 20 ms of µ-law.
const FRAME_BYTES: usize = 160;

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

/// A µ-law RTP packet (PT 0), the shape a takeover leg's uplink actually carries.
fn rtp_packet(sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0xFFu8; FRAME_BYTES]);
    packet
}

fn key(seed: u8) -> SrtpKeyMaterial {
    SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30 bytes")
}

/// One received datagram. `data` is cloned from a preallocated [`Bytes`] (a refcount bump), so no
/// bench point is measuring the allocator instead of `dispatch`.
fn packet(source: SocketAddr, data: &Bytes) -> RxPacket {
    RxPacket {
        endpoint: ENDPOINT,
        source,
        arrival: 0,
        data: data.clone(),
    }
}

/// Register one takeover leg and hand back the registry plus its mailbox, so each point can drain
/// what it feeds and none of them drifts into measuring a full channel.
fn registry(
    secure: Option<Arc<WsSecureLeg>>,
    ice_managed: bool,
) -> (WsRegistry, flume::Receiver<Bytes>) {
    let registry = WsRegistry::default();
    let (rtp_in, rtp_in_rx) = flume::bounded::<Bytes>(1024);
    registry.register(WsCallPlan {
        call_id: "bench".to_string(),
        endpoint_a: ENDPOINT,
        accepted_source: SourceFilter::Exact(addr(PEER).ip()),
        ice_pending: false,
        secure,
        egress: Arc::new(WsEgress::new(addr(PEER), ice_managed)),
        rtp_in,
        // The registry only ever aborts these; a takeover leg's real bridge and drain tasks are not
        // on the ingress path being measured.
        bridge_task: tokio::spawn(std::future::pending()),
        drain_task: tokio::spawn(std::future::pending()),
    });
    (registry, rtp_in_rx)
}

fn ws_takeover_dispatch(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    // `WsCallPlan` holds two `JoinHandle`s, so registration needs a runtime in scope.
    let _guard = runtime.enter();
    let mut group = criterion.benchmark_group("ws_takeover_dispatch");

    let peer = addr(PEER);
    let frame = Bytes::from(rtp_packet(1, 0x0A0A_0A0A));

    // Settled: gate + latch + mailbox, the latch already on this source.
    let (plain, plain_rx) = registry(None, false);
    group.bench_function("plaintext", |bencher| {
        bencher.iter(|| {
            plain.dispatch(black_box(packet(peer, &frame)));
            let _ = plain_rx.try_recv();
        })
    });

    // The same leg with the latch switched off (an ICE-managed egress): the delta is the latch.
    let (no_latch, no_latch_rx) = registry(None, true);
    group.bench_function("plaintext_no_latch", |bencher| {
        bencher.iter(|| {
            no_latch.dispatch(black_box(packet(peer, &frame)));
            let _ = no_latch_rx.try_recv();
        })
    });

    // The latch's write path on every packet — a source that never settles. Addresses are resolved
    // up front; parsing one per iteration would measure the parser, not the latch.
    let (rebind, rebind_rx) = registry(None, false);
    let sources: Vec<SocketAddr> = (41000u16..41064)
        .map(|port| SocketAddr::new(peer.ip(), port))
        .collect();
    let mut next = 0usize;
    group.bench_function("rebind", |bencher| {
        bencher.iter(|| {
            next = (next + 1) % sources.len();
            rebind.dispatch(black_box(packet(sources[next], &frame)));
            let _ = rebind_rx.try_recv();
        })
    });

    // An off-source flood: the gate must reject it more cheaply than it accepts real media.
    let off_source = addr(OFF_SOURCE);
    group.bench_function("dropped", |bencher| {
        bencher.iter(|| plain.dispatch(black_box(packet(off_source, &frame))))
    });

    // A secure leg: SRTP `unprotect` in front of the same gate and latch. Each iteration gets a fresh
    // sequence number, or RFC 3711 §3.3 replay protection would reject every packet after the first
    // and the point would report the crypto as costing nothing.
    let engine_key = key(0x11);
    let peer_key = key(0x22);
    let mut peer_leg = SecureLeg::new(&peer_key, &engine_key);
    let (secure, secure_rx) = registry(
        Some(Arc::new(WsSecureLeg::keyed(SecureLeg::new(
            &engine_key,
            &peer_key,
        )))),
        false,
    );
    let mut sequence = 0u16;
    group.bench_function("secure", |bencher| {
        bencher.iter_batched(
            || {
                sequence = sequence.wrapping_add(1);
                let mut sealed = Vec::new();
                peer_leg
                    .protect(&rtp_packet(sequence, 0x0A0A_0A0A), &mut sealed)
                    .expect("peer protect");
                Bytes::from(sealed)
            },
            |sealed| {
                secure.dispatch(black_box(packet(peer, &sealed)));
                let _ = secure_rx.try_recv();
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, ws_takeover_dispatch);
criterion_main!(benches);
