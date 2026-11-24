//! Sealing a decoded call's egress under SRTP (RFC 3711) must not add a heap allocation to the
//! per-packet path. The datagram handed to the datapath is owned bytes, which a plaintext leg pays
//! for too; the sealing itself writes into the leg's own reusable buffer. A counting global allocator
//! measures the same process loop with a plaintext egress and with a secure one, and the counts must
//! be equal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::media_pipeline::{DirectionConfig, EchoProfile, MediaCall};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
use std::sync::{Arc, Mutex};

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: delegates straight to the system allocator; only bumps a relaxed counter when armed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// The allocation counter is process-wide, so the measuring tests take turns.
static MEASURING: std::sync::Mutex<()> = std::sync::Mutex::new(());

const CALLER: &str = "192.0.2.10:5000";
const CALLEE: &str = "192.0.2.20:5000";
const WARM_FRAMES: u16 = 40;
const MEASURED_FRAMES: u16 = 200;

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn direction(ingress: u64, egress: u64, source: &str, destination: &str) -> DirectionConfig {
    let spec = CodecSpec::new(0, "PCMU", 8000, 1, 20);
    DirectionConfig {
        ingress_endpoint: EndpointId(ingress),
        accepted_source: SourceFilter::Exact(addr(source).ip()),
        egress_endpoint: EndpointId(egress),
        egress_dst: addr(destination),
        decoder: siphon_rtp_codec::factory::decoder_for(&spec).unwrap(),
        encoder: siphon_rtp_codec::factory::encoder_for(&spec).unwrap(),
        egress_ssrc: 0xE0E0_0001,
        egress_payload_type: 0,
        telephone_event_in: None,
        telephone_event_out: None,
        noise_suppression: false,
        echo: EchoProfile::default(),
        beep_detection: false,
        beep_cadence_guard_ms: None,
        produce_echo_reference: false,
        ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
    }
}

fn voice(sequence: u16) -> RxPacket {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet.extend_from_slice(&[0x40; 160]);
    RxPacket {
        endpoint: EndpointId(1),
        source: addr(CALLER),
        arrival: u64::from(sequence) * 20_000,
        data: Bytes::from(packet),
    }
}

/// Allocations over `MEASURED_FRAMES` frames of A's packets decoded and re-encoded toward B, which is
/// secure when `secure`, and how many datagrams went out in all.
fn allocations_of_the_call(secure: bool) -> (usize, usize) {
    let _turn = MEASURING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut call = MediaCall::new(
        "secure-egress",
        "tag-a",
        None,
        direction(1, 2, CALLER, CALLEE),
        direction(3, 1, CALLEE, CALLER),
        false,
    );
    if secure {
        let local = SrtpKeyMaterial::from_inline_bytes(&[1; 30]).unwrap();
        let remote = SrtpKeyMaterial::from_inline_bytes(&[2; 30]).unwrap();
        call = call.with_far_secure_leg(Arc::new(Mutex::new(SecureLeg::new(&local, &remote))));
    }
    // Built before arming: building a packet allocates, handling one must not.
    let packets: Vec<RxPacket> = (0..WARM_FRAMES + MEASURED_FRAMES).map(voice).collect();
    let mut out = Vec::with_capacity(8);
    let mut events = Vec::with_capacity(8);
    let mut run = |range: std::ops::Range<usize>, call: &mut MediaCall| -> usize {
        let mut sent = 0;
        for packet in &packets[range] {
            out.clear();
            events.clear();
            call.process(packet, &mut out, &mut events);
            sent += out.len();
        }
        sent
    };
    run(0..WARM_FRAMES as usize, &mut call);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let sent = run(
        WARM_FRAMES as usize..(WARM_FRAMES + MEASURED_FRAMES) as usize,
        &mut call,
    );
    ARMED.with(|armed| armed.set(false));
    (ALLOCATIONS.load(Ordering::Relaxed), sent)
}

#[test]
fn sealing_a_decoded_calls_egress_allocates_nothing_beyond_the_datagram_a_plain_leg_pays_for() {
    let (plain, plain_sent) = allocations_of_the_call(false);
    let (secure, secure_sent) = allocations_of_the_call(true);
    assert!(
        plain_sent >= usize::from(MEASURED_FRAMES) - 8 && secure_sent == plain_sent,
        "the loop really sends ({plain_sent} plain, {secure_sent} secure)"
    );
    assert!(plain > 0, "the call allocates its outbound datagrams");
    assert_eq!(
        secure, plain,
        "sealing writes into the leg's own buffer: no allocation beyond the owned datagram"
    );
}
