//! What a crypto bridge flow adds per packet so a hold in the decoding actor can continue its stream
//! ([`siphon_rtp_engine::egress_track`]) must allocate nothing in the steady state: neither the
//! recording of the forwarded position nor, on a released call that renumbers what its peer sends for
//! the rest of its life, the copy into the buffer the bridge keeps and reuses.
//!
//! A counting global allocator proves it over the same loop the bridge runs per datagram.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_engine::egress_track::{
    continue_in_place, continue_stream, EgressTrack, StreamPosition,
};

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

const FRAMES: u16 = 2_000;

/// The counter is global, so the tests take turns.
static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn take_turn() -> std::sync::MutexGuard<'static, ()> {
    TURN.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn packet(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet.resize(172, 0xFF);
    packet
}

/// Allocations over `FRAMES` packets through `track`, after one warm-up packet has sized the scratch.
fn allocations_over(track: &EgressTrack, in_place: bool) -> usize {
    let mut scratch = Vec::new();
    let mut packets: Vec<Vec<u8>> = (0..=FRAMES).map(packet).collect();
    let warm = packets.remove(0);
    assert!(continue_stream(track, &warm, &mut scratch, |_| None).is_some());
    track.commit();
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    for packet in &mut packets {
        if in_place {
            assert!(continue_in_place(track, packet));
            track.commit();
        } else {
            assert!(continue_stream(track, packet, &mut scratch, |_| None).is_some());
            track.commit();
        }
    }
    ARMED.with(|armed| armed.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

#[test]
fn recording_the_forwarded_stream_allocates_nothing_in_the_steady_state() {
    let _turn = take_turn();
    assert_eq!(allocations_over(&EgressTrack::default(), false), 0);
    assert_eq!(allocations_over(&EgressTrack::default(), true), 0);
}

#[test]
fn renumbering_a_released_stream_allocates_nothing_in_the_steady_state() {
    let _turn = take_turn();
    let continuing = || {
        EgressTrack::continuing(Some(StreamPosition {
            ssrc: 0x0A0A_0A0A,
            sequence: 5_000,
            timestamp: 800_000,
        }))
    };
    assert_eq!(allocations_over(&continuing(), false), 0);
    assert_eq!(allocations_over(&continuing(), true), 0);
}

#[test]
fn sending_under_a_fresh_ssrc_after_a_lost_position_allocates_nothing_in_the_steady_state() {
    let _turn = take_turn();
    let fresh = || {
        let track = EgressTrack::default();
        track.resolve_lost();
        track
    };
    assert_eq!(allocations_over(&fresh(), false), 0);
    assert_eq!(allocations_over(&fresh(), true), 0);
}

#[test]
fn a_guarded_flow_allocates_nothing_in_the_steady_state_before_and_after_a_restart() {
    let _turn = take_turn();
    assert_eq!(allocations_over(&EgressTrack::guarded(), false), 0);
    // A stream that restarts partway through: renumbering copies into the reused scratch.
    let track = EgressTrack::guarded();
    let mut scratch = Vec::new();
    let packets: Vec<Vec<u8>> = (0..1_000u16).chain(0..1_000u16).map(packet).collect();
    for packet in &packets[..2] {
        assert!(continue_stream(&track, packet, &mut scratch, |_| None).is_some());
        track.commit();
    }
    // The restart itself is a (rare) event that logs; what follows it is the steady state.
    for packet in &packets[2..=1_001] {
        continue_stream(&track, packet, &mut scratch, |_| None).expect("forwarded");
        track.commit();
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let mut renumbered = 0usize;
    for packet in &packets[1_002..] {
        let sent = continue_stream(&track, packet, &mut scratch, |_| None).expect("forwarded");
        renumbered += usize::from(sent[2..4] != packet[2..4]);
        track.commit();
    }
    ARMED.with(|armed| armed.set(false));
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed) - before, 0);
    assert!(renumbered > 900, "the restart was renumbered: {renumbered}");
}

#[test]
fn the_send_window_of_a_leg_allocates_nothing_in_the_steady_state() {
    let _turn = take_turn();
    use siphon_rtp_srtp::leg::SecureLeg;
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

    let local = SrtpKeyMaterial::from_inline_bytes(&[0xAA; 30]).expect("key");
    let remote = SrtpKeyMaterial::from_inline_bytes(&[0xBB; 30]).expect("key");
    let mut leg = SecureLeg::new(&local, &remote);
    let mut sealed = Vec::with_capacity(256);
    // The first packet of the SSRC creates its window; sizing the buffer is the other warm-up.
    leg.protect(&packet(0), &mut sealed).expect("first");
    let packets: Vec<Vec<u8>> = (1..=FRAMES).map(packet).collect();
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    for packet in &packets {
        leg.protect(packet, &mut sealed).expect("protect");
    }
    ARMED.with(|armed| armed.set(false));
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed) - before, 0);
    // And a refusal allocates nothing either.
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    assert!(leg.protect(&packets[0], &mut sealed).is_err());
    ARMED.with(|armed| armed.set(false));
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed) - before, 0);
}
