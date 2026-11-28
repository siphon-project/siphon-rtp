#![cfg(test)]

//! Lawful interception (ETSI TS 103 221-2 X3) of a split call, end to end on real sockets: X3 carries
//! what is on each wire. The target's own voice is what its leg receives; what the target hears is
//! what the bot plays its leg, never the other party's own voice, which the split isolated.
//!
//! The deliveries are sessions put in the engine's own table, with the delivery task replaced by a
//! channel the test reads: the framing and the TLS connection are covered by the delivery tests
//! (`tests/x3_delivery.rs`), the placement of the taps by the unit tests of the actor, and what only
//! this can show is the placement against a live engine over every call shape, through attach, detach,
//! a re-offer and a delete.

use super::secure_hold::*;
use super::ws_split::*;
use super::*;
use crate::media_pipeline::{MediaControl, MediaInput};
use crate::x3::{X3Delivery, X3Packet};
use siphon_rtp_li::PayloadDirection;
use siphon_rtp_proto::{X3EndReason, Xid};
use std::collections::HashSet;

const OWNER_TAG: &str = "a";

/// One more warrant on the call, as `attach_x3` leaves it, and the taps put where the call's media
/// is now (what a re-answer's carry does).
async fn intercept(rig: &Rig, xid_byte: u8, target_is_caller: bool) -> X3Delivery {
    let (factory, delivery) = crate::x3::x3_channel(8_192);
    let counters = factory.counters().clone();
    rig.engine
        .x3_sessions
        .entry(rig.call_id.to_string())
        .or_default()
        .push(crate::engine::intercept::X3Session {
            xid: Xid::from_bytes([xid_byte; 16]),
            delivery: format!("mediation-{xid_byte}.example.net:8090"),
            correlation_id: u64::from(xid_byte),
            from_tag: OWNER_TAG.to_string(),
            owner: CLIENT,
            bridged_endpoints: Vec::new(),
            factory,
            target_is_caller,
            counters,
            transport: tokio::spawn(std::future::pending::<()>()),
            ended: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            joined_endpoint: None,
            handing_over: Default::default(),
        });
    rig.engine.carry_x3_across_answer(rig.call_id).await;
    delivery
}

/// What an interception delivered, by direction.
#[derive(Default)]
struct Tapped {
    to_target: Vec<X3Packet>,
    from_target: Vec<X3Packet>,
}

fn take(delivery: &X3Delivery) -> Tapped {
    let mut tapped = Tapped::default();
    for packet in delivery.packets.try_iter() {
        match packet.direction {
            PayloadDirection::ToTarget => tapped.to_target.push(packet),
            _ => tapped.from_target.push(packet),
        }
    }
    tapped
}

/// The audio of the RTP packets an interception delivered (G.711 µ-law on every leg of these rigs).
fn pcm(packets: &[X3Packet]) -> Vec<i16> {
    let mut decoder = siphon_rtp_codec::g711::G711::ulaw();
    let mut samples = Vec::new();
    let mut frame = [0i16; 1024];
    for packet in packets {
        let count =
            siphon_rtp_codec::Decoder::decode(&mut decoder, &packet.payload[12..], &mut frame)
                .expect("decode");
        samples.extend_from_slice(&frame[..count]);
    }
    samples
}

fn stream_of(packet: &X3Packet) -> (u32, u16) {
    (
        u32::from_be_bytes([
            packet.payload[8],
            packet.payload[9],
            packet.payload[10],
            packet.payload[11],
        ]),
        u16::from_be_bytes([packet.payload[2], packet.payload[3]]),
    )
}

/// The tones a warrant on `target_is_caller` should see: (the target's own, what the target hears
/// from the bot, what the target heard from the other party before the split).
fn tones(target_is_caller: bool) -> (f32, f32, f32) {
    if target_is_caller {
        (A_TONE, TO_A_TONE, B_TONE)
    } else {
        (B_TONE, TO_B_TONE, A_TONE)
    }
}

/// What the target's phone heard in a window.
fn heard_by(heard: &(Heard, Heard), target_is_caller: bool) -> &Heard {
    if target_is_caller {
        &heard.0
    } else {
        &heard.1
    }
}

/// Every packet the target heard in a window was delivered to the interception, byte for byte, as
/// what is on the target's wire. The first few are not checked: a packet sent just before the window
/// opened was delivered, and drained, before the phone's window began to hear it.
#[track_caller]
fn assert_the_wire_was_delivered(heard: &Heard, tapped: &Tapped, who: &str) {
    assert!(
        heard.media.len() >= 25,
        "{who}: heard {}",
        heard.media.len()
    );
    for packet in heard.media.iter().skip(4) {
        let found = tapped
            .to_target
            .iter()
            .find(|delivered| stream_of(delivered) == (packet.ssrc, packet.sequence));
        let Some(found) = found else {
            panic!(
                "{who}: the target heard ssrc {:#x} sequence {} and the interception was not given it",
                packet.ssrc, packet.sequence
            );
        };
        assert_eq!(
            &found.payload[12..],
            packet.payload.as_slice(),
            "{who}: delivered as it was sent"
        );
    }
}

#[track_caller]
fn assert_no_duplicates(tapped: &[&X3Packet], who: &str) {
    let mut seen = HashSet::new();
    for packet in tapped {
        assert!(
            seen.insert((stream_of(packet), packet.direction as u8)),
            "{who}: {:?} was delivered twice",
            stream_of(packet)
        );
    }
}

/// The warrant on the target: before the split it sees the target's voice and the other party's; while
/// split, the target's voice and the bot's, and none of the other party's; after the detach, as before.
async fn assert_x3_through_the_split_cycle(mut rig: Rig, target_is_caller: bool) {
    let events = rig.engine.register_client(CLIENT);
    rig.warm_up().await;
    let (own, bot_tone, other) = tones(target_is_caller);
    // A second warrant on the same call, on the other party: its target side is the other wire.
    let (second_own, second_bot, second_other) = tones(!target_is_caller);
    let first = intercept(&rig, 1, target_is_caller).await;
    let second = intercept(&rig, 2, !target_is_caller).await;
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());

    // ---- before: the relay's mapping, each warrant sees both voices ------------------------------
    talk(&mut rig, &mut frame, 25, &mut log).await;
    for (delivery, own, other, who) in [
        (&first, own, other, "first warrant before the split"),
        (
            &second,
            second_own,
            second_other,
            "second warrant before the split",
        ),
    ] {
        let tapped = take(delivery);
        assert_hears(&pcm(&tapped.from_target), 8_000.0, own, who);
        assert_hears(&pcm(&tapped.to_target), 8_000.0, other, who);
    }

    // ---- attach: toward the target is now the bot -----------------------------------------------------
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );
    assert_eq!(rig.kind(), rig.held, "carried by the decoding actor");
    let mut everything_first: Vec<X3Packet> = Vec::new();
    talk(&mut rig, &mut frame, 15, &mut log).await;
    let _ = (take(&first), take(&second));
    let during = talk(&mut rig, &mut frame, 40, &mut log).await;
    let (tapped_first, tapped_second) = (take(&first), take(&second));
    assert_hears(
        &pcm(&tapped_first.to_target),
        8_000.0,
        bot_tone,
        "first warrant: what the target hears while split is the bot",
    );
    assert_hears(
        &pcm(&tapped_first.from_target),
        8_000.0,
        own,
        "first warrant: the target's own voice while split",
    );
    assert_the_wire_was_delivered(
        heard_by(&during, target_is_caller),
        &tapped_first,
        "first warrant, split",
    );
    assert_hears(
        &pcm(&tapped_second.to_target),
        8_000.0,
        second_bot,
        "second warrant: its target hears the bot on the other wire",
    );
    assert_hears(
        &pcm(&tapped_second.from_target),
        8_000.0,
        second_own,
        "second warrant: its target's own voice",
    );
    assert_the_wire_was_delivered(
        heard_by(&during, !target_is_caller),
        &tapped_second,
        "second warrant, split",
    );
    everything_first.extend(tapped_first.to_target);
    everything_first.extend(tapped_first.from_target);

    // ---- the bot hangs up: the call stays isolated, the wire carries silence --------------------------
    bot.control.lock().expect("control").close = true;
    wait_for("the end event", || {
        events.try_iter().any(|event| {
            matches!(&event, Event::WsSplitEnded(ended) if ended.reason == siphon_rtp_proto::WsSplitEndReason::WsClosed)
        })
    })
    .await;
    talk(&mut rig, &mut frame, 8, &mut log).await;
    let _ = (take(&first), take(&second));
    let quiet = talk(&mut rig, &mut frame, 30, &mut log).await;
    let tapped = take(&first);
    assert_silent_audio(
        &pcm(&tapped.to_target),
        8_000.0,
        "after the bot left, the wire to the target carries silence and none of the other party",
    );
    assert_hears(
        &pcm(&tapped.from_target),
        8_000.0,
        own,
        "after the bot left, the target's own voice is still delivered",
    );
    assert_the_wire_was_delivered(heard_by(&quiet, target_is_caller), &tapped, "ended split");
    let _ = take(&second);

    // ---- detach: the other party's voice is the target's wire again, once ------------------------------
    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "detach: {detached:?}"
    );
    assert_eq!(
        rig.kind(),
        if rig.original == PipelineKind::Passthrough {
            PipelineKind::Media
        } else {
            rig.original
        }
    );
    let _ = (take(&first), take(&second));
    talk(&mut rig, &mut frame, 12, &mut log).await;
    let _ = (take(&first), take(&second));
    const FRAMES: usize = 30;
    talk(&mut rig, &mut frame, FRAMES, &mut log).await;
    let tapped = take(&first);
    assert_hears(
        &pcm(&tapped.to_target),
        8_000.0,
        other,
        "after the detach the target hears, and the warrant is given, the other party",
    );
    assert_hears(
        &pcm(&tapped.from_target),
        8_000.0,
        own,
        "after the detach the target's own voice",
    );
    for (name, count) in [
        ("to", tapped.to_target.len()),
        ("from", tapped.from_target.len()),
    ] {
        assert!(
            (FRAMES - 3..=FRAMES + 3).contains(&count),
            "once per packet after the detach, no copy from the egress: {count} {name} the target"
        );
    }
    let refs: Vec<&X3Packet> = tapped.to_target.iter().chain(&tapped.from_target).collect();
    assert_no_duplicates(&refs, "after the detach");
    let tapped = take(&second);
    assert_hears(
        &pcm(&tapped.to_target),
        8_000.0,
        second_other,
        "second warrant after the detach",
    );
    assert_hears(
        &pcm(&tapped.from_target),
        8_000.0,
        second_own,
        "second warrant, own voice after the detach",
    );
    assert_eq!(
        log.0.rejected + log.1.rejected,
        0,
        "every datagram decrypts"
    );
    let _ = everything_first;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_call_x3_follows_the_wire_when_the_target_is_the_offerer() {
    assert_x3_through_the_split_cycle(plain_rig().await, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_call_x3_follows_the_wire_when_the_target_is_the_answerer() {
    assert_x3_through_the_split_cycle(plain_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_call_x3_follows_the_wire_when_the_target_is_the_offerer() {
    assert_x3_through_the_split_cycle(srtp_rig().await, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_call_x3_follows_the_wire_when_the_target_is_the_answerer() {
    assert_x3_through_the_split_cycle(srtp_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_offerer_call_x3_follows_the_wire_for_both_targets() {
    assert_x3_through_the_split_cycle(srtp_offerer_rig().await, true).await;
    assert_x3_through_the_split_cycle(srtp_offerer_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transcrypt_call_x3_follows_the_wire_for_both_targets() {
    assert_x3_through_the_split_cycle(srtp_transcrypt_rig().await, true).await;
    assert_x3_through_the_split_cycle(srtp_transcrypt_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_call_x3_follows_the_wire_when_the_target_is_the_offerer() {
    assert_x3_through_the_split_cycle(dtls_rig().await, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_call_x3_follows_the_wire_when_the_target_is_the_answerer() {
    assert_x3_through_the_split_cycle(dtls_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_ice_call_x3_follows_the_wire_for_both_targets() {
    assert_x3_through_the_split_cycle(dtls_ice_rig().await, true).await;
    assert_x3_through_the_split_cycle(dtls_ice_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_offerer_call_x3_follows_the_wire_for_both_targets() {
    assert_x3_through_the_split_cycle(dtls_offerer_rig().await, true).await;
    assert_x3_through_the_split_cycle(dtls_offerer_rig().await, false).await;
}

// ---- the interception comes after the split, goes before the detach, survives a re-offer -------------

/// What the target's warrant sees now, over `frames` of both parties talking: the bot to the target
/// and the target's own voice, and nothing of the other party.
async fn assert_split_view(
    rig: &mut Rig,
    frame: &mut usize,
    log: &mut (Heard, Heard),
    delivery: &X3Delivery,
    target_is_caller: bool,
    who: &str,
) {
    talk(rig, frame, 12, log).await;
    let _ = take(delivery);
    let heard = talk(rig, frame, 40, log).await;
    let tapped = take(delivery);
    let (own, bot_tone, _) = tones(target_is_caller);
    assert_hears(&pcm(&tapped.to_target), 8_000.0, bot_tone, who);
    assert_hears(&pcm(&tapped.from_target), 8_000.0, own, who);
    assert_the_wire_was_delivered(heard_by(&heard, target_is_caller), &tapped, who);
}

async fn assert_x3_attached_while_split(mut rig: Rig, target_is_caller: bool) {
    rig.warm_up().await;
    let bot = bot().await;
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    talk(&mut rig, &mut frame, 15, &mut log).await;

    // The warrant arrives on a call that is already split: not refused, and it delivers what is on the wire.
    let delivery = intercept(&rig, 3, target_is_caller).await;
    assert_eq!(
        rig.kind(),
        rig.held,
        "the interception does not move a split call"
    );
    assert!(rig.engine.media.is_split_marked(rig.call_id));
    assert_split_view(
        &mut rig,
        &mut frame,
        &mut log,
        &delivery,
        target_is_caller,
        "attached while split",
    )
    .await;

    // Another warrant joins; the first keeps delivering the same stream.
    let later = intercept(&rig, 4, target_is_caller).await;
    assert_split_view(
        &mut rig,
        &mut frame,
        &mut log,
        &later,
        target_is_caller,
        "second, while split",
    )
    .await;
    assert_split_view(
        &mut rig,
        &mut frame,
        &mut log,
        &delivery,
        target_is_caller,
        "first, after a second joined",
    )
    .await;

    // The first warrant is withdrawn while split: it ends, the other carries on, the call stays split.
    let events = rig.engine.register_client(CLIENT);
    let detached = rig
        .engine
        .handle(
            CLIENT,
            Command::DetachX3 {
                call_id: rig.call_id.into(),
                from_tag: OWNER_TAG.into(),
                xid: Some(Xid::from_bytes([3; 16])),
                delivery: None,
                correlation_id: None,
            },
        )
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    let ended: Vec<_> = events
        .try_iter()
        .filter_map(|event| match event {
            Event::X3Ended { xid, reason, .. } => Some((xid, reason)),
            _ => None,
        })
        .collect();
    assert_eq!(
        ended,
        vec![(Some(Xid::from_bytes([3; 16])), X3EndReason::Detached)]
    );
    assert_eq!(
        rig.kind(),
        rig.held,
        "the withdrawn warrant did not release the split's hold"
    );
    assert!(rig.engine.media.is_split_marked(rig.call_id));
    let _ = take(&delivery);
    assert_split_view(
        &mut rig,
        &mut frame,
        &mut log,
        &later,
        target_is_caller,
        "after the other warrant went",
    )
    .await;
    assert!(
        take(&delivery).to_target.is_empty(),
        "a withdrawn warrant is given nothing more"
    );
    let (heard_a, heard_b) = &log;
    assert_hears(
        &decode(heard_a)[decode(heard_a).len() - 1_600..],
        8_000.0,
        TO_A_TONE,
        "A still hears the bot",
    );
    assert_hears(
        &decode(heard_b)[decode(heard_b).len() - 1_600..],
        8_000.0,
        TO_B_TONE,
        "B still hears the bot",
    );
}

/// `detach_x3` answers only once the media actor has applied the removal of the withdrawn warrant's
/// taps. The actor's mailbox is held by the test, so nothing reaches it until released: a reply that
/// does not wait for the actor (the old behaviour) comes back while the actor still taps for the
/// warrant, and everything the actor handles from then on is content captured after the withdrawal.
async fn assert_detach_waits_for_the_actor(kept: Option<u8>) {
    let mut rig = plain_rig().await;
    rig.warm_up().await;
    let _withdrawn = intercept(&rig, 3, true).await;
    if let Some(byte) = kept {
        let _kept = intercept(&rig, byte, true).await;
    }
    let (real, unread) = rig
        .engine
        .media
        .wedge_mailbox_unbounded(rig.call_id)
        .expect("an actor");
    let detach = rig.engine.handle(
        CLIENT,
        Command::DetachX3 {
            call_id: rig.call_id.into(),
            from_tag: OWNER_TAG.into(),
            xid: Some(Xid::from_bytes([3; 16])),
            delivery: None,
            correlation_id: None,
        },
    );
    tokio::pin!(detach);
    let early = tokio::time::timeout(Duration::from_millis(300), &mut detach).await;
    assert!(
        early.is_err(),
        "detach_x3 answered while the actor had not applied the removal: {early:?}"
    );
    // What the handler sent the actor, in order, is released to it now.
    let mut released = 0;
    let mut removal_seen = false;
    for input in unread.try_iter() {
        if let MediaInput::Control(control) = &input {
            removal_seen |= matches!(control, MediaControl::StartX3(_) | MediaControl::StopX3);
        }
        real.send_async(input).await.expect("the actor is alive");
        released += 1;
    }
    assert!(
        released > 0 && removal_seen,
        "the removal reached the mailbox"
    );
    rig.engine.media.unwedge_mailbox(rig.call_id, real);
    let detached = tokio::time::timeout(Duration::from_secs(5), &mut detach)
        .await
        .expect("answered once the actor applied it");
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_one_of_two_warrants_waits_for_the_actor_to_drop_its_taps() {
    assert_detach_waits_for_the_actor(Some(4)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_the_last_warrant_waits_for_the_actor_to_drop_its_taps() {
    assert_detach_waits_for_the_actor(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_attached_to_a_split_plain_call_is_not_refused_and_delivers_the_wire() {
    assert_x3_attached_while_split(plain_rig().await, true).await;
    assert_x3_attached_while_split(plain_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_attached_to_a_split_sdes_call_is_not_refused_and_delivers_the_wire() {
    assert_x3_attached_while_split(srtp_rig().await, true).await;
    assert_x3_attached_while_split(srtp_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_attached_to_a_split_dtls_call_is_not_refused_and_delivers_the_wire() {
    assert_x3_attached_while_split(dtls_rig().await, true).await;
    assert_x3_attached_while_split(dtls_rig().await, false).await;
}

/// A re-offer answered while split: the warrant's taps are carried onto what carries the call now and
/// it goes on delivering the bot to the target and the target's own voice, never the other party.
async fn assert_x3_through_a_reoffer_while_split(mut rig: Rig, target_is_caller: bool) {
    rig.warm_up().await;
    let delivery = intercept(&rig, 5, target_is_caller).await;
    let bot = bot().await;
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    assert_split_view(
        &mut rig,
        &mut frame,
        &mut log,
        &delivery,
        target_is_caller,
        "before the re-offer",
    )
    .await;

    rig.reoffer().await;
    assert_eq!(rig.kind(), rig.held);
    assert_split_view(
        &mut rig,
        &mut frame,
        &mut log,
        &delivery,
        target_is_caller,
        "after the re-offer",
    )
    .await;

    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    talk(&mut rig, &mut frame, 12, &mut log).await;
    let _ = take(&delivery);
    talk(&mut rig, &mut frame, 30, &mut log).await;
    let tapped = take(&delivery);
    let (own, _, other) = tones(target_is_caller);
    assert_hears(
        &pcm(&tapped.to_target),
        8_000.0,
        other,
        "after the detach: the other party",
    );
    assert_hears(
        &pcm(&tapped.from_target),
        8_000.0,
        own,
        "after the detach: the target",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_survives_a_reoffer_of_a_split_sdes_call() {
    assert_x3_through_a_reoffer_while_split(srtp_rig().await, true).await;
    assert_x3_through_a_reoffer_while_split(srtp_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_survives_a_reoffer_of_a_split_dtls_call() {
    assert_x3_through_a_reoffer_while_split(dtls_rig().await, true).await;
    assert_x3_through_a_reoffer_while_split(dtls_rig().await, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_survives_a_reoffer_of_a_split_plain_call() {
    for target_is_caller in [true, false] {
        let mut rig = plain_rig().await;
        let addr_a = rig.a.socket.local_addr().expect("a");
        let addr_b = rig.b.socket.local_addr().expect("b");
        rig.reoffer = Some(Reoffer {
            sdp: sdp_for(addr_a, true),
            profile: ProfileFlags::default(),
            answer: sdp_for(addr_b, true),
            far_addr: addr_b,
        });
        assert_x3_through_a_reoffer_while_split(rig, target_is_caller).await;
    }
}

// ---- delete, restore --------------------------------------------------------------------------------

/// Deleting a split, intercepted call ends the delivery as an unsplit one does: one `x3_ended`, the
/// call's end, and the split's own events as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_split_intercepted_call_ends_the_delivery_once() {
    for rig in [plain_rig().await, srtp_rig().await, dtls_rig().await] {
        let mut rig = rig;
        let events = rig.engine.register_client(CLIENT);
        rig.warm_up().await;
        let bot = bot().await;
        let delivery = intercept(&rig, 6, true).await;
        let attached = rig
            .engine
            .handle(CLIENT, attach_command(&rig, &bot, None))
            .await;
        assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
        let mut log = (Heard::default(), Heard::default());
        talk(&mut rig, &mut 0, 12, &mut log).await;
        assert!(!take(&delivery).to_target.is_empty());
        let deleted = rig
            .engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: rig.call_id.into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let ended: Vec<_> = events
            .try_iter()
            .filter_map(|event| match event {
                Event::X3Ended { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(
            ended,
            vec![X3EndReason::CallEnded],
            "once, for the call's end"
        );
        assert!(!rig.engine.x3_sessions.contains_key(rig.call_id));
        assert_eq!(rig.engine.ws_split_count(), 0);
    }
}

/// A checkpoint of a split call restores isolated; the warrant, which belongs to the engine that
/// took the checkpoint, is attached again on the restored call and sees what the wire carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_split_call_is_intercepted_on_what_the_wire_carries() {
    for target_is_caller in [true, false] {
        let mut rig = plain_rig().await;
        let events = rig.engine.register_client(CLIENT);
        rig.warm_up().await;
        let bot = bot().await;
        let attached = rig
            .engine
            .handle(CLIENT, attach_command(&rig, &bot, None))
            .await;
        assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
        let mut frame = 0usize;
        let mut log = (Heard::default(), Heard::default());
        talk(&mut rig, &mut frame, 10, &mut log).await;
        let CmdResult::Checkpoint { snapshot } = rig
            .engine
            .handle(
                CLIENT,
                Command::Checkpoint {
                    call_id: rig.call_id.into(),
                    from_tag: "a".into(),
                },
            )
            .await
        else {
            panic!("a split call checkpoints");
        };
        rig.engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: rig.call_id.into(),
                    from_tag: "a".into(),
                    to_tag: None,
                },
            )
            .await;
        let restored = rig
            .engine
            .handle(CLIENT, Command::Restore { snapshot })
            .await;
        assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
        let _ = events.try_iter().count();
        let delivery = intercept(&rig, 7, target_is_caller).await;
        talk(&mut rig, &mut frame, 12, &mut log).await;
        let _ = take(&delivery);
        let heard = talk(&mut rig, &mut frame, 40, &mut log).await;
        let tapped = take(&delivery);
        let (own, _, _) = tones(target_is_caller);
        // The restored call is isolated and silent until detach: the wire carries silence and the
        // target's own voice is the only audio on the interception.
        assert_silent_audio(&pcm(&tapped.to_target), 8_000.0, "the restored wire");
        assert_hears(
            &pcm(&tapped.from_target),
            8_000.0,
            own,
            "the target's own voice",
        );
        assert_the_wire_was_delivered(heard_by(&heard, target_is_caller), &tapped, "restored");
    }
}
