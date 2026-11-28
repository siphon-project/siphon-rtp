#![cfg(test)]

//! The hand-over of a lawful interception across a re-answer of the same dialog. While the old call
//! is going away and the new one is not registered yet, the session stays in the map, marked: the
//! old call's teardown leaves it alone, and a `detach_x3` that lands in that window is recorded and
//! ends that delivery at once (delivery must not outlive a withdrawn warrant).
//!
//! The window is driven by hand here (the call removed, the hand-over begun) because the real one
//! is a few awaits wide and a test cannot land a command in it deterministically.

use super::*;
use siphon_rtp_proto::{X3EndReason, Xid};

const OWNER_TAG: &str = "tag-a";

pub(super) fn inject_session(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
) -> crate::x3::X3Delivery {
    inject_session_as(engine, call_id, Xid::default(), "mdf.example.net:8090")
}

/// A session of warrant `xid` delivering to `address`, added to the call's set.
fn inject_session_as(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    xid: Xid,
    address: &str,
) -> crate::x3::X3Delivery {
    let (factory, delivery) = crate::x3::x3_channel(8);
    let counters = factory.counters().clone();
    engine
        .x3_sessions
        .entry(call_id.to_string())
        .or_default()
        .push(crate::engine::intercept::X3Session {
            xid,
            delivery: address.to_string(),
            correlation_id: 1,
            from_tag: OWNER_TAG.to_string(),
            owner: CLIENT,
            bridged_endpoints: Vec::new(),
            factory,
            target_is_caller: true,
            counters,
            transport: tokio::spawn(std::future::pending::<()>()),
            ended: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            joined_endpoint: None,
            handing_over: Default::default(),
        });
    delivery
}

fn ended(events: &flume::Receiver<Event>) -> Vec<X3EndReason> {
    events
        .try_iter()
        .filter_map(|event| match event {
            Event::X3Ended { reason, .. } => Some(reason),
            _ => None,
        })
        .collect()
}

fn detach(call_id: &str) -> Command {
    Command::DetachX3 {
        call_id: call_id.into(),
        from_tag: OWNER_TAG.into(),
        xid: None,
        delivery: None,
        correlation_id: None,
    }
}

#[tokio::test]
async fn a_detach_in_the_hand_over_window_ends_the_delivery_at_once() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let _delivery = inject_session(&engine, "handover");

    assert!(engine.begin_x3_hand_over(CLIENT, "handover", OWNER_TAG));
    // The old call's teardown must not end what is being handed over.
    engine.stop_x3("handover", X3EndReason::CallEnded).await;
    assert!(engine.x3_sessions.contains_key("handover"));
    assert!(ended(&events).is_empty());

    // The warrant is withdrawn in the window: it ends before the reply, once.
    assert!(matches!(
        engine.handle(CLIENT, detach("handover")).await,
        CmdResult::Ok { .. }
    ));
    assert!(!engine.x3_sessions.contains_key("handover"));
    assert_eq!(ended(&events), vec![X3EndReason::Detached], "exactly one");

    engine.settle_x3_hand_over("handover").await;
    assert!(!engine.x3_sessions.contains_key("handover"));
    assert!(ended(&events).is_empty(), "settling reports nothing again");
}

#[tokio::test]
async fn a_hand_over_with_no_detach_keeps_the_session_until_the_call_ends() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let _delivery = inject_session(&engine, "kept");

    assert!(engine.begin_x3_hand_over(CLIENT, "kept", OWNER_TAG));
    engine.settle_x3_hand_over("kept").await;
    assert!(engine.x3_sessions.contains_key("kept"));
    assert!(ended(&events).is_empty());

    engine.stop_x3("kept", X3EndReason::CallEnded).await;
    assert_eq!(ended(&events), vec![X3EndReason::CallEnded]);
}

#[tokio::test]
async fn a_failed_re_answer_ends_the_interception_with_the_call() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let _delivery = inject_session(&engine, "failed");
    assert!(engine.begin_x3_hand_over(CLIENT, "failed", OWNER_TAG));
    engine.abandon_x3_hand_over("failed").await;
    assert_eq!(ended(&events), vec![X3EndReason::CallEnded]);

    // ... and Detached when the warrant was withdrawn meanwhile.
    let _delivery = inject_session(&engine, "failed-detached");
    assert!(engine.begin_x3_hand_over(CLIENT, "failed-detached", OWNER_TAG));
    engine.handle(CLIENT, detach("failed-detached")).await;
    engine.abandon_x3_hand_over("failed-detached").await;
    assert_eq!(ended(&events), vec![X3EndReason::Detached]);
}

#[tokio::test]
async fn another_dialog_or_owner_is_not_a_hand_over() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _events = engine.register_client(CLIENT);
    let _delivery = inject_session(&engine, "other");
    assert!(!engine.begin_x3_hand_over(CLIENT, "other", "another-tag"));
    assert!(!engine.begin_x3_hand_over(ClientId(99), "other", OWNER_TAG));
}

fn xid_of(byte: u8) -> Xid {
    Xid::from_bytes([byte; 16])
}

/// The (xid, reason) of every `x3_ended` so far.
fn ended_by_xid(events: &flume::Receiver<Event>) -> Vec<(Xid, X3EndReason)> {
    let mut ended: Vec<_> = events
        .try_iter()
        .filter_map(|event| match event {
            Event::X3Ended { xid, reason, .. } => Some((xid.expect("named"), reason)),
            _ => None,
        })
        .collect();
    ended.sort_by_key(|(xid, _)| *xid.as_bytes());
    ended
}

fn detach_xid(call_id: &str, xid: Xid) -> Command {
    Command::DetachX3 {
        call_id: call_id.into(),
        from_tag: OWNER_TAG.into(),
        xid: Some(xid),
        delivery: None,
        correlation_id: None,
    }
}

#[tokio::test]
async fn a_detach_of_one_warrant_in_the_hand_over_window_ends_that_warrant_only() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    // A real call under the sessions: the survivors' taps are installed on it again.
    let (_phone, address) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "two".into(),
                from_tag: OWNER_TAG.into(),
                sdp: sdp_for(address, true),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    let _one = inject_session_as(&engine, "two", xid_of(1), "mdf-one.example.net:8090");
    let _two = inject_session_as(&engine, "two", xid_of(2), "mdf-two.example.net:8090");
    assert!(engine.begin_x3_hand_over(CLIENT, "two", OWNER_TAG));

    // The old call's teardown leaves both alone.
    engine.stop_x3("two", X3EndReason::CallEnded).await;
    assert!(ended_by_xid(&events).is_empty());
    assert!(matches!(
        engine.handle(CLIENT, detach_xid("two", xid_of(1))).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        ended_by_xid(&events),
        vec![(xid_of(1), X3EndReason::Detached)],
        "only the withdrawn warrant ends, once, before the reply"
    );

    engine.settle_x3_hand_over("two").await;
    assert!(
        ended_by_xid(&events).is_empty(),
        "settling ends nothing more"
    );
    assert_eq!(
        engine.x3_sessions.get("two").map(|sessions| sessions.len()),
        Some(1),
        "the other delivery is handed over"
    );
    engine.stop_x3("two", X3EndReason::CallEnded).await;
    assert_eq!(
        ended_by_xid(&events),
        vec![(xid_of(2), X3EndReason::CallEnded)]
    );
}

#[tokio::test]
async fn a_failed_re_answer_ends_each_delivery_with_its_own_reason() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    // A real call under the sessions: the withdrawal re-installs the survivor's taps on it.
    let (_phone, address) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "abandon".into(),
                from_tag: OWNER_TAG.into(),
                sdp: sdp_for(address, true),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    let _one = inject_session_as(&engine, "abandon", xid_of(1), "mdf-one.example.net:8090");
    let _two = inject_session_as(&engine, "abandon", xid_of(2), "mdf-two.example.net:8090");
    assert!(engine.begin_x3_hand_over(CLIENT, "abandon", OWNER_TAG));
    engine
        .handle(CLIENT, detach_xid("abandon", xid_of(2)))
        .await;
    engine.abandon_x3_hand_over("abandon").await;
    assert_eq!(
        ended_by_xid(&events),
        vec![
            (xid_of(1), X3EndReason::CallEnded),
            (xid_of(2), X3EndReason::Detached)
        ]
    );
    assert!(!engine.x3_sessions.contains_key("abandon"));
}

#[tokio::test]
async fn ending_a_call_ends_every_delivery_with_one_event_each() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let _one = inject_session_as(&engine, "end", xid_of(1), "mdf-one.example.net:8090");
    let _two = inject_session_as(&engine, "end", xid_of(1), "mdf-two.example.net:8090");
    let _three = inject_session_as(&engine, "end", xid_of(3), "mdf-one.example.net:8090");
    engine.stop_x3("end", X3EndReason::CallEnded).await;
    assert_eq!(
        ended_by_xid(&events),
        vec![
            (xid_of(1), X3EndReason::CallEnded),
            (xid_of(1), X3EndReason::CallEnded),
            (xid_of(3), X3EndReason::CallEnded)
        ]
    );
    assert!(!engine.x3_sessions.contains_key("end"));
    // Nothing left: a second stop is silent.
    engine.stop_x3("end", X3EndReason::CallEnded).await;
    assert!(ended_by_xid(&events).is_empty());
}

#[tokio::test]
async fn survivors_that_cannot_be_re_tapped_end_loudly_instead_of_staying_deaf() {
    // No call stands under the sessions, so the survivors' taps cannot be installed again after
    // one delivery ends: they end `transport_error` rather than stay attached and deliver nothing.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let _one = inject_session_as(&engine, "deaf", xid_of(1), "mdf-one.example.net:8090");
    let _two = inject_session_as(&engine, "deaf", xid_of(2), "mdf-two.example.net:8090");
    engine
        .end_x3_where(
            "deaf",
            |session| session.xid == xid_of(1),
            |_| X3EndReason::Detached,
        )
        .await;
    assert_eq!(
        ended_by_xid(&events),
        vec![
            (xid_of(1), X3EndReason::Detached),
            (xid_of(2), X3EndReason::TransportError)
        ]
    );
    assert!(!engine.x3_sessions.contains_key("deaf"));
}

/// The real gap of a re-answer: the old call is gone from the table (so nothing can re-tap anyone on
/// it), its actor still runs, and a warrant is withdrawn. Only that warrant ends, before the reply;
/// the other is carried to the replacement pipeline and keeps delivering, the withdrawn one gets
/// nothing from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detach_in_the_real_gap_ends_only_the_withdrawn_warrant_and_the_other_is_carried_on() {
    const CALL: &str = "gap";
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let (_phone, address) = phone().await;
    let answer = || Command::AnswerLocal {
        call_id: CALL.into(),
        from_tag: OWNER_TAG.into(),
        sdp: sdp_for(address, true),
        profile: Default::default(),
    };
    let answered = engine.handle(CLIENT, answer()).await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    let withdrawn = inject_session_as(&engine, CALL, xid_of(1), "mdf-one.example.net:8090");
    let kept = inject_session_as(&engine, CALL, xid_of(2), "mdf-two.example.net:8090");
    engine.carry_x3_across_answer(CALL).await;

    // What `replace_local_call` does before it awaits the old call's teardown.
    let (_, previous) = engine.calls.remove(CALL).expect("the call stands");
    assert!(engine.begin_x3_hand_over(CLIENT, CALL, OWNER_TAG));
    let detached = engine.handle(CLIENT, detach_xid(CALL, xid_of(1))).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        ended_by_xid(&events),
        vec![(xid_of(1), X3EndReason::Detached)],
        "the withdrawn warrant ends once, the other is not touched"
    );
    assert_eq!(
        engine.x3_sessions.get(CALL).map(|sessions| sessions
            .iter()
            .map(|session| session.xid)
            .collect::<Vec<_>>()),
        Some(vec![xid_of(2)])
    );

    engine.finish_call(CALL, &previous, "replaced").await;
    let answered = engine.handle(CLIENT, answer()).await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    assert!(ended_by_xid(&events).is_empty(), "nothing else ended");

    let near = engine
        .calls
        .get(CALL)
        .map(|call| call.near.rtp.id)
        .expect("the replacement stands");
    let _ = (
        withdrawn.packets.try_iter().count(),
        kept.packets.try_iter().count(),
    );
    let packet = g711_rtp(0, 1, 0x00C0_FFEE, 0x55);
    engine.media().dispatch(siphon_rtp_datapath::RxPacket {
        endpoint: near,
        source: address,
        arrival: 0,
        data: bytes::Bytes::from(packet.clone()),
    });
    let delivered = tokio::time::timeout(Duration::from_secs(5), kept.packets.recv_async())
        .await
        .expect("the carried warrant keeps delivering")
        .expect("open");
    assert_eq!(delivered.payload, packet);
    assert!(
        withdrawn.packets.try_recv().is_err(),
        "the withdrawn warrant is given nothing by the replacement"
    );
    assert!(ended_by_xid(&events).is_empty(), "no second x3_ended");
}

/// The withdrawn warrant was the only one: the replacement carries nothing, and what a snapshot taken
/// before the withdrawal pre-tapped it with is taken off again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_that_empties_the_table_leaves_no_stale_tap_on_the_new_pipeline() {
    const CALL: &str = "stale";
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _events = engine.register_client(CLIENT);
    let (_phone, address) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: CALL.into(),
                from_tag: OWNER_TAG.into(),
                sdp: sdp_for(address, true),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    let stale = inject_session_as(&engine, CALL, xid_of(1), "mdf-one.example.net:8090");
    // The new pipeline was pre-tapped from a snapshot, then the warrant went from the table.
    engine.carry_x3_across_answer(CALL).await;
    engine.x3_sessions.remove(CALL);
    engine.carry_x3_across_answer(CALL).await;

    let near = engine
        .calls
        .get(CALL)
        .map(|call| call.near.rtp.id)
        .expect("the call stands");
    let _ = stale.packets.try_iter().count();
    engine.media().dispatch(siphon_rtp_datapath::RxPacket {
        endpoint: near,
        source: address,
        arrival: 0,
        data: bytes::Bytes::from(g711_rtp(0, 1, 0x00C0_FFEE, 0x55)),
    });
    // The actor handles this control after the packet (one mailbox, in order): by then the packet
    // was either tapped or not.
    engine.stop_actor_x3(CALL).await;
    assert!(
        stale.packets.try_recv().is_err(),
        "a warrant no longer in the table was still tapped on the pipeline"
    );
}
