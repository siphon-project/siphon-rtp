#![cfg(test)]

//! The hand-over of a lawful interception across a re-answer of the same dialog. While the old call
//! is going away and the new one is not registered yet, the session stays in the map, marked: the
//! old call's teardown leaves it alone, and a `detach_x3` that lands in that window is recorded and
//! honoured at the end of it, never lost (delivery must not outlive a withdrawn warrant).
//!
//! The window is driven by hand here (the call removed, the hand-over begun) because the real one
//! is a few awaits wide and a test cannot land a command in it deterministically.

use super::*;
use siphon_rtp_proto::X3EndReason;

const OWNER_TAG: &str = "tag-a";

fn inject_session(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> crate::x3::X3Delivery {
    let (factory, delivery) = crate::x3::x3_channel(8);
    let counters = factory.counters().clone();
    engine.x3_sessions.insert(
        call_id.to_string(),
        crate::engine::intercept::X3Session {
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
            detach_requested: Default::default(),
        },
    );
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
    }
}

#[tokio::test]
async fn a_detach_in_the_hand_over_window_is_honoured_when_it_ends() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let _delivery = inject_session(&engine, "handover");

    assert!(engine.begin_x3_hand_over(CLIENT, "handover", OWNER_TAG));
    // The old call's teardown must not end what is being handed over.
    engine.stop_x3("handover", X3EndReason::CallEnded).await;
    assert!(engine.x3_sessions.contains_key("handover"));
    assert!(ended(&events).is_empty());

    // The warrant is withdrawn in the window: accepted, and not lost.
    assert!(matches!(
        engine.handle(CLIENT, detach("handover")).await,
        CmdResult::Ok { .. }
    ));
    assert!(
        engine.x3_sessions.contains_key("handover"),
        "still handing over"
    );
    assert!(
        ended(&events).is_empty(),
        "nothing ends before the hand-over does"
    );

    engine.settle_x3_hand_over("handover").await;
    assert!(!engine.x3_sessions.contains_key("handover"));
    assert_eq!(ended(&events), vec![X3EndReason::Detached], "exactly one");
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
