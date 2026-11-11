//! A control command that asks a call's media actor or a room's actor for an answer must answer
//! itself even when that actor no longer serves its mailbox: it runs on the control connection
//! every call shares.

use super::*;

/// The bound a command may take here: the actor-reply timeout plus slack for a loaded runner.
const BOUNDED_COMMAND: Duration =
    Duration::from_secs(crate::mailbox::ACTOR_REPLY_TIMEOUT.as_secs() + 3);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn playback_verbs_answer_when_the_calls_media_actor_has_stopped_listening() {
    let (engine, _phone, _caller_target) = anchored_call("stuck-actor").await;
    let _unread = engine
        .media()
        .stall_mailbox("stuck-actor")
        .expect("a media call");
    let commands = [
        Command::StopMedia {
            call_id: "stuck-actor".into(),
            from_tag: "tag-a".into(),
            play_id: Some(1),
        },
        Command::SetPlayGain {
            call_id: "stuck-actor".into(),
            from_tag: "tag-a".into(),
            play_id: 1,
            gain_decibels: -6,
            to_tag: None,
        },
        Command::PlayDtmf {
            call_id: "stuck-actor".into(),
            from_tag: "tag-a".into(),
            code: "7".into(),
            duration_ms: Some(120),
            volume_dbm0: Some(-10),
            pause_ms: None,
            to_tag: None,
        },
    ];
    for command in commands {
        let verb = format!("{command:?}");
        let result = timeout(BOUNDED_COMMAND, engine.handle(CLIENT, command))
            .await
            .unwrap_or_else(|_| panic!("{verb} answers instead of waiting on the actor"));
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "an unanswered request is an error, not a hollow success: {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn room_playback_verbs_answer_when_the_room_actor_has_stopped_listening() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    seat_participant(&engine, "stuck-room", "alice", addr).await;
    let _unread = engine
        .conference()
        .stall_mailbox("stuck-room")
        .expect("a room");
    let commands = [
        Command::ConferenceStopPlay {
            conference_id: "stuck-room".into(),
            play_id: Some(1),
        },
        Command::ConferenceSetPlayGain {
            conference_id: "stuck-room".into(),
            play_id: 1,
            gain_decibels: -6,
        },
    ];
    for command in commands {
        let verb = format!("{command:?}");
        let result = timeout(BOUNDED_COMMAND, engine.handle(CLIENT, command))
            .await
            .unwrap_or_else(|_| panic!("{verb} answers instead of waiting on the room"));
        assert!(matches!(result, CmdResult::Error { .. }), "{result:?}");
    }
}
