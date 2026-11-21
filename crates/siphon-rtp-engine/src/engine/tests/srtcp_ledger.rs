//! The SRTCP send-index ledger through the engine (RFC 7714 §8, §9.4): the index is the key's, so a
//! seat that leaves and rejoins carries on, and a standby seeded from a checkpoint starts a margin
//! past the primary. The wire is read from what a phone receives.

use super::forward_preserve::{engine_with_dispatcher, expect, keyed_seat, media_key, ROOM};
use super::*;
use siphon_rtp_proto::{ForwardMedia, RtcpAppStream};

const SSRC: u32 = 0xC0FF_EE00;

/// Send the controller's RTCP APP to seat `tag` on its audio stream under a fixed SSRC, and read the
/// SRTCP index of the datagram its phone receives.
async fn app_index(engine: &Engine<UdpLoopbackDatapath>, phone: &UdpSocket, tag: &str) -> u32 {
    let result = engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: None,
                conference_id: Some(ROOM.into()),
                from_tag: Some(tag.into()),
                except_from_tags: Vec::new(),
                stream: RtcpAppStream::Audio,
                ssrc: Some(SSRC),
                name: "MCPT".into(),
                subtype: 1,
                payload: vec![0, 1, 2, 3],
            },
        )
        .await;
    assert_eq!(result, ok_empty(), "{result:?}");
    let datagram = expect(phone, 1).await.remove(0);
    assert_eq!(u32::from_be_bytes(datagram[4..8].try_into().unwrap()), SSRC);
    let at = datagram.len() - 8;
    u32::from_be_bytes(datagram[at..at + 4].try_into().unwrap()) & 0x7FFF_FFFF
}

async fn checkpoint(engine: &Engine<UdpLoopbackDatapath>) -> String {
    match engine.handle(CLIENT, Command::CheckpointSrtcpIndices).await {
        CmdResult::SrtcpIndices { snapshot } => snapshot,
        other => panic!("expected the ledger blob, got {other:?}"),
    }
}

/// The generation token of a checkpoint blob.
fn generation_of(blob: &str) -> String {
    serde_json::from_str::<serde_json::Value>(blob).unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_string()
}

/// What a controller does on a node that restored a ledger before re-seating anyone: checkpoint, store
/// the blob, confirm it. Only then does the node have a send window.
async fn open_window(engine: &Engine<UdpLoopbackDatapath>) {
    let blob = checkpoint(engine).await;
    let confirmed = engine
        .handle(
            CLIENT,
            Command::ConfirmSrtcpIndices {
                generation: generation_of(&blob),
            },
        )
        .await;
    assert_eq!(confirmed, ok_empty());
}

async fn leave(engine: &Engine<UdpLoopbackDatapath>, tag: &str) {
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardLeave {
                conference_id: ROOM.into(),
                from_tag: tag.into(),
            },
        )
        .await;
    assert_eq!(result, ok_empty());
}

#[tokio::test]
async fn a_seat_that_leaves_and_rejoins_with_its_key_carries_on_from_its_last_index() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    let mut indices = Vec::new();
    for _ in 0..3 {
        indices.push(app_index(&engine, &phone, "a").await);
    }
    assert_eq!(indices, vec![0, 1, 2]);
    leave(&engine, "a").await;
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    assert_eq!(app_index(&engine, &phone, "a").await, 3);
}

#[tokio::test]
async fn a_standby_seeded_from_the_checkpoint_starts_a_margin_past_the_primary() {
    let primary = engine_with_dispatcher();
    let _events = primary.register_client(CLIENT);
    let (phone, _) = keyed_seat(&primary, "a", vec![media_key(1)]).await;
    for _ in 0..3 {
        app_index(&primary, &phone, "a").await;
    }
    let blob = checkpoint(&primary).await;
    assert!(
        !blob.contains("3131313131313131"),
        "the blob names the key by an HMAC and carries none of its bytes: {blob}"
    );

    let standby = engine_with_dispatcher();
    let _events = standby.register_client(CLIENT);
    let restored = standby
        .handle(
            CLIENT,
            Command::RestoreSrtcpIndices {
                snapshot: blob.clone(),
            },
        )
        .await;
    assert_eq!(restored, ok_empty());
    // The controller rebuilds the room on the standby with the same key. The standby has restored a
    // ledger and has no send window yet: its seals are refused, loudly.
    let (phone, _) = keyed_seat(&standby, "a", vec![media_key(1)]).await;
    let refused = send_app(&standby, "a").await;
    assert!(
        matches!(&refused, CmdResult::Error { reason } if reason.contains("SRTCP protect failed")),
        "{refused:?}"
    );
    // It checkpoints, the controller stores the blob and confirms it: now it has a window.
    open_window(&standby).await;
    assert_eq!(app_index(&standby, &phone, "a").await, 3 + (1 << 16));
    // Restoring again, or an older checkpoint, never lowers it.
    standby
        .handle(CLIENT, Command::RestoreSrtcpIndices { snapshot: blob })
        .await;
    assert_eq!(
        app_index(&standby, &phone, "a").await,
        3 + (1 << 16) + 1,
        "the counter went on from where it was: a second import raised it to the same floor"
    );
}

#[tokio::test]
async fn a_standby_with_no_restored_ledger_starts_at_zero_so_the_controller_must_rekey() {
    // The documented hazard, pinned: nothing tells a fresh engine what the primary sent.
    let standby = engine_with_dispatcher();
    let _events = standby.register_client(CLIENT);
    let (phone, _) = keyed_seat(&standby, "a", vec![media_key(1)]).await;
    assert_eq!(app_index(&standby, &phone, "a").await, 0);
}

#[tokio::test]
async fn a_blob_that_is_not_the_ledger_is_refused_and_applies_nothing() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    for bad in ["", "not json", r#"{"version":9,"entries":[]}"#] {
        let result = engine
            .handle(
                CLIENT,
                Command::RestoreSrtcpIndices {
                    snapshot: bad.into(),
                },
            )
            .await;
        assert!(
            matches!(&result, CmdResult::Error { reason } if reason.contains("restore_srtcp_indices")),
            "{bad}: {result:?}"
        );
    }
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    assert_eq!(app_index(&engine, &phone, "a").await, 0);
}

#[tokio::test]
async fn node_info_advertises_srtcp_index_ledger() {
    let engine = engine_with_dispatcher();
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(node
        .features
        .iter()
        .any(|name| name == "srtcp_index_ledger"));
    let _ = ForwardMedia::Preserve;
}

/// Send the APP and return the room's reply, without reading the phone.
async fn send_app(engine: &Engine<UdpLoopbackDatapath>, tag: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: None,
                conference_id: Some(ROOM.into()),
                from_tag: Some(tag.into()),
                except_from_tags: Vec::new(),
                stream: RtcpAppStream::Audio,
                ssrc: Some(SSRC),
                name: "MCPT".into(),
                subtype: 1,
                payload: vec![0, 1, 2, 3],
            },
        )
        .await
}

#[tokio::test]
async fn a_key_that_was_installed_and_unused_at_the_checkpoint_starts_a_margin_past_zero_on_the_standby(
) {
    let primary = engine_with_dispatcher();
    let _events = primary.register_client(CLIENT);
    let (phone, _) = keyed_seat(&primary, "a", vec![media_key(1)]).await;
    // Nothing has been sent under the key when the controller checkpoints.
    let blob = checkpoint(&primary).await;
    // The key then sends before the primary fails.
    assert_eq!(app_index(&primary, &phone, "a").await, 0);

    let standby = engine_with_dispatcher();
    let _events = standby.register_client(CLIENT);
    standby
        .handle(CLIENT, Command::RestoreSrtcpIndices { snapshot: blob })
        .await;
    let (phone, _) = keyed_seat(&standby, "a", vec![media_key(1)]).await;
    open_window(&standby).await;
    assert_eq!(
        app_index(&standby, &phone, "a").await,
        1 << 16,
        "0 + margin, not 0"
    );
}

#[tokio::test]
async fn a_key_at_half_its_lease_raises_checkpoint_due_once_and_at_the_lease_the_seal_is_refused() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    // A small window so the test needs few datagrams; the verb uses the 65536 margin.
    let ledger = engine.conference().srtcp_ledger().clone();
    let _ = ledger.checkpoint(10, Some(CLIENT.0));
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    for expected in 0..4 {
        assert_eq!(app_index(&engine, &phone, "a").await, expected);
    }
    engine.sweep_srtcp_ledger();
    assert!(events
        .try_iter()
        .all(|event| !matches!(event, Event::SrtcpCheckpointDue { .. })));
    assert_eq!(app_index(&engine, &phone, "a").await, 4);
    engine.sweep_srtcp_ledger();
    let due: Vec<_> = events
        .try_iter()
        .filter(|event| matches!(event, Event::SrtcpCheckpointDue { entries: 1 }))
        .collect();
    assert_eq!(
        due.len(),
        1,
        "half way: the controller is told, naming nothing secret"
    );
    engine.sweep_srtcp_ledger();
    assert!(
        events
            .try_iter()
            .all(|event| !matches!(event, Event::SrtcpCheckpointDue { .. })),
        "once per crossing"
    );
    for expected in 5..10 {
        assert_eq!(app_index(&engine, &phone, "a").await, expected);
    }
    // The lease is 10: the next seal is refused, loudly, and counted.
    let refused = send_app(&engine, "a").await;
    assert!(
        matches!(&refused, CmdResult::Error { reason } if reason.contains("SRTCP protect failed")),
        "{refused:?}"
    );
    assert_eq!(ledger.lease_refused(), 1);
    // A checkpoint alone extends nothing; the controller's confirmation after storing it does.
    let blob = checkpoint(&engine).await;
    let refused = send_app(&engine, "a").await;
    assert!(matches!(&refused, CmdResult::Error { .. }), "{refused:?}");
    let generation = generation_of(&blob);
    let confirmed = engine
        .handle(CLIENT, Command::ConfirmSrtcpIndices { generation })
        .await;
    assert_eq!(confirmed, ok_empty());
    assert_eq!(app_index(&engine, &phone, "a").await, 10);
}

#[tokio::test]
async fn confirming_a_generation_that_was_never_taken_or_that_another_node_issued_is_refused() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let refused = engine
        .handle(
            CLIENT,
            Command::ConfirmSrtcpIndices {
                generation: "x-5".into(),
            },
        )
        .await;
    assert!(
        matches!(&refused, CmdResult::Error { reason } if reason.contains("confirm_srtcp_indices")),
        "{refused:?}"
    );
    let first = checkpoint(&engine).await;
    let second = checkpoint(&engine).await;
    assert_ne!(generation_of(&first), generation_of(&second));
    // A token from another process, whose counter happens to be the same, is a foreign token.
    let own = generation_of(&second);
    let number = own.split_once('-').unwrap().1;
    let foreign = engine
        .handle(
            CLIENT,
            Command::ConfirmSrtcpIndices {
                generation: format!("0000000000000000-{number}"),
            },
        )
        .await;
    assert!(
        matches!(&foreign, CmdResult::Error { reason } if reason.contains("not exported by this engine")),
        "{foreign:?}"
    );
    // The first took effect at export (this node never restored a ledger): confirming it is a no-op.
    let ok = engine
        .handle(
            CLIENT,
            Command::ConfirmSrtcpIndices {
                generation: generation_of(&first),
            },
        )
        .await;
    assert_eq!(ok, ok_empty());
}
