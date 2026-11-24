//! The SRTCP send-index ledger through the engine (RFC 7714 §8, §9.4): the index is the key's, so a
//! seat that leaves and rejoins carries on, and a standby seeded from a checkpoint starts a margin
//! past the primary. The wire is read from what a phone receives.

use super::forward_preserve::{
    engine_with_dispatcher, expect, join, keyed_seat, media_key, offer, set_media_keys, ROOM,
};
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

#[tokio::test]
async fn a_forward_join_with_a_new_key_is_refused_at_the_entry_cap_and_an_existing_key_still_joins()
{
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let ledger = engine.conference().srtcp_ledger().clone();
    ledger.set_max_entries(1);
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    assert_eq!(app_index(&engine, &phone, "a").await, 0);

    // A second client key is a new entry: the join fails with the reason, and counts.
    let (_other, addr) = super::phone().await;
    let refused = join(
        &engine,
        ForwardMedia::Preserve,
        "b",
        offer(addr, "RTP/SAVP", false, false),
        ProfileFlags {
            media_srtcp_keys: vec![media_key(2)],
            ..ProfileFlags::default()
        },
    )
    .await;
    assert!(
        matches!(&refused, CmdResult::Error { reason }
            if reason.contains("forward_join") && reason.contains("ledger is full")),
        "{refused:?}"
    );
    assert_eq!(ledger.len(), 1, "no entry was created or evicted");
    assert_eq!(ledger.install_refused(), 1);
    assert_eq!(
        app_index(&engine, &phone, "a").await,
        1,
        "the live key was untouched"
    );

    // The same key material in another seat adds no entry, so it still joins and shares the counter.
    let (second, _) = keyed_seat(&engine, "c", vec![media_key(1)]).await;
    assert_eq!(app_index(&engine, &second, "c").await, 2);
    assert_eq!(ledger.install_refused(), 1);
}

#[tokio::test]
async fn a_restore_of_a_checkpoint_with_more_entries_than_the_cap_is_refused_whole() {
    let primary = engine_with_dispatcher();
    let _events = primary.register_client(CLIENT);
    let (_a, _) = keyed_seat(&primary, "a", vec![media_key(1)]).await;
    let (_b, _) = keyed_seat(&primary, "b", vec![media_key(2)]).await;
    let blob = checkpoint(&primary).await;

    let standby = engine_with_dispatcher();
    let _events = standby.register_client(CLIENT);
    let ledger = standby.conference().srtcp_ledger().clone();
    ledger.set_max_entries(1);
    let refused = standby
        .handle(
            CLIENT,
            Command::RestoreSrtcpIndices {
                snapshot: blob.clone(),
            },
        )
        .await;
    assert!(
        matches!(&refused, CmdResult::Error { reason }
            if reason.contains("restore_srtcp_indices") && reason.contains("ledger is full")),
        "{refused:?}"
    );
    assert_eq!(ledger.len(), 0, "not even part of it was imported");
    ledger.set_max_entries(2);
    let accepted = standby
        .handle(CLIENT, Command::RestoreSrtcpIndices { snapshot: blob })
        .await;
    assert_eq!(accepted, ok_empty());
    assert_eq!(ledger.len(), 2);
}

#[tokio::test]
async fn set_floor_keys_with_a_new_key_is_refused_at_the_entry_cap_and_leaves_the_old_keys() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let ledger = engine.conference().srtcp_ledger().clone();
    ledger.set_max_entries(1);
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    let refused = set_media_keys(&engine, None, "a", vec![media_key(2)]).await;
    assert!(
        matches!(&refused, CmdResult::Error { reason }
            if reason.contains("set_floor_keys") && reason.contains("ledger is full")),
        "{refused:?}"
    );
    assert_eq!(ledger.install_refused(), 1);
    assert_eq!(
        app_index(&engine, &phone, "a").await,
        0,
        "still under key 1"
    );
}

#[tokio::test]
async fn a_controller_that_reconnects_and_restores_its_own_blob_keeps_the_live_room_sealing() {
    // The MCX scenario: the controller restores its stored blob on every connection, the engine
    // never restarted. The floor messages of the live room must not stop.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    for expected in 0..3 {
        assert_eq!(app_index(&engine, &phone, "a").await, expected);
    }
    // The controller checkpoints, stores the blob and confirms it.
    let stored = checkpoint(&engine).await;
    open_window(&engine).await;
    assert_eq!(app_index(&engine, &phone, "a").await, 3);

    // It reconnects and restores the stored blob before anything else.
    let _events = engine.register_client(CLIENT);
    let restored = engine
        .handle(
            CLIENT,
            Command::RestoreSrtcpIndices {
                snapshot: stored.clone(),
            },
        )
        .await;
    assert_eq!(restored, ok_empty());
    assert_eq!(
        app_index(&engine, &phone, "a").await,
        4,
        "no gap, no refusal: nothing moved"
    );
    // A key the room gains afterwards seals too: no node-wide window was closed.
    let (other_phone, _) = keyed_seat(&engine, "b", vec![media_key(2)]).await;
    assert_eq!(app_index(&engine, &other_phone, "b").await, 0);
    // And the same blob again, any number of times, is the same no-op.
    let again = engine
        .handle(CLIENT, Command::RestoreSrtcpIndices { snapshot: stored })
        .await;
    assert_eq!(again, ok_empty());
    assert_eq!(app_index(&engine, &phone, "a").await, 5);
}

#[tokio::test]
async fn a_restore_of_another_engines_blob_gates_every_key_until_the_engines_own_export_is_confirmed(
) {
    // Primary P sent 3 indices under key 2 and checkpointed it.
    let primary = engine_with_dispatcher();
    let _events = primary.register_client(CLIENT);
    let (phone, _) = keyed_seat(&primary, "x", vec![media_key(2)]).await;
    for _ in 0..3 {
        app_index(&primary, &phone, "x").await;
    }
    let blob = checkpoint(&primary).await;

    // This engine serves key 1 (unlisted) when the controller restores P's blob onto it.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (phone_one, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    assert_eq!(app_index(&engine, &phone_one, "a").await, 0);
    let restored = engine
        .handle(CLIENT, Command::RestoreSrtcpIndices { snapshot: blob })
        .await;
    assert_eq!(restored, ok_empty());
    // Key 1 (held, unlisted), key 2 (listed) and key 3 (new): none has a window until this
    // engine's own export is confirmed. Nothing durable bounds what it would send.
    let (phone_two, _) = keyed_seat(&engine, "b", vec![media_key(2)]).await;
    let (phone_three, _) = keyed_seat(&engine, "c", vec![media_key(3)]).await;
    for tag in ["a", "b", "c"] {
        let refused = send_app(&engine, tag).await;
        assert!(
            matches!(&refused, CmdResult::Error { reason } if reason.contains("SRTCP protect failed")),
            "{tag}: {refused:?}"
        );
    }
    open_window(&engine).await;
    assert_eq!(app_index(&engine, &phone_one, "a").await, 1 << 16);
    assert_eq!(app_index(&engine, &phone_two, "b").await, 3 + (1 << 16));
    assert_eq!(app_index(&engine, &phone_three, "c").await, 1 << 16);
}

#[tokio::test]
async fn a_blob_whose_origin_tag_was_forged_or_dropped_is_applied_not_skipped() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (phone, _) = keyed_seat(&engine, "a", vec![media_key(1)]).await;
    assert_eq!(app_index(&engine, &phone, "a").await, 0);
    let stored = checkpoint(&engine).await;
    // The same blob with one octet of the tag changed, and with the tag removed (a version 1 blob).
    let mut forged: serde_json::Value = serde_json::from_str(&stored).unwrap();
    let tag = forged["origin_tag"].as_str().unwrap().to_string();
    let flipped = format!(
        "{:02x}{}",
        u8::from_str_radix(&tag[..2], 16).unwrap() ^ 1,
        &tag[2..]
    );
    forged["origin_tag"] = serde_json::Value::String(flipped);
    let mut untagged: serde_json::Value = serde_json::from_str(&stored).unwrap();
    untagged["version"] = 1.into();
    untagged.as_object_mut().unwrap().remove("origin_tag");
    for blob in [forged, untagged] {
        let restored = engine
            .handle(
                CLIENT,
                Command::RestoreSrtcpIndices {
                    snapshot: blob.to_string(),
                },
            )
            .await;
        assert_eq!(restored, ok_empty());
        let refused = send_app(&engine, "a").await;
        assert!(
            matches!(&refused, CmdResult::Error { reason } if reason.contains("SRTCP protect failed")),
            "gated: {refused:?}"
        );
        open_window(&engine).await;
        assert!(app_index(&engine, &phone, "a").await >= 1 << 16);
    }
}
