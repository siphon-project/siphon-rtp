#![cfg(test)]

//! The owner of a seat that joined its room is the control client's identity. A controller identity
//! that has no connection is kept while it still owns such a seat, so a reconnect finds it again, and
//! is released once the last one is gone.

use super::*;
use siphon_rtp_proto::{ConferenceDtmf, ConferenceRole};

const ROOM: &str = "room";
const TAG: &str = "seat-a";

async fn join(engine: &Engine<UdpLoopbackDatapath>, client: ClientId) -> UdpSocket {
    let (phone, address) = phone().await;
    let result = engine
        .handle(
            client,
            Command::ConferenceJoin {
                conference_id: ROOM.into(),
                from_tag: TAG.into(),
                sdp: sdp_for(address, true),
                role: ConferenceRole::Talker,
                profile: Default::default(),
                dtmf: ConferenceDtmf::Events,
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    phone
}

fn disconnect(engine: &Engine<UdpLoopbackDatapath>, attachment: &ControllerAttachment) {
    engine.deregister_client(attachment.client, attachment.generation);
    engine.detach_controller("sbc-1", attachment.generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_controller_holding_only_a_joined_seat_keeps_its_identity_across_a_disconnect() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let first = engine
        .attach_controller("sbc-1", ClientId(1))
        .expect("attach");
    let _phone = join(&engine, first.client).await;
    assert_eq!(
        engine.conference.joined_seat_owner(ROOM, TAG),
        Some(first.client.0),
        "the seat is owned by the client whose join seated it"
    );

    disconnect(&engine, &first);
    let second = engine
        .attach_controller("sbc-1", ClientId(2))
        .expect("reattach");
    assert_eq!(
        second.client, first.client,
        "the identity was not reaped while it owned a seat"
    );
    assert!(
        engine.owns_joined_seat(second.client, ROOM, TAG),
        "and its seat is still its own, by identity rather than by channel"
    );
    assert!(
        !engine.owns_joined_seat(ClientId(99), ROOM, TAG),
        "another client does not own it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_identity_is_released_once_its_last_joined_seat_has_gone() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let first = engine
        .attach_controller("sbc-1", ClientId(1))
        .expect("attach");
    let _phone = join(&engine, first.client).await;
    disconnect(&engine, &first);
    assert!(!engine.controllers.is_empty(), "kept while the seat lives");

    // The seat goes without any control connection to see it (an idle reap, a failed ICE check).
    assert!(!engine.conference.leave(ROOM, TAG).is_empty());
    engine.end_orphaned_seat_x3().await;
    assert!(
        engine.controllers.is_empty(),
        "nothing holds the identity any more, so it is released"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_the_last_seat_of_a_detached_identity_releases_it() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let first = engine
        .attach_controller("sbc-1", ClientId(1))
        .expect("attach");
    let _phone = join(&engine, first.client).await;
    disconnect(&engine, &first);
    let second = engine
        .attach_controller("sbc-1", ClientId(2))
        .expect("reattach");
    let left = engine
        .handle(
            second.client,
            Command::ConferenceLeave {
                conference_id: ROOM.into(),
                from_tag: TAG.into(),
            },
        )
        .await;
    assert!(matches!(left, CmdResult::Ok { .. }), "{left:?}");
    disconnect(&engine, &second);
    assert!(engine.controllers.is_empty(), "no seat, no call: released");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_that_already_owns_a_joined_seat_cannot_be_re_keyed() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _events = engine.register_client(CLIENT);
    let _phone = join(&engine, CLIENT).await;
    assert!(matches!(
        engine.attach_controller("sbc-1", CLIENT),
        Err(ControllerAttachError::CallsAlreadyOwned)
    ));
}
