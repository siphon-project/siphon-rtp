#![cfg(test)]

//! An intercepted call's rebuilt media actor is tapped before it is registered, so the first packet
//! it takes is delivered (ETSI TS 103 221-2 §5.2: nothing the engine relays on an intercepted call
//! may leave untapped). The packet is handed to the media registry's dispatch straight after the
//! rebuild returns, before any control message could carry the taps across: a tap that is only put
//! back by such a message would miss it.

use super::x3_hand_over::inject_session;
use super::*;
use siphon_rtp_datapath::RxPacket;
use siphon_rtp_li::PayloadDirection;

const CALL_ID: &str = "rebuilt";
const SSRC: u32 = 0x00A1_B2C3;

/// A plain two-party relay, answered. Returns A's address and the engine endpoint A sends to.
async fn answered_relay(
    engine: &Engine<UdpLoopbackDatapath>,
) -> (UdpSocket, UdpSocket, SocketAddr, EndpointId) {
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: CALL_ID.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(offered, CmdResult::Ok { .. }), "{offered:?}");
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: CALL_ID.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    let near = engine
        .calls
        .get(CALL_ID)
        .map(|call| call.near.rtp.id)
        .expect("the call is installed");
    (phone_a, phone_b, addr_a, near)
}

/// Hand A's first packet to the media registry, the way the redirect dispatcher would.
fn dispatch_first_packet(
    engine: &Engine<UdpLoopbackDatapath>,
    endpoint: EndpointId,
    source: SocketAddr,
) -> Vec<u8> {
    let packet = g711_rtp(0, 1, SSRC, 0x55);
    engine.media().dispatch(RxPacket {
        endpoint,
        source,
        arrival: 0,
        data: bytes::Bytes::from(packet.clone()),
    });
    packet
}

async fn assert_delivered_once(delivery: &crate::x3::X3Delivery, packet: &[u8]) {
    let delivered = tokio::time::timeout(Duration::from_secs(2), delivery.packets.recv_async())
        .await
        .expect("the first packet is delivered, not relayed untapped")
        .expect("the delivery is open");
    assert_eq!(delivered.direction, PayloadDirection::FromTarget);
    assert_eq!(delivered.payload, packet);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), delivery.packets.recv_async())
            .await
            .is_err(),
        "delivered once, not once per actor"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_promoted_relay_taps_the_first_packet_its_actor_takes() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, _phone_b, addr_a, near) = answered_relay(&engine).await;
    let delivery = inject_session(&engine, CALL_ID);

    engine
        .promote_passthrough(CALL_ID)
        .await
        .expect("promote the relay");
    let packet = dispatch_first_packet(&engine, near, addr_a);

    assert_delivered_once(&delivery, &packet).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_two_party_processing_promotion_taps_the_first_packet_its_actor_takes() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, _phone_b, addr_a, near) = answered_relay(&engine).await;
    let delivery = inject_session(&engine, CALL_ID);

    engine
        .promote_to_processing(CALL_ID, false)
        .await
        .expect("promote the relay to a processing actor");
    let packet = dispatch_first_packet(&engine, near, addr_a);

    assert_delivered_once(&delivery, &packet).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgrading_an_intercepted_relay_to_processing_keeps_every_packet_tapped_once() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, _phone_b, addr_a, near) = answered_relay(&engine).await;
    let delivery = inject_session(&engine, CALL_ID);
    engine
        .promote_passthrough(CALL_ID)
        .await
        .expect("promote the relay");
    assert!(engine.media().is_relay_call(CALL_ID));

    engine
        .upgrade_relay_to_processing(CALL_ID, false)
        .await
        .expect("upgrade the relay");
    assert!(engine.media().is_transcoding_call(CALL_ID));
    let packet = dispatch_first_packet(&engine, near, addr_a);

    assert_delivered_once(&delivery, &packet).await;
}
