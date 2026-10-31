//! The contract carries `set_floor_keys` and `profile.floor_keys`, which this build does not
//! implement: each is refused, never ignored, and nothing is allocated for the refused request.
//! (`media: preserve` and `profile.key_mgmt` are served: see `forward_preserve`.)

use super::*;
use siphon_rtp_proto::{FloorKey, ForwardMedia};

const ROOM: &str = "group-1";

fn floor_key() -> FloorKey {
    FloorKey {
        mki: 7,
        key: vec![0x11; 16],
        salt: vec![0x22; 12],
    }
}

fn reason(result: CmdResult) -> String {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn offer_text(audio: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = audio.ip(),
        port = audio.port()
    )
}

fn secured(floor_keys: Vec<FloorKey>, key_mgmt: Option<&str>) -> ProfileFlags {
    ProfileFlags {
        floor_keys,
        key_mgmt: key_mgmt.map(str::to_string),
        ..ProfileFlags::default()
    }
}

async fn join(
    engine: &Engine<UdpLoopbackDatapath>,
    audio: SocketAddr,
    profile: ProfileFlags,
    media: ForwardMedia,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp: offer_text(audio),
                profile,
                media,
            },
        )
        .await
}

#[tokio::test]
async fn set_floor_keys_is_refused_as_unsupported() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    for (call_id, conference_id) in [(None, Some(ROOM)), (Some("call-1"), None)] {
        let result = engine
            .handle(
                CLIENT,
                Command::SetFloorKeys {
                    call_id: call_id.map(str::to_string),
                    conference_id: conference_id.map(str::to_string),
                    from_tag: "a".into(),
                    keys: vec![floor_key()],
                },
            )
            .await;
        assert_eq!(reason(result), "unsupported command: set_floor_keys");
    }
}

#[tokio::test]
async fn floor_keys_are_refused_on_join_and_offer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_, audio) = phone().await;
    for (profile, needle) in [
        (secured(vec![floor_key()], None), "floor_keys"),
        (
            secured(vec![floor_key()], Some("mikey AQAF")),
            "not supported",
        ),
    ] {
        let joined = reason(join(&engine, audio, profile.clone(), ForwardMedia::Translate).await);
        assert!(joined.contains(needle), "{joined}");
        let offered = reason(
            engine
                .handle(
                    CLIENT,
                    Command::ForwardOffer {
                        conference_id: ROOM.into(),
                        from_tag: "b".into(),
                        profile,
                        media: ForwardMedia::Translate,
                    },
                )
                .await,
        );
        assert!(offered.contains(needle), "{offered}");
    }
    assert_eq!(engine.conference().forward().seat_count(), 0);
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn floor_keys_are_refused_on_a_two_party_offer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_, audio) = phone().await;
    for profile in [secured(vec![floor_key()], None)] {
        let result = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "call-1".into(),
                    from_tag: "ft".into(),
                    sdp: offer_text(audio),
                    profile,
                },
            )
            .await;
        assert!(reason(result).contains("not supported"));
    }
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn a_key_mgmt_with_a_line_break_is_refused_for_its_line_break() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_, audio) = phone().await;
    let joined = reason(
        join(
            &engine,
            audio,
            secured(vec![], Some("mikey x\r\na=sendrecv")),
            ForwardMedia::Translate,
        )
        .await,
    );
    assert!(joined.contains("line break"), "{joined}");
}
