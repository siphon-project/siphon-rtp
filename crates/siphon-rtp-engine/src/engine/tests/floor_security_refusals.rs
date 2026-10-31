//! What is still refused of the floor-security contract. `floor_keys`, `set_floor_keys`,
//! `key_mgmt` and `media: preserve` are all served (see `floor_srtcp` and `forward_preserve`); a
//! `key_mgmt` value that would break the SDP line is refused for that reason, before anything is
//! allocated.

use super::*;
use siphon_rtp_proto::{FloorKey, ForwardMedia};

const ROOM: &str = "group-1";

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
