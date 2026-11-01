//! An ice-lite forwarding seat whose browser has several interfaces: it checks from every local
//! address and nominates one (RFC 8445 §7.3.1.5). The room's egress to the seat must follow the
//! nominated pair, not whichever address checked last.

use super::*;

const SEAT_UFRAG: &str = "SEATUF";
const SEAT_PWD: &str = "seatpasswordseatpassw";

fn ice_amr_wb_sdp(rtp: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{SEAT_UFRAG}\r\na=ice-pwd:{SEAT_PWD}\r\n\
         m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n\
         a=fmtp:96 octet-align=1\r\na=rtcp-mux\r\n\
         a=candidate:1 1 udp 2130706431 {ip} {port} typ host\r\n",
        ip = rtp.ip(),
        port = rtp.port()
    )
}

async fn bound(octet: u8) -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, octet), 0))
        .await
        .expect("bind");
    let address = socket.local_addr().expect("address");
    (socket, address)
}

/// Send a check from `socket` and wait for the engine's Binding success response (the room's own
/// egress may be interleaved on the same socket, so skip other datagrams).
async fn check_and_await_answer(
    socket: &UdpSocket,
    engine_seat: SocketAddr,
    username: &str,
    engine_pwd: &str,
    nominate: bool,
    transaction: u8,
) {
    let check = siphon_rtp_stun::client::binding_request_ice(
        &[transaction; 12],
        username,
        engine_pwd.as_bytes(),
        100,
        siphon_rtp_stun::client::IceRole::Controlling(1),
        nominate,
    );
    socket.send_to(&check, engine_seat).await.expect("check");
    let mut buffer = [0u8; 2048];
    for _ in 0..50 {
        let Ok(Ok((length, _))) = tokio::time::timeout(SHORT, socket.recv_from(&mut buffer)).await
        else {
            break;
        };
        if siphon_rtp_stun::parse(&buffer[..length])
            .is_ok_and(|message| message.message_type == siphon_rtp_stun::BINDING_SUCCESS)
        {
            return;
        }
    }
    panic!("the check was not answered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ice_lite_seat_is_sent_the_mix_on_the_nominated_pair_not_the_last_check() {
    let engine = engine_with_dispatcher();
    let (first, first_addr) = bound(2).await;
    let (nominated, _) = bound(3).await;
    let (last, _) = bound(4).await;

    let answer = join_with(&engine, "ice", ice_amr_wb_sdp(first_addr)).await;
    let answer = sdp::parse(&ok_sdp_text(&answer)).expect("answer");
    let engine_seat = answer.remote_rtp;
    let engine_ufrag = answer.ice_ufrag.clone().expect("engine ufrag");
    let engine_pwd = answer.ice_pwd.clone().expect("engine pwd");
    let username = format!("{engine_ufrag}:{SEAT_UFRAG}");

    let (source, source_port) = seat(&engine, "source", 96).await;
    assert_eq!(set_source(&engine, Some("source")).await, ok_empty());

    // Plain checks from two addresses and one nomination between them.
    check_and_await_answer(&first, engine_seat, &username, &engine_pwd, false, 1).await;
    check_and_await_answer(&nominated, engine_seat, &username, &engine_pwd, true, 2).await;
    check_and_await_answer(&last, engine_seat, &username, &engine_pwd, false, 3).await;

    // Let the room's follower apply the nomination, then talk.
    for sequence in 1..=20u16 {
        source
            .send_to(
                &media(
                    96,
                    sequence,
                    u32::from(sequence) * 320,
                    0x5050_5050,
                    &[7, 7],
                ),
                source_port,
            )
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        recv_rtp(&nominated, SHORT).await.is_some(),
        "the mix reaches the nominated pair"
    );
    assert!(
        recv_rtp(&last, NEGATIVE).await.is_none(),
        "a later plain check from another address does not steal the seat's egress"
    );
    assert!(
        recv_rtp(&first, NEGATIVE).await.is_none(),
        "the first checking address was never nominated"
    );
}
