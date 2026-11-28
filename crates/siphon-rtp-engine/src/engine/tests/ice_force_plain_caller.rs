#![cfg(test)]

//! `ice: force` mints ICE credentials for a call whose caller offered no ICE, to present to the
//! callee. The caller's own leg is not an ICE leg: it must stay on the signalled-source gate, because
//! the datapath's layer-4 ICE gate forwards only a STUN-validated source and a caller that never sends
//! a check would have every packet dropped (RFC 8839 §4.2: ICE applies to a party that offered it).

use super::*;

const B_UFRAG: &str = "BBBBBB";
const B_PWD: &str = "bpasswordbpasswordbpas";

fn force() -> ProfileFlags {
    ProfileFlags {
        ice: Some("force".into()),
        ..Default::default()
    }
}

fn with_ice(sdp: &str, addr: SocketAddr) -> String {
    sdp.replacen(
        "t=0 0\r\n",
        &format!("t=0 0\r\na=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n"),
        1,
    ) + &format!(
        "a=candidate:peer 1 UDP 2130706431 {} {} typ host\r\n",
        addr.ip(),
        addr.port()
    )
}

async fn near_stats(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
) -> (EndpointId, SocketAddr) {
    let call = engine.calls.get(call_id).expect("call");
    (call.near.rtp.id, call.near.rtp.local_addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_caller_toward_a_forced_ice_callee_keeps_the_signalled_source_gate() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    // Another source address: the signalled-source gate admits the signalled host.
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .expect("bind stranger");
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "force-plain".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: force(),
            },
        )
        .await;
    let far = sdp::parse(&ok_sdp_text(&offer)).expect("far offer");
    let engine_far = far.remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "force-plain".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: with_ice(&sdp_for(addr_b, false), addr_b),
                profile: force(),
            },
        )
        .await;
    let near_answer = ok_sdp_text(&answer);
    assert!(
        !near_answer.contains("a=ice-ufrag"),
        "A offered no ICE, so the answer carries none: {near_answer}"
    );
    let engine_near = sdp::parse(&near_answer).expect("near answer").remote_rtp;
    let (near_rtp, _) = near_stats(&engine, "force-plain").await;

    // B is an ICE leg: its check validates its source (RFC 8445 §7.3.1.5), which opens the egress.
    let check = nominating_binding_request(
        &[9u8; 12],
        &format!("{}:{B_UFRAG}", far.ice_ufrag.clone().expect("ufrag")),
        far.ice_pwd.clone().expect("pwd").as_bytes(),
    );
    phone_b.send_to(&check, engine_far).await.expect("check");
    let mut buffer = [0u8; 2048];
    timeout(Duration::from_secs(1), phone_b.recv_from(&mut buffer))
        .await
        .expect("the engine answers B's check")
        .expect("recv");

    // A stranger is still dropped (no RTPbleed), and does not latch the leg.
    stranger
        .send_to(&rtp(0x0BAD_0BAD), engine_near)
        .await
        .expect("stranger send");
    assert!(
        timeout(Duration::from_millis(200), phone_b.recv_from(&mut buffer))
            .await
            .is_err(),
        "a stranger's media is not relayed"
    );
    // A's media reaches B.
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), engine_near)
        .await
        .expect("a send");
    let (len, _) = timeout(Duration::from_secs(1), phone_b.recv_from(&mut buffer))
        .await
        .expect("A's media reaches B")
        .expect("recv");
    assert_eq!(&buffer[..len], rtp(0x0A0A_0A0A).as_slice());
    let stats = engine.datapath().stats(near_rtp).expect("stats");
    assert_eq!(stats.packets_dropped, 1, "only the stranger was dropped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_caller_toward_a_forced_ice_dtls_callee_is_not_gated_on_checks() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let profile = ProfileFlags {
        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
        ..force()
    };
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "force-dtls".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: profile.clone(),
            },
        )
        .await;
    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("certificate");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "force-dtls".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: with_ice(
                    &dtls_answer_sdp(addr_b, 0, "PCMU", &certificate, sdp::Setup::Active),
                    addr_b,
                ),
                profile,
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&answer))
        .expect("near answer")
        .remote_rtp;
    let (near_rtp, _) = near_stats(&engine, "force-dtls").await;
    for _ in 0..5 {
        phone_a
            .send_to(&rtp(0x0A0A_0A0A), engine_near)
            .await
            .expect("a send");
    }
    // Let the datapath receive them.
    let mut stats = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let current = engine.datapath().stats(near_rtp).expect("stats");
        if current.packets_in >= 5 {
            stats = Some(current);
            break;
        }
    }
    let stats = stats.expect("the datapath received A's packets");
    assert_eq!(
        stats.packets_dropped, 0,
        "A never sends a check, so the ICE gate must not be armed on its leg"
    );
}
