#![cfg(test)]

//! An `answer_local` leg that runs ICE is intercepted once its agent selected a pair: the
//! interception's taps ride the pipeline, which sends nothing before the selection (RFC 8445 §12),
//! so everything delivered toward the target is what really went to the selected pair, and what the
//! caller sent on it is delivered from the target.
//!
//! The delivery channel is read directly: the Mediation Function is covered end to end by
//! `tests/x3_answer_local.rs`, and the ICE harness (the engine's own agent driven by a peer agent)
//! is only reachable from inside the crate.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_li::PayloadDirection;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ice_answer_local_leg_is_intercepted_after_its_pair_is_selected() {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let _events = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{A_UFRAG}\r\na=ice-pwd:{A_PWD}\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
         a=candidate:peer 1 UDP 2130706431 {ip} {port} typ host\r\n\
         a=end-of-candidates\r\n",
        ip = addr_a.ip(),
        port = addr_a.port()
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ice-x3".into(),
                from_tag: "tag-a".into(),
                sdp: offer,
                profile: Default::default(),
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    let engine_media = answer.remote_rtp;
    let near_rtp = engine
        .calls
        .get("ice-x3")
        .map(|call| call.near.rtp.id)
        .expect("call");

    // Intercepted from before the selection: the pipeline sends nothing until the agent decides.
    let (factory, delivery) = crate::x3::x3_channel(4096);
    let counters = factory.counters().clone();
    engine.x3_sessions.insert(
        "ice-x3".to_string(),
        vec![crate::engine::intercept::X3Session {
            xid: Default::default(),
            delivery: "mdf.example.net:8090".to_string(),
            correlation_id: 1,
            from_tag: "tag-a".to_string(),
            owner: CLIENT,
            bridged_endpoints: Vec::new(),
            factory,
            target_is_caller: true,
            counters,
            transport: tokio::spawn(std::future::pending::<()>()),
            ended: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            joined_endpoint: None,
            handing_over: Default::default(),
        }],
    );
    engine.carry_x3_across_answer("ice-x3").await;
    assert!(
        engine.x3_sessions.contains_key("ice-x3"),
        "the taps went onto the ICE pipeline"
    );

    let is_rtp = |bytes: &[u8]| {
        bytes
            .first()
            .is_some_and(|first| (128..=191).contains(first))
    };
    let mut buffer = [0u8; 2048];
    let mut peer = peer_agent(&answer, addr_a);
    let mut now = 0u64;
    while now < 4_000 && engine.datapath().ice_validated_source(near_rtp).is_none() {
        for action in peer.poll(now) {
            if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                phone_a.send_to(&datagram, to).await.expect("peer send");
            }
        }
        engine.drive_ice_agents(now).await;
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(20), phone_a.recv_from(&mut buffer)).await
        {
            if is_rtp(&buffer[..len]) {
                continue;
            }
            for action in peer.on_datagram(addr_a, from, &buffer[..len], now) {
                if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                    phone_a.send_to(&datagram, to).await.expect("peer send");
                }
            }
            engine.drive_ice_agents(now).await;
        }
        now += 20;
    }
    assert_eq!(
        engine.datapath().ice_validated_source(near_rtp),
        Some(addr_a),
        "the agent selected the peer"
    );
    // Nothing was delivered toward the target before there was a pair to send to.
    let before: Vec<_> = delivery.packets.try_iter().collect();
    assert!(
        before
            .iter()
            .all(|packet| packet.direction != PayloadDirection::ToTarget
                || packet.destination == addr_a),
        "no egress is delivered that was not sent to the selected pair"
    );

    // After the selection: the caller's packets are from_target, the engine's egress to_target.
    let mut sent = Vec::new();
    let mut heard = Vec::new();
    for sequence in 0..15u16 {
        let packet = ulaw_rtp_packet(sequence, 0x0D0D_0D0D, 0x20);
        phone_a
            .send_to(&packet, engine_media)
            .await
            .expect("caller send");
        sent.push(packet);
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(1), phone_a.recv_from(&mut buffer)).await
        {
            if is_rtp(&buffer[..len]) {
                heard.push(buffer[..len].to_vec());
            }
        }
    }
    let mut delivered = before;
    delivered.extend(delivery.packets.try_iter());
    let from_target: Vec<_> = delivered
        .iter()
        .filter(|packet| packet.direction == PayloadDirection::FromTarget)
        .map(|packet| packet.payload.clone())
        .collect();
    assert_eq!(
        from_target, sent,
        "the caller's packets, once each, in order"
    );
    let to_target: Vec<_> = delivered
        .iter()
        .filter(|packet| packet.direction == PayloadDirection::ToTarget)
        .collect();
    assert!(!heard.is_empty(), "the pipeline sends to the selected pair");
    for packet in &heard {
        assert!(
            to_target
                .iter()
                .any(|delivered| &delivered.payload == packet),
            "everything the pair received was delivered toward the target"
        );
    }
    assert!(to_target.iter().all(|packet| packet.destination == addr_a));
}
