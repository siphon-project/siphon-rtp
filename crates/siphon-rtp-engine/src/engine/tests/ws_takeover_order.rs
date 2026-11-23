//! A WebSocket takeover bridge is registered before the live leg is redirected to it, and announced
//! only once the redirect has landed. The first datagram of a live call reaches the dispatcher the
//! instant a `Redirect` is installed, and one that finds no owner is dropped; and a controller must
//! never be told a bridge started when the redirect that makes it live was refused.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;

async fn relay_on_a_recording_datapath(
    call_id: &str,
) -> (
    Engine<LatchLearningDatapath>,
    LatchLearningDatapath,
    (UdpSocket, SocketAddr),
    (UdpSocket, SocketAddr),
) {
    let datapath = LatchLearningDatapath::new();
    let engine = Engine::new(datapath.clone());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    (engine, datapath, (phone_a, near_addr), (phone_b, far_addr))
}

fn attach(call_id: &str, ws_uri: &str) -> Command {
    Command::AttachWsBridge {
        call_id: call_id.into(),
        from_tag: "tag-a".into(),
        ws_uri: ws_uri.into(),
        profile: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_takeover_bridge_owns_the_leg_before_it_is_redirected() {
    let (engine, datapath, _a, _b) = relay_on_a_recording_datapath("ws-order").await;
    let _events = engine.register_client(CLIENT);
    let redirects: Arc<Mutex<Vec<(EndpointId, bool)>>> = Arc::new(Mutex::new(Vec::new()));
    let (seen, registry) = (redirects.clone(), engine.ws());
    datapath.on_redirect(move |endpoint| {
        seen.lock()
            .expect("redirect log")
            .push((endpoint, registry.owns(endpoint)));
    });
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let attached = engine.handle(CLIENT, attach("ws-order", &ws_uri)).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let seen = redirects.lock().expect("redirect log").clone();
    assert!(!seen.is_empty(), "the takeover redirected the leg");
    for (endpoint, owned) in seen {
        assert!(
            owned,
            "{endpoint:?} was redirected before the bridge owned it: its first datagram is dropped"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_redirect_announces_nothing_and_leaves_the_relay_running() {
    let (engine, datapath, (phone_a, near_addr), (phone_b, _)) =
        relay_on_a_recording_datapath("ws-refused").await;
    let events = engine.register_client(CLIENT);
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;

    datapath.fail_redirect_installs(true);
    let refused = engine.handle(CLIENT, attach("ws-refused", &ws_uri)).await;
    datapath.fail_redirect_installs(false);
    assert!(
        matches!(&refused, CmdResult::Error { reason } if reason.contains("redirect")),
        "the verb fails with the reason: {refused:?}"
    );

    // Nothing was announced: no started, and so no ended after it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                event,
                Event::WsBridgeStarted { .. } | Event::WsBridgeEnded { .. }
            ),
            "no lifecycle event for a bridge that never came up: {event:?}"
        );
    }
    // Nothing is left behind: no route, no call handle, no bridge record, and the call is still a
    // relay.
    assert!(!engine.ws().is_ws_call("ws-refused"));
    assert!(engine.ws_bridges.get("ws-refused").is_none());
    assert_eq!(
        engine.calls.get("ws-refused").expect("call").pipeline,
        PipelineKind::Passthrough
    );
    // And it still relays on its old path.
    for sequence in 0..5u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    let (relayed, _) = recv(&phone_b).await;
    assert!(!relayed.is_empty(), "B still hears A after the refusal");
}
