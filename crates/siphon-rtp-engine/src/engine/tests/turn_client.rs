//! The TURN client against the real in-process `siphon-rtp-turn` server, with coturn-style REST
//! credentials: allocation, the related address, permission and channel for the remote candidate,
//! refresh on a logical clock, a datagram relayed through the allocation, and release on delete.
//! No wall-clock sleeps decide an outcome: the ICE tick clock and the server's clock are driven
//! explicitly, and a short sleep only lets loopback datagrams land between ticks.

use super::*;
use siphon_rtp_turn::{FixedUnixClock, PeerIpPolicy, Turn, TurnConfig};

const REALM: &str = "turn.test";
const SECRET: &str = "static-auth-secret";

struct RealTurn {
    datapath: UdpLoopbackDatapath,
    turn: Turn,
    address: SocketAddr,
}

async fn real_turn_server() -> RealTurn {
    real_turn_server_granting(TurnConfig::new(REALM, SECRET).max_lifetime).await
}

/// The real server, granting at most `max_lifetime` seconds per allocation.
async fn real_turn_server_granting(max_lifetime: u32) -> RealTurn {
    let datapath = UdpLoopbackDatapath::new();
    let mut config = TurnConfig::new(REALM, SECRET);
    config.max_lifetime = max_lifetime;
    // The peers in these tests live on loopback, which the secure default denies.
    config.denied_peers = PeerIpPolicy::permissive();
    let unix_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("unix time")
        .as_secs();
    let turn = Turn::spawn(
        Arc::new(datapath.clone()),
        config,
        Arc::new(FixedUnixClock::new(unix_now)),
    )
    .expect("spawn turn");
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind turn listener");
    let address = socket.local_addr().expect("turn address");
    let serving = turn.clone();
    tokio::spawn(async move {
        let _ = serving.serve_udp(socket).await;
    });
    RealTurn {
        datapath,
        turn,
        address,
    }
}

fn rest_client(server: SocketAddr) -> TurnClientConfig {
    TurnClientConfig {
        servers: vec![server],
        credentials: TurnCredentialSource::Rest {
            secret: SECRET.to_string(),
            identity: "node-a".to_string(),
            ttl_secs: 3_600,
        },
    }
}

/// An engine with the full agent and the TURN client, a call offered with ICE (so the relay is
/// gathered) and answered (so the agent registers *after* the allocation exists), and the near
/// leg's RTP endpoint.
async fn relayed_call(
    server: &RealTurn,
    remote: SocketAddr,
    far: SocketAddr,
) -> (Engine<UdpLoopbackDatapath>, EndpointId, String) {
    let engine = Engine::new(UdpLoopbackDatapath::new())
        .with_full_ice()
        .with_turn_client(rest_client(server.address));
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "relayed".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(remote),
                profile: Default::default(),
            },
        )
        .await;
    let offered = ok_sdp_text(&offer);
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "relayed".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(far, false),
                profile: Default::default(),
            },
        )
        .await;
    let near_rtp = engine
        .calls
        .get("relayed")
        .map(|call| call.near.rtp.id)
        .expect("call");
    (engine, near_rtp, offered)
}

/// Drive the ICE tick from `from_ms` to `to_ms` in 20 ms steps until `done` holds.
async fn drive_until(
    engine: &Engine<UdpLoopbackDatapath>,
    from_ms: u64,
    to_ms: u64,
    mut done: impl FnMut() -> bool,
) -> bool {
    let mut now = from_ms;
    while now <= to_ms {
        engine.drive_ice_agents(now).await;
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        now += 20;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_credentials_allocate_and_the_relayed_candidate_carries_its_related_address() {
    let server = real_turn_server().await;
    let (_remote, remote_addr) = phone().await;
    let (_far, far_addr) = phone().await;
    let (engine, near_rtp, offered) = relayed_call(&server, remote_addr, far_addr).await;

    let parsed = sdp::parse(&offered).expect("offer sdp");
    let relay = parsed
        .candidates
        .iter()
        .find(|candidate| candidate.kind == siphon_rtp_ice::CandidateKind::Relayed)
        .unwrap_or_else(|| panic!("a relayed candidate is advertised: {offered}"));
    assert!(
        offered.contains("typ relay raddr"),
        "RFC 8839 §5.1: a relayed candidate carries raddr/rport: {offered}"
    );
    assert!(relay.related.is_some(), "the related address parsed back");
    assert!(
        server.turn.allocation_count().await >= 1,
        "the real server granted the allocation"
    );
    assert!(engine.ice_relays.contains_key(&near_rtp));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_registered_after_gathering_still_gets_the_allocation_and_its_permission() {
    let server = real_turn_server().await;
    let (_remote, remote_addr) = phone().await;
    let (_far, far_addr) = phone().await;
    let (engine, near_rtp, _offered) = relayed_call(&server, remote_addr, far_addr).await;

    // The agent was registered after the allocation was made. If the server's datagrams were not
    // routed to the allocation, no CreatePermission / ChannelBind answer would ever land.
    let permitted = drive_until(&engine, 0, 20_000, || {
        engine.ice_relays.get(&near_rtp).is_some_and(|allocation| {
            allocation.client.may_send_to(remote_addr)
                && allocation.client.channel_for(remote_addr).is_some()
        })
    })
    .await;
    assert!(
        permitted,
        "the remote candidate got a permission and a channel on the allocation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_datagram_leaves_through_the_allocation_to_the_remote_candidate() {
    let server = real_turn_server().await;
    let (remote, remote_addr) = phone().await;
    let (_far, far_addr) = phone().await;
    let (engine, near_rtp, _offered) = relayed_call(&server, remote_addr, far_addr).await;
    let relayed = engine
        .ice_relays
        .get(&near_rtp)
        .and_then(|allocation| allocation.client.relayed_address())
        .expect("allocated");
    assert!(
        drive_until(&engine, 0, 20_000, || {
            engine
                .ice_relays
                .get(&near_rtp)
                .is_some_and(|allocation| allocation.client.channel_for(remote_addr).is_some())
        })
        .await,
        "channel bound"
    );
    // Let the channel reach the datapath on the next tick.
    engine.drive_ice_agents(30_000).await;

    // A datagram the engine sends to the remote candidate is wrapped for the server and relayed;
    // the peer sees it come from the allocation's relayed address, not from the engine.
    engine
        .datapath()
        .send(near_rtp, remote_addr, b"through-the-relay")
        .await
        .expect("send");
    // The agent's own checks to the same remote also leave directly from the engine's endpoint, so
    // read until the payload appears, and require that it came from the relayed address.
    let mut buffer = [0u8; 2048];
    let mut arrived = false;
    for _ in 0..20 {
        let (len, from) = timeout(Duration::from_secs(2), remote.recv_from(&mut buffer))
            .await
            .expect("a relayed datagram arrives")
            .expect("recv");
        if &buffer[..len] == b"through-the-relay" {
            assert_eq!(from, relayed, "sourced from the relayed address");
            arrived = true;
            break;
        }
    }
    assert!(arrived, "the payload was relayed to the remote candidate");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_allocation_is_refreshed_before_it_lapses_on_the_server() {
    // A 30 s grant puts the refresh (75 % of the lifetime) inside the window where the call is still
    // up: the remote here never answers checks, so the agent fails and the call is reaped well
    // before the default 600 s grant would fall due — and a reaped call deletes its allocation.
    let server = real_turn_server_granting(30).await;
    let (_remote, remote_addr) = phone().await;
    let (_far, far_addr) = phone().await;
    let (engine, near_rtp, _offered) = relayed_call(&server, remote_addr, far_addr).await;
    assert!(
        drive_until(&engine, 0, 20_000, || {
            engine
                .ice_relays
                .get(&near_rtp)
                .is_some_and(|allocation| allocation.client.channel_for(remote_addr).is_some())
        })
        .await
    );
    let allocations = server.turn.allocation_count().await;
    assert!(allocations >= 1);

    // Server clock 20 s in (granted 30 s): still alive. The client's refresh falls due at 75 % of
    // the grant on the ICE clock, so tick through it in 20 ms steps and let it round-trip.
    server.datapath.advance_clock(20);
    drive_until(&engine, 20_000, 24_000, || false).await;
    assert!(
        engine.calls.contains_key("relayed"),
        "the call is still up, so the allocation was refreshed, not deleted"
    );

    // 20 s further the original 30 s grant is gone; only the refresh keeps the allocation.
    server.datapath.advance_clock(20);
    server.turn.reap();
    assert_eq!(
        server.turn.allocation_count().await,
        allocations,
        "the refresh extended the allocation past its original expiry"
    );
    assert!(
        engine
            .ice_relays
            .get(&near_rtp)
            .is_some_and(|allocation| !allocation.client.is_terminal()),
        "the client still holds a live allocation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_the_call_frees_the_allocation_on_the_server() {
    let server = real_turn_server().await;
    let (_remote, remote_addr) = phone().await;
    let (_far, far_addr) = phone().await;
    let (engine, near_rtp, _offered) = relayed_call(&server, remote_addr, far_addr).await;
    assert!(server.turn.allocation_count().await >= 1);
    assert!(engine.ice_relays.contains_key(&near_rtp));
    // Settle any request in flight so the delete is not queued behind one.
    drive_until(&engine, 0, 20_000, || {
        engine
            .ice_relays
            .get(&near_rtp)
            .is_some_and(|allocation| allocation.client.channel_for(remote_addr).is_some())
    })
    .await;

    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "relayed".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;

    assert!(
        engine.ice_relays.is_empty(),
        "no allocation outlives its call"
    );
    let mut remaining = server.turn.allocation_count().await;
    for _ in 0..100 {
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        remaining = server.turn.allocation_count().await;
    }
    assert_eq!(remaining, 0, "the server saw Refresh with lifetime 0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_server_that_allocates_wins_and_a_dead_one_is_skipped() {
    let server = real_turn_server().await;
    let dead: SocketAddr = "192.0.2.9:3478".parse().expect("addr");
    let engine = Engine::new(UdpLoopbackDatapath::new())
        .with_full_ice()
        .with_turn_client(TurnClientConfig {
            servers: vec![dead, server.address],
            ..rest_client(server.address)
        });
    let (_remote, remote_addr) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "failover".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(remote_addr),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        ok_sdp_text(&offer).contains("typ relay"),
        "the second server's relay is advertised after the first did not answer"
    );
    assert!(server.turn.allocation_count().await >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_info_lists_turn_client_only_when_it_is_configured() {
    let features = |result: CmdResult| match result {
        CmdResult::NodeInfo { node } => node.features,
        other => panic!("expected node info, got {other:?}"),
    };
    let plain = Engine::new(UdpLoopbackDatapath::new());
    let without = features(plain.handle(CLIENT, Command::NodeInfo).await);
    assert!(!without.iter().any(|feature| feature == "turn_client"));

    let configured = Engine::new(UdpLoopbackDatapath::new())
        .with_full_ice()
        .with_turn_client(rest_client("192.0.2.9:3478".parse().expect("addr")));
    let with = features(configured.handle(CLIENT, Command::NodeInfo).await);
    assert!(with.iter().any(|feature| feature == "turn_client"));
}
