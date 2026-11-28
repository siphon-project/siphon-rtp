#![cfg(test)]

//! With the full RFC 8445 agent on, the engine must say so in its SDP and take the role the SDP
//! exchange implies. The peer here is an independent agent that behaves as a browser does: it reads
//! the engine's SDP, takes its role from `a=ice-lite` (RFC 8445 §6.1.1) and uses nothing but the
//! credentials and candidates that SDP carried.

use super::*;
use siphon_rtp_ice::agent::{AgentConfig, Credentials};
use siphon_rtp_ice::{AgentAction, Candidate, CandidateKind, IceAgent, IceState};
use std::net::IpAddr;

const B_UFRAG: &str = "BBBBBB";
const B_PWD: &str = "bpasswordbpasswordbpas";

/// A browser-like peer: `engine_sdp` is the SDP the engine sent it, `offerer` is whether the peer
/// made the offer. RFC 8445 §6.1.1: the offerer controls unless the other side is lite; a peer
/// facing a lite engine always controls; the answerer of a full agent is controlled.
fn browser_agent(
    engine_sdp: &sdp::MediaInfo,
    local: SocketAddr,
    credentials: (&str, &str),
    offerer: bool,
) -> IceAgent {
    let controlling = engine_sdp.ice_lite || offerer;
    let local_candidate = Candidate::new("peer".to_string(), 1, local, CandidateKind::Host, 65535);
    IceAgent::new(
        AgentConfig::new(
            Credentials::new(credentials.0, credentials.1),
            Credentials::new(
                engine_sdp.ice_ufrag.clone().expect("engine ufrag"),
                engine_sdp.ice_pwd.clone().expect("engine pwd"),
            ),
            controlling,
            0xFFFF_0000_FFFF_0000,
        )
        .with_candidates(
            vec![local_candidate],
            engine_sdp
                .candidates
                .iter()
                .filter(|candidate| candidate.component == 1)
                .cloned()
                .collect(),
        ),
        0,
    )
}

/// The answer a browser sends: ICE credentials and its one host candidate.
fn browser_ice_answer(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
         a=candidate:peer 1 UDP 2130706431 {ip} {port} typ host\r\n\
         a=end-of-candidates\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

/// A 1:1 NAT between the peer and the engine: the engine advertises `public`, the datapath is bound
/// on `private`, and the NAT rewrites the address in both directions.
#[derive(Clone, Copy)]
struct OneToOneNat {
    public: IpAddr,
    private: IpAddr,
}

impl OneToOneNat {
    fn inbound(self, address: SocketAddr) -> SocketAddr {
        if address.ip() == self.public {
            SocketAddr::new(self.private, address.port())
        } else {
            address
        }
    }

    fn outbound(self, address: SocketAddr) -> SocketAddr {
        if address.ip() == self.private {
            SocketAddr::new(self.public, address.port())
        } else {
            address
        }
    }
}

/// Run `peer` against the engine's agents until both have selected a pair (or the budget ends).
/// Returns whether the peer's agent completed and the engine's datapath adopted `addr`.
async fn run_ice(
    engine: &Engine<UdpLoopbackDatapath>,
    peer: &mut IceAgent,
    socket: &UdpSocket,
    addr: SocketAddr,
    endpoint: EndpointId,
) -> bool {
    run_ice_through(engine, peer, socket, addr, Some(endpoint), None).await
}

async fn run_ice_through(
    engine: &Engine<UdpLoopbackDatapath>,
    peer: &mut IceAgent,
    socket: &UdpSocket,
    addr: SocketAddr,
    endpoint: Option<EndpointId>,
    nat: Option<OneToOneNat>,
) -> bool {
    // The engine's side has selected once the datapath adopted the peer's address; a seat the engine
    // does not expose an endpoint for is judged on the peer's agent alone, which only completes when
    // the engine's agent nominated (or accepted a nomination from) the pair.
    let engine_selected = |engine: &Engine<UdpLoopbackDatapath>| {
        endpoint
            .is_none_or(|endpoint| engine.datapath().ice_validated_source(endpoint) == Some(addr))
    };
    let to_wire = |to: SocketAddr| nat.map_or(to, |nat| nat.inbound(to));
    let from_wire = |from: SocketAddr| nat.map_or(from, |nat| nat.outbound(from));
    let mut buffer = [0u8; 2048];
    let mut now = 0u64;
    while now < 6_000 && (!engine_selected(engine) || peer.state() != IceState::Completed) {
        for action in peer.poll(now) {
            if let AgentAction::Send { to, datagram, .. } = action {
                socket
                    .send_to(&datagram, to_wire(to))
                    .await
                    .expect("peer send");
            }
        }
        engine.drive_ice_agents(now).await;
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(20), socket.recv_from(&mut buffer)).await
        {
            for action in peer.on_datagram(addr, from_wire(from), &buffer[..len], now) {
                if let AgentAction::Send { to, datagram, .. } = action {
                    socket
                        .send_to(&datagram, to_wire(to))
                        .await
                        .expect("peer send");
                }
            }
            engine.drive_ice_agents(now).await;
        }
        now += 20;
    }
    engine_selected(engine) && peer.state() == IceState::Completed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_agent_offering_to_a_browser_advertises_no_ice_lite_and_answers_its_checks() {
    // The observed shape: a plain caller rings an ICE callee. The engine offers to the callee.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (_phone_a, addr_a) = phone().await;
    let (browser, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "full-offerer".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: ProfileFlags {
                    ice: Some("force".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let far_offer = ok_sdp_text(&offer);
    assert!(
        !far_offer.contains("a=ice-lite"),
        "a full agent never advertises lite (RFC 8445 §5.1.1): {far_offer}"
    );
    let far_info = sdp::parse(&far_offer).expect("parse far offer");
    let mut peer = browser_agent(&far_info, addr_b, (B_UFRAG, B_PWD), false);
    assert!(
        !peer.is_controlling(),
        "the answerer of a full agent is controlled"
    );

    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "full-offerer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: browser_ice_answer(addr_b),
                profile: Default::default(),
            },
        )
        .await;
    let far_rtp = engine
        .calls
        .get("full-offerer")
        .and_then(|call| call.far.as_ref().map(|far| far.rtp.id))
        .expect("call with a far leg");
    assert!(
        run_ice(&engine, &mut peer, &browser, addr_b, far_rtp).await,
        "both agents select a pair (peer {:?})",
        peer.state()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_agent_answering_a_browser_offer_advertises_no_ice_lite_and_is_controlled() {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (browser, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "full-answerer".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "full-answerer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let near_answer = ok_sdp_text(&answer);
    assert!(
        !near_answer.contains("a=ice-lite"),
        "a full agent never advertises lite (RFC 8445 §5.1.1): {near_answer}"
    );
    let near = sdp::parse(&near_answer).expect("parse answer");
    let near_rtp = engine
        .calls
        .get("full-answerer")
        .map(|call| call.near.rtp.id)
        .expect("call");
    // The browser made the offer, so it controls (§6.1.1).
    let mut peer = browser_agent(&near, addr_a, (A_UFRAG, A_PWD), true);
    assert!(peer.is_controlling());
    assert!(
        run_ice(&engine, &mut peer, &browser, addr_a, near_rtp).await,
        "both agents select a pair (peer {:?})",
        peer.state()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_full_agent_the_engine_still_advertises_lite() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "lite".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: ProfileFlags {
                    ice: Some("force".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(ok_sdp_text(&offer).contains("a=ice-lite"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_agent_answers_checks_on_a_leg_advertised_at_a_different_address_than_it_is_bound() {
    // The far leg is bound on one address and advertised as another (a 1:1 NAT or an interface with
    // an advertised override), so its host candidate carries the advertised address while its socket
    // receives on the bound one. The agent resolves an inbound check to the candidate the check
    // reaches (RFC 8445 §7.3.1.3: the local candidate of the pair is the one whose base received
    // it), not to the socket's own address.
    let table = InterfaceTable::from_entries(
        vec![
            crate::interface::InterfaceEntry::new(
                "internal",
                "127.0.0.1".parse().expect("ip"),
                None,
            ),
            crate::interface::InterfaceEntry::new(
                "external",
                "127.0.0.2".parse().expect("ip"),
                Some("127.0.0.3".parse().expect("ip")),
            ),
        ],
        None,
    )
    .expect("interface table");
    let engine = Engine::new(UdpLoopbackDatapath::new())
        .with_interfaces(table)
        .with_full_ice();
    let (_phone_a, addr_a) = phone().await;
    let (browser, addr_b) = phone().await;
    let profile = ProfileFlags {
        direction: vec!["internal".into(), "external".into()],
        ice: Some("force".into()),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "natted".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: profile.clone(),
            },
        )
        .await;
    let far_info = sdp::parse(&ok_sdp_text(&offer)).expect("parse far offer");
    assert_eq!(
        far_info.remote_rtp.ip(),
        "127.0.0.3".parse::<IpAddr>().expect("ip"),
        "the far leg is advertised at the external address"
    );
    let mut peer = browser_agent(&far_info, addr_b, (B_UFRAG, B_PWD), false);
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "natted".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: browser_ice_answer(addr_b),
                profile,
            },
        )
        .await;
    let far_rtp = engine
        .calls
        .get("natted")
        .and_then(|call| call.far.as_ref().map(|far| far.rtp.id))
        .expect("call with a far leg");
    let nat = OneToOneNat {
        public: "127.0.0.3".parse().expect("ip"),
        private: "127.0.0.2".parse().expect("ip"),
    };
    assert!(
        run_ice_through(
            &engine,
            &mut peer,
            &browser,
            addr_b,
            Some(far_rtp),
            Some(nat)
        )
        .await,
        "both agents select a pair (peer {:?})",
        peer.state()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_agent_re_offer_toward_the_browser_leg_carries_no_ice_lite() {
    // The re-offer re-presents the far leg to B with the same ICE identity; it is the same emitter
    // posture as the first offer (RFC 8445 §5.1.1), with or without the full agent.
    for (full, expect_lite) in [(true, false), (false, true)] {
        let engine = if full {
            Engine::new(UdpLoopbackDatapath::new()).with_full_ice()
        } else {
            Engine::new(UdpLoopbackDatapath::new())
        };
        let (_phone_a, addr_a) = phone().await;
        let (_browser, addr_b) = phone().await;
        let profile = ProfileFlags {
            ice: Some("force".into()),
            ..Default::default()
        };
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "reoffer".into(),
                    from_tag: "a".into(),
                    sdp: sdp_for(addr_a, false),
                    profile: profile.clone(),
                },
            )
            .await;
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "reoffer".into(),
                    from_tag: "a".into(),
                    to_tag: "b".into(),
                    sdp: browser_ice_answer(addr_b),
                    profile: profile.clone(),
                },
            )
            .await;
        let reoffer = reoffer_from(&engine, "reoffer", "a", sdp_for(addr_a, false), profile).await;
        let text = ok_sdp_text(&reoffer);
        assert_eq!(
            text.contains("a=ice-lite"),
            expect_lite,
            "full agent {full}: {text}"
        );
        assert!(text.contains("a=ice-ufrag:"), "{text}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_agent_dial_out_to_a_browser_seat_controls_and_advertises_no_ice_lite() {
    // The engine offers a WebRTC seat. Without `a=ice-lite` the browser, answering, is controlled
    // (RFC 8445 §6.1.1), so the engine's agent has to be the controlling one: it nominates.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (browser, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: "room".into(),
                from_tag: "b".into(),
                profile: ProfileFlags {
                    transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer = ok_sdp_text(&offer);
    assert!(!offer.contains("a=ice-lite"), "{offer}");
    let engine_info = sdp::parse(&offer).expect("parse offer");
    let mut peer = browser_agent(&engine_info, addr_b, (B_UFRAG, B_PWD), false);
    assert!(!peer.is_controlling());
    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("certificate");
    let answer = format!(
        "{}a=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n\
         a=candidate:peer 1 UDP 2130706431 {ip} {port} typ host\r\na=end-of-candidates\r\n",
        super::webrtc_floor_channel::browser_offer(addr_b, &certificate, "active", false),
        ip = addr_b.ip(),
        port = addr_b.port(),
    );
    let seated = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: "room".into(),
                from_tag: "b".into(),
                sdp: answer,
                received_from: None,
            },
        )
        .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");
    // The engine's first check on the leg, read before the peer answers anything, so no 487 can have
    // changed its role: it controls as the offerer (RFC 8445 §6.1.1).
    let mut buffer = [0u8; 2048];
    let mut first_check = None;
    for now in (0..2_000u64).step_by(20) {
        engine.drive_ice_agents(now).await;
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(20), browser.recv_from(&mut buffer)).await
        {
            first_check = Some(buffer[..len].to_vec());
            break;
        }
    }
    let first_check = first_check.expect("the engine sends a connectivity check");
    let message = siphon_rtp_stun::parse(&first_check).expect("a STUN message");
    assert!(
        siphon_rtp_stun::client::ice_controlling(&message).is_some()
            && siphon_rtp_stun::client::ice_controlled(&message).is_none(),
        "the engine's initial role is controlling"
    );
    assert!(
        run_ice_through(&engine, &mut peer, &browser, addr_b, None, None).await,
        "the engine's agent nominates (peer {:?})",
        peer.state()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_agent_serves_a_browser_that_answers_with_credentials_and_no_candidates() {
    // RFC 8838 trickle: the answer carries ICE credentials and no candidates. The offer said "full",
    // so a full agent must serve the leg: it waits, learns the browser's address from the browser's own
    // check (RFC 8445 §7.3.1.3, peer-reflexive) and nominates.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (_phone_a, addr_a) = phone().await;
    let (browser, addr_b) = phone().await;
    let profile = ProfileFlags {
        ice: Some("force".into()),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "trickle-answer".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: profile.clone(),
            },
        )
        .await;
    let far_info = sdp::parse(&ok_sdp_text(&offer)).expect("parse far offer");
    assert!(!far_info.ice_lite);
    let mut peer = browser_agent(&far_info, addr_b, (B_UFRAG, B_PWD), false);
    let answer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr_b.ip(),
        port = addr_b.port()
    );
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "trickle-answer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer,
                profile,
            },
        )
        .await;
    let far_rtp = engine
        .calls
        .get("trickle-answer")
        .and_then(|call| call.far.as_ref().map(|far| far.rtp.id))
        .expect("call with a far leg");
    assert!(
        run_ice(&engine, &mut peer, &browser, addr_b, far_rtp).await,
        "both agents select a pair (peer {:?})",
        peer.state()
    );
}

/// Set up the call of `a_full_agent_serves_a_browser_that_answers_with_credentials_and_no_candidates`
/// and return the engine.
async fn call_with_a_candidate_less_answer(call_id: &str) -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (_phone_a, addr_a) = phone().await;
    let (_browser, addr_b) = phone().await;
    let profile = ProfileFlags {
        ice: Some("force".into()),
        ..Default::default()
    };
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: profile.clone(),
            },
        )
        .await;
    let answer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr_b.ip(),
        port = addr_b.port()
    );
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer,
                profile,
            },
        )
        .await;
    engine
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_never_delivers_a_candidate_has_its_call_torn_down_at_the_deadline() {
    let engine = call_with_a_candidate_less_answer("never").await;
    assert!(engine.drive_ice_agents(1_000).await.is_empty());
    assert!(engine.calls.contains_key("never"));
    let deadline = siphon_rtp_ice::agent::DEFAULT_ESTABLISHMENT_TIMEOUT_MS;
    assert!(engine
        .drive_ice_agents(1_000 + deadline - 1)
        .await
        .is_empty());
    assert!(engine.calls.contains_key("never"), "still waiting");
    let failed = engine.drive_ice_agents(1_000 + deadline).await;
    assert_eq!(failed, vec!["never".to_string()]);
    assert!(!engine.calls.contains_key("never"), "the call is torn down");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarding_seat_whose_participant_never_delivers_a_candidate_is_removed() {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (_browser, addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = addr.ip(),
        port = addr.port()
    );
    let joined = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: "room".into(),
                from_tag: "b".into(),
                sdp: offer,
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(joined, CmdResult::Ok { .. }), "{joined:?}");
    assert!(
        !ok_sdp_text(&joined).contains("a=ice-lite"),
        "a full agent serves the seat"
    );
    assert_eq!(engine.conference().forward().room_count(), 1);
    engine.drive_ice_agents(1_000).await;
    let deadline = siphon_rtp_ice::agent::DEFAULT_ESTABLISHMENT_TIMEOUT_MS;
    let failed = engine.drive_ice_agents(1_000 + deadline).await;
    assert_eq!(failed, vec!["room".to_string()]);
    assert_eq!(
        engine.conference().forward().room_count(),
        0,
        "the seat, and with it the empty room, is gone"
    );
    assert_eq!(
        engine.ice_agents.as_ref().map(|agents| agents.len()),
        Some(0),
        "the removed seat's agent is not polled for ever"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarding_seat_that_leaves_normally_leaves_no_agent_behind() {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (_browser, addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = addr.ip(),
        port = addr.port()
    );
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: "room".into(),
                from_tag: "b".into(),
                sdp: offer,
                profile: Default::default(),
            },
        )
        .await;
    assert_eq!(
        engine.ice_agents.as_ref().map(|agents| agents.len()),
        Some(1)
    );
    let left = engine
        .handle(
            CLIENT,
            Command::ForwardLeave {
                conference_id: "room".into(),
                from_tag: "b".into(),
            },
        )
        .await;
    assert!(matches!(left, CmdResult::Ok { .. }), "{left:?}");
    assert_eq!(
        engine.ice_agents.as_ref().map(|agents| agents.len()),
        Some(0)
    );
}

fn reoffer_without_candidates(addr: SocketAddr, ufrag: &str, pwd: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         a=ice-ufrag:{ufrag}\r\na=ice-pwd:{pwd}\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_candidate_less_ice_restart_replaces_the_agent_and_its_deadline() {
    // RFC 8839 §4.4.1.1: an ICE restart starts a new exchange, so the old exchange's establishment
    // deadline must not run on, with or without candidates.
    let engine = call_with_a_candidate_less_answer("restart").await;
    let (_phone_b2, addr_b) = phone().await;
    engine.drive_ice_agents(1_000).await; // the first agent's first poll: it fails at 31 000
    let profile = ProfileFlags {
        ice: Some("force".into()),
        ..Default::default()
    };
    let restarted = reoffer_from(
        &engine,
        "restart",
        "b",
        reoffer_without_candidates(addr_b, "RESTRT", "restartpasswordrestartp"),
        profile,
    )
    .await;
    assert!(matches!(restarted, CmdResult::Ok { .. }), "{restarted:?}");
    // The replaced agent's first poll is at 25 000; the old one would have failed by 31 000.
    assert!(engine.drive_ice_agents(25_000).await.is_empty());
    assert!(engine.drive_ice_agents(40_000).await.is_empty());
    assert!(
        engine.calls.contains_key("restart"),
        "the restarted exchange is waiting"
    );
    let deadline = siphon_rtp_ice::agent::DEFAULT_ESTABLISHMENT_TIMEOUT_MS;
    let failed = engine.drive_ice_agents(25_000 + deadline).await;
    assert_eq!(
        failed,
        vec!["restart".to_string()],
        "and has a deadline of its own"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_answer_with_unchanged_credentials_keeps_the_agent_that_learned_the_pair() {
    // Established through a peer-reflexive pair (the answer carried no candidates). A later answer
    // with the same credentials is the same ICE session (RFC 8445 §9): it must not replace the agent,
    // or the learned pair is lost and a fresh empty-checklist deadline reaps a healthy call.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (_phone_a, addr_a) = phone().await;
    let (browser, addr_b) = phone().await;
    let profile = ProfileFlags {
        ice: Some("force".into()),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "re-answer".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: profile.clone(),
            },
        )
        .await;
    let far_info = sdp::parse(&ok_sdp_text(&offer)).expect("parse far offer");
    let mut peer = browser_agent(&far_info, addr_b, (B_UFRAG, B_PWD), false);
    // rtcp-mux, so the one RTP agent is the whole exchange this test drives.
    let answer = format!(
        "{}a=rtcp-mux\r\n",
        reoffer_without_candidates(addr_b, B_UFRAG, B_PWD)
    );
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "re-answer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer.clone(),
                profile: profile.clone(),
            },
        )
        .await;
    let far_rtp = engine
        .calls
        .get("re-answer")
        .and_then(|call| call.far.as_ref().map(|far| far.rtp.id))
        .expect("call with a far leg");
    assert!(run_ice(&engine, &mut peer, &browser, addr_b, far_rtp).await);
    // An ordinary re-offer from A and the answer that completes it, B's credentials unchanged.
    let reoffer = reoffer_from(
        &engine,
        "re-answer",
        "a",
        sdp_for(addr_a, true),
        profile.clone(),
    )
    .await;
    assert!(matches!(reoffer, CmdResult::Ok { .. }), "{reoffer:?}");
    let re_answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "re-answer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer,
                profile,
            },
        )
        .await;
    assert!(
        matches!(re_answered, CmdResult::Ok { .. }),
        "{re_answered:?}"
    );
    // Nothing checks for far longer than the deadline, and the call stays up on its selected pair.
    let deadline = siphon_rtp_ice::agent::DEFAULT_ESTABLISHMENT_TIMEOUT_MS;
    for now in [10_000, 10_000 + deadline + 1, 10_000 + 2 * deadline] {
        assert!(engine.drive_ice_agents(now).await.is_empty(), "at {now}");
    }
    assert!(engine.calls.contains_key("re-answer"));
    assert_eq!(
        engine.datapath().ice_validated_source(far_rtp),
        Some(addr_b),
        "the selected pair is still the datapath's source"
    );
}
