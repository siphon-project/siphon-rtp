//! A room calling a participant out (`conference_offer` then `conference_answer`), and unlinking two
//! bridged rooms (`conference_unbridge`).

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;

/// An engine whose redirected datagrams reach the room actors.
fn engine_with_dispatcher() -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine
}

async fn offer_seat(
    engine: &Engine<UdpLoopbackDatapath>,
    conference_id: &str,
    from_tag: &str,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ConferenceOffer {
                conference_id: conference_id.into(),
                from_tag: from_tag.into(),
                role: ConferenceRole::Talker,
                profile,
            },
        )
        .await
}

async fn answer_seat(
    engine: &Engine<UdpLoopbackDatapath>,
    conference_id: &str,
    from_tag: &str,
    sdp: String,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ConferenceAnswer {
                conference_id: conference_id.into(),
                from_tag: from_tag.into(),
                sdp,
                received_from: None,
            },
        )
        .await
}

async fn join_seat(
    engine: &Engine<UdpLoopbackDatapath>,
    conference_id: &str,
    from_tag: &str,
    rtp: SocketAddr,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: conference_id.into(),
                from_tag: from_tag.into(),
                sdp: sdp_for(rtp, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

async fn leave_seat(
    engine: &Engine<UdpLoopbackDatapath>,
    conference_id: &str,
    from_tag: &str,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ConferenceLeave {
                conference_id: conference_id.into(),
                from_tag: from_tag.into(),
            },
        )
        .await
}

/// A participant's answer from `rtp`: `formats` (payload type, rtpmap) in order, then `extra` lines.
fn answer_sdp(rtp: SocketAddr, formats: &[(u8, &str)], extra: &str) -> String {
    let payload_types: Vec<String> = formats
        .iter()
        .map(|(payload_type, _)| payload_type.to_string())
        .collect();
    let mut sdp = format!(
        "v=0\r\no=- 7 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {payload_types}\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        payload_types = payload_types.join(" "),
    );
    for (payload_type, rtpmap) in formats {
        sdp.push_str(&format!("a=rtpmap:{payload_type} {rtpmap}\r\n"));
    }
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str(extra);
    sdp
}

/// A plain PCMU answer with the 8 kHz telephone-event the offer listed.
fn pcmu_answer(rtp: SocketAddr) -> String {
    answer_sdp(
        rtp,
        &[(0, "PCMU/8000"), (101, "telephone-event/8000")],
        "a=sendrecv\r\na=rtcp-mux\r\n",
    )
}

fn refusal(result: &CmdResult) -> &str {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Whether one of the next `frames` mix packets `phone` receives carries loud µ-law audio.
async fn hears_loud(phone: &UdpSocket, frames: usize) -> bool {
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_codec::Decoder as _;
    use siphon_rtp_media::rtp::RtpPacket;

    let mut decoder = G711::ulaw();
    for _ in 0..frames {
        let (datagram, _) = recv(phone).await;
        let Ok(packet) = RtpPacket::parse(&datagram) else {
            continue; // an RTCP sender report on the muxed endpoint
        };
        if packet.payload_type != 0 {
            continue;
        }
        let mut pcm = vec![0i16; 320];
        let samples = decoder.decode(packet.payload, &mut pcm).expect("decode");
        if siphon_rtp_dsp::EnergyVad::energy(&pcm[..samples]) > 1_000_000 {
            return true;
        }
    }
    false
}

/// Send `count` loud µ-law frames from `phone` to `engine_port`, starting at `first_sequence`.
async fn talk(
    phone: &UdpSocket,
    engine_port: SocketAddr,
    ssrc: u32,
    first_sequence: u16,
    count: u16,
) {
    for sequence in first_sequence..first_sequence + count {
        phone
            .send_to(&g711_rtp(0, sequence, ssrc, 0x00), engine_port)
            .await
            .expect("send");
    }
}

/// The participant the room dials out and the participant who joined hear each other, mixed minus
/// self, exactly as two joined participants do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialled_out_seat_and_a_joined_seat_hear_each_other() {
    let engine = engine_with_dispatcher();
    let (alice, alice_addr) = phone().await;
    let (carol, carol_addr) = phone().await;

    let alice_engine = sdp::parse(&ok_sdp_text(
        &join_seat(&engine, "room", "alice", alice_addr).await,
    ))
    .expect("join answer")
    .remote_rtp;
    let offered = offer_seat(&engine, "room", "carol", ProfileFlags::default()).await;
    let carol_engine = sdp::parse(&ok_sdp_text(&offered))
        .expect("the engine's own parser reads its offer")
        .remote_rtp;
    assert!(
        matches!(&offered, CmdResult::Ok { to_tag: Some(tag), .. } if tag == "carol"),
        "{offered:?}"
    );
    assert_eq!(engine.pending_seat_count(), 1);
    assert_eq!(
        engine.conference().participant_count(),
        1,
        "carol is not seated yet"
    );

    let answered = answer_seat(&engine, "room", "carol", pcmu_answer(carol_addr)).await;
    assert!(
        matches!(answered, CmdResult::Ok { sdp: None, .. }),
        "{answered:?}"
    );
    assert_eq!(engine.pending_seat_count(), 0);
    assert_eq!(engine.conference().participant_count(), 2);

    talk(&alice, alice_engine, 0x0A0A_0A0A, 0, 30).await;
    talk(&carol, carol_engine, 0x0C0C_0C0C, 0, 30).await;
    assert!(hears_loud(&carol, 12).await, "carol hears alice");
    assert!(hears_loud(&alice, 12).await, "alice hears carol");

    for tag in ["alice", "carol"] {
        assert!(matches!(
            leave_seat(&engine, "room", tag).await,
            CmdResult::Ok { .. }
        ));
    }
    assert!(!engine.conference().contains("room"));
}

/// The offer is a valid RFC 3264 offer listing only what a room can mix, widest band first, with one
/// telephone-event per clock rate, read here line by line rather than through the engine's parser.
#[tokio::test]
async fn the_offer_lists_only_codecs_the_room_can_mix() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = ok_sdp_text(&offer_seat(&engine, "room", "carol", ProfileFlags::default()).await);
    let lines: Vec<&str> = offer.split("\r\n").collect();
    assert_eq!(&lines[..1], ["v=0"], "{offer}");
    assert!(
        lines[1].starts_with("o=- ") && lines[1].ends_with(" 1 IN IP4 127.0.0.1"),
        "{offer}"
    );
    assert_eq!(
        &lines[2..5],
        ["s=-", "c=IN IP4 127.0.0.1", "t=0 0"],
        "{offer}"
    );
    let media: Vec<&str> = lines[5].split(' ').collect();
    assert_eq!(media[0], "m=audio");
    assert_eq!(
        media[2], "RTP/AVP",
        "plain RTP: no SDES or DTLS on an offered seat"
    );
    for attribute in ["a=sendrecv", "a=rtcp-mux", "a=ptime:20", "a=maxptime:120"] {
        assert!(lines.contains(&attribute), "{attribute} in {offer}");
    }
    assert!(
        !offer.contains("a=crypto") && !offer.contains("a=ice-"),
        "{offer}"
    );

    let info = sdp::parse(&offer).expect("parse");
    let codecs = info.audio_codecs();
    for codec in &codecs {
        assert!(
            super::super::room::build_seat_codec(codec.clone()).is_ok(),
            "{} is offered but the room cannot seat it",
            codec.encoding_name
        );
    }
    let names: Vec<&str> = codecs
        .iter()
        .map(|codec| codec.encoding_name.as_str())
        .collect();
    assert_eq!(names[0], "OPUS", "{names:?}");
    let expected_amr = cfg!(feature = "amr");
    assert_eq!(names.contains(&"AMR-WB"), expected_amr, "{names:?}");
    assert_eq!(names.contains(&"AMR"), expected_amr, "{names:?}");
    for always in ["G722", "PCMU", "PCMA", "GSM", "G726-32"] {
        assert!(names.contains(&always), "{always} in {names:?}");
    }
    // One telephone-event per clock rate the codecs use, at that rate (RFC 4733 §2.1).
    let mut rates: Vec<u32> = codecs.iter().map(|codec| codec.clock_rate_hz).collect();
    rates.sort_unstable();
    rates.dedup();
    let mut event_rates: Vec<u32> = info
        .telephone_events()
        .iter()
        .map(|event| event.clock_rate_hz)
        .collect();
    event_rates.sort_unstable();
    assert_eq!(event_rates, rates, "{offer}");
    // Every listed format is described, so a peer never has to guess a dynamic payload type.
    for payload_type in &media[3..] {
        assert!(
            offer.contains(&format!("a=rtpmap:{payload_type} ")),
            "{payload_type} in {offer}"
        );
    }
}

/// The profile's codec flags edit what is offered; a profile asking for security or ICE is refused.
#[tokio::test]
async fn the_profile_edits_the_offer_and_unsupported_postures_are_refused() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = ok_sdp_text(
        &offer_seat(
            &engine,
            "room",
            "carol",
            ProfileFlags {
                flags: vec!["codec-except-PCMA".into()],
                ..Default::default()
            },
        )
        .await,
    );
    assert!(offer.contains("m=audio "), "{offer}");
    let info = sdp::parse(&offer).expect("parse");
    let codecs: Vec<String> = info
        .audio_codecs()
        .into_iter()
        .map(|codec| codec.encoding_name)
        .collect();
    assert_eq!(codecs, ["PCMA"]);

    let refused = offer_seat(
        &engine,
        "room",
        "dave",
        ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        refusal(&refused),
        "conference_offer: transport_protocol RTP/SAVP is not supported on an offered seat (only \
         RTP/AVP)"
    );
    let refused = offer_seat(
        &engine,
        "room",
        "dave",
        ProfileFlags {
            flags: vec!["codec-except-EVS".into()],
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        refusal(&refused),
        "conference_offer: no codec the room can mix is left after the profile's codec flags"
    );
    assert_eq!(
        engine.pending_seat_count(),
        1,
        "only carol's offer is pending"
    );
}

/// An answer for a seat that was never offered is refused and seats nothing.
#[tokio::test]
async fn an_answer_without_an_offer_is_refused() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_carol, carol_addr) = phone().await;
    let refused = answer_seat(&engine, "room", "carol", pcmu_answer(carol_addr)).await;
    assert_eq!(
        refusal(&refused),
        "conference_answer: no conference_offer for from-tag carol awaits an answer in this room"
    );
    assert!(!engine.conference().contains("room"));
}

/// One port in the pool: a refused answer must give its seat's port back, or the next offer fails.
async fn the_port_was_freed(engine: &Engine<UdpLoopbackDatapath>) {
    assert_eq!(engine.pending_seat_count(), 0);
    assert!(!engine.conference().contains("room"), "nothing was seated");
    let again = offer_seat(engine, "room", "carol", ProfileFlags::default()).await;
    assert!(
        matches!(again, CmdResult::Ok { .. }),
        "the port came back: {again:?}"
    );
    assert!(engine.drop_pending_seat("room", "carol").await);
}

/// An answer choosing a codec that was not offered, one rejecting the audio stream, one that is
/// secure, and one that is not SDP are each refused, and each frees the seat's endpoint.
#[tokio::test]
async fn a_refused_answer_frees_the_offered_seat() {
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(1));
    let (_carol, carol_addr) = phone().await;
    let rejected_port = SocketAddr::new(carol_addr.ip(), 0);
    let cases = [
        (
            answer_sdp(carol_addr, &[(18, "G729/8000")], "a=sendrecv\r\n"),
            "conference_answer: the answer chose payload type 18, which was not offered",
            ProfileFlags {
                flags: vec!["codec-strip-G729".into()],
                ..Default::default()
            },
        ),
        (
            answer_sdp(carol_addr, &[(9, "PCMA/8000")], ""),
            "conference_answer: the answer maps payload type 9 to PCMA/8000, offered as G722/8000",
            ProfileFlags::default(),
        ),
        (
            answer_sdp(carol_addr, &[(127, "EVS/16000")], ""),
            "conference_answer: the answer chose payload type 127, which was not offered",
            ProfileFlags::default(),
        ),
        (
            answer_sdp(rejected_port, &[(0, "PCMU/8000")], ""),
            "conference_answer: the answer rejected the audio stream (port 0)",
            ProfileFlags::default(),
        ),
        (
            pcmu_answer(carol_addr).replace("RTP/AVP", "RTP/SAVP"),
            "conference_answer: the answer is secure, but the offer was RTP/AVP",
            ProfileFlags::default(),
        ),
        (
            "not sdp".to_string(),
            "conference_answer: SDP parse: no audio media line in SDP",
            ProfileFlags::default(),
        ),
    ];
    for (answer, reason, profile) in cases {
        let offered = offer_seat(&engine, "room", "carol", profile).await;
        assert!(matches!(offered, CmdResult::Ok { .. }), "{offered:?}");
        let refused = answer_seat(&engine, "room", "carol", answer).await;
        assert_eq!(refusal(&refused), reason);
        the_port_was_freed(&engine).await;
    }
}

/// `conference_leave` on an offered seat frees it, and the seat is gone for a later answer.
#[tokio::test]
async fn leaving_an_offered_seat_frees_it() {
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(1));
    let (_carol, carol_addr) = phone().await;
    assert!(matches!(
        offer_seat(&engine, "room", "carol", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        leave_seat(&engine, "room", "carol").await,
        CmdResult::Ok { .. }
    ));
    let late = answer_seat(&engine, "room", "carol", pcmu_answer(carol_addr)).await;
    assert!(
        refusal(&late).starts_with("conference_answer: no conference_offer"),
        "{late:?}"
    );
    the_port_was_freed(&engine).await;
}

/// An offered seat nobody answers expires on the setup timeout, or on the media timeout when the
/// setup timeout is disabled, and not before.
#[tokio::test]
async fn an_unanswered_offer_expires_on_the_sweep() {
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(1));
    assert!(matches!(
        offer_seat(&engine, "room", "carol", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    engine.datapath().advance_clock(4);
    assert_eq!(
        engine.reap_pending_seats(5, 2).await,
        0,
        "inside the setup timeout"
    );
    engine.datapath().advance_clock(1);
    assert_eq!(
        engine.reap_pending_seats(5, 2).await,
        1,
        "the setup timeout ran out"
    );
    the_port_was_freed(&engine).await;

    assert!(matches!(
        offer_seat(&engine, "room", "carol", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    engine.datapath().advance_clock(2);
    assert_eq!(
        engine.reap_pending_seats(0, 2).await,
        1,
        "with the setup timeout off, the media timeout bounds it"
    );
    assert_eq!(engine.pending_seat_count(), 0);
}

/// A from-tag already pending or seated cannot be offered again, and a pending one cannot join.
#[tokio::test]
async fn a_tag_that_is_pending_or_seated_is_not_offered_twice() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_alice, alice_addr) = phone().await;
    assert!(matches!(
        offer_seat(&engine, "room", "carol", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let again = offer_seat(&engine, "room", "carol", ProfileFlags::default()).await;
    assert_eq!(
        refusal(&again),
        "conference_offer: from-tag carol already has an offer awaiting its answer"
    );
    let joined = join_seat(&engine, "room", "carol", alice_addr).await;
    assert_eq!(
        refusal(&joined),
        "conference_join: from-tag carol has a conference_offer awaiting its answer"
    );
    // The same tag in another room is another seat.
    assert!(matches!(
        offer_seat(&engine, "other-room", "carol", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));

    assert!(matches!(
        join_seat(&engine, "room", "alice", alice_addr).await,
        CmdResult::Ok { .. }
    ));
    let seated = offer_seat(&engine, "room", "alice", ProfileFlags::default()).await;
    assert_eq!(
        refusal(&seated),
        "conference_offer: from-tag alice is already seated in this room"
    );
    assert_eq!(engine.pending_seat_count(), 2);
}

/// The answer's own codec is the one the seat is built in, with its event payload type, and an
/// answer of `a=recvonly` seats a held participant whom the idle sweep does not reap for silence.
#[tokio::test]
async fn an_answer_on_hold_seats_a_participant_the_idle_sweep_leaves_alone() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_carol, carol_addr) = phone().await;
    let (_alice, alice_addr) = phone().await;
    assert!(matches!(
        join_seat(&engine, "room", "alice", alice_addr).await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        offer_seat(&engine, "room", "carol", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let answer = answer_sdp(
        carol_addr,
        &[(8, "PCMA/8000"), (101, "telephone-event/8000")],
        "a=recvonly\r\n",
    );
    assert!(matches!(
        answer_seat(&engine, "room", "carol", answer).await,
        CmdResult::Ok { .. }
    ));
    assert!(engine
        .conference()
        .participant_at_tag("room", "carol")
        .is_some());
    engine.datapath().advance_clock(10);
    // Alice is silent and sendrecv, so she is reaped; carol said she would not send.
    assert_eq!(engine.reap_idle_conferences(3, 0).await, 1);
    assert!(engine
        .conference()
        .participant_at_tag("room", "carol")
        .is_some());
    assert!(engine
        .conference()
        .participant_at_tag("room", "alice")
        .is_none());
}

/// A draining node refuses a new offered seat as it refuses `offer` and `conference_join`, and still
/// takes the answer to a seat it offered before it started draining.
#[tokio::test]
async fn a_draining_node_refuses_conference_offer_and_still_seats_an_earlier_one() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_carol, carol_addr) = phone().await;
    assert!(matches!(
        offer_seat(&engine, "room", "carol", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        engine.handle(CLIENT, Command::Drain).await,
        CmdResult::Ok { .. }
    ));
    let refused = offer_seat(&engine, "room", "dave", ProfileFlags::default()).await;
    assert_eq!(
        refusal(&refused),
        "node is draining; not accepting new sessions"
    );
    let answered = answer_seat(&engine, "room", "carol", pcmu_answer(carol_addr)).await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    assert_eq!(engine.pending_seat_count(), 0);
}

/// `conference_unbridge` stops audio crossing between two rooms in both directions, and refuses a
/// pair that is not bridged or a room that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbridging_two_rooms_stops_audio_crossing() {
    let engine = engine_with_dispatcher();
    let (alice, alice_addr) = phone().await;
    let (bob, bob_addr) = phone().await;
    let alice_engine = sdp::parse(&ok_sdp_text(
        &join_seat(&engine, "room-x", "alice", alice_addr).await,
    ))
    .expect("answer")
    .remote_rtp;
    assert!(matches!(
        join_seat(&engine, "room-y", "bob", bob_addr).await,
        CmdResult::Ok { .. }
    ));

    let unbridge = |a: &str, b: &str| Command::ConferenceUnbridge {
        conference_id_a: a.into(),
        conference_id_b: b.into(),
    };
    assert_eq!(
        refusal(&engine.handle(CLIENT, unbridge("room-x", "room-y")).await),
        "conference_unbridge: the two conferences are not bridged"
    );
    assert_eq!(
        refusal(&engine.handle(CLIENT, unbridge("room-x", "ghost")).await),
        "conference_unbridge: unknown conference: ghost"
    );

    // Bridge both ways, prove bob hears alice, then unbridge naming the rooms the other way round.
    let bridged = engine
        .handle(
            CLIENT,
            Command::ConferenceBridge {
                conference_id_a: "room-x".into(),
                conference_id_b: "room-y".into(),
                direction: BridgeDirection::Both,
            },
        )
        .await;
    assert!(matches!(bridged, CmdResult::Ok { .. }), "{bridged:?}");
    talk(&alice, alice_engine, 0x0A0A_0A0A, 0, 40).await;
    assert!(
        hears_loud(&bob, 20).await,
        "bob hears alice across the bridge"
    );

    assert!(matches!(
        engine.handle(CLIENT, unbridge("room-y", "room-x")).await,
        CmdResult::Ok { .. }
    ));
    assert!(engine.conference().bridged_with("room-x").is_empty());
    assert!(engine.conference().bridged_with("room-y").is_empty());
    // Let the bridged audio already in flight drain, then alice talks on and bob hears none of it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    while timeout(Duration::from_millis(5), bob.recv_from(&mut [0u8; 2048]))
        .await
        .is_ok()
    {}
    talk(&alice, alice_engine, 0x0A0A_0A0A, 40, 40).await;
    assert!(!hears_loud(&bob, 15).await, "bob no longer hears alice");
    assert_eq!(
        refusal(&engine.handle(CLIENT, unbridge("room-x", "room-y")).await),
        "conference_unbridge: the two conferences are not bridged"
    );
}

/// The pending-seat store drains back to its baseline across every way a seat can end: answered and
/// left, left while pending, refused on its answer, and expired.
#[tokio::test]
async fn the_pending_seat_store_drains_to_baseline() {
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(4));
    let (_carol, carol_addr) = phone().await;
    for round in 0..20u16 {
        let tag = format!("carol-{round}");
        assert!(matches!(
            offer_seat(&engine, "room", &tag, ProfileFlags::default()).await,
            CmdResult::Ok { .. }
        ));
        match round % 4 {
            0 => {
                assert!(matches!(
                    answer_seat(&engine, "room", &tag, pcmu_answer(carol_addr)).await,
                    CmdResult::Ok { .. }
                ));
                assert!(matches!(
                    leave_seat(&engine, "room", &tag).await,
                    CmdResult::Ok { .. }
                ));
            }
            1 => assert!(matches!(
                leave_seat(&engine, "room", &tag).await,
                CmdResult::Ok { .. }
            )),
            2 => {
                let refused = answer_seat(&engine, "room", &tag, "not sdp".into()).await;
                assert!(matches!(refused, CmdResult::Error { .. }));
            }
            _ => {
                engine.datapath().advance_clock(10);
                assert_eq!(engine.reap_pending_seats(5, 5).await, 1);
            }
        }
        assert_eq!(engine.pending_seat_count(), 0, "round {round}");
        assert_eq!(engine.conference().room_count(), 0, "round {round}");
    }
    // Four ports and twenty rounds: had any round kept its port, the pool would have run dry.
    let (_a, a) = phone().await;
    for tag in ["a", "b", "c", "d"] {
        assert!(
            matches!(
                join_seat(&engine, "full", tag, a).await,
                CmdResult::Ok { .. }
            ),
            "{tag}"
        );
    }
}
