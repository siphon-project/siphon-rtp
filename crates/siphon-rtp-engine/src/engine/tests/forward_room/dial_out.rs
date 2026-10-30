//! A forwarding room calling a member out (`forward_offer` then `forward_answer`), seats in another
//! codec than the room's, and the backstop that frees a room nobody is left in.

use super::*;
use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_proto::{MediaTimeoutReason, RtcpAppStream};

/// TS 24.380 §8.2.4 Floor Request: SSRC 0x11223344, name MCPT, subtype 0.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];
const FLOOR_FMTP: &str = "mc_queueing;mc_priority=5;mc_granted";

async fn offer_member(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                profile,
            },
        )
        .await
}

async fn answer_member(engine: &Engine<UdpLoopbackDatapath>, tag: &str, sdp: String) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp,
                received_from: None,
            },
        )
        .await
}

fn refusal(result: &CmdResult) -> &str {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A member's answer from `audio`: one audio format with its rtpmap, optional fmtp, then optional
/// telephone-event and floor section (port 0 declines it).
fn answer(
    audio: SocketAddr,
    payload_type: u8,
    rtpmap: &str,
    fmtp: Option<&str>,
    event: Option<(u8, u32)>,
    floor_port: Option<u16>,
) -> String {
    let mut formats = payload_type.to_string();
    if let Some((event_type, _)) = event {
        formats.push_str(&format!(" {event_type}"));
    }
    let mut text = format!(
        "v=0\r\no=- 7 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {formats}\r\na=rtpmap:{payload_type} {rtpmap}\r\n",
        ip = audio.ip(),
        port = audio.port()
    );
    if let Some(fmtp) = fmtp {
        text.push_str(&format!("a=fmtp:{payload_type} {fmtp}\r\n"));
    }
    if let Some((event_type, rate)) = event {
        text.push_str(&format!("a=rtpmap:{event_type} telephone-event/{rate}\r\n"));
    }
    text.push_str("a=sendrecv\r\na=rtcp-mux\r\n");
    if let Some(port) = floor_port {
        text.push_str(&format!("m=application {port} udp MCPTT\r\n"));
    }
    text
}

fn amr_wb_answer(audio: SocketAddr, payload_type: u8) -> String {
    answer(
        audio,
        payload_type,
        "AMR-WB/16000",
        Some("octet-align=1"),
        None,
        None,
    )
}

fn names(offer: &str) -> Vec<String> {
    sdp::parse(offer)
        .expect("the engine's own parser reads its offer")
        .audio_codecs()
        .into_iter()
        .map(|codec| codec.encoding_name)
        .collect()
}

/// An engine with a bounded port pool and the redirect dispatcher running, so a leaked endpoint
/// shows as a later allocation failing.
fn small_engine(endpoints: usize) -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(endpoints));
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

#[tokio::test]
async fn a_dialled_out_member_is_forwarded_the_source_untouched_and_can_be_the_source() {
    let engine = engine_with_dispatcher();
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    let (phone_d, addr_d) = phone().await;

    let offer = ok_sdp_text(&offer_member(&engine, "d", ProfileFlags::default()).await);
    let info = sdp::parse(&offer).expect("parse");
    let first = &info.audio_codecs()[0];
    assert_eq!(
        (first.encoding_name.as_str(), first.payload_type),
        ("AMR-WB", 97),
        "the room's codec leads the offer under the conventional octet-aligned number: {offer}"
    );
    assert!(offer.contains("octet-align=1"), "{offer}");
    let port_d = info.remote_rtp;
    assert_eq!(engine.pending_seat_count(), 1);
    assert_eq!(
        engine.conference().forward().seat_count(),
        1,
        "not seated yet"
    );

    let answered = answer_member(&engine, "d", amr_wb_answer(addr_d, 97)).await;
    assert_eq!(answered, ok_empty());
    assert_eq!(engine.pending_seat_count(), 0);
    assert_eq!(engine.conference().forward().seat_count(), 2);

    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());
    let payload = [0xF1, 0x23, 0x45, 0x67, 0x89, 0xAB];
    phone_a
        .send_to(&media(96, 1, 320, 0xA0A0_A0A0, &payload), port_a)
        .await
        .expect("send");
    let heard = hear(&phone_d).await;
    assert_eq!(heard.payload, payload, "forwarded byte-identical");
    assert_eq!(
        heard.payload_type, 97,
        "under the number the member answered"
    );

    // And the dialled-out member can take the floor.
    assert_eq!(set_source(&engine, Some("d")).await, ok_empty());
    phone_d
        .send_to(&media(97, 1, 320, 0xD0D0_D0D0, &payload), port_d)
        .await
        .expect("send");
    let heard = hear(&phone_a).await;
    assert_eq!(heard.payload, payload);
    assert_eq!(heard.payload_type, 96);
}

#[tokio::test]
async fn the_first_offer_lists_every_codec_and_the_answer_fixes_the_rooms_codec() {
    let engine = engine_with_dispatcher();
    let (phone_d, addr_d) = phone().await;
    let offer = ok_sdp_text(&offer_member(&engine, "d", ProfileFlags::default()).await);
    let listed = names(&offer);
    assert_eq!(listed[0], "OPUS", "widest band first: {listed:?}");
    // Forwarding needs no encoder, so AMR is offered whether or not this build has the codec.
    for always in ["AMR-WB", "AMR", "G722", "PCMU", "PCMA", "G729"] {
        assert!(
            listed.iter().any(|name| name == always),
            "{always} in {listed:?}"
        );
    }
    let answered = answer_member(
        &engine,
        "d",
        answer(addr_d, 0, "PCMU/8000", None, Some((101, 8000)), None),
    )
    .await;
    assert_eq!(answered, ok_empty());
    let codec = engine
        .conference()
        .forward()
        .room_codec(ROOM)
        .expect("the room");
    assert_eq!(codec.describe(), "PCMU/8000");

    // A PCMA member then joins the PCMU room: transcoded for, not refused.
    let (phone_p, addr_p) = phone().await;
    let join = join_with(
        &engine,
        "p",
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=rtcp-mux\r\n",
            ip = addr_p.ip(),
            port = addr_p.port()
        ),
    )
    .await;
    let joined = sdp::parse(&ok_sdp_text(&join)).expect("answer");
    assert_eq!(joined.audio_codecs()[0].encoding_name, "PCMA");
    assert_eq!(set_source(&engine, Some("d")).await, ok_empty());
    let port_d = engine
        .conference()
        .forward()
        .seat_endpoint(ROOM, "d")
        .expect("seat");
    let _ = port_d;
    let d_engine_port = {
        // The engine port the dialled-out member talks to is the one its offer named.
        sdp::parse(&offer).expect("parse").remote_rtp
    };
    let mut encoder = factory::encoder_for(&CodecSpec::new(0, "PCMU", 8000, 1, 20)).unwrap();
    let mut heard = Vec::new();
    for frame in 0..6u16 {
        let pcm: Vec<i16> = (0..160)
            .map(|n| {
                ((f64::from(frame) * 160.0 + f64::from(n)) * 0.2)
                    .sin()
                    .mul_add(8000.0, 0.0) as i16
            })
            .collect();
        let mut payload = [0u8; 160];
        let length = encoder.encode(&pcm, &mut payload).unwrap();
        phone_d
            .send_to(
                &media(
                    0,
                    frame,
                    u32::from(frame) * 160,
                    0xD0D0_D0D0,
                    &payload[..length],
                ),
                d_engine_port,
            )
            .await
            .expect("send");
        heard.push(hear(&phone_p).await);
    }
    assert!(heard.iter().all(|packet| packet.payload_type == 8));
    assert!(heard.iter().all(|packet| packet.payload.len() == 160));
    let mut decoder = factory::decoder_for(&CodecSpec::new(8, "PCMA", 8000, 1, 20)).unwrap();
    let mut pcm = vec![0i16; 320];
    let mut energy = 0f64;
    for packet in &heard {
        let samples = decoder.decode(&packet.payload, &mut pcm).unwrap();
        energy += pcm[..samples]
            .iter()
            .map(|s| f64::from(*s).powi(2))
            .sum::<f64>();
    }
    let rms = (energy / (6.0 * 160.0)).sqrt();
    assert!(rms > 2000.0, "the PCMA member hears the PCMU talker: {rms}");
}

#[tokio::test]
async fn an_answer_with_a_codec_the_offer_did_not_list_is_refused_and_the_seat_freed() {
    // Two ports: seat a's and the offered seat's.
    let engine = small_engine(2);
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_phone_d, addr_d) = phone().await;
    assert!(matches!(
        offer_member(&engine, "d", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let refused = answer_member(
        &engine,
        "d",
        answer(addr_d, 77, "speex/8000", None, None, None),
    )
    .await;
    assert!(
        refusal(&refused).starts_with("forward_answer: the answer chose payload type 77"),
        "{refused:?}"
    );
    assert_eq!(engine.pending_seat_count(), 0);
    assert_eq!(engine.conference().forward().seat_count(), 1);
    // The offered seat's port is free again: another offer can take it.
    assert!(matches!(
        offer_member(&engine, "e", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    // The seat was consumed by the refused answer: it cannot be answered again.
    let again = answer_member(&engine, "d", amr_wb_answer(addr_d, 97)).await;
    assert!(
        refusal(&again).starts_with("forward_answer: no forward_offer"),
        "{again:?}"
    );
}

#[tokio::test]
async fn a_rejected_secure_or_foreign_family_answer_is_refused_and_freed() {
    let engine = small_engine(2);
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_phone_d, addr_d) = phone().await;
    for (text, why) in [
        (
            amr_wb_answer(SocketAddr::from(([127, 0, 0, 1], 0)), 97),
            "port 0",
        ),
        (
            amr_wb_answer(addr_d, 97).replace("RTP/AVP", "RTP/SAVP"),
            "secure",
        ),
        (
            amr_wb_answer(addr_d, 97).replace("IN IP4 127.0.0.1", "IN IP6 ::1"),
            "address family",
        ),
    ] {
        assert!(matches!(
            offer_member(&engine, "d", ProfileFlags::default()).await,
            CmdResult::Ok { .. }
        ));
        let refused = answer_member(&engine, "d", text).await;
        assert!(refusal(&refused).contains(why), "{why}: {refused:?}");
        assert_eq!(engine.pending_seat_count(), 0);
    }
}

#[tokio::test]
async fn an_unanswered_offer_is_reaped_by_the_setup_timeout_with_its_floor_endpoint() {
    // Audio and floor endpoints: the pool holds exactly one such offer.
    let engine = small_engine(2);
    let profile = || ProfileFlags {
        floor_fmtp: Some(FLOOR_FMTP.into()),
        ..Default::default()
    };
    assert!(matches!(
        offer_member(&engine, "d", profile()).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.pending_seat_count(), 1);
    engine.datapath().advance_clock(4);
    assert_eq!(
        engine.reap_pending_seats(5, 2).await,
        0,
        "inside the ceiling"
    );
    engine.datapath().advance_clock(1);
    assert_eq!(
        engine.reap_pending_seats(5, 2).await,
        1,
        "the ceiling ran out"
    );
    assert_eq!(engine.pending_seat_count(), 0);
    // Both endpoints came back.
    assert!(matches!(
        offer_member(&engine, "e", profile()).await,
        CmdResult::Ok { .. }
    ));
    // A late answer finds nothing to seat.
    let (_phone, addr) = phone().await;
    let late = answer_member(&engine, "d", amr_wb_answer(addr, 97)).await;
    assert!(refusal(&late).contains("no forward_offer"), "{late:?}");
}

#[tokio::test]
async fn leaving_drops_a_pending_offer_and_frees_its_endpoints() {
    let engine = small_engine(2);
    let profile = ProfileFlags {
        floor_fmtp: Some(FLOOR_FMTP.into()),
        ..Default::default()
    };
    assert!(matches!(
        offer_member(&engine, "d", profile.clone()).await,
        CmdResult::Ok { .. }
    ));
    let left = engine
        .handle(
            CLIENT,
            Command::ForwardLeave {
                conference_id: ROOM.into(),
                from_tag: "d".into(),
            },
        )
        .await;
    assert_eq!(left, ok_empty());
    assert_eq!(engine.pending_seat_count(), 0);
    assert!(matches!(
        offer_member(&engine, "e", profile).await,
        CmdResult::Ok { .. }
    ));
}

#[tokio::test]
async fn a_tag_that_is_pending_or_seated_is_not_offered_twice() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let seated = offer_member(&engine, "a", ProfileFlags::default()).await;
    assert_eq!(
        refusal(&seated),
        "forward_offer: from-tag a is already seated in this room"
    );
    assert!(matches!(
        offer_member(&engine, "d", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let pending = offer_member(&engine, "d", ProfileFlags::default()).await;
    assert_eq!(
        refusal(&pending),
        "forward_offer: from-tag d already has an offer awaiting its answer"
    );
}

#[tokio::test]
async fn the_floor_stream_of_a_dialled_out_seat_is_offered_anchored_and_delivers_rtcp_app() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let (_phone_d, addr_d) = phone().await;
    let (floor_d, floor_addr_d) = phone().await;
    let offer = ok_sdp_text(
        &offer_member(
            &engine,
            "d",
            ProfileFlags {
                floor_fmtp: Some(FLOOR_FMTP.into()),
                ..Default::default()
            },
        )
        .await,
    );
    let lines: Vec<&str> = offer.split("\r\n").collect();
    let floor_line = lines
        .iter()
        .position(|line| line.starts_with("m=application"))
        .expect("a floor section");
    assert!(
        lines[floor_line].ends_with(" udp MCPTT") && !lines[floor_line].contains(" 0 udp"),
        "{offer}"
    );
    assert!(
        lines.contains(&format!("a=fmtp:MCPTT {FLOOR_FMTP}").as_str()),
        "the controller's parameters verbatim: {offer}"
    );
    let engine_floor = sdp::parse_floor(&offer).expect("floor").remote;
    let engine_audio = sdp::parse(&offer).expect("parse").remote_rtp;
    assert_ne!(engine_floor.port(), engine_audio.port());

    let answered = answer_member(
        &engine,
        "d",
        answer(
            addr_d,
            97,
            "AMR-WB/16000",
            Some("octet-align=1"),
            None,
            Some(floor_addr_d.port()),
        ),
    )
    .await;
    // The room did not exist: the first seat fixes it. 97 is a listed format.
    assert_eq!(answered, ok_empty());
    floor_d
        .send_to(&FLOOR_REQUEST, engine_floor)
        .await
        .expect("send");
    let event = tokio::time::timeout(SHORT, app_events.recv_async())
        .await
        .expect("an rtcp_app event")
        .expect("open queue");
    assert_eq!(
        event,
        Event::RtcpApp {
            call_id: None,
            conference_id: Some(ROOM.into()),
            from_tag: "d".into(),
            stream: RtcpAppStream::Floor,
            ssrc: 0x1122_3344,
            name: "MCPT".into(),
            subtype: 0,
            payload: vec![0x00, 0x02, 0x05, 0x00],
        }
    );
}

#[tokio::test]
async fn declining_the_floor_stream_leaves_an_audio_only_seat_and_frees_its_endpoint() {
    // Audio + floor for the offered seat; after the answer only the audio endpoint stays, so a
    // second one-endpoint offer fits in the pool of three.
    let engine = small_engine(3);
    let (_phone_d, addr_d) = phone().await;
    assert!(matches!(
        offer_member(
            &engine,
            "d",
            ProfileFlags {
                floor_fmtp: Some(FLOOR_FMTP.into()),
                ..Default::default()
            }
        )
        .await,
        CmdResult::Ok { .. }
    ));
    let answered = answer_member(
        &engine,
        "d",
        answer(
            addr_d,
            97,
            "AMR-WB/16000",
            Some("octet-align=1"),
            None,
            Some(0),
        ),
    )
    .await;
    assert_eq!(answered, ok_empty());
    assert_eq!(engine.conference().forward().seat_count(), 1);
    assert_eq!(engine.endpoint_calls.len(), 1, "audio only");
    assert!(matches!(
        offer_member(&engine, "e", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        offer_member(&engine, "f", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
}

#[tokio::test]
async fn a_floor_fmtp_with_a_line_break_refuses_the_offer_before_allocating() {
    let engine = small_engine(1);
    let refused = offer_member(
        &engine,
        "d",
        ProfileFlags {
            floor_fmtp: Some("mc_granted\r\na=sendrecv".into()),
            ..Default::default()
        },
    )
    .await;
    assert!(refusal(&refused).contains("line break"), "{refused:?}");
    assert_eq!(engine.pending_seat_count(), 0);
    assert!(matches!(
        offer_member(&engine, "d", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
}

#[tokio::test]
async fn a_draining_node_refuses_forward_offer_but_completes_an_offered_seat() {
    let engine = engine_with_dispatcher();
    let (_phone_d, addr_d) = phone().await;
    assert!(matches!(
        offer_member(&engine, "d", ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.handle(CLIENT, Command::Drain).await, ok_empty());
    let refused = offer_member(&engine, "e", ProfileFlags::default()).await;
    assert_eq!(
        refusal(&refused),
        "node is draining; not accepting new sessions"
    );
    // The answer completes a setup the node had already admitted.
    assert_eq!(
        answer_member(&engine, "d", amr_wb_answer(addr_d, 97)).await,
        ok_empty()
    );
}

#[tokio::test]
async fn a_forwarding_room_and_a_mixing_conference_do_not_share_an_id_in_either_direction() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    // A mixing offer on a forwarding room's id.
    let mixing_offer = engine
        .handle(
            CLIENT,
            Command::ConferenceOffer {
                conference_id: ROOM.into(),
                from_tag: "m".into(),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert_eq!(
        refusal(&mixing_offer),
        format!("conference_offer: {ROOM} is a forwarding room; use forward_offer")
    );
    assert_eq!(engine.pending_seat_count(), 0);

    // A forwarding offer on a mixing room's id.
    let (_, addr) = phone().await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "mix".into(),
                from_tag: "m".into(),
                sdp: sdp_for(addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(joined, CmdResult::Ok { .. }), "{joined:?}");
    let forward_offer = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                conference_id: "mix".into(),
                from_tag: "d".into(),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert_eq!(
        refusal(&forward_offer),
        "forward_offer: mix is a mixing conference; use conference_offer"
    );
}

#[tokio::test]
async fn an_id_that_changed_kind_between_offer_and_answer_is_refused_and_freed() {
    let engine = small_engine(3);
    let (_phone_d, addr_d) = phone().await;
    // Offered while "late" names nothing; then a mixing room takes the id.
    assert!(matches!(
        engine
            .handle(
                CLIENT,
                Command::ForwardOffer {
                    conference_id: "late".into(),
                    from_tag: "d".into(),
                    profile: ProfileFlags::default(),
                },
            )
            .await,
        CmdResult::Ok { .. }
    ));
    let (_, addr) = phone().await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "late".into(),
                from_tag: "m".into(),
                sdp: sdp_for(addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(joined, CmdResult::Ok { .. }), "{joined:?}");
    let refused = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: "late".into(),
                from_tag: "d".into(),
                sdp: amr_wb_answer(addr_d, 97),
                received_from: None,
            },
        )
        .await;
    assert!(
        refusal(&refused).contains("is a mixing conference"),
        "{refused:?}"
    );
    assert_eq!(engine.pending_seat_count(), 0);
}

#[tokio::test]
async fn a_forwarding_room_that_appeared_after_a_mixing_offer_refuses_its_answer() {
    let engine = small_engine(3);
    let (_phone_c, addr_c) = phone().await;
    assert!(matches!(
        engine
            .handle(
                CLIENT,
                Command::ConferenceOffer {
                    conference_id: ROOM.into(),
                    from_tag: "c".into(),
                    role: ConferenceRole::Talker,
                    profile: ProfileFlags::default(),
                },
            )
            .await,
        CmdResult::Ok { .. }
    ));
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let refused = engine
        .handle(
            CLIENT,
            Command::ConferenceAnswer {
                conference_id: ROOM.into(),
                from_tag: "c".into(),
                sdp: answer(addr_c, 0, "PCMU/8000", None, None, None),
                received_from: None,
            },
        )
        .await;
    assert_eq!(
        refusal(&refused),
        format!("conference_answer: {ROOM} is a forwarding room; use forward_answer")
    );
    assert_eq!(engine.pending_seat_count(), 0);
}

#[tokio::test]
async fn node_info_advertises_dial_out_and_transcoding() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    for feature in ["forward_dialout", "forward_transcode"] {
        assert!(
            node.features.iter().any(|name| name == feature),
            "{feature}"
        );
    }
}

#[tokio::test]
async fn a_room_nobody_is_left_in_is_freed_with_one_timeout_per_seat() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_phone_b, _) = seat(&engine, "b", 96).await;
    engine.datapath().advance_clock(50);
    assert_eq!(
        engine.reap_idle_forward_rooms(60).await,
        0,
        "inside the ceiling"
    );
    assert_eq!(engine.reap_idle_forward_rooms(0).await, 0, "0 disables it");
    assert_eq!(engine.conference().forward().seat_count(), 2);
    engine.datapath().advance_clock(10);
    assert_eq!(engine.reap_idle_forward_rooms(60).await, 1);
    assert_eq!(engine.conference().forward().room_count(), 0);
    assert!(engine.endpoint_calls.is_empty(), "every endpoint was freed");

    let mut tags: Vec<String> = events
        .try_iter()
        .filter_map(|event| match event {
            Event::MediaTimeout {
                call_id,
                from_tag,
                conference_id,
                reason,
            } => {
                assert_eq!(call_id, "");
                assert_eq!(conference_id.as_deref(), Some(ROOM));
                assert_eq!(reason, MediaTimeoutReason::NoMedia);
                Some(from_tag)
            }
            _ => None,
        })
        .collect();
    tags.sort();
    assert_eq!(tags, ["a", "b"], "one per seat");
    assert_eq!(engine.reap_idle_forward_rooms(60).await, 0, "once");
}

#[tokio::test]
async fn one_seat_sending_rtcp_keeps_the_whole_room_and_no_seat_is_reaped_alone() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    let (_phone_b, _) = seat(&engine, "b", 96).await;
    engine.datapath().advance_clock(50);
    // A receiver report (RFC 3550 §6.2) from a listener is all a live group needs to send.
    let mut report = [0u8; 28];
    let length =
        siphon_rtp_media::rtcp::write_sender_report(0xA0A0_A0A0, 0, 0, 0, 0, &[], &mut report)
            .expect("report");
    phone_a
        .send_to(&report[..length], port_a)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.datapath().advance_clock(30);
    assert_eq!(
        engine.reap_idle_forward_rooms(60).await,
        0,
        "a was heard 30 ticks ago; b's silence alone frees nothing"
    );
    assert_eq!(engine.conference().forward().seat_count(), 2);
    assert!(events
        .try_iter()
        .all(|event| !matches!(event, Event::MediaTimeout { .. })));
    engine.datapath().advance_clock(40);
    assert_eq!(
        engine.reap_idle_forward_rooms(60).await,
        1,
        "now both are quiet"
    );
}

/// `frames` consecutive 20 ms frames of a 440 Hz tone through one encoder for `spec`.
fn tone_stream(spec: &CodecSpec, frames: usize) -> Vec<Vec<u8>> {
    let mut encoder = factory::encoder_for(spec).unwrap();
    let rate = encoder.params().sample_rate_hz as usize;
    let frame = rate / 50;
    let mut out = vec![0u8; 1500];
    (0..frames)
        .map(|step| {
            let pcm: Vec<i16> = (0..frame)
                .map(|n| {
                    let t = (step * frame + n) as f64 / rate as f64;
                    ((t * 440.0 * std::f64::consts::TAU).sin() * 8000.0) as i16
                })
                .collect();
            let length = encoder.encode(&pcm, &mut out).unwrap();
            out[..length].to_vec()
        })
        .collect()
}

/// RMS of `payloads` decoded as `spec` by one decoder, leaving out the first `skip` frames.
fn rms_after(spec: &CodecSpec, payloads: &[Vec<u8>], skip: usize) -> f64 {
    let mut decoder = factory::decoder_for(spec).unwrap();
    let mut pcm = vec![0i16; 11_520];
    let (mut energy, mut count) = (0f64, 0usize);
    for (index, payload) in payloads.iter().enumerate() {
        let values = decoder.decode(payload, &mut pcm).unwrap();
        if index >= skip {
            energy += pcm[..values]
                .iter()
                .map(|s| f64::from(*s).powi(2))
                .sum::<f64>();
            count += values;
        }
    }
    (energy / count as f64).sqrt()
}

/// A phone offer for one audio format.
fn offer_for(addr: SocketAddr, payload_type: u8, rtpmap: &str, fmtp: Option<&str>) -> String {
    let fmtp = fmtp.map_or(String::new(), |fmtp| {
        format!("a=fmtp:{payload_type} {fmtp}\r\n")
    });
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {payload_type}\r\na=rtpmap:{payload_type} {rtpmap}\r\n{fmtp}\
         a=rtcp-mux\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

/// An AMR-WB room with a talker `a` and a member `m` in `member`, joined by `forward_join`. The
/// talker is heard by the member as the member's own codec, and the member, when it takes the floor,
/// is heard by the talker as AMR-WB frames that decode to the same tone: compared by energy, because
/// a transcode is lossy and the point is that the audio arrives, not that the bytes match.
#[cfg(feature = "amr")]
async fn cross_codec_conversation(member: CodecSpec, rtpmap: &str, fmtp: Option<&str>) {
    let engine = engine_with_dispatcher();
    let mut amr = CodecSpec::new(96, "AMR-WB", 16_000, 1, 20);
    amr = amr.with_amr_params(Some(factory::AmrParams {
        octet_align: Some(true),
        ..Default::default()
    }));
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    let (phone_m, addr_m) = phone().await;
    let joined = join_with(
        &engine,
        "m",
        offer_for(addr_m, member.payload_type, rtpmap, fmtp),
    )
    .await;
    let answered = sdp::parse(&ok_sdp_text(&joined)).expect("answer");
    assert_eq!(
        answered.audio_codecs()[0].encoding_name,
        member.encoding_name,
        "the member is answered in its own codec"
    );
    let port_m = answered.remote_rtp;
    let member_step = member.clock_rate_hz / 50;

    // The AMR-WB talker is heard by the member in the member's codec.
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());
    let stream = tone_stream(&amr, 12);
    let mut heard = Vec::new();
    for (index, payload) in stream.iter().enumerate() {
        phone_a
            .send_to(
                &media(
                    96,
                    1 + index as u16,
                    index as u32 * 320,
                    0xA0A0_A0A0,
                    payload,
                ),
                port_a,
            )
            .await
            .expect("send");
        let packet = hear(&phone_m).await;
        assert_eq!(packet.payload_type, member.payload_type);
        heard.push(packet.payload);
    }
    let reference = rms_after(&amr, &stream, 3);
    let rms = rms_after(&member, &heard, 3);
    assert!(
        reference > 3000.0,
        "the fixture is a loud tone: {reference}"
    );
    assert!(
        (rms - reference).abs() / reference < 0.2,
        "the member hears the talker: {reference} vs {rms}"
    );

    // The member takes the floor and is heard as AMR-WB.
    assert_eq!(set_source(&engine, Some("m")).await, ok_empty());
    let stream = tone_stream(&member, 12);
    let mut heard = Vec::new();
    for (index, payload) in stream.iter().enumerate() {
        phone_m
            .send_to(
                &media(
                    member.payload_type,
                    1 + index as u16,
                    index as u32 * member_step,
                    0xB0B0_B0B0,
                    payload,
                ),
                port_m,
            )
            .await
            .expect("send");
        let packet = hear(&phone_a).await;
        assert_eq!(packet.payload_type, 96);
        heard.push(packet.payload);
    }
    let reference = rms_after(&member, &stream, 3);
    let rms = rms_after(&amr, &heard, 3);
    assert!(
        reference > 3000.0,
        "the fixture is a loud tone: {reference}"
    );
    assert!(
        (rms - reference).abs() / reference < 0.25,
        "the talker hears the member as AMR-WB: {reference} vs {rms}"
    );
}

#[cfg(feature = "amr")]
#[tokio::test]
async fn a_pcmu_seat_in_an_amr_wb_room_hears_the_source_and_is_heard_as_amr_wb() {
    cross_codec_conversation(CodecSpec::new(0, "PCMU", 8000, 1, 20), "PCMU/8000", None).await;
}

#[cfg(feature = "amr")]
#[tokio::test]
async fn an_opus_seat_in_an_amr_wb_room_hears_the_source_and_is_heard_as_amr_wb() {
    cross_codec_conversation(
        CodecSpec::new(111, "opus", 48_000, 2, 20),
        "opus/48000/2",
        Some("stereo=0;sprop-stereo=0"),
    )
    .await;
}

#[cfg(feature = "amr")]
#[tokio::test]
async fn a_bandwidth_efficient_amr_wb_seat_in_an_octet_aligned_room_is_transcoded_for() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_phone_b, addr_b) = phone().await;
    let joined = join_with(&engine, "b", amr_wb_sdp(addr_b, 96, "octet-align=0")).await;
    let answered = sdp::parse(&ok_sdp_text(&joined)).expect("answer");
    let spec = &answered.audio_codecs()[0];
    assert_eq!(spec.encoding_name, "AMR-WB");
    assert!(
        !spec.amr.and_then(|amr| amr.octet_align).unwrap_or(false),
        "answered in the seat's own payload format"
    );
}

#[cfg(feature = "amr")]
#[tokio::test]
async fn a_dialled_out_member_may_answer_in_a_codec_the_room_transcodes() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_phone_d, addr_d) = phone().await;
    let offer = ok_sdp_text(&offer_member(&engine, "d", ProfileFlags::default()).await);
    let listed = names(&offer);
    assert_eq!(listed[0], "AMR-WB", "the room's codec leads: {listed:?}");
    assert!(
        listed.iter().any(|name| name == "PCMU") && listed.iter().any(|name| name == "OPUS"),
        "codecs the room can transcode follow: {listed:?}"
    );
    let answered = answer_member(
        &engine,
        "d",
        answer(addr_d, 0, "PCMU/8000", None, None, None),
    )
    .await;
    assert_eq!(answered, ok_empty());
    assert_eq!(engine.conference().forward().seat_count(), 2);
}

#[cfg(not(feature = "amr"))]
#[tokio::test]
async fn without_amr_a_seat_in_another_codec_is_refused_naming_the_build_and_leaves_nothing() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_, addr) = phone().await;
    let CmdResult::Error { reason } = join_with(&engine, "p", sdp_for(addr, true)).await else {
        panic!("expected a refusal");
    };
    assert!(reason.contains("the room carries AMR-WB/16000"), "{reason}");
    assert!(
        reason.contains("this build lacks AMR transcoding"),
        "{reason}"
    );
    assert_eq!(engine.conference().forward().seat_count(), 1);
    assert_eq!(
        engine.endpoint_calls.len(),
        1,
        "the refused seat holds nothing"
    );
}

#[cfg(not(feature = "amr"))]
#[tokio::test]
async fn without_amr_the_offer_to_an_amr_room_lists_only_its_own_codec() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let offer = ok_sdp_text(&offer_member(&engine, "d", ProfileFlags::default()).await);
    assert_eq!(names(&offer), ["AMR-WB"]);
}
